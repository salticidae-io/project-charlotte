use std::{
    collections::VecDeque, error::Error, future::Future, io, net::SocketAddr, path::PathBuf,
    time::Duration,
};

use bytes::Bytes;
use futures_util::stream;
use http::{
    HeaderValue, Request, Response, StatusCode, Version,
    header::{self, HOST},
};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use modsecurity::{Intervention, ModSecurity, Rules, Transaction};

use crate::handler::{self, ResponseBody};

const CONNECTOR_INFO: &str = "project-charlotte/0.1.0";

#[derive(Clone, Copy)]
pub(crate) struct Waf {
    modsecurity: &'static ModSecurity,
    rules: &'static Rules,
    request_body_limit: usize,
    response_body_limit: usize,
}

impl Waf {
    pub(crate) fn load(
        rule_files: &[PathBuf],
        request_body_limit: usize,
        response_body_limit: usize,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let mut modsecurity = ModSecurity::new()?;
        modsecurity.set_connector_info(CONNECTOR_INFO)?;
        modsecurity.set_log_callback(|message| {
            eprintln!("ModSecurity: {}", String::from_utf8_lossy(message));
        });

        let mut rules = Rules::new()?;
        for path in rule_files {
            rules.add_file(path)?;
        }

        Ok(Self {
            modsecurity: Box::leak(Box::new(modsecurity)),
            rules: Box::leak(Box::new(rules)),
            request_body_limit,
            response_body_limit,
        })
    }

    pub(crate) async fn inspect<B, F, Fut>(
        &self,
        request: Request<B>,
        peer: SocketAddr,
        local: SocketAddr,
        next: F,
    ) -> Response<ResponseBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
        F: FnOnce(Request<Full<Bytes>>) -> Fut,
        Fut: Future<Output = Response<ResponseBody>>,
    {
        let (parts, body) = request.into_parts();
        let request_version = parts.version;
        let mut transaction = match Transaction::new(self.modsecurity, self.rules) {
            Ok(transaction) => transaction,
            Err(error) => {
                eprintln!("ModSecurity transaction creation failed: {error}");
                return handler::error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Request inspection failed\n",
                );
            }
        };

        let phase_result = process_request_headers(&mut transaction, &parts, peer, local);
        let intervention = match phase_result {
            Ok(intervention) => intervention,
            Err(error) => {
                eprintln!("ModSecurity request-header inspection failed: {error}");
                return fail_closed(&mut transaction);
            }
        };
        if let Some(intervention) = intervention {
            return finish_intervention(&mut transaction, intervention).await;
        }

        let collected = match Limited::new(body, self.request_body_limit).collect().await {
            Ok(body) => body,
            Err(error) if error.is::<http_body_util::LengthLimitError>() => {
                if let Err(error) = finish_logging(&mut transaction) {
                    eprintln!("ModSecurity logging failed: {error}");
                    return handler::error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Request inspection failed\n",
                    );
                }
                return handler::error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request body too large\n",
                );
            }
            Err(error) => {
                eprintln!("Request body read failed during ModSecurity inspection: {error}");
                if let Err(error) = finish_logging(&mut transaction) {
                    eprintln!("ModSecurity logging failed: {error}");
                    return handler::error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Request inspection failed\n",
                    );
                }
                return handler::error_response(StatusCode::BAD_REQUEST, "Invalid request body\n");
            }
        };
        let request_body = collected.to_bytes();
        let body_intervention = (|| {
            if !request_body.is_empty()
                && let Some(intervention) = transaction.append_request_body(&request_body)?
            {
                return Ok(Some(intervention));
            }
            transaction.process_request_body()
        })();
        match body_intervention {
            Ok(Some(intervention)) => {
                return finish_intervention(&mut transaction, intervention).await;
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!("ModSecurity request-body inspection failed: {error}");
                return fail_closed(&mut transaction);
            }
        }

        let request = Request::from_parts(parts, Full::new(request_body));
        let response = next(request).await;
        self.inspect_response(response, transaction, request_version)
            .await
    }

    async fn inspect_response(
        &self,
        response: Response<ResponseBody>,
        mut transaction: Transaction<'static>,
        request_version: Version,
    ) -> Response<ResponseBody> {
        let response_headers = response.headers().iter().try_for_each(|(name, value)| {
            transaction.add_response_header(name.as_str().as_bytes(), value.as_bytes())
        });
        let phase_result = response_headers.and_then(|()| {
            transaction.process_response_headers(
                i32::from(response.status().as_u16()),
                response_protocol(request_version),
            )
        });
        match phase_result {
            Ok(Some(intervention)) => {
                return finish_intervention(&mut transaction, intervention).await;
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!("ModSecurity response-header inspection failed: {error}");
                return fail_closed(&mut transaction);
            }
        }

        let (parts, mut body) = response.into_parts();
        let mut buffered = VecDeque::new();
        let mut buffered_bytes = 0usize;
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        let available = self.response_body_limit.saturating_sub(buffered_bytes);
                        if data.len() > available {
                            if available > 0 {
                                let prefix = data.slice(..available);
                                match transaction.append_response_body(&prefix) {
                                    Ok(Some(intervention)) => {
                                        return finish_intervention(&mut transaction, intervention)
                                            .await;
                                    }
                                    Ok(None) => {}
                                    Err(error) => {
                                        eprintln!(
                                            "ModSecurity response-body inspection failed: {error}"
                                        );
                                        return fail_closed(&mut transaction);
                                    }
                                }
                                buffered.push_back(Frame::data(prefix));
                            }
                            let remainder = data.slice(available..);
                            return Response::from_parts(
                                parts,
                                streaming_response_body(
                                    transaction,
                                    buffered,
                                    Some(Frame::data(remainder)),
                                    body,
                                ),
                            );
                        }

                        match transaction.append_response_body(data) {
                            Ok(Some(intervention)) => {
                                return finish_intervention(&mut transaction, intervention).await;
                            }
                            Ok(None) => {}
                            Err(error) => {
                                eprintln!("ModSecurity response-body inspection failed: {error}");
                                return fail_closed(&mut transaction);
                            }
                        }
                        buffered_bytes += data.len();
                    }
                    buffered.push_back(frame);
                }
                Some(Err(error)) => {
                    eprintln!("Response body read failed during ModSecurity inspection: {error}");
                    return fail_closed(&mut transaction);
                }
                None => {
                    match transaction.process_response_body() {
                        Ok(Some(intervention)) => {
                            return finish_intervention(&mut transaction, intervention).await;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            eprintln!("ModSecurity response-body inspection failed: {error}");
                            return fail_closed(&mut transaction);
                        }
                    }
                    if let Err(error) = finish_logging(&mut transaction) {
                        eprintln!("ModSecurity logging failed: {error}");
                        return handler::error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Response inspection failed\n",
                        );
                    }
                    return Response::from_parts(parts, buffered_response_body(buffered));
                }
            }
        }
    }
}

fn process_request_headers(
    transaction: &mut Transaction<'static>,
    parts: &http::request::Parts,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<Option<Intervention>, Box<dyn Error + Send + Sync>> {
    if let Some(intervention) = transaction.process_connection(
        &peer.ip().to_string(),
        peer.port(),
        &local.ip().to_string(),
        local.port(),
    )? {
        return Ok(Some(intervention));
    }
    let uri = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path(), |value| value.as_str());
    if let Some(intervention) =
        transaction.process_uri(uri, parts.method.as_str(), request_protocol(parts.version))?
    {
        return Ok(Some(intervention));
    }

    let mut has_host = false;
    for (name, value) in &parts.headers {
        has_host |= name == HOST;
        transaction.add_request_header(name.as_str().as_bytes(), value.as_bytes())?;
    }
    if !has_host && let Some(authority) = parts.uri.authority() {
        transaction.add_request_header(HOST.as_str().as_bytes(), authority.as_str().as_bytes())?;
    }
    Ok(transaction.process_request_headers()?)
}

fn request_protocol(version: Version) -> &'static str {
    match version {
        Version::HTTP_10 => "1.0",
        Version::HTTP_2 => "2.0",
        Version::HTTP_3 => "3.0",
        _ => "1.1",
    }
}

fn response_protocol(version: Version) -> &'static str {
    match version {
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

async fn finish_intervention(
    transaction: &mut Transaction<'static>,
    intervention: Intervention,
) -> Response<ResponseBody> {
    eprintln!("ModSecurity intervention: {intervention}");
    pause_for_intervention(&intervention).await;
    if let Err(error) = finish_logging(transaction) {
        eprintln!("ModSecurity logging failed: {error}");
        return handler::error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Request inspection failed\n",
        );
    }

    let status = if intervention.url.is_some() {
        StatusCode::from_u16(intervention.status as u16)
            .ok()
            .filter(|status| (300..400).contains(&status.as_u16()))
            .unwrap_or(StatusCode::FOUND)
    } else {
        StatusCode::from_u16(intervention.status as u16)
            .ok()
            .filter(|status| (400..600).contains(&status.as_u16()))
            .unwrap_or(StatusCode::FORBIDDEN)
    };
    let mut response = handler::error_response(status, "Request blocked by ModSecurity\n");
    if let Some(url) = intervention.url {
        let Ok(value) = HeaderValue::from_str(&url) else {
            return handler::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Invalid ModSecurity redirect\n",
            );
        };
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

async fn pause_for_intervention(intervention: &Intervention) {
    if intervention.pause > 0 {
        tokio::time::sleep(Duration::from_millis(intervention.pause as u64)).await;
    }
}

fn fail_closed(transaction: &mut Transaction<'static>) -> Response<ResponseBody> {
    if let Err(error) = finish_logging(transaction) {
        eprintln!("ModSecurity logging failed: {error}");
    }
    handler::error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Request inspection failed\n",
    )
}

fn finish_logging(
    transaction: &mut Transaction<'static>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    transaction.process_logging()?;
    Ok(())
}

fn buffered_response_body(frames: VecDeque<Frame<Bytes>>) -> ResponseBody {
    let frames = frames.into_iter().map(Ok::<_, io::Error>);
    StreamBody::new(stream::iter(frames)).boxed_unsync()
}

fn streaming_response_body(
    transaction: Transaction<'static>,
    buffered: VecDeque<Frame<Bytes>>,
    first_tail: Option<Frame<Bytes>>,
    body: ResponseBody,
) -> ResponseBody {
    let state = StreamingBody {
        transaction: Some(transaction),
        buffered,
        first_tail,
        body,
        process_response_body: true,
    };
    let chunks = stream::unfold(state, |mut state| async move {
        if let Some(frame) = state.buffered.pop_front() {
            return Some((Ok(frame), state));
        }
        let frame = if let Some(frame) = state.first_tail.take() {
            Some(Ok(frame))
        } else {
            state.body.frame().await
        };
        match frame {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref()
                    && let Some(transaction) = state.transaction.as_mut()
                {
                    match transaction.append_response_body(data) {
                        Ok(Some(intervention)) => {
                            eprintln!("ModSecurity response-body intervention: {intervention}");
                            pause_for_intervention(&intervention).await;
                            let _ = state.finish();
                            return Some((
                                Err(io::Error::other("response blocked by ModSecurity")),
                                state,
                            ));
                        }
                        Ok(None) => {}
                        Err(error) => {
                            eprintln!("ModSecurity response-body inspection failed: {error}");
                            let _ = state.finish();
                            return Some((
                                Err(io::Error::other("response inspection failed")),
                                state,
                            ));
                        }
                    }
                }
                Some((Ok(frame), state))
            }
            Some(Err(error)) => {
                let _ = state.finish();
                Some((Err(error), state))
            }
            None => {
                if state.process_response_body
                    && let Some(transaction) = state.transaction.as_mut()
                {
                    match transaction.process_response_body() {
                        Ok(Some(intervention)) => {
                            eprintln!("ModSecurity response-body intervention: {intervention}");
                            pause_for_intervention(&intervention).await;
                            let _ = state.finish();
                            return Some((
                                Err(io::Error::other("response blocked by ModSecurity")),
                                state,
                            ));
                        }
                        Ok(None) => {}
                        Err(error) => {
                            eprintln!("ModSecurity response-body inspection failed: {error}");
                            let _ = state.finish();
                            return Some((
                                Err(io::Error::other("response inspection failed")),
                                state,
                            ));
                        }
                    }
                }
                if let Err(error) = state.finish() {
                    eprintln!("ModSecurity logging failed: {error}");
                    return Some((Err(io::Error::other("ModSecurity logging failed")), state));
                }
                None
            }
        }
    });
    StreamBody::new(chunks).boxed_unsync()
}

struct StreamingBody {
    transaction: Option<Transaction<'static>>,
    buffered: VecDeque<Frame<Bytes>>,
    first_tail: Option<Frame<Bytes>>,
    body: ResponseBody,
    process_response_body: bool,
}

impl StreamingBody {
    fn finish(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        if let Some(mut transaction) = self.transaction.take() {
            transaction.process_logging()?;
        }
        Ok(())
    }
}

impl Drop for StreamingBody {
    fn drop(&mut self) {
        if let Err(error) = self.finish() {
            eprintln!("ModSecurity logging failed after response stream closed: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, OnceLock};

    use http_body_util::BodyExt;

    use crate::{
        config::Config,
        fuzz_support::{self, FuzzRequest},
        vhost::Router,
    };

    use super::Waf;

    fn fuzz_waf() -> Waf {
        static WAF: OnceLock<Waf> = OnceLock::new();
        *WAF.get_or_init(|| {
            let fixture = fuzz_support::fixture();
            Waf::load(
                std::slice::from_ref(&fixture.rules),
                16 * 1024 * 1024,
                1024 * 1024,
            )
            .expect("fuzz ModSecurity rules load")
        })
    }

    #[test_fuzz::test_fuzz]
    fn waf_request(input: FuzzRequest) {
        let Some(request) = input.build() else {
            return;
        };
        let fixture = fuzz_support::fixture();
        let mut config: Config = fuzz_support::fuzz_config(fixture.root.clone());
        config.fastcgi.clear();
        let (peer, local) = fuzz_support::addresses();
        let response = fuzz_support::run(async {
            let router = Router::load(Arc::new(config), None, Some(fuzz_waf()))
                .await
                .expect("WAF router loads");
            router.dispatch(request, peer, local).await
        });
        assert!((100..=599).contains(&response.status().as_u16()));
        let body = fuzz_support::run(async { response.into_body().collect().await })
            .expect("WAF response body should be readable")
            .to_bytes();
        assert!(
            !body
                .windows(fixture.outside_secret.len())
                .any(|window| window == fixture.outside_secret)
        );
    }

    #[test]
    fn fuzz_seed_waf_request() {
        waf_request(FuzzRequest::default());
        waf_request(FuzzRequest {
            uri: "/response-secret.txt".to_owned(),
            ..FuzzRequest::default()
        });
        waf_request(FuzzRequest {
            uri: "/safe.txt?block=yes".to_owned(),
            ..FuzzRequest::default()
        });
    }
}
