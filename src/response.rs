use std::{convert::Infallible, io, pin::Pin};

use bytes::{Bytes, BytesMut};
use chrono::Utc;
use futures_util::{FutureExt, StreamExt, stream};
use http::{HeaderValue, Response, StatusCode, header};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, BodyStream, Full, StreamBody, combinators::UnsyncBoxBody};

pub(crate) type ResponseBody = UnsyncBoxBody<Bytes, io::Error>;

#[cfg_attr(not(any(feature = "hosting", feature = "proxy")), allow(dead_code))]
const COALESCE_BODY_LIMIT: usize = 64 * 1024;

pub(crate) fn response(status: StatusCode, body: ResponseBody) -> Response<ResponseBody> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::SERVER,
        HeaderValue::from_static("project-charlotte"),
    );
    response
        .headers_mut()
        .insert(header::DATE, cached_date_header());
    response
}

fn cached_date_header() -> HeaderValue {
    thread_local! {
        static DATE_HEADER: std::cell::RefCell<Option<(i64, HeaderValue)>> = const { std::cell::RefCell::new(None) };
    }

    let now = Utc::now();
    let timestamp = now.timestamp();
    DATE_HEADER.with(|cached| {
        let mut cached = cached.borrow_mut();
        if let Some((cached_timestamp, value)) = cached.as_ref()
            && *cached_timestamp == timestamp
        {
            return value.clone();
        }
        let value = HeaderValue::from_str(&crate::httpdate::format_http_date(now))
            .expect("server generated a valid header value");
        *cached = Some((timestamp, value.clone()));
        value
    })
}

pub(crate) fn error_response(status: StatusCode, message: &'static str) -> Response<ResponseBody> {
    let bytes = Bytes::from_static(message.as_bytes());
    let length = bytes.len();
    let mut response = response(status, full_body(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    response
}

pub(crate) fn bot_response(parts: crate::bot::ResponseParts) -> Response<ResponseBody> {
    let bytes = Bytes::from(parts.body);
    let length = bytes.len();
    let mut response = response(parts.status, full_body(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(parts.content_type),
    );
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    if let Some(location) = parts.location
        && let Ok(value) = HeaderValue::from_str(&location)
    {
        response.headers_mut().insert(header::LOCATION, value);
    }
    if let Some(cookie) = parts.set_cookie
        && let Ok(value) = HeaderValue::from_str(&cookie)
    {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

#[cfg(feature = "acme")]
pub(crate) fn text_response(status: StatusCode, text: String) -> Response<ResponseBody> {
    let bytes = Bytes::from(text);
    let mut response = response(status, full_body(bytes));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

#[cfg(feature = "hosting")]
pub(crate) fn empty_body() -> ResponseBody {
    full_body(Bytes::new())
}

fn full_body(bytes: Bytes) -> ResponseBody {
    Full::new(bytes)
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

/// Gathers the frames of `body` that are already available into one, so that
/// a small response leaves in a single write. It never waits for a frame.
#[cfg_attr(not(any(feature = "hosting", feature = "proxy")), allow(dead_code))]
pub(crate) fn coalesce_ready_body(mut body: ResponseBody) -> ResponseBody {
    let mut first: Option<Bytes> = None;
    let mut buffered = BytesMut::new();
    let mut buffered_len = 0;
    let mut pending = None;
    let mut complete = false;

    loop {
        match std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).now_or_never() {
            None => break,
            Some(None) => {
                complete = true;
                break;
            }
            Some(Some(Ok(frame))) => match frame.into_data() {
                Ok(bytes) if bytes.is_empty() => {
                    pending = Some(Ok(Frame::data(bytes)));
                    break;
                }
                Ok(bytes) if buffered_len + bytes.len() <= COALESCE_BODY_LIMIT => {
                    buffered_len += bytes.len();
                    if buffered_len == bytes.len() {
                        first = Some(bytes);
                    } else {
                        if let Some(first) = first.take() {
                            buffered.extend_from_slice(&first);
                        }
                        buffered.extend_from_slice(&bytes);
                    }
                    if buffered_len == COALESCE_BODY_LIMIT {
                        break;
                    }
                }
                Ok(bytes) => {
                    pending = Some(Ok(Frame::data(bytes)));
                    break;
                }
                Err(frame) => {
                    pending = Some(Ok(frame));
                    break;
                }
            },
            Some(Some(Err(error))) => {
                pending = Some(Err(error));
                break;
            }
        }
    }

    let buffered = first.unwrap_or_else(|| buffered.freeze());
    if complete && pending.is_none() {
        return full_body(buffered);
    }

    let mut frames = Vec::with_capacity(2);
    if !buffered.is_empty() {
        frames.push(Ok(Frame::data(buffered)));
    }
    if let Some(frame) = pending {
        frames.push(frame);
    }
    StreamBody::new(stream::iter(frames).chain(BodyStream::new(body))).boxed_unsync()
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use http_body::{Body, Frame};
    use http_body_util::BodyExt;

    use super::{ResponseBody, coalesce_ready_body};

    struct PendingAfterPrefix(u8);

    impl Body for PendingAfterPrefix {
        type Data = Bytes;
        type Error = io::Error;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            match self.0 {
                0 => {
                    self.0 = 1;
                    Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"prefix")))))
                }
                1 => {
                    self.0 = 2;
                    Poll::Pending
                }
                2 => {
                    self.0 = 3;
                    Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"suffix")))))
                }
                _ => Poll::Ready(None),
            }
        }
    }

    #[tokio::test]
    async fn coalesces_ready_body_frames_into_one_exact_length_frame() {
        let body = http_body_util::StreamBody::new(futures_util::stream::iter([
            Ok::<_, io::Error>(Frame::data(Bytes::from_static(b"hello "))),
            Ok(Frame::data(Bytes::from_static(b"world"))),
        ]))
        .boxed_unsync();
        let mut body = coalesce_ready_body(body);

        assert_eq!(body.size_hint().exact(), Some(11));
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            Bytes::from_static(b"hello world")
        );
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn coalescing_pending_body_preserves_prefix_and_remaining_frames() {
        let body: ResponseBody = PendingAfterPrefix(0).boxed_unsync();
        let mut body = coalesce_ready_body(body);

        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            Bytes::from_static(b"prefix")
        );
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            Bytes::from_static(b"suffix")
        );
        assert!(body.frame().await.is_none());
    }
}
