//! Pooled HTTP/HTTPS upstream clients and reverse-proxy request/response handling.

use std::{
    error::Error,
    future::Future,
    io,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{self, HOST},
};
use http_body::Body;
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{Connected, Connection, HttpConnector},
    },
    rt::{TokioExecutor, TokioIo},
};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use tokio::net::TcpStream;
use tower_service::Service;

use crate::response::{self, ResponseBody};

type ProxyRequestBody = UnsyncBoxBody<Bytes, io::Error>;
type ProxyClient = Client<HttpsConnector<QuickAckConnector>, ProxyRequestBody>;

#[derive(Clone)]
struct QuickAckConnector {
    inner: HttpConnector,
}

struct QuickAckStream(TokioIo<TcpStream>);

impl Service<Uri> for QuickAckConnector {
    type Response = QuickAckStream;
    type Error = <HttpConnector as Service<Uri>>::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connecting = self.inner.call(uri);
        Box::pin(async move { connecting.await.map(QuickAckStream) })
    }
}

impl Connection for QuickAckStream {
    fn connected(&self) -> Connected {
        self.0.connected()
    }
}

impl Read for QuickAckStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.as_mut().get_mut();
        let result = Pin::new(&mut this.0).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            set_tcp_quickack(this.0.inner());
        }
        result
    }
}

impl Write for QuickAckStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.as_mut().get_mut().0).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.as_mut().get_mut().0).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.as_mut().get_mut().0).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.as_mut().get_mut().0).poll_write_vectored(context, buffers)
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn set_tcp_quickack(stream: &TcpStream) {
    use std::os::fd::AsRawFd;

    let enabled: nix::libc::c_int = 1;
    // SAFETY: the file descriptor is borrowed from a live TcpStream, and the
    // value pointer and length describe a valid c_int for the duration of the call.
    let result = unsafe {
        nix::libc::setsockopt(
            stream.as_raw_fd(),
            nix::libc::IPPROTO_TCP,
            nix::libc::TCP_QUICKACK,
            (&enabled as *const nix::libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as nix::libc::socklen_t,
        )
    };
    if result != 0 {
        crate::log_debug!(
            "could not enable TCP_QUICKACK on proxy upstream: {}",
            io::Error::last_os_error()
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn set_tcp_quickack(_stream: &TcpStream) {}

const HOP_BY_HOP_HEADERS: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

pub(crate) struct ReverseProxy {
    client: ProxyClient,
    scheme: String,
    authority: String,
    prefix: String,
    preserve_host: bool,
    timeout: Duration,
}

impl ReverseProxy {
    pub(crate) fn validate_upstream_url(
        upstream: &str,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        Self::upstream_parts(upstream).map(|_| ())
    }

    pub(crate) fn new(
        upstream: &str,
        preserve_host: bool,
        http2_only: bool,
        timeout: Duration,
        ca_root: Option<&Path>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let (scheme, authority, prefix) = Self::upstream_parts(upstream)?;

        let builder = if let Some(ca_root) = ca_root {
            let certs = CertificateDer::pem_file_iter(ca_root)?.collect::<Result<Vec<_>, _>>()?;
            if certs.is_empty() {
                return Err(format!(
                    "proxy CA root contains no certificates: {}",
                    ca_root.display()
                )
                .into());
            }
            let mut roots = rustls::RootCertStore::empty();
            for certificate in certs {
                roots.add(certificate)?;
            }
            let tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            HttpsConnectorBuilder::new().with_tls_config(tls)
        } else {
            HttpsConnectorBuilder::new().with_native_roots()?
        };
        let mut http_connector = HttpConnector::new();
        http_connector.enforce_http(false);
        http_connector.set_nodelay(true);
        let connector = builder
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(QuickAckConnector {
                inner: http_connector,
            });
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(64)
            .http2_only(http2_only)
            .build::<_, ProxyRequestBody>(connector);

        Ok(Self {
            client,
            scheme,
            authority,
            prefix,
            preserve_host,
            timeout,
        })
    }

    fn upstream_parts(
        upstream: &str,
    ) -> Result<(String, String, String), Box<dyn Error + Send + Sync>> {
        let uri = upstream.parse::<Uri>()?;
        let scheme = uri
            .scheme_str()
            .filter(|scheme| *scheme == "http" || *scheme == "https")
            .ok_or("proxy_pass must use the http or https scheme")?;
        let authority = uri
            .authority()
            .filter(|authority| !authority.host().is_empty() && !authority.as_str().contains('@'))
            .ok_or("proxy_pass must include a valid authority")?
            .as_str()
            .to_owned();
        if uri
            .path_and_query()
            .and_then(|path_and_query| path_and_query.query())
            .is_some()
        {
            return Err("proxy_pass must not include a query".into());
        }
        let prefix = uri.path().trim_end_matches('/').to_owned();
        Ok((scheme.to_owned(), authority, prefix))
    }

    pub(crate) async fn forward<B>(
        &self,
        mut request: Request<B>,
        peer: std::net::SocketAddr,
        tls: bool,
    ) -> Response<ResponseBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        if request.method() == Method::CONNECT || request.headers().contains_key(header::UPGRADE) {
            return response::error_response(
                StatusCode::NOT_IMPLEMENTED,
                "Proxying CONNECT and protocol upgrades is not supported\n",
            );
        }

        let original_host = request.headers().get(HOST).cloned().or_else(|| {
            request
                .uri()
                .authority()
                .and_then(|authority| HeaderValue::from_str(authority.as_str()).ok())
        });
        let path_and_query = request
            .uri()
            .path_and_query()
            .map_or("/", |path_and_query| path_and_query.as_str());
        let path_and_query = if path_and_query == "*" {
            "/"
        } else {
            path_and_query
        };
        if !path_and_query.starts_with('/') {
            return response::error_response(
                StatusCode::BAD_REQUEST,
                "Invalid proxy request URI\n",
            );
        }
        let target = format!("{}{}", self.prefix, path_and_query);
        let uri = match format!("{}://{}{}", self.scheme, self.authority, target).parse::<Uri>() {
            Ok(uri) => uri,
            Err(_) => {
                return response::error_response(
                    StatusCode::BAD_REQUEST,
                    "Invalid proxy request URI\n",
                );
            }
        };
        *request.uri_mut() = uri;
        *request.version_mut() = http::Version::HTTP_11;

        strip_hop_by_hop(request.headers_mut());
        let host = if self.preserve_host {
            original_host.clone()
        } else {
            HeaderValue::from_str(&self.authority).ok()
        };
        if let Some(host) = host {
            request.headers_mut().insert(HOST, host);
        }
        let forwarded_for = request
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
            .map_or_else(
                || peer.ip().to_string(),
                |value| format!("{value}, {}", peer.ip()),
            );
        if let Ok(value) = HeaderValue::from_str(&forwarded_for) {
            request.headers_mut().insert("x-forwarded-for", value);
        }
        request.headers_mut().insert(
            "x-forwarded-proto",
            HeaderValue::from_static(if tls { "https" } else { "http" }),
        );
        if let Some(host) = original_host {
            request.headers_mut().insert("x-forwarded-host", host);
        }

        let request = request.map(|body| {
            body.map_err(|error| io::Error::other(error.into()))
                .boxed_unsync()
        });
        match tokio::time::timeout(self.timeout, self.client.request(request)).await {
            Err(_) => response::error_response(StatusCode::GATEWAY_TIMEOUT, "Upstream timed out\n"),
            Ok(Err(error)) => {
                crate::log_error!("reverse proxy request failed: {error}");
                response::error_response(StatusCode::BAD_GATEWAY, "Upstream request failed\n")
            }
            Ok(Ok(mut response)) => {
                strip_hop_by_hop(response.headers_mut());
                let (parts, body) = response.into_parts();
                Response::from_parts(parts, body.map_err(io::Error::other).boxed_unsync())
            }
        }
    }
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let connection_headers = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| name.trim().parse::<HeaderName>().ok())
        .collect::<Vec<_>>();
    for name in HOP_BY_HOP_HEADERS {
        headers.remove(name);
    }
    for name in connection_headers {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::{ReverseProxy, strip_hop_by_hop};
    use http::{HeaderMap, HeaderValue};
    use std::time::Duration;

    #[test]
    fn validates_upstream_urls() {
        assert!(
            ReverseProxy::new(
                "ftp://example.test",
                true,
                false,
                Duration::from_secs(1),
                None
            )
            .is_err()
        );
        assert!(
            ReverseProxy::new(
                "http://example.test/path?query=1",
                true,
                false,
                Duration::from_secs(1),
                None
            )
            .is_err()
        );
        assert!(
            ReverseProxy::new(
                "http://user@example.test",
                true,
                false,
                Duration::from_secs(1),
                None
            )
            .is_err()
        );
    }

    #[test]
    fn strips_hop_by_hop_headers_and_connection_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "connection",
            HeaderValue::from_static("keep-alive, x-private"),
        );
        headers.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        headers.insert("x-private", HeaderValue::from_static("remove"));
        headers.insert("x-end-to-end", HeaderValue::from_static("keep"));

        strip_hop_by_hop(&mut headers);

        assert!(!headers.contains_key("connection"));
        assert!(!headers.contains_key("keep-alive"));
        assert!(!headers.contains_key("x-private"));
        assert_eq!(headers["x-end-to-end"], "keep");
    }

    #[test]
    fn joins_upstream_prefix_and_request_path() {
        let proxy = ReverseProxy::new(
            "http://upstream.test/base/",
            true,
            false,
            Duration::from_secs(1),
            None,
        )
        .unwrap();
        assert_eq!(proxy.prefix, "/base");
        assert_eq!(
            format!(
                "{}://{}{}{}",
                proxy.scheme, proxy.authority, proxy.prefix, "/item?q=1"
            ),
            "http://upstream.test/base/item?q=1"
        );
    }
}
