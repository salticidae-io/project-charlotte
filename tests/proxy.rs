#![forbid(unsafe_code)]
#![cfg(feature = "proxy")]

mod common;

use std::{
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

#[cfg(feature = "http3")]
use bytes::Buf;
use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
#[cfg(feature = "http3")]
use quinn::{Endpoint, VarInt};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fixture {
    root: PathBuf,
    http_address: SocketAddr,
    tls_address: SocketAddr,
    #[cfg(feature = "http3")]
    http3_address: SocketAddr,
    http3_only: bool,
    certificate: CertificateDer<'static>,
    server: Child,
    backend_tasks: Vec<JoinHandle<()>>,
    _serial_guard: tokio::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    async fn new() -> Self {
        Self::new_with_http3_only(false).await
    }

    #[cfg(feature = "http3")]
    async fn new_http3_only() -> Self {
        Self::new_with_http3_only(true).await
    }

    async fn new_with_http3_only(http3_only: bool) -> Self {
        let serial_guard = TEST_LOCK.lock().await;
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "project-charlotte-proxy-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();

        let generated = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "h2.example.test".to_owned(),
            "h3.example.test".to_owned(),
        ])
        .unwrap();
        let cert_path = root.join("server.pem");
        let key_path = root.join("server-key.pem");
        std::fs::write(&cert_path, generated.cert.pem()).unwrap();
        std::fs::write(&key_path, generated.signing_key.serialize_pem()).unwrap();
        let certificate = generated.cert.der().clone();
        let upstream_ca_path = root.join("upstream-ca.pem");
        std::fs::write(&upstream_ca_path, generated.cert.pem()).unwrap();

        let http_upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_upstream_address = http_upstream.local_addr().unwrap();
        let http_task = spawn_http_upstream(http_upstream);

        let tls_upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_upstream_address = tls_upstream.local_addr().unwrap();
        let tls_server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certificate.clone()],
                PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into()),
            )
            .unwrap();
        let mut tls_server_config = tls_server_config;
        tls_server_config.alpn_protocols = vec![b"h2".to_vec()];
        let tls_task = spawn_h2_upstream(tls_upstream, Arc::new(tls_server_config));

        let dead_address = common::reserve_tcp_address();

        let config_path = root.join("vhosts.yaml");
        std::fs::write(
            &config_path,
            format!(
                "vhost:\n  - server_names: [plain.example.test]\n    proxy_pass: \"http://{http_upstream_address}/base\"\n  - server_names: [h2.example.test]\n    proxy_pass: \"https://localhost:{}/secure\"\n    proxy_ca_root: upstream-ca.pem\n  - server_names: [h3.example.test]\n    proxy_pass: \"https://localhost:{}/secure\"\n    proxy_ca_root: upstream-ca.pem\n  - server_names: [upstream-host.example.test]\n    proxy_pass: \"http://{http_upstream_address}/override\"\n    proxy_preserve_host: false\n  - server_names: [timeout.example.test]\n    proxy_pass: \"http://{http_upstream_address}/base\"\n    proxy_timeout: 1\n  - server_names: [unreachable.example.test]\n    proxy_pass: \"http://{dead_address}\"\n",
                tls_upstream_address.port(),
                tls_upstream_address.port(),
            ),
        )
        .unwrap();

        let http_address = common::reserve_tcp_address();
        let tls_address = common::reserve_tcp_address();
        #[cfg(feature = "http3")]
        let http3_address = common::reserve_udp_address();

        let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
        command.arg("--bind").arg(http_address.to_string());
        if http3_only {
            command.arg("--no-plain-http");
        } else {
            command.arg("--tls-bind").arg(tls_address.to_string());
        }
        // A build without a feature refuses that feature's options.
        #[cfg(feature = "http3")]
        command.arg("--http3-bind").arg(http3_address.to_string());
        #[cfg(feature = "hosting")]
        command.arg("--root").arg(&root);
        command
            .arg("--config")
            .arg(&config_path)
            .arg("--tls-cert")
            .arg(&cert_path)
            .arg("--tls-key")
            .arg(&key_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let server = common::spawn(&mut command).unwrap();

        let mut fixture = Self {
            root,
            http_address,
            tls_address,
            #[cfg(feature = "http3")]
            http3_address,
            http3_only,
            certificate,
            server,
            backend_tasks: vec![http_task, tls_task],
            _serial_guard: serial_guard,
        };
        fixture.wait_until_ready().await;
        fixture
    }

    async fn wait_until_ready(&mut self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        #[cfg(feature = "http3")]
        let endpoint = self
            .http3_only
            .then(|| h3_client_endpoint(&self.certificate));
        loop {
            if let Some(status) = self.server.try_wait().unwrap() {
                panic!("Charlotte exited before becoming ready: {status}");
            }
            if self.http3_only {
                #[cfg(feature = "http3")]
                if let Some(endpoint) = &endpoint
                    && let Ok(Ok(connection)) = tokio::time::timeout(
                        Duration::from_millis(200),
                        endpoint
                            .connect(self.http3_address, "h3.example.test")
                            .unwrap(),
                    )
                    .await
                {
                    connection.close(VarInt::from_u32(0), b"ready");
                    return;
                }
            } else if TcpStream::connect(self.http_address).await.is_ok() {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                common::shutdown(&mut self.server);
                panic!("Charlotte did not become ready");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in self.backend_tasks.drain(..) {
            task.abort();
        }
        common::shutdown(&mut self.server);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[tokio::test]
async fn proxies_http1_http2_http3_and_handles_upstream_failures() {
    let fixture = Fixture::new().await;

    let response = http1_request(
        fixture.http_address,
        "POST",
        "/item?q=one",
        "plain.example.test",
        &[
            ("connection", "close, x-drop"),
            ("x-drop", "secret"),
            ("x-custom", "forwarded"),
        ],
        b"posted body",
    )
    .await;
    assert_eq!(response.status, 200);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains("method=POST"), "{body}");
    assert!(body.contains("path=/base/item?q=one"), "{body}");
    assert!(body.contains("host=plain.example.test"), "{body}");
    assert!(body.contains("proto=http"), "{body}");
    assert!(body.contains("xfh=plain.example.test"), "{body}");
    assert!(body.contains("xff=127.0.0.1"), "{body}");
    assert!(body.contains("x-custom=forwarded"), "{body}");
    assert!(body.contains("x-drop=<missing>"), "{body}");
    assert!(body.ends_with("body=posted body"), "{body}");
    assert!(!response.headers.contains_key("x-upstream-private"));

    let response = http1_request(
        fixture.http_address,
        "GET",
        "/slow",
        "timeout.example.test",
        &[],
        b"",
    )
    .await;
    assert_eq!(response.status, StatusCode::GATEWAY_TIMEOUT.as_u16());

    let response = http1_request(
        fixture.http_address,
        "GET",
        "/host",
        "upstream-host.example.test",
        &[],
        b"",
    )
    .await;
    assert_eq!(response.status, 200);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains("path=/override/host"), "{body}");
    assert!(body.contains("host=127.0.0.1:"), "{body}");
    assert!(body.contains("xfh=upstream-host.example.test"), "{body}");

    let response = h2_request(&fixture, "h2.example.test", "/item?q=two", b"h2 body").await;
    assert_eq!(response.status, 200);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains("path=/secure/item?q=two"), "{body}");
    assert!(body.contains("host=h2.example.test"), "{body}");
    assert!(body.contains("proto=https"), "{body}");
    assert!(body.ends_with("body=h2 body"), "{body}");

    #[cfg(feature = "http3")]
    {
        let response = h3_request(&fixture, "/item?q=three", b"h3 body").await;
        assert_eq!(response.status, 200);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains("path=/secure/item?q=three"), "{body}");
        assert!(body.contains("host=h3.example.test"), "{body}");
        assert!(body.contains("proto=https"), "{body}");
        assert!(body.ends_with("body=h3 body"), "{body}");
    }

    let response = http1_request(
        fixture.http_address,
        "GET",
        "/",
        "unreachable.example.test",
        &[],
        b"",
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_GATEWAY.as_u16());
}

#[cfg(feature = "http3")]
#[tokio::test]
async fn serves_http3_only_front_end() {
    let fixture = Fixture::new_http3_only().await;

    let response = h3_request(&fixture, "/only-h3", b"forwarded over QUIC").await;
    assert_eq!(response.status, 200);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains("path=/secure/only-h3"), "{body}");
    assert!(body.ends_with("body=forwarded over QUIC"), "{body}");

    assert!(TcpStream::connect(fixture.http_address).await.is_err());
    assert!(TcpStream::connect(fixture.tls_address).await.is_err());
}

#[tokio::test]
async fn rejects_startup_without_any_enabled_listener() {
    let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
    command
        .arg("--no-plain-http")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let output = common::output(&mut command).unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no listeners enabled"), "{stderr}");
}

fn spawn_http_upstream(listener: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = hyper::service::service_fn(echo_upstream);
                let builder = auto::Builder::new(TokioExecutor::new());
                let _ = builder
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    })
}

fn spawn_h2_upstream(listener: TcpListener, config: Arc<rustls::ServerConfig>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(config);
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let service = hyper::service::service_fn(echo_upstream);
                let builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                let _ = builder
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    })
}

async fn echo_upstream(request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = request.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    let value = |name: &str| {
        parts
            .headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("<missing>")
    };
    let response_body = format!(
        "method={}|path={}|host={}|xff={}|proto={}|xfh={}|x-custom={}|x-drop={}|body={}",
        parts.method,
        parts
            .uri
            .path_and_query()
            .map_or("/", |value| value.as_str()),
        value("host"),
        value("x-forwarded-for"),
        value("x-forwarded-proto"),
        value("x-forwarded-host"),
        value("x-custom"),
        value("x-drop"),
        String::from_utf8_lossy(&body),
    );
    if parts.uri.path().ends_with("/slow") {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let mut response = Response::new(Full::new(Bytes::from(response_body)));
    if parts.version == Version::HTTP_11 {
        response
            .headers_mut()
            .insert("connection", "x-upstream-private".parse().unwrap());
        response
            .headers_mut()
            .insert("x-upstream-private", "remove me".parse().unwrap());
    }
    Ok(response)
}

async fn http1_request(
    address: SocketAddr,
    method: &str,
    path: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    let mut stream = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(address))
        .await
        .unwrap()
        .unwrap();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n",
        body.len(),
    );
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("connection"))
    {
        request.push_str("Connection: close\r\n");
    }
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(8), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response has headers");
    let head = &response[..separator];
    let body = response[separator + 4..].to_vec();
    let head = String::from_utf8_lossy(head);
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut parsed_headers = HeaderMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            parsed_headers.insert(
                name.parse::<http::header::HeaderName>().unwrap(),
                value.trim().parse::<http::HeaderValue>().unwrap(),
            );
        }
    }
    HttpResponse {
        status,
        headers: parsed_headers,
        body,
    }
}

async fn h2_request(fixture: &Fixture, server_name: &str, path: &str, body: &[u8]) -> HttpResponse {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(fixture.certificate.clone()).unwrap();
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config));
    let stream = TcpStream::connect(fixture.tls_address).await.unwrap();
    let server_name_identity = ServerName::try_from(server_name.to_owned()).unwrap();
    let tls = connector
        .connect(server_name_identity, stream)
        .await
        .unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    let connection_task = tokio::spawn(connection);
    let request = Request::builder()
        .version(Version::HTTP_2)
        .method("POST")
        .uri(format!("https://{server_name}{path}"))
        .body(Full::new(Bytes::copy_from_slice(body)))
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    connection_task.abort();
    let _ = connection_task.await;
    HttpResponse {
        status,
        headers,
        body,
    }
}

#[cfg(feature = "http3")]
async fn h3_request(fixture: &Fixture, path: &str, body: &[u8]) -> HttpResponse {
    let endpoint = h3_client_endpoint(&fixture.certificate);
    let connection = tokio::time::timeout(
        Duration::from_secs(8),
        endpoint
            .connect(fixture.http3_address, "h3.example.test")
            .unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut driver, mut sender) = h3::client::builder()
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
        .await
        .unwrap();
    let driver_task = tokio::spawn(async move { driver.wait_idle().await });
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://h3.example.test{path}"))
        .body(())
        .unwrap();
    let mut request_stream = sender.send_request(request).await.unwrap();
    if !body.is_empty() {
        request_stream
            .send_data(Bytes::copy_from_slice(body))
            .await
            .unwrap();
    }
    request_stream.finish().await.unwrap();
    let response = request_stream.recv_response().await.unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let mut response_body = Vec::new();
    while let Some(mut chunk) = request_stream.recv_data().await.unwrap() {
        response_body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    drop(request_stream);
    drop(sender);
    endpoint.close(VarInt::from_u32(0), b"test complete");
    driver_task.abort();
    let _ = driver_task.await;
    HttpResponse {
        status,
        headers,
        body: response_body,
    }
}

#[cfg(feature = "http3")]
fn h3_client_endpoint(certificate: &CertificateDer<'static>) -> Endpoint {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.clone()).unwrap();
    let mut tls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap();
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    endpoint
}
