//! Integration tests for HTTP/3 serving with TLS and backend request routing.

#![forbid(unsafe_code)]
#![cfg(all(feature = "hosting", feature = "http3"))]

mod common;

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use bytes::{Buf, Bytes};
use futures_util::future::join_all;
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use quinn::{Endpoint, VarInt};
use rustls::pki_types::CertificateDer;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::sleep,
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fixture {
    root: PathBuf,
    tcp_address: SocketAddr,
    http3_address: SocketAddr,
    certificate: CertificateDer<'static>,
    server: Child,
    backend_task: JoinHandle<()>,
    _serial_guard: tokio::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    async fn new() -> Self {
        Self::new_with_bot(false).await
    }

    async fn new_with_bot(bot_detection: bool) -> Self {
        let extra_args = if bot_detection {
            vec!["--bot-detection".to_owned()]
        } else {
            Vec::new()
        };
        Self::new_with_args(&extra_args).await
    }

    async fn new_with_args(extra_args: &[String]) -> Self {
        let serial_guard = TEST_LOCK.lock().await;
        let root = create_document_root();
        std::fs::write(root.join("index.html"), "http3 static response").unwrap();
        std::fs::write(root.join("script.php"), "not served as static text").unwrap();
        std::fs::write(root.join("rules.conf"), modsecurity_rules()).unwrap();
        std::fs::write(root.join("large.bin"), vec![b'x'; 1024 * 1024]).unwrap();

        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_path = root.join("server.pem");
        let key_path = root.join("server-key.pem");
        std::fs::write(&cert_path, generated.cert.pem()).unwrap();
        std::fs::write(&key_path, generated.signing_key.serialize_pem()).unwrap();
        let certificate = generated.cert.der().clone();

        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_address = backend_listener.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = backend_listener.accept().await {
                tokio::spawn(async move {
                    if let Err(error) = serve_fastcgi_request(&mut stream).await {
                        eprintln!("mock FastCGI backend failed: {error}");
                    }
                });
            }
        });

        let tcp_address = common::reserve_tcp_address();
        let http3_address = common::reserve_udp_address();

        let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
        command
            .arg("--bind")
            .arg(tcp_address.to_string())
            .arg("--http3-bind")
            .arg(http3_address.to_string())
            .arg("--root")
            .arg(&root)
            .arg("--tls-cert")
            .arg(cert_path)
            .arg("--tls-key")
            .arg(key_path)
            .arg("--fastcgi")
            .arg(format!("php={backend_address}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for argument in extra_args {
            command.arg(argument.replace("$ROOT", root.to_string_lossy().as_ref()));
        }
        let server = common::spawn(&mut command).unwrap();

        let mut fixture = Self {
            root,
            tcp_address,
            http3_address,
            certificate,
            server,
            backend_task,
            _serial_guard: serial_guard,
        };
        fixture.wait_until_ready().await;
        fixture
    }

    async fn wait_until_ready(&mut self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if TcpStream::connect(self.tcp_address).await.is_ok() {
                return;
            }
            if let Some(status) = self.server.try_wait().unwrap() {
                panic!("webserver exited before becoming ready: {status}");
            }
            if tokio::time::Instant::now() >= deadline {
                common::shutdown(&mut self.server);
                panic!("webserver did not become ready");
            }
            sleep(Duration::from_millis(20)).await;
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.backend_task.abort();
        common::shutdown(&mut self.server);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn create_document_root() -> PathBuf {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "project-charlotte-http3-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

struct H3Response {
    status: u16,
    version: http::Version,
    headers: http::HeaderMap,
    body: Vec<u8>,
    body_chunks: usize,
}

type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

struct H3Client {
    endpoint: Endpoint,
    send_request: H3SendRequest,
    driver_task: JoinHandle<()>,
}

impl Drop for H3Client {
    fn drop(&mut self) {
        self.endpoint.close(VarInt::from_u32(0), b"test complete");
        self.driver_task.abort();
    }
}

async fn request(
    address: SocketAddr,
    certificate: &CertificateDer<'static>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> H3Response {
    let body_chunks = if body.is_empty() {
        Vec::new()
    } else {
        vec![Bytes::copy_from_slice(body)]
    };
    request_with_chunks(address, certificate, method, path, headers, &body_chunks).await
}

async fn request_with_chunks(
    address: SocketAddr,
    certificate: &CertificateDer<'static>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body_chunks: &[Bytes],
) -> H3Response {
    let mut client = connect(address, certificate).await;
    request_on_connection(&mut client, method, path, headers, body_chunks).await
}

async fn connect(address: SocketAddr, certificate: &CertificateDer<'static>) -> H3Client {
    let endpoint = client_endpoint(certificate);
    let connection = tokio::time::timeout(
        Duration::from_secs(8),
        endpoint.connect(address, "localhost").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let (mut driver, send_request) = h3::client::builder()
        .build(h3_quinn::Connection::new(connection))
        .await
        .unwrap();
    let driver_task = tokio::spawn(async move {
        let _ = driver.wait_idle().await;
    });
    H3Client {
        endpoint,
        send_request,
        driver_task,
    }
}

async fn request_on_connection(
    client: &mut H3Client,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body_chunks: &[Bytes],
) -> H3Response {
    let mut request = http::Request::builder()
        .method(method)
        .uri(format!("https://localhost{path}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request.body(()).unwrap();
    let mut request_stream = client.send_request.send_request(request).await.unwrap();
    for chunk in body_chunks {
        request_stream.send_data(chunk.clone()).await.unwrap();
    }
    request_stream.finish().await.unwrap();
    let response = request_stream.recv_response().await.unwrap();
    let status = response.status().as_u16();
    let version = response.version();
    let headers = response.headers().clone();
    let mut response_body = Vec::new();
    let mut body_chunks = 0;
    while let Some(mut chunk) = request_stream.recv_data().await.unwrap() {
        body_chunks += 1;
        response_body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }

    H3Response {
        status,
        version,
        headers,
        body: response_body,
        body_chunks,
    }
}

fn modsecurity_rules() -> &'static str {
    r#"SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule ARGS:q "@streq block" "id:100001,phase:1,deny,status:403,log"
"#
}

fn client_endpoint(certificate: &CertificateDer<'static>) -> Endpoint {
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

async fn serve_fastcgi_request(stream: &mut TcpStream) -> io::Result<()> {
    let (params, stdin) = read_fastcgi_request(stream).await?;
    let output = format!(
        "{}|{}|{}|{}|{}|{}",
        parameter(&params, "SERVER_PROTOCOL"),
        parameter(&params, "REQUEST_METHOD"),
        parameter(&params, "QUERY_STRING"),
        parameter(&params, "CONTENT_TYPE"),
        parameter(&params, "CONTENT_LENGTH"),
        String::from_utf8_lossy(&stdin),
    );
    let mut response = b"Content-Type: text/plain\r\n\r\n".to_vec();
    response.extend_from_slice(output.as_bytes());
    for chunk in response.chunks(usize::from(u16::MAX)) {
        write_fastcgi_record(stream, 6, 1, chunk).await?;
    }
    write_fastcgi_record(stream, 6, 1, &[]).await?;
    write_fastcgi_record(stream, 3, 1, &[0; 8]).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_fastcgi_request(
    stream: &mut TcpStream,
) -> io::Result<(HashMap<String, String>, Vec<u8>)> {
    let mut encoded_params = Vec::new();
    let mut params_done = false;
    let mut stdin = Vec::new();
    loop {
        let mut header = [0; 8];
        stream.read_exact(&mut header).await?;
        if header[0] != 1 || u16::from_be_bytes([header[2], header[3]]) != 1 {
            return Err(io::Error::other("unexpected FastCGI record header"));
        }
        let record_type = header[1];
        let content_length = usize::from(u16::from_be_bytes([header[4], header[5]]));
        let padding_length = usize::from(header[6]);
        let mut content = vec![0; content_length];
        stream.read_exact(&mut content).await?;
        if padding_length > 0 {
            let mut padding = vec![0; padding_length];
            stream.read_exact(&mut padding).await?;
        }
        match record_type {
            4 if content.is_empty() => params_done = true,
            4 => encoded_params.extend_from_slice(&content),
            5 if content.is_empty() && params_done => break,
            5 => stdin.extend_from_slice(&content),
            _ => {}
        }
    }
    Ok((decode_params(&encoded_params)?, stdin))
}

fn decode_params(mut input: &[u8]) -> io::Result<HashMap<String, String>> {
    let mut params = HashMap::new();
    while !input.is_empty() {
        let name_length = decode_length(&mut input)?;
        let value_length = decode_length(&mut input)?;
        if input.len() < name_length + value_length {
            return Err(io::Error::other("truncated FastCGI parameters"));
        }
        let name = String::from_utf8(input[..name_length].to_vec())
            .map_err(|error| io::Error::other(error.to_string()))?;
        let value = String::from_utf8(input[name_length..name_length + value_length].to_vec())
            .map_err(|error| io::Error::other(error.to_string()))?;
        input = &input[name_length + value_length..];
        params.insert(name, value);
    }
    Ok(params)
}

fn decode_length(input: &mut &[u8]) -> io::Result<usize> {
    let Some((&first, remaining)) = input.split_first() else {
        return Err(io::Error::other("truncated FastCGI parameter length"));
    };
    *input = remaining;
    if first & 0x80 == 0 {
        return Ok(usize::from(first));
    }
    if input.len() < 3 {
        return Err(io::Error::other("truncated FastCGI parameter length"));
    }
    let length = u32::from_be_bytes([first, input[0], input[1], input[2]]) & 0x7fff_ffff;
    *input = &input[3..];
    usize::try_from(length).map_err(|error| io::Error::other(error.to_string()))
}

async fn write_fastcgi_record(
    stream: &mut TcpStream,
    record_type: u8,
    request_id: u16,
    content: &[u8],
) -> io::Result<()> {
    let length =
        u16::try_from(content.len()).map_err(|error| io::Error::other(error.to_string()))?;
    let mut header = [0; 8];
    header[0] = 1;
    header[1] = record_type;
    header[2..4].copy_from_slice(&request_id.to_be_bytes());
    header[4..6].copy_from_slice(&length.to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(content).await
}

fn parameter<'a>(params: &'a HashMap<String, String>, name: &str) -> &'a str {
    params.get(name).map(String::as_str).unwrap_or("<missing>")
}

#[tokio::test]
async fn http3_serves_static_responses_and_preserves_http_version() {
    let fixture = Fixture::new().await;

    let response = request(
        fixture.http3_address,
        &fixture.certificate,
        "GET",
        "/index.html",
        &[],
        b"",
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.version, http::Version::HTTP_3);
    assert_eq!(response.body, b"http3 static response");
    assert!(response.headers.contains_key(http::header::CONTENT_TYPE));

    let not_found = request(
        fixture.http3_address,
        &fixture.certificate,
        "GET",
        "/missing",
        &[],
        b"",
    )
    .await;
    assert_eq!(not_found.status, 404);

    let head = request(
        fixture.http3_address,
        &fixture.certificate,
        "HEAD",
        "/index.html",
        &[],
        b"",
    )
    .await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());

    let rejected = request(
        fixture.http3_address,
        &fixture.certificate,
        "POST",
        "/index.html",
        &[],
        b"not allowed",
    )
    .await;
    assert_eq!(rejected.status, 405);
}

#[tokio::test]
async fn http3_forwards_fastcgi_protocol_and_request_body() {
    let fixture = Fixture::new().await;
    let response = request(
        fixture.http3_address,
        &fixture.certificate,
        "POST",
        "/script.php?item=one",
        &[("Content-Type", "text/plain")],
        b"payload",
    )
    .await;

    assert_eq!(response.status, 200);
    assert_eq!(
        response.body,
        b"HTTP/3.0|POST|item=one|text/plain|7|payload"
    );
}

#[tokio::test]
async fn http3_applies_bot_detection_to_requests() {
    let fixture = Fixture::new_with_bot(true).await;
    let response = request(
        fixture.http3_address,
        &fixture.certificate,
        "GET",
        "/index.html",
        &[("user-agent", "nuclei/3.0")],
        b"",
    )
    .await;

    assert_eq!(response.status, 403);
}

#[tokio::test]
async fn tcp_responses_advertise_http3() {
    let fixture = Fixture::new().await;
    let mut stream = TcpStream::connect(fixture.tcp_address).await.unwrap();
    stream
        .write_all(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response).to_ascii_lowercase();
    assert!(response.contains(&format!(
        "alt-svc: h3=\":{}\"",
        fixture.http3_address.port()
    )));
    assert!(response.contains("http3 static response"));
}

#[tokio::test]
async fn http3_multiplexes_concurrent_requests_on_one_connection() {
    let fixture = Fixture::new().await;
    let request_count = 8;
    for index in 0..request_count {
        std::fs::write(
            fixture.root.join(format!("response-{index}.txt")),
            format!("body-{index}"),
        )
        .unwrap();
    }

    let mut client = connect(fixture.http3_address, &fixture.certificate).await;
    let mut streams = Vec::with_capacity(request_count);
    for index in 0..request_count {
        let request = http::Request::builder()
            .method("GET")
            .uri(format!("https://localhost/response-{index}.txt"))
            .body(())
            .unwrap();
        let mut stream = client.send_request.send_request(request).await.unwrap();
        stream.finish().await.unwrap();
        streams.push(stream);
    }

    let responses = join_all(streams.into_iter().map(|mut stream| async move {
        let response = stream.recv_response().await.unwrap();
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        (response.status().as_u16(), body)
    }))
    .await;

    for (index, (status, body)) in responses.into_iter().enumerate() {
        assert_eq!(status, 200);
        assert_eq!(body, format!("body-{index}").as_bytes());
    }
}

#[tokio::test]
async fn http3_transfers_large_static_response_across_data_frames() {
    let fixture = Fixture::new().await;

    let response = request(
        fixture.http3_address,
        &fixture.certificate,
        "GET",
        "/large.bin",
        &[],
        b"",
    )
    .await;

    assert_eq!(response.status, 200);
    assert_eq!(response.body.len(), 1024 * 1024);
    assert!(response.body.iter().all(|byte| *byte == b'x'));
    assert!(
        response.body_chunks > 1,
        "response was sent in one DATA chunk"
    );
}

#[tokio::test]
async fn http3_streams_large_request_body_to_fastcgi_in_chunks() {
    let fixture = Fixture::new().await;
    let body = vec![b'x'; 200 * 1024];
    let chunks = body
        .chunks(16 * 1024)
        .map(Bytes::copy_from_slice)
        .collect::<Vec<_>>();

    let response = request_with_chunks(
        fixture.http3_address,
        &fixture.certificate,
        "POST",
        "/script.php",
        &[("Content-Type", "application/octet-stream")],
        &chunks,
    )
    .await;

    let prefix = format!("HTTP/3.0|POST||application/octet-stream|{}|", body.len());
    assert_eq!(response.status, 200);
    assert!(response.body.starts_with(prefix.as_bytes()));
    assert_eq!(&response.body[prefix.len()..], body.as_slice());
}

#[tokio::test]
async fn http3_handles_request_stream_reset_without_losing_server() {
    let fixture = Fixture::new().await;
    let mut client = connect(fixture.http3_address, &fixture.certificate).await;
    let request_message = http::Request::builder()
        .method("POST")
        .uri("https://localhost/script.php")
        .body(())
        .unwrap();
    let mut stream = client
        .send_request
        .send_request(request_message)
        .await
        .unwrap();
    stream
        .send_data(Bytes::from_static(b"partial request body"))
        .await
        .unwrap();
    drop(stream);
    drop(client);

    let response = request(
        fixture.http3_address,
        &fixture.certificate,
        "GET",
        "/index.html",
        &[],
        b"",
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"http3 static response");
}

#[tokio::test]
async fn http3_applies_modsecurity_rules() {
    let extra_args = vec![
        "--modsecurity-rules".to_owned(),
        "$ROOT/rules.conf".to_owned(),
    ];
    let fixture = Fixture::new_with_args(&extra_args).await;

    let blocked = request(
        fixture.http3_address,
        &fixture.certificate,
        "GET",
        "/index.html?q=block",
        &[],
        b"",
    )
    .await;
    let clean = request(
        fixture.http3_address,
        &fixture.certificate,
        "GET",
        "/index.html",
        &[],
        b"",
    )
    .await;

    assert_eq!(blocked.status, 403);
    assert_eq!(clean.status, 200);
}

#[tokio::test]
async fn http3_enforces_rate_limit_and_returns_retry_after() {
    let extra_args = vec![
        "--rate-limit".to_owned(),
        "1/m".to_owned(),
        "--rate-limit-burst".to_owned(),
        "1".to_owned(),
    ];
    let fixture = Fixture::new_with_args(&extra_args).await;

    let first = request(
        fixture.http3_address,
        &fixture.certificate,
        "GET",
        "/index.html",
        &[],
        b"",
    )
    .await;
    let limited = request(
        fixture.http3_address,
        &fixture.certificate,
        "GET",
        "/index.html",
        &[],
        b"",
    )
    .await;

    assert_eq!(first.status, 200);
    assert_eq!(limited.status, 429);
    assert_eq!(limited.headers.get("retry-after").unwrap(), "60");
}

#[tokio::test]
async fn http3_writes_access_log_entries() {
    let extra_args = vec![
        "--access-log-file".to_owned(),
        "$ROOT/access.log".to_owned(),
        "--access-log-format".to_owned(),
        "%H %m %U %>s".to_owned(),
    ];
    let fixture = Fixture::new_with_args(&extra_args).await;
    let response = request(
        fixture.http3_address,
        &fixture.certificate,
        "GET",
        "/index.html",
        &[],
        b"",
    )
    .await;
    assert_eq!(response.status, 200);

    let log_path = fixture.root.join("access.log");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
        if contents.contains("HTTP/3.0 GET /index.html 200") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "access log did not contain the HTTP/3 request: {contents:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn http3_listener_shuts_down_cleanly_on_sigterm() {
    let mut fixture = Fixture::new().await;
    let response = request(
        fixture.http3_address,
        &fixture.certificate,
        "GET",
        "/index.html",
        &[],
        b"",
    )
    .await;
    assert_eq!(response.status, 200);

    let pid = i32::try_from(fixture.server.id()).unwrap();
    kill(Pid::from_raw(pid), Signal::SIGTERM).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = fixture.server.try_wait().unwrap() {
            assert!(status.success(), "server exited unsuccessfully: {status}");
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "server did not stop after SIGTERM"
        );
        sleep(Duration::from_millis(20)).await;
    }
}
