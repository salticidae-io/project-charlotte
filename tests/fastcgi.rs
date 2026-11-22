//! Integration tests for FastCGI backends over TCP and Unix sockets.

#![forbid(unsafe_code)]
#![cfg(feature = "hosting")]

mod common;

use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::sleep,
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static BACKEND_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fixture {
    root: PathBuf,
    server_address: std::net::SocketAddr,
    server: Child,
    backend_task: Option<JoinHandle<()>>,
    _serial_guard: tokio::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    async fn tcp(timeout_seconds: u64, start_backend: bool) -> Self {
        Self::tcp_with_args(timeout_seconds, start_backend, &[]).await
    }

    async fn tcp_with_args(timeout_seconds: u64, start_backend: bool, extra: &[&str]) -> Self {
        let serial_guard = TEST_LOCK.lock().await;
        let root = create_document_root();
        create_documents(&root);

        let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_address = backend_listener.local_addr().unwrap();
        let backend_task = if start_backend {
            Some(tokio::spawn(async move {
                while let Ok((mut stream, _)) = backend_listener.accept().await {
                    BACKEND_CONNECTIONS.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        serve_mock_connection(&mut stream).await;
                    });
                }
            }))
        } else {
            drop(backend_listener);
            None
        };

        let (server, server_address) = start_server(
            &root,
            &format!("127.0.0.1:{}", backend_address.port()),
            timeout_seconds,
            extra,
        )
        .await;

        Self {
            root,
            server_address,
            server,
            backend_task,
            _serial_guard: serial_guard,
        }
    }

    #[cfg(unix)]
    async fn unix(timeout_seconds: u64) -> Self {
        use tokio::net::UnixListener;

        let serial_guard = TEST_LOCK.lock().await;
        let root = create_document_root();
        create_documents(&root);
        let socket_path = root.join("backend.sock");
        let backend_listener = UnixListener::bind(&socket_path).unwrap();
        let backend_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = backend_listener.accept().await {
                tokio::spawn(async move {
                    serve_mock_connection(&mut stream).await;
                });
            }
        });
        let backend_address = format!("unix:{}", socket_path.display());
        let (server, server_address) =
            start_server(&root, &backend_address, timeout_seconds, &[]).await;

        Self {
            root,
            server_address,
            server,
            backend_task: Some(backend_task),
            _serial_guard: serial_guard,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(task) = self.backend_task.take() {
            task.abort();
        }
        let _ = self.server.kill();
        let _ = self.server.wait();
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn create_document_root() -> PathBuf {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "project-charlotte-fastcgi-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn create_documents(root: &std::path::Path) {
    std::fs::write(root.join("script.php"), "not executed by the test server").unwrap();
    std::fs::create_dir(root.join("folder")).unwrap();
    std::fs::write(
        root.join("folder/index.php"),
        "not executed by the test server",
    )
    .unwrap();
    std::fs::write(root.join("static.txt"), "static response").unwrap();
}

async fn start_server(
    root: &std::path::Path,
    backend_address: &str,
    timeout_seconds: u64,
    extra: &[&str],
) -> (Child, std::net::SocketAddr) {
    let server_address = common::reserve_tcp_address();

    let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
    command
        .arg("--bind")
        .arg(server_address.to_string())
        .arg("--root")
        .arg(root)
        .arg("--index")
        .arg("index.php")
        .arg("--fastcgi")
        .arg(format!("php={backend_address}"))
        .arg("--fastcgi-timeout")
        .arg(timeout_seconds.to_string())
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = common::spawn(&mut command).unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(server_address).await.is_ok() {
            return (child, server_address);
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("webserver exited before becoming ready: {status}");
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("webserver did not become ready");
        }
        sleep(Duration::from_millis(20)).await;
    }
}

struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> HttpResponse {
    let mut stream = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(address))
        .await
        .unwrap()
        .unwrap();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(8), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> HttpResponse {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or_else(|| {
            panic!(
                "HTTP response headers missing: {:?}",
                String::from_utf8_lossy(response)
            )
        });
    let header_text = std::str::from_utf8(&response[..header_end]).unwrap();
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
    }

    let body = &response[header_end + 4..];
    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        decode_chunked_body(body)
    } else {
        body.to_vec()
    };
    HttpResponse {
        status,
        headers,
        body,
    }
}

fn decode_chunked_body(mut input: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size should be terminated");
        let size = std::str::from_utf8(&input[..line_end])
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let size = usize::from_str_radix(size, 16).unwrap();
        input = &input[line_end + 2..];
        if size == 0 {
            break;
        }
        assert!(input.len() >= size + 2);
        body.extend_from_slice(&input[..size]);
        assert_eq!(&input[size..size + 2], b"\r\n");
        input = &input[size + 2..];
    }
    body
}

/// Serves requests on one backend connection. Like php-fpm, it keeps the
/// connection open for another request only when FCGI_KEEP_CONN was set.
async fn serve_mock_connection<S>(stream: &mut S)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let Ok((params, stdin, keep_conn)) = read_fastcgi_request(stream).await else {
            return;
        };
        let close = params
            .get("QUERY_STRING")
            .is_some_and(|query| query.contains("mode=close"));
        serve_mock_request(stream, params, stdin).await;
        if close {
            return;
        }
        if !keep_conn {
            let mut remaining = Vec::new();
            let _ = stream.read_to_end(&mut remaining).await;
            return;
        }
    }
}

async fn serve_mock_request<S>(stream: &mut S, params: HashMap<String, String>, stdin: Vec<u8>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let query = params.get("QUERY_STRING").map(String::as_str).unwrap_or("");
    if query.contains("mode=slow") {
        sleep(Duration::from_secs(3)).await;
    }
    let (headers, body) = if query.contains("mode=status") {
        (
            "Status: 201 Created\r\nContent-Type: text/plain\r\n",
            b"created".to_vec(),
        )
    } else if query.contains("mode=location") {
        (
            "Location: /redirected\r\nContent-Type: text/plain\r\n",
            b"redirect".to_vec(),
        )
    } else if query.contains("mode=malformed") {
        ("not-a-header\r\n", Vec::new())
    } else {
        let body = format!(
            "method={}\nquery={}\nscript_name={}\npath_info={}\nprotocol={}\ncustom={}\nproxy={}\ncontent_length={}\ncontent_type={}\nbody={}",
            parameter(&params, "REQUEST_METHOD"),
            parameter(&params, "QUERY_STRING"),
            parameter(&params, "SCRIPT_NAME"),
            parameter(&params, "PATH_INFO"),
            parameter(&params, "SERVER_PROTOCOL"),
            parameter(&params, "HTTP_X_CHECK"),
            parameter(&params, "HTTP_PROXY"),
            parameter(&params, "CONTENT_LENGTH"),
            parameter(&params, "CONTENT_TYPE"),
            String::from_utf8_lossy(&stdin),
        );
        ("Content-Type: text/plain\r\n", body.into_bytes())
    };

    let mut output = headers.as_bytes().to_vec();
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(&body);
    write_fastcgi_record(stream, 6, 1, &output).await.unwrap();
    write_fastcgi_record(stream, 6, 1, &[]).await.unwrap();
    write_fastcgi_record(stream, 3, 1, &[0; 8]).await.unwrap();
    let _ = stream.flush().await;
}

fn parameter<'a>(params: &'a HashMap<String, String>, name: &str) -> &'a str {
    params.get(name).map(String::as_str).unwrap_or("<missing>")
}

async fn read_fastcgi_request<S>(
    stream: &mut S,
) -> io::Result<(HashMap<String, String>, Vec<u8>, bool)>
where
    S: AsyncRead + Unpin,
{
    let mut keep_conn = false;
    let mut encoded_params = Vec::new();
    let mut params_done = false;
    let mut stdin = Vec::new();
    loop {
        let mut header = [0; 8];
        stream.read_exact(&mut header).await?;
        assert_eq!(header[0], 1, "unexpected FastCGI protocol version");
        let record_type = header[1];
        let request_id = u16::from_be_bytes([header[2], header[3]]);
        assert_eq!(request_id, 1, "unexpected FastCGI request id");
        let content_length = usize::from(u16::from_be_bytes([header[4], header[5]]));
        let padding_length = usize::from(header[6]);
        let mut content = vec![0; content_length];
        stream.read_exact(&mut content).await?;
        if padding_length > 0 {
            let mut padding = vec![0; padding_length];
            stream.read_exact(&mut padding).await?;
        }
        match record_type {
            1 => keep_conn = content.get(2).is_some_and(|flags| flags & 1 != 0),
            4 if content.is_empty() => params_done = true,
            4 => encoded_params.extend_from_slice(&content),
            5 if content.is_empty() && params_done => break,
            5 => stdin.extend_from_slice(&content),
            _ => {}
        }
    }
    Ok((decode_params(&encoded_params), stdin, keep_conn))
}

fn decode_params(mut input: &[u8]) -> HashMap<String, String> {
    let mut params = HashMap::new();
    while !input.is_empty() {
        let name_length = decode_length(&mut input);
        let value_length = decode_length(&mut input);
        assert!(input.len() >= name_length + value_length);
        let name = String::from_utf8(input[..name_length].to_vec()).unwrap();
        let value =
            String::from_utf8(input[name_length..name_length + value_length].to_vec()).unwrap();
        input = &input[name_length + value_length..];
        params.insert(name, value);
    }
    params
}

fn decode_length(input: &mut &[u8]) -> usize {
    let first = input[0];
    *input = &input[1..];
    if first & 0x80 == 0 {
        usize::from(first)
    } else {
        assert!(input.len() >= 3);
        let length = u32::from_be_bytes([first, input[0], input[1], input[2]]) & 0x7fff_ffff;
        *input = &input[3..];
        usize::try_from(length).unwrap()
    }
}

async fn write_fastcgi_record<S>(
    stream: &mut S,
    record_type: u8,
    request_id: u16,
    content: &[u8],
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let length = u16::try_from(content.len()).unwrap();
    let mut header = [0; 8];
    header[0] = 1;
    header[1] = record_type;
    header[2..4].copy_from_slice(&request_id.to_be_bytes());
    header[4..6].copy_from_slice(&length.to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(content).await
}

#[tokio::test]
async fn get_forwards_cgi_parameters_and_excludes_proxy_header() {
    let fixture = Fixture::tcp(2, true).await;
    let response = request(
        fixture.server_address,
        "GET",
        "/script.php?value=world",
        &[("X-Check", "hello"), ("Proxy", "httpoxy-value")],
        b"",
    )
    .await;
    let body = String::from_utf8(response.body).unwrap();

    assert_eq!(response.status, 200);
    assert!(body.contains("method=GET\n"));
    assert!(body.contains("query=value=world\n"));
    assert!(body.contains("script_name=/script.php\n"));
    assert!(body.contains("protocol=HTTP/1.1\n"));
    assert!(body.contains("custom=hello\n"));
    assert!(body.contains("proxy=<missing>\n"));
}

#[tokio::test]
async fn post_forwards_body_content_type_and_length() {
    let fixture = Fixture::tcp(2, true).await;
    let response = request(
        fixture.server_address,
        "POST",
        "/script.php",
        &[("Content-Type", "text/plain"), ("X-Check", "posted")],
        b"payload",
    )
    .await;
    let body = String::from_utf8(response.body).unwrap();

    assert_eq!(response.status, 200);
    assert!(body.contains("method=POST\n"));
    assert!(body.contains("custom=posted\n"));
    assert!(body.contains("content_length=7\n"));
    assert!(body.contains("content_type=text/plain\n"));
    assert!(body.ends_with("body=payload"));
}

#[tokio::test]
async fn path_info_is_split_from_script_name() {
    let fixture = Fixture::tcp(2, true).await;
    let response = request(
        fixture.server_address,
        "GET",
        "/script.php/extra/path",
        &[],
        b"",
    )
    .await;

    assert_eq!(response.status, 200);
    let body = String::from_utf8(response.body).unwrap();
    assert!(body.contains("script_name=/script.php\n"));
    assert!(body.contains("path_info=/extra/path\n"));
}

#[tokio::test]
async fn status_location_and_head_behaviors_are_preserved() {
    let fixture = Fixture::tcp(2, true).await;

    let status = request(
        fixture.server_address,
        "GET",
        "/script.php?mode=status",
        &[],
        b"",
    )
    .await;
    assert_eq!(status.status, 201);
    assert_eq!(status.body, b"created");

    let location = request(
        fixture.server_address,
        "GET",
        "/script.php?mode=location",
        &[],
        b"",
    )
    .await;
    assert_eq!(location.status, 302);
    assert_eq!(location.headers.get("location").unwrap(), "/redirected");

    let head = request(fixture.server_address, "HEAD", "/script.php", &[], b"").await;
    assert_eq!(head.status, 200);
    assert!(head.body.is_empty());
}

#[tokio::test]
async fn configured_directory_index_runs_as_fastcgi() {
    let fixture = Fixture::tcp(2, true).await;
    let response = request(fixture.server_address, "GET", "/folder/", &[], b"").await;

    assert_eq!(response.status, 200);
    assert!(
        String::from_utf8(response.body)
            .unwrap()
            .contains("script_name=/folder/index.php\n")
    );
}

#[tokio::test]
async fn malformed_backend_output_and_backend_disconnect_return_bad_gateway() {
    let fixture = Fixture::tcp(2, true).await;
    let malformed = request(
        fixture.server_address,
        "GET",
        "/script.php?mode=malformed",
        &[],
        b"",
    )
    .await;
    assert_eq!(malformed.status, 502);

    drop(fixture);
    let unavailable = Fixture::tcp(2, false).await;
    let response = request(unavailable.server_address, "GET", "/script.php", &[], b"").await;
    assert_eq!(response.status, 502);
}

#[tokio::test]
async fn slow_backend_returns_gateway_timeout() {
    let fixture = Fixture::tcp(1, true).await;
    let response = request(
        fixture.server_address,
        "GET",
        "/script.php?mode=slow",
        &[],
        b"",
    )
    .await;

    assert_eq!(response.status, 504);
}

#[cfg(unix)]
#[tokio::test]
async fn unix_socket_backend_serves_dynamic_content() {
    let fixture = Fixture::unix(2).await;
    let response = request(
        fixture.server_address,
        "GET",
        "/script.php?value=unix",
        &[],
        b"",
    )
    .await;

    assert_eq!(response.status, 200);
    assert!(
        String::from_utf8(response.body)
            .unwrap()
            .contains("query=value=unix\n")
    );
}

#[tokio::test]
async fn static_fallback_methods_and_traversal_remain_unchanged() {
    let fixture = Fixture::tcp(2, true).await;

    let static_response = request(fixture.server_address, "GET", "/static.txt", &[], b"").await;
    assert_eq!(static_response.status, 200);
    assert_eq!(static_response.body, b"static response");

    let post = request(
        fixture.server_address,
        "POST",
        "/static.txt",
        &[],
        b"not allowed",
    )
    .await;
    assert_eq!(post.status, 405);

    let traversal = request(fixture.server_address, "GET", "/../Cargo.toml", &[], b"").await;
    assert!(matches!(traversal.status, 400 | 404));
}

#[tokio::test]
async fn reuses_keep_alive_backend_connections() {
    let fixture = Fixture::tcp(5, true).await;
    BACKEND_CONNECTIONS.store(0, Ordering::SeqCst);
    for query in ["first", "second", "third"] {
        let response = request(
            fixture.server_address,
            "GET",
            &format!("/script.php?{query}"),
            &[],
            b"",
        )
        .await;
        assert_eq!(response.status, 200);
        assert!(String::from_utf8_lossy(&response.body).contains(&format!("query={query}")));
    }
    assert_eq!(BACKEND_CONNECTIONS.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn keep_alive_can_be_disabled() {
    let fixture = Fixture::tcp_with_args(5, true, &["--fastcgi-keepalive", "0"]).await;
    BACKEND_CONNECTIONS.store(0, Ordering::SeqCst);
    for _ in 0..2 {
        let response = request(fixture.server_address, "GET", "/script.php", &[], b"").await;
        assert_eq!(response.status, 200);
    }
    assert_eq!(BACKEND_CONNECTIONS.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn retries_when_backend_closed_a_pooled_connection() {
    let fixture = Fixture::tcp(5, true).await;
    BACKEND_CONNECTIONS.store(0, Ordering::SeqCst);
    let response = request(
        fixture.server_address,
        "GET",
        "/script.php?mode=close",
        &[],
        b"",
    )
    .await;
    assert_eq!(response.status, 200);
    sleep(Duration::from_millis(50)).await;
    let response = request(fixture.server_address, "GET", "/script.php?after", &[], b"").await;
    assert_eq!(response.status, 200);
    assert!(String::from_utf8_lossy(&response.body).contains("query=after"));
    assert_eq!(BACKEND_CONNECTIONS.load(Ordering::SeqCst), 2);
}
