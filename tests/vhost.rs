#![forbid(unsafe_code)]

mod common;

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use nix::unistd::{User, geteuid};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::sleep,
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fixture {
    root: PathBuf,
    address: SocketAddr,
    server: Child,
    backend: Option<JoinHandle<()>>,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    async fn start(root: PathBuf, config: String, backend: Option<JoinHandle<()>>) -> Self {
        let guard = TEST_LOCK.lock().await;
        let config_path = root.join("vhosts.yaml");
        std::fs::write(&config_path, config).unwrap();
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut server = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
            .arg("--bind")
            .arg(address.to_string())
            .arg("--root")
            .arg(&root)
            .arg("--config")
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if TcpStream::connect(address).await.is_ok() {
                break;
            }
            if let Some(status) = server.try_wait().unwrap() {
                panic!("webserver exited before becoming ready: {status}");
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "webserver did not start"
            );
            sleep(Duration::from_millis(20)).await;
        }

        Self {
            root,
            address,
            server,
            backend,
            _guard: guard,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(backend) = self.backend.take() {
            backend.abort();
        }
        common::shutdown(&mut self.server);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn new_root() -> PathBuf {
    let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "project-charlotte-vhost-{}-{id}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn current_user_name() -> String {
    User::from_uid(geteuid()).unwrap().unwrap().name.to_owned()
}

fn vhost(name: &str, root: &Path, user: &str, extra: &str) -> String {
    format!(
        "  - server_names: {name}\n    root: {:?}\n    user: {:?}\n{extra}\n",
        root.to_string_lossy(),
        user
    )
}

struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn request(
    address: SocketAddr,
    host: &str,
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
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
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
                "invalid HTTP response: {:?}",
                String::from_utf8_lossy(response)
            )
        });
    let mut lines = std::str::from_utf8(&response[..header_end])
        .unwrap()
        .split("\r\n");
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
        let size = usize::from_str_radix(
            std::str::from_utf8(&input[..line_end])
                .unwrap()
                .split(';')
                .next()
                .unwrap(),
            16,
        )
        .unwrap();
        input = &input[line_end + 2..];
        if size == 0 {
            return body;
        }
        assert!(input.len() >= size + 2);
        body.extend_from_slice(&input[..size]);
        assert_eq!(&input[size..size + 2], b"\r\n");
        input = &input[size + 2..];
    }
}

#[tokio::test]
async fn routes_exact_wildcard_unknown_and_traversal_requests() {
    let root = new_root();
    let alpha = root.join("alpha");
    let beta = root.join("beta");
    let wildcard = root.join("wildcard");
    std::fs::create_dir_all(&alpha).unwrap();
    std::fs::create_dir_all(&beta).unwrap();
    std::fs::create_dir_all(&wildcard).unwrap();
    std::fs::write(alpha.join("page.txt"), "alpha site").unwrap();
    std::fs::write(beta.join("page.txt"), "beta site").unwrap();
    std::fs::write(wildcard.join("page.txt"), "wild site").unwrap();
    std::fs::write(root.join("page.txt"), "fallback site").unwrap();
    let user = current_user_name();
    let config = format!(
        "vhost:\n{}{}{}",
        vhost("[\"alpha.test\", \"www.alpha.test\"]", &alpha, &user, ""),
        vhost("[\"beta.test\"]", &beta, &user, ""),
        vhost("[\"*.wild.test\"]", &wildcard, &user, "")
    );
    let fixture = Fixture::start(root.clone(), config, None).await;

    let alpha_response = request(
        fixture.address,
        "ALPHA.TEST:18080",
        "GET",
        "/page.txt",
        &[],
        b"",
    )
    .await;
    assert_eq!(alpha_response.status, 200);
    assert_eq!(alpha_response.body, b"alpha site");

    let beta_response = request(fixture.address, "beta.test", "GET", "/page.txt", &[], b"").await;
    assert_eq!(beta_response.body, b"beta site");

    let alias_response = request(
        fixture.address,
        "www.alpha.test",
        "GET",
        "/page.txt",
        &[],
        b"",
    )
    .await;
    assert_eq!(alias_response.body, b"alpha site");

    let wildcard_response = request(
        fixture.address,
        "api.wild.test",
        "GET",
        "/page.txt",
        &[],
        b"",
    )
    .await;
    assert_eq!(wildcard_response.body, b"wild site");

    let fallback_response = request(
        fixture.address,
        "unconfigured.test",
        "GET",
        "/page.txt",
        &[],
        b"",
    )
    .await;
    assert_eq!(fallback_response.body, b"fallback site");

    let traversal = request(
        fixture.address,
        "alpha.test",
        "GET",
        "/%2e%2e/page.txt",
        &[],
        b"",
    )
    .await;
    assert_eq!(traversal.status, 404);
}

#[tokio::test]
async fn uses_default_vhost_for_unknown_hosts() {
    let root = new_root();
    let default_root = root.join("default");
    std::fs::create_dir_all(&default_root).unwrap();
    std::fs::write(default_root.join("page.txt"), "default vhost").unwrap();
    let config = format!(
        "vhost:\n{}",
        vhost(
            "[\"known.test\"]",
            &default_root,
            &current_user_name(),
            "    default: true",
        )
    );
    let fixture = Fixture::start(root, config, None).await;
    let response = request(
        fixture.address,
        "unknown.test",
        "GET",
        "/page.txt",
        &[],
        b"",
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"default vhost");
}

#[tokio::test]
async fn forwards_fastcgi_through_worker_and_strips_internal_headers() {
    let root = new_root();
    let site = root.join("site");
    std::fs::create_dir_all(&site).unwrap();
    std::fs::write(site.join("echo.php"), "not served as a file").unwrap();
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
    let backend = tokio::spawn(async move {
        while let Ok((mut stream, _)) = backend_listener.accept().await {
            tokio::spawn(async move {
                if let Err(error) = serve_fastcgi_request(&mut stream).await {
                    eprintln!("vhost mock FastCGI responder failed: {error}");
                }
            });
        }
    });
    let config = vhost(
        "[\"php.test\"]",
        &site,
        &current_user_name(),
        &format!("    fastcgi: [\"php={backend_address}\"]"),
    );
    let fixture = Fixture::start(root, format!("vhost:\n{config}"), Some(backend)).await;
    let response = request(
        fixture.address,
        "php.test",
        "POST",
        "/echo.php",
        &[("Content-Type", "text/plain")],
        b"payload",
    )
    .await;
    let body = String::from_utf8(response.body).unwrap();
    assert_eq!(response.status, 200);
    assert!(body.contains("protocol=HTTP/1.1"));
    assert!(body.contains("server_name=php.test"));
    assert!(body.contains("body=payload"));
    assert!(body.contains("peer=") && !body.contains("peer=<missing>"));
    assert!(body.contains("internal=<missing>"));
    assert!(!response.headers.contains_key("x-charlotte-peer"));
}

async fn serve_fastcgi_request<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (params, stdin) = read_fastcgi_request(stream).await?;
    let body = format!(
        "protocol={}\nserver_name={}\npeer={}\ninternal={}\nbody={}",
        params
            .get("SERVER_PROTOCOL")
            .map(String::as_str)
            .unwrap_or("<missing>"),
        params
            .get("SERVER_NAME")
            .map(String::as_str)
            .unwrap_or("<missing>"),
        params
            .get("REMOTE_ADDR")
            .map(String::as_str)
            .unwrap_or("<missing>"),
        params
            .get("HTTP_X_CHARLOTTE_PEER")
            .map(String::as_str)
            .unwrap_or("<missing>"),
        String::from_utf8_lossy(&stdin)
    );
    let mut output = b"Content-Type: text/plain\r\n\r\n".to_vec();
    output.extend_from_slice(body.as_bytes());
    write_fastcgi_record(stream, 6, 1, &output).await?;
    write_fastcgi_record(stream, 6, 1, &[]).await?;
    write_fastcgi_record(stream, 3, 1, &[0; 8]).await?;
    Ok(())
}

async fn read_fastcgi_request<S>(stream: &mut S) -> io::Result<(HashMap<String, String>, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut params_bytes = Vec::new();
    let mut stdin = Vec::new();
    let mut params_done = false;
    loop {
        let mut header = [0; 8];
        stream.read_exact(&mut header).await?;
        let record_type = header[1];
        let length = usize::from(u16::from_be_bytes([header[4], header[5]]));
        let padding = usize::from(header[6]);
        let mut content = vec![0; length];
        stream.read_exact(&mut content).await?;
        if padding > 0 {
            let mut ignored = vec![0; padding];
            stream.read_exact(&mut ignored).await?;
        }
        match record_type {
            4 if content.is_empty() => params_done = true,
            4 => params_bytes.extend_from_slice(&content),
            5 if content.is_empty() && params_done => break,
            5 => stdin.extend_from_slice(&content),
            _ => {}
        }
    }
    Ok((decode_params(&params_bytes), stdin))
}

fn decode_params(mut input: &[u8]) -> HashMap<String, String> {
    let mut params = HashMap::new();
    while !input.is_empty() {
        let name_len = decode_length(&mut input);
        let value_len = decode_length(&mut input);
        let name = String::from_utf8(input[..name_len].to_vec()).unwrap();
        let value = String::from_utf8(input[name_len..name_len + value_len].to_vec()).unwrap();
        input = &input[name_len + value_len..];
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
async fn refuses_privilege_change_when_server_is_non_root() {
    if geteuid().is_root()
        || current_user_name() == "nobody"
        || User::from_name("nobody").unwrap().is_none()
    {
        return;
    }
    let root = new_root();
    std::fs::create_dir(root.join("site")).unwrap();
    let config = format!(
        "vhost:\n{}",
        vhost("[\"nobody.test\"]", &root.join("site"), "nobody", "")
    );
    let config_path = root.join("vhosts.yaml");
    std::fs::write(&config_path, config).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .arg("--bind")
        .arg("127.0.0.1:0")
        .arg("--root")
        .arg(&root)
        .arg("--config")
        .arg(config_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("a non-root server can only run workers as its current uid and gid")
    );
    let _ = std::fs::remove_dir_all(root);
}
