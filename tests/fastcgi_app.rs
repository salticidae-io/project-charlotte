#![forbid(unsafe_code)]

mod common;

use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    os::fd::AsFd,
    os::unix::net::UnixListener as StdUnixListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use nix::unistd::{User, geteuid};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UnixListener},
    time::sleep,
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    address: SocketAddr,
    server: Child,
}

impl Fixture {
    async fn start(root: PathBuf, vhost_config: Option<String>, exit_after: Option<usize>) -> Self {
        Self::start_with(root, vhost_config, exit_after, &[], &[]).await
    }

    async fn start_with(
        root: PathBuf,
        vhost_config: Option<String>,
        exit_after: Option<usize>,
        extra_env: &[&str],
        extra_args: &[&str],
    ) -> Self {
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("echo.php"), "not served statically").unwrap();
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);

        let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
        command
            .arg("--bind")
            .arg(address.to_string())
            .arg("--root")
            .arg(&root)
            .arg("--fastcgi-timeout")
            .arg("8")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .env("CHARLOTTE_INHERITED_MARKER", "must-not-reach-app");
        if let Some(config) = vhost_config {
            let config_path = root.join("vhosts.yaml");
            std::fs::write(&config_path, config).unwrap();
            command.arg("--config").arg(config_path);
        } else {
            command.arg("--fastcgi-app").arg(format!(
                "php={}",
                std::env::current_exe().unwrap().display()
            ));
            for arg in ["--exact", "fcgi_app_helper", "--nocapture"] {
                command.arg("--fastcgi-app-arg").arg(format!("php={arg}"));
            }
            command
                .arg("--fastcgi-app-env")
                .arg("php=CHARLOTTE_FCGI_HELPER=1");
            command.arg("--fastcgi-app-env").arg("php=APP_MODE=cli");
            if let Some(count) = exit_after {
                command
                    .arg("--fastcgi-app-env")
                    .arg(format!("php=CHARLOTTE_FCGI_EXIT_AFTER={count}"));
            }
            for entry in extra_env {
                command.arg("--fastcgi-app-env").arg(format!("php={entry}"));
            }
        }
        command.args(extra_args);
        let mut server = command.spawn().unwrap();
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
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        common::shutdown(&mut self.server);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct HttpResponse {
    status: u16,
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
    let mut stream = tokio::time::timeout(Duration::from_secs(12), TcpStream::connect(address))
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
    tokio::time::timeout(Duration::from_secs(12), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> HttpResponse {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response headers should be present");
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
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect::<HashMap<_, _>>();
    let body = &response[header_end + 4..];
    let body = if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        decode_chunked_body(body)
    } else {
        body.to_vec()
    };
    HttpResponse { status, body }
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

fn new_root() -> PathBuf {
    let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "project-charlotte-fastcgi-app-{}-{id}",
        std::process::id()
    ))
}

#[tokio::test]
async fn launches_application_and_forwards_get_parameters_with_clean_environment() {
    let fixture = Fixture::start(new_root(), None, None).await;
    let response = request(
        fixture.address,
        "localhost",
        "GET",
        "/echo.php?item=one",
        &[],
        b"",
    )
    .await;
    let body = String::from_utf8(response.body).unwrap();
    assert_eq!(response.status, 200);
    assert!(body.contains("method=GET"));
    assert!(body.contains("query=item=one"));
    assert!(body.contains("app_mode=cli"));
    assert!(body.contains("inherited=<missing>"));
    assert!(body.contains("listen_fd=0"));
}

#[tokio::test]
async fn forwards_post_body_to_application() {
    let fixture = Fixture::start(new_root(), None, None).await;
    let response = request(
        fixture.address,
        "localhost",
        "POST",
        "/echo.php",
        &[("Content-Type", "text/plain")],
        b"posted payload",
    )
    .await;
    let body = String::from_utf8(response.body).unwrap();
    assert_eq!(response.status, 200);
    assert!(body.contains("length=14"));
    assert!(body.contains("content_type=text/plain"));
    assert!(body.contains("stdin=posted payload"));
}

#[tokio::test]
async fn restarts_application_after_it_exits() {
    let fixture = Fixture::start(new_root(), None, Some(1)).await;
    let first = request(
        fixture.address,
        "localhost",
        "GET",
        "/echo.php?first=1",
        &[],
        b"",
    )
    .await;
    let second = request(
        fixture.address,
        "localhost",
        "GET",
        "/echo.php?second=1",
        &[],
        b"",
    )
    .await;
    let first = String::from_utf8(first.body).unwrap();
    let second = String::from_utf8(second.body).unwrap();
    assert!(first.contains("query=first=1"));
    assert!(second.contains("query=second=1"));
    assert_ne!(field(&first, "pid"), field(&second, "pid"));
}

#[tokio::test]
async fn spreads_concurrent_requests_across_cli_workers() {
    let fixture = Fixture::start_with(
        new_root(),
        None,
        None,
        &["CHARLOTTE_FCGI_DELAY_MS=300"],
        &["--fastcgi-app-max-workers", "php=3"],
    )
    .await;
    let (first, second, third) = tokio::join!(
        request(
            fixture.address,
            "localhost",
            "GET",
            "/echo.php?worker=1",
            &[],
            b""
        ),
        request(
            fixture.address,
            "localhost",
            "GET",
            "/echo.php?worker=2",
            &[],
            b""
        ),
        request(
            fixture.address,
            "localhost",
            "GET",
            "/echo.php?worker=3",
            &[],
            b""
        ),
    );
    let mut pids = HashSet::new();
    for response in [first, second, third] {
        assert_eq!(response.status, 200);
        let body = String::from_utf8(response.body).unwrap();
        pids.insert(field(&body, "pid").to_owned());
    }
    assert_eq!(
        pids.len(),
        3,
        "requests should reach all workers spawned for the concurrent burst"
    );
}

#[tokio::test]
async fn sequential_requests_reuse_one_on_demand_worker() {
    let fixture = Fixture::start_with(
        new_root(),
        None,
        None,
        &[],
        &["--fastcgi-app-max-workers", "php=3"],
    )
    .await;
    let mut pids = HashSet::new();
    for index in 1..=4 {
        let response = request(
            fixture.address,
            "localhost",
            "GET",
            &format!("/echo.php?request={index}"),
            &[],
            b"",
        )
        .await;
        assert_eq!(response.status, 200);
        let body = String::from_utf8(response.body).unwrap();
        pids.insert(field(&body, "pid").to_owned());
    }
    assert_eq!(
        pids.len(),
        1,
        "sequential traffic should reuse an idle worker"
    );
}

#[tokio::test]
async fn reaps_extra_workers_after_the_pool_becomes_idle() {
    let fixture = Fixture::start_with(
        new_root(),
        None,
        None,
        &["CHARLOTTE_FCGI_DELAY_MS=300"],
        &[
            "--fastcgi-app-max-workers",
            "php=3",
            "--fastcgi-app-idle-timeout",
            "php=1",
        ],
    )
    .await;
    let (first, second, third) = tokio::join!(
        request(
            fixture.address,
            "localhost",
            "GET",
            "/echo.php?burst=1",
            &[],
            b""
        ),
        request(
            fixture.address,
            "localhost",
            "GET",
            "/echo.php?burst=2",
            &[],
            b""
        ),
        request(
            fixture.address,
            "localhost",
            "GET",
            "/echo.php?burst=3",
            &[],
            b""
        ),
    );
    let pids = [first, second, third]
        .into_iter()
        .map(|response| {
            assert_eq!(response.status, 200);
            let body = String::from_utf8(response.body).unwrap();
            field(&body, "pid").parse::<u32>().unwrap()
        })
        .collect::<HashSet<_>>();
    assert_eq!(pids.len(), 3, "the burst should spawn three workers");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = pids
            .iter()
            .filter(|pid| std::path::Path::new("/proc").join(pid.to_string()).exists())
            .count();
        if remaining == 1 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "expected idle workers to be reaped, but {remaining} of 3 remain"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn scales_pool_within_max_workers_and_back_up_after_reaping() {
    let fixture = Fixture::start_with(
        new_root(),
        None,
        None,
        &["CHARLOTTE_FCGI_DELAY_MS=300"],
        &[
            "--fastcgi-app-max-workers",
            "php=2",
            "--fastcgi-app-idle-timeout",
            "php=1",
        ],
    )
    .await;

    let started = tokio::time::Instant::now();
    let mut requests = tokio::task::JoinSet::new();
    for index in 1..=5 {
        let address = fixture.address;
        requests.spawn(async move {
            let path = format!("/echo.php?burst=1-{index}");
            request(address, "localhost", "GET", &path, &[], b"").await
        });
    }
    let mut first_pids = HashSet::new();
    while let Some(response) = requests.join_next().await {
        first_pids.insert(response_pid(response.unwrap()));
    }
    assert_eq!(first_pids.len(), 2, "pool must not exceed max_workers");
    assert!(
        started.elapsed() >= Duration::from_millis(800),
        "five delayed requests on two workers should queue in three rounds"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let survivor = loop {
        let alive = first_pids
            .iter()
            .copied()
            .filter(|pid| std::path::Path::new("/proc").join(pid.to_string()).exists())
            .collect::<Vec<_>>();
        if alive.len() == 1 {
            break alive[0];
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "expected idle pool to shrink to one worker, but {} of 2 remain",
            alive.len()
        );
        sleep(Duration::from_millis(100)).await;
    };

    let mut requests = tokio::task::JoinSet::new();
    for index in 1..=2 {
        let address = fixture.address;
        requests.spawn(async move {
            let path = format!("/echo.php?burst=2-{index}");
            request(address, "localhost", "GET", &path, &[], b"").await
        });
    }
    let mut second_pids = HashSet::new();
    while let Some(response) = requests.join_next().await {
        second_pids.insert(response_pid(response.unwrap()));
    }
    assert_eq!(
        second_pids.len(),
        2,
        "second burst should scale up to two workers"
    );
    assert!(
        second_pids.contains(&survivor),
        "the worker retained after reaping should be reused"
    );
    assert!(
        second_pids.iter().any(|pid| !first_pids.contains(pid)),
        "the second burst should spawn a replacement worker"
    );
}

#[tokio::test]
async fn restarts_each_cli_worker_independently() {
    let fixture = Fixture::start_with(
        new_root(),
        None,
        Some(1),
        &[],
        &["--fastcgi-app-max-workers", "php=2"],
    )
    .await;
    let mut pids = HashSet::new();
    for index in 1..=4 {
        let response = request(
            fixture.address,
            "localhost",
            "GET",
            &format!("/echo.php?request={index}"),
            &[],
            b"",
        )
        .await;
        assert_eq!(response.status, 200);
        let body = String::from_utf8(response.body).unwrap();
        pids.insert(field(&body, "pid").to_owned());
    }
    assert_eq!(pids.len(), 4, "each completed worker should be replaced");
}

#[tokio::test]
async fn immediately_restarts_cleanly_exited_cli_app() {
    let fixture = Fixture::start_with(
        new_root(),
        None,
        Some(1),
        &["CHARLOTTE_FCGI_DELAY_MS=100"],
        &["--fastcgi-app-max-workers", "php=1"],
    )
    .await;
    let started = tokio::time::Instant::now();
    let mut pids = HashSet::new();
    for index in 1..=4 {
        let response = request(
            fixture.address,
            "localhost",
            "GET",
            &format!("/echo.php?request={index}"),
            &[],
            b"",
        )
        .await;
        assert_eq!(response.status, 200);
        let body = String::from_utf8(response.body).unwrap();
        pids.insert(field(&body, "pid").to_owned());
    }
    assert_eq!(pids.len(), 4, "each cleanly exited app should be replaced");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "clean exits should not incur the crash-loop restart delay"
    );
}

#[tokio::test]
async fn rejects_missing_application_at_startup() {
    let root = new_root();
    std::fs::create_dir_all(&root).unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let mut server = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .arg("--bind")
        .arg(address.to_string())
        .arg("--root")
        .arg(&root)
        .arg("--fastcgi-app")
        .arg("php=/no/such/charlotte-fastcgi-app")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = server.try_wait().unwrap() {
            break status;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "server accepted missing app"
        );
        sleep(Duration::from_millis(20)).await;
    };
    let _ = std::fs::remove_dir_all(root);
    assert!(!status.success());
}

#[tokio::test]
async fn starts_vhost_application_inside_privileged_worker_identity() {
    let root = new_root();
    let site = root.join("site");
    std::fs::create_dir_all(&site).unwrap();
    std::fs::write(site.join("echo.php"), "not served statically").unwrap();
    let command = std::env::current_exe().unwrap();
    let user = User::from_uid(geteuid()).unwrap().unwrap().name;
    let config = format!(
        "vhost:\n  - server_names: [app.test]\n    root: {:?}\n    user: {:?}\n    fastcgi_app:\n      - extension: php\n        command: [{:?}, --exact, fcgi_app_helper, --nocapture]\n        env: {{ CHARLOTTE_FCGI_HELPER: \"1\", APP_MODE: vhost, CHARLOTTE_FCGI_DELAY_MS: \"200\" }}\n        max_workers: 3\n",
        site.to_string_lossy(),
        user,
        command.to_string_lossy()
    );
    let fixture = Fixture::start(root, Some(config), None).await;
    let (first, second, third) = tokio::join!(
        request(
            fixture.address,
            "app.test",
            "GET",
            "/echo.php?worker=1",
            &[],
            b""
        ),
        request(
            fixture.address,
            "app.test",
            "GET",
            "/echo.php?worker=2",
            &[],
            b""
        ),
        request(
            fixture.address,
            "app.test",
            "GET",
            "/echo.php?worker=3",
            &[],
            b""
        ),
    );
    let mut pids = HashSet::new();
    for response in [first, second, third] {
        assert_eq!(response.status, 200);
        let body = String::from_utf8(response.body).unwrap();
        assert!(body.contains("app_mode=vhost"));
        pids.insert(field(&body, "pid").to_owned());
    }
    assert_eq!(
        pids.len(),
        3,
        "requests should reach all configured workers"
    );
}

#[test]
fn fcgi_app_helper() {
    if std::env::var_os("CHARLOTTE_FCGI_HELPER").is_none() {
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(serve_fcgi_app())
        .unwrap();
}

async fn serve_fcgi_app() -> io::Result<()> {
    let listener_fd = std::io::stdin().as_fd().try_clone_to_owned()?;
    let listener = StdUnixListener::from(listener_fd);
    listener.set_nonblocking(true)?;
    let listener = UnixListener::from_std(listener)?;
    let exit_after = std::env::var("CHARLOTTE_FCGI_EXIT_AFTER")
        .ok()
        .and_then(|value| value.parse::<usize>().ok());
    let mut handled = 0;
    loop {
        let (mut stream, _) = listener.accept().await?;
        serve_fcgi_request(&mut stream).await?;
        handled += 1;
        if exit_after.is_some_and(|limit| handled >= limit) {
            return Ok(());
        }
    }
}

async fn serve_fcgi_request<S>(stream: &mut S) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (params, stdin) = read_fastcgi_request(stream).await?;
    if let Some(milliseconds) = std::env::var("CHARLOTTE_FCGI_DELAY_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
    {
        sleep(Duration::from_millis(milliseconds)).await;
    }
    let body = format!(
        "method={}\nquery={}\nlength={}\ncontent_type={}\napp_mode={}\ninherited={}\nlisten_fd={}\nstdin={}\npid={}",
        cgi_parameter(&params, "REQUEST_METHOD"),
        cgi_parameter(&params, "QUERY_STRING"),
        cgi_parameter(&params, "CONTENT_LENGTH"),
        cgi_parameter(&params, "CONTENT_TYPE"),
        std::env::var("APP_MODE").unwrap_or_else(|_| "<missing>".to_owned()),
        std::env::var("CHARLOTTE_INHERITED_MARKER").unwrap_or_else(|_| "<missing>".to_owned()),
        std::env::var("FCGI_LISTENSOCK_FILENO").unwrap_or_else(|_| "<missing>".to_owned()),
        String::from_utf8_lossy(&stdin),
        std::process::id(),
    );
    let mut output = b"Content-Type: text/plain\r\n\r\n".to_vec();
    output.extend_from_slice(body.as_bytes());
    write_fastcgi_record(stream, 6, 1, &output).await?;
    write_fastcgi_record(stream, 6, 1, &[]).await?;
    write_fastcgi_record(stream, 3, 1, &[0; 8]).await?;
    stream.flush().await?;
    let mut remaining = Vec::new();
    let _ = stream.read_to_end(&mut remaining).await;
    Ok(())
}

async fn read_fastcgi_request<S>(stream: &mut S) -> io::Result<(HashMap<String, String>, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut params_data = Vec::new();
    let mut stdin = Vec::new();
    let mut params_done = false;
    let mut stdin_done = false;
    while !params_done || !stdin_done {
        let (kind, _request_id, content) = read_fastcgi_record(stream).await?;
        match kind {
            4 => {
                if content.is_empty() {
                    params_done = true;
                } else {
                    params_data.extend_from_slice(&content);
                }
            }
            5 => {
                if content.is_empty() {
                    stdin_done = true;
                } else {
                    stdin.extend_from_slice(&content);
                }
            }
            _ => {}
        }
    }
    Ok((decode_params(&params_data), stdin))
}

async fn read_fastcgi_record<S>(stream: &mut S) -> io::Result<(u8, u16, Vec<u8>)>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0; 8];
    stream.read_exact(&mut header).await?;
    if header[0] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid FastCGI version",
        ));
    }
    let request_id = u16::from_be_bytes([header[2], header[3]]);
    let content_length = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let mut content = vec![0; content_length];
    stream.read_exact(&mut content).await?;
    if header[6] != 0 {
        let mut padding = vec![0; usize::from(header[6])];
        stream.read_exact(&mut padding).await?;
    }
    Ok((header[1], request_id, content))
}

fn decode_params(mut input: &[u8]) -> HashMap<String, String> {
    let mut params = HashMap::new();
    while !input.is_empty() {
        let name_length = decode_length(&mut input);
        let value_length = decode_length(&mut input);
        let name = String::from_utf8_lossy(&input[..name_length]).into_owned();
        input = &input[name_length..];
        let value = String::from_utf8_lossy(&input[..value_length]).into_owned();
        input = &input[value_length..];
        params.insert(name, value);
    }
    params
}

fn decode_length(input: &mut &[u8]) -> usize {
    if input[0] & 0x80 == 0 {
        let length = usize::from(input[0]);
        *input = &input[1..];
        length
    } else {
        let length = (usize::from(input[0] & 0x7f) << 24)
            | (usize::from(input[1]) << 16)
            | (usize::from(input[2]) << 8)
            | usize::from(input[3]);
        *input = &input[4..];
        length
    }
}

async fn write_fastcgi_record<S>(
    stream: &mut S,
    kind: u8,
    request_id: u16,
    content: &[u8],
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let content_length = u16::try_from(content.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "FastCGI record too large"))?;
    let mut record = vec![
        1,
        kind,
        (request_id >> 8) as u8,
        request_id as u8,
        (content_length >> 8) as u8,
        content_length as u8,
        0,
        0,
    ];
    record.extend_from_slice(content);
    stream.write_all(&record).await
}

fn cgi_parameter<'a>(params: &'a HashMap<String, String>, name: &str) -> &'a str {
    params.get(name).map(String::as_str).unwrap_or("<missing>")
}

fn field<'a>(body: &'a str, name: &str) -> &'a str {
    body.lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .unwrap_or("<missing>")
}

fn response_pid(response: HttpResponse) -> u32 {
    assert_eq!(response.status, 200);
    let body = String::from_utf8(response.body).unwrap();
    field(&body, "pid").parse().unwrap()
}
