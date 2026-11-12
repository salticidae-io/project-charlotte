#![forbid(unsafe_code)]
#![cfg(feature = "hosting")]

#[path = "common/mod.rs"]
mod common;

use std::{
    collections::HashMap,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::sleep,
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    address: std::net::SocketAddr,
    server: Child,
}

impl Fixture {
    async fn start() -> Self {
        Self::start_with(&[], &[]).await
    }

    async fn start_with(args: &[&str], env: &[(&str, &str)]) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "project-charlotte-cgi-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        write_script(
            &root.join("env.cgi"),
            r##"#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n%s|%s|%s' "$QUERY_STRING" "$PATH_INFO" "$REQUEST_METHOD"
"##,
            0o755,
        );
        write_script(
            &root.join("status.cgi"),
            r##"#!/bin/sh
printf 'Status: 201 Created\r\nContent-Type: text/plain\r\n\r\ncreated'
"##,
            0o755,
        );
        write_script(
            &root.join("broken.cgi"),
            r##"#!/bin/sh
printf 'not a CGI header\r\n\r\nbroken'
"##,
            0o755,
        );
        write_script(
            &root.join("lf.cgi"),
            r##"#!/bin/sh
printf 'Content-Type: text/plain\n\nlf headers'
"##,
            0o755,
        );
        write_script(
            &root.join("redirect.cgi"),
            r##"#!/bin/sh
printf 'Location: /next\r\n\r\n'
"##,
            0o755,
        );
        write_script(
            &root.join("large-header.cgi"),
            r##"#!/bin/sh
printf 'Content-Type: text/plain\r\nX-Fill: '
head -c 70000 /dev/zero | tr '\000' a
printf '\r\n\r\nbody'
"##,
            0o755,
        );
        write_script(
            &root.join("large-output.cgi"),
            r##"#!/bin/sh
printf 'Content-Type: application/octet-stream\r\n\r\n'
head -c 300000 /dev/zero | tr '\000' x
"##,
            0o755,
        );
        write_script(
            &root.join("non-executable.cgi"),
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nshould not run'\n",
            0o644,
        );
        write_script(
            &root.join("exit-nonzero.cgi"),
            r##"#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\noutput before exit'
exit 7
"##,
            0o755,
        );
        write_script(&root.join("no-headers.cgi"), "#!/bin/sh\nsleep 10\n", 0o755);
        write_script(
            &root.join("slow-body.cgi"),
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\nbefore-timeout'; sleep 10; printf after-timeout\n",
            0o755,
        );
        write_script(
            &root.join("isolated-env.cgi"),
            r##"#!/bin/sh
printf 'Content-Type: text/plain\r\n\r\n%s|%s|%s' "${CHARLOTTE_TEST_SECRET-unset}" "$GATEWAY_INTERFACE" "${PATH:+set}"
"##,
            0o755,
        );
        std::fs::create_dir_all(root.join("subdir")).unwrap();
        write_script(
            &root.join("subdir/pwd.cgi"),
            "#!/bin/sh\nprintf 'Content-Type: text/plain\\r\\n\\r\\n'; pwd\n",
            0o755,
        );
        write_script(
            &root.join("echo.sh"),
            r##"printf 'Content-Type: text/plain\r\n\r\n'
cat
"##,
            0o644,
        );
        std::fs::write(root.join("static.txt"), "static response").unwrap();

        Self::launch(root, args, env).await
    }

    async fn launch(root: PathBuf, args: &[&str], env: &[(&str, &str)]) -> Self {
        let address = common::reserve_tcp_address();
        let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
        command
            .arg("--bind")
            .arg(address.to_string())
            .arg("--root")
            .arg(&root)
            .arg("--cgi")
            .arg("cgi")
            .arg("--cgi")
            .arg("sh=/bin/sh")
            .arg("--fastcgi-timeout")
            .arg("5")
            .args(args)
            .envs(env.iter().copied())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut server = common::spawn(&mut command).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = server.try_wait().unwrap() {
                panic!("server exited before becoming ready: {status}");
            }
            if TcpStream::connect(address).await.is_ok() {
                if let Some(status) = server.try_wait().unwrap() {
                    panic!("server exited before becoming ready: {status}");
                }
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                common::shutdown(&mut server);
                panic!("server did not become ready");
            }
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

fn write_script(path: &std::path::Path, contents: &str, mode: u32) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
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
    body: &[u8],
) -> HttpResponse {
    request_with_host(address, method, path, body, "localhost").await
}

async fn request_with_host(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
    host: &str,
) -> HttpResponse {
    parse_http_response(&request_raw(address, method, path, body, host).await)
}

async fn request_raw(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
    host: &str,
) -> Vec<u8> {
    let mut stream = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(address))
        .await
        .unwrap()
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len(),
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(8), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

fn parse_http_response(response: &[u8]) -> HttpResponse {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response headers should be terminated");
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

#[tokio::test]
async fn serves_classic_cgi_scripts_and_preserves_static_fallback() {
    let fixture = Fixture::start().await;

    let response = request(fixture.address, "GET", "/env.cgi/extra/path?q=hello", b"").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"q=hello|/extra/path|GET");

    let response = request(fixture.address, "POST", "/echo.sh", b"post body").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"post body");

    let response = request(fixture.address, "GET", "/status.cgi", b"").await;
    assert_eq!(response.status, 201);
    assert_eq!(response.headers.get("content-type").unwrap(), "text/plain");
    assert_eq!(response.body, b"created");

    let response = request(fixture.address, "GET", "/broken.cgi", b"").await;
    assert_eq!(response.status, 502);

    let response = request(fixture.address, "GET", "/static.txt", b"").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"static response");
}

#[tokio::test]
async fn handles_cgi_headers_head_requests_and_script_working_directory() {
    let fixture = Fixture::start().await;

    let response = request(fixture.address, "GET", "/lf.cgi", b"").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"lf headers");

    let response = request(fixture.address, "GET", "/redirect.cgi", b"").await;
    assert_eq!(response.status, 302);
    assert_eq!(response.headers.get("location").unwrap(), "/next");

    let response = request(fixture.address, "HEAD", "/env.cgi", b"").await;
    assert_eq!(response.status, 200);
    assert!(response.body.is_empty());

    let response = request(fixture.address, "GET", "/subdir/pwd.cgi", b"").await;
    assert_eq!(response.status, 200);
    assert_eq!(
        std::str::from_utf8(&response.body).unwrap().trim(),
        std::fs::canonicalize(fixture.root.join("subdir"))
            .unwrap()
            .to_str()
            .unwrap()
    );
}

#[tokio::test]
async fn isolates_cgi_environment_and_streams_large_output() {
    let fixture = Fixture::start_with(&[], &[("CHARLOTTE_TEST_SECRET", "do-not-leak")]).await;

    let response = request(fixture.address, "GET", "/isolated-env.cgi", b"").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"unset|CGI/1.1|set");

    let response = request(fixture.address, "GET", "/large-output.cgi", b"").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body.len(), 300_000);
    assert!(response.body.iter().all(|byte| *byte == b'x'));
}

#[tokio::test]
async fn handles_cgi_spawn_errors_oversized_headers_and_nonzero_exit() {
    let fixture = Fixture::start().await;

    let response = request(fixture.address, "GET", "/large-header.cgi", b"").await;
    assert_eq!(response.status, 502);

    let response = request(fixture.address, "GET", "/non-executable.cgi", b"").await;
    assert_eq!(response.status, 502);

    let response = request(fixture.address, "GET", "/exit-nonzero.cgi", b"").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"output before exit");
}

#[tokio::test]
async fn times_out_cgi_before_headers_and_truncates_a_slow_body() {
    let fixture = Fixture::start_with(&["--fastcgi-timeout", "2"], &[]).await;

    let response = request(fixture.address, "GET", "/no-headers.cgi", b"").await;
    assert_eq!(response.status, 504);

    let raw = request_raw(fixture.address, "GET", "/slow-body.cgi", b"", "localhost").await;
    assert!(raw.starts_with(b"HTTP/1.1 200"), "response was {raw:?}");
    assert!(
        raw.windows(b"before-timeout".len())
            .any(|window| window == b"before-timeout")
    );
    assert!(
        !raw.windows(b"after-timeout".len())
            .any(|window| window == b"after-timeout")
    );
}

#[tokio::test]
async fn runs_cgi_in_vhost_worker_with_relative_interpreter() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let fixture_root = std::env::temp_dir().join(format!(
        "project-charlotte-cgi-vhost-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(&fixture_root).unwrap();
    std::fs::create_dir_all(fixture_root.join("bin")).unwrap();
    std::os::unix::fs::symlink("/bin/sh", fixture_root.join("bin/sh-link")).unwrap();
    write_script(
        &fixture_root.join("script.sh"),
        "printf 'Content-Type: text/plain\\r\\n\\r\\nvhost CGI works'\n",
        0o644,
    );
    let user = nix::unistd::User::from_uid(nix::unistd::geteuid())
        .unwrap()
        .unwrap()
        .name;
    let config_path = fixture_root.join("vhosts.yaml");
    std::fs::write(
        &config_path,
        format!(
            "vhost:\n  - server_names: [cgi.example.test]\n    root: {:?}\n    user: {:?}\n    cgi: [cgi, \"sh=bin/sh-link\"]\n",
            fixture_root.to_string_lossy(),
            user,
        ),
    )
    .unwrap();
    let config_arg = config_path.to_string_lossy().into_owned();
    let fixture = Fixture::launch(fixture_root, &["--config", &config_arg], &[]).await;

    let response = request_with_host(
        fixture.address,
        "GET",
        "/script.sh",
        b"",
        "cgi.example.test",
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"vhost CGI works");
}
