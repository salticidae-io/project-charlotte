#![forbid(unsafe_code)]

use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use nix::unistd::{User, geteuid};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::sleep,
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    address: SocketAddr,
    server: Child,
    backend_hits: Option<Arc<AtomicUsize>>,
    backend_task: Option<JoinHandle<()>>,
}

impl Fixture {
    async fn start(body_limit: Option<usize>, with_fastcgi: bool, with_vhost: bool) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "project-charlotte-modsecurity-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("clean.txt"), "clean response").unwrap();
        std::fs::write(root.join("secret.txt"), "response contains SECRET data").unwrap();
        std::fs::write(root.join("app.php"), "<?php echo 'ok';").unwrap();
        std::fs::write(root.join("rules.conf"), rules()).unwrap();

        let mut backend_hits = None;
        let mut backend_task = None;
        let mut backend_address = None;
        if with_fastcgi {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            backend_address = Some(listener.local_addr().unwrap());
            let hits = Arc::new(AtomicUsize::new(0));
            let task_hits = Arc::clone(&hits);
            backend_task = Some(tokio::spawn(async move {
                while let Ok((socket, _)) = listener.accept().await {
                    task_hits.fetch_add(1, Ordering::Relaxed);
                    drop(socket);
                }
            }));
            backend_hits = Some(hits);
        }

        let mut vhost_config = None;
        if with_vhost {
            let vhost_root = root.join("vhost-root");
            std::fs::create_dir_all(&vhost_root).unwrap();
            std::fs::write(vhost_root.join("clean.txt"), "vhost response").unwrap();
            let user = User::from_uid(geteuid()).unwrap().unwrap();
            let config_path = root.join("vhosts.toml");
            std::fs::write(
                &config_path,
                format!(
                    "[[vhost]]\nserver_names = [\"waf.example.test\"]\nroot = {:?}\nuser = {:?}\n",
                    vhost_root.to_string_lossy(),
                    user.name
                ),
            )
            .unwrap();
            vhost_config = Some(config_path);
        }

        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
        command
            .arg("--bind")
            .arg(address.to_string())
            .arg("--root")
            .arg(&root)
            .arg("--modsecurity-rules")
            .arg(root.join("rules.conf"));
        if let Some(limit) = body_limit {
            command
                .arg("--modsecurity-body-limit")
                .arg(limit.to_string());
        }
        if let Some(config_path) = vhost_config {
            command.arg("--config").arg(config_path);
        }
        if let Some(backend_address) = backend_address {
            command
                .arg("--fastcgi")
                .arg(format!("php={backend_address}"));
        }
        let mut server = command
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
            backend_hits,
            backend_task,
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

#[tokio::test]
async fn applies_request_response_and_redirect_rules() {
    let fixture = Fixture::start(None, false, false).await;

    let clean = send_request(&fixture, "GET", "/clean.txt", "", "").await;
    assert_eq!(clean.status, 200);
    assert_eq!(clean.body, b"clean response");

    let query = send_request(&fixture, "GET", "/clean.txt?q=block", "", "").await;
    assert_eq!(query.status, 403);

    let header = send_request(&fixture, "GET", "/clean.txt", "X-Block: yes\r\n", "").await;
    assert_eq!(header.status, 406);

    let redirect = send_request(&fixture, "GET", "/clean.txt?q=redirect", "", "").await;
    assert_eq!(redirect.status, 302);
    assert_eq!(
        redirect.headers.get("location").map(String::as_str),
        Some("https://example.test/blocked")
    );

    let response_body = send_request(&fixture, "GET", "/secret.txt", "", "").await;
    assert_eq!(response_body.status, 500);
    assert!(
        !response_body
            .body
            .windows(6)
            .any(|window| window == b"SECRET")
    );
}

#[tokio::test]
async fn blocks_request_body_before_fastcgi_backend() {
    let fixture = Fixture::start(None, true, false).await;
    let response = send_request(
        &fixture,
        "POST",
        "/app.php",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "comment=evil",
    )
    .await;
    assert_eq!(response.status, 418);
    assert_eq!(
        fixture
            .backend_hits
            .as_ref()
            .unwrap()
            .load(Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn enforces_request_body_limit() {
    let fixture = Fixture::start(Some(16), false, false).await;
    let response = send_request(
        &fixture,
        "POST",
        "/clean.txt",
        "Content-Type: text/plain\r\n",
        "this body is larger than sixteen bytes",
    )
    .await;
    assert_eq!(response.status, 413);
}

#[tokio::test]
async fn inspects_requests_routed_to_vhost_workers() {
    let fixture = Fixture::start(None, false, true).await;
    let clean =
        send_request_with_host(&fixture, "GET", "/clean.txt", "waf.example.test", "", "").await;
    assert_eq!(clean.status, 200);
    assert_eq!(clean.body, b"vhost response");

    let blocked = send_request_with_host(
        &fixture,
        "GET",
        "/clean.txt?q=block",
        "waf.example.test",
        "",
        "",
    )
    .await;
    assert_eq!(blocked.status, 403);
}

struct HttpResponse {
    status: u16,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
}

async fn send_request(
    fixture: &Fixture,
    method: &str,
    path: &str,
    extra_headers: &str,
    body: &str,
) -> HttpResponse {
    send_request_with_host(fixture, method, path, "example.test", extra_headers, body).await
}

async fn send_request_with_host(
    fixture: &Fixture,
    method: &str,
    path: &str,
    host: &str,
    extra_headers: &str,
    body: &str,
) -> HttpResponse {
    let mut stream = TcpStream::connect(fixture.address).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra_headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    parse_response(&raw)
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let separator = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response header terminator");
    let headers = String::from_utf8_lossy(&raw[..separator]);
    let mut lines = headers.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .expect("HTTP response status");
    let headers = lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_owned()))
        })
        .collect();
    HttpResponse {
        status,
        headers,
        body: raw[separator + 4..].to_vec(),
    }
}

fn rules() -> &'static str {
    r#"SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule ARGS:q "@streq block" "id:100001,phase:1,deny,status:403,log"
SecRule REQUEST_HEADERS:X-Block "@streq yes" "id:100002,phase:1,deny,status:406,log"
SecRule ARGS:q "@streq redirect" "id:100003,phase:1,redirect:'https://example.test/blocked',status:302,log"
SecRule ARGS:comment "@contains evil" "id:100004,phase:2,deny,status:418,log"
SecRule RESPONSE_BODY "@contains SECRET" "id:100005,phase:4,deny,status:500,log"
"#
}
