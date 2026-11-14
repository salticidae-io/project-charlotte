#![forbid(unsafe_code)]
#![cfg(feature = "hosting")]

mod common;

use std::{
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use nix::unistd::{User, geteuid};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixStream},
    time::sleep,
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    address: SocketAddr,
    socket: PathBuf,
    server: Child,
}

impl Fixture {
    async fn start() -> Self {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "project-charlotte-control-{}-{id}",
            std::process::id()
        ));
        let document_root = root.join("fallback");
        let vhost_dir = root.join("vhosts");
        std::fs::create_dir_all(&document_root).unwrap();
        std::fs::create_dir_all(&vhost_dir).unwrap();
        std::fs::write(document_root.join("index.html"), "fallback").unwrap();
        let config_file = root.join("vhosts.yaml");
        std::fs::write(&config_file, "vhost: []\n").unwrap();
        let socket = root.join("control.sock");
        let address = common::reserve_tcp_address();
        let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
        command
            .arg("--bind")
            .arg(address.to_string())
            .arg("--root")
            .arg(&document_root)
            .arg("--config")
            .arg(&config_file)
            .arg("--vhost-dir")
            .arg(&vhost_dir)
            .arg("--control-socket")
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let mut server = common::spawn(&mut command).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if socket.exists() && TcpStream::connect(address).await.is_ok() {
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
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o600
        );

        Self {
            root,
            address,
            socket,
            server,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        common::shutdown(&mut self.server);
        assert!(
            !self.socket.exists(),
            "control socket should be removed on shutdown"
        );
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

async fn control_request(socket: &PathBuf, method: &str, path: &str, body: &[u8]) -> HttpResponse {
    let mut stream = tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(socket))
        .await
        .unwrap()
        .unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    parse_response(&response)
}

async fn site_request(address: SocketAddr, host: &str) -> HttpResponse {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    parse_response(&response)
}

fn parse_response(response: &[u8]) -> HttpResponse {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response headers should end");
    let status = std::str::from_utf8(&response[..header_end])
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    HttpResponse {
        status,
        body: response[header_end + 4..].to_vec(),
    }
}

fn vhost_json(name: &str, root: &std::path::Path, user: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "server_names": [name],
        "root": root.display().to_string(),
        "user": user,
    }))
    .unwrap()
}

#[tokio::test]
async fn control_socket_validates_persists_and_routes_vhost_crud() {
    let fixture = Fixture::start().await;
    let document_root = fixture.root.join("site");
    std::fs::create_dir_all(&document_root).unwrap();
    std::fs::write(document_root.join("index.html"), "managed site").unwrap();
    let user = User::from_uid(geteuid()).unwrap().unwrap().name;
    let valid = vhost_json("control.example", &document_root, &user);

    let response = control_request(&fixture.socket, "PUT", "/vhosts/site", &valid).await;
    assert_eq!(response.status, 200);
    let config_file = fixture.root.join("vhosts/site.yaml");
    assert!(config_file.exists());
    assert_eq!(
        std::fs::metadata(&config_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o640
    );
    let response = site_request(fixture.address, "control.example").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"managed site");

    let response = control_request(&fixture.socket, "GET", "/vhosts/site", b"").await;
    assert_eq!(response.status, 200);
    let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(value["vhost"][0]["server_names"][0], "control.example");
    let response = control_request(&fixture.socket, "GET", "/vhosts", b"").await;
    assert_eq!(response.status, 200);
    let list: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "site")
    );

    let response = control_request(&fixture.socket, "POST", "/vhosts/site", &valid).await;
    assert_eq!(response.status, 409);

    let racing_vhost = vhost_json("race.example", &document_root, &user);
    let (first, second) = tokio::join!(
        control_request(&fixture.socket, "POST", "/vhosts/race", &racing_vhost),
        control_request(&fixture.socket, "POST", "/vhosts/race", &racing_vhost),
    );
    let mut statuses = [first.status, second.status];
    statuses.sort_unstable();
    assert_eq!(statuses, [201, 409]);
    assert_eq!(
        control_request(&fixture.socket, "DELETE", "/vhosts/race", b"")
            .await
            .status,
        204
    );

    let before = std::fs::read(&config_file).unwrap();
    let invalid = br#"{"server_names":["control.example"],"root":"/tmp","unknown":true}"#;
    let response = control_request(&fixture.socket, "PUT", "/vhosts/site", invalid).await;
    assert_eq!(response.status, 400);
    assert_eq!(std::fs::read(&config_file).unwrap(), before);
    let response = site_request(fixture.address, "control.example").await;
    assert_eq!(response.body, b"managed site");

    let duplicate = vhost_json("control.example", &document_root, &user);
    let response = control_request(&fixture.socket, "PUT", "/vhosts/duplicate", &duplicate).await;
    assert_eq!(response.status, 400);
    assert!(!fixture.root.join("vhosts/duplicate.yaml").exists());
    assert_eq!(
        control_request(&fixture.socket, "GET", "/vhosts/bad%2fname", b"")
            .await
            .status,
        400
    );

    let response = control_request(&fixture.socket, "GET", "/status", b"").await;
    assert_eq!(response.status, 200);
    let status: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(status["vhosts"], 1);
    let response = control_request(&fixture.socket, "PATCH", "/vhosts/site", b"").await;
    assert_eq!(response.status, 405);
    let oversized = vec![b' '; 1024 * 1024 + 1];
    let response = control_request(&fixture.socket, "PUT", "/vhosts/site", &oversized).await;
    assert_eq!(response.status, 413);

    let response = control_request(&fixture.socket, "DELETE", "/vhosts/site", b"").await;
    assert_eq!(response.status, 204);
    assert!(!config_file.exists());
    assert_eq!(
        control_request(&fixture.socket, "GET", "/vhosts/site", b"")
            .await
            .status,
        404
    );
    let response = site_request(fixture.address, "control.example").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"fallback");
}
