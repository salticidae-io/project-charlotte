//! Integration tests for the Unix-socket control API and virtual-host mutations.

#![forbid(unsafe_code)]
#![cfg(feature = "hosting")]

mod common;

use std::{
    io::Write,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
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

fn control_cli(socket: &Path, arguments: &[&str], input: Option<&[u8]>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_charlotte-ctl"));
    command
        .arg("--socket")
        .arg(socket)
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    let mut child = common::spawn(&mut command).unwrap();
    if let Some(input) = input {
        child.stdin.take().unwrap().write_all(input).unwrap();
    }
    child.wait_with_output().unwrap()
}

fn control_cli_from_environment(socket: &Path, arguments: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_charlotte-ctl"));
    command
        .env("CHARLOTTE_CONTROL_SOCKET", socket)
        .args(arguments);
    common::output(&mut command).unwrap()
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
    let site_traffic = &status["traffic"]["vhosts"]["control.example"];
    assert_eq!(site_traffic["requests"], 2);
    assert_eq!(site_traffic["client_errors"], 0);
    assert_eq!(site_traffic["server_errors"], 0);
    assert_eq!(site_traffic["bytes_out"], 2 * b"managed site".len() as u64);
    assert!(status["traffic"]["total"]["requests"].as_u64().unwrap() >= 2);
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

#[tokio::test]
async fn control_options_api_validates_persists_and_preserves_main_config() {
    let fixture = Fixture::start().await;
    let config_file = fixture.root.join("vhosts.yaml");
    let original_mode = std::fs::metadata(&config_file)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;

    let response = control_request(&fixture.socket, "GET", "/options", b"").await;
    assert_eq!(response.status, 200);
    let initial: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(initial["writable"], true);
    assert_eq!(initial["options"], serde_json::json!({}));
    assert_eq!(initial["restart_required"], false);
    assert!(
        initial["command_line"]
            .as_array()
            .unwrap()
            .iter()
            .any(|name| name == "bind")
    );
    let max_connections = initial["schema"]
        .as_array()
        .unwrap()
        .iter()
        .find(|option| option["name"] == "max_connections")
        .unwrap();
    assert_eq!(max_connections["kind"], "value");
    assert_eq!(
        max_connections["min"].as_f64(),
        Some(1.0),
        "{max_connections}"
    );

    let update = br#"{"debug":true,"header-read-timeout":31,"index":["home.html","index.html"]}"#;
    let response = control_request(&fixture.socket, "PUT", "/options", update).await;
    assert_eq!(
        response.status,
        200,
        "{}",
        String::from_utf8_lossy(&response.body)
    );
    let saved: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(saved["restart_required"], true);
    assert_eq!(saved["options"]["debug"], true);
    assert_eq!(saved["options"]["header_read_timeout"], 31);
    assert_eq!(
        saved["options"]["index"],
        serde_json::json!(["home.html", "index.html"])
    );
    let document: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&std::fs::read_to_string(&config_file).unwrap()).unwrap();
    let mapping = document.as_mapping().unwrap();
    assert!(mapping.contains_key(serde_yaml_ng::Value::String("vhost".to_owned())));
    assert_eq!(
        std::fs::metadata(&config_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        original_mode
    );

    let before_invalid = std::fs::read(&config_file).unwrap();
    for invalid in [
        br#"{"unknown_option":true}"#.as_slice(),
        br#"{"header_read_timeout":"not-a-number"}"#.as_slice(),
    ] {
        let response = control_request(&fixture.socket, "PUT", "/options", invalid).await;
        assert_eq!(response.status, 400);
        assert!(!String::from_utf8_lossy(&response.body).contains(".options-"));
        assert_eq!(std::fs::read(&config_file).unwrap(), before_invalid);
    }

    let response = control_request(&fixture.socket, "GET", "/options", b"").await;
    assert_eq!(response.status, 200);
    let current: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(current["options"], saved["options"]);
    assert_eq!(current["restart_required"], true);
}

#[tokio::test]
async fn control_cli_reads_and_replaces_global_options() {
    let fixture = Fixture::start().await;

    let output = control_cli(&fixture.socket, &["options"], None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let options: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(options["options"], serde_json::json!({}));

    let output = control_cli(
        &fixture.socket,
        &["set-options"],
        Some(br#"{"debug":true,"max_connections":2048}"#),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let saved: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(saved["options"]["debug"], true);
    assert_eq!(saved["options"]["max_connections"], 2048);
}

#[tokio::test]
async fn control_cli_supports_socket_operations() {
    let fixture = Fixture::start().await;
    let document_root = fixture.root.join("site");
    std::fs::create_dir_all(&document_root).unwrap();
    let user = User::from_uid(geteuid()).unwrap().unwrap().name;
    let site_config = vhost_json("control.example", &document_root, &user);

    let output = control_cli(&fixture.socket, &["put", "site"], Some(&site_config));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let put: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(put["name"], "site");
    assert!(String::from_utf8_lossy(&output.stdout).contains("\n  \"name\": \"site\""));

    let output = control_cli(&fixture.socket, &["get", "site"], None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let get: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(get["vhost"][0]["server_names"][0], "control.example");

    let output = control_cli(&fixture.socket, &["apply", "site", "-"], Some(&site_config));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = control_cli(&fixture.socket, &["list"], None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let list: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        list.as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "site")
    );

    let created_config = vhost_json("created.example", &document_root, &user);
    let config_file = fixture.root.join("created.yaml");
    std::fs::write(&config_file, &created_config).unwrap();
    let output = control_cli(
        &fixture.socket,
        &["create", "-created", config_file.to_str().unwrap()],
        None,
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let create: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(create["name"], "-created");

    let output = control_cli(
        &fixture.socket,
        &["create", "site", "-"],
        Some(&site_config),
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("virtual host already exists"));

    let output = control_cli(&fixture.socket, &["delete", "-created"], None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());

    let output = control_cli(&fixture.socket, &["status"], None);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["vhosts"], 1);
    assert!(status["version"].is_string());

    let output = control_cli_from_environment(&fixture.socket, &["status"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["vhosts"], 1);
}
