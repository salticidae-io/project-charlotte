//! Integration tests for client connection and handshake timeouts/limits.

#![forbid(unsafe_code)]

mod common;

use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use rcgen::{CertificateParams, KeyPair};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct RunningServer {
    child: Child,
    root: PathBuf,
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        common::shutdown(&mut self.child);
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn new_root() -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "project-charlotte-limits-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("index.html"), "ready").unwrap();
    root
}

fn start_server(root: &Path, address: SocketAddr, extra_args: &[&str]) -> RunningServer {
    let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
    command
        .arg("--bind")
        .arg(address.to_string())
        .args(extra_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if cfg!(feature = "hosting") {
        command.arg("--root").arg(root);
    }
    RunningServer {
        child: common::spawn(&mut command).unwrap(),
        root: root.to_owned(),
    }
}

async fn wait_until_ready(server: &mut RunningServer, address: SocketAddr) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            panic!("server exited before listening: {status}");
        }
        if TcpStream::connect(address).await.is_ok() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "server did not become ready"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

async fn assert_client_is_closed(address: SocketAddr, initial_bytes: Option<&[u8]>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    if let Some(bytes) = initial_bytes {
        stream.write_all(bytes).await.unwrap();
    }
    let started = tokio::time::Instant::now();
    let mut byte = [0; 1];
    let count = timeout(Duration::from_secs(4), stream.read(&mut byte))
        .await
        .expect("connection remained open beyond the timeout")
        .unwrap();
    assert_eq!(count, 0, "server sent unexpected bytes: {byte:?}");
    assert!(started.elapsed() >= Duration::from_millis(700));
}

#[tokio::test]
async fn closes_clients_that_send_no_bytes_or_an_incomplete_request_head() {
    let root = new_root();
    let address = common::reserve_tcp_address();
    let mut server = start_server(&root, address, &["--header-read-timeout", "1"]);
    wait_until_ready(&mut server, address).await;

    assert_client_is_closed(address, None).await;
    assert_client_is_closed(address, Some(b"GET / HTTP/1.1\r\nHost: example.test")).await;
}

#[tokio::test]
async fn tls_handshake_timeout_closes_a_client_that_sends_nothing() {
    let root = new_root();
    let cert_path = root.join("server.pem");
    let key_path = root.join("server-key.pem");
    let params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    fs::write(&cert_path, certificate.pem()).unwrap();
    fs::write(&key_path, key.serialize_pem()).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

    let address = common::reserve_tcp_address();
    let mut server = start_server(
        &root,
        address,
        &[
            "--no-plain-http",
            "--tls-bind",
            &address.to_string(),
            "--tls-cert",
            cert_path.to_str().unwrap(),
            "--tls-key",
            key_path.to_str().unwrap(),
            "--tls-handshake-timeout",
            "1",
        ],
    );
    wait_until_ready(&mut server, address).await;

    assert_client_is_closed(address, None).await;
}

#[tokio::test]
async fn max_connections_waits_for_an_existing_connection_to_close() {
    let root = new_root();
    let address = common::reserve_tcp_address();
    let mut server = start_server(&root, address, &["--max-connections", "1"]);
    wait_until_ready(&mut server, address).await;

    let first = TcpStream::connect(address).await.unwrap();
    sleep(Duration::from_millis(100)).await;
    let mut second = TcpStream::connect(address).await.unwrap();
    second
        .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut byte = [0; 1];
    assert!(
        timeout(Duration::from_millis(250), second.read(&mut byte))
            .await
            .is_err()
    );

    drop(first);
    let mut response = Vec::new();
    timeout(Duration::from_secs(4), second.read_to_end(&mut response))
        .await
        .expect("queued connection was not served after the first closed")
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 "), "{response:?}");
}
