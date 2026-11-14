//! Integration tests for file-backed access and error logs.

#![forbid(unsafe_code)]
#![cfg(feature = "hosting")]

#[path = "common/mod.rs"]
mod common;

use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::sleep,
};

async fn get(address: std::net::SocketAddr, path: &str, host: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(8), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}

async fn wait_for_line(path: &Path, needle: &str) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        if content.contains(needle) {
            return content;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "{} never contained {needle:?}; content: {content:?}",
                path.display()
            );
        }
        sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn writes_global_and_vhost_access_and_error_logs() {
    let base =
        std::env::temp_dir().join(format!("project-charlotte-logging-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let site = base.join("site");
    let fallback = base.join("fallback");
    std::fs::create_dir_all(&site).unwrap();
    std::fs::create_dir_all(&fallback).unwrap();
    std::fs::write(fallback.join("static.txt"), "fallback").unwrap();
    let script = site.join("noisy.cgi");
    std::fs::write(
        &script,
        "#!/bin/sh\necho 'script complaint' >&2\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok'\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let user = nix::unistd::User::from_uid(nix::unistd::geteuid())
        .unwrap()
        .unwrap()
        .name;
    let config = base.join("charlotte.yaml");
    std::fs::write(
        &config,
        format!(
            "vhost:\n  - server_names: [logs.example.test]\n    root: {:?}\n    user: {:?}\n    cgi: [cgi]\n    access_log: vhost-access.log\n    access_log_format: \"%v %>s %U %b\"\n    error_log: vhost-error.log\n    error_log_format: \"[%l] [client %a] %M\"\n",
            site.to_string_lossy(),
            user,
        ),
    )
    .unwrap();
    let global_access = base.join("access.log");
    let global_error = base.join("error.log");

    let address = common::reserve_tcp_address();
    let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
    command
        .arg("--bind")
        .arg(address.to_string())
        .arg("--root")
        .arg(&fallback)
        .arg("--config")
        .arg(&config)
        .arg("--access-log-file")
        .arg(&global_access)
        .arg("--access-log-format")
        .arg("common")
        .arg("--error-log-file")
        .arg(&global_error)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut server = common::spawn(&mut command).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(address).await.is_err() {
        if let Some(status) = server.try_wait().unwrap() {
            panic!("server exited before becoming ready: {status}");
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "server did not become ready"
        );
        sleep(Duration::from_millis(20)).await;
    }

    let response = get(address, "/noisy.cgi", "logs.example.test").await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let response = get(address, "/static.txt", "localhost").await;
    assert!(response.starts_with(b"HTTP/1.1 200"));

    let vhost_access = wait_for_line(&base.join("vhost-access.log"), "noisy.cgi").await;
    assert!(
        vhost_access.contains("logs.example.test 200 /noisy.cgi 2"),
        "{vhost_access}"
    );
    let vhost_error = wait_for_line(&base.join("vhost-error.log"), "script complaint").await;
    assert!(
        vhost_error.contains("[error] [client 127.0.0.1] CGI stderr: script complaint"),
        "{vhost_error}"
    );
    assert!(!vhost_error.contains("GET /"), "{vhost_error}");
    let access = wait_for_line(&global_access, "static.txt").await;
    assert!(access.contains("127.0.0.1 - - ["), "{access}");
    assert!(
        access.contains("\"GET /static.txt HTTP/1.1\" 200 8"),
        "{access}"
    );
    assert!(!access.contains("noisy.cgi"), "{access}");
    assert!(global_error.exists());
    let global_error = std::fs::read_to_string(&global_error).unwrap();
    assert!(!global_error.contains("GET /"), "{global_error}");

    common::shutdown(&mut server);
    let _ = std::fs::remove_dir_all(&base);
}
