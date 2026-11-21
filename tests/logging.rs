//! Integration tests for file-backed access and error logs.

#![forbid(unsafe_code)]
#![cfg(feature = "hosting")]

#[path = "common/mod.rs"]
mod common;

use std::{
    io::Read,
    net::TcpListener,
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

#[tokio::test]
async fn debug_startup_logs_listener_binding_to_stderr() {
    let root = std::env::temp_dir().join(format!(
        "project-charlotte-debug-logging-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let address = common::reserve_tcp_address();
    let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
    command
        .arg("--debug")
        .arg("--bind")
        .arg(address.to_string())
        .arg("--root")
        .arg(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut server = common::spawn(&mut command).unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while TcpStream::connect(address).await.is_err() {
        if let Some(status) = server.try_wait().unwrap() {
            panic!("server exited before becoming ready: {status}");
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "server did not start"
        );
        sleep(Duration::from_millis(20)).await;
    }
    common::shutdown(&mut server);
    let mut log = String::new();
    server
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();

    assert!(log.contains("Binding plain HTTP listener"), "{log}");
    assert!(log.contains("Bound plain HTTP listener"), "{log}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn startup_errors_default_to_stderr_without_an_error_log() {
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = occupied.local_addr().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .arg("--bind")
        .arg(address.to_string())
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("could not bind TCP listener"), "{stderr}");
    assert!(stderr.contains(&address.to_string()), "{stderr}");
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires root; run in the privileged CI job with cargo test -- --ignored"]
async fn root_helper_opens_vhost_logs_after_master_drops_privileges() {
    use std::os::unix::fs::MetadataExt;

    assert!(nix::unistd::geteuid().is_root(), "this test requires root");
    let user = nix::unistd::User::from_name("nobody")
        .unwrap()
        .expect("root test environment must provide the nobody account");
    let group = nix::unistd::Group::from_gid(user.gid)
        .unwrap()
        .expect("nobody's primary group must exist");

    let base = std::env::temp_dir().join(format!(
        "project-charlotte-root-logopener-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    let site = base.join("site");
    std::fs::create_dir_all(&site).unwrap();
    let script = site.join("noisy.cgi");
    std::fs::write(
        &script,
        "#!/bin/sh\necho 'script complaint' >&2\nprintf 'Content-Type: text/plain\\r\\n\\r\\nok'\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = base.join("charlotte.yaml");
    std::fs::write(
        &config,
        format!(
            "vhost:\n  - server_names: [logs.example.test]\n    root: {:?}\n    user: {:?}\n    cgi: [cgi]\n    access_log: vhost-access.log\n    access_log_format: \"%v %>s %U %b\"\n    error_log: vhost-error.log\n",
            site.to_string_lossy(),
            user.name,
        ),
    )
    .unwrap();
    let address = common::reserve_tcp_address();
    let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
    command
        .arg("--user")
        .arg(&user.name)
        .arg("--group")
        .arg(&group.name)
        .arg("--bind")
        .arg(address.to_string())
        .arg("--root")
        .arg(&site)
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut server = common::spawn(&mut command).unwrap();
    let pid = server.id();
    let vhost_log = base.join("vhost-access.log");
    let vhost_error_log = base.join("vhost-error.log");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = server.try_wait().unwrap() {
            panic!("server exited before opening the vhost log: {status}");
        }
        let master_uid = process_effective_uid(pid);
        let master_gid = process_effective_gid(pid);
        let root_helper_running = process_children(pid)
            .iter()
            .any(|child| process_effective_uid(*child) == Some(0));
        if master_uid == Some(user.uid.as_raw())
            && master_gid == Some(group.gid.as_raw())
            && root_helper_running
            && vhost_log.exists()
            && vhost_error_log.exists()
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "master/helper privilege split or vhost log open did not complete"
        );
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(std::fs::metadata(&vhost_log).unwrap().uid(), 0);
    assert_eq!(std::fs::metadata(&vhost_error_log).unwrap().uid(), 0);
    // The master keeps no capability that could restore its privileges: the
    // root helper is what starts workers under other accounts.
    let capabilities = process_permitted_capabilities(pid).unwrap();
    const IDENTITY_CAPABILITIES: u64 = (1 << 1) | (1 << 5) | (1 << 6) | (1 << 7);
    assert_eq!(capabilities & IDENTITY_CAPABILITIES, 0, "{capabilities:#x}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
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
    let access = wait_for_line(&vhost_log, "noisy.cgi").await;
    assert!(
        access.contains("logs.example.test 200 /noisy.cgi"),
        "{access}"
    );
    let error = wait_for_line(&vhost_error_log, "script complaint").await;
    assert!(error.contains("script complaint"), "{error}");

    common::shutdown(&mut server);
    let _ = std::fs::remove_dir_all(&base);
}

#[cfg(target_os = "linux")]
fn process_permitted_capabilities(pid: u32) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("CapPrm:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
}

#[cfg(target_os = "linux")]
fn process_effective_uid(pid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("Uid:")
                .and_then(|values| values.split_whitespace().nth(1))
                .and_then(|value| value.parse().ok())
        })
}

#[cfg(target_os = "linux")]
fn process_effective_gid(pid: u32) -> Option<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("Gid:")
                .and_then(|values| values.split_whitespace().nth(1))
                .and_then(|value| value.parse().ok())
        })
}

#[cfg(target_os = "linux")]
fn process_children(pid: u32) -> Vec<u32> {
    std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|value| value.parse().ok())
        .collect()
}
