//! Integration tests for graceful shutdown of idle and active connections.

#![cfg(all(target_os = "linux", feature = "hosting"))]
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

use nix::{
    sys::signal::{Signal, kill},
    unistd::{Pid, User, geteuid},
};
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
        "project-charlotte-shutdown-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    root
}

fn start_server(root: &Path, address: SocketAddr) -> RunningServer {
    let user = if geteuid().is_root() {
        User::from_name("nobody")
            .unwrap()
            .expect("root test environment must provide the nobody account")
    } else {
        User::from_uid(geteuid())
            .unwrap()
            .expect("test process must have a passwd entry")
    };
    let site = root.join("site");
    fs::create_dir_all(&site).unwrap();
    fs::set_permissions(&site, fs::Permissions::from_mode(0o777)).unwrap();
    let config = root.join("vhosts.yaml");
    fs::write(
        &config,
        format!(
            "vhost:\n  - server_names: [localhost]\n    root: {:?}\n    user: {:?}\n    cgi: [cgi]\n",
            site, user.name
        ),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
    command
        .arg("--bind")
        .arg(address.to_string())
        .arg("--root")
        .arg(root)
        .arg("--config")
        .arg(config)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    RunningServer {
        child: common::spawn(&mut command).unwrap(),
        root: root.to_path_buf(),
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

fn send_sigterm(server: &RunningServer) {
    let pid = i32::try_from(server.child.id()).unwrap();
    kill(Pid::from_raw(pid), Signal::SIGTERM).unwrap();
}

async fn wait_for_exit(server: &mut RunningServer, duration: Duration) -> std::process::ExitStatus {
    let deadline = tokio::time::Instant::now() + duration;
    loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            return status;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "server did not shut down promptly"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn sigterm_drains_an_in_flight_cgi_and_stops_its_worker() {
    let root = new_root();
    let site = root.join("site");
    fs::create_dir(&site).unwrap();
    let marker = site.join("cgi-started");
    let script = site.join("slow.cgi");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\n: > {:?}\nsleep 1\nprintf 'Content-Type: text/plain\\r\\n\\r\\nfinished'\n",
            marker
        ),
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let address = common::reserve_tcp_address();
    let mut server = start_server(&root, address);
    wait_until_ready(&mut server, address).await;
    let master_pid = server.child.id();

    let request = tokio::spawn(async move {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /slow.cgi HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !marker.exists() {
        if let Some(status) = server.child.try_wait().unwrap() {
            panic!("server exited before CGI began: {status}");
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "CGI script did not start"
        );
        sleep(Duration::from_millis(20)).await;
    }
    let worker_pid = common::descendants_with_argument(master_pid, "--worker")
        .into_iter()
        .next()
        .expect("hosted worker should be a direct child of the server");

    send_sigterm(&server);
    let response = timeout(Duration::from_secs(5), request)
        .await
        .expect("in-flight request did not complete during shutdown")
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
    assert!(
        response.windows(8).any(|window| window == b"finished"),
        "{response:?}"
    );
    assert!(
        wait_for_exit(&mut server, Duration::from_secs(5))
            .await
            .success()
    );
    assert!(
        !std::path::Path::new(&format!("/proc/{worker_pid}")).exists(),
        "hosted worker {worker_pid} survived master shutdown"
    );
}

#[tokio::test]
async fn sigterm_exits_promptly_when_the_server_is_idle() {
    let root = new_root();
    let address = common::reserve_tcp_address();
    let mut server = start_server(&root, address);
    wait_until_ready(&mut server, address).await;

    send_sigterm(&server);
    assert!(
        wait_for_exit(&mut server, Duration::from_secs(3))
            .await
            .success()
    );
}
