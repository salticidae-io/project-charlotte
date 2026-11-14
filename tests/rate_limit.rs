//! Integration tests for global rate limits and virtual-host overrides.

#![forbid(unsafe_code)]
#![cfg(feature = "hosting")]

mod common;

use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use nix::unistd::{User, geteuid};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::sleep,
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fixture {
    root: PathBuf,
    address: SocketAddr,
    server: Child,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    async fn start() -> Self {
        let guard = TEST_LOCK.lock().await;
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "project-charlotte-rate-limit-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.html"), "rate limit test").unwrap();
        let user = worker_user();
        let config_path = root.join("vhosts.yaml");
        std::fs::write(
            &config_path,
            format!(
                "vhost:\n  - server_names: [exempt.test]\n    root: {:?}\n    user: {:?}\n    rate_limit: off\n",
                root.to_string_lossy(),
                user,
            ),
        )
        .unwrap();

        let address = common::reserve_tcp_address();
        let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
        command
            .arg("--bind")
            .arg(address.to_string())
            .arg("--root")
            .arg(&root)
            .arg("--config")
            .arg(config_path)
            .arg("--rate-limit")
            .arg("1/m")
            .arg("--rate-limit-burst")
            .arg("2")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let mut server = common::spawn(&mut command).unwrap();

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
            _guard: guard,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        common::shutdown(&mut self.server);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn worker_user() -> String {
    let current = User::from_uid(geteuid()).unwrap().unwrap();
    if current.uid.as_raw() != 0 {
        current.name
    } else {
        User::from_name("nobody").unwrap().unwrap().name
    }
}

async fn request(address: SocketAddr, host: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!("GET /index.html HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn enforces_global_limit_and_allows_vhost_override() {
    let fixture = Fixture::start().await;

    assert!(
        request(fixture.address, "fallback.test")
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        request(fixture.address, "fallback.test")
            .await
            .starts_with("HTTP/1.1 200")
    );

    let limited = request(fixture.address, "fallback.test").await;
    assert!(limited.starts_with("HTTP/1.1 429"), "{limited}");
    assert!(
        limited
            .lines()
            .any(|line| line.eq_ignore_ascii_case("retry-after: 60"))
    );

    let exempt = request(fixture.address, "exempt.test").await;
    assert!(exempt.starts_with("HTTP/1.1 200"), "{exempt}");
}
