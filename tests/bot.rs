//! Integration tests for bot-detection policies, challenges, and crawler verification.

#![forbid(unsafe_code)]
#![cfg(feature = "hosting")]

mod common;

use std::{
    collections::HashMap,
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
    async fn start(bot: Option<&str>, vhost: Option<String>) -> Self {
        let guard = TEST_LOCK.lock().await;
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root =
            std::env::temp_dir().join(format!("project-charlotte-bot-{}-{id}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.html"), "bot test site").unwrap();

        let address = common::reserve_tcp_address();
        let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
        command
            .arg("--bind")
            .arg(address.to_string())
            .arg("--root")
            .arg(&root)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(policy) = bot {
            if policy.is_empty() {
                command.arg("--bot-detection");
            } else {
                let path = root.join("bot.yaml");
                std::fs::write(&path, policy).unwrap();
                command.arg("--bot-config").arg(path);
            }
        }
        if let Some(config) = vhost {
            let site = root.join("off-site");
            std::fs::create_dir_all(&site).unwrap();
            std::fs::write(site.join("index.html"), "vhost bot off").unwrap();
            let site_root = format!("{:?}", site.to_string_lossy());
            let config = config.replace("BOT_TEST_SITE_ROOT", &site_root);
            let path = root.join("vhosts.yaml");
            std::fs::write(&path, config).unwrap();
            command.arg("--config").arg(path);
        }
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

struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
}

async fn request(
    address: SocketAddr,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> HttpResponse {
    let mut stream = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(address))
        .await
        .unwrap()
        .unwrap();
    let mut message = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in headers {
        message.push_str(name);
        message.push_str(": ");
        message.push_str(value);
        message.push_str("\r\n");
    }
    message.push_str("\r\n");
    stream.write_all(message.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(8), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response headers should be complete");
    let response_headers = String::from_utf8_lossy(&response[..header_end]);
    let mut lines = response_headers.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split_ascii_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut response_headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            response_headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
    }
    let body = String::from_utf8_lossy(&response[header_end + 4..]).into_owned();
    HttpResponse {
        status,
        headers: response_headers,
        body,
    }
}

fn pow_nonce(seed: &str, difficulty: u8) -> u64 {
    (0_u64..)
        .find(|nonce| {
            let digest =
                ring::digest::digest(&ring::digest::SHA256, format!("{seed}{nonce}").as_bytes());
            let mut bits = 0_u8;
            for byte in digest.as_ref() {
                bits = bits.saturating_add(byte.leading_zeros() as u8);
                if *byte != 0 {
                    break;
                }
            }
            bits >= difficulty
        })
        .unwrap()
}

#[tokio::test]
async fn default_policy_blocks_scanners_and_challenges_automation() {
    let fixture = Fixture::start(Some(""), None).await;

    let scanner = request(
        fixture.address,
        "localhost",
        "/",
        &[("user-agent", "nuclei/3.0")],
    )
    .await;
    assert_eq!(scanner.status, 403);

    let automation = request(
        fixture.address,
        "localhost",
        "/",
        &[("user-agent", "curl/8.0")],
    )
    .await;
    assert_eq!(automation.status, 403);
    assert!(automation.body.contains("Checking your browser"));
}

#[tokio::test]
async fn challenge_completion_sets_cookie_and_allows_follow_up() {
    let fixture = Fixture::start(Some("verify_crawlers: false\n"), None).await;
    let challenge = request(
        fixture.address,
        "localhost",
        "/welcome?source=test",
        &[("user-agent", "curl/8.0")],
    )
    .await;
    assert_eq!(challenge.status, 403);
    let seed = challenge
        .body
        .split("const seed='")
        .nth(1)
        .and_then(|value| value.split('\'').next())
        .expect("challenge page should contain its seed");
    let expiry = challenge
        .body
        .split("exp=")
        .nth(1)
        .and_then(|value| value.split(',').next())
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let difficulty = challenge
        .body
        .split("difficulty=")
        .nth(1)
        .and_then(|value| value.split(',').next())
        .unwrap()
        .parse::<u8>()
        .unwrap();
    let nonce = pow_nonce(seed, difficulty);
    let solution = request(
        fixture.address,
        "localhost",
        &format!(
            "/.well-known/charlotte-bot-challenge?exp={expiry}&seed={seed}&nonce={nonce}&return=%2Fwelcome%3Fsource%3Dtest"
        ),
        &[("user-agent", "curl/8.0")],
    )
    .await;
    assert_eq!(solution.status, 303);
    assert_eq!(
        solution.headers.get("location").map(String::as_str),
        Some("/welcome?source=test")
    );
    let cookie = solution
        .headers
        .get("set-cookie")
        .and_then(|value| value.split(';').next())
        .unwrap()
        .to_owned();
    let follow_up = request(
        fixture.address,
        "localhost",
        "/",
        &[("user-agent", "curl/8.0"), ("cookie", &cookie)],
    )
    .await;
    assert_eq!(follow_up.status, 200);
}

#[tokio::test]
async fn honeypot_hit_bans_client_and_browser_headers_are_allowed() {
    let fixture = Fixture::start(
        Some("verify_crawlers: false\nhoneypot_paths: [/hidden]\n"),
        None,
    )
    .await;
    let trap = request(fixture.address, "localhost", "/hidden", &[]).await;
    assert_eq!(trap.status, 403);
    let banned = request(
        fixture.address,
        "localhost",
        "/",
        &[
            ("user-agent", "Mozilla/5.0 Chrome/130.0"),
            ("accept", "text/html"),
            ("accept-language", "en-US,en;q=0.9"),
            ("sec-fetch-mode", "navigate"),
        ],
    )
    .await;
    assert_eq!(banned.status, 403);
    drop(fixture);

    let browser_fixture = Fixture::start(Some("verify_crawlers: false\n"), None).await;
    let browser = request(
        browser_fixture.address,
        "localhost",
        "/",
        &[
            ("user-agent", "Mozilla/5.0 Chrome/130.0"),
            ("accept", "text/html"),
            ("accept-language", "en-US,en;q=0.9"),
            ("sec-fetch-mode", "navigate"),
        ],
    )
    .await;
    assert_eq!(browser.status, 200);
}

fn worker_user() -> Option<String> {
    if geteuid().is_root() {
        User::from_name("nobody")
            .ok()
            .flatten()
            .map(|user| user.name)
    } else {
        User::from_uid(geteuid())
            .ok()
            .flatten()
            .map(|user| user.name)
    }
}

#[tokio::test]
async fn vhost_bot_off_overrides_global_enforcement() {
    let Some(user) = worker_user() else {
        return;
    };
    let config = format!(
        "vhost:\n  - server_names: [off.example]\n    root: BOT_TEST_SITE_ROOT\n    user: {:?}\n    bot: off\n",
        user
    );
    let fixture = Fixture::start(Some("verify_crawlers: false\n"), Some(config)).await;
    let response = request(
        fixture.address,
        "off.example",
        "/",
        &[("user-agent", "nuclei/3.0")],
    )
    .await;
    assert_eq!(response.status, 200);
}
