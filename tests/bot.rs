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
        Self::start_with_args(bot, vhost, &[], false).await
    }

    async fn start_with_args(
        bot: Option<&str>,
        vhost: Option<String>,
        extra_args: &[String],
        capture_error_log: bool,
    ) -> Self {
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
        for argument in extra_args {
            command.arg(argument.replace("$ROOT", root.to_string_lossy().as_ref()));
        }
        if capture_error_log {
            command.arg("--error-log-file").arg(root.join("error.log"));
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
    request_method(address, host, "GET", path, headers).await
}

async fn request_method(
    address: SocketAddr,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> HttpResponse {
    let mut stream = tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(address))
        .await
        .unwrap()
        .unwrap();
    let mut message = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
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
async fn busy_bot_policy_is_inactive_until_server_traffic_crosses_threshold() {
    let fixture = Fixture::start(
        Some("busy_threshold: 20/s\nbusy_window: 1\nbusy_cooldown: 30\nverify_crawlers: false\n"),
        None,
    )
    .await;
    let scanner = [("user-agent", "nuclei/3.0")];
    assert_eq!(
        request(fixture.address, "localhost", "/", &scanner)
            .await
            .status,
        200
    );

    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..30 {
        let address = fixture.address;
        requests.spawn(async move {
            request(
                address,
                "localhost",
                "/",
                &[
                    ("user-agent", "Mozilla/5.0 Chrome/130.0"),
                    ("accept", "text/html"),
                    ("accept-language", "en-US"),
                ],
            )
            .await
        });
    }
    while let Some(result) = requests.join_next().await {
        result.unwrap();
    }

    assert_eq!(
        request(fixture.address, "localhost", "/", &scanner)
            .await
            .status,
        403
    );
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

#[tokio::test]
async fn log_mode_allows_scanners_and_records_the_log_action() {
    let fixture =
        Fixture::start_with_args(Some("mode: log\nverify_crawlers: false\n"), None, &[], true)
            .await;
    let response = request(
        fixture.address,
        "localhost",
        "/",
        &[("user-agent", "nuclei/3.0")],
    )
    .await;
    assert_eq!(response.status, 200);

    let log_path = fixture.root.join("error.log");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
        if contents.contains("action=Log") {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "bot log entry was not written: {contents:?}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn deny_and_allow_ip_ranges_apply_to_all_user_agents() {
    let denied_fixture = Fixture::start(
        Some("deny_ips: [127.0.0.1]\nverify_crawlers: false\n"),
        None,
    )
    .await;
    let denied = request(
        denied_fixture.address,
        "localhost",
        "/",
        &[
            ("user-agent", "Mozilla/5.0 Chrome/130.0"),
            ("accept", "text/html"),
            ("accept-language", "en-US"),
        ],
    )
    .await;
    assert_eq!(denied.status, 403);
    drop(denied_fixture);

    let allowed_fixture = Fixture::start(Some("allow_ips: [127.0.0.0/8]\n"), None).await;
    let scanner = request(
        allowed_fixture.address,
        "localhost",
        "/",
        &[("user-agent", "nuclei/3.0")],
    )
    .await;
    assert_eq!(scanner.status, 200);
}

#[tokio::test]
async fn disabling_challenges_allows_automation_but_still_blocks_scanners() {
    let fixture = Fixture::start(Some("challenge: false\nverify_crawlers: false\n"), None).await;
    let automation = request(
        fixture.address,
        "localhost",
        "/",
        &[("user-agent", "curl/8.0")],
    )
    .await;
    let scanner = request(
        fixture.address,
        "localhost",
        "/",
        &[("user-agent", "nuclei/3.0")],
    )
    .await;
    assert_eq!(automation.status, 200);
    assert_eq!(scanner.status, 403);
}

#[tokio::test]
async fn challenge_route_rejects_bad_solutions_and_tampered_cookies() {
    let fixture = Fixture::start(Some("verify_crawlers: false\n"), None).await;
    for (method, path) in [
        ("GET", "/.well-known/charlotte-bot-challenge"),
        (
            "GET",
            "/.well-known/charlotte-bot-challenge?exp=1&seed=bad&nonce=x&return=%2F",
        ),
        ("POST", "/.well-known/charlotte-bot-challenge"),
    ] {
        let response = request_method(
            fixture.address,
            "localhost",
            method,
            path,
            &[("user-agent", "curl/8.0")],
        )
        .await;
        assert_eq!(response.status, 403, "{method} {path}");
    }

    let challenge = request(
        fixture.address,
        "localhost",
        "/welcome",
        &[("user-agent", "curl/8.0")],
    )
    .await;
    let seed = challenge
        .body
        .split("const seed='")
        .nth(1)
        .and_then(|value| value.split('\'').next())
        .expect("challenge response should contain its seed");
    let expires = challenge
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
            "/.well-known/charlotte-bot-challenge?exp={expires}&seed={seed}&nonce={nonce}&return=%2Fwelcome"
        ),
        &[("user-agent", "curl/8.0")],
    )
    .await;
    assert_eq!(solution.status, 303);
    let mut cookie = solution
        .headers
        .get("set-cookie")
        .and_then(|value| value.split(';').next())
        .expect("valid challenge should set a cookie")
        .to_owned();
    let last = cookie.pop().unwrap();
    cookie.push(if last == '0' { '1' } else { '0' });
    let retry = request(
        fixture.address,
        "localhost",
        "/",
        &[("user-agent", "curl/8.0"), ("cookie", &cookie)],
    )
    .await;
    assert_eq!(retry.status, 403);
    assert!(retry.body.contains("Checking your browser"));
}

#[tokio::test]
async fn trusted_proxy_honeypot_ban_is_scoped_to_forwarded_client() {
    let extra_args = vec!["--trusted-proxy".to_owned(), "127.0.0.1".to_owned()];
    let fixture = Fixture::start_with_args(
        Some("verify_crawlers: false\nhoneypot_paths: [/hidden]\nhoneypot_ban: 60\n"),
        None,
        &extra_args,
        false,
    )
    .await;
    let trap = request(
        fixture.address,
        "localhost",
        "/hidden",
        &[("x-forwarded-for", "192.0.2.31")],
    )
    .await;
    assert_eq!(trap.status, 403);

    let browser_headers = [
        ("user-agent", "Mozilla/5.0 Chrome/130.0"),
        ("accept", "text/html"),
        ("accept-language", "en-US"),
    ];
    let banned = request(
        fixture.address,
        "localhost",
        "/",
        &[
            browser_headers[0],
            browser_headers[1],
            browser_headers[2],
            ("x-forwarded-for", "192.0.2.31"),
        ],
    )
    .await;
    let unaffected = request(
        fixture.address,
        "localhost",
        "/",
        &[
            browser_headers[0],
            browser_headers[1],
            browser_headers[2],
            ("x-forwarded-for", "192.0.2.32"),
        ],
    )
    .await;
    assert_eq!(banned.status, 403);
    assert_eq!(unaffected.status, 200);
}

#[test]
fn invalid_bot_policy_stops_server_startup() {
    let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "project-charlotte-bot-invalid-{}-{id}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("bot.yaml"),
        "challenge_threshold: 90\nblock_threshold: 80\n",
    )
    .unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
    command
        .arg("--bind")
        .arg(common::reserve_tcp_address().to_string())
        .arg("--root")
        .arg(&root)
        .arg("--bot-config")
        .arg(root.join("bot.yaml"));
    let output = common::output(&mut command).unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("challenge_threshold"));
}

#[tokio::test]
async fn vhost_bot_policy_replaces_the_global_policy() {
    let Some(user) = worker_user() else {
        return;
    };
    let config = format!(
        "vhost:\n  - server_names: [policy.example]\n    root: BOT_TEST_SITE_ROOT\n    user: {:?}\n    bot:\n      deny_user_agents: [vhost-bad]\n      verify_crawlers: false\n",
        user
    );
    let fixture = Fixture::start(
        Some("deny_user_agents: [global-bad]\nverify_crawlers: false\n"),
        Some(config),
    )
    .await;
    let inherited_rule_removed = request(
        fixture.address,
        "policy.example",
        "/",
        &[("user-agent", "global-bad")],
    )
    .await;
    let vhost_rule_applied = request(
        fixture.address,
        "policy.example",
        "/",
        &[("user-agent", "vhost-bad")],
    )
    .await;
    assert_eq!(inherited_rule_removed.status, 200);
    assert_eq!(vhost_rule_applied.status, 403);
}
