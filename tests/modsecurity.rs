//! Integration tests for ModSecurity request and response inspection.

#![forbid(unsafe_code)]
#![cfg(feature = "hosting")]

mod common;

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
    async fn start(
        body_limit: Option<usize>,
        with_fastcgi: bool,
        with_vhost: bool,
        disable_vhost_rule: bool,
    ) -> Self {
        Self::start_with_rules(
            body_limit,
            with_fastcgi,
            with_vhost,
            disable_vhost_rule,
            None,
        )
        .await
    }

    async fn start_with_rules(
        body_limit: Option<usize>,
        with_fastcgi: bool,
        with_vhost: bool,
        disable_vhost_rule: bool,
        rules_path: Option<PathBuf>,
    ) -> Self {
        Self::start_with_options(
            body_limit,
            with_fastcgi,
            with_vhost,
            disable_vhost_rule,
            rules_path,
            &[],
            None,
        )
        .await
    }

    async fn start_with_options(
        body_limit: Option<usize>,
        with_fastcgi: bool,
        with_vhost: bool,
        disable_vhost_rule: bool,
        rules_path: Option<PathBuf>,
        extra_args: &[&str],
        vhost_block_status: Option<u16>,
    ) -> Self {
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
            let config_path = root.join("vhosts.yaml");
            let disable_rules = if disable_vhost_rule {
                "    modsecurity_disable_rules: [\"100001-100001\"]\n"
            } else {
                ""
            };
            let block_status = vhost_block_status
                .map(|status| format!("    modsecurity_block_status: {status}\n"))
                .unwrap_or_default();
            std::fs::write(
                &config_path,
                format!(
                    "vhost:\n  - server_names: [waf.example.test]\n    root: {:?}\n    user: {:?}\n{disable_rules}{block_status}",
                    vhost_root.to_string_lossy(),
                    user.name
                ),
            )
            .unwrap();
            vhost_config = Some(config_path);
        }

        let address = common::reserve_tcp_address();
        let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
        command
            .arg("--bind")
            .arg(address.to_string())
            .arg("--root")
            .arg(&root)
            .arg("--modsecurity-rules")
            .arg(rules_path.unwrap_or_else(|| root.join("rules.conf")));
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
        command.args(extra_args);
        command.stdout(Stdio::null()).stderr(Stdio::inherit());
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
        common::shutdown(&mut self.server);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn crs_example_blocks_common_attacks() {
    let Some(rules_path) = crs_example_rules() else {
        return;
    };
    let fixture = Fixture::start_with_rules(None, false, false, false, Some(rules_path)).await;

    let clean = send_request(&fixture, "GET", "/clean.txt", "", "").await;
    assert_eq!(clean.status, 200);
    let clean_query = send_request(&fixture, "GET", "/clean.txt?q=hello+world", "", "").await;
    assert_eq!(clean_query.status, 200);

    for (name, path) in [
        ("SQL injection", "/clean.txt?id=1%27%20OR%20%271%27=%271"),
        (
            "cross-site scripting",
            "/clean.txt?q=%3Cscript%3Ealert(1)%3C/script%3E",
        ),
        (
            "local file inclusion",
            "/clean.txt?file=../../../../etc/passwd",
        ),
        ("remote code execution", "/clean.txt?cmd=;cat%20/etc/passwd"),
        ("restricted file", "/.htaccess"),
    ] {
        let response = send_request(&fixture, "GET", path, "", "").await;
        assert_eq!(response.status, 403, "{name} should be blocked");
    }

    let scanner = send_request(&fixture, "GET", "/clean.txt", "User-Agent: Nikto\r\n", "").await;
    assert_eq!(scanner.status, 403, "scanner user-agent should be blocked");

    let body_sqli = send_request(
        &fixture,
        "POST",
        "/clean.txt",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "user=admin' UNION SELECT password FROM users--",
    )
    .await;
    assert_eq!(
        body_sqli.status, 403,
        "SQL injection in a body should be blocked"
    );

    let xss_header = send_request(
        &fixture,
        "GET",
        "/clean.txt",
        "Referer: <script>alert(1)</script>\r\n",
        "",
    )
    .await;
    assert_eq!(xss_header.status, 403, "XSS in a header should be blocked");

    let trace = send_request(&fixture, "TRACE", "/clean.txt", "", "").await;
    assert_eq!(trace.status, 403, "TRACE should be blocked");

    let benign_post = send_request(
        &fixture,
        "POST",
        "/clean.txt",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "name=alice&msg=hi",
    )
    .await;
    assert_ne!(benign_post.status, 403, "benign POST should pass the WAF");
}

#[tokio::test]
async fn crs_example_inspects_vhost_requests() {
    let Some(rules_path) = crs_example_rules() else {
        return;
    };
    let fixture = Fixture::start_with_rules(None, false, true, false, Some(rules_path)).await;

    let clean =
        send_request_with_host(&fixture, "GET", "/clean.txt", "waf.example.test", "", "").await;
    assert_eq!(clean.status, 200);
    assert_eq!(clean.body, b"vhost response");

    let blocked = send_request_with_host(
        &fixture,
        "GET",
        "/clean.txt?id=1%27%20OR%20%271%27=%271",
        "waf.example.test",
        "",
        "",
    )
    .await;
    assert_eq!(blocked.status, 403, "vhost SQL injection should be blocked");
}

#[tokio::test]
async fn applies_request_response_and_redirect_rules() {
    let fixture = Fixture::start(None, false, false, false).await;

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
async fn configures_modsecurity_block_status_without_changing_redirects() {
    let fixture = Fixture::start_with_options(
        None,
        false,
        false,
        false,
        None,
        &["--modsecurity-block-status", "451"],
        None,
    )
    .await;

    let blocked = send_request(&fixture, "GET", "/clean.txt?q=block", "", "").await;
    assert_eq!(blocked.status, 451);

    let header = send_request(&fixture, "GET", "/clean.txt", "X-Block: yes\r\n", "").await;
    assert_eq!(header.status, 451);

    let request_body = send_request(
        &fixture,
        "POST",
        "/clean.txt",
        "Content-Type: application/x-www-form-urlencoded\r\n",
        "comment=evil",
    )
    .await;
    assert_eq!(request_body.status, 451);

    let response_body = send_request(&fixture, "GET", "/secret.txt", "", "").await;
    assert_eq!(response_body.status, 451);
    assert!(
        !response_body
            .body
            .windows(6)
            .any(|window| window == b"SECRET")
    );

    let clean = send_request(&fixture, "GET", "/clean.txt", "", "").await;
    assert_eq!(clean.status, 200);

    let redirect = send_request(&fixture, "GET", "/clean.txt?q=redirect", "", "").await;
    assert_eq!(redirect.status, 302);
    assert_eq!(
        redirect.headers.get("location").map(String::as_str),
        Some("https://example.test/blocked")
    );
}

#[tokio::test]
async fn vhost_modsecurity_block_status_overrides_global_status() {
    let fixture = Fixture::start_with_options(
        None,
        false,
        true,
        false,
        None,
        &["--modsecurity-block-status", "451"],
        Some(452),
    )
    .await;

    let fallback_blocked = send_request(&fixture, "GET", "/clean.txt?q=block", "", "").await;
    assert_eq!(fallback_blocked.status, 451);

    let vhost_blocked = send_request_with_host(
        &fixture,
        "GET",
        "/clean.txt?q=block",
        "waf.example.test",
        "",
        "",
    )
    .await;
    assert_eq!(vhost_blocked.status, 452);

    let redirect = send_request_with_host(
        &fixture,
        "GET",
        "/clean.txt?q=redirect",
        "waf.example.test",
        "",
        "",
    )
    .await;
    assert_eq!(redirect.status, 302);
}

#[tokio::test]
async fn vhost_modsecurity_block_status_overrides_rule_status_without_global_override() {
    let fixture = Fixture::start_with_options(None, false, true, false, None, &[], Some(452)).await;

    let fallback_query = send_request(&fixture, "GET", "/clean.txt?q=block", "", "").await;
    assert_eq!(fallback_query.status, 403);
    let fallback_header = send_request(&fixture, "GET", "/clean.txt", "X-Block: yes\r\n", "").await;
    assert_eq!(fallback_header.status, 406);

    let vhost_query = send_request_with_host(
        &fixture,
        "GET",
        "/clean.txt?q=block",
        "waf.example.test",
        "",
        "",
    )
    .await;
    assert_eq!(vhost_query.status, 452);
    let vhost_header = send_request_with_host(
        &fixture,
        "GET",
        "/clean.txt",
        "waf.example.test",
        "X-Block: yes\r\n",
        "",
    )
    .await;
    assert_eq!(vhost_header.status, 452);
}

#[test]
fn rejects_block_status_configuration_without_global_rules() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "project-charlotte-modsecurity-invalid-config-{}-{sequence}",
        std::process::id()
    ));
    let vhost_root = root.join("vhost-root");
    std::fs::create_dir_all(&vhost_root).unwrap();
    let user = User::from_uid(geteuid()).unwrap().unwrap();
    let config_path = root.join("vhosts.yaml");
    std::fs::write(
        &config_path,
        format!(
            "vhost:\n  - server_names: [waf.example.test]\n    root: {:?}\n    user: {:?}\n    modsecurity_block_status: 452\n",
            vhost_root.to_string_lossy(),
            user.name
        ),
    )
    .unwrap();

    let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
    command
        .args(["--bind", "127.0.0.1:0", "--root"])
        .arg(&root)
        .arg("--config")
        .arg(&config_path);
    let missing_rules = common::output(&mut command).unwrap();
    assert!(!missing_rules.status.success());
    assert!(
        String::from_utf8_lossy(&missing_rules.stderr)
            .contains("modsecurity_block_status requires --modsecurity-rules")
    );

    let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
    command
        .args(["--bind", "127.0.0.1:0", "--root"])
        .arg(&root)
        .args(["--modsecurity-block-status", "600"]);
    let invalid_global_status = common::output(&mut command).unwrap();
    assert!(!invalid_global_status.status.success());
    assert!(
        String::from_utf8_lossy(&invalid_global_status.stderr)
            .contains("invalid ModSecurity block status")
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
async fn blocks_request_body_before_fastcgi_backend() {
    let fixture = Fixture::start(None, true, false, false).await;
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
    let fixture = Fixture::start(Some(16), false, false, false).await;
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
    let fixture = Fixture::start(None, false, true, false).await;
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

#[tokio::test]
async fn vhost_can_disable_specific_rules_without_disabling_other_rules() {
    let fixture = Fixture::start(None, false, true, true).await;

    let fallback_blocked = send_request(&fixture, "GET", "/clean.txt?q=block", "", "").await;
    assert_eq!(fallback_blocked.status, 403);

    let excluded = send_request_with_host(
        &fixture,
        "GET",
        "/clean.txt?q=block",
        "waf.example.test",
        "",
        "",
    )
    .await;
    assert_eq!(excluded.status, 200);
    assert_eq!(excluded.body, b"vhost response");

    let still_enforced = send_request_with_host(
        &fixture,
        "GET",
        "/clean.txt",
        "waf.example.test",
        "X-Block: yes\r\n",
        "",
    )
    .await;
    assert_eq!(still_enforced.status, 406);
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

fn crs_example_rules() -> Option<PathBuf> {
    let crs_setup = PathBuf::from("/etc/modsecurity/crs/crs-setup.conf");
    let crs_rules = PathBuf::from("/usr/share/modsecurity-crs/rules");
    if !crs_setup.is_file() || !crs_rules.is_dir() {
        eprintln!(
            "skipping CRS integration test: install the OWASP CRS package (expected {} and {})",
            crs_setup.display(),
            crs_rules.display()
        );
        return None;
    }
    Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/modsecurity-crs.conf"))
}
