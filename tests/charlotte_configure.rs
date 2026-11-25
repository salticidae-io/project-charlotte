use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(feature = "hosting")]
use std::os::unix::fs::PermissionsExt;

const CONFIGURE: &str = env!("CARGO_BIN_EXE_charlotte-configure");

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "charlotte-configure-test-{}-{timestamp}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_configure(args: &[&str], answers: &str) -> Output {
    let mut child = Command::new(CONFIGURE)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answers.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[cfg(any(feature = "proxy", feature = "hosting"))]
fn blank_lines(count: usize) -> String {
    "\n".repeat(count)
}

/// Menu number of "Reverse proxy"; the three hosted site types precede it
/// only when hosting is compiled in.
fn proxy_site_choice() -> &'static str {
    if project_charlotte::configure_support::HOSTING_ENABLED {
        "4"
    } else {
        "1"
    }
}

const CURATED_SERVER_OPTIONS: &[&str] = &[
    "bind",
    "no_plain_http",
    "tls_bind",
    "http3_bind",
    "user",
    "group",
    "vhost_dir",
    "control_socket",
    "tls_cert",
    "tls_key",
    "acme_directory",
    "acme_cache",
    "acme_contact",
    "access_log",
    "access_log_file",
    "access_log_format",
    "error_log_file",
    "bot_detection",
    "bot_config",
    "bot_busy_threshold",
    "modsecurity_rules",
    "rate_limit",
    "rate_limit_burst",
    "trusted_proxy",
    "swarm_redis",
    "https_redirect",
    "debug",
];

fn server_options_answers(
    target: &str,
    value: &str,
    bind_values: &[&str],
    configure_vhost: bool,
) -> String {
    let available = project_charlotte::configure_support::server_options();
    let has_option = |name: &str| available.iter().any(|option| option.name == name);
    let mut answers = Vec::new();
    answers.extend(bind_values.iter().map(|value| (*value).to_owned()));
    answers.extend([
        String::new(), // plain HTTP listener choice
        String::new(), // TLS bind
    ]);
    if has_option("http3_bind") {
        answers.push(String::new());
    }
    answers.extend([
        String::new(), // master user
        String::new(), // vhost directory
        String::new(), // control socket
    ]);
    if has_option("tls_cert") {
        answers.push(String::new()); // no fallback certificate
    }
    if project_charlotte::configure_support::ACME_ENABLED {
        answers.push(String::new()); // ACME disabled
    }
    answers.extend([
        String::new(), // access log disabled
        String::new(), // error log to stderr
    ]);
    if has_option("bot_detection") {
        answers.push(String::new()); // bot protection disabled
    }
    answers.push(String::new()); // no ModSecurity rule files
    answers.push(String::new()); // rate limiting disabled
    answers.push(String::new()); // no trusted proxies
    if has_option("swarm_redis") {
        answers.push(String::new()); // swarm disabled
    }
    answers.extend([
        String::new(), // HTTPS redirect disabled
        String::new(), // debug disabled
    ]);

    let generic = available
        .iter()
        .filter(|option| !CURATED_SERVER_OPTIONS.contains(&option.name.as_str()))
        .collect::<Vec<_>>();
    let target_index = generic
        .iter()
        .position(|option| option.name == target)
        .expect("target option is in the generic menu");
    answers.push((target_index + 2).to_string()); // first menu item is Done
    answers.push(value.to_owned());
    answers.push(String::new()); // finish generic menu
    if project_charlotte::configure_support::HOSTING_ENABLED
        || project_charlotte::configure_support::PROXY_ENABLED
    {
        answers.push(if configure_vhost { "2" } else { "" }.to_owned());
    }
    if configure_vhost {
        answers.extend([
            "combined.example".to_owned(),
            proxy_site_choice().to_owned(), // reverse proxy
            "http://127.0.0.1:3000".to_owned(),
        ]);
        answers.extend((0..12).map(|_| String::new()));
    }
    answers.join("\n") + "\n"
}

#[cfg(feature = "proxy")]
#[test]
fn proxy_vhost_output_is_validated_by_the_server() {
    let temp = TempDir::new();
    let output_path = temp.path().join("proxy.yaml");
    let answers = format!(
        "proxy.example\n{}\nhttp://127.0.0.1:3000\n{}",
        proxy_site_choice(),
        blank_lines(12)
    );
    let output = run_configure(&[], &answers);
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let yaml = String::from_utf8(output.stdout).unwrap();
    fs::write(&output_path, &yaml).unwrap();
    let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    assert!(
        parsed["vhost"][0]["proxy_pass"]
            .as_str()
            .unwrap()
            .starts_with("http://")
    );
    assert!(parsed["vhost"][0].get("proxy_preserve_host").is_none());
    assert!(parsed["vhost"][0].get("proxy_http2").is_none());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains(&format!("  {}) Reverse proxy", proxy_site_choice()))
    );

    let checked = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .args(["--check-config", "--config"])
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("Configuration OK"));
}

#[test]
fn server_options_output_is_validated_by_the_server() {
    let temp = TempDir::new();
    let output_path = temp.path().join("server.yaml");
    let answers = server_options_answers("max_connections", "17", &[""], false);
    let output = run_configure(
        &[
            "--server-options",
            "--output",
            output_path.to_str().unwrap(),
        ],
        &answers,
    );
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    assert_eq!(parsed["options"]["bind"].as_str(), Some("127.0.0.1:8080"));
    assert_eq!(parsed["options"]["max_connections"].as_str(), Some("17"));
    assert!(parsed.get("vhost").is_none());
    check_config(&output_path, &yaml);
}

#[test]
fn invalid_server_option_is_reasked_before_writing() {
    let temp = TempDir::new();
    let output_path = temp.path().join("server.yaml");
    let answers = server_options_answers(
        "max_connections",
        "17",
        &["not-an-address", "127.0.0.1:8081"],
        false,
    );
    let output = run_configure(
        &[
            "--server-options",
            "--output",
            output_path.to_str().unwrap(),
        ],
        &answers,
    );
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    assert_eq!(parsed["options"]["bind"].as_str(), Some("127.0.0.1:8081"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Not applied:"));
    check_config(&output_path, &yaml);
}

#[cfg(feature = "proxy")]
#[test]
fn server_options_can_be_combined_with_a_proxy_vhost() {
    let temp = TempDir::new();
    let output_path = temp.path().join("combined.yaml");
    let answers = server_options_answers("max_connections", "17", &[""], true);
    let output = run_configure(
        &[
            "--server-options",
            "--output",
            output_path.to_str().unwrap(),
        ],
        &answers,
    );
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    assert_eq!(parsed["options"]["max_connections"].as_str(), Some("17"));
    assert_eq!(
        parsed["vhost"][0]["proxy_pass"].as_str(),
        Some("http://127.0.0.1:3000")
    );
    check_config(&output_path, &yaml);
}

#[cfg(feature = "hosting")]
#[test]
fn static_vhost_uses_the_current_non_root_account_and_existing_root() {
    let temp = TempDir::new();
    let root = temp.path().join("site");
    fs::create_dir(&root).unwrap();
    let username = if nix::unistd::geteuid().as_raw() == 0 {
        "nobody".to_owned()
    } else {
        nix::unistd::User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .unwrap()
            .name
    };
    let output_path = temp.path().join("static.yaml");
    let answers = format!(
        "static.example\n1\n{}\n{username}\n{}{}",
        root.display(),
        blank_lines(5),
        blank_lines(9)
    );
    let output = run_configure(&["--output", output_path.to_str().unwrap()], &answers);
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let yaml = fs::read_to_string(&output_path).unwrap();
    assert_eq!(
        fs::metadata(&output_path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    assert_eq!(
        parsed["vhost"][0]["root"].as_str(),
        Some(root.to_str().unwrap())
    );
    assert_eq!(parsed["vhost"][0]["user"].as_str(), Some(username.as_str()));
    let checked = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .args(["--check-config", "--config"])
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
}

#[cfg(feature = "proxy")]
#[test]
fn invalid_core_answers_are_rejected_and_reasked() {
    let temp = TempDir::new();
    let output_path = temp.path().join("reasked.yaml");
    let answers = format!(
        "bad name\n99\n{}\nnot an upstream\nbad name\n\nhttp://127.0.0.1:3000\ngood.example\n\n\n{}",
        proxy_site_choice(),
        blank_lines(12)
    );
    let output = run_configure(&["--output", output_path.to_str().unwrap()], &answers);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let transcript = String::from_utf8_lossy(&output.stderr);
    assert!(
        transcript.contains("Choose a number from 1 to"),
        "{transcript}"
    );
    assert!(
        transcript.contains("invalid virtual host name"),
        "{transcript}"
    );
    assert!(transcript.contains("proxy_pass"), "{transcript}");

    let yaml = fs::read_to_string(output_path).unwrap();
    assert!(yaml.contains("good.example"));
    assert!(!yaml.contains("bad name"));
}

#[cfg(feature = "hosting")]
#[test]
fn php_app_advanced_settings_are_emitted_and_check_cleanly() {
    let temp = TempDir::new();
    let root = temp.path().join("php-site");
    fs::create_dir(&root).unwrap();
    let username = if nix::unistd::geteuid().as_raw() == 0 {
        "nobody".to_owned()
    } else {
        nix::unistd::User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .unwrap()
            .name
    };
    let mut answers = vec![
        "php.example".to_owned(),
        "2".to_owned(),
        root.to_string_lossy().into_owned(),
        username,
        String::new(),
        "/usr/bin/php-cgi".to_owned(),
    ];
    answers.extend((0..4).map(|_| String::new())); // hosted options
    answers.extend([
        String::new(), // CGI mode
        String::new(), // maximum workers
        "1".to_owned(),
        String::new(),  // idle timeout
        "3".to_owned(), // disable PHP defaults
        "--custom-flag".to_owned(),
        String::new(),
        "CUSTOM=value".to_owned(),
        String::new(),
        "7".to_owned(), // FastCGI timeout
    ]);
    answers.extend((0..8).map(|_| String::new()));
    answers.push(String::new()); // skip advanced settings
    answers.push(String::new()); // terminate the final blank response
    let output = run_configure(&[], &answers.join("\n"));
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    let app = &parsed["vhost"][0]["fastcgi_app"][0];
    assert_eq!(app["min_workers"].as_u64(), Some(1));
    assert_eq!(app["php_defaults"].as_bool(), Some(false));
    assert_eq!(app["command"][1].as_str(), Some("--custom-flag"));
    assert_eq!(app["env"]["CUSTOM"].as_str(), Some("value"));
    assert_eq!(parsed["vhost"][0]["fastcgi_timeout"].as_u64(), Some(7));
    check_config(&temp.path().join("php.yaml"), &yaml);
}

#[cfg(feature = "hosting")]
#[test]
fn hosted_advanced_settings_cover_cgi_fastcgi_and_cgroups() {
    let temp = TempDir::new();
    let root = temp.path().join("site");
    fs::create_dir(&root).unwrap();
    let username = if nix::unistd::geteuid().as_raw() == 0 {
        "nobody".to_owned()
    } else {
        nix::unistd::User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .unwrap()
            .name
    };
    let mut answers = vec![
        "advanced.example".to_owned(),
        "1".to_owned(),
        root.to_string_lossy().into_owned(),
        username,
        String::new(),
    ];
    answers.extend((0..4).map(|_| String::new()));
    answers.extend((0..8).map(|_| String::new()));
    answers.extend([
        "2".to_owned(), // enable advanced settings
        "2".to_owned(), // worker threads
        "py=/usr/bin/python3".to_owned(),
        String::new(),
        "php=127.0.0.1:9000".to_owned(),
        String::new(),
        String::new(), // no additional managed app
        "charlotte-tests/site".to_owned(),
        "64M".to_owned(),
        "50%".to_owned(),
        "32".to_owned(),
    ]);
    if project_charlotte::configure_support::SWARM_ENABLED {
        answers.push(String::new()); // inherit swarm setting
    }
    answers.extend([String::new(), String::new()]); // log formats
    answers.push(String::new()); // terminate the final blank response
    let output = run_configure(&[], &answers.join("\n"));
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    let vhost = &parsed["vhost"][0];
    assert_eq!(vhost["worker_threads"].as_u64(), Some(2));
    assert_eq!(vhost["cgi"][0].as_str(), Some("py=/usr/bin/python3"));
    assert_eq!(vhost["fastcgi"][0].as_str(), Some("php=127.0.0.1:9000"));
    assert_eq!(vhost["cgroup"].as_str(), Some("charlotte-tests/site"));
    assert_eq!(vhost["cgroup_memory_max"].as_str(), Some("64M"));
    assert_eq!(vhost["cgroup_cpu_max"].as_str(), Some("50%"));
    assert_eq!(vhost["cgroup_pids_max"].as_str(), Some("32"));
    check_config(&temp.path().join("advanced.yaml"), &yaml);
}

#[cfg(feature = "proxy")]
#[test]
fn proxy_advanced_bot_and_log_formats_are_emitted() {
    let temp = TempDir::new();
    let output_path = temp.path().join("bot-proxy.yaml");
    let mut answers = vec![
        "bot-proxy.example".to_owned(),
        proxy_site_choice().to_owned(),
        "http://127.0.0.1:3000".to_owned(),
        String::new(),  // preserve host default
        String::new(),  // HTTP/2 default remains off
        String::new(),  // proxy timeout
        String::new(),  // no TLS
        String::new(),  // redirect inherit
        String::new(),  // not default vhost
        "3".to_owned(), // enforce with challenge
        String::new(),  // inherit rate limit
        String::new(),  // no ModSecurity
        String::new(),  // access log path
        String::new(),  // error log path
        "2".to_owned(), // advanced settings
        String::new(),  // CA bundle
    ];
    if project_charlotte::configure_support::SWARM_ENABLED {
        answers.push(String::new()); // inherit swarm setting
    }
    answers.extend(["%m %U".to_owned(), "[%l] %M".to_owned()]);
    answers.extend([
        "55".to_owned(), // challenge threshold
        String::new(),   // block threshold
        String::new(),   // difficulty
        String::new(),   // challenge TTL
        String::new(),   // honeypot ban
        String::new(),   // busy window
        String::new(),   // busy cooldown
        String::new(),   // busy threshold
    ]);
    for _ in 0..8 {
        answers.push(String::new()); // bot policy list
    }
    answers.extend([String::new(), String::new(), String::new()]); // policy booleans
    answers.push(String::new()); // terminate the final blank response
    let output = run_configure(&[], &answers.join("\n"));
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    let vhost = &parsed["vhost"][0];
    assert_eq!(vhost["bot"]["challenge_threshold"].as_u64(), Some(55));
    assert_eq!(vhost["access_log_format"].as_str(), Some("%m %U"));
    assert_eq!(vhost["error_log_format"].as_str(), Some("[%l] %M"));
    check_config(&output_path, &yaml);
}

fn check_config(path: &Path, yaml: &str) {
    fs::write(path, yaml).unwrap();
    let checked = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .args(["--check-config", "--config"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(String::from_utf8_lossy(&checked.stdout).contains("Configuration OK"));
}

#[test]
fn existing_output_is_not_overwritten_without_force() {
    let temp = TempDir::new();
    let output_path = temp.path().join("existing.yaml");
    fs::write(&output_path, "keep this content\n").unwrap();
    let output = run_configure(&["--output", output_path.to_str().unwrap()], "");
    assert!(!output.status.success());
    assert_eq!(
        fs::read_to_string(output_path).unwrap(),
        "keep this content\n"
    );
}

#[cfg(not(any(feature = "hosting", feature = "proxy")))]
#[test]
fn build_without_site_types_exits_without_prompting_or_writing() {
    let temp = TempDir::new();
    let output_path = temp.path().join("unsupported.yaml");
    let output = run_configure(&["--output", output_path.to_str().unwrap()], "");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("neither hosting nor proxy"));
    assert!(!output_path.exists());
}
