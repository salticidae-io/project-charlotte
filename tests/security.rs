//! Regression tests for the privilege, path-allowlist, and config-trust fixes.

#![cfg(unix)]
#![forbid(unsafe_code)]

mod common;

use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

use nix::unistd::{Group, User, geteuid, getgroups};

#[cfg(all(target_os = "linux", feature = "hosting"))]
use std::{
    process::{Child, Stdio},
    time::Duration,
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(name: &str) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "project-charlotte-{name}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn check_config(config: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .arg("--check-config")
        .arg("--config")
        .arg(config)
        .output()
        .unwrap()
}

fn output_stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn shared_supplementary_group() -> Option<Group> {
    let user = User::from_uid(geteuid()).ok()??;
    getgroups()
        .ok()?
        .into_iter()
        .filter(|gid| *gid != user.gid && gid.as_raw() != 0)
        .filter_map(|gid| Group::from_gid(gid).ok().flatten())
        .find(|group| group.mem.iter().any(|member| member != &user.name))
}

fn set_group(path: &Path, group: &Group) -> bool {
    Command::new("chgrp")
        .arg(&group.name)
        .arg(path)
        .status()
        .is_ok_and(|status| status.success())
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn check_config_rejects_world_writable_files_but_accepts_secure_files() {
    let directory = TestDirectory::new("security-world-write");
    let config = directory.path().join("main.yaml");
    fs::write(&config, "vhost: []\n").unwrap();

    set_mode(&config, 0o666);
    let output = check_config(&config);
    assert!(!output.status.success());
    assert!(
        output_stderr(&output).contains("must not be group- or world-writable"),
        "{}",
        output_stderr(&output)
    );

    set_mode(&config, 0o640);
    let output = check_config(&config);
    assert!(output.status.success(), "{}", output_stderr(&output));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "Configuration OK"
    );
}

#[test]
fn check_config_rejects_group_writable_configs_and_checks_symlink_targets() {
    let Some(group) = shared_supplementary_group() else {
        return;
    };
    let directory = TestDirectory::new("security-group-write");
    let config = directory.path().join("main.yaml");
    fs::write(&config, "vhost: []\n").unwrap();
    if !set_group(&config, &group) {
        return;
    }

    set_mode(&config, 0o660);
    let output = check_config(&config);
    assert!(!output.status.success());
    assert!(
        output_stderr(&output).contains("must not be group- or world-writable"),
        "{}",
        output_stderr(&output)
    );

    set_mode(&config, 0o640);
    let output = check_config(&config);
    assert!(output.status.success(), "{}", output_stderr(&output));

    let target = directory.path().join("target.yaml");
    let link = directory.path().join("linked.yaml");
    fs::write(&target, "vhost: []\n").unwrap();
    if !set_group(&target, &group) {
        return;
    }
    set_mode(&target, 0o660);
    symlink(&target, &link).unwrap();

    let output = check_config(&link);
    assert!(!output.status.success());
    assert!(
        output_stderr(&output).contains("must not be group- or world-writable"),
        "{}",
        output_stderr(&output)
    );

    set_mode(&target, 0o640);
    let output = check_config(&link);
    assert!(
        output.status.success(),
        "a trusted symlink target should remain supported: {}",
        output_stderr(&output)
    );
}

#[test]
fn check_config_rejects_a_group_writable_vhost_directory() {
    let Some(group) = shared_supplementary_group() else {
        return;
    };
    let directory = TestDirectory::new("security-vhost-dir");
    let vhosts = directory.path().join("vhosts");
    fs::create_dir(&vhosts).unwrap();
    if !set_group(&vhosts, &group) {
        return;
    }
    set_mode(&vhosts, 0o770);

    let output = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .arg("--check-config")
        .arg("--vhost-dir")
        .arg(&vhosts)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        output_stderr(&output).contains("must not be group- or world-writable"),
        "{}",
        output_stderr(&output)
    );
}

#[test]
fn packaged_defaults_run_unprivileged_with_systemd_sandboxing() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for path in [
        "packaging/default/project-charlotte",
        "packaging/default/project-charlotte-proxy",
    ] {
        let contents = fs::read_to_string(root.join(path)).unwrap();
        let options = contents
            .lines()
            .find(|line| line.starts_with("CHARLOTTE_OPTS="))
            .unwrap_or_else(|| panic!("{path} has no CHARLOTTE_OPTS"));
        assert!(options.contains("--user www-data"), "{path}: {options}");
    }

    let service =
        fs::read_to_string(root.join("packaging/systemd/project-charlotte.service")).unwrap();
    for directive in [
        "NoNewPrivileges=true",
        "ProtectSystem=full",
        "PrivateTmp=true",
        "SystemCallFilter=@system-service",
    ] {
        assert!(service.lines().any(|line| line == directive), "{directive}");
    }
    // RestrictSUIDSGID makes systemd fail openat2 with ENOSYS, which the root
    // helper needs for every log and TLS file, so the server cannot start.
    assert!(
        !service
            .lines()
            .any(|line| line.trim_start().starts_with("RestrictSUIDSGID=")),
        "RestrictSUIDSGID breaks the root helper's openat2"
    );
    let capability_bounding_set = service
        .lines()
        .find(|line| line.starts_with("CapabilityBoundingSet="))
        .expect("systemd service must bound capabilities");
    assert!(
        !capability_bounding_set
            .split_whitespace()
            .any(|capability| capability == "CAP_SYS_ADMIN"),
        "{capability_bounding_set}"
    );
}

#[cfg(all(target_os = "linux", feature = "hosting"))]
#[tokio::test]
#[ignore = "requires root; run in the privileged CI job with cargo test -- --ignored"]
async fn root_helper_restricts_new_log_paths_after_master_drops_privileges() {
    use std::os::unix::fs::MetadataExt;
    use tokio::time::sleep;

    assert!(geteuid().is_root(), "this test requires root");
    let user = User::from_name("nobody")
        .unwrap()
        .expect("root test environment must provide the nobody account");
    let group = Group::from_gid(user.gid)
        .unwrap()
        .expect("nobody's primary group must exist");

    let directory = TestDirectory::new("security-root-helper");
    let base = directory.path();
    let vhost_dir = base.join("vhosts");
    let root = base.join("site");
    let fallback_root = base.join("fallback");
    let allowed_logs = base.join("allowed-logs");
    let forbidden_logs = base.join("forbidden-logs");
    for path in [
        &vhost_dir,
        &root,
        &fallback_root,
        &allowed_logs,
        &forbidden_logs,
    ] {
        fs::create_dir(path).unwrap();
        set_mode(path, 0o755);
    }
    fs::write(root.join("page.txt"), "hosted").unwrap();
    fs::write(fallback_root.join("page.txt"), "fallback").unwrap();

    let initial_access = allowed_logs.join("initial-access.log");
    let initial_error = allowed_logs.join("initial-error.log");
    let initial_config = vhost_config(
        "initial.security.test",
        &root,
        &user.name,
        &group.name,
        &initial_access,
        &initial_error,
    );
    let initial_file = vhost_dir.join("initial.yaml");
    fs::write(&initial_file, initial_config).unwrap();
    set_mode(&initial_file, 0o644);

    let stderr_path = base.join("server.stderr");
    let stderr_file = fs::File::create(&stderr_path).unwrap();
    let address = common::reserve_tcp_address();
    let binary = common::worker_accessible_server_binary(base);
    let mut command = Command::new(binary);
    command
        .arg("--user")
        .arg(&user.name)
        .arg("--group")
        .arg(&group.name)
        .arg("--bind")
        .arg(address.to_string())
        .arg("--root")
        .arg(&fallback_root)
        .arg("--vhost-dir")
        .arg(&vhost_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr_file));
    let mut server = RunningServer(common::spawn(&mut command).unwrap());
    let pid = server.0.id();

    let startup_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = server.0.try_wait().unwrap() {
            panic!("server exited before opening initial vhost logs: {status}");
        }
        let root_helper_running = process_children(pid)
            .iter()
            .any(|child| process_effective_uid(*child) == Some(0));
        if process_effective_uid(pid) == Some(user.uid.as_raw())
            && root_helper_running
            && initial_access.exists()
            && initial_error.exists()
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < startup_deadline,
            "master/helper privilege split or initial log open did not complete"
        );
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(fs::metadata(&initial_access).unwrap().uid(), 0);
    assert_eq!(fs::metadata(&initial_error).unwrap().uid(), 0);

    let capabilities = process_permitted_capabilities(pid).unwrap();
    const MASTER_PRIVILEGE_CAPABILITIES: u64 = (1 << 1) | (1 << 5) | (1 << 6) | (1 << 7);
    assert_eq!(
        capabilities & MASTER_PRIVILEGE_CAPABILITIES,
        0,
        "master permitted capabilities: {capabilities:#x}"
    );

    assert_eq!(
        get_body(&address, "initial.security.test").await.1,
        "hosted"
    );

    let denied_access = forbidden_logs.join("denied-access.log");
    let denied_error = forbidden_logs.join("denied-error.log");
    let denied_root = base.join("denied-site");
    fs::create_dir(&denied_root).unwrap();
    set_mode(&denied_root, 0o755);
    fs::write(denied_root.join("page.txt"), "denied-vhost").unwrap();
    write_vhost_file(
        &vhost_dir.join("added.yaml"),
        "added.security.test",
        &denied_root,
        &user.name,
        &group.name,
        &denied_access,
        &denied_error,
    );

    let reload_error =
        wait_for_file_text(&stderr_path, "outside the directories the root helper").await;
    assert!(reload_error.contains("--log-dir"), "{reload_error}");
    assert!(!denied_access.exists(), "unlisted access log was created");
    assert!(!denied_error.exists(), "unlisted error log was created");
    assert_eq!(
        get_body(&address, "added.security.test").await.1,
        "fallback"
    );

    let allowed_access = allowed_logs.join("added-access.log");
    let allowed_error = allowed_logs.join("added-error.log");
    write_vhost_file(
        &vhost_dir.join("added.yaml"),
        "added.security.test",
        &denied_root,
        &user.name,
        &group.name,
        &allowed_access,
        &allowed_error,
    );
    wait_for_path(&allowed_access).await;
    wait_for_path(&allowed_error).await;
    assert_eq!(
        get_body_wait(&address, "added.security.test", "denied-vhost").await,
        "denied-vhost"
    );
    assert_eq!(fs::metadata(&allowed_access).unwrap().uid(), 0);
    assert_eq!(fs::metadata(&allowed_error).unwrap().uid(), 0);

    common::shutdown(&mut server.0);
}

#[cfg(all(target_os = "linux", feature = "hosting"))]
struct RunningServer(Child);

#[cfg(all(target_os = "linux", feature = "hosting"))]
impl Drop for RunningServer {
    fn drop(&mut self) {
        common::shutdown(&mut self.0);
    }
}

#[cfg(all(target_os = "linux", feature = "hosting"))]
fn vhost_config(
    hostname: &str,
    root: &Path,
    username: &str,
    group: &str,
    access_log: &Path,
    error_log: &Path,
) -> String {
    format!(
        "vhost:\n  - server_names: [{hostname:?}]\n    root: {:?}\n    user: {username:?}\n    group: {group:?}\n    access_log: {:?}\n    error_log: {:?}\n",
        root.to_string_lossy(),
        access_log.to_string_lossy(),
        error_log.to_string_lossy(),
    )
}

#[cfg(all(target_os = "linux", feature = "hosting"))]
fn write_vhost_file(
    path: &Path,
    hostname: &str,
    root: &Path,
    username: &str,
    group: &str,
    access_log: &Path,
    error_log: &Path,
) {
    fs::write(
        path,
        vhost_config(hostname, root, username, group, access_log, error_log),
    )
    .unwrap();
    set_mode(path, 0o644);
}

#[cfg(all(target_os = "linux", feature = "hosting"))]
async fn get_body(address: &std::net::SocketAddr, hostname: &str) -> (&'static str, String) {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };

    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!("GET /page.txt HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&response);
    let status = if response.starts_with("HTTP/1.1 200") {
        "HTTP/1.1 200"
    } else if response.starts_with("HTTP/1.0 200") {
        "HTTP/1.0 200"
    } else {
        panic!("unexpected response: {response}");
    };
    let (_, body) = response.split_once("\r\n\r\n").expect("response headers");
    (status, body.to_owned())
}

#[cfg(all(target_os = "linux", feature = "hosting"))]
async fn get_body_wait(
    address: &std::net::SocketAddr,
    hostname: &str,
    expected_body: &str,
) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let (_, body) = get_body(address, hostname).await;
        if body == expected_body {
            return body;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "host {hostname} did not serve expected body {expected_body:?}; got {body:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[cfg(all(target_os = "linux", feature = "hosting"))]
async fn wait_for_path(path: &Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        if path.exists() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "expected file {} was not created",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(all(target_os = "linux", feature = "hosting"))]
async fn wait_for_file_text(path: &Path, expected: &str) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let text = fs::read_to_string(path).unwrap_or_default();
        if text.contains(expected) {
            return text;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{expected:?} did not appear in {}: {text}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[cfg(all(target_os = "linux", feature = "hosting"))]
fn process_permitted_capabilities(pid: u32) -> Option<u64> {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("CapPrm:"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
}

#[cfg(all(target_os = "linux", feature = "hosting"))]
fn process_effective_uid(pid: u32) -> Option<u32> {
    fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix("Uid:")
                .and_then(|values| values.split_whitespace().nth(1))
                .and_then(|value| value.parse().ok())
        })
}

#[cfg(all(target_os = "linux", feature = "hosting"))]
fn process_children(pid: u32) -> Vec<u32> {
    fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
        .unwrap_or_default()
        .split_whitespace()
        .filter_map(|value| value.parse().ok())
        .collect()
}
