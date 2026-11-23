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

#[cfg(feature = "proxy")]
#[test]
fn proxy_vhost_output_is_validated_by_the_server() {
    let temp = TempDir::new();
    let output_path = temp.path().join("proxy.yaml");
    let answers = format!(
        "proxy.example\n4\nhttp://127.0.0.1:3000\n{}",
        blank_lines(11)
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
    assert!(String::from_utf8_lossy(&output.stderr).contains("  4) Reverse proxy"));

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
        blank_lines(8)
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
        "bad name\n99\n4\nnot an upstream\nbad name\n\nhttp://127.0.0.1:3000\ngood.example\n\n\n{}",
        blank_lines(11)
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
