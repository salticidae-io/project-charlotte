use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

#[cfg(feature = "hosting")]
use nix::unistd::{Group, User, getegid, geteuid};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

fn temp_dir() -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "project-charlotte-check-config-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&directory).unwrap();
    directory
}

#[test]
fn check_config_reports_yaml_errors_with_source_lines() {
    let directory = temp_dir();
    let config = directory.join("vhosts.yaml");
    fs::write(&config, "vhost:\n  - server_names: [broken.test\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .arg("--check-config")
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("{}:3:", config.display())),
        "{stderr}"
    );
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn check_config_accepts_empty_config_without_opening_logs() {
    let directory = temp_dir();
    let config = directory.join("vhosts.yaml");
    let error_log = directory.join("missing").join("error.log");
    fs::write(&config, "vhost: []\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .arg("--check-config")
        .arg("--config")
        .arg(&config)
        .arg("--error-log-file")
        .arg(&error_log)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "Configuration OK"
    );
    assert!(
        !error_log.exists(),
        "validation must not open configured logs"
    );
    let _ = fs::remove_dir_all(directory);
}

// A vhost with a document root needs the `hosting` feature; without it the
// config is rejected before the root is checked.
#[cfg(feature = "hosting")]
#[test]
fn check_config_reports_a_missing_vhost_root() {
    let directory = temp_dir();
    let config = directory.join("vhosts.yaml");
    let missing_root = directory.join("missing-site");
    let (user, group) = if geteuid().is_root() {
        let Some(user) = User::from_name("nobody").unwrap() else {
            let _ = fs::remove_dir_all(directory);
            return;
        };
        (user.name, user.gid)
    } else {
        let user = User::from_uid(geteuid()).unwrap().unwrap();
        (user.name, getegid())
    };
    let group = Group::from_gid(group).unwrap().unwrap().name;
    fs::write(
        &config,
        format!(
            "vhost:\n  - server_names: [missing.test]\n    root: {:?}\n    user: {:?}\n    group: {:?}\n",
            missing_root.to_string_lossy(),
            user,
            group
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .arg("--check-config")
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&missing_root.display().to_string()),
        "{stderr}"
    );
    assert!(stderr.contains("does not exist"), "{stderr}");
    let _ = fs::remove_dir_all(directory);
}
