use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

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
