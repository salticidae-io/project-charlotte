//! Helpers shared by the integration-test fixtures.

#![forbid(unsafe_code)]

use std::{
    fs,
    net::{SocketAddr, TcpListener, UdpSocket},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::Mutex,
    thread::sleep,
    time::{Duration, Instant},
};

use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};

/// How long a server is given to exit on its own before it is killed.
#[allow(dead_code)]
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
#[allow(dead_code)]
const SHUTDOWN_POLL: Duration = Duration::from_millis(10);

static SPAWN_LOCK: Mutex<()> = Mutex::new(());

fn spawn_lock() -> std::sync::MutexGuard<'static, ()> {
    SPAWN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[allow(dead_code)]
pub fn reserve_tcp_address() -> SocketAddr {
    let _guard = spawn_lock();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

#[allow(dead_code)]
pub fn reserve_udp_address() -> SocketAddr {
    let _guard = spawn_lock();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    address
}

#[allow(dead_code)]
pub fn spawn(command: &mut Command) -> std::io::Result<Child> {
    let _guard = spawn_lock();
    command.spawn()
}

#[allow(dead_code)]
pub fn output(command: &mut Command) -> std::io::Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = spawn(command)?;
    child.wait_with_output()
}

#[allow(dead_code)]
pub fn status(command: &mut Command) -> std::io::Result<ExitStatus> {
    let mut child = spawn(command)?;
    child.wait()
}

#[allow(dead_code)]
pub fn worker_accessible_server_binary(dir: &Path) -> PathBuf {
    fs::create_dir_all(dir).unwrap_or_else(|error| {
        panic!(
            "could not create worker binary directory {}: {error}",
            dir.display()
        )
    });
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap_or_else(|error| {
        panic!(
            "could not make worker binary directory {} accessible: {error}",
            dir.display()
        )
    });

    let canonical_dir = fs::canonicalize(dir).unwrap_or_else(|error| {
        panic!(
            "could not resolve worker binary directory {}: {error}",
            dir.display()
        )
    });
    for ancestor in canonical_dir.ancestors() {
        let metadata = fs::metadata(ancestor).unwrap_or_else(|error| {
            panic!(
                "could not inspect worker binary path {}: {error}",
                ancestor.display()
            )
        });
        assert_ne!(
            metadata.mode() & 0o001,
            0,
            "worker user cannot traverse {} (other-execute permission is required)",
            ancestor.display()
        );
    }

    let binary = canonical_dir.join("project-charlotte-worker-binary");
    fs::copy(env!("CARGO_BIN_EXE_project-charlotte"), &binary).unwrap_or_else(|error| {
        panic!(
            "could not copy server binary to {}: {error}",
            binary.display()
        )
    });
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap_or_else(|error| {
        panic!(
            "could not make worker binary {} executable: {error}",
            binary.display()
        )
    });
    binary
}

/// Stops a spawned webserver without orphaning the processes it started.
///
/// SIGKILL stops the server before it can drop the handles that stop its vhost
/// workers and FastCGI apps, so those children stay alive holding every
/// descriptor they inherited from the test binary. One of those is stderr, and
/// an orphan holding the write end of the test's output pipe keeps
/// `cargo test | ...` hanging long after the tests pass. SIGINT lets the server
/// shut down in order instead; SIGKILL remains as a fallback for a server that
/// does not take it.
#[allow(dead_code)]
pub fn shutdown(server: &mut Child) {
    if let Ok(pid) = i32::try_from(server.id())
        && kill(Pid::from_raw(pid), Signal::SIGINT).is_ok()
    {
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        loop {
            match server.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => {}
                Err(_) => break,
            }
            if Instant::now() >= deadline {
                break;
            }
            sleep(SHUTDOWN_POLL);
        }
    }
    let _ = server.kill();
    let _ = server.wait();
}

#[allow(dead_code)]
pub fn descendants_with_argument(root_pid: u32, argument: &str) -> Vec<u32> {
    let Ok(processes) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    processes
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            let Ok(command_line) = fs::read(format!("/proc/{pid}/cmdline")) else {
                return false;
            };
            if !command_line
                .split(|byte| *byte == 0)
                .any(|value| value == argument.as_bytes())
            {
                return false;
            }
            let mut current = *pid;
            for _ in 0..32 {
                let Some(parent) = process_parent(current) else {
                    return false;
                };
                if parent == root_pid {
                    return true;
                }
                if parent <= 1 || parent == current {
                    return false;
                }
                current = parent;
            }
            false
        })
        .collect()
}

fn process_parent(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:")?.trim().parse().ok())
}
