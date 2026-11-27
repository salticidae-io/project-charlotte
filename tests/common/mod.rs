//! Helpers shared by the integration-test fixtures.

#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

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
    let processes = process_snapshot();
    let by_pid = processes
        .iter()
        .map(|process| (process.pid, process))
        .collect::<std::collections::HashMap<_, _>>();
    processes
        .iter()
        .filter(|process| process.args.iter().any(|arg| arg == argument))
        .filter(|process| {
            let mut current = process.pid;
            for _ in 0..32 {
                let Some(parent) = by_pid.get(&current).map(|process| process.ppid) else {
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
        .map(|process| process.pid)
        .collect()
}

#[allow(dead_code)]
pub fn process_parent(pid: u32) -> Option<u32> {
    process_snapshot_for(pid).map(|process| process.ppid)
}

#[derive(Debug)]
struct ProcessSnapshot {
    pid: u32,
    ppid: u32,
    state: char,
    start: u64,
    args: Vec<String>,
}

#[allow(dead_code)]
pub fn process_children(pid: u32) -> Vec<u32> {
    #[cfg(target_os = "linux")]
    {
        let task_path = format!("/proc/{pid}/task");
        let Ok(tasks) = fs::read_dir(task_path) else {
            return Vec::new();
        };
        return tasks
            .flatten()
            .filter_map(|task| fs::read_to_string(task.path().join("children")).ok())
            .flat_map(|children| {
                children
                    .split_whitespace()
                    .filter_map(|child| child.parse::<u32>().ok())
                    .collect::<Vec<_>>()
            })
            .collect();
    }

    #[cfg(not(target_os = "linux"))]
    process_snapshot()
        .into_iter()
        .filter(|process| process.ppid == pid)
        .map(|process| process.pid)
        .collect()
}

#[allow(dead_code)]
pub fn process_args(pid: u32) -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        return fs::read(format!("/proc/{pid}/cmdline"))
            .unwrap_or_default()
            .split(|byte| *byte == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| String::from_utf8_lossy(arg).into_owned())
            .collect();
    }

    #[cfg(not(target_os = "linux"))]
    process_snapshot_for(pid)
        .map(|process| process.args)
        .unwrap_or_default()
}

#[allow(dead_code)]
pub fn process_state_and_start(pid: u32) -> Option<(char, u64)> {
    process_snapshot_for(pid).map(|process| (process.state, process.start))
}

#[cfg(target_os = "linux")]
fn process_snapshot() -> Vec<ProcessSnapshot> {
    let Ok(processes) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    processes
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(process_snapshot_for)
        .collect()
}

#[cfg(target_os = "linux")]
fn process_snapshot_for(pid: u32) -> Option<ProcessSnapshot> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat.rsplit_once(") ")?.1.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let ppid = fields.next()?.parse().ok()?;
    let start = fields.nth(17)?.parse().ok()?;
    let args = fs::read(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect();
    Some(ProcessSnapshot {
        pid,
        ppid,
        state,
        start,
        args,
    })
}

#[cfg(not(target_os = "linux"))]
fn process_snapshot_for(pid: u32) -> Option<ProcessSnapshot> {
    let output = std::process::Command::new("ps")
        .args([
            "-ww",
            "-p",
            &pid.to_string(),
            "-o",
            "pid=",
            "-o",
            "ppid=",
            "-o",
            "stat=",
            "-o",
            "lstart=",
            "-o",
            "command=",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(parse_process_line)
}

#[cfg(not(target_os = "linux"))]
fn process_snapshot() -> Vec<ProcessSnapshot> {
    let Ok(output) = std::process::Command::new("ps")
        .args([
            "-ww", "-A", "-o", "pid=", "-o", "ppid=", "-o", "stat=", "-o", "lstart=", "-o",
            "command=",
        ])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_process_line)
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn parse_process_line(line: &str) -> Option<ProcessSnapshot> {
    let mut fields = line.split_whitespace();
    let pid = fields.next()?.parse().ok()?;
    let ppid = fields.next()?.parse().ok()?;
    let state = fields.next()?.chars().next()?;
    let start = fields.by_ref().take(5).collect::<Vec<_>>().join(" ");
    if start.is_empty() {
        return None;
    }
    let command = fields.collect::<Vec<_>>().join(" ");
    let mut hasher = DefaultHasher::new();
    start.hash(&mut hasher);
    Some(ProcessSnapshot {
        pid,
        ppid,
        state,
        start: hasher.finish(),
        args: command.split_whitespace().map(str::to_owned).collect(),
    })
}
