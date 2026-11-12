//! Helpers shared by the integration-test fixtures.

#![forbid(unsafe_code)]

use std::{
    net::{SocketAddr, TcpListener, UdpSocket},
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
