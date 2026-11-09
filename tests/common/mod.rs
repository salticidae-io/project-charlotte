//! Helpers shared by the integration-test fixtures.

#![forbid(unsafe_code)]

use std::{
    process::Child,
    thread::sleep,
    time::{Duration, Instant},
};

use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};

/// How long a server is given to exit on its own before it is killed.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const SHUTDOWN_POLL: Duration = Duration::from_millis(10);

/// Stops a spawned webserver without orphaning the processes it started.
///
/// SIGKILL stops the server before it can drop the handles that stop its vhost
/// workers and FastCGI apps, so those children stay alive holding every
/// descriptor they inherited from the test binary. One of those is stderr, and
/// an orphan holding the write end of the test's output pipe keeps
/// `cargo test | ...` hanging long after the tests pass. SIGINT lets the server
/// shut down in order instead; SIGKILL remains as a fallback for a server that
/// does not take it.
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
