use std::{
    error::Error,
    fs::{self, DirBuilder},
    io,
    os::{
        fd::AsFd,
        unix::{fs::DirBuilderExt, net::UnixListener},
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use tokio::{
    process::{Child, Command},
    task::JoinHandle,
    time::sleep,
};

use crate::config::{Config, FastCgiAddress, FastCgiApp};

static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(0);
const QUICK_EXIT: Duration = Duration::from_secs(5);
const RESTART_DELAY: Duration = Duration::from_secs(1);

pub(crate) struct AppHandle {
    supervisor: JoinHandle<()>,
    socket_dir: PathBuf,
    pid: Arc<AtomicU32>,
}

impl Drop for AppHandle {
    fn drop(&mut self) {
        // Stop the supervisor first so that it cannot restart the app in
        // response to the kill below.
        self.supervisor.abort();
        // Aborting drops the supervisor's `Child`, and `kill_on_drop` would then
        // reap the app, but only once the runtime polls the task again. Signal
        // the process directly so that the descriptors it inherited - notably
        // stderr, which keeps a piped parent's output pipe open - are released
        // even when the runtime never gets another chance to run.
        let pid = self.pid.swap(0, Ordering::SeqCst);
        if let Ok(pid) = i32::try_from(pid)
            && pid > 0
        {
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
        if let Err(error) = fs::remove_dir_all(&self.socket_dir)
            && error.kind() != io::ErrorKind::NotFound
        {
            eprintln!(
                "could not remove FastCGI app socket directory {}: {error}",
                self.socket_dir.display()
            );
        }
    }
}

pub(crate) async fn start_apps(
    config: &mut Config,
) -> Result<Vec<AppHandle>, Box<dyn Error + Send + Sync>> {
    let root = config.root.clone();
    let mut handles = Vec::new();
    for backend in &mut config.fastcgi {
        let FastCgiAddress::Spawn(app) = &backend.address else {
            continue;
        };
        let extension = backend.extension.clone();
        let app = app.clone();
        let (socket_dir, socket_path, listener) = create_listener()?;
        let pid = Arc::new(AtomicU32::new(0));
        let child = match spawn_app(&app, &root, &listener, &pid) {
            Ok(child) => child,
            Err(error) => {
                drop(listener);
                let _ = fs::remove_dir_all(&socket_dir);
                return Err(error.into());
            }
        };
        eprintln!(
            "Started FastCGI app .{extension}: {}",
            app.program.display()
        );
        let supervisor = tokio::spawn(supervise(
            listener,
            app,
            root.clone(),
            child,
            Arc::clone(&pid),
        ));
        backend.address = FastCgiAddress::Unix(socket_path);
        handles.push(AppHandle {
            supervisor,
            socket_dir,
            pid,
        });
    }
    Ok(handles)
}

fn create_listener() -> io::Result<(PathBuf, PathBuf, UnixListener)> {
    let temp_dir = std::env::temp_dir();
    loop {
        let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
        let directory = temp_dir.join(format!(
            "project-charlotte-fcgi-{}-{id}",
            std::process::id()
        ));
        match DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {
                let socket_path = directory.join("fcgi.sock");
                match UnixListener::bind(&socket_path) {
                    Ok(listener) => return Ok((directory, socket_path, listener)),
                    Err(error) => {
                        let _ = fs::remove_dir_all(&directory);
                        return Err(error);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

fn spawn_app(
    app: &FastCgiApp,
    root: &Path,
    listener: &UnixListener,
    pid: &AtomicU32,
) -> io::Result<Child> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let listener_fd = listener.as_fd().try_clone_to_owned()?;
    let mut command = Command::new(&app.program);
    command
        .args(&app.args)
        .env_clear()
        .env("PATH", path)
        .envs(&app.env)
        .env("FCGI_LISTENSOCK_FILENO", "0")
        .stdin(Stdio::from(listener_fd))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .current_dir(root)
        .kill_on_drop(true);
    let child = command.spawn()?;
    // Recorded with no intervening await so that `AppHandle` never observes a
    // pid that has already been reaped and possibly recycled.
    pid.store(child.id().unwrap_or(0), Ordering::SeqCst);
    Ok(child)
}

async fn supervise(
    listener: UnixListener,
    app: FastCgiApp,
    root: PathBuf,
    mut child: Child,
    pid: Arc<AtomicU32>,
) {
    loop {
        let started = Instant::now();
        let status = child.wait().await;
        pid.store(0, Ordering::SeqCst);
        match status {
            Ok(status) => eprintln!("FastCGI app {} exited with {status}", app.program.display()),
            Err(error) => eprintln!(
                "could not wait for FastCGI app {}: {error}",
                app.program.display()
            ),
        }
        if started.elapsed() < QUICK_EXIT {
            sleep(RESTART_DELAY).await;
        }

        loop {
            match spawn_app(&app, &root, &listener, &pid) {
                Ok(restarted) => {
                    child = restarted;
                    break;
                }
                Err(error) => {
                    eprintln!(
                        "could not restart FastCGI app {}: {error}",
                        app.program.display()
                    );
                    sleep(RESTART_DELAY).await;
                }
            }
        }
    }
}
