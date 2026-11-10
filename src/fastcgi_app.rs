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
const RESTART_DELAY: Duration = Duration::from_secs(1);
const MIN_CLEAN_RUN: Duration = Duration::from_millis(50);

pub(crate) struct AppHandle {
    supervisors: Vec<(JoinHandle<()>, Arc<AtomicU32>)>,
    socket_dir: PathBuf,
}

impl Drop for AppHandle {
    fn drop(&mut self) {
        // Stop the supervisor first so that it cannot restart the app in
        // response to the kill below.
        for (supervisor, _) in &self.supervisors {
            supervisor.abort();
        }
        // Aborting drops each supervisor's `Child`, and `kill_on_drop` would
        // then reap the app, but only once the runtime polls the task again.
        // Signal the processes directly so inherited descriptors are released
        // even when the runtime never gets another chance to run.
        for (_, pid) in &self.supervisors {
            let pid = pid.swap(0, Ordering::SeqCst);
            if let Ok(pid) = i32::try_from(pid)
                && pid > 0
            {
                let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
            }
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
        let mut handle = AppHandle {
            supervisors: Vec::with_capacity(app.workers),
            socket_dir,
        };
        for _ in 0..app.workers {
            let worker_listener = listener.try_clone()?;
            let pid = Arc::new(AtomicU32::new(0));
            let (child, started) = spawn_app(&app, &root, &worker_listener, &pid)?;
            let supervisor = tokio::spawn(supervise(
                worker_listener,
                app.clone(),
                root.clone(),
                child,
                started,
                Arc::clone(&pid),
            ));
            handle.supervisors.push((supervisor, pid));
        }
        eprintln!(
            "Started {} FastCGI app worker(s) .{extension}: {}",
            app.workers,
            app.program.display()
        );
        backend.address = FastCgiAddress::Unix(socket_path);
        handles.push(handle);
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
) -> io::Result<(Child, Instant)> {
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
    Ok((child, Instant::now()))
}

async fn supervise(
    listener: UnixListener,
    app: FastCgiApp,
    root: PathBuf,
    mut child: Child,
    mut started: Instant,
    pid: Arc<AtomicU32>,
) {
    loop {
        let status = child.wait().await;
        pid.store(0, Ordering::SeqCst);
        let clean_exit = match status {
            Ok(status) => {
                eprintln!("FastCGI app {} exited with {status}", app.program.display());
                status.success()
            }
            Err(error) => {
                eprintln!(
                    "could not wait for FastCGI app {}: {error}",
                    app.program.display()
                );
                false
            }
        };
        if !clean_exit || started.elapsed() < MIN_CLEAN_RUN {
            sleep(RESTART_DELAY).await;
        }

        loop {
            match spawn_app(&app, &root, &listener, &pid) {
                Ok((restarted, restarted_at)) => {
                    child = restarted;
                    started = restarted_at;
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
