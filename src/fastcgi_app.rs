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
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
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
}

impl Drop for AppHandle {
    fn drop(&mut self) {
        self.supervisor.abort();
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
        let child = match spawn_app(&app, &root, &listener) {
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
        let supervisor = tokio::spawn(supervise(listener, app, root.clone(), child));
        backend.address = FastCgiAddress::Unix(socket_path);
        handles.push(AppHandle {
            supervisor,
            socket_dir,
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

fn spawn_app(app: &FastCgiApp, root: &Path, listener: &UnixListener) -> io::Result<Child> {
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
    command.spawn()
}

async fn supervise(listener: UnixListener, app: FastCgiApp, root: PathBuf, mut child: Child) {
    loop {
        let started = Instant::now();
        match child.wait().await {
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
            match spawn_app(&app, &root, &listener) {
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
