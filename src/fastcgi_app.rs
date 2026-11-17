//! Lifecycle management and pooling for server-managed FastCGI applications.

use std::{
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, DirBuilder},
    io,
    os::{
        fd::AsFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, PermissionsExt},
            net::UnixListener,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use tokio::{
    process::{Child, Command},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::sleep,
};

use crate::{
    config::{Config, FastCgiAddress, FastCgiApp},
    pathctx::PathContext,
};

static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(0);
const RESTART_DELAY: Duration = Duration::from_secs(1);
const MIN_CLEAN_RUN: Duration = Duration::from_millis(50);
const MAX_REAPER_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) struct AppPool {
    app: FastCgiApp,
    root: PathBuf,
    max_workers: usize,
    idle_timeout: Duration,
    socket_dir: PathBuf,
    slots: Mutex<Vec<WorkerSlot>>,
    permits: Arc<Semaphore>,
    reaper: Mutex<Option<JoinHandle<()>>>,
}

struct WorkerSlot {
    id: u64,
    socket_path: Arc<Path>,
    busy: bool,
    last_used: Instant,
    stopping: Arc<AtomicBool>,
    supervisor: JoinHandle<()>,
    pid: Arc<AtomicU32>,
}

pub(crate) struct WorkerLease {
    pool: Arc<AppPool>,
    slot_id: u64,
    socket_path: Arc<Path>,
    _permit: OwnedSemaphorePermit,
}

impl fmt::Debug for AppPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AppPool")
            .field("program", &self.app.program)
            .field("max_workers", &self.max_workers)
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

impl AppPool {
    fn new(app: FastCgiApp, root: PathBuf) -> io::Result<Arc<Self>> {
        validate_app_program(&app, &root)?;
        let socket_dir = create_socket_dir()?;
        let max_workers = app.max_workers;
        let pool = Arc::new(Self {
            max_workers,
            idle_timeout: app.idle_timeout,
            app,
            root,
            socket_dir,
            slots: Mutex::new(Vec::new()),
            permits: Arc::new(Semaphore::new(max_workers)),
            reaper: Mutex::new(None),
        });
        pool.start_reaper();
        Ok(pool)
    }

    pub(crate) fn app(&self) -> &FastCgiApp {
        &self.app
    }

    pub(crate) async fn acquire(self: &Arc<Self>) -> io::Result<WorkerLease> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| io::Error::other("FastCGI app worker pool is closed"))?;
        let mut slots = self.slots.lock().expect("FastCGI pool mutex poisoned");
        if let Some(slot) = slots.iter_mut().find(|slot| !slot.busy) {
            slot.busy = true;
            return Ok(WorkerLease {
                pool: Arc::clone(self),
                slot_id: slot.id,
                socket_path: Arc::clone(&slot.socket_path),
                _permit: permit,
            });
        }

        if slots.len() >= self.max_workers {
            return Err(io::Error::other("FastCGI app worker pool is at capacity"));
        }
        let mut slot = self.spawn_slot()?;
        slot.busy = true;
        let lease = WorkerLease {
            pool: Arc::clone(self),
            slot_id: slot.id,
            socket_path: Arc::clone(&slot.socket_path),
            _permit: permit,
        };
        slots.push(slot);
        Ok(lease)
    }

    fn spawn_slot(&self) -> io::Result<WorkerSlot> {
        let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
        let (socket_path, listener) = create_listener(&self.socket_dir, id)?;
        let pid = Arc::new(AtomicU32::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let (child, started) = spawn_app(&self.app, &self.root, &listener, &pid)?;
        let supervisor = tokio::spawn(supervise(
            listener,
            self.app.clone(),
            self.root.clone(),
            child,
            started,
            Arc::clone(&pid),
            Arc::clone(&stopping),
        ));
        Ok(WorkerSlot {
            id,
            socket_path: socket_path.into(),
            busy: false,
            last_used: Instant::now(),
            stopping,
            supervisor,
            pid,
        })
    }

    fn start_reaper(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let interval = (self.idle_timeout / 4).min(MAX_REAPER_INTERVAL);
        let reaper = tokio::spawn(async move {
            loop {
                sleep(interval).await;
                let Some(pool) = weak.upgrade() else {
                    return;
                };
                pool.reap_idle_workers();
            }
        });
        *self.reaper.lock().expect("FastCGI reaper mutex poisoned") = Some(reaper);
    }

    fn reap_idle_workers(&self) {
        let now = Instant::now();
        let mut slots = self.slots.lock().expect("FastCGI pool mutex poisoned");
        let mut index = 0;
        while index < slots.len() {
            let slot = &slots[index];
            if !slot.busy && now.duration_since(slot.last_used) >= self.idle_timeout {
                let slot = slots.remove(index);
                stop_slot(slot);
            } else {
                index += 1;
            }
        }
    }
}

impl Drop for AppPool {
    fn drop(&mut self) {
        if let Some(reaper) = self
            .reaper
            .get_mut()
            .expect("FastCGI reaper mutex poisoned")
            .take()
        {
            reaper.abort();
        }
        let slots = self
            .slots
            .get_mut()
            .expect("FastCGI pool mutex poisoned")
            .drain(..);
        for slot in slots {
            stop_slot(slot);
        }
        if let Err(error) = fs::remove_dir_all(&self.socket_dir)
            && error.kind() != io::ErrorKind::NotFound
        {
            crate::log_error!(
                "could not remove FastCGI app socket directory {}: {error}",
                self.socket_dir.display()
            );
        }
    }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        let mut slots = self.pool.slots.lock().expect("FastCGI pool mutex poisoned");
        if let Some(slot) = slots.iter_mut().find(|slot| slot.id == self.slot_id) {
            slot.busy = false;
            slot.last_used = Instant::now();
        }
    }
}

impl WorkerLease {
    pub(crate) fn socket_path(&self) -> &Path {
        &self.socket_path
    }
}

fn stop_slot(slot: WorkerSlot) {
    slot.stopping.store(true, Ordering::SeqCst);
    slot.supervisor.abort();
    let pid = slot.pid.swap(0, Ordering::SeqCst);
    if let Ok(pid) = i32::try_from(pid)
        && pid > 0
    {
        let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
    if let Err(error) = fs::remove_file(&slot.socket_path)
        && error.kind() != io::ErrorKind::NotFound
    {
        crate::log_error!(
            "could not remove FastCGI app socket {}: {error}",
            slot.socket_path.display()
        );
    }
}

pub(crate) async fn start_apps(config: &mut Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let root = config.root.clone();
    for backend in &mut config.fastcgi {
        let FastCgiAddress::Spawn(app) = &backend.address else {
            continue;
        };
        let pool = AppPool::new(app.clone(), root.clone())?;
        crate::log_error!(
            "Started FastCGI app pool .{}: {} (0–{} workers on demand)",
            backend.extension,
            app.program.display(),
            app.max_workers,
        );
        backend.address = FastCgiAddress::Pool(pool);
    }
    Ok(())
}

fn create_socket_dir() -> io::Result<PathBuf> {
    let temp_dir = std::env::temp_dir();
    loop {
        let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed);
        let directory = temp_dir.join(format!(
            "project-charlotte-fcgi-{}-{id}",
            std::process::id()
        ));
        match DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => return Ok(directory),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
}

fn create_listener(socket_dir: &Path, id: u64) -> io::Result<(PathBuf, UnixListener)> {
    let socket_path = socket_dir.join(format!("worker-{id}.sock"));
    let listener = UnixListener::bind(&socket_path)?;
    Ok((socket_path, listener))
}

fn validate_app_program(app: &FastCgiApp, root: &Path) -> io::Result<()> {
    let path = app
        .env
        .get("PATH")
        .map(OsString::from)
        .or_else(|| std::env::var_os("PATH"))
        .unwrap_or_default();
    let program = &app.program;
    let candidates = if program.as_os_str().as_bytes().contains(&b'/') {
        vec![if program.is_absolute() {
            program.to_path_buf()
        } else {
            root.join(program)
        }]
    } else {
        std::env::split_paths(&path)
            .map(|directory| {
                if directory.is_absolute() {
                    directory.join(program)
                } else {
                    root.join(directory).join(program)
                }
            })
            .collect()
    };

    for candidate in candidates {
        match fs::metadata(&candidate).path_context("inspect FastCGI app candidate", &candidate) {
            Ok(metadata) if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 => {
                return Ok(());
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "FastCGI app program {} was not found or is not executable",
            program.display()
        ),
    ))
}

fn spawn_app(
    app: &FastCgiApp,
    root: &Path,
    listener: &UnixListener,
    pid: &AtomicU32,
) -> io::Result<(Child, Instant)> {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let socket = listener
        .local_addr()
        .ok()
        .and_then(|address| address.as_pathname().map(|path| path.display().to_string()))
        .unwrap_or_else(|| "<unnamed>".to_owned());
    crate::log_debug!(
        "Starting FastCGI app {} on socket {}",
        app.program.display(),
        socket
    );
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
    command.as_std_mut().process_group(0);
    let child = command.spawn()?;
    // Recorded without an intervening await so shutdown can't see a stale pid.
    let child_pid = child.id().unwrap_or(0);
    pid.store(child_pid, Ordering::SeqCst);
    crate::log_debug!(
        "Started FastCGI app {} with pid {} on socket {}",
        app.program.display(),
        child_pid,
        socket
    );
    Ok((child, Instant::now()))
}

async fn supervise(
    listener: UnixListener,
    app: FastCgiApp,
    root: PathBuf,
    mut child: Child,
    mut started: Instant,
    pid: Arc<AtomicU32>,
    stopping: Arc<AtomicBool>,
) {
    loop {
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        let child_pid = child.id().and_then(|pid| i32::try_from(pid).ok());
        let status = child.wait().await;
        if let Some(pid) = child_pid {
            let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
        }
        pid.store(0, Ordering::SeqCst);
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        let clean_exit = match status {
            Ok(status) => {
                crate::log_error!("FastCGI app {} exited with {status}", app.program.display());
                status.success()
            }
            Err(error) => {
                crate::log_error!(
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
            if stopping.load(Ordering::SeqCst) {
                return;
            }
            match spawn_app(&app, &root, &listener, &pid) {
                Ok((restarted, restarted_at)) => {
                    if stopping.load(Ordering::SeqCst) {
                        if let Some(pid) = restarted.id().and_then(|pid| i32::try_from(pid).ok()) {
                            let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
                        }
                        pid.store(0, Ordering::SeqCst);
                        return;
                    }
                    child = restarted;
                    started = restarted_at;
                    break;
                }
                Err(error) => {
                    crate::log_error!(
                        "could not restart FastCGI app {}: {error}",
                        app.program.display()
                    );
                    sleep(RESTART_DELAY).await;
                }
            }
        }
    }
}
