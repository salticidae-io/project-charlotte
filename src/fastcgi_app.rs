//! Lifecycle management and pooling for server-managed FastCGI applications.

use std::{
    collections::HashSet,
    collections::hash_map::DefaultHasher,
    error::Error,
    ffi::OsString,
    fmt,
    fs::{self, DirBuilder, OpenOptions},
    hash::{Hash, Hasher},
    io::{self, Write},
    os::{
        fd::AsFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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
    unistd::{Group, Pid, User, getegid, geteuid},
};
use tokio::{
    process::{Child, Command},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::sleep,
};

use crate::{
    config::{Config, FastCgiAddress, FastCgiApp, FastCgiAppMode},
    logging::{Stage, StageTimer},
    pathctx::PathContext,
};

static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(0);
const RESTART_DELAY: Duration = Duration::from_secs(1);
const MIN_CLEAN_RUN: Duration = Duration::from_millis(50);
const MAX_REAPER_INTERVAL: Duration = Duration::from_secs(1);

pub(crate) struct AppPool {
    app: FastCgiApp,
    extension: String,
    root: PathBuf,
    min_workers: usize,
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
            .field("min_workers", &self.min_workers)
            .field("max_workers", &self.max_workers)
            .field("idle_timeout", &self.idle_timeout)
            .finish()
    }
}

impl AppPool {
    fn new(app: FastCgiApp, root: PathBuf, extension: String) -> io::Result<Arc<Self>> {
        validate_app_program(&app, &root)?;
        let socket_dir = create_socket_dir()?;
        let min_workers = app.min_workers.min(app.max_workers);
        let max_workers = app.max_workers;
        let pool = Arc::new(Self {
            min_workers,
            max_workers,
            idle_timeout: app.idle_timeout,
            extension,
            app,
            root,
            socket_dir,
            slots: Mutex::new(Vec::new()),
            permits: Arc::new(Semaphore::new(max_workers)),
            reaper: Mutex::new(None),
        });
        {
            let mut slots = pool.slots.lock().expect("FastCGI pool mutex poisoned");
            if pool.app.mode == FastCgiAppMode::Fpm {
                slots.push(pool.spawn_fpm_slot()?);
            } else {
                for _ in 0..pool.min_workers {
                    slots.push(pool.spawn_slot()?);
                }
            }
        }
        if pool.app.mode == FastCgiAppMode::Cgi {
            pool.start_reaper();
        }
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
        if self.app.mode == FastCgiAppMode::Fpm {
            let socket_path = {
                self.slots
                    .lock()
                    .expect("FastCGI pool mutex poisoned")
                    .first()
                    .map(|slot| Arc::clone(&slot.socket_path))
                    .ok_or_else(|| io::Error::other("PHP-FPM process is not running"))?
            };
            wait_for_socket(&socket_path).await?;
            return Ok(WorkerLease {
                pool: Arc::clone(self),
                slot_id: 0,
                socket_path,
                _permit: permit,
            });
        }
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
        let _spawn_timer = StageTimer::new(Stage::Spawn);
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
        let (child, started) = spawn_app(&self.app, &self.root, &self.extension, &listener, &pid)?;
        let supervisor = tokio::spawn(supervise(
            Some(listener),
            None,
            socket_path.clone(),
            self.extension.clone(),
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

    fn spawn_fpm_slot(&self) -> io::Result<WorkerSlot> {
        let socket_path = self.socket_dir.join("php-fpm.sock");
        let config_path = self.socket_dir.join("php-fpm.conf");
        let config = generate_fpm_config(&self.app, &self.root, &self.extension, &socket_path)?;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&config_path)?
            .write_all(config.as_bytes())?;
        let pid = Arc::new(AtomicU32::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let (child, started) = spawn_fpm(&self.app, &self.root, &config_path, &socket_path, &pid)?;
        let supervisor = tokio::spawn(supervise(
            None,
            Some(config_path),
            socket_path.clone(),
            self.extension.clone(),
            self.app.clone(),
            self.root.clone(),
            child,
            started,
            Arc::clone(&pid),
            Arc::clone(&stopping),
        ));
        Ok(WorkerSlot {
            id: 0,
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
            if slots.len() > self.min_workers
                && !slot.busy
                && now.duration_since(slot.last_used) >= self.idle_timeout
            {
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
        let pool = AppPool::new(app.clone(), root.clone(), backend.extension.clone())?;
        if app.mode == FastCgiAppMode::Fpm {
            crate::log_error!(
                "Started PHP-FPM app .{}: {} (up to {} concurrent requests)",
                backend.extension,
                app.program.display(),
                app.max_workers,
            );
        } else {
            crate::log_error!(
                "Started FastCGI app pool .{}: {} ({} warm, up to {} workers)",
                backend.extension,
                app.program.display(),
                app.min_workers,
                app.max_workers,
            );
        }
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

fn is_php_program(program: &Path) -> bool {
    program
        .file_name()
        .is_some_and(|name| name.to_string_lossy().to_ascii_lowercase().contains("php"))
}

fn php_settings(app: &FastCgiApp, cache_dir: Option<&Path>) -> Vec<(String, String)> {
    if !app.php_defaults || !is_php_program(&app.program) {
        return Vec::new();
    }

    let mut defaults = vec![
        ("opcache.enable", "1"),
        ("opcache.memory_consumption", "128"),
        ("opcache.interned_strings_buffer", "16"),
        ("opcache.max_accelerated_files", "20000"),
        ("opcache.validate_timestamps", "1"),
        ("opcache.revalidate_freq", "2"),
        ("realpath_cache_size", "4096K"),
        ("realpath_cache_ttl", "600"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect::<Vec<_>>();
    if let Some(cache_dir) = cache_dir {
        defaults.push((
            "opcache.file_cache".to_owned(),
            cache_dir.display().to_string(),
        ));
    }

    let overrides = user_ini_overrides(&app.args);
    defaults.retain(|(key, _)| !overrides.contains(&key.to_ascii_lowercase()));
    defaults
}

fn user_ini_overrides(args: &[String]) -> HashSet<String> {
    let mut overrides = HashSet::new();
    let mut index = 0;
    while index < args.len() {
        let value = if args[index] == "-d" {
            index += 1;
            args.get(index).map(String::as_str)
        } else {
            args[index].strip_prefix("-d")
        };
        if let Some((key, _)) = value.and_then(|setting| setting.split_once('=')) {
            overrides.insert(key.trim().to_ascii_lowercase());
        }
        index += 1;
    }
    overrides
}

fn opcache_cache_dir(root: &Path, app: &FastCgiApp, extension: &str) -> io::Result<PathBuf> {
    let mut hasher = DefaultHasher::new();
    root.hash(&mut hasher);
    app.program.hash(&mut hasher);
    extension.hash(&mut hasher);
    let directory = std::env::temp_dir().join(format!(
        "project-charlotte-opcache-{}-{:016x}",
        geteuid().as_raw(),
        hasher.finish()
    ));
    match DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    validate_private_cache_dir(&directory, geteuid().as_raw())?;
    Ok(directory)
}

fn validate_private_cache_dir(directory: &Path, expected_uid: u32) -> io::Result<()> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o077 != 0
        || metadata.mode() & 0o700 != 0o700
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "OPcache file-cache directory must be a private directory owned by the server user",
        ));
    }
    Ok(())
}

fn php_cache_dir(root: &Path, app: &FastCgiApp, extension: &str) -> Option<PathBuf> {
    if !app.php_defaults
        || !is_php_program(&app.program)
        || user_ini_overrides(&app.args).contains("opcache.file_cache")
    {
        return None;
    }
    match opcache_cache_dir(root, app, extension) {
        Ok(path) => Some(path),
        Err(error) => {
            crate::log_error!(
                "skipping OPcache file cache for {}: {error}",
                app.program.display()
            );
            None
        }
    }
}

fn fpm_config_value(value: &str) -> io::Result<String> {
    if value.contains(['\n', '\r', '\0']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PHP-FPM configuration values cannot contain line breaks or NUL",
        ));
    }
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    Ok(format!("\"{escaped}\""))
}

fn generate_fpm_config(
    app: &FastCgiApp,
    root: &Path,
    extension: &str,
    socket_path: &Path,
) -> io::Result<String> {
    let user = User::from_uid(geteuid())
        .map_err(io::Error::other)?
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "server user has no passwd entry")
        })?;
    let group = Group::from_gid(getegid())
        .map_err(io::Error::other)?
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "server group has no group entry")
        })?;
    let user = fpm_config_value(&user.name)?;
    let group = fpm_config_value(&group.name)?;
    let socket = fpm_config_value(&socket_path.display().to_string())?;
    let mut config = format!(
        "[global]\ndaemonize = no\nerror_log = /proc/self/fd/2\n\n[www]\nuser = {user}\ngroup = {group}\nlisten = {socket}\nlisten.mode = 0600\nclear_env = yes\npm.max_children = {}\npm.max_requests = 10000\ncatch_workers_output = yes\n",
        app.max_workers
    );
    if app.min_workers == 0 {
        config.push_str("pm = ondemand\n");
        config.push_str(&format!(
            "pm.process_idle_timeout = {}s\n",
            app.idle_timeout.as_secs()
        ));
    } else if app.min_workers >= app.max_workers {
        config.push_str("pm = static\n");
    } else {
        config.push_str(&format!(
            "pm = dynamic\npm.start_servers = {}\npm.min_spare_servers = {}\npm.max_spare_servers = {}\n",
            app.min_workers, app.min_workers, app.max_workers
        ));
    }

    let path = app
        .env
        .get("PATH")
        .cloned()
        .or_else(|| std::env::var("PATH").ok())
        .unwrap_or_default();
    config.push_str(&format!("env[PATH] = {}\n", fpm_config_value(&path)?));
    for (key, value) in &app.env {
        if key == "PATH" {
            continue;
        }
        config.push_str(&format!("env[{key}] = {}\n", fpm_config_value(value)?));
    }
    if let Some(cache_dir) = php_cache_dir(root, app, extension) {
        for (key, value) in php_settings(app, Some(&cache_dir)) {
            if key == "opcache.enable" {
                continue;
            }
            config.push_str(&format!(
                "php_admin_value[{key}] = {}\n",
                fpm_config_value(&value)?
            ));
        }
    } else {
        for (key, value) in php_settings(app, None) {
            if key == "opcache.enable" {
                continue;
            }
            config.push_str(&format!(
                "php_admin_value[{key}] = {}\n",
                fpm_config_value(&value)?
            ));
        }
    }
    Ok(config)
}

async fn wait_for_socket(socket_path: &Path) -> io::Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match tokio::fs::metadata(socket_path).await {
            Ok(metadata) if metadata.file_type().is_socket() => return Ok(()),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "PHP-FPM endpoint is not a Unix socket",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for PHP-FPM socket",
            ));
        }
        sleep(Duration::from_millis(25)).await;
    }
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
    extension: &str,
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
    let cache_dir = php_cache_dir(root, app, extension);
    let php_defaults = php_settings(app, cache_dir.as_deref());
    let mut command = Command::new(&app.program);
    for (key, value) in php_defaults {
        command.arg("-d").arg(format!("{key}={value}"));
    }
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
    if app.php_defaults && is_php_program(&app.program) {
        command.env(
            "PHP_FCGI_MAX_REQUESTS",
            app.env
                .get("PHP_FCGI_MAX_REQUESTS")
                .cloned()
                .unwrap_or_else(|| "10000".to_owned()),
        );
    }
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

fn spawn_fpm(
    app: &FastCgiApp,
    root: &Path,
    config_path: &Path,
    socket_path: &Path,
    pid: &AtomicU32,
) -> io::Result<(Child, Instant)> {
    if let Err(error) = fs::remove_file(socket_path)
        && error.kind() != io::ErrorKind::NotFound
    {
        return Err(error);
    }
    crate::log_debug!(
        "Starting PHP-FPM app {} with config {}",
        app.program.display(),
        config_path.display()
    );
    let path = std::env::var_os("PATH").unwrap_or_default();
    let mut command = Command::new(&app.program);
    let cache_dir = php_cache_dir(root, app, "php");
    for (key, value) in php_settings(app, cache_dir.as_deref()) {
        if key == "opcache.enable" {
            command.arg("-d").arg(format!("{key}={value}"));
        }
    }
    command
        .arg("-F")
        .arg("-y")
        .arg(config_path)
        .args(app.args.iter().map(OsString::from))
        .env_clear()
        .env("PATH", path)
        .envs(&app.env)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .current_dir(root)
        .kill_on_drop(true);
    if geteuid().is_root() {
        command.arg("-R");
    }
    command.as_std_mut().process_group(0);
    let child = command.spawn()?;
    let child_pid = child.id().unwrap_or(0);
    pid.store(child_pid, Ordering::SeqCst);
    crate::log_debug!(
        "Started PHP-FPM app {} with pid {} on socket {}",
        app.program.display(),
        child_pid,
        socket_path.display()
    );
    Ok((child, Instant::now()))
}

async fn supervise(
    listener: Option<UnixListener>,
    fpm_config: Option<PathBuf>,
    socket_path: PathBuf,
    extension: String,
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
            let spawned = match app.mode {
                FastCgiAppMode::Cgi => listener
                    .as_ref()
                    .ok_or_else(|| io::Error::other("CGI app listener is missing"))
                    .and_then(|listener| spawn_app(&app, &root, &extension, listener, &pid)),
                FastCgiAppMode::Fpm => fpm_config
                    .as_deref()
                    .ok_or_else(|| io::Error::other("PHP-FPM config is missing"))
                    .and_then(|config| spawn_fpm(&app, &root, config, &socket_path, &pid)),
            };
            match spawned {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn app(program: &str) -> FastCgiApp {
        FastCgiApp {
            program: PathBuf::from(program),
            args: Vec::new(),
            env: Default::default(),
            mode: FastCgiAppMode::Cgi,
            php_defaults: true,
            min_workers: 1,
            max_workers: 4,
            idle_timeout: Duration::from_secs(30),
        }
    }

    #[test]
    fn php_ini_defaults_respect_user_defined_overrides() {
        let mut app = app("php-cgi");
        app.args = vec![
            "-d".to_owned(),
            "opcache.enable=0".to_owned(),
            "-drealpath_cache_size=1M".to_owned(),
        ];
        let settings = php_settings(&app, Some(Path::new("/tmp/php-cache")));
        assert!(!settings.iter().any(|(key, _)| key == "opcache.enable"));
        assert!(!settings.iter().any(|(key, _)| key == "realpath_cache_size"));
        assert!(
            settings
                .iter()
                .any(|(key, value)| key == "opcache.file_cache" && value == "/tmp/php-cache")
        );

        app.args
            .push("-dopcache.file_cache=/custom/cache".to_owned());
        assert!(
            !php_settings(&app, Some(Path::new("/tmp/php-cache")))
                .iter()
                .any(|(key, _)| key == "opcache.file_cache")
        );
        assert!(php_cache_dir(Path::new("/tmp"), &app, "php").is_none());
    }

    #[test]
    fn recognizes_php_program_names() {
        assert!(is_php_program(Path::new("/usr/sbin/php-fpm8.3")));
        assert!(is_php_program(Path::new("/usr/bin/php-cgi")));
        assert!(!is_php_program(Path::new("/usr/bin/python3")));
    }

    #[test]
    fn fpm_config_selects_process_manager_and_quotes_environment_values() {
        let mut app = app("php-fpm");
        app.mode = FastCgiAppMode::Fpm;
        app.env
            .insert("APP_VALUE".to_owned(), "say \"hello\"".to_owned());
        let root = std::env::temp_dir().join(format!(
            "project-charlotte-fpm-root-{}-{}",
            std::process::id(),
            NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let socket = std::env::temp_dir().join("project-charlotte-fpm.sock");

        let dynamic = generate_fpm_config(&app, &root, "php", &socket).unwrap();
        let cache_dir = dynamic
            .lines()
            .find_map(|line| line.strip_prefix("php_admin_value[opcache.file_cache] = \""))
            .map(|value| PathBuf::from(value.trim_end_matches('"')))
            .unwrap();
        assert!(dynamic.contains("pm = dynamic"));
        assert!(dynamic.contains("pm.start_servers = 1"));
        assert!(dynamic.contains("pm.max_children = 4"));
        assert!(dynamic.contains("pm.max_requests = 10000"));
        assert!(dynamic.contains("env[APP_VALUE] = \"say \\\"hello\\\"\""));
        assert!(!dynamic.contains("php_admin_value[opcache.enable]"));
        assert!(dynamic.contains("php_admin_value[opcache.file_cache]"));

        app.min_workers = app.max_workers;
        assert!(
            generate_fpm_config(&app, &root, "php", &socket)
                .unwrap()
                .contains("pm = static")
        );
        app.min_workers = 0;
        assert!(
            generate_fpm_config(&app, &root, "php", &socket)
                .unwrap()
                .contains("pm = ondemand")
        );
        fs::remove_dir_all(cache_dir).unwrap();
    }

    #[test]
    fn rejects_opcache_cache_directory_with_insecure_permissions() {
        let path = std::env::temp_dir().join(format!(
            "project-charlotte-opcache-test-{}-{}",
            std::process::id(),
            NEXT_SOCKET_ID.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o755).create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validate_private_cache_dir(&path, geteuid().as_raw()).is_err());
        fs::remove_dir(path).unwrap();
    }
}
