//! Spawns, supervises, and forwards requests to workers for hosted virtual hosts.

use std::{
    collections::HashMap,
    error::Error,
    ffi::OsString,
    io,
    net::SocketAddr,
    os::{fd::OwnedFd, unix::net::UnixStream as StdUnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex as StdMutex, OnceLock, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{
    HeaderName, HeaderValue, Request, Response, StatusCode, Uri, Version,
    header::{HOST, RETRY_AFTER},
};
use http_body::Body;
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};
use hyper::{body::Incoming, client::conn::http2::SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo};
use nix::{
    sys::signal::{Signal, kill},
    unistd::{Group, Pid, User},
};
use tokio::{
    io::AsyncReadExt,
    net::UnixStream,
    runtime::Handle,
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore},
    time::timeout,
};

use super::{Rejection, TlsSni, request_authority};
use crate::{
    cgroup::CgroupSpec,
    config::{FastCgiAddress, FastCgiApp, FastCgiAppMode, FastCgiBackend},
    response::{self, ResponseBody},
};

const META_PEER: HeaderName = HeaderName::from_static("x-charlotte-peer");
const META_LOCAL: HeaderName = HeaderName::from_static("x-charlotte-local");
const META_VERSION: HeaderName = HeaderName::from_static("x-charlotte-version");
const META_TLS: HeaderName = HeaderName::from_static("x-charlotte-tls");
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(10);
const WORKER_START_QUEUE_WAIT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_WORKER_STARTS: usize = 16;
/// How long a worker is given to shut down on its own before it is killed.
const WORKER_SHUTDOWN_GRACE: Duration = Duration::from_millis(500);
const WORKER_SHUTDOWN_POLL: Duration = Duration::from_millis(5);
static WORKER_POOL: OnceLock<Arc<WorkerPool>> = OnceLock::new();
static WORKER_START_LIMITER: OnceLock<Arc<Semaphore>> = OnceLock::new();

type WorkerRequestBody = UnsyncBoxBody<Bytes, io::Error>;
type WorkerSender = SendRequest<WorkerRequestBody>;

pub(super) struct Worker {
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) root: PathBuf,
    pub(super) cgroup: Option<CgroupSpec>,
    pub(super) idle_timeout: Option<Duration>,
    pub(super) active: Arc<AtomicUsize>,
    pub(super) last_used: Arc<StdMutex<Instant>>,
    pub(super) index: Vec<String>,
    pub(super) listing: bool,
    pub(super) try_files: Vec<String>,
    pub(super) fastcgi: Vec<FastCgiBackend>,
    pub(super) fastcgi_timeout: Duration,
    pub(super) threads: usize,
    pub(super) error_log_file: Option<PathBuf>,
    pub(super) error_log_format: String,
    pub(super) process: Arc<Mutex<Option<WorkerProcess>>>,
    pub(super) reaper_wake: Arc<Notify>,
}

pub(super) struct WorkerProcess {
    pub(super) sender: WorkerSender,
    pub(super) child: Option<WorkerChild>,
    slot: Option<WorkerSlot>,
}

struct StartingChild {
    child: Option<WorkerChild>,
}

struct WorkerPool {
    state: StdMutex<WorkerPoolState>,
}

struct WorkerPoolState {
    limit: usize,
    next_id: u64,
    entries: HashMap<u64, WorkerEntry>,
}

struct WorkerEntry {
    active: Arc<AtomicUsize>,
    last_used: Arc<StdMutex<Instant>>,
    process: Weak<Mutex<Option<WorkerProcess>>>,
}

struct WorkerSlot {
    pool: Arc<WorkerPool>,
    id: u64,
}

struct WorkerReservation {
    slot: WorkerSlot,
    evicted: Option<WorkerProcess>,
}

#[derive(Debug)]
struct WorkerCapacityExhausted;

impl std::fmt::Display for WorkerCapacityExhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the live worker limit is reached and no idle worker can be evicted")
    }
}

impl Error for WorkerCapacityExhausted {}

#[derive(Debug)]
struct WorkerStartsExhausted;

impl std::fmt::Display for WorkerStartsExhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the worker start queue remained full for five seconds")
    }
}

impl Error for WorkerStartsExhausted {}

struct WorkerSpawn {
    uid: u32,
    gid: u32,
    error_log_file: Option<PathBuf>,
    cgroup: Option<CgroupSpec>,
    args: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
}

impl WorkerPool {
    fn new(limit: usize) -> Self {
        Self {
            state: StdMutex::new(WorkerPoolState {
                limit,
                next_id: 0,
                entries: HashMap::new(),
            }),
        }
    }

    fn set_limit(&self, limit: usize) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .limit = limit;
    }

    fn reserve(
        self: &Arc<Self>,
        worker: &Worker,
    ) -> Result<WorkerReservation, WorkerCapacityExhausted> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.limit == 0 || state.entries.len() < state.limit {
            let id = state.next_id();
            state.entries.insert(id, WorkerEntry::new(worker));
            return Ok(WorkerReservation {
                slot: WorkerSlot {
                    pool: Arc::clone(self),
                    id,
                },
                evicted: None,
            });
        }

        let mut candidates = state
            .entries
            .iter()
            .filter(|(_, entry)| entry.active.load(Ordering::Acquire) == 0)
            .map(|(id, entry)| {
                let last_used = *entry
                    .last_used
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (*id, last_used)
            })
            .collect::<Vec<_>>();
        candidates.sort_unstable_by_key(|(id, last_used)| (*last_used, *id));

        for (victim_id, _) in candidates {
            let Some(process) = state
                .entries
                .get(&victim_id)
                .and_then(|entry| entry.process.upgrade())
            else {
                continue;
            };
            let Ok(mut process_guard) = process.try_lock() else {
                continue;
            };
            let Some(mut evicted) = process_guard.take() else {
                continue;
            };
            let id = state.next_id();
            let mut slot = evicted.slot.take().unwrap_or_else(|| WorkerSlot {
                pool: Arc::clone(self),
                id: victim_id,
            });
            slot.id = id;
            state.entries.remove(&victim_id);
            state.entries.insert(id, WorkerEntry::new(worker));
            return Ok(WorkerReservation {
                slot,
                evicted: Some(evicted),
            });
        }

        Err(WorkerCapacityExhausted)
    }
}

impl WorkerPoolState {
    fn next_id(&mut self) -> u64 {
        loop {
            self.next_id = self.next_id.wrapping_add(1);
            if !self.entries.contains_key(&self.next_id) {
                return self.next_id;
            }
        }
    }
}

impl WorkerEntry {
    fn new(worker: &Worker) -> Self {
        Self {
            active: Arc::clone(&worker.active),
            last_used: Arc::clone(&worker.last_used),
            process: Arc::downgrade(&worker.process),
        }
    }
}

impl Drop for WorkerSlot {
    fn drop(&mut self) {
        self.pool
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entries
            .remove(&self.id);
    }
}

fn worker_pool() -> &'static Arc<WorkerPool> {
    WORKER_POOL.get_or_init(|| Arc::new(WorkerPool::new(0)))
}

pub(super) fn set_max_workers(limit: usize) {
    worker_pool().set_limit(limit);
}

pub(super) fn set_max_worker_starts(limit: usize) {
    let permits = if limit == 0 {
        Semaphore::MAX_PERMITS
    } else {
        limit
    };
    let _ = WORKER_START_LIMITER.set(Arc::new(Semaphore::new(permits)));
}

fn worker_start_limiter() -> &'static Arc<Semaphore> {
    WORKER_START_LIMITER.get_or_init(|| Arc::new(Semaphore::new(DEFAULT_MAX_WORKER_STARTS)))
}

async fn acquire_worker_start(
    semaphore: Arc<Semaphore>,
    wait: Duration,
) -> Result<OwnedSemaphorePermit, WorkerStartsExhausted> {
    match timeout(wait, semaphore.acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) | Err(_) => Err(WorkerStartsExhausted),
    }
}

pub(super) enum WorkerChild {
    Direct(Child),
    Helper(u64),
}

impl WorkerChild {
    fn id(&self) -> u64 {
        match self {
            Self::Direct(child) => u64::from(child.id()),
            Self::Helper(id) => *id,
        }
    }
    fn stop(&mut self, force: bool) -> io::Result<()> {
        match self {
            Self::Helper(id) => crate::logopener::stop_worker(*id, force),
            Self::Direct(child) => stop_direct_worker(child, force),
        }
    }
}

impl StartingChild {
    fn new(child: WorkerChild) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u64 {
        self.child.as_ref().expect("starting child is present").id()
    }

    fn disarm(mut self) -> WorkerChild {
        self.child.take().expect("starting child is present")
    }
}

impl Drop for StartingChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            stop_worker_in_background(child, true);
        }
    }
}

impl WorkerSpawn {
    fn spawn(self, child_socket: OwnedFd) -> Result<StartingChild, Box<dyn Error + Send + Sync>> {
        let child = if crate::logopener::is_active() {
            WorkerChild::Helper(crate::logopener::spawn_worker(
                self.uid,
                self.gid,
                &self.args,
                &self.environment,
                self.error_log_file.as_deref(),
                self.cgroup.as_ref(),
                child_socket,
            )?)
        } else {
            let mut command = Command::new(crate::worker_executable()?);
            command
                .args(&self.args)
                .env_clear()
                .envs(self.environment.iter().map(|(key, value)| (key, value)))
                .stdin(Stdio::from(child_socket))
                .current_dir("/");
            if let Some(path) = &self.error_log_file {
                let stderr = crate::logging::open_log_file(path)?;
                command.stderr(Stdio::from(stderr));
            }
            if let Some(spec) = &self.cgroup {
                let cgroup_procs = crate::cgroup::prepare(spec).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!(
                            "could not prepare worker cgroup {}: {error}",
                            spec.path.display()
                        ),
                    )
                })?;
                crate::cgroup::apply_to_command(&mut command, cgroup_procs);
            }
            if crate::privileges::can_set_ids()? {
                crate::privileges::apply_identity(&mut command, self.uid, self.gid)?;
            }
            let child = command.spawn()?;
            crate::log_debug!("Started virtual-host worker with pid {}", child.id());
            WorkerChild::Direct(child)
        };
        Ok(StartingChild::new(child))
    }
}

fn stop_worker_in_background(mut child: WorkerChild, force: bool) {
    let mut stop = move || {
        if let Err(error) = child.stop(force) {
            crate::log_error!("Could not stop virtual-host worker: {error}");
        }
    };
    if let Ok(runtime) = Handle::try_current() {
        runtime.spawn_blocking(stop);
    } else {
        stop();
    }
}

fn stop_direct_worker(child: &mut Child, force: bool) -> io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    if !force {
        let pid = i32::try_from(child.id())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid worker pid"))?;
        let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
        let deadline = Instant::now() + WORKER_SHUTDOWN_GRACE;
        while Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            thread::sleep(WORKER_SHUTDOWN_POLL);
        }
    }
    if let Err(error) = child.kill()
        && child.try_wait()?.is_none()
    {
        return Err(error);
    }
    child.wait()?;
    Ok(())
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            stop_worker_in_background(child, false);
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.reaper_wake.notify_one();
    }
}

impl Worker {
    pub(super) fn spawn_idle_reaper(worker: &Arc<Self>, timeout: Duration) {
        let wake = Arc::clone(&worker.reaper_wake);
        let worker: Weak<Self> = Arc::downgrade(worker);
        let interval = timeout.min(Duration::from_millis(250));
        tokio::spawn(async move {
            loop {
                let Some(strong_worker) = worker.upgrade() else {
                    break;
                };
                let process_running = strong_worker.process.lock().await.is_some();
                drop(strong_worker);
                if !process_running {
                    wake.notified().await;
                    continue;
                }
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = wake.notified() => continue,
                }
                let Some(strong_worker) = worker.upgrade() else {
                    break;
                };
                let process_remains = strong_worker.reap_idle(timeout).await;
                drop(strong_worker);
                if !process_remains {
                    continue;
                }
            }
        });
    }

    async fn reap_idle(&self, timeout: Duration) -> bool {
        let mut process = self.process.lock().await;
        if process.is_none() {
            return false;
        }
        if self.active.load(Ordering::Acquire) != 0 {
            return true;
        }
        let is_idle = {
            let last_used = self
                .last_used
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Instant::now().saturating_duration_since(*last_used) >= timeout
        };
        if is_idle && let Some(process) = process.take() {
            crate::log_debug!(
                "Stopping idle virtual-host worker for root {} after {} seconds",
                self.root.display(),
                timeout.as_secs()
            );
            drop(process);
            false
        } else {
            true
        }
    }

    #[cfg(test)]
    async fn process_is_running(&self) -> bool {
        self.process.lock().await.is_some()
    }

    async fn spawn_process(
        &self,
        slot: WorkerSlot,
    ) -> Result<WorkerProcess, Box<dyn Error + Send + Sync>> {
        crate::log_debug!(
            "Spawning virtual-host worker for root {} as uid {} gid {}{}",
            self.root.display(),
            self.uid,
            self.gid,
            self.cgroup
                .as_ref()
                .map_or_else(String::new, |spec| format!(
                    " in cgroup {}",
                    spec.path.display()
                ))
        );
        let (parent, child_socket) = StdUnixStream::pair()?;
        parent.set_nonblocking(true)?;
        let mut args = build_worker_args(WorkerArgs {
            uid: self.uid,
            gid: self.gid,
            root: &self.root,
            index: &self.index,
            listing: self.listing,
            try_files: &self.try_files,
            fastcgi: &self.fastcgi,
            timeout: self.fastcgi_timeout,
            error_log_format: &self.error_log_format,
        });
        args.push("--worker-threads".into());
        args.push(self.threads.to_string().into());
        if crate::logging::debug_enabled() {
            args.push("--debug".into());
        }
        let mut environment = WORKER_INHERITED_ENV
            .iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (OsString::from(name), value)))
            .collect::<Vec<_>>();
        if std::env::var_os("MALLOC_ARENA_MAX").is_none() {
            environment.push((OsString::from("MALLOC_ARENA_MAX"), OsString::from("1")));
        }
        if let Some(app_env) = worker_app_env(&self.fastcgi) {
            environment.push((
                OsString::from(crate::config::WORKER_APP_ENV),
                OsString::from(app_env),
            ));
        }

        let worker_spawn = WorkerSpawn {
            uid: self.uid,
            gid: self.gid,
            error_log_file: self.error_log_file.clone(),
            cgroup: self.cgroup.clone(),
            args,
            environment,
        };
        let child =
            tokio::task::spawn_blocking(move || worker_spawn.spawn(OwnedFd::from(child_socket)))
                .await
                .map_err(|error| {
                    io::Error::other(format!("worker spawn task failed: {error}"))
                })??;
        let mut stream = UnixStream::from_std(parent)?;
        if let Err(reason) = wait_for_ready(&mut stream, WORKER_READY_TIMEOUT).await {
            return Err(self.startup_failure(&child, &reason).into());
        }
        crate::log_debug!("Virtual-host worker {} is ready", child.id());
        let handshake = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .adaptive_window(true)
            .handshake(TokioIo::new(stream))
            .await;
        let (sender, connection) = match handshake {
            Ok(handshake) => handshake,
            Err(error) => {
                let reason = format!("failed the HTTP/2 handshake: {error}");
                return Err(self.startup_failure(&child, &reason).into());
            }
        };
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                crate::log_error!("virtual host worker connection closed: {error}");
            }
        });
        Ok(WorkerProcess {
            sender,
            child: Some(child.disarm()),
            slot: Some(slot),
        })
    }

    fn startup_failure(&self, _child: &StartingChild, reason: &str) -> String {
        let error_target = self
            .error_log_file
            .as_deref()
            .map_or_else(|| "stderr".to_owned(), |path| path.display().to_string());
        format!(
            "virtual host worker for root {} (uid {}, gid {}) {reason}; it is being stopped and its error was written to {error_target}",
            self.root.display(),
            self.uid,
            self.gid
        )
    }

    /// Sends a client's request to the worker and returns its response.
    pub(super) async fn forward<B>(
        &self,
        request: Request<B>,
        host: Option<&str>,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Response<ResponseBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let request = match worker_request(request, host, peer, local) {
            Ok(request) => request,
            Err((status, message)) => return response::error_response(status, message),
        };

        let request = request.map(|body| {
            body.map_err(|error| io::Error::other(error.into()))
                .boxed_unsync()
        });
        let activity = ActivityGuard::new(self);
        match self.dispatch(request).await {
            Ok(response) => {
                let (parts, body) = response.into_parts();
                let body =
                    response::coalesce_ready_body(body.map_err(io::Error::other).boxed_unsync());
                let body = body
                    .map_frame(move |frame| {
                        let _activity = &activity;
                        frame
                    })
                    .boxed_unsync();
                Response::from_parts(parts, body)
            }
            Err(error) => {
                if error.downcast_ref::<WorkerCapacityExhausted>().is_some() {
                    return worker_capacity_response();
                }
                if error.downcast_ref::<WorkerStartsExhausted>().is_some() {
                    return worker_start_response();
                }
                crate::log_error!("virtual host worker failed: {error}");
                response::error_response(StatusCode::BAD_GATEWAY, "Virtual host worker failed\n")
            }
        }
    }

    async fn dispatch(
        &self,
        request: Request<WorkerRequestBody>,
    ) -> Result<Response<Incoming>, Box<dyn Error + Send + Sync>> {
        // The lock covers only starting the worker and taking a handle to its
        // connection. Holding it while a request is in flight would let one
        // slow request stall every other request for the virtual host.
        let mut sender = {
            let mut process_guard = self.process.lock().await;
            if process_guard
                .as_ref()
                .is_none_or(|process| process.sender.is_closed())
            {
                *process_guard = None;
                let _start_permit = acquire_worker_start(
                    Arc::clone(worker_start_limiter()),
                    WORKER_START_QUEUE_WAIT,
                )
                .await
                .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)?;
                let reservation = worker_pool().reserve(self)?;
                if let Some(evicted) = reservation.evicted {
                    tokio::task::spawn_blocking(move || drop(evicted));
                }
                let _spawn_timing = crate::logging::StageTimer::new(crate::logging::Stage::Spawn);
                *process_guard = Some(self.spawn_process(reservation.slot).await?);
                self.reaper_wake.notify_one();
            }
            process_guard
                .as_ref()
                .expect("worker was started")
                .sender
                .clone()
        };
        let _backend_timing = crate::logging::StageTimer::new(crate::logging::Stage::Backend);
        match sender.send_request(request).await {
            Ok(response) => Ok(response),
            Err(error) => {
                // Only a broken connection condemns the worker; a failure of
                // this one request leaves it serving the others.
                let mut process_guard = self.process.lock().await;
                if process_guard
                    .as_ref()
                    .is_some_and(|process| process.sender.is_closed())
                {
                    *process_guard = None;
                }
                Err(error.into())
            }
        }
    }
}

fn worker_capacity_response() -> Response<ResponseBody> {
    worker_unavailable_response("Too many active workers\n")
}

fn worker_start_response() -> Response<ResponseBody> {
    worker_unavailable_response("Too many workers starting\n")
}

fn worker_unavailable_response(message: &'static str) -> Response<ResponseBody> {
    let mut response = response::error_response(StatusCode::SERVICE_UNAVAILABLE, message);
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

async fn wait_for_ready(stream: &mut UnixStream, ready_timeout: Duration) -> Result<(), String> {
    let result = timeout(ready_timeout, async {
        let mut byte = [0; 1];
        stream.read_exact(&mut byte).await?;
        Ok::<_, io::Error>(byte[0])
    })
    .await;
    match result {
        Ok(Ok(1)) => Ok(()),
        Ok(Ok(_)) => Err("sent an invalid ready signal".to_owned()),
        Ok(Err(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
            Err("exited before becoming ready".to_owned())
        }
        Ok(Err(error)) => Err(format!(
            "failed while waiting for the ready signal: {error}"
        )),
        Err(_) => Err("did not become ready before the timeout".to_owned()),
    }
}

struct ActivityGuard {
    active: Arc<AtomicUsize>,
    last_used: Arc<StdMutex<Instant>>,
}

impl ActivityGuard {
    fn new(worker: &Worker) -> Self {
        worker.active.fetch_add(1, Ordering::AcqRel);
        Self {
            active: Arc::clone(&worker.active),
            last_used: Arc::clone(&worker.last_used),
        }
    }
}

impl Drop for ActivityGuard {
    fn drop(&mut self) {
        *self
            .last_used
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Rewrites a request into the form a virtual host worker expects: an
/// absolute HTTP/2 request carrying the client's addresses and original
/// protocol version as private metadata headers.
///
/// `worker::prepare_request` reverses this, and must recover exactly the
/// path and query that were inspected before routing.
pub(super) fn worker_request<B>(
    mut request: Request<B>,
    host: Option<&str>,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<Request<B>, Rejection> {
    let authority = request_authority(&request)
        .or_else(|| host.map(str::to_owned))
        .unwrap_or_else(|| "localhost".to_owned());
    // The authority is spliced into the worker's request URI below. A `Host`
    // header is free-form text, so one such as `x/admin.php?` would otherwise
    // replace the path that was inspected before routing.
    if authority.parse::<http::uri::Authority>().is_err() {
        return Err((StatusCode::BAD_REQUEST, "Invalid Host\n"));
    }
    if let Ok(value) = HeaderValue::from_str(&authority) {
        request.headers_mut().insert(HOST, value);
    }
    let original_version = version_name(request.version());
    request.headers_mut().insert(
        META_PEER,
        HeaderValue::from_str(&peer.to_string()).expect("socket address is a valid header"),
    );
    request.headers_mut().insert(
        META_LOCAL,
        HeaderValue::from_str(&local.to_string()).expect("socket address is a valid header"),
    );
    request
        .headers_mut()
        .insert(META_VERSION, HeaderValue::from_static(original_version));
    let tls = request.extensions().get::<TlsSni>().is_some();
    request.headers_mut().insert(
        META_TLS,
        HeaderValue::from_static(if tls { "1" } else { "0" }),
    );
    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or("/", |value| value.as_str());
    let path_and_query = if path_and_query == "*" {
        "/"
    } else {
        path_and_query
    };
    let uri = format!("http://{authority}{path_and_query}")
        .parse::<Uri>()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid URI\n"))?;
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_2;
    Ok(request)
}

pub(super) fn resolve_identity(
    user_name: &str,
    group_name: Option<&str>,
) -> Result<(u32, u32), Box<dyn Error + Send + Sync>> {
    let user = User::from_name(user_name)?
        .ok_or_else(|| format!("unknown virtual host user: {user_name}"))?;
    let gid = if let Some(group_name) = group_name {
        Group::from_name(group_name)?
            .ok_or_else(|| format!("unknown virtual host group: {group_name}"))?
            .gid
    } else {
        user.gid
    };
    Ok((user.uid.as_raw(), gid.as_raw()))
}

pub(super) struct WorkerArgs<'a> {
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) root: &'a Path,
    pub(super) index: &'a [String],
    pub(super) listing: bool,
    pub(super) try_files: &'a [String],
    pub(super) fastcgi: &'a [FastCgiBackend],
    pub(super) timeout: Duration,
    pub(super) error_log_format: &'a str,
}

pub(super) fn build_worker_args(worker: WorkerArgs<'_>) -> Vec<OsString> {
    let WorkerArgs {
        uid,
        gid,
        root,
        index,
        listing,
        try_files,
        fastcgi,
        timeout,
        error_log_format,
    } = worker;
    let mut args = vec![
        "--worker".into(),
        "--worker-uid".into(),
        uid.to_string().into(),
        "--worker-gid".into(),
        gid.to_string().into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--fastcgi-timeout".into(),
        timeout.as_secs().to_string().into(),
        "--error-log-format".into(),
        error_log_format.into(),
    ];
    let keepalive = crate::fastcgi::keepalive_limit();
    if keepalive != crate::config::DEFAULT_FASTCGI_KEEPALIVE {
        args.push("--fastcgi-keepalive".into());
        args.push(keepalive.to_string().into());
    }
    let cache_ttl = crate::handler::static_cache_ttl().as_millis();
    if cache_ttl != u128::from(crate::config::DEFAULT_STATIC_CACHE_TTL_MS) {
        args.push("--static-cache-ttl-ms".into());
        args.push(cache_ttl.to_string().into());
    }
    for name in index {
        args.push("--index".into());
        args.push(name.into());
    }
    if !listing {
        args.push("--no-listing".into());
    }
    for entry in try_files {
        args.push("--try-files".into());
        args.push(entry.clone().into());
    }
    for backend in fastcgi {
        if let Some(app) = spawned_app(backend) {
            args.push("--fastcgi-app".into());
            args.push(format!("{}={}", backend.extension, app.program.display()).into());
            for arg in &app.args {
                args.push("--fastcgi-app-arg".into());
                args.push(format!("{}={arg}", backend.extension).into());
            }
            if app.mode != FastCgiAppMode::Cgi {
                args.push("--fastcgi-app-mode".into());
                args.push(format!("{}=fpm", backend.extension).into());
            }
            if !app.php_defaults {
                args.push("--fastcgi-app-php-defaults".into());
                args.push(format!("{}=off", backend.extension).into());
            }
            args.push("--fastcgi-app-max-workers".into());
            args.push(format!("{}={}", backend.extension, app.max_workers).into());
            if app.min_workers != crate::config::DEFAULT_FASTCGI_APP_MIN_WORKERS {
                args.push("--fastcgi-app-min-workers".into());
                args.push(format!("{}={}", backend.extension, app.min_workers).into());
            }
            if app.idle_timeout.as_secs() != crate::config::DEFAULT_FASTCGI_APP_IDLE_TIMEOUT_SECS {
                args.push("--fastcgi-app-idle-timeout".into());
                args.push(format!("{}={}", backend.extension, app.idle_timeout.as_secs()).into());
            }
        } else if let FastCgiAddress::Cgi(interpreter) = &backend.address {
            args.push("--cgi".into());
            args.push(match interpreter {
                Some(interpreter) => {
                    format!("{}={}", backend.extension, interpreter.display()).into()
                }
                None => backend.extension.clone().into(),
            });
        } else {
            args.push("--fastcgi".into());
            args.push(format_backend(backend).into());
        }
    }
    args
}

/// Encodes the environment of a worker's spawned FastCGI apps for
/// `WORKER_APP_ENV`. It travels in the worker's environment rather than its
/// arguments because a command line is readable by every local user, and
/// these values are where applications keep their credentials.
pub(super) fn worker_app_env(fastcgi: &[FastCgiBackend]) -> Option<String> {
    let entries = fastcgi
        .iter()
        .filter_map(|backend| spawned_app(backend).map(|app| (&backend.extension, app)))
        .flat_map(|(extension, app)| {
            app.env
                .iter()
                .map(move |(key, value)| (extension, key, value))
        })
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return None;
    }
    Some(serde_json::to_string(&entries).expect("strings serialize to JSON"))
}

fn spawned_app(backend: &FastCgiBackend) -> Option<&FastCgiApp> {
    match &backend.address {
        FastCgiAddress::Spawn(app) => Some(app),
        FastCgiAddress::Pool(pool) => Some(pool.app()),
        FastCgiAddress::Tcp(_) | FastCgiAddress::Unix(_) | FastCgiAddress::Cgi(_) => None,
    }
}

/// Variables a worker keeps from the server's environment. Everything else,
/// including whatever credentials the server was started with, is withheld.
const WORKER_INHERITED_ENV: [&str; 6] = [
    "PATH",
    "TMPDIR",
    "LD_LIBRARY_PATH",
    "LANG",
    "TZ",
    "MALLOC_ARENA_MAX",
];

fn format_backend(backend: &FastCgiBackend) -> String {
    match &backend.address {
        FastCgiAddress::Tcp(address) => format!("{}={address}", backend.extension),
        FastCgiAddress::Unix(path) => format!("{}=unix:{}", backend.extension, path.display()),
        FastCgiAddress::Cgi(interpreter) => match interpreter {
            Some(interpreter) => {
                format!("{}={}", backend.extension, interpreter.display())
            }
            None => backend.extension.clone(),
        },
        FastCgiAddress::Spawn(app) => format!("{}={}", backend.extension, app.program.display()),
        FastCgiAddress::Pool(pool) => {
            format!("{}={}", backend.extension, pool.app().program.display())
        }
    }
}

fn version_name(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "HTTP/0.9",
        Version::HTTP_10 => "HTTP/1.0",
        Version::HTTP_11 => "HTTP/1.1",
        Version::HTTP_2 => "HTTP/2.0",
        Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/1.1",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ActivityGuard, StartingChild, WORKER_SHUTDOWN_GRACE, Worker, WorkerChild, WorkerPool,
        WorkerProcess, acquire_worker_start, stop_direct_worker, wait_for_ready,
        worker_capacity_response, worker_start_response,
    };
    use bytes::Bytes;
    use http::{Request, Response, StatusCode, header::RETRY_AFTER};
    use http_body_util::{BodyExt, Full};
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::{
        convert::Infallible,
        path::PathBuf,
        process::Command,
        sync::{Arc, Mutex as StdMutex, atomic::AtomicUsize},
        time::{Duration, Instant},
    };
    use tokio::{net::UnixStream, sync::Mutex};

    #[tokio::test]
    async fn wait_for_ready_accepts_ready_signal() {
        let (mut reader, writer) = UnixStream::pair().unwrap();
        writer.try_write(&[1]).unwrap();

        assert_eq!(
            wait_for_ready(&mut reader, Duration::from_secs(1)).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn wait_for_ready_rejects_invalid_ready_signal() {
        let (mut reader, writer) = UnixStream::pair().unwrap();
        writer.try_write(&[0]).unwrap();

        assert_eq!(
            wait_for_ready(&mut reader, Duration::from_secs(1)).await,
            Err("sent an invalid ready signal".to_owned())
        );
    }

    #[tokio::test]
    async fn wait_for_ready_reports_eof_before_ready() {
        let (mut reader, writer) = UnixStream::pair().unwrap();
        drop(writer);

        assert_eq!(
            wait_for_ready(&mut reader, Duration::from_secs(1)).await,
            Err("exited before becoming ready".to_owned())
        );
    }

    #[tokio::test]
    async fn wait_for_ready_reports_timeout() {
        let (mut reader, _writer) = UnixStream::pair().unwrap();

        assert_eq!(
            wait_for_ready(&mut reader, Duration::from_millis(10)).await,
            Err("did not become ready before the timeout".to_owned())
        );
    }

    #[tokio::test]
    async fn reap_idle_keeps_worker_with_active_request() {
        let worker = test_worker(
            Duration::from_millis(10),
            Instant::now() - Duration::from_secs(1),
        )
        .await;
        worker.active.store(1, std::sync::atomic::Ordering::Release);

        worker.reap_idle(Duration::from_millis(10)).await;

        assert!(worker.process_is_running().await);
    }

    #[tokio::test]
    async fn reap_idle_keeps_recently_used_worker() {
        let worker = test_worker(Duration::from_secs(10), Instant::now()).await;

        worker.reap_idle(Duration::from_secs(10)).await;

        assert!(worker.process_is_running().await);
    }

    #[tokio::test]
    async fn idle_reaper_wakes_when_a_process_is_started() {
        let timeout = Duration::from_millis(10);
        let worker = Arc::new(test_worker(timeout, Instant::now() - Duration::from_secs(1)).await);
        let process = worker.process.lock().await.take();
        Worker::spawn_idle_reaper(&worker, timeout);
        tokio::task::yield_now().await;

        *worker.process.lock().await = process;
        worker.reaper_wake.notify_one();

        tokio::time::timeout(Duration::from_secs(1), async {
            while worker.process_is_running().await {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("idle process should be reaped after the reaper is woken");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn reap_idle_stops_expired_worker_and_reaps_its_child() {
        let timeout = Duration::from_millis(10);
        let worker = test_worker(timeout, Instant::now() - Duration::from_secs(1)).await;
        let pid = {
            let process = worker.process.lock().await;
            let Some(WorkerProcess {
                child: Some(WorkerChild::Direct(child)),
                ..
            }) = process.as_ref()
            else {
                panic!("expected direct worker process")
            };
            child.id()
        };

        worker.reap_idle(timeout).await;

        assert!(!worker.process_is_running().await);
        // The worker is stopped on a blocking task (SIGTERM, a grace period,
        // then SIGKILL), so its pid disappears asynchronously.
        tokio::time::timeout(Duration::from_secs(5), async {
            while PathBuf::from(format!("/proc/{pid}")).exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("idle worker child should be reaped");
    }

    #[tokio::test]
    async fn activity_guard_in_streaming_body_prevents_idle_reaping() {
        let timeout = Duration::from_millis(10);
        let worker = test_worker(timeout, Instant::now() - Duration::from_secs(1)).await;
        let activity = ActivityGuard::new(&worker);
        let mut body = Full::new(Bytes::from_static(b"streaming"))
            .map_frame(move |frame| {
                let _activity = &activity;
                frame
            })
            .boxed_unsync();

        worker.reap_idle(timeout).await;

        assert!(worker.process_is_running().await);
        assert_eq!(worker.active.load(std::sync::atomic::Ordering::Acquire), 1);
        let _ = body.frame().await;
        drop(body);
        assert_eq!(worker.active.load(std::sync::atomic::Ordering::Acquire), 0);
    }

    #[test]
    fn worker_pool_reserves_up_to_the_limit_and_releases_capacity_on_drop() {
        let pool = Arc::new(WorkerPool::new(2));
        let first = pool_test_worker(Instant::now());
        let second = pool_test_worker(Instant::now());
        let third = pool_test_worker(Instant::now());
        let first_slot = pool.reserve(&first).unwrap().slot;
        let second_slot = pool.reserve(&second).unwrap().slot;

        assert!(pool.reserve(&third).is_err());

        drop(first_slot);
        let third_slot = pool.reserve(&third).unwrap().slot;
        drop((second_slot, third_slot));
    }

    #[tokio::test]
    async fn worker_pool_evicts_the_least_recently_used_idle_process() {
        let pool = Arc::new(WorkerPool::new(2));
        let now = Instant::now();
        let older =
            Arc::new(test_worker(Duration::from_secs(60), now - Duration::from_secs(2)).await);
        let newer =
            Arc::new(test_worker(Duration::from_secs(60), now - Duration::from_secs(1)).await);
        let requester = pool_test_worker(now);

        let old_slot = pool.reserve(&older).unwrap().slot;
        older.process.lock().await.as_mut().unwrap().slot = Some(old_slot);
        let new_slot = pool.reserve(&newer).unwrap().slot;
        newer.process.lock().await.as_mut().unwrap().slot = Some(new_slot);

        let reservation = pool.reserve(&requester).unwrap();
        assert!(reservation.evicted.is_some());
        assert!(!older.process_is_running().await);
        assert!(newer.process_is_running().await);
        assert_eq!(pool.state.lock().unwrap().entries.len(), 2);

        let evicted = reservation.evicted.unwrap();
        assert!(evicted.slot.is_none());
        tokio::task::spawn_blocking(move || drop(evicted))
            .await
            .unwrap();
        drop(reservation.slot);
    }

    #[tokio::test]
    async fn worker_pool_does_not_evict_busy_or_locked_workers() {
        let pool = Arc::new(WorkerPool::new(1));
        let worker = Arc::new(test_worker(Duration::from_secs(60), Instant::now()).await);
        let requester = pool_test_worker(Instant::now());
        let slot = pool.reserve(&worker).unwrap().slot;
        worker.process.lock().await.as_mut().unwrap().slot = Some(slot);

        worker.active.store(1, std::sync::atomic::Ordering::Release);
        assert!(pool.reserve(&requester).is_err());

        worker.active.store(0, std::sync::atomic::Ordering::Release);
        let _process = worker.process.lock().await;
        assert!(pool.reserve(&requester).is_err());
    }

    #[tokio::test]
    async fn worker_start_limiter_times_out_when_all_slots_are_occupied() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        assert!(
            acquire_worker_start(Arc::clone(&semaphore), Duration::from_millis(10))
                .await
                .is_err()
        );
        drop(permit);
        assert!(
            acquire_worker_start(semaphore, Duration::from_millis(10))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn cancelling_startup_stops_and_reaps_the_child() {
        let child = Command::new("sleep").arg("60").spawn().unwrap();
        let pid = child.id();
        let starting = StartingChild::new(WorkerChild::Direct(child));
        let task = tokio::spawn(async move {
            let _starting = starting;
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("cancelled worker startup should stop and reap its child");
    }

    #[test]
    fn worker_capacity_exhaustion_returns_retryable_service_unavailable() {
        let response = worker_capacity_response();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "1");
    }

    #[test]
    fn worker_start_exhaustion_returns_retryable_service_unavailable() {
        let response = worker_start_response();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "1");
    }

    fn pool_test_worker(last_used: Instant) -> Arc<Worker> {
        Arc::new(Worker {
            uid: 0,
            gid: 0,
            root: PathBuf::from("/tmp/test-worker"),
            cgroup: None,
            idle_timeout: None,
            active: Arc::new(AtomicUsize::new(0)),
            last_used: Arc::new(StdMutex::new(last_used)),
            index: vec!["index.html".to_owned()],
            listing: true,
            try_files: Vec::new(),
            fastcgi: Vec::new(),
            fastcgi_timeout: Duration::from_secs(60),
            threads: 1,
            error_log_file: None,
            error_log_format: String::new(),
            process: Arc::new(Mutex::new(None)),
            reaper_wake: Arc::new(tokio::sync::Notify::new()),
        })
    }

    async fn test_worker(timeout: Duration, last_used: Instant) -> Worker {
        let (client, peer) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let service = service_fn(|_request: Request<hyper::body::Incoming>| async {
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .adaptive_window(true)
                .serve_connection(TokioIo::new(peer), service)
                .await;
        });
        let (sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .adaptive_window(true)
            .handshake(TokioIo::new(client))
            .await
            .unwrap();
        tokio::spawn(connection);
        let child = Command::new("sleep").arg("60").spawn().unwrap();

        Worker {
            uid: 0,
            gid: 0,
            root: PathBuf::from("/tmp/test-worker"),
            cgroup: None,
            idle_timeout: Some(timeout),
            active: Arc::new(AtomicUsize::new(0)),
            last_used: Arc::new(StdMutex::new(last_used)),
            index: vec!["index.html".to_owned()],
            listing: true,
            try_files: Vec::new(),
            fastcgi: Vec::new(),
            fastcgi_timeout: Duration::from_secs(60),
            threads: 1,
            error_log_file: None,
            error_log_format: String::new(),
            process: Arc::new(Mutex::new(Some(WorkerProcess {
                sender,
                child: Some(WorkerChild::Direct(child)),
                slot: None,
            }))),
            reaper_wake: Arc::new(tokio::sync::Notify::new()),
        }
    }

    #[test]
    fn stop_direct_worker_kills_and_reaps_a_child_that_ignores_sigterm() {
        let mut child = Command::new("sh")
            .args(["-c", "trap '' TERM; while :; do :; done"])
            .spawn()
            .unwrap();
        let started = Instant::now();

        stop_direct_worker(&mut child, false).unwrap();

        assert!(started.elapsed() < WORKER_SHUTDOWN_GRACE * 4);
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn stop_direct_worker_accepts_an_already_exited_child() {
        let mut child = Command::new("true").spawn().unwrap();
        assert!(child.wait().unwrap().success());

        stop_direct_worker(&mut child, false).unwrap();
        assert!(child.try_wait().unwrap().is_some());
    }
}
