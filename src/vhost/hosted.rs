//! Spawns, supervises, and forwards requests to workers for hosted virtual hosts.

use std::{
    error::Error,
    ffi::OsString,
    io,
    net::SocketAddr,
    os::{
        fd::OwnedFd,
        unix::{net::UnixStream as StdUnixStream, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Request, Response, StatusCode, Uri, Version, header::HOST};
use http_body::Body;
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};
use hyper::{body::Incoming, client::conn::http2::SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo};
use nix::{
    sys::signal::{Signal, kill},
    unistd::{Group, Pid, User},
};
use tokio::{io::AsyncReadExt, net::UnixStream, sync::Mutex, time::timeout};

use super::{Rejection, TlsSni, request_authority};
use crate::{
    config::{FastCgiAddress, FastCgiApp, FastCgiBackend},
    response::{self, ResponseBody},
};

const META_PEER: HeaderName = HeaderName::from_static("x-charlotte-peer");
const META_LOCAL: HeaderName = HeaderName::from_static("x-charlotte-local");
const META_VERSION: HeaderName = HeaderName::from_static("x-charlotte-version");
const META_TLS: HeaderName = HeaderName::from_static("x-charlotte-tls");
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a worker is given to shut down on its own before it is killed.
const WORKER_SHUTDOWN_GRACE: Duration = Duration::from_millis(500);
const WORKER_SHUTDOWN_POLL: Duration = Duration::from_millis(5);

type WorkerRequestBody = UnsyncBoxBody<Bytes, io::Error>;
type WorkerSender = SendRequest<WorkerRequestBody>;

pub(super) struct Worker {
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) root: PathBuf,
    pub(super) index: String,
    pub(super) listing: bool,
    pub(super) try_files: Vec<String>,
    pub(super) fastcgi: Vec<FastCgiBackend>,
    pub(super) fastcgi_timeout: Duration,
    pub(super) threads: usize,
    pub(super) process: Mutex<Option<WorkerProcess>>,
}

pub(super) struct WorkerProcess {
    pub(super) sender: WorkerSender,
    pub(super) child: Child,
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        // SIGKILL alone would stop the worker before it could drop the handles
        // that stop its FastCGI apps, orphaning those apps along with every
        // descriptor they inherited. Ask for an orderly exit first, and fall
        // back to SIGKILL only if the worker does not take it. The wait is
        // bounded and short because this runs on whichever thread drops the
        // worker, which may be a runtime thread.
        if let Ok(pid) = i32::try_from(self.child.id())
            && kill(Pid::from_raw(pid), Signal::SIGTERM).is_ok()
        {
            let deadline = Instant::now() + WORKER_SHUTDOWN_GRACE;
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) => {}
                    Err(_) => break,
                }
                if Instant::now() >= deadline {
                    break;
                }
                thread::sleep(WORKER_SHUTDOWN_POLL);
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Worker {
    pub(super) async fn spawn_process(
        &self,
    ) -> Result<WorkerProcess, Box<dyn Error + Send + Sync>> {
        let (parent, child_socket) = StdUnixStream::pair()?;
        parent.set_nonblocking(true)?;
        let mut command = Command::new(std::env::current_exe()?);
        if crate::privileges::can_set_ids()? {
            command.uid(self.uid).gid(self.gid);
        }
        command
            .args(build_worker_args(WorkerArgs {
                uid: self.uid,
                gid: self.gid,
                root: &self.root,
                index: &self.index,
                listing: self.listing,
                try_files: &self.try_files,
                fastcgi: &self.fastcgi,
                timeout: self.fastcgi_timeout,
            }))
            .arg("--worker-threads")
            .arg(self.threads.to_string())
            .env_clear()
            .envs(
                WORKER_INHERITED_ENV
                    .iter()
                    .filter_map(|name| std::env::var_os(name).map(|value| (name, value))),
            )
            .stdin(Stdio::from(OwnedFd::from(child_socket)))
            .current_dir("/");
        if let Some(app_env) = worker_app_env(&self.fastcgi) {
            command.env(crate::config::WORKER_APP_ENV, app_env);
        }

        let mut child = command.spawn()?;
        drop(command);
        let mut stream = UnixStream::from_std(parent)?;
        let ready_result = timeout(WORKER_READY_TIMEOUT, async {
            let mut byte = [0; 1];
            stream.read_exact(&mut byte).await?;
            Ok::<_, io::Error>(byte[0])
        })
        .await;
        match ready_result {
            Ok(Ok(1)) => {}
            Ok(Ok(_)) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("virtual host worker sent an invalid ready signal".into());
            }
            Ok(Err(error)) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("virtual host worker did not become ready".into());
            }
        }
        let handshake =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await;
        let (sender, connection) = match handshake {
            Ok(handshake) => handshake,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.into());
            }
        };
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("virtual host worker connection closed: {error}");
            }
        });
        Ok(WorkerProcess { sender, child })
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
        match self.dispatch(request).await {
            Ok(response) => {
                let (parts, body) = response.into_parts();
                let body =
                    response::coalesce_ready_body(body.map_err(io::Error::other).boxed_unsync());
                Response::from_parts(parts, body)
            }
            Err(error) => {
                eprintln!("virtual host worker failed: {error}");
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
                *process_guard = Some(self.spawn_process().await?);
            }
            process_guard
                .as_ref()
                .expect("worker was started")
                .sender
                .clone()
        };
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
    pub(super) index: &'a str,
    pub(super) listing: bool,
    pub(super) try_files: &'a [String],
    pub(super) fastcgi: &'a [FastCgiBackend],
    pub(super) timeout: Duration,
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
    } = worker;
    let mut args = vec![
        "--worker".into(),
        "--worker-uid".into(),
        uid.to_string().into(),
        "--worker-gid".into(),
        gid.to_string().into(),
        "--root".into(),
        root.as_os_str().to_owned(),
        "--index".into(),
        index.into(),
        "--fastcgi-timeout".into(),
        timeout.as_secs().to_string().into(),
    ];
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
            if app.max_workers != 1 {
                args.push("--fastcgi-app-max-workers".into());
                args.push(format!("{}={}", backend.extension, app.max_workers).into());
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
const WORKER_INHERITED_ENV: [&str; 5] = ["PATH", "TMPDIR", "LD_LIBRARY_PATH", "LANG", "TZ"];

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
