use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsString,
    io,
    net::SocketAddr,
    os::{fd::OwnedFd, unix::net::UnixStream as StdUnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, RwLock},
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
use serde::Deserialize;
use tokio::{io::AsyncReadExt, net::UnixStream, sync::Mutex, time::timeout};

use crate::{
    acme::AcmeManager,
    config::{Config, FastCgiAddress, FastCgiBackend, TlsFiles},
    handler::{self, ResponseBody},
    waf::{RuleIdSpec, Waf},
};

const META_PEER: HeaderName = HeaderName::from_static("x-charlotte-peer");
const META_LOCAL: HeaderName = HeaderName::from_static("x-charlotte-local");
const META_VERSION: HeaderName = HeaderName::from_static("x-charlotte-version");
const WORKER_READY_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a worker is given to shut down on its own before it is killed.
const WORKER_SHUTDOWN_GRACE: Duration = Duration::from_millis(500);
const WORKER_SHUTDOWN_POLL: Duration = Duration::from_millis(5);

type WorkerRequestBody = UnsyncBoxBody<Bytes, io::Error>;
type WorkerSender = SendRequest<WorkerRequestBody>;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    vhost: Vec<VhostFile>,
    #[serde(default)]
    vhost_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VhostFile {
    server_names: Vec<String>,
    root: PathBuf,
    user: String,
    group: Option<String>,
    index: Option<String>,
    listing: Option<bool>,
    #[serde(default)]
    fastcgi: Vec<String>,
    #[serde(default)]
    fastcgi_app: Vec<FastCgiAppFile>,
    fastcgi_timeout: Option<u64>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    #[serde(default)]
    default: bool,
    #[serde(default)]
    modsecurity_disable_rules: Vec<RuleIdFile>,
    acme: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum RuleIdFile {
    Integer(u64),
    RangeOrId(String),
}

impl RuleIdFile {
    fn parse(&self) -> Result<RuleIdSpec, String> {
        match self {
            Self::Integer(id) => id.to_string().parse(),
            Self::RangeOrId(value) => value.parse(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FastCgiAppFile {
    extension: String,
    command: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

struct Vhost {
    names: Vec<String>,
    tls: Option<TlsFiles>,
    acme: bool,
    default: bool,
    waf: Option<Waf>,
    worker: Arc<Worker>,
}

struct Worker {
    uid: u32,
    gid: u32,
    root: PathBuf,
    index: String,
    listing: bool,
    fastcgi: Vec<FastCgiBackend>,
    fastcgi_timeout: Duration,
    process: Mutex<Option<WorkerProcess>>,
}

struct WorkerProcess {
    sender: WorkerSender,
    child: Child,
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

pub(crate) struct Router {
    fallback: Arc<Config>,
    table: RwLock<Arc<VhostTable>>,
    sources: Mutex<SourceState>,
    dir: Option<PathBuf>,
    waf: Option<Waf>,
    acme: Option<AcmeManager>,
}

struct VhostTable {
    vhosts: Vec<Arc<Vhost>>,
    default: Option<usize>,
}

struct SourceState {
    main_entries: Vec<VhostFile>,
    main_vhosts: Option<Vec<Arc<Vhost>>>,
    files: BTreeMap<PathBuf, LoadedSource>,
}

struct LoadedSource {
    content: String,
    entries: Vec<VhostFile>,
    vhosts: Vec<Arc<Vhost>>,
}

#[derive(Clone, Debug)]
pub(crate) struct TlsSni(pub Option<String>);

impl Router {
    pub(crate) async fn load(
        fallback: Arc<Config>,
        path: Option<&PathBuf>,
        waf: Option<Waf>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let current_dir = std::env::current_dir()?;
        let config_dir = if let Some(path) = path {
            let config_dir = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."));
            if config_dir.is_absolute() {
                config_dir.to_path_buf()
            } else {
                current_dir.join(config_dir)
            }
        } else {
            current_dir.clone()
        };
        let file = if let Some(path) = path {
            let content = std::fs::read_to_string(path)?;
            toml::from_str(&content)?
        } else {
            FileConfig {
                vhost: Vec::new(),
                vhost_dir: None,
            }
        };
        let dir = fallback
            .vhost_dir
            .clone()
            .or_else(|| {
                file.vhost_dir
                    .clone()
                    .map(|dir| resolve_config_path(dir, &config_dir))
            })
            .map(|dir| resolve_config_path(dir, &current_dir));
        let mut router = Self::from_file(Arc::clone(&fallback), file, &config_dir, waf).await?;
        router.dir = dir;
        if router.dir.is_some() {
            router.reload_dir().await?;
        }
        Ok(router)
    }

    pub(crate) async fn reload_dir(&self) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let Some(dir) = &self.dir else {
            return Ok(false);
        };
        let mut sources = self.sources.lock().await;
        let paths = scan_vhost_files(dir)?;
        let mut candidates = Vec::with_capacity(paths.len());
        for path in paths {
            let content = std::fs::read_to_string(&path)?;
            let old = sources.files.get(&path);
            let entries = if old.is_some_and(|source| source.content == content) {
                old.expect("checked source exists").entries.clone()
            } else {
                let file: FileConfig = toml::from_str(&content)?;
                file.vhost
            };
            candidates.push((path, content, entries));
        }

        let mut all_entries = sources.main_entries.clone();
        for (_, _, entries) in &candidates {
            all_entries.extend(entries.iter().cloned());
        }
        validate_vhost_declarations(&all_entries)?;
        validate_vhost_waf_declarations(&all_entries, self.waf.is_some())?;

        let mut changed = sources.main_vhosts.is_none()
            || sources.files.len() != candidates.len()
            || candidates.iter().any(|(path, content, _)| {
                sources
                    .files
                    .get(path)
                    .is_none_or(|source| source.content != *content)
            });
        let main_vhosts = match &sources.main_vhosts {
            Some(vhosts) => vhosts.clone(),
            None => {
                let file = FileConfig {
                    vhost: sources.main_entries.clone(),
                    vhost_dir: None,
                };
                let router = Self::from_file(
                    Arc::clone(&self.fallback),
                    file,
                    &std::env::current_dir()?,
                    self.waf,
                )
                .await?;
                router.snapshot().vhosts.clone()
            }
        };

        let mut loaded = BTreeMap::new();
        for (path, content, entries) in candidates {
            if let Some(old) = sources.files.get(&path)
                && old.content == content
            {
                loaded.insert(
                    path,
                    LoadedSource {
                        content,
                        entries,
                        vhosts: old.vhosts.clone(),
                    },
                );
                continue;
            }
            let config_dir = path.parent().unwrap_or(dir);
            let mut vhosts = Vec::with_capacity(entries.len());
            for entry in &entries {
                let router = Self::from_file(
                    Arc::clone(&self.fallback),
                    FileConfig {
                        vhost: vec![entry.clone()],
                        vhost_dir: None,
                    },
                    config_dir,
                    self.waf,
                )
                .await?;
                vhosts.extend(router.snapshot().vhosts.iter().cloned());
            }
            loaded.insert(
                path,
                LoadedSource {
                    content,
                    entries,
                    vhosts,
                },
            );
        }

        let mut vhosts = main_vhosts.clone();
        for source in loaded.values() {
            vhosts.extend(source.vhosts.iter().cloned());
        }
        let default = vhosts.iter().position(|vhost| vhost.default);
        let new_table = Arc::new(VhostTable { vhosts, default });
        if !changed {
            changed = new_table.vhosts.len() != self.snapshot().vhosts.len();
        }
        sources.main_vhosts = Some(main_vhosts);
        sources.files = loaded;
        if changed {
            *self
                .table
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = new_table;
        }
        Ok(changed)
    }

    fn snapshot(&self) -> Arc<VhostTable> {
        Arc::clone(
            &self
                .table
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    async fn from_file(
        fallback: Arc<Config>,
        file: FileConfig,
        config_dir: &Path,
        waf: Option<Waf>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        validate_vhost_declarations(&file.vhost)?;
        validate_vhost_waf_declarations(&file.vhost, waf.is_some())?;
        let main_entries = file.vhost.clone();
        let mut vhosts = Vec::with_capacity(file.vhost.len());
        let default = file.vhost.iter().position(|entry| entry.default);

        for entry in file.vhost {
            let disabled_rules = entry
                .modsecurity_disable_rules
                .iter()
                .map(RuleIdFile::parse)
                .collect::<Result<Vec<_>, _>>()
                .map_err(io::Error::other)?;
            let vhost_waf = if disabled_rules.is_empty() {
                waf
            } else {
                Some(
                    waf.expect("non-empty rule exclusions require a global WAF")
                        .without_rules(&disabled_rules)?,
                )
            };
            let mut normalized_names = Vec::with_capacity(entry.server_names.len());
            for name in entry.server_names {
                let normalized = normalize_server_name(&name)
                    .ok_or_else(|| format!("invalid virtual host name: {name}"))?;
                normalized_names.push(normalized);
            }

            let (uid, gid) = resolve_identity(&entry.user, entry.group.as_deref())?;
            let index_name = entry.index.unwrap_or_else(|| fallback.index.clone());
            validate_index(&index_name)?;
            let listing = entry.listing.unwrap_or(fallback.listing);
            let mut fastcgi = entry
                .fastcgi
                .iter()
                .map(|value| crate::config::parse_fastcgi_backend(value))
                .collect::<Result<Vec<_>, _>>()?;
            let mut extensions = std::collections::HashSet::new();
            for backend in &fastcgi {
                if !extensions.insert(backend.extension.clone()) {
                    return Err(format!(
                        "duplicate FastCGI extension in vhost: {}",
                        backend.extension
                    )
                    .into());
                }
            }
            for app_file in entry.fastcgi_app {
                let Some(program) = app_file.command.first() else {
                    return Err(format!(
                        "vhost FastCGI app .{} command must not be empty",
                        app_file.extension
                    )
                    .into());
                };
                let extension = crate::config::normalize_extension(&app_file.extension)?;
                if !extensions.insert(extension.clone()) {
                    return Err(format!("duplicate FastCGI extension in vhost: {extension}").into());
                }
                if app_file.command.iter().any(|part| part.contains('\0')) {
                    return Err("vhost FastCGI app command cannot contain NUL".into());
                }
                for (key, value) in &app_file.env {
                    crate::config::validate_env_key(key)?;
                    if value.contains('\0') {
                        return Err("vhost FastCGI app environment value cannot contain NUL".into());
                    }
                }
                let mut backend =
                    crate::config::parse_fastcgi_app(&format!("{extension}={program}"))?;
                if let FastCgiAddress::Spawn(app) = &mut backend.address {
                    app.args = app_file.command.into_iter().skip(1).collect();
                    app.env = app_file.env;
                }
                fastcgi.push(backend);
            }
            let fastcgi = fastcgi
                .into_iter()
                .map(|mut backend| {
                    if let FastCgiAddress::Unix(path) = &mut backend.address
                        && path.is_relative()
                    {
                        *path = config_dir.join(&*path);
                    }
                    backend
                })
                .collect();
            let timeout_seconds = entry
                .fastcgi_timeout
                .unwrap_or(fallback.fastcgi_timeout.as_secs());
            if timeout_seconds == 0 {
                return Err("vhost FastCGI timeout must be greater than zero".into());
            }
            let tls = match (entry.tls_cert, entry.tls_key) {
                (Some(cert), Some(key)) => Some(TlsFiles {
                    cert: resolve_config_path(cert, config_dir),
                    key: resolve_config_path(key, config_dir),
                }),
                (None, None) => None,
                _ => return Err("vhost tls_cert and tls_key must be supplied together".into()),
            };
            let root = if entry.root.is_absolute() {
                entry.root
            } else {
                config_dir.join(entry.root)
            };
            let worker = Arc::new(Worker {
                uid,
                gid,
                root,
                index: index_name,
                listing,
                fastcgi,
                fastcgi_timeout: Duration::from_secs(timeout_seconds),
                process: Mutex::new(None),
            });
            let process = worker.spawn_process().await?;
            *worker.process.lock().await = Some(process);
            vhosts.push(Vhost {
                names: normalized_names,
                tls,
                acme: entry.acme.unwrap_or(true),
                default: entry.default,
                waf: vhost_waf,
                worker,
            });
        }

        let vhosts = vhosts.into_iter().map(Arc::new).collect::<Vec<_>>();
        Ok(Self {
            fallback,
            table: RwLock::new(Arc::new(VhostTable {
                vhosts: vhosts.clone(),
                default,
            })),
            sources: Mutex::new(SourceState {
                main_entries,
                main_vhosts: Some(vhosts),
                files: BTreeMap::new(),
            }),
            dir: None,
            waf,
            acme: None,
        })
    }

    pub(crate) fn acme_names(&self) -> Vec<String> {
        self.snapshot()
            .vhosts
            .iter()
            .filter(|vhost| vhost.acme && vhost.tls.is_none())
            .flat_map(|vhost| vhost.names.iter())
            .filter(|name| !name.starts_with("*."))
            .cloned()
            .collect()
    }

    pub(crate) fn document_roots(&self) -> Vec<PathBuf> {
        let table = self.snapshot();
        std::iter::once(self.fallback.root.clone())
            .chain(table.vhosts.iter().map(|vhost| vhost.worker.root.clone()))
            .collect()
    }

    pub(crate) fn set_acme_manager(&mut self, acme: Option<AcmeManager>) {
        self.acme = acme;
    }

    pub(crate) fn vhost_dir(&self) -> Option<PathBuf> {
        self.dir.clone()
    }

    pub(crate) async fn dispatch<B>(
        &self,
        request: Request<B>,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Response<ResponseBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let table = self.snapshot();
        if let Some(acme) = &self.acme {
            let host = request_host(&request);
            if request.method() == http::Method::GET
                && let Some(host) = host.as_deref()
                && let Some(body) = acme.challenge_response(host, request.uri().path()).await
            {
                return handler::text_response(StatusCode::OK, body);
            }
            if request.extensions().get::<TlsSni>().is_none()
                && let Some(host) = host.as_deref()
            {
                acme.maybe_provision(host);
            }
        }
        let selected = request_host(&request)
            .as_deref()
            .and_then(|host| Self::select_vhost(&table, host))
            .or(table.default);
        let waf = selected
            .and_then(|index| table.vhosts[index].waf)
            .or(self.waf);
        if let Some(waf) = waf {
            return waf
                .inspect(request, peer, local, |request| {
                    self.route(request, peer, local, Arc::clone(&table))
                })
                .await;
        }
        self.route(request, peer, local, table).await
    }

    pub(crate) fn sni_certificates(&self) -> (Vec<(String, TlsFiles)>, Option<TlsFiles>) {
        let table = self.snapshot();
        let entries = table
            .vhosts
            .iter()
            .filter_map(|vhost| {
                vhost.tls.as_ref().map(|tls| {
                    vhost
                        .names
                        .iter()
                        .cloned()
                        .map(|name| (name, tls.clone()))
                        .collect::<Vec<_>>()
                })
            })
            .flatten()
            .collect();
        let fallback = table
            .default
            .and_then(|index| table.vhosts[index].tls.clone());
        (entries, fallback)
    }

    async fn route<B>(
        &self,
        mut request: Request<B>,
        peer: SocketAddr,
        local: SocketAddr,
        table: Arc<VhostTable>,
    ) -> Response<ResponseBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let host = request_host(&request);
        if let (Some(TlsSni(Some(sni))), Some(host)) =
            (request.extensions().get::<TlsSni>(), host.as_deref())
        {
            let sni_selected = normalize_host(sni)
                .as_deref()
                .and_then(|sni| Self::select_vhost(&table, sni))
                .or(table.default);
            let host_selected = Self::select_vhost(&table, host).or(table.default);
            if sni_selected != host_selected {
                return handler::error_response(
                    StatusCode::MISDIRECTED_REQUEST,
                    "Request authority does not match TLS server name\n",
                );
            }
        }
        let selected = host
            .as_deref()
            .and_then(|host| Self::select_vhost(&table, host))
            .or(table.default);
        let Some(index) = selected else {
            return handler::handle_request(request, Arc::clone(&self.fallback), peer, local).await;
        };

        let authority = request_authority(&request)
            .or_else(|| host.map(|host| host.to_owned()))
            .unwrap_or_else(|| "localhost".to_owned());
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
        let path_and_query = request
            .uri()
            .path_and_query()
            .map_or("/", |value| value.as_str());
        let path_and_query = if path_and_query == "*" {
            "/"
        } else {
            path_and_query
        };
        let uri = match format!("http://{authority}{path_and_query}").parse::<Uri>() {
            Ok(uri) => uri,
            Err(_) => return handler::error_response(StatusCode::BAD_REQUEST, "Invalid URI\n"),
        };
        *request.uri_mut() = uri;
        *request.version_mut() = Version::HTTP_2;

        let request = request.map(|body| {
            body.map_err(|error| io::Error::other(error.into()))
                .boxed_unsync()
        });
        match table.vhosts[index].worker.dispatch(request).await {
            Ok(response) => {
                let (parts, body) = response.into_parts();
                let body = body.map_err(io::Error::other).boxed_unsync();
                Response::from_parts(parts, body)
            }
            Err(error) => {
                eprintln!("virtual host worker failed: {error}");
                handler::error_response(StatusCode::BAD_GATEWAY, "Virtual host worker failed\n")
            }
        }
    }

    fn select_vhost(table: &VhostTable, host: &str) -> Option<usize> {
        table
            .vhosts
            .iter()
            .enumerate()
            .filter_map(|(index, vhost)| {
                vhost
                    .names
                    .iter()
                    .filter_map(|name| match_score(name, host))
                    .max()
                    .map(|score| (index, score))
            })
            .max_by_key(|(_, score)| *score)
            .map(|(index, _)| index)
    }
}

impl Worker {
    async fn spawn_process(&self) -> Result<WorkerProcess, Box<dyn Error + Send + Sync>> {
        let (parent, child_socket) = StdUnixStream::pair()?;
        parent.set_nonblocking(true)?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args(build_worker_args(
                self.uid,
                self.gid,
                &self.root,
                &self.index,
                self.listing,
                &self.fastcgi,
                self.fastcgi_timeout,
            ))
            .stdin(Stdio::from(OwnedFd::from(child_socket)))
            .current_dir("/");

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

    async fn dispatch(
        &self,
        request: Request<WorkerRequestBody>,
    ) -> Result<Response<Incoming>, Box<dyn Error + Send + Sync>> {
        let mut process_guard = self.process.lock().await;
        if process_guard
            .as_ref()
            .is_none_or(|process| process.sender.is_closed())
        {
            *process_guard = None;
            *process_guard = Some(self.spawn_process().await?);
        }
        let process = process_guard.as_mut().expect("worker was started");
        match process.sender.send_request(request).await {
            Ok(response) => Ok(response),
            Err(error) => {
                *process_guard = None;
                Err(error.into())
            }
        }
    }
}

fn request_authority<B>(request: &Request<B>) -> Option<String> {
    request
        .uri()
        .authority()
        .map(ToString::to_string)
        .or_else(|| {
            request
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
}

fn request_host<B>(request: &Request<B>) -> Option<String> {
    let host_authority = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<http::uri::Authority>().ok());
    let authority = request.uri().authority().or(host_authority.as_ref())?;
    normalize_host(authority.host())
}

pub(crate) fn normalize_host(value: &str) -> Option<String> {
    let host = value.trim().trim_end_matches('.');
    if host.is_empty()
        || host
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'/' || byte == b'\\' || byte == 0)
    {
        return None;
    }
    Some(
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase(),
    )
}

fn normalize_server_name(value: &str) -> Option<String> {
    let value = value.trim();
    let wildcard = value.starts_with("*.");
    let value = value.strip_prefix("*.").unwrap_or(value);
    if value.contains('*') {
        return None;
    }
    let authority = value.parse::<http::uri::Authority>().ok()?;
    if authority.port().is_some() {
        return None;
    }
    let host = normalize_host(authority.host())?;
    if wildcard {
        if host.contains(':') {
            return None;
        }
        return Some(format!("*.{host}"));
    }
    Some(host)
}

pub(crate) fn match_score(pattern: &str, host: &str) -> Option<usize> {
    if pattern == host {
        return Some(usize::MAX);
    }
    let suffix = pattern.strip_prefix("*.")?;
    (host.len() > suffix.len()
        && host.ends_with(suffix)
        && host.as_bytes().get(host.len() - suffix.len() - 1) == Some(&b'.'))
    .then_some(suffix.len())
}

fn validate_index(index: &str) -> Result<(), Box<dyn Error + Send + Sync>> {
    if index.is_empty()
        || index.contains('/')
        || index.contains('\\')
        || index == "."
        || index == ".."
    {
        return Err("vhost index must be a non-empty file name".into());
    }
    Ok(())
}

fn validate_vhost_declarations(entries: &[VhostFile]) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut names = std::collections::HashSet::new();
    let mut has_default = false;
    for (index, entry) in entries.iter().enumerate() {
        if entry.tls_cert.is_some() != entry.tls_key.is_some() {
            return Err(
                format!("vhost {} must provide both tls_cert and tls_key", index + 1).into(),
            );
        }
        if entry.server_names.is_empty() {
            return Err(format!("vhost {} has no server_names", index + 1).into());
        }
        for rule in &entry.modsecurity_disable_rules {
            rule.parse().map_err(io::Error::other)?;
        }
        if entry.default {
            if has_default {
                return Err("only one vhost may be marked default".into());
            }
            has_default = true;
        }
        for name in &entry.server_names {
            let normalized = normalize_server_name(name)
                .ok_or_else(|| format!("invalid virtual host name: {name}"))?;
            if !names.insert(normalized.clone()) {
                return Err(format!("duplicate virtual host name: {normalized}").into());
            }
        }
    }
    Ok(())
}

fn validate_vhost_waf_declarations(
    entries: &[VhostFile],
    has_global_waf: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !has_global_waf
        && entries
            .iter()
            .any(|entry| !entry.modsecurity_disable_rules.is_empty())
    {
        return Err("modsecurity_disable_rules requires --modsecurity-rules".into());
    }
    Ok(())
}

fn resolve_config_path(path: PathBuf, config_dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        config_dir.join(path)
    }
}

fn scan_vhost_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path
            .file_name()
            .is_some_and(|name| !name.to_string_lossy().starts_with('.'))
            && path
                .extension()
                .is_some_and(|extension| extension == "toml")
            && path.is_file()
        {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn resolve_identity(
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

fn build_worker_args(
    uid: u32,
    gid: u32,
    root: &Path,
    index: &str,
    listing: bool,
    fastcgi: &[FastCgiBackend],
    timeout: Duration,
) -> Vec<OsString> {
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
    for backend in fastcgi {
        match &backend.address {
            FastCgiAddress::Spawn(app) => {
                args.push("--fastcgi-app".into());
                args.push(format!("{}={}", backend.extension, app.program.display()).into());
                for arg in &app.args {
                    args.push("--fastcgi-app-arg".into());
                    args.push(format!("{}={arg}", backend.extension).into());
                }
                for (key, value) in &app.env {
                    args.push("--fastcgi-app-env".into());
                    args.push(format!("{}={key}={value}", backend.extension).into());
                }
            }
            _ => {
                args.push("--fastcgi".into());
                args.push(format_backend(backend).into());
            }
        }
    }
    args
}

fn format_backend(backend: &FastCgiBackend) -> String {
    match &backend.address {
        FastCgiAddress::Tcp(address) => format!("{}={address}", backend.extension),
        FastCgiAddress::Unix(path) => format!("{}=unix:{}", backend.extension, path.display()),
        FastCgiAddress::Spawn(app) => format!("{}={}", backend.extension, app.program.display()),
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
        FileConfig, Router, VhostFile, build_worker_args, match_score, normalize_host,
        normalize_server_name, request_host, resolve_identity, scan_vhost_files,
        validate_vhost_declarations, validate_vhost_waf_declarations,
    };
    use crate::{
        config::{FastCgiAddress, FastCgiApp, FastCgiBackend},
        fuzz_support::{self, FuzzRequest},
    };
    use http::{HeaderValue, Request};
    use http_body_util::BodyExt;
    use std::{
        collections::BTreeMap,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn normalizes_authority_hosts() {
        for (input, expected) in [
            ("Example.COM:8080", "example.com"),
            ("example.com.", "example.com"),
            ("[2001:DB8::1]:443", "2001:db8::1"),
        ] {
            let authority = input.parse::<http::uri::Authority>().unwrap();
            assert_eq!(normalize_host(authority.host()).as_deref(), Some(expected));
        }
    }

    #[test]
    fn matches_exact_and_longest_wildcards() {
        let host = "api.dev.example.com";
        assert_eq!(match_score("*.example.com", host), Some(11));
        assert_eq!(match_score("*.dev.example.com", host), Some(15));
        assert_eq!(match_score("example.com", host), None);
        assert_eq!(match_score("api.dev.example.com", host), Some(usize::MAX));
        assert!(normalize_server_name("*.example.com").is_some());
        assert!(normalize_server_name("api.*.example.com").is_none());
    }

    fn declaration(names: &[&str], is_default: bool) -> VhostFile {
        VhostFile {
            server_names: names.iter().map(|name| (*name).to_owned()).collect(),
            root: "/tmp/site".into(),
            user: "user".to_owned(),
            group: None,
            index: None,
            listing: None,
            fastcgi: Vec::new(),
            fastcgi_app: Vec::new(),
            fastcgi_timeout: None,
            tls_cert: None,
            tls_key: None,
            default: is_default,
            modsecurity_disable_rules: Vec::new(),
            acme: None,
        }
    }

    #[test]
    fn validates_toml_vhost_names_and_defaults() {
        let parsed: FileConfig = toml::from_str(
            r#"
                [[vhost]]
                server_names = ["Example.com", "www.example.com"]
                root = "/tmp/site"
                user = "example"
                default = true
            "#,
        )
        .unwrap();
        assert!(validate_vhost_declarations(&parsed.vhost).is_ok());
        assert!(
            validate_vhost_declarations(&[
                declaration(&["example.com"], false),
                declaration(&["EXAMPLE.COM"], false),
            ])
            .is_err()
        );
        assert!(
            validate_vhost_declarations(&[
                declaration(&["one.example"], true),
                declaration(&["two.example"], true),
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_and_validates_modsecurity_rule_exclusions() {
        let parsed: FileConfig = toml::from_str(
            r#"
                [[vhost]]
                server_names = ["example.test"]
                root = "/tmp/site"
                user = "example"
                modsecurity_disable_rules = [100001, "2000-2099"]
            "#,
        )
        .unwrap();
        assert!(validate_vhost_declarations(&parsed.vhost).is_ok());
        assert!(validate_vhost_waf_declarations(&parsed.vhost, true).is_ok());
        assert!(validate_vhost_waf_declarations(&parsed.vhost, false).is_err());

        for rule in ["0", "2099-2000", "1001;SecRuleEngine Off", "1-2-3"] {
            let config = format!(
                "[[vhost]]\nserver_names = [\"example.test\"]\nroot = \"/tmp/site\"\nuser = \"example\"\nmodsecurity_disable_rules = [\"{rule}\"]\n"
            );
            let parsed: FileConfig = toml::from_str(&config).unwrap();
            assert!(
                validate_vhost_declarations(&parsed.vhost).is_err(),
                "{rule}"
            );
        }
    }

    #[test]
    fn parses_vhost_fastcgi_app_command_and_environment() {
        let parsed: FileConfig = toml::from_str(
            r#"
                [[vhost]]
                server_names = ["php.example"]
                root = "/srv/php"
                user = "php"

                [[vhost.fastcgi_app]]
                extension = "php"
                command = ["php8.4-cgi", "--foreground"]
                env = { APP_MODE = "test" }
            "#,
        )
        .unwrap();
        assert_eq!(parsed.vhost[0].fastcgi_app[0].extension, "php");
        assert_eq!(
            parsed.vhost[0].fastcgi_app[0].command,
            ["php8.4-cgi", "--foreground"]
        );
        assert_eq!(
            parsed.vhost[0].fastcgi_app[0]
                .env
                .get("APP_MODE")
                .map(String::as_str),
            Some("test")
        );
    }

    #[test]
    fn example_config_parses_and_validates() {
        let parsed: FileConfig = toml::from_str(include_str!("../examples/charlotte.toml"))
            .expect("example configuration should parse");
        let directory_entry: FileConfig =
            toml::from_str(include_str!("../examples/vhosts.d/example.toml"))
                .expect("example per-vhost file should parse");
        let mut entries = parsed.vhost;
        entries.extend(directory_entry.vhost);
        validate_vhost_declarations(&entries)
            .expect("example virtual host declarations should be valid");
        assert_eq!(entries[2].fastcgi_app.len(), 2);
        assert_eq!(parsed.vhost_dir.as_deref(), Some(Path::new("vhosts.d")));
    }

    #[test]
    fn scans_only_visible_toml_files_in_sorted_order() {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "project-charlotte-vhost-scan-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        for name in ["b.toml", "a.toml", ".hidden.toml", "swap.toml~", "temp.tmp"] {
            std::fs::write(directory.join(name), "").unwrap();
        }
        std::fs::create_dir(directory.join("directory.toml")).unwrap();

        let files = scan_vhost_files(&directory).unwrap();
        assert_eq!(
            files,
            vec![directory.join("a.toml"), directory.join("b.toml")]
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn validates_vhost_tls_certificate_pair() {
        let mut entry = declaration(&["example.test"], false);
        entry.tls_cert = Some("cert.pem".into());
        assert!(validate_vhost_declarations(&[entry]).is_err());
        let mut entry = declaration(&["example.test"], false);
        entry.tls_cert = Some("cert.pem".into());
        entry.tls_key = Some("key.pem".into());
        assert!(validate_vhost_declarations(&[entry]).is_ok());
    }

    #[test]
    fn rejects_unknown_vhost_user_and_builds_worker_arguments() {
        assert!(resolve_identity("charlotte-no-such-user", None).is_err());
        let args = build_worker_args(
            1001,
            1002,
            Path::new("/srv/example"),
            "home.php",
            false,
            &[
                FastCgiBackend {
                    extension: "php".to_owned(),
                    address: FastCgiAddress::Tcp("127.0.0.1:9000".to_owned()),
                },
                FastCgiBackend {
                    extension: "cgi".to_owned(),
                    address: FastCgiAddress::Spawn(FastCgiApp {
                        program: "/usr/bin/php8.4-cgi".into(),
                        args: vec!["--foreground".to_owned()],
                        env: BTreeMap::from([("APP_MODE".to_owned(), "worker".to_owned())]),
                    }),
                },
            ],
            Duration::from_secs(12),
        );
        let args = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.windows(2).any(|pair| pair == ["--worker-uid", "1001"]));
        assert!(args.contains(&"--no-listing".to_owned()));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--fastcgi", "php=127.0.0.1:9000"])
        );
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--fastcgi-app", "cgi=/usr/bin/php8.4-cgi"] })
        );
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--fastcgi-app-arg", "cgi=--foreground"] })
        );
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--fastcgi-app-env", "cgi=APP_MODE=worker"] })
        );
    }

    #[test_fuzz::test_fuzz]
    fn host_selection(host: String, uri: String, names: Vec<String>) {
        let Ok(mut request) = Request::builder().uri(uri).body(()) else {
            return;
        };
        if let Ok(value) = HeaderValue::from_str(&host) {
            request.headers_mut().insert("host", value);
        }
        let Some(host) = request_host(&request) else {
            return;
        };
        for name in names {
            let Some(pattern) = normalize_server_name(&name) else {
                continue;
            };
            if match_score(&pattern, &host).is_some() {
                let wildcard_match = pattern.strip_prefix("*.").is_some_and(|suffix| {
                    host.len() > suffix.len()
                        && host.ends_with(suffix)
                        && host.as_bytes().get(host.len() - suffix.len() - 1) == Some(&b'.')
                });
                assert!(pattern == host || wildcard_match);
            }
        }
    }

    #[test]
    fn fuzz_seed_host_selection() {
        host_selection(
            "Api.Example.test:8443".to_owned(),
            "/path".to_owned(),
            vec!["api.example.test".to_owned(), "*.example.test".to_owned()],
        );
        host_selection(
            "[2001:db8::1]:8080".to_owned(),
            "/".to_owned(),
            vec!["2001:db8::1".to_owned()],
        );
    }

    #[test_fuzz::test_fuzz]
    fn vhost_toml(input: String) {
        if let Ok(file) = toml::from_str::<FileConfig>(&input) {
            let _ = validate_vhost_declarations(&file.vhost);
        }
    }

    #[test]
    fn fuzz_seed_vhost_toml() {
        vhost_toml(
            "[[vhost]]\nserver_names = [\"example.test\"]\nroot = \"/tmp/site\"\nuser = \"user\"\n"
                .to_owned(),
        );
        vhost_toml("[[vhost]]\nserver_names = [\"*..\"]\n".to_owned());
    }

    #[test_fuzz::test_fuzz]
    fn router_request(input: FuzzRequest) {
        let Some(request) = input.build() else {
            return;
        };
        let fixture = fuzz_support::fixture();
        let mut config = fuzz_support::fuzz_config(fixture.root.clone());
        config.fastcgi.clear();
        let (peer, local) = fuzz_support::addresses();
        let response = fuzz_support::run(async {
            let router = Router::load(Arc::new(config), None, None)
                .await
                .expect("fallback router loads");
            router.dispatch(request, peer, local).await
        });
        assert!((100..=599).contains(&response.status().as_u16()));
        let body = fuzz_support::run(async { response.into_body().collect().await })
            .expect("router response body should be readable")
            .to_bytes();
        assert!(
            !body
                .windows(fixture.outside_secret.len())
                .any(|window| window == fixture.outside_secret)
        );
    }

    #[test]
    fn fuzz_seed_router_request() {
        router_request(FuzzRequest::default());
        router_request(FuzzRequest {
            uri: "/escape.txt".to_owned(),
            ..FuzzRequest::default()
        });
    }
}
