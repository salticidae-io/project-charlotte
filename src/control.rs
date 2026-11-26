//! HTTP/1.1 JSON control API served over a Unix socket.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::UnixStream as StdUnixStream,
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use bytes::{Bytes, BytesMut};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{Mutex, Semaphore, watch},
    task::{JoinHandle, JoinSet},
};

use crate::{
    config::Config,
    pathctx::PathContext,
    reload,
    tls::SniHandle,
    vhost::{ControlError, Router},
};

const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_CONNECTIONS: usize = 32;

#[derive(Clone)]
struct ControlState {
    router: Arc<Router>,
    config: Config,
    sni: Option<SniHandle>,
    started: Instant,
    startup_options: serde_yaml_ng::Value,
    cli_args: Arc<Vec<String>>,
    command_line: Vec<String>,
    options_lock: Arc<Mutex<()>>,
}

pub(crate) async fn spawn(
    path: PathBuf,
    router: Arc<Router>,
    config: Config,
    sni: Option<SniHandle>,
    started: Instant,
    startup_options: serde_yaml_ng::Value,
    cli_args: Vec<String>,
    command_line: Vec<String>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<JoinHandle<()>> {
    prepare_socket_directory(&path, None)?;
    remove_stale_socket(&path)?;
    let listener = UnixListener::bind(&path).path_context("bind control socket", &path)?;
    if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .path_context("set permissions on control socket", &path)
    {
        drop(listener);
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }
    let state = ControlState {
        router,
        config,
        sni,
        started,
        startup_options,
        cli_args: Arc::new(cli_args),
        command_line,
        options_lock: Arc::new(Mutex::new(())),
    };

    Ok(tokio::spawn(async move {
        let mut connections = JoinSet::new();
        let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        while !*shutdown.borrow() {
            tokio::select! {
                result = shutdown.changed() => {
                    if result.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result {
                        crate::log_error!("control connection task failed: {error}");
                    }
                }
                accepted = listener.accept(), if slots.available_permits() > 0 => {
                    match accepted {
                        Ok((stream, _)) => {
                            let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                                continue;
                            };
                            let state = state.clone();
                            connections.spawn(async move {
                                let _permit = permit;
                                if let Err(error) = serve_connection(stream, state).await {
                                    crate::log_error!("control connection failed: {error}");
                                }
                            });
                        }
                        Err(error) => {
                            crate::log_error!("control socket accept failed: {error}");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        drop(listener);
        remove_socket_file(&path);
    }))
}

const SOCKET_DIRECTORY_MODE: u32 = 0o750;

/// Ensures the control socket's parent directory exists and is usable by the
/// account that binds the socket. With `owner`, a missing directory (or a
/// dedicated one that is empty or holds only the old socket) is assigned to
/// that uid/gid; shared directories are never re-owned.
pub(crate) fn prepare_socket_directory(socket: &Path, owner: Option<(u32, u32)>) -> io::Result<()> {
    let Some(directory) = socket
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    let link = match std::fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Intermediate directories stay traversable so the socket owner
            // can reach its own directory.
            if let Some(ancestor) = directory
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o755)
                    .create(ancestor)
                    .path_context("create control socket directory", ancestor)?;
            }
            std::fs::DirBuilder::new()
                .mode(SOCKET_DIRECTORY_MODE)
                .create(directory)
                .path_context("create control socket directory", directory)?;
            secure_socket_directory(directory, owner)?;
            crate::log_debug!("Created control socket directory {}", directory.display());
            return Ok(());
        }
        Err(error) => {
            return Err(error).path_context("inspect control socket directory", directory);
        }
    };
    let metadata = if link.file_type().is_symlink() {
        std::fs::metadata(directory).path_context("inspect control socket directory", directory)?
    } else {
        link.clone()
    };
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "control socket directory {} is not a directory",
                directory.display()
            ),
        ));
    }
    let Some((uid, gid)) = owner else {
        return Ok(());
    };
    let mode = metadata.mode();
    if link.file_type().is_symlink() {
        if directory_writable(&metadata, uid, gid) {
            return Ok(());
        }
    } else if metadata.uid() == uid {
        if metadata.gid() == gid && mode & 0o300 == 0o300 && mode & 0o022 == 0 {
            return Ok(());
        }
        return secure_socket_directory(directory, owner);
    } else if directory_writable(&metadata, uid, gid) {
        return Ok(());
    } else if is_dedicated_socket_directory(directory, socket)? {
        return secure_socket_directory(directory, owner);
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!(
            "control socket directory {} is not writable by uid {uid} gid {gid}; \
             change its ownership or choose a dedicated directory",
            directory.display()
        ),
    ))
}

fn directory_writable(metadata: &std::fs::Metadata, uid: u32, gid: u32) -> bool {
    let mode = metadata.mode();
    if uid == 0 {
        true
    } else if metadata.uid() == uid {
        mode & 0o300 == 0o300
    } else if metadata.gid() == gid {
        mode & 0o030 == 0o030
    } else {
        mode & 0o003 == 0o003
    }
}

fn is_dedicated_socket_directory(directory: &Path, socket: &Path) -> io::Result<bool> {
    let socket_name = socket.file_name();
    for entry in
        std::fs::read_dir(directory).path_context("read control socket directory", directory)?
    {
        let entry = entry.path_context("read control socket directory entry", directory)?;
        if Some(entry.file_name().as_os_str()) != socket_name {
            return Ok(false);
        }
    }
    Ok(true)
}

fn secure_socket_directory(directory: &Path, owner: Option<(u32, u32)>) -> io::Result<()> {
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::lchown(directory, Some(uid), Some(gid))
            .path_context("change ownership of control socket directory", directory)?;
    }
    std::fs::set_permissions(
        directory,
        std::fs::Permissions::from_mode(SOCKET_DIRECTORY_MODE),
    )
    .path_context("set permissions on control socket directory", directory)?;
    if let Some((uid, gid)) = owner {
        crate::log_debug!(
            "Prepared control socket directory {} for uid {uid} and gid {gid}",
            directory.display()
        );
    }
    Ok(())
}

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path).path_context("inspect control socket", path) {
        Ok(metadata) if metadata.file_type().is_socket() => match StdUnixStream::connect(path) {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!(
                    "control socket is already accepting connections: {}",
                    path.display()
                ),
            )),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                std::fs::remove_file(path).path_context("remove stale control socket", path)
            }
            Err(error) => Err(error).path_context("connect to control socket", path),
        },
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "refusing to replace non-socket control path {}",
                path.display()
            ),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn remove_socket_file(path: &Path) {
    if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
        && let Err(error) = std::fs::remove_file(path)
    {
        crate::log_error!(
            "could not remove control socket {}: {error}",
            path.display()
        );
    }
}

async fn serve_connection(stream: UnixStream, state: ControlState) -> hyper::Result<()> {
    let service = service_fn(move |request| {
        let state = state.clone();
        async move { Ok::<_, std::convert::Infallible>(handle_request(request, state).await) }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await
}

async fn handle_request(request: Request<Incoming>, state: ControlState) -> Response<Full<Bytes>> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    match path.as_str() {
        "/status" if method == Method::GET => json_response(
            StatusCode::OK,
            serde_json::json!({
                "uptime_seconds": state.started.elapsed().as_secs(),
                "vhosts": state.router.control_vhost_count(),
                "version": env!("CARGO_PKG_VERSION"),
                "traffic": state.router.control_traffic(),
            }),
        ),
        "/vhosts" if method == Method::GET => json_response(
            StatusCode::OK,
            serde_json::json!(state.router.control_list().await),
        ),
        "/status" | "/vhosts" => method_not_allowed(),
        "/options" if method == Method::GET => handle_options_get(state).await,
        "/options" if method == Method::PUT => handle_options_put(request, state).await,
        "/options" => method_not_allowed(),
        _ => {
            let Some(name) = path.strip_prefix("/vhosts/") else {
                return error_response(StatusCode::NOT_FOUND, "route not found");
            };
            if name.is_empty() || name.contains('/') {
                return error_response(StatusCode::BAD_REQUEST, "invalid virtual-host name");
            }
            handle_vhost_request(request, name, state).await
        }
    }
}

static NEXT_OPTIONS_TEMP: AtomicU64 = AtomicU64::new(0);

async fn handle_options_get(state: ControlState) -> Response<Full<Bytes>> {
    let Some(path) = state.config.config_file.as_deref() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server was not started with --config",
        );
    };
    let _guard = state.options_lock.lock().await;
    let contents = match crate::vhost::read_trusted_config(path) {
        Ok(contents) => contents,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    let document = match serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&contents) {
        Ok(document) => document,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    let options = document
        .as_mapping()
        .and_then(|mapping| mapping.get(serde_yaml_ng::Value::String("options".to_owned())))
        .filter(|value| value.is_mapping())
        .cloned()
        .unwrap_or_else(empty_options);
    let (writable, reason) = match options_writable(path) {
        Ok(reason) => (reason.is_none(), reason),
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    let schema = crate::config::Config::configurable_options()
        .into_iter()
        .map(|option| {
            let kind = match option.kind {
                crate::config::OptionKind::Flag => "flag",
                crate::config::OptionKind::Value => "value",
                crate::config::OptionKind::List => "list",
            };
            let numeric = option.value_name.as_deref().is_some_and(|name| {
                matches!(
                    name,
                    "N" | "SECS"
                        | "SEC"
                        | "SECONDS"
                        | "MS"
                        | "MILLISECONDS"
                        | "CODE"
                        | "BYTES"
                        | "FRACTION"
                        | "PCT"
                        | "COUNT"
                        | "THREADS"
                        | "TTL"
                )
            });
            let (minimum, maximum) = match option.name.as_str() {
                "threads" | "worker_threads" | "max_connections" => (Some(1.0), None),
                "fastcgi_keepalive" => (Some(0.0), Some(1024.0)),
                "static_cache_ttl_ms" => (Some(0.0), Some(3_600_000.0)),
                "modsecurity_block_status" => (Some(400.0), Some(599.0)),
                _ if numeric && option.value_name.as_deref() == Some("FRACTION") => {
                    (Some(0.0), Some(1.0))
                }
                _ if numeric => (Some(0.0), None),
                _ => (None, None),
            };
            serde_json::json!({
                "name": option.name,
                "help": option.help,
                "kind": kind,
                "value_name": option.value_name,
                "default": option.default,
                "path": option.path,
                "min": minimum,
                "max": maximum,
            })
        })
        .collect::<Vec<_>>();
    let restart_required = options != state.startup_options;
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "file": path,
            "writable": writable,
            "reason": reason,
            "options": options,
            "restart_required": restart_required,
            "command_line": state.command_line,
            "schema": schema,
        }),
    )
}

async fn handle_options_put(
    request: Request<Incoming>,
    state: ControlState,
) -> Response<Full<Bytes>> {
    let Some(path) = state.config.config_file.as_deref() else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "server was not started with --config",
        );
    };
    let _guard = state.options_lock.lock().await;
    let body = match read_body(request.into_body()).await {
        Ok(body) => body,
        Err(error) => return control_error(error),
    };
    let text = match std::str::from_utf8(&body) {
        Ok(text) => text,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let submitted = match serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text) {
        Ok(value) => value,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let Some(submitted) = submitted.as_mapping() else {
        return error_response(StatusCode::BAD_REQUEST, "options must be a mapping");
    };
    let mut options = serde_yaml_ng::Mapping::new();
    for (key, value) in submitted {
        let Some(key) = key.as_str() else {
            return error_response(StatusCode::BAD_REQUEST, "option names must be strings");
        };
        if !value.is_null() {
            options.insert(
                serde_yaml_ng::Value::String(key.replace('-', "_")),
                value.clone(),
            );
        }
    }
    match options_writable(path) {
        Ok(None) => {}
        Ok(Some(reason)) => return error_response(StatusCode::CONFLICT, &reason),
        Err(error) => return error_response(StatusCode::CONFLICT, &error.to_string()),
    }
    let contents = match crate::vhost::read_trusted_config(path) {
        Ok(contents) => contents,
        Err(error) => return error_response(StatusCode::CONFLICT, &error.to_string()),
    };
    let mut document = match serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&contents) {
        Ok(value) => value,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
    };
    let Some(mapping) = document.as_mapping_mut() else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "main configuration must be a mapping",
        );
    };
    let options_key = serde_yaml_ng::Value::String("options".to_owned());
    if options.is_empty() {
        mapping.remove(&options_key);
    } else {
        mapping.insert(options_key, serde_yaml_ng::Value::Mapping(options.clone()));
    }
    let updated = match serde_yaml_ng::to_string(&document) {
        Ok(updated) => updated,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    let temporary = match write_options_temp(path, &updated) {
        Ok(temporary) => temporary,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    };
    if let Err(error) = validate_options_file(&temporary, path, &state.cli_args) {
        let _ = fs::remove_file(&temporary);
        return error_response(StatusCode::BAD_REQUEST, &error);
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        && let Ok(directory) = fs::File::open(parent)
        && let Err(error) = directory.sync_all()
    {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    let options_value = if options.is_empty() {
        empty_options()
    } else {
        serde_yaml_ng::Value::Mapping(options)
    };
    json_response(
        StatusCode::OK,
        serde_json::json!({
            "options": options_value,
            "restart_required": options_value != state.startup_options,
        }),
    )
}

fn empty_options() -> serde_yaml_ng::Value {
    serde_yaml_ng::Value::Mapping(serde_yaml_ng::Mapping::new())
}

fn options_writable(path: &Path) -> io::Result<Option<String>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(Some(
            "The main configuration is a symbolic link and cannot be atomically replaced."
                .to_owned(),
        ));
    }
    let uid = nix::unistd::geteuid().as_raw();
    if metadata.uid() != uid {
        return Ok(Some(format!(
            "The main configuration is owned by uid {}; the server runs as uid {uid}.",
            metadata.uid()
        )));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory = fs::metadata(parent)?;
    if !has_write_access(&directory) {
        return Ok(Some(format!(
            "The configuration directory {} is not writable by the server.",
            parent.display()
        )));
    }
    Ok(None)
}

fn has_write_access(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    if nix::unistd::geteuid().is_root() {
        return true;
    }
    let mode = metadata.mode();
    if metadata.uid() == nix::unistd::geteuid().as_raw() {
        mode & 0o200 != 0
    } else {
        let group = nix::unistd::getegid().as_raw() == metadata.gid()
            || nix::unistd::getgroups()
                .is_ok_and(|groups| groups.iter().any(|group| group.as_raw() == metadata.gid()));
        if group {
            mode & 0o020 != 0
        } else {
            mode & 0o002 != 0
        }
    }
}

fn write_options_temp(path: &Path, contents: &str) -> io::Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    for _ in 0..16 {
        let id = NEXT_OPTIONS_TEMP.fetch_add(1, Ordering::Relaxed);
        let temporary = parent.join(format!(".{name}.options-{}-{id}.tmp", std::process::id()));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let result = (|| {
            file.write_all(contents.as_bytes())?;
            file.sync_all()?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(mode))?;
            Ok(temporary.clone())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        return result;
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a temporary configuration file",
    ))
}

fn validate_options_file(
    temporary: &Path,
    original: &Path,
    cli_args: &[String],
) -> Result<(), String> {
    let mut args = Vec::new();
    let mut skip_next = false;
    for argument in cli_args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if argument == "--config" {
            skip_next = true;
        } else if argument == "--check-config" || argument.starts_with("--config=") {
            continue;
        } else {
            args.push(argument.clone());
        }
    }
    args.push("--config".to_owned());
    args.push(temporary.to_string_lossy().into_owned());
    args.push("--check-config".to_owned());
    let temporary_path = temporary.to_string_lossy().into_owned();
    let original_path = original.to_string_lossy().into_owned();
    let config = match Config::parse(args)
        .map_err(|error| error.replace(&temporary_path, &original_path))?
    {
        crate::config::ParseResult::Config(config) => *config,
        crate::config::ParseResult::Help => {
            return Err("could not validate the updated configuration".to_owned());
        }
    };
    let diagnostics = crate::vhost::check_config(&config);
    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(diagnostics
            .join("\n")
            .replace(&temporary_path, &original_path))
    }
}

async fn handle_vhost_request(
    request: Request<Incoming>,
    name: &str,
    state: ControlState,
) -> Response<Full<Bytes>> {
    match *request.method() {
        Method::GET => match state.router.control_get(name).await {
            Ok(value) => json_response(StatusCode::OK, value),
            Err(error) => control_error(error),
        },
        Method::POST | Method::PUT => {
            let create_only = request.method() == Method::POST;
            let body = match read_body(request.into_body()).await {
                Ok(body) => body,
                Err(error) => return control_error(error),
            };
            let text = match std::str::from_utf8(&body) {
                Ok(text) => text,
                Err(error) => {
                    return error_response(StatusCode::BAD_REQUEST, &error.to_string());
                }
            };
            let value = match serde_yaml_ng::from_str(text) {
                Ok(value) => value,
                Err(error) => return error_response(StatusCode::BAD_REQUEST, &error.to_string()),
            };
            match state.router.control_put(name, value, create_only).await {
                Ok(()) => {
                    reload::apply_vhost_change(&state.router, &state.config, state.sni.as_ref())
                        .await;
                    let status = if create_only {
                        StatusCode::CREATED
                    } else {
                        StatusCode::OK
                    };
                    json_response(status, serde_json::json!({"name": name}))
                }
                Err(error) => control_error(error),
            }
        }
        Method::DELETE => match state.router.control_delete(name).await {
            Ok(()) => {
                reload::apply_vhost_change(&state.router, &state.config, state.sni.as_ref()).await;
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Full::new(Bytes::new()))
                    .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
            }
            Err(error) => control_error(error),
        },
        _ => method_not_allowed(),
    }
}

async fn read_body(mut body: Incoming) -> Result<Bytes, ControlError> {
    let mut bytes = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| ControlError::BadRequest(error.to_string()))?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > MAX_BODY_BYTES {
                return Err(ControlError::PayloadTooLarge);
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes.freeze())
}

fn control_error(error: ControlError) -> Response<Full<Bytes>> {
    match error {
        ControlError::BadRequest(message) => error_response(StatusCode::BAD_REQUEST, &message),
        ControlError::PayloadTooLarge => error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!("request body exceeds {MAX_BODY_BYTES} bytes"),
        ),
        ControlError::NotFound => error_response(StatusCode::NOT_FOUND, "virtual host not found"),
        ControlError::Conflict(message) => error_response(StatusCode::CONFLICT, &message),
        ControlError::Unavailable(message) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, &message)
        }
        ControlError::Internal(message) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, &message)
        }
    }
}

fn method_not_allowed() -> Response<Full<Bytes>> {
    let mut response = error_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    response.headers_mut().insert(
        header::ALLOW,
        "GET, POST, PUT, DELETE"
            .parse()
            .expect("static header value"),
    );
    response
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json_response(status, serde_json::json!({"error": message}))
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"{}"))))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::net::UnixListener,
        sync::atomic::{AtomicU64, Ordering},
    };

    use std::os::unix::fs::PermissionsExt;

    use super::{prepare_socket_directory, remove_stale_socket};

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    fn temporary_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "project-charlotte-{label}-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn current_owner() -> (u32, u32) {
        (
            nix::unistd::geteuid().as_raw(),
            nix::unistd::getegid().as_raw(),
        )
    }

    #[test]
    fn creates_missing_control_socket_directory_with_private_mode() {
        let base = temporary_path("control-dir");
        let directory = base.join("nested").join("run");
        let socket = directory.join("control.sock");

        prepare_socket_directory(&socket, Some(current_owner())).unwrap();

        let metadata = fs::metadata(&directory).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o750);
        assert_eq!(
            fs::metadata(base.join("nested"))
                .unwrap()
                .permissions()
                .mode()
                & 0o005,
            0o005
        );
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn tightens_owned_control_socket_directory() {
        let directory = temporary_path("control-dir-owned");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();

        prepare_socket_directory(&directory.join("control.sock"), Some(current_owner())).unwrap();

        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o750
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn leaves_existing_directory_alone_without_owner() {
        let directory = temporary_path("control-dir-plain");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).unwrap();

        prepare_socket_directory(&directory.join("control.sock"), None).unwrap();

        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o755
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_non_directory_control_socket_parent() {
        let parent = temporary_path("control-dir-file");
        fs::write(&parent, "").unwrap();

        let error = prepare_socket_directory(&parent.join("control.sock"), None).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        fs::remove_file(parent).unwrap();
    }

    #[test]
    fn refuses_to_remove_non_socket_control_paths() {
        let path = std::env::temp_dir().join(format!(
            "project-charlotte-control-path-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, "keep").unwrap();
        let error = remove_stale_socket(&path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn refuses_to_unlink_an_active_control_socket() {
        let path = std::env::temp_dir().join(format!(
            "project-charlotte-active-control-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let error = remove_stale_socket(&path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert!(path.exists());
        drop(listener);
        fs::remove_file(path).unwrap();
    }
}
