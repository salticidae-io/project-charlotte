use std::{
    io,
    os::unix::{
        fs::{FileTypeExt, PermissionsExt},
        net::UnixStream as StdUnixStream,
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use bytes::{Bytes, BytesMut};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::{Semaphore, watch},
    task::{JoinHandle, JoinSet},
};

use crate::{
    config::Config,
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
}

pub(crate) async fn spawn(
    path: PathBuf,
    router: Arc<Router>,
    config: Config,
    sni: Option<SniHandle>,
    started: Instant,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<JoinHandle<()>> {
    remove_stale_socket(&path)?;
    let listener = UnixListener::bind(&path)?;
    if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        drop(listener);
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }
    let state = ControlState {
        router,
        config,
        sni,
        started,
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
                        eprintln!("control connection task failed: {error}");
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
                                    eprintln!("control connection failed: {error}");
                                }
                            });
                        }
                        Err(error) => {
                            eprintln!("control socket accept failed: {error}");
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

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
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
                std::fs::remove_file(path)
            }
            Err(error) => Err(error),
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
        eprintln!(
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
            }),
        ),
        "/vhosts" if method == Method::GET => json_response(
            StatusCode::OK,
            serde_json::json!(state.router.control_list().await),
        ),
        "/status" | "/vhosts" => method_not_allowed(),
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

    use super::remove_stale_socket;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

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
