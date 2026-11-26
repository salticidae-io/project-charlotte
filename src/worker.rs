//! Private HTTP/2 worker service with request metadata validation and privilege dropping.

use std::{
    error::Error,
    net::SocketAddr,
    os::{fd::AsFd, unix::net::UnixStream as StdUnixStream},
    sync::Arc,
};

use http::{Request, StatusCode, Uri, Version};
use hyper::{server::conn::http2, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use nix::unistd::{Gid, Uid, User, getegid, geteuid, setgid, setuid};
use tokio::{
    io::AsyncWriteExt,
    net::UnixStream,
    signal::unix::{SignalKind, signal},
};

use crate::{
    config::Config, fastcgi_app, handler, pathctx::PathContext, privileges, vhost::TlsSni,
};

pub(crate) fn drop_privileges(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let uid = Uid::from_raw(config.worker_uid.ok_or("worker uid is missing")?);
    let gid = Gid::from_raw(config.worker_gid.ok_or("worker gid is missing")?);
    if geteuid().is_root() {
        if let Some(user) = User::from_uid(uid)? {
            let user_name = std::ffi::CString::new(user.name)?;
            privileges::initialize_groups(user_name.as_c_str(), gid)?;
        } else {
            privileges::set_groups(&[])?;
        }
        setgid(gid)?;
        setuid(uid)?;
    } else if geteuid() != uid || getegid() != gid {
        return Err("a non-root server can only run workers as its current uid and gid".into());
    } else {
        let mut actual_groups = privileges::get_groups()?;
        let mut expected_groups = privileges::supplementary_groups(uid, gid)?;
        actual_groups.sort_unstable_by_key(|group| group.as_raw());
        expected_groups.sort_unstable_by_key(|group| group.as_raw());
        if actual_groups != expected_groups {
            crate::log_error!(
                "virtual host worker supplementary groups differ from those configured for uid {} and gid {}",
                uid.as_raw(),
                gid.as_raw()
            );
        }
    }
    privileges::clear_all()?;
    Ok(())
}

pub(crate) async fn run(config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let result = run_inner(config).await;
    if let Err(error) = &result {
        crate::log_error!("virtual host worker failed: {error}");
    }
    result
}

async fn run_inner(mut config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    crate::log_debug!(
        "Starting virtual-host worker pid {} as uid {} gid {}",
        std::process::id(),
        config.worker_uid.unwrap_or_default(),
        config.worker_gid.unwrap_or_default()
    );
    let root = tokio::fs::canonicalize(&config.root)
        .await
        .path_context("resolve document root", &config.root)?;
    if !tokio::fs::metadata(&root)
        .await
        .path_context("inspect document root", &root)?
        .is_dir()
    {
        return Err(format!(
            "worker document root is not a directory: {}",
            root.display()
        )
        .into());
    }
    config.root = root;
    let _fastcgi_apps = fastcgi_app::start_apps(&mut config).await?;
    let socket_fd = std::io::stdin().as_fd().try_clone_to_owned()?;
    let socket = StdUnixStream::from(socket_fd);
    socket.set_nonblocking(true)?;
    let mut socket = UnixStream::from_std(socket)?;
    socket.write_all(&[1]).await?;
    crate::log_debug!("Virtual-host worker pid {} is ready", std::process::id());

    let config = Arc::new(config);
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        let config = Arc::clone(&config);
        async move { Ok::<_, std::convert::Infallible>(dispatch(request, config).await) }
    });
    let io = TokioIo::new(socket);
    let connection = http2::Builder::new(TokioExecutor::new())
        .adaptive_window(true)
        .serve_connection(io, service);
    // A worker that is killed outright cannot drop `_fastcgi_apps`, which would
    // orphan every app it spawned and leak the descriptors they inherited. Shut
    // down on a signal instead so that those handles run their cleanup.
    tokio::select! {
        result = connection => result?,
        () = terminated() => {}
    }
    Ok(())
}

/// Resolves once the worker is asked to shut down.
async fn terminated() {
    let mut interrupt = match signal(SignalKind::interrupt()) {
        Ok(stream) => stream,
        Err(error) => {
            crate::log_error!("virtual host worker could not listen for SIGINT: {error}");
            return std::future::pending().await;
        }
    };
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        Err(error) => {
            crate::log_error!("virtual host worker could not listen for SIGTERM: {error}");
            return std::future::pending().await;
        }
    };
    tokio::select! {
        _ = interrupt.recv() => {}
        _ = terminate.recv() => {}
    }
}

async fn dispatch(
    mut request: Request<hyper::body::Incoming>,
    config: Arc<Config>,
) -> http::Response<handler::ResponseBody> {
    let (peer, local) = match prepare_request(&mut request) {
        Ok(addresses) => addresses,
        Err(PrepareError::Metadata) => {
            return handler::error_response(StatusCode::BAD_REQUEST, "Invalid worker metadata\n");
        }
        Err(PrepareError::Uri) => {
            return handler::error_response(StatusCode::BAD_REQUEST, "Invalid URI\n");
        }
    };
    let server_name = request
        .headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    crate::logging::with_request_context(
        crate::logging::RequestContext {
            client: Some(peer),
            local: Some(local),
            server_name,
            error_log: None,
            timing: None,
        },
        handler::handle_request(request, config, peer, local),
    )
    .await
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum PrepareError {
    Metadata,
    Uri,
}

pub(crate) fn prepare_request<B>(
    request: &mut Request<B>,
) -> Result<(SocketAddr, SocketAddr), PrepareError> {
    let Some(peer) = take_socket_addr(request, "x-charlotte-peer") else {
        return Err(PrepareError::Metadata);
    };
    let Some(local) = take_socket_addr(request, "x-charlotte-local") else {
        return Err(PrepareError::Metadata);
    };
    let Some(version) = request
        .headers_mut()
        .remove("x-charlotte-version")
        .and_then(|value| value.to_str().ok().and_then(parse_version))
    else {
        return Err(PrepareError::Metadata);
    };

    let tls = request
        .headers_mut()
        .remove("x-charlotte-tls")
        .is_some_and(|value| value == "1");
    if tls {
        // Tells the request handler that the client connection was encrypted.
        request.extensions_mut().insert(TlsSni(None));
    }

    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or("/", |value| value.as_str());
    let uri = match Uri::builder().path_and_query(path_and_query).build() {
        Ok(uri) => uri,
        Err(_) => return Err(PrepareError::Uri),
    };
    *request.uri_mut() = uri;
    *request.version_mut() = version;
    Ok((peer, local))
}

fn take_socket_addr<B>(request: &mut Request<B>, name: &str) -> Option<SocketAddr> {
    request
        .headers_mut()
        .remove(name)
        .and_then(|value| value.to_str().ok()?.parse().ok())
}

fn parse_version(value: &str) -> Option<Version> {
    match value {
        "HTTP/0.9" => Some(Version::HTTP_09),
        "HTTP/1.0" => Some(Version::HTTP_10),
        "HTTP/1.1" => Some(Version::HTTP_11),
        "HTTP/2.0" => Some(Version::HTTP_2),
        "HTTP/3.0" => Some(Version::HTTP_3),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::prepare_request;
    use crate::fuzz_support::FuzzRequest;

    #[test_fuzz::test_fuzz]
    fn worker_metadata(request: FuzzRequest) {
        let Some(mut request) = request.build() else {
            return;
        };
        if prepare_request(&mut request).is_ok() {
            for name in [
                "x-charlotte-peer",
                "x-charlotte-local",
                "x-charlotte-version",
                "x-charlotte-tls",
            ] {
                assert!(!request.headers().contains_key(name));
            }
            assert!(request.uri().path().starts_with('/'));
        }
    }

    #[test]
    fn fuzz_seed_worker_metadata() {
        worker_metadata(FuzzRequest {
            uri: "http://example.test/a.php?x=1".to_owned(),
            version: "HTTP/2.0".to_owned(),
            headers: vec![
                ("x-charlotte-peer".to_owned(), b"127.0.0.1:12345".to_vec()),
                ("x-charlotte-local".to_owned(), b"127.0.0.1:8080".to_vec()),
                ("x-charlotte-version".to_owned(), b"HTTP/1.1".to_vec()),
            ],
            ..FuzzRequest::default()
        });
        worker_metadata(FuzzRequest::default());
    }
}
