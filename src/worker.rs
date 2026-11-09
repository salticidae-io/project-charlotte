use std::{
    error::Error,
    net::SocketAddr,
    os::{fd::AsFd, unix::net::UnixStream as StdUnixStream},
    sync::Arc,
};

use http::{Request, StatusCode, Uri, Version};
use hyper::{server::conn::http2, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use nix::unistd::{Gid, Uid, getegid, geteuid, getgroups, setgid, setgroups, setuid};
use tokio::{io::AsyncWriteExt, net::UnixStream};

use crate::{config::Config, handler};

pub(crate) fn drop_privileges(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let uid = Uid::from_raw(config.worker_uid.ok_or("worker uid is missing")?);
    let gid = Gid::from_raw(config.worker_gid.ok_or("worker gid is missing")?);
    if geteuid().is_root() {
        setgroups(&[])?;
        setgid(gid)?;
        setuid(uid)?;
    } else if geteuid() != uid || getegid() != gid {
        return Err("a non-root server can only run workers as its current uid and gid".into());
    } else if !getgroups()?.is_empty() {
        // A non-root process cannot clear inherited groups; retaining the current
        // user's groups is safe only when the worker keeps that same identity.
        eprintln!("virtual host worker retains the server user's supplementary groups");
    }
    Ok(())
}

pub(crate) async fn run(mut config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let root = tokio::fs::canonicalize(&config.root).await?;
    if !tokio::fs::metadata(&root).await?.is_dir() {
        return Err(format!(
            "worker document root is not a directory: {}",
            root.display()
        )
        .into());
    }
    config.root = root;
    let socket_fd = std::io::stdin().as_fd().try_clone_to_owned()?;
    let socket = StdUnixStream::from(socket_fd);
    socket.set_nonblocking(true)?;
    let mut socket = UnixStream::from_std(socket)?;
    socket.write_all(&[1]).await?;

    let config = Arc::new(config);
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        let config = Arc::clone(&config);
        async move { Ok::<_, std::convert::Infallible>(dispatch(request, config).await) }
    });
    let io = TokioIo::new(socket);
    http2::Builder::new(TokioExecutor::new())
        .serve_connection(io, service)
        .await?;
    Ok(())
}

async fn dispatch(
    mut request: Request<hyper::body::Incoming>,
    config: Arc<Config>,
) -> http::Response<handler::ResponseBody> {
    let Some(peer) = take_socket_addr(&mut request, "x-charlotte-peer") else {
        return handler::error_response(StatusCode::BAD_REQUEST, "Invalid worker metadata\n");
    };
    let Some(local) = take_socket_addr(&mut request, "x-charlotte-local") else {
        return handler::error_response(StatusCode::BAD_REQUEST, "Invalid worker metadata\n");
    };
    let Some(version) = request
        .headers_mut()
        .remove("x-charlotte-version")
        .and_then(|value| value.to_str().ok().and_then(parse_version))
    else {
        return handler::error_response(StatusCode::BAD_REQUEST, "Invalid worker metadata\n");
    };

    let path_and_query = request
        .uri()
        .path_and_query()
        .map_or("/", |value| value.as_str());
    let uri = match Uri::builder().path_and_query(path_and_query).build() {
        Ok(uri) => uri,
        Err(_) => return handler::error_response(StatusCode::BAD_REQUEST, "Invalid URI\n"),
    };
    *request.uri_mut() = uri;
    *request.version_mut() = version;
    handler::handle_request(request, config, peer, local).await
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
