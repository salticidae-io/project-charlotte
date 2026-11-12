#![forbid(unsafe_code)]

#[cfg(feature = "acme")]
mod acme;
mod config;
#[cfg(feature = "hosting")]
mod fastcgi;
#[cfg(feature = "hosting")]
mod fastcgi_app;
#[cfg(feature = "hosting")]
mod handler;
#[cfg(feature = "http3")]
mod http3;
mod httpdate;
#[cfg(feature = "hosting")]
mod mime;
mod privileges;
#[cfg(feature = "proxy")]
mod proxy;
mod reload;
mod response;
mod tls;
mod vhost;
mod waf;
#[cfg(feature = "hosting")]
mod worker;

#[cfg(all(test, feature = "hosting"))]
mod fuzz_support;

use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};

use http::StatusCode;
use hyper::{Request, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

#[cfg(feature = "acme")]
use crate::acme::AcmeManager;
#[cfg(feature = "hosting")]
use crate::config::FastCgiAddress;
use crate::{
    config::{Config, ParseResult},
    tls::TlsSetup,
    vhost::{Router, TlsSni},
    waf::Waf,
};

/// Connections served at once across the TCP listeners. Further connections
/// wait in the listen backlog rather than consume descriptors and memory.
const MAX_CONNECTIONS: usize = 4096;
/// How long a client may take to send a complete request head.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// How often an idle HTTP/2 connection is probed, and how long it has to
/// answer before it is closed.
const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);
/// Pause after a failed `accept`, so that a persistent failure such as
/// descriptor exhaustion does not spin the accept loop.
const ACCEPT_ERROR_DELAY: Duration = Duration::from_millis(100);

/// Waits for a free connection slot, then for a connection.
async fn accept(
    listener: Option<&TcpListener>,
    limiter: &Arc<Semaphore>,
) -> (
    std::io::Result<(TcpStream, SocketAddr)>,
    OwnedSemaphorePermit,
) {
    let Some(listener) = listener else {
        return std::future::pending().await;
    };
    let permit = Arc::clone(limiter)
        .acquire_owned()
        .await
        .expect("connection limiter is never closed");
    (listener.accept().await, permit)
}

/// Unpacks an accepted connection. A failure to accept must not stop the
/// server: it is usually transient (the peer already hung up) or a resource
/// limit that clears when other connections close.
async fn accepted_stream(
    accepted: std::io::Result<(TcpStream, SocketAddr)>,
) -> Option<(TcpStream, SocketAddr, SocketAddr)> {
    let result = accepted.and_then(|(stream, peer)| {
        let _ = stream.set_nodelay(true);
        let local = stream.local_addr()?;
        Ok((stream, peer, local))
    });
    match result {
        Ok(connection) => Some(connection),
        Err(error) => {
            eprintln!("Could not accept connection: {error}");
            tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
            None
        }
    }
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = match Config::parse(std::env::args().skip(1))? {
        ParseResult::Help => {
            println!("{}", Config::usage());
            return Ok(());
        }
        ParseResult::Config(config) => *config,
    };
    #[cfg(feature = "hosting")]
    let mut config = config;
    #[cfg(not(feature = "hosting"))]
    let config = config;

    #[cfg(feature = "hosting")]
    if config.worker {
        if let Ok(app_env) = std::env::var(config::WORKER_APP_ENV) {
            config.apply_fastcgi_app_env(&app_env)?;
        }
        worker::drop_privileges(&config)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.worker_threads)
            .enable_all()
            .build()?;
        return runtime.block_on(worker::run(config));
    }
    privileges::drop_master(&config)?;
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if let Some(threads) = config.threads {
        builder.worker_threads(threads);
    }
    let runtime = builder.enable_all().build()?;
    runtime.block_on(run_master(config))
}

async fn run_master(config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(feature = "hosting")]
    let root = tokio::fs::canonicalize(&config.root).await?;
    #[cfg(feature = "hosting")]
    if !tokio::fs::metadata(&root).await?.is_dir() {
        return Err(format!("document root is not a directory: {}", root.display()).into());
    }
    #[cfg(feature = "hosting")]
    let mut config = Config { root, ..config };
    #[cfg(not(feature = "hosting"))]
    let config = config;
    #[cfg(feature = "hosting")]
    let _fastcgi_apps = fastcgi_app::start_apps(&mut config).await?;
    let listener = TcpListener::bind(config.bind).await?;
    let waf = if config.modsecurity_rules.is_empty() {
        None
    } else {
        Some(Waf::load(
            &config.modsecurity_rules,
            config.modsecurity_body_limit,
            config.modsecurity_response_body_limit,
            config
                .modsecurity_block_status
                .map(|status| StatusCode::from_u16(status).expect("validated ModSecurity status")),
        )?)
    };
    let router = Router::load(Arc::new(config.clone()), config.config_file.as_ref(), waf).await?;
    #[cfg(feature = "acme")]
    let router = {
        let mut router = router;
        if let Some(settings) = config.acme.clone() {
            let cache = settings.cache.clone();
            let acme = AcmeManager::load(settings, router.acme_names()).await?;
            let cache = tokio::fs::canonicalize(&cache).await?;
            for root in router.document_roots() {
                let root = tokio::fs::canonicalize(root).await?;
                if cache.starts_with(root) {
                    return Err("ACME cache must be outside every served document root".into());
                }
            }
            router.set_acme_manager(Some(acme));
        }
        router
    };
    let router = Arc::new(router);
    let tls_setup = TlsSetup::load(&config, &router)?;
    if config.tls_bind.is_some() && tls_setup.is_none() {
        return Err("--tls-bind requires a global or virtual-host TLS certificate".into());
    }
    #[cfg(feature = "acme")]
    if config.acme.is_some() {
        eprintln!(
            "ACME enabled; eligible virtual-host certificates will be provisioned on plaintext traffic"
        );
    }
    let tls_listener = match (config.tls_bind, tls_setup.as_ref()) {
        (Some(address), Some(_)) => Some(TcpListener::bind(address).await?),
        _ => None,
    };
    #[cfg(feature = "http3")]
    let http3_endpoint = if let Some(tls) = &tls_setup {
        Some(http3::bind(config.http3_bind, &tls.http3)?)
    } else {
        None
    };
    #[cfg(feature = "http3")]
    let alt_svc_port = http3_endpoint.as_ref().map(|(_, address)| address.port());
    #[cfg(not(feature = "http3"))]
    let alt_svc_port = None;
    let tls_acceptor = tls_setup
        .as_ref()
        .map(|tls| TlsAcceptor::from(Arc::clone(&tls.tcp)));
    #[cfg(feature = "hosting")]
    eprintln!(
        "Listening on http://{} with root {}",
        config.bind,
        config.root.display()
    );
    #[cfg(not(feature = "hosting"))]
    eprintln!("Listening on http://{}", config.bind);
    if let Some(listener) = &tls_listener {
        eprintln!("Listening on https://{}", listener.local_addr()?);
    }
    #[cfg(feature = "http3")]
    if let Some((_, address)) = &http3_endpoint {
        eprintln!("Listening on {} (HTTP/3)", address);
    }
    #[cfg(feature = "hosting")]
    for backend in &config.fastcgi {
        if let FastCgiAddress::Cgi(interpreter) = &backend.address {
            let interpreter = interpreter.as_ref().map_or_else(
                || "direct executable".to_owned(),
                |path| path.display().to_string(),
            );
            eprintln!("CGI .{} -> {interpreter}", backend.extension);
            continue;
        }
        let address = match &backend.address {
            FastCgiAddress::Tcp(address) => address.clone(),
            FastCgiAddress::Unix(path) => format!("unix:{}", path.display()),
            FastCgiAddress::Cgi(_) => unreachable!("CGI backends were logged above"),
            FastCgiAddress::Spawn(app) => format!("spawn:{}", app.program.display()),
            FastCgiAddress::Pool(pool) => format!("spawn:{}", pool.app().program.display()),
        };
        eprintln!("FastCGI .{} -> {address}", backend.extension);
    }
    if !config.modsecurity_rules.is_empty() {
        eprintln!(
            "ModSecurity enabled with {} rule file(s)",
            config.modsecurity_rules.len()
        );
    }

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    #[cfg(feature = "http3")]
    let http3_task = http3_endpoint.map(|(endpoint, address)| {
        let router = Arc::clone(&router);
        let shutdown = shutdown_rx.clone();
        tokio::spawn(async move { http3::serve(endpoint, address, router, shutdown).await })
    });
    let reload_task = router
        .vhost_dir()
        .map(|dir| {
            reload::spawn_watcher(
                Arc::clone(&router),
                dir,
                config.clone(),
                tls_setup.as_ref().map(|tls| tls.sni.clone()),
                shutdown_rx.clone(),
            )
        })
        .transpose()?;
    let mut connections = JoinSet::new();
    let limiter = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = signal_tx.send(true);
        }
    });

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            // Reap finished connections as they end; left in the set, each
            // would hold its task allocation until shutdown.
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    eprintln!("Connection task failed: {error}");
                }
            }
            (accepted, permit) = accept(Some(&listener), &limiter) => {
                let Some((stream, peer, local)) = accepted_stream(accepted).await else {
                    continue;
                };
                let router = Arc::clone(&router);
                let connection_shutdown = shutdown_rx.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_connection(
                        stream,
                        peer,
                        local,
                        router,
                        connection_shutdown,
                        alt_svc_port,
                        None,
                    ).await {
                        eprintln!("Connection from {peer} failed: {error}");
                    }
                });
            }
            (accepted, permit) = accept(tls_listener.as_ref(), &limiter) => {
                let Some((stream, peer, local)) = accepted_stream(accepted).await else {
                    continue;
                };
                let router = Arc::clone(&router);
                let connection_shutdown = shutdown_rx.clone();
                let acceptor = tls_acceptor
                    .as_ref()
                    .expect("TLS listener requires a TLS acceptor")
                    .clone();
                connections.spawn(async move {
                    let _permit = permit;
                    match timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => {
                            let sni = stream.get_ref().1.server_name().map(Arc::<str>::from);
                            if let Err(error) = serve_connection(
                                stream,
                                peer,
                                local,
                                router,
                                connection_shutdown,
                                alt_svc_port,
                                Some(sni),
                            )
                            .await
                            {
                                eprintln!("TLS connection from {peer} failed: {error}");
                            }
                        }
                        Ok(Err(error)) => {
                            eprintln!("TLS handshake from {peer} failed: {error}");
                        }
                        Err(_) => eprintln!("TLS handshake from {peer} timed out"),
                    }
                });
            }
        }
    }

    let _ = shutdown_tx.send(true);
    if let Some(task) = reload_task
        && let Err(error) = task.await
    {
        eprintln!("vhost watcher task failed: {error}");
    }
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            eprintln!("Connection task failed: {error}");
        }
    }
    #[cfg(feature = "http3")]
    if let Some(task) = http3_task {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("HTTP/3 server failed: {error}"),
            Err(error) => eprintln!("HTTP/3 server task failed: {error}"),
        }
    }
    Ok(())
}

async fn serve_connection<I>(
    stream: I,
    peer: SocketAddr,
    local: SocketAddr,
    router: Arc<Router>,
    mut shutdown: watch::Receiver<bool>,
    alt_svc_port: Option<u16>,
    sni: Option<Option<Arc<str>>>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let (request_seen, mut first_request) = watch::channel(false);
    let service = service_fn(move |mut request: Request<hyper::body::Incoming>| {
        let router = Arc::clone(&router);
        let sni = sni.clone();
        request_seen.send_replace(true);
        async move {
            if let Some(sni) = sni {
                request.extensions_mut().insert(TlsSni(sni));
            }
            let mut response = router.dispatch(request, peer, local).await;
            if let Some(port) = alt_svc_port
                && let Ok(value) = format!("h3=\":{port}\"").parse()
            {
                response.headers_mut().insert(http::header::ALT_SVC, value);
            }
            Ok::<_, std::convert::Infallible>(response)
        }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    // Without these a client can hold a connection open indefinitely without
    // ever completing a request.
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(HTTP2_KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT);
    let mut connection = Box::pin(builder.serve_connection(io, service));

    if *shutdown.borrow() {
        connection.as_mut().graceful_shutdown();
        connection.await?;
        return Ok(());
    }

    // Hyper's header timeout starts with the first byte of a request, and
    // protocol detection before it has no timeout at all. This deadline covers
    // a client that connects and then sends nothing, or too little to tell.
    let no_request = async {
        timeout(HEADER_READ_TIMEOUT, first_request.wait_for(|seen| *seen))
            .await
            .is_err()
    };
    tokio::pin!(no_request);
    let mut awaiting_first_request = true;
    loop {
        tokio::select! {
            result = &mut connection => return result,
            _ = shutdown.changed() => {
                connection.as_mut().graceful_shutdown();
                connection.await?;
                return Ok(());
            }
            expired = &mut no_request, if awaiting_first_request => {
                if expired {
                    return Ok(());
                }
                awaiting_first_request = false;
            }
        }
    }
}
