#![forbid(unsafe_code)]

mod config;
mod fastcgi;
mod fastcgi_app;
mod handler;
mod http3;
mod httpdate;
mod mime;
mod tls;
mod vhost;
mod waf;
mod worker;

#[cfg(test)]
mod fuzz_support;

use std::{error::Error, net::SocketAddr, sync::Arc, time::Duration};

use hyper::{Request, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::watch,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

use crate::{
    config::{Config, FastCgiAddress, ParseResult},
    tls::TlsSetup,
    vhost::{Router, TlsSni},
    waf::Waf,
};

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = match Config::parse(std::env::args().skip(1))? {
        ParseResult::Help => {
            println!("{}", Config::usage());
            return Ok(());
        }
        ParseResult::Config(config) => *config,
    };

    if config.worker {
        worker::drop_privileges(&config)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        return runtime.block_on(worker::run(config));
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_master(config))
}

async fn run_master(config: Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    let root = tokio::fs::canonicalize(&config.root).await?;
    if !tokio::fs::metadata(&root).await?.is_dir() {
        return Err(format!("document root is not a directory: {}", root.display()).into());
    }
    let mut config = Config { root, ..config };
    let _fastcgi_apps = fastcgi_app::start_apps(&mut config).await?;
    let listener = TcpListener::bind(config.bind).await?;
    let waf = if config.modsecurity_rules.is_empty() {
        None
    } else {
        Some(Waf::load(
            &config.modsecurity_rules,
            config.modsecurity_body_limit,
            config.modsecurity_response_body_limit,
        )?)
    };
    let router =
        Arc::new(Router::load(Arc::new(config.clone()), config.config_file.as_ref(), waf).await?);
    let tls_setup = TlsSetup::load(&config, &router)?;
    if config.tls_bind.is_some() && tls_setup.is_none() {
        return Err("--tls-bind requires a global or virtual-host TLS certificate".into());
    }
    let tls_listener = match (config.tls_bind, tls_setup.as_ref()) {
        (Some(address), Some(_)) => Some(TcpListener::bind(address).await?),
        _ => None,
    };
    let http3_endpoint = if let Some(tls) = &tls_setup {
        Some(http3::bind(config.http3_bind, &tls.http3)?)
    } else {
        None
    };
    let alt_svc_port = http3_endpoint.as_ref().map(|(_, address)| address.port());
    let tls_acceptor = tls_setup
        .as_ref()
        .map(|tls| TlsAcceptor::from(Arc::clone(&tls.tcp)));
    eprintln!(
        "Listening on http://{} with root {}",
        config.bind,
        config.root.display()
    );
    if let Some(listener) = &tls_listener {
        eprintln!("Listening on https://{}", listener.local_addr()?);
    }
    if let Some((_, address)) = &http3_endpoint {
        eprintln!("Listening on {} (HTTP/3)", address);
    }
    for backend in &config.fastcgi {
        let address = match &backend.address {
            FastCgiAddress::Tcp(address) => address.clone(),
            FastCgiAddress::Unix(path) => format!("unix:{}", path.display()),
            FastCgiAddress::Spawn(app) => format!("spawn:{}", app.program.display()),
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
    let http3_task = http3_endpoint.map(|(endpoint, address)| {
        let router = Arc::clone(&router);
        let shutdown = shutdown_rx.clone();
        tokio::spawn(async move { http3::serve(endpoint, address, router, shutdown).await })
    });
    let mut connections = JoinSet::new();
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            let _ = signal_tx.send(true);
        }
    });

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let router = Arc::clone(&router);
                let connection_shutdown = shutdown_rx.clone();
                let local = stream.local_addr()?;
                connections.spawn(async move {
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
            accepted = async {
                match &tls_listener {
                    Some(listener) => listener.accept().await,
                    None => std::future::pending().await,
                }
            } => {
                let (stream, peer) = accepted?;
                let local = stream.local_addr()?;
                let router = Arc::clone(&router);
                let connection_shutdown = shutdown_rx.clone();
                let acceptor = tls_acceptor
                    .as_ref()
                    .expect("TLS listener requires a TLS acceptor")
                    .clone();
                connections.spawn(async move {
                    match timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                        Ok(Ok(stream)) => {
                            let sni = stream.get_ref().1.server_name().map(str::to_owned);
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
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            eprintln!("Connection task failed: {error}");
        }
    }
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
    sni: Option<Option<String>>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let service = service_fn(move |mut request: Request<hyper::body::Incoming>| {
        let router = Arc::clone(&router);
        let sni = sni.clone();
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
    let builder = auto::Builder::new(TokioExecutor::new());
    let mut connection = Box::pin(builder.serve_connection(io, service));

    if *shutdown.borrow() {
        connection.as_mut().graceful_shutdown();
        connection.await?;
        return Ok(());
    }

    tokio::select! {
        result = &mut connection => result?,
        _ = shutdown.changed() => {
            connection.as_mut().graceful_shutdown();
            connection.await?;
        }
    }
    Ok(())
}
