#![forbid(unsafe_code)]

mod config;
mod fastcgi;
mod handler;
mod http3;
mod httpdate;
mod mime;
mod vhost;
mod waf;
mod worker;

#[cfg(test)]
mod fuzz_support;

use std::{error::Error, net::SocketAddr, sync::Arc};

use hyper::{Request, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};

use crate::{
    config::{Config, FastCgiAddress, ParseResult},
    vhost::Router,
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
    let listener = TcpListener::bind(config.bind).await?;
    let http3_endpoint = if let Some(tls) = &config.tls {
        let endpoint = http3::bind(config.http3_bind, tls)?;
        Some(endpoint)
    } else {
        None
    };
    if let Some((_, address)) = &http3_endpoint {
        config.http3_bind = *address;
    }
    let config = Arc::new(config);
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
        Arc::new(Router::load(Arc::clone(&config), config.config_file.as_ref(), waf).await?);
    eprintln!(
        "Listening on http://{} with root {}",
        config.bind,
        config.root.display()
    );
    if let Some((_, address)) = &http3_endpoint {
        eprintln!("Listening on {} (HTTP/3)", address);
    }
    for backend in &config.fastcgi {
        let address = match &backend.address {
            FastCgiAddress::Tcp(address) => address.clone(),
            FastCgiAddress::Unix(path) => format!("unix:{}", path.display()),
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
                let config = Arc::clone(&config);
                let router = Arc::clone(&router);
                let connection_shutdown = shutdown_rx.clone();
                let local = stream.local_addr()?;
                connections.spawn(async move {
                    if let Err(error) = serve_connection(stream, peer, local, config, router, connection_shutdown).await {
                        eprintln!("Connection from {peer} failed: {error}");
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

async fn serve_connection(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    local: SocketAddr,
    config: Arc<Config>,
    router: Arc<Router>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let io = TokioIo::new(stream);
    let http3_port = config.tls.as_ref().map(|_| config.http3_bind.port());
    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
        let router = Arc::clone(&router);
        async move {
            let mut response = router.dispatch(request, peer, local).await;
            if let Some(port) = http3_port
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
