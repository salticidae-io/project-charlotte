//! Library entry point that composes server services and coordinates listeners and shutdown.

#![deny(unsafe_code)]

#[cfg(feature = "acme")]
mod acme;
mod bot;
#[cfg_attr(not(feature = "hosting"), allow(dead_code))]
mod cgroup;
mod config;
mod control;
#[cfg(feature = "hosting")]
mod fastcgi;
#[cfg(feature = "hosting")]
mod fastcgi_app;
mod forwarded;
#[cfg(feature = "hosting")]
mod handler;
#[cfg(feature = "http3")]
mod http3;
mod httpdate;
mod ja4;
mod logging;
mod logopener;
#[cfg(feature = "hosting")]
mod mime;
mod pathctx;
mod privileges;
#[cfg(feature = "proxy")]
mod proxy;
mod ratelimit;
mod reload;
mod response;
#[cfg(feature = "swarm")]
mod swarm;
mod tls;
mod traffic;
mod vhost;
mod waf;
#[cfg(feature = "hosting")]
mod worker;

/// Internal entry points used by the interactive vhost configuration tool.
#[doc(hidden)]
pub mod configure_support {
    pub use crate::config::{OptionInfo, OptionKind};
    /// Whether this build can host document-root virtual hosts.
    pub const HOSTING_ENABLED: bool = cfg!(feature = "hosting");
    /// Whether this build can proxy virtual hosts to HTTP upstreams.
    pub const PROXY_ENABLED: bool = cfg!(feature = "proxy");
    /// Whether this build supports ACME certificate provisioning.
    pub const ACME_ENABLED: bool = cfg!(feature = "acme");
    /// Whether this build supports Redis-backed swarm access checks.
    pub const SWARM_ENABLED: bool = cfg!(feature = "swarm");

    /// Returns visible global options that can be configured by the wizard.
    pub fn server_options() -> Vec<OptionInfo> {
        crate::config::Config::configurable_options()
    }

    /// Returns the YAML keys accepted by a virtual-host declaration.
    pub fn vhost_keys() -> &'static [&'static str] {
        crate::vhost::configure_vhost_keys()
    }

    /// Returns the YAML keys accepted by a managed FastCGI application.
    pub fn fastcgi_app_keys() -> &'static [&'static str] {
        crate::vhost::configure_fastcgi_app_keys()
    }

    /// Returns the YAML keys accepted by a bot policy.
    pub fn bot_policy_keys() -> &'static [&'static str] {
        crate::vhost::configure_bot_policy_keys()
    }

    /// Validates a single-vhost YAML document using Charlotte's startup validator.
    ///
    /// `config_dir` is the directory against which relative paths in the vhost
    /// are resolved. Set `has_waf` when the server will load ModSecurity rules
    /// globally; vhost ModSecurity overrides require that global configuration.
    ///
    /// # Errors
    /// Returns one or more diagnostics if the YAML is malformed, contains
    /// forbidden global settings, declares anything other than one vhost, or
    /// fails the same semantic checks used by server startup.
    pub fn validate_vhost_yaml(
        yaml: &str,
        config_dir: &std::path::Path,
        has_waf: bool,
    ) -> Result<(), Vec<String>> {
        crate::vhost::validate_vhost_document(yaml, config_dir, has_waf)
    }

    /// Validates a generated main config containing global `options` and an
    /// optional single `vhost` entry.
    pub fn validate_main_config_yaml(
        yaml: &str,
        config_dir: &std::path::Path,
    ) -> Result<(), Vec<String>> {
        crate::vhost::validate_main_document(yaml, config_dir)
    }
}

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
#[cfg(any(feature = "acme", feature = "hosting"))]
use crate::pathctx::PathContext;
use crate::{
    config::{Config, ParseResult},
    ja4::{ClientHelloInfo, RecordingStream, TlsFingerprint, parse_client_hello},
    ratelimit::RateLimiter,
    tls::TlsSetup,
    vhost::{Router, TlsSni},
    waf::Waf,
};

/// Internal entry points used by the Gungraun benchmark harness.
#[doc(hidden)]
pub mod bench {
    /// Decodes a request path for static-file lookup.
    #[cfg(feature = "hosting")]
    pub fn decode_request_path(path: &str) -> Option<std::path::PathBuf> {
        crate::handler::decode_request_path(path)
    }

    /// Parses a single byte range against a representation size.
    #[cfg(feature = "hosting")]
    pub fn parse_byte_range(value: &str, size: u64) -> Result<Option<(u64, u64)>, ()> {
        crate::handler::parse_byte_range(value, size)
    }

    /// Escapes HTML text into an existing output buffer.
    #[cfg(feature = "hosting")]
    pub fn escape_html_into(output: &mut String, value: &str) {
        crate::handler::escape_html_into(output, value);
    }

    /// Formats a timestamp as an HTTP date.
    pub fn format_http_date(time: chrono::DateTime<chrono::Utc>) -> String {
        crate::httpdate::format_http_date(time)
    }

    /// Parses an HTTP date.
    pub fn parse_http_date(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
        crate::httpdate::parse_http_date(value)
    }

    /// Looks up a MIME type by file path.
    #[cfg(feature = "hosting")]
    pub fn mime_for_path(path: &std::path::Path) -> &'static str {
        crate::mime::for_path(path)
    }

    /// Returns the match score for an exact or wildcard host pattern.
    pub fn match_host(pattern: &str, host: &str) -> Option<usize> {
        crate::vhost::match_score(pattern, host)
    }

    /// Selects an SNI entry, falling back only when no host pattern matches.
    pub fn select_sni_entry<'a, T>(
        entries: &'a [(String, T)],
        fallback: Option<&'a T>,
        server_name: Option<&str>,
    ) -> Option<&'a T> {
        crate::tls::select_key(entries, fallback, server_name)
    }
}

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
            crate::log_error!("Could not accept connection: {error}");
            tokio::time::sleep(ACCEPT_ERROR_DELAY).await;
            None
        }
    }
}

/// Runs the server using the process command-line arguments.
pub fn run() -> Result<(), Box<dyn Error + Send + Sync>> {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|argument| argument == logopener::HELPER_ARGUMENT)
    {
        return logopener::run_helper(0);
    }
    let config = match Config::parse(std::env::args().skip(1))? {
        ParseResult::Help => {
            println!("{}", Config::usage());
            return Ok(());
        }
        ParseResult::Config(config) => *config,
    };
    if config.check_config {
        let diagnostics = vhost::check_config(&config);
        if diagnostics.is_empty() {
            println!("Configuration OK");
            return Ok(());
        }
        return Err(diagnostics.join("\n").into());
    }
    #[cfg(feature = "hosting")]
    let mut config = config;
    #[cfg(feature = "hosting")]
    {
        fastcgi::set_keepalive_limit(config.fastcgi_keepalive);
        handler::set_static_cache_ttl(config.static_cache_ttl);
    }
    #[cfg(not(feature = "hosting"))]
    let config = config;

    let error_target = if cfg!(feature = "hosting") && config.worker {
        logging::LogTarget::stderr()
    } else if let Some(path) = config.error_log_file.as_deref() {
        logging::open_log(path, "error")?
    } else {
        logging::LogTarget::stderr()
    };
    logging::set_global_error_log(std::sync::Arc::new(logging::ErrorLog::new(
        error_target,
        logging::ErrorFormat::parse(&config.error_log_format)?,
    )));
    let access_target = if config.access_log_file.is_some() {
        Some(logging::open_log(
            config
                .access_log_file
                .as_deref()
                .expect("checked access log path"),
            "access",
        )?)
    } else if config.access_log {
        Some(logging::LogTarget::stdout())
    } else {
        None
    };
    let access_log = access_target.map(|target| {
        logging::AccessLog::new(
            target,
            logging::AccessFormat::parse(&config.access_log_format)
                .expect("validated access log format"),
        )
    });
    logging::set_global_access_log(access_log.map(std::sync::Arc::new));
    logging::set_debug(config.debug);
    crate::log_debug!(
        "Error log target: {}",
        config
            .error_log_file
            .as_deref()
            .map_or_else(|| "stderr".to_owned(), |path| path.display().to_string())
    );
    crate::log_debug!(
        "Access log target: {}",
        config.access_log_file.as_deref().map_or_else(
            || if config.access_log {
                "stdout"
            } else {
                "disabled"
            }
            .to_owned(),
            |path| path.display().to_string()
        )
    );

    let report_startup_errors = config.error_log_file.is_some();
    let startup_result = (move || -> Result<(), Box<dyn Error + Send + Sync>> {
        #[cfg(feature = "hosting")]
        if config.worker {
            crate::log_debug!("Starting in virtual-host worker mode");
            if let Ok(app_env) = std::env::var(config::WORKER_APP_ENV) {
                config.apply_fastcgi_app_env(&app_env)?;
            }
            worker::drop_privileges(&config)?;
            crate::log_debug!(
                "Starting worker runtime with {} thread(s)",
                config.worker_threads
            );
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(config.worker_threads)
                .enable_all()
                .build()?;
            return runtime.block_on(worker::run(config));
        }
        crate::log_debug!("Starting master process");
        logopener::start(&config)?;
        // Read the main configuration while still privileged; the --user
        // account may not be able to traverse its directory.
        let main_config = config
            .config_file
            .as_deref()
            .map(vhost::read_trusted_config)
            .transpose()?;
        privileges::drop_master(&config)?;
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        if let Some(threads) = config.threads {
            builder.worker_threads(threads);
        }
        crate::log_debug!(
            "Starting master runtime with {} thread(s)",
            config
                .threads
                .map_or_else(|| "Tokio default".to_owned(), |threads| threads.to_string())
        );
        let runtime = builder.enable_all().build()?;
        runtime.block_on(run_master(config, main_config))
    })();
    if report_startup_errors {
        if let Err(error) = &startup_result {
            crate::log_error!("Startup failed: {error}");
        }
    }
    logging::flush_logs();
    startup_result
}

async fn run_master(
    config: Config,
    main_config: Option<String>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(feature = "hosting")]
    let root = tokio::fs::canonicalize(&config.root)
        .await
        .path_context("resolve document root", &config.root)?;
    #[cfg(feature = "hosting")]
    if !tokio::fs::metadata(&root)
        .await
        .path_context("inspect document root", &root)?
        .is_dir()
    {
        return Err(format!("document root is not a directory: {}", root.display()).into());
    }
    #[cfg(feature = "hosting")]
    crate::log_debug!("Resolved fallback document root to {}", root.display());
    #[cfg(feature = "hosting")]
    let mut config = Config { root, ..config };
    #[cfg(not(feature = "hosting"))]
    let config = config;
    #[cfg(feature = "hosting")]
    crate::log_debug!("Starting configured FastCGI applications");
    #[cfg(feature = "hosting")]
    let _fastcgi_apps = fastcgi_app::start_apps(&mut config).await?;
    let listener = if config.plain_http {
        crate::log_debug!("Binding plain HTTP listener to {}", config.bind);
        let listener = TcpListener::bind(config.bind).await.map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("could not bind TCP listener to {}: {error}", config.bind),
            )
        })?;
        crate::log_debug!("Bound plain HTTP listener on {}", listener.local_addr()?);
        Some(listener)
    } else {
        crate::log_debug!("Plain HTTP listener disabled");
        None
    };
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
    let rate_limit = config
        .rate_limit
        .map(|limit| Arc::new(RateLimiter::new(limit)));
    log_debug!("Loading virtual-host router");
    let router = Router::load(
        Arc::new(config.clone()),
        config.config_file.as_ref(),
        main_config,
        rate_limit,
        waf,
    )
    .await?;
    log_debug!("Loaded virtual-host router");
    #[cfg(feature = "acme")]
    let router = {
        let mut router = router;
        if let Some(settings) = config.acme.clone() {
            let cache = settings.cache.clone();
            log_debug!("Initializing ACME manager with cache {}", cache.display());
            let acme = AcmeManager::load(settings, router.acme_names()).await?;
            let cache = tokio::fs::canonicalize(&cache)
                .await
                .path_context("resolve ACME cache directory", &cache)?;
            for root in router.document_roots() {
                let root = tokio::fs::canonicalize(&root)
                    .await
                    .path_context("resolve document root", &root)?;
                if cache.starts_with(root) {
                    return Err("ACME cache must be outside every served document root".into());
                }
            }
            router.set_acme_manager(Some(acme));
            log_debug!("Initialized ACME manager");
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
        crate::log_error!(
            "ACME enabled; eligible virtual-host certificates will be provisioned on plaintext traffic"
        );
    }
    let tls_listener = match (config.tls_bind, tls_setup.as_ref()) {
        (Some(address), Some(_)) => {
            crate::log_debug!("Binding TLS listener to {address}");
            let listener = TcpListener::bind(address).await.map_err(|error| {
                std::io::Error::new(
                    error.kind(),
                    format!("could not bind TLS listener to {address}: {error}"),
                )
            })?;
            crate::log_debug!("Bound TLS listener on {}", listener.local_addr()?);
            Some(listener)
        }
        _ => None,
    };
    if let Some(listener) = &tls_listener {
        router.set_https_port(listener.local_addr()?.port());
    }
    #[cfg(feature = "http3")]
    let http3_endpoint = if let Some(tls) = &tls_setup {
        crate::log_debug!("Binding HTTP/3 endpoint to {}", config.http3_bind);
        let endpoint = http3::bind(config.http3_bind, &tls.http3)?;
        crate::log_debug!("Bound HTTP/3 endpoint on {}", endpoint.1);
        Some(endpoint)
    } else {
        None
    };
    #[cfg(feature = "http3")]
    let http3_active = http3_endpoint.is_some();
    #[cfg(not(feature = "http3"))]
    let http3_active = false;
    if !config.plain_http && tls_listener.is_none() && !http3_active {
        #[cfg(feature = "http3")]
        let message =
            "no listeners enabled; HTTP/3 requires a TLS certificate (or enable plain HTTP/TLS)";
        #[cfg(not(feature = "http3"))]
        let message = "no listeners enabled; enable plain HTTP or configure a TLS listener";
        return Err(message.into());
    }
    #[cfg(feature = "http3")]
    let alt_svc_port = http3_endpoint.as_ref().map(|(_, address)| address.port());
    #[cfg(not(feature = "http3"))]
    let alt_svc_port = None;
    let tls_acceptor = tls_setup
        .as_ref()
        .map(|tls| TlsAcceptor::from(Arc::clone(&tls.tcp)));
    #[cfg(feature = "hosting")]
    if let Some(listener) = &listener {
        crate::log_notice!(
            "Listening on http://{} with root {}",
            listener.local_addr()?,
            config.root.display()
        );
    }
    #[cfg(not(feature = "hosting"))]
    if let Some(listener) = &listener {
        crate::log_notice!("Listening on http://{}", listener.local_addr()?);
    }
    if let Some(listener) = &tls_listener {
        crate::log_notice!("Listening on https://{}", listener.local_addr()?);
    }
    #[cfg(feature = "http3")]
    if let Some((_, address)) = &http3_endpoint {
        crate::log_notice!("Listening on {} (HTTP/3)", address);
    }
    #[cfg(feature = "hosting")]
    for backend in &config.fastcgi {
        if let FastCgiAddress::Cgi(interpreter) = &backend.address {
            let interpreter = interpreter.as_ref().map_or_else(
                || "direct executable".to_owned(),
                |path| path.display().to_string(),
            );
            crate::log_notice!("CGI .{} -> {interpreter}", backend.extension);
            continue;
        }
        let address = match &backend.address {
            FastCgiAddress::Tcp(address) => address.clone(),
            FastCgiAddress::Unix(path) => format!("unix:{}", path.display()),
            FastCgiAddress::Cgi(_) => unreachable!("CGI backends were logged above"),
            FastCgiAddress::Spawn(app) => format!("spawn:{}", app.program.display()),
            FastCgiAddress::Pool(pool) => format!("spawn:{}", pool.app().program.display()),
        };
        crate::log_notice!("FastCGI .{} -> {address}", backend.extension);
    }
    if !config.modsecurity_rules.is_empty() {
        crate::log_notice!(
            "ModSecurity enabled with {} rule file(s)",
            config.modsecurity_rules.len()
        );
    }

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let started = std::time::Instant::now();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
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
    let control_task = if let Some(path) = config.control_socket.clone() {
        Some(
            control::spawn(
                path,
                Arc::clone(&router),
                config.clone(),
                tls_setup.as_ref().map(|tls| tls.sni.clone()),
                started,
                shutdown_rx.clone(),
            )
            .await?,
        )
    } else {
        None
    };
    let mut connections = JoinSet::new();
    let limiter = Arc::new(Semaphore::new(config.max_connections));
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if result.is_ok() {
                    let _ = signal_tx.send(true);
                }
            }
            _ = terminate.recv() => {
                let _ = signal_tx.send(true);
            }
        }
    });

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            // Reap finished connections as they end; left in the set, each
            // would hold its task allocation until shutdown.
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    crate::log_error!("Connection task failed: {error}");
                }
            }
            (accepted, permit) = accept(listener.as_ref(), &limiter) => {
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
                        config.header_read_timeout,
                        None,
                        None,
                    ).await {
                        crate::log_error!("Connection from {peer} failed: {error}");
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
                    let recording = RecordingStream::new(stream);
                    let captured = recording.captured();
                    match timeout(config.tls_handshake_timeout, acceptor.accept(recording)).await {
                        Ok(Ok(stream)) => {
                            let sni = stream.get_ref().1.server_name().map(Arc::<str>::from);
                            let fingerprint = parse_client_hello(
                                &captured
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner),
                            )
                            .map(Arc::new);
                            if let Err(error) = serve_connection(
                                stream,
                                peer,
                                local,
                                router,
                                connection_shutdown,
                                alt_svc_port,
                                config.header_read_timeout,
                                Some(sni),
                                fingerprint,
                            )
                            .await
                            {
                                crate::log_error!("TLS connection from {peer} failed: {error}");
                            }
                        }
                        Ok(Err(error)) => {
                            crate::log_error!("TLS handshake from {peer} failed: {error}");
                        }
                        Err(_) => crate::log_error!("TLS handshake from {peer} timed out"),
                    }
                });
            }
        }
    }

    let _ = shutdown_tx.send(true);
    if let Some(task) = reload_task
        && let Err(error) = task.await
    {
        crate::log_error!("vhost watcher task failed: {error}");
    }
    if let Some(task) = control_task
        && let Err(error) = task.await
    {
        crate::log_error!("control socket task failed: {error}");
    }
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            crate::log_error!("Connection task failed: {error}");
        }
    }
    #[cfg(feature = "http3")]
    if let Some(task) = http3_task {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => crate::log_error!("HTTP/3 server failed: {error}"),
            Err(error) => crate::log_error!("HTTP/3 server task failed: {error}"),
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
    header_read_timeout: Duration,
    sni: Option<Option<Arc<str>>>,
    fingerprint: Option<Arc<ClientHelloInfo>>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let alt_svc = alt_svc_port.and_then(|port| format!("h3=\":{port}\"").parse().ok());
    let (request_seen, mut first_request) = watch::channel(false);
    let service = service_fn(move |mut request: Request<hyper::body::Incoming>| {
        let router = Arc::clone(&router);
        let sni = sni.clone();
        let fingerprint = fingerprint.clone();
        let alt_svc = alt_svc.clone();
        request_seen.send_replace(true);
        async move {
            if let Some(sni) = sni {
                request.extensions_mut().insert(TlsSni(sni));
            }
            if let Some(fingerprint) = fingerprint {
                request.extensions_mut().insert(TlsFingerprint(fingerprint));
            }
            let mut response = router.dispatch(request, peer, local).await;
            if let Some(value) = alt_svc {
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
        .header_read_timeout(header_read_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .adaptive_window(true)
        .max_concurrent_streams(256)
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
        timeout(header_read_timeout, first_request.wait_for(|seen| *seen))
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
