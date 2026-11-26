//! Standalone control-socket UI. Run `charlotte-admin --help` for configuration.
//! TLS can be served directly with `--tls-cert` and `--tls-key`, or terminated
//! at a trusted reverse proxy. The proxy must strip external forwarding headers.
//! IP checks always use the TCP peer, never forwarding headers, so a proxy
//! cannot convey client IPs here.
//! Sessions are in memory and disappear on restart.
//! Example: `CHARLOTTE_ADMIN_PASSWORD=... charlotte-admin --base-url
//! http://localhost:8080 --socket /run/charlotte/control.sock`. Protect the
//! listener and control socket from untrusted local users. Per-peer request
//! and login rate limits are configurable;
//! lockouts and counters are in memory and are not an audit log.
//! Traffic graphs are built by sampling the control socket's `/status` counters
//! every `--sample-interval` seconds; the last `--history` samples are kept in
//! memory, so graph history starts empty whenever this process restarts.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Extension, Json, Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite};
use url::Url;

#[derive(Parser)]
#[command(about = "Web administration for a Charlotte control socket")]
struct Config {
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
    /// Public URL, including any path prefix; use HTTPS in production.
    #[arg(long, env = "CHARLOTTE_ADMIN_BASE_URL")]
    base_url: String,
    #[arg(
        long,
        env = "CHARLOTTE_CONTROL_SOCKET",
        default_value = "/run/charlotte/control.sock"
    )]
    socket: PathBuf,
    /// Static password (prefer environment variable over command line).
    #[arg(long, env = "CHARLOTTE_ADMIN_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    /// PEM certificate chain for HTTPS. Must be used with --tls-key.
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// PEM private key for HTTPS. Must be used with --tls-cert.
    #[arg(long, hide_env_values = true)]
    tls_key: Option<PathBuf>,
    /// Allowed TCP peer IP address; repeat for multiple addresses. Default: loopback only.
    #[arg(long)]
    allow_ip: Vec<IpAddr>,
    /// Maximum requests per minute per peer IP (0 disables this limit).
    #[arg(long, default_value_t = 600)]
    rate_limit: u64,
    /// Maximum sign-in endpoint requests per minute per peer IP (0 disables this limit).
    #[arg(long, default_value_t = 10)]
    login_rate_limit: u64,
    /// Failed sign-ins before an IP is locked out (0 disables lockouts).
    #[arg(long, default_value_t = 5)]
    max_login_failures: u64,
    /// Lockout duration and failed-sign-in counting window in seconds.
    #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(1..))]
    lockout_seconds: u64,
    /// Seconds between traffic samples used for graphs.
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=3600))]
    sample_interval: u64,
    /// Number of traffic samples kept in memory (default: one hour at 10 s).
    #[arg(long, default_value_t = 360, value_parser = clap::value_parser!(u64).range(2..=100_000))]
    history: u64,
}

struct Session {
    csrf: String,
    expires: Instant,
}
struct ClientLimits {
    last_seen: Instant,
    requests_started: Option<Instant>,
    requests: u64,
    logins_started: Option<Instant>,
    logins: u64,
    failures_started: Option<Instant>,
    failures: u64,
    locked_at: Option<Instant>,
}
impl ClientLimits {
    fn new(now: Instant) -> Self {
        Self {
            last_seen: now,
            requests_started: None,
            requests: 0,
            logins_started: None,
            logins: 0,
            failures_started: None,
            failures: 0,
            locked_at: None,
        }
    }
}
struct Limiter {
    clients: Mutex<HashMap<IpAddr, ClientLimits>>,
    request_limit: u64,
    login_limit: u64,
    max_login_failures: u64,
    lockout: Duration,
}
impl Limiter {
    const MAX_CLIENTS: usize = 4096;
    const WINDOW: Duration = Duration::from_secs(60);

    fn new(config: &Config) -> Self {
        Self {
            clients: Mutex::new(HashMap::new()),
            request_limit: config.rate_limit,
            login_limit: config.login_rate_limit,
            max_login_failures: config.max_login_failures,
            lockout: Duration::from_secs(config.lockout_seconds),
        }
    }

    fn entry<'a>(
        &'a self,
        clients: &'a mut HashMap<IpAddr, ClientLimits>,
        ip: IpAddr,
        now: Instant,
    ) -> Option<&'a mut ClientLimits> {
        let idle_timeout = Self::WINDOW.max(self.lockout);
        clients.retain(|_, client| {
            now.saturating_duration_since(client.last_seen) < idle_timeout
                || client
                    .locked_at
                    .is_some_and(|at| now.saturating_duration_since(at) < self.lockout)
        });
        if !clients.contains_key(&ip) && clients.len() >= Self::MAX_CLIENTS {
            return None;
        }
        let client = clients.entry(ip).or_insert_with(|| ClientLimits::new(now));
        client.last_seen = now;
        Some(client)
    }

    fn request(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        if self.request_limit == 0 {
            return None;
        }
        let mut clients = self.clients.lock().unwrap();
        let Some(client) = self.entry(&mut clients, ip, now) else {
            return Some(Self::WINDOW);
        };
        match client.requests_started {
            Some(started) if now.saturating_duration_since(started) < Self::WINDOW => {
                if client.requests >= self.request_limit {
                    return Some(
                        Self::WINDOW.saturating_sub(now.saturating_duration_since(started)),
                    );
                }
                client.requests = client.requests.saturating_add(1);
            }
            _ => {
                client.requests_started = Some(now);
                client.requests = 1;
            }
        }
        None
    }

    fn login_attempt(&self, ip: IpAddr, now: Instant) -> Option<Duration> {
        if self.login_limit == 0 && self.max_login_failures == 0 {
            return None;
        }
        let mut clients = self.clients.lock().unwrap();
        let Some(client) = self.entry(&mut clients, ip, now) else {
            return Some(Self::WINDOW);
        };
        if let Some(locked_at) = client.locked_at {
            let elapsed = now.saturating_duration_since(locked_at);
            if elapsed < self.lockout {
                return Some(self.lockout.saturating_sub(elapsed));
            }
            client.locked_at = None;
            client.failures_started = None;
            client.failures = 0;
        }
        if client
            .failures_started
            .is_some_and(|started| now.saturating_duration_since(started) >= self.lockout)
        {
            client.failures_started = None;
            client.failures = 0;
        }
        if self.login_limit == 0 {
            return None;
        }
        match client.logins_started {
            Some(started) if now.saturating_duration_since(started) < Self::WINDOW => {
                if client.logins >= self.login_limit {
                    return Some(
                        Self::WINDOW.saturating_sub(now.saturating_duration_since(started)),
                    );
                }
                client.logins = client.logins.saturating_add(1);
            }
            _ => {
                client.logins_started = Some(now);
                client.logins = 1;
            }
        }
        None
    }

    fn failure(&self, ip: IpAddr, now: Instant) {
        if self.max_login_failures == 0 {
            return;
        }
        let mut clients = self.clients.lock().unwrap();
        let Some(client) = self.entry(&mut clients, ip, now) else {
            return;
        };
        if client
            .failures_started
            .is_none_or(|started| now.saturating_duration_since(started) >= self.lockout)
        {
            client.failures_started = Some(now);
            client.failures = 0;
        }
        client.failures = client.failures.saturating_add(1);
        if client.failures >= self.max_login_failures {
            client.locked_at = Some(now);
            eprintln!(
                "admin login locked out {ip} for {} seconds",
                self.lockout.as_secs()
            );
        }
    }

    fn success(&self, ip: IpAddr) {
        if let Some(client) = self.clients.lock().unwrap().get_mut(&ip) {
            client.failures_started = None;
            client.failures = 0;
            client.locked_at = None;
        }
    }
}
struct App {
    config: Config,
    base: Url,
    prefix: String,
    control: reqwest::Client,
    sessions: Mutex<HashMap<String, Session>>,
    limiter: Limiter,
    history: Mutex<VecDeque<serde_json::Value>>,
}
type Shared = Arc<App>;

fn random() -> String {
    let mut bytes = [0; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .expect("OS randomness unavailable");
    URL_SAFE_NO_PAD.encode(bytes)
}
fn equal(a: &str, b: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, b"charlotte-admin comparison");
    hmac::verify(&key, b.as_bytes(), hmac::sign(&key, a.as_bytes()).as_ref()).is_ok()
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|v| v.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}
fn cookie_value(app: &App, name: &str, value: &str, age: u64) -> String {
    format!(
        "{name}={value}; Path={}; HttpOnly; SameSite=Lax; Max-Age={age}{}",
        if app.prefix.is_empty() {
            "/"
        } else {
            &app.prefix
        },
        if app.base.scheme() == "https" {
            "; Secure"
        } else {
            ""
        }
    )
}
fn origin(app: &App) -> String {
    app.base.origin().ascii_serialization()
}
fn valid_origin(headers: &HeaderMap, app: &App) -> bool {
    headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) == Some(origin(app).as_str())
}
fn session(app: &App, headers: &HeaderMap) -> Option<String> {
    let id = cookie(headers, "charlotte_session")?;
    let mut sessions = app.sessions.lock().unwrap();
    sessions.retain(|_, v| v.expires > Instant::now());
    sessions.get(&id).map(|s| s.csrf.clone())
}
fn issue_session(app: &App) -> Response {
    let id = random();
    let csrf = random();
    let mut sessions = app.sessions.lock().unwrap();
    sessions.retain(|_, s| s.expires > Instant::now());
    if sessions.len() >= 1024 {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    sessions.insert(
        id.clone(),
        Session {
            csrf,
            expires: Instant::now() + Duration::from_secs(8 * 3600),
        },
    );
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie_value(app, "charlotte_session", &id, 8 * 3600)
            .parse()
            .unwrap(),
    );
    response
}

async fn guard(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let allowed = if app.config.allow_ip.is_empty() {
        peer.ip().is_loopback()
    } else {
        app.config.allow_ip.contains(&peer.ip())
    };
    if !allowed {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut response = if let Some(wait) = app.limiter.request(peer.ip(), Instant::now()) {
        too_many_requests(wait)
    } else {
        next.run(request).await
    };
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    h.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    if app.config.tls_cert.is_some() {
        h.insert(
            "strict-transport-security",
            "max-age=31536000".parse().unwrap(),
        );
    }
    h.insert(header::CONTENT_SECURITY_POLICY, "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'".parse().unwrap());
    h.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    response
}

fn too_many_requests(wait: Duration) -> Response {
    let seconds = wait
        .as_secs()
        .saturating_add(u64::from(wait.subsec_nanos() > 0))
        .max(1);
    let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, seconds.to_string().parse().unwrap());
    response
}

async fn index() -> Html<&'static str> {
    Html(UI)
}
async fn auth_methods() -> Json<serde_json::Value> {
    Json(serde_json::json!({"password": true}))
}
#[derive(Deserialize)]
struct Login {
    password: String,
}
async fn login(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(login): Json<Login>,
) -> Response {
    login_at(&app, peer.ip(), headers, login, Instant::now()).await
}
async fn login_at(
    app: &App,
    ip: IpAddr,
    headers: HeaderMap,
    login: Login,
    now: Instant,
) -> Response {
    if !valid_origin(&headers, &app) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(wait) = app.limiter.login_attempt(ip, now) {
        return too_many_requests(wait);
    }
    if app
        .config
        .password
        .as_ref()
        .is_some_and(|p| equal(p, &login.password))
    {
        app.limiter.success(ip);
        issue_session(&app)
    } else {
        app.limiter.failure(ip, now);
        StatusCode::UNAUTHORIZED.into_response()
    }
}
async fn csrf(State(app): State<Shared>, headers: HeaderMap) -> Response {
    match session(&app, &headers) {
        Some(token) => Json(serde_json::json!({"csrf": token})).into_response(),
        None => StatusCode::UNAUTHORIZED.into_response(),
    }
}
fn authorized(app: &App, headers: &HeaderMap, mutation: bool) -> bool {
    session(app, headers).is_some_and(|csrf| {
        !mutation
            || (valid_origin(headers, app)
                && headers
                    .get("x-csrf-token")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| equal(v, &csrf)))
    })
}
async fn logout(State(app): State<Shared>, headers: HeaderMap) -> Response {
    if !authorized(&app, &headers, true) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(id) = cookie(&headers, "charlotte_session") {
        app.sessions.lock().unwrap().remove(&id);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie_value(&app, "charlotte_session", "", 0)
            .parse()
            .unwrap(),
    );
    response
}

async fn proxy(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    Path(route): Path<String>,
    body: Bytes,
) -> Response {
    let mutation = method != Method::GET;
    if !authorized(&app, &headers, mutation) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let valid = match route.as_str() {
        "status" | "vhosts" => method == Method::GET,
        "options" => matches!(method, Method::GET | Method::PUT),
        _ => route.strip_prefix("vhosts/").is_some_and(|name| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
                && matches!(
                    method,
                    Method::GET | Method::POST | Method::PUT | Method::DELETE
                )
        }),
    };
    if !valid {
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = app
        .control
        .request(method, format!("http://localhost/{route}"))
        .body(body)
        .send()
        .await;
    let Ok(result) = result else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let status = result.status();
    match result.bytes().await {
        Ok(bytes) if bytes.len() <= 1024 * 1024 => {
            (status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response()
        }
        _ => StatusCode::BAD_GATEWAY.into_response(),
    }
}

async fn sample(app: &App) -> Option<serde_json::Value> {
    let response = app
        .control
        .get("http://localhost/status")
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?;
    let status: serde_json::Value = response.json().await.ok()?;
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs_f64();
    Some(serde_json::json!({
        "time": time,
        "uptime_seconds": status.get("uptime_seconds")?,
        "traffic": status.get("traffic")?,
    }))
}
fn record(app: &App, sample: serde_json::Value) {
    let mut history = app.history.lock().unwrap();
    let limit = usize::try_from(app.config.history).unwrap_or(usize::MAX);
    while history.len() >= limit {
        history.pop_front();
    }
    history.push_back(sample);
}
async fn sampler(app: Shared) {
    let mut ticker = tokio::time::interval(Duration::from_secs(app.config.sample_interval));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        if let Some(sample) = sample(&app).await {
            record(&app, sample);
        }
    }
}
async fn history(State(app): State<Shared>, headers: HeaderMap) -> Response {
    if !authorized(&app, &headers, false) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let samples: Vec<_> = app.history.lock().unwrap().iter().cloned().collect();
    Json(serde_json::json!({"interval": app.config.sample_interval, "samples": samples}))
        .into_response()
}

fn validate(config: &Config) -> Result<(Url, String), String> {
    let base = Url::parse(&config.base_url).map_err(|e| e.to_string())?;
    if base.username() != ""
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || base.host_str().is_none()
    {
        return Err("invalid base URL".into());
    }
    let loopback = match base.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if base.scheme() != "https"
        && !(base.scheme() == "http" && loopback && config.bind.ip().is_loopback())
    {
        return Err("base URL must use HTTPS (HTTP is permitted only on loopback)".into());
    }
    let prefix = base.path().trim_end_matches('/').to_owned();
    if !prefix
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
        || prefix.contains("//")
    {
        return Err("invalid base URL path".into());
    }
    if config.password.as_ref().is_some_and(|p| p.is_empty()) {
        return Err("password must not be empty".into());
    }
    if config.lockout_seconds == 0 {
        return Err("lockout duration must be at least one second".into());
    }
    if config.tls_cert.is_some() != config.tls_key.is_some() {
        return Err("TLS requires both --tls-cert and --tls-key".into());
    }
    if config.tls_cert.is_some() && base.scheme() != "https" {
        return Err("base URL must use HTTPS when TLS is enabled".into());
    }
    if config.password.is_none() {
        return Err("configure --password or CHARLOTTE_ADMIN_PASSWORD".into());
    }
    Ok((base, prefix))
}

fn load_tls_config(
    cert_path: &FsPath,
    key_path: &FsPath,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let certs = CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err("TLS certificate file contains no certificates".into());
    }
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_file(key_path)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tls)
}

async fn serve<S>(stream: S, router: Router, peer: SocketAddr)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = router.layer(Extension(ConnectInfo(peer))).into_service();
    let service = hyper_util::service::TowerToHyperService::new(service);
    let builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    let connection =
        builder.serve_connection_with_upgrades(hyper_util::rt::TokioIo::new(stream), service);
    if let Err(error) = connection.await {
        eprintln!("admin HTTP connection from {peer} failed: {error}");
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::parse();
    let (base, prefix) = validate(&config).map_err(std::io::Error::other)?;
    let control = reqwest::Client::builder()
        .unix_socket(config.socket.clone())
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let bind = config.bind;
    let limiter = Limiter::new(&config);
    let app = Arc::new(App {
        config,
        base,
        prefix: prefix.clone(),
        control,
        sessions: Mutex::new(HashMap::new()),
        limiter,
        history: Mutex::new(VecDeque::new()),
    });
    tokio::spawn(sampler(app.clone()));
    let routes = Router::new()
        .route("/", get(index))
        .route("/auth", get(auth_methods))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/csrf", get(csrf))
        .route("/history", get(history))
        .route("/api/{*route}", axum::routing::any(proxy));
    let router = if prefix.is_empty() {
        routes
    } else {
        Router::new().nest(&prefix, routes)
    }
    .layer(DefaultBodyLimit::max(1024 * 1024))
    .layer(middleware::from_fn_with_state(app.clone(), guard))
    .with_state(app.clone());
    let tls = match (&app.config.tls_cert, &app.config.tls_key) {
        (Some(cert), Some(key)) => Some(tokio_rustls::TlsAcceptor::from(Arc::new(
            load_tls_config(cert, key).map_err(|error| std::io::Error::other(error.to_string()))?,
        ))),
        _ => None,
    };
    let listener = tokio::net::TcpListener::bind(bind).await?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let router = router.clone();
        if let Some(acceptor) = tls.clone() {
            tokio::spawn(async move {
                match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
                    Ok(Ok(stream)) => serve(stream, router, peer).await,
                    Ok(Err(error)) => eprintln!("admin TLS handshake from {peer} failed: {error}"),
                    Err(_) => eprintln!("admin TLS handshake from {peer} timed out"),
                }
            });
        } else {
            tokio::spawn(serve(stream, router, peer));
        }
    }
}

const UI: &str = include_str!("charlotte-admin-ui.html");

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            bind: "127.0.0.1:8080".parse().unwrap(),
            base_url: "http://localhost:8080/admin".into(),
            socket: "/tmp/control.sock".into(),
            password: Some("secret".into()),
            tls_cert: None,
            tls_key: None,
            allow_ip: vec![],
            rate_limit: 600,
            login_rate_limit: 10,
            max_login_failures: 5,
            lockout_seconds: 900,
            sample_interval: 10,
            history: 3,
        }
    }
    fn app() -> Shared {
        app_with_limits(600, 10, 5, 900)
    }
    fn app_with_limits(
        rate_limit: u64,
        login_rate_limit: u64,
        max_login_failures: u64,
        lockout_seconds: u64,
    ) -> Shared {
        let mut config = config();
        config.rate_limit = rate_limit;
        config.login_rate_limit = login_rate_limit;
        config.max_login_failures = max_login_failures;
        config.lockout_seconds = lockout_seconds;
        let (base, prefix) = validate(&config).unwrap();
        let limiter = Limiter::new(&config);
        Arc::new(App {
            config,
            base,
            prefix,
            control: reqwest::Client::new(),
            sessions: Mutex::new(HashMap::new()),
            limiter,
            history: Mutex::new(VecDeque::new()),
        })
    }
    fn origin_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::ORIGIN, "http://localhost:8080".parse().unwrap());
        headers
    }
    fn session_headers(app: &App) -> HeaderMap {
        let issued = issue_session(app);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            issued.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .parse()
                .unwrap(),
        );
        headers
    }
    #[tokio::test]
    async fn password_lockout_blocks_correct_password_until_expiry() {
        let app = app_with_limits(0, 0, 2, 5);
        let ip = "192.0.2.10".parse().unwrap();
        let now = Instant::now();
        let headers = origin_headers();
        assert_eq!(
            login_at(
                &app,
                ip,
                headers.clone(),
                Login {
                    password: "wrong".into()
                },
                now,
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            login_at(
                &app,
                ip,
                headers.clone(),
                Login {
                    password: "wrong".into()
                },
                now + Duration::from_secs(1),
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let locked = login_at(
            &app,
            ip,
            headers.clone(),
            Login {
                password: "secret".into(),
            },
            now + Duration::from_secs(2),
        )
        .await;
        assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(locked.headers()[header::RETRY_AFTER], "4");
        let unlocked = login_at(
            &app,
            ip,
            headers,
            Login {
                password: "secret".into(),
            },
            now + Duration::from_secs(6),
        )
        .await;
        assert_eq!(unlocked.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn successful_login_resets_failed_attempt_count() {
        let app = app_with_limits(0, 0, 3, 10);
        let ip = "192.0.2.11".parse().unwrap();
        let now = Instant::now();
        for offset in [0, 1] {
            assert_eq!(
                login_at(
                    &app,
                    ip,
                    origin_headers(),
                    Login {
                        password: "wrong".into()
                    },
                    now + Duration::from_secs(offset),
                )
                .await
                .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            login_at(
                &app,
                ip,
                origin_headers(),
                Login {
                    password: "secret".into()
                },
                now + Duration::from_secs(2),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        for offset in [3, 4, 5] {
            assert_eq!(
                login_at(
                    &app,
                    ip,
                    origin_headers(),
                    Login {
                        password: "wrong".into()
                    },
                    now + Duration::from_secs(offset),
                )
                .await
                .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            login_at(
                &app,
                ip,
                origin_headers(),
                Login {
                    password: "secret".into()
                },
                now + Duration::from_secs(6),
            )
            .await
            .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[test]
    fn request_and_login_limits_are_per_ip_and_reset_after_a_minute() {
        let request_limiter = Limiter::new(&Config {
            rate_limit: 2,
            login_rate_limit: 0,
            max_login_failures: 0,
            ..config()
        });
        let first = "192.0.2.20".parse().unwrap();
        let second = "192.0.2.21".parse().unwrap();
        let now = Instant::now();
        assert_eq!(request_limiter.request(first, now), None);
        assert_eq!(request_limiter.request(first, now), None);
        assert_eq!(
            request_limiter.request(first, now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(request_limiter.request(second, now), None);
        assert_eq!(
            request_limiter.request(first, now + Duration::from_secs(60)),
            None
        );

        let login_limiter = Limiter::new(&Config {
            rate_limit: 0,
            login_rate_limit: 1,
            max_login_failures: 0,
            ..config()
        });
        assert_eq!(login_limiter.login_attempt(first, now), None);
        assert_eq!(
            login_limiter.login_attempt(first, now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(login_limiter.login_attempt(second, now), None);
        assert_eq!(
            login_limiter.login_attempt(first, now + Duration::from_secs(60)),
            None
        );
    }

    #[tokio::test]
    async fn history_is_bounded_and_requires_a_session() {
        let app = app();
        for time in 0..5 {
            record(&app, serde_json::json!({"time": time}));
        }
        let times: Vec<_> = app
            .history
            .lock()
            .unwrap()
            .iter()
            .map(|s| s["time"].clone())
            .collect();
        assert_eq!(times, [2, 3, 4]);
        let denied = history(State(app.clone()), HeaderMap::new()).await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let allowed = history(State(app.clone()), session_headers(&app)).await;
        assert_eq!(allowed.status(), StatusCode::OK);
    }
    #[test]
    fn configuration_fails_closed() {
        let mut c = config();
        assert!(validate(&c).is_ok());
        c.lockout_seconds = 0;
        assert!(validate(&c).is_err());
        c.lockout_seconds = 900;
        c.password = None;
        assert!(validate(&c).is_err());
        c.password = Some("secret".into());
        c.base_url = "http://example.com".into();
        assert!(validate(&c).is_err());
        c.base_url = "https://example.com/admin".into();
        assert!(validate(&c).is_ok());
        c.tls_cert = Some("cert.pem".into());
        assert!(validate(&c).is_err());
        c.tls_key = Some("key.pem".into());
        assert!(validate(&c).is_ok());
        c.base_url = "http://localhost:8080/admin".into();
        assert!(validate(&c).is_err());
        c.tls_cert = None;
        c.tls_key = None;
    }
    #[tokio::test]
    async fn sessions_require_origin_and_csrf_for_writes() {
        let app = app();
        let response = issue_session(&app);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .parse()
                .unwrap(),
        );
        assert!(authorized(&app, &headers, false));
        assert!(!authorized(&app, &headers, true));
        let token = session(&app, &headers).unwrap();
        headers.insert("x-csrf-token", token.parse().unwrap());
        headers.insert(header::ORIGIN, "http://evil.example".parse().unwrap());
        assert!(!authorized(&app, &headers, true));
        headers.insert(header::ORIGIN, "http://localhost:8080".parse().unwrap());
        assert!(authorized(&app, &headers, true));
        assert_eq!(
            logout(State(app.clone()), headers.clone()).await.status(),
            StatusCode::NO_CONTENT
        );
        assert!(!authorized(&app, &headers, false));
    }
    #[tokio::test]
    async fn bridge_forwards_authenticated_request_to_unix_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let socket = PathBuf::from(format!("admin-test-{}.sock", &random()[..12]));
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = [0; 4096];
            let n = stream.read(&mut data).await.unwrap();
            assert!(
                std::str::from_utf8(&data[..n])
                    .unwrap()
                    .starts_with("GET /status HTTP/1.1")
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await
                .unwrap();
        });
        let mut app = app();
        Arc::get_mut(&mut app).unwrap().control = reqwest::Client::builder()
            .unix_socket(socket.clone())
            .no_proxy()
            .build()
            .unwrap();
        let issued = issue_session(&app);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            issued.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .parse()
                .unwrap(),
        );
        let result = proxy(
            State(app),
            headers,
            Method::GET,
            Path("status".into()),
            Bytes::new(),
        )
        .await;
        assert_eq!(result.status(), StatusCode::OK);
        server.await.unwrap();
        std::fs::remove_file(socket).unwrap();
    }

    #[tokio::test]
    async fn tls_listener_serves_https_with_hsts() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let directory = std::env::temp_dir().join(format!("charlotte-admin-tls-{}", random()));
        std::fs::create_dir_all(&directory).unwrap();
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = directory.join("cert.pem");
        let key_path = directory.join("key.pem");
        std::fs::write(&cert_path, generated.cert.pem()).unwrap();
        std::fs::write(&key_path, generated.signing_key.serialize_pem()).unwrap();
        let tls = load_tls_config(&cert_path, &key_path).unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let mut app = app();
        let state = Arc::get_mut(&mut app).unwrap();
        state.config.tls_cert = Some(cert_path.clone());
        state.config.tls_key = Some(key_path.clone());
        let router = Router::new()
            .route("/", get(index))
            .route("/auth", get(auth_methods))
            .layer(middleware::from_fn_with_state(app.clone(), guard))
            .with_state(app.clone());
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            serve(stream, router, peer).await;
        });

        let mut roots = rustls::RootCertStore::empty();
        roots.add(generated.cert.der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let mut stream = connector.connect(server_name, stream).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(
            response
                .to_ascii_lowercase()
                .contains("strict-transport-security: max-age=31536000")
        );
        server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}
