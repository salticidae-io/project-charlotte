//! Standalone control-socket UI. Run `charlotte-admin --help` for configuration.
//! Terminate TLS at a trusted reverse proxy; this process serves HTTP only. The
//! proxy must strip external forwarding headers. IP checks always use the TCP
//! peer, never forwarding headers, so a proxy cannot convey client IPs here.
//! Sessions and OAuth attempts are in memory and disappear on restart.
//! Example: `CHARLOTTE_ADMIN_PASSWORD=... charlotte-admin --base-url
//! http://localhost:8080 --socket /run/charlotte/control.sock`. For Google,
//! register `<base-url>/oauth/callback` and configure the client ID, secret and
//! at least one `--google-email`. Protect the listener and control socket from
//! untrusted local users. There is no built-in login rate limiting or audit log.
//! Traffic graphs are built by sampling the control socket's `/status` counters
//! every `--sample-interval` seconds; the last `--history` samples are kept in
//! memory, so graph history starts empty whenever this process restarts.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::Parser;
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::Deserialize;
use url::Url;

#[derive(Parser)]
#[command(about = "Web administration for a Charlotte control socket")]
struct Config {
    #[arg(long, default_value = "127.0.0.1:8080")]
    bind: SocketAddr,
    /// Public URL, including any path prefix; HTTPS required except on loopback.
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
    #[arg(long, env = "CHARLOTTE_GOOGLE_CLIENT_ID")]
    google_client_id: Option<String>,
    #[arg(long, env = "CHARLOTTE_GOOGLE_CLIENT_SECRET", hide_env_values = true)]
    google_client_secret: Option<String>,
    /// Allowed Google email address; repeat for multiple users.
    #[arg(long)]
    google_email: Vec<String>,
    /// Allowed TCP peer IP address; repeat for multiple addresses. Default: loopback only.
    #[arg(long)]
    allow_ip: Vec<IpAddr>,
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
struct Attempt {
    browser: String,
    expires: Instant,
}
struct App {
    config: Config,
    base: Url,
    prefix: String,
    control: reqwest::Client,
    google: reqwest::Client,
    sessions: Mutex<HashMap<String, Session>>,
    attempts: Mutex<HashMap<String, Attempt>>,
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
fn path(app: &App, suffix: &str) -> String {
    format!("{}{}", app.prefix, suffix)
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
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    h.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    h.insert(header::CONTENT_SECURITY_POLICY, "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'".parse().unwrap());
    h.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    response
}

async fn index() -> Html<&'static str> {
    Html(UI)
}
#[derive(Deserialize)]
struct Login {
    password: String,
}
async fn login(
    State(app): State<Shared>,
    headers: HeaderMap,
    Json(login): Json<Login>,
) -> Response {
    if !valid_origin(&headers, &app) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if app
        .config
        .password
        .as_ref()
        .is_some_and(|p| equal(p, &login.password))
    {
        issue_session(&app)
    } else {
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

async fn oauth_start(State(app): State<Shared>) -> Response {
    let Some(client) = &app.config.google_client_id else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let state = random();
    let browser = random();
    let mut attempts = app.attempts.lock().unwrap();
    attempts.retain(|_, a| a.expires > Instant::now());
    if attempts.len() >= 1024 {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    attempts.insert(
        state.clone(),
        Attempt {
            browser: browser.clone(),
            expires: Instant::now() + Duration::from_secs(300),
        },
    );
    let mut url = Url::parse("https://accounts.google.com/o/oauth2/v2/auth").unwrap();
    url.query_pairs_mut()
        .append_pair("client_id", client)
        .append_pair(
            "redirect_uri",
            &format!("{}{}", origin(&app), path(&app, "/oauth/callback")),
        )
        .append_pair("response_type", "code")
        .append_pair("scope", "openid email")
        .append_pair("state", &state);
    let mut response = Redirect::to(url.as_str()).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        cookie_value(&app, "charlotte_oauth", &browser, 300)
            .parse()
            .unwrap(),
    );
    response
}
#[derive(Deserialize)]
struct Callback {
    state: String,
    code: String,
}
#[derive(Deserialize)]
struct Token {
    access_token: String,
}
#[derive(Deserialize)]
struct Identity {
    email: String,
    email_verified: bool,
    sub: String,
}
async fn oauth_callback(
    State(app): State<Shared>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<Callback>,
) -> Response {
    let attempt = app.attempts.lock().unwrap().remove(&query.state);
    if !attempt.is_some_and(|a| {
        a.expires > Instant::now()
            && cookie(&headers, "charlotte_oauth").is_some_and(|v| equal(&v, &a.browser))
    }) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let (Some(client), Some(secret)) = (
        &app.config.google_client_id,
        &app.config.google_client_secret,
    ) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let redirect = format!("{}{}", origin(&app), path(&app, "/oauth/callback"));
    let token = app
        .google
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", query.code.as_str()),
            ("client_id", client),
            ("client_secret", secret),
            ("redirect_uri", &redirect),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await;
    let Ok(token) = token else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let Ok(token) = token.error_for_status() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(token) = token.json::<Token>().await else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let identity = app
        .google
        .get("https://openidconnect.googleapis.com/v1/userinfo")
        .bearer_auth(token.access_token)
        .send()
        .await;
    let Ok(identity) = identity else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let Ok(identity) = identity.error_for_status() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(identity) = identity.json::<Identity>().await else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    if !identity.email_verified
        || identity.sub.is_empty()
        || !app
            .config
            .google_email
            .iter()
            .any(|e| e.eq_ignore_ascii_case(&identity.email))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let session = issue_session(&app);
    if session.status() != StatusCode::NO_CONTENT {
        return session;
    }
    let mut response = Redirect::to(&path(&app, "/")).into_response();
    if let Some(cookie) = session.headers().get(header::SET_COOKIE) {
        response
            .headers_mut()
            .append(header::SET_COOKIE, cookie.clone());
    }
    response.headers_mut().append(
        header::SET_COOKIE,
        cookie_value(&app, "charlotte_oauth", "", 0)
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
    let google = config.google_client_id.is_some()
        && config.google_client_secret.is_some()
        && !config.google_email.is_empty();
    if (config.google_client_id.is_some()
        || config.google_client_secret.is_some()
        || !config.google_email.is_empty())
        && !google
    {
        return Err("Google login requires client ID, secret and an email allowlist".into());
    }
    if config.password.is_none() && !google {
        return Err("configure at least one authentication method".into());
    }
    Ok((base, prefix))
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
    let google = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let bind = config.bind;
    let app = Arc::new(App {
        config,
        base,
        prefix: prefix.clone(),
        control,
        google,
        sessions: Mutex::new(HashMap::new()),
        attempts: Mutex::new(HashMap::new()),
        history: Mutex::new(VecDeque::new()),
    });
    tokio::spawn(sampler(app.clone()));
    let routes = Router::new()
        .route("/", get(index))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/csrf", get(csrf))
        .route("/history", get(history))
        .route("/oauth/start", get(oauth_start))
        .route("/oauth/callback", get(oauth_callback))
        .route("/api/{*route}", axum::routing::any(proxy));
    let router = if prefix.is_empty() {
        routes
    } else {
        Router::new().nest(&prefix, routes)
    }
    .layer(DefaultBodyLimit::max(1024 * 1024))
    .layer(middleware::from_fn_with_state(app.clone(), guard))
    .with_state(app);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

const UI: &str = r#"<!doctype html><meta charset="utf-8"><title>Charlotte admin</title>
<h1>Charlotte admin</h1><div id="login"><input id="password" type="password" placeholder="Password"><button onclick="login()">Sign in</button> <a id="google" href="oauth/start">Sign in with Google</a></div>
<style>body{font-family:sans-serif;margin:1em 2em}canvas{border:1px solid #ddd;display:block;margin:.3em 0 1em;max-width:100%}.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(460px,1fr));gap:0 2em}h3{margin:.2em 0}</style>
<div id="admin" hidden><button onclick="load()">Refresh</button> <button onclick="logout()">Sign out</button>
<h2>Server traffic</h2><div class="charts"><div><h3>Requests</h3><canvas id="serverRequests" width="560" height="200"></canvas></div><div><h3>Bandwidth</h3><canvas id="serverBytes" width="560" height="200"></canvas></div></div>
<h2>Virtual host traffic <select id="vhost" onchange="draw()"></select></h2><div class="charts"><div><h3>Requests</h3><canvas id="vhostRequests" width="560" height="200"></canvas></div><div><h3>Bandwidth</h3><canvas id="vhostBytes" width="560" height="200"></canvas></div></div>
<h2>Status</h2><pre id="status"></pre><h2>Virtual hosts</h2><pre id="hosts"></pre><input id="name" placeholder="Host name"><button onclick="readHost()">Get</button><button onclick="save('POST')">Create</button><button onclick="save('PUT')">Replace</button><button onclick="save('DELETE')">Delete</button><p><textarea id="config" rows="18" cols="80" placeholder="YAML or JSON configuration"></textarea></p></div><pre id="message"></pre>
<script>
let token=''; let samples=[]; let timer=null; const $=id=>document.getElementById(id); const root=location.pathname.replace(/\/$/,'')+'/'; $('google').href=root+'oauth/start';
async function request(url,options={}) { let r=await fetch(root+url,options); let text=await r.text(); if(!r.ok) throw Error(r.status+' '+text); return text; }
function show(e){$('message').textContent=String(e)}
const KEYS=['requests','client_errors','server_errors','bytes_in','bytes_out'];
const REQUESTS=[{key:'requests',label:'requests',color:'#1f6feb'},{key:'client_errors',label:'4xx',color:'#d29922'},{key:'server_errors',label:'5xx',color:'#cf222e'}];
const BYTES=[{key:'bytes_in',label:'in',color:'#2da44e'},{key:'bytes_out',label:'out',color:'#8250df'}];
function rates(pick){let out=[];for(let i=1;i<samples.length;i++){const a=samples[i-1],b=samples[i],dt=b.time-a.time,cur=pick(b);if(!cur||dt<=0)continue;const reset=b.uptime_seconds<a.uptime_seconds,prev=reset?{}:(pick(a)||{});const r={t:b.time};for(const k of KEYS)r[k]=Math.max(0,(cur[k]||0)-(prev[k]||0))/dt;out.push(r)}return out}
function fmt(v,bytes){const u=bytes?['B/s','KiB/s','MiB/s','GiB/s']:['req/s'];let i=0;if(bytes)while(v>=1024&&i<3){v/=1024;i++}return v.toFixed(v<10?2:0)+' '+u[i]}
function chart(id,data,series,bytes){const c=$(id),g=c.getContext('2d'),W=c.width,H=c.height,L=70,B=18,T=18;g.clearRect(0,0,W,H);g.font='11px sans-serif';let max=0;for(const d of data)for(const s of series)max=Math.max(max,d[s.key]);max=max||1;g.strokeStyle='#bbb';g.beginPath();g.moveTo(L,T);g.lineTo(L,H-B);g.lineTo(W,H-B);g.stroke();g.fillStyle='#444';g.fillText(fmt(max,bytes),2,T+8);g.fillText(fmt(0,bytes),2,H-B);series.forEach((s,i)=>{g.fillStyle=s.color;g.fillText('\u25A0 '+s.label,L+8+i*80,12)});if(data.length<2){g.fillStyle='#888';g.fillText('Collecting samples\u2026',L+10,H/2);return}const t0=data[0].t,t1=data[data.length-1].t,x=t=>L+(t-t0)/(t1-t0)*(W-L-4),y=v=>(H-B)-v/max*(H-B-T);g.fillStyle='#444';g.fillText(new Date(t0*1000).toLocaleTimeString(),L,H-4);const e=new Date(t1*1000).toLocaleTimeString();g.fillText(e,W-g.measureText(e).width-2,H-4);for(const s of series){g.strokeStyle=s.color;g.lineWidth=1.5;g.beginPath();data.forEach((d,j)=>j?g.lineTo(x(d.t),y(d[s.key])):g.moveTo(x(d.t),y(d[s.key])));g.stroke()}}
function draw(){const server=rates(s=>s.traffic.total);chart('serverRequests',server,REQUESTS,false);chart('serverBytes',server,BYTES,true);const sel=$('vhost'),names=samples.length?Object.keys(samples[samples.length-1].traffic.vhosts).sort():[],current=sel.value;if(names.join('\n')!==Array.from(sel.options,o=>o.value).join('\n')){sel.replaceChildren(...names.map(n=>{const o=document.createElement('option');o.value=n;o.textContent=n;return o}));if(names.includes(current))sel.value=current}const name=sel.value,vhost=name?rates(s=>s.traffic.vhosts[name]):[];chart('vhostRequests',vhost,REQUESTS,false);chart('vhostBytes',vhost,BYTES,true)}
async function graphs(){try{const h=JSON.parse(await request('history'));samples=h.samples;draw();clearTimeout(timer);timer=setTimeout(graphs,h.interval*1000)}catch(e){show(e)}}
async function refresh(){try { token=JSON.parse(await request('csrf')).csrf; $('login').hidden=true; $('admin').hidden=false; await load(); await graphs(); } catch(e){clearTimeout(timer); $('login').hidden=false; $('admin').hidden=true;} }
async function login(){try{await request('login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:$('password').value})}); $('password').value=''; show(''); await refresh()}catch(e){show(e)}}
async function load(){try{$('status').textContent=await request('api/status'); $('hosts').textContent=await request('api/vhosts')}catch(e){show(e)}}
function host(){return 'api/vhosts/'+encodeURIComponent($('name').value)}
async function readHost(){try{$('config').value=await request(host())}catch(e){show(e)}}
async function save(method){try{if(method==='DELETE'&&!confirm('Delete this host?'))return; $('message').textContent=await request(host(),{method,headers:{'X-CSRF-Token':token},body:method==='DELETE'?undefined:$('config').value}); await load()}catch(e){show(e)}}
async function logout(){try{await request('logout',{method:'POST',headers:{'X-CSRF-Token':token}}); await refresh()}catch(e){show(e)}} refresh();
</script>"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            bind: "127.0.0.1:8080".parse().unwrap(),
            base_url: "http://localhost:8080/admin".into(),
            socket: "/tmp/control.sock".into(),
            password: Some("secret".into()),
            google_client_id: None,
            google_client_secret: None,
            google_email: vec![],
            allow_ip: vec![],
            sample_interval: 10,
            history: 3,
        }
    }
    fn app() -> Shared {
        let config = config();
        let (base, prefix) = validate(&config).unwrap();
        Arc::new(App {
            config,
            base,
            prefix,
            control: reqwest::Client::new(),
            google: reqwest::Client::new(),
            sessions: Mutex::new(HashMap::new()),
            attempts: Mutex::new(HashMap::new()),
            history: Mutex::new(VecDeque::new()),
        })
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
        c.password = None;
        assert!(validate(&c).is_err());
        c.google_client_id = Some("id".into());
        assert!(validate(&c).is_err());
        c.password = Some("secret".into());
        c.google_client_id = None;
        c.base_url = "http://example.com".into();
        assert!(validate(&c).is_err());
        c.base_url = "https://example.com/admin".into();
        assert!(validate(&c).is_ok());
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
    async fn oauth_state_is_browser_bound_and_one_use() {
        let app = app();
        app.attempts.lock().unwrap().insert(
            "state".into(),
            Attempt {
                browser: "browser".into(),
                expires: Instant::now() + Duration::from_secs(30),
            },
        );
        let result = oauth_callback(
            State(app.clone()),
            HeaderMap::new(),
            axum::extract::Query(Callback {
                state: "state".into(),
                code: "code".into(),
            }),
        )
        .await;
        assert_eq!(result.status(), StatusCode::FORBIDDEN);
        assert!(app.attempts.lock().unwrap().is_empty());
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
}
