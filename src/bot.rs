//! Bot scoring, crawler verification, and challenge or block responses.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use http::{HeaderMap, Request, StatusCode, header};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::{forwarded::TrustedProxy, ja4::ClientHelloInfo};

const CACHE_SHARDS: usize = 16;
const CACHE_CAPACITY: usize = 256;
pub(crate) const CHALLENGE_PATH: &str = "/.well-known/charlotte-bot-challenge";
const BOT_COOKIE: &str = "charlotte_bot";
const SHA256_JS: &str = r#"const sha256K=[],sha256H=[];function sha256(input){if(!sha256K.length){const marked={};for(let candidate=2,n=0;n<64;candidate++){if(!marked[candidate]){for(let multiple=candidate*candidate;multiple<313;multiple+=candidate)marked[multiple]=true;if(n<8)sha256H[n]=(Math.sqrt(candidate)%1*4294967296)|0;sha256K[n]=(Math.pow(candidate,1/3)%1*4294967296)|0;n++}}}const bitLength=input.length*8;input+='\x80';while(input.length%64!==56)input+='\x00';const words=[];for(let i=0;i<input.length;i++)words[i>>2]=(words[i>>2]||0)|(input.charCodeAt(i)<<(24-(i%4)*8));words.push((bitLength/4294967296)|0,bitLength|0);const hash=sha256H.slice(),rotate=(x,n)=>(x>>>n)|(x<<(32-n));for(let offset=0;offset<words.length;offset+=16){const schedule=words.slice(offset,offset+16);for(let i=16;i<64;i++){const x=schedule[i-15],y=schedule[i-2],s0=rotate(x,7)^rotate(x,18)^(x>>>3),s1=rotate(y,17)^rotate(y,19)^(y>>>10);schedule[i]=(schedule[i-16]+s0+schedule[i-7]+s1)|0}let[a,b,c,d,e,f,g,h]=hash;for(let i=0;i<64;i++){const s1=rotate(e,6)^rotate(e,11)^rotate(e,25),choice=(e&f)^(~e&g),t1=(h+s1+choice+sha256K[i]+schedule[i])|0,s0=rotate(a,2)^rotate(a,13)^rotate(a,22),majority=(a&b)^(a&c)^(b&c),t2=(s0+majority)|0;h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0}hash[0]=(hash[0]+a)|0;hash[1]=(hash[1]+b)|0;hash[2]=(hash[2]+c)|0;hash[3]=(hash[3]+d)|0;hash[4]=(hash[4]+e)|0;hash[5]=(hash[5]+f)|0;hash[6]=(hash[6]+g)|0;hash[7]=(hash[7]+h)|0}return hash.map(value=>(value>>>0).toString(16).padStart(8,'0')).join('')}"#;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum BotMode {
    #[default]
    Enforce,
    Log,
    Off,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BotPolicyFile {
    #[serde(default)]
    pub(crate) mode: BotMode,
    #[serde(default = "default_challenge_threshold")]
    challenge_threshold: u32,
    #[serde(default = "default_block_threshold")]
    block_threshold: u32,
    #[serde(default = "default_true")]
    challenge: bool,
    #[serde(default = "default_difficulty")]
    challenge_difficulty: u8,
    #[serde(default = "default_challenge_ttl")]
    challenge_ttl: u64,
    #[serde(default)]
    allow_ips: Vec<String>,
    #[serde(default)]
    deny_ips: Vec<String>,
    #[serde(default)]
    allow_user_agents: Vec<String>,
    #[serde(default)]
    deny_user_agents: Vec<String>,
    #[serde(default = "default_true")]
    builtin_rules: bool,
    #[serde(default)]
    honeypot_paths: Vec<String>,
    #[serde(default = "default_ban_ttl")]
    honeypot_ban: u64,
    #[serde(default)]
    exempt_paths: Vec<String>,
    #[serde(default = "default_true")]
    verify_crawlers: bool,
    #[serde(default)]
    ja4_allow: Vec<String>,
    #[serde(default)]
    ja4_deny: Vec<String>,
}

impl Default for BotPolicyFile {
    fn default() -> Self {
        Self {
            mode: BotMode::Enforce,
            challenge_threshold: default_challenge_threshold(),
            block_threshold: default_block_threshold(),
            challenge: true,
            challenge_difficulty: default_difficulty(),
            challenge_ttl: default_challenge_ttl(),
            allow_ips: Vec::new(),
            deny_ips: Vec::new(),
            allow_user_agents: Vec::new(),
            deny_user_agents: Vec::new(),
            builtin_rules: true,
            honeypot_paths: Vec::new(),
            honeypot_ban: default_ban_ttl(),
            exempt_paths: Vec::new(),
            verify_crawlers: true,
            ja4_allow: Vec::new(),
            ja4_deny: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

const fn default_challenge_threshold() -> u32 {
    40
}

const fn default_block_threshold() -> u32 {
    80
}

const fn default_difficulty() -> u8 {
    16
}

const fn default_challenge_ttl() -> u64 {
    3600
}

const fn default_ban_ttl() -> u64 {
    3600
}

#[derive(Clone, Debug)]
pub(crate) struct BotPolicy {
    mode: BotMode,
    challenge_threshold: u32,
    block_threshold: u32,
    challenge: bool,
    challenge_difficulty: u8,
    challenge_ttl: u64,
    allow_ips: Vec<TrustedProxy>,
    deny_ips: Vec<TrustedProxy>,
    allow_user_agents: Vec<String>,
    deny_user_agents: Vec<String>,
    builtin_rules: bool,
    honeypot_paths: Vec<String>,
    honeypot_ban: u64,
    exempt_paths: Vec<String>,
    verify_crawlers: bool,
    ja4_allow: Vec<String>,
    ja4_deny: Vec<String>,
}

impl BotPolicy {
    pub(crate) fn parse(file: BotPolicyFile) -> Result<Self, String> {
        if file.challenge_threshold > file.block_threshold {
            return Err("bot challenge_threshold must not exceed block_threshold".to_owned());
        }
        if file.challenge_threshold == 0 || file.block_threshold > 100 {
            return Err("bot thresholds must be between 1 and 100".to_owned());
        }
        if file.challenge_difficulty > 24 {
            return Err("bot challenge_difficulty must be between 0 and 24".to_owned());
        }
        if file.challenge_ttl == 0
            || file.challenge_ttl > 7 * 24 * 3600
            || file.honeypot_ban == 0
            || file.honeypot_ban > 30 * 24 * 3600
        {
            return Err(
                "bot challenge_ttl must be at most 7 days and honeypot_ban at most 30 days"
                    .to_owned(),
            );
        }
        if file
            .allow_user_agents
            .iter()
            .chain(&file.deny_user_agents)
            .any(String::is_empty)
        {
            return Err("bot user-agent patterns must not be empty".to_owned());
        }
        let parse_ips = |values: Vec<String>| {
            values
                .iter()
                .map(|value| {
                    TrustedProxy::from_str(value)
                        .map_err(|_| format!("invalid bot IP address or CIDR: {value}"))
                })
                .collect::<Result<Vec<_>, _>>()
        };
        for path in file.honeypot_paths.iter().chain(&file.exempt_paths) {
            if !path.starts_with('/') || path.starts_with("//") || path.starts_with("/\\") {
                return Err(format!("bot paths must be local absolute paths: {path}"));
            }
        }
        Ok(Self {
            mode: file.mode,
            challenge_threshold: file.challenge_threshold,
            block_threshold: file.block_threshold,
            challenge: file.challenge,
            challenge_difficulty: file.challenge_difficulty,
            challenge_ttl: file.challenge_ttl,
            allow_ips: parse_ips(file.allow_ips)?,
            deny_ips: parse_ips(file.deny_ips)?,
            allow_user_agents: normalize_patterns(file.allow_user_agents),
            deny_user_agents: normalize_patterns(file.deny_user_agents),
            builtin_rules: file.builtin_rules,
            honeypot_paths: file.honeypot_paths,
            honeypot_ban: file.honeypot_ban,
            exempt_paths: file.exempt_paths,
            verify_crawlers: file.verify_crawlers,
            ja4_allow: file.ja4_allow,
            ja4_deny: file.ja4_deny,
        })
    }

    #[cfg(test)]
    pub(crate) fn default_enforcing() -> Self {
        Self::parse(BotPolicyFile::default()).expect("default bot policy is valid")
    }

    pub(crate) fn challenge_parameters(&self) -> (u8, u64) {
        (self.challenge_difficulty, self.challenge_ttl)
    }
}

fn normalize_patterns(patterns: Vec<String>) -> Vec<String> {
    patterns
        .into_iter()
        .map(|pattern| pattern.to_ascii_lowercase())
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CrawlerCheck {
    Verified,
    Impostor,
    Error,
}

struct TtlEntry<T> {
    expires: Instant,
    value: T,
}

pub(crate) struct BotState {
    key: hmac::Key,
    bans: Vec<Mutex<HashMap<IpAddr, TtlEntry<()>>>>,
    crawlers: Vec<Mutex<HashMap<(IpAddr, &'static str), TtlEntry<CrawlerCheck>>>>,
    crawler_dns_slots: Arc<Semaphore>,
}

impl BotState {
    pub(crate) fn new() -> Result<Arc<Self>, String> {
        let mut key = [0_u8; 32];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| "could not initialize bot challenge signing key".to_owned())?;
        Ok(Arc::new(Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, &key),
            bans: (0..CACHE_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            crawlers: (0..CACHE_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            crawler_dns_slots: Arc::new(Semaphore::new(16)),
        }))
    }

    fn shard(&self, ip: IpAddr) -> usize {
        match ip {
            IpAddr::V4(ip) => usize::from(ip.octets()[3]) % CACHE_SHARDS,
            IpAddr::V6(ip) => usize::from(ip.octets()[15]) % CACHE_SHARDS,
        }
    }

    fn banned(&self, ip: IpAddr, now: Instant) -> bool {
        let mut bans = self.bans[self.shard(ip)]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        bans.retain(|_, entry| entry.expires > now);
        bans.contains_key(&ip)
    }

    fn ban(&self, ip: IpAddr, ttl: Duration, now: Instant) {
        let mut bans = self.bans[self.shard(ip)]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        bans.retain(|_, entry| entry.expires > now);
        if bans.len() >= CACHE_CAPACITY {
            if let Some(key) = bans.keys().next().copied() {
                bans.remove(&key);
            }
        }
        bans.insert(
            ip,
            TtlEntry {
                expires: now + ttl,
                value: (),
            },
        );
    }

    async fn crawler_check(&self, ip: IpAddr, suffix: &'static str) -> CrawlerCheck {
        let shard = self.shard(ip);
        let key = (ip, suffix);
        let now = Instant::now();
        {
            let mut cache = self.crawlers[shard]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cache.retain(|_, entry| entry.expires > now);
            if let Some(entry) = cache.get(&key) {
                return entry.value;
            }
        }

        let lookup = tokio::time::timeout(Duration::from_secs(2), async {
            let permit = Arc::clone(&self.crawler_dns_slots)
                .try_acquire_owned()
                .ok()?;
            let reverse_ip = ip;
            let (hostname, _permit) =
                tokio::task::spawn_blocking(move || (dns_lookup::lookup_addr(&reverse_ip), permit))
                    .await
                    .ok()?;
            let hostname = hostname.ok()?;
            let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
            if !hostname.ends_with(suffix) {
                return Some(false);
            }
            let mut addresses = tokio::net::lookup_host((hostname.as_str(), 80))
                .await
                .ok()?;
            Some(addresses.any(|address| address.ip() == ip))
        })
        .await;
        let check = match lookup {
            Ok(Some(true)) => CrawlerCheck::Verified,
            Ok(Some(false)) => CrawlerCheck::Impostor,
            Ok(None) | Err(_) => CrawlerCheck::Error,
        };
        let ttl = if check == CrawlerCheck::Error {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(3600)
        };
        let mut cache = self.crawlers[shard]
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.retain(|_, entry| entry.expires > now);
        if cache.len() >= CACHE_CAPACITY {
            if let Some(key) = cache.keys().next().copied() {
                cache.remove(&key);
            }
        }
        cache.insert(
            key,
            TtlEntry {
                expires: now + ttl,
                value: check,
            },
        );
        check
    }

    fn signature(&self, data: &[u8]) -> String {
        hex_encode(hmac::sign(&self.key, data).as_ref())
    }

    fn expected_seed(&self, client: IpAddr, expires: u64) -> String {
        self.signature(format!("challenge:{}:{expires}", client_prefix(client)).as_bytes())
    }

    fn cookie_value(&self, client: IpAddr, expires: u64) -> String {
        self.signature(format!("cookie:{}:{expires}", client_prefix(client)).as_bytes())
    }

    pub(crate) fn has_valid_cookie(&self, headers: &HeaderMap, client: IpAddr) -> bool {
        let now = unix_time();
        headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|cookie| cookie.trim().strip_prefix(&format!("{BOT_COOKIE}=")))
            .any(|value| {
                let Some((expires, signature)) = value.split_once('.') else {
                    return false;
                };
                let Ok(expires) = expires.parse::<u64>() else {
                    return false;
                };
                expires >= now
                    && expires <= now.saturating_add(7 * 24 * 3600)
                    && constant_time_eq(signature, &self.cookie_value(client, expires))
            })
    }

    pub(crate) fn challenge<B>(
        &self,
        request: &Request<B>,
        client: SocketAddr,
        difficulty: u8,
        ttl: u64,
    ) -> ResponseParts {
        let expires = unix_time().saturating_add(ttl);
        let seed = self.expected_seed(client.ip(), expires);
        let return_path = request
            .uri()
            .path_and_query()
            .map_or("/", |value| value.as_str());
        let escaped_path = javascript_string(return_path);
        let html = format!(
            "<!doctype html><meta charset=utf-8><title>Checking your browser</title><p>Checking your browser before accessing this site.</p><script>{SHA256_JS};(()=>{{const seed='{seed}',exp={expires},difficulty={difficulty},ret=encodeURIComponent('{escaped_path}');for(let n=0;;n++){{const h=sha256(seed+n);let z=0;for(const c of h){{const value=parseInt(c,16);if(value===0)z+=4;else{{for(let mask=8;mask>value;mask>>=1)z++;break}}if(z>=difficulty)break}}if(z>=difficulty){{location.href='{CHALLENGE_PATH}?exp='+exp+'&seed='+seed+'&nonce='+n+'&return='+ret;return}}}}}})()</script>"
        );
        ResponseParts {
            status: StatusCode::FORBIDDEN,
            body: html,
            content_type: "text/html; charset=utf-8",
            location: None,
            set_cookie: None,
        }
    }

    pub(crate) fn solve_challenge<B>(
        &self,
        request: &Request<B>,
        client: SocketAddr,
        tls: bool,
        difficulty: u8,
        ttl: u64,
    ) -> ResponseParts {
        let query = request.uri().query().unwrap_or_default();
        let params = query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .map(|(key, value)| (key, value))
            .collect::<HashMap<_, _>>();
        let Some(exp) = params
            .get("exp")
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return forbidden_challenge();
        };
        let Some(seed) = params.get("seed") else {
            return forbidden_challenge();
        };
        let Some(nonce) = params.get("nonce") else {
            return forbidden_challenge();
        };
        let Some(return_path) = params.get("return").and_then(|value| percent_decode(value)) else {
            return forbidden_challenge();
        };
        if exp < unix_time()
            || exp > unix_time().saturating_add(ttl)
            || !constant_time_eq(seed, &self.expected_seed(client.ip(), exp))
            || !safe_return_path(&return_path)
            || !verify_pow(seed, nonce, difficulty)
        {
            return forbidden_challenge();
        }
        let cookie_exp = unix_time().saturating_add(7 * 24 * 3600);
        let cookie = format!(
            "{BOT_COOKIE}={cookie_exp}.{}; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax{}",
            self.cookie_value(client.ip(), cookie_exp),
            if tls { "; Secure" } else { "" }
        );
        ResponseParts {
            status: StatusCode::SEE_OTHER,
            body: String::new(),
            content_type: "text/plain; charset=utf-8",
            location: Some(return_path),
            set_cookie: Some(cookie),
        }
    }
}

pub(crate) struct ResponseParts {
    pub(crate) status: StatusCode,
    pub(crate) body: String,
    pub(crate) content_type: &'static str,
    pub(crate) location: Option<String>,
    pub(crate) set_cookie: Option<String>,
}

fn forbidden_challenge() -> ResponseParts {
    ResponseParts {
        status: StatusCode::FORBIDDEN,
        body: "Invalid bot challenge".to_owned(),
        content_type: "text/plain; charset=utf-8",
        location: None,
        set_cookie: None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BotAction {
    Allow,
    Log,
    Challenge,
    Block,
}

#[derive(Debug)]
pub(crate) struct Verdict {
    pub(crate) score: u32,
    pub(crate) reasons: Vec<&'static str>,
    pub(crate) action: BotAction,
}

pub(crate) async fn evaluate<B>(
    policy: &BotPolicy,
    state: &BotState,
    request: &Request<B>,
    client: SocketAddr,
    fingerprint: Option<&ClientHelloInfo>,
) -> Verdict {
    let path = request.uri().path();
    if policy.mode == BotMode::Off
        || policy
            .exempt_paths
            .iter()
            .any(|prefix| path.starts_with(prefix))
        || policy
            .allow_ips
            .iter()
            .any(|range| range.contains(client.ip()))
    {
        return verdict(0, Vec::new(), BotAction::Allow);
    }

    let now = Instant::now();
    if state.banned(client.ip(), now) {
        return verdict(
            100,
            vec!["honeypot ban"],
            if policy.mode == BotMode::Log {
                BotAction::Log
            } else {
                BotAction::Block
            },
        );
    }
    if policy
        .honeypot_paths
        .iter()
        .any(|honeypot| path == honeypot)
    {
        state.ban(client.ip(), Duration::from_secs(policy.honeypot_ban), now);
        return verdict(
            100,
            vec!["honeypot path"],
            if policy.mode == BotMode::Log {
                BotAction::Log
            } else {
                BotAction::Block
            },
        );
    }

    let user_agent = request
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let ua = user_agent.to_ascii_lowercase();
    let mut score = 0;
    let mut reasons = Vec::new();
    let fingerprint_denied = fingerprint.is_some_and(|fingerprint| {
        policy
            .ja4_deny
            .iter()
            .any(|value| value == &fingerprint.ja4)
    });
    let explicitly_denied = policy
        .deny_ips
        .iter()
        .any(|range| range.contains(client.ip()))
        || policy
            .deny_user_agents
            .iter()
            .any(|pattern| ua.contains(pattern));
    if explicitly_denied || fingerprint_denied {
        add_score(&mut score, &mut reasons, 100, "explicit deny rule");
    }
    if !explicitly_denied
        && !fingerprint_denied
        && policy
            .allow_user_agents
            .iter()
            .any(|pattern| ua.contains(pattern))
    {
        return verdict(0, Vec::new(), BotAction::Allow);
    }

    if policy.builtin_rules {
        if ua.is_empty() {
            add_score(&mut score, &mut reasons, 50, "empty user-agent");
        }
        const SCANNERS: &[&str] = &[
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "zgrab",
            "nuclei",
            "wpscan",
            "acunetix",
            "nessus",
            "openvas",
            "dirbuster",
            "gobuster",
            "ffuf",
        ];
        const AUTOMATION: &[&str] = &[
            "curl",
            "wget",
            "python-requests",
            "python-urllib",
            "go-http-client",
            "okhttp",
            "java/",
            "libwww-perl",
            "scrapy",
            "aiohttp",
            "axios",
            "node-fetch",
            "httpclient",
            "headlesschrome",
            "phantomjs",
        ];
        if SCANNERS.iter().any(|pattern| ua.contains(pattern)) {
            add_score(&mut score, &mut reasons, 100, "scanner user-agent");
        } else if AUTOMATION.iter().any(|pattern| ua.contains(pattern)) {
            add_score(&mut score, &mut reasons, 50, "automation user-agent");
        }
        if is_browser(&ua) {
            if request.version() == http::Version::HTTP_10 {
                add_score(&mut score, &mut reasons, 30, "browser claims HTTP/1.0");
            }
            if !request.headers().contains_key(header::ACCEPT) {
                add_score(&mut score, &mut reasons, 20, "browser missing Accept");
            }
            if !request.headers().contains_key(header::ACCEPT_LANGUAGE) {
                add_score(
                    &mut score,
                    &mut reasons,
                    20,
                    "browser missing Accept-Language",
                );
            }
            if request.extensions().get::<crate::vhost::TlsSni>().is_some()
                && !request.headers().contains_key("sec-fetch-mode")
            {
                add_score(
                    &mut score,
                    &mut reasons,
                    15,
                    "browser missing Sec-Fetch-Mode",
                );
            }
        }
    }

    if let Some(fingerprint) = fingerprint {
        if !explicitly_denied
            && !fingerprint_denied
            && policy
                .ja4_allow
                .iter()
                .any(|value| value == &fingerprint.ja4)
        {
            return verdict(score, reasons, BotAction::Allow);
        }
        if is_browser(&ua) {
            if !fingerprint
                .alpn
                .iter()
                .any(|protocol| protocol == "h2" || protocol == "http/1.1")
            {
                add_score(
                    &mut score,
                    &mut reasons,
                    30,
                    "browser JA4 lacks browser ALPN",
                );
            }
            if fingerprint.max_version < 0x0304 {
                add_score(&mut score, &mut reasons, 30, "browser negotiated old TLS");
            }
            if ua.contains("chrome") || ua.contains("chromium") || ua.contains("edg/") {
                if !fingerprint.grease {
                    add_score(&mut score, &mut reasons, 40, "Chromium JA4 lacks GREASE");
                }
            }
        }
    }

    if policy.verify_crawlers
        && let Some(suffix) = claimed_crawler_suffix(&ua)
    {
        match state.crawler_check(client.ip(), suffix).await {
            CrawlerCheck::Verified if !explicitly_denied && !fingerprint_denied => {
                return verdict(score, reasons, BotAction::Allow);
            }
            CrawlerCheck::Verified => {}
            CrawlerCheck::Impostor => {
                add_score(
                    &mut score,
                    &mut reasons,
                    100,
                    "unverified crawler user-agent",
                );
            }
            CrawlerCheck::Error => {}
        }
    }

    let action = if score >= policy.block_threshold {
        BotAction::Block
    } else if score >= policy.challenge_threshold && policy.challenge {
        BotAction::Challenge
    } else {
        BotAction::Allow
    };
    if policy.mode == BotMode::Log && score > 0 {
        verdict(score, reasons, BotAction::Log)
    } else {
        verdict(score, reasons, action)
    }
}

fn claimed_crawler_suffix(user_agent: &str) -> Option<&'static str> {
    if user_agent.contains("googlebot") {
        Some(".googlebot.com")
    } else if user_agent.contains("bingbot") {
        Some(".search.msn.com")
    } else if user_agent.contains("applebot") {
        Some(".applebot.apple.com")
    } else if user_agent.contains("yandexbot") {
        Some(".yandex.ru")
    } else if user_agent.contains("baiduspider") {
        Some(".crawl.baidu.com")
    } else if user_agent.contains("duckduckbot") {
        Some(".duckduckgo.com")
    } else {
        None
    }
}

fn is_browser(user_agent: &str) -> bool {
    ["chrome/", "chromium/", "firefox/", "safari/", "edg/"]
        .iter()
        .any(|pattern| user_agent.contains(pattern))
}

fn add_score(score: &mut u32, reasons: &mut Vec<&'static str>, amount: u32, reason: &'static str) {
    *score = score.saturating_add(amount);
    reasons.push(reason);
}

fn verdict(score: u32, reasons: Vec<&'static str>, action: BotAction) -> Verdict {
    Verdict {
        score,
        reasons,
        action,
    }
}

fn client_prefix(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], 0))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            IpAddr::V6(Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                0,
                0,
                0,
                0,
            ))
        }
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(HEX[usize::from(byte >> 4)]));
        value.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    value
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn verify_pow(seed: &str, nonce: &str, difficulty: u8) -> bool {
    if nonce.is_empty() || nonce.len() > 20 || !nonce.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, format!("{seed}{nonce}").as_bytes());
    let leading_zero_bits = digest
        .as_ref()
        .iter()
        .map(|byte| byte.leading_zeros() as u8)
        .take_while(|bits| *bits == 8)
        .sum::<u8>()
        + digest
            .as_ref()
            .iter()
            .find(|byte| **byte != 0)
            .map_or(0, |byte| byte.leading_zeros() as u8);
    leading_zero_bits >= difficulty
}

fn safe_return_path(path: &str) -> bool {
    path.starts_with('/') && !path.starts_with("//") && !path.starts_with("/\\")
}

fn percent_decode(value: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push((hex_value(high)? << 4) | hex_value(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn javascript_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\'' => escaped.push_str("\\'"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '<' => escaped.push_str("\\x3c"),
            '>' => escaped.push_str("\\x3e"),
            '&' => escaped.push_str("\\x26"),
            '\u{2028}' => escaped.push_str("\\u2028"),
            '\u{2029}' => escaped.push_str("\\u2029"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\u{:04x}", character as u32);
            }
            character => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::{
        BotAction, BotMode, BotPolicy, BotPolicyFile, BotState, CHALLENGE_PATH, evaluate,
        unix_time, verify_pow,
    };
    use http::{HeaderMap, HeaderValue, Request, StatusCode, Version, header};
    use std::{net::SocketAddr, str::FromStr};

    fn address(value: &str) -> SocketAddr {
        SocketAddr::from_str(value).unwrap()
    }

    #[tokio::test]
    async fn automation_is_challenged_and_scanners_are_blocked() {
        let policy = BotPolicy::default_enforcing();
        let state = BotState::new().unwrap();
        let automation = Request::builder()
            .header("user-agent", "python-requests/2.31")
            .body(())
            .unwrap();
        let scanner = Request::builder()
            .header("user-agent", "nuclei/3.0")
            .body(())
            .unwrap();
        assert_eq!(
            evaluate(&policy, &state, &automation, address("192.0.2.1:80"), None)
                .await
                .action,
            BotAction::Challenge
        );
        assert_eq!(
            evaluate(&policy, &state, &scanner, address("192.0.2.2:80"), None)
                .await
                .action,
            BotAction::Block
        );
    }

    #[tokio::test]
    async fn log_mode_never_enforces_and_allow_rules_bypass_scoring() {
        let file = BotPolicyFile {
            mode: BotMode::Log,
            ..BotPolicyFile::default()
        };
        let policy = BotPolicy::parse(file).unwrap();
        let state = BotState::new().unwrap();
        let scanner = Request::builder()
            .header("user-agent", "sqlmap")
            .body(())
            .unwrap();
        assert_eq!(
            evaluate(&policy, &state, &scanner, address("192.0.2.3:80"), None)
                .await
                .action,
            BotAction::Log
        );
        let allow = BotPolicy::parse(BotPolicyFile {
            allow_user_agents: vec!["example-crawler".to_owned()],
            ..BotPolicyFile::default()
        })
        .unwrap();
        let crawler = Request::builder()
            .header("user-agent", "Example-Crawler")
            .body(())
            .unwrap();
        assert_eq!(
            evaluate(&allow, &state, &crawler, address("192.0.2.4:80"), None)
                .await
                .action,
            BotAction::Allow
        );
    }

    #[tokio::test]
    async fn browser_headers_and_http_version_are_scored() {
        let policy = BotPolicy::default_enforcing();
        let state = BotState::new().unwrap();
        let mut request = Request::builder()
            .version(Version::HTTP_10)
            .header("user-agent", "Mozilla/5.0 Chrome/130.0")
            .body(())
            .unwrap();
        request.extensions_mut().insert(crate::vhost::TlsSni(None));
        let verdict = evaluate(&policy, &state, &request, address("192.0.2.5:80"), None).await;
        assert_eq!(verdict.score, 85);
        assert_eq!(verdict.action, BotAction::Block);
    }

    #[tokio::test]
    async fn honeypot_bans_the_client_and_exempt_paths_skip_checks() {
        let state = BotState::new().unwrap();
        let policy = BotPolicy::parse(BotPolicyFile {
            honeypot_paths: vec!["/hidden".to_owned()],
            exempt_paths: vec!["/health".to_owned()],
            verify_crawlers: false,
            ..BotPolicyFile::default()
        })
        .unwrap();
        let trap = Request::builder().uri("/hidden").body(()).unwrap();
        let ip = address("192.0.2.6:80");
        assert_eq!(
            evaluate(&policy, &state, &trap, ip, None).await.action,
            BotAction::Block
        );
        let normal = Request::builder()
            .uri("/health")
            .header("user-agent", "nuclei")
            .body(())
            .unwrap();
        assert_eq!(
            evaluate(&policy, &state, &normal, ip, None).await.action,
            BotAction::Allow
        );
    }

    #[test]
    fn validates_policy_bounds_and_path_safety() {
        assert!(
            BotPolicy::parse(BotPolicyFile {
                challenge_difficulty: 25,
                ..BotPolicyFile::default()
            })
            .is_err()
        );
        assert!(
            BotPolicy::parse(BotPolicyFile {
                honeypot_paths: vec!["//attacker.example".to_owned()],
                ..BotPolicyFile::default()
            })
            .is_err()
        );
        assert!(
            BotPolicy::parse(BotPolicyFile {
                deny_ips: vec!["192.0.2.0/24".to_owned()],
                ..BotPolicyFile::default()
            })
            .is_ok()
        );
    }

    #[test]
    fn proof_of_work_requires_leading_zero_bits() {
        let seed = "seed";
        let nonce = (0_u64..)
            .find(|nonce| verify_pow(seed, &nonce.to_string(), 8))
            .unwrap()
            .to_string();
        assert!(verify_pow(seed, &nonce, 8));
        assert!(!verify_pow(seed, "not-a-number", 1));
    }

    #[test]
    fn signed_challenge_cookie_is_valid_for_client_prefix_and_tls() {
        let state = BotState::new().unwrap();
        let client = address("192.0.2.17:8080");
        let expires = unix_time() + 60;
        let seed = state.expected_seed(client.ip(), expires);
        let nonce = (0_u64..)
            .find(|nonce| verify_pow(&seed, &nonce.to_string(), 8))
            .unwrap();
        let request = Request::builder()
            .uri(format!(
                "{CHALLENGE_PATH}?exp={expires}&seed={seed}&nonce={nonce}&return=%2Fwelcome%3Fok%3D1"
            ))
            .body(())
            .unwrap();
        let result = state.solve_challenge(&request, client, true, 8, 3600);
        assert_eq!(result.status, StatusCode::SEE_OTHER);
        assert_eq!(result.location.as_deref(), Some("/welcome?ok=1"));
        let cookie = result.set_cookie.unwrap();
        assert!(cookie.ends_with("; Secure"));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(cookie.split(';').next().unwrap()).unwrap(),
        );
        assert!(state.has_valid_cookie(&headers, client.ip()));
        assert!(!state.has_valid_cookie(&headers, address("192.0.3.17:8080").ip()));
    }

    #[test]
    fn challenge_rejects_expired_proofs_and_external_return_paths() {
        let state = BotState::new().unwrap();
        let client = address("192.0.2.18:8080");
        let expired = unix_time().saturating_sub(1);
        let seed = state.expected_seed(client.ip(), expired);
        let nonce = (0_u64..)
            .find(|nonce| verify_pow(&seed, &nonce.to_string(), 4))
            .unwrap();
        let expired_request = Request::builder()
            .uri(format!(
                "{CHALLENGE_PATH}?exp={expired}&seed={seed}&nonce={nonce}&return=%2F"
            ))
            .body(())
            .unwrap();
        assert_eq!(
            state
                .solve_challenge(&expired_request, client, false, 4, 3600)
                .status,
            StatusCode::FORBIDDEN
        );

        let expires = unix_time() + 60;
        let seed = state.expected_seed(client.ip(), expires);
        let nonce = (0_u64..)
            .find(|nonce| verify_pow(&seed, &nonce.to_string(), 4))
            .unwrap();
        let external_return = Request::builder()
            .uri(format!(
                "{CHALLENGE_PATH}?exp={expires}&seed={seed}&nonce={nonce}&return=%2F%2Fexample.com"
            ))
            .body(())
            .unwrap();
        assert_eq!(
            state
                .solve_challenge(&external_return, client, false, 4, 3600)
                .status,
            StatusCode::FORBIDDEN
        );
    }
}
