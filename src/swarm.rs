//! Redis-backed access checks compatible with logchomper's redis-accessproxy.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use chrono::{DateTime, Local};
use http::StatusCode;
use redis::aio::ConnectionManager;
use tokio::{sync::OnceCell, time::timeout};

use crate::forwarded::TrustedProxy;

const DEFAULT_VHOST_THRESHOLD: u64 = 1000;
const DEFAULT_CLASS_MIN_VHOST_COUNT: u64 = 3;
const OFFLINE_TTL: Duration = Duration::from_secs(120);
const MAX_CACHE_ENTRIES: usize = 4096;
const MINUTES_BACK: i64 = 5;

#[derive(Clone, Debug)]
pub(crate) struct SwarmConfig {
    pub(crate) upstream_url: String,
    pub(crate) local_url: Option<String>,
    pub(crate) vhost_threshold: u64,
    pub(crate) class_min_vhost_count: u64,
    pub(crate) hit_threshold: Option<u64>,
    pub(crate) malicious_pct: Option<f64>,
    pub(crate) dynamic_pct: Option<f64>,
    pub(crate) spam_pct: Option<f64>,
    pub(crate) classification_limits: bool,
    pub(crate) whitelist: Vec<TrustedProxy>,
    pub(crate) machine_key: Option<String>,
    pub(crate) timeout: Duration,
    pub(crate) neg_ttl: Duration,
    pub(crate) pos_ttl: Duration,
    pub(crate) pos_tti: Duration,
}

impl SwarmConfig {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        upstream_url: String,
        local_url: Option<String>,
        vhost_threshold: Option<u64>,
        class_min_vhost_count: Option<u64>,
        hit_threshold: Option<u64>,
        malicious_pct: Option<f64>,
        dynamic_pct: Option<f64>,
        spam_pct: Option<f64>,
        classification_limits: bool,
        whitelist: Vec<TrustedProxy>,
        machine_key: Option<String>,
        timeout_ms: Option<u64>,
        neg_ttl_secs: Option<u64>,
        pos_ttl_secs: Option<u64>,
        pos_tti_secs: Option<u64>,
    ) -> Result<Self, String> {
        validate_redis_url(&upstream_url, "--swarm-redis")?;
        if let Some(url) = &local_url {
            validate_redis_url(url, "--swarm-local-redis")?;
        }
        for (option, limit) in [
            ("--swarm-malicious-pct", malicious_pct),
            ("--swarm-dynamic-pct", dynamic_pct),
            ("--swarm-spam-pct", spam_pct),
        ] {
            if limit.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value)) {
                return Err(format!("{option} must be a finite fraction from 0 to 1"));
            }
        }
        if machine_key.as_ref().is_some_and(String::is_empty) {
            return Err("--swarm-machine-key must not be empty".to_owned());
        }
        let timeout = Duration::from_millis(timeout_ms.unwrap_or(3000));
        let neg_ttl = Duration::from_secs(neg_ttl_secs.unwrap_or(60));
        let pos_ttl = Duration::from_secs(pos_ttl_secs.unwrap_or(3600));
        let pos_tti = Duration::from_secs(pos_tti_secs.unwrap_or(900));
        if timeout.is_zero() {
            return Err("--swarm-timeout-ms must be greater than zero".to_owned());
        }
        if neg_ttl.is_zero() {
            return Err("--swarm-neg-cache-ttl must be greater than zero".to_owned());
        }
        if pos_ttl.is_zero() {
            return Err("--swarm-pos-cache-ttl must be greater than zero".to_owned());
        }
        if pos_tti.is_zero() {
            return Err("--swarm-pos-cache-tti must be greater than zero".to_owned());
        }
        let machine_key = machine_key.or_else(default_machine_key);
        Ok(Self {
            upstream_url,
            local_url,
            vhost_threshold: vhost_threshold.unwrap_or(DEFAULT_VHOST_THRESHOLD),
            class_min_vhost_count: class_min_vhost_count.unwrap_or(DEFAULT_CLASS_MIN_VHOST_COUNT),
            hit_threshold,
            malicious_pct,
            dynamic_pct,
            spam_pct,
            classification_limits,
            whitelist,
            machine_key,
            timeout,
            neg_ttl,
            pos_ttl,
            pos_tti,
        })
    }
}

fn validate_redis_url(value: &str, option: &str) -> Result<(), String> {
    let client = redis::Client::open(value)
        .map_err(|error| format!("{option} has an invalid Redis URL: {error}"))?;
    let _ = client;
    let scheme = value.split_once(':').map_or("", |(scheme, _)| scheme);
    if !matches!(scheme, "redis" | "rediss" | "redis+unix" | "unix") {
        return Err(format!(
            "{option} must use redis, rediss, redis+unix, or unix URL scheme"
        ));
    }
    Ok(())
}

fn default_machine_key() -> Option<String> {
    nix::unistd::gethostname()
        .ok()
        .map(|hostname| format!("blocklist:machine:{}", hostname.to_string_lossy()))
}

#[derive(Clone, Debug)]
pub(crate) struct Blocked {
    pub(crate) status: StatusCode,
    pub(crate) reason: String,
}

#[derive(Clone, Copy, Debug, Default)]
struct ClassCounts {
    dynamic: u64,
    malicious: u64,
    spam: u64,
}

#[derive(Clone, Copy, Debug)]
struct ClassLimits {
    malicious: Option<f64>,
    dynamic: Option<f64>,
    spam: Option<f64>,
}

#[derive(Clone, Debug)]
struct CacheEntry {
    reason: Option<String>,
    expires_at: Instant,
    idle_at: Instant,
}

#[derive(Default)]
struct ResultCache {
    entries: Mutex<HashMap<IpAddr, CacheEntry>>,
}

impl ResultCache {
    fn get_negative(&self, ip: IpAddr, now: Instant) -> bool {
        let mut entries = self.lock();
        entries.retain(|_, entry| entry.expires_at > now);
        entries
            .get(&ip)
            .is_some_and(|entry| entry.idle_at > now && entry.reason.is_none())
    }

    fn get_positive(&self, ip: IpAddr, now: Instant, idle_ttl: Duration) -> Option<String> {
        let mut entries = self.lock();
        entries.retain(|_, entry| entry.expires_at > now && entry.idle_at > now);
        let entry = entries.get_mut(&ip)?;
        let reason = entry.reason.clone()?;
        entry.idle_at = now.checked_add(idle_ttl).unwrap_or(now);
        Some(reason)
    }

    fn insert_negative(&self, ip: IpAddr, now: Instant, ttl: Duration) {
        self.insert(
            ip,
            CacheEntry {
                reason: None,
                expires_at: now.checked_add(ttl).unwrap_or(now),
                idle_at: now.checked_add(ttl).unwrap_or(now),
            },
            now,
        );
    }

    fn insert_positive(
        &self,
        ip: IpAddr,
        reason: String,
        now: Instant,
        ttl: Duration,
        idle_ttl: Duration,
    ) {
        self.insert(
            ip,
            CacheEntry {
                reason: Some(reason),
                expires_at: now.checked_add(ttl).unwrap_or(now),
                idle_at: now.checked_add(idle_ttl).unwrap_or(now),
            },
            now,
        );
    }

    fn insert(&self, ip: IpAddr, entry: CacheEntry, now: Instant) {
        let mut entries = self.lock();
        entries.retain(|_, current| current.expires_at > now && current.idle_at > now);
        if entries.len() >= MAX_CACHE_ENTRIES && !entries.contains_key(&ip) {
            if let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, current)| current.idle_at)
                .map(|(key, _)| *key)
            {
                entries.remove(&oldest);
            }
        }
        entries.insert(ip, entry);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, CacheEntry>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub(crate) struct Swarm {
    config: SwarmConfig,
    upstream_client: redis::Client,
    local_client: Option<redis::Client>,
    upstream_connection: OnceCell<ConnectionManager>,
    local_connection: OnceCell<ConnectionManager>,
    negative_cache: ResultCache,
    positive_cache: ResultCache,
    offline_until: Mutex<Option<Instant>>,
}

impl Swarm {
    pub(crate) fn new(config: SwarmConfig) -> Result<Self, redis::RedisError> {
        Ok(Self {
            upstream_client: redis::Client::open(config.upstream_url.as_str())?,
            local_client: config
                .local_url
                .as_deref()
                .map(redis::Client::open)
                .transpose()?,
            config,
            upstream_connection: OnceCell::new(),
            local_connection: OnceCell::new(),
            negative_cache: ResultCache::default(),
            positive_cache: ResultCache::default(),
            offline_until: Mutex::new(None),
        })
    }

    pub(crate) async fn check(&self, ip: IpAddr) -> Option<Blocked> {
        match timeout(self.config.timeout, self.check_inner(ip)).await {
            Ok(blocked) => blocked,
            Err(_) => {
                self.mark_offline();
                None
            }
        }
    }

    async fn check_inner(&self, ip: IpAddr) -> Option<Blocked> {
        let now = Instant::now();
        if self.negative_cache.get_negative(ip, now) {
            return None;
        }
        if self
            .config
            .whitelist
            .iter()
            .any(|network| network.contains(ip))
        {
            return None;
        }
        if let Some(reason) = self
            .positive_cache
            .get_positive(ip, now, self.config.pos_tti)
        {
            return Some(blocked(
                StatusCode::TOO_MANY_REQUESTS,
                format!("Cached: ({reason})"),
            ));
        }

        let ip_text = ip.to_string();
        let mut upstream = if self.is_offline() {
            None
        } else {
            self.upstream_connection().await
        };
        if let Some(connection) = upstream.as_mut() {
            if in_blocklist(connection, "blocklist:global", &ip_text).await {
                return self.cache_block(ip, "Global blocklist");
            }
            if let Some(key) = &self.config.machine_key
                && in_blocklist(connection, key, &ip_text).await
            {
                return self.cache_block(ip, "Machine blocklist");
            }
        }

        if let Some(connection) = self.local_connection().await {
            let key = format!("customer_blocklist_{ip_text}");
            if redis::cmd("EXISTS")
                .arg(key)
                .query_async::<bool>(&mut connection.clone())
                .await
                .unwrap_or(false)
            {
                return Some(blocked(
                    StatusCode::FORBIDDEN,
                    "Blacklisted(Forbidden)".to_owned(),
                ));
            }
        }

        if self.is_offline() || upstream.is_none() {
            return None;
        }

        let connection = upstream.as_mut()?;
        match self.thresholds(connection, &ip_text).await {
            ThresholdResult::Allow { cache: true } => {
                self.negative_cache
                    .insert_negative(ip, Instant::now(), self.config.neg_ttl);
                None
            }
            ThresholdResult::Allow { cache: false } => None,
            ThresholdResult::Block(reason) => self.cache_block(ip, reason),
        }
    }

    fn cache_block(&self, ip: IpAddr, reason: impl Into<String>) -> Option<Blocked> {
        let reason = reason.into();
        self.positive_cache.insert_positive(
            ip,
            reason.clone(),
            Instant::now(),
            self.config.pos_ttl,
            self.config.pos_tti,
        );
        Some(blocked(StatusCode::TOO_MANY_REQUESTS, reason))
    }

    async fn upstream_connection(&self) -> Option<ConnectionManager> {
        match self
            .upstream_connection
            .get_or_try_init(|| async { self.upstream_client.get_connection_manager().await })
            .await
        {
            Ok(connection) => Some(connection.clone()),
            Err(error) => {
                crate::log_error!("swarm Redis connection failed: {error}");
                self.mark_offline();
                None
            }
        }
    }

    async fn local_connection(&self) -> Option<ConnectionManager> {
        let client = self.local_client.as_ref()?;
        match self
            .local_connection
            .get_or_try_init(|| async { client.get_connection_manager().await })
            .await
        {
            Ok(connection) => Some(connection.clone()),
            Err(error) => {
                crate::log_error!("swarm local Redis connection failed: {error}");
                None
            }
        }
    }

    async fn thresholds(&self, connection: &mut ConnectionManager, ip: &str) -> ThresholdResult {
        let now = Local::now();
        let timestamp = now.timestamp();
        let keys = redis_keys(ip, now);
        let vhost_count = redis::cmd("ZCOUNT")
            .arg(&keys.vhosts)
            .arg(timestamp - MINUTES_BACK * 60)
            .arg(timestamp)
            .query_async::<u64>(&mut connection.clone())
            .await
            .unwrap_or(0);
        if vhost_count > self.config.vhost_threshold {
            return ThresholdResult::Block(format!("OverVhostCnt({vhost_count})"));
        }
        if !self.config.classification_limits || vhost_count <= self.config.class_min_vhost_count {
            return ThresholdResult::Allow { cache: true };
        }
        let Some(hit_threshold) = self.config.hit_threshold else {
            return ThresholdResult::Allow { cache: true };
        };

        let mut class_keys = Vec::with_capacity(MINUTES_BACK as usize);
        for minute in 1..=MINUTES_BACK {
            let bucket = now - chrono::Duration::seconds(minute * 60);
            let keys = redis_keys(ip, bucket);
            class_keys.push(keys.classes);
        }
        let mut hit_pipe = redis::pipe();
        for minute in 1..=MINUTES_BACK {
            let bucket = now - chrono::Duration::seconds(minute * 60);
            let keys = redis_keys(ip, bucket);
            hit_pipe.cmd("ZSCORE").arg(&keys.hits).arg(ip);
        }
        let hits = match hit_pipe
            .query_async::<Vec<Option<u64>>>(&mut connection.clone())
            .await
        {
            Ok(hits) => hits,
            Err(_) => return ThresholdResult::Allow { cache: false },
        };
        let hit_total = hits.into_iter().flatten().fold(0u64, u64::saturating_add);
        if hit_total < hit_threshold {
            return ThresholdResult::Allow { cache: true };
        }

        let mut counts = ClassCounts::default();
        let mut class_pipe = redis::pipe();
        for key in &class_keys {
            class_pipe
                .cmd("HMGET")
                .arg(key)
                .arg("dynamic")
                .arg("malicious")
                .arg("spam")
                .arg("static")
                .arg("path");
        }
        let class_values = match class_pipe
            .query_async::<Vec<Vec<Option<u64>>>>(&mut connection.clone())
            .await
        {
            Ok(values) => values,
            Err(_) => return ThresholdResult::Allow { cache: false },
        };
        for values in class_values {
            counts.dynamic = counts
                .dynamic
                .saturating_add(values.first().copied().flatten().unwrap_or(0));
            counts.malicious = counts
                .malicious
                .saturating_add(values.get(1).copied().flatten().unwrap_or(0));
            counts.spam = counts
                .spam
                .saturating_add(values.get(2).copied().flatten().unwrap_or(0));
        }
        let limits = ClassLimits {
            malicious: self.config.malicious_pct,
            dynamic: self.config.dynamic_pct,
            spam: self.config.spam_pct,
        };
        class_verdict(counts, hit_total, limits).map_or(
            ThresholdResult::Allow { cache: true },
            ThresholdResult::Block,
        )
    }

    fn mark_offline(&self) {
        *self
            .offline_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Instant::now() + OFFLINE_TTL);
    }

    fn is_offline(&self) -> bool {
        let now = Instant::now();
        let mut offline = self
            .offline_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if offline.is_some_and(|until| until <= now) {
            *offline = None;
        }
        offline.is_some()
    }
}

enum ThresholdResult {
    Allow { cache: bool },
    Block(String),
}

fn blocked(status: StatusCode, reason: String) -> Blocked {
    Blocked { status, reason }
}

async fn in_blocklist(connection: &mut ConnectionManager, key: &str, ip: &str) -> bool {
    let score = redis::cmd("ZSCORE")
        .arg(key)
        .arg(ip)
        .query_async::<Option<f64>>(&mut connection.clone())
        .await
        .unwrap_or(None);
    score.is_some_and(|score| blocklist_active(score, Local::now().timestamp()))
}

fn blocklist_active(score: f64, now: i64) -> bool {
    score == 0.0 || score > now as f64
}

struct RedisKeys {
    vhosts: String,
    hits: String,
    classes: String,
}

fn redis_keys(ip: &str, time: DateTime<Local>) -> RedisKeys {
    let hour_minute = time.format("%H%M");
    RedisKeys {
        vhosts: format!("{ip}_vhosts"),
        hits: format!("{hour_minute}_hits"),
        classes: format!("{hour_minute}_{ip}_classes"),
    }
}

fn class_verdict(counts: ClassCounts, total: u64, limits: ClassLimits) -> Option<String> {
    if total == 0 {
        return None;
    }
    for (count, limit, reason) in [
        (counts.malicious, limits.malicious, "OverClassMal"),
        (counts.dynamic, limits.dynamic, "OverClassDyn"),
        (counts.spam, limits.spam, "OverClassSpam"),
    ] {
        let Some(limit) = limit else {
            continue;
        };
        let fraction = count as f64 / total as f64;
        if fraction > limit {
            return Some(format!("{reason}({fraction})"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        CacheEntry, ClassCounts, ClassLimits, ResultCache, Swarm, SwarmConfig, blocklist_active,
        class_verdict, redis_keys,
    };
    use chrono::{Local, TimeZone};
    use std::{
        net::IpAddr,
        time::{Duration, Instant},
    };

    #[test]
    fn builds_logchomper_redis_key_names() {
        let time = Local.with_ymd_and_hms(2026, 11, 21, 15, 7, 0).unwrap();
        let keys = redis_keys("192.0.2.10", time);
        assert_eq!(keys.vhosts, "192.0.2.10_vhosts");
        assert_eq!(keys.hits, "1507_hits");
        assert_eq!(keys.classes, "1507_192.0.2.10_classes");
    }

    #[test]
    fn blocklist_score_zero_is_permanent_and_future_score_is_active() {
        assert!(blocklist_active(0.0, 100));
        assert!(blocklist_active(101.0, 100));
        assert!(!blocklist_active(100.0, 100));
        assert!(!blocklist_active(99.0, 100));
    }

    #[test]
    fn classification_checks_malicious_then_dynamic_then_spam_strictly() {
        let limits = ClassLimits {
            malicious: Some(0.25),
            dynamic: Some(0.25),
            spam: Some(0.25),
        };
        assert_eq!(
            class_verdict(
                ClassCounts {
                    malicious: 2,
                    dynamic: 3,
                    spam: 0
                },
                4,
                limits,
            ),
            Some("OverClassMal(0.5)".to_owned())
        );
        assert_eq!(
            class_verdict(
                ClassCounts {
                    malicious: 0,
                    dynamic: 2,
                    spam: 2
                },
                4,
                limits,
            ),
            Some("OverClassDyn(0.5)".to_owned())
        );
        assert_eq!(
            class_verdict(
                ClassCounts {
                    malicious: 1,
                    dynamic: 0,
                    spam: 0
                },
                4,
                limits
            ),
            None
        );
    }

    #[test]
    fn cache_obeys_negative_ttl_and_positive_ttl_and_tti() {
        let cache = ResultCache::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let now = Instant::now();
        cache.insert_negative(ip, now, Duration::from_secs(2));
        assert!(cache.get_negative(ip, now + Duration::from_secs(1)));
        assert!(!cache.get_negative(ip, now + Duration::from_secs(3)));

        cache.insert_positive(
            ip,
            "blocked".to_owned(),
            now,
            Duration::from_secs(10),
            Duration::from_secs(4),
        );
        assert_eq!(
            cache.get_positive(ip, now + Duration::from_secs(3), Duration::from_secs(4)),
            Some("blocked".to_owned())
        );
        assert_eq!(
            cache.get_positive(ip, now + Duration::from_secs(8), Duration::from_secs(4)),
            None
        );
        let entry = CacheEntry {
            reason: Some("ttl".to_owned()),
            expires_at: now + Duration::from_secs(1),
            idle_at: now + Duration::from_secs(10),
        };
        cache.insert("192.0.2.2".parse().unwrap(), entry, now);
        assert_eq!(
            cache.get_positive(
                "192.0.2.2".parse().unwrap(),
                now + Duration::from_secs(2),
                Duration::from_secs(4)
            ),
            None
        );
    }

    #[test]
    fn configured_whitelist_uses_trusted_proxy_cidr_matching() {
        let whitelist: crate::forwarded::TrustedProxy = "192.0.2.0/24".parse().unwrap();
        assert!(whitelist.contains("192.0.2.7".parse().unwrap()));
        assert!(!whitelist.contains("192.0.3.7".parse().unwrap()));
    }

    #[tokio::test]
    async fn whitelisted_clients_skip_redis_connections() {
        let whitelist = vec!["192.0.2.0/24".parse().unwrap()];
        let config = SwarmConfig::new(
            "redis://127.0.0.1:1/".to_owned(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            whitelist,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
        let swarm = Swarm::new(config).unwrap();
        assert!(swarm.check("192.0.2.15".parse().unwrap()).await.is_none());
    }
}
