//! Redis-backed access checks and request recording for swarm mode.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::{DateTime, Local};
use http::StatusCode;
use redis::aio::ConnectionManager;
use tokio::{
    process::Command,
    sync::{OnceCell, mpsc},
    task::JoinHandle,
    time::{MissedTickBehavior, interval, timeout},
};

use crate::forwarded::TrustedProxy;

const DEFAULT_VHOST_THRESHOLD: u64 = 1000;
const DEFAULT_CLASS_MIN_VHOST_COUNT: u64 = 3;
const OFFLINE_TTL: Duration = Duration::from_secs(120);
const MAX_CACHE_ENTRIES: usize = 4096;
const MINUTES_BACK: i64 = 5;
const RECORD_CHANNEL_CAPACITY: usize = 8192;
const SHORT_KEY_TTL: u64 = 600;
const DAILY_KEY_TTL: u64 = 7 * 24 * 60 * 60;
const DEFAULT_NFT_ALLOW_SETS: [&str; 5] = [
    "trusted_upstream_provider_ips",
    "dh_metrics_ips",
    "dh_nrpe",
    "dh_internal",
    "dh_wl_in4",
];
const DEFAULT_NFT_DENY_SETS: [&str; 2] = ["dh_ban_in4", "addr-set-418"];

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
    pub(crate) record: bool,
    pub(crate) flush_interval: Duration,
    pub(crate) malicious_files: Vec<String>,
    pub(crate) dynamic_extensions: Vec<String>,
    pub(crate) spam_substrings: Vec<String>,
    pub(crate) nft: bool,
    pub(crate) nft_allow_sets: Vec<String>,
    pub(crate) nft_deny_sets: Vec<String>,
    pub(crate) nft_refresh: Duration,
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
        record: bool,
        flush_ms: Option<u64>,
        malicious_files: Vec<String>,
        dynamic_extensions: Vec<String>,
        spam_substrings: Vec<String>,
        nft: bool,
        nft_allow_sets: Vec<String>,
        nft_deny_sets: Vec<String>,
        nft_refresh_secs: Option<u64>,
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
        let flush_interval = Duration::from_millis(flush_ms.unwrap_or(10_000));
        let nft_refresh = Duration::from_secs(nft_refresh_secs.unwrap_or(3600));
        if timeout.is_zero() {
            return Err("--swarm-timeout-ms must be greater than zero".to_owned());
        }
        if flush_interval.is_zero() {
            return Err("--swarm-flush-ms must be greater than zero".to_owned());
        }
        if nft_refresh.is_zero() {
            return Err("--swarm-nft-refresh-secs must be greater than zero".to_owned());
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
        let dynamic_extensions = if dynamic_extensions.is_empty() {
            vec!["php".to_owned(), "cgi".to_owned()]
        } else {
            dynamic_extensions
        }
        .into_iter()
        .map(|extension| extension.trim_start_matches('.').to_ascii_lowercase())
        .collect();
        let nft_allow_sets = if nft_allow_sets.is_empty() {
            DEFAULT_NFT_ALLOW_SETS
                .into_iter()
                .map(str::to_owned)
                .collect()
        } else {
            nft_allow_sets
        };
        let nft_deny_sets = if nft_deny_sets.is_empty() {
            DEFAULT_NFT_DENY_SETS
                .into_iter()
                .map(str::to_owned)
                .collect()
        } else {
            nft_deny_sets
        };
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
            record,
            flush_interval,
            malicious_files,
            dynamic_extensions,
            spam_substrings,
            nft,
            nft_allow_sets,
            nft_deny_sets,
            nft_refresh,
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
    static_count: u64,
    path: u64,
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
    record_sender: Option<mpsc::Sender<RecordedRequest>>,
    writer_task: Option<JoinHandle<()>>,
    nft_members: Arc<RwLock<NftMembers>>,
    nft_task: Option<JoinHandle<()>>,
}

impl Swarm {
    pub(crate) fn new(config: SwarmConfig) -> Result<Self, redis::RedisError> {
        let upstream_client = redis::Client::open(config.upstream_url.as_str())?;
        let local_client = config
            .local_url
            .as_deref()
            .map(redis::Client::open)
            .transpose()?;
        let (record_sender, writer_task) = if config.record {
            let (sender, receiver) = mpsc::channel(RECORD_CHANNEL_CAPACITY);
            let client = upstream_client.clone();
            let writer_config = config.clone();
            let task = tokio::spawn(async move {
                run_record_writer(receiver, client, writer_config).await;
            });
            (Some(sender), Some(task))
        } else {
            (None, None)
        };
        let nft_members = Arc::new(RwLock::new(NftMembers::default()));
        let nft_task = if config.nft {
            let members = Arc::clone(&nft_members);
            let allow_sets = config.nft_allow_sets.clone();
            let deny_sets = config.nft_deny_sets.clone();
            let refresh = config.nft_refresh;
            Some(tokio::spawn(async move {
                refresh_nft_members(members, allow_sets, deny_sets, refresh).await;
            }))
        } else {
            None
        };
        Ok(Self {
            upstream_client,
            local_client,
            config,
            upstream_connection: OnceCell::new(),
            local_connection: OnceCell::new(),
            negative_cache: ResultCache::default(),
            positive_cache: ResultCache::default(),
            offline_until: Mutex::new(None),
            record_sender,
            writer_task,
            nft_members,
            nft_task,
        })
    }

    pub(crate) fn recording_enabled(&self) -> bool {
        self.record_sender.is_some()
    }

    pub(crate) fn record(
        &self,
        ip: IpAddr,
        vhost: String,
        url: String,
        user_agent: String,
        status: StatusCode,
    ) {
        if let Some(sender) = &self.record_sender {
            let _ = sender.try_send(RecordedRequest {
                ip,
                vhost,
                url,
                user_agent,
                status: status.as_u16(),
            });
        }
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

        {
            let members = self
                .nft_members
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if members.allow.iter().any(|member| member.contains(ip)) {
                return None;
            }
            if members.deny.iter().any(|member| member.contains(ip)) {
                return self.cache_block(ip, "IP in NFT Blocklist");
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
        let keys = redis_keys(ip, now, false);
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
            let keys = redis_keys(ip, bucket, false);
            class_keys.push(keys.classes);
        }
        let mut hit_pipe = redis::pipe();
        for minute in 1..=MINUTES_BACK {
            let bucket = now - chrono::Duration::seconds(minute * 60);
            let keys = redis_keys(ip, bucket, false);
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

impl Drop for Swarm {
    fn drop(&mut self) {
        if let Some(task) = self.writer_task.take() {
            task.abort();
        }
        if let Some(task) = self.nft_task.take() {
            task.abort();
        }
    }
}

#[derive(Debug)]
struct RecordedRequest {
    ip: IpAddr,
    vhost: String,
    url: String,
    user_agent: String,
    status: u16,
}

#[derive(Default)]
struct RequestBatch {
    hits: u64,
    vhosts: HashMap<String, u64>,
    user_agents: HashMap<String, u64>,
    urls: HashMap<String, u64>,
    statuses: HashMap<u16, u64>,
}

impl RequestBatch {
    fn add(&mut self, request: RecordedRequest) {
        self.hits = self.hits.saturating_add(1);
        increment(&mut self.vhosts, request.vhost, 1);
        increment(&mut self.user_agents, request.user_agent, 1);
        increment(&mut self.urls, request.url, 1);
        increment(&mut self.statuses, request.status, 1);
    }
}

fn increment<K: std::hash::Hash + Eq>(counts: &mut HashMap<K, u64>, key: K, amount: u64) {
    let count = counts.entry(key).or_default();
    *count = count.saturating_add(amount);
}

async fn run_record_writer(
    mut receiver: mpsc::Receiver<RecordedRequest>,
    client: redis::Client,
    config: SwarmConfig,
) {
    let mut batch = HashMap::<String, RequestBatch>::new();
    let mut connection = None;
    let mut flush = interval(config.flush_interval);
    flush.set_missed_tick_behavior(MissedTickBehavior::Delay);
    flush.tick().await;
    loop {
        tokio::select! {
            request = receiver.recv() => {
                let Some(request) = request else {
                    break;
                };
                increment_batch(&mut batch, request);
            }
            _ = flush.tick() => {
                if batch.is_empty() {
                    continue;
                }
                let commands = build_write_commands(&batch, Local::now(), &config);
                if connection.is_none() {
                    match client.get_connection_manager().await {
                        Ok(manager) => connection = Some(manager),
                        Err(error) => {
                            crate::log_error!("swarm Redis writer connection failed; dropping batch: {error}");
                        }
                    }
                }
                let write_result = if let Some(manager) = connection.as_mut() {
                    let mut pipeline = redis::pipe();
                    for command in commands {
                        let Some((name, args)) = command.split_first() else {
                            continue;
                        };
                        let mut redis_command = redis::cmd(name);
                        for arg in args {
                            redis_command.arg(arg);
                        }
                        pipeline.add_command(redis_command);
                    }
                    Some(pipeline.exec_async(manager).await)
                } else {
                    None
                };
                if let Some(Err(error)) = write_result {
                    crate::log_error!("swarm Redis write failed; dropping batch: {error}");
                    connection = None;
                }
                batch.clear();
            }
        }
    }
}

fn increment_batch(batch: &mut HashMap<String, RequestBatch>, request: RecordedRequest) {
    batch
        .entry(request.ip.to_string())
        .or_default()
        .add(request);
}

fn build_write_commands(
    batch: &HashMap<String, RequestBatch>,
    now: DateTime<Local>,
    config: &SwarmConfig,
) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let mut expired = HashSet::new();
    for (client, data) in batch {
        let is_whitelisted = client
            .parse::<IpAddr>()
            .ok()
            .is_some_and(|ip| config.whitelist.iter().any(|network| network.contains(ip)));
        let keys = redis_keys(client, now, is_whitelisted);
        let lifetime = if is_whitelisted {
            DAILY_KEY_TTL
        } else {
            SHORT_KEY_TTL
        };

        commands.push(vec![
            "ZINCRBY".to_owned(),
            keys.hits.clone(),
            data.hits.to_string(),
            client.clone(),
        ]);
        push_expire(&mut commands, &mut expired, &keys.hits, lifetime);

        if !data.vhosts.is_empty() {
            let mut command = vec!["ZADD".to_owned(), keys.vhosts.clone()];
            for vhost in data.vhosts.keys() {
                command.push(now.timestamp().to_string());
                command.push(vhost.clone());
            }
            commands.push(command);
        }
        push_expire(&mut commands, &mut expired, &keys.vhosts, lifetime);

        for (user_agent, count) in &data.user_agents {
            commands.push(vec![
                "ZINCRBY".to_owned(),
                keys.user_agents.clone(),
                count.to_string(),
                user_agent.clone(),
            ]);
        }
        push_expire(&mut commands, &mut expired, &keys.user_agents, lifetime);

        for (status, count) in &data.statuses {
            if *status == 418 {
                push_zincrby(&mut commands, &keys.status_418, client, *count);
            } else if *status == 429 {
                push_zincrby(&mut commands, &keys.status_429, client, *count);
            }
            push_zincrby(
                &mut commands,
                &keys.daily_by_code,
                &status.to_string(),
                *count,
            );
        }
        push_expire(&mut commands, &mut expired, &keys.status_418, DAILY_KEY_TTL);
        push_expire(&mut commands, &mut expired, &keys.status_429, DAILY_KEY_TTL);
        push_expire(
            &mut commands,
            &mut expired,
            &keys.daily_by_code,
            DAILY_KEY_TTL,
        );

        let mut classes = ClassCounts::default();
        for (url, count) in &data.urls {
            push_zincrby(&mut commands, &keys.urls, url, *count);
            for class in classify(url, config) {
                match class {
                    RequestClass::Malicious => {
                        classes.malicious = classes.malicious.saturating_add(*count)
                    }
                    RequestClass::Dynamic => {
                        classes.dynamic = classes.dynamic.saturating_add(*count)
                    }
                    RequestClass::Spam => classes.spam = classes.spam.saturating_add(*count),
                    RequestClass::Static => {
                        classes.static_count = classes.static_count.saturating_add(*count)
                    }
                    RequestClass::Path => classes.path = classes.path.saturating_add(*count),
                }
            }
        }
        push_expire(&mut commands, &mut expired, &keys.urls, lifetime);
        for (name, count) in [
            ("static", classes.static_count),
            ("malicious", classes.malicious),
            ("path", classes.path),
            ("dynamic", classes.dynamic),
            ("spam", classes.spam),
        ] {
            if count > 0 {
                commands.push(vec![
                    "HINCRBY".to_owned(),
                    keys.classes.clone(),
                    name.to_owned(),
                    count.to_string(),
                ]);
            }
        }
        push_expire(&mut commands, &mut expired, &keys.classes, lifetime);
    }
    commands
}

fn push_zincrby(commands: &mut Vec<Vec<String>>, key: &str, member: &str, count: u64) {
    commands.push(vec![
        "ZINCRBY".to_owned(),
        key.to_owned(),
        count.to_string(),
        member.to_owned(),
    ]);
}

fn push_expire(
    commands: &mut Vec<Vec<String>>,
    expired: &mut HashSet<String>,
    key: &str,
    lifetime: u64,
) {
    if expired.insert(key.to_owned()) {
        commands.push(vec![
            "EXPIRE".to_owned(),
            key.to_owned(),
            lifetime.to_string(),
            "NX".to_owned(),
        ]);
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RequestClass {
    Malicious,
    Dynamic,
    Spam,
    Static,
    Path,
}

fn classify(url: &str, config: &SwarmConfig) -> HashSet<RequestClass> {
    let path = url.split_once('?').map_or(url, |(path, _)| path);
    if path == "/" {
        return HashSet::from([RequestClass::Path]);
    }
    let filename = std::path::Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let mut classes = HashSet::new();
    if config.malicious_files.iter().any(|file| file == filename) {
        classes.insert(RequestClass::Malicious);
    }
    match std::path::Path::new(filename)
        .extension()
        .and_then(|extension| extension.to_str())
    {
        Some(extension)
            if config
                .dynamic_extensions
                .iter()
                .any(|dynamic| dynamic.eq_ignore_ascii_case(extension)) =>
        {
            classes.insert(RequestClass::Dynamic);
        }
        Some(_) => {
            classes.insert(RequestClass::Static);
        }
        None => {
            classes.insert(RequestClass::Path);
        }
    }
    if config
        .spam_substrings
        .iter()
        .any(|substring| url.contains(substring))
    {
        classes.insert(RequestClass::Spam);
    }
    classes
}

#[derive(Clone, Copy, Debug)]
enum NftMember {
    Ip(IpAddr),
    Cidr(TrustedProxy),
    Range { start: IpAddr, end: IpAddr },
}

impl NftMember {
    fn contains(self, ip: IpAddr) -> bool {
        match self {
            Self::Ip(address) => address == ip,
            Self::Cidr(network) => network.contains(ip),
            Self::Range { start, end } => match (start, end, ip) {
                (IpAddr::V4(start), IpAddr::V4(end), IpAddr::V4(ip)) => {
                    u32::from(start) <= u32::from(ip) && u32::from(ip) <= u32::from(end)
                }
                (IpAddr::V6(start), IpAddr::V6(end), IpAddr::V6(ip)) => {
                    u128::from(start) <= u128::from(ip) && u128::from(ip) <= u128::from(end)
                }
                _ => false,
            },
        }
    }
}

#[derive(Default)]
struct NftMembers {
    allow: Vec<NftMember>,
    deny: Vec<NftMember>,
}

async fn refresh_nft_members(
    members: Arc<RwLock<NftMembers>>,
    allow_sets: Vec<String>,
    deny_sets: Vec<String>,
    refresh: Duration,
) {
    let failure_logged = AtomicBool::new(false);
    let mut ticker = interval(refresh);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match read_nft_members(&allow_sets, &deny_sets).await {
            Ok(updated) => {
                *members
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = updated;
            }
            Err(error) => {
                *members
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = NftMembers::default();
                if !failure_logged.swap(true, Ordering::Relaxed) {
                    crate::log_error!(
                        "unable to read nftables ruleset; swarm nft checks fail open: {error}"
                    );
                }
            }
        }
    }
}

async fn read_nft_members(
    allow_sets: &[String],
    deny_sets: &[String],
) -> Result<NftMembers, String> {
    let output = Command::new("nft")
        .args(["-j", "list", "ruleset"])
        .output()
        .await
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    let document = serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    parse_nft_members(&document, allow_sets, deny_sets)
}

fn parse_nft_members(
    document: &serde_json::Value,
    allow_sets: &[String],
    deny_sets: &[String],
) -> Result<NftMembers, String> {
    let objects = document
        .get("nftables")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "nft JSON has no nftables object list".to_owned())?;
    let mut result = NftMembers::default();
    for object in objects {
        let Some(set) = object.get("set") else {
            continue;
        };
        let Some(name) = set.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let destination = if allow_sets.iter().any(|candidate| candidate == name) {
            Some(&mut result.allow)
        } else if deny_sets.iter().any(|candidate| candidate == name) {
            Some(&mut result.deny)
        } else {
            None
        };
        let Some(destination) = destination else {
            continue;
        };
        if let Some(elements) = set.get("elem").and_then(serde_json::Value::as_array) {
            destination.extend(elements.iter().filter_map(parse_nft_member));
        }
    }
    Ok(result)
}

fn parse_nft_member(value: &serde_json::Value) -> Option<NftMember> {
    if let Some(element) = value.get("elem") {
        return parse_nft_member(element);
    }
    if let Some(value) = value.get("val") {
        return parse_nft_member(value);
    }
    if let Some(address) = parse_nft_ip(value) {
        return Some(NftMember::Ip(address));
    }
    if let Some(range) = value.get("range").and_then(serde_json::Value::as_array)
        && let (Some(start), Some(end)) = (
            range.first().and_then(parse_nft_ip),
            range.get(1).and_then(parse_nft_ip),
        )
        && same_family(start, end)
        && range_start_before_end(start, end)
    {
        return Some(NftMember::Range { start, end });
    }
    if let Some(prefix) = value.get("prefix")
        && let Some(address) = prefix.get("addr").and_then(parse_nft_ip)
        && let Some(length) = prefix
            .get("len")
            .and_then(serde_json::Value::as_u64)
            .and_then(|length| u8::try_from(length).ok())
    {
        return format!("{address}/{length}")
            .parse::<TrustedProxy>()
            .ok()
            .map(NftMember::Cidr);
    }
    None
}

fn parse_nft_ip(value: &serde_json::Value) -> Option<IpAddr> {
    value
        .as_str()
        .or_else(|| value.get("string").and_then(serde_json::Value::as_str))
        .and_then(|address| address.parse().ok())
}

fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

fn range_start_before_end(start: IpAddr, end: IpAddr) -> bool {
    match (start, end) {
        (IpAddr::V4(start), IpAddr::V4(end)) => u32::from(start) <= u32::from(end),
        (IpAddr::V6(start), IpAddr::V6(end)) => u128::from(start) <= u128::from(end),
        _ => false,
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
    user_agents: String,
    urls: String,
    daily_by_code: String,
    status_418: String,
    status_429: String,
}

fn redis_keys(ip: &str, time: DateTime<Local>, whitelisted: bool) -> RedisKeys {
    let hour_minute = time.format("%H%M");
    let date = time.format("%F");
    let (vhosts, user_agents, urls, classes, daily_by_code, status_418, status_429) = if whitelisted
    {
        let base_key = format!("wl_{date}_{ip}");
        (
            format!("wl_{base_key}_vhosts"),
            format!("{base_key}_ua"),
            format!("{base_key}_urls"),
            format!("{base_key}_classes"),
            format!("wl_daily_bycode_{date}"),
            format!("{base_key}_418"),
            format!("{base_key}_429"),
        )
    } else {
        let base_key = format!("{hour_minute}_{ip}");
        let date_hour = time.format("%F_%H");
        (
            format!("{ip}_vhosts"),
            format!("{base_key}_ua"),
            format!("{base_key}_urls"),
            format!("{base_key}_classes"),
            format!("daily_bycode_{date}"),
            format!("{date_hour}_418"),
            format!("{date_hour}_429"),
        )
    };
    RedisKeys {
        vhosts,
        hits: format!("{hour_minute}_hits"),
        classes,
        user_agents,
        urls,
        daily_by_code,
        status_418,
        status_429,
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
        CacheEntry, ClassCounts, ClassLimits, RecordedRequest, RequestBatch, RequestClass,
        ResultCache, Swarm, SwarmConfig, blocklist_active, build_write_commands, class_verdict,
        classify, parse_nft_members, redis_keys,
    };
    use chrono::{Local, TimeZone};
    use std::{
        collections::{HashMap, HashSet},
        net::IpAddr,
        time::{Duration, Instant},
    };

    #[test]
    fn builds_redis_key_names_for_normal_and_whitelisted_clients() {
        let time = Local.with_ymd_and_hms(2026, 11, 21, 15, 7, 0).unwrap();
        let keys = redis_keys("192.0.2.10", time, false);
        assert_eq!(keys.vhosts, "192.0.2.10_vhosts");
        assert_eq!(keys.hits, "1507_hits");
        assert_eq!(keys.classes, "1507_192.0.2.10_classes");
        assert_eq!(keys.user_agents, "1507_192.0.2.10_ua");
        assert_eq!(keys.urls, "1507_192.0.2.10_urls");
        assert_eq!(keys.daily_by_code, "daily_bycode_2026-11-21");
        assert_eq!(keys.status_418, "2026-11-21_15_418");
        assert_eq!(keys.status_429, "2026-11-21_15_429");

        let keys = redis_keys("192.0.2.10", time, true);
        assert_eq!(keys.vhosts, "wl_wl_2026-11-21_192.0.2.10_vhosts");
        assert_eq!(keys.hits, "1507_hits");
        assert_eq!(keys.classes, "wl_2026-11-21_192.0.2.10_classes");
        assert_eq!(keys.user_agents, "wl_2026-11-21_192.0.2.10_ua");
        assert_eq!(keys.urls, "wl_2026-11-21_192.0.2.10_urls");
        assert_eq!(keys.daily_by_code, "wl_daily_bycode_2026-11-21");
        assert_eq!(keys.status_418, "wl_2026-11-21_192.0.2.10_418");
        assert_eq!(keys.status_429, "wl_2026-11-21_192.0.2.10_429");
    }

    fn test_config(whitelist: Vec<crate::forwarded::TrustedProxy>) -> SwarmConfig {
        SwarmConfig::new(
            "redis://127.0.0.1:6379/".to_owned(),
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
            true,
            None,
            vec!["wp-login.php".to_owned()],
            vec!["php".to_owned()],
            vec!["spam".to_owned()],
            false,
            Vec::new(),
            Vec::new(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn classifies_path_static_dynamic_malicious_and_spam_urls() {
        let config = test_config(Vec::new());
        assert_eq!(classify("/", &config), HashSet::from([RequestClass::Path]));
        assert_eq!(
            classify("/search", &config),
            HashSet::from([RequestClass::Path])
        );
        assert_eq!(
            classify("/image.jpg", &config),
            HashSet::from([RequestClass::Static])
        );
        assert_eq!(
            classify("/index.PHP", &config),
            HashSet::from([RequestClass::Dynamic])
        );
        assert_eq!(
            classify("/wp-login.php?query=spam", &config),
            HashSet::from([
                RequestClass::Malicious,
                RequestClass::Dynamic,
                RequestClass::Spam,
            ])
        );
    }

    #[test]
    fn builds_redis_write_commands_for_codes_classes_and_expirations() {
        let config = test_config(Vec::new());
        let time = Local.with_ymd_and_hms(2026, 11, 21, 15, 7, 0).unwrap();
        let mut batch = HashMap::new();
        let mut data = RequestBatch::default();
        for url in ["/wp-login.php?spam", "/wp-login.php?spam", "/search"] {
            data.add(RecordedRequest {
                ip: "192.0.2.10".parse().unwrap(),
                vhost: "example.test".to_owned(),
                url: url.to_owned(),
                user_agent: "test-agent".to_owned(),
                status: 200,
            });
        }
        data.statuses.insert(418, 1);
        data.statuses.insert(429, 1);
        batch.insert("192.0.2.10".to_owned(), data);

        let commands = build_write_commands(&batch, time, &config);
        assert!(commands.contains(&vec![
            "ZINCRBY".to_owned(),
            "1507_hits".to_owned(),
            "3".to_owned(),
            "192.0.2.10".to_owned(),
        ]));
        assert!(commands.contains(&vec![
            "ZADD".to_owned(),
            "192.0.2.10_vhosts".to_owned(),
            time.timestamp().to_string(),
            "example.test".to_owned(),
        ]));
        assert!(commands.contains(&vec![
            "ZINCRBY".to_owned(),
            "daily_bycode_2026-11-21".to_owned(),
            "1".to_owned(),
            "418".to_owned(),
        ]));
        assert!(commands.contains(&vec![
            "ZINCRBY".to_owned(),
            "2026-11-21_15_429".to_owned(),
            "1".to_owned(),
            "192.0.2.10".to_owned(),
        ]));
        assert!(commands.contains(&vec![
            "HINCRBY".to_owned(),
            "1507_192.0.2.10_classes".to_owned(),
            "malicious".to_owned(),
            "2".to_owned(),
        ]));
        assert!(commands.contains(&vec![
            "HINCRBY".to_owned(),
            "1507_192.0.2.10_classes".to_owned(),
            "dynamic".to_owned(),
            "2".to_owned(),
        ]));
        assert!(commands.contains(&vec![
            "HINCRBY".to_owned(),
            "1507_192.0.2.10_classes".to_owned(),
            "spam".to_owned(),
            "2".to_owned(),
        ]));
        assert!(commands.contains(&vec![
            "HINCRBY".to_owned(),
            "1507_192.0.2.10_classes".to_owned(),
            "path".to_owned(),
            "1".to_owned(),
        ]));

        let expiration_commands = commands
            .iter()
            .filter(|command| command.first().is_some_and(|name| name == "EXPIRE"))
            .collect::<Vec<_>>();
        assert_eq!(expiration_commands.len(), 8);
        let keys = expiration_commands
            .iter()
            .map(|command| command[1].as_str())
            .collect::<HashSet<_>>();
        assert_eq!(keys.len(), expiration_commands.len());
        assert!(expiration_commands.iter().any(|command| {
            command[1] == "1507_hits" && command[2] == "600" && command[3] == "NX"
        }));
        assert!(expiration_commands.iter().any(|command| {
            command[1] == "daily_bycode_2026-11-21" && command[2] == "604800" && command[3] == "NX"
        }));
    }

    #[test]
    fn parses_nft_set_ips_ranges_and_prefixes() {
        let document = serde_json::json!({
            "nftables": [
                {"set": {"name": "allow", "elem": [
                    {"elem": {"val": "192.0.2.1"}},
                    {"elem": {"val": {"range": ["198.51.100.10", "198.51.100.20"]}}},
                    {"elem": {"val": {"prefix": {"addr": "2001:db8::", "len": 32}}}}
                ]}},
                {"set": {"name": "deny", "elem": [
                    {"elem": {"val": {"prefix": {"addr": "203.0.113.0", "len": 24}}}}
                ]}}
            ]
        });
        let members =
            parse_nft_members(&document, &["allow".to_owned()], &["deny".to_owned()]).unwrap();
        assert_eq!(members.allow.len(), 3);
        assert_eq!(members.deny.len(), 1);
        assert!(members.allow[0].contains("192.0.2.1".parse().unwrap()));
        assert!(members.allow[1].contains("198.51.100.15".parse().unwrap()));
        assert!(members.allow[2].contains("2001:db8:1::1".parse().unwrap()));
        assert!(members.deny[0].contains("203.0.113.45".parse().unwrap()));
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
                    spam: 0,
                    ..ClassCounts::default()
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
                    spam: 2,
                    ..ClassCounts::default()
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
                    spam: 0,
                    ..ClassCounts::default()
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
            true,
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            false,
            Vec::new(),
            Vec::new(),
            None,
        )
        .unwrap();
        let swarm = Swarm::new(config).unwrap();
        assert!(swarm.check("192.0.2.15".parse().unwrap()).await.is_none());
    }
}
