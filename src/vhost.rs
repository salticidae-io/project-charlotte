//! Loads and validates virtual hosts, matches hosts, and dispatches requests.

#[cfg(any(feature = "hosting", feature = "proxy"))]
use std::time::Duration;
use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::SocketAddr,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock,
        atomic::{AtomicU16, AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode, header::HOST};
use http_body::Body;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

#[cfg(feature = "acme")]
use crate::acme::AcmeManager;
#[cfg(feature = "hosting")]
use crate::cgroup::CgroupSpec;
#[cfg(feature = "hosting")]
use crate::config::FastCgiAddress;
#[cfg(feature = "proxy")]
use crate::forwarded::DirectPeer;
#[cfg(feature = "hosting")]
use crate::handler;
#[cfg(feature = "proxy")]
use crate::proxy::ReverseProxy;
use crate::{
    bot::{self, BotAction, BotPolicy, BotPolicyFile, BotState},
    config::{Config, TlsFiles},
    forwarded,
    ja4::TlsFingerprint,
    pathctx::PathContext,
    ratelimit::{RateLimit, RateLimiter},
    response::{self, ResponseBody},
    waf::{RuleIdSpec, Waf},
};

/// Master-side management of the worker processes that serve hosted sites.
#[cfg(feature = "hosting")]
mod hosted;
#[cfg(feature = "hosting")]
use hosted::*;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    vhost: Vec<VhostFile>,
    #[serde(default)]
    vhost_dir: Option<PathBuf>,
    #[serde(default)]
    options: Option<serde_yaml_ng::Value>,
}

// Every build accepts the same declarations, so that one built without a
// feature can say which feature a setting needs instead of calling it unknown.
#[cfg_attr(not(feature = "hosting"), allow(dead_code))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VhostFile {
    server_names: Vec<String>,
    root: Option<PathBuf>,
    user: Option<String>,
    group: Option<String>,
    #[serde(default, deserialize_with = "deserialize_index")]
    index: Option<Vec<String>>,
    listing: Option<bool>,
    try_files: Option<Vec<String>>,
    #[serde(default)]
    fastcgi: Vec<String>,
    #[serde(default)]
    cgi: Vec<String>,
    #[serde(default)]
    fastcgi_app: Vec<FastCgiAppFile>,
    fastcgi_timeout: Option<u64>,
    worker_threads: Option<usize>,
    worker_idle_timeout: Option<u64>,
    cgroup: Option<String>,
    cgroup_memory_max: Option<String>,
    cgroup_cpu_max: Option<String>,
    cgroup_pids_max: Option<String>,
    rate_limit: Option<String>,
    rate_limit_burst: Option<u32>,
    bot: Option<BotPolicyDeclarationFile>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    https_redirect: Option<bool>,
    #[serde(default)]
    default: bool,
    #[serde(default)]
    modsecurity_disable_rules: Vec<RuleIdFile>,
    modsecurity_block_status: Option<u16>,
    acme: Option<bool>,
    proxy_pass: Option<String>,
    proxy_preserve_host: Option<bool>,
    proxy_timeout: Option<u64>,
    proxy_ca_root: Option<PathBuf>,
    access_log: Option<PathBuf>,
    access_log_format: Option<String>,
    error_log: Option<PathBuf>,
    error_log_format: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum RuleIdFile {
    Integer(u64),
    RangeOrId(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum BotPolicyDeclarationFile {
    String(String),
    Policy(BotPolicyFile),
}

impl RuleIdFile {
    fn parse(&self) -> Result<RuleIdSpec, String> {
        match self {
            Self::Integer(id) => id.to_string().parse(),
            Self::RangeOrId(value) => value.parse(),
        }
    }
}

#[cfg_attr(not(feature = "hosting"), allow(dead_code))]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FastCgiAppFile {
    extension: String,
    command: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default, alias = "workers")]
    max_workers: Option<usize>,
    idle_timeout: Option<u64>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum IndexFile {
    String(String),
    List(Vec<String>),
}

fn deserialize_index<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(
        Option::<IndexFile>::deserialize(deserializer)?.map(|index| match index {
            IndexFile::String(name) => vec![name],
            IndexFile::List(names) => names,
        }),
    )
}

struct Vhost {
    names: Vec<String>,
    tls: Option<TlsFiles>,
    https_redirect: Option<bool>,
    #[cfg(feature = "acme")]
    acme: bool,
    default: bool,
    waf: Option<Waf>,
    rate_limit: VhostRateLimit,
    bot: VhostBot,
    access_log: Option<Arc<crate::logging::AccessLog>>,
    error_log: Arc<crate::logging::ErrorLog>,
    #[cfg(feature = "hosting")]
    worker: Option<Arc<Worker>>,
    #[cfg(feature = "proxy")]
    proxy: Option<Arc<ReverseProxy>>,
}

enum VhostRateLimit {
    Inherit,
    Off,
    Limit(Arc<RateLimiter>),
}

enum VhostBot {
    Inherit,
    Off,
    Policy(Arc<BotPolicy>),
}

pub(crate) struct Router {
    fallback: Arc<Config>,
    table: RwLock<Arc<VhostTable>>,
    sources: Mutex<SourceState>,
    dir: Option<PathBuf>,
    waf: Option<Waf>,
    rate_limit: Option<Arc<RateLimiter>>,
    bot: Option<Arc<BotPolicy>>,
    bot_state: Arc<BotState>,
    access_log: Option<Arc<crate::logging::AccessLog>>,
    error_log: Arc<crate::logging::ErrorLog>,
    https_port: AtomicU16,
    #[cfg(feature = "acme")]
    acme: Option<AcmeManager>,
}

pub(crate) enum ControlError {
    BadRequest(String),
    PayloadTooLarge,
    NotFound,
    Conflict(String),
    Unavailable(String),
    Internal(String),
}

struct VhostTable {
    vhosts: Vec<Arc<Vhost>>,
    default: Option<usize>,
}

struct SourceState {
    main_entries: Vec<VhostFile>,
    main_vhosts: Option<Vec<Arc<Vhost>>>,
    files: BTreeMap<PathBuf, LoadedSource>,
}

struct LoadedSource {
    content: String,
    entries: Vec<VhostFile>,
    vhosts: Vec<Arc<Vhost>>,
}

#[derive(Clone, Debug)]
pub(crate) struct TlsSni(pub Option<Arc<str>>);

impl Router {
    pub(crate) async fn load(
        fallback: Arc<Config>,
        path: Option<&PathBuf>,
        content: Option<String>,
        rate_limit: Option<Arc<RateLimiter>>,
        waf: Option<Waf>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let error_log = if let Some(log) = crate::logging::global_error_log() {
            log
        } else {
            let target = match fallback.error_log_file.as_deref() {
                Some(path) => crate::logging::open_log(path, "error")?,
                None => crate::logging::LogTarget::stderr(),
            };
            Arc::new(crate::logging::ErrorLog::new(
                target,
                crate::logging::ErrorFormat::parse(&fallback.error_log_format)?,
            ))
        };
        let access_log = if let Some(log) = crate::logging::global_access_log() {
            Some(log)
        } else {
            let target = match fallback.access_log_file.as_deref() {
                Some(path) => Some(crate::logging::open_log(path, "access")?),
                None if fallback.access_log => Some(crate::logging::LogTarget::stdout()),
                None => None,
            };
            target.map(|target| {
                Arc::new(crate::logging::AccessLog::new(
                    target,
                    crate::logging::AccessFormat::parse(&fallback.access_log_format)
                        .expect("validated access log format"),
                ))
            })
        };
        let bot = fallback
            .bot
            .clone()
            .map(BotPolicy::parse)
            .transpose()?
            .map(Arc::new);
        let bot_state = BotState::new().map_err(io::Error::other)?;
        let current_dir = std::env::current_dir()?;
        let config_dir = if let Some(path) = path {
            let config_dir = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."));
            if config_dir.is_absolute() {
                config_dir.to_path_buf()
            } else {
                current_dir.join(config_dir)
            }
        } else {
            current_dir.clone()
        };
        let file = if let Some(path) = path {
            // The master normally reads the file before dropping privileges,
            // because the unprivileged user may not be able to reach it.
            let content = match content {
                Some(content) => content,
                None => read_trusted_config(path)?,
            };
            parse_file_config(&content)?
        } else {
            FileConfig {
                vhost: Vec::new(),
                vhost_dir: None,
                options: None,
            }
        };
        let dir = fallback
            .vhost_dir
            .clone()
            .or_else(|| {
                file.vhost_dir
                    .clone()
                    .map(|dir| resolve_config_path(dir, &config_dir))
            })
            .map(|dir| resolve_config_path(dir, &current_dir));
        let mut router = Self::from_file(
            Arc::clone(&fallback),
            file,
            &config_dir,
            rate_limit,
            waf,
            bot,
            bot_state,
            access_log.clone(),
            Arc::clone(&error_log),
        )
        .await?;
        router.dir = dir;
        if router.dir.is_some() {
            router.reload_dir().await?;
        }
        Ok(router)
    }

    pub(crate) async fn reload_dir(&self) -> Result<bool, Box<dyn Error + Send + Sync>> {
        self.reload_dir_with(None, false).await
    }

    async fn reload_dir_with(
        &self,
        override_file: Option<(PathBuf, Option<String>)>,
        create_only: bool,
    ) -> Result<bool, Box<dyn Error + Send + Sync>> {
        let Some(dir) = &self.dir else {
            return Ok(false);
        };
        let mut sources = self.sources.lock().await;
        ensure_trusted_config(dir)?;
        let mut paths = scan_vhost_files(dir)?;
        if let Some((path, content)) = &override_file {
            if path.parent() != Some(dir.as_path()) {
                return Err("virtual-host override is outside the configured directory".into());
            }
            if content.is_some()
                && create_only
                && paths.iter().any(|candidate| {
                    candidate.file_stem().is_some() && candidate.file_stem() == path.file_stem()
                })
            {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "virtual host already exists",
                )
                .into());
            }
            if content.is_none() && !paths.contains(path) {
                return Err(
                    io::Error::new(io::ErrorKind::NotFound, "virtual host not found").into(),
                );
            }
            if content.is_some() && !paths.contains(path) {
                paths.push(path.clone());
                paths.sort();
            } else if content.is_none() {
                paths.retain(|candidate| candidate != path);
            }
        }
        let mut candidates = Vec::with_capacity(paths.len());
        for path in paths {
            let content = if let Some((override_path, Some(content))) = &override_file
                && override_path == &path
            {
                content.clone()
            } else {
                read_trusted_config(&path)?
            };
            let old = sources.files.get(&path);
            let entries = if old.is_some_and(|source| source.content == content) {
                old.expect("checked source exists").entries.clone()
            } else {
                let file = parse_file_config(&content)?;
                if file.options.is_some() {
                    return Err(format!(
                        "{}: options are only allowed in the main config file",
                        path.display()
                    )
                    .into());
                }
                file.vhost
            };
            candidates.push((path, content, entries));
        }

        let all_entries = sources
            .main_entries
            .iter()
            .chain(candidates.iter().flat_map(|(_, _, entries)| entries));
        validate_vhost_declarations(all_entries.clone())?;
        validate_vhost_waf_declarations(all_entries, self.waf.is_some())?;

        let mut changed = sources.main_vhosts.is_none()
            || sources.files.len() != candidates.len()
            || candidates.iter().any(|(path, content, _)| {
                sources
                    .files
                    .get(path)
                    .is_none_or(|source| source.content != *content)
            });
        let main_vhosts = match &sources.main_vhosts {
            Some(vhosts) => vhosts.clone(),
            None => {
                let file = FileConfig {
                    vhost: sources.main_entries.clone(),
                    vhost_dir: None,
                    options: None,
                };
                let router = Self::from_file(
                    Arc::clone(&self.fallback),
                    file,
                    &std::env::current_dir()?,
                    self.rate_limit.clone(),
                    self.waf,
                    self.bot.clone(),
                    Arc::clone(&self.bot_state),
                    self.access_log.clone(),
                    Arc::clone(&self.error_log),
                )
                .await?;
                router.snapshot().vhosts.clone()
            }
        };

        let mut loaded = BTreeMap::new();
        for (path, content, entries) in candidates {
            if let Some(old) = sources.files.get(&path)
                && old.content == content
            {
                loaded.insert(
                    path,
                    LoadedSource {
                        content,
                        entries,
                        vhosts: old.vhosts.clone(),
                    },
                );
                continue;
            }
            let config_dir = path.parent().unwrap_or(dir);
            let mut vhosts = Vec::with_capacity(entries.len());
            for entry in &entries {
                let router = Self::from_file(
                    Arc::clone(&self.fallback),
                    FileConfig {
                        vhost: vec![entry.clone()],
                        vhost_dir: None,
                        options: None,
                    },
                    config_dir,
                    self.rate_limit.clone(),
                    self.waf,
                    self.bot.clone(),
                    Arc::clone(&self.bot_state),
                    self.access_log.clone(),
                    Arc::clone(&self.error_log),
                )
                .await?;
                vhosts.extend(router.snapshot().vhosts.iter().cloned());
            }
            loaded.insert(
                path,
                LoadedSource {
                    content,
                    entries,
                    vhosts,
                },
            );
        }

        let mut vhosts = main_vhosts.clone();
        for source in loaded.values() {
            vhosts.extend(source.vhosts.iter().cloned());
        }
        #[cfg(all(feature = "acme", feature = "hosting"))]
        if let Some(acme) = &self.acme {
            ensure_acme_cache_is_private(acme.cache_dir(), &vhosts)?;
        }
        let default = vhosts.iter().position(|vhost| vhost.default);
        let new_table = Arc::new(VhostTable { vhosts, default });
        if !changed {
            changed = new_table.vhosts.len() != self.snapshot().vhosts.len();
        }
        if let Some((path, content)) = &override_file {
            match content {
                Some(content) => persist_vhost_file(dir, path, content)?,
                None => match std::fs::metadata(path)
                    .path_context("inspect virtual-host config", path)
                {
                    Ok(_) => {
                        std::fs::remove_file(path)
                            .path_context("remove virtual-host config", path)?;
                        std::fs::File::open(dir)
                            .path_context("open virtual-host directory", dir)?
                            .sync_all()
                            .path_context("sync virtual-host directory", dir)?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                },
            }
        }
        sources.main_vhosts = Some(main_vhosts);
        sources.files = loaded;
        if changed {
            *self
                .table
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = new_table;
        }
        Ok(changed)
    }

    pub(crate) async fn control_list(&self) -> Vec<serde_json::Value> {
        let sources = self.sources.lock().await;
        let mut vhosts = Vec::new();
        let config_file = self
            .fallback
            .config_file
            .as_ref()
            .map_or_else(|| "config".to_owned(), |path| path.display().to_string());
        for (index, entry) in sources.main_entries.iter().enumerate() {
            let name = entry
                .server_names
                .first()
                .cloned()
                .unwrap_or_else(|| format!("config-{}", index + 1));
            vhosts.push(serde_json::json!({
                "name": name,
                "file": config_file,
                "server_names": entry.server_names,
                "source": "config",
                "read_only": true,
            }));
        }
        for (path, source) in &sources.files {
            let name = path
                .file_stem()
                .map_or_else(String::new, |stem| stem.to_string_lossy().into_owned());
            let server_names = source
                .entries
                .iter()
                .flat_map(|entry| entry.server_names.iter().cloned())
                .collect::<Vec<_>>();
            vhosts.push(serde_json::json!({
                "name": name,
                "file": path.display().to_string(),
                "server_names": server_names,
                "source": "vhost_dir",
                "read_only": false,
            }));
        }
        vhosts
    }

    pub(crate) async fn control_get(&self, name: &str) -> Result<serde_json::Value, ControlError> {
        if !valid_control_name(name) {
            return Err(ControlError::BadRequest(
                "invalid virtual-host name".to_owned(),
            ));
        }
        let sources = self.sources.lock().await;
        let source = sources
            .files
            .iter()
            .find(|(path, _)| {
                path.extension().is_some_and(|extension| extension == "yml")
                    && path
                        .file_stem()
                        .is_some_and(|stem| stem.to_string_lossy() == name)
            })
            .or_else(|| {
                sources.files.iter().find(|(path, _)| {
                    path.file_stem()
                        .is_some_and(|stem| stem.to_string_lossy() == name)
                })
            });
        if let Some((path, source)) = source {
            let entries = source
                .entries
                .iter()
                .map(serde_json::to_value)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| ControlError::Internal(error.to_string()))?;
            return Ok(serde_json::json!({
                "name": name,
                "file": path.display().to_string(),
                "source": "vhost_dir",
                "read_only": false,
                "vhost": entries,
            }));
        }
        if let Some((index, entry)) = sources.main_entries.iter().enumerate().find(|(_, entry)| {
            entry
                .server_names
                .first()
                .is_some_and(|primary| primary == name)
        }) {
            let entry = serde_json::to_value(entry)
                .map_err(|error| ControlError::Internal(error.to_string()))?;
            let file = self
                .fallback
                .config_file
                .as_ref()
                .map_or_else(|| "config".to_owned(), |path| path.display().to_string());
            return Ok(serde_json::json!({
                "name": sources.main_entries[index].server_names.first(),
                "file": file,
                "source": "config",
                "read_only": true,
                "vhost": [entry],
            }));
        }
        Err(ControlError::NotFound)
    }

    pub(crate) async fn control_put(
        &self,
        name: &str,
        value: serde_yaml_ng::Value,
        create_only: bool,
    ) -> Result<(), ControlError> {
        let dir = self.dir.as_ref().ok_or_else(|| {
            ControlError::Unavailable("no vhost directory is configured".to_owned())
        })?;
        if !valid_control_name(name) {
            return Err(ControlError::BadRequest(
                "invalid virtual-host name".to_owned(),
            ));
        }
        let content = render_control_vhost(value)
            .map_err(|error| ControlError::BadRequest(error.to_string()))?;
        if self.is_read_only_main_vhost(name).await {
            return Err(ControlError::Conflict(
                "virtual hosts in the main configuration are read-only".to_owned(),
            ));
        }
        let yaml_path = dir.join(format!("{name}.yaml"));
        let yml_path = dir.join(format!("{name}.yml"));
        let exists = yaml_path.exists() || yml_path.exists();
        if create_only && exists {
            return Err(ControlError::Conflict(
                "virtual host already exists".to_owned(),
            ));
        }
        let path = if yml_path.exists() {
            yml_path
        } else {
            yaml_path
        };
        self.reload_dir_with(Some((path, Some(content))), create_only)
            .await
            .map_err(control_reload_error)?;
        Ok(())
    }

    pub(crate) async fn control_delete(&self, name: &str) -> Result<(), ControlError> {
        let dir = self.dir.as_ref().ok_or_else(|| {
            ControlError::Unavailable("no vhost directory is configured".to_owned())
        })?;
        if !valid_control_name(name) {
            return Err(ControlError::BadRequest(
                "invalid virtual-host name".to_owned(),
            ));
        }
        if self.is_read_only_main_vhost(name).await {
            return Err(ControlError::Conflict(
                "virtual hosts in the main configuration are read-only".to_owned(),
            ));
        }
        let yaml_path = dir.join(format!("{name}.yaml"));
        let yml_path = dir.join(format!("{name}.yml"));
        let path = if yml_path.exists() {
            yml_path
        } else if yaml_path.exists() {
            yaml_path
        } else {
            return Err(ControlError::NotFound);
        };
        self.reload_dir_with(Some((path, None)), false)
            .await
            .map_err(control_reload_error)?;
        Ok(())
    }

    async fn is_read_only_main_vhost(&self, name: &str) -> bool {
        let sources = self.sources.lock().await;
        sources.main_entries.iter().any(|entry| {
            entry
                .server_names
                .first()
                .is_some_and(|primary| primary == name)
        })
    }

    pub(crate) fn control_vhost_count(&self) -> usize {
        self.snapshot().vhosts.len()
    }

    fn snapshot(&self) -> Arc<VhostTable> {
        Arc::clone(
            &self
                .table
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    // A build with neither hosting nor proxying refuses every declaration
    // before it reaches the loop below, which then has nothing to construct.
    #[cfg_attr(
        not(any(feature = "hosting", feature = "proxy")),
        allow(unused_mut, unused_variables)
    )]
    async fn from_file(
        fallback: Arc<Config>,
        file: FileConfig,
        config_dir: &Path,
        rate_limit: Option<Arc<RateLimiter>>,
        waf: Option<Waf>,
        bot: Option<Arc<BotPolicy>>,
        bot_state: Arc<BotState>,
        global_access_log: Option<Arc<crate::logging::AccessLog>>,
        global_error_log: Arc<crate::logging::ErrorLog>,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        validate_vhost_declarations(&file.vhost)?;
        validate_vhost_waf_declarations(&file.vhost, waf.is_some())?;
        let main_entries = file.vhost.clone();
        let process_dir = std::env::current_dir()?;
        let mut vhosts = Vec::with_capacity(file.vhost.len());
        let default = file.vhost.iter().position(|entry| entry.default);

        for mut entry in file.vhost {
            let access_target = match entry.access_log.take() {
                Some(path) => Some(crate::logging::open_log(
                    &resolve_config_path(path, config_dir),
                    "access",
                )?),
                None => global_access_log.as_ref().map(|log| log.target()),
            };
            let access_format = crate::logging::AccessFormat::parse(
                entry
                    .access_log_format
                    .as_deref()
                    .unwrap_or(&fallback.access_log_format),
            )?;
            let access_log = access_target
                .map(|target| Arc::new(crate::logging::AccessLog::new(target, access_format)));
            let default_error_log_file = fallback.error_log_file.as_ref().map(|path| {
                if path.is_absolute() {
                    path.clone()
                } else {
                    process_dir.join(path)
                }
            });
            let error_log_file = entry
                .error_log
                .take()
                .map(|path| resolve_config_path(path, config_dir))
                .or(default_error_log_file);
            let error_target = match error_log_file.as_deref() {
                Some(path) => crate::logging::open_log(path, "error")?,
                None => global_error_log.target(),
            };
            let error_log_format = entry
                .error_log_format
                .take()
                .unwrap_or_else(|| fallback.error_log_format.clone());
            let error_format = crate::logging::ErrorFormat::parse(&error_log_format)?;
            let error_log = Arc::new(crate::logging::ErrorLog::new(error_target, error_format));
            let vhost_rate_limit = match entry.rate_limit.as_deref() {
                None => VhostRateLimit::Inherit,
                Some("off") => VhostRateLimit::Off,
                Some(rate) => VhostRateLimit::Limit(Arc::new(RateLimiter::new(RateLimit::parse(
                    rate,
                    entry.rate_limit_burst,
                )?))),
            };
            let vhost_bot = match entry.bot.take() {
                None => VhostBot::Inherit,
                Some(BotPolicyDeclarationFile::String(value)) if value == "off" => VhostBot::Off,
                Some(BotPolicyDeclarationFile::String(value)) => {
                    return Err(format!(
                        "vhost bot setting must be `off` or a policy map: {value}"
                    )
                    .into());
                }
                Some(BotPolicyDeclarationFile::Policy(policy)) => {
                    VhostBot::Policy(Arc::new(BotPolicy::parse(policy)?))
                }
            };
            let block_status = entry
                .modsecurity_block_status
                .or(fallback.modsecurity_block_status)
                .map(|status| {
                    http::StatusCode::from_u16(status).expect("validated ModSecurity block status")
                });
            let disabled_rules = entry
                .modsecurity_disable_rules
                .iter()
                .map(RuleIdFile::parse)
                .collect::<Result<Vec<_>, _>>()
                .map_err(io::Error::other)?;
            let vhost_waf = if disabled_rules.is_empty() {
                waf
            } else {
                Some(
                    waf.expect("non-empty rule exclusions require a global WAF")
                        .without_rules(&disabled_rules)?,
                )
            };
            let vhost_waf = vhost_waf.map(|waf| waf.with_block_status(block_status));
            let mut normalized_names = Vec::with_capacity(entry.server_names.len());
            for name in &entry.server_names {
                let normalized = normalize_server_name(name)
                    .ok_or_else(|| format!("invalid virtual host name: {name}"))?;
                normalized_names.push(normalized);
            }

            let tls = match (entry.tls_cert.take(), entry.tls_key.take()) {
                (Some(cert), Some(key)) => Some(TlsFiles {
                    cert: resolve_config_path(cert, config_dir),
                    key: resolve_config_path(key, config_dir),
                }),
                (None, None) => None,
                _ => return Err("vhost tls_cert and tls_key must be supplied together".into()),
            };

            #[cfg(feature = "proxy")]
            if let Some(upstream) = entry.proxy_pass.take() {
                let ca_root = entry
                    .proxy_ca_root
                    .take()
                    .map(|path| resolve_config_path(path, config_dir));
                let proxy = Arc::new(ReverseProxy::new(
                    &upstream,
                    entry.proxy_preserve_host.unwrap_or(true),
                    Duration::from_secs(entry.proxy_timeout.unwrap_or(60)),
                    ca_root.as_deref(),
                )?);
                vhosts.push(Vhost {
                    names: normalized_names,
                    tls,
                    https_redirect: entry.https_redirect,
                    #[cfg(feature = "acme")]
                    acme: entry.acme.unwrap_or(true),
                    default: entry.default,
                    waf: vhost_waf,
                    rate_limit: vhost_rate_limit,
                    bot: vhost_bot,
                    access_log: access_log.clone(),
                    error_log: Arc::clone(&error_log),
                    #[cfg(feature = "hosting")]
                    worker: None,
                    #[cfg(feature = "proxy")]
                    proxy: Some(proxy),
                });
                continue;
            }

            #[cfg(feature = "hosting")]
            {
                let user = entry
                    .user
                    .as_deref()
                    .ok_or("vhost user is required unless proxy_pass is configured")?;
                let (uid, gid) = resolve_identity(user, entry.group.as_deref())?;
                if uid == 0 {
                    // A worker exists to confine a site to an unprivileged
                    // account; one running as root confines nothing.
                    return Err(format!("virtual host user must not be root: {user}").into());
                }
                validate_worker_identity(uid, gid)?;
                let worker_cgroup = cgroup_for_vhost(
                    &entry,
                    &fallback,
                    uid,
                    gid,
                    normalized_names.first().map_or("", String::as_str),
                )?;
                let index_names = entry.index.unwrap_or_else(|| fallback.index.clone());
                validate_index(&index_names)?;
                let listing = entry.listing.unwrap_or(fallback.listing);
                let try_files = entry
                    .try_files
                    .unwrap_or_else(|| fallback.try_files.clone());
                crate::config::validate_try_files(&try_files)
                    .map_err(|error| format!("vhost try_files: {error}"))?;
                let mut fastcgi = entry
                    .fastcgi
                    .iter()
                    .map(|value| crate::config::parse_fastcgi_backend(value))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut extensions = std::collections::HashSet::new();
                for backend in &fastcgi {
                    if !extensions.insert(backend.extension.clone()) {
                        return Err(format!(
                            "duplicate backend extension in vhost: {}",
                            backend.extension
                        )
                        .into());
                    }
                }
                for value in &entry.cgi {
                    let backend = crate::config::parse_cgi_backend(value)?;
                    if !extensions.insert(backend.extension.clone()) {
                        return Err(format!(
                            "duplicate backend extension in vhost: {}",
                            backend.extension
                        )
                        .into());
                    }
                    fastcgi.push(backend);
                }
                for app_file in entry.fastcgi_app {
                    let Some(program) = app_file.command.first() else {
                        return Err(format!(
                            "vhost FastCGI app .{} command must not be empty",
                            app_file.extension
                        )
                        .into());
                    };
                    let extension = crate::config::normalize_extension(&app_file.extension)?;
                    if !extensions.insert(extension.clone()) {
                        return Err(
                            format!("duplicate backend extension in vhost: {extension}").into()
                        );
                    }
                    if app_file.command.iter().any(|part| part.contains('\0')) {
                        return Err("vhost FastCGI app command cannot contain NUL".into());
                    }
                    let max_workers = app_file.max_workers.unwrap_or(1);
                    crate::config::parse_fastcgi_app_max_workers(&max_workers.to_string())
                        .map_err(|error| format!("vhost FastCGI app .{extension}: {error}"))?;
                    let idle_timeout = app_file
                        .idle_timeout
                        .map_or(
                            Ok(Duration::from_secs(
                                crate::config::DEFAULT_FASTCGI_APP_IDLE_TIMEOUT_SECS,
                            )),
                            |seconds| {
                                crate::config::parse_fastcgi_app_idle_timeout(&seconds.to_string())
                            },
                        )
                        .map_err(|error| format!("vhost FastCGI app .{extension}: {error}"))?;
                    for (key, value) in &app_file.env {
                        crate::config::validate_env_key(key)?;
                        if value.contains('\0') {
                            return Err(
                                "vhost FastCGI app environment value cannot contain NUL".into()
                            );
                        }
                    }
                    let mut backend =
                        crate::config::parse_fastcgi_app(&format!("{extension}={program}"))?;
                    if let FastCgiAddress::Spawn(app) = &mut backend.address {
                        app.args = app_file.command.into_iter().skip(1).collect();
                        app.env = app_file.env;
                        app.max_workers = max_workers;
                        app.idle_timeout = idle_timeout;
                    }
                    fastcgi.push(backend);
                }
                let fastcgi = fastcgi
                    .into_iter()
                    .map(|mut backend| {
                        if let FastCgiAddress::Unix(path) = &mut backend.address
                            && path.is_relative()
                        {
                            *path = config_dir.join(&*path);
                        }
                        if let FastCgiAddress::Cgi(Some(interpreter)) = &mut backend.address
                            && interpreter.is_relative()
                        {
                            *interpreter = config_dir.join(&*interpreter);
                        }
                        backend
                    })
                    .collect();
                let timeout_seconds = entry
                    .fastcgi_timeout
                    .unwrap_or(fallback.fastcgi_timeout.as_secs());
                if timeout_seconds == 0 {
                    return Err("vhost FastCGI timeout must be greater than zero".into());
                }
                let threads = match entry.worker_threads {
                    Some(threads) => crate::config::parse_thread_count(&threads.to_string())
                        .map_err(|error| format!("vhost worker_threads: {error}"))?,
                    None => fallback.worker_threads,
                };
                let root = entry
                    .root
                    .take()
                    .ok_or("vhost root is required unless proxy_pass is configured")?;
                let root = if root.is_absolute() {
                    root
                } else {
                    config_dir.join(root)
                };
                check_vhost_root(&root)?;
                let idle_timeout = entry
                    .worker_idle_timeout
                    .map_or(fallback.worker_idle_timeout, Duration::from_secs);
                let worker = Arc::new(Worker {
                    uid,
                    gid,
                    root,
                    cgroup: worker_cgroup,
                    idle_timeout: (idle_timeout != Duration::ZERO).then_some(idle_timeout),
                    active: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    last_used: Arc::new(std::sync::Mutex::new(std::time::Instant::now())),
                    index: index_names,
                    listing,
                    try_files,
                    fastcgi,
                    fastcgi_timeout: Duration::from_secs(timeout_seconds),
                    threads,
                    error_log_file,
                    error_log_format,
                    process: Mutex::new(None),
                });
                if let Some(timeout) = worker.idle_timeout {
                    Worker::spawn_idle_reaper(&worker, timeout);
                }
                vhosts.push(Vhost {
                    names: normalized_names,
                    tls,
                    https_redirect: entry.https_redirect,
                    #[cfg(feature = "acme")]
                    acme: entry.acme.unwrap_or(true),
                    default: entry.default,
                    waf: vhost_waf,
                    rate_limit: vhost_rate_limit,
                    bot: vhost_bot,
                    access_log,
                    error_log,
                    #[cfg(feature = "hosting")]
                    worker: Some(worker),
                    #[cfg(feature = "proxy")]
                    proxy: None,
                });
            }
        }

        let vhosts = vhosts.into_iter().map(Arc::new).collect::<Vec<_>>();
        Ok(Self {
            fallback,
            table: RwLock::new(Arc::new(VhostTable {
                vhosts: vhosts.clone(),
                default,
            })),
            sources: Mutex::new(SourceState {
                main_entries,
                main_vhosts: Some(vhosts),
                files: BTreeMap::new(),
            }),
            dir: None,
            waf,
            rate_limit,
            bot,
            bot_state,
            access_log: global_access_log,
            error_log: global_error_log,
            https_port: AtomicU16::new(0),
            #[cfg(feature = "acme")]
            acme: None,
        })
    }

    #[cfg(feature = "acme")]
    pub(crate) fn acme_names(&self) -> Vec<String> {
        self.snapshot()
            .vhosts
            .iter()
            .filter(|vhost| vhost.acme && vhost.tls.is_none())
            .flat_map(|vhost| vhost.names.iter())
            .filter(|name| !name.starts_with("*."))
            .cloned()
            .collect()
    }

    #[cfg(feature = "acme")]
    pub(crate) fn document_roots(&self) -> Vec<PathBuf> {
        let table = self.snapshot();
        #[cfg(feature = "hosting")]
        {
            std::iter::once(self.fallback.root.clone())
                .chain(
                    table.vhosts.iter().filter_map(|vhost| {
                        vhost.worker.as_ref().map(|worker| worker.root.clone())
                    }),
                )
                .collect()
        }
        #[cfg(not(feature = "hosting"))]
        {
            let _ = table;
            Vec::new()
        }
    }

    #[cfg(feature = "acme")]
    pub(crate) fn set_acme_manager(&mut self, acme: Option<AcmeManager>) {
        self.acme = acme;
    }

    #[cfg(feature = "acme")]
    pub(crate) fn acme_manager(&self) -> Option<&AcmeManager> {
        self.acme.as_ref()
    }

    pub(crate) fn vhost_dir(&self) -> Option<PathBuf> {
        self.dir.clone()
    }

    pub(crate) fn set_https_port(&self, port: u16) {
        self.https_port.store(port, Ordering::Relaxed);
    }

    pub(crate) async fn dispatch<B>(
        &self,
        request: Request<B>,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Response<ResponseBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let mut request = request;
        let (client, trusted_chain) =
            forwarded::resolve(peer, request.headers(), &self.fallback.trusted_proxies);
        forwarded::sanitize(request.headers_mut(), trusted_chain.as_deref());
        #[cfg(feature = "proxy")]
        request.extensions_mut().insert(DirectPeer(peer));
        // Routing follows the authority of an absolute request target (or of
        // HTTP/2's `:authority`) in preference to `Host`. Make the header agree
        // before anything inspects it, so that the WAF and the backend see the
        // host the request is actually routed to.
        if let Some(authority) = request.uri().authority()
            && let Ok(value) = HeaderValue::from_str(authority.as_str())
        {
            request.headers_mut().insert(HOST, value);
        }
        let table = self.snapshot();
        let host = request_host(&request);
        let selected = host
            .as_deref()
            .and_then(|host| Self::select_vhost(&table, host))
            .or(table.default);
        let vhost = selected.map(|index| &table.vhosts[index]);
        let server_name = vhost
            .and_then(|vhost| vhost.names.first())
            .cloned()
            .or_else(|| host.clone())
            .unwrap_or_default();
        let error_log = vhost.map_or_else(
            || Arc::clone(&self.error_log),
            |vhost| Arc::clone(&vhost.error_log),
        );
        let access_log =
            vhost.map_or_else(|| self.access_log.clone(), |vhost| vhost.access_log.clone());
        let received = access_log
            .as_ref()
            .map(|_| Arc::new(std::sync::atomic::AtomicU64::new(0)));
        let access_request = received
            .as_ref()
            .map(|received| crate::logging::AccessRequest {
                method: request.method().clone(),
                path: request
                    .uri()
                    .path_and_query()
                    .map_or("/", |value| value.as_str())
                    .to_owned(),
                version: request.version(),
                client,
                peer,
                local,
                server_name: server_name.clone(),
                ja4: request
                    .extensions()
                    .get::<TlsFingerprint>()
                    .map_or_else(|| "-".to_owned(), |fingerprint| fingerprint.0.ja4.clone()),
                headers: request.headers().clone(),
                received: Arc::clone(received),
                started: std::time::SystemTime::now(),
            });
        let request = request.map(|body| crate::logging::CountedBody::new(body, received));
        let context = crate::logging::RequestContext {
            client: Some(client),
            local: Some(local),
            server_name,
            error_log: Some(error_log),
        };
        let response = crate::logging::with_request_context(
            context,
            self.dispatch_inner(request, client, local, table, host, selected),
        )
        .await;
        if let (Some(log), Some(access_request)) = (access_log, access_request) {
            let (parts, body) = response.into_parts();
            let access_response = crate::logging::AccessResponse {
                status: parts.status.as_u16(),
                version: parts.version,
                headers: parts.headers.clone(),
            };
            let body = crate::logging::LoggedBody::new(body, log, access_request, access_response)
                .boxed_unsync();
            Response::from_parts(parts, body)
        } else {
            response
        }
    }

    async fn dispatch_inner<B>(
        &self,
        request: Request<B>,
        peer: SocketAddr,
        local: SocketAddr,
        table: Arc<VhostTable>,
        host: Option<String>,
        selected: Option<usize>,
    ) -> Response<ResponseBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        self.bot_state.record_request();
        let host = host.as_deref();
        let https_port = self.https_port.load(Ordering::Relaxed);
        #[cfg(feature = "acme")]
        if let Some(acme) = &self.acme {
            if request.method() == http::Method::GET
                && let Some(host) = host
                && let Some(body) = acme.challenge_response(host, request.uri().path()).await
            {
                return response::text_response(StatusCode::OK, body);
            }
            if request.extensions().get::<TlsSni>().is_none()
                && let Some(host) = host
            {
                acme.maybe_provision(host);
            }
        }
        if request.extensions().get::<TlsSni>().is_none()
            && https_port != 0
            && let Some(index) = selected
            && let Some(vhost) = table.vhosts.get(index)
            && vhost.https_redirect.unwrap_or(self.fallback.https_redirect)
            && let Some(host) = host
            && (vhost.tls.is_some() || {
                #[cfg(feature = "acme")]
                {
                    self.acme
                        .as_ref()
                        .is_some_and(|acme| acme.certificate_store().get(host).is_some())
                }
                #[cfg(not(feature = "acme"))]
                {
                    false
                }
            })
        {
            let path_and_query = request
                .uri()
                .path_and_query()
                .map_or("/", |value| value.as_str());
            let location = https_redirect_location(host, https_port, path_and_query);
            if http::HeaderValue::from_str(&location).is_ok() {
                let status = if matches!(request.method(), &http::Method::GET | &http::Method::HEAD)
                {
                    StatusCode::MOVED_PERMANENTLY
                } else {
                    StatusCode::PERMANENT_REDIRECT
                };
                return response::redirect_response(status, location);
            }
        }
        let rate_limit = match selected {
            Some(index) => match &table.vhosts[index].rate_limit {
                VhostRateLimit::Inherit => self.rate_limit.as_ref(),
                VhostRateLimit::Off => None,
                VhostRateLimit::Limit(rate_limit) => Some(rate_limit),
            },
            None => self.rate_limit.as_ref(),
        };
        if let Some(rate_limit) = rate_limit
            && let Err(retry_after) = rate_limit.check(peer.ip())
        {
            return crate::ratelimit::too_many_requests(retry_after);
        }
        let bot_policy = match selected {
            Some(index) => match &table.vhosts[index].bot {
                VhostBot::Inherit => self.bot.as_ref(),
                VhostBot::Off => None,
                VhostBot::Policy(policy) => Some(policy),
            },
            None => self.bot.as_ref(),
        };
        if let Some(policy) = bot_policy {
            let tls = request.extensions().get::<TlsSni>().is_some();
            if request.uri().path() == bot::CHALLENGE_PATH {
                if request.method() != http::Method::GET {
                    return response::error_response(
                        StatusCode::FORBIDDEN,
                        "Invalid bot challenge\n",
                    );
                }
                let (difficulty, ttl) = policy.challenge_parameters();
                return response::bot_response(
                    self.bot_state
                        .solve_challenge(&request, peer, tls, difficulty, ttl),
                );
            }
            let fingerprint = request
                .extensions()
                .get::<TlsFingerprint>()
                .map(|fingerprint| fingerprint.0.as_ref());
            let verdict = bot::evaluate(policy, &self.bot_state, &request, peer, fingerprint).await;
            if verdict.action != BotAction::Allow {
                crate::log_error!(
                    "bot detection: client={peer} score={} action={:?} reasons={:?}",
                    verdict.score,
                    verdict.action,
                    verdict.reasons
                );
            }
            match verdict.action {
                BotAction::Allow | BotAction::Log => {}
                BotAction::Block => {
                    return response::error_response(StatusCode::FORBIDDEN, "Forbidden\n");
                }
                BotAction::Challenge
                    if self
                        .bot_state
                        .has_valid_cookie(request.headers(), peer.ip()) => {}
                BotAction::Challenge => {
                    let (difficulty, ttl) = policy.challenge_parameters();
                    return response::bot_response(
                        self.bot_state.challenge(&request, peer, difficulty, ttl),
                    );
                }
            }
        }
        let waf = selected
            .and_then(|index| table.vhosts[index].waf)
            .or(self.waf);
        if let Some(waf) = waf {
            return waf
                .inspect(request, peer, local, |request| {
                    self.route(request, host, peer, local, &table)
                })
                .await;
        }
        self.route(request, host, peer, local, &table).await
    }

    pub(crate) fn sni_certificates(&self) -> (Vec<(String, TlsFiles)>, Option<TlsFiles>) {
        let table = self.snapshot();
        let entries = table
            .vhosts
            .iter()
            .filter_map(|vhost| {
                vhost.tls.as_ref().map(|tls| {
                    vhost
                        .names
                        .iter()
                        .cloned()
                        .map(|name| (name, tls.clone()))
                        .collect::<Vec<_>>()
                })
            })
            .flatten()
            .collect();
        let fallback = table
            .default
            .and_then(|index| table.vhosts[index].tls.clone());
        (entries, fallback)
    }

    #[cfg_attr(not(feature = "hosting"), allow(unused_variables))]
    async fn route<B>(
        &self,
        request: Request<B>,
        host: Option<&str>,
        peer: SocketAddr,
        local: SocketAddr,
        table: &VhostTable,
    ) -> Response<ResponseBody>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Box<dyn Error + Send + Sync>>,
    {
        let index = match select_route(table, &request, host) {
            Ok(Some(index)) => index,
            Ok(None) => {
                #[cfg(feature = "hosting")]
                return handler::handle_request(request, Arc::clone(&self.fallback), peer, local)
                    .await;
                // Without hosting there is no fallback site to serve.
                #[cfg(not(feature = "hosting"))]
                return response::error_response(StatusCode::NOT_FOUND, "Not found\n");
            }
            Err((status, message)) => return response::error_response(status, message),
        };
        let vhost = &table.vhosts[index];
        #[cfg(feature = "proxy")]
        if let Some(proxy) = &vhost.proxy {
            let tls = request.extensions().get::<TlsSni>().is_some();
            let direct_peer = request
                .extensions()
                .get::<DirectPeer>()
                .map_or(peer, |direct_peer| direct_peer.0);
            let response = proxy.forward(request, direct_peer, tls).await;
            let (parts, body) = response.into_parts();
            return Response::from_parts(parts, response::coalesce_ready_body(body));
        }
        #[cfg(feature = "hosting")]
        if let Some(worker) = &vhost.worker {
            return worker.forward(request, host, peer, local).await;
        }
        // Loading refuses a virtual host that this build cannot serve.
        response::error_response(StatusCode::NOT_FOUND, "Not found\n")
    }

    fn select_vhost(table: &VhostTable, host: &str) -> Option<usize> {
        table
            .vhosts
            .iter()
            .enumerate()
            .filter_map(|(index, vhost)| {
                vhost
                    .names
                    .iter()
                    .filter_map(|name| match_score(name, host))
                    .max()
                    .map(|score| (index, score))
            })
            .max_by_key(|(_, score)| *score)
            .map(|(index, _)| index)
    }
}

/// A request that routing refuses, as the status and body of its response.
type Rejection = (StatusCode, &'static str);

/// Chooses the virtual host for a request, or `None` for the fallback site.
///
/// A request that arrived over TLS is refused when its authority selects a
/// different virtual host than the server name the connection was
/// established for.
fn select_route<B>(
    table: &VhostTable,
    request: &Request<B>,
    host: Option<&str>,
) -> Result<Option<usize>, Rejection> {
    if let (Some(TlsSni(Some(sni))), Some(host)) = (request.extensions().get::<TlsSni>(), host) {
        let sni_selected = normalize_host(sni)
            .as_deref()
            .and_then(|sni| Router::select_vhost(table, sni))
            .or(table.default);
        let host_selected = Router::select_vhost(table, host).or(table.default);
        if sni_selected != host_selected {
            return Err((
                StatusCode::MISDIRECTED_REQUEST,
                "Request authority does not match TLS server name\n",
            ));
        }
    }
    Ok(host
        .and_then(|host| Router::select_vhost(table, host))
        .or(table.default))
}

#[cfg(feature = "hosting")]
fn request_authority<B>(request: &Request<B>) -> Option<String> {
    request
        .uri()
        .authority()
        .map(ToString::to_string)
        .or_else(|| {
            request
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
}

fn request_host<B>(request: &Request<B>) -> Option<String> {
    let host_authority = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<http::uri::Authority>().ok());
    let authority = request.uri().authority().or(host_authority.as_ref())?;
    normalize_host(authority.host())
}

fn https_redirect_location(host: &str, port: u16, path_and_query: &str) -> String {
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let authority = if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    };
    format!("https://{authority}{path_and_query}")
}

pub(crate) fn normalize_host(value: &str) -> Option<String> {
    let host = value.trim().trim_end_matches('.');
    if host.is_empty()
        || host
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte == b'/' || byte == b'\\' || byte == 0)
    {
        return None;
    }
    Some(
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase(),
    )
}

fn normalize_server_name(value: &str) -> Option<String> {
    let value = value.trim();
    let wildcard = value.starts_with("*.");
    let value = value.strip_prefix("*.").unwrap_or(value);
    if value.contains('*') {
        return None;
    }
    let authority = value.parse::<http::uri::Authority>().ok()?;
    if authority.port().is_some() {
        return None;
    }
    let host = normalize_host(authority.host())?;
    if wildcard {
        if host.contains(':') {
            return None;
        }
        return Some(format!("*.{host}"));
    }
    Some(host)
}

pub(crate) fn match_score(pattern: &str, host: &str) -> Option<usize> {
    if pattern == host {
        return Some(usize::MAX);
    }
    let suffix = pattern.strip_prefix("*.")?;
    (host.len() > suffix.len()
        && host.ends_with(suffix)
        && host.as_bytes().get(host.len() - suffix.len() - 1) == Some(&b'.'))
    .then_some(suffix.len())
}

#[cfg(feature = "hosting")]
fn validate_index(index: &[String]) -> Result<(), Box<dyn Error + Send + Sync>> {
    crate::config::validate_index_names(index)
        .map_err(|_| "vhost index must be a non-empty list of file names".into())
}

#[cfg(feature = "hosting")]
fn cgroup_for_vhost(
    entry: &VhostFile,
    fallback: &Config,
    uid: u32,
    gid: u32,
    name: &str,
) -> Result<Option<CgroupSpec>, Box<dyn Error + Send + Sync>> {
    let global = fallback.worker_cgroup.as_ref();
    let path = entry
        .cgroup
        .as_deref()
        .or_else(|| global.and_then(|spec| spec.path.to_str()));
    let memory_max = entry
        .cgroup_memory_max
        .as_deref()
        .or_else(|| global.and_then(|spec| spec.memory_max.as_deref()));
    let cpu_max = entry
        .cgroup_cpu_max
        .as_deref()
        .or_else(|| global.and_then(|spec| spec.cpu_max.as_deref()));
    let pids_max = entry
        .cgroup_pids_max
        .as_deref()
        .or_else(|| global.and_then(|spec| spec.pids_max.as_deref()));
    let Some(path) = path else {
        if memory_max.is_some() || cpu_max.is_some() || pids_max.is_some() {
            return Err("worker cgroup limits require a cgroup path".into());
        }
        return Ok(None);
    };
    Ok(Some(
        CgroupSpec::new(path, memory_max, cpu_max, pids_max)?.expand(uid, gid, name)?,
    ))
}

fn validate_vhost_declarations<'a>(
    entries: impl IntoIterator<Item = &'a VhostFile>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut names = std::collections::HashSet::new();
    let mut has_default = false;
    for (index, entry) in entries.into_iter().enumerate() {
        if let Some(feature) = missing_feature(entry) {
            return Err(format!(
                "vhost {} requires the `{feature}` feature, which this build does not include",
                index + 1
            )
            .into());
        }
        if entry.proxy_pass.is_some() {
            if entry.cgroup.is_some()
                || entry.cgroup_memory_max.is_some()
                || entry.cgroup_cpu_max.is_some()
                || entry.cgroup_pids_max.is_some()
            {
                return Err(format!(
                    "vhost {} worker cgroup options require a hosted vhost",
                    index + 1
                )
                .into());
            }
            #[cfg(feature = "proxy")]
            ReverseProxy::validate_upstream_url(entry.proxy_pass.as_deref().unwrap())
                .map_err(|error| format!("vhost {} proxy_pass: {error}", index + 1))?;
            if !entry.fastcgi.is_empty()
                || !entry.cgi.is_empty()
                || !entry.fastcgi_app.is_empty()
                || entry.try_files.is_some()
            {
                return Err(format!(
                    "vhost {} proxy_pass cannot be combined with FastCGI, CGI, fastcgi_app, or try_files",
                    index + 1
                )
                .into());
            }
        } else {
            if entry.root.is_none() {
                return Err(format!(
                    "vhost {} root is required unless proxy_pass is configured",
                    index + 1
                )
                .into());
            }
            if entry.user.is_none() {
                return Err(format!(
                    "vhost {} user is required unless proxy_pass is configured",
                    index + 1
                )
                .into());
            }
            if entry.proxy_preserve_host.is_some()
                || entry.proxy_timeout.is_some()
                || entry.proxy_ca_root.is_some()
            {
                return Err(format!("vhost {} proxy options require proxy_pass", index + 1).into());
            }
        }
        if entry.proxy_timeout == Some(0) {
            return Err(format!(
                "vhost {} proxy_timeout must be greater than zero",
                index + 1
            )
            .into());
        }
        if entry.tls_cert.is_some() != entry.tls_key.is_some() {
            return Err(
                format!("vhost {} must provide both tls_cert and tls_key", index + 1).into(),
            );
        }
        #[cfg(feature = "hosting")]
        {
            if let Some(path) = entry.cgroup.as_deref() {
                CgroupSpec::new(
                    path,
                    entry.cgroup_memory_max.as_deref(),
                    entry.cgroup_cpu_max.as_deref(),
                    entry.cgroup_pids_max.as_deref(),
                )
                .map_err(|error| format!("vhost {} cgroup: {error}", index + 1))?;
            } else {
                if let Some(limit) = entry.cgroup_memory_max.as_deref() {
                    crate::cgroup::normalize_memory_max(limit).map_err(|error| {
                        format!("vhost {} cgroup_memory_max: {error}", index + 1)
                    })?;
                }
                if let Some(limit) = entry.cgroup_cpu_max.as_deref() {
                    crate::cgroup::normalize_cpu_max(limit)
                        .map_err(|error| format!("vhost {} cgroup_cpu_max: {error}", index + 1))?;
                }
                if let Some(limit) = entry.cgroup_pids_max.as_deref() {
                    crate::cgroup::normalize_pids_max(limit)
                        .map_err(|error| format!("vhost {} cgroup_pids_max: {error}", index + 1))?;
                }
            }
        }
        if let Some(threads) = entry.worker_threads {
            crate::config::parse_thread_count(&threads.to_string())
                .map_err(|error| format!("vhost {} worker_threads: {error}", index + 1))?;
        }
        match entry.rate_limit.as_deref() {
            Some("off") => {
                if entry.rate_limit_burst.is_some() {
                    return Err(format!(
                        "vhost {} rate_limit_burst cannot be used with rate_limit: off",
                        index + 1
                    )
                    .into());
                }
            }
            Some(rate) => {
                RateLimit::parse(rate, entry.rate_limit_burst)
                    .map_err(|error| format!("vhost {} rate_limit: {error}", index + 1))?;
            }
            None if entry.rate_limit_burst.is_some() => {
                return Err(
                    format!("vhost {} rate_limit_burst requires rate_limit", index + 1).into(),
                );
            }
            None => {}
        }
        match &entry.bot {
            Some(BotPolicyDeclarationFile::String(value)) if value == "off" => {}
            Some(BotPolicyDeclarationFile::String(value)) => {
                return Err(format!(
                    "vhost {} bot setting must be `off` or a policy map: {value}",
                    index + 1
                )
                .into());
            }
            Some(BotPolicyDeclarationFile::Policy(policy)) => {
                BotPolicy::parse(policy.clone())
                    .map_err(|error| format!("vhost {} bot: {error}", index + 1))?;
            }
            None => {}
        }
        if let Some(status) = entry.modsecurity_block_status {
            crate::config::parse_modsecurity_block_status(&status.to_string()).map_err(
                |error| format!("vhost {} modsecurity_block_status: {error}", index + 1),
            )?;
        }
        for app in &entry.fastcgi_app {
            if let Some(max_workers) = app.max_workers {
                crate::config::parse_fastcgi_app_max_workers(&max_workers.to_string()).map_err(
                    |error| {
                        format!(
                            "vhost {} FastCGI app .{}: {error}",
                            index + 1,
                            app.extension
                        )
                    },
                )?;
            }
            if let Some(idle_timeout) = app.idle_timeout {
                crate::config::parse_fastcgi_app_idle_timeout(&idle_timeout.to_string()).map_err(
                    |error| {
                        format!(
                            "vhost {} FastCGI app .{}: {error}",
                            index + 1,
                            app.extension
                        )
                    },
                )?;
            }
        }
        if let Some(try_files) = &entry.try_files {
            crate::config::validate_try_files(try_files)
                .map_err(|error| format!("vhost {} try_files: {error}", index + 1))?;
        }
        if entry.server_names.is_empty() {
            return Err(format!("vhost {} has no server_names", index + 1).into());
        }
        for rule in &entry.modsecurity_disable_rules {
            rule.parse().map_err(io::Error::other)?;
        }
        if entry.default {
            if has_default {
                return Err("only one vhost may be marked default".into());
            }
            has_default = true;
        }
        for name in &entry.server_names {
            let normalized = normalize_server_name(name)
                .ok_or_else(|| format!("invalid virtual host name: {name}"))?;
            if let Some(normalized) = names.replace(normalized) {
                return Err(format!("duplicate virtual host name: {normalized}").into());
            }
        }
    }
    Ok(())
}

/// Names the Cargo feature that a declaration depends on when this binary was
/// built without it: proxying for `proxy_pass`, hosting for a document root,
/// and ACME for an explicit `acme: true`.
fn missing_feature(entry: &VhostFile) -> Option<&'static str> {
    if (entry.cgroup.is_some()
        || entry.cgroup_memory_max.is_some()
        || entry.cgroup_cpu_max.is_some()
        || entry.cgroup_pids_max.is_some())
        && !cfg!(feature = "hosting")
    {
        return Some("hosting");
    }
    if entry.proxy_pass.is_some() {
        if !cfg!(feature = "proxy") {
            return Some("proxy");
        }
    } else if !cfg!(feature = "hosting") {
        return Some("hosting");
    }
    if entry.acme == Some(true) && !cfg!(feature = "acme") {
        return Some("acme");
    }
    None
}

fn validate_vhost_waf_declarations<'a>(
    entries: impl IntoIterator<Item = &'a VhostFile, IntoIter: Clone>,
    has_global_waf: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut entries = entries.into_iter();
    if !has_global_waf
        && entries
            .clone()
            .any(|entry| !entry.modsecurity_disable_rules.is_empty())
    {
        return Err("modsecurity_disable_rules requires --modsecurity-rules".into());
    }
    if !has_global_waf && entries.any(|entry| entry.modsecurity_block_status.is_some()) {
        return Err("modsecurity_block_status requires --modsecurity-rules".into());
    }
    Ok(())
}

/// Reads trusted configuration through the same descriptor used for its trust check.
///
/// Virtual host declarations choose the account a worker runs as and the
/// programs it starts, so whoever can write them controls the server.
pub(crate) fn read_trusted_config(path: &Path) -> io::Result<String> {
    let mut file = File::open(path).path_context("open virtual-host config", path)?;
    let metadata = file
        .metadata()
        .path_context("inspect virtual-host config", path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} must be a regular file", path.display()),
        ));
    }
    ensure_trusted_metadata(&metadata, path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .path_context("read virtual-host config", path)?;
    Ok(content)
}

/// Checks a configuration path without consuming its contents.
pub(crate) fn ensure_trusted_config(path: &Path) -> io::Result<()> {
    let file = File::open(path).path_context("open virtual-host config", path)?;
    ensure_trusted_metadata(
        &file
            .metadata()
            .path_context("inspect virtual-host config", path)?,
        path,
    )
}

fn ensure_trusted_metadata(metadata: &std::fs::Metadata, path: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let owner = metadata.uid();
    let current_uid = nix::unistd::geteuid().as_raw();
    if owner != 0 && owner != current_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must be owned by root or by the user running the server",
                path.display()
            ),
        ));
    }
    let allow_group_write =
        metadata.gid() == 0 || (owner == current_uid && private_group_write_allowed(metadata));
    if !trusted_write_mode(metadata.mode(), allow_group_write) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} must not be group- or world-writable", path.display()),
        ));
    }
    Ok(())
}

fn trusted_write_mode(mode: u32, allow_group_write: bool) -> bool {
    mode & 0o002 == 0 && (mode & 0o020 == 0 || allow_group_write)
}

fn private_group_write_allowed(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    use caps::{CapSet, Capability};
    use nix::unistd::{Gid, Group, Uid, User};

    let uid = nix::unistd::geteuid();
    if uid.is_root()
        || crate::logopener::is_active()
        || caps::has_cap(None, CapSet::Effective, Capability::CAP_SETUID).unwrap_or(true)
    {
        return false;
    }
    let Ok(Some(user)) = User::from_uid(Uid::from_raw(metadata.uid())) else {
        return false;
    };
    let gid = Gid::from_raw(metadata.gid());
    if user.gid != gid {
        return false;
    }
    let Ok(Some(group)) = Group::from_gid(gid) else {
        return false;
    };
    if !group.mem.iter().all(|member| member == &user.name) {
        return false;
    }
    let Ok(passwd) = std::fs::read_to_string("/etc/passwd") else {
        return false;
    };
    let mut primary_group_members = 0;
    for line in passwd.lines() {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 4 || fields[3].parse::<u32>().ok() != Some(gid.as_raw()) {
            continue;
        }
        if fields[0] != user.name || fields[2].parse::<u32>().ok() != Some(metadata.uid()) {
            return false;
        }
        primary_group_members += 1;
    }
    primary_group_members == 1
}

/// Refuses a set of virtual hosts in which a document root would expose the
/// ACME cache, which holds private keys.
#[cfg(all(feature = "acme", feature = "hosting"))]
fn ensure_acme_cache_is_private(cache: &Path, vhosts: &[Arc<Vhost>]) -> io::Result<()> {
    let cache =
        match std::fs::canonicalize(cache).path_context("resolve ACME cache directory", cache) {
            Ok(cache) => cache,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
    for vhost in vhosts {
        if let Some(worker) = &vhost.worker {
            let root = match std::fs::canonicalize(&worker.root)
                .path_context("resolve document root", &worker.root)
            {
                Ok(root) => root,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if cache.starts_with(&root) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "ACME cache must be outside every served document root: {}",
                        root.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

fn resolve_config_path(path: PathBuf, config_dir: &Path) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        config_dir.join(path)
    }
}

pub(crate) fn helper_directories(config: &Config) -> io::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let current_dir = std::env::current_dir()?;
    let config_dir = config
        .config_file
        .as_deref()
        .and_then(Path::parent)
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(|parent| resolve_config_path(parent.to_path_buf(), &current_dir))
        .unwrap_or_else(|| current_dir.clone());
    let mut log_dirs = config
        .log_dirs
        .iter()
        .cloned()
        .map(|path| resolve_config_path(path, &current_dir))
        .collect::<Vec<_>>();
    let mut tls_dirs = config
        .tls_dirs
        .iter()
        .cloned()
        .map(|path| resolve_config_path(path, &current_dir))
        .collect::<Vec<_>>();
    for path in [
        config.access_log_file.as_deref(),
        config.error_log_file.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        add_parent_directory(&mut log_dirs, path, &current_dir);
    }
    if let Some(tls) = &config.tls {
        add_parent_directory(&mut tls_dirs, &tls.cert, &current_dir);
        add_parent_directory(&mut tls_dirs, &tls.key, &current_dir);
    }
    #[cfg(feature = "acme")]
    if let Some(acme) = &config.acme {
        tls_dirs.push(resolve_config_path(acme.cache.clone(), &current_dir));
    }

    let main_file = if let Some(path) = &config.config_file {
        let contents = read_trusted_config(path)?;
        let file = parse_file_config(&contents)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        for entry in &file.vhost {
            append_vhost_helper_directories(entry, &mut log_dirs, &mut tls_dirs, &config_dir);
        }
        Some(file)
    } else {
        None
    };
    let vhost_dir = config
        .vhost_dir
        .clone()
        .or_else(|| {
            main_file.as_ref().and_then(|file| {
                file.vhost_dir
                    .clone()
                    .map(|dir| resolve_config_path(dir, &config_dir))
            })
        })
        .map(|dir| resolve_config_path(dir, &current_dir));
    if let Some(dir) = vhost_dir {
        ensure_trusted_config(&dir)?;
        for path in scan_vhost_files(&dir)? {
            let contents = read_trusted_config(&path)?;
            let file = parse_file_config(&contents)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            for entry in &file.vhost {
                let entry_dir = path.parent().unwrap_or(&dir);
                append_vhost_helper_directories(entry, &mut log_dirs, &mut tls_dirs, entry_dir);
            }
        }
    }
    Ok((
        deduplicate_directories(log_dirs),
        deduplicate_directories(tls_dirs),
    ))
}

fn append_vhost_helper_directories(
    entry: &VhostFile,
    log_dirs: &mut Vec<PathBuf>,
    tls_dirs: &mut Vec<PathBuf>,
    config_dir: &Path,
) {
    for path in [entry.access_log.as_ref(), entry.error_log.as_ref()]
        .into_iter()
        .flatten()
    {
        add_parent_directory(log_dirs, path, config_dir);
    }
    for path in [entry.tls_cert.as_ref(), entry.tls_key.as_ref()]
        .into_iter()
        .flatten()
    {
        add_parent_directory(tls_dirs, path, config_dir);
    }
}

fn add_parent_directory(directories: &mut Vec<PathBuf>, path: &Path, base: &Path) {
    let path = resolve_config_path(path.to_path_buf(), base);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(base);
    directories.push(parent.to_path_buf());
}

fn deduplicate_directories(directories: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut unique = Vec::new();
    for directory in directories {
        if !unique.contains(&directory) {
            unique.push(directory);
        }
    }
    unique
}

fn scan_vhost_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let directory = File::open(dir).path_context("open virtual-host directory", dir)?;
    ensure_trusted_metadata(
        &directory
            .metadata()
            .path_context("inspect virtual-host directory", dir)?,
        dir,
    )?;
    let fd_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    for entry in std::fs::read_dir(&fd_path).path_context("read virtual-host directory", dir)? {
        let entry = entry.path_context("read virtual-host directory entry", dir)?;
        let name = entry.file_name();
        let path = fd_path.join(&name);
        if !name.to_string_lossy().starts_with('.')
            && path
                .extension()
                .is_some_and(|extension| extension == "yaml" || extension == "yml")
        {
            match std::fs::metadata(&path).path_context("inspect virtual-host config", &path) {
                Ok(metadata) if metadata.is_file() => files.push(dir.join(name)),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
    }
    files.sort();
    Ok(files)
}

struct LocatedVhost {
    path: PathBuf,
    line: Option<usize>,
    index: usize,
    config_dir: PathBuf,
    entry: VhostFile,
}

/// Checks the configured virtual-host files without opening logs or starting
/// any of the server's runtime services.
pub(crate) fn check_config(fallback: &Config) -> Vec<String> {
    let mut diagnostics = Vec::new();
    let current_dir = match std::env::current_dir() {
        Ok(current_dir) => current_dir,
        Err(error) => {
            diagnostics.push(format!("could not determine current directory: {error}"));
            PathBuf::from(".")
        }
    };
    let config_dir = fallback
        .config_file
        .as_ref()
        .and_then(|path| path.parent())
        .filter(|parent| !parent.as_os_str().is_empty())
        .map_or_else(
            || current_dir.clone(),
            |parent| {
                if parent.is_absolute() {
                    parent.to_path_buf()
                } else {
                    current_dir.join(parent)
                }
            },
        );
    let mut entries = Vec::new();
    let main_vhost_dir = fallback.config_file.as_ref().and_then(|path| {
        read_config_file_for_check(path, &mut diagnostics).and_then(|(content, file)| {
            append_located_entries(path, &content, file.vhost, &config_dir, &mut entries);
            file.vhost_dir
        })
    });
    let dir = fallback
        .vhost_dir
        .clone()
        .map(|dir| resolve_config_path(dir, &current_dir))
        .or_else(|| main_vhost_dir.map(|dir| resolve_config_path(dir, &config_dir)));

    if let Some(dir) = dir {
        if let Err(error) = ensure_trusted_config(&dir) {
            diagnostics.push(format!("{}: {error}", dir.display()));
        }
        match scan_vhost_files(&dir) {
            Ok(paths) => {
                for path in paths {
                    let Some((content, file)) = read_config_file_for_check(&path, &mut diagnostics)
                    else {
                        continue;
                    };
                    if file.options.is_some() {
                        diagnostics.push(format!(
                            "{}: options are only allowed in the main config file",
                            path.display()
                        ));
                        continue;
                    }
                    let entry_config_dir = path.parent().unwrap_or(&dir);
                    append_located_entries(
                        &path,
                        &content,
                        file.vhost,
                        entry_config_dir,
                        &mut entries,
                    );
                }
            }
            Err(error) => diagnostics.push(format!("{}: {error}", dir.display())),
        }
    }

    let has_waf = !fallback.modsecurity_rules.is_empty();
    let mut names: HashMap<String, (PathBuf, Option<usize>, usize)> = HashMap::new();
    let mut default: Option<(PathBuf, Option<usize>, usize)> = None;
    for located in &entries {
        let location = source_location(&located.path, located.line, located.index);
        if let Err(error) =
            validate_vhost_entry(&located.entry, fallback, &located.config_dir, has_waf)
        {
            diagnostics.push(format!("{location}: {error}"));
        }

        if located.entry.default {
            if let Some((first_path, first_line, first_index)) = &default {
                let first = source_location(first_path, *first_line, *first_index);
                diagnostics.push(format!(
                    "{location}: only one vhost may be marked default; first declared at {first}"
                ));
            } else {
                default = Some((located.path.clone(), located.line, located.index));
            }
        }
        for name in &located.entry.server_names {
            if let Some(normalized) = normalize_server_name(name) {
                if let Some((first_path, first_line, first_index)) = names.get(&normalized) {
                    let first = source_location(first_path, *first_line, *first_index);
                    diagnostics.push(format!(
                        "{location}: duplicate virtual host name: {normalized}; first declared at {first}"
                    ));
                } else {
                    names.insert(
                        normalized,
                        (located.path.clone(), located.line, located.index),
                    );
                }
            }
        }
    }
    diagnostics
}

fn read_config_file_for_check(
    path: &Path,
    diagnostics: &mut Vec<String>,
) -> Option<(String, FileConfig)> {
    let content = match read_trusted_config(path) {
        Ok(content) => content,
        Err(error) => {
            diagnostics.push(format!("{}: {error}", path.display()));
            return None;
        }
    };
    match parse_file_config(&content) {
        Ok(file) => Some((content, file)),
        Err(error) => {
            if let Some(location) = error.location() {
                diagnostics.push(format!(
                    "{}:{}:{}: {error}",
                    path.display(),
                    location.line(),
                    location.column()
                ));
            } else {
                diagnostics.push(format!("{}: {error}", path.display()));
            }
            None
        }
    }
}

fn append_located_entries(
    path: &Path,
    content: &str,
    file_entries: Vec<VhostFile>,
    config_dir: &Path,
    entries: &mut Vec<LocatedVhost>,
) {
    let lines = vhost_entry_lines(content);
    let locations = if lines.len() == file_entries.len() {
        lines.into_iter().map(Some).collect::<Vec<_>>()
    } else {
        let key_line = vhost_key_line(content);
        vec![key_line; file_entries.len()]
    };
    for (index, (entry, line)) in file_entries.into_iter().zip(locations).enumerate() {
        entries.push(LocatedVhost {
            path: path.to_path_buf(),
            line,
            index: index + 1,
            config_dir: config_dir.to_path_buf(),
            entry,
        });
    }
}

fn vhost_key_line(content: &str) -> Option<usize> {
    content.lines().enumerate().find_map(|(index, line)| {
        let trimmed = line.trim_start();
        (line.len() == trimmed.len()
            && trimmed
                .strip_prefix("vhost:")
                .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace)))
        .then_some(index + 1)
    })
}

fn vhost_entry_lines(content: &str) -> Vec<usize> {
    let Some(key_line) = vhost_key_line(content) else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    let mut item_indent = None;
    for (index, line) in content.lines().enumerate().skip(key_line) {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - trimmed.len();
        let is_item = trimmed == "-" || trimmed.starts_with("- ") || trimmed.starts_with("-\t");
        if is_item {
            match item_indent {
                Some(item_indent) if indent == item_indent => lines.push(index + 1),
                Some(item_indent) if indent > item_indent => {}
                Some(_) => break,
                None => {
                    item_indent = Some(indent);
                    lines.push(index + 1);
                }
            }
        } else if item_indent.is_some_and(|item_indent| indent <= item_indent) {
            break;
        }
    }
    lines
}

fn source_location(path: &Path, line: Option<usize>, index: usize) -> String {
    match line {
        Some(line) => format!("{}:{line}", path.display()),
        None => format!("{}:entry {index}", path.display()),
    }
}

#[cfg_attr(not(feature = "proxy"), allow(unused_variables))]
fn validate_vhost_entry(
    entry: &VhostFile,
    fallback: &Config,
    config_dir: &Path,
    has_waf: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    validate_vhost_declarations(std::iter::once(entry))?;
    validate_vhost_waf_declarations(std::iter::once(entry), has_waf)?;
    crate::logging::AccessFormat::parse(
        entry
            .access_log_format
            .as_deref()
            .unwrap_or(&fallback.access_log_format),
    )?;
    crate::logging::ErrorFormat::parse(
        entry
            .error_log_format
            .as_deref()
            .unwrap_or(&fallback.error_log_format),
    )?;

    #[cfg(feature = "proxy")]
    if let Some(upstream) = &entry.proxy_pass {
        let ca_root = entry
            .proxy_ca_root
            .clone()
            .map(|path| resolve_config_path(path, config_dir));
        ReverseProxy::new(
            upstream,
            entry.proxy_preserve_host.unwrap_or(true),
            Duration::from_secs(entry.proxy_timeout.unwrap_or(60)),
            ca_root.as_deref(),
        )?;
    }

    #[cfg(feature = "hosting")]
    if entry.proxy_pass.is_none() {
        let user = entry
            .user
            .as_deref()
            .ok_or("vhost user is required unless proxy_pass is configured")?;
        let (uid, gid) = resolve_identity(user, entry.group.as_deref())?;
        if uid == 0 {
            return Err(format!("virtual host user must not be root: {user}").into());
        }
        validate_worker_identity(uid, gid)?;
        let name = entry.server_names.first().map_or("", String::as_str);
        cgroup_for_vhost(entry, fallback, uid, gid, name)?;
        validate_index(entry.index.as_deref().unwrap_or(&fallback.index))?;
        let root = entry
            .root
            .as_ref()
            .ok_or("vhost root is required unless proxy_pass is configured")?;
        check_vhost_root(&resolve_config_path(root.clone(), config_dir))?;
        crate::config::validate_try_files(
            entry.try_files.as_deref().unwrap_or(&fallback.try_files),
        )?;

        let mut extensions = std::collections::HashSet::new();
        for value in &entry.fastcgi {
            let backend = crate::config::parse_fastcgi_backend(value)?;
            if !extensions.insert(backend.extension.clone()) {
                return Err(format!(
                    "duplicate backend extension in vhost: {}",
                    backend.extension
                )
                .into());
            }
        }
        for value in &entry.cgi {
            let backend = crate::config::parse_cgi_backend(value)?;
            if !extensions.insert(backend.extension.clone()) {
                return Err(format!(
                    "duplicate backend extension in vhost: {}",
                    backend.extension
                )
                .into());
            }
        }
        for app in &entry.fastcgi_app {
            let Some(program) = app.command.first() else {
                return Err(format!(
                    "vhost FastCGI app .{} command must not be empty",
                    app.extension
                )
                .into());
            };
            let extension = crate::config::normalize_extension(&app.extension)?;
            if !extensions.insert(extension.clone()) {
                return Err(format!("duplicate backend extension in vhost: {extension}").into());
            }
            if app.command.iter().any(|part| part.contains('\0')) {
                return Err("vhost FastCGI app command cannot contain NUL".into());
            }
            crate::config::parse_fastcgi_app(&format!("{extension}={program}"))?;
            crate::config::parse_fastcgi_app_max_workers(
                &app.max_workers.unwrap_or(1).to_string(),
            )?;
            crate::config::parse_fastcgi_app_idle_timeout(
                &app.idle_timeout
                    .unwrap_or(crate::config::DEFAULT_FASTCGI_APP_IDLE_TIMEOUT_SECS)
                    .to_string(),
            )?;
            for (key, value) in &app.env {
                crate::config::validate_env_key(key)?;
                if value.contains('\0') {
                    return Err("vhost FastCGI app environment value cannot contain NUL".into());
                }
            }
        }
        if entry
            .fastcgi_timeout
            .unwrap_or(fallback.fastcgi_timeout.as_secs())
            == 0
        {
            return Err("vhost FastCGI timeout must be greater than zero".into());
        }
    }
    Ok(())
}

#[cfg(feature = "hosting")]
fn check_vhost_root(root: &Path) -> io::Result<()> {
    match std::fs::metadata(root) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("vhost root {} is not a directory", root.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            crate::log_debug!(
                "Could not inspect vhost root {} as the master; the worker will check access",
                root.display()
            );
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("vhost root {} does not exist", root.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotADirectory => Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("vhost root {} is not a directory", root.display()),
        )),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("could not inspect vhost root {}: {error}", root.display()),
        )),
    }
}

#[cfg(feature = "hosting")]
fn validate_worker_identity(uid: u32, gid: u32) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !crate::privileges::can_set_ids()?
        && !crate::logopener::is_active()
        && (nix::unistd::geteuid().as_raw() != uid || nix::unistd::getegid().as_raw() != gid)
    {
        return Err("a non-root server can only run workers as its current uid and gid".into());
    }
    Ok(())
}

fn control_reload_error(error: Box<dyn Error + Send + Sync>) -> ControlError {
    let message = error.to_string();
    match error.downcast_ref::<io::Error>().map(io::Error::kind) {
        Some(io::ErrorKind::AlreadyExists) => ControlError::Conflict(message),
        Some(io::ErrorKind::NotFound) => ControlError::NotFound,
        Some(_) => ControlError::Unavailable(message),
        None => ControlError::BadRequest(message),
    }
}

fn parse_file_config(content: &str) -> Result<FileConfig, serde_yaml_ng::Error> {
    if content.trim().is_empty() {
        Ok(FileConfig::default())
    } else {
        serde_yaml_ng::from_str(content)
    }
}

fn valid_control_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        && bytes.len() <= 63
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn render_control_vhost(value: serde_yaml_ng::Value) -> Result<String, serde_yaml_ng::Error> {
    let entry: VhostFile = serde_yaml_ng::from_value(value)?;
    Ok(format!("vhost:\n{}", serde_yaml_ng::to_string(&[entry])?))
}

fn persist_vhost_file(dir: &Path, path: &Path, content: &str) -> io::Result<()> {
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if path.parent() != Some(dir) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "virtual-host file is outside the configured directory",
        ));
    }
    let name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "virtual-host path has no file name",
        )
    })?;
    let mut temp_path = None;
    let mut temp_file = None;
    for _ in 0..16 {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = dir.join(format!(
            ".{}.tmp-{}-{id}",
            name.to_string_lossy(),
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&candidate)
            .path_context("create temporary virtual-host config", &candidate)
        {
            Ok(file) => {
                if let Err(error) = file
                    .set_permissions(std::fs::Permissions::from_mode(0o640))
                    .path_context(
                        "set permissions on temporary virtual-host config",
                        &candidate,
                    )
                {
                    drop(file);
                    let _ = std::fs::remove_file(&candidate);
                    return Err(error);
                }
                temp_path = Some(candidate);
                temp_file = Some(file);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    let temp_path = temp_path.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a temporary virtual-host file",
        )
    })?;
    let mut temp_file = temp_file.expect("temporary path and file are created together");
    let result = (|| {
        temp_file
            .write_all(content.as_bytes())
            .path_context("write temporary virtual-host config", &temp_path)?;
        temp_file
            .sync_all()
            .path_context("sync temporary virtual-host config", &temp_path)?;
        drop(temp_file);
        std::fs::rename(&temp_path, path).path_context("replace virtual-host config", path)?;
        std::fs::File::open(dir)
            .path_context("open virtual-host directory", dir)?
            .sync_all()
            .path_context("sync virtual-host directory", dir)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp_path);
    }
    result
}

#[cfg(all(test, feature = "hosting"))]
mod tests {
    use super::{
        FileConfig, Router, TlsSni, Vhost, VhostFile, VhostTable, Worker, WorkerArgs,
        build_worker_args, cgroup_for_vhost, ensure_trusted_config, https_redirect_location,
        match_score, normalize_host, normalize_server_name, parse_file_config,
        render_control_vhost, request_host, resolve_identity, scan_vhost_files, select_route,
        trusted_write_mode, valid_control_name, validate_index, validate_vhost_declarations,
        validate_vhost_waf_declarations, worker_app_env, worker_request,
    };
    use crate::{
        config::{
            Config, FastCgiAddress, FastCgiApp, FastCgiBackend, ParseResult, normalize_extension,
            parse_fastcgi_app, parse_fastcgi_backend, validate_env_key, validate_try_files,
        },
        fuzz_support::{self, FuzzRequest},
    };
    use http::{HeaderValue, Request, StatusCode, Version, header::HOST};
    use std::{
        collections::{BTreeMap, HashSet},
        path::{Path, PathBuf},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn normalizes_authority_hosts() {
        for (input, expected) in [
            ("Example.COM:8080", "example.com"),
            ("example.com.", "example.com"),
            ("[2001:DB8::1]:443", "2001:db8::1"),
        ] {
            let authority = input.parse::<http::uri::Authority>().unwrap();
            assert_eq!(normalize_host(authority.host()).as_deref(), Some(expected));
        }
    }

    #[test]
    fn validates_control_names_and_renders_vhost_yaml() {
        for name in ["example", "example.test", "vhost-1", "site_2"] {
            assert!(valid_control_name(name));
        }
        for name in ["", ".hidden", "../escape", "a/b"] {
            assert!(!valid_control_name(name));
        }
        assert!(!valid_control_name(&"a".repeat(65)));

        let entry: serde_yaml_ng::Value = serde_yaml_ng::from_str(
            "server_names: [control.example]\nroot: /srv/site\nuser: nobody\n",
        )
        .unwrap();
        let rendered = render_control_vhost(entry).unwrap();
        let parsed = parse_file_config(&rendered).unwrap();
        assert_eq!(parsed.vhost.len(), 1);
        assert_eq!(parsed.vhost[0].server_names, ["control.example"]);
        assert_eq!(
            parsed.vhost[0].root.as_deref(),
            Some(Path::new("/srv/site"))
        );
    }

    #[test]
    fn matches_exact_and_longest_wildcards() {
        let host = "api.dev.example.com";
        assert_eq!(match_score("*.example.com", host), Some(11));
        assert_eq!(match_score("*.dev.example.com", host), Some(15));
        assert_eq!(match_score("example.com", host), None);
        assert_eq!(match_score("api.dev.example.com", host), Some(usize::MAX));
        assert!(normalize_server_name("*.example.com").is_some());
        assert!(normalize_server_name("api.*.example.com").is_none());
    }

    #[test]
    fn https_redirect_location_formats_default_port_and_ipv6() {
        assert_eq!(
            https_redirect_location("example.test", 443, "/path?q=1"),
            "https://example.test/path?q=1"
        );
        assert_eq!(
            https_redirect_location("2001:db8::1", 8443, "/"),
            "https://[2001:db8::1]:8443/"
        );
    }

    fn declaration(names: &[&str], is_default: bool) -> VhostFile {
        VhostFile {
            server_names: names.iter().map(|name| (*name).to_owned()).collect(),
            root: Some("/tmp/site".into()),
            user: Some("user".to_owned()),
            group: None,
            index: None,
            listing: None,
            try_files: None,
            fastcgi: Vec::new(),
            cgi: Vec::new(),
            fastcgi_app: Vec::new(),
            fastcgi_timeout: None,
            worker_threads: None,
            worker_idle_timeout: None,
            cgroup: None,
            cgroup_memory_max: None,
            cgroup_cpu_max: None,
            cgroup_pids_max: None,
            rate_limit: None,
            rate_limit_burst: None,
            bot: None,
            tls_cert: None,
            tls_key: None,
            https_redirect: None,
            default: is_default,
            modsecurity_disable_rules: Vec::new(),
            modsecurity_block_status: None,
            acme: None,
            proxy_pass: None,
            proxy_preserve_host: None,
            proxy_timeout: None,
            proxy_ca_root: None,
            access_log: None,
            access_log_format: None,
            error_log: None,
            error_log_format: None,
        }
    }

    #[test]
    fn validates_yaml_vhost_names_and_defaults() {
        let parsed: FileConfig = serde_yaml_ng::from_str(
            r#"
                vhost:
                  - server_names: [Example.com, www.example.com]
                    root: /tmp/site
                    user: example
                    default: true
            "#,
        )
        .unwrap();
        assert!(validate_vhost_declarations(&parsed.vhost).is_ok());
        assert!(
            validate_vhost_declarations(&[
                declaration(&["example.com"], false),
                declaration(&["EXAMPLE.COM"], false),
            ])
            .is_err()
        );
        assert!(
            validate_vhost_declarations(&[
                declaration(&["one.example"], true),
                declaration(&["two.example"], true),
            ])
            .is_err()
        );
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn validates_and_merges_vhost_cgroup_settings() {
        let mut valid = declaration(&["*.example.test"], false);
        valid.cgroup = Some("/charlotte/{uid}/{name}".to_owned());
        valid.cgroup_memory_max = Some("128M".to_owned());
        valid.cgroup_cpu_max = Some("50%".to_owned());
        valid.cgroup_pids_max = Some("24".to_owned());
        assert!(validate_vhost_declarations([&valid]).is_ok());

        let mut invalid_path = valid.clone();
        invalid_path.cgroup = Some("../outside".to_owned());
        assert!(validate_vhost_declarations([&invalid_path]).is_err());
        let mut invalid_limit = valid.clone();
        invalid_limit.cgroup_cpu_max = Some("0%".to_owned());
        assert!(validate_vhost_declarations([&invalid_limit]).is_err());

        let fallback = match Config::parse([
            "--worker-cgroup".to_owned(),
            "charlotte/global/{uid}".to_owned(),
            "--worker-cgroup-pids-max".to_owned(),
            "48".to_owned(),
        ])
        .unwrap()
        {
            crate::config::ParseResult::Config(config) => config,
            crate::config::ParseResult::Help => panic!("expected config"),
        };
        let mut inherited = declaration(&["*.example.test"], false);
        inherited.cgroup_memory_max = Some("1G".to_owned());
        let inherited = cgroup_for_vhost(&inherited, &fallback, 1001, 1002, "*.example.test")
            .unwrap()
            .unwrap();
        assert_eq!(inherited.path, PathBuf::from("charlotte/global/1001"));
        assert_eq!(inherited.memory_max.as_deref(), Some("1073741824"));
        assert_eq!(inherited.pids_max.as_deref(), Some("48"));

        let mut missing_path = declaration(&["example.test"], false);
        missing_path.cgroup_pids_max = Some("10".to_owned());
        let no_global_cgroup = match Config::parse(Vec::<String>::new()).unwrap() {
            crate::config::ParseResult::Config(config) => config,
            crate::config::ParseResult::Help => panic!("expected config"),
        };
        let error =
            cgroup_for_vhost(&missing_path, &no_global_cgroup, 1, 1, "example.test").unwrap_err();
        assert!(error.to_string().contains("limits require a cgroup path"));
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn validates_proxy_vhost_configuration() {
        let parsed: FileConfig = serde_yaml_ng::from_str(
            r#"
                vhost:
                  - server_names: [proxy.example.test]
                    proxy_pass: https://127.0.0.1:9443/base
                    proxy_preserve_host: false
                    proxy_timeout: 15
                    proxy_ca_root: certs/upstream.pem
            "#,
        )
        .unwrap();
        assert!(validate_vhost_declarations(&parsed.vhost).is_ok());
        assert_eq!(parsed.vhost[0].root, None);
        assert_eq!(parsed.vhost[0].user, None);
        assert_eq!(parsed.vhost[0].proxy_timeout, Some(15));

        let mut invalid_scheme = parsed.vhost[0].clone();
        invalid_scheme.proxy_pass = Some("ftp://upstream.example.test".to_owned());
        assert!(validate_vhost_declarations(&[invalid_scheme]).is_err());

        let mut mixed_backend = parsed.vhost[0].clone();
        mixed_backend.fastcgi.push("php=127.0.0.1:9000".to_owned());
        assert!(validate_vhost_declarations(&[mixed_backend]).is_err());

        let mut missing_root = declaration(&["static.example.test"], false);
        missing_root.root = None;
        assert!(validate_vhost_declarations(&[missing_root]).is_err());

        let mut zero_timeout = parsed.vhost[0].clone();
        zero_timeout.proxy_timeout = Some(0);
        assert!(validate_vhost_declarations(&[zero_timeout]).is_err());
    }

    #[test]
    fn validates_vhost_worker_threads() {
        let mut entry = declaration(&["threads.example"], false);
        entry.worker_threads = Some(8);
        assert!(validate_vhost_declarations(std::slice::from_ref(&entry)).is_ok());
        for invalid in [0, 1025] {
            entry.worker_threads = Some(invalid);
            assert!(validate_vhost_declarations(std::slice::from_ref(&entry)).is_err());
        }
    }

    #[test]
    fn validates_vhost_rate_limit_settings() {
        let parsed: FileConfig = serde_yaml_ng::from_str(
            r#"
                vhost:
                  - server_names: [limit.example]
                    root: /tmp/site
                    user: user
                    rate_limit: "10/s"
                    rate_limit_burst: 20
            "#,
        )
        .unwrap();
        assert_eq!(parsed.vhost[0].rate_limit.as_deref(), Some("10/s"));
        assert_eq!(parsed.vhost[0].rate_limit_burst, Some(20));
        assert!(validate_vhost_declarations(&parsed.vhost).is_ok());

        let mut entry = declaration(&["limit.example"], false);
        entry.rate_limit = Some("10/s".to_owned());
        assert!(validate_vhost_declarations(std::slice::from_ref(&entry)).is_ok());

        entry.rate_limit_burst = Some(20);
        assert!(validate_vhost_declarations(std::slice::from_ref(&entry)).is_ok());

        entry.rate_limit = Some("off".to_owned());
        assert!(validate_vhost_declarations(std::slice::from_ref(&entry)).is_err());
        entry.rate_limit_burst = None;
        assert!(validate_vhost_declarations(std::slice::from_ref(&entry)).is_ok());

        entry.rate_limit = Some("invalid".to_owned());
        assert!(validate_vhost_declarations(std::slice::from_ref(&entry)).is_err());
        entry.rate_limit = None;
        assert!(validate_vhost_declarations(std::slice::from_ref(&entry)).is_ok());
        entry.rate_limit_burst = Some(1);
        assert!(validate_vhost_declarations(std::slice::from_ref(&entry)).is_err());
    }

    #[test]
    fn parses_and_validates_vhost_try_files() {
        let parsed: FileConfig = serde_yaml_ng::from_str(
            r#"
                vhost:
                  - server_names: [try-files.example]
                    root: /srv/site
                    user: site
                    try_files: ["$uri", "$uri/", /index.html, "=404"]
            "#,
        )
        .unwrap();
        assert_eq!(
            parsed.vhost[0].try_files.as_ref().unwrap(),
            &["$uri", "$uri/", "/index.html", "=404"]
        );
        assert!(validate_vhost_declarations(&parsed.vhost).is_ok());

        let mut entry = declaration(&["try-files.example"], false);
        entry.try_files = Some(vec!["$uri".to_owned()]);
        assert!(validate_vhost_declarations(&[entry]).is_err());
    }

    #[test]
    fn parses_and_validates_modsecurity_rule_exclusions() {
        let parsed: FileConfig = serde_yaml_ng::from_str(
            r#"
                vhost:
                  - server_names: [example.test]
                    root: /tmp/site
                    user: example
                    modsecurity_disable_rules: [100001, "2000-2099"]
            "#,
        )
        .unwrap();
        assert!(validate_vhost_declarations(&parsed.vhost).is_ok());
        assert!(validate_vhost_waf_declarations(&parsed.vhost, true).is_ok());
        assert!(validate_vhost_waf_declarations(&parsed.vhost, false).is_err());

        for rule in ["0", "2099-2000", "1001;SecRuleEngine Off", "1-2-3"] {
            let config = format!(
                "vhost:\n  - server_names: [example.test]\n    root: /tmp/site\n    user: example\n    modsecurity_disable_rules: [\"{rule}\"]\n"
            );
            let parsed: FileConfig = serde_yaml_ng::from_str(&config).unwrap();
            assert!(
                validate_vhost_declarations(&parsed.vhost).is_err(),
                "{rule}"
            );
        }
    }

    #[test]
    fn parses_and_validates_modsecurity_block_status() {
        let parsed: FileConfig = serde_yaml_ng::from_str(
            r#"
                vhost:
                  - server_names: [example.test]
                    root: /tmp/site
                    user: example
                    modsecurity_block_status: 451
            "#,
        )
        .unwrap();
        assert_eq!(parsed.vhost[0].modsecurity_block_status, Some(451));
        assert!(validate_vhost_declarations(&parsed.vhost).is_ok());
        assert!(validate_vhost_waf_declarations(&parsed.vhost, true).is_ok());
        assert!(validate_vhost_waf_declarations(&parsed.vhost, false).is_err());

        for status in [399, 600] {
            let mut entry = parsed.vhost[0].clone();
            entry.modsecurity_block_status = Some(status);
            assert!(validate_vhost_declarations(&[entry]).is_err());
        }
    }

    #[test]
    fn parses_vhost_fastcgi_app_command_and_environment() {
        let parsed: FileConfig = serde_yaml_ng::from_str(
            r#"
                vhost:
                  - server_names: [php.example]
                    root: /srv/php
                    user: php
                    fastcgi_app:
                      - extension: php
                        command: [php8.4-cgi, --foreground]
                        env: { APP_MODE: test }
                        max_workers: 4
                        idle_timeout: 12
            "#,
        )
        .unwrap();
        assert_eq!(parsed.vhost[0].fastcgi_app[0].extension, "php");
        assert_eq!(parsed.vhost[0].fastcgi_app[0].max_workers, Some(4));
        assert_eq!(parsed.vhost[0].fastcgi_app[0].idle_timeout, Some(12));
        assert!(validate_vhost_declarations(&parsed.vhost).is_ok());
        assert_eq!(
            parsed.vhost[0].fastcgi_app[0].command,
            ["php8.4-cgi", "--foreground"]
        );
        assert_eq!(
            parsed.vhost[0].fastcgi_app[0]
                .env
                .get("APP_MODE")
                .map(String::as_str),
            Some("test")
        );

        let mut invalid = parsed.vhost[0].clone();
        invalid.fastcgi_app[0].max_workers = Some(0);
        assert!(validate_vhost_declarations(&[invalid]).is_err());
        let mut invalid = parsed.vhost[0].clone();
        invalid.fastcgi_app[0].idle_timeout = Some(0);
        assert!(validate_vhost_declarations(&[invalid]).is_err());

        let legacy: FileConfig = serde_yaml_ng::from_str(
            r#"
                vhost:
                  - server_names: [legacy.example]
                    root: /srv/legacy
                    user: legacy
                    fastcgi_app:
                      - extension: php
                        command: [php-cgi]
                        workers: 3
            "#,
        )
        .unwrap();
        assert_eq!(legacy.vhost[0].fastcgi_app[0].max_workers, Some(3));
    }

    #[test]
    fn example_config_parses_and_validates() {
        let parsed: FileConfig =
            serde_yaml_ng::from_str(include_str!("../examples/charlotte.yaml"))
                .expect("example configuration should parse");
        let directory_entry: FileConfig =
            serde_yaml_ng::from_str(include_str!("../examples/vhosts.d/example.yaml"))
                .expect("example per-vhost file should parse");
        let mut entries = parsed.vhost;
        entries.extend(directory_entry.vhost);
        validate_vhost_declarations(&entries)
            .expect("example virtual host declarations should be valid");
        assert_eq!(entries[2].fastcgi_app.len(), 2);
        assert_eq!(parsed.vhost_dir.as_deref(), Some(Path::new("vhosts.d")));
    }

    #[test]
    fn parses_and_validates_vhost_bot_modes() {
        let off: FileConfig = serde_yaml_ng::from_str(
            "vhost:\n  - server_names: [off.example]\n    root: /srv/off\n    user: site\n    bot: off\n",
        )
        .unwrap();
        validate_vhost_declarations(&off.vhost).unwrap();
        assert!(matches!(
            off.vhost[0].bot,
            Some(super::BotPolicyDeclarationFile::String(ref value)) if value == "off"
        ));

        let policy: FileConfig = serde_yaml_ng::from_str(
            "vhost:\n  - server_names: [policy.example]\n    root: /srv/policy\n    user: site\n    bot:\n      mode: log\n      verify_crawlers: false\n",
        )
        .unwrap();
        validate_vhost_declarations(&policy.vhost).unwrap();
        assert!(matches!(
            policy.vhost[0].bot,
            Some(super::BotPolicyDeclarationFile::Policy(_))
        ));

        let invalid: FileConfig = serde_yaml_ng::from_str(
            "vhost:\n  - server_names: [invalid.example]\n    root: /srv/invalid\n    user: site\n    bot:\n      challenge_threshold: 90\n      block_threshold: 80\n",
        )
        .unwrap();
        assert!(validate_vhost_declarations(&invalid.vhost).is_err());
        let invalid_mode: FileConfig = serde_yaml_ng::from_str(
            "vhost:\n  - server_names: [unknown.example]\n    root: /srv/unknown\n    user: site\n    bot: enabled\n"
        )
        .unwrap();
        assert!(validate_vhost_declarations(&invalid_mode.vhost).is_err());
    }

    #[test]
    fn parses_empty_config_as_no_vhosts() {
        assert!(parse_file_config(" \n\t").unwrap().vhost.is_empty());
    }

    #[test]
    fn parses_single_and_list_directory_indexes_and_rejects_empty_list() {
        let single = parse_file_config(
            "vhost:\n  - server_names: [single.example]\n    root: /srv/single\n    user: site\n    index: index.htm\n",
        )
        .unwrap();
        assert_eq!(single.vhost[0].index.as_deref().unwrap(), ["index.htm"]);

        let list = parse_file_config(
            "vhost:\n  - server_names: [list.example]\n    root: /srv/list\n    user: site\n    index: [index.htm, index.html]\n",
        )
        .unwrap();
        let indexes = list.vhost[0].index.as_deref().unwrap();
        assert_eq!(indexes, ["index.htm", "index.html"]);
        validate_index(indexes).unwrap();
        assert!(validate_index(&[]).is_err());

        let empty = parse_file_config(
            "vhost:\n  - server_names: [empty.example]\n    root: /srv/empty\n    user: site\n    index: []\n",
        )
        .unwrap();
        assert!(validate_index(empty.vhost[0].index.as_deref().unwrap()).is_err());
    }

    #[test]
    fn scans_visible_yaml_files_in_sorted_order() {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "project-charlotte-vhost-scan-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        for name in [
            "b.yaml",
            "a.yml",
            "c.yaml",
            "legacy.toml",
            ".hidden.yaml",
            "swap.yaml~",
            "temp.tmp",
        ] {
            std::fs::write(directory.join(name), "").unwrap();
        }
        std::fs::create_dir(directory.join("directory.yaml")).unwrap();

        let files = scan_vhost_files(&directory).unwrap();
        assert_eq!(
            files,
            vec![
                directory.join("a.yml"),
                directory.join("b.yaml"),
                directory.join("c.yaml")
            ]
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn validates_vhost_tls_certificate_pair() {
        let mut entry = declaration(&["example.test"], false);
        entry.tls_cert = Some("cert.pem".into());
        assert!(validate_vhost_declarations(&[entry]).is_err());
        let mut entry = declaration(&["example.test"], false);
        entry.tls_cert = Some("cert.pem".into());
        entry.tls_key = Some("key.pem".into());
        assert!(validate_vhost_declarations(&[entry]).is_ok());
    }

    #[test]
    fn rejects_unknown_vhost_user_and_builds_worker_arguments() {
        assert!(resolve_identity("charlotte-no-such-user", None).is_err());
        let backends = [
            FastCgiBackend {
                extension: "php".to_owned(),
                address: FastCgiAddress::Tcp("127.0.0.1:9000".to_owned()),
            },
            FastCgiBackend {
                extension: "cgi".to_owned(),
                address: FastCgiAddress::Spawn(FastCgiApp {
                    program: "/usr/bin/php8.4-cgi".into(),
                    args: vec!["--foreground".to_owned()],
                    env: BTreeMap::from([("APP_MODE".to_owned(), "worker".to_owned())]),
                    max_workers: 4,
                    idle_timeout: Duration::from_secs(12),
                }),
            },
        ];
        let args = build_worker_args(WorkerArgs {
            uid: 1001,
            gid: 1002,
            root: Path::new("/srv/example"),
            index: &["home.php".to_owned(), "index.php".to_owned()],
            listing: false,
            try_files: &["$uri".to_owned(), "=404".to_owned()],
            fastcgi: &backends,
            timeout: Duration::from_secs(12),
            error_log_format: "[%l] %M",
        });
        let args = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.windows(2).any(|pair| pair == ["--worker-uid", "1001"]));
        assert!(args.contains(&"--no-listing".to_owned()));
        assert!(args.windows(2).any(|pair| pair == ["--try-files", "$uri"]));
        assert!(args.windows(2).any(|pair| pair == ["--try-files", "=404"]));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--fastcgi", "php=127.0.0.1:9000"])
        );
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--fastcgi-app", "cgi=/usr/bin/php8.4-cgi"] })
        );
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--fastcgi-app-arg", "cgi=--foreground"] })
        );
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--fastcgi-app-max-workers", "cgi=4"] })
        );
        assert!(
            args.windows(2)
                .any(|pair| { pair == ["--fastcgi-app-idle-timeout", "cgi=12"] })
        );
        // App environment may hold credentials, so it must stay off the
        // command line, which every local user can read.
        assert!(!args.iter().any(|arg| arg.contains("APP_MODE")));
        assert_eq!(
            worker_app_env(&backends).as_deref(),
            Some(r#"[["cgi","APP_MODE","worker"]]"#)
        );
        assert_eq!(worker_app_env(&backends[..1]), None);
    }

    #[test]
    fn parses_and_forwards_vhost_cgi_backends() {
        let file = parse_file_config(
            "vhost:\n  - server_names: [cgi.example]\n    root: /srv/cgi\n    user: cgi\n    cgi: [cgi, py=/usr/bin/python3]\n",
        )
        .unwrap();
        assert_eq!(file.vhost[0].cgi, ["cgi", "py=/usr/bin/python3"]);
        let backends = file.vhost[0]
            .cgi
            .iter()
            .map(|value| crate::config::parse_cgi_backend(value).unwrap())
            .collect::<Vec<_>>();
        let args = build_worker_args(WorkerArgs {
            uid: 1001,
            gid: 1002,
            root: Path::new("/srv/cgi"),
            index: &["index.html".to_owned()],
            listing: true,
            try_files: &[],
            fastcgi: &backends,
            timeout: Duration::from_secs(30),
            error_log_format: "[%l] %M",
        });
        let args = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(args.windows(2).any(|pair| pair == ["--cgi", "cgi"]));
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--cgi", "py=/usr/bin/python3"])
        );
    }

    #[test_fuzz::test_fuzz]
    fn host_selection(host: String, uri: String, names: Vec<String>) {
        let Ok(mut request) = Request::builder().uri(uri).body(()) else {
            return;
        };
        if let Ok(value) = HeaderValue::from_str(&host) {
            request.headers_mut().insert("host", value);
        }
        let Some(host) = request_host(&request) else {
            return;
        };
        for name in names {
            let Some(pattern) = normalize_server_name(&name) else {
                continue;
            };
            match pattern.strip_prefix("*.") {
                Some(suffix) => {
                    // A wildcard covers subdomains only: never the apex, and
                    // never a different domain that merely ends the same way.
                    assert_eq!(match_score(&pattern, suffix), None);
                    assert_eq!(match_score(&pattern, &format!("a{suffix}")), None);
                    assert!(
                        match_score(&pattern, &format!("a.{suffix}"))
                            .is_some_and(|score| score < usize::MAX)
                    );
                    if match_score(&pattern, &host).is_some() {
                        assert!(host.ends_with(&format!(".{suffix}")));
                    }
                }
                None => {
                    assert_eq!(match_score(&pattern, &pattern), Some(usize::MAX));
                    if match_score(&pattern, &host).is_some() {
                        assert_eq!(pattern, host);
                    }
                }
            }
        }
    }

    #[test]
    fn fuzz_seed_host_selection() {
        host_selection(
            "Api.Example.test:8443".to_owned(),
            "/path".to_owned(),
            vec!["api.example.test".to_owned(), "*.example.test".to_owned()],
        );
        host_selection(
            "[2001:db8::1]:8080".to_owned(),
            "/".to_owned(),
            vec!["2001:db8::1".to_owned()],
        );
    }

    #[test_fuzz::test_fuzz]
    fn vhost_yaml(input: String) {
        if let Ok(file) = serde_yaml_ng::from_str::<FileConfig>(&input) {
            let _ = validate_vhost_declarations(&file.vhost);
        }
    }

    #[test]
    fn fuzz_seed_vhost_yaml() {
        vhost_yaml(
            "vhost:\n  - server_names: [example.test]\n    root: /tmp/site\n    user: user\n"
                .to_owned(),
        );
        vhost_yaml("vhost:\n  - server_names: [\"*..\"]\n".to_owned());
    }

    #[test_fuzz::test_fuzz]
    fn router_request(input: FuzzRequest) {
        let Some(request) = input.build() else {
            return;
        };
        let fixture = fuzz_support::fixture();
        let mut config = fuzz_support::fuzz_config(fixture.root.clone());
        config.fastcgi.clear();
        let (peer, local) = fuzz_support::addresses();
        let method = request.method().clone();
        let collected = fuzz_support::collect(async {
            let router = Router::load(Arc::new(config), None, None, None, None)
                .await
                .expect("fallback router loads");
            router.dispatch(request, peer, local).await
        });
        assert!(
            collected.error.is_none(),
            "router response body should be readable"
        );
        fuzz_support::assert_response_invariants(&method, &collected);
    }

    #[test]
    fn fuzz_seed_router_request() {
        router_request(FuzzRequest::default());
        router_request(FuzzRequest {
            uri: "/escape.txt".to_owned(),
            ..FuzzRequest::default()
        });
    }

    /// A routing table whose workers are never started; it exercises vhost
    /// selection and request rewriting without spawning processes.
    fn fuzz_table(default: bool) -> VhostTable {
        let vhost = |names: &[&str], default: bool| {
            Arc::new(Vhost {
                names: names.iter().map(|name| (*name).to_owned()).collect(),
                tls: None,
                https_redirect: None,
                #[cfg(feature = "acme")]
                acme: false,
                default,
                waf: None,
                rate_limit: super::VhostRateLimit::Inherit,
                bot: super::VhostBot::Inherit,
                access_log: None,
                error_log: Arc::new(crate::logging::ErrorLog::new(
                    crate::logging::LogTarget::stderr(),
                    crate::logging::ErrorFormat::parse("%M").expect("valid test format"),
                )),
                worker: Some(Arc::new(Worker {
                    uid: 0,
                    gid: 0,
                    root: PathBuf::from("/"),
                    cgroup: None,
                    idle_timeout: None,
                    active: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                    last_used: Arc::new(std::sync::Mutex::new(std::time::Instant::now())),
                    index: vec!["index.html".to_owned()],
                    listing: false,
                    try_files: Vec::new(),
                    fastcgi: Vec::new(),
                    fastcgi_timeout: Duration::from_secs(1),
                    threads: 1,
                    error_log_file: None,
                    error_log_format: "[%l] %M".to_owned(),
                    process: tokio::sync::Mutex::new(None),
                })),
                #[cfg(feature = "proxy")]
                proxy: None,
            })
        };
        VhostTable {
            vhosts: vec![
                vhost(&["example.test", "*.example.test"], false),
                vhost(&["other.test", "*.dev.example.test"], default),
            ],
            default: default.then_some(1),
        }
    }

    /// Routes a request to a vhost in the master and unpacks it again the way
    /// the worker does. The worker must see exactly the request target that
    /// the master (and therefore the WAF) saw.
    #[test_fuzz::test_fuzz]
    fn worker_roundtrip(input: FuzzRequest, sni: Option<String>, default: bool) {
        let Some(mut request) = input.build() else {
            return;
        };
        let has_sni = sni.is_some();
        if let Some(sni) = sni {
            request.extensions_mut().insert(TlsSni(Some(sni.into())));
        }
        let table = fuzz_table(default);
        let host = request_host(&request);
        let index = match select_route(&table, &request, host.as_deref()) {
            Ok(Some(index)) => index,
            Ok(None) => {
                assert!(!default, "a default vhost handles every request");
                return;
            }
            Err((status, _)) => {
                assert_eq!(status, StatusCode::MISDIRECTED_REQUEST);
                assert!(has_sni && host.is_some());
                return;
            }
        };
        if !default {
            let host = host
                .as_deref()
                .expect("only a default matches without a host");
            assert!(
                table.vhosts[index]
                    .names
                    .iter()
                    .any(|name| match_score(name, host).is_some())
            );
        }

        let version = request.version();
        let target = match request.uri().path_and_query().map(|value| value.as_str()) {
            None | Some("*") => "/".to_owned(),
            Some(value) => value.to_owned(),
        };
        let (peer, local) = fuzz_support::addresses();
        let Ok(mut forwarded) = worker_request(request, host.as_deref(), peer, local) else {
            return;
        };
        // The master's connection state is not the client's to assert.
        forwarded.extensions_mut().remove::<TlsSni>();
        assert_eq!(forwarded.version(), Version::HTTP_2);
        assert_eq!(
            forwarded.headers().get(HOST).map(HeaderValue::as_bytes),
            forwarded
                .uri()
                .authority()
                .map(|authority| authority.as_str().as_bytes())
        );

        let addresses = crate::worker::prepare_request(&mut forwarded)
            .expect("worker accepts the request the master forwarded");
        assert_eq!(addresses, (peer, local));
        assert_eq!(forwarded.extensions().get::<TlsSni>().is_some(), has_sni);
        assert_eq!(forwarded.version(), version);
        assert_eq!(
            forwarded
                .uri()
                .path_and_query()
                .map_or("/", |value| value.as_str()),
            target
        );
    }

    #[test]
    fn fuzz_seed_worker_roundtrip() {
        worker_roundtrip(
            FuzzRequest {
                uri: "/a.php?x=1".to_owned(),
                headers: vec![
                    ("host".to_owned(), b"www.example.test:8443".to_vec()),
                    ("x-charlotte-peer".to_owned(), b"203.0.113.9:1".to_vec()),
                ],
                ..FuzzRequest::default()
            },
            Some("www.example.test".to_owned()),
            false,
        );
        worker_roundtrip(
            FuzzRequest {
                uri: "https://other.test/".to_owned(),
                version: "HTTP/2.0".to_owned(),
                ..FuzzRequest::default()
            },
            Some("example.test".to_owned()),
            false,
        );
        worker_roundtrip(
            FuzzRequest {
                method: "OPTIONS".to_owned(),
                uri: "*".to_owned(),
                ..FuzzRequest::default()
            },
            None,
            true,
        );
        worker_roundtrip(
            FuzzRequest {
                uri: "/ignored".to_owned(),
                headers: vec![("host".to_owned(), b"x/admin.php?".to_vec())],
                ..FuzzRequest::default()
            },
            None,
            true,
        );
    }

    #[test]
    fn refuses_world_writable_configuration() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "project-charlotte-trust-{}-{}.yaml",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ensure_trusted_config(&path).is_ok());
        assert!(!trusted_write_mode(0o664, false));
        assert!(trusted_write_mode(0o664, true));
        assert!(!trusted_write_mode(0o666, true));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(ensure_trusted_config(&path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn trusted_configuration_is_a_regular_file_read_through_its_descriptor() {
        let directory = std::env::temp_dir().join(format!(
            "project-charlotte-trusted-read-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("site.yaml");
        std::fs::write(&path, "vhost: []\n").unwrap();
        let link = directory.join("enabled.yaml");
        std::os::unix::fs::symlink(&path, &link).unwrap();

        assert_eq!(super::read_trusted_config(&path).unwrap(), "vhost: []\n");
        assert_eq!(super::read_trusted_config(&link).unwrap(), "vhost: []\n");
        let error = super::read_trusted_config(&directory).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn helper_directories_cover_configured_logs_and_tls_files() {
        let directory = std::env::temp_dir().join(format!(
            "project-charlotte-helper-directories-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let vhosts = directory.join("vhosts.d");
        std::fs::create_dir_all(&vhosts).unwrap();
        let config_path = directory.join("charlotte.yaml");
        std::fs::write(
            &config_path,
            "vhost_dir: vhosts.d\nvhost:\n  - server_names: [main.example.test]\n    proxy_pass: http://127.0.0.1:9\n    access_log: logs/main.log\n    tls_cert: /etc/ssl/main/cert.pem\n    tls_key: /etc/ssl/private/main.key\n",
        )
        .unwrap();
        std::fs::write(
            vhosts.join("site.yaml"),
            "vhost:\n  - server_names: [site.example.test]\n    proxy_pass: http://127.0.0.1:9\n    error_log: /var/log/site/error.log\n    access_log: /var/log/site/access.log\n",
        )
        .unwrap();
        let ParseResult::Config(config) = Config::parse([
            "--config".to_owned(),
            config_path.to_string_lossy().into_owned(),
            "--error-log-file".to_owned(),
            "/var/log/charlotte/error.log".to_owned(),
            "--log-dir".to_owned(),
            "/srv/logs".to_owned(),
            "--tls-dir".to_owned(),
            "/srv/tls".to_owned(),
        ])
        .unwrap() else {
            panic!("expected config")
        };

        let (logs, tls) = super::helper_directories(&config).unwrap();

        assert_eq!(
            logs,
            [
                PathBuf::from("/srv/logs"),
                PathBuf::from("/var/log/charlotte"),
                directory.join("logs"),
                PathBuf::from("/var/log/site"),
            ]
        );
        assert_eq!(
            tls,
            [
                PathBuf::from("/srv/tls"),
                PathBuf::from("/etc/ssl/main"),
                PathBuf::from("/etc/ssl/private"),
            ]
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_configuration_error_includes_path() {
        let path = std::env::temp_dir().join(format!(
            "project-charlotte-missing-config-{}-{}.yaml",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));

        let error = ensure_trusted_config(&path).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert!(error.to_string().contains(&path.display().to_string()));
    }

    #[test]
    fn host_header_cannot_replace_the_worker_request_path() {
        let (peer, local) = fuzz_support::addresses();
        for host in ["x/admin.php?", "x/admin.php#", "x?y", "a b", ""] {
            let request = Request::builder()
                .uri("/inspected")
                .header(HOST, host)
                .body(())
                .unwrap();
            let rejection = worker_request(request, None, peer, local).unwrap_err();
            assert_eq!(rejection.0, StatusCode::BAD_REQUEST, "Host: {host:?}");
        }
        let request = Request::builder()
            .uri("/inspected")
            .header(HOST, "example.test:8443")
            .body(())
            .unwrap();
        let forwarded = worker_request(request, None, peer, local).unwrap();
        assert_eq!(forwarded.uri(), "http://example.test:8443/inspected");
    }

    /// A spawned FastCGI app as `(extension, command, environment)`.
    type FuzzApp = (String, Vec<String>, Vec<(String, String)>);

    /// The master hands each worker its configuration as command-line
    /// arguments. Whatever vhost validation accepts must reach the worker
    /// unchanged.
    #[test_fuzz::test_fuzz]
    fn worker_args(
        index: Vec<String>,
        listing: bool,
        try_files: Vec<String>,
        fastcgi: Vec<String>,
        apps: Vec<FuzzApp>,
        timeout: u64,
        root: String,
    ) {
        if validate_index(&index).is_err()
            || validate_try_files(&try_files).is_err()
            || timeout == 0
        {
            return;
        }
        // Vhost roots are resolved against the config directory before the
        // master builds worker arguments, so an empty root is unreachable.
        if root.is_empty() {
            return;
        }
        let mut backends = Vec::new();
        for value in &fastcgi {
            let Ok(backend) = parse_fastcgi_backend(value) else {
                return;
            };
            backends.push(backend);
        }
        for (extension, command, env) in apps {
            let (Ok(extension), Some(program)) = (normalize_extension(&extension), command.first())
            else {
                return;
            };
            if command.iter().any(|part| part.contains('\0'))
                || env
                    .iter()
                    .any(|(key, value)| validate_env_key(key).is_err() || value.contains('\0'))
            {
                return;
            }
            let Ok(mut backend) = parse_fastcgi_app(&format!("{extension}={program}")) else {
                return;
            };
            if let FastCgiAddress::Spawn(app) = &mut backend.address {
                app.args = command.into_iter().skip(1).collect();
                app.env = env.into_iter().collect();
            }
            backends.push(backend);
        }
        let mut extensions = HashSet::new();
        if !backends
            .iter()
            .all(|backend| extensions.insert(backend.extension.clone()))
        {
            return;
        }

        let args = build_worker_args(WorkerArgs {
            uid: 1000,
            gid: 1001,
            root: Path::new(&root),
            index: &index,
            listing,
            try_files: &try_files,
            fastcgi: &backends,
            timeout: Duration::from_secs(timeout),
            error_log_format: "[%l] %M",
        })
        .into_iter()
        .map(|arg| arg.into_string().expect("worker arguments are UTF-8"))
        .collect::<Vec<_>>();
        let mut config = match Config::parse(args) {
            Ok(ParseResult::Config(config)) => config,
            Ok(ParseResult::Help) => panic!("worker arguments were parsed as a help request"),
            Err(error) => panic!("worker rejected the master's arguments: {error}"),
        };
        if let Some(app_env) = worker_app_env(&backends) {
            config
                .apply_fastcgi_app_env(&app_env)
                .expect("worker accepts the app environment the master encoded");
        }
        assert!(config.worker);
        assert_eq!(
            (config.worker_uid, config.worker_gid),
            (Some(1000), Some(1001))
        );
        assert_eq!(config.root, Path::new(&root));
        assert_eq!(config.index, index);
        assert_eq!(config.listing, listing);
        assert_eq!(config.try_files, try_files);
        assert_eq!(config.fastcgi_timeout, Duration::from_secs(timeout));
        assert_eq!(format!("{:?}", config.fastcgi), format!("{backends:?}"));
    }

    #[test]
    fn fuzz_seed_worker_args() {
        worker_args(
            vec!["index.php".to_owned()],
            false,
            vec!["$uri".to_owned(), "/index.php?$args".to_owned()],
            vec![
                "php=127.0.0.1:9000".to_owned(),
                "py=unix:/run/py.sock".to_owned(),
            ],
            vec![(
                "cgi".to_owned(),
                vec![
                    "/usr/bin/app".to_owned(),
                    "--mode=fast".to_owned(),
                    "--help".to_owned(),
                ],
                vec![("APP_MODE".to_owned(), "a=b".to_owned())],
            )],
            30,
            "/srv/site".to_owned(),
        );
        worker_args(
            vec!["--no-listing".to_owned()],
            true,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            1,
            "--help".to_owned(),
        );
        worker_args(
            vec!["index.php".to_owned()],
            false,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            1,
            String::new(),
        );
    }
}

/// Tests that hold in every combination of features, unlike those above,
/// which need a hosted site to route to.
#[cfg(test)]
mod feature_tests {
    use super::{
        check_config, missing_feature, parse_file_config, validate_vhost_declarations,
        vhost_entry_lines,
    };
    use crate::config::{Config, ParseResult};
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    fn temp_dir() -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "project-charlotte-check-config-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    fn check_file(path: &Path) -> Vec<String> {
        let ParseResult::Config(config) = Config::parse([
            "--check-config".to_owned(),
            "--config".to_owned(),
            path.to_string_lossy().into_owned(),
        ])
        .unwrap() else {
            panic!("expected a configuration");
        };
        check_config(&config)
    }

    fn declaration(yaml: &str) -> super::VhostFile {
        parse_file_config(yaml).unwrap().vhost.remove(0)
    }

    #[test]
    fn names_the_feature_a_declaration_needs() {
        let proxied =
            declaration("vhost:\n  - server_names: [a.test]\n    proxy_pass: http://127.0.0.1:1\n");
        assert_eq!(
            missing_feature(&proxied),
            (!cfg!(feature = "proxy")).then_some("proxy")
        );

        let hosted =
            declaration("vhost:\n  - server_names: [b.test]\n    root: /srv/b\n    user: nobody\n");
        assert_eq!(
            missing_feature(&hosted),
            (!cfg!(feature = "hosting")).then_some("hosting")
        );

        // Opting out of ACME asks nothing of the build; opting in does.
        let mut entry = declaration(
            "vhost:\n  - server_names: [c.test]\n    proxy_pass: http://127.0.0.1:1\n    acme: false\n",
        );
        assert_eq!(missing_feature(&entry), missing_feature(&proxied));
        entry.acme = Some(true);
        let expected = if !cfg!(feature = "proxy") {
            Some("proxy")
        } else if !cfg!(feature = "acme") {
            Some("acme")
        } else {
            None
        };
        assert_eq!(missing_feature(&entry), expected);
    }

    #[test]
    fn refuses_declarations_of_features_left_out_of_the_build() {
        for (yaml, feature, enabled) in [
            (
                "vhost:\n  - server_names: [a.test]\n    proxy_pass: http://127.0.0.1:1\n",
                "proxy",
                cfg!(feature = "proxy"),
            ),
            (
                "vhost:\n  - server_names: [b.test]\n    root: /srv/b\n    user: nobody\n",
                "hosting",
                cfg!(feature = "hosting"),
            ),
        ] {
            let parsed = parse_file_config(yaml).unwrap();
            match validate_vhost_declarations(&parsed.vhost) {
                Ok(()) => assert!(
                    enabled,
                    "{feature} declaration accepted without the feature"
                ),
                Err(error) => {
                    assert!(!enabled, "{feature} declaration refused: {error}");
                    assert!(
                        error
                            .to_string()
                            .contains(&format!("requires the `{feature}` feature")),
                        "{error}"
                    );
                }
            }
        }
    }

    #[test]
    fn maps_block_sequence_entries_without_matching_nested_lists() {
        let content = concat!(
            "vhost:\n",
            "  - server_names: [first.test]\n",
            "    fastcgi_app:\n",
            "      - extension: php\n",
            "        command: [/usr/bin/php-cgi]\n",
            "  - server_names: [second.test]\n",
            "vhost_dir: ./sites\n",
        );
        assert_eq!(vhost_entry_lines(content), [2, 6]);
        assert_eq!(
            vhost_entry_lines("vhost:\n- server_names: [root.test]\n"),
            [2]
        );
    }

    #[test]
    fn check_config_reports_yaml_and_semantic_errors_with_entry_lines() {
        let directory = temp_dir();
        let syntax_path = directory.join("syntax.yaml");
        fs::write(&syntax_path, "vhost:\n  - server_names: [broken.test\n").unwrap();
        let syntax_errors = check_file(&syntax_path);
        assert!(
            syntax_errors
                .iter()
                .any(|error| error.starts_with(&format!("{}:3:", syntax_path.display()))),
            "{syntax_errors:?}"
        );

        #[cfg(feature = "proxy")]
        {
            let semantic_path = directory.join("semantic.yaml");
            fs::write(
                &semantic_path,
                concat!(
                    "vhost:\n",
                    "  - server_names: [rate.test]\n",
                    "    proxy_pass: http://127.0.0.1:8080\n",
                    "    rate_limit: invalid\n",
                    "  - server_names: [second-rate.test]\n",
                    "    proxy_pass: http://127.0.0.1:8080\n",
                    "    rate_limit: invalid\n",
                ),
            )
            .unwrap();
            let semantic_errors = check_file(&semantic_path);
            for line in [2, 5] {
                assert!(
                    semantic_errors.iter().any(|error| {
                        error.starts_with(&format!("{}:{line}:", semantic_path.display()))
                            && error.contains("rate_limit")
                    }),
                    "{semantic_errors:?}"
                );
            }
        }
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn check_config_rejects_global_options_in_vhost_directory_files() {
        let directory = temp_dir();
        let vhost_dir = directory.join("sites");
        fs::create_dir_all(&vhost_dir).unwrap();
        let main_path = directory.join("main.yaml");
        fs::write(&main_path, "vhost_dir: sites\n").unwrap();
        let site_path = vhost_dir.join("site.yaml");
        fs::write(
            &site_path,
            "options:\n  debug: true\nvhost:\n  - server_names: [site.test]\n    proxy_pass: http://127.0.0.1:8080\n",
        )
        .unwrap();

        let errors = check_file(&main_path);
        assert!(
            errors.iter().any(|error| {
                error.starts_with(&site_path.display().to_string())
                    && error.contains("options are only allowed in the main config file")
            }),
            "{errors:?}"
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn check_config_reports_duplicate_names_across_main_and_directory_files() {
        let directory = temp_dir();
        let vhost_dir = directory.join("sites");
        fs::create_dir_all(&vhost_dir).unwrap();
        let main_path = directory.join("main.yaml");
        fs::write(
            &main_path,
            concat!(
                "vhost_dir: sites\n",
                "vhost:\n",
                "  - server_names: [duplicate.test]\n",
                "    proxy_pass: http://127.0.0.1:8080\n",
                "    default: true\n",
            ),
        )
        .unwrap();
        let dir_path = vhost_dir.join("site.yaml");
        fs::write(
            &dir_path,
            concat!(
                "vhost:\n",
                "  - server_names: [duplicate.test]\n",
                "    proxy_pass: http://127.0.0.1:8080\n",
                "    default: true\n",
            ),
        )
        .unwrap();

        let errors = check_file(&main_path);
        assert!(
            errors.iter().any(|error| {
                error.starts_with(&format!("{}:2:", dir_path.display()))
                    && error.contains("duplicate virtual host name")
                    && error.contains(&format!("{}:3", main_path.display()))
            }),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|error| {
                error.starts_with(&format!("{}:2:", dir_path.display()))
                    && error.contains("only one vhost may be marked default")
                    && error.contains(&format!("{}:3", main_path.display()))
            }),
            "{errors:?}"
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[cfg(feature = "proxy")]
    #[test]
    fn reverse_proxy_acme_example_parses_and_validates() {
        let parsed =
            parse_file_config(include_str!("../examples/reverse-proxy-acme.yaml")).unwrap();
        assert!(validate_vhost_declarations(&parsed.vhost).is_ok());
        assert!(!parsed.vhost.is_empty());
        assert!(parsed.vhost.iter().all(|vhost| {
            vhost.proxy_pass.is_some()
                && vhost.tls_cert.is_none()
                && vhost.tls_key.is_none()
                && vhost.acme != Some(false)
        }));
    }
}
