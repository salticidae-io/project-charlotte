//! Command-line parsing and shared server, virtual-host, and backend settings.

// Every build parses the same settings into the same structures, and refuses
// the options of a feature it was built without before they take effect.
// What a reduced build never reads is therefore not an oversight.
#![cfg_attr(
    not(all(feature = "acme", feature = "hosting", feature = "http3")),
    allow(dead_code)
)]

#[cfg(feature = "hosting")]
use crate::cgroup::CgroupSpec;
use crate::{
    bot::{BotPolicy, BotPolicyFile},
    forwarded::TrustedProxy,
    ratelimit::RateLimit,
};
use clap::{
    ArgAction, ArgMatches, ColorChoice, CommandFactory, FromArgMatches, Parser, error::ErrorKind,
    parser::ValueSource,
};
#[cfg(feature = "hosting")]
use std::sync::Arc;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Debug)]
pub struct FastCgiBackend {
    pub extension: String,
    pub address: FastCgiAddress,
}

#[derive(Clone, Debug)]
pub enum FastCgiAddress {
    Tcp(String),
    Unix(PathBuf),
    Cgi(Option<PathBuf>),
    Spawn(FastCgiApp),
    #[cfg(feature = "hosting")]
    Pool(Arc<crate::fastcgi_app::AppPool>),
}

#[derive(Clone, Debug)]
pub struct FastCgiApp {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub min_workers: usize,
    pub max_workers: usize,
    pub idle_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub debug: bool,
    pub server_timing: bool,
    pub plain_http: bool,
    pub https_redirect: bool,
    pub bind: SocketAddr,
    pub max_connections: usize,
    pub header_read_timeout: Duration,
    pub tls_handshake_timeout: Duration,
    pub tls_bind: Option<SocketAddr>,
    pub http3_bind: SocketAddr,
    pub root: PathBuf,
    pub config_file: Option<PathBuf>,
    pub vhost_dir: Option<PathBuf>,
    pub control_socket: Option<PathBuf>,
    pub index: Vec<String>,
    pub listing: bool,
    pub try_files: Vec<String>,
    pub fastcgi: Vec<FastCgiBackend>,
    pub fastcgi_timeout: Duration,
    pub threads: Option<usize>,
    pub worker_threads: usize,
    pub worker_idle_timeout: Duration,
    #[cfg(feature = "hosting")]
    pub worker_cgroup: Option<CgroupSpec>,
    pub(crate) rate_limit: Option<RateLimit>,
    pub(crate) trusted_proxies: Vec<TrustedProxy>,
    pub(crate) access_log: bool,
    pub(crate) access_log_file: Option<PathBuf>,
    pub(crate) log_dirs: Vec<PathBuf>,
    pub(crate) tls_dirs: Vec<PathBuf>,
    pub(crate) access_log_format: String,
    pub(crate) error_log_file: Option<PathBuf>,
    pub(crate) error_log_format: String,
    pub(crate) bot: Option<BotPolicyFile>,
    pub modsecurity_rules: Vec<PathBuf>,
    pub modsecurity_block_status: Option<u16>,
    pub modsecurity_body_limit: usize,
    pub modsecurity_response_body_limit: usize,
    pub tls: Option<TlsFiles>,
    pub acme: Option<AcmeSettings>,
    pub check_config: bool,
    pub worker: bool,
    pub worker_uid: Option<u32>,
    pub worker_gid: Option<u32>,
    pub master_user: Option<String>,
    pub master_group: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AcmeSettings {
    pub directory: String,
    pub cache: PathBuf,
    pub contacts: Vec<String>,
    pub ca_root: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct TlsFiles {
    pub cert: PathBuf,
    pub key: PathBuf,
}

pub enum ParseResult {
    Help,
    Config(Box<Config>),
}

const HOSTING: bool = cfg!(feature = "hosting");
const ACME: bool = cfg!(feature = "acme");
const HTTP3: bool = cfg!(feature = "http3");

/// Command-line options. Every build accepts the same set so that options of
/// a compiled-out feature can be refused with a clear message; those options
/// are hidden from the help text.
#[derive(Debug, Parser)]
#[command(
    name = "project-charlotte",
    args_override_self = true,
    disable_version_flag = true,
    color = ColorChoice::Never
)]
struct Cli {
    /// Log verbose startup details
    #[arg(long)]
    debug: bool,
    /// Add per-request stage durations to the Server-Timing response header
    #[arg(long)]
    server_timing: bool,
    /// Drop privileges to this user after binding the listeners
    #[arg(long, value_name = "USER", value_parser = parse_cli_name("--user", "user"), allow_hyphen_values = true)]
    user: Option<String>,
    /// Group to drop privileges to (requires --user)
    #[arg(long, value_name = "GROUP", value_parser = parse_cli_name("--group", "group"), allow_hyphen_values = true)]
    group: Option<String>,
    /// Plain HTTP listen address
    #[arg(long, value_name = "ADDRESS", default_value = "127.0.0.1:8080", value_parser = parse_cli_address("socket address"), allow_hyphen_values = true)]
    bind: SocketAddr,
    /// Maximum number of concurrent client connections
    #[arg(long, value_name = "N", default_value = "4096", value_parser = parse_positive_usize, allow_hyphen_values = true)]
    max_connections: usize,
    /// Seconds allowed to receive a complete request head
    #[arg(long, value_name = "SECS", default_value = "30", value_parser = parse_cli_timeout, allow_hyphen_values = true)]
    header_read_timeout: Duration,
    /// Seconds allowed to complete a TLS handshake
    #[arg(long, value_name = "SECS", default_value = "10", value_parser = parse_cli_timeout, allow_hyphen_values = true)]
    tls_handshake_timeout: Duration,
    /// Disable the plain HTTP listener
    #[arg(long)]
    no_plain_http: bool,
    /// Redirect HTTP requests for certified virtual hosts to HTTPS
    #[arg(long)]
    https_redirect: bool,
    /// TLS (HTTP/1.1 and HTTP/2) listen address
    #[arg(long, value_name = "ADDRESS", value_parser = parse_cli_address("TLS socket address"), allow_hyphen_values = true)]
    tls_bind: Option<SocketAddr>,
    /// Document root of the fallback site
    #[arg(long, value_name = "DIRECTORY", default_value = ".", hide = !HOSTING, allow_hyphen_values = true)]
    root: PathBuf,
    /// Directory index file name (may be repeated or comma-separated, in lookup order)
    #[arg(long, value_name = "NAME", value_delimiter = ',', default_value = "index.html", hide = !HOSTING, allow_hyphen_values = true)]
    index: Vec<String>,
    /// Disable directory listings
    #[arg(long, hide = !HOSTING)]
    no_listing: bool,
    /// try_files entry (repeat for each entry, in order)
    #[arg(long, value_name = "ENTRY", hide = !HOSTING, allow_hyphen_values = true)]
    try_files: Vec<String>,
    /// FastCGI backend for an extension (ADDR is HOST:PORT or unix:PATH)
    #[arg(long, value_name = "EXT=ADDR", hide = !HOSTING, allow_hyphen_values = true)]
    fastcgi: Vec<String>,
    /// Classic CGI extension, optionally run through an interpreter
    #[arg(long, value_name = "EXT[=INTERPRETER]", hide = !HOSTING, allow_hyphen_values = true)]
    cgi: Vec<String>,
    /// Spawned FastCGI application for an extension
    #[arg(long, value_name = "EXT=PROGRAM", hide = !HOSTING, allow_hyphen_values = true)]
    fastcgi_app: Vec<String>,
    /// Argument passed to a spawned FastCGI application
    #[arg(long, value_name = "EXT=ARG", hide = !HOSTING, allow_hyphen_values = true)]
    fastcgi_app_arg: Vec<String>,
    /// Maximum worker processes of a spawned FastCGI application
    #[arg(long, alias = "fastcgi-app-workers", value_name = "EXT=N", hide = !HOSTING, allow_hyphen_values = true)]
    fastcgi_app_max_workers: Vec<String>,
    /// Minimum number of warm spawned FastCGI application workers
    #[arg(long, value_name = "EXT=N", hide = !HOSTING, allow_hyphen_values = true)]
    fastcgi_app_min_workers: Vec<String>,
    /// Seconds an idle FastCGI application worker is kept before it is stopped
    #[arg(long, value_name = "EXT=SECS", hide = !HOSTING, allow_hyphen_values = true)]
    fastcgi_app_idle_timeout: Vec<String>,
    /// Environment variable of a spawned FastCGI application
    #[arg(long, value_name = "EXT=KEY=VALUE", hide = !HOSTING, allow_hyphen_values = true)]
    fastcgi_app_env: Vec<String>,
    /// FastCGI/CGI timeout in seconds
    #[arg(long, value_name = "SECS", default_value = "60", value_parser = parse_cli_fastcgi_timeout, hide = !HOSTING, allow_hyphen_values = true)]
    fastcgi_timeout: Duration,
    /// Runtime threads of the master process
    #[arg(long, value_name = "N", value_parser = parse_thread_count, allow_hyphen_values = true)]
    threads: Option<usize>,
    /// Runtime threads of each vhost worker
    #[arg(long, value_name = "N", default_value_t = DEFAULT_WORKER_THREADS, value_parser = parse_thread_count, hide = !HOSTING, allow_hyphen_values = true)]
    worker_threads: usize,
    /// Seconds a hosted worker is kept alive without requests; 0 disables reaping
    #[arg(long, value_name = "SECS", default_value = "300", hide = !HOSTING, allow_hyphen_values = true)]
    worker_idle_timeout: u64,
    /// Cgroup v2 path for hosted workers, relative to /sys/fs/cgroup
    #[arg(long, value_name = "PATH", hide = !HOSTING, allow_hyphen_values = true)]
    worker_cgroup: Option<String>,
    /// Memory limit for hosted workers (bytes or K/M/G/T; max for unlimited)
    #[arg(long, value_name = "LIMIT", hide = !HOSTING, allow_hyphen_values = true)]
    worker_cgroup_memory_max: Option<String>,
    /// CPU limit for hosted workers (max, percentage, or QUOTA [PERIOD])
    #[arg(long, value_name = "LIMIT", hide = !HOSTING, allow_hyphen_values = true)]
    worker_cgroup_cpu_max: Option<String>,
    /// PID limit for hosted workers (positive integer or max)
    #[arg(long, value_name = "LIMIT", hide = !HOSTING, allow_hyphen_values = true)]
    worker_cgroup_pids_max: Option<String>,
    /// Per-client request rate (N/s, N/m, or N/h)
    #[arg(long, value_name = "RATE", allow_hyphen_values = true)]
    rate_limit: Option<String>,
    /// Maximum burst for --rate-limit; defaults to the rate per second, rounded up
    #[arg(long, value_name = "N", allow_hyphen_values = true)]
    rate_limit_burst: Option<u32>,
    /// Trusted reverse-proxy address or CIDR; may be repeated
    #[arg(long, value_name = "CIDR", allow_hyphen_values = true)]
    trusted_proxy: Vec<String>,
    /// Write access-log records to stdout
    #[arg(long)]
    access_log: bool,
    /// Append access-log records to a file
    #[arg(long, value_name = "FILE", allow_hyphen_values = true)]
    access_log_file: Option<PathBuf>,
    /// Apache-compatible access log format
    #[arg(long, value_name = "FORMAT", allow_hyphen_values = true)]
    access_log_format: Option<String>,
    /// Append error-log records to a file
    #[arg(long, value_name = "FILE", allow_hyphen_values = true)]
    error_log_file: Option<PathBuf>,
    /// Directory the root helper may use for log files; may be repeated
    #[arg(long, value_name = "DIRECTORY", allow_hyphen_values = true)]
    log_dir: Vec<PathBuf>,
    /// Directory the root helper may use for TLS PEM files; may be repeated
    #[arg(long, value_name = "DIRECTORY", allow_hyphen_values = true)]
    tls_dir: Vec<PathBuf>,
    /// Apache-compatible error log format
    #[arg(long, value_name = "FORMAT", allow_hyphen_values = true)]
    error_log_format: Option<String>,
    /// Enable the built-in bot-detection policy
    #[arg(long)]
    bot_detection: bool,
    /// Load a bot-detection policy from YAML (also enables detection)
    #[arg(long, value_name = "FILE", allow_hyphen_values = true)]
    bot_config: Option<PathBuf>,
    /// Only activate bot protection while server traffic is busy (N/s, N/m, or N/h)
    #[arg(long, value_name = "RATE", allow_hyphen_values = true)]
    bot_busy_threshold: Option<String>,
    /// ModSecurity rules file (repeatable)
    #[arg(long, value_name = "FILE", allow_hyphen_values = true)]
    modsecurity_rules: Vec<PathBuf>,
    /// HTTP status returned for blocking interventions
    #[arg(long, value_name = "CODE", value_parser = parse_modsecurity_block_status, allow_hyphen_values = true)]
    modsecurity_block_status: Option<u16>,
    /// Request body inspection limit
    #[arg(long, value_name = "BYTES", value_parser = parse_cli_body_limit, allow_hyphen_values = true)]
    modsecurity_body_limit: Option<usize>,
    /// Response body inspection limit (defaults to 64 KiB)
    #[arg(long, value_name = "BYTES", value_parser = parse_cli_body_limit, allow_hyphen_values = true)]
    modsecurity_response_body_limit: Option<usize>,
    /// Virtual-host YAML file
    #[arg(long = "config", value_name = "YAML_FILE", allow_hyphen_values = true)]
    config_file: Option<PathBuf>,
    /// Directory of virtual-host YAML files, reloaded on change
    #[arg(long, value_name = "DIRECTORY", allow_hyphen_values = true)]
    vhost_dir: Option<PathBuf>,
    /// Unix socket for managing virtual hosts
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    control_socket: Option<PathBuf>,
    /// Validate virtual-host configuration and exit
    #[arg(long)]
    check_config: bool,
    /// Fallback TLS certificate chain (PEM)
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    tls_cert: Option<PathBuf>,
    /// Fallback TLS private key (PEM)
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    tls_key: Option<PathBuf>,
    /// ACME directory URL, or letsencrypt / letsencrypt-staging
    #[arg(long, value_name = "URL", value_parser = parse_cli_acme_directory, hide = !ACME, allow_hyphen_values = true)]
    acme_directory: Option<String>,
    /// ACME account and certificate cache directory
    #[arg(long, value_name = "DIR", hide = !ACME, allow_hyphen_values = true)]
    acme_cache: Option<PathBuf>,
    /// ACME account contact URI (repeatable)
    #[arg(long, value_name = "URI", value_parser = parse_cli_acme_contact, hide = !ACME, allow_hyphen_values = true)]
    acme_contact: Vec<String>,
    /// Extra CA root trusted for the ACME directory
    #[arg(long, value_name = "PEM", hide = !ACME, allow_hyphen_values = true)]
    acme_ca_root: Option<PathBuf>,
    /// HTTP/3 (QUIC) listen address; defaults to the TLS address
    #[arg(long, value_name = "ADDRESS", value_parser = parse_cli_address("HTTP/3 socket address"), hide = !HTTP3, allow_hyphen_values = true)]
    http3_bind: Option<SocketAddr>,
    // Internal options used when the master re-executes itself as a worker.
    #[arg(long, hide = true)]
    worker: bool,
    #[arg(long, hide = true, value_parser = parse_cli_id("uid"), allow_hyphen_values = true)]
    worker_uid: Option<u32>,
    #[arg(long, hide = true, value_parser = parse_cli_id("gid"), allow_hyphen_values = true)]
    worker_gid: Option<u32>,
}

/// Option ids grouped by the feature they belong to.
const FEATURE_OPTIONS: &[(&str, bool, &[&str])] = &[
    (
        "hosting",
        HOSTING,
        &[
            "worker",
            "worker_uid",
            "worker_gid",
            "root",
            "index",
            "no_listing",
            "try_files",
            "fastcgi",
            "cgi",
            "fastcgi_app",
            "fastcgi_app_arg",
            "fastcgi_app_max_workers",
            "fastcgi_app_min_workers",
            "fastcgi_app_idle_timeout",
            "fastcgi_app_env",
            "fastcgi_timeout",
            "worker_threads",
            "worker_idle_timeout",
            "worker_cgroup",
            "worker_cgroup_memory_max",
            "worker_cgroup_cpu_max",
            "worker_cgroup_pids_max",
        ],
    ),
    (
        "acme",
        ACME,
        &[
            "acme_directory",
            "acme_cache",
            "acme_contact",
            "acme_ca_root",
        ],
    ),
    ("http3", HTTP3, &["http3_bind"]),
];

impl Config {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<ParseResult, String> {
        let args = args.into_iter().collect::<Vec<_>>();
        let matches = match Cli::command().try_get_matches_from(
            std::iter::once("project-charlotte".to_owned()).chain(args.iter().cloned()),
        ) {
            Ok(matches) => matches,
            Err(error) if error.kind() == ErrorKind::DisplayHelp => return Ok(ParseResult::Help),
            Err(error) => return Err(error.to_string().trim_end().to_owned()),
        };
        let matches = if let Some(config_path) = matches.get_one::<PathBuf>("config_file") {
            let config_path = config_path.clone();
            let content = crate::vhost::read_trusted_config(&config_path)
                .map_err(|error| format!("{}: {error}", config_path.display()))?;
            let value: serde_yaml_ng::Value = match serde_yaml_ng::from_str(&content) {
                Ok(value) => value,
                Err(_) if matches.get_flag("check_config") => serde_yaml_ng::Value::Null,
                Err(error) => {
                    return Err(if let Some(location) = error.location() {
                        format!(
                            "{}:{}:{}: {error}",
                            config_path.display(),
                            location.line(),
                            location.column()
                        )
                    } else {
                        format!("{}: {error}", config_path.display())
                    });
                }
            };
            let options = value.as_mapping().and_then(|mapping| {
                mapping.get(serde_yaml_ng::Value::String("options".to_owned()))
            });
            if let Some(options) = options {
                let file_args = options_to_args(options, &matches, &config_path)?;
                if file_args.is_empty() {
                    matches
                } else {
                    match Cli::command().try_get_matches_from(
                        std::iter::once("project-charlotte".to_owned())
                            .chain(file_args)
                            .chain(args.iter().cloned()),
                    ) {
                        Ok(matches) => matches,
                        Err(error) if error.kind() == ErrorKind::DisplayHelp => {
                            return Ok(ParseResult::Help);
                        }
                        Err(error) => {
                            return Err(format!(
                                "{}: {}",
                                config_path.display(),
                                error.to_string().trim_end()
                            ));
                        }
                    }
                }
            } else {
                matches
            }
        } else {
            matches
        };
        reject_compiled_out_options(&matches)?;
        let cli = Cli::from_arg_matches(&matches).map_err(|error| error.to_string())?;

        let mut backend_values = indexed_values(&matches, "fastcgi", &cli.fastcgi);
        backend_values.extend(indexed_values(&matches, "cgi", &cli.cgi));
        backend_values.extend(indexed_values(&matches, "fastcgi_app", &cli.fastcgi_app));
        backend_values.sort_by_key(|(index, _, _)| *index);
        let mut fastcgi = Vec::new();
        for (_, kind, value) in backend_values {
            let backend = match kind {
                "fastcgi" => parse_fastcgi_backend(value)?,
                "cgi" => parse_cgi_backend(value)?,
                _ => parse_fastcgi_app(value)?,
            };
            add_backend(&mut fastcgi, backend)?;
        }

        let mut fastcgi_app_args = Vec::new();
        for value in &cli.fastcgi_app_arg {
            let (extension, arg) = value.split_once('=').ok_or_else(|| {
                format!("invalid FastCGI app argument: {value}; expected EXT=ARG")
            })?;
            if arg.contains('\0') {
                return Err("FastCGI app argument cannot contain NUL".to_owned());
            }
            fastcgi_app_args.push((normalize_extension(extension)?, arg.to_owned()));
        }

        let mut fastcgi_app_max_workers = Vec::new();
        for value in &cli.fastcgi_app_max_workers {
            let (extension, max_workers) = value.split_once('=').ok_or_else(|| {
                format!("invalid FastCGI app max worker count: {value}; expected EXT=N")
            })?;
            let extension = normalize_extension(extension)?;
            let max_workers = parse_fastcgi_app_max_workers(max_workers)?;
            if fastcgi_app_max_workers
                .iter()
                .any(|(existing, _): &(String, usize)| existing == &extension)
            {
                return Err(format!(
                    "duplicate FastCGI app max worker count for extension: {extension}"
                ));
            }
            fastcgi_app_max_workers.push((extension, max_workers));
        }

        let mut fastcgi_app_min_workers = Vec::new();
        for value in &cli.fastcgi_app_min_workers {
            let (extension, min_workers) = value.split_once('=').ok_or_else(|| {
                format!("invalid FastCGI app min worker count: {value}; expected EXT=N")
            })?;
            let extension = normalize_extension(extension)?;
            let min_workers = parse_fastcgi_app_min_workers(min_workers)?;
            if fastcgi_app_min_workers
                .iter()
                .any(|(existing, _): &(String, usize)| existing == &extension)
            {
                return Err(format!(
                    "duplicate FastCGI app min worker count for extension: {extension}"
                ));
            }
            fastcgi_app_min_workers.push((extension, min_workers));
        }

        let mut fastcgi_app_idle_timeouts = Vec::new();
        for value in &cli.fastcgi_app_idle_timeout {
            let (extension, timeout) = value.split_once('=').ok_or_else(|| {
                format!("invalid FastCGI app idle timeout: {value}; expected EXT=SECS")
            })?;
            let extension = normalize_extension(extension)?;
            let timeout = parse_fastcgi_app_idle_timeout(timeout)?;
            if fastcgi_app_idle_timeouts
                .iter()
                .any(|(existing, _): &(String, Duration)| existing == &extension)
            {
                return Err(format!(
                    "duplicate FastCGI app idle timeout for extension: {extension}"
                ));
            }
            fastcgi_app_idle_timeouts.push((extension, timeout));
        }

        let mut fastcgi_app_env = Vec::new();
        for value in &cli.fastcgi_app_env {
            let (extension, assignment) = value.split_once('=').ok_or_else(|| {
                format!("invalid FastCGI app environment: {value}; expected EXT=KEY=VALUE")
            })?;
            let (key, env_value) = assignment.split_once('=').ok_or_else(|| {
                format!("invalid FastCGI app environment: {value}; expected EXT=KEY=VALUE")
            })?;
            validate_env_key(key)?;
            if env_value.contains('\0') {
                return Err("FastCGI app environment value cannot contain NUL".to_owned());
            }
            fastcgi_app_env.push((
                normalize_extension(extension)?,
                key.to_owned(),
                env_value.to_owned(),
            ));
        }

        let Cli {
            user: master_user,
            group: master_group,
            debug,
            server_timing,
            bind,
            max_connections,
            header_read_timeout,
            tls_handshake_timeout,
            no_plain_http,
            https_redirect,
            tls_bind,
            root,
            index,
            no_listing,
            try_files,
            fastcgi_timeout,
            fastcgi_app_min_workers: _,
            fastcgi_app_max_workers: _,
            threads,
            worker_threads,
            worker_idle_timeout,
            worker_cgroup,
            worker_cgroup_memory_max,
            worker_cgroup_cpu_max,
            worker_cgroup_pids_max,
            rate_limit,
            rate_limit_burst,
            trusted_proxy,
            access_log,
            access_log_file,
            log_dir,
            tls_dir,
            access_log_format,
            error_log_file,
            error_log_format,
            bot_detection,
            bot_config,
            bot_busy_threshold,
            modsecurity_rules,
            modsecurity_block_status,
            modsecurity_body_limit: body_limit,
            modsecurity_response_body_limit: response_body_limit,
            config_file,
            vhost_dir,
            control_socket,
            check_config,
            tls_cert,
            tls_key,
            acme_directory,
            acme_cache,
            acme_contact: acme_contacts,
            acme_ca_root,
            http3_bind,
            worker,
            worker_uid,
            worker_gid,
            ..
        } = cli;
        let listing = !no_listing;
        let rate_limit = match rate_limit {
            Some(rate) => Some(RateLimit::parse(&rate, rate_limit_burst)?),
            None if rate_limit_burst.is_some() => {
                return Err("--rate-limit-burst requires --rate-limit".to_owned());
            }
            None => None,
        };
        let trusted_proxies = trusted_proxy
            .iter()
            .map(|value| value.parse())
            .collect::<Result<Vec<TrustedProxy>, String>>()?;
        let access_log_format = access_log_format.unwrap_or_else(|| {
            "%a:%{remote}p %{c}a:%{remote}p [%{begin:%Y-%m-%dT%H:%M:%SZ}t] \"%m %U%q %H\" %>s \"%{Host}i\" \"%{User-Agent}i\" \"%{ja4}n\"".to_owned()
        });
        crate::logging::AccessFormat::parse(&access_log_format)?;
        let error_log_format =
            error_log_format.unwrap_or_else(|| "[%t] [%l] [pid %P] [module %m] %M".to_owned());
        crate::logging::ErrorFormat::parse(&error_log_format)?;
        let bot = if let Some(path) = bot_config {
            let content = std::fs::read_to_string(&path).map_err(|error| {
                format!("could not read bot policy {}: {error}", path.display())
            })?;
            let mut policy: BotPolicyFile = serde_yaml_ng::from_str(&content)
                .map_err(|error| format!("invalid bot policy {}: {error}", path.display()))?;
            if let Some(threshold) = bot_busy_threshold {
                policy.set_busy_threshold(threshold);
            }
            BotPolicy::parse(policy.clone())?;
            Some(policy)
        } else if bot_detection {
            let mut policy = BotPolicyFile::default();
            if let Some(threshold) = bot_busy_threshold {
                policy.set_busy_threshold(threshold);
            }
            BotPolicy::parse(policy.clone())?;
            Some(policy)
        } else if bot_busy_threshold.is_some() {
            return Err("--bot-busy-threshold requires --bot-detection or --bot-config".to_owned());
        } else {
            None
        };
        let modsecurity_body_limit = body_limit.unwrap_or(16 * 1024 * 1024);
        let modsecurity_response_body_limit =
            response_body_limit.or(body_limit).unwrap_or(64 * 1024);

        validate_index_names(&index).map_err(|error| format!("--index {error}"))?;
        validate_try_files(&try_files)?;

        for (extension, arg) in fastcgi_app_args {
            let Some(FastCgiBackend {
                address: FastCgiAddress::Spawn(app),
                ..
            }) = fastcgi
                .iter_mut()
                .find(|backend| backend.extension == extension)
            else {
                return Err(format!(
                    "FastCGI app argument references undeclared app extension: {extension}"
                ));
            };
            app.args.push(arg);
        }
        for (extension, max_workers) in fastcgi_app_max_workers {
            let Some(FastCgiBackend {
                address: FastCgiAddress::Spawn(app),
                ..
            }) = fastcgi
                .iter_mut()
                .find(|backend| backend.extension == extension)
            else {
                return Err(format!(
                    "FastCGI app max worker count references undeclared app extension: {extension}"
                ));
            };
            app.max_workers = max_workers;
            app.min_workers = app.min_workers.min(max_workers);
        }
        for (extension, min_workers) in fastcgi_app_min_workers {
            let Some(FastCgiBackend {
                address: FastCgiAddress::Spawn(app),
                ..
            }) = fastcgi
                .iter_mut()
                .find(|backend| backend.extension == extension)
            else {
                return Err(format!(
                    "FastCGI app min worker count references undeclared app extension: {extension}"
                ));
            };
            app.min_workers = min_workers.min(app.max_workers);
        }
        for (extension, idle_timeout) in fastcgi_app_idle_timeouts {
            let Some(FastCgiBackend {
                address: FastCgiAddress::Spawn(app),
                ..
            }) = fastcgi
                .iter_mut()
                .find(|backend| backend.extension == extension)
            else {
                return Err(format!(
                    "FastCGI app idle timeout references undeclared app extension: {extension}"
                ));
            };
            app.idle_timeout = idle_timeout;
        }
        for (extension, key, value) in fastcgi_app_env {
            add_fastcgi_app_env(&mut fastcgi, &extension, key, value)?;
        }

        let tls = match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => Some(TlsFiles { cert, key }),
            (None, None) => None,
            _ => return Err("--tls-cert and --tls-key must be supplied together".to_owned()),
        };

        let acme = match (acme_directory, acme_cache) {
            (Some(directory), Some(cache)) => Some(AcmeSettings {
                directory,
                cache,
                contacts: acme_contacts,
                ca_root: acme_ca_root,
            }),
            (Some(_), None) => return Err("--acme-directory requires --acme-cache".to_owned()),
            (None, Some(_)) => return Err("--acme-cache requires --acme-directory".to_owned()),
            (None, None) if !acme_contacts.is_empty() || acme_ca_root.is_some() => {
                return Err("ACME contact and CA options require --acme-directory".to_owned());
            }
            (None, None) => None,
        };

        if no_plain_http && acme.is_some() {
            return Err(
                "--no-plain-http cannot be used with ACME; HTTP-01 requires plaintext HTTP"
                    .to_owned(),
            );
        }

        if master_group.is_some() && master_user.is_none() {
            return Err("--group requires --user".to_owned());
        }
        if worker && (master_user.is_some() || master_group.is_some()) {
            return Err("--user and --group cannot be used with --worker".to_owned());
        }
        if worker_uid.is_some() != worker_gid.is_some() {
            return Err("--worker-uid and --worker-gid must be supplied together".to_owned());
        }
        if !worker && (worker_uid.is_some() || worker_gid.is_some()) {
            return Err("worker uid/gid options require --worker".to_owned());
        }
        if worker && worker_uid.is_none() {
            return Err("--worker requires worker uid/gid options".to_owned());
        }
        #[cfg(feature = "hosting")]
        let worker_cgroup = match worker_cgroup {
            Some(path) => Some(
                CgroupSpec::new(
                    &path,
                    worker_cgroup_memory_max.as_deref(),
                    worker_cgroup_cpu_max.as_deref(),
                    worker_cgroup_pids_max.as_deref(),
                )
                .map_err(|error| format!("--worker-cgroup: {error}"))?,
            ),
            None if worker_cgroup_memory_max.is_some()
                || worker_cgroup_cpu_max.is_some()
                || worker_cgroup_pids_max.is_some() =>
            {
                return Err("--worker-cgroup limits require --worker-cgroup".to_owned());
            }
            None => None,
        };
        #[cfg(not(feature = "hosting"))]
        let _ = (
            worker_cgroup,
            worker_cgroup_memory_max,
            worker_cgroup_cpu_max,
            worker_cgroup_pids_max,
        );
        if worker && check_config {
            return Err("--check-config cannot be used with --worker".to_owned());
        }

        Ok(ParseResult::Config(Box::new(Self {
            debug,
            server_timing,
            plain_http: !no_plain_http,
            https_redirect,
            bind,
            max_connections,
            header_read_timeout,
            tls_handshake_timeout,
            tls_bind,
            http3_bind: http3_bind.unwrap_or_else(|| tls_bind.unwrap_or(bind)),
            root,
            config_file,
            vhost_dir,
            control_socket,
            index,
            listing,
            try_files,
            fastcgi,
            fastcgi_timeout,
            threads,
            worker_threads,
            worker_idle_timeout: Duration::from_secs(worker_idle_timeout),
            #[cfg(feature = "hosting")]
            worker_cgroup,
            rate_limit,
            trusted_proxies,
            access_log,
            access_log_file,
            log_dirs: log_dir,
            tls_dirs: tls_dir,
            access_log_format,
            error_log_file,
            error_log_format,
            bot,
            modsecurity_rules,
            modsecurity_block_status,
            modsecurity_body_limit,
            modsecurity_response_body_limit,
            tls,
            acme,
            check_config,
            worker,
            worker_uid,
            worker_gid,
            master_user,
            master_group,
        })))
    }

    /// Applies spawned-app environment that the master passed to this worker
    /// through `WORKER_APP_ENV`, encoded as `[[extension, key, value], ...]`.
    #[cfg(feature = "hosting")]
    pub(crate) fn apply_fastcgi_app_env(&mut self, encoded: &str) -> Result<(), String> {
        let entries: Vec<(String, String, String)> = serde_json::from_str(encoded)
            .map_err(|error| format!("invalid {WORKER_APP_ENV}: {error}"))?;
        for (extension, key, value) in entries {
            validate_env_key(&key)?;
            if value.contains('\0') {
                return Err("FastCGI app environment value cannot contain NUL".to_owned());
            }
            let extension = normalize_extension(&extension)?;
            add_fastcgi_app_env(&mut self.fastcgi, &extension, key, value)?;
        }
        Ok(())
    }

    pub fn usage() -> String {
        format!(
            "{}\nCompiled features: {}",
            Cli::command().render_help().to_string().trim_end(),
            compiled_features()
        )
    }
}

fn options_to_args(
    options: &serde_yaml_ng::Value,
    cli_matches: &ArgMatches,
    config_path: &Path,
) -> Result<Vec<String>, String> {
    let mapping = options
        .as_mapping()
        .ok_or_else(|| format!("{}: options must be a mapping", config_path.display()))?;
    let command = Cli::command();
    let mut args = Vec::new();
    for (key, value) in mapping {
        let key = key.as_str().ok_or_else(|| {
            format!(
                "{}: option names in options must be strings",
                config_path.display()
            )
        })?;
        let normalized_key = key.replace('-', "_");
        if matches!(
            normalized_key.as_str(),
            "config" | "check_config" | "help" | "worker" | "worker_uid" | "worker_gid"
        ) {
            return Err(format!(
                "{}: option {key} is not allowed in options",
                config_path.display()
            ));
        }
        let Some(arg) = command.get_arguments().find(|arg| {
            arg.get_long()
                .is_some_and(|long| long.replace('-', "_") == normalized_key)
        }) else {
            return Err(format!(
                "{}: unknown option in options: {key}",
                config_path.display()
            ));
        };
        if cli_matches.value_source(arg.get_id().as_str()) == Some(ValueSource::CommandLine) {
            continue;
        }
        let long = arg
            .get_long()
            .expect("matched an argument with a long name");
        if matches!(arg.get_action(), ArgAction::SetTrue) {
            match value.as_bool() {
                Some(true) => args.push(format!("--{long}")),
                Some(false) => {}
                None => {
                    return Err(format!(
                        "{}: option {key} must be a boolean",
                        config_path.display()
                    ));
                }
            }
            continue;
        }

        let values = if matches!(arg.get_action(), ArgAction::Append) {
            match value {
                serde_yaml_ng::Value::Sequence(values) => values.iter().collect::<Vec<_>>(),
                value => vec![value],
            }
        } else {
            vec![value]
        };
        if values.is_empty() {
            return Err(format!(
                "{}: option {key} must not be an empty sequence",
                config_path.display()
            ));
        }
        for value in values {
            let value = option_scalar(value).ok_or_else(|| {
                format!(
                    "{}: option {key} must have a scalar value",
                    config_path.display()
                )
            })?;
            let value = if is_path_option(&normalized_key) {
                resolve_option_path(&value, config_path)
                    .map_err(|error| format!("{}: {error}", config_path.display()))?
            } else {
                value
            };
            args.push(format!("--{long}"));
            args.push(value);
        }
    }
    Ok(args)
}

fn option_scalar(value: &serde_yaml_ng::Value) -> Option<String> {
    match value {
        serde_yaml_ng::Value::String(value) => Some(value.clone()),
        serde_yaml_ng::Value::Number(value) => Some(value.to_string()),
        serde_yaml_ng::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn is_path_option(key: &str) -> bool {
    matches!(
        key,
        "root"
            | "vhost_dir"
            | "control_socket"
            | "access_log_file"
            | "error_log_file"
            | "log_dir"
            | "tls_dir"
            | "bot_config"
            | "modsecurity_rules"
            | "tls_cert"
            | "tls_key"
            | "acme_cache"
            | "acme_ca_root"
    )
}

fn resolve_option_path(value: &str, config_path: &Path) -> Result<String, String> {
    let path = Path::new(value);
    if path.is_absolute() {
        return Ok(value.to_owned());
    }
    let path = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join(path);
    let path = if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map_err(|error| format!("could not resolve relative option path: {error}"))?
            .join(path)
    };
    Ok(path.to_string_lossy().into_owned())
}

/// Environment variable through which the master hands a worker the
/// environment of its spawned FastCGI apps.
#[cfg(feature = "hosting")]
pub(crate) const WORKER_APP_ENV: &str = "CHARLOTTE_FASTCGI_APP_ENV";

/// The names of the optional features this binary was built with.
fn compiled_features() -> String {
    let features = [
        ("acme", cfg!(feature = "acme")),
        ("hosting", cfg!(feature = "hosting")),
        ("http3", cfg!(feature = "http3")),
        ("proxy", cfg!(feature = "proxy")),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name))
    .collect::<Vec<_>>();
    if features.is_empty() {
        "none".to_owned()
    } else {
        features.join(", ")
    }
}

/// Refuses options of a Cargo feature this binary was built without, so that
/// they are not silently accepted and ignored. The earliest such option on the
/// command line is reported.
fn reject_compiled_out_options(matches: &ArgMatches) -> Result<(), String> {
    let refused = FEATURE_OPTIONS
        .iter()
        .filter(|(_, enabled, _)| !enabled)
        .flat_map(|(feature, _, ids)| ids.iter().map(move |id| (*feature, *id)))
        .filter(|(_, id)| matches.value_source(id) == Some(ValueSource::CommandLine))
        .filter_map(|(feature, id)| Some((matches.index_of(id)?, feature, id)))
        .min_by_key(|(index, _, _)| *index);
    match refused {
        Some((_, feature, id)) => Err(format!(
            "--{} requires the `{feature}` feature, which this build does not include (compiled features: {})",
            id.replace('_', "-"),
            compiled_features()
        )),
        None => Ok(()),
    }
}

/// Values of a repeatable option paired with their command-line positions, so
/// that values of different options can be processed in the order given.
fn indexed_values<'a>(
    matches: &ArgMatches,
    id: &'static str,
    values: &'a [String],
) -> Vec<(usize, &'static str, &'a str)> {
    matches
        .indices_of(id)
        .into_iter()
        .flatten()
        .zip(values)
        .map(|(index, value)| (index, id, value.as_str()))
        .collect()
}

fn parse_cli_address(
    what: &'static str,
) -> impl Fn(&str) -> Result<SocketAddr, String> + Clone + Send + Sync + 'static {
    move |value| {
        value
            .parse()
            .map_err(|_| format!("invalid {what}: {value}"))
    }
}

fn parse_cli_name(
    option: &'static str,
    what: &'static str,
) -> impl Fn(&str) -> Result<String, String> + Clone + Send + Sync + 'static {
    move |value| {
        if value.is_empty() {
            Err(format!("{option} requires a non-empty {what} name"))
        } else {
            Ok(value.to_owned())
        }
    }
}

fn parse_cli_id(
    what: &'static str,
) -> impl Fn(&str) -> Result<u32, String> + Clone + Send + Sync + 'static {
    move |value| {
        value
            .parse()
            .map_err(|_| format!("invalid worker {what}: {value}"))
    }
}

fn parse_cli_fastcgi_timeout(value: &str) -> Result<Duration, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("invalid FastCGI timeout: {value}"))
}

fn parse_positive_usize(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|number| *number > 0)
        .ok_or_else(|| format!("invalid positive number: {value}"))
}

fn parse_cli_timeout(value: &str) -> Result<Duration, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("invalid timeout: {value}; expected a positive number of seconds"))
}

fn parse_cli_body_limit(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|limit| *limit > 0)
        .ok_or_else(|| format!("invalid ModSecurity body limit: {value}"))
}

fn parse_cli_acme_directory(value: &str) -> Result<String, String> {
    let directory = match value {
        "letsencrypt" => "https://acme-v02.api.letsencrypt.org/directory",
        "letsencrypt-staging" => "https://acme-staging-v02.api.letsencrypt.org/directory",
        _ => value,
    };
    if !(directory.starts_with("https://") || directory.starts_with("http://")) {
        return Err("--acme-directory must be an HTTP(S) URL or a known alias".to_owned());
    }
    Ok(directory.to_owned())
}

fn parse_cli_acme_contact(value: &str) -> Result<String, String> {
    if value.is_empty() || !value.contains(':') || value.contains('\0') {
        return Err(format!("invalid ACME contact URI: {value}"));
    }
    Ok(value.to_owned())
}

fn add_fastcgi_app_env(
    fastcgi: &mut [FastCgiBackend],
    extension: &str,
    key: String,
    value: String,
) -> Result<(), String> {
    let Some(FastCgiBackend {
        address: FastCgiAddress::Spawn(app),
        ..
    }) = fastcgi
        .iter_mut()
        .find(|backend| backend.extension == extension)
    else {
        return Err(format!(
            "FastCGI app environment references undeclared app extension: {extension}"
        ));
    };
    if app.env.insert(key.clone(), value).is_some() {
        return Err(format!("duplicate FastCGI app environment key: {key}"));
    }
    Ok(())
}

pub(crate) fn validate_try_files(entries: &[String]) -> Result<(), String> {
    if entries.is_empty() {
        return Ok(());
    }
    if entries.len() < 2 {
        return Err("try_files requires at least two entries".to_owned());
    }

    for entry in entries {
        validate_try_files_variables(entry)?;
    }

    for entry in &entries[..entries.len() - 1] {
        if !entry.starts_with('/') && !entry.starts_with("$uri") {
            return Err(format!("invalid try_files candidate: {entry}"));
        }
    }

    let fallback = entries.last().expect("non-empty try_files entries");
    if let Some(code) = fallback.strip_prefix('=') {
        if code
            .parse::<u16>()
            .is_ok_and(|code| (100..=599).contains(&code))
        {
            return Ok(());
        }
        return Err(format!("invalid try_files status code: {fallback}"));
    }
    if !fallback.starts_with('/') || fallback.parse::<http::uri::PathAndQuery>().is_err() {
        return Err(format!("invalid try_files fallback URI: {fallback}"));
    }
    Ok(())
}

pub(crate) fn validate_index_names(names: &[String]) -> Result<(), String> {
    if names.is_empty() {
        return Err("must contain at least one file name".to_owned());
    }
    if names.iter().any(|name| {
        name.is_empty() || name.contains('/') || name.contains('\\') || name == "." || name == ".."
    }) {
        return Err("entries must be non-empty file names without path separators".to_owned());
    }
    Ok(())
}

fn validate_try_files_variables(entry: &str) -> Result<(), String> {
    let bytes = entry.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'$' {
            index += 1;
            continue;
        }
        let variable = ["$uri", "$args", "$query_string", "$is_args"]
            .into_iter()
            .find(|variable| {
                entry[index..].starts_with(variable)
                    && bytes
                        .get(index + variable.len())
                        .is_none_or(|next| !next.is_ascii_alphanumeric() && *next != b'_')
            });
        let Some(variable) = variable else {
            return Err(format!("unsupported try_files variable in: {entry}"));
        };
        index += variable.len();
    }
    Ok(())
}

pub(crate) fn parse_fastcgi_backend(value: &str) -> Result<FastCgiBackend, String> {
    let (extension, address) = value
        .split_once('=')
        .ok_or_else(|| format!("invalid FastCGI backend: {value}; expected EXT=ADDR"))?;
    let extension = normalize_extension(extension)?;
    let address = if let Some(path) = address.strip_prefix("unix:") {
        if path.is_empty() {
            return Err("FastCGI Unix socket path cannot be empty".to_owned());
        }
        FastCgiAddress::Unix(PathBuf::from(path))
    } else {
        let (host, port) = address
            .rsplit_once(':')
            .ok_or_else(|| format!("invalid FastCGI TCP address: {address}"))?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let valid_host = !host.is_empty()
            && !host.bytes().any(|byte| byte.is_ascii_whitespace())
            && (!host.contains(':') || address.starts_with('['));
        let valid_port = port.parse::<u16>().is_ok_and(|port| port > 0);
        if !valid_host || !valid_port {
            return Err(format!("invalid FastCGI TCP address: {address}"));
        }
        FastCgiAddress::Tcp(address.to_owned())
    };
    Ok(FastCgiBackend { extension, address })
}

fn add_backend(fastcgi: &mut Vec<FastCgiBackend>, backend: FastCgiBackend) -> Result<(), String> {
    if fastcgi
        .iter()
        .any(|existing| existing.extension == backend.extension)
    {
        return Err(format!(
            "duplicate backend extension: {}",
            backend.extension
        ));
    }
    fastcgi.push(backend);
    Ok(())
}

pub(crate) fn parse_cgi_backend(value: &str) -> Result<FastCgiBackend, String> {
    let (extension, interpreter) = match value.split_once('=') {
        Some((extension, interpreter)) => {
            if interpreter.is_empty() || interpreter.contains('\0') {
                return Err("CGI interpreter cannot be empty or contain NUL".to_owned());
            }
            (extension, Some(PathBuf::from(interpreter)))
        }
        None => (value, None),
    };
    let extension = normalize_extension(extension)?;
    Ok(FastCgiBackend {
        extension,
        address: FastCgiAddress::Cgi(interpreter),
    })
}

pub(crate) fn parse_fastcgi_app(value: &str) -> Result<FastCgiBackend, String> {
    let (extension, program) = value
        .split_once('=')
        .ok_or_else(|| format!("invalid FastCGI app: {value}; expected EXT=PROGRAM"))?;
    let extension = normalize_extension(extension)?;
    if program.is_empty() || program.contains('\0') {
        return Err("FastCGI app program cannot be empty or contain NUL".to_owned());
    }
    Ok(FastCgiBackend {
        extension,
        address: FastCgiAddress::Spawn(FastCgiApp {
            program: PathBuf::from(program),
            args: Vec::new(),
            env: BTreeMap::new(),
            min_workers: 1,
            max_workers: default_fastcgi_app_max_workers(),
            idle_timeout: Duration::from_secs(DEFAULT_FASTCGI_APP_IDLE_TIMEOUT_SECS),
        }),
    })
}

pub(crate) fn normalize_extension(extension: &str) -> Result<String, String> {
    let extension = extension.trim_start_matches('.').to_ascii_lowercase();
    if extension.is_empty() || !extension.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(format!("invalid FastCGI extension: {extension}"));
    }
    Ok(extension)
}

pub(crate) fn validate_env_key(key: &str) -> Result<(), String> {
    let mut bytes = key.bytes();
    let valid_first = bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_');
    if !valid_first || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        return Err(format!("invalid FastCGI app environment key: {key}"));
    }
    Ok(())
}

pub const DEFAULT_WORKER_THREADS: usize = 2;
pub const MAX_THREADS: usize = 1024;
pub const MAX_FASTCGI_APP_WORKERS: usize = 256;
pub const DEFAULT_FASTCGI_APP_MIN_WORKERS: usize = 1;
pub const DEFAULT_FASTCGI_APP_IDLE_TIMEOUT_SECS: u64 = 60;
pub const MAX_FASTCGI_APP_IDLE_TIMEOUT_SECS: u64 = 86_400;

pub(crate) fn default_fastcgi_app_max_workers() -> usize {
    std::thread::available_parallelism().map_or(1, |count| count.get().min(8))
}

pub fn parse_modsecurity_block_status(value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .ok()
        .filter(|status| (400..=599).contains(status))
        .ok_or_else(|| format!("invalid ModSecurity block status: {value}; expected 400-599"))
}

pub fn parse_fastcgi_app_max_workers(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|workers| (1..=MAX_FASTCGI_APP_WORKERS).contains(workers))
        .ok_or_else(|| {
            format!(
                "invalid FastCGI app max worker count: {value}; expected 1-{MAX_FASTCGI_APP_WORKERS}"
            )
        })
}

pub fn parse_fastcgi_app_min_workers(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|workers| *workers <= MAX_FASTCGI_APP_WORKERS)
        .ok_or_else(|| {
            format!(
                "invalid FastCGI app min worker count: {value}; expected 0-{MAX_FASTCGI_APP_WORKERS}"
            )
        })
}

pub fn parse_fastcgi_app_idle_timeout(value: &str) -> Result<Duration, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|seconds| (1..=MAX_FASTCGI_APP_IDLE_TIMEOUT_SECS).contains(seconds))
        .map(Duration::from_secs)
        .ok_or_else(|| {
            format!(
                "invalid FastCGI app idle timeout: {value}; expected 1-{MAX_FASTCGI_APP_IDLE_TIMEOUT_SECS} seconds"
            )
        })
}

pub fn parse_thread_count(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|threads| (1..=MAX_THREADS).contains(threads))
        .ok_or_else(|| format!("invalid thread count: {value}; expected 1-{MAX_THREADS}"))
}

#[cfg(test)]
mod tests {
    use super::{Config, ParseResult, parse_modsecurity_block_status};
    #[cfg(feature = "hosting")]
    use super::{
        DEFAULT_FASTCGI_APP_IDLE_TIMEOUT_SECS, FastCgiAddress, default_fastcgi_app_max_workers,
        validate_try_files,
    };
    use crate::forwarded::TrustedProxy;
    use crate::ratelimit::RateLimit;
    use std::time::Duration;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    static NEXT_CONFIG_FILE: AtomicUsize = AtomicUsize::new(0);

    fn write_config_file(content: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "project-charlotte-cli-config-{}-{}.yaml",
            std::process::id(),
            NEXT_CONFIG_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, content).unwrap();
        path
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn parses_options() {
        let parsed = Config::parse([
            "--bind".to_owned(),
            "0.0.0.0:9000".to_owned(),
            "--root".to_owned(),
            "public".to_owned(),
            "--index".to_owned(),
            "home.htm".to_owned(),
            "--no-listing".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.bind.to_string(), "0.0.0.0:9000");
        assert_eq!(config.max_connections, 4096);
        assert_eq!(config.header_read_timeout, Duration::from_secs(30));
        assert_eq!(config.tls_handshake_timeout, Duration::from_secs(10));
        assert_eq!(config.http3_bind, config.bind);
        assert_eq!(config.root.as_path(), std::path::Path::new("public"));
        assert_eq!(config.config_file, None);
        assert_eq!(config.control_socket, None);
        assert_eq!(config.index, ["home.htm"]);
        assert!(!config.listing);
        assert!(config.try_files.is_empty());
        assert!(config.worker_cgroup.is_none());
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn parses_worker_cgroup_path_and_limits() {
        let parsed = Config::parse([
            "--worker-cgroup".to_owned(),
            "/charlotte/sites/{uid}/{name}".to_owned(),
            "--worker-cgroup-memory-max".to_owned(),
            "64M".to_owned(),
            "--worker-cgroup-cpu-max".to_owned(),
            "150%".to_owned(),
            "--worker-cgroup-pids-max".to_owned(),
            "32".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        let cgroup = config.worker_cgroup.unwrap();
        assert_eq!(cgroup.path, PathBuf::from("charlotte/sites/{uid}/{name}"));
        assert_eq!(cgroup.memory_max.as_deref(), Some("67108864"));
        assert_eq!(cgroup.cpu_max.as_deref(), Some("150000 100000"));
        assert_eq!(cgroup.pids_max.as_deref(), Some("32"));

        assert!(
            Config::parse(["--worker-cgroup-memory-max".to_owned(), "1G".to_owned(),]).is_err()
        );
        assert!(Config::parse(["--worker-cgroup".to_owned(), "../escape".to_owned(),]).is_err());
        assert!(
            Config::parse([
                "--worker-cgroup".to_owned(),
                "site".to_owned(),
                "--worker-cgroup-pids-max".to_owned(),
                "0".to_owned(),
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_connection_limits_and_timeouts() {
        let parsed = Config::parse([
            "--max-connections".to_owned(),
            "12".to_owned(),
            "--header-read-timeout".to_owned(),
            "3".to_owned(),
            "--tls-handshake-timeout".to_owned(),
            "2".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.max_connections, 12);
        assert_eq!(config.header_read_timeout, Duration::from_secs(3));
        assert_eq!(config.tls_handshake_timeout, Duration::from_secs(2));

        for (option, value) in [
            ("--max-connections", "0"),
            ("--max-connections", "not-a-number"),
            ("--header-read-timeout", "0"),
            ("--tls-handshake-timeout", "-1"),
        ] {
            assert!(
                Config::parse([option.to_owned(), value.to_owned()]).is_err(),
                "accepted {option} {value}"
            );
        }
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn parses_multiple_directory_indexes_in_order() {
        let parsed = Config::parse([
            "--index".to_owned(),
            "home.htm,index.html".to_owned(),
            "--index".to_owned(),
            "default.php".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.index, ["home.htm", "index.html", "default.php"]);

        assert!(Config::parse(["--index".to_owned(), "../index.html".to_owned()]).is_err());
        assert!(Config::parse(["--index".to_owned(), "".to_owned()]).is_err());
    }

    #[test]
    fn parses_control_socket() {
        let parsed = Config::parse([
            "--control-socket".to_owned(),
            "/run/charlotte/control.sock".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(
            config.control_socket.as_deref(),
            Some(std::path::Path::new("/run/charlotte/control.sock"))
        );
    }

    #[test]
    fn parses_rate_limit_and_rejects_invalid_options() {
        let parsed = Config::parse([
            "--rate-limit".to_owned(),
            "20/s".to_owned(),
            "--rate-limit-burst".to_owned(),
            "40".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(
            config.rate_limit,
            Some(RateLimit::parse("20/s", Some(40)).unwrap())
        );

        assert!(Config::parse(["--rate-limit-burst".to_owned(), "2".to_owned()]).is_err());
        assert!(Config::parse(["--rate-limit".to_owned(), "0/m".to_owned()]).is_err());
        assert!(
            Config::parse([
                "--rate-limit".to_owned(),
                "1/s".to_owned(),
                "--rate-limit-burst".to_owned(),
                "0".to_owned()
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_trusted_proxies_and_access_logging() {
        let parsed = Config::parse([
            "--trusted-proxy".to_owned(),
            "10.0.0.0/8".to_owned(),
            "--trusted-proxy".to_owned(),
            "::1".to_owned(),
            "--access-log".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(
            config.trusted_proxies,
            vec![
                "10.0.0.0/8".parse::<TrustedProxy>().unwrap(),
                "::1".parse::<TrustedProxy>().unwrap(),
            ]
        );
        assert!(config.access_log);
        assert!(Config::parse(["--trusted-proxy".to_owned(), "10.0.0.0/99".to_owned()]).is_err());
    }

    #[test]
    fn enables_default_bot_detection_and_loads_valid_policy_yaml() {
        let parsed = Config::parse(["--bot-detection".to_owned()]).unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert!(config.bot.is_some());

        let path = std::env::temp_dir().join(format!(
            "project-charlotte-bot-config-{}-{}.yaml",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(
            &path,
            "mode: log\nchallenge_threshold: 20\nblock_threshold: 70\nverify_crawlers: false\n",
        )
        .unwrap();
        let parsed = Config::parse([
            "--bot-config".to_owned(),
            path.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert!(config.bot.is_some());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn bot_busy_threshold_requires_and_configures_bot_detection() {
        let parsed = Config::parse([
            "--bot-detection".to_owned(),
            "--bot-busy-threshold".to_owned(),
            "20/s".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert!(config.bot.is_some());

        let error = Config::parse(["--bot-busy-threshold".to_owned(), "20/s".to_owned()])
            .err()
            .unwrap();
        assert!(error.contains("requires --bot-detection or --bot-config"));
        assert!(
            Config::parse([
                "--bot-detection".to_owned(),
                "--bot-busy-threshold".to_owned(),
                "invalid".to_owned(),
            ])
            .is_err()
        );

        let path = std::env::temp_dir().join(format!(
            "project-charlotte-bot-busy-config-{}-{}.yaml",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(&path, "busy_threshold: invalid\n").unwrap();
        assert!(
            Config::parse([
                "--bot-config".to_owned(),
                path.to_string_lossy().into_owned(),
                "--bot-busy-threshold".to_owned(),
                "20/s".to_owned(),
            ])
            .is_ok()
        );
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn parses_and_validates_try_files() {
        let parsed = Config::parse([
            "--try-files".to_owned(),
            "$uri".to_owned(),
            "--try-files".to_owned(),
            "$uri/".to_owned(),
            "--try-files".to_owned(),
            "/index.html?$args".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.try_files, ["$uri", "$uri/", "/index.html?$args"]);

        assert!(validate_try_files(&[]).is_ok());
        for entries in [
            vec!["/only-one".to_owned()],
            vec!["relative".to_owned(), "=404".to_owned()],
            vec!["/$unknown".to_owned(), "=404".to_owned()],
            vec!["/$uri_extra".to_owned(), "=404".to_owned()],
            vec!["/$uri".to_owned(), "=99".to_owned()],
            vec!["/$uri".to_owned(), "=600".to_owned()],
            vec!["/$uri".to_owned(), "not-a-uri".to_owned()],
            vec!["/$uri".to_owned(), "/bad uri".to_owned()],
        ] {
            assert!(validate_try_files(&entries).is_err(), "{entries:?}");
            let args = entries
                .iter()
                .flat_map(|entry| ["--try-files".to_owned(), entry.clone()])
                .collect::<Vec<_>>();
            assert!(Config::parse(args).is_err());
        }
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn rejects_invalid_index() {
        assert!(Config::parse(["--index".to_owned(), "../secret".to_owned()]).is_err());
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn parses_fastcgi_tcp_and_unix_backends() {
        let parsed = Config::parse([
            "--fastcgi".to_owned(),
            ".PHP=127.0.0.1:9000".to_owned(),
            "--fastcgi".to_owned(),
            "cgi=unix:/run/fcgi.sock".to_owned(),
            "--fastcgi-timeout".to_owned(),
            "12".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.fastcgi.len(), 2);
        assert_eq!(config.fastcgi[0].extension, "php");
        assert!(matches!(config.fastcgi[0].address, FastCgiAddress::Tcp(_)));
        assert!(matches!(config.fastcgi[1].address, FastCgiAddress::Unix(_)));
        assert_eq!(config.fastcgi_timeout, std::time::Duration::from_secs(12));
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn parses_classic_cgi_backends_and_rejects_duplicate_extensions() {
        let parsed = Config::parse([
            "--cgi".to_owned(),
            "cgi".to_owned(),
            "--cgi".to_owned(),
            "py=/usr/bin/python3".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert!(matches!(
            config.fastcgi[0].address,
            FastCgiAddress::Cgi(None)
        ));
        assert!(matches!(
            &config.fastcgi[1].address,
            FastCgiAddress::Cgi(Some(path)) if path == std::path::Path::new("/usr/bin/python3")
        ));
        for value in ["", "=sh", "sh=", "sh=bad\0path"] {
            assert!(Config::parse(["--cgi".to_owned(), value.to_owned()]).is_err());
        }
        assert!(
            Config::parse([
                "--fastcgi".to_owned(),
                "php=127.0.0.1:9000".to_owned(),
                "--cgi".to_owned(),
                ".PHP".to_owned(),
            ])
            .is_err()
        );
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn rejects_invalid_fastcgi_addresses_and_duplicates() {
        assert!(Config::parse(["--fastcgi".to_owned(), "php=localhost".to_owned()]).is_err());
        assert!(
            Config::parse([
                "--fastcgi".to_owned(),
                "php=127.0.0.1:9000".to_owned(),
                "--fastcgi".to_owned(),
                ".PHP=127.0.0.1:9001".to_owned(),
            ])
            .is_err()
        );
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn parses_fastcgi_app_and_preserves_args_pool_options_and_environment() {
        let parsed = Config::parse([
            "--fastcgi-app-arg".to_owned(),
            "PHP=--foreground".to_owned(),
            "--fastcgi-app-env".to_owned(),
            "php=APP_MODE=production".to_owned(),
            "--fastcgi-app-max-workers".to_owned(),
            "php=4".to_owned(),
            "--fastcgi-app-idle-timeout".to_owned(),
            "php=12".to_owned(),
            "--fastcgi-app".to_owned(),
            "php=/usr/bin/php8.4-cgi".to_owned(),
            "--fastcgi-app-arg".to_owned(),
            "php=--bind".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.fastcgi.len(), 1);
        assert_eq!(config.fastcgi[0].extension, "php");
        let FastCgiAddress::Spawn(app) = &config.fastcgi[0].address else {
            panic!("expected spawned FastCGI app")
        };
        assert_eq!(app.program, PathBuf::from("/usr/bin/php8.4-cgi"));
        assert_eq!(app.args, ["--foreground", "--bind"]);
        assert_eq!(app.max_workers, 4);
        assert_eq!(app.idle_timeout, Duration::from_secs(12));
        assert_eq!(
            app.env.get("APP_MODE").map(String::as_str),
            Some("production")
        );
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn fastcgi_app_defaults_to_one_warm_worker_and_cpu_bound_maximum() {
        let parsed = Config::parse(["--fastcgi-app".to_owned(), "php=php-cgi".to_owned()]).unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        let FastCgiAddress::Spawn(app) = &config.fastcgi[0].address else {
            panic!("expected spawned FastCGI app")
        };
        assert_eq!(app.min_workers, 1);
        assert_eq!(app.max_workers, default_fastcgi_app_max_workers());
        assert!((1..=8).contains(&app.max_workers));
        assert_eq!(config.modsecurity_response_body_limit, 64 * 1024);
        assert_eq!(
            app.idle_timeout,
            Duration::from_secs(DEFAULT_FASTCGI_APP_IDLE_TIMEOUT_SECS)
        );
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn fastcgi_app_min_workers_and_response_body_limit_options() {
        let parsed = Config::parse([
            "--fastcgi-app".to_owned(),
            "php=php-cgi".to_owned(),
            "--fastcgi-app-max-workers".to_owned(),
            "php=2".to_owned(),
            "--fastcgi-app-min-workers".to_owned(),
            "php=5".to_owned(),
            "--modsecurity-body-limit".to_owned(),
            "1000".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        let FastCgiAddress::Spawn(app) = &config.fastcgi[0].address else {
            panic!("expected spawned FastCGI app")
        };
        assert_eq!(app.min_workers, 2, "the minimum is clamped to the maximum");
        assert_eq!(config.modsecurity_response_body_limit, 1000);
        let ParseResult::Config(config) = Config::parse([
            "--modsecurity-body-limit".to_owned(),
            "1000".to_owned(),
            "--modsecurity-response-body-limit".to_owned(),
            "2000".to_owned(),
        ])
        .unwrap() else {
            panic!("expected config")
        };
        assert_eq!(config.modsecurity_body_limit, 1000);
        assert_eq!(config.modsecurity_response_body_limit, 2000);
        assert!(
            Config::parse(["--fastcgi-app-min-workers".to_owned(), "php=1".to_owned()]).is_err()
        );
        assert!(
            Config::parse([
                "--fastcgi-app".to_owned(),
                "php=php-cgi".to_owned(),
                "--fastcgi-app-min-workers".to_owned(),
                "php=257".to_owned(),
            ])
            .is_err()
        );
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn fastcgi_app_workers_flag_remains_an_alias() {
        let parsed = Config::parse([
            "--fastcgi-app".to_owned(),
            "php=php-cgi".to_owned(),
            "--fastcgi-app-workers".to_owned(),
            "php=3".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        let FastCgiAddress::Spawn(app) = &config.fastcgi[0].address else {
            panic!("expected spawned FastCGI app")
        };
        assert_eq!(app.max_workers, 3);
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn rejects_invalid_fastcgi_app_declarations_and_options() {
        assert!(Config::parse(["--fastcgi-app".to_owned(), "php=".to_owned()]).is_err());
        assert!(
            Config::parse([
                "--fastcgi-app".to_owned(),
                "php=php-cgi".to_owned(),
                "--fastcgi".to_owned(),
                "PHP=127.0.0.1:9000".to_owned()
            ])
            .is_err()
        );
        assert!(Config::parse(["--fastcgi-app-arg".to_owned(), "php=--arg".to_owned()]).is_err());
        assert!(Config::parse(["--fastcgi-app-env".to_owned(), "php=KEY".to_owned()]).is_err());
        for value in ["php=0", "php=nope", "php=257", "php"] {
            assert!(
                Config::parse([
                    "--fastcgi-app-max-workers".to_owned(),
                    value.to_owned(),
                    "--fastcgi-app".to_owned(),
                    "php=php-cgi".to_owned(),
                ])
                .is_err(),
                "{value}"
            );
        }
        assert!(
            Config::parse(["--fastcgi-app-max-workers".to_owned(), "php=2".to_owned(),]).is_err()
        );
        assert!(
            Config::parse([
                "--fastcgi-app".to_owned(),
                "php=php-cgi".to_owned(),
                "--fastcgi-app-max-workers".to_owned(),
                "php=2".to_owned(),
                "--fastcgi-app-workers".to_owned(),
                ".PHP=3".to_owned(),
            ])
            .is_err()
        );
        for value in ["php=0", "php=nope", "php=86401", "php"] {
            assert!(
                Config::parse([
                    "--fastcgi-app-idle-timeout".to_owned(),
                    value.to_owned(),
                    "--fastcgi-app".to_owned(),
                    "php=php-cgi".to_owned(),
                ])
                .is_err(),
                "{value}"
            );
        }
        assert!(
            Config::parse([
                "--fastcgi-app".to_owned(),
                "php=php-cgi".to_owned(),
                "--fastcgi-app-idle-timeout".to_owned(),
                "php=1".to_owned(),
                "--fastcgi-app-idle-timeout".to_owned(),
                ".PHP=2".to_owned(),
            ])
            .is_err()
        );
        assert!(
            Config::parse(["--fastcgi-app-idle-timeout".to_owned(), "php=10".to_owned(),]).is_err()
        );
        assert!(
            Config::parse([
                "--fastcgi-app-env".to_owned(),
                "php=1BAD=value".to_owned(),
                "--fastcgi-app".to_owned(),
                "php=php-cgi".to_owned()
            ])
            .is_err()
        );
    }

    #[cfg(feature = "http3")]
    #[test]
    fn parses_http3_tls_options_and_bind_override() {
        let parsed = Config::parse([
            "--bind".to_owned(),
            "127.0.0.1:8080".to_owned(),
            "--http3-bind".to_owned(),
            "127.0.0.1:8443".to_owned(),
            "--tls-cert".to_owned(),
            "server.pem".to_owned(),
            "--tls-key".to_owned(),
            "server-key.pem".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.http3_bind.to_string(), "127.0.0.1:8443");
        assert_eq!(config.tls_bind, None);
        assert_eq!(
            config.tls.as_ref().unwrap().cert,
            PathBuf::from("server.pem")
        );
        assert_eq!(
            config.tls.as_ref().unwrap().key,
            PathBuf::from("server-key.pem")
        );
    }

    #[cfg(feature = "http3")]
    #[test]
    fn tls_bind_defaults_http3_bind_when_not_overridden() {
        let parsed = Config::parse([
            "--bind".to_owned(),
            "127.0.0.1:8080".to_owned(),
            "--tls-bind".to_owned(),
            "127.0.0.1:8443".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.tls_bind.unwrap().to_string(), "127.0.0.1:8443");
        assert_eq!(config.http3_bind.to_string(), "127.0.0.1:8443");

        let parsed = Config::parse([
            "--tls-bind".to_owned(),
            "127.0.0.1:8443".to_owned(),
            "--http3-bind".to_owned(),
            "127.0.0.1:9443".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.http3_bind.to_string(), "127.0.0.1:9443");
    }

    #[cfg(feature = "http3")]
    #[test]
    fn rejects_incomplete_tls_options_and_invalid_http3_bind() {
        assert!(Config::parse(["--tls-cert".to_owned(), "server.pem".to_owned()]).is_err());
        assert!(Config::parse(["--tls-key".to_owned(), "server-key.pem".to_owned()]).is_err());
        assert!(Config::parse(["--http3-bind".to_owned(), "localhost".to_owned()]).is_err());
        assert!(Config::parse(["--tls-bind".to_owned(), "localhost".to_owned()]).is_err());
    }

    #[cfg(feature = "acme")]
    #[test]
    fn parses_acme_options_and_requires_cache() {
        let parsed = Config::parse([
            "--acme-directory".to_owned(),
            "letsencrypt-staging".to_owned(),
            "--acme-cache".to_owned(),
            "/var/lib/charlotte/acme".to_owned(),
            "--acme-contact".to_owned(),
            "mailto:admin@example.test".to_owned(),
            "--acme-ca-root".to_owned(),
            "pebble.pem".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        let acme = config.acme.unwrap();
        assert_eq!(
            acme.directory,
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(acme.cache, PathBuf::from("/var/lib/charlotte/acme"));
        assert_eq!(acme.contacts, ["mailto:admin@example.test"]);
        assert_eq!(acme.ca_root, Some(PathBuf::from("pebble.pem")));
        assert!(
            Config::parse([
                "--acme-directory".to_owned(),
                "https://ca.test/dir".to_owned()
            ])
            .is_err()
        );
        assert!(Config::parse(["--acme-cache".to_owned(), "/tmp/acme".to_owned()]).is_err());
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn parses_thread_options_and_rejects_invalid_counts() {
        let ParseResult::Config(defaults) = Config::parse(Vec::<String>::new()).unwrap() else {
            panic!("expected config")
        };
        assert_eq!(defaults.threads, None);
        assert_eq!(defaults.worker_threads, 2);
        assert_eq!(defaults.worker_idle_timeout, Duration::from_secs(300));

        let parsed = Config::parse([
            "--threads".to_owned(),
            "8".to_owned(),
            "--worker-threads".to_owned(),
            "3".to_owned(),
            "--worker-idle-timeout".to_owned(),
            "0".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.threads, Some(8));
        assert_eq!(config.worker_threads, 3);
        assert_eq!(config.worker_idle_timeout, Duration::ZERO);
        for invalid in ["0", "-1", "abc", "1025"] {
            assert!(Config::parse(["--threads".to_owned(), invalid.to_owned()]).is_err());
            assert!(Config::parse(["--worker-threads".to_owned(), invalid.to_owned()]).is_err());
        }
        assert!(Config::parse(["--worker-idle-timeout".to_owned(), "-1".to_owned()]).is_err());
    }

    #[test]
    fn parses_vhost_directory_option() {
        let parsed = Config::parse([
            "--vhost-dir".to_owned(),
            "/etc/charlotte/vhosts.d".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(
            config.vhost_dir,
            Some(PathBuf::from("/etc/charlotte/vhosts.d"))
        );
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn parses_global_options_from_config_file_and_resolves_relative_paths() {
        let path = write_config_file(
            "options:\n  bind: 127.0.0.1:8123\n  debug: true\n  https_redirect: true\n  index: [home.htm, index.html]\n  user: charlotte\n  threads: 4\n  access-log-file: logs/access.log\n  log-dir: [logs, audit]\n  tls-dir: certificates\n  worker_cgroup: charlotte/sites/{uid}/{name}\n  worker_cgroup_memory_max: 512M\n  worker_cgroup_cpu_max: 150%\n  worker_cgroup_pids_max: 64\n",
        );
        let parsed =
            Config::parse(["--config".to_owned(), path.to_string_lossy().into_owned()]).unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };

        assert_eq!(config.bind.to_string(), "127.0.0.1:8123");
        assert!(config.debug);
        assert!(config.https_redirect);
        assert_eq!(config.index, ["home.htm", "index.html"]);
        assert_eq!(config.master_user.as_deref(), Some("charlotte"));
        assert_eq!(config.threads, Some(4));
        let cgroup = config.worker_cgroup.as_ref().unwrap();
        assert_eq!(cgroup.path, PathBuf::from("charlotte/sites/{uid}/{name}"));
        assert_eq!(cgroup.memory_max.as_deref(), Some("536870912"));
        assert_eq!(cgroup.cpu_max.as_deref(), Some("150000 100000"));
        assert_eq!(cgroup.pids_max.as_deref(), Some("64"));
        assert_eq!(
            config.access_log_file,
            Some(path.parent().unwrap().join("logs/access.log"))
        );
        assert_eq!(
            config.log_dirs,
            [
                path.parent().unwrap().join("logs"),
                path.parent().unwrap().join("audit")
            ]
        );
        assert_eq!(
            config.tls_dirs,
            [path.parent().unwrap().join("certificates")]
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn parses_repeatable_helper_directory_flags() {
        let ParseResult::Config(config) = Config::parse([
            "--log-dir".to_owned(),
            "/var/log/charlotte".to_owned(),
            "--log-dir".to_owned(),
            "/srv/logs".to_owned(),
            "--tls-dir".to_owned(),
            "/etc/charlotte/tls".to_owned(),
        ])
        .unwrap() else {
            panic!("expected config")
        };
        assert_eq!(
            config.log_dirs,
            [
                PathBuf::from("/var/log/charlotte"),
                PathBuf::from("/srv/logs")
            ]
        );
        assert_eq!(config.tls_dirs, [PathBuf::from("/etc/charlotte/tls")]);
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn command_line_values_override_global_file_defaults() {
        let path = write_config_file(
            "options:\n  bind: 127.0.0.1:8123\n  index: [home.htm, index.html]\n",
        );
        let parsed = Config::parse([
            "--config".to_owned(),
            path.to_string_lossy().into_owned(),
            "--bind".to_owned(),
            "127.0.0.1:9123".to_owned(),
            "--index".to_owned(),
            "cli.html".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };

        assert_eq!(config.bind.to_string(), "127.0.0.1:9123");
        assert_eq!(config.index, ["cli.html"]);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_unknown_reserved_and_mistyped_global_options() {
        for (contents, expected) in [
            ("options:\n  not-a-real-option: true\n", "unknown option"),
            ("options:\n  worker: true\n", "not allowed"),
            ("options:\n  debug: \"true\"\n", "must be a boolean"),
        ] {
            let path = write_config_file(contents);
            let error = Config::parse(["--config".to_owned(), path.to_string_lossy().into_owned()])
                .err()
                .expect("invalid options should be rejected");
            assert!(error.contains(&path.display().to_string()), "{error}");
            assert!(error.contains(expected), "{error}");
            fs::remove_file(path).unwrap();
        }
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn parses_config_file_and_worker_identity() {
        let path = write_config_file("");
        let parsed = Config::parse([
            "--config".to_owned(),
            path.to_string_lossy().into_owned(),
            "--debug".to_owned(),
            "--worker".to_owned(),
            "--worker-uid".to_owned(),
            "1000".to_owned(),
            "--worker-gid".to_owned(),
            "1001".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.config_file, Some(path.clone()));
        assert!(config.debug);
        assert!(config.worker);
        assert_eq!(config.worker_uid, Some(1000));
        assert_eq!(config.worker_gid, Some(1001));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn debug_flag_defaults_off_and_can_be_enabled() {
        let ParseResult::Config(defaults) = Config::parse(Vec::<String>::new()).unwrap() else {
            panic!("expected config")
        };
        assert!(!defaults.debug);
        assert!(!defaults.https_redirect);

        let ParseResult::Config(config) = Config::parse(["--debug".to_owned()]).unwrap() else {
            panic!("expected config")
        };
        assert!(config.debug);

        let ParseResult::Config(config) = Config::parse(["--https-redirect".to_owned()]).unwrap()
        else {
            panic!("expected config")
        };
        assert!(config.https_redirect);
    }

    #[test]
    fn parses_modsecurity_rules_and_body_limit() {
        let parsed = Config::parse([
            "--modsecurity-rules".to_owned(),
            "base.conf".to_owned(),
            "--modsecurity-rules".to_owned(),
            "local.conf".to_owned(),
            "--modsecurity-body-limit".to_owned(),
            "4096".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(
            config.modsecurity_rules,
            [PathBuf::from("base.conf"), PathBuf::from("local.conf")]
        );
        assert_eq!(config.modsecurity_body_limit, 4096);
        assert_eq!(config.modsecurity_response_body_limit, 4096);
    }

    #[test]
    fn parses_modsecurity_block_status() {
        let parsed =
            Config::parse(["--modsecurity-block-status".to_owned(), "451".to_owned()]).unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.modsecurity_block_status, Some(451));
        assert_eq!(parse_modsecurity_block_status("400").unwrap(), 400);
        assert_eq!(parse_modsecurity_block_status("599").unwrap(), 599);
        for invalid in ["399", "600", "0", "abc", "-1"] {
            assert!(
                parse_modsecurity_block_status(invalid).is_err(),
                "{invalid}"
            );
            assert!(
                Config::parse(["--modsecurity-block-status".to_owned(), invalid.to_owned()])
                    .is_err()
            );
        }
    }

    #[test]
    fn rejects_invalid_modsecurity_body_limit() {
        assert!(Config::parse(["--modsecurity-body-limit".to_owned(), "0".to_owned()]).is_err());
        assert!(
            Config::parse([
                "--modsecurity-body-limit".to_owned(),
                "not-a-number".to_owned()
            ])
            .is_err()
        );
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn rejects_worker_identity_without_worker_mode() {
        assert!(
            Config::parse([
                "--worker-uid".to_owned(),
                "1000".to_owned(),
                "--worker-gid".to_owned(),
                "1000".to_owned(),
            ])
            .is_err()
        );
    }

    #[test]
    fn parses_master_identity_options() {
        let parsed = Config::parse([
            "--user".to_owned(),
            "charlotte".to_owned(),
            "--group".to_owned(),
            "www-data".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.master_user.as_deref(), Some("charlotte"));
        assert_eq!(config.master_group.as_deref(), Some("www-data"));
    }

    #[test]
    fn rejects_invalid_master_identity_options() {
        assert!(Config::parse(["--group".to_owned(), "www-data".to_owned()]).is_err());
        assert!(Config::parse(["--user".to_owned(), "".to_owned()]).is_err());
        assert!(Config::parse(["--group".to_owned(), "".to_owned()]).is_err());
        assert!(
            Config::parse([
                "--user".to_owned(),
                "charlotte".to_owned(),
                "--worker".to_owned(),
                "--worker-uid".to_owned(),
                "1000".to_owned(),
                "--worker-gid".to_owned(),
                "1000".to_owned(),
            ])
            .is_err()
        );
    }

    #[test]
    fn refuses_options_of_features_left_out_of_the_build() {
        for (args, feature, enabled) in [
            (
                vec!["--root", "public"],
                "hosting",
                cfg!(feature = "hosting"),
            ),
            (
                vec!["--fastcgi", "php=127.0.0.1:9000"],
                "hosting",
                cfg!(feature = "hosting"),
            ),
            (
                vec!["--worker-threads", "2"],
                "hosting",
                cfg!(feature = "hosting"),
            ),
            (
                vec![
                    "--acme-directory",
                    "letsencrypt-staging",
                    "--acme-cache",
                    "cache",
                ],
                "acme",
                cfg!(feature = "acme"),
            ),
            (
                vec!["--http3-bind", "127.0.0.1:8443"],
                "http3",
                cfg!(feature = "http3"),
            ),
        ] {
            match Config::parse(args.iter().map(|arg| (*arg).to_owned())) {
                Ok(_) => assert!(enabled, "{args:?} accepted without `{feature}`"),
                Err(error) => {
                    assert!(!enabled, "{args:?} refused: {error}");
                    assert!(
                        error.contains(&format!("requires the `{feature}` feature")),
                        "{error}"
                    );
                }
            }
        }

        // Options that belong to no feature are accepted by every build.
        let path = write_config_file("");
        assert!(
            Config::parse([
                "--bind".to_owned(),
                "127.0.0.1:8080".to_owned(),
                "--tls-bind".to_owned(),
                "127.0.0.1:8443".to_owned(),
                "--user".to_owned(),
                "nobody".to_owned(),
                "--config".to_owned(),
                path.to_string_lossy().into_owned(),
                "--threads".to_owned(),
                "4".to_owned(),
            ])
            .is_ok()
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn usage_lists_the_options_of_compiled_features_only() {
        let usage = Config::usage();
        assert_eq!(usage.contains("--root"), cfg!(feature = "hosting"));
        assert_eq!(usage.contains("--fastcgi-app"), cfg!(feature = "hosting"));
        assert_eq!(usage.contains("--acme-directory"), cfg!(feature = "acme"));
        assert_eq!(usage.contains("--http3-bind"), cfg!(feature = "http3"));
        assert!(usage.contains("--user") && usage.contains("--tls-bind"));

        let features = usage.rsplit("Compiled features: ").next().unwrap();
        for (name, enabled) in [
            ("acme", cfg!(feature = "acme")),
            ("hosting", cfg!(feature = "hosting")),
            ("http3", cfg!(feature = "http3")),
            ("proxy", cfg!(feature = "proxy")),
        ] {
            assert_eq!(features.split(", ").any(|feature| feature == name), enabled);
        }
    }

    #[test]
    fn help_and_scalar_overrides() {
        for flag in ["--help", "-h"] {
            assert!(matches!(
                Config::parse([flag.to_owned()]),
                Ok(ParseResult::Help)
            ));
        }
        let Ok(ParseResult::Config(config)) = Config::parse(
            [
                "--bind",
                "127.0.0.1:1",
                "--bind",
                "127.0.0.1:2",
                "--threads",
                "3",
                "--threads",
                "4",
            ]
            .map(str::to_owned),
        ) else {
            panic!("expected config")
        };
        assert_eq!(config.bind.to_string(), "127.0.0.1:2");
        assert_eq!(config.threads, Some(4));
        assert!(Config::parse(["--bind".to_owned()]).is_err());
        assert!(Config::parse(["--unknown".to_owned()]).is_err());
        let error = Config::parse(["--threads", "0"].map(str::to_owned))
            .err()
            .expect("invalid thread count");
        assert!(error.contains("invalid thread count: 0"), "{error}");
    }

    #[test]
    fn can_disable_plain_http_listener() {
        let Ok(ParseResult::Config(default_config)) = Config::parse(Vec::<String>::new()) else {
            panic!("expected config")
        };
        assert!(default_config.plain_http);

        let Ok(ParseResult::Config(config)) = Config::parse(["--no-plain-http".to_owned()]) else {
            panic!("expected config")
        };
        assert!(!config.plain_http);
    }

    #[test]
    fn check_config_is_an_option_and_is_rejected_for_workers() {
        let Ok(ParseResult::Config(default_config)) = Config::parse(Vec::<String>::new()) else {
            panic!("expected config");
        };
        assert!(!default_config.check_config);
        let Ok(ParseResult::Config(config)) = Config::parse(["--check-config".to_owned()]) else {
            panic!("expected config");
        };
        assert!(config.check_config);

        #[cfg(feature = "hosting")]
        {
            let error = Config::parse(
                [
                    "--check-config",
                    "--worker",
                    "--worker-uid",
                    "1000",
                    "--worker-gid",
                    "1000",
                ]
                .map(str::to_owned),
            )
            .err()
            .expect("worker mode must reject config validation");
            assert!(error.contains("--check-config cannot be used with --worker"));
        }
    }

    #[cfg(feature = "acme")]
    #[test]
    fn rejects_disabling_plain_http_with_acme() {
        let error = Config::parse(
            [
                "--no-plain-http",
                "--acme-directory",
                "letsencrypt-staging",
                "--acme-cache",
                "/var/lib/charlotte/acme",
            ]
            .map(str::to_owned),
        )
        .err()
        .expect("ACME requires plaintext HTTP");
        assert!(error.contains("HTTP-01 requires plaintext HTTP"), "{error}");
    }

    #[cfg(feature = "hosting")]
    #[test]
    fn keeps_interleaved_backend_order_and_hyphen_values() {
        let Ok(ParseResult::Config(config)) = Config::parse(
            [
                "--cgi",
                "cgi",
                "--fastcgi",
                "php=127.0.0.1:9000",
                "--fastcgi-app",
                "py=/usr/bin/app",
                "--fastcgi-app-arg",
                "py=--verbose",
                "--fastcgi-app-workers",
                "py=3",
                "--try-files",
                "$uri",
                "--try-files",
                "=404",
            ]
            .map(str::to_owned),
        ) else {
            panic!("expected config")
        };
        let extensions = config
            .fastcgi
            .iter()
            .map(|backend| backend.extension.as_str())
            .collect::<Vec<_>>();
        assert_eq!(extensions, ["cgi", "php", "py"]);
        let FastCgiAddress::Spawn(app) = &config.fastcgi[2].address else {
            panic!("expected spawned app")
        };
        assert_eq!(app.args, ["--verbose"]);
        assert_eq!(app.max_workers, 3);
        assert_eq!(config.try_files, ["$uri", "=404"]);
    }

    #[test_fuzz::test_fuzz]
    fn cli_args(args: Vec<String>) {
        let _ = Config::parse(args);
    }

    #[test]
    fn fuzz_seed_cli_args() {
        cli_args(vec!["--help".to_owned()]);
        cli_args(vec![
            "--bind".to_owned(),
            "127.0.0.1:8080".to_owned(),
            "--fastcgi".to_owned(),
            "php=127.0.0.1:9000".to_owned(),
        ]);
    }

    #[test_fuzz::test_fuzz]
    fn fastcgi_backend(value: &str) {
        let _ = super::parse_fastcgi_backend(value);
    }

    #[test]
    fn fuzz_seed_fastcgi_backend() {
        fastcgi_backend("php=127.0.0.1:9000");
        fastcgi_backend("php=unix:/run/php.sock");
    }
}
