use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser, error::ErrorKind};
use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

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
    Pool(Arc<crate::fastcgi_app::AppPool>),
}

#[derive(Clone, Debug)]
pub struct FastCgiApp {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub max_workers: usize,
    pub idle_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub tls_bind: Option<SocketAddr>,
    pub http3_bind: SocketAddr,
    pub root: PathBuf,
    pub config_file: Option<PathBuf>,
    pub vhost_dir: Option<PathBuf>,
    pub index: String,
    pub listing: bool,
    pub try_files: Vec<String>,
    pub fastcgi: Vec<FastCgiBackend>,
    pub fastcgi_timeout: Duration,
    pub threads: Option<usize>,
    pub worker_threads: usize,
    pub modsecurity_rules: Vec<PathBuf>,
    pub modsecurity_block_status: Option<u16>,
    pub modsecurity_body_limit: usize,
    pub modsecurity_response_body_limit: usize,
    pub tls: Option<TlsFiles>,
    pub acme: Option<AcmeSettings>,
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

#[derive(Debug, Parser)]
#[command(
    name = "project-charlotte",
    args_override_self = true,
    disable_version_flag = true
)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:8080", allow_hyphen_values = true)]
    bind: String,
    #[arg(long, allow_hyphen_values = true)]
    tls_bind: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    http3_bind: Option<String>,
    #[arg(long, default_value = ".", allow_hyphen_values = true)]
    root: PathBuf,
    #[arg(long, allow_hyphen_values = true)]
    config: Option<PathBuf>,
    #[arg(long, allow_hyphen_values = true)]
    vhost_dir: Option<PathBuf>,
    #[arg(long, default_value = "index.html", allow_hyphen_values = true)]
    index: String,
    #[arg(long = "no-listing")]
    no_listing: bool,
    #[arg(long, allow_hyphen_values = true)]
    try_files: Vec<String>,
    #[arg(long, allow_hyphen_values = true)]
    fastcgi: Vec<String>,
    #[arg(long, allow_hyphen_values = true)]
    cgi: Vec<String>,
    #[arg(long, allow_hyphen_values = true)]
    fastcgi_app: Vec<String>,
    #[arg(long, allow_hyphen_values = true)]
    fastcgi_app_arg: Vec<String>,
    #[arg(
        long = "fastcgi-app-max-workers",
        alias = "fastcgi-app-workers",
        allow_hyphen_values = true
    )]
    fastcgi_app_max_workers: Vec<String>,
    #[arg(long, allow_hyphen_values = true)]
    fastcgi_app_idle_timeout: Vec<String>,
    #[arg(long, allow_hyphen_values = true)]
    fastcgi_app_env: Vec<String>,
    #[arg(long, default_value = "60", value_parser = parse_cli_fastcgi_timeout, allow_hyphen_values = true)]
    fastcgi_timeout: u64,
    #[arg(long, value_parser = parse_cli_thread_count, allow_hyphen_values = true)]
    threads: Option<usize>,
    #[arg(
        long,
        default_value_t = DEFAULT_WORKER_THREADS,
        value_parser = parse_cli_thread_count,
        allow_hyphen_values = true
    )]
    worker_threads: usize,
    #[arg(long, allow_hyphen_values = true)]
    modsecurity_rules: Vec<PathBuf>,
    #[arg(long, value_parser = parse_cli_modsecurity_block_status, allow_hyphen_values = true)]
    modsecurity_block_status: Option<u16>,
    #[arg(long, value_parser = parse_cli_positive_usize, allow_hyphen_values = true)]
    modsecurity_body_limit: Option<usize>,
    #[arg(long, allow_hyphen_values = true)]
    tls_cert: Option<PathBuf>,
    #[arg(long, allow_hyphen_values = true)]
    tls_key: Option<PathBuf>,
    #[arg(long, allow_hyphen_values = true)]
    acme_directory: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    acme_cache: Option<PathBuf>,
    #[arg(long, allow_hyphen_values = true)]
    acme_contact: Vec<String>,
    #[arg(long, allow_hyphen_values = true)]
    acme_ca_root: Option<PathBuf>,
    #[arg(long)]
    worker: bool,
    #[arg(long, allow_hyphen_values = true)]
    worker_uid: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    worker_gid: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    user: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    group: Option<String>,
}

impl Config {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<ParseResult, String> {
        let matches = match Cli::command()
            .try_get_matches_from(std::iter::once("project-charlotte".to_owned()).chain(args))
        {
            Ok(matches) => matches,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
                ) =>
            {
                return Ok(ParseResult::Help);
            }
            Err(error) => return Err(error.to_string()),
        };
        let cli = Cli::from_arg_matches(&matches).map_err(|error| error.to_string())?;

        let bind = cli
            .bind
            .parse()
            .map_err(|_| format!("invalid socket address: {}", cli.bind))?;
        let tls_bind = cli
            .tls_bind
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| format!("invalid TLS socket address: {value}"))
            })
            .transpose()?;
        let http3_bind = cli
            .http3_bind
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| format!("invalid HTTP/3 socket address: {value}"))
            })
            .transpose()?;
        let mut modsecurity_body_limit = 16 * 1024 * 1024;
        let mut modsecurity_response_body_limit = 1024 * 1024;
        if let Some(limit) = cli.modsecurity_body_limit {
            modsecurity_body_limit = limit;
            modsecurity_response_body_limit = limit;
        }

        let mut backend_values = indexed_values(&matches, "fastcgi", cli.fastcgi);
        backend_values.extend(indexed_values(&matches, "cgi", cli.cgi));
        backend_values.extend(indexed_values(&matches, "fastcgi_app", cli.fastcgi_app));
        backend_values.sort_by_key(|(index, _, _)| *index);
        let mut fastcgi = Vec::new();
        for (_, kind, value) in backend_values {
            let backend = match kind.as_str() {
                "fastcgi" => parse_fastcgi_backend(&value)?,
                "cgi" => parse_cgi_backend(&value)?,
                "fastcgi_app" => parse_fastcgi_app(&value)?,
                _ => unreachable!("indexed backend kind is known"),
            };
            add_backend(&mut fastcgi, backend)?;
        }

        let mut fastcgi_app_args = Vec::new();
        for value in cli.fastcgi_app_arg {
            let (extension, arg) = value.split_once('=').ok_or_else(|| {
                format!("invalid FastCGI app argument: {value}; expected EXT=ARG")
            })?;
            if arg.contains('\0') {
                return Err("FastCGI app argument cannot contain NUL".to_owned());
            }
            fastcgi_app_args.push((normalize_extension(extension)?, arg.to_owned()));
        }

        let mut fastcgi_app_max_workers = Vec::new();
        for value in cli.fastcgi_app_max_workers {
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

        let mut fastcgi_app_idle_timeouts = Vec::new();
        for value in cli.fastcgi_app_idle_timeout {
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
        for value in cli.fastcgi_app_env {
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

        let acme_contacts = cli.acme_contact;
        for value in &acme_contacts {
            if value.is_empty() || !value.contains(':') || value.contains('\0') {
                return Err(format!("invalid ACME contact URI: {value}"));
            }
        }
        let acme_directory = cli.acme_directory.map(|value| {
            match value.as_str() {
                "letsencrypt" => "https://acme-v02.api.letsencrypt.org/directory",
                "letsencrypt-staging" => "https://acme-staging-v02.api.letsencrypt.org/directory",
                _ => value.as_str(),
            }
            .to_owned()
        });
        if let Some(directory) = &acme_directory
            && !(directory.starts_with("https://") || directory.starts_with("http://"))
        {
            return Err("--acme-directory must be an HTTP(S) URL or a known alias".to_owned());
        }

        let worker_uid = cli
            .worker_uid
            .map(|value| {
                value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid worker uid: {value}"))
            })
            .transpose()?;
        let worker_gid = cli
            .worker_gid
            .map(|value| {
                value
                    .parse::<u32>()
                    .map_err(|_| format!("invalid worker gid: {value}"))
            })
            .transpose()?;
        if cli.user.as_deref() == Some("") {
            return Err("--user requires a non-empty user name".to_owned());
        }
        if cli.group.as_deref() == Some("") {
            return Err("--group requires a non-empty group name".to_owned());
        }
        let fastcgi_timeout = Duration::from_secs(cli.fastcgi_timeout);
        let threads = cli.threads;
        let worker_threads = cli.worker_threads;
        let modsecurity_rules = cli.modsecurity_rules;
        let modsecurity_block_status = cli.modsecurity_block_status;
        let tls_cert = cli.tls_cert;
        let tls_key = cli.tls_key;
        let acme_cache = cli.acme_cache;
        let acme_ca_root = cli.acme_ca_root;
        let config_file = cli.config;
        let vhost_dir = cli.vhost_dir;
        let worker = cli.worker;
        let master_user = cli.user;
        let master_group = cli.group;
        let root = cli.root;
        let index = cli.index;
        let listing = !cli.no_listing;
        let try_files = cli.try_files;

        if index.is_empty()
            || index.contains('/')
            || index.contains('\\')
            || index == "."
            || index == ".."
        {
            return Err("--index must be a non-empty file name".to_owned());
        }
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

        Ok(ParseResult::Config(Box::new(Self {
            bind,
            tls_bind,
            http3_bind: http3_bind.unwrap_or_else(|| tls_bind.unwrap_or(bind)),
            root,
            config_file,
            vhost_dir,
            index,
            listing,
            try_files,
            fastcgi,
            fastcgi_timeout,
            threads,
            worker_threads,
            modsecurity_rules,
            modsecurity_block_status,
            modsecurity_body_limit,
            modsecurity_response_body_limit,
            tls,
            acme,
            worker,
            worker_uid,
            worker_gid,
            master_user,
            master_group,
        })))
    }

    /// Applies spawned-app environment that the master passed to this worker
    /// through `WORKER_APP_ENV`, encoded as `[[extension, key, value], ...]`.
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
        Cli::command().render_help().to_string()
    }
}

/// Environment variable through which the master hands a worker the
/// environment of its spawned FastCGI apps.
pub(crate) const WORKER_APP_ENV: &str = "CHARLOTTE_FASTCGI_APP_ENV";

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
            max_workers: 1,
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
pub const DEFAULT_FASTCGI_APP_IDLE_TIMEOUT_SECS: u64 = 60;
pub const MAX_FASTCGI_APP_IDLE_TIMEOUT_SECS: u64 = 86_400;

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

fn indexed_values(
    matches: &ArgMatches,
    id: &str,
    values: Vec<String>,
) -> Vec<(usize, String, String)> {
    matches
        .indices_of(id)
        .into_iter()
        .flatten()
        .zip(values)
        .map(|(index, value)| (index, id.to_owned(), value))
        .collect()
}

fn parse_cli_fastcgi_timeout(value: &str) -> Result<u64, std::io::Error> {
    value
        .parse::<u64>()
        .ok()
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| std::io::Error::other(format!("invalid FastCGI timeout: {value}")))
}

fn parse_cli_thread_count(value: &str) -> Result<usize, std::io::Error> {
    parse_thread_count(value).map_err(std::io::Error::other)
}

fn parse_cli_modsecurity_block_status(value: &str) -> Result<u16, std::io::Error> {
    parse_modsecurity_block_status(value).map_err(std::io::Error::other)
}

fn parse_cli_positive_usize(value: &str) -> Result<usize, std::io::Error> {
    value
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| std::io::Error::other(format!("invalid ModSecurity body limit: {value}")))
}

#[cfg(test)]
mod tests {
    use super::{
        Config, DEFAULT_FASTCGI_APP_IDLE_TIMEOUT_SECS, FastCgiAddress, ParseResult,
        parse_modsecurity_block_status, validate_try_files,
    };
    use std::{path::PathBuf, time::Duration};

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
        assert_eq!(config.http3_bind, config.bind);
        assert_eq!(config.root.as_path(), std::path::Path::new("public"));
        assert_eq!(config.config_file, None);
        assert_eq!(config.index, "home.htm");
        assert!(!config.listing);
        assert!(config.try_files.is_empty());
    }

    #[test]
    fn cli_keeps_last_scalar_value_and_accepts_hyphen_leading_values() {
        let parsed = Config::parse([
            "--bind".to_owned(),
            "127.0.0.1:8080".to_owned(),
            "--bind".to_owned(),
            "127.0.0.1:9000".to_owned(),
            "--index".to_owned(),
            "-home.html".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.bind.to_string(), "127.0.0.1:9000");
        assert_eq!(config.index, "-home.html");
    }

    #[test]
    fn parses_interleaved_backend_options_in_command_line_order() {
        let error = match Config::parse([
            "--fastcgi-app".to_owned(),
            "invalid".to_owned(),
            "--fastcgi".to_owned(),
            "invalid".to_owned(),
        ]) {
            Err(error) => error,
            Ok(_) => panic!("expected invalid backend declaration"),
        };
        assert!(error.contains("invalid FastCGI app: invalid"), "{error}");
    }

    #[test]
    fn clap_help_is_handled_and_usage_lists_options() {
        assert!(matches!(
            Config::parse(["--help".to_owned()]).unwrap(),
            ParseResult::Help
        ));
        assert!(Config::usage().contains("--fastcgi-app-max-workers"));
    }

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

    #[test]
    fn rejects_invalid_index() {
        assert!(Config::parse(["--index".to_owned(), "../secret".to_owned()]).is_err());
    }

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

    #[test]
    fn fastcgi_app_defaults_to_one_worker() {
        let parsed = Config::parse(["--fastcgi-app".to_owned(), "php=php-cgi".to_owned()]).unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        let FastCgiAddress::Spawn(app) = &config.fastcgi[0].address else {
            panic!("expected spawned FastCGI app")
        };
        assert_eq!(app.max_workers, 1);
        assert_eq!(
            app.idle_timeout,
            Duration::from_secs(DEFAULT_FASTCGI_APP_IDLE_TIMEOUT_SECS)
        );
    }

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

    #[test]
    fn rejects_incomplete_tls_options_and_invalid_http3_bind() {
        assert!(Config::parse(["--tls-cert".to_owned(), "server.pem".to_owned()]).is_err());
        assert!(Config::parse(["--tls-key".to_owned(), "server-key.pem".to_owned()]).is_err());
        assert!(Config::parse(["--http3-bind".to_owned(), "localhost".to_owned()]).is_err());
        assert!(Config::parse(["--tls-bind".to_owned(), "localhost".to_owned()]).is_err());
    }

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

    #[test]
    fn parses_thread_options_and_rejects_invalid_counts() {
        let ParseResult::Config(defaults) = Config::parse(Vec::<String>::new()).unwrap() else {
            panic!("expected config")
        };
        assert_eq!(defaults.threads, None);
        assert_eq!(defaults.worker_threads, 2);

        let parsed = Config::parse([
            "--threads".to_owned(),
            "8".to_owned(),
            "--worker-threads".to_owned(),
            "3".to_owned(),
        ])
        .unwrap();
        let ParseResult::Config(config) = parsed else {
            panic!("expected config")
        };
        assert_eq!(config.threads, Some(8));
        assert_eq!(config.worker_threads, 3);
        for invalid in ["0", "-1", "abc", "1025"] {
            assert!(Config::parse(["--threads".to_owned(), invalid.to_owned()]).is_err());
            assert!(Config::parse(["--worker-threads".to_owned(), invalid.to_owned()]).is_err());
        }
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

    #[test]
    fn parses_config_file_and_worker_identity() {
        let parsed = Config::parse([
            "--config".to_owned(),
            "sites.yaml".to_owned(),
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
        assert_eq!(config.config_file, Some(PathBuf::from("sites.yaml")));
        assert!(config.worker);
        assert_eq!(config.worker_uid, Some(1000));
        assert_eq!(config.worker_gid, Some(1001));
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
