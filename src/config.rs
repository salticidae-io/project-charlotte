use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Clone, Debug)]
pub struct FastCgiBackend {
    pub extension: String,
    pub address: FastCgiAddress,
}

#[derive(Clone, Debug)]
pub enum FastCgiAddress {
    Tcp(String),
    Unix(PathBuf),
    Spawn(FastCgiApp),
}

#[derive(Clone, Debug)]
pub struct FastCgiApp {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub tls_bind: Option<SocketAddr>,
    pub http3_bind: SocketAddr,
    pub root: PathBuf,
    pub config_file: Option<PathBuf>,
    pub index: String,
    pub listing: bool,
    pub fastcgi: Vec<FastCgiBackend>,
    pub fastcgi_timeout: Duration,
    pub modsecurity_rules: Vec<PathBuf>,
    pub modsecurity_body_limit: usize,
    pub modsecurity_response_body_limit: usize,
    pub tls: Option<TlsFiles>,
    pub acme: Option<AcmeSettings>,
    pub worker: bool,
    pub worker_uid: Option<u32>,
    pub worker_gid: Option<u32>,
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

impl Config {
    pub fn parse(args: impl IntoIterator<Item = String>) -> Result<ParseResult, String> {
        let mut bind = "127.0.0.1:8080"
            .parse()
            .expect("valid default socket address");
        let mut tls_bind = None;
        let mut http3_bind = None;
        let mut root = PathBuf::from(".");
        let mut index = String::from("index.html");
        let mut listing = true;
        let mut fastcgi = Vec::new();
        let mut fastcgi_app_args = Vec::new();
        let mut fastcgi_app_env = Vec::new();
        let mut fastcgi_timeout = Duration::from_secs(60);
        let mut modsecurity_rules = Vec::new();
        let mut modsecurity_body_limit = 16 * 1024 * 1024;
        let mut modsecurity_response_body_limit = 1024 * 1024;
        let mut tls_cert = None;
        let mut tls_key = None;
        let mut acme_directory = None;
        let mut acme_cache = None;
        let mut acme_contacts = Vec::new();
        let mut acme_ca_root = None;
        let mut config_file = None;
        let mut worker = false;
        let mut worker_uid = None;
        let mut worker_gid = None;
        let mut args = args.into_iter();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--help" | "-h" => return Ok(ParseResult::Help),
                "--worker" => worker = true,
                "--no-listing" => listing = false,
                "--fastcgi" => {
                    let value = next_value(&mut args, "--fastcgi")?;
                    let backend = parse_fastcgi_backend(&value)?;
                    if fastcgi
                        .iter()
                        .any(|existing: &FastCgiBackend| existing.extension == backend.extension)
                    {
                        return Err(format!(
                            "duplicate FastCGI extension: {}",
                            backend.extension
                        ));
                    }
                    fastcgi.push(backend);
                }
                "--fastcgi-app" => {
                    let value = next_value(&mut args, "--fastcgi-app")?;
                    let backend = parse_fastcgi_app(&value)?;
                    if fastcgi
                        .iter()
                        .any(|existing: &FastCgiBackend| existing.extension == backend.extension)
                    {
                        return Err(format!(
                            "duplicate FastCGI extension: {}",
                            backend.extension
                        ));
                    }
                    fastcgi.push(backend);
                }
                "--fastcgi-app-arg" => {
                    let value = next_value(&mut args, "--fastcgi-app-arg")?;
                    let (extension, arg) = value.split_once('=').ok_or_else(|| {
                        format!("invalid FastCGI app argument: {value}; expected EXT=ARG")
                    })?;
                    if arg.contains('\0') {
                        return Err("FastCGI app argument cannot contain NUL".to_owned());
                    }
                    fastcgi_app_args.push((normalize_extension(extension)?, arg.to_owned()));
                }
                "--fastcgi-app-env" => {
                    let value = next_value(&mut args, "--fastcgi-app-env")?;
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
                "--fastcgi-timeout" => {
                    let value = next_value(&mut args, "--fastcgi-timeout")?;
                    let seconds = value
                        .parse::<u64>()
                        .ok()
                        .filter(|seconds| *seconds > 0)
                        .ok_or_else(|| format!("invalid FastCGI timeout: {value}"))?;
                    fastcgi_timeout = Duration::from_secs(seconds);
                }
                "--modsecurity-rules" => {
                    modsecurity_rules
                        .push(PathBuf::from(next_value(&mut args, "--modsecurity-rules")?));
                }
                "--modsecurity-body-limit" => {
                    let value = next_value(&mut args, "--modsecurity-body-limit")?;
                    let limit = value
                        .parse::<usize>()
                        .ok()
                        .filter(|limit| *limit > 0)
                        .ok_or_else(|| format!("invalid ModSecurity body limit: {value}"))?;
                    modsecurity_body_limit = limit;
                    modsecurity_response_body_limit = limit;
                }
                "--tls-cert" => {
                    tls_cert = Some(PathBuf::from(next_value(&mut args, "--tls-cert")?))
                }
                "--tls-key" => tls_key = Some(PathBuf::from(next_value(&mut args, "--tls-key")?)),
                "--acme-directory" => {
                    let value = next_value(&mut args, "--acme-directory")?;
                    let directory = match value.as_str() {
                        "letsencrypt" => "https://acme-v02.api.letsencrypt.org/directory",
                        "letsencrypt-staging" => {
                            "https://acme-staging-v02.api.letsencrypt.org/directory"
                        }
                        _ => value.as_str(),
                    };
                    if !(directory.starts_with("https://") || directory.starts_with("http://")) {
                        return Err(
                            "--acme-directory must be an HTTP(S) URL or a known alias".to_owned()
                        );
                    }
                    acme_directory = Some(directory.to_owned());
                }
                "--acme-cache" => {
                    acme_cache = Some(PathBuf::from(next_value(&mut args, "--acme-cache")?))
                }
                "--acme-contact" => {
                    let value = next_value(&mut args, "--acme-contact")?;
                    if value.is_empty() || !value.contains(':') || value.contains('\0') {
                        return Err(format!("invalid ACME contact URI: {value}"));
                    }
                    acme_contacts.push(value);
                }
                "--acme-ca-root" => {
                    acme_ca_root = Some(PathBuf::from(next_value(&mut args, "--acme-ca-root")?))
                }
                "--http3-bind" => {
                    let value = next_value(&mut args, "--http3-bind")?;
                    http3_bind = Some(
                        value
                            .parse()
                            .map_err(|_| format!("invalid HTTP/3 socket address: {value}"))?,
                    );
                }
                "--tls-bind" => {
                    let value = next_value(&mut args, "--tls-bind")?;
                    tls_bind = Some(
                        value
                            .parse()
                            .map_err(|_| format!("invalid TLS socket address: {value}"))?,
                    );
                }
                "--bind" => {
                    let value = next_value(&mut args, "--bind")?;
                    bind = value
                        .parse()
                        .map_err(|_| format!("invalid socket address: {value}"))?;
                }
                "--root" => root = PathBuf::from(next_value(&mut args, "--root")?),
                "--index" => index = next_value(&mut args, "--index")?,
                "--config" => config_file = Some(PathBuf::from(next_value(&mut args, "--config")?)),
                "--worker-uid" => {
                    let value = next_value(&mut args, "--worker-uid")?;
                    worker_uid = Some(
                        value
                            .parse::<u32>()
                            .map_err(|_| format!("invalid worker uid: {value}"))?,
                    );
                }
                "--worker-gid" => {
                    let value = next_value(&mut args, "--worker-gid")?;
                    worker_gid = Some(
                        value
                            .parse::<u32>()
                            .map_err(|_| format!("invalid worker gid: {value}"))?,
                    );
                }
                _ => return Err(format!("unknown argument: {arg}\n{}", Self::usage())),
            }
        }

        if index.is_empty()
            || index.contains('/')
            || index.contains('\\')
            || index == "."
            || index == ".."
        {
            return Err("--index must be a non-empty file name".to_owned());
        }

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
        for (extension, key, value) in fastcgi_app_env {
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
            index,
            listing,
            fastcgi,
            fastcgi_timeout,
            modsecurity_rules,
            modsecurity_body_limit,
            modsecurity_response_body_limit,
            tls,
            acme,
            worker,
            worker_uid,
            worker_gid,
        })))
    }

    pub fn usage() -> &'static str {
        "Usage: project-charlotte [--bind ADDRESS] [--tls-bind ADDRESS] [--root DIRECTORY] [--index NAME] [--no-listing] [--fastcgi EXT=ADDR]... [--fastcgi-app EXT=PROGRAM]... [--fastcgi-app-arg EXT=ARG]... [--fastcgi-app-env EXT=KEY=VALUE]... [--fastcgi-timeout SECS] [--modsecurity-rules FILE]... [--modsecurity-body-limit BYTES] [--config FILE] [--tls-cert PATH --tls-key PATH] [--acme-directory URL|letsencrypt|letsencrypt-staging --acme-cache DIR] [--acme-contact URI]... [--acme-ca-root PEM] [--http3-bind ADDRESS] [--help]"
    }
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

fn next_value(args: &mut impl Iterator<Item = String>, option: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("missing value for {option}"))
}

#[cfg(test)]
mod tests {
    use super::{Config, FastCgiAddress, ParseResult};
    use std::path::PathBuf;

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
    fn parses_fastcgi_app_and_preserves_args_and_environment() {
        let parsed = Config::parse([
            "--fastcgi-app-arg".to_owned(),
            "PHP=--foreground".to_owned(),
            "--fastcgi-app-env".to_owned(),
            "php=APP_MODE=production".to_owned(),
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
        assert_eq!(
            app.env.get("APP_MODE").map(String::as_str),
            Some("production")
        );
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
    fn parses_config_file_and_worker_identity() {
        let parsed = Config::parse([
            "--config".to_owned(),
            "sites.toml".to_owned(),
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
        assert_eq!(config.config_file, Some(PathBuf::from("sites.toml")));
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
