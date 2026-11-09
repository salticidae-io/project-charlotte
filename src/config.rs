use std::{net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Clone, Debug)]
pub struct FastCgiBackend {
    pub extension: String,
    pub address: FastCgiAddress,
}

#[derive(Clone, Debug)]
pub enum FastCgiAddress {
    Tcp(String),
    Unix(PathBuf),
}

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub http3_bind: SocketAddr,
    pub root: PathBuf,
    pub config_file: Option<PathBuf>,
    pub index: String,
    pub listing: bool,
    pub fastcgi: Vec<FastCgiBackend>,
    pub fastcgi_timeout: Duration,
    pub tls: Option<TlsFiles>,
    pub worker: bool,
    pub worker_uid: Option<u32>,
    pub worker_gid: Option<u32>,
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
        let mut http3_bind = None;
        let mut root = PathBuf::from(".");
        let mut index = String::from("index.html");
        let mut listing = true;
        let mut fastcgi = Vec::new();
        let mut fastcgi_timeout = Duration::from_secs(60);
        let mut tls_cert = None;
        let mut tls_key = None;
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
                "--fastcgi-timeout" => {
                    let value = next_value(&mut args, "--fastcgi-timeout")?;
                    let seconds = value
                        .parse::<u64>()
                        .ok()
                        .filter(|seconds| *seconds > 0)
                        .ok_or_else(|| format!("invalid FastCGI timeout: {value}"))?;
                    fastcgi_timeout = Duration::from_secs(seconds);
                }
                "--tls-cert" => {
                    tls_cert = Some(PathBuf::from(next_value(&mut args, "--tls-cert")?))
                }
                "--tls-key" => tls_key = Some(PathBuf::from(next_value(&mut args, "--tls-key")?)),
                "--http3-bind" => {
                    let value = next_value(&mut args, "--http3-bind")?;
                    http3_bind = Some(
                        value
                            .parse()
                            .map_err(|_| format!("invalid HTTP/3 socket address: {value}"))?,
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

        let tls = match (tls_cert, tls_key) {
            (Some(cert), Some(key)) => Some(TlsFiles { cert, key }),
            (None, None) => None,
            _ => return Err("--tls-cert and --tls-key must be supplied together".to_owned()),
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
            http3_bind: http3_bind.unwrap_or(bind),
            root,
            config_file,
            index,
            listing,
            fastcgi,
            fastcgi_timeout,
            tls,
            worker,
            worker_uid,
            worker_gid,
        })))
    }

    pub fn usage() -> &'static str {
        "Usage: project-charlotte [--bind ADDRESS] [--root DIRECTORY] [--index NAME] [--no-listing] [--fastcgi EXT=ADDR]... [--fastcgi-timeout SECS] [--config FILE] [--tls-cert PATH --tls-key PATH] [--http3-bind ADDRESS] [--help]"
    }
}

pub(crate) fn parse_fastcgi_backend(value: &str) -> Result<FastCgiBackend, String> {
    let (extension, address) = value
        .split_once('=')
        .ok_or_else(|| format!("invalid FastCGI backend: {value}; expected EXT=ADDR"))?;
    let extension = extension.trim_start_matches('.').to_ascii_lowercase();
    if extension.is_empty() || !extension.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(format!("invalid FastCGI extension: {extension}"));
    }
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
    fn rejects_incomplete_tls_options_and_invalid_http3_bind() {
        assert!(Config::parse(["--tls-cert".to_owned(), "server.pem".to_owned()]).is_err());
        assert!(Config::parse(["--tls-key".to_owned(), "server-key.pem".to_owned()]).is_err());
        assert!(Config::parse(["--http3-bind".to_owned(), "localhost".to_owned()]).is_err());
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
}
