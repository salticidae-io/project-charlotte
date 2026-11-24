use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::{self, BufRead, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    sync::atomic::{AtomicU64, Ordering},
};

use clap::Parser;
use project_charlotte::configure_support::{
    ACME_ENABLED, HOSTING_ENABLED, OptionInfo, OptionKind, PROXY_ENABLED, SWARM_ENABLED,
    server_options, validate_main_config_yaml, validate_vhost_yaml,
};
use serde::Serialize;
use serde_yaml_ng::{Mapping, Value};

#[derive(Debug, Parser)]
#[command(about = "Build a Charlotte virtual host by answering setup questions")]
struct Cli {
    /// Write YAML to a file instead of stdout
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Replace the output file if it already exists
    #[arg(long, requires = "output")]
    force: bool,
    /// Also configure server-wide defaults in an options mapping
    #[arg(long)]
    server_options: bool,
}

fn main() -> ExitCode {
    match run_cli() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("charlotte-configure: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_cli() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    if let Some(path) = &cli.output
        && path.exists()
        && !cli.force
    {
        return Err(format!(
            "{} already exists; pass --force to replace it",
            path.display()
        )
        .into());
    }

    let config_dir = cli
        .output
        .as_deref()
        .and_then(Path::parent)
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let stdin = io::stdin();
    let stderr = io::stderr();
    let mut wizard = Wizard::new(stdin.lock(), stderr.lock(), config_dir, cli.server_options);
    let yaml = wizard.run()?;
    match cli.output {
        Some(path) => write_output(&path, yaml.as_bytes(), cli.force)?,
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(yaml.as_bytes())?;
            stdout.flush()?;
        }
    }
    Ok(())
}

struct Wizard<R, W> {
    input: R,
    output: W,
    config_dir: PathBuf,
    server_options_mode: bool,
    global_options: Option<Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SiteKind {
    Static,
    PhpApp,
    ExternalFastCgi,
    Proxy,
}

#[derive(Clone)]
struct CoreAnswers {
    names: String,
    site_kind: SiteKind,
    root: String,
    user: String,
    group: String,
    php_program: String,
    upstream: String,
}

#[cfg(test)]
const ASKED_VHOST_KEYS: &[&str] = &[
    "server_names",
    "root",
    "user",
    "group",
    "index",
    "listing",
    "try_files",
    "fastcgi",
    "cgi",
    "fastcgi_app",
    "fastcgi_timeout",
    "worker_threads",
    "worker_idle_timeout",
    "cgroup",
    "cgroup_memory_max",
    "cgroup_cpu_max",
    "cgroup_pids_max",
    "rate_limit",
    "rate_limit_burst",
    "bot",
    "tls_cert",
    "tls_key",
    "tls_chain",
    "https_redirect",
    "default",
    "modsecurity_disable_rules",
    "modsecurity_block_status",
    "modsecurity_response_body",
    "acme",
    "proxy_pass",
    "proxy_preserve_host",
    "proxy_http2",
    "swarm",
    "proxy_timeout",
    "proxy_ca_root",
    "access_log",
    "access_log_format",
    "error_log",
    "error_log_format",
];
#[cfg(test)]
const NOT_ASKED_VHOST_KEYS: &[&str] = &[];
#[cfg(test)]
const ASKED_FASTCGI_APP_KEYS: &[&str] = &[
    "extension",
    "command",
    "env",
    "mode",
    "php_defaults",
    "max_workers",
    "min_workers",
    "idle_timeout",
];
#[cfg(test)]
const NOT_ASKED_FASTCGI_APP_KEYS: &[&str] = &["workers"];
#[cfg(test)]
const ASKED_BOT_POLICY_KEYS: &[&str] = &[
    "mode",
    "challenge_threshold",
    "block_threshold",
    "challenge",
    "challenge_difficulty",
    "challenge_ttl",
    "allow_ips",
    "deny_ips",
    "allow_user_agents",
    "deny_user_agents",
    "builtin_rules",
    "honeypot_paths",
    "honeypot_ban",
    "exempt_paths",
    "verify_crawlers",
    "ja4_allow",
    "ja4_deny",
    "busy_threshold",
    "busy_window",
    "busy_cooldown",
];
#[cfg(test)]
const NOT_ASKED_BOT_POLICY_KEYS: &[&str] = &[];

const CURATED_SERVER_OPTIONS: &[&str] = &[
    "bind",
    "no_plain_http",
    "tls_bind",
    "http3_bind",
    "user",
    "group",
    "vhost_dir",
    "control_socket",
    "tls_cert",
    "tls_key",
    "acme_directory",
    "acme_cache",
    "acme_contact",
    "access_log",
    "access_log_file",
    "access_log_format",
    "error_log_file",
    "bot_detection",
    "bot_config",
    "bot_busy_threshold",
    "modsecurity_rules",
    "rate_limit",
    "rate_limit_burst",
    "trusted_proxy",
    "swarm_redis",
    "https_redirect",
    "debug",
];

impl Default for CoreAnswers {
    fn default() -> Self {
        Self {
            names: "example.com".to_owned(),
            site_kind: if HOSTING_ENABLED {
                SiteKind::Static
            } else {
                SiteKind::Proxy
            },
            root: "/var/www/html".to_owned(),
            user: current_account_name().unwrap_or_default(),
            group: String::new(),
            php_program: "/usr/bin/php-cgi".to_owned(),
            upstream: "http://127.0.0.1:3000".to_owned(),
        }
    }
}

impl<R: BufRead, W: Write> Wizard<R, W> {
    fn new(input: R, output: W, config_dir: &Path, server_options_mode: bool) -> Self {
        Self {
            input,
            output,
            config_dir: config_dir.to_path_buf(),
            server_options_mode,
            global_options: server_options_mode.then(|| Value::Mapping(Mapping::new())),
        }
    }

    fn run(&mut self) -> Result<String, Box<dyn Error>> {
        if site_choices().is_empty() && !self.server_options_mode {
            return Err("this build has neither hosting nor proxy support".into());
        }
        if self.server_options_mode {
            self.server_options_questions()?;
            if !site_choices().is_empty()
                && self.choice("Also configure a virtual host?", &["No", "Yes"], 0)? == 1
            {
                let (host, has_waf) = self.vhost_questions()?;
                let yaml = serialize_main_config(self.global_options.as_ref(), Some(&host))?;
                self.validate(&host, has_waf).map_err(|errors| {
                    format!(
                        "refusing to write invalid configuration: {}",
                        errors.join("; ")
                    )
                })?;
                return Ok(yaml);
            }
            let yaml = serialize_main_config(self.global_options.as_ref(), None)?;
            validate_main_config_yaml(&yaml, &self.config_dir).map_err(|errors| {
                format!(
                    "refusing to write invalid configuration: {}",
                    errors.join("; ")
                )
            })?;
            return Ok(yaml);
        }
        let (host, has_waf) = self.vhost_questions()?;
        let yaml = serialize_vhost(&host)?;
        self.validate(&host, has_waf).map_err(|errors| {
            format!(
                "refusing to write invalid configuration: {}",
                errors.join("; ")
            )
        })?;
        Ok(yaml)
    }

    fn vhost_questions(&mut self) -> Result<(Value, bool), Box<dyn Error>> {
        let mut defaults = CoreAnswers::default();
        let (mut host, mut has_waf) = loop {
            let (candidate, candidate_waf) = self.core_questions(&mut defaults)?;
            match self.validate(&candidate, candidate_waf) {
                Ok(()) => break (candidate, candidate_waf),
                Err(errors) => {
                    writeln!(self.output, "That setup is not valid:")?;
                    for error in errors {
                        writeln!(self.output, "  - {error}")?;
                    }
                    writeln!(
                        self.output,
                        "Please review the site details and try again.\n"
                    )?;
                }
            }
        };

        if matches!(
            defaults.site_kind,
            SiteKind::Static | SiteKind::PhpApp | SiteKind::ExternalFastCgi
        ) {
            self.hosted_options(&mut host, has_waf)?;
        }
        match defaults.site_kind {
            SiteKind::PhpApp => self.php_options(&mut host, has_waf)?,
            SiteKind::ExternalFastCgi => self.external_fastcgi_options(&mut host, has_waf)?,
            SiteKind::Proxy => self.proxy_options(&mut host, has_waf)?,
            SiteKind::Static => {}
        }
        has_waf = self.global_waf_enabled().unwrap_or(has_waf);
        has_waf = self.shared_options(&mut host, has_waf)?;
        self.advanced_options(&mut host, has_waf, defaults.site_kind)?;
        Ok((host, has_waf))
    }

    fn server_options_questions(&mut self) -> Result<(), Box<dyn Error>> {
        let mut options = self
            .global_options
            .as_ref()
            .and_then(Value::as_mapping)
            .cloned()
            .unwrap_or_default();
        writeln!(
            self.output,
            "Configure server-wide defaults. Leave optional values blank to keep the default."
        )?;

        self.ask_optional_global_value(
            &mut options,
            "bind",
            "Plain HTTP listen address",
            Some("127.0.0.1:8080"),
        )?;
        let no_plain_http =
            self.choice("Plain HTTP listener", &["Keep enabled", "Disable"], 0)? == 1;
        self.apply_global_value(&mut options, "no_plain_http", Value::Bool(no_plain_http))?;
        self.ask_optional_global_value(&mut options, "tls_bind", "TLS listen address", Some(""))?;
        if server_option_exists("http3_bind") {
            self.ask_optional_global_value(
                &mut options,
                "http3_bind",
                "HTTP/3 listen address",
                Some(""),
            )?;
        }

        self.ask_optional_global_value(&mut options, "user", "Master user", Some(""))?;
        if options.contains_key(Value::String("user".to_owned())) {
            self.ask_optional_global_value(&mut options, "group", "Master group", Some(""))?;
        }
        self.ask_optional_global_value(
            &mut options,
            "vhost_dir",
            "Directory of virtual-host YAML files",
            Some(""),
        )?;
        self.ask_optional_global_value(
            &mut options,
            "control_socket",
            "Control socket path",
            Some(""),
        )?;

        if server_option_exists("tls_cert") {
            let certificate = self.choice(
                "Fallback TLS certificate",
                &["No fallback certificate", "Set certificate and key"],
                0,
            )?;
            if certificate == 1 {
                let cert = self.ask(
                    "Certificate chain PEM path",
                    Some("/etc/ssl/site/fullchain.pem"),
                )?;
                let key = self.ask("Private key PEM path", Some("/etc/ssl/site/privkey.pem"))?;
                let mut candidate = options.clone();
                candidate.insert(Value::String("tls_cert".to_owned()), Value::String(cert));
                candidate.insert(Value::String("tls_key".to_owned()), Value::String(key));
                self.accept_global_candidate(&mut options, candidate)?;
            }
        }

        if ACME_ENABLED {
            let acme = self.choice(
                "ACME certificate provisioning",
                &[
                    "Disabled",
                    "Let's Encrypt production",
                    "Let's Encrypt staging",
                    "Custom directory URL",
                ],
                0,
            )?;
            if acme != 0 {
                let directory = match acme {
                    1 => "letsencrypt".to_owned(),
                    2 => "letsencrypt-staging".to_owned(),
                    _ => self.ask("ACME directory URL", None)?,
                };
                let cache = self.ask("ACME cache directory", Some("/var/lib/charlotte/acme"))?;
                let contacts = self.ask_lines("ACME contact URIs (optional)")?;
                let mut candidate = options.clone();
                candidate.insert(
                    Value::String("acme_directory".to_owned()),
                    Value::String(directory),
                );
                candidate.insert(Value::String("acme_cache".to_owned()), Value::String(cache));
                if contacts.is_empty() {
                    candidate.remove(Value::String("acme_contact".to_owned()));
                } else {
                    candidate.insert(
                        Value::String("acme_contact".to_owned()),
                        Value::Sequence(strings_to_values(contacts)),
                    );
                }
                self.accept_global_candidate(&mut options, candidate)?;
            }
        }

        let access_log = self.choice(
            "Server-wide access log",
            &["Disabled", "Write to stdout", "Write to file"],
            0,
        )?;
        match access_log {
            1 => {
                self.apply_global_value(&mut options, "access_log", Value::Bool(true))?;
                options.remove(Value::String("access_log_file".to_owned()));
            }
            2 => {
                self.ask_optional_global_value(
                    &mut options,
                    "access_log_file",
                    "Access log file path",
                    Some("/var/log/charlotte/access.log"),
                )?;
            }
            _ => {
                options.remove(Value::String("access_log".to_owned()));
                options.remove(Value::String("access_log_file".to_owned()));
            }
        }
        if access_log != 0 {
            self.ask_optional_global_value(
                &mut options,
                "access_log_format",
                "Access log format (blank uses the default)",
                Some(""),
            )?;
        }
        let error_log =
            self.choice("Server-wide error log", &["Use stderr", "Write to file"], 0)?;
        if error_log == 1 {
            self.ask_optional_global_value(
                &mut options,
                "error_log_file",
                "Error log file path",
                Some("/var/log/charlotte/error.log"),
            )?;
        } else {
            options.remove(Value::String("error_log_file".to_owned()));
        }

        if server_option_exists("bot_detection") {
            let bot = self.choice(
                "Server-wide bot protection",
                &["Disabled", "Built-in policy", "Policy file"],
                0,
            )?;
            match bot {
                1 => {
                    self.apply_global_value(&mut options, "bot_detection", Value::Bool(true))?;
                    options.remove(Value::String("bot_config".to_owned()));
                }
                2 => {
                    let path = self.ask("Bot policy YAML file", None)?;
                    let mut candidate = options.clone();
                    candidate.remove(Value::String("bot_detection".to_owned()));
                    candidate.insert(Value::String("bot_config".to_owned()), Value::String(path));
                    self.accept_global_candidate(&mut options, candidate)?;
                }
                _ => {
                    options.remove(Value::String("bot_detection".to_owned()));
                    options.remove(Value::String("bot_config".to_owned()));
                }
            }
            if bot != 0 {
                self.ask_optional_global_value(
                    &mut options,
                    "bot_busy_threshold",
                    "Busy traffic threshold (for example 100/s; blank disables the gate)",
                    Some(""),
                )?;
            }
        }

        self.ask_global_list(&mut options, "modsecurity_rules", "ModSecurity rule files")?;
        let rate_limit = self.choice(
            "Server-wide per-client rate limit",
            &["Disabled", "Set a rate limit"],
            0,
        )?;
        if rate_limit == 1 {
            loop {
                let rate = self.ask("Rate (for example 20/s, 600/m, or 36000/h)", Some("20/s"))?;
                let burst = self.ask("Maximum burst (blank uses the default)", Some(""))?;
                let mut candidate = options.clone();
                candidate.insert(Value::String("rate_limit".to_owned()), Value::String(rate));
                if burst.is_empty() {
                    candidate.remove(Value::String("rate_limit_burst".to_owned()));
                } else {
                    candidate.insert(
                        Value::String("rate_limit_burst".to_owned()),
                        Value::String(burst),
                    );
                }
                if self.accept_global_candidate(&mut options, candidate)? {
                    break;
                }
            }
        }
        self.ask_global_list(
            &mut options,
            "trusted_proxy",
            "Trusted proxy addresses or CIDRs",
        )?;
        if SWARM_ENABLED {
            self.ask_optional_global_value(
                &mut options,
                "swarm_redis",
                "Swarm Redis URL (blank disables swarm checks)",
                Some(""),
            )?;
        }
        self.ask_global_flag(
            &mut options,
            "https_redirect",
            "Redirect certified vhosts to HTTPS?",
        )?;
        self.ask_global_flag(&mut options, "debug", "Enable verbose startup debugging?")?;

        loop {
            let remaining = generic_server_options();
            if remaining.is_empty() {
                break;
            }
            let mut labels = vec!["Done".to_owned()];
            labels.extend(remaining.iter().map(|option| {
                if option.help.is_empty() {
                    format!("--{}", option.name.replace('_', "-"))
                } else {
                    format!("--{} — {}", option.name.replace('_', "-"), option.help)
                }
            }));
            let label_refs = labels.iter().map(String::as_str).collect::<Vec<_>>();
            let choice = self.choice("Set another server option?", &label_refs, 0)?;
            if choice == 0 {
                break;
            }
            self.configure_generic_option(&mut options, &remaining[choice - 1])?;
        }
        self.global_options = Some(Value::Mapping(options));
        Ok(())
    }

    fn ask_optional_global_value(
        &mut self,
        options: &mut Mapping,
        key: &str,
        question: &str,
        default: Option<&str>,
    ) -> Result<(), Box<dyn Error>> {
        loop {
            let value = self.ask(question, default)?;
            let mut candidate = options.clone();
            if value.is_empty() {
                candidate.remove(Value::String(key.to_owned()));
            } else {
                candidate.insert(Value::String(key.to_owned()), Value::String(value));
            }
            if self.accept_global_candidate(options, candidate)? {
                return Ok(());
            }
        }
    }

    fn ask_global_list(
        &mut self,
        options: &mut Mapping,
        key: &str,
        question: &str,
    ) -> Result<(), Box<dyn Error>> {
        loop {
            let values = self.ask_lines(question)?;
            let mut candidate = options.clone();
            if values.is_empty() {
                candidate.remove(Value::String(key.to_owned()));
            } else {
                candidate.insert(
                    Value::String(key.to_owned()),
                    Value::Sequence(strings_to_values(values)),
                );
            }
            if self.accept_global_candidate(options, candidate)? {
                return Ok(());
            }
        }
    }

    fn ask_global_flag(
        &mut self,
        options: &mut Mapping,
        key: &str,
        question: &str,
    ) -> Result<(), Box<dyn Error>> {
        let enabled = self.choice(question, &["No", "Yes"], 0)? == 1;
        self.apply_global_value(options, key, Value::Bool(enabled))?;
        Ok(())
    }

    fn apply_global_value(
        &mut self,
        options: &mut Mapping,
        key: &str,
        value: Value,
    ) -> Result<bool, Box<dyn Error>> {
        let mut candidate = options.clone();
        candidate.insert(Value::String(key.to_owned()), value);
        self.accept_global_candidate(options, candidate)
    }

    fn accept_global_candidate(
        &mut self,
        options: &mut Mapping,
        candidate: Mapping,
    ) -> Result<bool, Box<dyn Error>> {
        let yaml = serialize_main_config(Some(&Value::Mapping(candidate.clone())), None)?;
        match validate_main_config_yaml(&yaml, &self.config_dir) {
            Ok(()) => {
                *options = candidate;
                Ok(true)
            }
            Err(errors) => {
                for error in errors {
                    writeln!(self.output, "Not applied: {error}")?;
                }
                Ok(false)
            }
        }
    }

    fn configure_generic_option(
        &mut self,
        options: &mut Mapping,
        option: &OptionInfo,
    ) -> Result<(), Box<dyn Error>> {
        let key = option.name.as_str();
        match option.kind {
            OptionKind::Flag => {
                let question = format!("{} (--{})", option.help, key.replace('_', "-"));
                let selection = self.choice(&question, &["Unset", "Yes", "No"], 0)?;
                let mut candidate = options.clone();
                match selection {
                    0 => {
                        candidate.remove(Value::String(key.to_owned()));
                    }
                    1 => {
                        candidate.insert(Value::String(key.to_owned()), Value::Bool(true));
                    }
                    _ => {
                        candidate.insert(Value::String(key.to_owned()), Value::Bool(false));
                    }
                }
                self.accept_global_candidate(options, candidate)?;
            }
            _ if key == "fastcgi_app_mode" => loop {
                let extension = self.ask("FastCGI app extension", None)?;
                let mode =
                    self.choice("Managed app mode", &["CGI workers", "PHP-FPM process"], 0)?;
                let value = format!("{extension}={}", if mode == 0 { "cgi" } else { "fpm" });
                if self.append_global_value(options, key, value)? {
                    break;
                }
            },
            _ if key == "fastcgi_app_php_defaults" => loop {
                let extension = self.ask("FastCGI app extension", None)?;
                let enabled = self.choice("Enable PHP performance defaults?", &["No", "Yes"], 1)?;
                let value = format!("{extension}={}", if enabled == 0 { "off" } else { "on" });
                if self.append_global_value(options, key, value)? {
                    break;
                }
            },
            OptionKind::Value => {
                let label = option.value_name.as_deref().unwrap_or("VALUE");
                let default = option
                    .default
                    .as_deref()
                    .map_or_else(String::new, |value| format!("; default {value}"));
                let question = format!(
                    "{} (--{} {label}{default}; blank removes this setting)",
                    option.help,
                    key.replace('_', "-")
                );
                loop {
                    let value = self.ask(&question, Some(""))?;
                    let mut candidate = options.clone();
                    if value.is_empty() {
                        candidate.remove(Value::String(key.to_owned()));
                    } else {
                        candidate.insert(Value::String(key.to_owned()), Value::String(value));
                    }
                    if self.accept_global_candidate(options, candidate)? {
                        break;
                    }
                }
            }
            OptionKind::List => {
                let default = option
                    .default
                    .as_deref()
                    .map_or_else(String::new, |value| format!("; default {value}"));
                let question = format!(
                    "{} (--{}; one value per line{default})",
                    option.help,
                    key.replace('_', "-")
                );
                self.ask_global_list(options, key, &question)?;
            }
        }
        Ok(())
    }

    fn append_global_value(
        &mut self,
        options: &mut Mapping,
        key: &str,
        value: String,
    ) -> Result<bool, Box<dyn Error>> {
        let mut candidate = options.clone();
        let mut values = options
            .get(Value::String(key.to_owned()))
            .and_then(Value::as_sequence)
            .cloned()
            .unwrap_or_default();
        values.push(Value::String(value));
        candidate.insert(Value::String(key.to_owned()), Value::Sequence(values));
        self.accept_global_candidate(options, candidate)
    }

    fn global_waf_enabled(&self) -> Option<bool> {
        self.global_options
            .as_ref()?
            .as_mapping()
            .map(|options| options.contains_key(Value::String("modsecurity_rules".to_owned())))
    }

    fn core_questions(&mut self, defaults: &mut CoreAnswers) -> io::Result<(Value, bool)> {
        defaults.names = self.ask("Server names (comma-separated)", Some(&defaults.names))?;
        let site_choices = site_choices();
        let default_site = site_choices
            .iter()
            .position(|(kind, _)| *kind == defaults.site_kind)
            .unwrap_or(0);
        let selected = self.choice(
            "What kind of site are you configuring?",
            &site_choices
                .iter()
                .map(|(_, label)| *label)
                .collect::<Vec<_>>(),
            default_site,
        )?;
        defaults.site_kind = site_choices[selected].0;

        let mut host = Mapping::new();
        let names = defaults
            .names
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| Value::String(name.to_owned()))
            .collect::<Vec<_>>();
        host.insert(
            Value::String("server_names".to_owned()),
            Value::Sequence(names),
        );

        match defaults.site_kind {
            SiteKind::Static | SiteKind::PhpApp | SiteKind::ExternalFastCgi => {
                defaults.root = self.ask("Document root directory", Some(&defaults.root))?;
                defaults.user = self.ask("Worker user", Some(&defaults.user))?;
                defaults.group = self.ask(
                    "Worker group (blank uses the user's primary group)",
                    Some(&defaults.group),
                )?;
                insert_mapping_string(&mut host, "root", &defaults.root);
                insert_mapping_string(&mut host, "user", &defaults.user);
                if !defaults.group.trim().is_empty() {
                    insert_mapping_string(&mut host, "group", &defaults.group);
                }
                match defaults.site_kind {
                    SiteKind::PhpApp => {
                        defaults.php_program =
                            self.ask("PHP CGI/FPM executable path", Some(&defaults.php_program))?;
                        let mut app = Mapping::new();
                        app.insert(
                            Value::String("extension".to_owned()),
                            Value::String("php".to_owned()),
                        );
                        app.insert(
                            Value::String("command".to_owned()),
                            Value::Sequence(vec![Value::String(defaults.php_program.clone())]),
                        );
                        host.insert(
                            Value::String("fastcgi_app".to_owned()),
                            Value::Sequence(vec![Value::Mapping(app)]),
                        );
                    }
                    SiteKind::ExternalFastCgi => {
                        let address_kind = self.choice(
                            "How does the PHP-FPM backend listen?",
                            &["TCP host:port", "Unix socket"],
                            0,
                        )?;
                        let address = if address_kind == 0 {
                            self.ask("FastCGI host:port", Some("127.0.0.1:9000"))?
                        } else {
                            self.ask("FastCGI Unix socket path", Some("/run/php/php-fpm.sock"))?
                        };
                        insert_sequence(
                            &mut host,
                            "fastcgi",
                            vec![Value::String(if address_kind == 0 {
                                format!("php={address}")
                            } else {
                                format!("php=unix:{address}")
                            })],
                        );
                    }
                    SiteKind::Static | SiteKind::Proxy => {}
                }
            }
            SiteKind::Proxy => {
                defaults.upstream = self.ask("Upstream URL", Some(&defaults.upstream))?;
                insert_mapping_string(&mut host, "proxy_pass", &defaults.upstream);
            }
        }
        Ok((Value::Mapping(host), false))
    }

    fn hosted_options(&mut self, host: &mut Value, has_waf: bool) -> Result<(), Box<dyn Error>> {
        loop {
            let indexes = self.ask(
                "Directory index names, comma-separated (blank inherits; a value replaces the global list)",
                Some(""),
            )?;
            if indexes.trim().is_empty() {
                break;
            }
            let mut candidate = host.clone();
            insert_sequence_value(
                &mut candidate,
                "index",
                indexes
                    .split(',')
                    .map(str::trim)
                    .map(|name| Value::String(name.to_owned()))
                    .collect(),
            );
            if self.accept_candidate(host, candidate, has_waf)? {
                break;
            }
            writeln!(self.output, "Enter valid file names separated by commas.")?;
        }

        let listing = self.choice(
            "Directory listings",
            &["Inherit global setting", "Enable", "Disable"],
            0,
        )?;
        if listing != 0 {
            let mut candidate = host.clone();
            insert_bool(&mut candidate, "listing", listing == 1);
            self.accept_candidate(host, candidate, has_waf)?;
        }
        let try_files = self.choice(
            "Fallback for missing files",
            &[
                "Inherit global setting",
                "Return 404",
                "Serve index.html",
                "Custom list",
            ],
            0,
        )?;
        if try_files != 0 {
            if try_files == 3 {
                self.optional_value(
                    host,
                    "Custom try_files entries, comma-separated",
                    has_waf,
                    |input| {
                        let entries = input
                            .split(',')
                            .map(str::trim)
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned)
                            .collect::<Vec<_>>();
                        if entries.is_empty() {
                            return Err("enter at least one try_files value".to_owned());
                        }
                        serde_yaml_ng::to_value(entries).map_err(|error| error.to_string())
                    },
                    |candidate, value| {
                        insert_value(candidate, "try_files", value);
                        Ok(())
                    },
                )?;
            } else {
                let entries = if try_files == 1 {
                    vec!["$uri".to_owned(), "=404".to_owned()]
                } else {
                    vec!["$uri".to_owned(), "/index.html".to_owned()]
                };
                let mut candidate = host.clone();
                insert_sequence_value(&mut candidate, "try_files", strings_to_values(entries));
                self.accept_candidate(host, candidate, has_waf)?;
            }
        }
        loop {
            let timeout = self.ask(
                "Worker idle timeout in seconds (blank uses global default)",
                Some(""),
            )?;
            if timeout.trim().is_empty() {
                break;
            }
            let Ok(seconds) = timeout.trim().parse::<u64>() else {
                writeln!(self.output, "Enter a non-negative number of seconds.")?;
                continue;
            };
            let mut candidate = host.clone();
            insert_serialized(&mut candidate, "worker_idle_timeout", seconds)?;
            if self.accept_candidate(host, candidate, has_waf)? {
                break;
            }
        }
        Ok(())
    }

    fn php_options(&mut self, host: &mut Value, has_waf: bool) -> Result<(), Box<dyn Error>> {
        self.app_details(host, 0, has_waf)?;
        Ok(())
    }

    fn app_details(
        &mut self,
        host: &mut Value,
        app_index: usize,
        has_waf: bool,
    ) -> Result<(), Box<dyn Error>> {
        let mode = self.choice("Managed PHP mode", &["CGI workers", "PHP-FPM process"], 0)?;
        let mut candidate = host.clone();
        if let Some(app) = app_mut(&mut candidate, app_index) {
            insert_string_value(app, "mode", if mode == 1 { "fpm" } else { "cgi" });
        }
        self.accept_candidate(host, candidate, has_waf)?;

        for (question, key, min, max) in [
            (
                "Maximum app workers (1-256; blank uses the default)",
                "max_workers",
                1,
                256,
            ),
            (
                "Minimum warm app workers (blank uses the default)",
                "min_workers",
                0,
                256,
            ),
            (
                "App idle timeout in seconds (blank uses the default)",
                "idle_timeout",
                1,
                86_400,
            ),
        ] {
            self.optional_value(
                host,
                question,
                has_waf,
                move |input| {
                    let value = input
                        .parse::<usize>()
                        .map_err(|_| format!("enter a whole number from {min} to {max}"))?;
                    if !(min..=max).contains(&value) {
                        return Err(format!("enter a whole number from {min} to {max}"));
                    }
                    serde_yaml_ng::to_value(value).map_err(|error| error.to_string())
                },
                move |candidate, value| {
                    let app = app_mut(candidate, app_index)
                        .ok_or_else(|| "managed app entry is missing".to_owned())?;
                    app.insert(Value::String(key.to_owned()), value);
                    Ok(())
                },
            )?;
        }

        let php_defaults = self.choice(
            "PHP performance defaults",
            &["Inherit default", "Enable", "Disable"],
            0,
        )?;
        if php_defaults != 0 {
            let mut candidate = host.clone();
            if let Some(app) = app_mut(&mut candidate, app_index) {
                app.insert(
                    Value::String("php_defaults".to_owned()),
                    Value::Bool(php_defaults == 1),
                );
            }
            self.accept_candidate(host, candidate, has_waf)?;
        }

        loop {
            let args =
                self.ask_lines("Additional command arguments (one per line; blank to finish)")?;
            if args.is_empty() {
                break;
            }
            let mut candidate = host.clone();
            if let Some(app) = app_mut(&mut candidate, app_index) {
                let command = app
                    .get_mut(Value::String("command".to_owned()))
                    .and_then(Value::as_sequence_mut)
                    .ok_or("managed app command is missing")?;
                command.extend(strings_to_values(args));
            }
            if self.accept_candidate(host, candidate, has_waf)? {
                break;
            }
        }

        loop {
            let env = self
                .ask_lines("App environment KEY=VALUE entries (one per line; blank to finish)")?;
            if env.is_empty() {
                break;
            }
            let mut values = Mapping::new();
            let mut parse_error = None;
            for entry in &env {
                let Some((key, value)) = entry.split_once('=') else {
                    parse_error = Some(format!("environment entry must be KEY=VALUE: {entry}"));
                    break;
                };
                if key.is_empty() || key.contains('\0') || value.contains('\0') {
                    parse_error = Some(
                        "environment keys and values must be non-empty and contain no NUL"
                            .to_owned(),
                    );
                    break;
                }
                values.insert(
                    Value::String(key.to_owned()),
                    Value::String(value.to_owned()),
                );
            }
            if let Some(error) = parse_error {
                writeln!(self.output, "{error}")?;
                continue;
            }
            let mut candidate = host.clone();
            if let Some(app) = app_mut(&mut candidate, app_index) {
                let current = app
                    .entry(Value::String("env".to_owned()))
                    .or_insert_with(|| Value::Mapping(Mapping::new()));
                let Value::Mapping(current) = current else {
                    return Err("managed app environment must be a mapping".into());
                };
                current.extend(values);
            }
            if self.accept_candidate(host, candidate, has_waf)? {
                break;
            }
        }

        self.optional_value(
            host,
            "FastCGI timeout in seconds (blank uses 60)",
            has_waf,
            |input| {
                let timeout = input
                    .parse::<u64>()
                    .map_err(|_| "enter a positive number of seconds".to_owned())?;
                if timeout == 0 {
                    return Err("enter a positive number of seconds".to_owned());
                }
                serde_yaml_ng::to_value(timeout).map_err(|error| error.to_string())
            },
            |candidate, value| {
                insert_value(candidate, "fastcgi_timeout", value);
                Ok(())
            },
        )?;
        Ok(())
    }

    fn external_fastcgi_options(
        &mut self,
        host: &mut Value,
        has_waf: bool,
    ) -> Result<(), Box<dyn Error>> {
        loop {
            let timeout = self.ask("FastCGI timeout in seconds (blank uses 60)", Some(""))?;
            if timeout.trim().is_empty() {
                break;
            }
            let Ok(seconds) = timeout.trim().parse::<u64>() else {
                writeln!(self.output, "Enter a positive number of seconds.")?;
                continue;
            };
            let mut candidate = host.clone();
            insert_serialized(&mut candidate, "fastcgi_timeout", seconds)?;
            if self.accept_candidate(host, candidate, has_waf)? {
                break;
            }
        }
        Ok(())
    }

    fn proxy_options(&mut self, host: &mut Value, has_waf: bool) -> Result<(), Box<dyn Error>> {
        for (question, key) in [
            ("Preserve the incoming Host header?", "proxy_preserve_host"),
            (
                "Use HTTP/2 to the upstream (h2c for http:// URLs)?",
                "proxy_http2",
            ),
        ] {
            let choice = self.choice(question, &["Inherit default", "Yes", "No"], 0)?;
            if choice != 0 {
                let mut candidate = host.clone();
                insert_bool(&mut candidate, key, choice == 1);
                self.accept_candidate(host, candidate, has_waf)?;
            }
        }
        loop {
            let timeout = self.ask("Upstream timeout in seconds (blank uses 60)", Some(""))?;
            if timeout.trim().is_empty() {
                break;
            }
            let Ok(seconds) = timeout.trim().parse::<u64>() else {
                writeln!(self.output, "Enter a positive number of seconds.")?;
                continue;
            };
            let mut candidate = host.clone();
            insert_serialized(&mut candidate, "proxy_timeout", seconds)?;
            if self.accept_candidate(host, candidate, has_waf)? {
                break;
            }
        }
        Ok(())
    }

    fn advanced_options(
        &mut self,
        host: &mut Value,
        has_waf: bool,
        site_kind: SiteKind,
    ) -> Result<(), Box<dyn Error>> {
        if self.choice("Configure advanced settings?", &["No", "Yes"], 0)? == 0 {
            return Ok(());
        }

        if HOSTING_ENABLED && site_kind != SiteKind::Proxy {
            self.optional_value(
                host,
                "Worker thread count (blank uses the default)",
                has_waf,
                |input| {
                    let value = input
                        .parse::<usize>()
                        .map_err(|_| "enter a positive whole number".to_owned())?;
                    if value == 0 {
                        return Err("enter a positive whole number".to_owned());
                    }
                    serde_yaml_ng::to_value(value).map_err(|error| error.to_string())
                },
                |candidate, value| {
                    insert_value(candidate, "worker_threads", value);
                    Ok(())
                },
            )?;
            self.optional_list(
                host,
                "CGI backends (one EXT or EXT=INTERPRETER per line)",
                "cgi",
                has_waf,
            )?;
            self.optional_list(
                host,
                "Additional FastCGI backends (one EXT=ADDR per line)",
                "fastcgi",
                has_waf,
            )?;
            self.additional_apps(host, has_waf)?;

            for key in [
                "cgroup",
                "cgroup_memory_max",
                "cgroup_cpu_max",
                "cgroup_pids_max",
            ] {
                self.optional_value(
                    host,
                    &format!("{key} (blank leaves it unchanged)"),
                    has_waf,
                    |input| Ok(Value::String(input.to_owned())),
                    move |candidate, value| {
                        insert_value(candidate, key, value);
                        Ok(())
                    },
                )?;
            }
        }

        if PROXY_ENABLED && site_kind == SiteKind::Proxy {
            self.optional_value(
                host,
                "HTTPS upstream CA bundle path (blank uses system roots)",
                has_waf,
                |input| Ok(Value::String(input.to_owned())),
                |candidate, value| {
                    insert_value(candidate, "proxy_ca_root", value);
                    Ok(())
                },
            )?;
        }

        if SWARM_ENABLED {
            let swarm = self.choice(
                "Swarm access checks",
                &["Inherit global setting", "Enable", "Disable"],
                0,
            )?;
            if swarm != 0 {
                let mut candidate = host.clone();
                insert_bool(&mut candidate, "swarm", swarm == 1);
                self.accept_candidate(host, candidate, has_waf)?;
            }
        }

        for (question, key) in [
            (
                "Access log format (blank inherits the global format)",
                "access_log_format",
            ),
            (
                "Error log format (blank inherits the global format)",
                "error_log_format",
            ),
        ] {
            self.optional_value(
                host,
                question,
                has_waf,
                |input| Ok(Value::String(input.to_owned())),
                move |candidate, value| {
                    insert_value(candidate, key, value);
                    Ok(())
                },
            )?;
        }

        if has_waf {
            self.optional_list(
                host,
                "ModSecurity rule IDs or ranges to disable (one per line)",
                "modsecurity_disable_rules",
                has_waf,
            )?;
        }
        self.advanced_bot_options(host, has_waf)?;
        Ok(())
    }

    fn additional_apps(&mut self, host: &mut Value, has_waf: bool) -> Result<(), Box<dyn Error>> {
        loop {
            if self.choice("Add another managed FastCGI app?", &["No", "Yes"], 0)? == 0 {
                return Ok(());
            }
            let extension = self.ask("App extension (for example py)", None)?;
            let command = self.ask("App executable path", None)?;
            let mut app = Mapping::new();
            insert_string_value(&mut app, "extension", &extension);
            insert_sequence(&mut app, "command", vec![Value::String(command)]);
            let mut candidate = host.clone();
            if let Some(apps) = mapping_sequence_mut(&mut candidate, "fastcgi_app") {
                apps.push(Value::Mapping(app));
            }
            if self.accept_candidate(host, candidate, has_waf)? {
                let app_index = host
                    .as_mapping()
                    .and_then(|mapping| mapping.get(Value::String("fastcgi_app".to_owned())))
                    .and_then(Value::as_sequence)
                    .map_or(0, |apps| apps.len() - 1);
                self.app_details(host, app_index, has_waf)?;
            }
        }
    }

    fn advanced_bot_options(
        &mut self,
        host: &mut Value,
        has_waf: bool,
    ) -> Result<(), Box<dyn Error>> {
        let is_policy = host
            .as_mapping()
            .and_then(|mapping| mapping.get(Value::String("bot".to_owned())))
            .is_some_and(Value::is_mapping);
        if !is_policy {
            return Ok(());
        }

        for (question, key, min, max) in [
            (
                "Bot challenge threshold (0-100)",
                "challenge_threshold",
                0,
                100,
            ),
            ("Bot block threshold (0-100)", "block_threshold", 0, 100),
            ("Challenge difficulty (0-30)", "challenge_difficulty", 0, 30),
            (
                "Challenge lifetime in seconds",
                "challenge_ttl",
                1,
                u64::MAX,
            ),
            (
                "Honeypot ban duration in seconds",
                "honeypot_ban",
                1,
                u64::MAX,
            ),
            (
                "Busy request window in seconds (1-60)",
                "busy_window",
                1,
                60,
            ),
            (
                "Busy protection cooldown in seconds",
                "busy_cooldown",
                1,
                86_400,
            ),
        ] {
            self.optional_bot_value(host, question, key, has_waf, move |input| {
                let value = input
                    .parse::<u64>()
                    .map_err(|_| format!("enter a whole number from {min} to {max}"))?;
                if !(min..=max).contains(&value) {
                    return Err(format!("enter a whole number from {min} to {max}"));
                }
                serde_yaml_ng::to_value(value).map_err(|error| error.to_string())
            })?;
        }

        for (question, key) in [(
            "Bot busy traffic threshold (for example 100/s; blank disables the gate)",
            "busy_threshold",
        )] {
            self.optional_bot_value(host, question, key, has_waf, |input| {
                Ok(Value::String(input.to_owned()))
            })?;
        }

        for (question, key) in [
            (
                "Allowlisted client IPs or CIDRs (one per line)",
                "allow_ips",
            ),
            ("Denied client IPs or CIDRs (one per line)", "deny_ips"),
            (
                "Allowed user-agent patterns (one per line)",
                "allow_user_agents",
            ),
            (
                "Denied user-agent patterns (one per line)",
                "deny_user_agents",
            ),
            ("Honeypot paths (one per line)", "honeypot_paths"),
            ("Exempt paths (one per line)", "exempt_paths"),
            ("Allowed JA4 fingerprints (one per line)", "ja4_allow"),
            ("Denied JA4 fingerprints (one per line)", "ja4_deny"),
        ] {
            self.optional_bot_list(host, question, key, has_waf)?;
        }

        for (question, key) in [
            ("Challenge suspicious clients?", "challenge"),
            ("Use built-in bot rules?", "builtin_rules"),
            ("Verify claimed search crawlers?", "verify_crawlers"),
        ] {
            let value = self.choice(question, &["Inherit", "Yes", "No"], 0)?;
            if value != 0 {
                let mut candidate = host.clone();
                if let Some(bot) = bot_mapping_mut(&mut candidate) {
                    bot.insert(Value::String(key.to_owned()), Value::Bool(value == 1));
                }
                self.accept_candidate(host, candidate, has_waf)?;
            }
        }
        Ok(())
    }

    fn optional_bot_list(
        &mut self,
        host: &mut Value,
        question: &str,
        key: &str,
        has_waf: bool,
    ) -> Result<(), Box<dyn Error>> {
        loop {
            let values = self.ask_lines(question)?;
            if values.is_empty() {
                return Ok(());
            }
            let mut candidate = host.clone();
            if let Some(bot) = bot_mapping_mut(&mut candidate) {
                bot.insert(
                    Value::String(key.to_owned()),
                    Value::Sequence(strings_to_values(values)),
                );
            }
            if self.accept_candidate(host, candidate, has_waf)? {
                return Ok(());
            }
            writeln!(
                self.output,
                "Those values were not accepted; try the list again."
            )?;
        }
    }

    fn optional_bot_value<P>(
        &mut self,
        host: &mut Value,
        question: &str,
        key: &str,
        has_waf: bool,
        parse: P,
    ) -> Result<(), Box<dyn Error>>
    where
        P: FnMut(&str) -> Result<Value, String>,
    {
        self.optional_value(host, question, has_waf, parse, move |candidate, value| {
            let bot = bot_mapping_mut(candidate)
                .ok_or_else(|| "bot policy is no longer a mapping".to_owned())?;
            bot.insert(Value::String(key.to_owned()), value);
            Ok(())
        })
    }

    fn optional_list(
        &mut self,
        host: &mut Value,
        question: &str,
        key: &str,
        has_waf: bool,
    ) -> Result<(), Box<dyn Error>> {
        loop {
            let values = self.ask_lines(question)?;
            if values.is_empty() {
                return Ok(());
            }
            let mut candidate = host.clone();
            if let Some(mapping) = candidate.as_mapping_mut() {
                let mut combined = mapping
                    .get(Value::String(key.to_owned()))
                    .and_then(Value::as_sequence)
                    .cloned()
                    .unwrap_or_default();
                combined.extend(strings_to_values(values));
                mapping.insert(Value::String(key.to_owned()), Value::Sequence(combined));
            }
            if self.accept_candidate(host, candidate, has_waf)? {
                return Ok(());
            }
            writeln!(
                self.output,
                "Those values were not accepted; try the list again."
            )?;
        }
    }

    fn optional_value<P, A>(
        &mut self,
        current: &mut Value,
        question: &str,
        has_waf: bool,
        mut parse: P,
        mut apply: A,
    ) -> Result<(), Box<dyn Error>>
    where
        P: FnMut(&str) -> Result<Value, String>,
        A: FnMut(&mut Value, Value) -> Result<(), String>,
    {
        loop {
            let input = self.ask(question, Some(""))?;
            if input.trim().is_empty() {
                return Ok(());
            }
            let value = match parse(input.trim()) {
                Ok(value) => value,
                Err(error) => {
                    writeln!(self.output, "{error}")?;
                    continue;
                }
            };
            let mut candidate = current.clone();
            if let Err(error) = apply(&mut candidate, value) {
                writeln!(self.output, "{error}")?;
                continue;
            }
            if self.accept_candidate(current, candidate, has_waf)? {
                return Ok(());
            }
        }
    }

    fn shared_options(
        &mut self,
        host: &mut Value,
        mut has_waf: bool,
    ) -> Result<bool, Box<dyn Error>> {
        let mut tls_choices = vec!["No TLS certificate".to_owned()];
        if ACME_ENABLED {
            tls_choices.push("Automatic ACME certificate".to_owned());
        }
        tls_choices.push("Certificate and key files".to_owned());
        let tls = self.choice(
            "TLS setup",
            &tls_choices.iter().map(String::as_str).collect::<Vec<_>>(),
            0,
        )?;
        let acme_choice = ACME_ENABLED && tls == 1;
        let cert_choice = tls == tls_choices.len() - 1;
        if acme_choice {
            let mut candidate = host.clone();
            insert_bool(&mut candidate, "acme", true);
            self.accept_candidate(host, candidate, has_waf)?;
        } else if cert_choice {
            let cert = self.ask(
                "TLS certificate chain PEM path",
                Some("/etc/ssl/site/fullchain.pem"),
            )?;
            let key = self.ask(
                "TLS private key PEM path",
                Some("/etc/ssl/site/privkey.pem"),
            )?;
            let mut candidate = host.clone();
            insert_string(&mut candidate, "tls_cert", &cert);
            insert_string(&mut candidate, "tls_key", &key);
            let chain = self.ask("Intermediate chain PEM path (optional)", Some(""))?;
            if !chain.trim().is_empty() {
                insert_string(&mut candidate, "tls_chain", chain.trim());
            }
            self.accept_candidate(host, candidate, has_waf)?;
        }

        let redirect = self.choice(
            "Redirect HTTP to HTTPS",
            &["Inherit global setting", "Enable", "Disable"],
            0,
        )?;
        if redirect != 0 {
            let mut candidate = host.clone();
            insert_bool(&mut candidate, "https_redirect", redirect == 1);
            self.accept_candidate(host, candidate, has_waf)?;
        }
        if self.choice("Make this the default vhost?", &["No", "Yes"], 0)? == 1 {
            let mut candidate = host.clone();
            insert_bool(&mut candidate, "default", true);
            self.accept_candidate(host, candidate, has_waf)?;
        }

        let bot = self.choice(
            "Bot protection",
            &[
                "Inherit global setting",
                "Off",
                "Enforce with challenge",
                "Enforce without challenge",
                "Log only",
            ],
            0,
        )?;
        if bot != 0 {
            let mut candidate = host.clone();
            match bot {
                1 => insert_string(&mut candidate, "bot", "off"),
                2 | 3 | 4 => {
                    let mut policy = Mapping::new();
                    insert_string_value(
                        &mut policy,
                        "mode",
                        if bot == 4 { "log" } else { "enforce" },
                    );
                    if bot == 2 || bot == 3 {
                        insert_bool_value(&mut policy, "challenge", bot == 2);
                    }
                    insert_value(&mut candidate, "bot", Value::Mapping(policy));
                }
                _ => {}
            }
            self.accept_candidate(host, candidate, has_waf)?;
        }

        let rate = self.choice(
            "Per-client rate limit",
            &[
                "Inherit global setting",
                "Disable for this vhost",
                "Set a custom rate",
            ],
            0,
        )?;
        if rate == 1 {
            let mut candidate = host.clone();
            insert_string(&mut candidate, "rate_limit", "off");
            self.accept_candidate(host, candidate, has_waf)?;
        } else if rate == 2 {
            loop {
                let rate = self.ask("Rate (for example 20/s, 600/m, or 36000/h)", Some("20/s"))?;
                let burst = self.ask("Maximum burst", Some("20"))?;
                let Ok(burst) = burst.trim().parse::<u32>() else {
                    writeln!(self.output, "Enter a positive whole-number burst.")?;
                    continue;
                };
                let mut candidate = host.clone();
                insert_string(&mut candidate, "rate_limit", &rate);
                insert_serialized(&mut candidate, "rate_limit_burst", burst)?;
                if self.accept_candidate(host, candidate, has_waf)? {
                    break;
                }
                writeln!(
                    self.output,
                    "That rate or burst is invalid; please try again."
                )?;
            }
        }

        let modsecurity = if self.server_options_mode {
            has_waf
        } else {
            self.choice(
                "Does the main server configuration load ModSecurity rules?",
                &["No", "Yes"],
                usize::from(has_waf),
            )? == 1
        };
        if modsecurity {
            has_waf = true;
            let response = self.choice(
                "ModSecurity response-body inspection",
                &[
                    "Inherit global behavior",
                    "Inspect response bodies",
                    "Stream without body inspection",
                ],
                0,
            )?;
            if response != 0 {
                let mut candidate = host.clone();
                insert_bool(&mut candidate, "modsecurity_response_body", response == 1);
                self.accept_candidate(host, candidate, has_waf)?;
            }
            loop {
                let status = self.ask(
                    "ModSecurity block status (400-599; blank inherits)",
                    Some(""),
                )?;
                if status.trim().is_empty() {
                    break;
                }
                let Ok(status) = status.trim().parse::<u16>() else {
                    writeln!(self.output, "Enter a status code from 400 to 599.")?;
                    continue;
                };
                let mut candidate = host.clone();
                insert_serialized(&mut candidate, "modsecurity_block_status", status)?;
                if self.accept_candidate(host, candidate, has_waf)? {
                    break;
                }
            }
        }

        for (question, key) in [
            (
                "Per-vhost access log path (blank inherits the global setting)",
                "access_log",
            ),
            (
                "Per-vhost error log path (blank inherits the global setting)",
                "error_log",
            ),
        ] {
            let path = self.ask(question, Some(""))?;
            if !path.trim().is_empty() {
                let mut candidate = host.clone();
                insert_string(&mut candidate, key, path.trim());
                self.accept_candidate(host, candidate, has_waf)?;
            }
        }
        Ok(has_waf)
    }

    fn validate(&self, host: &Value, has_waf: bool) -> Result<(), Vec<String>> {
        if self.server_options_mode {
            let yaml = serialize_main_config(self.global_options.as_ref(), Some(host))
                .map_err(|error| vec![error.to_string()])?;
            return validate_main_config_yaml(&yaml, &self.config_dir);
        }
        let yaml = serialize_vhost(host).map_err(|error| vec![error.to_string()])?;
        validate_vhost_yaml(&yaml, &self.config_dir, has_waf)
    }

    fn accept_candidate(
        &mut self,
        current: &mut Value,
        candidate: Value,
        has_waf: bool,
    ) -> Result<bool, Box<dyn Error>> {
        match self.validate(&candidate, has_waf) {
            Ok(()) => {
                *current = candidate;
                Ok(true)
            }
            Err(errors) => {
                for error in errors {
                    writeln!(self.output, "Not applied: {error}")?;
                }
                Ok(false)
            }
        }
    }

    fn ask(&mut self, question: &str, default: Option<&str>) -> io::Result<String> {
        loop {
            match default.filter(|value| !value.is_empty()) {
                Some(default) => write!(self.output, "{question} [{default}]: ")?,
                None => write!(self.output, "{question}: ")?,
            }
            self.output.flush()?;
            let mut input = String::new();
            if self.input.read_line(&mut input)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "input ended before setup was complete",
                ));
            }
            let value = input.trim().to_owned();
            if !value.is_empty() {
                return Ok(value);
            }
            if let Some(default) = default {
                return Ok(default.to_owned());
            }
            writeln!(self.output, "Please enter a value.")?;
        }
    }

    fn ask_lines(&mut self, question: &str) -> io::Result<Vec<String>> {
        writeln!(self.output, "{question}")?;
        writeln!(
            self.output,
            "  Enter one value per line; submit a blank line when finished."
        )?;
        let mut values = Vec::new();
        loop {
            write!(self.output, "> ")?;
            self.output.flush()?;
            let mut input = String::new();
            if self.input.read_line(&mut input)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "input ended before setup was complete",
                ));
            }
            let value = input.trim();
            if value.is_empty() {
                return Ok(values);
            }
            values.push(value.to_owned());
        }
    }

    fn choice(&mut self, question: &str, options: &[&str], default: usize) -> io::Result<usize> {
        loop {
            writeln!(self.output, "{question}")?;
            for (index, option) in options.iter().enumerate() {
                writeln!(self.output, "  {}) {option}", index + 1)?;
            }
            write!(self.output, "Select [{}]: ", default + 1)?;
            self.output.flush()?;
            let mut input = String::new();
            if self.input.read_line(&mut input)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "input ended before setup was complete",
                ));
            }
            let answer = input.trim();
            if answer.is_empty() {
                return Ok(default);
            }
            match answer.parse::<usize>() {
                Ok(choice) if (1..=options.len()).contains(&choice) => return Ok(choice - 1),
                _ => writeln!(self.output, "Choose a number from 1 to {}.", options.len())?,
            }
        }
    }
}

fn site_choices() -> Vec<(SiteKind, &'static str)> {
    let mut choices = Vec::new();
    if HOSTING_ENABLED {
        choices.extend([
            (SiteKind::Static, "Static files"),
            (SiteKind::PhpApp, "Managed PHP application"),
            (SiteKind::ExternalFastCgi, "External FastCGI (php-fpm)"),
        ]);
    }
    if PROXY_ENABLED {
        choices.push((SiteKind::Proxy, "Reverse proxy"));
    }
    choices
}

fn current_account_name() -> Option<String> {
    let user = nix::unistd::User::from_uid(nix::unistd::geteuid())
        .ok()
        .flatten()?;
    if user.uid.as_raw() == 0 {
        nix::unistd::User::from_name("nobody")
            .ok()
            .flatten()
            .map(|user| user.name)
    } else {
        Some(user.name)
    }
}

fn mapping_sequence_mut<'a>(host: &'a mut Value, key: &str) -> Option<&'a mut Vec<Value>> {
    host.as_mapping_mut()?
        .get_mut(Value::String(key.to_owned()))?
        .as_sequence_mut()
}

fn app_mut(host: &mut Value, index: usize) -> Option<&mut Mapping> {
    mapping_sequence_mut(host, "fastcgi_app")?
        .get_mut(index)?
        .as_mapping_mut()
}

fn bot_mapping_mut(host: &mut Value) -> Option<&mut Mapping> {
    host.as_mapping_mut()?
        .get_mut(Value::String("bot".to_owned()))?
        .as_mapping_mut()
}

fn insert_mapping_string(host: &mut Mapping, key: &str, value: &str) {
    host.insert(
        Value::String(key.to_owned()),
        Value::String(value.to_owned()),
    );
}

fn insert_string(host: &mut Value, key: &str, value: &str) {
    insert_value(host, key, Value::String(value.to_owned()));
}

fn insert_bool(host: &mut Value, key: &str, value: bool) {
    insert_value(host, key, Value::Bool(value));
}

fn insert_value(host: &mut Value, key: &str, value: Value) {
    if let Value::Mapping(mapping) = host {
        mapping.insert(Value::String(key.to_owned()), value);
    }
}

fn insert_serialized<T: Serialize>(
    host: &mut Value,
    key: &str,
    value: T,
) -> Result<(), serde_yaml_ng::Error> {
    insert_value(host, key, serde_yaml_ng::to_value(value)?);
    Ok(())
}

fn insert_sequence(host: &mut Mapping, key: &str, values: Vec<Value>) {
    host.insert(Value::String(key.to_owned()), Value::Sequence(values));
}

fn insert_sequence_value(host: &mut Value, key: &str, values: Vec<Value>) {
    insert_value(host, key, Value::Sequence(values));
}

fn insert_string_value(host: &mut Mapping, key: &str, value: &str) {
    host.insert(
        Value::String(key.to_owned()),
        Value::String(value.to_owned()),
    );
}

fn insert_bool_value(host: &mut Mapping, key: &str, value: bool) {
    host.insert(Value::String(key.to_owned()), Value::Bool(value));
}

fn strings_to_values(values: Vec<String>) -> Vec<Value> {
    values.into_iter().map(Value::String).collect()
}

fn serialize_vhost(host: &Value) -> Result<String, serde_yaml_ng::Error> {
    let mut document = Mapping::new();
    document.insert(
        Value::String("vhost".to_owned()),
        Value::Sequence(vec![host.clone()]),
    );
    serde_yaml_ng::to_string(&document)
}

fn serialize_main_config(
    options: Option<&Value>,
    host: Option<&Value>,
) -> Result<String, serde_yaml_ng::Error> {
    let mut document = Mapping::new();
    if let Some(options) = options {
        document.insert(Value::String("options".to_owned()), options.clone());
    }
    if let Some(host) = host {
        document.insert(
            Value::String("vhost".to_owned()),
            Value::Sequence(vec![host.clone()]),
        );
    }
    serde_yaml_ng::to_string(&document)
}

fn server_option_exists(name: &str) -> bool {
    server_options().iter().any(|option| option.name == name)
}

fn generic_server_options() -> Vec<OptionInfo> {
    server_options()
        .into_iter()
        .filter(|option| !CURATED_SERVER_OPTIONS.contains(&option.name.as_str()))
        .collect()
}

fn write_output(path: &Path, contents: &[u8], force: bool) -> io::Result<()> {
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !force {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(path)?;
        let result = (|| {
            file.set_permissions(fs::Permissions::from_mode(0o644))?;
            file.write_all(contents)?;
            file.sync_all()
        })();
        if result.is_err() {
            drop(file);
            let _ = fs::remove_file(path);
        }
        return result;
    }
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "output path must name a file")
    })?;
    let mut temporary_path = None;
    let mut temporary_file = None;
    for _ in 0..32 {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            ".{}.{}.{}.tmp",
            file_name.to_string_lossy(),
            std::process::id(),
            id
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&candidate)
        {
            Ok(file) => {
                temporary_path = Some(candidate);
                temporary_file = Some(file);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    let temporary_path = temporary_path.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate temporary output file",
        )
    })?;
    let mut file = temporary_file
        .ok_or_else(|| io::Error::other("temporary output path was created without its file"))?;
    let result = (|| {
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary_path, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary_path);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_schema_covered(type_name: &str, fields: &[&str], asked: &[&str], not_asked: &[&str]) {
        for field in fields {
            let asked_count = usize::from(asked.contains(field));
            let not_asked_count = usize::from(not_asked.contains(field));
            assert_eq!(
                asked_count + not_asked_count,
                1,
                "{type_name}.{field} must be listed exactly once as asked or deliberately not asked"
            );
        }
        for key in asked {
            assert!(
                fields.contains(key),
                "{type_name}.{key} is listed as asked but is not a YAML field"
            );
        }
    }

    #[test]
    fn every_configuration_field_is_asked_or_explicitly_out_of_scope() {
        assert_schema_covered(
            "VhostFile",
            project_charlotte::configure_support::vhost_keys(),
            ASKED_VHOST_KEYS,
            NOT_ASKED_VHOST_KEYS,
        );
        assert_schema_covered(
            "FastCgiAppFile",
            project_charlotte::configure_support::fastcgi_app_keys(),
            ASKED_FASTCGI_APP_KEYS,
            NOT_ASKED_FASTCGI_APP_KEYS,
        );
        assert_schema_covered(
            "BotPolicyFile",
            project_charlotte::configure_support::bot_policy_keys(),
            ASKED_BOT_POLICY_KEYS,
            NOT_ASKED_BOT_POLICY_KEYS,
        );
        assert_eq!(NOT_ASKED_FASTCGI_APP_KEYS, &["workers"]);
    }

    #[test]
    fn every_visible_server_option_is_curated_or_in_the_generic_menu() {
        let all = server_options();
        let generic = generic_server_options();
        let generic_names = generic
            .iter()
            .map(|option| option.name.as_str())
            .collect::<Vec<_>>();
        let all_names = all
            .iter()
            .map(|option| option.name.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            all_names.len(),
            all_names
                .iter()
                .copied()
                .collect::<std::collections::HashSet<_>>()
                .len()
        );
        for option in &all {
            assert!(
                CURATED_SERVER_OPTIONS.contains(&option.name.as_str())
                    || generic_names.contains(&option.name.as_str()),
                "{} is missing from both the guided questions and generic menu",
                option.name
            );
        }
        for reserved in [
            "config",
            "check_config",
            "help",
            "worker",
            "worker_uid",
            "worker_gid",
        ] {
            assert!(
                !all_names.contains(&reserved),
                "reserved option {reserved} is exposed"
            );
        }
        assert!(generic_names.contains(&"max_connections"));
        assert_eq!(
            all.iter()
                .find(|option| option.name == "debug")
                .map(|option| option.kind),
            Some(OptionKind::Flag)
        );
        assert_eq!(
            all.iter()
                .find(|option| option.name == "max_connections")
                .map(|option| option.kind),
            Some(OptionKind::Value)
        );
        if HOSTING_ENABLED {
            assert_eq!(
                all.iter()
                    .find(|option| option.name == "index")
                    .map(|option| option.kind),
                Some(OptionKind::List)
            );
        }
    }
}
