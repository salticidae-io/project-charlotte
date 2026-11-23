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
    ACME_ENABLED, HOSTING_ENABLED, PROXY_ENABLED, validate_vhost_yaml,
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
    let mut wizard = Wizard::new(stdin.lock(), stderr.lock(), config_dir);
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
    fn new(input: R, output: W, config_dir: &Path) -> Self {
        Self {
            input,
            output,
            config_dir: config_dir.to_path_buf(),
        }
    }

    fn run(&mut self) -> Result<String, Box<dyn Error>> {
        if site_choices().is_empty() {
            return Err("this build has neither hosting nor proxy support".into());
        }
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
        has_waf = self.shared_options(&mut host, has_waf)?;
        let yaml = serialize_vhost(&host)?;
        self.validate(&host, has_waf).map_err(|errors| {
            format!(
                "refusing to write invalid configuration: {}",
                errors.join("; ")
            )
        })?;
        Ok(yaml)
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
                "Additional directory index names, comma-separated (blank inherits the global list)",
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
            &["Inherit global setting", "Return 404", "Serve index.html"],
            0,
        )?;
        if try_files != 0 {
            let entries = if try_files == 1 {
                vec!["$uri".to_owned(), "=404".to_owned()]
            } else {
                vec!["$uri".to_owned(), "/index.html".to_owned()]
            };
            let mut candidate = host.clone();
            insert_sequence_value(&mut candidate, "try_files", strings_to_values(entries));
            self.accept_candidate(host, candidate, has_waf)?;
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
        let mode = self.choice("Managed PHP mode", &["CGI workers", "PHP-FPM process"], 0)?;
        if mode == 1 {
            let mut candidate = host.clone();
            let app = first_app_mut(&mut candidate).ok_or("missing PHP app entry")?;
            insert_string_value(app, "mode", "fpm");
            self.accept_candidate(host, candidate, has_waf)?;
        }
        loop {
            let max_workers = self.ask(
                "Maximum PHP workers (1-256; blank uses the default)",
                Some(""),
            )?;
            if max_workers.trim().is_empty() {
                break;
            }
            let Ok(workers) = max_workers.trim().parse::<usize>() else {
                writeln!(self.output, "Enter a whole number from 1 to 256.")?;
                continue;
            };
            let mut candidate = host.clone();
            if let Some(app) = first_app_mut(&mut candidate) {
                insert_serialized_mapping(app, "max_workers", workers)?;
            }
            if self.accept_candidate(host, candidate, has_waf)? {
                break;
            }
        }
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
        for (question, key, default) in [
            (
                "Preserve the incoming Host header?",
                "proxy_preserve_host",
                0,
            ),
            (
                "Use HTTP/2 to the upstream (h2c for http:// URLs)?",
                "proxy_http2",
                0,
            ),
        ] {
            let choice = self.choice(question, &["Yes", "No"], default)?;
            let mut candidate = host.clone();
            insert_bool(&mut candidate, key, choice == 0);
            self.accept_candidate(host, candidate, has_waf)?;
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

        let modsecurity = self.choice(
            "Does the main server configuration load ModSecurity rules?",
            &["No", "Yes"],
            usize::from(has_waf),
        )? == 1;
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

fn first_app_mut(host: &mut Value) -> Option<&mut Mapping> {
    let Value::Mapping(host) = host else {
        return None;
    };
    let apps = host.get_mut(Value::String("fastcgi_app".to_owned()))?;
    let Value::Sequence(apps) = apps else {
        return None;
    };
    let Value::Mapping(app) = apps.first_mut()? else {
        return None;
    };
    Some(app)
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

fn insert_serialized_mapping<T: Serialize>(
    host: &mut Mapping,
    key: &str,
    value: T,
) -> Result<(), serde_yaml_ng::Error> {
    host.insert(
        Value::String(key.to_owned()),
        serde_yaml_ng::to_value(value)?,
    );
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
