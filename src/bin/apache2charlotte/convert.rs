use std::collections::{BTreeMap, HashMap, HashSet};

use super::parse::{Directive, Node, Section};

#[derive(Clone, Debug)]
enum Value {
    String(String),
    Bool(bool),
    Number(u64),
    Strings(Vec<String>),
}

#[derive(Default)]
struct VirtualHost {
    names: Vec<String>,
    fields: BTreeMap<String, Value>,
    comments: Vec<String>,
}

pub(super) fn convert(nodes: &[Node]) -> String {
    let mut comments = vec![
        "# Converted from Apache configuration. Review all TODO and unmapped directives.".to_owned(),
        "# Global Apache settings are retained below as comments; configure listener and process settings with Charlotte's command-line options.".to_owned(),
    ];
    let mut global_user = None;
    let mut global_group = None;
    let mut log_formats = HashMap::new();
    collect_global_settings(nodes, &mut global_user, &mut global_group, &mut log_formats);
    let mut vhosts = Vec::new();
    convert_global_nodes(
        nodes,
        &mut comments,
        &mut vhosts,
        global_user.as_deref(),
        global_group.as_deref(),
        &log_formats,
    );

    let mut names = HashSet::new();
    let mut output_hosts = Vec::new();
    for mut host in vhosts {
        host.names.retain(|name| {
            if names.insert(name.to_ascii_lowercase()) {
                true
            } else {
                host.comments.push(format!(
                    "# Duplicate server name {name:?} was removed; names may only occur once across Charlotte vhosts."
                ));
                false
            }
        });
        if host.names.is_empty() {
            comments.extend(host.comments);
            continue;
        }
        host.fields.insert(
            "server_names".to_owned(),
            Value::Strings(host.names.clone()),
        );
        if !host.fields.contains_key("proxy_pass") {
            if !host.fields.contains_key("root") {
                host.comments.push(
                    "# TODO: set root to a document directory; static vhosts require root."
                        .to_owned(),
                );
            }
            if !host.fields.contains_key("user") {
                host.comments.push(
                    "# TODO: set user to an unprivileged account; worker vhosts require user."
                        .to_owned(),
                );
            }
        }
        output_hosts.push(host);
    }

    let mut output = String::new();
    for comment in comments {
        output.push_str(&comment);
        output.push('\n');
    }
    if output_hosts.is_empty() {
        output.push_str("vhost: []\n");
        return output;
    }
    output.push_str("vhost:\n");
    for host in output_hosts {
        for comment in host.comments {
            output.push_str("  ");
            output.push_str(&comment);
            output.push('\n');
        }
        output.push_str("  - server_names: ");
        let names = match host.fields.get("server_names") {
            Some(Value::Strings(values)) => values,
            _ => unreachable!("server_names is always emitted as a string list"),
        };
        write_strings(&mut output, names);
        output.push('\n');
        for (key, value) in host.fields {
            if key == "server_names" {
                continue;
            }
            output.push_str("    ");
            output.push_str(&key);
            output.push_str(": ");
            match value {
                Value::String(value) => output.push_str(&yaml_string(&value)),
                Value::Bool(value) => output.push_str(if value { "true" } else { "false" }),
                Value::Number(value) => output.push_str(&value.to_string()),
                Value::Strings(values) => write_strings(&mut output, &values),
            }
            output.push('\n');
        }
    }
    output
}

fn convert_global_nodes(
    nodes: &[Node],
    comments: &mut Vec<String>,
    vhosts: &mut Vec<VirtualHost>,
    global_user: Option<&str>,
    global_group: Option<&str>,
    log_formats: &HashMap<String, String>,
) {
    for node in nodes {
        match node {
            Node::Directive(directive) => comment_directive(directive, comments),
            Node::Section(section) if section.name.eq_ignore_ascii_case("VirtualHost") => {
                let mut host = convert_vhost(section, global_user, global_group, log_formats);
                if host.names.is_empty() {
                    host.comments.push(format!(
                        "# TODO: omitted <VirtualHost> without a usable ServerName/ServerAlias ({})",
                        section.location
                    ));
                    comment_section(section, &mut host.comments);
                    comments.extend(host.comments);
                } else {
                    vhosts.push(host);
                }
            }
            Node::Section(section) => {
                comment_section_boundary(section, true, comments);
                convert_global_nodes(
                    &section.children,
                    comments,
                    vhosts,
                    global_user,
                    global_group,
                    log_formats,
                );
                comment_section_boundary(section, false, comments);
            }
        }
    }
}

fn collect_global_settings(
    nodes: &[Node],
    user: &mut Option<String>,
    group: &mut Option<String>,
    formats: &mut HashMap<String, String>,
) {
    for node in nodes {
        match node {
            Node::Directive(directive) => {
                if directive.name.eq_ignore_ascii_case("User") {
                    *user = directive.args.first().cloned();
                } else if directive.name.eq_ignore_ascii_case("Group") {
                    *group = directive.args.first().cloned();
                } else if directive.name.eq_ignore_ascii_case("LogFormat")
                    && directive.args.len() >= 2
                {
                    formats.insert(
                        directive.args.last().cloned().unwrap_or_default(),
                        directive.args[0].clone(),
                    );
                }
            }
            Node::Section(section) if !section.name.eq_ignore_ascii_case("VirtualHost") => {
                collect_global_settings(&section.children, user, group, formats);
            }
            Node::Section(_) => {}
        }
    }
}

fn convert_vhost(
    section: &Section,
    global_user: Option<&str>,
    global_group: Option<&str>,
    log_formats: &HashMap<String, String>,
) -> VirtualHost {
    let mut host = VirtualHost::default();
    if let Some(user) = global_user {
        host.fields
            .insert("user".to_owned(), Value::String(user.to_owned()));
    }
    if let Some(group) = global_group {
        host.fields
            .insert("group".to_owned(), Value::String(group.to_owned()));
    }
    let document_root = section.children.iter().find_map(|node| match node {
        Node::Directive(directive) if directive.name.eq_ignore_ascii_case("DocumentRoot") => {
            directive.args.first().cloned()
        }
        _ => None,
    });
    convert_nodes(
        &section.children,
        &mut host,
        log_formats,
        document_root.as_deref(),
        None,
    );
    host
}

fn convert_nodes(
    nodes: &[Node],
    host: &mut VirtualHost,
    log_formats: &HashMap<String, String>,
    document_root: Option<&str>,
    files_match: Option<&str>,
) {
    for node in nodes {
        match node {
            Node::Directive(directive) => {
                if !convert_directive(directive, host, log_formats, document_root, files_match) {
                    comment_directive(directive, &mut host.comments);
                }
            }
            Node::Section(section) => {
                if section.name.eq_ignore_ascii_case("Directory") {
                    let directory = section.args.first().map(String::as_str);
                    let applies = document_root.is_some_and(|root| {
                        directory.is_some_and(|directory| {
                            normalize_path(root) == normalize_path(directory)
                        })
                    });
                    if applies {
                        comment_section_boundary(section, true, &mut host.comments);
                        convert_nodes(&section.children, host, log_formats, document_root, None);
                        comment_section_boundary(section, false, &mut host.comments);
                    } else {
                        comment_section(section, &mut host.comments);
                    }
                } else if section.name.eq_ignore_ascii_case("FilesMatch") {
                    let pattern = section.args.first().map(String::as_str);
                    comment_section_boundary(section, true, &mut host.comments);
                    convert_nodes(&section.children, host, log_formats, document_root, pattern);
                    comment_section_boundary(section, false, &mut host.comments);
                } else {
                    comment_section(section, &mut host.comments);
                }
            }
        }
    }
}

fn convert_directive(
    directive: &Directive,
    host: &mut VirtualHost,
    log_formats: &HashMap<String, String>,
    document_root: Option<&str>,
    files_match: Option<&str>,
) -> bool {
    let args = directive.args.as_slice();
    let Some(value) = args.first().map(String::as_str) else {
        return false;
    };
    match directive.name.to_ascii_lowercase().as_str() {
        "servername" | "serveralias" => {
            for name in args {
                if let Some(name) = normalize_server_name(name) {
                    host.names.push(name);
                } else {
                    comment_directive_with_reason(
                        directive,
                        "wildcard/glob names other than a leading '*.' are not supported",
                        &mut host.comments,
                    );
                }
            }
            true
        }
        "documentroot" => {
            set_string(host, "root", value);
            true
        }
        "assignuserid" | "suexecusergroup" if args.len() >= 2 => {
            set_string(host, "user", value);
            set_string(host, "group", &args[1]);
            true
        }
        "directoryindex" => {
            set_string(host, "index", value);
            if args.len() > 1 {
                comment_directive_with_reason(
                    directive,
                    "Charlotte supports one index file; only the first Apache entry was converted",
                    &mut host.comments,
                );
            }
            true
        }
        "options" => convert_options(directive, host),
        "fallbackresource" if !value.eq_ignore_ascii_case("disabled") => {
            set_strings(host, "try_files", vec!["$uri".to_owned(), value.to_owned()]);
            true
        }
        "sslcertificatefile" => {
            set_string(host, "tls_cert", value);
            true
        }
        "sslcertificatekeyfile" => {
            set_string(host, "tls_key", value);
            true
        }
        "proxypass" if args.len() >= 2 => {
            if value == "/" {
                set_string(host, "proxy_pass", &args[1]);
                true
            } else {
                comment_directive_with_reason(
                    directive,
                    "path-specific ProxyPass rules do not have a direct Charlotte representation",
                    &mut host.comments,
                );
                true
            }
        }
        "proxypreservehost" => {
            if let Some(value) = parse_on_off(value) {
                host.fields
                    .insert("proxy_preserve_host".to_owned(), Value::Bool(value));
                true
            } else {
                false
            }
        }
        "proxytimeout" => match value.parse::<u64>() {
            Ok(seconds) if seconds > 0 => {
                host.fields
                    .insert("proxy_timeout".to_owned(), Value::Number(seconds));
                true
            }
            _ => false,
        },
        "sslproxycacertificatefile" => {
            set_string(host, "proxy_ca_root", value);
            true
        }
        "proxypassmatch" => {
            if let Some(backend) = parse_proxy_fcgi(args) {
                append_string(host, "fastcgi", backend);
                true
            } else {
                comment_directive_with_reason(
                    directive,
                    "only simple PHP ProxyPassMatch FastCGI rules can be converted",
                    &mut host.comments,
                );
                true
            }
        }
        "sethandler" if files_match.is_some() => {
            if let Some(extension) = php_extension(files_match.unwrap_or_default())
                && let Some(address) = parse_sethandler_fcgi(value)
            {
                append_string(host, "fastcgi", format!("{extension}={address}"));
                true
            } else {
                comment_directive_with_reason(
                    directive,
                    "SetHandler requires a matching PHP FilesMatch and a simple FastCGI target",
                    &mut host.comments,
                );
                true
            }
        }
        "addhandler" if args.len() >= 2 && value.eq_ignore_ascii_case("cgi-script") => {
            for extension in &args[1..] {
                append_string(host, "cgi", extension.trim_start_matches('.').to_owned());
            }
            true
        }
        "customlog" if args.len() >= 2 => {
            if value.starts_with('|') {
                comment_directive_with_reason(
                    directive,
                    "piped log programs are not supported",
                    &mut host.comments,
                );
            } else {
                set_string(host, "access_log", value);
                let format = log_formats
                    .get(&args[1])
                    .map(String::as_str)
                    .unwrap_or(&args[1]);
                set_string(host, "access_log_format", format);
            }
            true
        }
        "transferlog" => {
            if value.starts_with('|') {
                comment_directive_with_reason(
                    directive,
                    "piped log programs are not supported",
                    &mut host.comments,
                );
            } else {
                set_string(host, "access_log", value);
            }
            true
        }
        "errorlog" => {
            if value.starts_with('|') {
                comment_directive_with_reason(
                    directive,
                    "piped log programs are not supported",
                    &mut host.comments,
                );
            } else {
                set_string(host, "error_log", value);
            }
            true
        }
        "errorlogformat" => {
            let format = if args.len() > 1 && matches!(value, "request" | "connection") {
                &args[1]
            } else {
                value
            };
            set_string(host, "error_log_format", format);
            true
        }
        "logformat" => {
            comment_directive_with_reason(
                directive,
                "format nickname was retained for resolving CustomLog; review format semantics",
                &mut host.comments,
            );
            true
        }
        "secruleremovebyid" => {
            let ids = args
                .iter()
                .flat_map(|argument| argument.split(','))
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if ids.is_empty() {
                false
            } else {
                append_strings(host, "modsecurity_disable_rules", ids);
                true
            }
        }
        "user" | "group" => {
            comment_directive_with_reason(
                directive,
                "global process identity was also applied to this vhost where available",
                &mut host.comments,
            );
            true
        }
        _ => {
            let _ = document_root;
            false
        }
    }
}

fn convert_options(directive: &Directive, host: &mut VirtualHost) -> bool {
    let mut listing = None;
    let mut unsupported = Vec::new();
    for option in &directive.args {
        match option.to_ascii_lowercase().as_str() {
            "indexes" | "+indexes" | "all" | "+all" => listing = Some(true),
            "-indexes" | "none" => listing = Some(false),
            value if value.starts_with('+') || value.starts_with('-') => {
                if value.ends_with("indexes") {
                    listing = Some(value.starts_with('+'));
                } else {
                    unsupported.push(option.clone());
                }
            }
            _ => unsupported.push(option.clone()),
        }
    }
    if let Some(listing) = listing {
        host.fields
            .insert("listing".to_owned(), Value::Bool(listing));
    }
    if !unsupported.is_empty() {
        comment_directive_with_reason(
            directive,
            &format!("unsupported Options values: {}", unsupported.join(" ")),
            &mut host.comments,
        );
    }
    true
}

fn parse_proxy_fcgi(args: &[String]) -> Option<String> {
    let pattern = args.first()?;
    let extension = php_extension(pattern)?;
    let target = args.get(1)?;
    let address = if let Some(unix) = target.strip_prefix("fcgi://") {
        if let Some((socket, _)) = unix.split_once('|') {
            format!("unix:{}", socket.strip_prefix("unix:").unwrap_or(socket))
        } else {
            let (authority, path) = unix.split_once('/').unwrap_or((unix, ""));
            if !path.is_empty() {
                return None;
            }
            authority.to_owned()
        }
    } else if let Some((socket, _)) = target
        .strip_prefix("proxy:unix:")
        .and_then(|value| value.split_once("|fcgi://"))
    {
        format!("unix:{socket}")
    } else {
        return None;
    };
    Some(format!("{extension}={address}"))
}

fn parse_sethandler_fcgi(value: &str) -> Option<String> {
    if let Some(rest) = value.strip_prefix("proxy:unix:") {
        let (socket, _) = rest.split_once("|fcgi://")?;
        return Some(format!("unix:{socket}"));
    }
    value.strip_prefix("proxy:fcgi://").map(str::to_owned)
}

fn php_extension(pattern: &str) -> Option<String> {
    let lowercase = pattern.to_ascii_lowercase();
    let marker = lowercase.find("\\.php")?;
    let after_dot = marker + 2;
    if lowercase
        .as_bytes()
        .get(after_dot..after_dot + 3)
        .is_some_and(|value| value == b"php")
    {
        Some("php".to_owned())
    } else {
        None
    }
}

fn normalize_server_name(value: &str) -> Option<String> {
    let mut name = value.trim().to_owned();
    if name.starts_with('[') {
        let end = name.find(']')?;
        let suffix = &name[end + 1..];
        if !suffix.is_empty()
            && !suffix
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok())
        {
            return None;
        }
        name.truncate(end + 1);
    } else if name.matches(':').count() == 1 {
        let (host, port) = name.rsplit_once(':')?;
        if port.parse::<u16>().is_err() {
            return None;
        }
        name = host.to_owned();
    } else if name.contains(':') {
        return None;
    }
    name = name.trim_end_matches('.').to_owned();
    if name.contains('*') && !name.starts_with("*.") {
        return None;
    }
    if name.contains('?') || name.contains('[') || name.contains(']') {
        return None;
    }
    (!name.is_empty()).then_some(name)
}

fn normalize_path(value: &str) -> String {
    value.trim_end_matches('/').to_owned()
}

fn parse_on_off(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "on" | "true" | "yes" => Some(true),
        "off" | "false" | "no" => Some(false),
        _ => None,
    }
}

fn set_string(host: &mut VirtualHost, key: &str, value: &str) {
    host.fields
        .insert(key.to_owned(), Value::String(value.to_owned()));
}

fn set_strings(host: &mut VirtualHost, key: &str, values: Vec<String>) {
    host.fields.insert(key.to_owned(), Value::Strings(values));
}

fn append_string(host: &mut VirtualHost, key: &str, value: String) {
    let values = match host.fields.remove(key) {
        Some(Value::Strings(values)) => values,
        _ => Vec::new(),
    };
    let mut values = values;
    values.push(value);
    set_strings(host, key, values);
}

fn append_strings(host: &mut VirtualHost, key: &str, additions: Vec<String>) {
    for value in additions {
        append_string(host, key, value);
    }
}

fn comment_directive(directive: &Directive, comments: &mut Vec<String>) {
    let reason = if directive.name.eq_ignore_ascii_case("Listen") {
        "configure an equivalent --bind, --tls-bind, or --http3-bind address manually"
    } else {
        "no direct Charlotte representation"
    };
    comment_directive_with_reason(directive, reason, comments);
}

fn comment_directive_with_reason(directive: &Directive, reason: &str, comments: &mut Vec<String>) {
    comments.push(format!("# UNMAPPED ({reason}) at {}", directive.location));
    comments.push(format!("#   {}", directive.raw.trim()));
}

fn comment_section(section: &Section, comments: &mut Vec<String>) {
    comment_section_boundary(section, true, comments);
    for child in &section.children {
        match child {
            Node::Directive(directive) => comment_directive(directive, comments),
            Node::Section(section) => comment_section(section, comments),
        }
    }
    comment_section_boundary(section, false, comments);
}

fn comment_section_boundary(section: &Section, opening: bool, comments: &mut Vec<String>) {
    let raw = if opening {
        &section.raw_open
    } else {
        &section.raw_close
    };
    comments.push(format!("# Apache section at {}", section.location));
    comments.push(format!("#   {}", raw.trim()));
}

fn write_strings(output: &mut String, values: &[String]) {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push_str(", ");
        }
        output.push_str(&yaml_string(value));
    }
    output.push(']');
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}
