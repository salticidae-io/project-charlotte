use std::collections::{BTreeMap, HashMap, HashSet};

use super::parse::{Block, Directive, Node};

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

#[derive(Default)]
struct HttpSettings {
    user: Option<String>,
    group: Option<String>,
    log_formats: HashMap<String, String>,
    upstreams: HashMap<String, String>,
}

pub(super) fn convert(nodes: &[Node]) -> String {
    let mut comments = vec![
        "# Converted from nginx configuration. Review all TODO and unmapped directives.".to_owned(),
        "# Global nginx settings are retained below as comments; configure listener and process settings with Charlotte's command-line options.".to_owned(),
    ];
    let mut hosts = Vec::new();
    let (main_user, main_group) = collect_main_user(nodes);
    for node in nodes {
        match node {
            Node::Directive(directive) if directive.name.eq_ignore_ascii_case("user") => {
                comment_directive_with_reason(
                    directive,
                    "converted to the default user/group for generated vhosts",
                    &mut comments,
                );
            }
            Node::Directive(directive) => comment_directive(directive, &mut comments),
            Node::Block(block) if block.name.eq_ignore_ascii_case("http") => {
                let settings =
                    collect_http_settings(block, main_user.as_deref(), main_group.as_deref());
                comment_block_boundary(
                    block,
                    true,
                    &mut comments,
                    "HTTP settings are shown for migration context",
                );
                convert_http_children(block, &settings, &mut comments, &mut hosts);
                comment_block_boundary(block, false, &mut comments, "end of HTTP settings");
            }
            Node::Block(block) => comment_block(
                block,
                &mut comments,
                "global nginx block has no direct Charlotte representation",
            ),
        }
    }

    let mut used_names = HashSet::new();
    let mut output_hosts = Vec::new();
    for mut host in hosts {
        host.names.retain(|name| {
            if used_names.insert(name.to_ascii_lowercase()) {
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
        if let Some(Value::Strings(names)) = host.fields.get("server_names") {
            write_strings(&mut output, names);
        }
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

fn collect_main_user(nodes: &[Node]) -> (Option<String>, Option<String>) {
    nodes
        .iter()
        .find_map(|node| match node {
            Node::Directive(directive) if directive.name.eq_ignore_ascii_case("user") => Some((
                directive.args.first().cloned(),
                directive.args.get(1).cloned(),
            )),
            _ => None,
        })
        .unwrap_or_default()
}

fn collect_http_settings(
    block: &Block,
    main_user: Option<&str>,
    main_group: Option<&str>,
) -> HttpSettings {
    let mut settings = HttpSettings {
        user: main_user.map(str::to_owned),
        group: main_group.map(str::to_owned),
        ..HttpSettings::default()
    };
    for node in &block.children {
        match node {
            Node::Directive(directive) => match directive.name.to_ascii_lowercase().as_str() {
                "user" if !directive.args.is_empty() => {
                    settings.user = directive.args.first().cloned();
                    settings.group = directive.args.get(1).cloned();
                }
                "log_format" if directive.args.len() >= 2 => {
                    settings
                        .log_formats
                        .insert(directive.args[0].clone(), directive.args[1..].join(" "));
                }
                _ => {}
            },
            Node::Block(upstream) if upstream.name.eq_ignore_ascii_case("upstream") => {
                if let Some(name) = upstream.args.first() {
                    if let Some(server) = upstream.children.iter().find_map(|node| match node {
                        Node::Directive(directive)
                            if directive.name.eq_ignore_ascii_case("server") =>
                        {
                            directive.args.first().cloned()
                        }
                        _ => None,
                    }) {
                        settings.upstreams.insert(name.clone(), server);
                    }
                }
            }
            _ => {}
        }
    }
    settings
}

fn convert_http_children(
    block: &Block,
    settings: &HttpSettings,
    comments: &mut Vec<String>,
    hosts: &mut Vec<VirtualHost>,
) {
    for node in &block.children {
        match node {
            Node::Directive(directive) => {
                if directive.name.eq_ignore_ascii_case("user") {
                    comment_directive_with_reason(
                        directive,
                        "converted to the default user/group for generated vhosts",
                        comments,
                    );
                } else if directive.name.eq_ignore_ascii_case("log_format") {
                    comment_directive_with_reason(
                        directive,
                        "used when translating access_log formats",
                        comments,
                    );
                } else {
                    comment_directive(directive, comments);
                }
            }
            Node::Block(server) if server.name.eq_ignore_ascii_case("server") => {
                let host = convert_server(server, settings);
                if host.names.is_empty() {
                    comments.push(format!(
                        "# TODO: omitted server block without a usable server_name ({})",
                        server.location
                    ));
                    comment_block(
                        server,
                        comments,
                        "server block could not be represented without a usable name",
                    );
                } else {
                    hosts.push(host);
                }
            }
            Node::Block(upstream) if upstream.name.eq_ignore_ascii_case("upstream") => {
                comment_block(
                    upstream,
                    comments,
                    "upstream first server is used to resolve proxy_pass",
                );
            }
            Node::Block(other) => comment_block(
                other,
                comments,
                "HTTP-level block has no direct Charlotte representation",
            ),
        }
    }
}

fn convert_server(block: &Block, settings: &HttpSettings) -> VirtualHost {
    let mut host = VirtualHost::default();
    if let Some(user) = &settings.user {
        set_string(&mut host, "user", user);
    }
    if let Some(group) = &settings.group {
        set_string(&mut host, "group", group);
    }
    for node in &block.children {
        match node {
            Node::Directive(directive) => convert_server_directive(directive, &mut host, settings),
            Node::Block(location) if location.name.eq_ignore_ascii_case("location") => {
                convert_location(location, &mut host, settings);
            }
            Node::Block(other) => comment_block(
                other,
                &mut host.comments,
                "server-level block has no direct Charlotte representation",
            ),
        }
    }
    host
}

fn convert_server_directive(
    directive: &Directive,
    host: &mut VirtualHost,
    settings: &HttpSettings,
) {
    let args = directive.args.as_slice();
    let Some(value) = args.first().map(String::as_str) else {
        comment_directive(directive, &mut host.comments);
        return;
    };
    match directive.name.to_ascii_lowercase().as_str() {
        "server_name" => {
            for name in args {
                match normalize_server_name(name) {
                    Some(names) => host.names.extend(names),
                    None => comment_directive_with_reason(
                        directive,
                        "regex names, the '_' catch-all, and unsupported wildcard forms need manual routing",
                        &mut host.comments,
                    ),
                }
            }
        }
        "listen" => comment_directive_with_reason(
            directive,
            "configure an equivalent --bind, --tls-bind, or --http3-bind address manually",
            &mut host.comments,
        ),
        "root" => set_string(host, "root", value),
        "index" => {
            set_string(host, "index", value);
            if args.len() > 1 {
                comment_directive_with_reason(
                    directive,
                    "Charlotte supports one index file; only the first nginx entry was converted",
                    &mut host.comments,
                );
            }
        }
        "autoindex" => match parse_on_off(value) {
            Some(value) => {
                host.fields.insert("listing".to_owned(), Value::Bool(value));
            }
            None => comment_directive(directive, &mut host.comments),
        },
        "ssl_certificate" => set_string(host, "tls_cert", value),
        "ssl_certificate_key" => set_string(host, "tls_key", value),
        "access_log" => convert_access_log(directive, host, &settings.log_formats),
        "error_log" => convert_error_log(directive, host),
        "proxy_set_header" => set_proxy_preserve_host(directive, host),
        "proxy_ssl_trusted_certificate" => set_string(host, "proxy_ca_root", value),
        "proxy_read_timeout" => set_timeout(directive, host, "proxy_timeout", value),
        _ => comment_directive(directive, &mut host.comments),
    }
}

fn convert_location(block: &Block, host: &mut VirtualHost, settings: &HttpSettings) {
    let args = block.args.iter().map(String::as_str).collect::<Vec<_>>();
    let path_location = args.as_slice() == ["/"];
    let php_location = args
        .iter()
        .any(|argument| argument.contains(".php") || argument.contains("php$"))
        && args.iter().any(|argument| argument.starts_with('~'));
    if !path_location && !php_location {
        comment_block(
            block,
            &mut host.comments,
            "only location / and PHP regex locations are converted",
        );
        return;
    }

    comment_block_boundary(
        block,
        true,
        &mut host.comments,
        if php_location {
            "PHP location directives are converted"
        } else {
            "root location directives are converted"
        },
    );
    for node in &block.children {
        match node {
            Node::Directive(directive) => {
                let args = directive.args.as_slice();
                let Some(value) = args.first().map(String::as_str) else {
                    comment_directive(directive, &mut host.comments);
                    continue;
                };
                match directive.name.to_ascii_lowercase().as_str() {
                    "root" if path_location => set_string(host, "root", value),
                    "index" if path_location => {
                        set_string(host, "index", value);
                        if args.len() > 1 {
                            comment_directive_with_reason(
                                directive,
                                "Charlotte supports one index file; only the first nginx entry was converted",
                                &mut host.comments,
                            );
                        }
                    }
                    "autoindex" if path_location => match parse_on_off(value) {
                        Some(value) => {
                            host.fields.insert("listing".to_owned(), Value::Bool(value));
                        }
                        None => comment_directive(directive, &mut host.comments),
                    },
                    "try_files" if path_location => {
                        host.fields
                            .insert("try_files".to_owned(), Value::Strings(args.to_vec()));
                    }
                    "proxy_pass" if path_location => {
                        match resolve_proxy_pass(value, &settings.upstreams) {
                            Some(target) => set_string(host, "proxy_pass", &target),
                            None => comment_directive_with_reason(
                                directive,
                                "proxy_pass contains an unresolved variable or unsupported upstream reference",
                                &mut host.comments,
                            ),
                        }
                    }
                    "proxy_set_header" if path_location => {
                        set_proxy_preserve_host(directive, host);
                    }
                    "access_log" if path_location => {
                        convert_access_log(directive, host, &settings.log_formats);
                    }
                    "error_log" if path_location => convert_error_log(directive, host),
                    "proxy_read_timeout" if path_location => {
                        set_timeout(directive, host, "proxy_timeout", value);
                    }
                    "proxy_ssl_trusted_certificate" if path_location => {
                        set_string(host, "proxy_ca_root", value);
                    }
                    "fastcgi_pass" if php_location => match normalize_fastcgi_address(value) {
                        Some(address) => append_string(host, "fastcgi", format!("php={address}")),
                        None => comment_directive_with_reason(
                            directive,
                            "FastCGI variables are not supported as backend addresses",
                            &mut host.comments,
                        ),
                    },
                    "fastcgi_read_timeout" if php_location => {
                        set_timeout(directive, host, "fastcgi_timeout", value);
                    }
                    _ => comment_directive(directive, &mut host.comments),
                }
            }
            Node::Block(other) => comment_block(
                other,
                &mut host.comments,
                "nested location blocks are not converted",
            ),
        }
    }
    comment_block_boundary(
        block,
        false,
        &mut host.comments,
        "end of converted location",
    );
}

fn convert_access_log(
    directive: &Directive,
    host: &mut VirtualHost,
    formats: &HashMap<String, String>,
) {
    let args = directive.args.as_slice();
    let Some(path) = args.first() else {
        comment_directive(directive, &mut host.comments);
        return;
    };
    if path == "off" || path.starts_with("syslog:") {
        comment_directive_with_reason(
            directive,
            "disabled and syslog access logs have no direct Charlotte file setting",
            &mut host.comments,
        );
        return;
    }
    if args.len() > 2 {
        comment_directive_with_reason(
            directive,
            "buffering and conditional access_log options have no direct Charlotte representation",
            &mut host.comments,
        );
        return;
    }
    let format = args.get(1).map_or("combined", String::as_str);
    let translated = if format == "combined" {
        Some("combined".to_owned())
    } else if let Some(format) = formats.get(format) {
        match translate_log_format(format) {
            Ok(format) => Some(format),
            Err(variable) => {
                comment_directive_with_reason(
                    directive,
                    &format!("access log contains unsupported format variable ${variable}"),
                    &mut host.comments,
                );
                None
            }
        }
    } else {
        comment_directive_with_reason(
            directive,
            &format!("access_log format {format:?} is not a known nginx log_format"),
            &mut host.comments,
        );
        None
    };
    if let Some(format) = translated {
        set_string(host, "access_log", path);
        set_string(host, "access_log_format", &format);
    }
}

fn set_proxy_preserve_host(directive: &Directive, host: &mut VirtualHost) {
    if directive.args.len() >= 2
        && directive.args[0].eq_ignore_ascii_case("Host")
        && directive.args[1] == "$host"
    {
        host.fields
            .insert("proxy_preserve_host".to_owned(), Value::Bool(true));
    } else {
        comment_directive_with_reason(
            directive,
            "only 'proxy_set_header Host $host' maps to proxy_preserve_host",
            &mut host.comments,
        );
    }
}

fn convert_error_log(directive: &Directive, host: &mut VirtualHost) {
    let args = directive.args.as_slice();
    let Some(path) = args.first() else {
        comment_directive(directive, &mut host.comments);
        return;
    };
    if path == "off" || path == "stderr" || path.starts_with("syslog:") {
        comment_directive_with_reason(
            directive,
            "off, stderr, and syslog error logs need manual configuration",
            &mut host.comments,
        );
        return;
    }
    set_string(host, "error_log", path);
    if args.len() > 1 {
        comment_directive_with_reason(
            directive,
            "the nginx error-log severity is not configurable per Charlotte vhost",
            &mut host.comments,
        );
    }
}

fn translate_log_format(format: &str) -> Result<String, String> {
    let mut translated = String::with_capacity(format.len());
    let mut remaining = format;
    while let Some(start) = remaining.find('$') {
        translated.push_str(&remaining[..start]);
        remaining = &remaining[start + 1..];
        let variable;
        if let Some(braced) = remaining.strip_prefix('{') {
            let Some(end) = braced.find('}') else {
                return Err(braced.to_owned());
            };
            variable = &braced[..end];
            remaining = &braced[end + 1..];
        } else {
            let end = remaining
                .char_indices()
                .find_map(|(index, character)| {
                    (!character.is_ascii_alphanumeric() && character != '_').then_some(index)
                })
                .unwrap_or(remaining.len());
            if end == 0 {
                translated.push('$');
                continue;
            }
            variable = &remaining[..end];
            remaining = &remaining[end..];
        }
        translated.push_str(nginx_log_code(variable).ok_or_else(|| variable.to_owned())?);
    }
    translated.push_str(remaining);
    Ok(translated)
}

fn nginx_log_code(variable: &str) -> Option<&'static str> {
    match variable {
        "remote_addr" => Some("%a"),
        "remote_user" => Some("%u"),
        "time_local" => Some("%t"),
        "request" => Some("%r"),
        "status" => Some("%s"),
        "body_bytes_sent" => Some("%b"),
        "bytes_sent" => Some("%O"),
        "request_length" => Some("%I"),
        "request_method" => Some("%m"),
        "request_uri" => Some("%U%q"),
        "uri" => Some("%U"),
        "query_string" => Some("%q"),
        "server_name" => Some("%v"),
        "server_port" => Some("%p"),
        "http_referer" => Some("%{Referer}i"),
        "http_user_agent" => Some("%{User-Agent}i"),
        "http_host" => Some("%{Host}i"),
        _ => None,
    }
}

fn resolve_proxy_pass(value: &str, upstreams: &HashMap<String, String>) -> Option<String> {
    if value.contains('$') {
        return None;
    }
    let (scheme, rest) = value.split_once("://")?;
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let upstream = &rest[..authority_end];
    if let Some(server) = upstreams.get(upstream) {
        Some(format!("{scheme}://{server}{}", &rest[authority_end..]))
    } else {
        Some(value.to_owned())
    }
}

fn normalize_fastcgi_address(value: &str) -> Option<String> {
    if value.contains('$') {
        return None;
    }
    Some(value.strip_suffix(':').unwrap_or(value).to_owned())
}

fn set_timeout(directive: &Directive, host: &mut VirtualHost, key: &str, value: &str) {
    match parse_seconds(value) {
        Some(seconds) if seconds > 0 => {
            host.fields.insert(key.to_owned(), Value::Number(seconds));
        }
        _ => comment_directive_with_reason(
            directive,
            "timeout must be a positive whole number of seconds after unit conversion",
            &mut host.comments,
        ),
    }
}

fn parse_seconds(value: &str) -> Option<u64> {
    let unit_start = value
        .char_indices()
        .find_map(|(index, character)| (!character.is_ascii_digit()).then_some(index))
        .unwrap_or(value.len());
    let amount = value[..unit_start].parse::<u64>().ok()?;
    let multiplier = match &value[unit_start..] {
        "" | "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "ms" if amount % 1000 == 0 => return Some(amount / 1000),
        _ => return None,
    };
    amount.checked_mul(multiplier)
}

fn normalize_server_name(name: &str) -> Option<Vec<String>> {
    if name == "_" || name.starts_with('~') || name.is_empty() {
        return None;
    }
    if let Some(suffix) = name.strip_prefix('.') {
        if suffix.is_empty() || suffix.contains('*') {
            return None;
        }
        return Some(vec![suffix.to_owned(), format!("*.{suffix}")]);
    }
    if let Some(suffix) = name.strip_prefix("*.") {
        if suffix.is_empty() || suffix.contains('*') {
            return None;
        }
    } else if name.contains('*') {
        return None;
    }
    Some(vec![name.to_owned()])
}

fn parse_on_off(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

fn set_string(host: &mut VirtualHost, key: &str, value: &str) {
    host.fields
        .insert(key.to_owned(), Value::String(value.to_owned()));
}

fn append_string(host: &mut VirtualHost, key: &str, value: String) {
    match host
        .fields
        .entry(key.to_owned())
        .or_insert_with(|| Value::Strings(Vec::new()))
    {
        Value::Strings(values) => values.push(value),
        _ => unreachable!("FastCGI field is always a string list"),
    }
}

fn comment_directive(directive: &Directive, comments: &mut Vec<String>) {
    let reason = if directive.name.eq_ignore_ascii_case("listen") {
        "configure an equivalent --bind, --tls-bind, or --http3-bind address manually"
    } else {
        "no direct Charlotte representation"
    };
    comment_directive_with_reason(directive, reason, comments);
}

fn comment_directive_with_reason(directive: &Directive, reason: &str, comments: &mut Vec<String>) {
    comments.push(format!("# UNMAPPED ({reason}) at {}", directive.location));
    for line in directive.raw.lines() {
        comments.push(format!("#   {}", line.trim()));
    }
}

fn comment_block(block: &Block, comments: &mut Vec<String>, reason: &str) {
    comment_block_boundary(block, true, comments, reason);
    for child in &block.children {
        match child {
            Node::Directive(directive) => comment_directive(directive, comments),
            Node::Block(block) => comment_block(block, comments, reason),
        }
    }
    comment_block_boundary(block, false, comments, "end of unmapped block");
}

fn comment_block_boundary(block: &Block, opening: bool, comments: &mut Vec<String>, reason: &str) {
    if opening {
        comments.push(format!("# BLOCK ({reason}) at {}", block.location));
        for line in block.raw_open.lines() {
            comments.push(format!("#   {}", line.trim()));
        }
    } else {
        comments.push(format!("#   {}", block.raw_close.trim()));
    }
}

fn write_strings(output: &mut String, values: &[String]) {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push_str(&yaml_string(value));
    }
    output.push(']');
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}
