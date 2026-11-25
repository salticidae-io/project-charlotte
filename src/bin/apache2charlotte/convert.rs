use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Write as _,
    os::unix::fs::MetadataExt,
    path::Path,
};

use nix::unistd::{Gid, Group, Uid, User};

use super::parse::{Directive, Node, Section};

#[derive(Clone, Debug)]
enum Value {
    String(String),
    Bool(bool),
    Number(u64),
    Strings(Vec<String>),
    Apps(Vec<serde_json::Value>),
}

#[derive(Default)]
struct VirtualHost {
    names: Vec<String>,
    fields: BTreeMap<String, Value>,
    comments: Vec<String>,
    php_ini: Vec<(Directive, Option<String>)>,
    app_handlers: HashMap<String, AppHandlerKind>,
    handler_order: Vec<(String, HandlerKind)>,
    fcgid_wrapper_extensions: HashSet<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppHandlerKind {
    DirectApp,
    Fcgid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandlerKind {
    Fastcgi,
    App,
}

pub(super) fn convert(nodes: &[Node], include_comments: bool, user_from_root: bool) -> String {
    let mut comments = vec![
        "# Converted from Apache configuration. Review all TODO and unmapped directives.".to_owned(),
        "# Global Apache settings are retained below as comments; configure listener and process settings with Charlotte's command-line options.".to_owned(),
    ];
    let mut global_user = None;
    let mut global_group = None;
    let mut log_formats = HashMap::new();
    let mut global_php = Vec::new();
    collect_global_settings(nodes, &mut global_user, &mut global_group, &mut log_formats);
    collect_global_php(nodes, None, &mut global_php);
    let mut vhosts = Vec::new();
    convert_global_nodes(
        nodes,
        &mut comments,
        &mut vhosts,
        global_user.as_deref(),
        global_group.as_deref(),
        &log_formats,
        &global_php,
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
        if user_from_root {
            apply_root_owner(&mut host);
        }
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
    if include_comments {
        for comment in comments {
            write_comment(&mut output, "", &comment);
        }
    }
    if output_hosts.is_empty() {
        output.push_str("vhost: []\n");
        return output;
    }
    output.push_str("vhost:\n");
    for host in output_hosts {
        if include_comments {
            for comment in host.comments {
                write_comment(&mut output, "  ", &comment);
            }
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
                Value::Apps(values) => output
                    .push_str(&serde_json::to_string(&values).unwrap_or_else(|_| "[]".to_owned())),
            }
            output.push('\n');
        }
    }
    output
}

fn apply_root_owner(host: &mut VirtualHost) {
    let Some(Value::String(root)) = host.fields.get("root") else {
        return;
    };
    let Ok(metadata) = std::fs::metadata(root) else {
        comment_root_owner_unavailable(host);
        return;
    };
    let owner = User::from_uid(Uid::from_raw(metadata.uid()));
    let group = Group::from_gid(Gid::from_raw(metadata.gid()));
    let (Ok(Some(owner)), Ok(Some(group))) = (owner, group) else {
        comment_root_owner_unavailable(host);
        return;
    };
    set_root_identity(host, "user", owner.name);
    set_root_identity(host, "group", group.name);
}

fn set_root_identity(host: &mut VirtualHost, field: &str, value: String) {
    if let Some(Value::String(previous)) =
        host.fields.insert(field.to_owned(), Value::String(value))
    {
        host.comments.push(format!(
            "# --user-from-root replaced configured {field} value {previous:?} with the root directory owner."
        ));
    }
}

fn comment_root_owner_unavailable(host: &mut VirtualHost) {
    host.comments.push(
        "# --user-from-root could not determine owner/group for the root; existing user and group values were kept."
            .to_owned(),
    );
}

fn convert_global_nodes(
    nodes: &[Node],
    comments: &mut Vec<String>,
    vhosts: &mut Vec<VirtualHost>,
    global_user: Option<&str>,
    global_group: Option<&str>,
    log_formats: &HashMap<String, String>,
    global_php: &[GlobalPhpDirective],
) {
    for node in nodes {
        match node {
            Node::Directive(directive) => comment_directive(directive, comments),
            Node::Section(section) if section.name.eq_ignore_ascii_case("VirtualHost") => {
                let mut host = convert_vhost(section, global_user, global_group, log_formats);
                apply_global_php(&mut host, global_php);
                finalize_php_handlers_and_ini(&mut host);
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
                    global_php,
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

#[derive(Clone)]
struct GlobalPhpDirective {
    directive: Directive,
    pattern: Option<String>,
}

fn collect_global_php(
    nodes: &[Node],
    pattern: Option<String>,
    directives: &mut Vec<GlobalPhpDirective>,
) {
    for node in nodes {
        match node {
            Node::Directive(directive) if is_php_directive(&directive.name) => {
                directives.push(GlobalPhpDirective {
                    directive: directive.clone(),
                    pattern: pattern.clone(),
                });
            }
            Node::Directive(_) => {}
            Node::Section(section) if section.name.eq_ignore_ascii_case("VirtualHost") => {}
            Node::Section(section) => {
                let nested_pattern = section_pattern(section).or(pattern.clone());
                collect_global_php(&section.children, nested_pattern, directives);
            }
        }
    }
}

fn is_php_directive(name: &str) -> bool {
    let name = canonical_directive_name(name);
    matches!(
        name.as_str(),
        "addhandler"
            | "addtype"
            | "sethandler"
            | "proxypass"
            | "proxypassmatch"
            | "fastcgiexternalserver"
            | "fcgidwrapper"
            | "fcgidmaxprocessesperclass"
            | "fcgidmaxprocesses"
            | "fcgididletimeout"
            | "fcgidiotimeout"
            | "fcgidbusytimeout"
            | "fcgidinitialenv"
            | "php_value"
            | "php_flag"
            | "php_admin_value"
            | "php_admin_flag"
            | "suphp_addhandler"
            | "suphp_engine"
    )
}

fn canonical_directive_name(name: &str) -> String {
    let lowercase = name.to_ascii_lowercase();
    match lowercase.as_str() {
        "fcgiwrapper" => "fcgidwrapper".to_owned(),
        "maxprocesscount" => "fcgidmaxprocesses".to_owned(),
        "defaultmaxclassprocesscount" => "fcgidmaxprocessesperclass".to_owned(),
        "ipccommtimeout" => "fcgidiotimeout".to_owned(),
        "busytimeout" => "fcgidbusytimeout".to_owned(),
        "defaultinitenv" => "fcgidinitialenv".to_owned(),
        "idletimeout" => "fcgididletimeout".to_owned(),
        _ => lowercase,
    }
}

fn section_pattern(section: &Section) -> Option<String> {
    if section.name.eq_ignore_ascii_case("Files") || section.name.eq_ignore_ascii_case("FilesMatch")
    {
        let pattern = section.args.first()?;
        return Some(if pattern == "~" {
            section.args.get(1)?.clone()
        } else {
            pattern.clone()
        });
    }
    if section.name.eq_ignore_ascii_case("Location") {
        let args = section
            .args
            .strip_prefix(&["~".to_owned()])
            .unwrap_or(&section.args);
        let value = args.join(" ");
        if value.contains("\\.") || value.contains(".php") || value.contains("*.php") {
            return Some(value);
        }
    }
    None
}

fn apply_global_php(host: &mut VirtualHost, directives: &[GlobalPhpDirective]) {
    if !host.fields.contains_key("root") || has_php_handler(host) {
        return;
    }
    let applicable: Vec<_> = directives
        .iter()
        .filter(|item| {
            !matches!(
                item.directive.name.to_ascii_lowercase().as_str(),
                "php_value" | "php_flag" | "php_admin_value" | "php_admin_flag"
            )
        })
        .collect();
    let has_ini = directives.iter().any(|item| {
        matches!(
            item.directive.name.to_ascii_lowercase().as_str(),
            "php_value" | "php_flag" | "php_admin_value" | "php_admin_flag"
        )
    });
    if applicable.is_empty() && !has_ini {
        return;
    }
    host.comments.push(
        "# Applied global Apache PHP handler settings because this vhost has a root and no PHP handler of its own."
            .to_owned(),
    );
    for item in &applicable {
        let pattern = item.pattern.as_deref();
        if !convert_directive(&item.directive, host, &HashMap::new(), None, pattern) {
            comment_directive(&item.directive, &mut host.comments);
        }
    }
    for item in directives.iter().filter(|item| {
        matches!(
            item.directive.name.to_ascii_lowercase().as_str(),
            "php_value" | "php_flag" | "php_admin_value" | "php_admin_flag"
        )
    }) {
        host.php_ini
            .push((item.directive.clone(), item.pattern.clone()));
    }
}

fn has_php_handler(host: &VirtualHost) -> bool {
    let fastcgi_has_php = matches!(host.fields.get("fastcgi"), Some(Value::Strings(values)) if values.iter().any(|value| value.split_once('=').is_some_and(|(extension, _)| is_php_extension(extension))));
    let app_has_php = matches!(host.fields.get("fastcgi_app"), Some(Value::Apps(values)) if values.iter().any(|app| app.get("extension").and_then(serde_json::Value::as_str).is_some_and(is_php_extension)));
    fastcgi_has_php || app_has_php
}

fn is_php_extension(extension: &str) -> bool {
    let extension = extension.to_ascii_lowercase();
    extension.starts_with("php") || matches!(extension.as_str(), "phtml" | "phar" | "phps")
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
                    let pattern = section_pattern(section);
                    comment_section_boundary(section, true, &mut host.comments);
                    convert_nodes(
                        &section.children,
                        host,
                        log_formats,
                        document_root,
                        pattern.as_deref(),
                    );
                    comment_section_boundary(section, false, &mut host.comments);
                } else if section.name.eq_ignore_ascii_case("Files")
                    || section.name.eq_ignore_ascii_case("Location")
                    || section.name.eq_ignore_ascii_case("IfModule")
                    || section.name.eq_ignore_ascii_case("IfDefine")
                    || section.name.to_ascii_lowercase().starts_with("if")
                {
                    let nested_pattern =
                        section_pattern(section).or_else(|| files_match.map(str::to_owned));
                    comment_section_boundary(section, true, &mut host.comments);
                    convert_nodes(
                        &section.children,
                        host,
                        log_formats,
                        document_root,
                        nested_pattern.as_deref(),
                    );
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
    match canonical_directive_name(&directive.name).as_str() {
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
        "assignuserid" | "suexecusergroup" | "ruidgid" | "suphp_usergroup" if args.len() >= 2 => {
            set_string(host, "user", value);
            set_string(host, "group", &args[1]);
            true
        }
        "directoryindex" => {
            let (indexes, skipped) = convert_index_names(args);
            if !indexes.is_empty() {
                set_strings(host, "index", indexes);
            }
            if !skipped.is_empty() {
                comment_directive_with_reason(
                    directive,
                    "Charlotte supports bare index file names; unsupported Apache DirectoryIndex entries were skipped",
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
        "sslcertificatechainfile" => {
            set_string(host, "tls_chain", value);
            true
        }
        "proxypass" if args.len() >= 2 && value == "/" => {
            set_string(host, "proxy_pass", &args[1]);
            true
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
        "proxypassmatch" | "proxypass" => {
            if let Some((backends, document_path)) = parse_proxy_fcgi(args) {
                for backend in backends {
                    append_fastcgi_backend(host, backend);
                }
                if document_path {
                    host.comments.push(
                        "# TODO: Apache's FastCGI SCRIPT_FILENAME document path was not preserved; Charlotte derives it from root."
                            .to_owned(),
                    );
                }
                true
            } else {
                let reason = if directive.name.eq_ignore_ascii_case("ProxyPass") {
                    "path-specific ProxyPass rules require a PHP FastCGI target to be converted"
                } else {
                    "only PHP FastCGI ProxyPassMatch rules can be converted"
                };
                comment_directive_with_reason(directive, reason, &mut host.comments);
                true
            }
        }
        "sethandler" => {
            if let Some(pattern) = files_match
                && let Some(address) = parse_sethandler_fcgi(value)
            {
                let extensions = php_extensions(pattern);
                if extensions.is_empty() {
                    comment_directive_with_reason(
                        directive,
                        "could not infer a PHP extension from this handler section",
                        &mut host.comments,
                    );
                } else {
                    append_fastcgi(host, &extensions, &address);
                }
                true
            } else if let Some(pattern) = files_match
                && value.eq_ignore_ascii_case("fcgid-script")
            {
                let extensions = php_extensions(pattern);
                if extensions.is_empty() {
                    comment_directive_with_reason(
                        directive,
                        "could not infer a PHP extension from this handler section",
                        &mut host.comments,
                    );
                } else {
                    register_fcgid_handler(host, &extensions);
                }
                true
            } else if let Some(pattern) = files_match
                && is_php_handler(value)
            {
                let extensions = php_extensions(pattern);
                if extensions.is_empty() {
                    comment_directive_with_reason(
                        directive,
                        "could not infer a PHP extension from this handler section",
                        &mut host.comments,
                    );
                } else {
                    add_php_app(host, &extensions, "php-cgi");
                    host.comments.push(
                        "# TODO: mod_php was converted to a spawned php-cgi FastCGI app; verify the installed executable and PHP runtime configuration."
                            .to_owned(),
                    );
                }
                true
            } else {
                comment_directive_with_reason(
                    directive,
                    "SetHandler requires a PHP Files/FilesMatch/Location context and a supported PHP handler",
                    &mut host.comments,
                );
                true
            }
        }
        "addhandler" | "addtype" if args.len() >= 2 => {
            let extensions = args[1..]
                .iter()
                .flat_map(|pattern| php_extensions(pattern))
                .collect::<Vec<_>>();
            if let Some(address) = parse_sethandler_fcgi(value) {
                if extensions.is_empty() {
                    comment_directive_with_reason(
                        directive,
                        "could not infer a PHP extension from AddHandler/AddType",
                        &mut host.comments,
                    );
                } else {
                    append_fastcgi(host, &extensions, &address);
                }
                true
            } else if is_php_handler(value) || is_php_mime_type(value) {
                if extensions.is_empty() {
                    comment_directive_with_reason(
                        directive,
                        "could not infer a PHP extension from AddHandler/AddType",
                        &mut host.comments,
                    );
                } else {
                    add_php_app(host, &extensions, "php-cgi");
                    host.comments.push(
                        "# TODO: mod_php was converted to a spawned php-cgi FastCGI app; verify the installed executable and PHP runtime configuration."
                            .to_owned(),
                    );
                }
                true
            } else if directive.name.eq_ignore_ascii_case("AddHandler")
                && value.eq_ignore_ascii_case("cgi-script")
            {
                for extension in &args[1..] {
                    append_string(host, "cgi", extension.trim_start_matches('.').to_owned());
                }
                true
            } else if value.eq_ignore_ascii_case("fcgid-script") {
                if !extensions.is_empty() {
                    register_fcgid_handler(host, &extensions);
                } else {
                    comment_directive_with_reason(
                        directive,
                        "could not infer a PHP extension for this fcgid-script handler",
                        &mut host.comments,
                    );
                }
                true
            } else {
                false
            }
        }
        "suphp_addhandler" if args.len() >= 1 => {
            let mut extensions = args
                .iter()
                .flat_map(|arg| php_extensions(arg))
                .collect::<Vec<_>>();
            if extensions.is_empty() {
                extensions.push("php".to_owned());
            }
            add_php_app(host, &extensions, "php-cgi");
            true
        }
        "suphp_engine" if value.eq_ignore_ascii_case("on") => {
            add_php_app(host, &["php".to_owned()], "php-cgi");
            true
        }
        "rmode" => {
            comment_directive_with_reason(
                directive,
                "mod_ruid2 execution mode has no direct Charlotte equivalent; review worker user/group",
                &mut host.comments,
            );
            true
        }
        "fastcgiexternalserver" => convert_fastcgi_external_server(directive, host),
        "fcgidwrapper" => convert_fcgid_wrapper(directive, host, files_match),
        "fcgidmaxprocessesperclass" | "fcgidmaxprocesses" => {
            set_app_number(directive, host, files_match, "max_workers");
            true
        }
        "fcgididletimeout" => {
            set_app_number(directive, host, files_match, "idle_timeout");
            true
        }
        "fcgidiotimeout" | "fcgidbusytimeout" => {
            set_number_from_directive(directive, host, "fastcgi_timeout");
            true
        }
        "fcgidinitialenv" => {
            set_app_env(directive, host, files_match);
            true
        }
        "php_value" | "php_flag" | "php_admin_value" | "php_admin_flag" => {
            host.php_ini
                .push((directive.clone(), files_match.map(str::to_owned)));
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

fn parse_proxy_fcgi(args: &[String]) -> Option<(Vec<String>, bool)> {
    let extensions = php_extensions(args.first()?);
    if extensions.is_empty() {
        return None;
    }
    let (address, has_document_path) = parse_fcgi_target(args.get(1)?)?;
    Some((
        extensions
            .into_iter()
            .map(|extension| format!("{extension}={address}"))
            .collect(),
        has_document_path,
    ))
}

fn parse_fcgi_target(target: &str) -> Option<(String, bool)> {
    let target = target.strip_prefix("proxy:").unwrap_or(target);
    if let Some(rest) = target.strip_prefix("unix:") {
        let (socket, fcgi) = rest.split_once("|fcgi://")?;
        let (_, path) = fcgi.split_once('/').unwrap_or((fcgi, ""));
        return Some((format!("unix:{socket}"), !path.is_empty()));
    }
    let rest = target.strip_prefix("fcgi://")?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty() {
        return None;
    }
    Some((authority.to_owned(), !path.is_empty()))
}

fn parse_sethandler_fcgi(value: &str) -> Option<String> {
    parse_fcgi_target(value).map(|(address, _)| address)
}

fn php_extensions(pattern: &str) -> Vec<String> {
    let lowercase = pattern.to_ascii_lowercase();
    let marker = lowercase
        .find("\\.")
        .map(|index| index + 2)
        .or_else(|| lowercase.find("*.").map(|index| index + 2))
        .or_else(|| lowercase.find('.').map(|index| index + 1));
    let Some(marker) = marker else {
        return Vec::new();
    };
    let suffix = &lowercase[marker..];
    let group = suffix.find('(');
    let prefix_end = group.unwrap_or_else(|| {
        suffix
            .find(|character: char| !character.is_ascii_alphanumeric())
            .unwrap_or(suffix.len())
    });
    let prefix = &suffix[..prefix_end];
    let mut extensions = Vec::new();
    if let Some(open) = group {
        let prefix = &suffix[..open];
        let alternatives = suffix[open..]
            .strip_prefix("(?:")
            .or_else(|| suffix[open..].strip_prefix('('));
        if let Some(alternatives) = alternatives
            && let Some((alternatives, rest)) = alternatives.split_once(')')
        {
            for alternative in alternatives.split('|') {
                append_php_extension_alternative(prefix, alternative, &mut extensions);
            }
            if let Some(digits) = optional_digit_class(rest) {
                let alternatives = extensions.clone();
                for extension in alternatives {
                    extensions.extend(digits.iter().map(|digit| format!("{extension}{digit}")));
                }
            }
        }
    } else if !prefix.is_empty() {
        append_optional_literal_digit(prefix, &suffix[prefix_end..], &mut extensions);
        extensions.push(prefix.to_owned());
        let rest = &suffix[prefix_end..];
        if let Some(digits) = optional_digit_class(rest) {
            extensions.extend(digits.iter().map(|digit| format!("{prefix}{digit}")));
        }
    }
    extensions.retain(|extension| {
        extension.starts_with("php") || matches!(extension.as_str(), "phtml" | "phar" | "phps")
    });
    let mut seen = HashSet::new();
    extensions.retain(|extension| seen.insert(extension.clone()));
    extensions
}

fn append_php_extension_alternative(prefix: &str, alternative: &str, extensions: &mut Vec<String>) {
    let literal: String = alternative
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric())
        .collect();
    if literal.is_empty() {
        return;
    }
    let extension = format!("{prefix}{literal}");
    let rest = &alternative[literal.len()..];
    append_optional_literal_digit(&extension, rest, extensions);
    extensions.push(extension.clone());
    if let Some(digits) = optional_digit_class(rest) {
        extensions.extend(digits.iter().map(|digit| format!("{extension}{digit}")));
    }
}

fn append_optional_literal_digit(extension: &str, rest: &str, extensions: &mut Vec<String>) {
    if rest.starts_with('?')
        && extension
            .chars()
            .last()
            .is_some_and(|character| character.is_ascii_digit())
    {
        extensions.push(extension[..extension.len() - 1].to_owned());
    }
}

fn optional_digit_class(value: &str) -> Option<Vec<u8>> {
    let class = value.strip_prefix('[')?;
    let (class, suffix) = class.split_once(']')?;
    if !suffix.starts_with('?') {
        return None;
    }
    if let Some((start, end)) = class.split_once('-') {
        let (start, end) = (start.parse::<u8>().ok()?, end.parse::<u8>().ok()?);
        if start > end || end - start > 12 {
            return None;
        }
        return Some((start..=end).collect());
    }
    let digits: Vec<_> = class
        .chars()
        .map(|character| {
            character
                .to_digit(10)
                .and_then(|digit| u8::try_from(digit).ok())
        })
        .collect::<Option<_>>()?;
    (!digits.is_empty()).then_some(digits)
}

fn append_fastcgi(host: &mut VirtualHost, extensions: &[String], address: &str) {
    for extension in extensions {
        append_fastcgi_backend(host, format!("{extension}={address}"));
    }
}

fn append_fastcgi_backend(host: &mut VirtualHost, backend: String) {
    if let Some((extension, _)) = backend.split_once('=') {
        host.handler_order
            .push((extension.to_ascii_lowercase(), HandlerKind::Fastcgi));
    }
    append_string(host, "fastcgi", backend);
}

fn ensure_app(host: &mut VirtualHost, extensions: &[String], command: &str) {
    let apps = host
        .fields
        .entry("fastcgi_app".to_owned())
        .or_insert_with(|| Value::Apps(Vec::new()));
    let Value::Apps(apps) = apps else {
        return;
    };
    for extension in extensions {
        let extension = extension.trim_start_matches('.').to_ascii_lowercase();
        if extension.is_empty()
            || apps.iter().any(|app| {
                app.get("extension")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|existing| existing.eq_ignore_ascii_case(&extension))
            })
        {
            continue;
        }
        apps.push(serde_json::json!({
            "extension": extension,
            "command": [command],
            "env": {},
        }));
    }
}

fn add_php_app(host: &mut VirtualHost, extensions: &[String], command: &str) {
    ensure_app(host, extensions, command);
    for extension in extensions {
        host.handler_order
            .push((extension.to_ascii_lowercase(), HandlerKind::App));
        host.app_handlers
            .entry(extension.to_ascii_lowercase())
            .or_insert(AppHandlerKind::DirectApp);
    }
}

fn register_fcgid_handler(host: &mut VirtualHost, extensions: &[String]) {
    ensure_app(host, extensions, "php-cgi");
    for extension in extensions {
        host.app_handlers
            .entry(extension.clone())
            .or_insert(AppHandlerKind::Fcgid);
        host.handler_order
            .push((extension.clone(), HandlerKind::App));
    }
}

fn app_extensions(pattern: Option<&str>) -> Vec<String> {
    pattern
        .map(php_extensions)
        .filter(|extensions| !extensions.is_empty())
        .unwrap_or_else(|| vec!["php".to_owned()])
}

fn convert_fastcgi_external_server(directive: &Directive, host: &mut VirtualHost) -> bool {
    let mut address = None;
    let mut timeout = None;
    let mut unsupported = Vec::new();
    let mut options = directive.args.iter();
    let _path = options.next();
    while let Some(option) = options.next() {
        match option.as_str() {
            "-host" => address = options.next().cloned(),
            "-socket" => address = options.next().map(|socket| format!("unix:{socket}")),
            "-idle-timeout" => timeout = options.next().and_then(|value| value.parse::<u64>().ok()),
            _ => unsupported.push(option.clone()),
        }
    }
    if let Some(address) = address {
        append_fastcgi(host, &["php".to_owned()], &address);
        if let Some(timeout) = timeout.filter(|timeout| *timeout > 0) {
            host.fields
                .insert("fastcgi_timeout".to_owned(), Value::Number(timeout));
        }
        if !unsupported.is_empty() {
            comment_directive_with_reason(
                directive,
                &format!(
                    "unsupported FastCgiExternalServer options: {}",
                    unsupported.join(" ")
                ),
                &mut host.comments,
            );
        }
    } else {
        comment_directive_with_reason(
            directive,
            "FastCgiExternalServer requires a supported -host or -socket target",
            &mut host.comments,
        );
    }
    true
}

fn convert_fcgid_wrapper(
    directive: &Directive,
    host: &mut VirtualHost,
    pattern: Option<&str>,
) -> bool {
    let Some(wrapper) = directive.args.first() else {
        return false;
    };
    let extensions_from_args: Vec<_> = directive.args[1..]
        .iter()
        .flat_map(|argument| php_extensions(argument))
        .collect();
    let extensions = if extensions_from_args.is_empty() {
        app_extensions(pattern)
    } else {
        extensions_from_args
    };
    let mut command = wrapper
        .split_whitespace()
        .map(|part| serde_json::Value::String(part.to_owned()))
        .collect::<Vec<_>>();
    command.extend(
        directive.args[1..]
            .iter()
            .filter(|argument| {
                !argument.eq_ignore_ascii_case("virtual") && php_extensions(argument).is_empty()
            })
            .cloned()
            .map(serde_json::Value::String),
    );
    if directive.args[1..]
        .iter()
        .any(|argument| argument.eq_ignore_ascii_case("virtual"))
    {
        host.comments.push(
            "# TODO: FCGIWrapper virtual flag was ignored because it has no Charlotte equivalent."
                .to_owned(),
        );
    }
    let allowed_extensions: Vec<_> = extensions
        .iter()
        .filter(|extension| {
            if host.app_handlers.get(*extension) == Some(&AppHandlerKind::DirectApp) {
                host.comments.push(format!(
                    "# FcgidWrapper for {extension} was ignored because an earlier PHP app handler takes precedence."
                ));
                false
            } else if host.fcgid_wrapper_extensions.contains(*extension) {
                host.comments.push(format!(
                    "# Later FcgidWrapper for {extension} was ignored; the first wrapper takes precedence."
                ));
                false
            } else {
                true
            }
        })
        .cloned()
        .collect();
    if allowed_extensions.is_empty() {
        return true;
    }
    ensure_app(host, &allowed_extensions, wrapper);
    if let Some(Value::Apps(apps)) = host.fields.get_mut("fastcgi_app") {
        for app in apps {
            if app
                .get("extension")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|extension| {
                    allowed_extensions
                        .iter()
                        .any(|candidate| candidate == extension)
                })
            {
                app["command"] = serde_json::Value::Array(command.clone());
            }
        }
    }
    for extension in allowed_extensions {
        if host.app_handlers.get(&extension) != Some(&AppHandlerKind::Fcgid) {
            host.handler_order
                .push((extension.clone(), HandlerKind::App));
        }
        host.fcgid_wrapper_extensions.insert(extension.clone());
        host.app_handlers.insert(extension, AppHandlerKind::Fcgid);
    }
    true
}

fn set_app_number(directive: &Directive, host: &mut VirtualHost, pattern: Option<&str>, key: &str) {
    let value = directive
        .args
        .first()
        .and_then(|value| value.parse::<u64>().ok());
    if let Some(value) = value.filter(|value| *value > 0) {
        let extensions = app_extensions(pattern);
        ensure_app(host, &extensions, "php-cgi");
        if let Some(Value::Apps(apps)) = host.fields.get_mut("fastcgi_app") {
            for app in apps {
                if app
                    .get("extension")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|extension| {
                        extensions.iter().any(|candidate| candidate == extension)
                    })
                {
                    app[key] = serde_json::json!(value);
                }
            }
        }
    } else {
        comment_directive_with_reason(
            directive,
            "expected a positive numeric value for the FastCGI app setting",
            &mut host.comments,
        );
    }
}

fn set_number_from_directive(directive: &Directive, host: &mut VirtualHost, key: &str) {
    if let Some(value) = directive
        .args
        .first()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
    {
        host.fields.insert(key.to_owned(), Value::Number(value));
    } else {
        comment_directive_with_reason(
            directive,
            "expected a positive timeout in seconds",
            &mut host.comments,
        );
    }
}

fn set_app_env(directive: &Directive, host: &mut VirtualHost, pattern: Option<&str>) {
    let Some((key, values)) = directive.args.split_first() else {
        return;
    };
    let value = values.join(" ");
    let extensions = app_extensions(pattern);
    ensure_app(host, &extensions, "php-cgi");
    if let Some(Value::Apps(apps)) = host.fields.get_mut("fastcgi_app") {
        for app in apps {
            if app
                .get("extension")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|extension| extensions.iter().any(|candidate| candidate == extension))
            {
                app["env"][key] = serde_json::Value::String(value.clone());
            }
        }
    }
}

fn finalize_php_handlers(host: &mut VirtualHost) {
    let pending = std::mem::take(&mut host.php_ini);
    for (directive, pattern) in pending {
        let extensions = app_extensions(pattern.as_deref());
        let name = directive.args.first().cloned().unwrap_or_default();
        let value = directive.args.get(1..).unwrap_or_default().join(" ");
        if name.is_empty() || value.is_empty() {
            comment_directive_with_reason(
                &directive,
                "PHP ini directives need a name and value",
                &mut host.comments,
            );
            continue;
        }
        let is_flag = matches!(
            directive.name.to_ascii_lowercase().as_str(),
            "php_flag" | "php_admin_flag"
        );
        let ini_value = if is_flag {
            match parse_on_off(&value) {
                Some(true) => "1",
                Some(false) => "0",
                None => {
                    comment_directive_with_reason(
                        &directive,
                        "PHP flag directives require On or Off",
                        &mut host.comments,
                    );
                    continue;
                }
            }
        } else {
            value.as_str()
        };
        let mut matched = false;
        if let Some(Value::Apps(apps)) = host.fields.get_mut("fastcgi_app") {
            for app in apps {
                if app
                    .get("extension")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|extension| {
                        extensions.iter().any(|candidate| candidate == extension)
                    })
                {
                    if let Some(command) = app
                        .get_mut("command")
                        .and_then(serde_json::Value::as_array_mut)
                    {
                        if !command.is_empty() {
                            command.push(serde_json::json!("-d"));
                            command.push(serde_json::json!(format!("{name}={ini_value}")));
                            matched = true;
                        }
                    }
                }
            }
        }
        if !matched {
            comment_directive_with_reason(
                &directive,
                "Charlotte does not send PHP_VALUE to FastCGI servers; add this to the PHP-FPM pool as php_value[name] = value",
                &mut host.comments,
            );
        }
    }
}

fn finalize_php_handlers_and_ini(host: &mut VirtualHost) {
    skip_unqualified_apps(host);
    let explicit_php_backend = matches!(host.fields.get("fastcgi"), Some(Value::Strings(backends)) if backends.iter().any(|backend| backend.split_once('=').is_some_and(|(extension, _)| extension.eq_ignore_ascii_case("php"))));
    let mut first_handlers = HashMap::new();
    let mut seen_extensions = HashSet::new();
    for (extension, kind) in &host.handler_order {
        first_handlers.entry(extension.clone()).or_insert(*kind);
        let repeated_extension = !seen_extensions.insert(extension.clone());
        if extension == "php" && explicit_php_backend {
            if *kind == HandlerKind::Fastcgi && repeated_extension {
                host.comments.push(format!(
                    "# Later {:?} handler for extension {extension} was overridden by the first handler.",
                    kind
                ));
            }
        } else if repeated_extension {
            host.comments.push(format!(
                "# Later {:?} handler for extension {extension} was overridden by the first handler.",
                kind
            ));
        }
    }
    let has_php_app = matches!(host.fields.get("fastcgi_app"), Some(Value::Apps(apps)) if apps.iter().any(|app| app.get("extension").and_then(serde_json::Value::as_str).is_some_and(|extension| extension.eq_ignore_ascii_case("php"))));
    if explicit_php_backend {
        first_handlers.insert("php".to_owned(), HandlerKind::Fastcgi);
        if has_php_app {
            host.comments.push(
                "# Spawned FastCGI app for php was overridden by the explicit FastCGI backend."
                    .to_owned(),
            );
        }
    }

    let mut seen_backends = HashSet::new();
    if let Some(Value::Strings(backends)) = host.fields.get_mut("fastcgi") {
        backends.retain(|backend| {
            let Some((extension, _)) = backend.split_once('=') else {
                return true;
            };
            let extension = extension.to_ascii_lowercase();
            first_handlers.get(&extension) != Some(&HandlerKind::App)
                && seen_backends.insert(extension)
        });
    }
    if let Some(Value::Apps(apps)) = host.fields.get_mut("fastcgi_app") {
        let mut seen_apps = HashSet::new();
        apps.retain(|app| {
            let Some(extension) = app.get("extension").and_then(serde_json::Value::as_str) else {
                return true;
            };
            let extension = extension.to_ascii_lowercase();
            !(explicit_php_backend && extension == "php")
                && first_handlers.get(&extension) != Some(&HandlerKind::Fastcgi)
                && seen_apps.insert(extension)
        });
    }
    if matches!(host.fields.get("fastcgi_app"), Some(Value::Apps(apps)) if apps.is_empty()) {
        host.fields.remove("fastcgi_app");
    }
    finalize_php_handlers(host);
}

fn skip_unqualified_apps(host: &mut VirtualHost) {
    let mut skipped_extensions = HashSet::new();
    let mut comments = Vec::new();
    if let Some(Value::Apps(apps)) = host.fields.get_mut("fastcgi_app") {
        apps.retain(|app| {
            let command_args = app
                .get("command")
                .and_then(serde_json::Value::as_array);
            let command = command_args
                .and_then(|command| command.first())
                .and_then(serde_json::Value::as_str);
            if command.is_some_and(|command| {
                !command.is_empty() && Path::new(command).is_absolute()
            }) {
                return true;
            }

            let extension = app
                .get("extension")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<unknown>");
            if extension != "<unknown>" {
                skipped_extensions.insert(extension.to_ascii_lowercase());
            }
            let command = match command {
                Some("") => "<empty>",
                Some(command) => command,
                None if command_args.is_some_and(Vec::is_empty) => "<empty>",
                None => "<missing>",
            };
            comments.push(format!(
                "# Skipped FastCGI app for {extension}: command {command} is not a fully-qualified path."
            ));
            false
        });
    }
    if matches!(host.fields.get("fastcgi_app"), Some(Value::Apps(apps)) if apps.is_empty()) {
        host.fields.remove("fastcgi_app");
    }
    host.handler_order.retain(|(extension, kind)| {
        *kind != HandlerKind::App || !skipped_extensions.contains(extension)
    });
    for extension in skipped_extensions {
        host.app_handlers.remove(&extension);
    }
    host.comments.extend(comments);
}

fn is_php_handler(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value == "php-script"
        || value.ends_with("-script") && value.starts_with("php")
        || value.starts_with("application/x-httpd-php")
}

fn is_php_mime_type(value: &str) -> bool {
    value
        .to_ascii_lowercase()
        .starts_with("application/x-httpd-php")
}

#[cfg(test)]
mod tests {
    use super::{
        AppHandlerKind, HandlerKind, Value, VirtualHost, php_extensions, skip_unqualified_apps,
        yaml_comment,
    };

    #[test]
    fn parses_common_php_regex_and_glob_extensions() {
        assert_eq!(php_extensions(r"\.php$"), ["php"]);
        assert_eq!(
            php_extensions(r".+\.ph(?:ar|p|tml)$"),
            ["phar", "php", "phtml"]
        );
        assert_eq!(
            php_extensions(r"\.ph(?:p[3-8]?|ar|tml)$"),
            [
                "php", "php3", "php4", "php5", "php6", "php7", "php8", "phar", "phtml"
            ]
        );
        assert_eq!(php_extensions(r"\.(php|phtml)"), ["php", "phtml"]);
        assert_eq!(php_extensions("*.php"), ["php"]);
    }

    #[test]
    fn expands_optional_php_version_classes() {
        assert_eq!(
            php_extensions(r"\.php[3-8]?"),
            ["php", "php3", "php4", "php5", "php6", "php7", "php8"]
        );
        assert_eq!(php_extensions(r"\.ph[3-8]?"), Vec::<String>::new());
    }

    #[test]
    fn escapes_yaml_line_breaks_and_non_printable_comment_characters() {
        assert_eq!(
            yaml_comment(
                "directive\r\n\u{85}\u{2028}\u{2029}\u{0c}\u{1}\t\u{feff}\u{fffe}\u{ffff}"
            ),
            "# directive\\u{D}\\u{A}\\u{85}\\u{2028}\\u{2029}\\u{C}\\u{1}\t\\u{FEFF}\\u{FFFE}\\u{FFFF}"
        );
        assert_eq!(yaml_comment("# already a comment"), "# already a comment");
    }

    #[test]
    fn skips_apps_with_missing_empty_or_relative_commands() {
        let mut host = VirtualHost::default();
        host.fields.insert(
            "fastcgi_app".to_owned(),
            Value::Apps(vec![
                serde_json::json!({"extension": "missing"}),
                serde_json::json!({"extension": "empty", "command": []}),
                serde_json::json!({"extension": "relative", "command": ["bin/php-cgi"]}),
                serde_json::json!({"extension": "absolute", "command": ["/usr/bin/php-cgi"]}),
            ]),
        );
        for extension in ["missing", "empty", "relative", "absolute"] {
            host.handler_order
                .push((extension.to_owned(), HandlerKind::App));
            host.app_handlers
                .insert(extension.to_owned(), AppHandlerKind::DirectApp);
        }

        skip_unqualified_apps(&mut host);

        let Some(Value::Apps(apps)) = host.fields.get("fastcgi_app") else {
            panic!("the absolute FastCGI app should be retained");
        };
        assert_eq!(apps.len(), 1);
        assert_eq!(apps[0]["extension"], "absolute");
        assert_eq!(
            host.handler_order,
            [("absolute".to_owned(), HandlerKind::App)]
        );
        assert_eq!(host.app_handlers.len(), 1);
        assert!(host.app_handlers.contains_key("absolute"));
        assert!(
            host.comments
                .iter()
                .any(|comment| comment.contains("command <missing>"))
        );
        assert!(
            host.comments
                .iter()
                .any(|comment| comment.contains("command <empty>"))
        );
        assert!(
            host.comments
                .iter()
                .any(|comment| comment.contains("command bin/php-cgi"))
        );
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

fn convert_index_names(names: &[String]) -> (Vec<String>, Vec<String>) {
    let mut indexes = Vec::new();
    let mut skipped = Vec::new();
    for name in names {
        if is_index_name(name) {
            indexes.push(name.clone());
        } else {
            skipped.push(name.clone());
        }
    }
    (indexes, skipped)
}

fn is_index_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && name != "."
        && name != ".."
        && !name.eq_ignore_ascii_case("disabled")
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

fn write_comment(output: &mut String, indent: &str, comment: &str) {
    output.push_str(indent);
    output.push_str(&yaml_comment(comment));
    output.push('\n');
}

fn yaml_comment(comment: &str) -> String {
    let mut escaped = String::with_capacity(comment.len());
    if !comment.starts_with('#') {
        escaped.push_str("# ");
    }
    for character in comment.chars() {
        if matches!(character, '\n' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
            || (character.is_control() && character != '\t')
            || matches!(character, '\u{feff}' | '\u{fffe}' | '\u{ffff}')
        {
            write!(escaped, "\\u{{{:X}}}", character as u32)
                .expect("writing to a String cannot fail");
        } else {
            escaped.push(character);
        }
    }
    escaped
}
