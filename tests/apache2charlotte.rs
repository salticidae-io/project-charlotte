use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

use nix::unistd::{Gid, Group, Uid, User};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

fn temp_dir() -> PathBuf {
    let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "project-charlotte-apache2charlotte-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).unwrap();
    directory
}

#[test]
fn converts_recursive_includes_and_preserves_unmapped_directives() {
    let root = temp_dir();
    let nested = root.join("conf.d/nested");
    let optional = root.join("optional");
    fs::create_dir_all(&nested).unwrap();
    fs::create_dir_all(&optional).unwrap();
    fs::write(
        root.join("httpd.conf"),
        concat!(
            "ServerRoot \"\"\n",
            "User charlotte\n",
            "Group web\n",
            "LogFormat \"%h %r\" common\n",
            "Include conf.d\n",
            "IncludeOptional ${OPTIONAL_DIR}/*.conf\n",
            "<IfDefine ${FEATURE_NAME}>\n",
            "ConditionalDirective enabled\n",
            "</IfDefine>\n",
        ),
    )
    .unwrap();
    fs::write(
        root.join("conf.d/site.conf"),
        concat!(
            "<VirtualHost *:80>\n",
            "  ServerName example.test:80\n",
            "  ServerAlias www.example.test *.wild.example.test\n",
            "  DocumentRoot /srv/www/example.test\n",
            "  <Directory /srv/www/example.test/>\n",
            "    Options +Indexes -FollowSymLinks\n",
            "    DirectoryIndex index.php index.html /cgi-bin/list\n",
            "    FallbackResource /index.php\n",
            "  </Directory>\n",
            "  AddHandler cgi-script .cgi\n",
            "  ProxyPassMatch \\.php fcgi://127.0.0.1:9000\n",
            "  CustomLog logs/access.log common\n",
            "  ErrorLog logs/error.log\n",
            "  UnknownDirective \"kept # as text\"\n",
            "</VirtualHost>\n",
        ),
    )
    .unwrap();
    fs::write(
        nested.join("proxy.conf"),
        concat!(
            "<IfModule mod_proxy.c>\n",
            "<VirtualHost *:443>\n",
            "  ServerName proxy.example.test\n",
            "  ProxyPass / https://upstream.example.test/base\n",
            "  ProxyPreserveHost Off\n",
            "  ProxyTimeout 45\n",
            "</VirtualHost>\n",
            "</IfModule>\n",
        ),
    )
    .unwrap();
    fs::write(
        nested.join("fastcgi.conf"),
        concat!(
            "<VirtualHost *:80>\n",
            "  ServerName fastcgi.example.test\n",
            "  DocumentRoot /srv/www/fastcgi\n",
            "  <FilesMatch \"\\.php$\">\n",
            "    SetHandler \"proxy:unix:/run/php.sock|fcgi://localhost\"\n",
            "  </FilesMatch>\n",
            "</VirtualHost>\n",
        ),
    )
    .unwrap();
    fs::write(
        optional.join("extra.conf"),
        "<VirtualHost *:80>\nServerName optional.example.test\nProxyPass / http://127.0.0.1:8080\n</VirtualHost>\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_apache2charlotte"))
        .arg(root.join("httpd.conf"))
        .arg("-D")
        .arg("OPTIONAL_DIR=optional")
        .arg("-D")
        .arg("FEATURE_NAME=FEATURE_TEST")
        .arg("-D")
        .arg("FEATURE_TEST")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "converter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = String::from_utf8(output.stdout).unwrap();
    let document: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    let hosts = document["vhost"].as_sequence().unwrap();
    assert_eq!(hosts.len(), 4);

    let find_host = |name: &str| {
        hosts
            .iter()
            .find(|host| {
                host["server_names"].as_sequence().is_some_and(|names| {
                    names
                        .iter()
                        .any(|candidate| candidate.as_str() == Some(name))
                })
            })
            .unwrap_or_else(|| panic!("missing converted vhost {name}"))
    };
    let static_host = find_host("example.test");
    assert_eq!(
        static_host["server_names"],
        serde_yaml_ng::Value::Sequence(vec![
            serde_yaml_ng::Value::String("example.test".to_owned()),
            serde_yaml_ng::Value::String("www.example.test".to_owned()),
            serde_yaml_ng::Value::String("*.wild.example.test".to_owned()),
        ])
    );
    assert_eq!(static_host["root"], "/srv/www/example.test");
    assert_eq!(static_host["user"], "charlotte");
    assert_eq!(static_host["group"], "web");
    assert_eq!(static_host["listing"], true);
    assert_eq!(
        static_host["index"],
        serde_yaml_ng::Value::Sequence(vec![
            serde_yaml_ng::Value::String("index.php".to_owned()),
            serde_yaml_ng::Value::String("index.html".to_owned()),
        ])
    );
    assert!(yaml.contains("unsupported Apache DirectoryIndex entries were skipped"));
    assert_eq!(
        static_host["try_files"],
        serde_yaml_ng::Value::Sequence(vec![
            serde_yaml_ng::Value::String("$uri".to_owned()),
            serde_yaml_ng::Value::String("/index.php".to_owned()),
        ])
    );
    assert_eq!(static_host["access_log_format"], "%h %r");
    assert_eq!(static_host["fastcgi"][0], "php=127.0.0.1:9000");
    assert!(yaml.contains("UnknownDirective \"kept # as text\""));
    assert!(yaml.contains("ConditionalDirective enabled"));

    let proxy_host = find_host("proxy.example.test");
    assert_eq!(
        proxy_host["proxy_pass"],
        "https://upstream.example.test/base"
    );
    assert_eq!(proxy_host["proxy_preserve_host"], false);
    assert_eq!(proxy_host["proxy_timeout"], 45);
    let fastcgi_host = find_host("fastcgi.example.test");
    assert_eq!(fastcgi_host["fastcgi"][0], "php=unix:/run/php.sock");
    let optional_host = find_host("optional.example.test");
    assert_eq!(optional_host["server_names"][0], "optional.example.test");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn converts_fcgid_wrappers_nested_in_files_sections() {
    let root = temp_dir();
    fs::write(
        root.join("httpd.conf"),
        format!(
            concat!(
                "<VirtualHost *:80>\n",
                "  ServerName wrapped-directory.example.test\n",
                "  DocumentRoot {0}/www\n",
                "  <Directory {0}/www>\n",
                "    <Files ~ \"\\.php$\">\n",
                "      SetHandler fcgid-script\n",
                "      FCGIWrapper /usr/local/bin/php-wrapper .php\n",
                "    </Files>\n",
                "  </Directory>\n",
                "</VirtualHost>\n",
                "<VirtualHost *:80>\n",
                "  ServerName wrapped-quoted.example.test\n",
                "  DocumentRoot {0}/www\n",
                "  <Files \"*.php\">\n",
                "    SetHandler fcgid-script\n",
                "    FCGIWrapper \"/usr/bin/php-cgi -c /etc/php.ini\" virtual\n",
                "  </Files>\n",
                "</VirtualHost>\n",
                "<VirtualHost *:80>\n",
                "  ServerName wrapped-pattern.example.test\n",
                "  DocumentRoot {0}/www\n",
                "  <Files ~ \"\\.(php5?|phtml)$\">\n",
                "    AddHandler fcgid-script .php\n",
                "    FCGIWrapper /usr/bin/php-cgi\n",
                "  </Files>\n",
                "</VirtualHost>\n",
            ),
            root.display()
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_apache2charlotte"))
        .arg(root.join("httpd.conf"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "converter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = String::from_utf8(output.stdout).unwrap();
    let document: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    let hosts = document["vhost"].as_sequence().unwrap();
    let find_host = |name: &str| {
        hosts
            .iter()
            .find(|host| host["server_names"][0] == name)
            .unwrap_or_else(|| panic!("missing converted vhost {name}"))
    };

    let directory = find_host("wrapped-directory.example.test");
    assert_eq!(directory["fastcgi_app"][0]["extension"], "php");
    assert_eq!(
        directory["fastcgi_app"][0]["command"][0],
        "/usr/local/bin/php-wrapper"
    );

    let quoted = find_host("wrapped-quoted.example.test");
    assert_eq!(quoted["fastcgi_app"][0]["extension"], "php");
    assert_eq!(
        quoted["fastcgi_app"][0]["command"],
        serde_yaml_ng::Value::Sequence(vec![
            serde_yaml_ng::Value::String("/usr/bin/php-cgi".to_owned()),
            serde_yaml_ng::Value::String("-c".to_owned()),
            serde_yaml_ng::Value::String("/etc/php.ini".to_owned()),
        ])
    );
    assert!(yaml.contains("FCGIWrapper virtual flag was ignored"));

    let patterned = find_host("wrapped-pattern.example.test");
    let apps = patterned["fastcgi_app"].as_sequence().unwrap();
    for extension in ["php", "php5", "phtml"] {
        let app = apps
            .iter()
            .find(|app| app["extension"] == extension)
            .unwrap_or_else(|| panic!("missing FastCGI app for {extension}"));
        assert_eq!(app["command"][0], "/usr/bin/php-cgi");
    }
    assert!(
        !yaml.contains("# UNMAPPED"),
        "recognized FCGIWrapper directives should not be left unmapped:\n{yaml}"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn converts_common_php_handlers_and_global_php_configuration() {
    let root = temp_dir();
    fs::write(
        root.join("httpd.conf"),
        concat!(
            "<IfModule mod_proxy_fcgi.c>\n",
            "  <FilesMatch \".+\\.ph(?:ar|p|tml)$\">\n",
            "    SetHandler \"proxy:unix:/run/php/php8.2-fpm.sock|fcgi://localhost\"\n",
            "  </FilesMatch>\n",
            "  php_value max_execution_time 35\n",
            "</IfModule>\n",
            "<VirtualHost *:80>\n",
            "  ServerName global-php.example.test\n",
            "  DocumentRoot /srv/global-php\n",
            "</VirtualHost>\n",
            "<VirtualHost *:80>\n",
            "  ServerName proxy-path.example.test\n",
            "  DocumentRoot /srv/proxy-path\n",
            "  ProxyPassMatch ^/(.+\\.php)$ fcgi://127.0.0.1:9000/var/www/$1\n",
            "  AddType application/x-httpd-php .php\n",
            "  php_admin_value memory_limit 256M\n",
            "</VirtualHost>\n",
            "<VirtualHost *:80>\n",
            "  ServerName unix-handler.example.test\n",
            "  DocumentRoot /srv/unix-handler\n",
            "  AddHandler \"proxy:unix:/run/php/site.sock|fcgi://localhost\" .php\n",
            "</VirtualHost>\n",
            "<VirtualHost *:80>\n",
            "  ServerName mod-php.example.test\n",
            "  DocumentRoot /srv/mod-php\n",
            "  AddType application/x-httpd-php .php\n",
            "  php_admin_value memory_limit 128M\n",
            "  FcgidWrapper /usr/local/bin/late-wrapper .php\n",
            "</VirtualHost>\n",
            "<VirtualHost *:80>\n",
            "  ServerName fcgid.example.test\n",
            "  DocumentRoot /srv/fcgid\n",
            "  AddHandler fcgid-script .php\n",
            "  FcgidWrapper /usr/local/bin/php-fcgi .php\n",
            "  FcgidMaxProcessesPerClass 12\n",
            "  FcgidIdleTimeout 40\n",
            "  FcgidIOTimeout 90\n",
            "  FcgidBusyTimeout 100\n",
            "  FcgidInitialEnv FOO \"bar baz\"\n",
            "</VirtualHost>\n",
            "<VirtualHost *:80>\n",
            "  ServerName external.example.test\n",
            "  DocumentRoot /srv/external\n",
            "  FastCgiExternalServer /usr/lib/cgi-bin/php -host 127.0.0.1:9010 -idle-timeout 75\n",
            "</VirtualHost>\n",
            "<VirtualHost *:80>\n",
            "  ServerName external-socket.example.test\n",
            "  DocumentRoot /srv/external-socket\n",
            "  FastCgiExternalServer /usr/lib/cgi-bin/php -socket /run/php/fastcgi.sock\n",
            "</VirtualHost>\n",
            "<VirtualHost *:80>\n",
            "  ServerName proxy-pass.example.test\n",
            "  DocumentRoot /srv/proxy-pass\n",
            "  ProxyPass /index.php fcgi://127.0.0.1:9020/var/www/index.php\n",
            "</VirtualHost>\n",
            "<VirtualHost *:80>\n",
            "  ServerName location-handler.example.test\n",
            "  DocumentRoot /srv/location-handler\n",
            "  <Files \"*.php\">\n",
            "    AddHandler proxy:fcgi://127.0.0.1:9040 .php\n",
            "  </Files>\n",
            "  <Location ~ \\.php$>\n",
            "    SetHandler proxy:fcgi://127.0.0.1:9030\n",
            "  </Location>\n",
            "</VirtualHost>\n",
            "<VirtualHost *:80>\n",
            "  ServerName suphp.example.test\n",
            "  DocumentRoot /srv/suphp\n",
            "  suPHP_UserGroup siteuser sitegroup\n",
            "  suPHP_AddHandler x-httpd-php .php\n",
            "</VirtualHost>\n",
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_apache2charlotte"))
        .arg(root.join("httpd.conf"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "converter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = String::from_utf8(output.stdout).unwrap();
    let document: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    let hosts = document["vhost"].as_sequence().unwrap();
    assert_eq!(hosts.len(), 10);
    let find_host = |name: &str| {
        hosts
            .iter()
            .find(|host| {
                host["server_names"].as_sequence().is_some_and(|names| {
                    names
                        .iter()
                        .any(|candidate| candidate.as_str() == Some(name))
                })
            })
            .unwrap_or_else(|| panic!("missing converted vhost {name}"))
    };

    let global = find_host("global-php.example.test");
    let global_backends = global["fastcgi"].as_sequence().unwrap();
    for extension in ["phar", "php", "phtml"] {
        assert!(global_backends.iter().any(|backend| {
            backend.as_str().is_some_and(|backend| {
                backend == format!("{extension}=unix:/run/php/php8.2-fpm.sock")
            })
        }));
    }
    assert!(yaml.contains("Applied global Apache PHP handler settings"));
    assert!(yaml.contains("add this to the PHP-FPM pool as php_value[name] = value"));

    let proxy_path = find_host("proxy-path.example.test");
    assert_eq!(proxy_path["fastcgi"][0], "php=127.0.0.1:9000");
    assert!(proxy_path.get("fastcgi_app").is_none());
    assert!(yaml.contains("SCRIPT_FILENAME document path was not preserved"));
    assert!(yaml.contains("php_admin_value memory_limit 256M"));

    let unix_handler = find_host("unix-handler.example.test");
    assert_eq!(unix_handler["fastcgi"][0], "php=unix:/run/php/site.sock");

    let mod_php = find_host("mod-php.example.test");
    assert!(mod_php.get("fastcgi_app").is_none());
    assert!(
        yaml.contains("Skipped FastCGI app for php: command php-cgi is not a fully-qualified path")
    );
    assert!(yaml.contains("php_admin_value memory_limit 128M"));
    assert!(yaml.contains("FcgidWrapper for php was ignored"));

    let fcgid = find_host("fcgid.example.test");
    assert_eq!(
        fcgid["fastcgi_app"][0]["command"][0],
        "/usr/local/bin/php-fcgi"
    );
    assert_eq!(fcgid["fastcgi_app"][0]["max_workers"], 12);
    assert_eq!(fcgid["fastcgi_app"][0]["idle_timeout"], 40);
    assert_eq!(fcgid["fastcgi_app"][0]["env"]["FOO"], "bar baz");
    assert_eq!(fcgid["fastcgi_timeout"], 100);

    let external = find_host("external.example.test");
    assert_eq!(external["fastcgi"][0], "php=127.0.0.1:9010");
    assert_eq!(external["fastcgi_timeout"], 75);

    let external_socket = find_host("external-socket.example.test");
    assert_eq!(
        external_socket["fastcgi"][0],
        "php=unix:/run/php/fastcgi.sock"
    );

    let proxy_pass = find_host("proxy-pass.example.test");
    assert_eq!(proxy_pass["fastcgi"][0], "php=127.0.0.1:9020");
    assert!(yaml.contains("SCRIPT_FILENAME document path was not preserved"));

    let location_handler = find_host("location-handler.example.test");
    assert_eq!(location_handler["fastcgi"][0], "php=127.0.0.1:9040");
    assert!(
        yaml.contains(
            "Later Fastcgi handler for extension php was overridden by the first handler"
        )
    );

    let suphp = find_host("suphp.example.test");
    assert_eq!(suphp["user"], "siteuser");
    assert_eq!(suphp["group"], "sitegroup");
    assert!(suphp.get("fastcgi_app").is_none());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn skips_fastcgi_apps_without_absolute_commands() {
    let root = temp_dir();
    fs::write(
        root.join("httpd.conf"),
        concat!(
            "<VirtualHost *:80>\n",
            "  ServerName mod-php-bare.example.test\n",
            "  DocumentRoot /srv/mod-php-bare\n",
            "  AddType application/x-httpd-php .php\n",
            "  php_admin_value memory_limit 64M\n",
            "</VirtualHost>\n",
            "<VirtualHost *:80>\n",
            "  ServerName absolute-wrapper.example.test\n",
            "  DocumentRoot /srv/absolute-wrapper\n",
            "  FcgidWrapper /usr/local/bin/php-cgi .php\n",
            "</VirtualHost>\n",
            "<VirtualHost *:80>\n",
            "  ServerName relative-wrapper.example.test\n",
            "  DocumentRoot /srv/relative-wrapper\n",
            "  FcgidWrapper bin/php-cgi .php\n",
            "</VirtualHost>\n",
            "<VirtualHost *:80>\n",
            "  ServerName explicit-backend.example.test\n",
            "  DocumentRoot /srv/explicit-backend\n",
            "  AddType application/x-httpd-php .php\n",
            "  ProxyPassMatch ^/(.+\\.php)$ fcgi://127.0.0.1:9000/var/www/$1\n",
            "</VirtualHost>\n",
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_apache2charlotte"))
        .arg(root.join("httpd.conf"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "converter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = String::from_utf8(output.stdout).unwrap();
    let document: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    let hosts = document["vhost"].as_sequence().unwrap();
    let find_host = |name: &str| {
        hosts
            .iter()
            .find(|host| host["server_names"][0] == name)
            .unwrap_or_else(|| panic!("missing converted vhost {name}"))
    };

    let mod_php = find_host("mod-php-bare.example.test");
    assert!(mod_php.get("fastcgi_app").is_none());
    assert!(
        yaml.contains("Skipped FastCGI app for php: command php-cgi is not a fully-qualified path")
    );
    assert!(yaml.contains(
        "UNMAPPED (Charlotte does not send PHP_VALUE to FastCGI servers; add this to the PHP-FPM pool as php_value[name] = value)"
    ));

    let absolute = find_host("absolute-wrapper.example.test");
    assert_eq!(
        absolute["fastcgi_app"][0]["command"][0],
        "/usr/local/bin/php-cgi"
    );

    let relative = find_host("relative-wrapper.example.test");
    assert!(relative.get("fastcgi_app").is_none());
    assert!(yaml.contains(
        "Skipped FastCGI app for php: command bin/php-cgi is not a fully-qualified path"
    ));

    let explicit = find_host("explicit-backend.example.test");
    assert_eq!(explicit["fastcgi"][0], "php=127.0.0.1:9000");
    assert!(explicit.get("fastcgi_app").is_none());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn escapes_line_breaks_and_control_characters_in_comments() {
    let root = temp_dir();
    fs::write(
        root.join("httpd.conf"),
        concat!(
            "UnknownTopLevel top\rreturn\u{85}next\u{2028}line\u{0c}page\u{1}start\r\n",
            "<VirtualHost *:80>\r\n",
            "  ServerName escaped.example.test\r\n",
            "  DocumentRoot /srv/escaped\r\n",
            "  UnknownVhost vhost\rreturn\u{85}next\u{2028}line\u{0c}page\u{1}start\r\n",
            "</VirtualHost>\r\n",
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_apache2charlotte"))
        .arg(root.join("httpd.conf"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "converter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = String::from_utf8(output.stdout).unwrap();
    let _: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    for escaped in [r"\u{D}", r"\u{85}", r"\u{2028}", r"\u{C}", r"\u{1}"] {
        assert!(
            yaml.contains(escaped),
            "missing escaped character {escaped}"
        );
    }
    assert!(yaml.contains("UnknownTopLevel"));
    assert!(yaml.contains("UnknownVhost"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn omits_comments_when_requested() {
    let root = temp_dir();
    fs::write(
        root.join("httpd.conf"),
        concat!(
            "<VirtualHost *:80>\n",
            "  ServerName no-comments.example.test\n",
            "  DocumentRoot /srv/no-comments\n",
            "  UnknownDirective retained only as a review comment\n",
            "</VirtualHost>\n",
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_apache2charlotte"))
        .arg(root.join("httpd.conf"))
        .arg("--no-comments")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "converter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = String::from_utf8(output.stdout).unwrap();
    assert!(
        yaml.lines().all(|line| !line.trim_start().starts_with('#')),
        "unexpected comment in output:\n{yaml}"
    );
    let document: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    let hosts = document["vhost"].as_sequence().unwrap();
    assert_eq!(hosts[0]["server_names"][0], "no-comments.example.test");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn takes_user_and_group_from_document_root_when_requested() {
    let root = temp_dir();
    let missing_root = root.join("missing-root");
    fs::write(
        root.join("httpd.conf"),
        format!(
            concat!(
                "User globaluser\n",
                "Group globalgroup\n",
                "<VirtualHost *:80>\n",
                "  ServerName root-owner.example.test\n",
                "  DocumentRoot {:?}\n",
                "</VirtualHost>\n",
                "<VirtualHost *:80>\n",
                "  ServerName missing-root.example.test\n",
                "  DocumentRoot {:?}\n",
                "</VirtualHost>\n",
            ),
            root, missing_root,
        ),
    )
    .unwrap();
    let metadata = fs::metadata(&root).unwrap();
    let expected_user = User::from_uid(Uid::from_raw(metadata.uid()))
        .unwrap()
        .unwrap()
        .name;
    let expected_group = Group::from_gid(Gid::from_raw(metadata.gid()))
        .unwrap()
        .unwrap()
        .name;

    let output = Command::new(env!("CARGO_BIN_EXE_apache2charlotte"))
        .arg(root.join("httpd.conf"))
        .arg("--user-from-root")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "converter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let yaml = String::from_utf8(output.stdout).unwrap();
    let document: serde_yaml_ng::Value = serde_yaml_ng::from_str(&yaml).unwrap();
    let hosts = document["vhost"].as_sequence().unwrap();
    let root_owner = hosts
        .iter()
        .find(|host| host["server_names"][0] == "root-owner.example.test")
        .unwrap();
    assert_eq!(root_owner["user"], expected_user);
    assert_eq!(root_owner["group"], expected_group);
    assert!(yaml.contains("replaced configured user value \"globaluser\""));
    assert!(yaml.contains("replaced configured group value \"globalgroup\""));
    let missing = hosts
        .iter()
        .find(|host| host["server_names"][0] == "missing-root.example.test")
        .unwrap();
    assert_eq!(missing["user"], "globaluser");
    assert_eq!(missing["group"], "globalgroup");
    assert!(yaml.contains("--user-from-root could not determine owner/group"));

    let _ = fs::remove_dir_all(root);
}

#[test]
#[cfg(feature = "hosting")]
fn converted_yaml_passes_charlotte_config_validation() {
    let root = temp_dir();
    let site = root.join("site");
    fs::create_dir_all(&site).unwrap();
    fs::write(site.join("index.html"), "converted config validation").unwrap();
    let apache_config = root.join("httpd.conf");
    let output_config = root.join("charlotte.yaml");
    fs::write(
        &apache_config,
        format!(
            "<VirtualHost *:80>\n  ServerName converted-apache.test\n  DocumentRoot {:?}\n</VirtualHost>\n",
            site.to_string_lossy()
        ),
    )
    .unwrap();

    let conversion = Command::new(env!("CARGO_BIN_EXE_apache2charlotte"))
        .arg(&apache_config)
        .arg("--user-from-root")
        .arg("--output")
        .arg(&output_config)
        .output()
        .unwrap();
    assert!(
        conversion.status.success(),
        "converter failed: {}",
        String::from_utf8_lossy(&conversion.stderr)
    );

    let validation = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .arg("--check-config")
        .arg("--config")
        .arg(&output_config)
        .output()
        .unwrap();
    assert!(
        validation.status.success(),
        "converted configuration was rejected: {}",
        String::from_utf8_lossy(&validation.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&validation.stdout).trim(),
        "Configuration OK"
    );
    let _ = fs::remove_dir_all(root);
}
