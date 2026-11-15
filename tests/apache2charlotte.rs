use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
};

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
            "    DirectoryIndex index.php index.html\n",
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
    assert_eq!(static_host["index"], "index.php");
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
