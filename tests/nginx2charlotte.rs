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
        "project-charlotte-nginx2charlotte-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).unwrap();
    directory
}

#[test]
fn converts_recursive_includes_and_supported_server_directives() {
    let root = temp_dir();
    fs::create_dir_all(root.join("conf.d")).unwrap();
    fs::create_dir_all(root.join("sites/nested")).unwrap();
    fs::write(
        root.join("nginx.conf"),
        r#"user charlotte web;
events {}
http {
    log_format charlotte '$remote_addr - "$request" $status $bytes_sent $request_length';
    upstream backend {
        server 127.0.0.1:8080;
        server 127.0.0.1:8081;
    }
    include conf.d/*.conf;
    include sites;
    include optional-*.conf;
}
"#,
    )
    .unwrap();
    fs::write(
        root.join("conf.d/static.conf"),
        r#"server {
    listen 443 ssl;
    server_name .example.test;
    root /srv/www/example.test;
    index index.php index.html;
    ssl_certificate /etc/ssl/example.pem;
    ssl_certificate_key /etc/ssl/example.key;
    access_log /var/log/nginx/access.log charlotte;
    error_log /var/log/nginx/error.log warn;
    add_header X-Test "kept # as text";
    location / {
        autoindex on;
        try_files $uri $uri/ /index.php?$query_string;
    }
}
"#,
    )
    .unwrap();
    fs::write(
        root.join("sites/proxy.conf"),
        r#"server {
    server_name proxy.example.test;
    location / {
        proxy_pass http://backend/api;
        proxy_set_header Host $host;
        proxy_read_timeout 45s;
        proxy_ssl_trusted_certificate /etc/ssl/backend-ca.pem;
    }
}
"#,
    )
    .unwrap();
    fs::write(
        root.join("sites/nested/php.conf"),
        r"server {
    server_name php.example.test;
    root /srv/php;
    location ~ \.php$ {
        fastcgi_pass unix:/run/php.sock;
        fastcgi_read_timeout 2m;
    }
}
",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_nginx2charlotte"))
        .arg(root.join("nginx.conf"))
        .arg("--prefix")
        .arg(&root)
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
    assert_eq!(hosts.len(), 3);

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
    assert_eq!(static_host["root"], "/srv/www/example.test");
    assert_eq!(static_host["user"], "charlotte");
    assert_eq!(static_host["group"], "web");
    assert_eq!(static_host["index"], "index.php");
    assert_eq!(static_host["listing"], true);
    assert_eq!(static_host["tls_cert"], "/etc/ssl/example.pem");
    assert_eq!(static_host["tls_key"], "/etc/ssl/example.key");
    assert_eq!(static_host["access_log"], "/var/log/nginx/access.log");
    assert_eq!(static_host["access_log_format"], "%a - \"%r\" %s %O %I");
    assert_eq!(static_host["error_log"], "/var/log/nginx/error.log");
    assert_eq!(
        static_host["try_files"],
        serde_yaml_ng::Value::Sequence(vec![
            serde_yaml_ng::Value::String("$uri".to_owned()),
            serde_yaml_ng::Value::String("$uri/".to_owned()),
            serde_yaml_ng::Value::String("/index.php?$query_string".to_owned()),
        ])
    );

    let proxy_host = find_host("proxy.example.test");
    assert_eq!(proxy_host["proxy_pass"], "http://127.0.0.1:8080/api");
    assert_eq!(proxy_host["proxy_preserve_host"], true);
    assert_eq!(proxy_host["proxy_timeout"], 45);
    assert_eq!(proxy_host["proxy_ca_root"], "/etc/ssl/backend-ca.pem");

    let php_host = find_host("php.example.test");
    assert_eq!(php_host["fastcgi"][0], "php=unix:/run/php.sock");
    assert_eq!(php_host["fastcgi_timeout"], 120);
    assert!(yaml.contains("add_header X-Test \"kept # as text\""));
    assert!(yaml.contains("--tls-bind"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn comments_out_catch_all_names_and_reports_malformed_syntax() {
    let root = temp_dir();
    fs::write(
        root.join("nginx.conf"),
        "http { server { listen 443 ssl; server_name _; } }\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nginx2charlotte"))
        .arg(root.join("nginx.conf"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let yaml = String::from_utf8(output.stdout).unwrap();
    assert!(yaml.contains("vhost: []"));
    assert!(yaml.contains("omitted server block"));
    assert!(yaml.contains("listen 443 ssl"));

    fs::write(root.join("broken.conf"), "http { server { listen 80 } }\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_nginx2charlotte"))
        .arg(root.join("broken.conf"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected ';'"));
    let _ = fs::remove_dir_all(root);
}
