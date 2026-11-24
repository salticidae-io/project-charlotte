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
    index index.php index.html /index.php;
    ssl_certificate /etc/ssl/example.pem;
    ssl_certificate_key /etc/ssl/example.key;
    ssl_trusted_certificate /etc/ssl/ca-bundle.pem;
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
    assert_eq!(
        static_host["index"],
        serde_yaml_ng::Value::Sequence(vec![
            serde_yaml_ng::Value::String("index.php".to_owned()),
            serde_yaml_ng::Value::String("index.html".to_owned()),
        ])
    );
    assert!(yaml.contains("unsupported nginx index entries were skipped"));
    assert_eq!(static_host["listing"], true);
    assert_eq!(static_host["tls_cert"], "/etc/ssl/example.pem");
    assert_eq!(static_host["tls_key"], "/etc/ssl/example.key");
    assert!(yaml.contains("used for OCSP stapling or client-certificate verification"));
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

#[test]
fn omits_comments_when_requested() {
    let root = temp_dir();
    fs::write(
        root.join("nginx.conf"),
        concat!(
            "http {\n",
            "  server {\n",
            "    server_name no-comments.example.test;\n",
            "    root /srv/no-comments;\n",
            "    unknown_setting retained_as_a_review_comment;\n",
            "  }\n",
            "}\n",
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_nginx2charlotte"))
        .arg(root.join("nginx.conf"))
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
#[cfg(feature = "hosting")]
fn converted_yaml_passes_charlotte_config_validation() {
    let root = temp_dir();
    let site = root.join("site");
    fs::create_dir_all(&site).unwrap();
    fs::write(site.join("index.html"), "converted config validation").unwrap();
    let nginx_config = root.join("nginx.conf");
    let output_config = root.join("charlotte.yaml");
    fs::write(
        &nginx_config,
        format!(
            "http {{ server {{ server_name converted-nginx.test; root {}; }} }}\n",
            site.display()
        ),
    )
    .unwrap();

    let conversion = Command::new(env!("CARGO_BIN_EXE_nginx2charlotte"))
        .arg(&nginx_config)
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

#[test]
fn takes_user_and_group_from_root_when_requested() {
    let root = temp_dir();
    let missing_root = root.join("missing-root");
    fs::write(
        root.join("nginx.conf"),
        format!(
            concat!(
                "user globaluser globalgroup;\n",
                "http {{\n",
                "  server {{\n",
                "    server_name root-owner.example.test;\n",
                "    root {:?};\n",
                "  }}\n",
                "  server {{\n",
                "    server_name missing-root.example.test;\n",
                "    root {:?};\n",
                "  }}\n",
                "}}\n",
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

    let output = Command::new(env!("CARGO_BIN_EXE_nginx2charlotte"))
        .arg(root.join("nginx.conf"))
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
