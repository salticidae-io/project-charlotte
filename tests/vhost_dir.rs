//! Integration tests for loading and reloading virtual hosts from a directory.

#![forbid(unsafe_code)]
#![cfg(feature = "hosting")]

mod common;

use std::{
    error::Error,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use nix::unistd::{User, geteuid};
use rustls::{RootCertStore, pki_types::CertificateDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::sleep,
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    path: PathBuf,
    vhost_dir: PathBuf,
    address: SocketAddr,
    server: Child,
}

impl Fixture {
    async fn start(main_config: Option<String>, initial_vhost: Option<(&str, &str)>) -> Self {
        Self::start_with_tls(main_config, initial_vhost, None).await
    }

    async fn start_with_tls(
        main_config: Option<String>,
        initial_vhost: Option<(&str, &str)>,
        tls_address: Option<SocketAddr>,
    ) -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "project-charlotte-vhost-dir-{}-{sequence}",
            std::process::id()
        ));
        let vhost_dir = path.join("vhosts.d");
        std::fs::create_dir_all(&vhost_dir).unwrap();
        let default_root = path.join("default");
        std::fs::create_dir_all(&default_root).unwrap();
        std::fs::write(default_root.join("page.txt"), "fallback").unwrap();
        let has_main_config = main_config.is_some();
        if let Some(config) = main_config {
            std::fs::write(path.join("main.yaml"), config).unwrap();
        }
        if let Some((hostname, body)) = initial_vhost {
            let root = path.join("initial-root");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::write(root.join("page.txt"), body).unwrap();
            std::fs::write(
                vhost_dir.join("initial.yaml"),
                vhost_config(hostname, &root),
            )
            .unwrap();
        }

        let address = common::reserve_tcp_address();
        let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
        command
            .arg("--bind")
            .arg(address.to_string())
            .arg("--root")
            .arg(&default_root)
            .arg("--vhost-dir")
            .arg(&vhost_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if has_main_config {
            command.arg("--config").arg(path.join("main.yaml"));
        }
        if let Some(address) = tls_address {
            command.arg("--tls-bind").arg(address.to_string());
        }
        let mut server = common::spawn(&mut command).unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if let Ok(Ok(mut stream)) =
                tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(address)).await
            {
                let _ = stream
                    .write_all(
                        b"GET /page.txt HTTP/1.1\r\nHost: unknown.test\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let mut response = Vec::new();
                if tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
                    .await
                    .is_ok()
                    && response.starts_with(b"HTTP/")
                    && response.ends_with(b"fallback")
                {
                    break;
                }
            }
            if let Some(status) = server.try_wait().unwrap() {
                panic!("webserver exited before becoming ready: {status}");
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "webserver did not start"
            );
            sleep(Duration::from_millis(20)).await;
        }

        Self {
            path,
            vhost_dir,
            address,
            server,
        }
    }

    fn add_root(&self, name: &str, body: &str) -> PathBuf {
        let root = self.path.join(name);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("page.txt"), body).unwrap();
        root
    }

    fn config(&self, filename: &str, hostname: &str, root: &Path) {
        std::fs::write(self.vhost_dir.join(filename), vhost_config(hostname, root)).unwrap();
    }

    async fn body(&self, hostname: &str) -> String {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(self.address))
                .await
            {
                Ok(Ok(stream)) => break stream,
                _ if tokio::time::Instant::now() < deadline => {
                    sleep(Duration::from_millis(50)).await
                }
                Err(_) => panic!("timed out connecting to server at {}", self.address),
                Ok(Err(error)) => {
                    panic!("could not connect to server at {}: {error}", self.address)
                }
            }
        };
        stream
            .write_all(
                format!("GET /page.txt HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("HTTP response headers");
        assert!(response.starts_with(b"HTTP/1.1 200") || response.starts_with(b"HTTP/1.0 200"));
        String::from_utf8_lossy(&response[header_end + 4..]).into_owned()
    }

    async fn wait_for_body(&self, hostname: &str, expected: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if self.body(hostname).await == expected {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "host {hostname} did not serve expected body {expected:?}"
            );
            sleep(Duration::from_millis(75)).await;
        }
    }

    async fn tls_body(
        &self,
        address: SocketAddr,
        hostname: &str,
        certificate: CertificateDer<'static>,
    ) -> Result<String, Box<dyn Error + Send + Sync>> {
        let mut roots = RootCertStore::empty();
        roots.add(certificate)?;
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(address).await?;
        let server_name = rustls::pki_types::ServerName::try_from(hostname.to_owned())?;
        let mut stream = connector.connect(server_name, stream).await?;
        stream
            .write_all(
                format!("GET /page.txt HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        let header_end = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .ok_or("HTTP response headers were incomplete")?;
        Ok(String::from_utf8_lossy(&response[header_end + 4..]).into_owned())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        common::shutdown(&mut self.server);
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn current_user_name() -> String {
    User::from_uid(geteuid()).unwrap().unwrap().name
}

fn worker_user_name() -> String {
    if geteuid().is_root() {
        "nobody".to_owned()
    } else {
        current_user_name()
    }
}

fn vhost_config(hostname: &str, root: &Path) -> String {
    format!(
        "vhost:\n  - server_names: [{hostname:?}]\n    root: {:?}\n    user: {:?}\n",
        root.to_string_lossy(),
        current_user_name()
    )
}

#[tokio::test]
async fn loads_and_reloads_added_modified_and_deleted_vhost_files() {
    let fixture = Fixture::start(None, Some(("alpha.test", "alpha"))).await;
    let beta_root = fixture.add_root("beta-root", "beta");
    let changed_root = fixture.add_root("changed-root", "changed");

    fixture.wait_for_body("alpha.test", "alpha").await;
    assert_eq!(fixture.body("unknown.test").await, "fallback");

    fixture.config("beta.yaml", "beta.test", &beta_root);
    fixture.wait_for_body("beta.test", "beta").await;

    fixture.config("beta.yaml", "beta.test", &changed_root);
    fixture.wait_for_body("beta.test", "changed").await;

    std::fs::remove_file(fixture.vhost_dir.join("beta.yaml")).unwrap();
    fixture.wait_for_body("beta.test", "fallback").await;
}

#[tokio::test]
async fn invalid_or_duplicate_files_keep_the_previous_configuration_and_merge_main_config() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let main_root = std::env::temp_dir().join(format!(
        "project-charlotte-main-vhost-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(&main_root).unwrap();
    std::fs::write(main_root.join("page.txt"), "main").unwrap();
    let main_config = vhost_config("main.test", &main_root);
    let fixture = Fixture::start(Some(main_config), Some(("beta.test", "beta"))).await;
    let duplicate_root = fixture.add_root("duplicate-root", "duplicate");

    fixture.wait_for_body("main.test", "main").await;
    fixture.wait_for_body("beta.test", "beta").await;

    std::fs::write(
        fixture.vhost_dir.join("initial.yaml"),
        "vhost:\n  - [invalid",
    )
    .unwrap();
    sleep(Duration::from_millis(600)).await;
    assert_eq!(fixture.body("beta.test").await, "beta");

    fixture.config("duplicate.yaml", "main.test", &duplicate_root);
    sleep(Duration::from_millis(600)).await;
    assert_eq!(fixture.body("beta.test").await, "beta");
    assert_eq!(fixture.body("main.test").await, "main");
    drop(fixture);
    std::fs::remove_dir_all(main_root).unwrap();
}

#[tokio::test]
async fn adding_vhost_tls_certificate_updates_sni_without_restart() {
    let tls_address = common::reserve_tcp_address();
    let fixture = Fixture::start_with_tls(None, None, Some(tls_address)).await;
    let root = fixture.add_root("tls-reload-root", "reloaded TLS certificate");
    let generated = rcgen::generate_simple_self_signed(vec!["reload.test".to_owned()]).unwrap();
    let cert_path = fixture.path.join("reload.pem");
    let key_path = fixture.path.join("reload-key.pem");
    std::fs::write(&cert_path, generated.cert.pem()).unwrap();
    std::fs::write(&key_path, generated.signing_key.serialize_pem()).unwrap();
    let certificate = generated.cert.der().clone();
    std::fs::write(
        fixture.vhost_dir.join("reload.yaml"),
        format!(
            "vhost:\n  - server_names: [reload.test]\n    root: {:?}\n    user: {:?}\n    tls_cert: {:?}\n    tls_key: {:?}\n",
            root.to_string_lossy(),
            worker_user_name(),
            cert_path.to_string_lossy(),
            key_path.to_string_lossy()
        ),
    )
    .unwrap();
    fixture
        .wait_for_body("reload.test", "reloaded TLS certificate")
        .await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(body) = fixture
            .tls_body(tls_address, "reload.test", certificate.clone())
            .await
            && body == "reloaded TLS certificate"
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "new vhost certificate was not selected by SNI"
        );
        sleep(Duration::from_millis(100)).await;
    }
}
