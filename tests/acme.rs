#![forbid(unsafe_code)]

mod common;

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use nix::unistd::{User, geteuid};
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::sleep,
};
use tokio_rustls::TlsAcceptor;

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fixture {
    root: PathBuf,
    cache: PathBuf,
    address: SocketAddr,
    server: Child,
    mock: JoinHandle<()>,
    acme_requests: Arc<AtomicUsize>,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    async fn start() -> Self {
        let guard = TEST_LOCK.lock().await;
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "project-charlotte-acme-{}-{sequence}",
            std::process::id()
        ));
        let alpha = root.join("alpha");
        let disabled = root.join("disabled");
        std::fs::create_dir_all(&alpha).unwrap();
        std::fs::create_dir_all(&disabled).unwrap();
        std::fs::write(alpha.join("plain.txt"), "acme enabled site").unwrap();
        std::fs::write(disabled.join("plain.txt"), "acme disabled site").unwrap();

        let directory_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let directory_address = directory_listener.local_addr().unwrap();
        let (directory_cert, directory_key) = make_directory_certificate();
        let directory_cert_path = root.join("directory-ca.pem");
        std::fs::write(&directory_cert_path, directory_cert.pem()).unwrap();
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(directory_cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(directory_key.serialize_der().into()),
            )
            .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let acme_requests = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::clone(&acme_requests);
        let mock = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = directory_listener.accept().await else {
                    return;
                };
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let Ok(count) = stream.read(&mut buffer).await else {
                        break;
                    };
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&buffer[..count]);
                    if request.len() > 16 * 1024 {
                        break;
                    }
                }
                request_count.fetch_add(1, Ordering::Relaxed);
                let response = if request.starts_with(b"GET /directory ") {
                    let body = format!(
                        "{{\"newNonce\":\"https://{directory_address}/nonce\",\"newAccount\":\"https://{directory_address}/account\",\"newOrder\":\"https://{directory_address}/order\",\"revokeCert\":\"https://{directory_address}/revoke\",\"keyChange\":\"https://{directory_address}/key-change\"}}"
                    );
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else if request.starts_with(b"HEAD ") {
                    "HTTP/1.1 200 OK\r\nReplay-Nonce: mock-nonce\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        .to_owned()
                } else {
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"
                        .to_owned()
                };
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let config_path = root.join("vhosts.toml");
        let user = User::from_uid(geteuid()).unwrap().unwrap().name;
        std::fs::write(
            &config_path,
            format!(
                concat!(
                    "[[vhost]]\nserver_names = [\"alpha.acme.test\"]\nroot = {:?}\nuser = {:?}\n\n",
                    "[[vhost]]\nserver_names = [\"disabled.acme.test\"]\nroot = {:?}\nuser = {:?}\nacme = false\n"
                ),
                alpha.to_string_lossy(),
                user,
                disabled.to_string_lossy(),
                user,
            ),
        )
        .unwrap();
        let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap();
        drop(reservation);
        let cache = root.with_extension("acme-cache");
        let server = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
            .arg("--bind")
            .arg(address.to_string())
            .arg("--http3-bind")
            .arg("127.0.0.1:0")
            .arg("--root")
            .arg(&root)
            .arg("--config")
            .arg(&config_path)
            .arg("--acme-directory")
            .arg(format!("https://{directory_address}/directory"))
            .arg("--acme-cache")
            .arg(&cache)
            .arg("--acme-ca-root")
            .arg(&directory_cert_path)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let mut fixture = Self {
            root,
            cache,
            address,
            server,
            mock,
            acme_requests,
            _guard: guard,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if TcpStream::connect(address).await.is_ok() {
                break;
            }
            if let Some(status) = fixture.server.try_wait().unwrap() {
                panic!("webserver exited before becoming ready: {status}");
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "webserver did not start"
            );
            sleep(Duration::from_millis(20)).await;
        }
        fixture
    }
}

fn make_directory_certificate() -> (rcgen::Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let key = KeyPair::generate().unwrap();
    let certificate = params.self_signed(&key).unwrap();
    (certificate, key)
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.mock.abort();
        common::shutdown(&mut self.server);
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_dir_all(&self.cache);
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

async fn request(fixture: &Fixture, host: &str, path: &str) -> io::Result<HttpResponse> {
    let mut stream = TcpStream::connect(fixture.address).await?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing response headers"))?;
    let status = std::str::from_utf8(&response[..header_end])
        .unwrap()
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing response status"))?;
    Ok(HttpResponse {
        status,
        body: response[header_end + 4..].to_vec(),
    })
}

#[tokio::test]
async fn plaintext_requests_trigger_acme_without_blocking_and_unknown_tokens_fall_through() {
    let fixture = Fixture::start().await;

    let disabled = request(&fixture, "disabled.acme.test", "/plain.txt")
        .await
        .unwrap();
    assert_eq!(disabled.status, 200);
    assert_eq!(disabled.body, b"acme disabled site");
    sleep(Duration::from_millis(200)).await;
    assert_eq!(fixture.acme_requests.load(Ordering::Relaxed), 0);

    let enabled = request(&fixture, "alpha.acme.test", "/plain.txt")
        .await
        .unwrap();
    assert_eq!(enabled.status, 200);
    assert_eq!(enabled.body, b"acme enabled site");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while fixture.acme_requests.load(Ordering::Relaxed) == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "ACME request was not attempted"
        );
        sleep(Duration::from_millis(20)).await;
    }

    let unknown_challenge = request(
        &fixture,
        "alpha.acme.test",
        "/.well-known/acme-challenge/not-a-known-token",
    )
    .await
    .unwrap();
    assert_eq!(unknown_challenge.status, 404);
}

#[test]
fn rejects_acme_cache_inside_a_served_document_root() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "project-charlotte-acme-cache-root-{}-{sequence}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .arg("--bind")
        .arg("127.0.0.1:0")
        .arg("--root")
        .arg(&root)
        .arg("--acme-directory")
        .arg("https://ca.example.test/directory")
        .arg("--acme-cache")
        .arg(root.join("acme-cache"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("ACME cache must be outside every served document root")
    );
    std::fs::remove_dir_all(root).unwrap();
}
