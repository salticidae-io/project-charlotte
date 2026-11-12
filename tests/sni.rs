#![forbid(unsafe_code)]
#![cfg(all(feature = "hosting", feature = "http3"))]

mod common;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Buf, Bytes};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use nix::unistd::{User, geteuid};
use quinn::{Endpoint, VarInt};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::sleep,
};
use tokio_rustls::TlsConnector;

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Fixture {
    root: PathBuf,
    tcp_address: SocketAddr,
    tls_address: SocketAddr,
    http3_address: SocketAddr,
    alpha_cert: CertificateDer<'static>,
    beta_cert: CertificateDer<'static>,
    fallback_cert: CertificateDer<'static>,
    server: Child,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

#[derive(Clone, Copy)]
struct FixtureOptions {
    global_certificate: bool,
    default_vhost_certificate: bool,
}

impl Fixture {
    async fn new() -> Self {
        Self::start(FixtureOptions {
            global_certificate: true,
            default_vhost_certificate: true,
        })
        .await
    }

    async fn without_global_certificate() -> Self {
        Self::start(FixtureOptions {
            global_certificate: false,
            default_vhost_certificate: true,
        })
        .await
    }

    async fn without_fallback_certificate() -> Self {
        Self::start(FixtureOptions {
            global_certificate: false,
            default_vhost_certificate: false,
        })
        .await
    }

    async fn start(options: FixtureOptions) -> Self {
        let guard = TEST_LOCK.lock().await;
        let root = create_root();
        let alpha_root = root.join("alpha");
        let beta_root = root.join("beta");
        std::fs::create_dir_all(&alpha_root).unwrap();
        std::fs::create_dir_all(&beta_root).unwrap();
        std::fs::write(alpha_root.join("index.html"), "alpha vhost").unwrap();
        std::fs::write(beta_root.join("index.html"), "beta vhost").unwrap();
        std::fs::write(root.join("index.html"), "fallback vhost").unwrap();

        let (alpha_cert, alpha_cert_path, alpha_key_path) =
            write_certificate(&root, "alpha", &["alpha.test"]);
        let (beta_cert, _, _) = write_certificate(&root, "beta", &["*.beta.test", "unknown.test"]);
        let (fallback_cert, fallback_cert_path, fallback_key_path) = write_certificate(
            &root,
            "fallback",
            &["unknown.test", "localhost", "127.0.0.1"],
        );

        let username = User::from_uid(geteuid()).unwrap().unwrap().name;
        let config_path = root.join("vhosts.yaml");
        let default_certificate = if options.default_vhost_certificate {
            "    tls_cert: beta.pem\n    tls_key: beta-key.pem\n"
        } else {
            ""
        };
        std::fs::write(
            &config_path,
            format!(
                concat!(
                    "vhost:\n  - server_names: [alpha.test]\n    root: {:?}\n    user: {:?}\n",
                    "    tls_cert: {:?}\n    tls_key: {:?}\n",
                    "  - server_names: [\"*.beta.test\"]\n    root: {:?}\n    user: {:?}\n",
                    "{}    default: true\n"
                ),
                alpha_root.to_string_lossy(),
                username,
                alpha_cert_path.to_string_lossy(),
                alpha_key_path.to_string_lossy(),
                beta_root.to_string_lossy(),
                username,
                default_certificate,
            ),
        )
        .unwrap();

        let tcp_address = common::reserve_tcp_address();
        let tls_address = common::reserve_tcp_address();
        let http3_address = common::reserve_udp_address();
        let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
        command
            .arg("--bind")
            .arg(tcp_address.to_string())
            .arg("--tls-bind")
            .arg(tls_address.to_string())
            .arg("--http3-bind")
            .arg(http3_address.to_string())
            .arg("--root")
            .arg(&root)
            .arg("--config")
            .arg(config_path);
        if options.global_certificate {
            command
                .arg("--tls-cert")
                .arg(fallback_cert_path)
                .arg("--tls-key")
                .arg(fallback_key_path);
        }
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let server = common::spawn(&mut command).unwrap();

        let mut fixture = Self {
            root,
            tcp_address,
            tls_address,
            http3_address,
            alpha_cert,
            beta_cert,
            fallback_cert,
            server,
            _guard: guard,
        };
        fixture.wait_until_ready().await;
        fixture
    }

    async fn wait_until_ready(&mut self) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if TcpStream::connect(self.tls_address).await.is_ok() {
                return;
            }
            if let Some(status) = self.server.try_wait().unwrap() {
                panic!("webserver exited before becoming ready: {status}");
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "webserver did not start"
            );
            sleep(Duration::from_millis(20)).await;
        }
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.alpha_cert.clone()).unwrap();
        roots.add(self.beta_cert.clone()).unwrap();
        roots.add(self.fallback_cert.clone()).unwrap();
        roots
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        common::shutdown(&mut self.server);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct HttpsResponse {
    status: u16,
    version: http::Version,
    body: Vec<u8>,
    certificate: Vec<u8>,
    alpn: Option<Vec<u8>>,
}

async fn https_request(
    fixture: &Fixture,
    server_name: ServerName<'static>,
    host: &str,
    alpn_protocols: Vec<Vec<u8>>,
) -> HttpsResponse {
    https_request_with_config(
        fixture,
        server_name,
        host,
        client_config(fixture.roots(), alpn_protocols),
    )
    .await
}

async fn https_request_with_config(
    fixture: &Fixture,
    server_name: ServerName<'static>,
    host: &str,
    config: rustls::ClientConfig,
) -> HttpsResponse {
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(fixture.tls_address).await.unwrap();
    let mut tls = connector.connect(server_name, stream).await.unwrap();
    let state = tls.get_ref().1;
    let certificate = state.peer_certificates().unwrap()[0].as_ref().to_vec();
    let alpn = state.alpn_protocol().map(<[u8]>::to_vec);
    tls.write_all(
        format!("GET /index.html HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response);
    let response_line = response.lines().next().unwrap();
    let mut response_parts = response_line.split_whitespace();
    let version = match response_parts.next().unwrap() {
        "HTTP/1.0" => http::Version::HTTP_10,
        "HTTP/1.1" => http::Version::HTTP_11,
        other => panic!("unexpected HTTP response version: {other}"),
    };
    let status = response_parts.next().unwrap().parse().unwrap();
    let body = response
        .split_once("\r\n\r\n")
        .map_or_else(Vec::new, |(_, body)| body.as_bytes().to_vec());
    HttpsResponse {
        status,
        version,
        body,
        certificate,
        alpn,
    }
}

async fn https_h2_request(
    fixture: &Fixture,
    server_name: ServerName<'static>,
    authority: &str,
) -> HttpsResponse {
    let connector = TlsConnector::from(Arc::new(client_config(
        fixture.roots(),
        vec![b"h2".to_vec()],
    )));
    let stream = TcpStream::connect(fixture.tls_address).await.unwrap();
    let tls = connector.connect(server_name, stream).await.unwrap();
    let state = tls.get_ref().1;
    let certificate = state.peer_certificates().unwrap()[0].as_ref().to_vec();
    let alpn = state.alpn_protocol().map(<[u8]>::to_vec);
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    let connection_task = tokio::spawn(connection);
    let request = http::Request::builder()
        .version(http::Version::HTTP_2)
        .uri(format!("https://{authority}/index.html"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    let status = response.status().as_u16();
    let version = response.version();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    connection_task.abort();
    let _ = connection_task.await;
    HttpsResponse {
        status,
        version,
        body,
        certificate,
        alpn,
    }
}

async fn http3_request(
    fixture: &Fixture,
    server_name: &str,
    authority: &str,
) -> (u16, Vec<u8>, Vec<u8>) {
    let endpoint = h3_client_endpoint(fixture.roots());
    let connection = tokio::time::timeout(
        Duration::from_secs(8),
        endpoint
            .connect(fixture.http3_address, server_name)
            .unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let identity = connection.peer_identity().unwrap();
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .expect("rustls peer identity is a certificate chain");
    let certificate = chain[0].as_ref().to_vec();
    let (mut driver, mut sender) = h3::client::builder()
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection))
        .await
        .unwrap();
    let driver_task = tokio::spawn(async move { driver.wait_idle().await });
    let request = http::Request::builder()
        .uri(format!("https://{authority}/index.html"))
        .body(())
        .unwrap();
    let mut stream = sender.send_request(request).await.unwrap();
    stream.finish().await.unwrap();
    let response = stream.recv_response().await.unwrap();
    let status = response.status().as_u16();
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    drop(stream);
    drop(sender);
    endpoint.close(VarInt::from_u32(0), b"test complete");
    driver_task.abort();
    let _ = driver_task.await;
    (status, body, certificate)
}

fn client_config(roots: RootCertStore, alpn_protocols: Vec<Vec<u8>>) -> rustls::ClientConfig {
    client_config_with_versions(
        roots,
        alpn_protocols,
        &[&rustls::version::TLS13, &rustls::version::TLS12],
    )
}

fn client_config_with_versions(
    roots: RootCertStore,
    alpn_protocols: Vec<Vec<u8>>,
    versions: &[&'static rustls::SupportedProtocolVersion],
) -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols;
    config
}

async fn plain_http_request(address: SocketAddr, host: &str) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            format!("GET /index.html HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8_lossy(&response);
    let status = response
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let body = response
        .split_once("\r\n\r\n")
        .map_or_else(Vec::new, |(_, body)| body.as_bytes().to_vec());
    (status, body)
}

fn h3_client_endpoint(roots: RootCertStore) -> Endpoint {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(config).unwrap();
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    endpoint
}

fn create_root() -> PathBuf {
    let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let root =
        std::env::temp_dir().join(format!("project-charlotte-sni-{}-{id}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn write_certificate(
    root: &Path,
    name: &str,
    subject_alt_names: &[&str],
) -> (CertificateDer<'static>, PathBuf, PathBuf) {
    let generated = rcgen::generate_simple_self_signed(
        subject_alt_names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let cert_path = root.join(format!("{name}.pem"));
    let key_path = root.join(format!("{name}-key.pem"));
    std::fs::write(&cert_path, generated.cert.pem()).unwrap();
    std::fs::write(&key_path, generated.signing_key.serialize_pem()).unwrap();
    (generated.cert.der().clone(), cert_path, key_path)
}

fn current_name(name: &str) -> ServerName<'static> {
    ServerName::try_from(name.to_owned()).unwrap()
}

#[tokio::test]
async fn https_selects_exact_wildcard_and_global_fallback_certificates() {
    let fixture = Fixture::new().await;

    let alpha = https_request(
        &fixture,
        current_name("alpha.test"),
        "alpha.test",
        vec![b"http/1.1".to_vec()],
    )
    .await;
    assert_eq!(alpha.status, 200);
    assert_eq!(alpha.body, b"alpha vhost");
    assert_eq!(alpha.certificate, fixture.alpha_cert.as_ref());
    assert_eq!(alpha.alpn.as_deref(), Some(b"http/1.1".as_slice()));

    let wildcard = https_request(
        &fixture,
        current_name("x.beta.test"),
        "x.beta.test",
        vec![b"http/1.1".to_vec()],
    )
    .await;
    assert_eq!(wildcard.status, 200);
    assert_eq!(wildcard.body, b"beta vhost");
    assert_eq!(wildcard.certificate, fixture.beta_cert.as_ref());

    let unknown = https_request(
        &fixture,
        current_name("unknown.test"),
        "unknown.test",
        vec![b"http/1.1".to_vec()],
    )
    .await;
    assert_eq!(unknown.status, 200);
    assert_eq!(unknown.body, b"beta vhost");
    assert_eq!(unknown.certificate, fixture.fallback_cert.as_ref());
}

#[tokio::test]
async fn https_rejects_host_mismatch_and_negotiates_http2() {
    let fixture = Fixture::new().await;
    let mismatch = https_request(
        &fixture,
        current_name("alpha.test"),
        "x.beta.test",
        vec![b"http/1.1".to_vec()],
    )
    .await;
    assert_eq!(mismatch.status, 421);

    let connector = TlsConnector::from(Arc::new(client_config(
        fixture.roots(),
        vec![b"h2".to_vec()],
    )));
    let stream = TcpStream::connect(fixture.tls_address).await.unwrap();
    let tls = connector
        .connect(current_name("alpha.test"), stream)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
}

#[tokio::test]
async fn https_http2_routes_by_authority_and_rejects_mismatches() {
    let fixture = Fixture::new().await;
    let response = https_h2_request(&fixture, current_name("alpha.test"), "alpha.test").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.version, http::Version::HTTP_2);
    assert_eq!(response.body, b"alpha vhost");
    assert_eq!(response.certificate, fixture.alpha_cert.as_ref());
    assert_eq!(response.alpn.as_deref(), Some(b"h2".as_slice()));

    let mismatch = https_h2_request(&fixture, current_name("alpha.test"), "x.beta.test").await;
    assert_eq!(mismatch.status, 421);
    assert_eq!(mismatch.version, http::Version::HTTP_2);
}

#[tokio::test]
async fn https_normalizes_case_and_port_in_host_authority() {
    let fixture = Fixture::new().await;
    let response = https_request(
        &fixture,
        current_name("alpha.test"),
        "ALPHA.TEST:443",
        vec![b"http/1.1".to_vec()],
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"alpha vhost");
}

#[tokio::test]
async fn unknown_sni_falling_back_to_default_vhost_rejects_other_authority() {
    let fixture = Fixture::new().await;
    let response = https_request(
        &fixture,
        current_name("unknown.test"),
        "alpha.test",
        vec![b"http/1.1".to_vec()],
    )
    .await;
    assert_eq!(response.status, 421);
    assert_eq!(response.certificate, fixture.fallback_cert.as_ref());
}

#[tokio::test]
async fn https_supports_tls12_with_sni_certificate_selection() {
    let fixture = Fixture::new().await;
    let response = https_request_with_config(
        &fixture,
        current_name("alpha.test"),
        "alpha.test",
        client_config_with_versions(
            fixture.roots(),
            vec![b"http/1.1".to_vec()],
            &[&rustls::version::TLS12],
        ),
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"alpha vhost");
    assert_eq!(response.certificate, fixture.alpha_cert.as_ref());
}

#[tokio::test]
async fn http3_selects_sni_certificate_and_rejects_authority_mismatch() {
    let fixture = Fixture::new().await;
    let (status, body, certificate) = http3_request(&fixture, "alpha.test", "alpha.test").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"alpha vhost");
    assert_eq!(certificate, fixture.alpha_cert.as_ref());

    let (status, _, certificate) = http3_request(&fixture, "alpha.test", "x.beta.test").await;
    assert_eq!(status, 421);
    assert_eq!(certificate, fixture.alpha_cert.as_ref());
}

#[tokio::test]
async fn http3_selects_wildcard_and_global_fallback_certificates() {
    let fixture = Fixture::new().await;
    let (status, body, certificate) = http3_request(&fixture, "x.beta.test", "x.beta.test").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"beta vhost");
    assert_eq!(certificate, fixture.beta_cert.as_ref());

    let (status, body, certificate) = http3_request(&fixture, "unknown.test", "unknown.test").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"beta vhost");
    assert_eq!(certificate, fixture.fallback_cert.as_ref());
}

#[tokio::test]
async fn missing_sni_uses_the_global_fallback_certificate() {
    let fixture = Fixture::new().await;
    let response = https_request(
        &fixture,
        ServerName::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST).into()),
        "alpha.test",
        vec![b"http/1.1".to_vec()],
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"alpha vhost");
    assert_eq!(response.certificate, fixture.fallback_cert.as_ref());
}

#[tokio::test]
async fn default_vhost_certificate_is_fallback_without_global_tls_files() {
    let fixture = Fixture::without_global_certificate().await;
    let response = https_request(
        &fixture,
        current_name("unknown.test"),
        "unknown.test",
        vec![b"http/1.1".to_vec()],
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"beta vhost");
    assert_eq!(response.certificate, fixture.beta_cert.as_ref());
}

#[tokio::test]
async fn missing_fallback_certificate_aborts_unknown_sni_but_keeps_known_vhosts_available() {
    let fixture = Fixture::without_fallback_certificate().await;
    let connector = TlsConnector::from(Arc::new(client_config(
        fixture.roots(),
        vec![b"http/1.1".to_vec()],
    )));
    let stream = TcpStream::connect(fixture.tls_address).await.unwrap();
    let handshake = tokio::time::timeout(
        Duration::from_secs(8),
        connector.connect(current_name("unknown.test"), stream),
    )
    .await;
    assert!(
        matches!(handshake, Ok(Err(_))),
        "unknown SNI unexpectedly succeeded"
    );

    let response = https_request(
        &fixture,
        current_name("alpha.test"),
        "alpha.test",
        vec![b"http/1.1".to_vec()],
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"alpha vhost");
    assert_eq!(response.certificate, fixture.alpha_cert.as_ref());
}

#[tokio::test]
async fn plain_http_routes_hosts_without_tls_sni_checks() {
    let fixture = Fixture::new().await;
    let (status, body) = plain_http_request(fixture.tcp_address, "alpha.test").await;
    assert_eq!(status, 200);
    assert_eq!(body, b"alpha vhost");
}

#[tokio::test]
async fn tls_listener_requires_a_configured_certificate() {
    let _guard = TEST_LOCK.lock().await;
    let root = create_root();
    let address = common::reserve_tcp_address();
    let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
    command
        .arg("--bind")
        .arg(common::reserve_tcp_address().to_string())
        .arg("--tls-bind")
        .arg(address.to_string())
        .arg("--root")
        .arg(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut server = common::spawn(&mut command).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(status) = server.try_wait().unwrap() {
                break status;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let status = match result {
        Ok(status) => status,
        Err(_) => {
            common::shutdown(&mut server);
            let _ = std::fs::remove_dir_all(&root);
            panic!("server did not reject --tls-bind without a certificate");
        }
    };
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        !status.success(),
        "server started without a TLS certificate"
    );
}
