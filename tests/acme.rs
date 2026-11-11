#![forbid(unsafe_code)]

mod common;

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use nix::unistd::{User, geteuid};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, IsCa, Issuer, KeyPair,
    SanType,
};
use rustls::pki_types::{
    CertificateDer, CertificateSigningRequestDer, PrivateKeyDer, ServerName, pem::PemObject,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::sleep,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, server::TlsStream as ServerTlsStream};

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

        let config_path = root.join("vhosts.yaml");
        let user = User::from_uid(geteuid()).unwrap().unwrap().name;
        std::fs::write(
            &config_path,
            format!(
                concat!(
                    "vhost:\n  - server_names: [alpha.acme.test]\n    root: {:?}\n    user: {:?}\n",
                    "  - server_names: [disabled.acme.test]\n    root: {:?}\n    user: {:?}\n    acme: false\n"
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
    request_at(fixture.address, host, path).await
}

async fn request_at(address: SocketAddr, host: &str, path: &str) -> io::Result<HttpResponse> {
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    parse_http_response(&response)
}

async fn tls_request(
    address: SocketAddr,
    host: &str,
    ca_certificate: CertificateDer<'static>,
) -> io::Result<HttpResponse> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_certificate).unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(address).await?;
    let mut stream = connector
        .connect(ServerName::try_from(host.to_owned()).unwrap(), stream)
        .await?;
    stream
        .write_all(
            format!("GET /plain.txt HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> io::Result<HttpResponse> {
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

const ISSUANCE_HOST: &str = "issued.acme.test";
const CHALLENGE_TOKEN: &str = "integration-test-token";

struct IssuanceFixture {
    root: PathBuf,
    cache: PathBuf,
    address: SocketAddr,
    tls_address: SocketAddr,
    acme_address: SocketAddr,
    ca_certificate: CertificateDer<'static>,
    server: Child,
    mock: JoinHandle<()>,
    order_count: Arc<AtomicUsize>,
    challenge_valid: Arc<std::sync::atomic::AtomicBool>,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

impl IssuanceFixture {
    async fn start() -> Self {
        let guard = TEST_LOCK.lock().await;
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "project-charlotte-acme-issuance-{}-{sequence}",
            std::process::id()
        ));
        let site = root.join("site");
        let fallback = root.join("fallback");
        std::fs::create_dir_all(&site).unwrap();
        std::fs::create_dir_all(&fallback).unwrap();
        std::fs::write(site.join("plain.txt"), "issued certificate site").unwrap();

        let mut ca_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        ca_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_certificate.pem();
        let ca_der = CertificateDer::from(ca_certificate.der().to_vec());
        let ca_path = root.join("acme-ca.pem");
        std::fs::write(&ca_path, &ca_pem).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);
        let mut directory_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        directory_params
            .subject_alt_names
            .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let directory_key = KeyPair::generate().unwrap();
        let directory_certificate = directory_params.signed_by(&directory_key, &issuer).unwrap();

        let address = reserve_tcp_address();
        let tls_address = reserve_tcp_address();
        let acme_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let acme_address = acme_listener.local_addr().unwrap();
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(directory_certificate.der().to_vec())],
                PrivateKeyDer::Pkcs8(directory_key.serialize_der().into()),
            )
            .unwrap();
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let order_count = Arc::new(AtomicUsize::new(0));
        let challenge_valid = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let finalized = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let issued_certificate = Arc::new(StdMutex::new(None::<String>));
        let mock_order_count = Arc::clone(&order_count);
        let mock_challenge_valid = Arc::clone(&challenge_valid);
        let mock_finalized = Arc::clone(&finalized);
        let mock_issued_certificate = Arc::clone(&issued_certificate);
        let mock = tokio::spawn(async move {
            let mut nonce = 0;
            loop {
                let Ok((stream, _)) = acme_listener.accept().await else {
                    return;
                };
                let mut stream = match acceptor.accept(stream).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        eprintln!("issuance mock ACME TLS accept failed: {error}");
                        continue;
                    }
                };
                nonce += 1;
                if let Err(error) = handle_acme_connection(
                    &mut stream,
                    acme_address,
                    address,
                    &issuer,
                    &ca_pem,
                    &mock_order_count,
                    &mock_challenge_valid,
                    &mock_finalized,
                    &mock_issued_certificate,
                    nonce,
                )
                .await
                {
                    eprintln!("mock ACME request failed: {error}");
                }
            }
        });

        let config_path = root.join("vhosts.yaml");
        let user = User::from_uid(geteuid()).unwrap().unwrap().name;
        std::fs::write(
            &config_path,
            format!(
                "vhost:\n  - server_names: [{ISSUANCE_HOST:?}]\n    root: {:?}\n    user: {:?}\n",
                site.to_string_lossy(),
                user,
            ),
        )
        .unwrap();
        let cache = root.with_extension("issuance-cache");
        let server = start_issuance_server(
            address,
            tls_address,
            &fallback,
            &config_path,
            &cache,
            &ca_path,
            acme_address,
        );
        let mut fixture = Self {
            root,
            cache,
            address,
            tls_address,
            acme_address,
            ca_certificate: ca_der,
            server,
            mock,
            order_count,
            challenge_valid,
            _guard: guard,
        };
        wait_for_server(&mut fixture.server, &[address, tls_address]).await;
        fixture
    }

    async fn restart(&mut self) {
        common::shutdown(&mut self.server);
        self.server = start_issuance_server(
            self.address,
            self.tls_address,
            &self.root.join("fallback"),
            &self.root.join("vhosts.yaml"),
            &self.cache,
            &self.root.join("acme-ca.pem"),
            self.acme_address,
        );
        wait_for_server(&mut self.server, &[self.address, self.tls_address]).await;
    }
}

impl Drop for IssuanceFixture {
    fn drop(&mut self) {
        self.mock.abort();
        common::shutdown(&mut self.server);
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_dir_all(&self.cache);
    }
}

fn reserve_tcp_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn start_issuance_server(
    address: SocketAddr,
    tls_address: SocketAddr,
    fallback: &std::path::Path,
    config: &std::path::Path,
    cache: &std::path::Path,
    ca_path: &std::path::Path,
    acme_address: SocketAddr,
) -> Child {
    Command::new(env!("CARGO_BIN_EXE_project-charlotte"))
        .arg("--bind")
        .arg(address.to_string())
        .arg("--tls-bind")
        .arg(tls_address.to_string())
        .arg("--http3-bind")
        .arg("127.0.0.1:0")
        .arg("--root")
        .arg(fallback)
        .arg("--config")
        .arg(config)
        .arg("--acme-directory")
        .arg(format!("https://{acme_address}/directory"))
        .arg("--acme-cache")
        .arg(cache)
        .arg("--acme-ca-root")
        .arg(ca_path)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

async fn wait_for_server(server: &mut Child, addresses: &[SocketAddr]) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        let mut all_ready = true;
        for address in addresses {
            if TcpStream::connect(address).await.is_err() {
                all_ready = false;
                break;
            }
        }
        if all_ready {
            return;
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
}

struct AcmeRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

async fn read_acme_request(stream: &mut ServerTlsStream<TcpStream>) -> io::Result<AcmeRequest> {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index;
        }
        if bytes.len() > 64 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ACME headers too large",
            ));
        }
        let mut buffer = [0; 2048];
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "empty ACME request",
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    };
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut lines = headers.lines();
    let mut request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing ACME request line"))?
        .split_whitespace();
    let method = request_line.next().unwrap_or_default().to_owned();
    let path = request_line.next().unwrap_or_default().to_owned();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let body_start = header_end + 4;
    let expected_length = body_start + content_length;
    while bytes.len() < expected_length {
        let mut buffer = [0; 2048];
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated ACME request",
            ));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(AcmeRequest {
        method,
        path,
        body: bytes[body_start..expected_length].to_vec(),
    })
}

async fn handle_acme_connection(
    stream: &mut ServerTlsStream<TcpStream>,
    address: SocketAddr,
    charlotte_address: SocketAddr,
    issuer: &Issuer<'_, KeyPair>,
    ca_pem: &str,
    order_count: &AtomicUsize,
    challenge_valid: &std::sync::atomic::AtomicBool,
    finalized: &std::sync::atomic::AtomicBool,
    issued_certificate: &StdMutex<Option<String>>,
    nonce: usize,
) -> io::Result<()> {
    let request = read_acme_request(stream).await?;
    let base = format!("https://{address}");
    let authz_url = format!("{base}/authorization/1");
    let challenge_url = format!("{base}/challenge/1");
    let finalize_url = format!("{base}/finalize/1");
    let order_url = format!("{base}/order/1");
    let cert_url = format!("{base}/certificate/1");
    let (status, content_type, extra_headers, body) = match (
        request.method.as_str(),
        request.path.as_str(),
    ) {
        ("GET", "/directory") => (
            "200 OK",
            "application/json",
            String::new(),
            format!(
                "{{\"newNonce\":\"{base}/nonce\",\"newAccount\":\"{base}/account\",\"newOrder\":\"{base}/new-order\",\"revokeCert\":\"{base}/revoke\",\"keyChange\":\"{base}/key-change\"}}"
            ),
        ),
        ("HEAD", "/nonce") => ("200 OK", "application/json", String::new(), String::new()),
        ("POST", "/account") => (
            "201 Created",
            "application/json",
            format!("Location: {base}/account/1\r\n"),
            "{\"status\":\"valid\"}".to_owned(),
        ),
        ("POST", "/new-order") => {
            order_count.fetch_add(1, Ordering::Relaxed);
            (
                "201 Created",
                "application/json",
                format!("Location: {order_url}\r\n"),
                format!(
                    "{{\"status\":\"pending\",\"authorizations\":[\"{authz_url}\"],\"finalize\":\"{finalize_url}\"}}"
                ),
            )
        }
        ("POST", "/authorization/1") => (
            "200 OK",
            "application/json",
            String::new(),
            format!(
                "{{\"status\":\"pending\",\"identifier\":{{\"type\":\"dns\",\"value\":\"{ISSUANCE_HOST}\"}},\"challenges\":[{{\"type\":\"http-01\",\"url\":\"{challenge_url}\",\"status\":\"pending\",\"token\":\"{CHALLENGE_TOKEN}\"}}]}}"
            ),
        ),
        ("POST", "/challenge/1") => {
            let valid = request_at(
                charlotte_address,
                ISSUANCE_HOST,
                &format!("/.well-known/acme-challenge/{CHALLENGE_TOKEN}"),
            )
            .await
            .is_ok_and(|response| {
                response.status == 200
                    && response
                        .body
                        .starts_with(format!("{CHALLENGE_TOKEN}.").as_bytes())
            });
            challenge_valid.store(valid, Ordering::Relaxed);
            let status = if valid { "valid" } else { "invalid" };
            (
                "200 OK",
                "application/json",
                String::new(),
                format!(
                    "{{\"type\":\"http-01\",\"url\":\"{challenge_url}\",\"status\":\"{status}\",\"token\":\"{CHALLENGE_TOKEN}\"}}"
                ),
            )
        }
        ("POST", "/order/1") => {
            let status = if !challenge_valid.load(Ordering::Relaxed) {
                "invalid"
            } else if finalized.load(Ordering::Relaxed) {
                "valid"
            } else {
                "ready"
            };
            let certificate_field = if status == "valid" {
                format!(",\"certificate\":\"{cert_url}\"")
            } else {
                String::new()
            };
            (
                "200 OK",
                "application/json",
                String::new(),
                format!(
                    "{{\"status\":\"{status}\",\"authorizations\":[\"{authz_url}\"],\"finalize\":\"{finalize_url}\"{certificate_field}}}"
                ),
            )
        }
        ("POST", "/finalize/1") => {
            let jws: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let payload = decode_base64url(jws["payload"].as_str().unwrap()).unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            let encoded_csr = payload["csr"].as_str().unwrap();
            let csr_der = decode_base64url(encoded_csr).unwrap();
            let csr = CertificateSigningRequestDer::from(csr_der);
            let params = CertificateSigningRequestParams::from_der(&csr).unwrap();
            let certificate = params.signed_by(issuer).unwrap();
            *issued_certificate.lock().unwrap() = Some(format!("{}{}", certificate.pem(), ca_pem));
            finalized.store(true, Ordering::Relaxed);
            (
                "200 OK",
                "application/json",
                String::new(),
                format!(
                    "{{\"status\":\"processing\",\"authorizations\":[\"{authz_url}\"],\"finalize\":\"{finalize_url}\"}}"
                ),
            )
        }
        ("POST", "/certificate/1") => (
            "200 OK",
            "application/pem-certificate-chain",
            String::new(),
            issued_certificate
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_default(),
        ),
        _ => (
            "404 Not Found",
            "application/json",
            String::new(),
            "{}".to_owned(),
        ),
    };
    write_acme_response(stream, status, content_type, &extra_headers, &body, nonce).await
}

async fn write_acme_response(
    stream: &mut ServerTlsStream<TcpStream>,
    status: &str,
    content_type: &str,
    extra_headers: &str,
    body: &str,
    nonce: usize,
) -> io::Result<()> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nReplay-Nonce: test-nonce-{nonce}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await
}

fn decode_base64url(input: &str) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(format!("invalid base64url byte: {byte}")),
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
            accumulator &= (1 << bits) - 1;
        }
    }
    if bits == 6 || accumulator != 0 {
        return Err("invalid base64url trailing bits".to_owned());
    }
    Ok(output)
}

#[tokio::test]
async fn issues_caches_and_serves_certificate_from_local_acme_directory() {
    let mut fixture = IssuanceFixture::start().await;
    assert!(
        tls_request(
            fixture.tls_address,
            ISSUANCE_HOST,
            fixture.ca_certificate.clone()
        )
        .await
        .is_err(),
        "TLS should not have a certificate before ACME issuance"
    );

    let response = request_at(fixture.address, ISSUANCE_HOST, "/plain.txt")
        .await
        .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"issued certificate site");

    let account_path = fixture.cache.join("account.json");
    let certificate_path = fixture.cache.join(format!("{ISSUANCE_HOST}.cert.pem"));
    let key_path = fixture.cache.join(format!("{ISSUANCE_HOST}.key.pem"));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while !account_path.exists() || !certificate_path.exists() || !key_path.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "ACME certificate was not written to the cache"
        );
        sleep(Duration::from_millis(20)).await;
    }
    assert!(fixture.challenge_valid.load(Ordering::Relaxed));
    assert_eq!(fixture.order_count.load(Ordering::Relaxed), 1);

    assert_eq!(
        std::fs::metadata(&fixture.cache)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(account_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&certificate_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );

    let certificates = CertificateDer::pem_file_iter(&certificate_path)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let (_, leaf) = x509_parser::parse_x509_certificate(certificates[0].as_ref()).unwrap();
    let subject_alt_names = leaf
        .tbs_certificate
        .subject_alternative_name()
        .unwrap()
        .unwrap();
    assert!(subject_alt_names.value.general_names.iter().any(|name| {
        matches!(
            name,
            x509_parser::extensions::GeneralName::DNSName(name) if *name == ISSUANCE_HOST
        )
    }));

    let response = tls_request(
        fixture.tls_address,
        ISSUANCE_HOST,
        fixture.ca_certificate.clone(),
    )
    .await
    .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"issued certificate site");

    fixture.restart().await;
    let response = tls_request(
        fixture.tls_address,
        ISSUANCE_HOST,
        fixture.ca_certificate.clone(),
    )
    .await
    .unwrap();
    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"issued certificate site");
    assert_eq!(fixture.order_count.load(Ordering::Relaxed), 1);
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
