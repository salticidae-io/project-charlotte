//! End-to-end compatibility checks for the logchomper Redis access data.

#![forbid(unsafe_code)]
#![cfg(all(feature = "swarm", feature = "hosting"))]

mod common;

use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    sync::{Arc, Mutex},
    time::Duration,
};

use nix::unistd::{User, geteuid};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    time::sleep,
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);
static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Default)]
struct RedisData {
    sorted_scores: HashMap<(String, String), f64>,
    vhost_counts: HashMap<String, u64>,
    class_counts: HashMap<String, [u64; 5]>,
    existing_keys: HashSet<String>,
}

struct MockRedis {
    address: SocketAddr,
    data: Arc<Mutex<RedisData>>,
    task: tokio::task::JoinHandle<()>,
}

impl MockRedis {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let data = Arc::new(Mutex::new(RedisData::default()));
        let task_data = Arc::clone(&data);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let data = Arc::clone(&task_data);
                tokio::spawn(async move {
                    let _ = serve_redis_connection(stream, data).await;
                });
            }
        });
        Self {
            address,
            data,
            task,
        }
    }

    fn url(&self) -> String {
        format!("redis://{}/", self.address)
    }

    fn update(&self, update: impl FnOnce(&mut RedisData)) {
        update(
            &mut self
                .data
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
    }
}

impl Drop for MockRedis {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_redis_connection(stream: TcpStream, data: Arc<Mutex<RedisData>>) -> io::Result<()> {
    let mut stream = BufReader::new(stream);
    loop {
        let command = read_redis_command(&mut stream).await?;
        if command.is_empty() {
            return Ok(());
        }
        let response = redis_response(&command, &data);
        stream.get_mut().write_all(response.as_bytes()).await?;
    }
}

async fn read_redis_command(stream: &mut BufReader<TcpStream>) -> io::Result<Vec<String>> {
    let mut line = Vec::new();
    if stream.read_until(b'\n', &mut line).await? == 0 {
        return Ok(Vec::new());
    }
    if line.first() != Some(&b'*') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected RESP array",
        ));
    }
    let count = parse_resp_length(&line)?;
    let mut command = Vec::with_capacity(count);
    for _ in 0..count {
        line.clear();
        stream.read_until(b'\n', &mut line).await?;
        if line.first() != Some(&b'$') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected RESP bulk string",
            ));
        }
        let length = parse_resp_length(&line)?;
        let mut bytes = vec![0; length + 2];
        stream.read_exact(&mut bytes).await?;
        bytes.truncate(length);
        command.push(String::from_utf8_lossy(&bytes).into_owned());
    }
    Ok(command)
}

fn parse_resp_length(line: &[u8]) -> io::Result<usize> {
    let value = std::str::from_utf8(line)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .trim()
        .get(1..)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid RESP length"))?
        .parse::<usize>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(value)
}

fn redis_response(command: &[String], data: &Mutex<RedisData>) -> String {
    let Some(name) = command.first().map(|name| name.to_ascii_uppercase()) else {
        return "-ERR empty command\r\n".to_owned();
    };
    match name.as_str() {
        "HELLO" => "-ERR unknown command 'HELLO'\r\n".to_owned(),
        "CLIENT" | "AUTH" | "SELECT" => "+OK\r\n".to_owned(),
        "PING" => "+PONG\r\n".to_owned(),
        "ZSCORE" => {
            let Some((key, member)) = command.get(1).zip(command.get(2)) else {
                return "-ERR wrong number of arguments\r\n".to_owned();
            };
            let score = data
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .sorted_scores
                .get(&(key.clone(), member.clone()))
                .copied();
            score.map_or_else(
                || "$-1\r\n".to_owned(),
                |score| bulk_string(&score.to_string()),
            )
        }
        "ZCOUNT" => {
            let Some(key) = command.get(1) else {
                return "-ERR wrong number of arguments\r\n".to_owned();
            };
            let count = data
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .vhost_counts
                .get(key)
                .copied()
                .unwrap_or(0);
            format!(":{count}\r\n")
        }
        "HMGET" => {
            let Some(key) = command.get(1) else {
                return "-ERR wrong number of arguments\r\n".to_owned();
            };
            let counts = data
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .class_counts
                .get(key)
                .copied()
                .unwrap_or_default();
            let mut response = format!("*{}\r\n", command.len().saturating_sub(2));
            for field in command.iter().skip(2) {
                let index = match field.as_str() {
                    "dynamic" => Some(0),
                    "malicious" => Some(1),
                    "spam" => Some(2),
                    "static" => Some(3),
                    "path" => Some(4),
                    _ => None,
                };
                if let Some(index) = index {
                    response.push_str(&bulk_string(&counts[index].to_string()));
                } else {
                    response.push_str("$-1\r\n");
                }
            }
            response
        }
        "EXISTS" => {
            let present = command.get(1).is_some_and(|key| {
                data.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .existing_keys
                    .contains(key)
            });
            format!(":{}\r\n", u8::from(present))
        }
        _ => "-ERR unsupported command\r\n".to_owned(),
    }
}

fn bulk_string(value: &str) -> String {
    format!("${}\r\n{value}\r\n", value.len())
}

struct Fixture {
    root: PathBuf,
    address: SocketAddr,
    server: Child,
    _guard: tokio::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    async fn start(
        upstream: &str,
        local: Option<&str>,
        trusted_proxy: bool,
        swarm: Option<bool>,
    ) -> Self {
        Self::start_with_args(upstream, local, trusted_proxy, swarm, &[]).await
    }

    async fn start_with_args(
        upstream: &str,
        local: Option<&str>,
        trusted_proxy: bool,
        swarm: Option<bool>,
        extra_args: &[&str],
    ) -> Self {
        let guard = TEST_LOCK.lock().await;
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "project-charlotte-swarm-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.html"), "swarm test").unwrap();
        let config_path = root.join("vhosts.yaml");
        std::fs::write(&config_path, vhost_config(&root, &worker_user(), swarm)).unwrap();

        let address = common::reserve_tcp_address();
        let mut command = Command::new(env!("CARGO_BIN_EXE_project-charlotte"));
        command
            .arg("--bind")
            .arg(address.to_string())
            .arg("--root")
            .arg(&root)
            .arg("--config")
            .arg(&config_path)
            .arg("--swarm-redis")
            .arg(upstream)
            .arg("--swarm-machine-key")
            .arg("test-machine")
            .arg("--swarm-vhost-threshold")
            .arg("1")
            .arg("--swarm-timeout-ms")
            .arg("1000")
            .arg("--swarm-neg-cache-ttl")
            .arg("1")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        if let Some(local) = local {
            command.arg("--swarm-local-redis").arg(local);
        }
        if trusted_proxy {
            command.arg("--trusted-proxy").arg("127.0.0.1");
        }
        command.args(extra_args);
        let mut server = common::spawn(&mut command).unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            if TcpStream::connect(address).await.is_ok() {
                break;
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
            root,
            address,
            server,
            _guard: guard,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        common::shutdown(&mut self.server);
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn vhost_config(root: &std::path::Path, user: &str, swarm: Option<bool>) -> String {
    let swarm_line = swarm.map_or_else(String::new, |enabled| format!("    swarm: {enabled}\n"));
    format!(
        "vhost:\n  - server_names: [swarm.test]\n    root: {:?}\n    user: {user:?}\n{swarm_line}",
        root.to_string_lossy()
    )
}

fn worker_user() -> String {
    let current = User::from_uid(geteuid()).unwrap().unwrap();
    if current.uid.as_raw() != 0 {
        current.name
    } else {
        User::from_name("nobody").unwrap().unwrap().name
    }
}

async fn request(address: SocketAddr, forwarded_ip: Option<&str>) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let forwarded =
        forwarded_ip.map_or_else(String::new, |ip| format!("X-Forwarded-For: {ip}\r\n"));
    stream
        .write_all(
            format!(
                "GET /index.html HTTP/1.1\r\nHost: swarm.test\r\n{forwarded}Connection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn global_blocklist_returns_proxy_compatible_429() {
    let redis = MockRedis::start().await;
    redis.update(|data| {
        data.sorted_scores
            .insert(("blocklist:global".to_owned(), "127.0.0.1".to_owned()), 0.0);
    });
    let fixture = Fixture::start(&redis.url(), None, false, None).await;

    let response = request(fixture.address, None).await;
    assert!(response.starts_with("HTTP/1.1 429"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("block-reason: global blocklist"),
        "{response}"
    );
}

#[tokio::test]
async fn expired_global_score_is_allowed_and_vhost_threshold_blocks() {
    let redis = MockRedis::start().await;
    let expired = chrono::Local::now().timestamp() as f64 - 1.0;
    redis.update(|data| {
        data.sorted_scores.insert(
            ("blocklist:global".to_owned(), "127.0.0.1".to_owned()),
            expired,
        );
        data.vhost_counts
            .insert("198.51.100.10_vhosts".to_owned(), 2);
    });
    let fixture = Fixture::start(&redis.url(), None, true, None).await;

    let allowed = request(fixture.address, None).await;
    assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");

    let forwarded = request(fixture.address, Some("198.51.100.10")).await;
    assert!(forwarded.starts_with("HTTP/1.1 429"), "{forwarded}");
    assert!(forwarded.contains("OverVhostCnt(2)"), "{forwarded}");
}

#[tokio::test]
async fn classification_limits_use_pipelined_hit_and_class_queries() {
    let redis = MockRedis::start().await;
    let ip = "198.51.100.11";
    let now = chrono::Local::now();
    redis.update(|data| {
        data.vhost_counts.insert(format!("{ip}_vhosts"), 2);
        for minute in 1..=5 {
            let bucket = now - chrono::Duration::seconds(minute * 60);
            let prefix = bucket.format("%H%M");
            data.sorted_scores
                .insert((format!("{prefix}_hits"), ip.to_owned()), 1.0);
            data.class_counts
                .insert(format!("{prefix}_{ip}_classes"), [0, 4, 0, 1, 0]);
        }
    });
    let fixture = Fixture::start_with_args(
        &redis.url(),
        None,
        true,
        None,
        &[
            "--swarm-vhost-threshold",
            "100",
            "--swarm-class-min-vhost-count",
            "1",
            "--swarm-hit-threshold",
            "1",
            "--swarm-classification-limits",
            "--swarm-malicious-pct",
            "0.5",
        ],
    )
    .await;

    let response = request(fixture.address, Some(ip)).await;
    assert!(response.starts_with("HTTP/1.1 429"), "{response}");
    assert!(response.contains("OverClassMal("), "{response}");
}

#[tokio::test]
async fn local_customer_blocklist_returns_403() {
    let upstream = MockRedis::start().await;
    let local = MockRedis::start().await;
    local.update(|data| {
        data.existing_keys
            .insert("customer_blocklist_127.0.0.1".to_owned());
    });
    let fixture = Fixture::start(&upstream.url(), Some(&local.url()), false, None).await;

    let response = request(fixture.address, None).await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("block-reason: blacklisted(forbidden)"),
        "{response}"
    );
}

#[tokio::test]
async fn trusted_forwarded_client_ip_is_used_for_redis_checks() {
    let redis = MockRedis::start().await;
    redis.update(|data| {
        data.sorted_scores.insert(
            ("blocklist:global".to_owned(), "198.51.100.10".to_owned()),
            0.0,
        );
    });
    let fixture = Fixture::start(&redis.url(), None, true, None).await;

    let response = request(fixture.address, Some("198.51.100.10")).await;
    assert!(response.starts_with("HTTP/1.1 429"), "{response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("block-reason: global blocklist"),
        "{response}"
    );
}

#[tokio::test]
async fn unreachable_redis_fails_open() {
    let unused = common::reserve_tcp_address();
    let url = format!("redis://{unused}/");
    let fixture = Fixture::start(&url, None, false, None).await;

    let response = request(fixture.address, None).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}

#[tokio::test]
async fn vhost_can_opt_out_of_swarm_checks() {
    let redis = MockRedis::start().await;
    redis.update(|data| {
        data.sorted_scores
            .insert(("blocklist:global".to_owned(), "127.0.0.1".to_owned()), 0.0);
    });
    let fixture = Fixture::start(&redis.url(), None, false, Some(false)).await;

    let response = request(fixture.address, None).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
}
