//! Root-only integration tests for master and hosted-worker identity setup.

#![cfg(all(target_os = "linux", feature = "hosting"))]
#![forbid(unsafe_code)]

mod common;

use std::{
    ffi::CString,
    fs,
    net::{SocketAddr, TcpStream as StdTcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

use nix::unistd::{Gid, Group, User, geteuid, getgrouplist};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

struct RunningServer(Child);

impl Drop for RunningServer {
    fn drop(&mut self) {
        common::shutdown(&mut self.0);
    }
}

struct CgroupCleanup(String);

impl Drop for CgroupCleanup {
    fn drop(&mut self) {
        let group = PathBuf::from("/sys/fs/cgroup").join(&self.0);
        let _ = fs::remove_dir(group.join("site"));
        let _ = fs::remove_dir(group);
    }
}

fn temp_root(name: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("project-charlotte-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).unwrap();
    path
}

fn nobody() -> (User, Group) {
    assert!(geteuid().is_root(), "this test requires root");
    let user = User::from_name("nobody")
        .unwrap()
        .expect("root test environment must provide the nobody account");
    let group = Group::from_gid(user.gid)
        .unwrap()
        .expect("nobody's primary group must exist");
    (user, group)
}

fn expected_groups(user: &User, primary: Gid) -> Vec<u32> {
    let name = CString::new(user.name.as_str()).unwrap();
    let mut groups = getgrouplist(name.as_c_str(), primary)
        .unwrap()
        .into_iter()
        .map(Gid::as_raw)
        .collect::<Vec<_>>();
    groups.sort_unstable();
    groups.dedup();
    groups
}

fn proc_field(pid: u32, name: &str) -> Vec<String> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix(&format!("{name}:"))
                .map(|value| value.split_whitespace().map(str::to_owned).collect())
        })
        .unwrap_or_else(|| panic!("/proc/{pid}/status has no {name} field"))
}

fn wait_until_ready(pid: u32, address: SocketAddr, server: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = server.try_wait().unwrap() {
            panic!("server exited before listening: {status}");
        }
        if StdTcpStream::connect(address).is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "server {pid} did not become ready"
        );
        sleep(Duration::from_millis(20));
    }
}

fn parse_caps(pid: u32, name: &str) -> u64 {
    u64::from_str_radix(&proc_field(pid, name)[0], 16).unwrap()
}

#[test]
#[ignore = "requires root; run in the privileged CI job with cargo test -- --ignored"]
fn master_drop_uses_target_groups_and_removes_identity_capabilities() {
    let (user, group) = nobody();
    let root = temp_root("master-groups");
    fs::write(root.join("index.html"), "ready").unwrap();
    let address = common::reserve_tcp_address();
    let binary = common::worker_accessible_server_binary(&root);
    let mut command = Command::new(binary);
    command
        .arg("--user")
        .arg(&user.name)
        .arg("--group")
        .arg(&group.name)
        .arg("--bind")
        .arg(address.to_string())
        .arg("--root")
        .arg(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut server = RunningServer(common::spawn(&mut command).unwrap());
    let pid = server.0.id();
    wait_until_ready(pid, address, &mut server.0);

    assert_eq!(proc_field(pid, "Uid")[1], user.uid.as_raw().to_string());
    assert_eq!(proc_field(pid, "Gid")[1], group.gid.as_raw().to_string());
    let mut actual_groups = proc_field(pid, "Groups")
        .iter()
        .map(|group| group.parse::<u32>().unwrap())
        .collect::<Vec<_>>();
    actual_groups.sort_unstable();
    assert_eq!(actual_groups, expected_groups(&user, group.gid));

    const IDENTITY_CAPABILITIES: u64 = (1 << 1) | (1 << 5) | (1 << 6) | (1 << 7);
    for field in ["CapEff", "CapPrm"] {
        let caps = parse_caps(pid, field);
        assert_eq!(caps & IDENTITY_CAPABILITIES, 0, "{field}: {caps:#x}");
    }
    drop(server);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test]
#[ignore = "requires root; run in the privileged CI job with cargo test -- --ignored"]
async fn hosted_worker_uses_the_configured_users_supplementary_groups() {
    let (user, group) = nobody();
    let base = temp_root("worker-groups");
    let site = base.join("site");
    fs::create_dir(&site).unwrap();
    fs::write(site.join("index.html"), "worker response").unwrap();
    let config = base.join("vhosts.yaml");
    fs::write(
        &config,
        format!(
            "vhost:\n  - server_names: [groups.example.test]\n    root: {:?}\n    user: {:?}\n    group: {:?}\n",
            site,
            user.name,
            group.name
        ),
    )
    .unwrap();
    let address = common::reserve_tcp_address();
    let binary = common::worker_accessible_server_binary(&base);
    let mut command = Command::new(binary);
    command
        .arg("--bind")
        .arg(address.to_string())
        .arg("--root")
        .arg(&base)
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut server = RunningServer(common::spawn(&mut command).unwrap());
    let master_pid = server.0.id();
    wait_until_ready(master_pid, address, &mut server.0);

    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            b"GET /index.html HTTP/1.1\r\nHost: groups.example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
    assert!(response.ends_with(b"worker response"), "{response:?}");

    let deadline = Instant::now() + Duration::from_secs(5);
    let worker_pid = loop {
        if let Some(status) = server.0.try_wait().unwrap() {
            panic!("server exited before worker remained inspectable: {status}");
        }
        if let Some(worker_pid) = common::descendants_with_argument(master_pid, "--worker")
            .into_iter()
            .next()
        {
            break worker_pid;
        }
        assert!(
            Instant::now() < deadline,
            "hosted worker did not stay alive"
        );
        sleep(Duration::from_millis(20));
    };

    assert_eq!(
        proc_field(worker_pid, "Uid")[1],
        user.uid.as_raw().to_string()
    );
    assert_eq!(
        proc_field(worker_pid, "Gid")[1],
        group.gid.as_raw().to_string()
    );
    let mut actual_groups = proc_field(worker_pid, "Groups")
        .iter()
        .map(|group| group.parse::<u32>().unwrap())
        .collect::<Vec<_>>();
    actual_groups.sort_unstable();
    assert_eq!(actual_groups, expected_groups(&user, group.gid));

    drop(server);
    fs::remove_dir_all(base).unwrap();
}

#[tokio::test]
#[ignore = "requires root and a writable cgroup v2 hierarchy; run in the privileged CI job with cargo test -- --ignored"]
async fn hosted_worker_joins_its_configured_cgroup_before_exec() {
    let (user, group) = nobody();
    let base = temp_root("worker-cgroup");
    let site = base.join("site");
    fs::create_dir(&site).unwrap();
    fs::write(site.join("index.html"), "cgroup worker response").unwrap();

    let cgroup = format!("charlotte-test-{}/site", std::process::id());
    let cgroup_path = PathBuf::from("/sys/fs/cgroup").join(&cgroup);
    assert!(
        !cgroup_path.exists(),
        "refusing to reuse existing test cgroup {}",
        cgroup_path.display()
    );
    let _cgroup_cleanup = CgroupCleanup(format!("charlotte-test-{}", std::process::id()));

    let config = base.join("vhosts.yaml");
    fs::write(
        &config,
        format!(
            "vhost:\n  - server_names: [cgroup.example.test]\n    root: {:?}\n    user: {:?}\n    group: {:?}\n    cgroup: {:?}\n    cgroup_pids_max: 32\n",
            site,
            user.name,
            group.name,
            cgroup
        ),
    )
    .unwrap();
    let address = common::reserve_tcp_address();
    let binary = common::worker_accessible_server_binary(&base);
    let mut command = Command::new(binary);
    command
        .arg("--user")
        .arg(&user.name)
        .arg("--group")
        .arg(&group.name)
        .arg("--bind")
        .arg(address.to_string())
        .arg("--root")
        .arg(&base)
        .arg("--config")
        .arg(&config)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut server = RunningServer(common::spawn(&mut command).unwrap());
    let master_pid = server.0.id();
    wait_until_ready(master_pid, address, &mut server.0);

    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            b"GET /index.html HTTP/1.1\r\nHost: cgroup.example.test\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
    assert!(
        response.ends_with(b"cgroup worker response"),
        "{response:?}"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    let worker_pid = loop {
        if let Some(status) = server.0.try_wait().unwrap() {
            panic!("server exited before cgroup worker remained inspectable: {status}");
        }
        if let Some(worker_pid) = common::descendants_with_argument(master_pid, "--worker")
            .into_iter()
            .next()
        {
            break worker_pid;
        }
        assert!(
            Instant::now() < deadline,
            "hosted cgroup worker did not stay alive"
        );
        sleep(Duration::from_millis(20));
    };

    let memberships = fs::read_to_string(format!("/proc/{worker_pid}/cgroup")).unwrap();
    assert!(
        memberships
            .lines()
            .any(|line| line.ends_with(&format!("::/{cgroup}"))),
        "worker is not in {cgroup}: {memberships}"
    );
    assert_eq!(
        fs::read_to_string(cgroup_path.join("pids.max"))
            .unwrap()
            .trim(),
        "32"
    );

    drop(server);
    drop(_cgroup_cleanup);
    fs::remove_dir_all(base).unwrap();
}
