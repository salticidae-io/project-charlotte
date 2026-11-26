//! Opens log files and reads TLS PEM sections in a small root helper when the master drops privileges.

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::os::fd::BorrowedFd;
use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    fs::{self, File},
    io::{self, IoSlice, IoSliceMut, Read},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};

#[cfg(target_os = "linux")]
use caps::{CapSet, Capability, CapsHashSet};
use nix::{
    errno::Errno,
    fcntl::OFlag,
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::signal::{Signal, kill},
    sys::{
        socket::{
            AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
            recvmsg, sendmsg, socketpair,
        },
        stat::{SFlag, fstat},
    },
    unistd::{Pid, close, geteuid},
};
#[cfg(target_os = "macos")]
use nix::{fcntl::openat, sys::stat::Mode};
use rustls::pki_types::pem::{self, PemObject};

use crate::pathctx::PathContext;
use crate::{cgroup::CgroupSpec, config::Config};

pub(crate) const HELPER_ARGUMENT: &str = "--internal-root-log-opener";

const MAX_PACKET_SIZE: usize = 64 * 1024;
const MAX_TLS_PEM_SIZE: usize = 1024 * 1024;
const READY: u8 = 0xff;

#[cfg(target_os = "linux")]
const SOCKET_FLAGS: SockFlag = SockFlag::SOCK_CLOEXEC;
#[cfg(target_os = "macos")]
const SOCKET_FLAGS: SockFlag = SockFlag::empty();
#[cfg(target_os = "linux")]
const SOCKET_TYPE: SockType = SockType::SeqPacket;
#[cfg(target_os = "macos")]
const SOCKET_TYPE: SockType = SockType::Datagram;

fn socketpair_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let (first, second) = socketpair(AddressFamily::Unix, SOCKET_TYPE, None, SOCKET_FLAGS)
        .map_err(io::Error::from)?;
    set_cloexec(first.as_raw_fd())?;
    set_cloexec(second.as_raw_fd())?;
    #[cfg(target_os = "macos")]
    {
        set_nosigpipe(first.as_raw_fd())?;
        set_nosigpipe(second.as_raw_fd())?;
    }
    Ok((first, second))
}

#[allow(unsafe_code)]
fn set_cloexec(descriptor: RawFd) -> io::Result<()> {
    // SAFETY: fcntl is called with a valid descriptor and integer commands.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fcntl updates descriptor flags for the valid descriptor.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn set_nosigpipe(descriptor: RawFd) -> io::Result<()> {
    let enabled: libc::c_int = 1;
    // SAFETY: the option value is a valid integer and the socket descriptor is open.
    if unsafe {
        libc::setsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum RequestKind {
    OpenLog,
    ReadTlsPem,
}

struct AllowedDirectory {
    path: PathBuf,
    descriptor: OwnedFd,
}

struct AllowedDirectories {
    logs: Vec<AllowedDirectory>,
    tls: Vec<AllowedDirectory>,
}

struct Helper {
    socket: OwnedFd,
    _process: Child,
}

static HELPER: OnceLock<Mutex<Helper>> = OnceLock::new();

pub(crate) fn is_active() -> bool {
    HELPER.get().is_some()
}

pub(crate) fn start(config: &Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if config.master_user.is_none() || !geteuid().is_root() || HELPER.get().is_some() {
        return Ok(());
    }

    // The helper pins its directories when it is configured, which is before
    // the privilege drop prepares the ACME cache.
    #[cfg(feature = "acme")]
    if let Some(acme) = &config.acme
        && let Err(error) = fs::symlink_metadata(&acme.cache)
        && error.kind() == io::ErrorKind::NotFound
    {
        fs::create_dir_all(&acme.cache).path_context("create ACME cache directory", &acme.cache)?;
    }
    let (log_dirs, tls_dirs) = crate::vhost::helper_directories(config)?;
    let configure = configure_packet(&log_dirs, &tls_dirs)?;
    let (parent, child) = socketpair_cloexec()?;
    let stderr = config
        .error_log_file
        .as_deref()
        .map(crate::logging::open_log_file)
        .transpose()?;
    let mut process = Command::new(std::env::current_exe()?)
        .arg(HELPER_ARGUMENT)
        .env_clear()
        .stdin(Stdio::from(child))
        .stdout(Stdio::null())
        .stderr(stderr.map_or_else(Stdio::inherit, Stdio::from))
        .spawn()?;
    crate::log_debug!("Started root log/TLS helper with pid {}", process.id());

    let mut response = [0; 1];
    let ready = receive_packet(parent.as_raw_fd(), &mut response).and_then(|(length, fds)| {
        close_received_fds(&fds);
        if length == 1 && response[0] == READY {
            Ok(())
        } else {
            Err(io::Error::other("root log helper did not become ready"))
        }
    });
    if let Err(error) = ready {
        let _ = process.kill();
        let _ = process.wait();
        return Err(error.into());
    }
    if let Err(error) = request_configure(parent.as_raw_fd(), &configure) {
        let _ = process.kill();
        let _ = process.wait();
        return Err(error.into());
    }

    HELPER
        .set(Mutex::new(Helper {
            socket: parent,
            _process: process,
        }))
        .map_err(|_| io::Error::other("root log helper was already started"))?;
    Ok(())
}

pub(crate) fn open(path: &Path) -> io::Result<Option<File>> {
    let Some(helper) = HELPER.get() else {
        return Ok(None);
    };
    let path = helper_request_path(path)?;
    let helper = helper
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    request_open(helper.socket.as_raw_fd(), RequestKind::OpenLog, &path).map(Some)
}

pub(crate) fn read_tls_pem(path: &Path) -> io::Result<Option<Vec<(pem::SectionKind, Vec<u8>)>>> {
    let Some(helper) = HELPER.get() else {
        return Ok(None);
    };
    let path = helper_request_path(path)?;
    let helper = helper
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    request_tls_pem(helper.socket.as_raw_fd(), &path).map(Some)
}

#[cfg(feature = "hosting")]
pub(crate) fn spawn_worker(
    uid: u32,
    gid: u32,
    args: &[OsString],
    environment: &[(OsString, OsString)],
    stderr_path: Option<&Path>,
    cgroup: Option<&CgroupSpec>,
    child_socket: OwnedFd,
) -> io::Result<u64> {
    let helper = HELPER
        .get()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "root helper is not active"))?;
    let stderr_path = stderr_path.map(helper_request_path).transpose()?;
    let request = spawn_worker_packet(uid, gid, args, environment, stderr_path.as_deref(), cgroup)?;
    let helper = helper
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    send_packet(
        helper.socket.as_raw_fd(),
        &request,
        Some(child_socket.as_raw_fd()),
    )?;
    let mut response = [0; 9];
    let (length, received_fds) = receive_packet(helper.socket.as_raw_fd(), &mut response)?;
    close_received_fds(&received_fds);
    match (response[0], length) {
        (0, 9) => Ok(u64::from_be_bytes(response[1..9].try_into().map_err(
            |_| io::Error::new(io::ErrorKind::InvalidData, "invalid worker id"),
        )?)),
        (1, length) if length > 1 => Err(io::Error::other(String::from_utf8_lossy(
            &response[1..length],
        ))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid root helper worker response",
        )),
    }
}

#[cfg(feature = "hosting")]
pub(crate) fn stop_worker(id: u64, force: bool) -> io::Result<()> {
    let helper = HELPER
        .get()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "root helper is not active"))?;
    let helper = helper
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut request = vec![4, u8::from(force)];
    request.extend_from_slice(&id.to_be_bytes());
    send_packet(helper.socket.as_raw_fd(), &request, None)?;
    let mut response = [0; 1024];
    let (length, received_fds) = receive_packet(helper.socket.as_raw_fd(), &mut response)?;
    close_received_fds(&received_fds);
    match response.first().copied() {
        Some(0) if length == 1 => Ok(()),
        Some(1) if length > 1 => Err(io::Error::other(String::from_utf8_lossy(
            &response[1..length],
        ))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid root helper worker-stop response",
        )),
    }
}

#[allow(unsafe_code)]
pub(crate) fn run_helper(socket: RawFd) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !geteuid().is_root() {
        return Err("root log helper must run as root".into());
    }
    restrict_capabilities()?;
    close_inherited_fds(socket)?;
    // SAFETY: the internal helper is launched with stdin owned by this process as its socket.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    serve_socket(socket, true)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn restrict_capabilities() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut retained = CapsHashSet::new();
    let dac_override = Capability::CAP_DAC_OVERRIDE;
    if caps::has_cap(None, CapSet::Permitted, dac_override)? {
        retained.insert(dac_override);
    }
    #[cfg(feature = "hosting")]
    for capability in [
        Capability::CAP_SETUID,
        Capability::CAP_SETGID,
        Capability::CAP_KILL,
    ] {
        if caps::has_cap(None, CapSet::Permitted, capability)? {
            retained.insert(capability);
        }
    }
    caps::clear(None, CapSet::Ambient)?;
    caps::clear(None, CapSet::Inheritable)?;
    caps::set(None, CapSet::Effective, &retained)?;
    caps::set(None, CapSet::Permitted, &retained)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn restrict_capabilities() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Ok(())
}

fn close_inherited_fds(socket: RawFd) -> io::Result<()> {
    let mut descriptors = Vec::new();
    #[cfg(target_os = "linux")]
    let descriptor_directory = "/proc/self/fd";
    #[cfg(not(target_os = "linux"))]
    let descriptor_directory = "/dev/fd";
    for entry in fs::read_dir(descriptor_directory)? {
        let entry = entry?;
        if let Some(descriptor) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
            && descriptor != socket
            && !(0..=2).contains(&descriptor)
        {
            descriptors.push(descriptor);
        }
    }
    for descriptor in descriptors {
        if let Err(error) = close(descriptor)
            && error != Errno::EBADF
        {
            return Err(error.into());
        }
    }
    Ok(())
}

fn serve_socket(socket: OwnedFd, send_ready: bool) -> io::Result<()> {
    let socket_fd = socket.as_raw_fd();
    if send_ready {
        send_packet(socket_fd, &[READY], None)?;
    }
    let mut packet = vec![0; MAX_PACKET_SIZE];
    let mut allowed_directories = None;
    let mut workers = HashMap::new();
    let mut next_worker_id = 1u64;
    loop {
        let mut poll_fds = [PollFd::new(socket.as_fd(), PollFlags::POLLIN)];
        match poll(&mut poll_fds, PollTimeout::from(1000u16)) {
            Ok(0) => {
                reap_workers(&mut workers);
                continue;
            }
            Ok(_) => {}
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(error.into()),
        }
        #[cfg(target_os = "macos")]
        let disconnected = poll_fds[0]
            .revents()
            .is_some_and(|events| events.intersects(PollFlags::POLLHUP | PollFlags::POLLERR));
        #[cfg(not(target_os = "macos"))]
        let disconnected = false;
        let (length, received_fds) = if disconnected {
            (0, Vec::new())
        } else {
            match receive_packet(socket_fd, &mut packet) {
                Ok(packet) => packet,
                #[cfg(target_os = "macos")]
                Err(error) if error.raw_os_error() == Some(libc::ECONNRESET) => (0, Vec::new()),
                Err(error) => return Err(error),
            }
        };
        if length == 0 {
            close_received_fds(&received_fds);
            for (_, mut child) in workers.drain() {
                if let Err(error) = terminate_worker(&mut child, false) {
                    crate::log_error!("Could not stop helper worker on master disconnect: {error}");
                }
            }
            return Ok(());
        }
        let child_socket = if packet[0] == 3 && received_fds.len() == 1 {
            Some(own_received_fd(received_fds[0]))
        } else {
            None
        };
        if packet[0] == 3 && child_socket.is_none() {
            close_received_fds(&received_fds);
            send_error(
                socket_fd,
                "worker spawn requests require exactly one socket descriptor",
            )?;
            continue;
        }
        if packet[0] != 3 && !received_fds.is_empty() {
            close_received_fds(&received_fds);
            send_error(
                socket_fd,
                "this root helper request must not pass file descriptors",
            )?;
            continue;
        }
        if packet[0] == 2 {
            if allowed_directories.is_some() {
                send_error(socket_fd, "root helper directories are already configured")?;
                continue;
            }
            match parse_configure(&packet[..length]).and_then(open_allowed_directories) {
                Ok(directories) => {
                    allowed_directories = Some(directories);
                    send_packet(socket_fd, &[0], None)?;
                }
                Err(error) => send_error(socket_fd, &error.to_string())?,
            }
            continue;
        }
        let Some(directories) = allowed_directories.as_ref() else {
            drop(child_socket);
            send_error(socket_fd, "root helper directories are not configured")?;
            continue;
        };
        if packet[0] == 3 {
            let child_socket = child_socket.expect("validated worker socket descriptor");
            match parse_spawn_worker(&packet[..length])
                .and_then(|request| spawn_worker_process(request, child_socket, directories))
            {
                Ok(mut child) => {
                    let id = next_worker_id;
                    let Some(next_id) = next_worker_id.checked_add(1) else {
                        let _ = terminate_worker(&mut child, true);
                        send_error(socket_fd, "root helper worker id space exhausted")?;
                        continue;
                    };
                    next_worker_id = next_id;
                    workers.insert(id, child);
                    let mut response = vec![0];
                    response.extend_from_slice(&id.to_be_bytes());
                    send_packet(socket_fd, &response, None)?;
                }
                Err(error) => send_error(socket_fd, &error.to_string())?,
            }
            continue;
        }
        if packet[0] == 4 {
            // A worker that already exited may have been reaped, so an
            // unknown id is not an error.
            match parse_stop_worker(&packet[..length]).and_then(|(id, force)| {
                match workers.remove(&id) {
                    Some(mut child) => terminate_worker(&mut child, force),
                    None => Ok(()),
                }
            }) {
                Ok(()) => send_packet(socket_fd, &[0], None)?,
                Err(error) => send_error(socket_fd, &error.to_string())?,
            }
            continue;
        }
        match parse_request(&packet[..length]) {
            Ok((RequestKind::OpenLog, path)) => {
                match open_allowed_file(&path, &directories.logs, true)
                    .path_context("open log file", &path)
                {
                    Ok(file) => {
                        let descriptor = file.as_raw_fd();
                        send_packet(socket_fd, &[0], Some(descriptor))?;
                    }
                    Err(error) => send_error(socket_fd, &error.to_string())?,
                }
            }
            Ok((RequestKind::ReadTlsPem, path)) => {
                match read_allowed_tls_pem(&path, &directories.tls)
                    .and_then(encode_tls_pem_response)
                {
                    Ok(response) => send_packet(socket_fd, &response, None)?,
                    Err(error) => send_error(socket_fd, &error.to_string())?,
                }
            }
            Err(error) => send_error(socket_fd, &error.to_string())?,
        }
    }
}

struct SpawnWorkerRequest {
    uid: u32,
    gid: u32,
    args: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    stderr_path: Option<PathBuf>,
    cgroup: Option<CgroupSpec>,
}

#[cfg_attr(not(feature = "hosting"), allow(dead_code))]
fn spawn_worker_packet(
    uid: u32,
    gid: u32,
    args: &[OsString],
    environment: &[(OsString, OsString)],
    stderr_path: Option<&Path>,
    cgroup: Option<&CgroupSpec>,
) -> io::Result<Vec<u8>> {
    let request = SpawnWorkerRequest {
        uid,
        gid,
        args: args.to_vec(),
        environment: environment.to_vec(),
        stderr_path: stderr_path.map(Path::to_path_buf),
        cgroup: cgroup.cloned(),
    };
    validate_spawn_worker(&request)?;
    let args_count = u16::try_from(args.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many worker arguments"))?;
    let env_count = u16::try_from(environment.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many worker variables"))?;
    let mut packet = vec![3];
    packet.extend_from_slice(&uid.to_be_bytes());
    packet.extend_from_slice(&gid.to_be_bytes());
    packet.extend_from_slice(&args_count.to_be_bytes());
    for argument in args {
        push_os_string(&mut packet, argument)?;
    }
    packet.extend_from_slice(&env_count.to_be_bytes());
    for (key, value) in environment {
        push_os_string(&mut packet, key)?;
        push_os_string(&mut packet, value)?;
    }
    if let Some(path) = stderr_path {
        packet.push(1);
        push_os_string(&mut packet, path.as_os_str())?;
    } else {
        packet.push(0);
    }
    if let Some(spec) = cgroup {
        packet.push(1);
        push_os_string(&mut packet, spec.path.as_os_str())?;
        push_optional_string(&mut packet, spec.memory_max.as_deref())?;
        push_optional_string(&mut packet, spec.cpu_max.as_deref())?;
        push_optional_string(&mut packet, spec.pids_max.as_deref())?;
    } else {
        packet.push(0);
    }
    if packet.len() > MAX_PACKET_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root helper worker request is too large",
        ));
    }
    Ok(packet)
}

#[cfg_attr(not(feature = "hosting"), allow(dead_code))]
fn push_os_string(packet: &mut Vec<u8>, value: &std::ffi::OsStr) -> io::Result<()> {
    let bytes = value.as_bytes();
    if bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "worker arguments and environment must not contain NUL bytes",
        ));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "worker field is too long"))?;
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(bytes);
    Ok(())
}

fn push_optional_string(packet: &mut Vec<u8>, value: Option<&str>) -> io::Result<()> {
    if let Some(value) = value {
        packet.push(1);
        push_os_string(packet, std::ffi::OsStr::new(value))?;
    } else {
        packet.push(0);
    }
    Ok(())
}

fn parse_spawn_worker(packet: &[u8]) -> io::Result<SpawnWorkerRequest> {
    if packet.len() < 11 || packet[0] != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete worker spawn request",
        ));
    }
    let uid = u32::from_be_bytes(
        packet[1..5]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid worker uid"))?,
    );
    let gid = u32::from_be_bytes(
        packet[5..9]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid worker gid"))?,
    );
    let mut offset = 9;
    let args_count = read_u16(packet, &mut offset)?;
    let mut args = Vec::with_capacity(usize::from(args_count));
    for _ in 0..args_count {
        args.push(read_os_string(packet, &mut offset)?);
    }
    let env_count = read_u16(packet, &mut offset)?;
    let mut environment = Vec::with_capacity(usize::from(env_count));
    for _ in 0..env_count {
        environment.push((
            read_os_string(packet, &mut offset)?,
            read_os_string(packet, &mut offset)?,
        ));
    }
    let stderr_path = match packet.get(offset).copied() {
        Some(0) => {
            offset += 1;
            None
        }
        Some(1) => {
            offset += 1;
            Some(PathBuf::from(read_os_string(packet, &mut offset)?))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid worker stderr path flag",
            ));
        }
    };
    let cgroup = match packet.get(offset).copied() {
        Some(0) => {
            offset += 1;
            None
        }
        Some(1) => {
            offset += 1;
            let path = read_os_string(packet, &mut offset)?;
            let path = path.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "cgroup path must be UTF-8")
            })?;
            if path.starts_with('/') {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "worker cgroup path must be relative to /sys/fs/cgroup",
                ));
            }
            let memory_max = read_optional_string(packet, &mut offset)?;
            let cpu_max = read_optional_string(packet, &mut offset)?;
            let pids_max = read_optional_string(packet, &mut offset)?;
            Some(
                CgroupSpec::new(
                    path,
                    memory_max.as_deref(),
                    cpu_max.as_deref(),
                    pids_max.as_deref(),
                )
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            )
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid worker cgroup flag",
            ));
        }
    };
    if offset != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing data in worker spawn request",
        ));
    }
    let request = SpawnWorkerRequest {
        uid,
        gid,
        args,
        environment,
        stderr_path,
        cgroup,
    };
    validate_spawn_worker(&request)?;
    Ok(request)
}

fn read_u16(packet: &[u8], offset: &mut usize) -> io::Result<u16> {
    let bytes = packet
        .get(
            *offset..offset.checked_add(2).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid worker request offset")
            })?,
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "incomplete worker count"))?;
    *offset += 2;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_os_string(packet: &[u8], offset: &mut usize) -> io::Result<OsString> {
    let bytes = packet
        .get(
            *offset..offset.checked_add(4).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid worker request offset")
            })?,
        )
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "incomplete worker field"))?;
    let length = usize::try_from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid worker field length"))?;
    *offset += 4;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid worker field length"))?;
    let bytes = packet
        .get(*offset..end)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "incomplete worker field"))?;
    if bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "worker arguments and environment must not contain NUL bytes",
        ));
    }
    *offset = end;
    Ok(OsString::from_vec(bytes.to_vec()))
}

fn read_optional_string(packet: &[u8], offset: &mut usize) -> io::Result<Option<String>> {
    match packet.get(*offset).copied() {
        Some(0) => {
            *offset += 1;
            Ok(None)
        }
        Some(1) => {
            *offset += 1;
            read_os_string(packet, offset)?
                .into_string()
                .map(Some)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "cgroup limit must be UTF-8")
                })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid optional cgroup limit flag",
        )),
    }
}

fn validate_spawn_worker(request: &SpawnWorkerRequest) -> io::Result<()> {
    if request.uid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "root helper refuses to spawn a uid 0 worker",
        ));
    }
    let uid = request.uid.to_string();
    let gid = request.gid.to_string();
    let expected = [
        Some("--worker"),
        Some("--worker-uid"),
        Some(uid.as_str()),
        Some("--worker-gid"),
        Some(gid.as_str()),
    ];
    if request.args.len() < expected.len()
        || request
            .args
            .iter()
            .take(expected.len())
            .zip(expected)
            .any(|(argument, expected)| argument.to_str() != expected)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "worker arguments must begin with --worker --worker-uid UID --worker-gid GID",
        ));
    }
    let mut names = HashSet::new();
    for (name, value) in &request.environment {
        if !allowed_worker_environment(name.as_bytes()) || !names.insert(name) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "worker environment contains a disallowed or duplicate variable",
            ));
        }
        if value.as_bytes().contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker environment values must not contain NUL bytes",
            ));
        }
    }
    if let Some(path) = &request.stderr_path
        && (!path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir)))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "worker stderr path must be absolute and contain no '..' components",
        ));
    }
    if let Some(spec) = &request.cgroup {
        if spec.path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "worker cgroup path must be relative to /sys/fs/cgroup",
            ));
        }
        CgroupSpec::new(
            spec.path.to_str().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "cgroup path must be UTF-8")
            })?,
            spec.memory_max.as_deref(),
            spec.cpu_max.as_deref(),
            spec.pids_max.as_deref(),
        )?;
    }
    Ok(())
}

fn allowed_worker_environment(name: &[u8]) -> bool {
    matches!(
        name,
        b"PATH"
            | b"TMPDIR"
            | b"LD_LIBRARY_PATH"
            | b"LANG"
            | b"TZ"
            | b"MALLOC_ARENA_MAX"
            | b"CHARLOTTE_FASTCGI_APP_ENV"
    )
}

#[cfg(not(feature = "hosting"))]
fn spawn_worker_process(
    _request: SpawnWorkerRequest,
    _child_socket: OwnedFd,
    _directories: &AllowedDirectories,
) -> io::Result<Child> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "this build does not host sites",
    ))
}

#[cfg(feature = "hosting")]
fn spawn_worker_process(
    request: SpawnWorkerRequest,
    child_socket: OwnedFd,
    directories: &AllowedDirectories,
) -> io::Result<Child> {
    let mut command = Command::new(crate::worker_executable()?);
    command
        .args(&request.args)
        .env_clear()
        .envs(request.environment.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::from(child_socket))
        .current_dir("/");
    if let Some(path) = request.stderr_path {
        let stderr = open_allowed_file(&path, &directories.logs, true)?;
        command.stderr(Stdio::from(File::from(stderr)));
    }
    if let Some(spec) = request.cgroup.as_ref() {
        let cgroup_procs = crate::cgroup::prepare(spec).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "could not prepare worker cgroup {}: {error}",
                    spec.path.display()
                ),
            )
        })?;
        crate::cgroup::apply_to_command(&mut command, cgroup_procs);
    }
    crate::privileges::apply_identity(&mut command, request.uid, request.gid)
        .map_err(io::Error::other)?;
    command.spawn()
}

fn parse_stop_worker(packet: &[u8]) -> io::Result<(u64, bool)> {
    if packet.len() != 10 || packet[0] != 4 || packet[1] > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid root helper worker-stop request",
        ));
    }
    let id = u64::from_be_bytes(packet[2..10].try_into().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid root helper worker id")
    })?);
    Ok((id, packet[1] == 1))
}

fn reap_workers(workers: &mut HashMap<u64, Child>) {
    workers.retain(|id, child| match child.try_wait() {
        Ok(Some(status)) => {
            crate::log_debug!("Reaped root-helper worker {id} with status {status}");
            false
        }
        Ok(None) => true,
        Err(error) => {
            crate::log_error!("Could not inspect root-helper worker {id}: {error}");
            true
        }
    });
}

fn terminate_worker(child: &mut Child, force: bool) -> io::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    if !force {
        let pid = i32::try_from(child.id())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid worker pid"))?;
        let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            if child.try_wait()?.is_some() {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    if let Err(error) = child.kill()
        && child.try_wait()?.is_none()
    {
        return Err(error);
    }
    child.wait()?;
    Ok(())
}

fn helper_request_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    normalize_absolute_path(&absolute)
}

fn normalize_absolute_path(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root helper paths must be absolute",
        ));
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if components.pop().is_none() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "root helper path cannot escape the filesystem root",
                    ));
                }
            }
            std::path::Component::Normal(component) => components.push(component.to_os_string()),
            std::path::Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid root helper path prefix",
                ));
            }
        }
    }
    let mut normalized = PathBuf::from("/");
    for component in components {
        normalized.push(component);
    }
    Ok(normalized)
}

fn configure_packet(log_dirs: &[PathBuf], tls_dirs: &[PathBuf]) -> io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;

    let mut packet = vec![2];
    for directories in [log_dirs, tls_dirs] {
        let count = u16::try_from(directories.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "too many helper directories")
        })?;
        packet.extend_from_slice(&count.to_be_bytes());
        for directory in directories {
            let bytes = directory.as_os_str().as_bytes();
            let length = u32::try_from(bytes.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path is too long"))?;
            packet.extend_from_slice(&length.to_be_bytes());
            packet.extend_from_slice(bytes);
        }
    }
    if packet.len() > MAX_PACKET_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root helper directory configuration is too large",
        ));
    }
    Ok(packet)
}

fn request_configure(socket: RawFd, request: &[u8]) -> io::Result<()> {
    send_packet(socket, request, None)?;
    let mut response = [0; 1024];
    let (length, received_fds) = receive_packet(socket, &mut response)?;
    close_received_fds(&received_fds);
    match response.first().copied() {
        Some(0) if length == 1 => Ok(()),
        Some(1) if length > 1 => Err(io::Error::other(String::from_utf8_lossy(
            &response[1..length],
        ))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid root helper configuration response",
        )),
    }
}

fn parse_configure(packet: &[u8]) -> io::Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    use std::os::unix::ffi::OsStringExt;

    if packet.first() != Some(&2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid root helper configuration request",
        ));
    }
    let mut offset = 1;
    let mut read_directories = || -> io::Result<Vec<PathBuf>> {
        let count_bytes = packet.get(offset..offset + 2).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "incomplete directory count")
        })?;
        offset += 2;
        let count = u16::from_be_bytes([count_bytes[0], count_bytes[1]]);
        let mut directories = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let length_bytes = packet.get(offset..offset + 4).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incomplete directory path length",
                )
            })?;
            offset += 4;
            let length = usize::try_from(u32::from_be_bytes([
                length_bytes[0],
                length_bytes[1],
                length_bytes[2],
                length_bytes[3],
            ]))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid path length"))?;
            let bytes = packet
                .get(
                    offset..offset.checked_add(length).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid path length")
                    })?,
                )
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "incomplete directory path")
                })?;
            offset += length;
            directories.push(PathBuf::from(OsString::from_vec(bytes.to_vec())));
        }
        Ok(directories)
    };
    let logs = read_directories()?;
    let tls = read_directories()?;
    if offset != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing data in root helper configuration",
        ));
    }
    Ok((logs, tls))
}

fn open_allowed_directories(
    (logs, tls): (Vec<PathBuf>, Vec<PathBuf>),
) -> io::Result<AllowedDirectories> {
    Ok(AllowedDirectories {
        logs: open_directory_list(logs)?,
        tls: open_directory_list(tls)?,
    })
}

fn open_directory_list(paths: Vec<PathBuf>) -> io::Result<Vec<AllowedDirectory>> {
    paths
        .into_iter()
        .map(|path| {
            let path = normalize_absolute_path(&path)?;
            if path == Path::new("/") {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the root directory cannot be allowlisted",
                ));
            }
            let file = File::open(&path).path_context("open root helper directory", &path)?;
            let metadata = file.metadata()?;
            if !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("helper path is not a directory: {}", path.display()),
                ));
            }
            Ok(AllowedDirectory {
                path,
                descriptor: file.into(),
            })
        })
        .collect()
}

fn parse_request(packet: &[u8]) -> io::Result<(RequestKind, PathBuf)> {
    if packet.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete root helper request",
        ));
    }
    let kind = match packet[0] {
        0 => RequestKind::OpenLog,
        1 => RequestKind::ReadTlsPem,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown root helper request kind",
            ));
        }
    };
    let length = u32::from_be_bytes(
        packet[1..5]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid path length"))?,
    ) as usize;
    if length != packet.len() - 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid root helper request length",
        ));
    }
    Ok((
        kind,
        PathBuf::from(OsString::from_vec(packet[5..].to_vec())),
    ))
}

fn open_allowed_file(
    path: &Path,
    directories: &[AllowedDirectory],
    log: bool,
) -> io::Result<OwnedFd> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "root helper paths must be absolute and contain no '..' components",
        ));
    }
    let (directory, relative) = directories
        .iter()
        .find_map(|directory| {
            path.strip_prefix(&directory.path)
                .ok()
                .filter(|relative| !relative.as_os_str().is_empty())
                .map(|relative| (directory, relative))
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is outside the directories the root helper was started with; add its directory with --log-dir or --tls-dir, or restart the server",
                    path.display()
                ),
            )
        })?;
    let flags = if log {
        OFlag::O_WRONLY
            | OFlag::O_APPEND
            | OFlag::O_CREAT
            | OFlag::O_CLOEXEC
            | OFlag::O_NOFOLLOW
            | OFlag::O_NOCTTY
            | OFlag::O_NONBLOCK
    } else {
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NOCTTY | OFlag::O_NONBLOCK
    };
    let mode = if log { 0o640 } else { 0 };
    let file = openat2_beneath(directory.descriptor.as_raw_fd(), relative, flags, mode)?;
    let metadata = fstat(&file).map_err(io::Error::from)?;
    if !SFlag::from_bits_truncate(metadata.st_mode).contains(SFlag::S_IFREG) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root helper path is not a regular file",
        ));
    }
    if !log && (metadata.st_size < 0 || metadata.st_size as u64 > MAX_TLS_PEM_SIZE as u64) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS PEM file exceeds the 1 MiB size limit",
        ));
    }
    Ok(file)
}

fn read_allowed_tls_pem(
    path: &Path,
    directories: &[AllowedDirectory],
) -> io::Result<Vec<(pem::SectionKind, Vec<u8>)>> {
    let file = File::from(open_allowed_file(path, directories, false)?);
    let mut contents = Vec::new();
    file.take((MAX_TLS_PEM_SIZE + 1) as u64)
        .read_to_end(&mut contents)?;
    if contents.len() > MAX_TLS_PEM_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS PEM file exceeds the 1 MiB size limit",
        ));
    }
    tls_pem_sections(contents.as_slice())
}

#[cfg(target_os = "linux")]
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
#[cfg(target_os = "linux")]
const RESOLVE_BENEATH: u64 = 0x08;

#[cfg(target_os = "linux")]
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn openat2_beneath(
    directory: RawFd,
    relative: &Path,
    flags: OFlag,
    mode: u32,
) -> io::Result<OwnedFd> {
    use std::{os::fd::FromRawFd, os::unix::ffi::OsStrExt};

    let path = CString::new(relative.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    let flags = u64::try_from(flags.bits())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid open flags"))?;
    let how = OpenHow {
        flags,
        mode: u64::from(mode),
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `path` is NUL-terminated, `how` is a valid open_how structure, and
    // `directory` is a live directory descriptor retained by the helper.
    let descriptor = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_openat2,
            directory,
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(nix::libc::ENOSYS) {
            return Err(io::Error::new(
                error.kind(),
                "openat2 is unavailable (os error 38); the root helper needs Linux 5.6 or \
                 later, and a seccomp sandbox such as systemd's RestrictSUIDSGID=true blocks it",
            ));
        }
        return Err(error);
    }
    let descriptor = RawFd::try_from(descriptor)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid file descriptor"))?;
    // SAFETY: the successful syscall returned a new descriptor owned by this call.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn openat2_beneath(
    directory: RawFd,
    relative: &Path,
    flags: OFlag,
    mode: u32,
) -> io::Result<OwnedFd> {
    let components = relative.components().collect::<Vec<_>>();
    let mut parent: Option<OwnedFd> = None;
    for (index, component) in components.iter().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "root helper paths must contain only normal path components",
            ));
        };
        let is_final = index + 1 == components.len();
        let open_flags = if is_final {
            flags
        } else {
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC
        };
        let open_mode =
            if is_final {
                Mode::from_bits_truncate(u16::try_from(mode).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "invalid file mode")
                })?)
            } else {
                Mode::empty()
            };
        let descriptor = if let Some(parent) = parent.as_ref() {
            openat(parent, *name, open_flags, open_mode)
        } else {
            // SAFETY: the caller passes a live directory descriptor retained by the helper.
            let directory = unsafe { BorrowedFd::borrow_raw(directory) };
            openat(directory, *name, open_flags, open_mode)
        }
        .map_err(io::Error::from)?;
        if is_final {
            return Ok(descriptor);
        }
        parent = Some(descriptor);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "root helper path must name a file",
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn openat2_beneath(
    _directory: RawFd,
    _relative: &Path,
    _flags: OFlag,
    _mode: u32,
) -> io::Result<OwnedFd> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the root helper requires Linux openat2",
    ))
}

pub(crate) fn tls_pem_sections(reader: impl Read) -> io::Result<Vec<(pem::SectionKind, Vec<u8>)>> {
    <(pem::SectionKind, Vec<u8>)>::pem_reader_iter(reader)
        .map(|section| section.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)))
        .filter_map(|section| match section {
            Ok((kind, der))
                if matches!(
                    kind,
                    pem::SectionKind::Certificate
                        | pem::SectionKind::PrivateKey
                        | pem::SectionKind::RsaPrivateKey
                        | pem::SectionKind::EcPrivateKey
                ) =>
            {
                Some(Ok((kind, der)))
            }
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .collect()
}

fn encode_tls_pem_response(sections: Vec<(pem::SectionKind, Vec<u8>)>) -> io::Result<Vec<u8>> {
    let mut response = Vec::with_capacity(1);
    response.push(2);
    for (kind, der) in sections {
        let tag = match kind {
            pem::SectionKind::Certificate => 1,
            pem::SectionKind::PrivateKey => 2,
            pem::SectionKind::RsaPrivateKey => 3,
            pem::SectionKind::EcPrivateKey => 4,
            _ => continue,
        };
        let length = u32::try_from(der.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "TLS PEM section is too large")
        })?;
        let new_len = response
            .len()
            .checked_add(5)
            .and_then(|length| length.checked_add(der.len()))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "TLS PEM response is too large")
            })?;
        if new_len > MAX_PACKET_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS certificate/key sections exceed the 64 KiB root helper response limit",
            ));
        }
        response.push(tag);
        response.extend_from_slice(&length.to_be_bytes());
        response.extend_from_slice(&der);
    }
    Ok(response)
}

fn request_packet(kind: RequestKind, path: &Path) -> io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;

    let path_bytes = path.as_os_str().as_bytes();
    let length = u32::try_from(path_bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path is too long"))?;
    let mut request = Vec::with_capacity(5 + path_bytes.len());
    request.push(match kind {
        RequestKind::OpenLog => 0,
        RequestKind::ReadTlsPem => 1,
    });
    request.extend_from_slice(&length.to_be_bytes());
    request.extend_from_slice(path_bytes);
    if request.len() > MAX_PACKET_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "root helper path is too long",
        ));
    }
    Ok(request)
}

fn request_open(socket: RawFd, kind: RequestKind, path: &Path) -> io::Result<File> {
    let request = request_packet(kind, path)?;
    send_packet(socket, &request, None)?;

    let mut response = vec![0; MAX_PACKET_SIZE];
    let (length, received_fds) = receive_packet(socket, &mut response)?;
    if length == 0 {
        close_received_fds(&received_fds);
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "root log helper closed its connection",
        ));
    }
    match (response[0], received_fds.as_slice()) {
        (0, [descriptor]) if length == 1 => Ok(File::from(own_received_fd(*descriptor))),
        (1, []) => Err(io::Error::other(String::from_utf8_lossy(
            &response[1..length],
        ))),
        _ => {
            close_received_fds(&received_fds);
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid response from root log helper",
            ))
        }
    }
}

fn request_tls_pem(socket: RawFd, path: &Path) -> io::Result<Vec<(pem::SectionKind, Vec<u8>)>> {
    let request = request_packet(RequestKind::ReadTlsPem, path)?;
    send_packet(socket, &request, None)?;

    let mut response = vec![0; MAX_PACKET_SIZE];
    let (length, received_fds) = receive_packet(socket, &mut response)?;
    if length == 0 {
        close_received_fds(&received_fds);
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "root log helper closed its connection",
        ));
    }
    match (response[0], received_fds.as_slice()) {
        (1, []) => Err(io::Error::other(String::from_utf8_lossy(
            &response[1..length],
        ))),
        (2, []) => decode_tls_pem_response(&response[1..length]),
        _ => {
            close_received_fds(&received_fds);
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TLS response from root log helper",
            ))
        }
    }
}

fn decode_tls_pem_response(mut payload: &[u8]) -> io::Result<Vec<(pem::SectionKind, Vec<u8>)>> {
    let mut sections = Vec::new();
    while !payload.is_empty() {
        if payload.len() < 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete TLS section from root log helper",
            ));
        }
        let kind = match payload[0] {
            1 => pem::SectionKind::Certificate,
            2 => pem::SectionKind::PrivateKey,
            3 => pem::SectionKind::RsaPrivateKey,
            4 => pem::SectionKind::EcPrivateKey,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown TLS section kind from root log helper",
                ));
            }
        };
        let length = u32::from_be_bytes(payload[1..5].try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid TLS section length")
        })?) as usize;
        if length > payload.len() - 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid TLS section length from root log helper",
            ));
        }
        sections.push((kind, payload[5..5 + length].to_vec()));
        payload = &payload[5 + length..];
    }
    Ok(sections)
}

fn send_error(socket: RawFd, message: &str) -> io::Result<()> {
    let message = message.as_bytes();
    let length = message.len().min(MAX_PACKET_SIZE - 1);
    let mut response = Vec::with_capacity(length + 1);
    response.push(1);
    response.extend_from_slice(&message[..length]);
    send_packet(socket, &response, None)
}

fn send_packet(socket: RawFd, packet: &[u8], descriptor: Option<RawFd>) -> io::Result<()> {
    let iov = [IoSlice::new(packet)];
    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_NOSIGNAL;
    #[cfg(target_os = "macos")]
    let flags = MsgFlags::empty();
    let sent = if let Some(descriptor) = descriptor {
        let descriptors = [descriptor];
        let control = [ControlMessage::ScmRights(&descriptors)];
        sendmsg::<()>(socket, &iov, &control, flags, None)
    } else {
        sendmsg::<()>(socket, &iov, &[], flags, None)
    }
    .map_err(io::Error::from)?;
    if sent != packet.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short write to root log helper socket",
        ));
    }
    Ok(())
}

fn receive_packet(socket: RawFd, packet: &mut [u8]) -> io::Result<(usize, Vec<RawFd>)> {
    let mut iov = [IoSliceMut::new(packet)];
    let mut control = nix::cmsg_space!([RawFd; 8]);
    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_CMSG_CLOEXEC;
    #[cfg(target_os = "macos")]
    let flags = MsgFlags::empty();
    let message =
        recvmsg::<()>(socket, &mut iov, Some(&mut control), flags).map_err(io::Error::from)?;
    let length = message.bytes;
    let truncated = message
        .flags
        .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC);
    let mut descriptors = Vec::new();
    for control_message in message.cmsgs().map_err(io::Error::from)? {
        if let ControlMessageOwned::ScmRights(received) = control_message {
            descriptors.extend(received);
        }
    }
    #[cfg(target_os = "macos")]
    for descriptor in &descriptors {
        if let Err(error) = set_cloexec(*descriptor) {
            close_received_fds(&descriptors);
            return Err(error);
        }
    }
    if truncated {
        close_received_fds(&descriptors);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized packet from root log helper",
        ));
    }
    Ok((length, descriptors))
}

fn close_received_fds(descriptors: &[RawFd]) {
    for descriptor in descriptors {
        let _ = close(*descriptor);
    }
}

#[allow(unsafe_code)]
fn own_received_fd(descriptor: RawFd) -> OwnedFd {
    // SAFETY: the descriptor came from SCM_RIGHTS in this process and ownership is transferred here once.
    unsafe { OwnedFd::from_raw_fd(descriptor) }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let id = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "project-charlotte-logopener-{}-{timestamp}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn opens_regular_files_and_rejects_directories_and_symlinks() {
        let directory = temp_dir();
        let outside = temp_dir();
        let regular = directory.join("access.log");
        let symlink_path = directory.join("symlink.log");
        let symlink_directory = directory.join("escape");
        let (server, client) = socketpair_cloexec().unwrap();
        let server_thread = thread::spawn(move || serve_socket(server, false));
        request_configure(
            client.as_raw_fd(),
            &configure_packet(
                std::slice::from_ref(&directory),
                std::slice::from_ref(&directory),
            )
            .unwrap(),
        )
        .unwrap();

        let mut file = request_open(client.as_raw_fd(), RequestKind::OpenLog, &regular).unwrap();
        file.write_all(b"first\n").unwrap();
        drop(file);
        assert!(request_open(client.as_raw_fd(), RequestKind::OpenLog, &directory).is_err());

        fs::write(&regular, b"target\n").unwrap();
        symlink(&regular, &symlink_path).unwrap();
        fs::write(outside.join("secret.log"), b"secret\n").unwrap();
        symlink(&outside, &symlink_directory).unwrap();
        assert!(request_open(client.as_raw_fd(), RequestKind::OpenLog, &symlink_path).is_err());
        assert!(
            request_open(
                client.as_raw_fd(),
                RequestKind::OpenLog,
                &directory.join("../secret.log")
            )
            .is_err()
        );
        assert!(
            request_open(
                client.as_raw_fd(),
                RequestKind::OpenLog,
                &symlink_directory.join("secret.log")
            )
            .is_err()
        );
        let error = request_open(
            client.as_raw_fd(),
            RequestKind::OpenLog,
            &outside.join("secret.log"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("--log-dir"), "{error}");
        assert!(
            request_configure(
                client.as_raw_fd(),
                &configure_packet(
                    std::slice::from_ref(&outside),
                    std::slice::from_ref(&outside)
                )
                .unwrap(),
            )
            .is_err()
        );
        assert!(
            request_open(
                client.as_raw_fd(),
                RequestKind::OpenLog,
                &outside.join("secret.log"),
            )
            .is_err()
        );

        drop(client);
        server_thread.join().unwrap().unwrap();
        assert_eq!(fs::read(outside.join("secret.log")).unwrap(), b"secret\n");
        let mut contents = String::new();
        File::open(&regular)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "target\n");
        fs::remove_dir_all(directory).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn refuses_requests_before_directories_are_configured_and_the_root_directory() {
        let directory = temp_dir();
        let (server, client) = socketpair_cloexec().unwrap();
        let server_thread = thread::spawn(move || serve_socket(server, false));

        assert!(
            request_open(
                client.as_raw_fd(),
                RequestKind::OpenLog,
                &directory.join("access.log"),
            )
            .is_err()
        );
        assert!(
            request_configure(
                client.as_raw_fd(),
                &configure_packet(&[PathBuf::from("/")], &[]).unwrap(),
            )
            .is_err()
        );
        assert!(
            request_configure(
                client.as_raw_fd(),
                &configure_packet(&[PathBuf::from("/..")], &[]).unwrap(),
            )
            .is_err()
        );

        drop(client);
        server_thread.join().unwrap().unwrap();
        assert!(!directory.join("access.log").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    fn worker_args(uid: u32, gid: u32) -> Vec<OsString> {
        [
            "--worker".to_owned(),
            "--worker-uid".to_owned(),
            uid.to_string(),
            "--worker-gid".to_owned(),
            gid.to_string(),
            "--root".to_owned(),
            "/srv/site".to_owned(),
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn worker_spawn_requests_round_trip_and_are_validated() {
        let environment = vec![(OsString::from("PATH"), OsString::from("/usr/bin"))];
        let cgroup =
            CgroupSpec::new("charlotte/{uid}", Some("64M"), Some("max"), Some("8")).unwrap();
        let packet = spawn_worker_packet(
            1000,
            1001,
            &worker_args(1000, 1001),
            &environment,
            Some(Path::new("/var/log/site/error.log")),
            Some(&cgroup),
        )
        .unwrap();
        let request = parse_spawn_worker(&packet).unwrap();
        assert_eq!(request.uid, 1000);
        assert_eq!(request.gid, 1001);
        assert_eq!(request.args, worker_args(1000, 1001));
        assert_eq!(request.environment, environment);
        assert_eq!(request.cgroup, Some(cgroup.clone()));
        assert_eq!(
            request.stderr_path.as_deref(),
            Some(Path::new("/var/log/site/error.log"))
        );
        assert!(parse_spawn_worker(&packet[..packet.len() - 1]).is_err());

        let request = |uid, args: Vec<OsString>, name: &str, stderr: Option<&str>| {
            validate_spawn_worker(&SpawnWorkerRequest {
                uid,
                gid: 1001,
                args,
                environment: vec![(OsString::from(name), OsString::from("value"))],
                stderr_path: stderr.map(PathBuf::from),
                cgroup: None,
            })
        };
        assert!(request(1000, worker_args(1000, 1001), "TZ", None).is_ok());
        assert!(request(1000, worker_args(1000, 1001), "MALLOC_ARENA_MAX", None).is_ok());
        // Root, another account's arguments, and a non-worker command line.
        assert!(request(0, worker_args(0, 1001), "TZ", None).is_err());
        assert!(request(1000, worker_args(1002, 1001), "TZ", None).is_err());
        assert!(request(1000, worker_args(1000, 0), "TZ", None).is_err());
        assert!(request(1000, vec![OsString::from(HELPER_ARGUMENT)], "TZ", None).is_err());
        assert!(request(1000, worker_args(1000, 1001), "LD_PRELOAD", None).is_err());
        assert!(request(1000, worker_args(1000, 1001), "TZ", Some("error.log")).is_err());
        assert!(request(1000, worker_args(1000, 1001), "TZ", Some("/var/log/../x")).is_err());
        assert!(
            validate_spawn_worker(&SpawnWorkerRequest {
                uid: 1000,
                gid: 1001,
                args: worker_args(1000, 1001),
                environment: vec![
                    (OsString::from("TZ"), OsString::from("UTC")),
                    (OsString::from("TZ"), OsString::from("UTC")),
                ],
                stderr_path: None,
                cgroup: None,
            })
            .is_err()
        );
    }

    #[test]
    fn worker_spawn_requires_one_descriptor_and_other_requests_none() {
        let directory = temp_dir();
        let (server, client) = socketpair_cloexec().unwrap();
        let server_thread = thread::spawn(move || serve_socket(server, false));
        request_configure(
            client.as_raw_fd(),
            &configure_packet(std::slice::from_ref(&directory), &[]).unwrap(),
        )
        .unwrap();
        let mut response = [0; 256];

        let packet =
            spawn_worker_packet(1000, 1001, &worker_args(1000, 1001), &[], None, None).unwrap();
        send_packet(client.as_raw_fd(), &packet, None).unwrap();
        let (length, _) = receive_packet(client.as_raw_fd(), &mut response).unwrap();
        assert_eq!(response[0], 1);
        assert!(String::from_utf8_lossy(&response[1..length]).contains("exactly one"));

        send_packet(
            client.as_raw_fd(),
            &[4, 0, 0, 0, 0, 0, 0, 0, 0, 9],
            Some(client.as_raw_fd()),
        )
        .unwrap();
        let (_, _) = receive_packet(client.as_raw_fd(), &mut response).unwrap();
        assert_eq!(response[0], 1);

        // Stopping a worker that is not running succeeds.
        send_packet(client.as_raw_fd(), &[4, 0, 0, 0, 0, 0, 0, 0, 0, 9], None).unwrap();
        let (length, _) = receive_packet(client.as_raw_fd(), &mut response).unwrap();
        assert_eq!(&response[..length], &[0]);

        drop(client);
        server_thread.join().unwrap().unwrap();
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reads_only_tls_pem_sections_and_rejects_symlinks() {
        let directory = temp_dir();
        let pem_path = directory.join("cert-and-key.pem");
        let symlink_path = directory.join("symlink.pem");
        let text_path = directory.join("text.pem");
        let (server, client) = socketpair_cloexec().unwrap();
        let server_thread = thread::spawn(move || serve_socket(server, false));
        request_configure(
            client.as_raw_fd(),
            &configure_packet(
                std::slice::from_ref(&directory),
                std::slice::from_ref(&directory),
            )
            .unwrap(),
        )
        .unwrap();

        fs::write(
            &pem_path,
            b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n-----BEGIN PUBLIC KEY-----\nBwgJ\n-----END PUBLIC KEY-----\n-----BEGIN PRIVATE KEY-----\nBAUG\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let sections = request_tls_pem(client.as_raw_fd(), &pem_path).unwrap();
        assert_eq!(
            sections,
            vec![
                (pem::SectionKind::Certificate, vec![1, 2, 3]),
                (pem::SectionKind::PrivateKey, vec![4, 5, 6]),
            ]
        );

        symlink(&pem_path, &symlink_path).unwrap();
        assert!(request_tls_pem(client.as_raw_fd(), &symlink_path).is_err());

        fs::write(&text_path, b"not a PEM file").unwrap();
        assert!(
            request_tls_pem(client.as_raw_fd(), &text_path)
                .unwrap()
                .is_empty()
        );

        drop(client);
        server_thread.join().unwrap().unwrap();
        fs::remove_dir_all(directory).unwrap();
    }
}
