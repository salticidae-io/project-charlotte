//! Opens log files and reads TLS PEM sections in a small root helper when the master drops privileges.

use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, IoSlice, IoSliceMut, Read},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::ffi::OsStringExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
};

use caps::{CapSet, Capability, CapsHashSet};
use nix::{
    errno::Errno,
    fcntl::{OFlag, open as open_fd},
    sys::{
        socket::{
            AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags, SockFlag, SockType,
            recvmsg, sendmsg, socketpair,
        },
        stat::{Mode, SFlag, fstat},
    },
    unistd::{close, geteuid},
};
use rustls::pki_types::pem::{self, PemObject};

use crate::config::Config;
use crate::pathctx::PathContext;

pub(crate) const HELPER_ARGUMENT: &str = "--internal-root-log-opener";

const MAX_PACKET_SIZE: usize = 64 * 1024;
const MAX_TLS_PEM_SIZE: usize = 1024 * 1024;
const READY: u8 = 0xff;

#[derive(Clone, Copy)]
enum RequestKind {
    OpenLog,
    ReadTlsPem,
}

struct Helper {
    socket: OwnedFd,
    _process: Child,
}

static HELPER: OnceLock<Mutex<Helper>> = OnceLock::new();

pub(crate) fn start(config: &Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if config.master_user.is_none() || !geteuid().is_root() || HELPER.get().is_some() {
        return Ok(());
    }

    let (parent, child) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC,
    )?;
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
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let helper = helper
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    request_open(helper.socket.as_raw_fd(), RequestKind::OpenLog, &path).map(Some)
}

pub(crate) fn read_tls_pem(path: &Path) -> io::Result<Option<Vec<(pem::SectionKind, Vec<u8>)>>> {
    let Some(helper) = HELPER.get() else {
        return Ok(None);
    };
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let helper = helper
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    request_tls_pem(helper.socket.as_raw_fd(), &path).map(Some)
}

pub(crate) fn run_helper(socket: RawFd) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !geteuid().is_root() {
        return Err("root log helper must run as root".into());
    }
    restrict_capabilities()?;
    close_inherited_fds(socket)?;
    serve_socket(socket, true)?;
    Ok(())
}

fn restrict_capabilities() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut retained = CapsHashSet::new();
    let dac_override = Capability::CAP_DAC_OVERRIDE;
    if caps::has_cap(None, CapSet::Permitted, dac_override)? {
        retained.insert(dac_override);
    }
    caps::clear(None, CapSet::Ambient)?;
    caps::clear(None, CapSet::Inheritable)?;
    caps::set(None, CapSet::Effective, &retained)?;
    caps::set(None, CapSet::Permitted, &retained)?;
    Ok(())
}

fn close_inherited_fds(socket: RawFd) -> io::Result<()> {
    let mut descriptors = Vec::new();
    for entry in fs::read_dir("/proc/self/fd")? {
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

fn serve_socket(socket: RawFd, send_ready: bool) -> io::Result<()> {
    if send_ready {
        send_packet(socket, &[READY], None)?;
    }
    let mut packet = vec![0; MAX_PACKET_SIZE];
    loop {
        let (length, received_fds) = receive_packet(socket, &mut packet)?;
        if length == 0 {
            close_received_fds(&received_fds);
            return Ok(());
        }
        if !received_fds.is_empty() {
            close_received_fds(&received_fds);
            send_error(socket, "log open requests must not pass file descriptors")?;
            continue;
        }
        match parse_request(&packet[..length]) {
            Ok((RequestKind::OpenLog, path)) => {
                match open_regular_file(path.clone()).path_context("open log file", &path) {
                    Ok(file) => {
                        let descriptor = file.as_raw_fd();
                        send_packet(socket, &[0], Some(descriptor))?;
                    }
                    Err(error) => send_error(socket, &error.to_string())?,
                }
            }
            Ok((RequestKind::ReadTlsPem, path)) => {
                match read_tls_pem_file(&path).and_then(encode_tls_pem_response) {
                    Ok(response) => send_packet(socket, &response, None)?,
                    Err(error) => send_error(socket, &error.to_string())?,
                }
            }
            Err(error) => send_error(socket, &error.to_string())?,
        }
    }
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

fn open_regular_file(path: PathBuf) -> io::Result<OwnedFd> {
    let flags = OFlag::O_WRONLY
        | OFlag::O_APPEND
        | OFlag::O_CREAT
        | OFlag::O_CLOEXEC
        | OFlag::O_NOFOLLOW
        | OFlag::O_NOCTTY
        | OFlag::O_NONBLOCK;
    let file = open_fd(&path, flags, Mode::from_bits_truncate(0o640)).map_err(io::Error::from)?;
    let metadata = fstat(&file).map_err(io::Error::from)?;
    if !SFlag::from_bits_truncate(metadata.st_mode).contains(SFlag::S_IFREG) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "log path is not a regular file",
        ));
    }
    Ok(file)
}

fn open_tls_file(path: &Path) -> io::Result<OwnedFd> {
    let flags = OFlag::O_RDONLY
        | OFlag::O_CLOEXEC
        | OFlag::O_NOFOLLOW
        | OFlag::O_NOCTTY
        | OFlag::O_NONBLOCK;
    let file = open_fd(path, flags, Mode::empty()).map_err(io::Error::from)?;
    let metadata = fstat(&file).map_err(io::Error::from)?;
    if !SFlag::from_bits_truncate(metadata.st_mode).contains(SFlag::S_IFREG) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TLS PEM path is not a regular file",
        ));
    }
    if metadata.st_size < 0 || metadata.st_size as u64 > MAX_TLS_PEM_SIZE as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TLS PEM file exceeds the 1 MiB size limit",
        ));
    }
    Ok(file)
}

fn read_tls_pem_file(path: &Path) -> io::Result<Vec<(pem::SectionKind, Vec<u8>)>> {
    let file = File::from(open_tls_file(path)?);
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
    let flags = MsgFlags::MSG_NOSIGNAL;
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
    let message = recvmsg::<()>(socket, &mut iov, Some(&mut control), MsgFlags::empty())
        .map_err(io::Error::from)?;
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

    use nix::sys::socket::{AddressFamily, SockFlag, SockType, socketpair};

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
        let regular = directory.join("access.log");
        let symlink_path = directory.join("symlink.log");
        let (server, client) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        let server_thread = thread::spawn(move || serve_socket(server.as_raw_fd(), false));

        let mut file = request_open(client.as_raw_fd(), RequestKind::OpenLog, &regular).unwrap();
        file.write_all(b"first\n").unwrap();
        drop(file);
        assert!(request_open(client.as_raw_fd(), RequestKind::OpenLog, &directory).is_err());

        fs::write(&regular, b"target\n").unwrap();
        symlink(&regular, &symlink_path).unwrap();
        assert!(request_open(client.as_raw_fd(), RequestKind::OpenLog, &symlink_path).is_err());

        drop(client);
        server_thread.join().unwrap().unwrap();
        let mut contents = String::new();
        File::open(&regular)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "target\n");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn reads_only_tls_pem_sections_and_rejects_symlinks() {
        let directory = temp_dir();
        let pem_path = directory.join("cert-and-key.pem");
        let symlink_path = directory.join("symlink.pem");
        let text_path = directory.join("text.pem");
        let (server, client) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC,
        )
        .unwrap();
        let server_thread = thread::spawn(move || serve_socket(server.as_raw_fd(), false));

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
