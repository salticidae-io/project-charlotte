//! Drops master privileges and narrows process capabilities.

#[cfg(feature = "acme")]
use std::path::Path;
use std::{
    error::Error,
    ffi::{CStr, CString},
    io,
};
#[cfg(feature = "hosting")]
use std::{os::unix::process::CommandExt, process::Command};

#[cfg(target_os = "linux")]
use caps::{CapSet, Capability, CapsHashSet};
#[cfg(target_os = "linux")]
use nix::sys::prctl::set_keepcaps;
#[cfg(all(feature = "hosting", target_os = "linux"))]
use nix::unistd::setgroups;
use nix::unistd::{Group, User, geteuid, setgid, setuid};

#[cfg(feature = "acme")]
use nix::unistd::{FchownatFlags, Gid, Uid, fchownat};

use crate::config::Config;
#[cfg(feature = "acme")]
use crate::pathctx::PathContext;

#[cfg(all(feature = "hosting", target_os = "linux"))]
const SETUID: Capability = Capability::CAP_SETUID;
#[cfg(all(feature = "hosting", target_os = "linux"))]
const SETGID: Capability = Capability::CAP_SETGID;
#[cfg(all(feature = "hosting", target_os = "linux"))]
const KILL: Capability = Capability::CAP_KILL;
#[cfg(target_os = "linux")]
const NET_BIND_SERVICE: Capability = Capability::CAP_NET_BIND_SERVICE;

pub(crate) fn drop_master(config: &Config) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(user_name) = &config.master_user {
        if !geteuid().is_root() {
            return Err("--user requires the server to start as root".into());
        }
        let user = User::from_name(user_name)?
            .ok_or_else(|| format!("unknown user for --user: {user_name}"))?;
        let gid = match &config.master_group {
            Some(group_name) => {
                Group::from_name(group_name)?
                    .ok_or_else(|| format!("unknown group for --group: {group_name}"))?
                    .gid
            }
            None => user.gid,
        };
        crate::log_debug!(
            "Dropping master privileges to user {user_name} (uid {}) and gid {}",
            user.uid.as_raw(),
            gid.as_raw()
        );
        let group_count = supplementary_groups(user.uid, gid)?.len();
        let user_name_c = CString::new(user.name.as_str())?;
        #[cfg(feature = "acme")]
        if let Some(settings) = &config.acme {
            prepare_acme_cache(&settings.cache, user.uid, gid)?;
        }
        if let Some(socket) = &config.control_socket {
            crate::control::prepare_socket_directory(
                socket,
                Some((user.uid.as_raw(), gid.as_raw())),
            )?;
        }
        #[cfg(target_os = "linux")]
        let keep_net_bind_service = caps::has_cap(None, CapSet::Permitted, NET_BIND_SERVICE)?;
        #[cfg(target_os = "linux")]
        set_keepcaps(true)?;
        initialize_groups(user_name_c.as_c_str(), gid)?;
        crate::log_debug!(
            "Initialized {group_count} supplementary groups for master user {user_name}"
        );
        setgid(gid)?;
        setuid(user.uid)?;
        #[cfg(target_os = "linux")]
        set_keepcaps(false)?;
        #[cfg(target_os = "linux")]
        retain_master_capabilities(keep_net_bind_service, false)?;
        crate::log_debug!(
            "Master privileges dropped to uid {} and gid {}",
            user.uid.as_raw(),
            gid.as_raw()
        );
    }
    // Only a build that hosts sites starts workers under other accounts, so
    // only it has a use for the identity-changing capabilities.
    #[cfg(all(feature = "hosting", target_os = "linux"))]
    if config.master_user.is_none() && !geteuid().is_root() {
        let permitted = caps::read(None, CapSet::Permitted)?;
        if permitted.contains(&SETUID) && permitted.contains(&SETGID) {
            let keep_net_bind_service = permitted.contains(&NET_BIND_SERVICE);
            let mut effective = CapsHashSet::new();
            effective.insert(SETUID);
            effective.insert(SETGID);
            if permitted.contains(&KILL) {
                effective.insert(KILL);
            }
            if keep_net_bind_service {
                effective.insert(NET_BIND_SERVICE);
            }
            caps::set(None, CapSet::Effective, &effective)?;
            setgroups(&[])?;
            retain_master_capabilities(keep_net_bind_service, true)?;
        }
    }
    Ok(())
}

pub(crate) fn supplementary_groups(
    uid: nix::unistd::Uid,
    gid: nix::unistd::Gid,
) -> Result<Vec<nix::unistd::Gid>, Box<dyn Error + Send + Sync>> {
    let Some(user) = User::from_uid(uid)? else {
        return Ok(vec![gid]);
    };
    let user_name = CString::new(user.name)?;
    groups_for_user(user_name.as_c_str(), gid)
}

#[cfg(target_os = "linux")]
fn groups_for_user(
    user_name: &CStr,
    gid: nix::unistd::Gid,
) -> Result<Vec<nix::unistd::Gid>, Box<dyn Error + Send + Sync>> {
    Ok(nix::unistd::getgrouplist(user_name, gid)?)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn groups_for_user(
    user_name: &CStr,
    gid: nix::unistd::Gid,
) -> Result<Vec<nix::unistd::Gid>, Box<dyn Error + Send + Sync>> {
    let mut capacity = 16_usize;
    loop {
        let mut groups = vec![0 as libc::c_int; capacity];
        let mut count = capacity as libc::c_int;
        // SAFETY: the C string is NUL-terminated and the group array has `count` slots.
        let result = unsafe {
            libc::getgrouplist(
                user_name.as_ptr(),
                gid.as_raw() as libc::c_int,
                groups.as_mut_ptr(),
                &mut count,
            )
        };
        if result >= 0 {
            groups.truncate(count as usize);
            let mut groups = groups
                .into_iter()
                .map(|group| nix::unistd::Gid::from_raw(group as libc::gid_t))
                .collect::<Vec<_>>();
            if !groups.contains(&gid) {
                groups.push(gid);
            }
            return Ok(groups);
        }
        if capacity >= 65_536 {
            return Err(io::Error::last_os_error().into());
        }
        capacity *= 2;
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn initialize_groups(user_name: &CStr, gid: nix::unistd::Gid) -> io::Result<()> {
    nix::unistd::initgroups(user_name, gid).map_err(io::Error::from)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) fn initialize_groups(user_name: &CStr, gid: nix::unistd::Gid) -> io::Result<()> {
    // SAFETY: the C string is NUL-terminated and the group ID is valid for this process.
    if unsafe { libc::initgroups(user_name.as_ptr(), gid.as_raw() as libc::c_int) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(feature = "hosting", target_os = "linux"))]
pub(crate) fn set_groups(groups: &[nix::unistd::Gid]) -> io::Result<()> {
    nix::unistd::setgroups(groups).map_err(io::Error::from)
}

#[cfg(all(feature = "hosting", target_os = "macos"))]
#[allow(unsafe_code)]
pub(crate) fn set_groups(groups: &[nix::unistd::Gid]) -> io::Result<()> {
    let groups = groups
        .iter()
        .map(|group| group.as_raw() as libc::gid_t)
        .collect::<Vec<_>>();
    let count = libc::c_int::try_from(groups.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "too many supplementary groups")
    })?;
    // SAFETY: the group array is valid for `count` elements for the duration of the call.
    if unsafe { libc::setgroups(count, groups.as_ptr()) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn get_groups() -> io::Result<Vec<nix::unistd::Gid>> {
    nix::unistd::getgroups().map_err(io::Error::from)
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(crate) fn get_groups() -> io::Result<Vec<nix::unistd::Gid>> {
    // SAFETY: a null pointer is permitted when querying the number of group IDs.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    // SAFETY: the vector has space for the group count reported by the preceding call.
    let actual = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if actual < 0 {
        return Err(io::Error::last_os_error());
    }
    groups.truncate(actual as usize);
    Ok(groups.into_iter().map(nix::unistd::Gid::from_raw).collect())
}

#[cfg(feature = "acme")]
fn prepare_acme_cache(path: &Path, uid: Uid, gid: Gid) -> io::Result<()> {
    match std::fs::symlink_metadata(path).path_context("inspect ACME cache directory", path) {
        Ok(metadata) if !metadata.file_type().is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "ACME cache path {} must be a real directory, not a symlink",
                    path.display()
                ),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).path_context("create ACME cache directory", path)?;
        }
        Err(error) => return Err(error),
    }

    let metadata =
        std::fs::symlink_metadata(path).path_context("inspect ACME cache directory", path)?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "ACME cache path {} must be a real directory",
                path.display()
            ),
        ));
    }

    let current_directory = std::fs::File::open(".")
        .path_context("open current directory for ACME cache", Path::new("."))?;
    for entry in std::fs::read_dir(path).path_context("read ACME cache directory", path)? {
        let entry = entry.path_context("read ACME cache directory entry", path)?;
        let entry_path = entry.path();
        if entry
            .file_type()
            .path_context("inspect ACME cache entry", &entry_path)?
            .is_file()
        {
            fchownat(
                &current_directory,
                &entry_path,
                Some(uid),
                Some(gid),
                FchownatFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map_err(io::Error::from)
            .path_context("change ownership of ACME cache file", &entry_path)?;
        }
    }

    fchownat(
        &current_directory,
        path,
        Some(uid),
        Some(gid),
        FchownatFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(io::Error::from)
    .path_context("change ownership of ACME cache directory", path)?;
    crate::log_debug!(
        "Prepared ACME cache {} for uid {} and gid {}",
        path.display(),
        uid.as_raw(),
        gid.as_raw()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn retain_master_capabilities(
    keep_net_bind_service: bool,
    keep_worker_capabilities: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    #[cfg(not(feature = "hosting"))]
    let _ = keep_worker_capabilities;
    let mut retained = CapsHashSet::new();
    #[cfg(feature = "hosting")]
    if keep_worker_capabilities {
        retained.insert(SETUID);
        retained.insert(SETGID);
        if caps::has_cap(None, CapSet::Permitted, KILL)? {
            retained.insert(KILL);
        }
    }
    if keep_net_bind_service {
        retained.insert(NET_BIND_SERVICE);
    }

    caps::clear(None, CapSet::Ambient)?;
    caps::clear(None, CapSet::Inheritable)?;
    caps::set(None, CapSet::Effective, &retained)?;
    caps::set(None, CapSet::Permitted, &retained)?;
    Ok(())
}

#[cfg(feature = "hosting")]
#[allow(unsafe_code)]
pub(crate) fn apply_identity(
    command: &mut Command,
    uid: u32,
    gid: u32,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    use nix::unistd::{Gid, Uid, setgid, setuid};

    let uid = Uid::from_raw(uid);
    let gid = Gid::from_raw(gid);
    let groups = supplementary_groups(uid, gid)?;
    // SAFETY: the callback performs only credential syscalls using values prepared before fork.
    unsafe {
        command.pre_exec(move || {
            set_groups(&groups)?;
            setgid(gid).map_err(io::Error::from)?;
            setuid(uid).map_err(io::Error::from)?;
            Ok(())
        });
    }
    Ok(())
}

#[cfg(all(feature = "hosting", target_os = "linux"))]
pub(crate) fn clear_all() -> Result<(), Box<dyn Error + Send + Sync>> {
    caps::clear(None, CapSet::Ambient)?;
    caps::clear(None, CapSet::Effective)?;
    caps::clear(None, CapSet::Inheritable)?;
    caps::clear(None, CapSet::Permitted)?;
    Ok(())
}

#[cfg(all(feature = "hosting", not(target_os = "linux")))]
pub(crate) fn clear_all() -> Result<(), Box<dyn Error + Send + Sync>> {
    Ok(())
}

#[cfg(all(feature = "hosting", target_os = "linux"))]
pub(crate) fn can_set_ids() -> Result<bool, Box<dyn Error + Send + Sync>> {
    if geteuid().is_root() {
        return Ok(true);
    }
    Ok(caps::has_cap(None, CapSet::Effective, SETUID)?
        && caps::has_cap(None, CapSet::Effective, SETGID)?)
}

#[cfg(all(feature = "hosting", not(target_os = "linux")))]
pub(crate) fn can_set_ids() -> Result<bool, Box<dyn Error + Send + Sync>> {
    Ok(geteuid().is_root())
}

#[cfg(all(test, feature = "acme"))]
mod tests {
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use nix::unistd::{getegid, geteuid};

    use super::prepare_acme_cache;

    static NEXT_TEMPORARY_PATH: AtomicU64 = AtomicU64::new(0);

    fn temporary_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "charlotte-acme-cache-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn prepares_existing_cache_and_regular_entries() {
        let cache = temporary_path();
        std::fs::create_dir(&cache).unwrap();
        let cert = cache.join("cert.pem");
        std::fs::write(&cert, b"certificate").unwrap();
        let link = cache.join("cert-link.pem");
        std::os::unix::fs::symlink(&cert, &link).unwrap();

        prepare_acme_cache(&cache, geteuid(), getegid()).unwrap();

        assert!(std::fs::metadata(&cache).unwrap().is_dir());
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn creates_missing_cache_directory() {
        let cache = temporary_path();

        prepare_acme_cache(&cache, geteuid(), getegid()).unwrap();

        assert!(std::fs::metadata(&cache).unwrap().is_dir());
        std::fs::remove_dir_all(cache).unwrap();
    }

    #[test]
    fn rejects_symlink_cache_directory() {
        let target = temporary_path();
        std::fs::create_dir(&target).unwrap();
        let cache = temporary_path();
        std::os::unix::fs::symlink(&target, &cache).unwrap();

        let error = prepare_acme_cache(&cache, geteuid(), getegid()).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            std::fs::symlink_metadata(&cache)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_file(cache).unwrap();
        std::fs::remove_dir_all(target).unwrap();
    }
}

#[cfg(all(test, feature = "hosting"))]
mod supplementary_groups_tests {
    use nix::unistd::{Gid, Uid, getegid, geteuid};

    use super::supplementary_groups;

    #[test]
    fn supplementary_groups_include_the_primary_group() {
        let gid = getegid();

        let groups = supplementary_groups(geteuid(), gid).unwrap();

        assert!(groups.contains(&gid));
    }

    #[test]
    fn unknown_user_falls_back_to_the_primary_group() {
        let gid = Gid::from_raw(12345);

        let groups = supplementary_groups(Uid::from_raw(u32::MAX), gid).unwrap();

        assert_eq!(groups, vec![gid]);
    }
}
