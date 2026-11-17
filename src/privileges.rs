//! Drops master privileges and narrows process capabilities.

use std::{error::Error, ffi::CString};
#[cfg(feature = "acme")]
use std::{io, path::Path};

use caps::{CapSet, Capability, CapsHashSet};
#[cfg(feature = "hosting")]
use nix::unistd::setgroups;
use nix::{
    sys::prctl::set_keepcaps,
    unistd::{Group, User, geteuid, initgroups, setgid, setuid},
};

#[cfg(feature = "acme")]
use nix::unistd::{FchownatFlags, Gid, Uid, fchownat};

use crate::config::Config;
#[cfg(feature = "acme")]
use crate::pathctx::PathContext;

#[cfg(feature = "hosting")]
const SETUID: Capability = Capability::CAP_SETUID;
#[cfg(feature = "hosting")]
const SETGID: Capability = Capability::CAP_SETGID;
#[cfg(feature = "hosting")]
const KILL: Capability = Capability::CAP_KILL;
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
        let keep_net_bind_service = caps::has_cap(None, CapSet::Permitted, NET_BIND_SERVICE)?;

        set_keepcaps(true)?;
        initgroups(user_name_c.as_c_str(), gid)?;
        crate::log_debug!(
            "Initialized {group_count} supplementary groups for master user {user_name}"
        );
        setgid(gid)?;
        setuid(user.uid)?;
        set_keepcaps(false)?;
        retain_master_capabilities(keep_net_bind_service)?;
        crate::log_debug!(
            "Master privileges dropped to uid {} and gid {}",
            user.uid.as_raw(),
            gid.as_raw()
        );
    }
    // Only a build that hosts sites starts workers under other accounts, so
    // only it has a use for the identity-changing capabilities.
    #[cfg(feature = "hosting")]
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
            retain_master_capabilities(keep_net_bind_service)?;
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
    Ok(nix::unistd::getgrouplist(user_name.as_c_str(), gid)?)
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

fn retain_master_capabilities(
    keep_net_bind_service: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut retained = CapsHashSet::new();
    #[cfg(feature = "hosting")]
    {
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
pub(crate) fn clear_all() -> Result<(), Box<dyn Error + Send + Sync>> {
    caps::clear(None, CapSet::Ambient)?;
    caps::clear(None, CapSet::Effective)?;
    caps::clear(None, CapSet::Inheritable)?;
    caps::clear(None, CapSet::Permitted)?;
    Ok(())
}

#[cfg(feature = "hosting")]
pub(crate) fn can_set_ids() -> Result<bool, Box<dyn Error + Send + Sync>> {
    if geteuid().is_root() {
        return Ok(true);
    }
    Ok(caps::has_cap(None, CapSet::Effective, SETUID)?
        && caps::has_cap(None, CapSet::Effective, SETGID)?)
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
