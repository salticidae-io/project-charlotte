use std::error::Error;

use caps::{CapSet, Capability, CapsHashSet};
use nix::{
    sys::prctl::set_keepcaps,
    unistd::{Group, User, geteuid, setgid, setgroups, setuid},
};

use crate::config::Config;

#[cfg(feature = "hosting")]
const SETUID: Capability = Capability::CAP_SETUID;
#[cfg(feature = "hosting")]
const SETGID: Capability = Capability::CAP_SETGID;
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
        let keep_net_bind_service = caps::has_cap(None, CapSet::Permitted, NET_BIND_SERVICE)?;

        set_keepcaps(true)?;
        setgroups(&[])?;
        setgid(gid)?;
        setuid(user.uid)?;
        set_keepcaps(false)?;
        retain_master_capabilities(keep_net_bind_service)?;
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

fn retain_master_capabilities(
    keep_net_bind_service: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut retained = CapsHashSet::new();
    #[cfg(feature = "hosting")]
    {
        retained.insert(SETUID);
        retained.insert(SETGID);
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
