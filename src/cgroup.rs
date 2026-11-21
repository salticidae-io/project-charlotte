//! Validates and prepares cgroup v2 groups for hosted workers.

use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CgroupSpec {
    pub(crate) path: PathBuf,
    pub(crate) memory_max: Option<String>,
    pub(crate) cpu_max: Option<String>,
    pub(crate) pids_max: Option<String>,
}

impl CgroupSpec {
    pub(crate) fn new(
        path: &str,
        memory_max: Option<&str>,
        cpu_max: Option<&str>,
        pids_max: Option<&str>,
    ) -> io::Result<Self> {
        Ok(Self {
            path: validate_path(path)?,
            memory_max: memory_max.map(normalize_memory_max).transpose()?,
            cpu_max: cpu_max.map(normalize_cpu_max).transpose()?,
            pids_max: pids_max.map(normalize_pids_max).transpose()?,
        })
    }

    pub(crate) fn expand(&self, uid: u32, gid: u32, name: &str) -> io::Result<Self> {
        let safe_name = name
            .replace("*.", "wildcard.")
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let expanded = self
            .path
            .to_string_lossy()
            .replace("{uid}", &uid.to_string())
            .replace("{gid}", &gid.to_string())
            .replace("{name}", &safe_name);
        Self::new(
            &expanded,
            self.memory_max.as_deref(),
            self.cpu_max.as_deref(),
            self.pids_max.as_deref(),
        )
    }
}

pub(crate) fn validate_path(path: &str) -> io::Result<PathBuf> {
    if path.chars().any(char::is_control) {
        return Err(invalid("cgroup path cannot contain control characters"));
    }
    let relative = path.trim_start_matches('/');
    if relative.is_empty() {
        return Err(invalid(
            "cgroup path must name a group below /sys/fs/cgroup",
        ));
    }
    for component in relative.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(invalid("cgroup path has an empty, '.' or '..' component"));
        }
        if component.starts_with("cgroup.") {
            return Err(invalid(
                "cgroup path components cannot start with 'cgroup.'",
            ));
        }
        validate_placeholders(component)?;
    }
    Ok(PathBuf::from(relative))
}

fn validate_placeholders(component: &str) -> io::Result<()> {
    let mut remaining = component;
    while let Some(open) = remaining.find('{') {
        remaining = &remaining[open + 1..];
        let close = remaining
            .find('}')
            .ok_or_else(|| invalid("unclosed placeholder in cgroup path"))?;
        if !matches!(&remaining[..close], "uid" | "gid" | "name") {
            return Err(invalid(
                "cgroup path placeholders must be {uid}, {gid} or {name}",
            ));
        }
        remaining = &remaining[close + 1..];
    }
    if remaining.contains('}') {
        return Err(invalid("unmatched '}' in cgroup path"));
    }
    Ok(())
}

pub(crate) fn normalize_memory_max(value: &str) -> io::Result<String> {
    if value == "max" {
        return Ok(value.to_owned());
    }
    let (number, multiplier) = match value.as_bytes().last() {
        Some(b'K' | b'k') => (&value[..value.len() - 1], 1_u64 << 10),
        Some(b'M' | b'm') => (&value[..value.len() - 1], 1_u64 << 20),
        Some(b'G' | b'g') => (&value[..value.len() - 1], 1_u64 << 30),
        Some(b'T' | b't') => (&value[..value.len() - 1], 1_u64 << 40),
        _ => (value, 1),
    };
    let bytes = number
        .parse::<u64>()
        .ok()
        .and_then(|number| number.checked_mul(multiplier))
        .filter(|bytes| *bytes > 0)
        .ok_or_else(|| invalid("memory limit must be 'max' or a positive byte count with an optional K/M/G/T suffix"))?;
    Ok(bytes.to_string())
}

pub(crate) fn normalize_cpu_max(value: &str) -> io::Result<String> {
    if value == "max" {
        return Ok("max 100000".to_owned());
    }
    if let Some(percent) = value.strip_suffix('%') {
        let quota = percent
            .parse::<u64>()
            .ok()
            .filter(|percent| *percent > 0)
            .and_then(|percent| percent.checked_mul(1_000))
            .ok_or_else(|| invalid("CPU percentage must be a positive integer followed by '%'"))?;
        return Ok(format!("{quota} 100000"));
    }
    let mut parts = value.split_ascii_whitespace();
    let quota_value = parts.next();
    let period = parts
        .next()
        .map_or(Ok(100_000), |part| part.parse::<u64>())
        .map_err(|_| invalid("CPU period must be an integer from 1000 through 1000000"))?;
    if parts.next().is_some() || !(1_000..=1_000_000).contains(&period) {
        return Err(invalid(
            "CPU limit must be QUOTA [PERIOD], with PERIOD from 1000 through 1000000",
        ));
    }
    if quota_value == Some("max") {
        return Ok(format!("max {period}"));
    }
    let quota = quota_value
        .and_then(|part| part.parse::<u64>().ok())
        .filter(|quota| *quota > 0)
        .ok_or_else(|| {
            invalid("CPU limit must be 'max', a positive percentage, or QUOTA [PERIOD]")
        })?;
    Ok(format!("{quota} {period}"))
}

pub(crate) fn normalize_pids_max(value: &str) -> io::Result<String> {
    if value == "max" {
        return Ok(value.to_owned());
    }
    let pids = value
        .parse::<u64>()
        .ok()
        .filter(|pids| *pids > 0)
        .ok_or_else(|| invalid("pids limit must be 'max' or a positive integer"))?;
    Ok(pids.to_string())
}

pub(crate) fn prepare(spec: &CgroupSpec) -> io::Result<File> {
    prepare_at(Path::new("/sys/fs/cgroup"), spec)
}

fn prepare_at(root: &Path, spec: &CgroupSpec) -> io::Result<File> {
    let needed = [
        spec.memory_max.as_ref().map(|_| "memory"),
        spec.cpu_max.as_ref().map(|_| "cpu"),
        spec.pids_max.as_ref().map(|_| "pids"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let root_metadata = fs::symlink_metadata(root)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(invalid("cgroup root must be a real directory"));
    }

    let mut current = root.to_path_buf();
    for component in &spec.path {
        if !needed.is_empty() {
            enable_controllers(&current, &needed)?;
        }
        let next = current.join(component);
        match fs::symlink_metadata(&next) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(invalid("cgroup path contains a non-directory or symlink")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&next).map_err(|error| {
                    io::Error::new(
                        error.kind(),
                        format!("could not create cgroup {}: {error}", next.display()),
                    )
                })?;
                #[cfg(test)]
                initialize_test_group(&next, &current)?;
            }
            Err(error) => return Err(error),
        }
        current = next;
    }

    if let Some(limit) = &spec.memory_max {
        write_limit(&current.join("memory.max"), limit, &current)?;
    }
    if let Some(limit) = &spec.cpu_max {
        write_limit(&current.join("cpu.max"), limit, &current)?;
    }
    if let Some(limit) = &spec.pids_max {
        write_limit(&current.join("pids.max"), limit, &current)?;
    }
    OpenOptions::new()
        .write(true)
        .open(current.join("cgroup.procs"))
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "could not open cgroup.procs for {}: {error}",
                    current.display()
                ),
            )
        })
}

fn enable_controllers(parent: &Path, needed: &[&str]) -> io::Result<()> {
    let available = fs::read_to_string(parent.join("cgroup.controllers")).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "could not read cgroup.controllers in {}: {error}",
                parent.display()
            ),
        )
    })?;
    let available = available.split_ascii_whitespace().collect::<Vec<_>>();
    let enabled = fs::read_to_string(parent.join("cgroup.subtree_control")).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "could not read cgroup.subtree_control in {}: {error}",
                parent.display()
            ),
        )
    })?;
    let enabled = enabled
        .split_ascii_whitespace()
        .map(|controller| controller.trim_start_matches('+'))
        .collect::<Vec<_>>();
    let mut commands = Vec::new();
    for controller in needed {
        if !available.contains(controller) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "cgroup controller '{controller}' is unavailable in {}",
                    parent.display()
                ),
            ));
        }
        if !enabled.contains(controller) {
            commands.push(format!("+{controller}"));
        }
    }
    if !commands.is_empty() {
        fs::write(parent.join("cgroup.subtree_control"), commands.join(" ")).map_err(|error| {
            let explanation = if error.raw_os_error() == Some(nix::errno::Errno::EBUSY as i32) {
                "; move processes out of this cgroup before enabling controllers"
            } else {
                ""
            };
            io::Error::new(
                error.kind(),
                format!(
                    "could not enable cgroup controllers in {}{explanation}: {error}",
                    parent.display()
                ),
            )
        })?;
    }
    Ok(())
}

fn write_limit(path: &Path, limit: &str, group: &Path) -> io::Result<()> {
    fs::write(path, limit).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "could not set cgroup limit for {}: {error}",
                group.display()
            ),
        )
    })
}

#[allow(unsafe_code)]
pub(crate) fn apply_to_command(command: &mut Command, cgroup_procs: File) {
    // SAFETY: the callback only performs a single write syscall using a file opened before fork.
    unsafe {
        command.pre_exec(move || {
            let written = nix::unistd::write(&cgroup_procs, b"0").map_err(io::Error::from)?;
            if written != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "could not move worker into its cgroup",
                ));
            }
            Ok(())
        });
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
fn initialize_test_group(path: &Path, parent: &Path) -> io::Result<()> {
    let controllers = fs::read_to_string(parent.join("cgroup.subtree_control"))?;
    let controllers = controllers
        .split_ascii_whitespace()
        .map(|controller| controller.trim_start_matches('+'))
        .collect::<Vec<_>>()
        .join(" ");
    fs::write(path.join("cgroup.controllers"), &controllers)?;
    fs::write(path.join("cgroup.subtree_control"), "")?;
    fs::write(path.join("cgroup.procs"), "")?;
    for controller in controllers.split_ascii_whitespace() {
        match controller {
            "memory" => fs::write(path.join("memory.max"), "max")?,
            "cpu" => fs::write(path.join("cpu.max"), "max 100000")?,
            "pids" => fs::write(path.join("pids.max"), "max")?,
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::{
        CgroupSpec, apply_to_command, normalize_cpu_max, normalize_memory_max, normalize_pids_max,
        prepare_at, validate_path,
    };

    static NEXT_TEMPORARY_PATH: AtomicU64 = AtomicU64::new(0);

    fn temporary_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "project-charlotte-cgroup-{}-{}",
            std::process::id(),
            NEXT_TEMPORARY_PATH.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn fake_root(root: &PathBuf) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("cgroup.controllers"), "cpu memory pids").unwrap();
        fs::write(root.join("cgroup.subtree_control"), "").unwrap();
        fs::write(root.join("cgroup.procs"), "").unwrap();
    }

    #[test]
    fn validates_and_normalizes_paths_and_limits() {
        assert_eq!(
            validate_path("/sites/{uid}/{gid}/{name}").unwrap(),
            PathBuf::from("sites/{uid}/{gid}/{name}")
        );
        for path in [
            "",
            "/",
            "a//b",
            "a/./b",
            "a/../b",
            "a/cgroup.procs",
            "a/{unknown}",
            "a/\0b",
        ] {
            assert!(validate_path(path).is_err(), "accepted {path:?}");
        }
        assert_eq!(normalize_memory_max("2M").unwrap(), "2097152");
        assert_eq!(normalize_memory_max("max").unwrap(), "max");
        assert!(normalize_memory_max("0").is_err());
        assert!(normalize_memory_max("18446744073709551615T").is_err());
        assert_eq!(normalize_cpu_max("150%").unwrap(), "150000 100000");
        assert_eq!(normalize_cpu_max("50000 250000").unwrap(), "50000 250000");
        assert_eq!(normalize_cpu_max("max").unwrap(), "max 100000");
        assert_eq!(normalize_cpu_max("max 100000").unwrap(), "max 100000");
        assert!(normalize_cpu_max("0%").is_err());
        assert!(normalize_cpu_max("50000 100").is_err());
        assert_eq!(normalize_pids_max("12").unwrap(), "12");
        assert_eq!(normalize_pids_max("max").unwrap(), "max");
        assert!(normalize_pids_max("0").is_err());
    }

    #[test]
    fn expands_identity_and_host_placeholders() {
        let spec = CgroupSpec::new("sites/{uid}/{gid}/{name}", None, None, None).unwrap();
        let expanded = spec.expand(33, 33, "*.example.test").unwrap();
        assert_eq!(
            expanded.path,
            PathBuf::from("sites/33/33/wildcard.example.test")
        );
    }

    #[test]
    fn prepares_cgroup_limits_and_enables_controllers() {
        let root = temporary_path();
        fake_root(&root);
        let spec = CgroupSpec::new("tenant/site", Some("64M"), Some("50%"), Some("10")).unwrap();

        let procs = super::prepare_at(&root, &spec).unwrap();

        let group = root.join("tenant/site");
        assert!(group.is_dir());
        assert_eq!(
            fs::read_to_string(group.join("memory.max")).unwrap(),
            "67108864"
        );
        assert_eq!(
            fs::read_to_string(group.join("cpu.max")).unwrap(),
            "50000 100000"
        );
        assert_eq!(fs::read_to_string(group.join("pids.max")).unwrap(), "10");
        assert_eq!(
            fs::read_to_string(root.join("cgroup.subtree_control")).unwrap(),
            "+memory +cpu +pids"
        );
        assert_eq!(
            fs::read_to_string(root.join("tenant/cgroup.subtree_control")).unwrap(),
            "+memory +cpu +pids"
        );
        drop(procs);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn command_pre_exec_enrolls_child_in_prepared_cgroup() {
        let root = temporary_path();
        fake_root(&root);
        let spec = CgroupSpec::new("workers/site", None, None, None).unwrap();
        let procs = prepare_at(&root, &spec).unwrap();
        let mut command = Command::new("sh");
        command.args(["-c", "true"]);
        apply_to_command(&mut command, procs);

        let status = command.status().unwrap();

        assert!(status.success());
        assert_eq!(
            fs::read_to_string(root.join("workers/site/cgroup.procs")).unwrap(),
            "0"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
