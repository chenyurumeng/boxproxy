use crate::config::Config;
use crate::exec::Runner;
use crate::logger;
use crate::service;
use crate::Result;
use logger::{arg, LogKey};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CgroupVersion {
    V1,
    V2,
}

#[derive(Clone, Debug)]
struct CgroupMount {
    root: PathBuf,
    version: CgroupVersion,
}

pub fn apply_current(config: &Config, runner: &Runner) -> Result<()> {
    let pid = current_pid(config, runner)?;
    apply(config, pid)
}

pub(crate) fn apply(config: &Config, pid: u32) -> Result<()> {
    let mut any_enabled = false;
    let mut applied = Vec::new();
    let mut failed = Vec::new();

    if config.cgroup_memcg {
        any_enabled = true;
        match apply_memcg(config, pid) {
            Ok(detail) => applied.push(format!("memory {detail}")),
            Err(err) => failed.push(format!("memory {err}")),
        }
    }
    if config.cgroup_blkio {
        any_enabled = true;
        match apply_blkio(config, pid) {
            Ok(detail) => applied.push(format!("blkio {detail}")),
            Err(err) => failed.push(format!("blkio {err}")),
        }
    }

    if !any_enabled {
        logger::debug_key(config, LogKey::ResourceDisabled, &[]);
        return Ok(());
    }

    let applied_text = if applied.is_empty() {
        "none".to_string()
    } else {
        applied.join("; ")
    };
    if failed.is_empty() {
        logger::info_key(
            config,
            LogKey::ResourceApplied,
            &[arg("pid", pid), arg("applied", applied_text)],
        );
    } else {
        logger::warn_key(
            config,
            LogKey::ResourcePartiallyFailed,
            &[
                arg("pid", pid),
                arg("applied", applied_text),
                arg("failed", failed.join("; ")),
            ],
        );
    }

    Ok(())
}

fn current_pid(config: &Config, runner: &Runner) -> Result<u32> {
    if let Some(pid) = service::current_core_pid(config, runner) {
        return Ok(pid);
    }
    Err(format!("service is not running: {}", config.bin_name))
}

fn apply_memcg(config: &Config, pid: u32) -> Result<String> {
    let limit = parse_size(&config.memcg_limit)
        .ok_or_else(|| format!("invalid memory limit: {}", config.memcg_limit))?;
    let cgroup =
        find_cgroup_mount("memory").ok_or_else(|| "memory cgroup path not found".to_string())?;
    let target = ensure_cgroup_target(&cgroup, "memory", &["box", config.bin_name.as_str()])?;
    let limit_file = match cgroup.version {
        CgroupVersion::V1 => "memory.limit_in_bytes",
        CgroupVersion::V2 => "memory.max",
    };
    write_value(&target.join(limit_file), &limit.to_string())?;
    write_pid(&target, pid)?;
    Ok(format!(
        "-> {}, limit {}",
        target.display(),
        human_size(limit)
    ))
}

fn apply_blkio(config: &Config, pid: u32) -> Result<String> {
    let cgroup = find_cgroup_mount("io")
        .or_else(|| find_cgroup_mount("blkio"))
        .ok_or_else(|| "I/O cgroup path not found".to_string())?;
    let weight = parse_io_weight(config.weight.trim(), cgroup.version)?;
    let candidates: &[&str] = if cgroup.version == CgroupVersion::V1 {
        &["box", "foreground", "top-app"]
    } else {
        &["box"]
    };
    let controller = if cgroup.version == CgroupVersion::V1 {
        "blkio"
    } else {
        "io"
    };
    let target = ensure_cgroup_target(&cgroup, controller, candidates)?;
    let weight_file = match cgroup.version {
        CgroupVersion::V1 => "blkio.weight",
        CgroupVersion::V2 => "io.weight",
    };
    let weight_value = match cgroup.version {
        CgroupVersion::V1 => weight.to_string(),
        CgroupVersion::V2 => format!("default {weight}"),
    };
    if target.file_name().and_then(|name| name.to_str()) == Some("box") {
        write_value(&target.join(weight_file), &weight_value)?;
    }
    write_pid(&target, pid)?;
    let detail = if target.file_name().and_then(|name| name.to_str()) == Some("box") {
        format!("-> {}, weight {weight}", target.display())
    } else {
        format!("-> {}, inherited weight", target.display())
    };
    Ok(detail)
}

fn find_cgroup_mount(controller: &str) -> Option<CgroupMount> {
    let mounts = fs::read_to_string("/proc/mounts")
        .or_else(|_| fs::read_to_string("/proc/self/mounts"))
        .ok()?;
    cgroup_mount_from_text(&mounts, controller)
}

fn cgroup_mount_from_text(mounts: &str, controller: &str) -> Option<CgroupMount> {
    let mut v2_root = None;
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let _source = parts.next();
        let mount_point = parts.next()?;
        let fs_type = parts.next()?;
        let options = parts.next().unwrap_or_default();
        if fs_type == "cgroup" && options.split(',').any(|item| item == controller) {
            return Some(CgroupMount {
                root: PathBuf::from(unescape_mount_path(mount_point)),
                version: CgroupVersion::V1,
            });
        }
        if fs_type == "cgroup2" {
            v2_root = Some(PathBuf::from(unescape_mount_path(mount_point)));
        }
    }
    v2_root.map(|root| CgroupMount {
        root,
        version: CgroupVersion::V2,
    })
}

fn ensure_cgroup_target(
    cgroup: &CgroupMount,
    controller: &str,
    candidates: &[&str],
) -> Result<PathBuf> {
    if cgroup.version == CgroupVersion::V2 {
        enable_cgroup_v2_controller(&cgroup.root, controller)?;
    }
    ensure_target_dir(&cgroup.root, candidates)
}

fn enable_cgroup_v2_controller(root: &Path, controller: &str) -> Result<()> {
    let available = fs::read_to_string(root.join("cgroup.controllers")).map_err(|err| {
        format!(
            "read cgroup v2 controllers {} failed: {err}",
            root.display()
        )
    })?;
    if !available.split_whitespace().any(|item| item == controller) {
        return Err(format!("cgroup v2 controller {controller} is unavailable"));
    }

    let subtree_control = root.join("cgroup.subtree_control");
    let enabled = fs::read_to_string(&subtree_control).map_err(|err| {
        format!(
            "read cgroup v2 subtree controls {} failed: {err}",
            subtree_control.display()
        )
    })?;
    if !enabled.split_whitespace().any(|item| item == controller) {
        write_value(&subtree_control, &format!("+{controller}"))?;
    }
    Ok(())
}

fn ensure_target_dir(root: &Path, candidates: &[&str]) -> Result<PathBuf> {
    for (index, name) in candidates.iter().enumerate() {
        let target = root.join(name);
        if target.is_dir() {
            return Ok(target);
        }
        if index == 0 && fs::create_dir_all(&target).is_ok() && target.is_dir() {
            return Ok(target);
        }
    }
    Err(format!("cgroup target unavailable: {}", root.display()))
}

fn write_value(path: &Path, value: &str) -> Result<()> {
    fs::write(path, format!("{value}\n"))
        .map_err(|err| format!("write {} failed: {err}", path.display()))
}

fn write_pid(target: &Path, pid: u32) -> Result<()> {
    write_value(&target.join("cgroup.procs"), &pid.to_string())
}

fn parse_io_weight(value: &str, version: CgroupVersion) -> Result<u32> {
    let value = if value.is_empty() { "900" } else { value };
    let weight = value
        .parse::<u32>()
        .map_err(|_| format!("invalid I/O weight: {value}"))?;
    let (minimum, maximum) = match version {
        CgroupVersion::V1 => (10, 1000),
        CgroupVersion::V2 => (1, 10_000),
    };
    if !(minimum..=maximum).contains(&weight) {
        return Err(format!(
            "I/O weight {weight} is outside the cgroup v{} range {minimum}-{maximum}",
            match version {
                CgroupVersion::V1 => 1,
                CgroupVersion::V2 => 2,
            }
        ));
    }
    Ok(weight)
}

fn parse_size(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (number, multiplier) = match value.chars().last()? {
        'k' | 'K' => (&value[..value.len() - 1], 1024_u64),
        'm' | 'M' => (&value[..value.len() - 1], 1024_u64 * 1024),
        'g' | 'G' => (&value[..value.len() - 1], 1024_u64 * 1024 * 1024),
        ch if ch.is_ascii_digit() => (value, 1),
        _ => return None,
    };
    number.trim().parse::<u64>().ok()?.checked_mul(multiplier)
}

fn human_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GiB", bytes as f64 / 1024_f64 / 1024_f64 / 1024_f64)
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / 1024_f64 / 1024_f64)
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024_f64)
    } else {
        format!("{bytes} B")
    }
}

fn unescape_mount_path(path: &str) -> String {
    path.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cgroup_v1_controller_before_v2_fallback() {
        let mounts =
            "none /sys/fs/cgroup/memory cgroup rw,memory 0 0\nnone /sys/fs/cgroup cgroup2 rw 0 0\n";
        let mount = cgroup_mount_from_text(mounts, "memory").unwrap();
        assert_eq!(mount.version, CgroupVersion::V1);
        assert_eq!(mount.root, PathBuf::from("/sys/fs/cgroup/memory"));
    }

    #[test]
    fn falls_back_to_cgroup_v2() {
        let mounts = "none /sys/fs/cgroup cgroup2 rw 0 0\n";
        let mount = cgroup_mount_from_text(mounts, "memory").unwrap();
        assert_eq!(mount.version, CgroupVersion::V2);
        assert_eq!(mount.root, PathBuf::from("/sys/fs/cgroup"));
    }

    #[test]
    fn validates_io_weight_for_each_cgroup_version() {
        assert_eq!(parse_io_weight("900", CgroupVersion::V1).unwrap(), 900);
        assert!(parse_io_weight("1001", CgroupVersion::V1).is_err());
        assert_eq!(parse_io_weight("10000", CgroupVersion::V2).unwrap(), 10000);
        assert!(parse_io_weight("10001", CgroupVersion::V2).is_err());
    }
}
