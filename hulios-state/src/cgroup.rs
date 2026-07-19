use anyhow::{Context, Result};
use std::path::PathBuf;

pub fn get_cgroup_path() -> Result<PathBuf> {
    if let Ok(mocked_path) = std::env::var("HULIOS_CGROUP_DIR_PATH") {
        return Ok(PathBuf::from(mocked_path));
    }

    let proc_cgroup = std::path::Path::new("/proc/self/cgroup");
    let sys_cgroup = std::path::Path::new("/sys/fs/cgroup");

    let controllers_path = sys_cgroup.join("cgroup.controllers");
    if !controllers_path.exists() {
        anyhow::bail!(
            "cgroup v2 is not mounted: {:?} is missing",
            controllers_path
        );
    }

    let content = std::fs::read_to_string(proc_cgroup)
        .with_context(|| format!("Failed to read cgroup file {:?}", proc_cgroup))?;

    let mut cgroup_v2_subpath = None;
    for line in content.lines() {
        let line = line.trim();
        if let Some(path_part) = line.strip_prefix("0::") {
            cgroup_v2_subpath = Some(path_part);
            break;
        }
    }

    let base_path = match cgroup_v2_subpath {
        Some(subpath) if subpath != "/" => {
            let subpath_clean = subpath.strip_prefix('/').unwrap_or(subpath);
            let full_path = sys_cgroup.join(subpath_clean);
            if full_path.exists() {
                full_path
            } else {
                sys_cgroup.to_path_buf()
            }
        }
        _ => sys_cgroup.to_path_buf(),
    };

    Ok(base_path.join("hulios"))
}

pub fn detect_cgroup_path_state() -> Result<PathBuf> {
    let p = get_cgroup_path()?;
    if std::env::var("HULIOS_MOCK_RECOVERY").is_err() {
        std::fs::create_dir_all(&p)
            .with_context(|| format!("Failed to create cgroup directory {:?}", p))?;
        let procs_path = p.join("cgroup.procs");
        let pid = std::process::id();
        std::fs::write(&procs_path, pid.to_string())
            .with_context(|| format!("Failed to write PID to {:?}", procs_path))?;
    }
    Ok(p)
}

pub fn is_cgroup_stale() -> bool {
    let path = crate::types::get_cgroup_dir_path();
    if !path.exists() {
        return false;
    }
    let procs_path = path.join("cgroup.procs");
    if !procs_path.exists() {
        return true;
    }
    match std::fs::read_to_string(&procs_path) {
        Ok(content) => content.trim().is_empty(),
        Err(_) => true,
    }
}
