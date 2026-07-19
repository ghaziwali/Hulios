use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    programs::{cgroup_sock::CgroupSockLink, lsm::LsmLink, CgroupAttachMode, CgroupSock, Lsm},
    Btf, Ebpf,
};
use std::path::PathBuf;
use tracing::warn;

pub struct EbpfConfig {
    pub cgroup_path: PathBuf,
}

pub struct EbpfHandles {
    pub sock_mark_link: Option<CgroupSockLink>,
    pub lsm_link: Option<LsmLink>,
}

pub async fn load_ebpf(cfg: &EbpfConfig) -> Result<EbpfHandles> {
    let _ = cfg;
    // We load the compiled BPF bytecode
    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/hulios_ebpf.bpf.o"
    )))
    .context("Failed to load eBPF bytecode")?;

    // Load and attach the cgroup/sock_create program
    let sock_program: &mut CgroupSock = bpf
        .program_mut("mark_hulios_socket")
        .context("Program mark_hulios_socket not found")?
        .try_into()
        .context("Failed to cast program to CgroupSock")?;

    sock_program
        .load()
        .context("Failed to load mark_hulios_socket program")?;

    // Open the cgroup directory
    let cgroup_path = detect_cgroup_path()?;
    let cgroup_file = std::fs::File::open(&cgroup_path)
        .with_context(|| format!("Failed to open cgroup path {:?}", cgroup_path))?;

    let sock_link_id = sock_program
        .attach(cgroup_file, CgroupAttachMode::Single)
        .context("Failed to attach mark_hulios_socket program")?;

    let sock_mark_link = sock_program
        .take_link(sock_link_id)
        .context("Failed to take link for mark_hulios_socket")?;

    // Load and attach the LSM/socket_create program
    let lsm_program: &mut Lsm = match bpf.program_mut("block_af_packet") {
        Some(prog) => match prog.try_into() {
            Ok(p) => p,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to cast block_af_packet to Lsm: {e}"
                ));
            }
        },
        None => {
            return Err(anyhow::anyhow!("Program block_af_packet not found"));
        }
    };

    let mut lsm_link = None;

    // Load BTF
    let btf = Btf::from_sys_fs();
    match btf {
        Ok(btf) => match lsm_program.load("socket_create", &btf) {
            Ok(_) => match lsm_program.attach() {
                Ok(link_id) => match lsm_program.take_link(link_id) {
                    Ok(link) => {
                        lsm_link = Some(link);
                    }
                    Err(e) => {
                        warn!("Failed to take link for block_af_packet: {e}");
                    }
                },
                Err(e) => {
                    warn!("Failed to attach block_af_packet (LSM may not be supported): {e}");
                }
            },
            Err(e) => {
                warn!("Failed to load LSM program (continuing in degraded mode): {e}");
            }
        },
        Err(e) => {
            warn!("Failed to load BTF (continuing in degraded mode): {e}");
        }
    }

    Ok(EbpfHandles {
        sock_mark_link: Some(sock_mark_link),
        lsm_link,
    })
}

pub fn detect_cgroup_path() -> Result<PathBuf> {
    detect_cgroup_path_impl(
        std::path::Path::new("/proc/self/cgroup"),
        std::path::Path::new("/sys/fs/cgroup"),
    )
}

fn detect_cgroup_path_impl(
    proc_cgroup: &std::path::Path,
    sys_cgroup: &std::path::Path,
) -> Result<PathBuf> {
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

    match cgroup_v2_subpath {
        Some(subpath) if subpath != "/" => {
            let subpath_clean = subpath.strip_prefix('/').unwrap_or(subpath);
            let full_path = sys_cgroup.join(subpath_clean);
            if full_path.exists() {
                return Ok(full_path);
            }
        }
        _ => {}
    }

    let fallback_path = sys_cgroup.join("hulios");
    std::fs::create_dir_all(&fallback_path)
        .with_context(|| format!("Failed to create cgroup directory {:?}", fallback_path))?;

    let procs_path = fallback_path.join("cgroup.procs");
    let pid = std::process::id();
    std::fs::write(&procs_path, pid.to_string())
        .with_context(|| format!("Failed to write PID to {:?}", procs_path))?;

    Ok(fallback_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;

    #[test]
    fn test_detect_cgroup_path_missing_controllers() {
        let temp_dir =
            std::env::temp_dir().join(format!("hulios_test_missing_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let proc_cgroup = temp_dir.join("cgroup");
        File::create(&proc_cgroup).unwrap();

        let sys_cgroup = temp_dir.join("sys_cgroup");
        fs::create_dir_all(&sys_cgroup).unwrap();

        let res = detect_cgroup_path_impl(&proc_cgroup, &sys_cgroup);
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("cgroup v2 is not mounted"));

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_detect_cgroup_path_systemd() {
        let temp_dir =
            std::env::temp_dir().join(format!("hulios_test_systemd_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let proc_cgroup = temp_dir.join("cgroup");
        let mut f = File::create(&proc_cgroup).unwrap();
        writeln!(f, "0::/user.slice/user-1000.slice").unwrap();

        let sys_cgroup = temp_dir.join("sys_cgroup");
        fs::create_dir_all(&sys_cgroup).unwrap();
        File::create(sys_cgroup.join("cgroup.controllers")).unwrap();

        let target_cgroup = sys_cgroup.join("user.slice/user-1000.slice");
        fs::create_dir_all(&target_cgroup).unwrap();

        let res = detect_cgroup_path_impl(&proc_cgroup, &sys_cgroup);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), target_cgroup);

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_detect_cgroup_path_fallback_root() {
        let temp_dir =
            std::env::temp_dir().join(format!("hulios_test_fallback_root_{}", std::process::id()));
        fs::create_dir_all(&temp_dir).unwrap();

        let proc_cgroup = temp_dir.join("cgroup");
        let mut f = File::create(&proc_cgroup).unwrap();
        writeln!(f, "0::/").unwrap();

        let sys_cgroup = temp_dir.join("sys_cgroup");
        fs::create_dir_all(&sys_cgroup).unwrap();
        File::create(sys_cgroup.join("cgroup.controllers")).unwrap();

        let res = detect_cgroup_path_impl(&proc_cgroup, &sys_cgroup);
        assert!(res.is_ok());
        let expected_path = sys_cgroup.join("hulios");
        assert_eq!(res.unwrap(), expected_path);
        assert!(expected_path.join("cgroup.procs").exists());

        fs::remove_dir_all(&temp_dir).unwrap();
    }

    #[test]
    fn test_detect_cgroup_path_fallback_not_found() {
        let temp_dir = std::env::temp_dir().join(format!(
            "hulios_test_fallback_missing_{}",
            std::process::id()
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        let proc_cgroup = temp_dir.join("cgroup");
        let mut f = File::create(&proc_cgroup).unwrap();
        writeln!(f, "1:name=systemd:/user.slice").unwrap();

        let sys_cgroup = temp_dir.join("sys_cgroup");
        fs::create_dir_all(&sys_cgroup).unwrap();
        File::create(sys_cgroup.join("cgroup.controllers")).unwrap();

        let res = detect_cgroup_path_impl(&proc_cgroup, &sys_cgroup);
        assert!(res.is_ok());
        let expected_path = sys_cgroup.join("hulios");
        assert_eq!(res.unwrap(), expected_path);
        assert!(expected_path.join("cgroup.procs").exists());

        fs::remove_dir_all(&temp_dir).unwrap();
    }
}
