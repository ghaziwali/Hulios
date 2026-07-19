use crate::types::EbpfHandlesState;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub fn find_ebpf_file(dir: &Path) -> Option<PathBuf> {
    if dir.is_file() {
        if dir.file_name()?.to_str()? == "hulios_ebpf.bpf.o" {
            return Some(dir.to_path_buf());
        }
    } else if dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                if let Some(path) = find_ebpf_file(&entry.path()) {
                    return Some(path);
                }
            }
        }
    }
    None
}

pub fn find_ebpf_object_path() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("HULIOS_EBPF_PATH") {
        return Ok(PathBuf::from(p));
    }
    let standard_paths = [
        "/usr/lib/hulios/hulios_ebpf.bpf.o",
        "/run/hulios/hulios_ebpf.bpf.o",
    ];
    for p in &standard_paths {
        let path = PathBuf::from(p);
        if path.exists() {
            return Ok(path);
        }
    }

    // Search the workspace target directory for testing/dev
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().unwrap();
    let target_dir = workspace_root.join("target");
    if target_dir.exists() {
        if let Some(path) = find_ebpf_file(&target_dir) {
            return Ok(path);
        }
    }

    anyhow::bail!("Could not find hulios_ebpf.bpf.o")
}

pub fn load_ebpf_state(
    cgroup_path: &Path,
    custom_bytes: Option<&[u8]>,
    hickory_ip: &str,
    ipv6_disabled: bool,
    fwmark: u32,
) -> Result<EbpfHandlesState> {
    if std::env::var("HULIOS_MOCK_EBPF").is_ok() {
        tracing::info!("[Mock] Loaded eBPF programs");
        return Ok(EbpfHandlesState {
            sock_mark_link: None,
            lsm_link: None,
            connect4_link: None,
            connect6_link: None,
            sendmsg4_link: None,
            sendmsg6_link: None,
        });
    }

    let mut bpf = if std::env::var("HULIOS_EBPF_PATH").is_ok() {
        let ebpf_path = find_ebpf_object_path()?;
        let data = std::fs::read(&ebpf_path)
            .with_context(|| format!("Failed to read eBPF object file at {:?}", ebpf_path))?;
        aya::Ebpf::load(&data).context("Failed to load eBPF bytecode from path")?
    } else if let Some(bytes) = custom_bytes {
        aya::Ebpf::load(bytes).context("Failed to load embedded eBPF bytecode")?
    } else {
        let ebpf_path = find_ebpf_object_path()?;
        let data = std::fs::read(&ebpf_path)
            .with_context(|| format!("Failed to read eBPF object file at {:?}", ebpf_path))?;
        aya::Ebpf::load(&data).context("Failed to load eBPF bytecode")?
    };

    // Populate CONFIG_MAP: key 3 for Hickory IP, key 4 for IPv6 disable flag, key 2 for main fwmark
    if let Some(m) = bpf.map_mut("CONFIG_MAP") {
        if let Ok(mut config_map) = aya::maps::HashMap::try_from(m) {
            let ip: std::net::Ipv4Addr = hickory_ip.parse().context("Invalid Hickory IP")?;
            let ip_u32 = u32::from_ne_bytes(ip.octets());
            config_map.insert(3, ip_u32, 0)?;
            config_map.insert(4, if ipv6_disabled { 1u32 } else { 0u32 }, 0)?;
            config_map.insert(2, fwmark, 0)?;
        }
    }

    let sock_program: &mut aya::programs::CgroupSock = bpf
        .program_mut("mark_hulios_socket")
        .context("Program mark_hulios_socket not found")?
        .try_into()
        .context("Failed to cast program to CgroupSock")?;

    sock_program
        .load()
        .context("Failed to load mark_hulios_socket program")?;

    let cgroup_file = std::fs::File::open(cgroup_path)
        .with_context(|| format!("Failed to open cgroup path {:?}", cgroup_path))?;

    let sock_link_id = sock_program
        .attach(cgroup_file, aya::programs::CgroupAttachMode::Single)
        .context("Failed to attach mark_hulios_socket program")?;

    let sock_mark_link = sock_program
        .take_link(sock_link_id)
        .context("Failed to take link for mark_hulios_socket")?;

    // Load connect4, connect6, sendmsg4, sendmsg6, attach them to the cgroup
    let connect4_program: &mut aya::programs::CgroupSockAddr = bpf
        .program_mut("connect4")
        .context("Program connect4 not found")?
        .try_into()
        .context("Failed to cast program to CgroupSockAddr")?;
    connect4_program
        .load()
        .context("Failed to load connect4 program")?;
    let root_cgroup_path = std::path::Path::new("/sys/fs/cgroup");
    let cgroup_file_c4 = std::fs::File::open(root_cgroup_path).with_context(|| {
        format!(
            "Failed to open root cgroup path for connect4 {:?}",
            root_cgroup_path
        )
    })?;
    let connect4_link_id = connect4_program
        .attach(cgroup_file_c4, aya::programs::CgroupAttachMode::Single)
        .context("Failed to attach connect4 program")?;
    let connect4_link = connect4_program
        .take_link(connect4_link_id)
        .context("Failed to take link for connect4")?;

    let connect6_program: &mut aya::programs::CgroupSockAddr = bpf
        .program_mut("connect6")
        .context("Program connect6 not found")?
        .try_into()
        .context("Failed to cast program to CgroupSockAddr")?;
    connect6_program
        .load()
        .context("Failed to load connect6 program")?;
    let cgroup_file_c6 = std::fs::File::open(root_cgroup_path).with_context(|| {
        format!(
            "Failed to open root cgroup path for connect6 {:?}",
            root_cgroup_path
        )
    })?;
    let connect6_link_id = connect6_program
        .attach(cgroup_file_c6, aya::programs::CgroupAttachMode::Single)
        .context("Failed to attach connect6 program")?;
    let connect6_link = connect6_program
        .take_link(connect6_link_id)
        .context("Failed to take link for connect6")?;

    let sendmsg4_program: &mut aya::programs::CgroupSockAddr = bpf
        .program_mut("sendmsg4")
        .context("Program sendmsg4 not found")?
        .try_into()
        .context("Failed to cast program to CgroupSockAddr")?;
    sendmsg4_program
        .load()
        .context("Failed to load sendmsg4 program")?;
    let cgroup_file_sm4 = std::fs::File::open(root_cgroup_path).with_context(|| {
        format!(
            "Failed to open root cgroup path for sendmsg4 {:?}",
            root_cgroup_path
        )
    })?;
    let sendmsg4_link_id = sendmsg4_program
        .attach(cgroup_file_sm4, aya::programs::CgroupAttachMode::Single)
        .context("Failed to attach sendmsg4 program")?;
    let sendmsg4_link = sendmsg4_program
        .take_link(sendmsg4_link_id)
        .context("Failed to take link for sendmsg4")?;

    let sendmsg6_program: &mut aya::programs::CgroupSockAddr = bpf
        .program_mut("sendmsg6")
        .context("Program sendmsg6 not found")?
        .try_into()
        .context("Failed to cast program to CgroupSockAddr")?;
    sendmsg6_program
        .load()
        .context("Failed to load sendmsg6 program")?;
    let cgroup_file_sm6 = std::fs::File::open(root_cgroup_path).with_context(|| {
        format!(
            "Failed to open root cgroup path for sendmsg6 {:?}",
            root_cgroup_path
        )
    })?;
    let sendmsg6_link_id = sendmsg6_program
        .attach(cgroup_file_sm6, aya::programs::CgroupAttachMode::Single)
        .context("Failed to attach sendmsg6 program")?;
    let sendmsg6_link = sendmsg6_program
        .take_link(sendmsg6_link_id)
        .context("Failed to take link for sendmsg6")?;

    let lsm_program: &mut aya::programs::Lsm = match bpf.program_mut("block_af_packet") {
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
    let btf = aya::Btf::from_sys_fs();
    match btf {
        Ok(btf) => match lsm_program.load("socket_create", &btf) {
            Ok(_) => match lsm_program.attach() {
                Ok(link_id) => match lsm_program.take_link(link_id) {
                    Ok(link) => {
                        lsm_link = Some(link);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to take link for block_af_packet: {e}");
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        "Failed to attach block_af_packet (LSM may not be supported): {e}"
                    );
                }
            },
            Err(_e) => {
                tracing::info!("LSM raw socket protection not supported by kernel (standard IP routing rules remain active)");
            }
        },
        Err(_e) => {
            tracing::info!("BTF not supported by kernel (standard IP routing rules remain active)");
        }
    }

    Ok(EbpfHandlesState {
        sock_mark_link: Some(sock_mark_link),
        lsm_link,
        connect4_link: Some(connect4_link),
        connect6_link: Some(connect6_link),
        sendmsg4_link: Some(sendmsg4_link),
        sendmsg6_link: Some(sendmsg6_link),
    })
}
