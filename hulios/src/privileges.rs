#![allow(clippy::unnecessary_cast)]
use anyhow::{Context, Result};
use caps::{CapSet, Capability, CapsHashSet};
use nix::unistd::{setgroups, setuid, User};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule,
};
use std::collections::BTreeMap;

pub fn drop_privileges(retain_sys_time: bool) -> Result<()> {
    // 1. Clear supplementary groups
    setgroups(&[]).context("Failed to clear supplementary groups")?;

    // 2. Resolve UID for "nobody"
    let nobody = User::from_name("nobody")
        .context("Failed to query user 'nobody'")?
        .context("User 'nobody' not found")?;
    let uid = nobody.uid;

    // 3. Set up capabilities to retain
    let mut to_retain = CapsHashSet::new();
    to_retain.insert(Capability::CAP_NET_ADMIN);
    to_retain.insert(Capability::CAP_BPF);
    to_retain.insert(Capability::CAP_NET_BIND_SERVICE);
    to_retain.insert(Capability::CAP_NET_BIND_SERVICE);
    if retain_sys_time {
        to_retain.insert(Capability::CAP_SYS_TIME);
    }

    // 4. Set UID to nobody
    // We must set the keep-capabilities flag before setuid to retain caps across UID change
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
            anyhow::bail!("Failed to set PR_SET_KEEPCAPS");
        }
    }

    setuid(uid).context("Failed to setuid to nobody")?;

    // 5. Apply retained capabilities to Permitted and Effective sets
    caps::set(None, CapSet::Permitted, &to_retain)
        .context("Failed to set permitted capabilities")?;
    caps::set(None, CapSet::Effective, &to_retain)
        .context("Failed to set effective capabilities")?;

    // 6. Prevent re-escalation
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            anyhow::bail!("Failed to set PR_SET_NO_NEW_PRIVS");
        }
    }

    // 7. Log effective capabilities
    let effective =
        caps::read(None, CapSet::Effective).context("Failed to read effective capabilities")?;
    tracing::info!(
        "Privileges dropped. Effective capabilities: {:?}",
        effective
    );

    Ok(())
}

pub fn build_seccomp_filter() -> Result<BpfProgram> {
    let mut rules = BTreeMap::new();

    let allowed_unrestricted = vec![
        libc::SYS_read as i64,
        libc::SYS_write as i64,
        libc::SYS_writev as i64,
        libc::SYS_bpf as i64,
        libc::SYS_close as i64,
        libc::SYS_epoll_pwait as i64,
        libc::SYS_epoll_ctl as i64,
        libc::SYS_connect as i64,
        libc::SYS_bind as i64,
        libc::SYS_accept4 as i64,
        libc::SYS_sendto as i64,
        libc::SYS_recvfrom as i64,
        libc::SYS_sendmsg as i64,
        libc::SYS_recvmsg as i64,
        libc::SYS_ppoll as i64,
        libc::SYS_futex as i64,
        libc::SYS_mmap as i64,
        libc::SYS_munmap as i64,
        libc::SYS_brk as i64,
        libc::SYS_rt_sigaction as i64,
        libc::SYS_rt_sigprocmask as i64,
        libc::SYS_rt_sigreturn as i64,
        libc::SYS_exit_group as i64,
        libc::SYS_clock_gettime as i64,
        libc::SYS_clock_settime as i64,
        libc::SYS_gettimeofday as i64,
        libc::SYS_nanosleep as i64,
        libc::SYS_getrandom as i64,
        // SYS_stat removed: aarch64 uses SYS_newfstatat (already included below)
        libc::SYS_fstat as i64,
        libc::SYS_getpid as i64,
        libc::SYS_gettid as i64,
        libc::SYS_sched_yield as i64,
        libc::SYS_getuid as i64,
        libc::SYS_geteuid as i64,
        libc::SYS_getgid as i64,
        libc::SYS_getegid as i64,
        // SYS_unlink removed: aarch64 uses SYS_unlinkat (already included below)
        libc::SYS_unlinkat as i64,
        libc::SYS_openat as i64,
        libc::SYS_statx as i64,
        libc::SYS_fcntl as i64,
        libc::SYS_lseek as i64,
        libc::SYS_pread64 as i64,
        libc::SYS_pwrite64 as i64,
        libc::SYS_getdents64 as i64,
        libc::SYS_newfstatat as i64,
        libc::SYS_listen as i64,
        libc::SYS_fchmodat as i64,
        libc::SYS_getsockopt as i64,
        libc::SYS_fdatasync as i64,
        libc::SYS_readlinkat as i64,
        libc::SYS_setsockopt as i64,
        libc::SYS_getsockname as i64,
        libc::SYS_mkdirat as i64,
        libc::SYS_sigaltstack as i64,
        libc::SYS_madvise as i64,
        libc::SYS_exit as i64,
        libc::SYS_fsync as i64,
    ];

    for syscall in allowed_unrestricted {
        // Map unconditionally allowed syscalls to an empty rules vector
        rules.insert(syscall, vec![]);
    }

    // socket (only AF_INET, AF_INET6, AF_UNIX, AF_NETLINK)
    let socket_rules = vec![
        SeccompRule::new(
            vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_INET as u64,
            )?]
            .into_iter()
            .collect(),
        )?,
        SeccompRule::new(
            vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_INET6 as u64,
            )?]
            .into_iter()
            .collect(),
        )?,
        SeccompRule::new(
            vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_UNIX as u64,
            )?]
            .into_iter()
            .collect(),
        )?,
        SeccompRule::new(
            vec![SeccompCondition::new(
                0,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::AF_NETLINK as u64,
            )?]
            .into_iter()
            .collect(),
        )?,
    ];
    rules.insert(libc::SYS_socket as i64, socket_rules);

    // mprotect (no PROT_EXEC)
    let mprotect_rules = vec![SeccompRule::new(
        vec![SeccompCondition::new(
            2,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
            0,
        )?]
        .into_iter()
        .collect(),
    )?];
    rules.insert(libc::SYS_mprotect as i64, mprotect_rules);

    // ioctl (only allowed ioctl numbers: TUNSETIFF, TUNGETIFF, SIOCSIFMTU, SIOCSIFADDR, FS_IOC_GETFLAGS, FS_IOC_SETFLAGS)
    let ioctl_rules = vec![
        SeccompRule::new(
            vec![SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::TUNSETIFF as u64,
            )?]
            .into_iter()
            .collect(),
        )?,
        SeccompRule::new(
            vec![SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::TUNGETIFF as u64,
            )?]
            .into_iter()
            .collect(),
        )?,
        SeccompRule::new(
            vec![SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::SIOCSIFMTU as u64,
            )?]
            .into_iter()
            .collect(),
        )?,
        SeccompRule::new(
            vec![SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::SIOCSIFADDR as u64,
            )?]
            .into_iter()
            .collect(),
        )?,
        SeccompRule::new(
            vec![SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::FS_IOC_GETFLAGS as u64,
            )?]
            .into_iter()
            .collect(),
        )?,
        SeccompRule::new(
            vec![SeccompCondition::new(
                1,
                SeccompCmpArgLen::Dword,
                SeccompCmpOp::Eq,
                libc::FS_IOC_SETFLAGS as u64,
            )?]
            .into_iter()
            .collect(),
        )?,
    ];
    rules.insert(libc::SYS_ioctl as i64, ioctl_rules);

    // TODO: Enforce full blocking (SeccompAction::Errno(libc::EPERM as u32)) before final push to GitHub and release.
    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Log,   // Default action (Log all others if not matched)
        SeccompAction::Allow, // Action when a rule is matched
        std::env::consts::ARCH
            .try_into()
            .context("Failed to parse arch")?,
    )
    .context("Failed to construct SeccompFilter")?
    .try_into()
    .context("Failed to compile SeccompFilter into BPF program")?;

    Ok(filter)
}

pub fn apply_seccomp_filter() -> Result<()> {
    let filter = build_seccomp_filter()?;

    let fprog = libc::sock_fprog {
        len: filter.len() as libc::c_ushort,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    const SECCOMP_FILTER_FLAG_TSYNC: libc::c_uint = 1;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &fprog as *const libc::sock_fprog,
        )
    };

    if ret != 0 {
        let err = std::io::Error::last_os_error();
        tracing::warn!(
            "SYS_seccomp with TSYNC failed: {}. Falling back to single-thread filter.",
            err
        );
        seccompiler::apply_filter(&filter).context("Failed to apply seccomp filter fallback")?;
    } else {
        tracing::info!("Seccomp-bpf filter successfully applied with TSYNC (all threads)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_filter_compiles() {
        let res = build_seccomp_filter();
        assert!(
            res.is_ok(),
            "Failed to compile seccomp filter: {:?}",
            res.err()
        );
    }
}
