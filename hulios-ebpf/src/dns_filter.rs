use crate::sock_mark::CONFIG_MAP;
use aya_ebpf::{macros::cgroup_sock_addr, programs::SockAddrContext};
use hulios_common::{HULIOS_BYPASS_FWMARK, HULIOS_DNS_IPV6_MAGIC, HULIOS_FWMARK};

#[inline(always)]
#[allow(static_mut_refs)]
unsafe fn is_our_traffic(mark: u32) -> bool {
    let mut main_fwmark = HULIOS_FWMARK;
    if let Some(cfg_mark) = CONFIG_MAP.get(&2) {
        main_fwmark = *cfg_mark;
    }
    let mut bypass_fwmark = HULIOS_BYPASS_FWMARK;
    if let Some(cfg_mark) = CONFIG_MAP.get(&1) {
        bypass_fwmark = *cfg_mark;
    }
    mark == main_fwmark || mark == bypass_fwmark
}

#[cgroup_sock_addr(connect4)]
#[allow(static_mut_refs)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    unsafe {
        let sock_addr = &mut *ctx.sock_addr;
        let port = u16::from_be(sock_addr.user_port as u16);
        if port == 53 {
            let sk = sock_addr.__bindgen_anon_1.sk;
            if !sk.is_null() {
                let mark = (*sk).mark;
                if is_our_traffic(mark) {
                    return 1;
                }
            }

            if sock_addr.user_ip4 == 0x0100007f || sock_addr.user_ip4 == 0x0200007f {
                return 1;
            }

            if let Some(redirect_ip) = CONFIG_MAP.get(&3) {
                sock_addr.user_ip4 = *redirect_ip;
            } else {
                sock_addr.user_ip4 = 0x0100007f;
            }
            return 1;
        }
    }
    1
}

#[cgroup_sock_addr(connect6)]
#[allow(static_mut_refs)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    unsafe {
        let sock_addr = &mut *ctx.sock_addr;
        let port = u16::from_be(sock_addr.user_port as u16);
        if port == 53 {
            let sk = sock_addr.__bindgen_anon_1.sk;
            if !sk.is_null() {
                let mark = (*sk).mark;
                if is_our_traffic(mark) {
                    return 1;
                }
            }

            if let Some(disabled) = CONFIG_MAP.get(&4) {
                if *disabled == 1 {
                    return 0;
                }
            }

            // Redirect to magic IPv6 DNS address
            sock_addr.user_ip6[0] = HULIOS_DNS_IPV6_MAGIC[0];
            sock_addr.user_ip6[1] = HULIOS_DNS_IPV6_MAGIC[1];
            sock_addr.user_ip6[2] = HULIOS_DNS_IPV6_MAGIC[2];
            sock_addr.user_ip6[3] = HULIOS_DNS_IPV6_MAGIC[3];
            return 1;
        }
    }
    1
}

#[cgroup_sock_addr(sendmsg4)]
#[allow(static_mut_refs)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    unsafe {
        let sock_addr = &mut *ctx.sock_addr;
        let port = u16::from_be(sock_addr.user_port as u16);
        if port == 53 {
            let sk = sock_addr.__bindgen_anon_1.sk;
            if !sk.is_null() {
                let mark = (*sk).mark;
                if is_our_traffic(mark) {
                    return 1;
                }
            }

            if sock_addr.user_ip4 == 0x0100007f || sock_addr.user_ip4 == 0x0200007f {
                return 1;
            }

            if let Some(redirect_ip) = CONFIG_MAP.get(&3) {
                sock_addr.user_ip4 = *redirect_ip;
            } else {
                sock_addr.user_ip4 = 0x0100007f;
            }
            return 1;
        }
    }
    1
}

#[cgroup_sock_addr(sendmsg6)]
#[allow(static_mut_refs)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    unsafe {
        let sock_addr = &mut *ctx.sock_addr;
        let port = u16::from_be(sock_addr.user_port as u16);
        if port == 53 {
            let sk = sock_addr.__bindgen_anon_1.sk;
            if !sk.is_null() {
                let mark = (*sk).mark;
                if is_our_traffic(mark) {
                    return 1;
                }
            }

            if let Some(disabled) = CONFIG_MAP.get(&4) {
                if *disabled == 1 {
                    return 0;
                }
            }

            // Redirect to magic IPv6 DNS address
            sock_addr.user_ip6[0] = HULIOS_DNS_IPV6_MAGIC[0];
            sock_addr.user_ip6[1] = HULIOS_DNS_IPV6_MAGIC[1];
            sock_addr.user_ip6[2] = HULIOS_DNS_IPV6_MAGIC[2];
            sock_addr.user_ip6[3] = HULIOS_DNS_IPV6_MAGIC[3];
            return 1;
        }
    }
    1
}
