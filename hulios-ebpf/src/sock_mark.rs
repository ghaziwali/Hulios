use aya_ebpf::{
    helpers::bpf_get_socket_cookie,
    macros::{cgroup_sock, map},
    maps::HashMap,
    programs::SockContext,
};
use hulios_common::HULIOS_FWMARK;
use hulios_common::{SocketCookie, SocketInfo};

#[map]
pub static mut SOCKET_MAP: HashMap<SocketCookie, SocketInfo> = HashMap::with_max_entries(1024, 0);

#[map]
pub static mut CONFIG_MAP: HashMap<u32, u32> = HashMap::with_max_entries(10, 0);

#[cgroup_sock(sock_create)]
#[allow(static_mut_refs)]
pub fn mark_hulios_socket(ctx: SockContext) -> i32 {
    unsafe {
        let sk = ctx.sock;
        if sk.is_null() {
            return 1;
        }

        let family = (*sk).family;
        if family != 2 && family != 10 {
            return 1;
        }

        let cookie = bpf_get_socket_cookie(sk as *mut _);
        if let Some(info) = SOCKET_MAP.get(&cookie) {
            (*sk).mark = info.fwmark;
        } else {
            let mut mark = HULIOS_FWMARK;
            if let Some(cfg_mark) = CONFIG_MAP.get(&2) {
                mark = *cfg_mark;
            }
            (*sk).mark = mark;
        }
    }
    1
}
