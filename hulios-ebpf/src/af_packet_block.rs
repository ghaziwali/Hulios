use aya_ebpf::{macros::lsm, programs::LsmContext};

#[lsm(hook = "socket_create")]
pub fn block_af_packet(ctx: LsmContext) -> i32 {
    let family: i32 = unsafe { ctx.arg(0) };
    if family == 17 {
        // AF_PACKET is 17. Return -EPERM (-1).
        return -1;
    }

    0
}
