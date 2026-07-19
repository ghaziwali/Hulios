#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

pub mod af_packet_block;
pub mod dns_filter;
pub mod sock_mark;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
