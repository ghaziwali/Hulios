#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

// Minimal stub for eBPF program compiling with todo!()
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
