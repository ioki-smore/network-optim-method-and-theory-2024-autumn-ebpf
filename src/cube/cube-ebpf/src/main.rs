#![no_std]
#![no_main]

mod maps;
mod mm;
mod net;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
