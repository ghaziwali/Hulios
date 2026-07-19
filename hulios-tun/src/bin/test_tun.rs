use tun::platform::Device;
use tun::Configuration;

fn main() {
    let mut config = Configuration::default();
    config.name("hulios_test");

    let device = tun::create(&config).unwrap();
    let _typed_device: Device = device;

    println!("Compiled successfully!");
}
