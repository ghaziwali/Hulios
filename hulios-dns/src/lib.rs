pub mod detect;
pub mod rebinding;
pub mod resolver;

pub use detect::{detect_active_interfaces, hickory_bind_ip};
pub use rebinding::check_rebinding;
pub use resolver::{
    start_dns_resolver, start_dns_resolver_with_sockets, DnsConfig, DnsHandle, TorResolver,
};
