#![no_std]

/// The default firewall mark (fwmark) used by Hulios to identify its own sockets/traffic.
pub const HULIOS_FWMARK: u32 = 42;

/// The bypass/escape firewall mark (fwmark) used for split tunneling or portal escape.
pub const HULIOS_BYPASS_FWMARK: u32 = 43;

/// A type representing a socket cookie (a unique identifier for a socket).
pub type SocketCookie = u64;

/// A type representing a cgroup v2 ID.
pub type CgroupId = u64;

/// Represents a socket tracking entry, storing information about a monitored socket.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SocketInfo {
    /// The cgroup ID associated with the socket.
    pub cgroup_id: CgroupId,
    /// The owner's User ID (UID).
    pub uid: u32,
    /// The firewall mark currently set on this socket.
    pub fwmark: u32,
}

/// Represents the key structure for cgroup/destination-based stream isolation.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct IsolationKey {
    /// The cgroup ID of the initiating process.
    pub cgroup_id: CgroupId,
    /// The IPv4 or IPv6 destination address representation (stored as raw bytes).
    pub dest_ip: [u8; 16],
    /// The destination port.
    pub dest_port: u16,
    /// Padding to ensure proper alignment.
    pub _padding: u16,
}

/// Magic IPv6 address for Hickory DNS on the TUN interface.
/// Encoded as [u32; 4] in network (big-endian) byte order.
/// Represents fdbe:0000:0000:0000:0000:0000:0000:0053
pub const HULIOS_DNS_IPV6_MAGIC: [u32; 4] = [
    u32::from_ne_bytes([0xfd, 0xbe, 0x00, 0x00]),
    0x00000000,
    0x00000000,
    u32::from_ne_bytes([0x00, 0x00, 0x00, 0x53]),
];

/// Magic IPv6 DNS address as a string for bind calls.
pub const HULIOS_DNS_IPV6_MAGIC_STR: &str = "fdbe::53";
