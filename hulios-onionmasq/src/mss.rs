pub fn clamp_mss(frame: &mut [u8], max_mss: u16) {
    if frame.is_empty() {
        return;
    }

    let version = frame[0] >> 4;
    let (ip_header_len, protocol) = if version == 4 {
        if frame.len() < 20 {
            return;
        }
        let ihl = frame[0] & 0x0F;
        let header_len = (ihl as usize) * 4;
        if frame.len() < header_len {
            return;
        }
        let protocol = frame[9];
        (header_len, protocol)
    } else if version == 6 {
        if frame.len() < 40 {
            return;
        }
        let next_header = frame[6];
        let mut offset = 40;
        let mut nexthdr = next_header;

        while nexthdr != 6 && nexthdr != 59 {
            if nexthdr == 0 || nexthdr == 43 || nexthdr == 60 || nexthdr == 135 {
                if frame.len() < offset + 8 {
                    return;
                }
                nexthdr = frame[offset];
                let ext_len = frame[offset + 1];
                offset += (ext_len as usize + 1) * 8;
            } else if nexthdr == 44 {
                if frame.len() < offset + 8 {
                    return;
                }
                nexthdr = frame[offset];
                offset += 8;
            } else if nexthdr == 51 {
                if frame.len() < offset + 8 {
                    return;
                }
                nexthdr = frame[offset];
                let ext_len = frame[offset + 1];
                offset += (ext_len as usize + 2) * 4;
            } else {
                break;
            }
        }
        (offset, nexthdr)
    } else {
        return;
    };

    if protocol != 6 {
        return;
    }

    let tcp_offset = ip_header_len;
    if frame.len() < tcp_offset + 20 {
        return;
    }

    let tcp_flags = frame[tcp_offset + 13];
    let syn_flag = (tcp_flags & 0x02) != 0;
    if !syn_flag {
        return;
    }

    let data_offset = (frame[tcp_offset + 12] >> 4) as usize;
    let tcp_header_len = data_offset * 4;
    if tcp_header_len < 20 || frame.len() < tcp_offset + tcp_header_len {
        return;
    }

    let mut opt_offset = tcp_offset + 20;
    let opt_end = tcp_offset + tcp_header_len;

    while opt_offset < opt_end {
        let kind = frame[opt_offset];
        if kind == 0 {
            break;
        } else if kind == 1 {
            opt_offset += 1;
        } else {
            if opt_offset + 1 >= opt_end {
                break;
            }
            let length = frame[opt_offset + 1] as usize;
            if length < 2 || opt_offset + length > opt_end {
                break;
            }

            if kind == 2 && length == 4 {
                let old_mss = u16::from_be_bytes([frame[opt_offset + 2], frame[opt_offset + 3]]);
                if old_mss > max_mss {
                    let new_mss = max_mss;
                    frame[opt_offset + 2] = (new_mss >> 8) as u8;
                    frame[opt_offset + 3] = (new_mss & 0xFF) as u8;

                    let old_csum =
                        u16::from_be_bytes([frame[tcp_offset + 16], frame[tcp_offset + 17]]);
                    let mut sum = old_csum as u32 + old_mss as u32 + !new_mss as u32;
                    while sum >> 16 != 0 {
                        sum = (sum & 0xFFFF) + (sum >> 16);
                    }
                    let new_csum = sum as u16;
                    frame[tcp_offset + 16] = (new_csum >> 8) as u8;
                    frame[tcp_offset + 17] = (new_csum & 0xFF) as u8;
                }
                break;
            }
            opt_offset += length;
        }
    }
}

pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.as_chunks::<2>().0 {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if !data.len().is_multiple_of(2) {
        sum += (*data.last().unwrap() as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn icmpv6_checksum(src_ip: &[u8], dest_ip: &[u8], icmpv6_data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in src_ip.as_chunks::<2>().0 {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dest_ip.as_chunks::<2>().0 {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += (icmpv6_data.len() as u32) & 0xFFFF;
    sum += (icmpv6_data.len() as u32) >> 16;
    sum += 58u32; // Next Header for ICMPv6

    for chunk in icmpv6_data.as_chunks::<2>().0 {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if !icmpv6_data.len().is_multiple_of(2) {
        sum += (*icmpv6_data.last().unwrap() as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn reject_udp_and_icmp(packet: &[u8], fd: std::os::fd::RawFd) -> bool {
    if packet.is_empty() {
        return false;
    }

    let version = packet[0] >> 4;
    if version == 4 {
        if packet.len() < 20 {
            return false;
        }
        let ihl = (packet[0] & 0x0F) as usize * 4;
        if packet.len() < ihl {
            return false;
        }
        let protocol = packet[9];
        if protocol == 1 {
            // ICMP: silently drop
            return true;
        }
        if protocol == 17 {
            // UDP
            if packet.len() < ihl + 8 {
                return true; // too short, drop
            }
            let dest_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            if dest_port == 53 {
                return false; // let DNS queries through
            }

            // Build ICMPv4 Port Unreachable
            let original_payload_len = std::cmp::min(packet.len(), ihl + 8);
            let new_packet_len = 20 + 8 + original_payload_len;
            let mut new_packet = vec![0u8; new_packet_len];

            // IPv4 header
            new_packet[0] = 0x45; // Version 4, IHL 5
            new_packet[1] = 0x00;
            let total_len_be = (new_packet_len as u16).to_be_bytes();
            new_packet[2] = total_len_be[0];
            new_packet[3] = total_len_be[1];
            new_packet[8] = 64; // TTL
            new_packet[9] = 1; // Protocol: ICMP
            new_packet[12..16].copy_from_slice(&packet[16..20]); // Src IP = original Dest IP
            new_packet[16..20].copy_from_slice(&packet[12..16]); // Dest IP = original Src IP

            let ip_checksum = internet_checksum(&new_packet[0..20]);
            new_packet[10] = (ip_checksum >> 8) as u8;
            new_packet[11] = (ip_checksum & 0xFF) as u8;

            // ICMPv4 header
            new_packet[20] = 3; // Type: Destination Unreachable
            new_packet[21] = 3; // Code: Port Unreachable
                                // Checksum at 22..24 (zero for calculation)
                                // 24..28: Unused (all zeros)
            new_packet[28..28 + original_payload_len]
                .copy_from_slice(&packet[..original_payload_len]);

            let icmp_checksum = internet_checksum(&new_packet[20..]);
            new_packet[22] = (icmp_checksum >> 8) as u8;
            new_packet[23] = (icmp_checksum & 0xFF) as u8;

            // Write back to TUN
            unsafe {
                let _ = libc::write(
                    fd,
                    new_packet.as_ptr() as *const libc::c_void,
                    new_packet.len(),
                );
            }
            return true;
        }
    } else if version == 6 {
        if packet.len() < 40 {
            return false;
        }
        let next_header = packet[6];
        if next_header == 58 {
            // ICMPv6: silently drop
            return true;
        }
        if next_header == 17 {
            // UDP
            if packet.len() < 48 {
                return true; // too short, drop
            }
            let dest_port = u16::from_be_bytes([packet[42], packet[43]]);
            if dest_port == 53 {
                return false; // let DNS queries through
            }

            // Build ICMPv6 Port Unreachable
            let original_payload_len = std::cmp::min(packet.len(), 1232);
            let new_packet_len = 40 + 8 + original_payload_len;
            let mut new_packet = vec![0u8; new_packet_len];

            // IPv6 header
            new_packet[0] = 0x60; // Version 6
            let payload_len_be = ((8 + original_payload_len) as u16).to_be_bytes();
            new_packet[4] = payload_len_be[0];
            new_packet[5] = payload_len_be[1];
            new_packet[6] = 58; // Next Header: ICMPv6
            new_packet[7] = 64; // Hop Limit
            new_packet[8..24].copy_from_slice(&packet[24..40]); // Src IP = original Dest IP
            new_packet[24..40].copy_from_slice(&packet[8..24]); // Dest IP = original Src IP

            // ICMPv6 header
            new_packet[40] = 1; // Type: Destination Unreachable
            new_packet[41] = 4; // Code: Port Unreachable
                                // Checksum at 42..44
            new_packet[48..48 + original_payload_len]
                .copy_from_slice(&packet[..original_payload_len]);

            let icmp_checksum =
                icmpv6_checksum(&new_packet[8..24], &new_packet[24..40], &new_packet[40..]);
            new_packet[42] = (icmp_checksum >> 8) as u8;
            new_packet[43] = (icmp_checksum & 0xFF) as u8;

            // Write back to TUN
            unsafe {
                let _ = libc::write(
                    fd,
                    new_packet.as_ptr() as *const libc::c_void,
                    new_packet.len(),
                );
            }
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calculate_tcp_checksum(ipv4_hdr: &[u8], tcp_hdr: &[u8]) -> u16 {
        let mut sum = 0u32;
        sum += u16::from_be_bytes([ipv4_hdr[12], ipv4_hdr[13]]) as u32;
        sum += u16::from_be_bytes([ipv4_hdr[14], ipv4_hdr[15]]) as u32;
        sum += u16::from_be_bytes([ipv4_hdr[16], ipv4_hdr[17]]) as u32;
        sum += u16::from_be_bytes([ipv4_hdr[18], ipv4_hdr[19]]) as u32;
        sum += 6u32;
        sum += tcp_hdr.len() as u32;

        for chunk in tcp_hdr.as_chunks::<2>().0 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        if !tcp_hdr.len().is_multiple_of(2) {
            sum += (*tcp_hdr.last().unwrap() as u32) << 8;
        }

        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[test]
    fn test_clamp_mss_ipv4_syn() {
        let ipv4_hdr = vec![
            0x45, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
            10, 0, 0, 2,
        ];
        let mut tcp_hdr = vec![
            0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x60, 0x02,
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        ];

        let csum = calculate_tcp_checksum(&ipv4_hdr, &tcp_hdr);
        tcp_hdr[16] = (csum >> 8) as u8;
        tcp_hdr[17] = (csum & 0xFF) as u8;

        let mut packet = [ipv4_hdr, tcp_hdr].concat();

        clamp_mss(&mut packet, 1300);

        let new_mss = u16::from_be_bytes([packet[42], packet[43]]);
        assert_eq!(new_mss, 1300);

        let calculated = calculate_tcp_checksum(&packet[..20], &packet[20..]);
        assert_eq!(calculated, 0);
    }

    #[test]
    fn test_clamp_mss_ipv4_syn_smaller() {
        let ipv4_hdr = vec![
            0x45, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
            10, 0, 0, 2,
        ];
        let mut tcp_hdr = vec![
            0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x60, 0x02,
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x04, 0xb0,
        ];

        let csum = calculate_tcp_checksum(&ipv4_hdr, &tcp_hdr);
        tcp_hdr[16] = (csum >> 8) as u8;
        tcp_hdr[17] = (csum & 0xFF) as u8;

        let mut packet = [ipv4_hdr, tcp_hdr].concat();

        clamp_mss(&mut packet, 1300);

        let new_mss = u16::from_be_bytes([packet[42], packet[43]]);
        assert_eq!(new_mss, 1200);

        let calculated = calculate_tcp_checksum(&packet[..20], &packet[20..]);
        assert_eq!(calculated, 0);
    }

    #[test]
    fn test_clamp_mss_ipv4_non_syn() {
        let ipv4_hdr = vec![
            0x45, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, 10, 0, 0, 1,
            10, 0, 0, 2,
        ];
        let mut tcp_hdr = vec![
            0x30, 0x39, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x60, 0x10,
            0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        ];

        let csum = calculate_tcp_checksum(&ipv4_hdr, &tcp_hdr);
        tcp_hdr[16] = (csum >> 8) as u8;
        tcp_hdr[17] = (csum & 0xFF) as u8;

        let mut packet = [ipv4_hdr, tcp_hdr].concat();

        clamp_mss(&mut packet, 1300);

        let new_mss = u16::from_be_bytes([packet[42], packet[43]]);
        assert_eq!(new_mss, 1460);
    }
}
