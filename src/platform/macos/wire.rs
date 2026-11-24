//! Byte layouts pinned to libc 0.2.191 and XNU xnu-12377.1.9.
//! Native compile-time assertions below fail closed if the target ABI differs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::{Address, CollectError};

pub(super) const IFMIB_SIZE: usize = 180;
pub(super) const AF_INET: u8 = 2;
pub(super) const AF_LINK: u8 = 18;
pub(super) const AF_INET6: u8 = 30;

pub(super) struct Link {
    pub index: u32,
    pub address: Option<Vec<u8>>,
}

pub(super) fn ifmib_counters(bytes: &[u8], expected_name: &[u8]) -> Option<(u64, u64)> {
    valid_ifmib(bytes, expected_name)?;
    // if_data64 is packed(4). Never create a reference to either u64 field.
    Some((
        u64::from_ne_bytes(bytes.get(116..124)?.try_into().ok()?),
        u64::from_ne_bytes(bytes.get(124..132)?.try_into().ok()?),
    ))
}

pub(super) fn ifmib_mtu(bytes: &[u8], expected_name: &[u8]) -> Option<u32> {
    valid_ifmib(bytes, expected_name)?;
    let mtu = u32::from_ne_bytes(bytes.get(60..64)?.try_into().ok()?);
    (mtu != 0).then_some(mtu)
}

fn valid_ifmib(bytes: &[u8], expected_name: &[u8]) -> Option<()> {
    (bytes.len() == IFMIB_SIZE && valid_name(expected_name)).then_some(())?;
    (name(bytes.get(..16)?)? == expected_name).then_some(())
}

/// Darwin routing messages use ROUNDUP32 even on LP64, including a four-byte
/// slot for sa_len == 0. This is not alignment to the host's sizeof(long).
pub(super) fn sockaddr_stride(length: usize) -> Option<usize> {
    if length == 0 {
        Some(4)
    } else {
        length.checked_add(3).map(|length| length & !3)
    }
}

pub(super) fn prefix(mask: &[u8]) -> Option<u8> {
    if !matches!(mask.len(), 4 | 16) {
        return None;
    }
    let mut count = 0;
    let mut zero_seen = false;
    for byte in mask {
        for bit in (0..8).rev() {
            if byte & (1 << bit) == 0 {
                zero_seen = true;
            } else if zero_seen {
                return None;
            } else {
                count += 1;
            }
        }
    }
    Some(count)
}

pub(super) fn valid_name(name: &[u8]) -> bool {
    !name.is_empty() && name.len() < 16 && !name.contains(&0)
}

pub(super) fn name(field: &[u8]) -> Option<&[u8]> {
    let end = field.iter().position(|byte| *byte == 0)?;
    let name = field.get(..end)?;
    valid_name(name).then_some(name)
}

fn sockaddr(bytes: &[u8]) -> Result<&[u8], CollectError> {
    let len = bytes.first().copied().unwrap_or(0) as usize;
    if len < 2 {
        return Err(CollectError("short Darwin sockaddr header".into()));
    }
    bytes
        .get(..len)
        .ok_or_else(|| CollectError("truncated Darwin sockaddr".into()))
}

pub(super) fn link(bytes: &[u8], expected_name: &[u8]) -> Result<Link, CollectError> {
    let bytes = sockaddr(bytes)?;
    if bytes.len() < 8 || bytes[1] != AF_LINK || !valid_name(expected_name) {
        return Err(CollectError("invalid Darwin link sockaddr header".into()));
    }
    let index = u16::from_ne_bytes([bytes[2], bytes[3]]) as u32;
    let name_end = 8 + bytes[5] as usize;
    let address_end = name_end + bytes[6] as usize;
    let selector_end = address_end + bytes[7] as usize;
    if index == 0 || selector_end > bytes.len() || bytes.get(8..name_end) != Some(expected_name) {
        return Err(CollectError(
            "invalid Darwin link identity or extents".into(),
        ));
    }
    // sdl_data[12] is only a minimum work area, not the allocation's cap.
    let address = bytes[name_end..address_end].to_vec();
    Ok(Link {
        index,
        address: (!address.is_empty()).then_some(address),
    })
}

pub(super) fn address(
    bytes: &[u8],
    mask: Option<&[u8]>,
    index: u32,
) -> Result<Option<Address>, CollectError> {
    let bytes = sockaddr(bytes)?;
    let family = bytes[1];
    let (ip, scope_id, range, size) = match family {
        AF_INET => {
            if bytes.len() != 16 {
                return Err(CollectError("invalid Darwin IPv4 sockaddr size".into()));
            }
            let octets = [bytes[4], bytes[5], bytes[6], bytes[7]];
            (IpAddr::V4(Ipv4Addr::from(octets)), None, 4..8, 16)
        }
        AF_INET6 => {
            if bytes.len() != 28 {
                return Err(CollectError("invalid Darwin IPv6 sockaddr size".into()));
            }
            let mut octets = [0; 16];
            octets.copy_from_slice(&bytes[8..24]);
            let explicit = u32::from_ne_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
            // XNU IN6_IS_SCOPE_EMBED excludes unicast-based link-local
            // multicast (flags 0x30). Such groups still need an interface
            // zone, but their group bits must not be interpreted or cleared.
            let unicast_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
            let multicast_scope = if octets[0] == 0xff {
                octets[1] & 0x0f
            } else {
                0
            };
            let local = unicast_local || matches!(multicast_scope, 1 | 2);
            let embeds = unicast_local
                || multicast_scope == 1
                || (multicast_scope == 2 && octets[1] & 0xf0 != 0x30);
            let scope = if local {
                let embedded = if embeds {
                    u16::from_be_bytes([octets[2], octets[3]]) as u32
                } else {
                    0
                };
                if index == 0
                    || (explicit != 0 && explicit != index)
                    || (embedded != 0 && embedded != index)
                {
                    return Err(CollectError(
                        "conflicting Darwin IPv6 interface scope".into(),
                    ));
                }
                if embeds {
                    octets[2..4].fill(0);
                }
                Some(index)
            } else {
                (explicit != 0).then_some(explicit)
            };
            (IpAddr::V6(Ipv6Addr::from(octets)), scope, 8..24, 28)
        }
        _ => return Ok(None),
    };
    // A malformed/absent mask makes only the prefix unavailable, not the IP.
    let prefix = mask.and_then(|mask| {
        let mask = sockaddr(mask).ok()?;
        if mask.len() != size || (mask[1] != 0 && mask[1] != family) {
            return None;
        }
        prefix(mask.get(range)?)
    });
    Ok(Some(Address {
        ip,
        prefix,
        scope_id,
    }))
}

#[cfg(target_os = "macos")]
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<libc::ifmibdata>() == IFMIB_SIZE);
    assert!(align_of::<libc::ifmibdata>() == 4);
    assert!(offset_of!(libc::ifmibdata, ifmd_data) == 52);
    assert!(size_of::<libc::if_data64>() == 128);
    assert!(align_of::<libc::if_data64>() == 4);
    assert!(offset_of!(libc::if_data64, ifi_mtu) == 8);
    assert!(offset_of!(libc::if_data64, ifi_ibytes) == 64);
    assert!(offset_of!(libc::if_data64, ifi_obytes) == 72);
    assert!(size_of::<libc::sockaddr_in>() == 16);
    assert!(offset_of!(libc::sockaddr_in, sin_addr) == 4);
    assert!(size_of::<libc::sockaddr_in6>() == 28);
    assert!(offset_of!(libc::sockaddr_in6, sin6_addr) == 8);
    assert!(offset_of!(libc::sockaddr_in6, sin6_scope_id) == 24);
    assert!(offset_of!(libc::sockaddr_dl, sdl_data) == 8);
    assert!(libc::IFNAMSIZ == 16);
    assert!(libc::AF_INET == AF_INET as i32);
    assert!(libc::AF_INET6 == AF_INET6 as i32);
    assert!(libc::AF_LINK == AF_LINK as i32);
};
