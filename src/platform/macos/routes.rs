//! Read-only NET_RT_DUMP / RTM_GET routes, not the GET2 header's semantics.
//! Layout/flags: libc 0.2.191 and XNU xnu-12377.1.9 bsd/net/route.h.
//! Bitmap order and ROUNDUP32: that XNU's rtsock.c rt_msg2/sysctl_dumpentry.

use std::collections::BTreeSet;

use crate::model::{Coverage, Defaults, Family};

use super::wire::{self, AF_INET, AF_INET6, AF_LINK};

const HEADER_LEN: usize = 92;
const VERSION: u8 = 5;
const GET: u8 = 4;
const CTL_NET: i32 = 4;
const PF_ROUTE: i32 = 17;
const NET_RT_DUMP: i32 = 1;
const MAX_DUMP: usize = 16 * 1024 * 1024;
const UP: u32 = 0x1;
const GATEWAY: u32 = 0x2;
// Host, reject, blackhole, local/broadcast/multicast, condemned and dead routes
// cannot be usable forwarding defaults. IFSCOPE is deliberately not excluded.
const NON_FORWARDING: u32 = 0x4 | 0x8 | 0x1000 | 0x00e0_0000 | 0x0200_0000 | 0x2000_0000;

/// Only success and ENOMEM have a meaningful returned byte count. Other errors
/// must not cause the caller to interpret any possibly untouched output bytes.
pub(super) enum QueryResult {
    Success(usize),
    NoMemory(usize),
    Failed(String),
}

pub(super) fn decode(mut bytes: &[u8], family: Family) -> Coverage<BTreeSet<u32>> {
    let mut members = BTreeSet::new();
    let mut failure = None;
    let mut offset = 0;
    while !bytes.is_empty() {
        let len = bytes
            .get(..2)
            .map(|len| u16::from_ne_bytes([len[0], len[1]]) as usize)
            .unwrap_or(0);
        if len < HEADER_LEN || len > bytes.len() {
            failure.get_or_insert_with(|| format!("invalid or truncated route header at {offset}"));
            break;
        }
        match member(&bytes[..len], family) {
            Ok(Some(index)) => {
                members.insert(index);
            }
            Ok(None) => {}
            Err(reason) => {
                failure.get_or_insert_with(|| format!("{reason} at {offset}"));
            }
        }
        // A complete, bounded header supplies the next record boundary. Never
        // search arbitrary bytes for a plausible header after a framing error.
        bytes = &bytes[len..];
        offset += len;
    }
    match failure {
        Some(reason) => Coverage::Incomplete {
            value: members,
            reason: format!("Darwin {} route dump: {reason}", label(family)),
        },
        None => Coverage::Complete(members),
    }
}

fn member(bytes: &[u8], family: Family) -> Result<Option<u32>, &'static str> {
    // Called only for complete HEADER_LEN-or-larger records. Copy individual
    // native-endian fields; do not cast a possibly unaligned slice to a header.
    if bytes[2] != VERSION || bytes[3] != GET {
        return Err("unsupported route version or message type (expected DUMP/GET)");
    }
    if bytes[24..28] != [0; 4] {
        return Err("route message reports an error");
    }
    let flags = u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let bitmap = u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let addresses = sockaddrs(&bytes[HEADER_LEN..], bitmap)?;
    let destination = addresses[0].ok_or("route has no destination")?;
    let ip = ip_bytes(destination, family)?;
    if flags & UP == 0 || flags & NON_FORWARDING != 0 {
        return Ok(None);
    }
    let prefix = mask_prefix(addresses[2].ok_or("network route has no netmask")?, family)?;
    if prefix != 0 || ip.iter().any(|byte| *byte != 0) {
        return Ok(None);
    }
    if flags & GATEWAY != 0 && addresses[1].is_none() {
        return Err("gateway route has no next-hop sockaddr");
    }

    let mut index = u16::from_ne_bytes([bytes[4], bytes[5]]) as u32;
    let ifp = addresses[4].map(link_index).transpose()?.unwrap_or(0);
    let gateway = match addresses[1] {
        Some(address) => match address.get(1) {
            Some(&AF_LINK) => link_index(address)?,
            Some(&AF_INET) => {
                ip_bytes(address, Family::V4)?;
                0
            }
            Some(&AF_INET6) => {
                ip_bytes(address, Family::V6)?;
                0
            }
            _ => return Err("unsupported gateway sockaddr family"),
        },
        None => 0,
    };
    // IFP describes the egress. A gateway AF_LINK is also applicable to a
    // direct/on-link route, but a gateway route's next hop is not an egress ID.
    for candidate in [ifp, if flags & GATEWAY == 0 { gateway } else { 0 }] {
        if candidate != 0 {
            if index != 0 && index != candidate {
                return Err("conflicting route interface indices");
            }
            index = candidate;
        }
    }
    if index == 0 {
        Err("default route has no usable interface index")
    } else {
        Ok(Some(index))
    }
}

fn sockaddrs(mut bytes: &[u8], bitmap: u32) -> Result<[Option<&[u8]>; 8], &'static str> {
    if bitmap & !0xff != 0 {
        return Err("unsupported route address bitmap");
    }
    let mut addresses = [None; 8];
    for (slot, address) in addresses.iter_mut().enumerate() {
        if bitmap & (1 << slot) == 0 {
            continue;
        }
        let len = bytes.first().copied().ok_or("missing route sockaddr")? as usize;
        // Zero-length NETMASK/GENMASK records are legitimate. They still occupy
        // four bytes and must not terminate iteration before later RTAX slots.
        if len == 1 || (len == 0 && !matches!(slot, 2 | 3)) {
            return Err("invalid route sockaddr length");
        }
        let stride = wire::sockaddr_stride(len).ok_or("route sockaddr stride overflow")?;
        let padded = bytes
            .get(..stride)
            .ok_or("truncated route sockaddr or padding")?;
        *address = Some(&padded[..len]);
        bytes = &bytes[stride..];
    }
    if !bytes.is_empty() {
        return Err("unclaimed route sockaddr payload");
    }
    Ok(addresses)
}

fn ip_bytes(bytes: &[u8], family: Family) -> Result<&[u8], &'static str> {
    let (af, length, start, end) = match family {
        Family::V4 => (AF_INET, 16, 4, 8),
        Family::V6 => (AF_INET6, 28, 8, 24),
    };
    if bytes.len() != length || bytes[1] != af {
        return Err("invalid IP sockaddr length or family");
    }
    Ok(&bytes[start..end])
}

fn mask_prefix(mask: &[u8], family: Family) -> Result<u8, &'static str> {
    let (length, start, width) = match family {
        Family::V4 => (16, 4, 4),
        Family::V6 => (28, 8, 16),
    };
    if mask.len() > length {
        return Err("invalid route netmask length");
    }
    // XNU xnu-12377.1.9 route.c/RTAX_NETMASK: rn_addmask may fill the
    // pre-address header with all ones, so sa_family is opaque here. The
    // already-validated destination family selects mask offset/width instead.
    // Radix masks may omit zero tail bytes (or all bytes for /0). Pad only the
    // missing address bits. Scope/port/padding bytes are not prefix bits.
    let mut bits = [0; 16];
    if mask.len() > start {
        let present = (mask.len() - start).min(width);
        bits[..present].copy_from_slice(&mask[start..start + present]);
    }
    wire::prefix(&bits[..width]).ok_or("noncontiguous route netmask")
}

fn link_index(bytes: &[u8]) -> Result<u32, &'static str> {
    if bytes.len() < 8 || bytes[1] != AF_LINK {
        return Err("invalid route link sockaddr");
    }
    let end = 8 + bytes[5] as usize + bytes[6] as usize + bytes[7] as usize;
    if end > bytes.len() {
        return Err("truncated route link sockaddr extents");
    }
    Ok(u16::from_ne_bytes([bytes[2], bytes[3]]) as u32)
}

fn label(family: Family) -> &'static str {
    match family {
        Family::V4 => "IPv4",
        Family::V6 => "IPv6",
    }
}

fn query_failure(members: BTreeSet<u32>, family: Family, detail: &str) -> Coverage<BTreeSet<u32>> {
    let reason = format!("Darwin {} route dump: {detail}", label(family));
    if members.is_empty() {
        Coverage::Unavailable(reason)
    } else {
        Coverage::Incomplete {
            value: members,
            reason,
        }
    }
}

pub(super) fn collect_with(
    family: Family,
    query: &mut impl FnMut(&[i32; 6], Option<&mut [u8]>) -> QueryResult,
) -> Coverage<BTreeSet<u32>> {
    let af = match family {
        Family::V4 => AF_INET,
        Family::V6 => AF_INET6,
    };
    let mib = [CTL_NET, PF_ROUTE, 0, af as i32, NET_RT_DUMP, 0];
    let mut known = BTreeSet::new();
    for _ in 0..3 {
        let size = match query(&mib, None) {
            QueryResult::Success(size) => size,
            QueryResult::NoMemory(size) => {
                if size > MAX_DUMP {
                    return query_failure(known, family, "size query exceeds the 16 MiB limit");
                }
                continue;
            }
            QueryResult::Failed(reason) => return query_failure(known, family, &reason),
        };
        if size > MAX_DUMP {
            return query_failure(known, family, "size query exceeds the 16 MiB limit");
        }
        if size == 0 {
            return Coverage::Complete(BTreeSet::new());
        }
        let mut bytes = Vec::new();
        if bytes.try_reserve_exact(size).is_err() {
            return query_failure(known, family, "route buffer allocation failed");
        }
        bytes.resize(size, 0);
        match query(&mib, Some(&mut bytes)) {
            QueryResult::Success(length) if length <= size => {
                return match decode(&bytes[..length], family) {
                    complete @ Coverage::Complete(_) => complete,
                    Coverage::Incomplete { mut value, reason } => {
                        value.extend(known);
                        Coverage::Incomplete { value, reason }
                    }
                    Coverage::Unavailable(reason) => query_failure(known, family, &reason),
                };
            }
            QueryResult::Failed(reason) => return query_failure(known, family, &reason),
            QueryResult::Success(length) | QueryResult::NoMemory(length) => {
                // ENOMEM may have copied a useful prefix, not a complete dump.
                // A returned size beyond our buffer is likewise never complete.
                match decode(&bytes[..length.min(size)], family) {
                    Coverage::Complete(value) | Coverage::Incomplete { value, .. } => {
                        known.extend(value)
                    }
                    Coverage::Unavailable(_) => {}
                }
                if length > MAX_DUMP {
                    return query_failure(
                        known,
                        family,
                        "returned length exceeds the 16 MiB limit",
                    );
                }
            }
        }
        // Growth does not imply oldlenp is the new required capacity. Query a
        // fresh size every attempt; a later complete dump replaces stale data.
    }
    query_failure(known, family, "truncated/growing dump after three attempts")
}

pub(super) fn defaults_with(
    mut query: impl FnMut(&[i32; 6], Option<&mut [u8]>) -> QueryResult,
) -> Defaults {
    Defaults {
        v4: collect_with(Family::V4, &mut query),
        v6: collect_with(Family::V6, &mut query),
    }
}

#[cfg(target_os = "macos")]
pub(super) mod native {
    use std::{io, ptr};

    use super::{Defaults, QueryResult, defaults_with};

    pub(in crate::platform::macos) fn defaults() -> Defaults {
        defaults_with(query)
    }

    fn query(mib: &[i32; 6], out: Option<&mut [u8]>) -> QueryResult {
        let mut mib = *mib;
        let (oldp, mut length) = match out {
            Some(bytes) => (bytes.as_mut_ptr().cast(), bytes.len()),
            None => (ptr::null_mut(), 0),
        };
        // SAFETY: mib is six live native c_int values; oldp is null for the
        // size query or points to initialized, uniquely borrowed writable byte
        // storage of length bytes. oldlenp is a live size_t. Null newp/zero
        // newlen make both calls read-only. No pointer or borrowed data escapes.
        let status =
            unsafe { libc::sysctl(mib.as_mut_ptr(), 6, oldp, &mut length, ptr::null_mut(), 0) };
        if status == 0 {
            QueryResult::Success(length)
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOMEM) {
                QueryResult::NoMemory(length)
            } else {
                QueryResult::Failed(error.to_string())
            }
        }
    }
}

// Source-backed assertions, not selected-SDK/native runtime evidence. Task8
// must check the actual SDK and run both Darwin architectures before acceptance.
#[cfg(target_os = "macos")]
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<libc::rt_msghdr>() == HEADER_LEN);
    assert!(align_of::<libc::rt_msghdr>() == 4);
    assert!(size_of::<libc::rt_metrics>() == 56);
    assert!(offset_of!(libc::rt_msghdr, rtm_msglen) == 0);
    assert!(offset_of!(libc::rt_msghdr, rtm_version) == 2);
    assert!(offset_of!(libc::rt_msghdr, rtm_type) == 3);
    assert!(offset_of!(libc::rt_msghdr, rtm_index) == 4);
    assert!(offset_of!(libc::rt_msghdr, rtm_flags) == 8);
    assert!(offset_of!(libc::rt_msghdr, rtm_addrs) == 12);
    assert!(offset_of!(libc::rt_msghdr, rtm_errno) == 24);
    assert!(offset_of!(libc::rt_msghdr, rtm_rmx) == 36);
    assert!(offset_of!(libc::sockaddr_dl, sdl_index) == 2);
    assert!(offset_of!(libc::sockaddr_dl, sdl_nlen) == 5);
    assert!(offset_of!(libc::sockaddr_dl, sdl_alen) == 6);
    assert!(offset_of!(libc::sockaddr_dl, sdl_slen) == 7);
    assert!(libc::CTL_NET == CTL_NET && libc::PF_ROUTE == PF_ROUTE);
    assert!(libc::NET_RT_DUMP == NET_RT_DUMP);
    assert!(libc::RTM_VERSION == VERSION as i32 && libc::RTM_GET == GET as i32);
    assert!(libc::RTM_GET2 != GET as i32);
    assert!(libc::RTF_UP == UP as i32 && libc::RTF_GATEWAY == GATEWAY as i32);
    assert!(
        (libc::RTF_HOST
            | libc::RTF_REJECT
            | libc::RTF_BLACKHOLE
            | libc::RTF_LOCAL
            | libc::RTF_BROADCAST
            | libc::RTF_MULTICAST
            | libc::RTF_CONDEMNED
            | libc::RTF_DEAD) as u32
            == NON_FORWARDING
    );
    assert!(libc::RTF_IFSCOPE as u32 & NON_FORWARDING == 0);
    assert!(libc::RTAX_MAX == 8);
    assert!(libc::RTAX_DST == 0 && libc::RTAX_GATEWAY == 1 && libc::RTAX_NETMASK == 2);
    assert!(libc::RTAX_GENMASK == 3 && libc::RTAX_IFP == 4 && libc::RTAX_IFA == 5);
    assert!(libc::RTAX_AUTHOR == 6 && libc::RTAX_BRD == 7);
};
