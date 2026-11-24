mod ethtool;
pub mod inventory;
pub mod netlink;
pub mod nexthops;
pub mod routes;

use crate::model::{CollectError, Coverage, Defaults, InterfaceId, Snapshot};
use std::collections::BTreeMap;

fn defaults_with(mut dump: impl FnMut(u16, &[u8]) -> Result<Vec<u8>, CollectError>) -> Defaults {
    // Linux v6.12 rtnetlink.h: RTM_GETROUTE=26, rtmsg=12. AF_INET/AF_INET6
    // only; RT_TABLE_UNSPEC, no RTA_TABLE/filter/lookup attributes or flags.
    // The accepted dump transport supplies NLM_F_REQUEST | NLM_F_DUMP.
    let v4 = dump(26, &[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let v6 = dump(26, &[10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    let needs_v4 = v4.as_ref().is_ok_and(|bytes| routes::needs_nexthops(bytes));
    let needs_v6 = v6.as_ref().is_ok_and(|bytes| routes::needs_nexthops(bytes));
    let (hops, object_warning) = if needs_v4 || needs_v6 {
        // RTM_GETNEXTHOP=106, nhmsg=8, AF_UNSPEC includes cross-family
        // members/groups. No NHA_OIF/NHA_GROUPS filtering; only if referenced.
        match dump(106, &[0; 8]) {
            Ok(bytes) => match nexthops::decode(&bytes) {
                Coverage::Complete(hops) => (hops, None),
                Coverage::Incomplete { value, reason } => (value, Some(reason)),
                Coverage::Unavailable(reason) => (BTreeMap::new(), Some(reason)),
            },
            Err(error) => (BTreeMap::new(), Some(error.0)),
        }
    } else {
        (BTreeMap::new(), None)
    };
    let decode = |result: Result<Vec<u8>, CollectError>, family: &str, needs_objects| {
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(error) => {
                return Coverage::Unavailable(format!("{family} route dump: {}", error.0));
            }
        };
        let coverage = routes::decode(&bytes, &hops);
        match (coverage, object_warning.as_ref().filter(|_| needs_objects)) {
            (Coverage::Complete(value), Some(reason)) => Coverage::Incomplete {
                value,
                reason: format!("nexthop dump: {reason}"),
            },
            (Coverage::Incomplete { value, reason }, Some(warning)) => Coverage::Incomplete {
                value,
                reason: format!("{reason}; nexthop dump: {warning}"),
            },
            (coverage, _) => coverage,
        }
    };
    Defaults {
        v4: decode(v4, "IPv4", needs_v4),
        v6: decode(v6, "IPv6", needs_v6),
    }
}

#[cfg(target_os = "linux")]
pub fn defaults() -> Defaults {
    defaults_with(netlink::dump)
}

fn collect_with(
    mut dump: impl FnMut(u16, &[u8]) -> Result<Vec<u8>, CollectError>,
    mut speed: impl FnMut(&InterfaceId) -> Option<u64>,
) -> Result<Snapshot, CollectError> {
    let links = dump(18, &[0; 16])?; // RTM_GETLINK, ifinfomsg AF_UNSPEC
    let at = std::time::Instant::now(); // near counter collection, before later queries
    let mut interfaces = inventory::decode_links(&links, at)?;
    let addresses = dump(22, &[0; 8])?; // RTM_GETADDR, ifaddrmsg AF_UNSPEC
    inventory::attach_addresses(&mut interfaces, &addresses)?;
    for interface in &mut interfaces {
        interface.speed_bps = speed(&interface.id);
    }
    Ok(Snapshot { interfaces })
}

#[cfg(target_os = "linux")]
pub fn snapshot() -> Result<Snapshot, CollectError> {
    collect_with(netlink::dump, ethtool::speed)
}

#[cfg(target_os = "linux")]
fn owned_socket(domain: i32, kind: i32, protocol: i32) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{FromRawFd, OwnedFd};
    // SAFETY: socket takes only integer arguments. libc0.2.191 exports the
    // target ABI; CLOEXEC is set atomically, and no raw fd escapes on success.
    let fd = unsafe { libc::socket(domain, kind | libc::SOCK_CLOEXEC, protocol) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is a newly created, valid, uniquely owned descriptor. Every
    // caller retains this OwnedFd across syscalls and drops it on ALL exits.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests;
