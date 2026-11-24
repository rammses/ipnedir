mod ethtool;
pub mod inventory;
pub mod netlink;

use crate::model::{CollectError, InterfaceId, Snapshot};

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
