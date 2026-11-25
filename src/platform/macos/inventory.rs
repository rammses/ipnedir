use std::{collections::BTreeMap, time::Instant};

use crate::model::{CollectError, Counters, Interface, InterfaceId, Snapshot};

use super::{media, wire};

pub(super) struct Entry {
    pub name: Vec<u8>,
    pub index: u32,
    pub flags: u32,
    pub address: Option<Vec<u8>>,
    pub netmask: Option<Vec<u8>>,
}

pub(super) struct Observation {
    pub before: Option<InterfaceId>,
    pub after: Option<InterfaceId>,
    pub ifmib: Option<Vec<u8>>,
    pub at: Instant,
    pub media: Option<(u32, u32)>,
}

pub(super) fn assemble(entries: &[Entry]) -> Result<Snapshot, CollectError> {
    let mut interfaces = BTreeMap::<InterfaceId, Interface>::new();
    let mut indices = BTreeMap::new();
    let mut names = BTreeMap::new();
    let mut flags = BTreeMap::new();
    for entry in entries {
        if entry.index == 0 || !wire::valid_name(&entry.name) {
            return Err(CollectError("invalid Darwin inventory identity".into()));
        }
        if indices
            .insert(entry.index, &entry.name)
            .is_some_and(|name| name != &entry.name)
            || names
                .insert(&entry.name, entry.index)
                .is_some_and(|index| index != entry.index)
            || flags
                .insert(entry.index, entry.flags)
                .is_some_and(|flags| flags != entry.flags)
        {
            return Err(CollectError(
                "Darwin inventory identity or flags changed during enumeration".into(),
            ));
        }
        let id = InterfaceId {
            index: entry.index,
            name: entry.name.clone(),
        };
        let interface = interfaces.entry(id.clone()).or_insert_with(|| Interface {
            id,
            state: media::state(entry.flags & 1 != 0, None),
            addresses: vec![],
            link_address: None,
            mtu: None,
            speed_bps: None,
            counters: None,
        });
        if let Some(bytes) = &entry.address {
            if bytes.get(1) == Some(&wire::AF_LINK) {
                let link = wire::link(bytes, &entry.name)?;
                if link.index != entry.index {
                    return Err(CollectError("Darwin link/index identity mismatch".into()));
                }
                if let Some(address) = link.address {
                    if interface
                        .link_address
                        .as_ref()
                        .is_some_and(|old| *old != address)
                    {
                        return Err(CollectError("conflicting Darwin link addresses".into()));
                    }
                    interface.link_address = Some(address);
                }
            } else if let Some(address) =
                wire::address(bytes, entry.netmask.as_deref(), entry.index)?
                && !interface.addresses.contains(&address)
            {
                interface.addresses.push(address);
            }
        }
    }
    Ok(Snapshot {
        interfaces: interfaces.into_values().collect(),
    })
}

pub(super) fn enrich(interface: &mut Interface, admin_up: bool, observation: Observation) {
    // Each observation is independent: failures cannot leave stale values.
    interface.state = media::state(admin_up, None);
    interface.mtu = None;
    interface.speed_bps = None;
    interface.counters = None;
    if observation.before.as_ref() != Some(&interface.id)
        || observation.after.as_ref() != Some(&interface.id)
    {
        return;
    }
    if let Some(bytes) = observation.ifmib {
        interface.mtu = wire::ifmib_mtu(&bytes, &interface.id.name);
        interface.counters =
            wire::ifmib_counters(&bytes, &interface.id.name).map(|(rx, tx)| Counters {
                at: observation.at,
                rx_bytes: Some(rx),
                tx_bytes: Some(tx),
            });
    }
    if let Some((status, active)) = observation.media {
        interface.state = media::state(admin_up, Some(status));
        if admin_up {
            interface.speed_bps = media::speed(active, status);
        }
    }
}

pub(super) struct IfAddrsOwner<T> {
    pub head: *mut T,
    release: unsafe extern "C" fn(*mut T),
}

impl<T> IfAddrsOwner<T> {
    /// # Safety
    /// `head` must be the unique list allocation accepted by `release` (or null).
    /// All borrows of its contents must end before this owner is dropped.
    pub(super) unsafe fn new(head: *mut T, release: unsafe extern "C" fn(*mut T)) -> Self {
        Self { head, release }
    }
}

impl<T> Drop for IfAddrsOwner<T> {
    fn drop(&mut self) {
        if !self.head.is_null() {
            // SAFETY: new transfers unique ownership and the matching releaser.
            unsafe { (self.release)(self.head) };
        }
    }
}

#[cfg(target_os = "macos")]
pub(super) mod native {
    use std::{
        ffi::{CStr, CString},
        io,
        os::fd::{AsFd, FromRawFd, OwnedFd},
        ptr, slice,
    };

    use crate::model::State;

    use super::*;

    pub(in crate::platform::macos) fn snapshot() -> Result<Snapshot, CollectError> {
        let entries = entries()?;
        let mut snapshot = assemble(&entries)?;
        // This socket is for local read-only media ioctls, never traffic.
        // Failure loses optional media data, not the mandatory inventory.
        let socket = media_socket();
        for interface in &mut snapshot.interfaces {
            // Assembly has applied only IFF_UP, with no inferred carrier.
            let admin_up = interface.state != State::Down;
            let before = identity(interface.id.index);
            let matches = before.as_ref() == Some(&interface.id);
            let ifmib = if matches {
                read_ifmib(interface.id.index)
            } else {
                None
            };
            // Per-interface monotonic sample time, immediately after sysctl.
            let at = Instant::now();
            let media = if matches {
                socket
                    .as_ref()
                    .and_then(|fd| media::query(fd.as_fd(), &interface.id.name))
            } else {
                None
            };
            let after = identity(interface.id.index);
            enrich(
                interface,
                admin_up,
                Observation {
                    before,
                    after,
                    ifmib,
                    at,
                    media,
                },
            );
        }
        Ok(snapshot)
    }

    fn entries() -> Result<Vec<Entry>, CollectError> {
        let mut head = ptr::null_mut();
        // SAFETY: valid out-pointer. On success getifaddrs transfers one
        // null-terminated list, including its names and sockaddr allocations.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Err(CollectError(format!(
                "getifaddrs: {}",
                io::Error::last_os_error()
            )));
        }
        // SAFETY: one successful allocation, one matching freeifaddrs owner.
        let owner = unsafe { IfAddrsOwner::new(head, libc::freeifaddrs) };
        let mut current = owner.head;
        let mut entries = Vec::new();
        while !current.is_null() {
            // SAFETY: current is a node in the still-owned getifaddrs list.
            let entry = unsafe { &*current };
            if entry.ifa_name.is_null() {
                return Err(CollectError(
                    "getifaddrs returned a null interface name".into(),
                ));
            }
            // SAFETY: getifaddrs supplies a NUL-terminated name for each node.
            // Copy bytes, not UTF-8, before releasing any native storage.
            let name = unsafe { CStr::from_ptr(entry.ifa_name) }
                .to_bytes()
                .to_vec();
            if !wire::valid_name(&name) {
                return Err(CollectError(
                    "getifaddrs returned an invalid interface name".into(),
                ));
            }
            // SAFETY: the name remains live and terminated under owner.
            let index = unsafe { libc::if_nametoindex(entry.ifa_name) };
            if index == 0 {
                return Err(CollectError(
                    "getifaddrs interface index is unavailable".into(),
                ));
            }
            entries.push(Entry {
                name,
                index,
                flags: entry.ifa_flags,
                // SAFETY: these null-or-sockaddr pointers belong to owner.
                address: unsafe { copy_sockaddr(entry.ifa_addr) },
                netmask: unsafe { copy_sockaddr(entry.ifa_netmask) },
            });
            // ifa_data is deliberately not read: it contains 32-bit if_data
            // counters, not the 64-bit IFMIB sample required by this adapter.
            current = entry.ifa_next;
        }
        // No references into owner escape; Drop also covers every early error.
        Ok(entries)
    }

    /// Copy an API-owned variable-size sockaddr, not a fixed sockaddr_dl cast.
    unsafe fn copy_sockaddr(address: *const libc::sockaddr) -> Option<Vec<u8>> {
        if address.is_null() {
            return None;
        }
        let bytes = address.cast::<u8>();
        // SAFETY: caller supplies a getifaddrs sockaddr allocation. Darwin's
        // first byte is sa_len, and the API owns at least that many bytes.
        let len = unsafe { bytes.read() } as usize;
        if len == 0 {
            // Libinfo getifaddrs.c RTAX_NETMASK zero-fills an address-sized
            // allocation for this special mask. Preserve the already-read
            // length byte as an owned marker, without reading family/payload
            // beyond sa_len. Ordinary address decoding still rejects it.
            return Some(vec![0]);
        }
        // SAFETY: the allocation is live until owner drops. Copy exactly len,
        // not routing padding or a full sockaddr cast for a compact netmask.
        Some(unsafe { slice::from_raw_parts(bytes, len) }.to_vec())
    }

    fn identity(index: u32) -> Option<InterfaceId> {
        if index == 0 {
            return None;
        }
        let mut name = [0 as libc::c_char; libc::IFNAMSIZ];
        // SAFETY: IFNAMSIZ bytes of writable storage as required by the API.
        if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
            return None;
        }
        let bytes = name.map(|byte| byte as u8);
        let name = wire::name(&bytes)?.to_vec();
        let c_name = CString::new(name.as_slice()).ok()?;
        // SAFETY: the owned CString is NUL-terminated and live for this call.
        if unsafe { libc::if_nametoindex(c_name.as_ptr()) } != index {
            return None;
        }
        Some(InterfaceId { index, name })
    }

    fn read_ifmib(index: u32) -> Option<Vec<u8>> {
        let mut mib = [
            libc::CTL_NET,
            libc::PF_LINK,
            libc::NETLINK_GENERIC,
            libc::IFMIB_IFDATA,
            libc::c_int::try_from(index).ok()?,
            libc::IFDATA_GENERAL,
        ];
        let mut bytes = vec![0; std::mem::size_of::<libc::ifmibdata>()];
        let mut len = bytes.len();
        // SAFETY: the MIB and length pointers are valid; oldp has len writable
        // bytes. Null newp/zero newlen make this sysctl read-only. Kernel copies
        // bytes, so oldp need not be aligned as a Rust packed struct reference.
        let result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                bytes.as_mut_ptr().cast(),
                &mut len,
                ptr::null_mut(),
                0,
            )
        };
        // A successful zero-filled response is still validated by raw name in
        // enrich. Failures/size races never expose this initialized buffer.
        (result == 0 && len == wire::IFMIB_SIZE).then_some(bytes)
    }

    fn media_socket() -> Option<OwnedFd> {
        // SAFETY: no pointer arguments; this only creates a local ioctl socket.
        let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if raw < 0 {
            return None;
        }
        // SAFETY: a successful socket call transfers one unique descriptor.
        Some(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}
