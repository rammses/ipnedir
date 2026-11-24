//! Media words/packed request: XNU xnu-12377.1.9 net/if{,_media}.h.

use crate::model::State;

use super::wire;

#[repr(C, packed(4))]
pub(super) struct IfMediaReq {
    pub name: [u8; 16],
    pub current: i32,
    pub mask: i32,
    pub status: i32,
    pub active: i32,
    pub count: i32,
    pub list: *mut i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Query {
    Extended,
    Compatible,
}

pub(super) enum IoctlError {
    Unsupported,
    Other,
}

pub(super) fn state(admin_up: bool, status: Option<u32>) -> State {
    if !admin_up {
        return State::Down;
    }
    match status {
        Some(status) if status & 1 != 0 => {
            if status & 2 != 0 {
                State::Up
            } else {
                State::Down
            }
        }
        _ => State::Unknown,
    }
}

pub(super) fn speed(active: u32, status: u32) -> Option<u64> {
    if status & 3 != 3 || active & 0xe0 != 0x20 {
        return None;
    }
    // Invert IFM_X_SUBTYPE, excluding type/options/instance bits.
    let subtype = active & 0x000f001f;
    let number = (subtype & 0x1f) | ((subtype & 0x000f0000) >> 11);
    Some(match number {
        3 | 4 | 5 | 12 | 13 => 10_000_000,
        6..=10 => 100_000_000,
        11 | 14 | 15 | 16 | 24 | 25 => 1_000_000_000,
        22 | 32 | 36 | 63 => 2_500_000_000,
        23 | 64 | 69 | 70 => 5_000_000_000,
        18..=21 | 26..=29 | 33..=35 | 42 | 59 => 10_000_000_000,
        30 => 20_000_000_000,
        _ => return None,
    })
}

pub(super) fn query_with(
    name: &[u8],
    mut call: impl FnMut(Query, &mut IfMediaReq) -> Result<(), IoctlError>,
) -> Option<(u32, u32)> {
    if !wire::valid_name(name) {
        return None;
    }
    for query in [Query::Extended, Query::Compatible] {
        // A failed ioctl may have partially overwritten the request. The
        // compatibility call gets a fresh zeroed payload, with no user list.
        let mut request = IfMediaReq {
            name: [0; 16],
            current: 0,
            mask: 0,
            status: 0,
            active: 0,
            count: 0,
            list: std::ptr::null_mut(),
        };
        request.name[..name.len()].copy_from_slice(name);
        match call(query, &mut request) {
            Ok(()) => {
                if wire::name(&request.name) != Some(name) {
                    return None;
                }
                // Copy packed fields by value, never through references.
                return Some((request.status as u32, request.active as u32));
            }
            Err(IoctlError::Unsupported) if query == Query::Extended => continue,
            Err(_) => return None,
        }
    }
    None
}

#[cfg(target_os = "macos")]
pub(super) fn query(fd: std::os::fd::BorrowedFd<'_>, name: &[u8]) -> Option<(u32, u32)> {
    use std::{io, os::fd::AsRawFd};

    query_with(name, |query, request| {
        let command = match query {
            Query::Extended => libc::SIOCGIFXMEDIA,
            Query::Compatible => libc::SIOCGIFMEDIA,
        };
        // SAFETY: request matches the pinned 44-byte packed native ABI (const
        // assertions below). It is initialized, count=0 and list=null, so no
        // media list buffer is requested. fd is borrowed, never closed here.
        if unsafe { libc::ioctl(fd.as_raw_fd(), command, request as *mut IfMediaReq) } == 0 {
            return Ok(());
        }
        let errno = io::Error::last_os_error().raw_os_error();
        if matches!(errno, Some(libc::ENOTTY | libc::ENOTSUP | libc::EOPNOTSUPP)) {
            Err(IoctlError::Unsupported)
        } else {
            Err(IoctlError::Other)
        }
    })
}

#[cfg(target_os = "macos")]
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    assert!(size_of::<libc::c_int>() == 4);
    assert!(size_of::<IfMediaReq>() == 44);
    assert!(align_of::<IfMediaReq>() == 4);
    assert!(offset_of!(IfMediaReq, list) == 36);
    assert!((libc::SIOCGIFXMEDIA >> 16) & 0x1fff == 44);
    assert!((libc::SIOCGIFMEDIA >> 16) & 0x1fff == 44);
    assert!(libc::IFF_UP == 1);
};
