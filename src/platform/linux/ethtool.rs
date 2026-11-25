use crate::model::InterfaceId;
use std::io;

pub(super) trait Access {
    fn identity(&mut self, name: &[u8]) -> io::Result<InterfaceId>;
    fn query(&mut self, name: &[u8], words: &mut [u32]) -> io::Result<()>;
}

// linux/ethtool.h: GLINKSETTINGS header48 bytes, signed nwords at15,
// followed by three nwords*u32 bitmaps. Store u32s so ioctl data is aligned.
pub(super) fn required_words(words: &[u32]) -> Option<usize> {
    if words.len() < 12 || words[0] != 0x4c {
        return None;
    }
    let signed = i16::from(words[3].to_ne_bytes()[3] as i8);
    if !(-127..=-1).contains(&signed) {
        return None;
    }
    // Widen BEFORE negation: -i8::MIN is not representable in i8.
    let nwords = usize::try_from(-signed).ok()?;
    12_usize.checked_add(3_usize.checked_mul(nwords)?)
}

fn mbps_to_bps(speed: u32) -> Option<u64> {
    // Linux v6.12 ethtool_validate_speed permits 0..=INT_MAX or the separate
    // SPEED_UNKNOWN (-1) sentinel; neither zero nor unknown is a reportable rate.
    if speed == 0 || speed > i32::MAX as u32 {
        return None;
    }
    u64::from(speed).checked_mul(1_000_000)
}

pub(super) fn modern_speed(words: &[u32], nwords: usize) -> Option<u64> {
    if !(1..=127).contains(&nwords) || words.len() != 12 + 3 * nwords || words[0] != 0x4c {
        return None;
    }
    let returned = words[3].to_ne_bytes()[3] as i8;
    if returned <= 0 || returned as usize != nwords {
        return None;
    }
    mbps_to_bps(words[1])
}

pub(super) fn legacy_speed(words: &[u32]) -> Option<u64> {
    // ethtool_cmd44 bytes: low16 speed at12, high16 at28 (not adjacent).
    if words.len() != 11 || words[0] != 1 {
        return None;
    }
    let low = u16::from_ne_bytes(words[3].to_ne_bytes()[..2].try_into().ok()?);
    let high = u16::from_ne_bytes(words[7].to_ne_bytes()[..2].try_into().ok()?);
    let speed = u32::from(low) | (u32::from(high) << 16);
    if speed == 65_535 {
        return None;
    } // legacy SPEED_UNKNOWN16
    mbps_to_bps(speed)
}

fn query_legacy(io: &mut impl Access, name: &[u8]) -> Option<u64> {
    let mut words = [0_u32; 11];
    words[0] = 1; // ETHTOOL_GSET; NEVER ETHTOOL_SSET.
    io.query(name, &mut words).ok()?;
    legacy_speed(&words)
}

fn query_speed(io: &mut impl Access, name: &[u8]) -> Option<u64> {
    let mut probe = [0_u32; 12];
    probe[0] = 0x4c; // ETHTOOL_GLINKSETTINGS, nwords0 handshake
    if io.query(name, &mut probe).is_err() {
        return query_legacy(io, name);
    }
    let size = required_words(&probe)?;
    let nwords = (size - 12) / 3;
    let mut words = Vec::new();
    words.try_reserve_exact(size).ok()?;
    words.resize(size, 0);
    words[0] = 0x4c;
    let mut count = [0; 4];
    count[3] = u8::try_from(nwords).ok()?;
    words[3] = u32::from_ne_bytes(count);
    if io.query(name, &mut words).is_err() {
        return query_legacy(io, name);
    }
    modern_speed(&words, nwords)
}

pub(super) fn speed_with(io: &mut impl Access, id: &InterfaceId) -> Option<u64> {
    if id.index == 0
        || id.index > i32::MAX as u32
        || id.name.is_empty()
        || id.name.len() >= 16
        || id.name.contains(&0)
    {
        return None;
    }
    if io.identity(&id.name).ok()? != *id {
        return None;
    }
    let speed = query_speed(io, &id.name);
    if io.identity(&id.name).ok()? != *id {
        return None;
    }
    // Even on a down interface a positive value is a DRIVER report. It is
    // deliberately not filtered or presented here as a negotiated live speed.
    speed
}

#[cfg(target_os = "linux")]
pub(super) fn speed(id: &InterfaceId) -> Option<u64> {
    let fd = super::owned_socket(libc::AF_INET, libc::SOCK_DGRAM, 0).ok()?;
    speed_with(&mut native::NativeAccess { fd }, id)
}

#[cfg(target_os = "linux")]
mod native {
    use super::{Access, InterfaceId};
    use std::{
        io, mem,
        os::fd::{AsRawFd, OwnedFd},
    };

    pub(super) struct NativeAccess {
        pub(super) fd: OwnedFd,
    }

    fn named_request(name: &[u8]) -> io::Result<libc::ifreq> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // SAFETY: pinned libc's target ifreq is a C union of integer/POD/
        // pointer layouts; all-zero representation is valid for initialization.
        let mut request: libc::ifreq = unsafe { mem::zeroed() };
        for (to, from) in request.ifr_name.iter_mut().zip(name) {
            *to = *from as libc::c_char;
        }
        Ok(request)
    }

    impl Access for NativeAccess {
        fn identity(&mut self, name: &[u8]) -> io::Result<InterfaceId> {
            let mut by_name = named_request(name)?;
            // SAFETY: live owned datagram socket, writable target libc ifreq
            // with a checked NUL-terminated raw name. SIOCGIFINDEX only reads
            // network state and writes the index union member in this buffer.
            if unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::SIOCGIFINDEX, &mut by_name) } < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful SIOCGIFINDEX initialized the ifru_ifindex member.
            let index = unsafe { by_name.ifr_ifru.ifru_ifindex };
            if index <= 0 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut by_index = named_request(name)?;
            by_index.ifr_ifru.ifru_ifindex = index;
            // SAFETY: initialized writable libc ifreq, positive index input,
            // same live socket; SIOCGIFNAME is a read-only identity query.
            if unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::SIOCGIFNAME, &mut by_index) } < 0 {
                return Err(io::Error::last_os_error());
            }
            let end = by_index
                .ifr_name
                .iter()
                .position(|&b| b == 0)
                .ok_or(io::ErrorKind::InvalidData)?;
            if end == 0 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            // c_char signedness is target-dependent; preserve its byte bits.
            let name = by_index.ifr_name[..end]
                .iter()
                .map(|b| b.to_ne_bytes()[0])
                .collect();
            Ok(InterfaceId {
                index: index as u32,
                name,
            })
        }

        fn query(&mut self, name: &[u8], words: &mut [u32]) -> io::Result<()> {
            // Whitelist GET commands and validate capacity against the ABI
            // BEFORE handing the kernel a pointer. No setter is possible here.
            let expected = match words.first() {
                Some(1) => 11,
                Some(0x4c) if words.len() >= 12 => {
                    let count = words[3].to_ne_bytes()[3] as i8;
                    if count < 0 {
                        return Err(io::ErrorKind::InvalidInput.into());
                    }
                    12 + 3 * count as usize
                }
                _ => return Err(io::ErrorKind::InvalidInput.into()),
            };
            if words.len() != expected {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let mut request = named_request(name)?;
            request.ifr_ifru.ifru_data = words.as_mut_ptr().cast();
            // SAFETY: libc0.2.191 supplies target ifreq/ifru_data/SIOCETHTOOL.
            // The buffer is u32-aligned, initialized and exclusively borrowed
            // across ioctl; checked sizes match linux/ethtool.h:44 GSET or
            //48+3*nwords*4 GLINKSETTINGS (max1572). The kernel uses the supplied
            // nonnegative nwords capacity. Only read-only commands1/0x4c enter.
            if unsafe { libc::ioctl(self.fd.as_raw_fd(), libc::SIOCETHTOOL, &mut request) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}
