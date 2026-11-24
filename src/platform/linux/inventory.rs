use super::netlink::{aligned_record, for_messages, u16_ne, u32_ne};
use crate::model::{Address, CollectError, Counters, Interface, InterfaceId, State};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Instant,
};

pub fn decode_stats64(bytes: &[u8]) -> Option<(u64, u64)> {
    // linux/if_link.h: two packet u64s precede RX/TX bytes. New kernels
    // may append fields; only this checked prefix is needed.
    Some((
        u64::from_ne_bytes(bytes.get(16..24)?.try_into().ok()?),
        u64::from_ne_bytes(bytes.get(24..32)?.try_into().ok()?),
    ))
}

fn for_attributes(
    mut bytes: &[u8],
    mut visit: impl FnMut(u16, &[u8]) -> Result<(), CollectError>,
) -> Result<(), CollectError> {
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(CollectError("short route attribute".into()));
        }
        let len = usize::from(u16_ne(bytes));
        let (_, rest) = aligned_record(bytes, len, 4)?;
        visit(u16_ne(&bytes[2..]) & 0x3fff, &bytes[4..len])?;
        bytes = rest;
    }
    Ok(())
}

pub fn decode_links(bytes: &[u8], at: Instant) -> Result<Vec<Interface>, CollectError> {
    let mut links = Vec::new();
    let mut indices = BTreeSet::new();
    for_messages(bytes, |msg| {
        // linux/rtnetlink.h: RTM_NEWLINK + 16-byte ifinfomsg.
        if msg.kind != 16 || msg.payload.len() < 16 {
            return Err(CollectError("invalid link inventory message".into()));
        }
        let index = u32_ne(&msg.payload[4..]);
        if index == 0 || index > i32::MAX as u32 || !indices.insert(index) {
            return Err(CollectError("invalid or duplicate interface index".into()));
        }
        let mut name = None;
        let mut state = State::Unknown;
        let mut mtu = None;
        let mut link_address = None;
        let mut counters = None;
        for_attributes(&msg.payload[16..], |kind, value| {
            match kind {
                3 => {
                    if name.is_some()
                        || value.len() < 2
                        || value.len() > 16
                        || value.last() != Some(&0)
                        || value[..value.len() - 1].contains(&0)
                    {
                        return Err(CollectError("invalid interface name".into()));
                    }
                    name = Some(value[..value.len() - 1].to_vec());
                }
                1 => link_address = (!value.is_empty()).then(|| value.to_vec()),
                4 => mtu = (value.len() == 4).then(|| u32_ne(value)),
                16 => {
                    state = match value {
                        [6] => State::Up,
                        [2] => State::Down,
                        _ => State::Unknown,
                    }
                }
                23 => {
                    counters = decode_stats64(value).map(|(rx, tx)| Counters {
                        at,
                        rx_bytes: Some(rx),
                        tx_bytes: Some(tx),
                    })
                }
                _ => {}
            }
            Ok(())
        })?;
        links.push(Interface {
            id: InterfaceId {
                index,
                name: name.ok_or_else(|| CollectError("missing interface name".into()))?,
            },
            state,
            addresses: Vec::new(),
            mtu,
            link_address,
            counters,
            speed_bps: None,
        });
        Ok(())
    })?;
    Ok(links)
}

pub fn attach_addresses(links: &mut [Interface], bytes: &[u8]) -> Result<(), CollectError> {
    for_messages(bytes, |msg| {
        // linux/if_addr.h: RTM_NEWADDR + 8-byte ifaddrmsg; IFA_LOCAL is
        // assigned address, IFA_ADDRESS can instead be a point-to-point peer.
        if msg.kind != 20 || msg.payload.len() < 8 {
            return Err(CollectError("invalid address inventory message".into()));
        }
        let family = msg.payload[0];
        if family != 2 && family != 10 {
            return for_attributes(&msg.payload[8..], |_, _| Ok(()));
        }
        let index = u32_ne(&msg.payload[4..]);
        let interface = links
            .iter_mut()
            .find(|item| item.id.index == index && index > 0)
            .ok_or_else(|| CollectError("address interface disappeared from inventory".into()))?;
        let mut local = None;
        let mut peer = None;
        for_attributes(&msg.payload[8..], |kind, value| {
            if kind == 1 || kind == 2 {
                let ip = match (family, value.len()) {
                    (2, 4) => IpAddr::V4(Ipv4Addr::from(
                        <[u8; 4]>::try_from(value).expect("checked IPv4"),
                    )),
                    (10, 16) => IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(value).expect("checked IPv6"),
                    )),
                    _ => return Err(CollectError("invalid assigned address length".into())),
                };
                let slot = if kind == 2 { &mut local } else { &mut peer };
                if slot.replace(ip).is_some() {
                    return Err(CollectError("duplicate assigned address attribute".into()));
                }
            }
            Ok(())
        })?;
        let ip = local
            .or(peer)
            .ok_or_else(|| CollectError("missing assigned address".into()))?;
        let prefix = msg.payload[1];
        let prefix = (prefix <= if family == 2 { 32 } else { 128 }).then_some(prefix);
        let scope_id = match ip {
            IpAddr::V6(v6)
                if v6.is_unicast_link_local()
                    || msg.payload[3] == 253
                    || (v6.is_multicast() && matches!(v6.octets()[1] & 15, 1 | 2)) =>
            {
                Some(index)
            }
            _ => None,
        };
        interface.addresses.push(Address {
            ip,
            prefix,
            scope_id,
        });
        Ok(())
    })
}
