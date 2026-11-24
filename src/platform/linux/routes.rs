//! Configured forwarding-default membership, not a policy/egress lookup.
//!
//! Wire constants/layouts: Linux v6.12 include/uapi/linux/rtnetlink.h.
//! rtmsg is 12 bytes, rtattr is four bytes, rtnexthop is eight bytes.
use super::netlink::{aligned_record, for_messages, u16_ne, u32_ne};
use super::nexthops::{self, Hop};
use crate::model::{CollectError, Coverage};
use std::collections::{BTreeMap, BTreeSet};

pub fn decode(bytes: &[u8], hops: &BTreeMap<u32, Hop>) -> Coverage<BTreeSet<u32>> {
    let mut routes = scan(bytes);
    for id in routes.ids {
        match nexthops::members(id, hops) {
            Coverage::Complete(indices) => routes.indices.extend(indices),
            Coverage::Incomplete { value, reason } => {
                routes.indices.extend(value);
                routes.reason.get_or_insert(reason);
            }
            Coverage::Unavailable(reason) => {
                routes.reason.get_or_insert(reason);
            }
        }
    }
    covered(routes.indices, routes.reason)
}

pub(super) fn needs_nexthops(bytes: &[u8]) -> bool {
    !scan(bytes).ids.is_empty()
}

#[derive(Default)]
struct Routes {
    indices: BTreeSet<u32>,
    ids: BTreeSet<u32>,
    reason: Option<String>,
}

fn scan(bytes: &[u8]) -> Routes {
    let mut routes = Routes::default();
    let result = for_messages(bytes, |message| {
        let result = if message.kind == 24 {
            // RTM_NEWROUTE
            route(message.payload, &mut routes)
        } else {
            Err(CollectError(format!(
                "unexpected route message {}",
                message.kind
            )))
        };
        if let Err(error) = result {
            routes.reason.get_or_insert(error.0);
        }
        Ok(()) // An invalid route must not hide later, well-framed routes.
    });
    if let Err(error) = result {
        routes.reason.get_or_insert(error.0);
    }
    routes
}

fn route(payload: &[u8], routes: &mut Routes) -> Result<(), CollectError> {
    if payload.len() < 12 {
        return Err(CollectError("short rtmsg".into()));
    }
    if payload[1] != 0 || payload[7] != 1 {
        // zero rtm_dst_len, RTN_UNICAST only
        return Ok(());
    }
    let address_len = match payload[0] {
        2 => 4,   // AF_INET
        10 => 16, // AF_INET6
        family => return Err(CollectError(format!("unsupported route family {family}"))),
    };
    if u32_ne(&payload[8..]) & (1 | 16) != 0 {
        // RTNH_F_DEAD | RTNH_F_LINKDOWN
        return Ok(());
    }

    let mut local = Routes::default();
    let mut zero_destination = true;
    let mut forwarding = false;
    let mut table = u32::from(payload[4]);
    for attribute in attributes(&payload[12..]) {
        let result = attribute.and_then(|(kind, value)| {
            match kind {
                1 => {
                    // RTA_DST: addresses are bytes in NETWORK order, not native integers.
                    if value.len() != address_len {
                        return Err(CollectError("invalid route destination length".into()));
                    }
                    zero_destination = value.iter().all(|byte| *byte == 0);
                }
                4 => {
                    // RTA_OIF; no RTA_GATEWAY requirement (on-link / point-to-point).
                    let index = word(value, "RTA_OIF")?;
                    if index == 0 || index > i32::MAX as u32 {
                        return Err(CollectError("invalid route output index".into()));
                    }
                    local.indices.insert(index);
                    forwarding = true;
                }
                9 => {
                    // RTA_MULTIPATH, flat aligned rtnexthop records
                    forwarding = true;
                    inline_members(value, &mut local.indices)?;
                }
                15 => table = word(value, "RTA_TABLE")?,
                30 => {
                    // RTA_NH_ID, absent from some libc versions
                    let id = word(value, "RTA_NH_ID")?;
                    if id == 0 {
                        return Err(CollectError("zero route nexthop ID".into()));
                    }
                    local.ids.insert(id);
                    forwarding = true;
                }
                _ => {} // Unknown optional metadata does not imply missing members.
            }
            Ok(())
        });
        if let Err(error) = result {
            local.reason.get_or_insert(error.0);
        }
    }
    // The header table and its u32 override are intentionally NEVER filters.
    // Source prefixes/TOS likewise do not make a configured default a nondefault.
    let _ = table;
    if zero_destination {
        if !forwarding {
            local
                .reason
                .get_or_insert("default route has no supported output interface".into());
        }
        routes.indices.extend(local.indices);
        routes.ids.extend(local.ids);
        if let Some(reason) = local.reason {
            routes.reason.get_or_insert(reason);
        }
    }
    Ok(())
}

fn inline_members(mut bytes: &[u8], indices: &mut BTreeSet<u32>) -> Result<(), CollectError> {
    if bytes.is_empty() {
        return Err(CollectError("empty route multipath array".into()));
    }
    while !bytes.is_empty() {
        if bytes.len() < 8 {
            return Err(CollectError("short rtnexthop".into()));
        }
        let len = usize::from(u16_ne(bytes));
        let (record, rest) = aligned_record(bytes, len, 8)?;
        // Validate the nested rtattrs even though gateways/weights are not needed.
        for attribute in attributes(&record[8..len]) {
            attribute?;
        }
        if record[2] & (1 | 16) == 0 {
            let index = u32_ne(&record[4..]); // signed UAPI int, positive indices only
            if index == 0 || index > i32::MAX as u32 {
                return Err(CollectError("invalid inline nexthop index".into()));
            }
            indices.insert(index);
        }
        bytes = rest;
    }
    Ok(())
}

// Task-local rtattr iterator shared with the nexthop decoder. Framing and
// alignment remain delegated to Task2's checked helper; no casts/FFI here.
pub(super) fn attributes(
    mut bytes: &[u8],
) -> impl Iterator<Item = Result<(u16, &[u8]), CollectError>> {
    std::iter::from_fn(move || {
        if bytes.is_empty() {
            return None;
        }
        let result = (|| {
            if bytes.len() < 4 {
                return Err(CollectError("short route attribute".into()));
            }
            let len = usize::from(u16_ne(bytes));
            let (record, rest) = aligned_record(bytes, len, 4)?;
            bytes = rest;
            Ok((u16_ne(&record[2..]) & 0x3fff, &record[4..len]))
        })();
        if result.is_err() {
            bytes = &[]; // No valid boundary remains; never loop without progress.
        }
        Some(result)
    })
}

pub(super) fn word(bytes: &[u8], field: &str) -> Result<u32, CollectError> {
    if bytes.len() != 4 {
        return Err(CollectError(format!("invalid {field} length")));
    }
    Ok(u32_ne(bytes))
}

pub(super) fn covered<T>(value: T, reason: Option<String>) -> Coverage<T> {
    match reason {
        Some(reason) => Coverage::Incomplete { value, reason },
        None => Coverage::Complete(value),
    }
}
