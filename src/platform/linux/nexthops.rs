//! Linux v6.12 include/uapi/linux/{nexthop.h,rtnetlink.h}:
//! RTM_NEWNEXTHOP=104, nhmsg=8 bytes; NHA_GROUP is a flat array of
//! eight-byte nexthop_grp entries, not nested attributes. Weights do not
//! change configured membership, including resilient groups (type 1).
use super::netlink::{for_messages, u16_ne, u32_ne};
use super::routes::{attributes, covered, word};
use crate::model::{CollectError, Coverage};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Hop {
    Device { index: u32, usable: bool },
    Group(Vec<u32>),
    Unsupported,
}

pub fn members(id: u32, hops: &BTreeMap<u32, Hop>) -> Coverage<BTreeSet<u32>> {
    let mut resolver = Resolver {
        hops,
        visited: BTreeSet::new(),
        active: BTreeSet::new(),
        indices: BTreeSet::new(),
        reason: None,
    };
    resolver.visit(id, 0);
    covered(resolver.indices, resolver.reason)
}

struct Resolver<'a> {
    hops: &'a BTreeMap<u32, Hop>,
    visited: BTreeSet<u32>,
    active: BTreeSet<u32>,
    indices: BTreeSet<u32>,
    reason: Option<String>,
}

impl Resolver<'_> {
    fn visit(&mut self, id: u32, depth: usize) {
        if self.active.contains(&id) {
            self.reason
                .get_or_insert_with(|| format!("nexthop cycle at ID {id}"));
            return;
        }
        if self.visited.contains(&id) {
            return; // Already collected; a shared subgroup is not a cycle.
        }
        if depth >= 16 {
            self.reason
                .get_or_insert("nexthop depth limit (16) reached".into());
            return;
        }
        if self.visited.len() >= 4096 {
            self.reason
                .get_or_insert("nexthop visited-ID limit (4096) reached".into());
            return;
        }
        self.visited.insert(id);
        self.active.insert(id);
        let hops = self.hops;
        match hops.get(&id) {
            Some(Hop::Device {
                index,
                usable: true,
            }) if *index > 0 && *index <= i32::MAX as u32 => {
                self.indices.insert(*index);
            }
            Some(Hop::Device { usable: false, .. }) => {} // Dead/linkdown/blackhole is known.
            Some(Hop::Group(ids)) => {
                for child in ids {
                    self.visit(*child, depth + 1);
                }
            }
            None => {
                self.reason
                    .get_or_insert_with(|| format!("missing nexthop ID {id}"));
            }
            _ => {
                self.reason
                    .get_or_insert_with(|| format!("unsupported nexthop ID {id}"));
            }
        }
        self.active.remove(&id);
    }
}

pub(super) fn decode(bytes: &[u8]) -> Coverage<BTreeMap<u32, Hop>> {
    let mut hops = BTreeMap::new();
    let mut reason = None;
    let result = for_messages(bytes, |message| {
        let result = if message.kind == 104 {
            // RTM_NEWNEXTHOP
            object(message.payload)
        } else {
            Err(CollectError(format!(
                "unexpected nexthop message {}",
                message.kind
            )))
        };
        match result {
            Ok((id, hop, warning)) => {
                if hops.insert(id, hop).is_some() {
                    hops.insert(id, Hop::Unsupported);
                    reason.get_or_insert_with(|| format!("duplicate nexthop ID {id}"));
                }
                if let Some(warning) = warning {
                    reason.get_or_insert(warning);
                }
            }
            Err(error) => {
                reason.get_or_insert(error.0);
            }
        }
        Ok(())
    });
    if let Err(error) = result {
        reason.get_or_insert(error.0);
    }
    covered(hops, reason)
}

fn object(payload: &[u8]) -> Result<(u32, Hop, Option<String>), CollectError> {
    if payload.len() < 8 {
        return Err(CollectError("short nhmsg".into()));
    }
    let mut id = None;
    let mut group = None;
    let mut group_type = 0;
    let mut oif = None;
    let mut blackhole = false;
    let mut fdb = false;
    for attribute in attributes(&payload[8..]) {
        let (kind, value) = attribute?;
        match kind {
            1 => id = Some(word(value, "NHA_ID")?),
            2 => group = Some(value),
            3 => {
                if value.len() != 2 {
                    return Err(CollectError("invalid NHA_GROUP_TYPE length".into()));
                }
                group_type = u16_ne(value);
            }
            4 => {
                if !value.is_empty() {
                    return Err(CollectError("invalid NHA_BLACKHOLE flag".into()));
                }
                blackhole = true;
            }
            5 => oif = Some(word(value, "NHA_OIF")?),
            11 => fdb = true, // NHA_FDB is not an IP-forwarding object.
            _ => {}           // Gateways/encapsulation/stats do not add output devices.
        }
    }
    let id = id
        .filter(|id| *id != 0)
        .ok_or_else(|| CollectError("missing/zero NHA_ID".into()))?;
    if !matches!(payload[0], 0 | 2 | 10) || fdb || (group.is_some() && group_type > 1) {
        return Ok((id, Hop::Unsupported, None));
    }
    if blackhole || u32_ne(&payload[4..]) & (1 | 16) != 0 {
        // Hop's existing contract has no Blackhole variant; known unusable
        // devices resolve to an empty complete set without inventing an index.
        return Ok((
            id,
            Hop::Device {
                index: oif.unwrap_or(0),
                usable: false,
            },
            None,
        ));
    }
    if let Some(group) = group {
        if group.is_empty() {
            return Err(CollectError(format!("empty nexthop group {id}")));
        }
        let (entries, remainder) = group.as_chunks::<8>();
        let ids = entries.iter().map(|entry| u32_ne(entry)).collect();
        let reason = (!remainder.is_empty()).then(|| format!("malformed nexthop group {id} array"));
        return Ok((id, Hop::Group(ids), reason));
    }
    let hop = match oif {
        Some(index) if index > 0 && index <= i32::MAX as u32 => Hop::Device {
            index,
            usable: true,
        },
        _ => Hop::Unsupported,
    };
    Ok((id, hop, None))
}
