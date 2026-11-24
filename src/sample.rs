use crate::model::{Interface, InterfaceId, Rates, Snapshot};
use std::collections::BTreeMap;

/// Best-effort snapshot deltas, not proof of device-lifetime continuity.
pub fn rates(before: &Interface, after: &Interface) -> Rates {
    let unavailable = Rates { rx: None, tx: None };
    if before.id != after.id {
        return unavailable;
    }
    let (Some(before), Some(after)) = (&before.counters, &after.counters) else {
        return unavailable;
    };
    let Some(elapsed) = after.at.checked_duration_since(before.at) else {
        return unavailable;
    };
    if elapsed.is_zero() {
        return unavailable;
    }

    let direction = |before: Option<u64>, after: Option<u64>| {
        let delta = after?.checked_sub(before?)?;
        let bps = delta as f64 * 8.0 / elapsed.as_secs_f64();
        bps.is_finite().then_some(bps)
    };
    Rates {
        rx: direction(before.rx_bytes, after.rx_bytes),
        tx: direction(before.tx_bytes, after.tx_bytes),
    }
}

/// Retain only the later inventory, matching earlier samples by full identity.
pub fn combine(before: &Snapshot, after: &Snapshot) -> BTreeMap<InterfaceId, Rates> {
    let before: BTreeMap<_, _> = before
        .interfaces
        .iter()
        .map(|interface| (&interface.id, interface))
        .collect();
    after
        .interfaces
        .iter()
        .map(|interface| {
            let sampled_rates = before
                .get(&interface.id)
                .map_or(Rates { rx: None, tx: None }, |before| {
                    rates(before, interface)
                });
            (interface.id.clone(), sampled_rates)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{combine, rates};
    use crate::model::{Counters, Interface, InterfaceId, Rates, Snapshot, State};
    use std::{
        collections::BTreeMap,
        time::{Duration, Instant},
    };

    fn samples() -> (Interface, Interface) {
        let at = Instant::now();
        let before = Interface {
            id: InterfaceId {
                index: 7,
                name: b"eth0".to_vec(),
            },
            state: State::Up,
            addresses: vec![],
            link_address: None,
            mtu: Some(1500),
            speed_bps: None,
            counters: Some(Counters {
                at,
                rx_bytes: Some(100),
                tx_bytes: Some(500),
            }),
        };
        let mut after = before.clone();
        after.counters = Some(Counters {
            at: at + Duration::from_secs(2),
            rx_bytes: Some(250100),
            tx_bytes: Some(1000),
        });
        (before, after)
    }

    #[test]
    fn sample_rates_use_bits_and_actual_elapsed() {
        let (before, after) = samples();
        // Same identity and nondecreasing counters permit only a best-effort delta,
        // not a claim of proven device-lifetime continuity.
        assert_eq!(
            rates(&before, &after),
            Rates {
                rx: Some(1_000_000.0),
                tx: Some(2_000.0),
            }
        );
    }

    #[test]
    fn sample_rates_use_fractional_elapsed_seconds() {
        let (before, mut after) = samples();
        after.counters.as_mut().unwrap().at =
            before.counters.as_ref().unwrap().at + Duration::from_millis(500);
        assert_eq!(
            rates(&before, &after),
            Rates {
                rx: Some(4_000_000.0),
                tx: Some(8_000.0),
            }
        );
    }

    #[test]
    fn sample_rates_require_full_index_and_raw_name_identity() {
        let (before, mut after) = samples();
        after.id.index = 8;
        assert_eq!(rates(&before, &after), Rates { rx: None, tx: None });

        let (mut before, mut after) = samples();
        before.id.name = b"eth\xff".to_vec();
        after.id.name = b"eth\xfe".to_vec();
        assert_eq!(rates(&before, &after), Rates { rx: None, tx: None });

        // A valid sample must still work; identity rejection cannot be unconditional.
        after.id.name = b"eth\xff".to_vec();
        assert_eq!(
            rates(&before, &after),
            Rates {
                rx: Some(1_000_000.0),
                tx: Some(2_000.0),
            }
        );
    }

    #[test]
    fn sample_missing_samples_make_both_directions_unavailable() {
        for (omit_before, omit_after) in [(true, false), (false, true), (true, true)] {
            let (mut before, mut after) = samples();
            if omit_before {
                before.counters = None;
            }
            if omit_after {
                after.counters = None;
            }
            assert_eq!(rates(&before, &after), Rates { rx: None, tx: None });
        }
    }

    #[test]
    fn sample_missing_direction_preserves_the_other_direction() {
        for (omit_before, omit_rx, expected) in [
            (
                true,
                true,
                Rates {
                    rx: None,
                    tx: Some(2_000.0),
                },
            ),
            (
                false,
                true,
                Rates {
                    rx: None,
                    tx: Some(2_000.0),
                },
            ),
            (
                true,
                false,
                Rates {
                    rx: Some(1_000_000.0),
                    tx: None,
                },
            ),
            (
                false,
                false,
                Rates {
                    rx: Some(1_000_000.0),
                    tx: None,
                },
            ),
        ] {
            let (mut before, mut after) = samples();
            let counters = if omit_before {
                before.counters.as_mut().unwrap()
            } else {
                after.counters.as_mut().unwrap()
            };
            if omit_rx {
                counters.rx_bytes = None;
            } else {
                counters.tx_bytes = None;
            }
            assert_eq!(rates(&before, &after), expected);
        }
    }

    #[test]
    fn sample_nonpositive_elapsed_time_makes_both_directions_unavailable() {
        for earlier in [false, true] {
            let (mut before, mut after) = samples();
            let before_at = &mut before.counters.as_mut().unwrap().at;
            let after_at = &mut after.counters.as_mut().unwrap().at;
            if earlier {
                std::mem::swap(before_at, after_at);
            } else {
                *after_at = *before_at;
            }
            assert_eq!(rates(&before, &after), Rates { rx: None, tx: None });
        }
    }

    #[test]
    fn sample_decreasing_counter_invalidates_only_its_direction() {
        for (rx_bytes, tx_bytes, expected) in [
            (
                99,
                1000,
                Rates {
                    rx: None,
                    tx: Some(2_000.0),
                },
            ),
            (
                250100,
                499,
                Rates {
                    rx: Some(1_000_000.0),
                    tx: None,
                },
            ),
        ] {
            let (before, mut after) = samples();
            let counters = after.counters.as_mut().unwrap();
            counters.rx_bytes = Some(rx_bytes);
            counters.tx_bytes = Some(tx_bytes);
            assert_eq!(rates(&before, &after), expected);
        }
    }

    #[test]
    fn sample_unchanged_counters_are_valid_zero_rates() {
        let (before, mut after) = samples();
        let counters = after.counters.as_mut().unwrap();
        counters.rx_bytes = Some(100);
        counters.tx_bytes = Some(500);
        assert_eq!(
            rates(&before, &after),
            Rates {
                rx: Some(0.0),
                tx: Some(0.0),
            }
        );
    }

    #[test]
    fn sample_u64_max_does_not_overflow_or_lose_small_deltas_before_conversion() {
        let (mut before, mut after) = samples();
        let before_counters = before.counters.as_mut().unwrap();
        before_counters.rx_bytes = Some(0);
        before_counters.tx_bytes = Some(u64::MAX - 100);
        let after_counters = after.counters.as_mut().unwrap();
        after_counters.at = before_counters.at + Duration::from_secs(1);
        after_counters.rx_bytes = Some(u64::MAX);
        after_counters.tx_bytes = Some(u64::MAX);
        assert_eq!(
            rates(&before, &after),
            Rates {
                rx: Some(1.475_739_525_896_764_1e20),
                tx: Some(800.0),
            }
        );
    }

    #[test]
    fn sample_combine_keeps_only_after_inventory_including_new_devices() {
        let (before, after) = samples();
        let mut removed = before.clone();
        removed.id = InterfaceId {
            index: 3,
            name: b"removed".to_vec(),
        };
        let mut added = after.clone();
        added.id = InterfaceId {
            index: 9,
            name: b"added".to_vec(),
        };
        assert_eq!(
            combine(
                &Snapshot {
                    interfaces: vec![removed, before],
                },
                &Snapshot {
                    interfaces: vec![added, after],
                },
            ),
            BTreeMap::from([
                (
                    InterfaceId {
                        index: 7,
                        name: b"eth0".to_vec(),
                    },
                    Rates {
                        rx: Some(1_000_000.0),
                        tx: Some(2_000.0),
                    },
                ),
                (
                    InterfaceId {
                        index: 9,
                        name: b"added".to_vec(),
                    },
                    Rates { rx: None, tx: None },
                ),
            ])
        );
    }

    #[test]
    fn sample_combine_does_not_match_reused_index_or_reused_name() {
        let (before, after) = samples();
        let mut reused_index = after.clone();
        reused_index.id.name = b"eth1".to_vec();
        let mut reused_name = after;
        reused_name.id.index = 8;
        assert_eq!(
            combine(
                &Snapshot {
                    interfaces: vec![before],
                },
                &Snapshot {
                    interfaces: vec![reused_name, reused_index],
                },
            ),
            BTreeMap::from([
                (
                    InterfaceId {
                        index: 7,
                        name: b"eth1".to_vec(),
                    },
                    Rates { rx: None, tx: None },
                ),
                (
                    InterfaceId {
                        index: 8,
                        name: b"eth0".to_vec(),
                    },
                    Rates { rx: None, tx: None },
                ),
            ])
        );
    }

    #[test]
    fn sample_combine_retains_devices_without_any_before_inventory() {
        let (_, after) = samples();
        assert_eq!(
            combine(
                &Snapshot { interfaces: vec![] },
                &Snapshot {
                    interfaces: vec![after],
                },
            ),
            BTreeMap::from([(
                InterfaceId {
                    index: 7,
                    name: b"eth0".to_vec(),
                },
                Rates { rx: None, tx: None },
            )])
        );
    }
}
