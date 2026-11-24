use std::{
    cell::Cell,
    mem::{align_of, offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    rc::Rc,
    time::Instant,
};

use crate::model::{Address, InterfaceId, State};

use super::{inventory, media, wire};

fn ifmib() -> Vec<u8> {
    let mut bytes = vec![0; 180];
    bytes[..4].copy_from_slice(b"en0\0");
    bytes[60..64].copy_from_slice(&1500_u32.to_ne_bytes());
    bytes[116..124].copy_from_slice(&4_294_967_396_u64.to_ne_bytes());
    bytes[124..132].copy_from_slice(&8_589_934_792_u64.to_ne_bytes());
    bytes
}

fn link(name: &[u8], index: u16, address: &[u8]) -> Vec<u8> {
    let len = 8 + name.len() + address.len();
    let mut bytes = vec![
        len as u8,
        18,
        0,
        0,
        6,
        name.len() as u8,
        address.len() as u8,
        0,
    ];
    bytes[2..4].copy_from_slice(&index.to_ne_bytes());
    bytes.extend_from_slice(name);
    bytes.extend_from_slice(address);
    bytes
}

fn v4(ip: [u8; 4]) -> Vec<u8> {
    let mut bytes = vec![0; 16];
    bytes[0] = 16;
    bytes[1] = 2;
    bytes[4..8].copy_from_slice(&ip);
    bytes
}

fn v6(ip: [u8; 16], scope: u32) -> Vec<u8> {
    let mut bytes = vec![0; 28];
    bytes[0] = 28;
    bytes[1] = 30;
    bytes[8..24].copy_from_slice(&ip);
    bytes[24..28].copy_from_slice(&scope.to_ne_bytes());
    bytes
}

fn entry(name: &[u8], index: u32, flags: u32, address: Option<Vec<u8>>) -> inventory::Entry {
    inventory::Entry {
        name: name.to_vec(),
        index,
        flags,
        address,
        netmask: None,
    }
}

#[test]
fn darwin_inventory_ifmib_reads_packed_native_u64_above_four_gib() {
    let bytes = ifmib();
    assert_eq!(
        wire::ifmib_counters(&bytes, b"en0"),
        Some((4_294_967_396, 8_589_934_792))
    );
    // The slice's base and both u64 fields may be unaligned.
    let mut unaligned = vec![0];
    unaligned.extend_from_slice(&bytes);
    assert_eq!(
        wire::ifmib_counters(&unaligned[1..], b"en0"),
        Some((4_294_967_396, 8_589_934_792))
    );
    assert_eq!(wire::ifmib_mtu(&bytes, b"en0"), Some(1500));
}

#[test]
fn darwin_inventory_zero_filled_ifmib_is_not_a_valid_zero_sample() {
    assert_eq!(wire::ifmib_counters(&[0_u8; 180], b"en0"), None);
    let mut bytes = vec![0; 180];
    bytes[..4].copy_from_slice(b"en0\0");
    assert_eq!(wire::ifmib_counters(&bytes, b"en0"), Some((0, 0)));
    assert_eq!(wire::ifmib_mtu(&bytes, b"en0"), None);
}

#[test]
fn darwin_inventory_ifmib_rejects_wrong_unterminated_and_truncated_identity() {
    let bytes = ifmib();
    assert_eq!(wire::ifmib_counters(&bytes, b"en1"), None);
    for len in [0, 15, 52, 116, 123, 124, 131, 132, 179] {
        assert_eq!(
            wire::ifmib_counters(&bytes[..len], b"en0"),
            None,
            "len={len}"
        );
        assert_eq!(wire::ifmib_mtu(&bytes[..len], b"en0"), None, "len={len}");
    }
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(wire::ifmib_counters(&long, b"en0"), None);
    let mut unterminated = bytes;
    unterminated[..16].fill(b'e');
    assert_eq!(
        wire::ifmib_counters(&unterminated, b"eeeeeeeeeeeeeeee"),
        None
    );
    assert_eq!(wire::name(b""), None);
    assert_eq!(wire::name(b"\0"), None);
    assert_eq!(wire::name(b"en0"), None);
    assert_eq!(wire::name(b"e\xff\0tail"), Some(b"e\xff".as_slice()));
}

#[test]
fn darwin_inventory_masks_require_full_contiguous_v4_or_v6_width() {
    for (mask, want) in [
        (vec![0, 0, 0, 0], Some(0)),
        (vec![255, 255, 255, 255], Some(32)),
        (vec![255, 255, 254, 0], Some(23)),
        (vec![255, 0, 255, 0], None),
        (vec![255, 255, 127, 0], None),
        (vec![255; 3], None),
        (vec![255; 5], None),
        (vec![255; 15], None),
        (vec![255; 17], None),
        (vec![], None),
        (vec![255; 16], Some(128)),
        (vec![0; 16], Some(0)),
        (
            vec![
                255, 255, 255, 255, 255, 255, 255, 255, 128, 0, 0, 0, 0, 0, 0, 0,
            ],
            Some(65),
        ),
    ] {
        assert_eq!(wire::prefix(&mask), want, "{mask:?}");
    }
}

#[test]
fn darwin_inventory_link_extent_can_exceed_twelve_bytes_without_lossy_names() {
    let bytes = link(b"bridge\xff1234", 7, &[1, 2, 3, 4, 5, 6, 7, 8]);
    let parsed = wire::link(&bytes, b"bridge\xff1234").unwrap();
    assert_eq!(parsed.index, 7);
    assert_eq!(parsed.address, Some(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    assert!(wire::link(&bytes, b"bridge\xfe1234").is_err());
    for len in 0..bytes.len() {
        assert!(
            wire::link(&bytes[..len], b"bridge\xff1234").is_err(),
            "len={len}"
        );
    }
    let mut bad = bytes.clone();
    bad[7] = 5; // selector also has to fit the actual sdl_len.
    assert!(wire::link(&bad, b"bridge\xff1234").is_err());
    let mut bad = bytes;
    bad[0] = 8;
    assert!(wire::link(&bad, b"bridge\xff1234").is_err());
    assert_eq!(
        wire::link(&link(b"lo0", 1, &[]), b"lo0").unwrap().address,
        None
    );
}

#[test]
fn darwin_inventory_bad_masks_preserve_the_assigned_address() {
    let ip = v4([192, 0, 2, 9]);
    let want = Address {
        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
        prefix: None,
        scope_id: None,
    };
    for mask in [
        None,
        Some(vec![]),
        Some(v4([255, 0, 255, 0])),
        Some(v6([255; 16], 0)),
    ] {
        assert_eq!(
            wire::address(&ip, mask.as_deref(), 7).unwrap(),
            Some(want.clone())
        );
    }
    let mut short = v4([255, 255, 255, 0]);
    short[0] = 7;
    assert_eq!(
        wire::address(&ip, Some(&short), 7).unwrap(),
        Some(want.clone())
    );
    let mut long = v4([255, 255, 255, 0]);
    long.push(0);
    long[0] = 17;
    assert_eq!(wire::address(&ip, Some(&long), 7).unwrap(), Some(want));
    let mut valid = v4([255, 255, 255, 0]);
    valid[1] = 0; // Darwin netmasks can have AF_UNSPEC.
    assert_eq!(
        wire::address(&ip, Some(&valid), 7).unwrap().unwrap().prefix,
        Some(24)
    );
}

#[test]
fn darwin_inventory_ipv6_scopes_are_owned_and_only_local_scope_is_deembedded() {
    let local = [0xfe, 0x80, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    let mask = v6(
        [
            255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        0,
    );
    assert_eq!(
        wire::address(&v6(local, 0), Some(&mask), 7).unwrap(),
        Some(Address {
            ip: "fe80::9".parse().unwrap(),
            prefix: Some(64),
            scope_id: Some(7),
        })
    );
    let explicit = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    assert_eq!(
        wire::address(&v6(explicit, 7), None, 7)
            .unwrap()
            .unwrap()
            .scope_id,
        Some(7)
    );
    assert_eq!(
        wire::address(&v6(explicit, 0), None, 7)
            .unwrap()
            .unwrap()
            .scope_id,
        Some(7)
    );
    assert!(wire::address(&v6(local, 8), None, 7).is_err());
    let global = [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
    assert_eq!(
        wire::address(&v6(global, 0), None, 7).unwrap(),
        Some(Address {
            ip: "2001:db8::9".parse().unwrap(),
            prefix: None,
            scope_id: None,
        })
    );
    assert_eq!(
        wire::address(&v6(Ipv6Addr::LOCALHOST.octets(), 0), None, 1)
            .unwrap()
            .unwrap()
            .scope_id,
        None
    );
    let multicast = [0xff, 2, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert_eq!(
        wire::address(&v6(multicast, 0), None, 7).unwrap(),
        Some(Address {
            ip: "ff02::1".parse().unwrap(),
            prefix: None,
            scope_id: Some(7),
        })
    );
}

#[test]
fn darwin_inventory_unicast_based_linklocal_multicast_does_not_embed_scope() {
    // IN6_IS_ADDR_MC_LINKLOCAL excludes flags 0x30. These bytes are group
    // data, not a KAME interface index, even though the address needs a zone.
    let group = [0xff, 0x32, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    for explicit in [0, 7] {
        assert_eq!(
            wire::address(&v6(group, explicit), None, 7).unwrap(),
            Some(Address {
                ip: "ff32:1234::1".parse().unwrap(),
                prefix: None,
                scope_id: Some(7),
            })
        );
    }
}

#[test]
fn darwin_inventory_malformed_assigned_sockaddrs_are_explicit_errors() {
    for bytes in [vec![], vec![16], vec![16, 2], vec![28, 30], vec![1, 2]] {
        assert!(wire::address(&bytes, None, 7).is_err(), "{bytes:?}");
    }
    let mut bytes = v4([192, 0, 2, 9]);
    bytes[0] = 8;
    assert!(wire::address(&bytes, None, 7).is_err());
    assert_eq!(wire::address(&[2, 99], None, 7).unwrap(), None);
}

#[test]
fn darwin_inventory_assembly_keeps_no_ip_multiple_addresses_and_raw_identity() {
    let mut a = entry(b"en0", 7, 0x41, Some(v4([192, 0, 2, 9])));
    a.netmask = Some(v4([255, 255, 255, 0]));
    let entries = vec![
        a,
        entry(b"bridge\xff0", 9, 0, Some(link(b"bridge\xff0", 9, &[]))),
        entry(b"en0", 7, 0x41, Some(link(b"en0", 7, &[0, 1, 2, 3, 4, 5]))),
        entry(b"en0", 7, 0x41, Some(v4([192, 0, 2, 10]))),
        entry(b"en0", 7, 0x41, Some(v6(Ipv6Addr::LOCALHOST.octets(), 0))),
        entry(b"en0", 7, 0x41, Some(v4([192, 0, 2, 10]))),
        entry(b"utun0", 10, 1, None),
    ];
    let snapshot = inventory::assemble(&entries).unwrap();
    assert_eq!(snapshot.interfaces.len(), 3);
    let en = &snapshot.interfaces[0];
    assert_eq!(
        en.id,
        InterfaceId {
            index: 7,
            name: b"en0".to_vec()
        }
    );
    assert_eq!(en.state, State::Unknown); // IFF_RUNNING is not carrier.
    assert_eq!(
        en.addresses,
        vec![
            Address {
                ip: "192.0.2.9".parse().unwrap(),
                prefix: Some(24),
                scope_id: None
            },
            Address {
                ip: "192.0.2.10".parse().unwrap(),
                prefix: None,
                scope_id: None
            },
            Address {
                ip: "::1".parse().unwrap(),
                prefix: None,
                scope_id: None
            },
        ]
    );
    assert_eq!(en.link_address, Some(vec![0, 1, 2, 3, 4, 5]));
    assert_eq!(en.mtu, None);
    assert_eq!(en.speed_bps, None);
    assert!(en.counters.is_none());
    assert_eq!(snapshot.interfaces[1].id.name, b"bridge\xff0");
    assert_eq!(snapshot.interfaces[1].state, State::Down);
    assert!(snapshot.interfaces[1].addresses.is_empty());
    assert_eq!(snapshot.interfaces[2].state, State::Unknown);
    assert!(snapshot.interfaces[2].addresses.is_empty());
}

#[test]
fn darwin_inventory_assembly_rejects_missing_or_conflicting_mandatory_identity() {
    for entries in [
        vec![entry(b"", 7, 1, None)],
        vec![entry(b"en\0x", 7, 1, None)],
        vec![entry(b"0123456789abcdef", 7, 1, None)],
        vec![entry(b"en0", 0, 1, None)],
        vec![entry(b"en0", 7, 1, None), entry(b"en1", 7, 1, None)],
        vec![entry(b"en0", 7, 1, None), entry(b"en0", 8, 1, None)],
        vec![entry(b"en0", 7, 1, Some(link(b"en0", 8, &[])))],
        vec![entry(b"en0", 7, 1, Some(vec![16, 2]))],
    ] {
        assert!(inventory::assemble(&entries).is_err());
    }
}

#[test]
fn darwin_inventory_observations_validate_identity_and_clear_stale_optional_data() {
    let mut interface = inventory::assemble(&[entry(b"en0", 7, 1, None)])
        .unwrap()
        .interfaces
        .remove(0);
    let id = interface.id.clone();
    let at = Instant::now();
    inventory::enrich(
        &mut interface,
        true,
        inventory::Observation {
            before: Some(id.clone()),
            after: Some(id.clone()),
            ifmib: Some(ifmib()),
            at,
            media: Some((3, 0x30)),
        },
    );
    assert_eq!(interface.state, State::Up);
    assert_eq!(interface.speed_bps, Some(1_000_000_000));
    assert_eq!(interface.mtu, Some(1500));
    let counters = interface.counters.as_ref().unwrap();
    assert_eq!(
        (counters.rx_bytes, counters.tx_bytes),
        (Some(4_294_967_396), Some(8_589_934_792))
    );
    assert_eq!(counters.at, at);
    inventory::enrich(
        &mut interface,
        true,
        inventory::Observation {
            before: Some(id.clone()),
            after: Some(id.clone()),
            ifmib: None,
            at,
            media: None,
        },
    );
    assert_eq!(interface.state, State::Unknown);
    assert_eq!(interface.mtu, None);
    assert_eq!(interface.speed_bps, None);
    assert!(interface.counters.is_none());
    for (before, after) in [
        (None, Some(id.clone())),
        (Some(id.clone()), None),
        (
            Some(id.clone()),
            Some(InterfaceId {
                index: 7,
                name: b"en1".to_vec(),
            }),
        ),
        (
            Some(InterfaceId {
                index: 8,
                name: b"en0".to_vec(),
            }),
            Some(id.clone()),
        ),
    ] {
        inventory::enrich(
            &mut interface,
            true,
            inventory::Observation {
                before,
                after,
                ifmib: Some(ifmib()),
                at,
                media: Some((3, 0x30)),
            },
        );
        assert_eq!(interface.state, State::Unknown);
        assert!(interface.counters.is_none());
        assert_eq!(interface.mtu, None);
        assert_eq!(interface.speed_bps, None);
    }
    inventory::enrich(
        &mut interface,
        false,
        inventory::Observation {
            before: Some(id.clone()),
            after: Some(id),
            ifmib: Some(vec![0; 180]),
            at,
            media: Some((3, 0x30)),
        },
    );
    assert_eq!(interface.state, State::Down);
    assert_eq!(interface.speed_bps, None);
    assert!(interface.counters.is_none());
}

struct FixtureList {
    entries: Vec<inventory::Entry>,
    releases: Rc<Cell<u32>>,
}

unsafe extern "C" fn release_fixture(ptr: *mut FixtureList) {
    // SAFETY: each test passes the uniquely owned Box::into_raw allocation.
    let list = unsafe { Box::from_raw(ptr) };
    list.releases.set(list.releases.get() + 1);
}

#[test]
fn darwin_inventory_list_ownership_frees_once_on_success_and_decode_error() {
    for valid in [true, false] {
        let releases = Rc::new(Cell::new(0));
        let raw = Box::into_raw(Box::new(FixtureList {
            entries: vec![entry(
                if valid { b"en0" } else { b"" },
                7,
                1,
                Some(v4([192, 0, 2, 9])),
            )],
            releases: releases.clone(),
        }));
        let result = {
            // SAFETY: transfer the allocation to one owner; borrow only until drop.
            let owner = unsafe { inventory::IfAddrsOwner::new(raw, release_fixture) };
            inventory::assemble(unsafe { &(*owner.head).entries })
        };
        assert_eq!(releases.get(), 1);
        if valid {
            let snapshot = result.unwrap();
            assert_eq!(snapshot.interfaces[0].id.name, b"en0");
            assert_eq!(
                snapshot.interfaces[0].addresses[0].ip,
                "192.0.2.9".parse::<IpAddr>().unwrap()
            );
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn darwin_media_state_requires_valid_status_not_running_or_selected_media() {
    for (admin, status, want) in [
        (false, None, State::Down),
        (false, Some(3), State::Down),
        (true, Some(3), State::Up),
        (true, Some(7), State::Up),
        (true, Some(1), State::Down),
        (true, Some(5), State::Down),
        (true, None, State::Unknown),
        (true, Some(0), State::Unknown),
        (true, Some(2), State::Unknown),
    ] {
        assert_eq!(media::state(admin, status), want, "{admin} {status:?}");
    }
}

#[test]
fn darwin_media_speed_uses_only_recognized_active_ethernet_subtypes() {
    // Literal media words from xnu-12377.1.9/bsd/net/if_media.h; do not
    // construct expectations with the encoder/decoder under test.
    for (words, want) in [
        (&[0x23, 0x24, 0x25, 0x2c, 0x2d][..], 10_000_000),
        (&[0x26, 0x27, 0x28, 0x29, 0x2a][..], 100_000_000),
        (&[0x2b, 0x2e, 0x2f, 0x30, 0x38, 0x39][..], 1_000_000_000),
        (&[0x36, 0x10020, 0x10024, 0x1003f][..], 2_500_000_000),
        (&[0x37, 0x20020, 0x20025, 0x20026][..], 5_000_000_000),
        (
            &[
                0x32, 0x33, 0x34, 0x35, 0x3a, 0x3b, 0x3c, 0x3d, 0x10021, 0x10022, 0x10023, 0x1002a,
                0x1003b,
            ][..],
            10_000_000_000,
        ),
        (&[0x3e][..], 20_000_000_000),
    ] {
        for word in words {
            assert_eq!(media::speed(*word, 3), Some(want), "word={word:#x}");
            assert_eq!(media::speed(*word | 0xa0100100, 7), Some(want));
        }
    }
    for active in [0, 0x20, 0x21, 0x22, 0x3f, 0x83, 0x43, 0x10026, 0xf003f] {
        assert_eq!(media::speed(active, 3), None, "active={active:#x}");
    }
    for status in [0, 1, 2, 4, 5, 6] {
        assert_eq!(media::speed(0x30, status), None, "status={status}");
    }
}

#[test]
fn darwin_media_request_layout_matches_the_64_bit_packed_ioctl_abi() {
    assert_eq!(size_of::<media::IfMediaReq>(), 44);
    assert_eq!(align_of::<media::IfMediaReq>(), 4);
    assert_eq!(offset_of!(media::IfMediaReq, current), 16);
    assert_eq!(offset_of!(media::IfMediaReq, status), 24);
    assert_eq!(offset_of!(media::IfMediaReq, active), 28);
    assert_eq!(offset_of!(media::IfMediaReq, count), 32);
    assert_eq!(offset_of!(media::IfMediaReq, list), 36);
}

#[test]
fn darwin_media_extended_success_ignores_nominal_current_and_preserves_active() {
    let result = media::query_with(b"e\xff0", |query, request| {
        assert_eq!(query, media::Query::Extended);
        assert_eq!(&request.name[..4], b"e\xff0\0");
        request.current = 0x35; // selected 10G is not active 1G.
        request.status = 3;
        request.active = 0x30;
        Ok(())
    });
    assert_eq!(result, Some((3, 0x30)));
    let (status, active) = result.unwrap();
    assert_eq!(media::speed(active, status), Some(1_000_000_000));
}

#[test]
fn darwin_media_compatibility_retry_only_after_unsupported_and_resets_request() {
    let mut calls = Vec::new();
    let result = media::query_with(b"en0", |query, request| {
        calls.push(query);
        if query == media::Query::Extended {
            request.status = 3;
            request.active = 0x35;
            request.count = 20;
            return Err(media::IoctlError::Unsupported);
        }
        let status = request.status;
        let count = request.count;
        let list = request.list;
        assert_eq!((status, count), (0, 0));
        assert!(list.is_null());
        request.status = 1;
        request.active = 0x30;
        Ok(())
    });
    assert_eq!(calls, [media::Query::Extended, media::Query::Compatible]);
    assert_eq!(result, Some((1, 0x30)));
    assert_eq!(media::speed(result.unwrap().1, result.unwrap().0), None);
    let mut calls = 0;
    assert_eq!(
        media::query_with(b"en0", |_, _| {
            calls += 1;
            Err(media::IoctlError::Other)
        }),
        None
    );
    assert_eq!(calls, 1);
    assert_eq!(
        media::query_with(b"en0", |_, _| Err(media::IoctlError::Unsupported)),
        None
    );
}

#[test]
fn darwin_media_invalid_names_or_returned_identity_are_unavailable() {
    for name in [b"".as_slice(), b"0123456789abcdef", b"en\0x"] {
        assert_eq!(
            media::query_with(name, |_, _| panic!("invalid name reached ioctl")),
            None
        );
    }
    assert_eq!(
        media::query_with(b"en0", |_, request| {
            request.name[2] = b'1';
            request.status = 3;
            request.active = 0x30;
            Ok(())
        }),
        None
    );
}

// Task8 must run these on both supported Darwin architectures and compare the
// selected SDK headers as well. Linux executing the portable tests is NOT that
// evidence. A changed native ABI fails before any FFI buffer can be used.
#[cfg(target_os = "macos")]
#[test]
fn darwin_inventory_native_libc_layout_matches_pinned_ifmib_and_sockaddrs() {
    assert_eq!(size_of::<libc::ifmibdata>(), 180);
    assert_eq!(align_of::<libc::ifmibdata>(), 4);
    assert_eq!(offset_of!(libc::ifmibdata, ifmd_data), 52);
    assert_eq!(size_of::<libc::if_data64>(), 128);
    assert_eq!(align_of::<libc::if_data64>(), 4);
    assert_eq!(offset_of!(libc::if_data64, ifi_ibytes), 64);
    assert_eq!(offset_of!(libc::if_data64, ifi_obytes), 72);
    assert_eq!(size_of::<libc::sockaddr_in>(), 16);
    assert_eq!(size_of::<libc::sockaddr_in6>(), 28);
    assert_eq!(offset_of!(libc::sockaddr_dl, sdl_data), 8);
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_media_native_ioctl_encoding_uses_the_packed_request_size() {
    assert_eq!(libc::SIOCGIFXMEDIA, 0xc02c6948);
    assert_eq!(libc::SIOCGIFMEDIA, 0xc02c6938);
    assert_eq!(size_of::<media::IfMediaReq>(), 44);
    assert_eq!(align_of::<media::IfMediaReq>(), 4);
    assert_eq!(offset_of!(media::IfMediaReq, list), 36);
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_inventory_native_read_only_loopback_has_owned_addresses_and_ifmib() {
    let started = Instant::now();
    let snapshot = super::snapshot().expect("mandatory Darwin inventory");
    let finished = Instant::now();
    let loopback = snapshot
        .interfaces
        .iter()
        .find(|interface| interface.id.name == b"lo0")
        .expect("native loopback interface");
    assert_ne!(loopback.id.index, 0);
    assert!(
        loopback
            .addresses
            .iter()
            .any(|address| address.ip == IpAddr::V4(Ipv4Addr::LOCALHOST))
    );
    assert!(
        loopback
            .addresses
            .iter()
            .any(|address| address.ip == IpAddr::V6(Ipv6Addr::LOCALHOST))
    );
    let counters = loopback
        .counters
        .as_ref()
        .expect("Task8 requires a validated native loopback IFMIB observation");
    assert!(counters.rx_bytes.is_some());
    assert!(counters.tx_bytes.is_some());
    assert!(started <= counters.at && counters.at <= finished);
    assert!(loopback.mtu.is_some());
}
