use std::{
    cell::Cell,
    collections::{BTreeSet, VecDeque},
    mem::{align_of, offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    rc::Rc,
    time::Instant,
};

use crate::model::{Address, Coverage, Family, InterfaceId, State};

use super::{inventory, media, routes, wire};

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

// Literal Darwin DUMP/GET layout, independent of the decoder/stride helpers.
// Changing the header size, field offsets, RTAX order or ROUNDUP32 breaks the
// memberships below, not just an assertion about the fixture's own structure.
fn route(index: u16, flags: u32, addresses: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut bytes = vec![0; 92];
    bytes[2] = 5;
    bytes[3] = 4;
    bytes[4..6].copy_from_slice(&index.to_ne_bytes());
    bytes[8..12].copy_from_slice(&flags.to_ne_bytes());
    let mut bitmap = 0_u32;
    let mut previous = None;
    for (slot, address) in addresses {
        assert!(previous.is_none_or(|last| last < *slot));
        previous = Some(*slot);
        bitmap |= 1 << slot;
        bytes.extend_from_slice(address);
        while !bytes.len().is_multiple_of(4) {
            bytes.push(0);
        }
    }
    bytes[12..16].copy_from_slice(&bitmap.to_ne_bytes());
    let len = u16::try_from(bytes.len()).unwrap();
    bytes[..2].copy_from_slice(&len.to_ne_bytes());
    bytes
}

fn route_v4(index: u16) -> Vec<u8> {
    route(index, 1, &[(0, v4([0; 4])), (2, vec![0; 4])])
}

fn route_v6(index: u16) -> Vec<u8> {
    route(index, 1, &[(0, v6([0; 16], 0)), (2, vec![0; 4])])
}

fn route_incomplete(coverage: Coverage<BTreeSet<u32>>, expected: &[u32]) {
    match coverage {
        Coverage::Incomplete { value, reason } => {
            assert_eq!(value, expected.iter().copied().collect());
            assert!(!reason.is_empty());
        }
        other => panic!("expected incomplete {expected:?}, got {other:?}"),
    }
}

#[test]
fn darwin_routes_zero_length_sockaddr_advances_four_on_lp64() {
    assert_eq!(wire::sockaddr_stride(0), Some(4));
    assert_eq!(wire::sockaddr_stride(1), Some(4));
    assert_eq!(wire::sockaddr_stride(4), Some(4));
    assert_eq!(wire::sockaddr_stride(5), Some(8));
    assert_eq!(wire::sockaddr_stride(usize::MAX - 3), Some(usize::MAX - 3));
    assert_eq!(wire::sockaddr_stride(usize::MAX), None);
}

#[test]
fn darwin_routes_v4_preserves_all_scoped_and_gateway_free_defaults() {
    let mut bytes = route(
        4,
        3,
        &[(0, v4([0; 4])), (1, v4([192, 0, 2, 1])), (2, vec![0; 4])],
    );
    bytes.extend(route(
        19,
        0x0100_0001,
        &[(0, v4([0; 4])), (2, vec![4, 0, 0, 0])],
    ));
    bytes.extend(route_v4(4));
    assert_eq!(
        routes::decode(&bytes, Family::V4),
        Coverage::Complete(BTreeSet::from([4, 19]))
    );
}

#[test]
fn darwin_routes_v6_preserves_scoped_and_point_to_point_defaults() {
    let mut gateway = [0; 16];
    gateway[..2].copy_from_slice(&[0xfe, 0x80]);
    gateway[15] = 1;
    let mut bytes = route(
        4,
        0x0100_0003,
        &[(0, v6([0; 16], 4)), (1, v6(gateway, 4)), (2, vec![0; 4])],
    );
    bytes.extend(route(
        19,
        0x0100_0001,
        &[(0, v6([0; 16], 19)), (2, vec![8, 0, 0, 0, 0, 0, 0, 0])],
    ));
    assert_eq!(
        routes::decode(&bytes, Family::V6),
        Coverage::Complete(BTreeSet::from([4, 19]))
    );
}

#[test]
fn darwin_routes_bitmap_order_advances_past_zero_masks_and_odd_link_extents() {
    let bytes = route(
        0,
        1,
        &[
            (0, v4([0; 4])),
            (1, v4([192, 0, 2, 1])),
            (2, vec![0; 4]),
            (3, vec![0; 4]),
            (4, link(b"en0", 23, &[])),
            (5, v4([192, 0, 2, 9])),
            (6, v4([192, 0, 2, 2])),
            (7, v4([192, 0, 2, 10])),
        ],
    );
    assert_eq!(
        routes::decode(&bytes, Family::V4),
        Coverage::Complete(BTreeSet::from([23]))
    );
}

#[test]
fn darwin_routes_direct_link_gateway_can_supply_the_interface() {
    let bytes = route(
        0,
        1,
        &[
            (0, v6([0; 16], 0)),
            (1, link(b"utun2", 29, &[])),
            (2, vec![0; 4]),
        ],
    );
    assert_eq!(
        routes::decode(&bytes, Family::V6),
        Coverage::Complete(BTreeSet::from([29]))
    );
}

#[test]
fn darwin_routes_gateway_next_hop_index_is_not_an_egress_fallback() {
    let addresses = [(0, v4([0; 4])), (1, link(b"", 99, &[])), (2, vec![0; 4])];
    assert_eq!(
        routes::decode(&route(4, 3, &addresses), Family::V4),
        Coverage::Complete(BTreeSet::from([4]))
    );
    route_incomplete(routes::decode(&route(0, 3, &addresses), Family::V4), &[]);
    route_incomplete(routes::decode(&route_v4(0), Family::V4), &[]);
    let mut gateway = [0; 16];
    gateway[..2].copy_from_slice(&[0xfe, 0x80]);
    gateway[15] = 1;
    route_incomplete(
        routes::decode(
            &route(
                0,
                3,
                &[(0, v6([0; 16], 0)), (1, v6(gateway, 27)), (2, vec![0; 4])],
            ),
            Family::V6,
        ),
        &[],
    );
}

#[test]
fn darwin_routes_conflicting_or_malformed_link_identity_is_incomplete() {
    let mut bad_link = link(b"en0", 4, &[]);
    bad_link[6] = 255;
    for ifp in [link(b"en0", 19, &[]), bad_link, vec![2, 18], v4([0; 4])] {
        route_incomplete(
            routes::decode(
                &route(4, 1, &[(0, v4([0; 4])), (2, vec![0; 4]), (4, ifp)]),
                Family::V4,
            ),
            &[],
        );
    }
}

#[test]
fn darwin_routes_short_masks_keep_their_actual_nondefault_prefix_bits() {
    for mask in [vec![5, 0, 0, 0, 0xff], vec![8, 2, 0, 0, 0xff, 0xff, 0, 0]] {
        assert_eq!(
            routes::decode(&route(4, 1, &[(0, v4([0; 4])), (2, mask)]), Family::V4),
            Coverage::Complete(BTreeSet::new())
        );
    }
    assert_eq!(
        routes::decode(
            &route(
                4,
                1,
                &[(0, v6([0; 16], 0)), (2, vec![9, 0, 0, 0, 0, 0, 0, 0, 0x80])]
            ),
            Family::V6,
        ),
        Coverage::Complete(BTreeSet::new())
    );
    for mask in [vec![2, 0], vec![4, 2, 0, 0], v4([0; 4])] {
        assert_eq!(
            routes::decode(&route(4, 1, &[(0, v4([0; 4])), (2, mask)]), Family::V4),
            Coverage::Complete(BTreeSet::from([4]))
        );
    }
}

#[test]
fn darwin_routes_radix_masks_v4_opaque_headers_keep_default_coverage() {
    // XNU rn_addmask may fill bytes before sin_addr with all ones. Neither
    // 0xff, another AF value, nor an opaque header is a mask-family tag.
    for mask in [
        vec![4, 0xff, 0xff, 0xff],
        vec![2, 0x7e],
        vec![4, 30, 0, 0],
        vec![5, 30, 0x12, 0x34, 0],
    ] {
        let bytes = [
            route_v4(3),
            route(7, 1, &[(0, v4([0; 4])), (2, mask)]),
            route_v4(11),
        ]
        .concat();
        assert_eq!(
            routes::decode(&bytes, Family::V4),
            Coverage::Complete(BTreeSet::from([3, 7, 11]))
        );
    }
}

#[test]
fn darwin_routes_radix_masks_v6_opaque_headers_keep_default_coverage() {
    for mask in [
        vec![8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![2, 0x7e],
        vec![9, 2, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0],
    ] {
        let bytes = [
            route_v6(3),
            route(7, 0x0100_0001, &[(0, v6([0; 16], 7)), (2, mask)]),
            route_v6(11),
        ]
        .concat();
        assert_eq!(
            routes::decode(&bytes, Family::V6),
            Coverage::Complete(BTreeSet::from([3, 7, 11]))
        );
    }
}

#[test]
fn darwin_routes_radix_masks_v4_opaque_headers_preserve_nondefault_prefix_bits() {
    // /1, /24 and /32 are nondefaults even with an all-zero destination.
    for mask in [
        vec![5, 0xff, 0xff, 0xff, 0x80],
        vec![7, 0x7e, 0x12, 0x34, 0xff, 0xff, 0xff],
        vec![8, 30, 0x12, 0x34, 0xff, 0xff, 0xff, 0xff],
    ] {
        let bytes = [
            route_v4(3),
            route(7, 1, &[(0, v4([0; 4])), (2, mask)]),
            route_v4(11),
        ]
        .concat();
        assert_eq!(
            routes::decode(&bytes, Family::V4),
            Coverage::Complete(BTreeSet::from([3, 11]))
        );
    }
}

#[test]
fn darwin_routes_radix_masks_v6_opaque_headers_preserve_nondefault_prefix_bits() {
    // Trimmed /1 and /64 masks; only bytes at/after sin6_addr are prefix bits.
    for mask in [
        vec![9, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80],
        vec![
            16, 0x7e, 1, 2, 3, 4, 5, 6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
    ] {
        let bytes = [
            route_v6(3),
            route(7, 0x0100_0001, &[(0, v6([0; 16], 7)), (2, mask)]),
            route_v6(11),
        ]
        .concat();
        assert_eq!(
            routes::decode(&bytes, Family::V6),
            Coverage::Complete(BTreeSet::from([3, 11]))
        );
    }
}

#[test]
fn darwin_routes_nondefault_destinations_and_host_routes_are_not_defaults() {
    let mut bytes = route(4, 1, &[(0, v4([192, 0, 2, 0])), (2, vec![0; 4])]);
    bytes.extend(route(19, 5, &[(0, v4([0; 4]))]));
    assert_eq!(
        routes::decode(&bytes, Family::V4),
        Coverage::Complete(BTreeSet::new())
    );
    let mut ip = [0; 16];
    ip[0] = 0x20;
    assert_eq!(
        routes::decode(&route(4, 1, &[(0, v6(ip, 0)), (2, vec![0; 4])]), Family::V6),
        Coverage::Complete(BTreeSet::new())
    );
}

#[test]
fn darwin_routes_nonforwarding_dead_reject_blackhole_and_down_are_excluded() {
    let mut bytes = Vec::new();
    for flags in [
        0,
        9,
        0x1001,
        0x2000_0001,
        0x0200_0001,
        0x0020_0001,
        0x0040_0001,
        0x0080_0001,
    ] {
        bytes.extend(route(19, flags, &[(0, v4([0; 4])), (2, vec![0; 4])]));
    }
    bytes.extend(route_v4(4));
    assert_eq!(
        routes::decode(&bytes, Family::V4),
        Coverage::Complete(BTreeSet::from([4]))
    );
}

#[test]
fn darwin_routes_malformed_masks_cannot_become_complete_empty_or_defaults() {
    // The former [4, 30, 0, 0] case is a valid opaque radix-mask header, now
    // covered positively above. Use actual malformed address bits instead.
    for mask in [
        vec![5, 0, 0, 0, 0x81],
        vec![6, 0xff, 0xff, 0xff, 0, 0x80],
        vec![17; 17],
    ] {
        route_incomplete(
            routes::decode(&route(4, 1, &[(0, v4([0; 4])), (2, mask)]), Family::V4),
            &[],
        );
    }
    route_incomplete(
        routes::decode(&route(4, 1, &[(0, v4([0; 4]))]), Family::V4),
        &[],
    );
}

#[test]
fn darwin_routes_wrong_family_is_visible_and_does_not_cross_pollinate() {
    let mut bytes = route_v4(4);
    bytes.extend(route_v6(19));
    route_incomplete(routes::decode(&bytes, Family::V4), &[4]);
    route_incomplete(routes::decode(&bytes, Family::V6), &[19]);
    // Opaque headers are valid only for masks, never ordinary destinations or
    // gateways. Keep both family checks despite accepting an opaque mask.
    let mut opaque_ip = v4([0; 4]);
    opaque_ip[1] = 0xff;
    for (flags, addresses) in [
        (
            1,
            vec![(0, opaque_ip.clone()), (2, vec![4, 0xff, 0xff, 0xff])],
        ),
        (
            3,
            vec![
                (0, v4([0; 4])),
                (1, opaque_ip),
                (2, vec![4, 0xff, 0xff, 0xff]),
            ],
        ),
    ] {
        route_incomplete(
            routes::decode(&route(19, flags, &addresses), Family::V4),
            &[],
        );
    }
}

#[test]
fn darwin_routes_bad_version_get2_errno_and_bitmap_preserve_other_records_only() {
    let good = route_v4(4);
    let mut malformed = Vec::new();
    let mut version = route_v4(99);
    version[2] = 4;
    malformed.push(version);
    for kind in [1, 0x0e, 0x14] {
        let mut bytes = route_v4(99);
        bytes[3] = kind;
        malformed.push(bytes);
    }
    let mut failed = route_v4(99);
    failed[24..28].copy_from_slice(&5_i32.to_ne_bytes());
    malformed.push(failed);
    let mut bitmap = route_v4(99);
    bitmap[12..16].copy_from_slice(&0x105_u32.to_ne_bytes());
    malformed.push(bitmap);
    malformed.push(route(99, 1, &[(2, vec![0; 4])]));
    for bad in malformed {
        let bytes = [good.clone(), bad, route_v4(19)].concat();
        route_incomplete(routes::decode(&bytes, Family::V4), &[4, 19]);
    }
}

#[test]
fn darwin_routes_short_headers_impossible_msglen_and_all_truncations_are_visible() {
    let good = route_v4(4);
    for end in 1..good.len() {
        route_incomplete(routes::decode(&good[..end], Family::V4), &[]);
    }
    for len in [0_u16, 4, 91, u16::MAX] {
        let mut bad = good.clone();
        bad[..2].copy_from_slice(&len.to_ne_bytes());
        route_incomplete(
            routes::decode(&[good.clone(), bad].concat(), Family::V4),
            &[4],
        );
    }
    assert_eq!(
        routes::decode(&[], Family::V4),
        Coverage::Complete(BTreeSet::new())
    );
}

#[test]
fn darwin_routes_sockaddr_lengths_padding_and_unclaimed_payload_are_checked() {
    for address in [
        vec![0; 4],
        vec![1, 2, 0, 0],
        vec![7, 2, 0, 0, 0, 0, 0],
        vec![255, 2, 0, 0],
    ] {
        route_incomplete(
            routes::decode(&route(4, 1, &[(0, address), (2, vec![0; 4])]), Family::V4),
            &[],
        );
    }
    let mut no_padding = route(4, 1, &[(0, v4([0; 4])), (2, vec![5, 0, 0, 0, 0])]);
    no_padding.truncate(113);
    no_padding[..2].copy_from_slice(&113_u16.to_ne_bytes());
    route_incomplete(routes::decode(&no_padding, Family::V4), &[]);
    let mut extra = route_v4(4);
    extra.extend_from_slice(&[0; 4]);
    extra[..2].copy_from_slice(&116_u16.to_ne_bytes());
    route_incomplete(routes::decode(&extra, Family::V4), &[]);
    route_incomplete(
        routes::decode(
            &route(4, 1, &[(0, v4([0; 4])), (1, vec![0; 4]), (2, vec![0; 4])]),
            Family::V4,
        ),
        &[],
    );
}

struct RouteQueryStep {
    mib: [i32; 6],
    capacity: Option<usize>,
    bytes: Vec<u8>,
    result: routes::QueryResult,
}

struct RouteQuery(VecDeque<RouteQueryStep>);

impl RouteQuery {
    fn call(&mut self, mib: &[i32; 6], out: Option<&mut [u8]>) -> routes::QueryResult {
        let step = self.0.pop_front().expect("unexpected extra sysctl call");
        assert_eq!(
            *mib, step.mib,
            "collector must request a per-family DUMP, not DUMP2 or a setter"
        );
        assert_eq!(out.as_ref().map(|bytes| bytes.len()), step.capacity);
        if let Some(out) = out {
            out[..step.bytes.len()].copy_from_slice(&step.bytes);
        } else {
            assert!(step.bytes.is_empty());
        }
        step.result
    }

    fn collect(&mut self, family: Family) -> Coverage<BTreeSet<u32>> {
        let result = routes::collect_with(family, &mut |mib, out| self.call(mib, out));
        assert!(self.0.is_empty(), "collector skipped required sysctl calls");
        result
    }
}

fn route_size(family: i32, result: routes::QueryResult) -> RouteQueryStep {
    RouteQueryStep {
        mib: [4, 17, 0, family, 1, 0],
        capacity: None,
        bytes: vec![],
        result,
    }
}

fn route_data(
    family: i32,
    capacity: usize,
    bytes: Vec<u8>,
    result: routes::QueryResult,
) -> RouteQueryStep {
    RouteQueryStep {
        mib: [4, 17, 0, family, 1, 0],
        capacity: Some(capacity),
        bytes,
        result,
    }
}

#[test]
fn darwin_routes_query_separate_family_mibs_return_owned_independent_coverage() {
    let bytes = route_v4(4);
    let mut query = RouteQuery(VecDeque::from([
        route_size(2, routes::QueryResult::Success(512)),
        route_data(2, 512, bytes, routes::QueryResult::Success(112)),
        route_size(30, routes::QueryResult::Failed("denied".into())),
    ]));
    let defaults = routes::defaults_with(|mib, out| query.call(mib, out));
    assert!(query.0.is_empty());
    drop(query);
    assert_eq!(defaults.v4, Coverage::Complete(BTreeSet::from([4])));
    assert!(matches!(defaults.v6, Coverage::Unavailable(reason) if !reason.is_empty()));
}

#[test]
fn darwin_routes_query_successful_empty_size_is_complete_without_data_query() {
    let mut query = RouteQuery(VecDeque::from([route_size(
        30,
        routes::QueryResult::Success(0),
    )]));
    assert_eq!(
        query.collect(Family::V6),
        Coverage::Complete(BTreeSet::new())
    );
}

#[test]
fn darwin_routes_query_errors_never_turn_into_complete_empty_or_trust_failed_bytes() {
    let scripts = [
        VecDeque::from([route_size(2, routes::QueryResult::Failed("denied".into()))]),
        VecDeque::from([
            route_size(2, routes::QueryResult::Success(112)),
            route_data(
                2,
                112,
                route_v4(99),
                routes::QueryResult::Failed("I/O error".into()),
            ),
        ]),
    ];
    for steps in scripts {
        assert!(
            matches!(RouteQuery(steps).collect(Family::V4), Coverage::Unavailable(reason) if !reason.is_empty())
        );
    }
}

#[test]
fn darwin_routes_query_growth_restarts_size_and_success_replaces_old_partial_members() {
    let mut query = RouteQuery(VecDeque::from([
        route_size(2, routes::QueryResult::Success(112)),
        route_data(2, 112, route_v4(4), routes::QueryResult::NoMemory(112)),
        route_size(2, routes::QueryResult::Success(224)),
        route_data(2, 224, route_v4(19), routes::QueryResult::Success(112)),
    ]));
    assert_eq!(
        query.collect(Family::V4),
        Coverage::Complete(BTreeSet::from([19]))
    );
}

#[test]
fn darwin_routes_query_growth_exhausts_three_attempts_and_keeps_only_valid_records() {
    let mut steps = VecDeque::new();
    for index in [4, 19, 4] {
        steps.push_back(route_size(2, routes::QueryResult::Success(120)));
        let bytes = [route_v4(index), vec![0xff; 8]].concat();
        steps.push_back(route_data(
            2,
            120,
            bytes,
            routes::QueryResult::NoMemory(120),
        ));
    }
    route_incomplete(RouteQuery(steps).collect(Family::V4), &[4, 19]);
}

#[test]
fn darwin_routes_query_later_size_failure_retains_valid_partial_members_with_warning() {
    let mut query = RouteQuery(VecDeque::from([
        route_size(30, routes::QueryResult::Success(124)),
        route_data(30, 124, route_v6(19), routes::QueryResult::NoMemory(124)),
        route_size(30, routes::QueryResult::Failed("table unavailable".into())),
    ]));
    route_incomplete(query.collect(Family::V6), &[19]);
}

#[test]
fn darwin_routes_query_zero_length_enomem_is_never_a_complete_empty_dump() {
    for size_query in [false, true] {
        let mut steps = VecDeque::new();
        for _ in 0..3 {
            if size_query {
                steps.push_back(route_size(2, routes::QueryResult::NoMemory(0)));
            } else {
                steps.push_back(route_size(2, routes::QueryResult::Success(112)));
                steps.push_back(route_data(2, 112, vec![], routes::QueryResult::NoMemory(0)));
            }
        }
        assert!(
            matches!(RouteQuery(steps).collect(Family::V4), Coverage::Unavailable(reason) if !reason.is_empty())
        );
    }
}

#[test]
fn darwin_routes_query_caps_allocation_at_sixteen_mib_without_narrowing() {
    for size in [16 * 1024 * 1024 + 1, usize::MAX] {
        let mut query = RouteQuery(VecDeque::from([route_size(
            2,
            routes::QueryResult::Success(size),
        )]));
        assert!(
            matches!(query.collect(Family::V4), Coverage::Unavailable(reason) if !reason.is_empty())
        );
    }
    let mut query = RouteQuery(VecDeque::from([
        route_size(2, routes::QueryResult::Success(16 * 1024 * 1024)),
        route_data(2, 16 * 1024 * 1024, vec![], routes::QueryResult::Success(0)),
    ]));
    assert_eq!(
        query.collect(Family::V4),
        Coverage::Complete(BTreeSet::new())
    );
}

#[test]
fn darwin_routes_query_oversized_returned_length_is_truncated_not_complete() {
    let mut steps = VecDeque::new();
    for _ in 0..3 {
        steps.push_back(route_size(2, routes::QueryResult::Success(112)));
        steps.push_back(route_data(
            2,
            112,
            route_v4(4),
            routes::QueryResult::Success(113),
        ));
    }
    route_incomplete(RouteQuery(steps).collect(Family::V4), &[4]);
}

#[test]
fn darwin_routes_query_success_with_malformed_tail_is_still_incomplete() {
    let mut query = RouteQuery(VecDeque::from([
        route_size(2, routes::QueryResult::Success(116)),
        route_data(
            2,
            116,
            [route_v4(4), vec![0xff; 4]].concat(),
            routes::QueryResult::Success(116),
        ),
    ]));
    route_incomplete(query.collect(Family::V4), &[4]);
}

#[test]
fn darwin_routes_gateway_flag_without_a_next_hop_is_incomplete() {
    route_incomplete(
        routes::decode(
            &route(4, 3, &[(0, v4([0; 4])), (2, vec![0; 4])]),
            Family::V4,
        ),
        &[],
    );
}

#[test]
fn darwin_routes_masks_use_only_present_address_bits_not_stride_or_scope_bytes() {
    let mut padded = route(4, 1, &[(0, v4([0; 4])), (2, vec![5, 0, 0, 0, 0])]);
    padded[113..116].fill(0xff);
    assert_eq!(
        routes::decode(&padded, Family::V4),
        Coverage::Complete(BTreeSet::from([4]))
    );
    let bytes = route(
        19,
        0x0100_0001,
        &[(0, v6([0; 16], 19)), (2, v6([0; 16], u32::MAX))],
    );
    assert_eq!(
        routes::decode(&bytes, Family::V6),
        Coverage::Complete(BTreeSet::from([19]))
    );
}

#[test]
fn darwin_routes_query_ipv4_failure_does_not_prevent_ipv6_membership() {
    let mut query = RouteQuery(VecDeque::from([
        route_size(2, routes::QueryResult::Failed("no IPv4 table".into())),
        route_size(30, routes::QueryResult::Success(124)),
        route_data(30, 124, route_v6(19), routes::QueryResult::Success(124)),
    ]));
    let defaults = routes::defaults_with(|mib, out| query.call(mib, out));
    assert!(query.0.is_empty());
    assert!(matches!(defaults.v4, Coverage::Unavailable(reason) if !reason.is_empty()));
    assert_eq!(defaults.v6, Coverage::Complete(BTreeSet::from([19])));
}

#[test]
fn darwin_routes_query_third_attempt_can_succeed_with_a_new_complete_empty_dump() {
    let mut query = RouteQuery(VecDeque::from([
        route_size(2, routes::QueryResult::Success(112)),
        route_data(2, 112, route_v4(4), routes::QueryResult::NoMemory(112)),
        route_size(2, routes::QueryResult::Success(112)),
        route_data(2, 112, route_v4(19), routes::QueryResult::NoMemory(112)),
        route_size(2, routes::QueryResult::Success(0)),
    ]));
    assert_eq!(
        query.collect(Family::V4),
        Coverage::Complete(BTreeSet::new())
    );
}

#[test]
fn darwin_routes_query_later_data_error_retains_only_prior_valid_prefix() {
    let mut query = RouteQuery(VecDeque::from([
        route_size(2, routes::QueryResult::Success(112)),
        route_data(2, 112, route_v4(4), routes::QueryResult::NoMemory(112)),
        route_size(2, routes::QueryResult::Success(112)),
        route_data(
            2,
            112,
            route_v4(99),
            routes::QueryResult::Failed("denied".into()),
        ),
    ]));
    route_incomplete(query.collect(Family::V4), &[4]);
}

#[test]
fn darwin_routes_query_reported_growth_over_limit_keeps_valid_members_with_warning() {
    let mut query = RouteQuery(VecDeque::from([
        route_size(2, routes::QueryResult::Success(112)),
        route_data(
            2,
            112,
            route_v4(4),
            routes::QueryResult::NoMemory(16 * 1024 * 1024 + 1),
        ),
    ]));
    route_incomplete(query.collect(Family::V4), &[4]);
    let mut query = RouteQuery(VecDeque::from([route_size(
        2,
        routes::QueryResult::NoMemory(16 * 1024 * 1024 + 1),
    )]));
    assert!(
        matches!(query.collect(Family::V4), Coverage::Unavailable(reason) if !reason.is_empty())
    );
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_routes_native_get_header_and_link_layout_match_pinned_sources() {
    assert_eq!(size_of::<libc::rt_msghdr>(), 92);
    assert_eq!(align_of::<libc::rt_msghdr>(), 4);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_index), 4);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_flags), 8);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_addrs), 12);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_errno), 24);
    assert_eq!(offset_of!(libc::rt_msghdr, rtm_rmx), 36);
    assert_eq!(offset_of!(libc::sockaddr_dl, sdl_index), 2);
    assert_eq!(offset_of!(libc::sockaddr_dl, sdl_data), 8);
    assert_eq!(libc::RTM_VERSION, 5);
    assert_eq!(libc::RTM_GET, 4);
    assert_eq!(libc::RTM_GET2, 0x14);
    assert_eq!(libc::RTAX_IFP, 4);
    assert_eq!(libc::NET_RT_DUMP, 1);
    assert_eq!(wire::sockaddr_stride(0), Some(4));
    assert_eq!(wire::sockaddr_stride(5), Some(8));
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_routes_native_read_only_defaults_have_explicit_per_family_coverage() {
    let defaults = super::defaults();
    for coverage in [defaults.v4, defaults.v6] {
        match coverage {
            Coverage::Complete(members) => assert!(members.iter().all(|index| *index != 0)),
            other => panic!("native route dump did not complete: {other:?}"),
        }
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
    let mut compact = v4([255, 255, 255, 0]);
    compact[0] = 7;
    assert_eq!(
        wire::address(&ip, Some(&compact), 7)
            .unwrap()
            .unwrap()
            .prefix,
        Some(24)
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
fn darwin_inventory_compact_masks_zero_extend_only_the_declared_address_bits() {
    let ip = v4([192, 0, 2, 9]);
    for (mask, expected) in [
        (vec![5, 2, 0, 0, 255], 8),
        (vec![6, 2, 0, 0, 255, 255], 16),
        (vec![7, 2, 0, 0, 255, 255, 255], 24),
        (vec![8, 2, 0, 0, 255, 255, 255, 255], 32),
        (vec![7, 0, 0, 0, 255, 255, 255], 24),
        // Poison after sa_len must not contribute another eight mask bits.
        (vec![7, 2, 0, 0, 255, 255, 255, 255], 24),
    ] {
        assert_eq!(
            wire::address(&ip, Some(&mask), 7).unwrap(),
            Some(Address {
                ip: "192.0.2.9".parse().unwrap(),
                prefix: Some(expected),
                scope_id: None,
            }),
            "mask={mask:?}"
        );
    }
    for (mask, expected) in [
        (
            vec![
                16, 30, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255,
            ],
            64,
        ),
        (
            vec![
                24, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255,
            ],
            128,
        ),
    ] {
        assert_eq!(
            wire::address(&v6(Ipv6Addr::LOCALHOST.octets(), 0), Some(&mask), 1)
                .unwrap()
                .unwrap()
                .prefix,
            Some(expected),
            "IPv6 mask={mask:?}"
        );
    }
}

#[test]
fn darwin_inventory_explicit_zero_length_and_full_zero_masks_are_valid() {
    // Native copy retains the observed zero sa_len byte as [0], not an empty
    // or missing mask. Libinfo zero-fills that special RTAX_NETMASK allocation.
    for (ip, full_zero) in [
        (v4([192, 0, 2, 9]), v4([0; 4])),
        (v6(Ipv6Addr::LOCALHOST.octets(), 0), v6([0; 16], 0)),
    ] {
        for mask in [vec![0], full_zero] {
            assert_eq!(
                wire::address(&ip, Some(&mask), 1).unwrap().unwrap().prefix,
                Some(0),
                "mask={mask:?}"
            );
        }
    }
}

#[test]
fn darwin_inventory_malformed_compact_masks_preserve_ip_without_a_prefix() {
    let ip = v4([192, 0, 2, 9]);
    for mask in [
        vec![],
        vec![1],
        vec![2, 2],
        vec![3, 2, 0],
        vec![4, 2, 0, 0],
        vec![7, 2, 0, 0, 255, 255], // shorter than the declared length
        vec![7, 30, 0, 0, 255, 255, 255],
        vec![7, 2, 0, 0, 255, 0, 255],
        vec![17, 2, 0, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![0, 255], // not the owned zero-length marker
    ] {
        assert_eq!(
            wire::address(&ip, Some(&mask), 7).unwrap(),
            Some(Address {
                ip: "192.0.2.9".parse().unwrap(),
                prefix: None,
                scope_id: None,
            }),
            "mask={mask:?}"
        );
    }
    for mask in [
        vec![8, 30, 0, 0, 0, 0, 0, 0],
        vec![10, 30, 0, 0, 0, 0, 0, 0, 255],
        v4([255; 4]),
    ] {
        let address = wire::address(&v6(Ipv6Addr::LOCALHOST.octets(), 0), Some(&mask), 1)
            .unwrap()
            .unwrap();
        assert_eq!(address.ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(address.prefix, None, "IPv6 mask={mask:?}");
    }
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
