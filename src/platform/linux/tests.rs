use super::ethtool::{self, Access};
use super::inventory::{attach_addresses, decode_links, decode_stats64};
use super::netlink::{self, Datagram, Transport};
use super::{nexthops, routes};
use crate::model::Coverage;
use crate::model::{Address, State};
use crate::model::{CollectError, InterfaceId};
use std::collections::{BTreeMap, BTreeSet};
use std::{collections::VecDeque, io, time::Duration};
use std::{net::IpAddr, time::Instant};

fn attr(kind: u16, payload: &[u8]) -> Vec<u8> {
    let len = payload.len().checked_add(4).unwrap();
    let padded = len.checked_add(3).unwrap() & !3;
    let mut bytes = Vec::with_capacity(padded);
    bytes.extend(u16::try_from(len).unwrap().to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(payload);
    bytes.resize(padded, 0);
    bytes
}

fn message(kind: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len().checked_add(16).unwrap();
    let padded = len.checked_add(3).unwrap() & !3;
    let mut bytes = Vec::with_capacity(padded);
    bytes.extend(u32::try_from(len).unwrap().to_ne_bytes());
    bytes.extend(kind.to_ne_bytes());
    bytes.extend(2_u16.to_ne_bytes()); // NLM_F_MULTI
    bytes.extend(seq.to_ne_bytes());
    bytes.extend(73_u32.to_ne_bytes()); // Recipient port ID is not sender sockaddr PID.
    bytes.extend(payload);
    bytes.resize(padded, 0);
    bytes
}

fn link(index: i32, name: &[u8], operstate: Option<u8>, extra: &[u8]) -> Vec<u8> {
    let mut payload = vec![0, 0, 1, 0]; // AF_UNSPEC, pad, ARPHRD_ETHER
    payload.extend(index.to_ne_bytes());
    payload.extend(1_u32.to_ne_bytes()); // IFF_UP is not a substitute for operstate.
    payload.extend(0_u32.to_ne_bytes());
    payload.extend(attr(3, name));
    if let Some(state) = operstate {
        payload.extend(attr(16, &[state]));
    }
    payload.extend(extra);
    message(16, 7, &payload)
}

fn address(index: u32, family: u8, prefix: u8, scope: u8, attrs: &[u8]) -> Vec<u8> {
    let mut payload = vec![family, prefix, 0, scope];
    payload.extend(index.to_ne_bytes());
    payload.extend(attrs);
    message(20, 7, &payload)
}

#[test]
fn linux_snapshot_stats64_accepts_64_bit_prefix_and_growing_tail() {
    let bytes: Vec<u8> = [7_u64, 9, 4_294_967_396, 8_589_934_792]
        .into_iter()
        .flat_map(u64::to_ne_bytes)
        .collect();
    assert_eq!(decode_stats64(&bytes), Some((4_294_967_396, 8_589_934_792)));
    assert_eq!(decode_stats64(&bytes[..31]), None);
    let mut growing = bytes;
    growing.extend([0x55; 72]);
    assert_eq!(
        decode_stats64(&growing),
        Some((4_294_967_396, 8_589_934_792))
    );
    let mut unaligned = vec![0xff];
    unaligned.extend(growing);
    assert_eq!(
        decode_stats64(&unaligned[1..]),
        Some((4_294_967_396, 8_589_934_792))
    );
}

#[test]
fn linux_snapshot_keeps_link_only_down_unknown_tunnel_bridge_and_raw_names() {
    let at = Instant::now();
    let stats: Vec<u8> = [7_u64, 9, 4_294_967_396, 8_589_934_792]
        .into_iter()
        .flat_map(u64::to_ne_bytes)
        .collect();
    let mut extra = attr(4, &9000_u32.to_ne_bytes());
    extra.extend(attr(1, &[0x02, 0, 0, 0, 0, 0x09]));
    extra.extend(attr(23, &stats));
    extra.extend(attr(6000, &[5]));
    let mut bytes = link(2, b"eth\xff\0", Some(6), &extra);
    bytes.extend(link(3, b"down0\0", Some(2), &[]));
    bytes.extend(link(4, b"tun0\0", Some(0), &attr(18, &attr(1, b"tun\0"))));
    bytes.extend(link(5, b"br0\0", None, &attr(18, &attr(1, b"bridge\0"))));
    let links = decode_links(&bytes, at).unwrap();
    assert_eq!(links.len(), 4);
    assert_eq!(links[0].id.index, 2);
    assert_eq!(links[0].id.name, b"eth\xff");
    assert_eq!(links[0].state, State::Up);
    assert_eq!(links[1].state, State::Down);
    assert_eq!(links[2].state, State::Unknown);
    assert_eq!(links[3].state, State::Unknown);
    assert_eq!(links[0].mtu, Some(9000));
    assert_eq!(links[0].link_address, Some(vec![2, 0, 0, 0, 0, 9]));
    let counters = links[0].counters.as_ref().unwrap();
    assert_eq!(
        (counters.rx_bytes, counters.tx_bytes),
        (Some(4_294_967_396), Some(8_589_934_792))
    );
    assert_eq!(counters.at, at);
    assert!(
        links
            .iter()
            .all(|item| item.addresses.is_empty() && item.speed_bps.is_none())
    );
    assert!(
        links[1..]
            .iter()
            .all(|item| item.counters.is_none() && item.mtu.is_none())
    );
}

#[test]
fn linux_snapshot_rejects_invalid_identity_and_malformed_attributes() {
    for index in [0, -1, i32::MIN] {
        assert!(decode_links(&link(index, b"bad\0", None, &[]), Instant::now()).is_err());
    }
    for name in [&b""[..], &b"\0"[..], &b"no-nul"[..], &b"bad\0tail\0"[..]] {
        assert!(decode_links(&link(2, name, None, &[]), Instant::now()).is_err());
    }
    let mut duplicate = link(2, b"a\0", None, &[]);
    duplicate.extend(link(2, b"b\0", None, &[]));
    assert!(decode_links(&duplicate, Instant::now()).is_err());
    // Unknown attributes must still pass length/alignment validation.
    for bad in [
        vec![3, 0, 0xff, 0x7f],
        vec![9, 0, 0xff, 0x7f, 1, 2, 3, 4],
        vec![5, 0, 0xff, 0x7f, 1],
    ] {
        assert!(decode_links(&link(2, b"a\0", None, &bad), Instant::now()).is_err());
    }
    assert!(decode_links(&message(16, 7, &[0; 15]), Instant::now()).is_err());
    let mut short_header = link(2, b"a\0", None, &[]);
    short_header[0..4].copy_from_slice(&15_u32.to_ne_bytes());
    assert!(decode_links(&short_header, Instant::now()).is_err());
}

#[test]
fn linux_snapshot_optional_malformed_metadata_and_32bit_stats_stay_unavailable() {
    let mut extras = attr(4, &[1, 2, 3]);
    extras.extend(attr(16, &[6, 6]));
    extras.extend(attr(23, &[0; 31]));
    extras.extend(attr(7, &[0xff; 96])); // IFLA_STATS is never a 64-bit source.
    let links = decode_links(&link(2, b"a\0", None, &extras), Instant::now()).unwrap();
    assert_eq!(links[0].mtu, None);
    assert_eq!(links[0].state, State::Unknown);
    assert!(links[0].counters.is_none());
}

#[test]
fn linux_snapshot_only_kernel_up_down_map_to_badges_other_states_are_unknown() {
    // R2 Linux mapping: NOTPRESENT/LOWERLAYERDOWN/TESTING/DORMANT are
    // conservatively UNKNOWN, not a synthesized DOWN badge.
    for operstate in [0, 1, 3, 4, 5, 7, 255] {
        let links = decode_links(&link(2, b"a\0", Some(operstate), &[]), Instant::now()).unwrap();
        assert_eq!(links[0].state, State::Unknown, "operstate {operstate}");
    }
}

#[test]
fn linux_snapshot_all_assigned_addresses_local_not_peer_scopes_and_prefixes() {
    let mut links = decode_links(&link(2, b"p2p\0", None, &[]), Instant::now()).unwrap();
    let mut p2p = attr(1, &[192, 0, 2, 254]);
    p2p.extend(attr(2, &[192, 0, 2, 1]));
    p2p.extend(attr(6000, &[7]));
    let mut bytes = address(2, 2, 24, 0, &p2p);
    bytes.extend(address(2, 2, 32, 0, &attr(1, &[198, 51, 100, 9])));
    bytes.extend(address(
        2,
        10,
        64,
        253,
        &attr(1, &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9]),
    ));
    bytes.extend(address(
        2,
        10,
        128,
        0,
        &attr(
            1,
            &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8],
        ),
    ));
    bytes.extend(address(2, 2, 33, 0, &attr(1, &[203, 0, 113, 7])));
    bytes.extend(address(2, 10, 129, 0, &attr(1, &[0; 16])));
    attach_addresses(&mut links, &bytes).unwrap();
    let expected: Vec<Address> = [
        ("192.0.2.1", Some(24), None),
        ("198.51.100.9", Some(32), None),
        ("fe80::9", Some(64), Some(2)),
        ("2001:db8::8", Some(128), None),
        ("203.0.113.7", None, None),
        ("::", None, None),
    ]
    .into_iter()
    .map(|(ip, prefix, scope_id)| Address {
        ip: ip.parse::<IpAddr>().unwrap(),
        prefix,
        scope_id,
    })
    .collect();
    assert_eq!(links[0].addresses, expected);
}

#[test]
fn linux_snapshot_bad_address_dump_is_not_empty_success() {
    let mut links = decode_links(&link(2, b"a\0", None, &[]), Instant::now()).unwrap();
    for bytes in [
        address(0, 2, 24, 0, &attr(1, &[192, 0, 2, 1])),
        address(99, 2, 24, 0, &attr(1, &[192, 0, 2, 1])),
        address(2, 2, 24, 0, &attr(1, &[192, 0, 2])),
        address(2, 2, 24, 0, &[]),
        address(2, 99, 0, 0, &[3, 0, 0xff, 0x7f]),
        message(20, 7, &[0; 7]),
    ] {
        assert!(attach_addresses(&mut links, &bytes).is_err());
    }
    // A structurally valid unrelated address family is harmless.
    attach_addresses(&mut links, &address(2, 17, 0, 0, &attr(6000, &[1]))).unwrap();
    assert!(links[0].addresses.is_empty());
}

fn packet(bytes: Vec<u8>) -> Datagram {
    Datagram {
        bytes,
        sender_family: 16,
        sender_pid: 0,
        sender_len: 12,
        flags: 0,
    }
}

fn control(kind: u16, seq: u32, error: i32) -> Vec<u8> {
    let mut payload = error.to_ne_bytes().to_vec();
    if kind == 2 {
        payload.extend(message(18, seq, &[])); // full nlmsgerr's embedded header
    }
    message(kind, seq, &payload)
}

struct NativeBatches {
    now: Instant,
    batches: VecDeque<(Duration, io::Result<Datagram>)>,
    sends: Vec<(Instant, Vec<u8>)>,
    deadlines: Vec<Instant>,
    clock_tick: Duration,
    clock_reads: std::cell::Cell<u32>,
    send_script: VecDeque<(Duration, io::Result<()>)>,
}

impl NativeBatches {
    fn new(batches: Vec<Datagram>) -> Self {
        Self {
            now: Instant::now(),
            batches: batches
                .into_iter()
                .map(|p| (Duration::ZERO, Ok(p)))
                .collect(),
            sends: Vec::new(),
            deadlines: Vec::new(),
            clock_tick: Duration::ZERO,
            clock_reads: std::cell::Cell::new(0),
            send_script: VecDeque::new(),
        }
    }
}

impl Transport for NativeBatches {
    fn now(&self) -> Instant {
        let reads = self.clock_reads.get();
        self.clock_reads.set(reads + 1);
        self.now + self.clock_tick * reads
    }
    fn send(&mut self, request: &[u8], deadline: Instant) -> io::Result<()> {
        self.sends.push((deadline, request.to_vec()));
        let (elapsed, result) = self
            .send_script
            .pop_front()
            .unwrap_or((Duration::ZERO, Ok(())));
        self.now += elapsed;
        result
    }
    fn receive(&mut self, deadline: Instant) -> io::Result<Datagram> {
        self.deadlines.push(deadline);
        let (elapsed, result) = self
            .batches
            .pop_front()
            .unwrap_or((Duration::from_secs(1), Err(io::ErrorKind::TimedOut.into())));
        self.now += elapsed;
        result
    }
}

#[test]
fn linux_transport_complete_batches_consume_ack_done_and_validate_request() {
    let data = message(16, 7, &[0; 16]);
    let mut first = control(2, 7, 0);
    first.extend(&data);
    first.extend(message(6000, 7, &[1]));
    let mut io = NativeBatches::new(vec![packet(first), packet(control(3, 7, 0))]);
    let result = netlink::dump_with(&mut io, 18, &[0; 16], 7).unwrap();
    assert_eq!(result, data); // Header PID73 is valid from sockaddr PID0.
    assert_eq!(io.sends.len(), 1);
    let request = &io.sends[0].1;
    // Literal field expectations, read in native order on either test host.
    assert_eq!(u32::from_ne_bytes(request[0..4].try_into().unwrap()), 32);
    assert_eq!(u16::from_ne_bytes(request[4..6].try_into().unwrap()), 18);
    assert_eq!(u16::from_ne_bytes(request[6..8].try_into().unwrap()), 0x301);
    assert_eq!(u32::from_ne_bytes(request[8..12].try_into().unwrap()), 7);
    assert_eq!(u32::from_ne_bytes(request[12..16].try_into().unwrap()), 0);
    assert_eq!(&request[16..], &[0; 16]);
}

#[test]
fn linux_transport_rejects_sender_family_length_pid_and_sequence_not_header_pid() {
    for variant in 0..4 {
        let mut p = packet(control(3, 7, 0));
        match variant {
            0 => p.sender_pid = 19,
            1 => p.sender_family = 2,
            2 => p.sender_len = 11,
            _ => p.bytes[8..12].copy_from_slice(&8_u32.to_ne_bytes()),
        }
        let mut io = NativeBatches::new(vec![p]);
        assert!(
            netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err(),
            "variant {variant}"
        );
    }
    let mut io = NativeBatches::new(vec![packet(control(3, 7, 0))]);
    assert!(netlink::dump_with(&mut io, 18, &[0; 16], 0).is_err());
}

#[test]
fn linux_transport_error_done_overrun_eof_trunc_and_partial_are_errors() {
    for bytes in [
        control(2, 7, -1),
        control(3, 7, -5),
        message(4, 7, &[]),
        Vec::new(),
        message(2, 7, &[0; 4]),
        message(3, 7, &[0; 3]),
    ] {
        let mut io = NativeBatches::new(vec![packet(bytes)]);
        assert!(netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err());
    }
    let mut truncated = packet(control(3, 7, 0));
    truncated.flags = 0x20; // Linux MSG_TRUNC, not Darwin's flag value.
    let mut io = NativeBatches::new(vec![truncated]);
    assert!(netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err());
    let mut io = NativeBatches::new(vec![packet(message(16, 7, &[0; 16]))]);
    assert!(netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err());
    let mut after_done = control(3, 7, 0);
    after_done.extend(message(16, 7, &[0; 16]));
    let mut io = NativeBatches::new(vec![packet(after_done)]);
    assert!(netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err());
}

#[test]
fn linux_transport_rejects_malformed_lengths_alignment_and_missing_multipart() {
    let mut over = message(16, 7, &[0; 16]);
    over[0..4].copy_from_slice(&999_u32.to_ne_bytes());
    let mut short = message(16, 7, &[]);
    short[0..4].copy_from_slice(&15_u32.to_ne_bytes());
    let mut unaligned = message(6000, 7, &[1]);
    unaligned.pop();
    let mut single = message(16, 7, &[0; 16]);
    single[6..8].copy_from_slice(&0_u16.to_ne_bytes());
    for bad in [over, short, unaligned, single, vec![0; 15]] {
        let mut io = NativeBatches::new(vec![packet(bad), packet(control(3, 7, 0))]);
        assert!(netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err());
    }
}

#[test]
fn linux_transport_interruption_on_any_message_discards_partial_retries_only_once() {
    for kind in [16, 3, 6000] {
        let mut interrupted = message(kind, 7, &[0; 16]);
        interrupted[6..8].copy_from_slice(&0x12_u16.to_ne_bytes());
        let mut first = message(16, 7, &[1; 16]);
        first.extend(interrupted);
        let mut second = message(16, 8, &[2; 16]);
        second.extend(control(3, 8, 0));
        let mut io = NativeBatches::new(vec![packet(first), packet(second)]);
        let result = netlink::dump_with(&mut io, 18, &[0; 16], 7).unwrap();
        assert_eq!(result, message(16, 8, &[2; 16]));
        assert_eq!(io.sends.len(), 2);
    }
    let mut io = NativeBatches::new(
        (7..=9)
            .map(|seq| {
                let mut bytes = control(3, seq, 0);
                bytes[6..8].copy_from_slice(&0x12_u16.to_ne_bytes());
                packet(bytes)
            })
            .collect(),
    );
    assert!(netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err());
    assert_eq!(io.sends.len(), 2);
    assert_eq!(io.batches.len(), 1);
}

#[test]
fn linux_transport_deadline_is_whole_dump_across_eintr_unknown_and_retry() {
    let mut io = NativeBatches::new(vec![]);
    let start = io.now;
    io.batches.push_back((
        Duration::from_millis(200),
        Err(io::ErrorKind::Interrupted.into()),
    ));
    io.batches.push_back((
        Duration::from_millis(200),
        Ok(packet(message(6000, 7, &[]))),
    ));
    let mut interrupted = control(3, 7, 0);
    interrupted[6..8].copy_from_slice(&0x12_u16.to_ne_bytes());
    io.batches
        .push_back((Duration::from_millis(200), Ok(packet(interrupted))));
    io.batches
        .push_back((Duration::from_millis(401), Ok(packet(control(3, 8, 0)))));
    assert!(netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err());
    assert!(
        io.deadlines
            .iter()
            .all(|&d| d == start + Duration::from_secs(1))
    );
    assert!(
        io.sends
            .iter()
            .all(|(d, _)| *d == start + Duration::from_secs(1))
    );
    assert_eq!(io.sends.len(), 2);

    let mut io = NativeBatches::new(vec![]);
    io.batches.push_back((
        Duration::from_millis(10),
        Err(io::ErrorKind::Interrupted.into()),
    ));
    io.batches
        .push_back((Duration::from_millis(10), Ok(packet(control(3, 7, 0)))));
    assert!(
        netlink::dump_with(&mut io, 18, &[0; 16], 7)
            .unwrap()
            .is_empty()
    );
    let mut io = NativeBatches::new(vec![]);
    io.batches.extend((0..20).map(|_| {
        (
            Duration::from_millis(100),
            Ok(packet(message(6000, 7, &[]))),
        )
    }));
    assert!(netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err());
    assert_eq!(io.batches.len(), 10); // Unrelated traffic cannot restart deadline.
}

#[test]
fn linux_transport_caps_datagram_before_allocation_and_total_including_unknown() {
    assert_eq!(
        netlink::datagram_capacity(4 * 1024 * 1024).unwrap(),
        4_194_304
    );
    assert!(netlink::datagram_capacity(4 * 1024 * 1024 + 1).is_err());
    assert!(netlink::datagram_capacity(usize::MAX).is_err());
    assert!(netlink::datagram_capacity(0).is_err());
    let mut io = NativeBatches::new(vec![packet(vec![0; 4 * 1024 * 1024 + 1])]);
    assert!(netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err());
    let large = message(6000, 7, &vec![0; 4 * 1024 * 1024 - 16]);
    let mut io = NativeBatches::new((0..5).map(|_| packet(large.clone())).collect());
    let err = netlink::dump_with(&mut io, 18, &[0; 16], 7).unwrap_err();
    assert!(err.0.contains("16 MiB"), "{err:?}");
    assert!(io.batches.is_empty());
}

#[test]
fn linux_transport_completion_must_still_be_inside_original_deadline() {
    let mut io = NativeBatches::new(vec![packet(control(3, 7, 0))]);
    io.clock_tick = Duration::from_millis(250);
    // Request at250ms, receive starts500ms, datagram checked750ms;
    // completion validation must also reject a result reaching1000ms.
    assert!(netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err());
}

#[test]
fn linux_transport_never_sends_mutating_kinds_or_accepts_filtered_inventory() {
    for kind in [0, 16, 17, 19, 20, 21, 23, 65535] {
        let mut io = NativeBatches::new(vec![packet(control(3, 7, 0))]);
        assert!(
            netlink::dump_with(&mut io, kind, &[0; 16], 7).is_err(),
            "kind{kind}"
        );
        assert!(io.sends.is_empty());
    }
    for kind in [16, 3, 6000] {
        let mut filtered = message(kind, 7, &[0; 16]);
        filtered[6..8].copy_from_slice(&0x22_u16.to_ne_bytes());
        let mut io = NativeBatches::new(vec![packet(filtered), packet(control(3, 7, 0))]);
        assert!(netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err());
    }
}

#[test]
fn linux_transport_send_eintr_preserves_deadline_and_other_send_errors_fail() {
    let mut io = NativeBatches::new(vec![packet(control(3, 7, 0))]);
    let start = io.now;
    io.send_script.push_back((
        Duration::from_millis(200),
        Err(io::ErrorKind::Interrupted.into()),
    ));
    assert!(
        netlink::dump_with(&mut io, 18, &[0; 16], 7)
            .unwrap()
            .is_empty()
    );
    assert_eq!(io.sends.len(), 2);
    assert_eq!(io.sends[0].1, io.sends[1].1);
    assert!(
        io.sends
            .iter()
            .all(|(d, _)| *d == start + Duration::from_secs(1))
    );
    let mut io = NativeBatches::new(vec![packet(control(3, 7, 0))]);
    io.send_script
        .push_back((Duration::ZERO, Err(io::ErrorKind::PermissionDenied.into())));
    assert!(netlink::dump_with(&mut io, 18, &[0; 16], 7).is_err());
    assert_eq!(io.batches.len(), 1);
}

#[test]
fn linux_transport_retry_does_not_reset_dump_allocation_budget() {
    let large = message(6000, 7, &vec![0; 4 * 1024 * 1024 - 16]);
    let mut interrupted = large.clone();
    interrupted[6..8].copy_from_slice(&0x12_u16.to_ne_bytes());
    let mut retry = large.clone();
    retry[8..12].copy_from_slice(&8_u32.to_ne_bytes());
    let mut io = NativeBatches::new(vec![
        packet(large),
        packet(interrupted),
        packet(retry.clone()),
        packet(retry.clone()),
        packet(retry),
    ]);
    let error = netlink::dump_with(&mut io, 18, &[0; 16], 7).unwrap_err();
    assert!(error.0.contains("16 MiB"), "{error:?}");
    assert_eq!(io.sends.len(), 2);
    assert!(io.batches.is_empty());
}

fn settings(cmd: u32, count: i8, speed: u32, words: usize) -> Vec<u32> {
    let mut out = vec![0; words];
    out[0] = cmd;
    out[1] = speed;
    let mut bytes = [0; 4];
    bytes[3] = count as u8; // nwords is byte15 in the48-byte header.
    out[3] = u32::from_ne_bytes(bytes);
    out
}

fn legacy(speed: u32) -> Vec<u32> {
    let mut out = vec![0; 11];
    out[0] = 1;
    let mut low = [0; 4];
    low[..2].copy_from_slice(&(speed as u16).to_ne_bytes());
    out[3] = u32::from_ne_bytes(low);
    let mut high = [0; 4];
    high[..2].copy_from_slice(&((speed >> 16) as u16).to_ne_bytes());
    out[7] = u32::from_ne_bytes(high);
    out
}

fn test_id() -> InterfaceId {
    InterfaceId {
        index: 2,
        name: b"eth\xff".to_vec(),
    }
}

struct SettingsIo {
    replies: VecDeque<io::Result<Vec<u32>>>,
    identities: VecDeque<io::Result<InterfaceId>>,
    calls: Vec<(u32, usize, i8)>,
}

impl SettingsIo {
    fn new(replies: Vec<io::Result<Vec<u32>>>) -> Self {
        Self {
            replies: replies.into(),
            identities: vec![Ok(test_id()), Ok(test_id())].into(),
            calls: Vec::new(),
        }
    }
}

impl Access for SettingsIo {
    fn identity(&mut self, name: &[u8]) -> io::Result<InterfaceId> {
        assert_eq!(name, b"eth\xff");
        self.identities.pop_front().unwrap()
    }
    fn query(&mut self, name: &[u8], words: &mut [u32]) -> io::Result<()> {
        assert_eq!(name, b"eth\xff");
        self.calls
            .push((words[0], words.len() * 4, words[3].to_ne_bytes()[3] as i8));
        let reply = self.replies.pop_front().expect("unexpected extra ioctl")?;
        if reply.len() != words.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        words.copy_from_slice(&reply);
        Ok(())
    }
}

#[test]
fn linux_ethtool_successful_negative_handshake_does_not_use_probe_speed() {
    let mut io = SettingsIo::new(vec![
        Ok(settings(0x4c, -3, u32::MAX, 12)),
        Ok(settings(0x4c, 3, 10_000, 21)),
    ]);
    assert_eq!(
        ethtool::speed_with(&mut io, &test_id()),
        Some(10_000_000_000)
    );
    assert_eq!(io.calls, [(0x4c, 48, 0), (0x4c, 84, 3)]);
    assert!(io.identities.is_empty()); // Must recheck identity AFTER both ioctls.
}

#[test]
fn linux_ethtool_handshake_signed_bounds_and_maximum_allocation() {
    assert_eq!(
        ethtool::required_words(&settings(0x4c, -1, 0, 12)),
        Some(15)
    );
    assert_eq!(
        ethtool::required_words(&settings(0x4c, -127, 0, 12)),
        Some(393)
    );
    for count in [-128, 0, 1, 127] {
        assert_eq!(ethtool::required_words(&settings(0x4c, count, 0, 12)), None);
    }
    assert_eq!(ethtool::required_words(&settings(1, -3, 0, 12)), None);
    assert_eq!(
        ethtool::required_words(&settings(0x4c, -3, 0, 12)[..11]),
        None
    );
    let mut io = SettingsIo::new(vec![
        Ok(settings(0x4c, -127, 0, 12)),
        Ok(settings(0x4c, 127, 1, 393)),
    ]);
    assert_eq!(ethtool::speed_with(&mut io, &test_id()), Some(1_000_000));
    assert_eq!(io.calls, [(0x4c, 48, 0), (0x4c, 1572, 127)]);
}

#[test]
fn linux_ethtool_returned_command_count_length_and_speed_sentinels() {
    assert_eq!(
        ethtool::modern_speed(&settings(0x4c, 3, 1000, 21), 3),
        Some(1_000_000_000)
    );
    assert_eq!(
        ethtool::modern_speed(&settings(0x4c, 3, 4_294_967_294, 21), 3),
        Some(4_294_967_294_000_000)
    );
    for words in [
        settings(1, 3, 1000, 21),
        settings(0x4c, 2, 1000, 21),
        settings(0x4c, -3, 1000, 21),
        settings(0x4c, 0, 1000, 21),
        settings(0x4c, 3, 1000, 20),
        settings(0x4c, 3, 0, 21),
        settings(0x4c, 3, u32::MAX, 21),
    ] {
        assert_eq!(ethtool::modern_speed(&words, 3), None);
    }
    assert_eq!(
        ethtool::legacy_speed(&legacy(100_000)),
        Some(100_000_000_000)
    );
    for speed in [0, 65_535, u32::MAX] {
        assert_eq!(ethtool::legacy_speed(&legacy(speed)), None);
    }
    let mut wrong_cmd = legacy(1000);
    wrong_cmd[0] = 0x4c;
    assert_eq!(ethtool::legacy_speed(&wrong_cmd), None);
    assert_eq!(ethtool::legacy_speed(&legacy(1000)[..10]), None);
}

#[test]
fn linux_ethtool_fallback_uses_44byte_legacy_and_failures_are_optional() {
    let mut io = SettingsIo::new(vec![
        Err(io::ErrorKind::Unsupported.into()),
        Ok(legacy(100_000)),
    ]);
    assert_eq!(
        ethtool::speed_with(&mut io, &test_id()),
        Some(100_000_000_000)
    );
    assert_eq!(io.calls, [(0x4c, 48, 0), (1, 44, 0)]);
    for error in [
        io::ErrorKind::Unsupported,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::NotFound,
    ] {
        let mut io = SettingsIo::new(vec![Err(error.into()), Err(error.into())]);
        assert_eq!(ethtool::speed_with(&mut io, &test_id()), None);
    }
    let mut io = SettingsIo::new(vec![
        Ok(settings(0x4c, -3, 0, 12)),
        Err(io::ErrorKind::Unsupported.into()),
        Ok(legacy(1000)),
    ]);
    assert_eq!(
        ethtool::speed_with(&mut io, &test_id()),
        Some(1_000_000_000)
    );
}

#[test]
fn linux_ethtool_changed_identity_and_invalid_names_cannot_attach_speed() {
    for before in [true, false] {
        for changed in [
            InterfaceId {
                index: 3,
                ..test_id()
            },
            InterfaceId {
                name: b"renamed".to_vec(),
                ..test_id()
            },
        ] {
            let mut io = SettingsIo::new(vec![
                Ok(settings(0x4c, -1, 0, 12)),
                Ok(settings(0x4c, 1, 1000, 15)),
            ]);
            io.identities[usize::from(!before)] = Ok(changed);
            assert_eq!(ethtool::speed_with(&mut io, &test_id()), None);
            if before {
                assert!(io.calls.is_empty());
            }
        }
    }
    for name in [Vec::new(), vec![b'a'; 16], b"bad\0name".to_vec()] {
        let mut io = SettingsIo::new(vec![]);
        let id = InterfaceId { name, ..test_id() };
        assert_eq!(ethtool::speed_with(&mut io, &id), None);
        assert!(io.calls.is_empty());
    }
    let mut io = SettingsIo::new(vec![]);
    assert_eq!(
        ethtool::speed_with(
            &mut io,
            &InterfaceId {
                index: 0,
                ..test_id()
            }
        ),
        None
    );
}

#[test]
fn linux_snapshot_native_boundary_ignores_matching_wrong_view_values() {
    // A paired wrong-view sysfs fixture is NOT an eligible production input.
    // This exercises the real socket-result assembly boundary, not a file mock.
    let wrong_view = (test_id(), 999_999_u64, 888_888_u64, 777_000_000_u64);
    let stats: Vec<u8> = [0_u64, 0, 4_294_967_396, 8_589_934_792]
        .into_iter()
        .flat_map(u64::to_ne_bytes)
        .collect();
    for native_present in [true, false] {
        let extra = if native_present {
            attr(23, &stats)
        } else {
            vec![]
        };
        let mut driver = SettingsIo::new(if native_present {
            vec![
                Ok(settings(0x4c, -1, 0, 12)),
                Ok(settings(0x4c, 1, 10_000, 15)),
            ]
        } else {
            vec![
                Err(io::ErrorKind::Unsupported.into()),
                Err(io::ErrorKind::Unsupported.into()),
            ]
        });
        let snapshot = super::collect_with(
            |kind, payload| match kind {
                18 => {
                    assert_eq!(payload, &[0; 16]);
                    Ok(link(2, b"eth\xff\0", Some(2), &extra))
                }
                22 => {
                    assert_eq!(payload, &[0; 8]);
                    Ok(address(2, 2, 24, 0, &attr(2, &[192, 0, 2, 1])))
                }
                _ => panic!("unexpected dump"),
            },
            |id| ethtool::speed_with(&mut driver, id),
        )
        .unwrap();
        let item = &snapshot.interfaces[0];
        assert_eq!(item.id, wrong_view.0);
        assert_eq!(item.state, State::Down);
        assert_eq!(
            item.speed_bps,
            if native_present {
                Some(10_000_000_000)
            } else {
                None
            }
        );
        assert_ne!(item.speed_bps, Some(wrong_view.3));
        if native_present {
            let counters = item.counters.as_ref().unwrap();
            assert_eq!(
                (counters.rx_bytes, counters.tx_bytes),
                (Some(4_294_967_396), Some(8_589_934_792))
            );
            assert_ne!(
                (counters.rx_bytes, counters.tx_bytes),
                (Some(wrong_view.1), Some(wrong_view.2))
            );
        } else {
            assert!(item.counters.is_none());
        }
        assert_eq!(item.addresses.len(), 1);
    }
}

#[test]
fn linux_snapshot_address_dump_failure_is_explicit_inventory_error() {
    let result = super::collect_with(
        |kind, _| {
            if kind == 18 {
                Ok(link(2, b"a\0", None, &[]))
            } else {
                Err(CollectError("address transport failed".into()))
            }
        },
        |_| panic!("must not query speeds after inventory failure"),
    );
    assert!(result.unwrap_err().0.contains("address transport failed"));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_snapshot_native() {
    use std::collections::BTreeSet;
    let before = Instant::now();
    let snapshot = super::snapshot().unwrap();
    let after = Instant::now();
    let mut indices = BTreeSet::new();
    for item in &snapshot.interfaces {
        assert!(item.id.index > 0 && indices.insert(item.id.index));
        assert!(!item.id.name.is_empty());
        if let Some(counters) = &item.counters {
            assert!(before <= counters.at && counters.at <= after);
            assert!(counters.rx_bytes.is_some() && counters.tx_bytes.is_some());
        }
        for address in &item.addresses {
            assert!(
                address
                    .prefix
                    .is_none_or(|p| p <= if address.ip.is_ipv4() { 32 } else { 128 })
            );
            if let Some(scope) = address.scope_id {
                assert_eq!(scope, item.id.index);
                assert!(address.ip.is_ipv6());
            }
        }
    }
    assert!(
        snapshot
            .interfaces
            .iter()
            .any(|item| item.id.name == b"lo" && item.addresses.iter().any(|a| a.ip.is_loopback()))
    );
    let speeds: Vec<u64> = snapshot
        .interfaces
        .iter()
        .filter_map(|i| i.speed_bps)
        .collect();
    let wide = snapshot
        .interfaces
        .iter()
        .filter(|i| {
            i.counters.as_ref().is_some_and(|c| {
                c.rx_bytes.is_some_and(|b| b > u64::from(u32::MAX))
                    || c.tx_bytes.is_some_and(|b| b > u64::from(u32::MAX))
            })
        })
        .count();
    eprintln!(
        "native snapshot: interfaces={}, counters={}, counters_above_32bit={}, driver_speeds_bps={speeds:?}; loopback with assigned address present",
        snapshot.interfaces.len(),
        snapshot
            .interfaces
            .iter()
            .filter(|i| i.counters.is_some())
            .count(),
        wide
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_transport_native_socket_is_bound_nonblocking_cloexec_and_owned() {
    use std::{
        mem,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
    };
    let mut socket = netlink::native::RouteSocket::open().unwrap();
    let fd = socket.fd.as_raw_fd();
    // SAFETY: fcntl queries a live borrowed descriptor; no pointer arguments.
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK,
        0
    );
    // SAFETY: the descriptor is live, and F_GETFD only reads its flags.
    assert_ne!(
        unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    // SAFETY: sockaddr_nl consists of integers/padding; zero is valid.
    let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
    let mut len = mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: initialized address and length buffers are writable for their
    // declared sizes; the socket remains borrowed and owned by RouteSocket.
    assert_eq!(
        unsafe {
            libc::getsockname(
                fd,
                (&mut address as *mut libc::sockaddr_nl).cast(),
                &mut len,
            )
        },
        0
    );
    assert_eq!(address.nl_family, libc::AF_NETLINK as u16);
    assert!(address.nl_pid > 0);
    assert_eq!(address.nl_groups, 0);
    // Move the tested owner onto an unusually high descriptor to avoid races
    // with ordinary parallel-test descriptor reuse after drop.
    // SAFETY: F_DUPFD_CLOEXEC returns a new independently owned descriptor.
    let high = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 128) };
    assert!(high >= 128);
    // SAFETY: successful fcntl above returned sole ownership of this new fd.
    let old = mem::replace(&mut socket.fd, unsafe { OwnedFd::from_raw_fd(high) });
    drop(old);
    drop(socket);
    // SAFETY: F_GETFD accepts an invalid descriptor and reports EBADF; it does
    // not dereference memory or transfer ownership.
    assert_eq!(unsafe { libc::fcntl(high, libc::F_GETFD) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
}

fn route(family: u8, prefix: u8, table: u8, kind: u8, attrs: &[u8]) -> Vec<u8> {
    // Linux rtmsg: 12 bytes, followed by four-byte-aligned rtattrs.
    let mut payload = vec![family, prefix, 0, 0, table, 4, 0, kind, 0, 0, 0, 0];
    payload.extend(attrs);
    message(24, 7, &payload) // RTM_NEWROUTE
}

fn inline_hop(index: i32, flags: u8, attrs: &[u8]) -> Vec<u8> {
    let len = 8 + attrs.len();
    let mut bytes = u16::try_from(len).unwrap().to_ne_bytes().to_vec();
    bytes.extend([flags, 0]); // rtnh_flags, rtnh_hops (weight, not member count)
    bytes.extend(index.to_ne_bytes());
    bytes.extend(attrs);
    bytes.resize((len + 3) & !3, 0);
    bytes
}

fn route_fixtures() -> (Vec<u8>, Vec<u8>) {
    let mut main = attr(4, &2_u32.to_ne_bytes());
    main.extend(attr(5, &[192, 0, 2, 1])); // Gateway is network-order address bytes.
    let mut v4 = route(2, 0, 254, 1, &main);
    let mut policy = attr(15, &100_u32.to_ne_bytes()); // RTA_TABLE overrides header.
    policy.extend(attr(4, &7_u32.to_ne_bytes()));
    v4.extend(route(2, 0, 0, 1, &policy));
    v4.extend(route(2, 0, 100, 1, &attr(4, &11_u32.to_ne_bytes()))); // No gateway.

    let mut multipath = inline_hop(
        7,
        0,
        &attr(
            5,
            &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
    );
    multipath.extend(inline_hop(9, 0, &[]));
    let v6 = route(10, 0, 100, 1, &attr(9, &multipath));
    (v4, v6)
}

#[test]
fn linux_routes_all_tables_both_families_inline_and_gateway_free_defaults() {
    let (v4, v6) = route_fixtures();
    assert_eq!(
        routes::decode(&v4, &BTreeMap::new()),
        Coverage::Complete(BTreeSet::from([2, 7, 11]))
    );
    assert_eq!(
        routes::decode(&v6, &BTreeMap::new()),
        Coverage::Complete(BTreeSet::from([7, 9]))
    );
    let mut unaligned = vec![0xff];
    unaligned.extend(v6);
    assert_eq!(
        routes::decode(&unaligned[1..], &BTreeMap::new()),
        Coverage::Complete(BTreeSet::from([7, 9]))
    );
}

#[test]
fn linux_routes_exclude_nondefaults_nonforwarding_and_dead_linkdown_members() {
    let mut bytes = route(2, 24, 254, 1, &attr(4, &30_u32.to_ne_bytes()));
    for kind in [2, 3, 4, 5, 6, 7, 8, 9, 10, 11] {
        bytes.extend(route(2, 0, 254, kind, &attr(4, &31_u32.to_ne_bytes())));
    }
    for flags in [1_u32, 16] {
        let mut dead = route(2, 0, 254, 1, &attr(4, &32_u32.to_ne_bytes()));
        dead[24..28].copy_from_slice(&flags.to_ne_bytes());
        bytes.extend(dead);
    }
    let mut multipath = inline_hop(7, 4 | 8, &attr(6000, &[0x55]));
    multipath.extend(inline_hop(8, 1, &[]));
    multipath.extend(inline_hop(9, 16, &[]));
    bytes.extend(route(10, 0, 254, 1, &attr(9, &multipath)));
    assert_eq!(
        routes::decode(&bytes, &BTreeMap::new()),
        Coverage::Complete(BTreeSet::from([7]))
    );
}

#[test]
fn linux_routes_source_specific_zero_destination_and_optional_attributes() {
    let mut attrs = attr(1, &[0; 16]);
    attrs.extend(attr(
        2,
        &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    ));
    attrs.extend(attr(15, &70_000_u32.to_ne_bytes()));
    attrs.extend(attr(4, &9_u32.to_ne_bytes()));
    attrs.extend(attr(6000, &[0xff]));
    let mut bytes = route(10, 0, 254, 1, &attrs);
    bytes[18] = 64; // rtm_src_len: still a configured destination default.
    assert_eq!(
        routes::decode(&bytes, &BTreeMap::new()),
        Coverage::Complete(BTreeSet::from([9]))
    );
    let mut nonzero = attr(1, &[192, 0, 2, 0]);
    nonzero.extend(attr(4, &12_u32.to_ne_bytes()));
    assert_eq!(
        routes::decode(&route(2, 0, 254, 1, &nonzero), &BTreeMap::new()),
        Coverage::Complete(BTreeSet::new())
    );
    assert_eq!(
        routes::decode(&[], &BTreeMap::new()),
        Coverage::Complete(BTreeSet::new())
    );
}

#[test]
fn linux_routes_malformed_wire_and_missing_forwarding_are_explicit_partial() {
    let valid = route(2, 0, 254, 1, &attr(4, &2_u32.to_ne_bytes()));
    let malformed = [
        message(24, 7, &[2; 11]),
        route(2, 0, 254, 1, &[3, 0, 4, 0]), // attr length < header
        route(2, 0, 254, 1, &attr(4, &[2; 3])),
        route(2, 0, 254, 1, &attr(15, &[0; 3])),
        route(2, 0, 254, 1, &attr(1, &[0; 16])), // IPv4 DST must be four bytes.
        route(2, 0, 254, 1, &attr(9, &[8, 0, 0, 0, 7, 0, 0])), // short rtnexthop
        route(2, 0, 254, 1, &attr(9, &[7, 0, 0, 0, 7, 0, 0, 0])),
        route(2, 0, 254, 1, &attr(9, &inline_hop(-1, 0, &[]))),
        route(2, 0, 254, 1, &attr(9, &inline_hop(0, 0, &[]))),
        route(2, 0, 254, 1, &attr(4, &0_u32.to_ne_bytes())),
        route(2, 0, 254, 1, &attr(4, &u32::MAX.to_ne_bytes())),
        route(2, 0, 254, 1, &[]),
        route(99, 0, 254, 1, &attr(4, &8_u32.to_ne_bytes())),
        message(2, 7, &(-22_i32).to_ne_bytes()), // NLMSG_ERROR cannot mean no defaults.
        vec![0; 15],
    ];
    for bad in malformed {
        let mut bytes = valid.clone();
        bytes.extend(&bad);
        assert!(
            matches!(routes::decode(&bytes, &BTreeMap::new()), Coverage::Incomplete { value, reason } if value == BTreeSet::from([2]) && !reason.is_empty()),
            "bad wire: {bad:?}"
        );
    }
    // Retain already decoded inline members if a later record is truncated.
    let mut partial = inline_hop(7, 0, &[]);
    partial.extend([8, 0, 0]);
    assert!(
        matches!(routes::decode(&route(10, 0, 254, 1, &attr(9, &partial)), &BTreeMap::new()), Coverage::Incomplete { value, .. } if value == BTreeSet::from([7]))
    );
}

#[test]
fn linux_routes_query_constructs_family_all_table_dumps_and_skips_unneeded_objects() {
    let (v4, v6) = route_fixtures();
    let mut calls = Vec::new();
    let result = super::defaults_with(|kind, payload| {
        calls.push((kind, payload.to_vec()));
        match calls.len() {
            1 => Ok(v4.clone()),
            2 => Ok(v6.clone()),
            _ => panic!("direct/inline routes must not query objects"),
        }
    });
    assert_eq!(
        calls,
        vec![
            (26, vec![2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (26, vec![10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        ]
    );
    assert_eq!(result.v4, Coverage::Complete(BTreeSet::from([2, 7, 11])));
    assert_eq!(result.v6, Coverage::Complete(BTreeSet::from([7, 9])));
}

#[test]
fn linux_routes_query_failures_are_per_family_not_empty_success() {
    let mut calls = 0;
    let result = super::defaults_with(|kind, payload| {
        calls += 1;
        assert_eq!(kind, 26);
        match payload[0] {
            2 => Err(CollectError("denied".into())),
            10 => Ok(route(10, 0, 254, 1, &attr(4, &9_u32.to_ne_bytes()))),
            _ => panic!("wrong family"),
        }
    });
    assert_eq!(calls, 2);
    assert_eq!(
        result.v4,
        Coverage::Unavailable("IPv4 route dump: denied".into())
    );
    assert_eq!(result.v6, Coverage::Complete(BTreeSet::from([9])));
}

fn nh_object(family: u8, flags: u32, id: u32, attrs: &[u8]) -> Vec<u8> {
    let mut payload = vec![family, 0, 4, 0];
    payload.extend(flags.to_ne_bytes()); // nhmsg is eight bytes, not rtmsg.
    payload.extend(attr(1, &id.to_ne_bytes()));
    payload.extend(attrs);
    message(104, 7, &payload)
}

fn nh_group(ids: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for id in ids {
        bytes.extend(id.to_ne_bytes());
        bytes.extend([0xfe, 0, 0, 0]); // ID + weight/reserved, NOT nested attrs.
    }
    attr(2, &bytes)
}

fn hop_fixtures() -> BTreeMap<u32, nexthops::Hop> {
    use nexthops::Hop;
    BTreeMap::from([
        (
            10,
            Hop::Device {
                index: 7,
                usable: true,
            },
        ),
        (
            11,
            Hop::Device {
                index: 9,
                usable: true,
            },
        ),
        (20, Hop::Group(vec![10, 11])),
    ])
}

#[test]
fn linux_nexthops_members_direct_group_and_dead_devices() {
    let mut hops = hop_fixtures();
    assert_eq!(
        nexthops::members(20, &hops),
        Coverage::Complete(BTreeSet::from([7, 9]))
    );
    assert_eq!(
        nexthops::members(10, &hops),
        Coverage::Complete(BTreeSet::from([7]))
    );
    hops.insert(
        11,
        nexthops::Hop::Device {
            index: 9,
            usable: false,
        },
    );
    assert_eq!(
        nexthops::members(20, &hops),
        Coverage::Complete(BTreeSet::from([7]))
    );
    assert_eq!(
        nexthops::members(11, &hops),
        Coverage::Complete(BTreeSet::new())
    );
}

#[test]
fn linux_nexthops_missing_unsupported_and_cycles_preserve_known_members() {
    use nexthops::Hop;
    let mut hops = hop_fixtures();
    hops.insert(20, Hop::Group(vec![10, 404, 11]));
    assert_eq!(
        nexthops::members(20, &hops),
        Coverage::Incomplete {
            value: BTreeSet::from([7, 9]),
            reason: "missing nexthop ID 404".into()
        }
    );
    hops.insert(20, Hop::Group(vec![10, 21]));
    hops.insert(21, Hop::Group(vec![11, 20]));
    assert_eq!(
        nexthops::members(20, &hops),
        Coverage::Incomplete {
            value: BTreeSet::from([7, 9]),
            reason: "nexthop cycle at ID 20".into()
        }
    );
    hops.insert(21, Hop::Unsupported);
    assert_eq!(
        nexthops::members(20, &hops),
        Coverage::Incomplete {
            value: BTreeSet::from([7]),
            reason: "unsupported nexthop ID 21".into()
        }
    );
    // Shared subgroups are not cycles and must not create spurious warnings.
    hops.insert(20, Hop::Group(vec![21, 22]));
    hops.insert(21, Hop::Group(vec![10, 11]));
    hops.insert(22, Hop::Group(vec![10, 11]));
    assert_eq!(
        nexthops::members(20, &hops),
        Coverage::Complete(BTreeSet::from([7, 9]))
    );
}

#[test]
fn linux_nexthops_depth_16_and_visited_4096_limits_are_explicit() {
    use nexthops::Hop;
    let mut hops = BTreeMap::new();
    for id in 1..16 {
        hops.insert(id, Hop::Group(vec![id + 1]));
    }
    hops.insert(
        16,
        Hop::Device {
            index: 7,
            usable: true,
        },
    );
    assert_eq!(
        nexthops::members(1, &hops),
        Coverage::Complete(BTreeSet::from([7]))
    );
    hops.insert(16, Hop::Group(vec![17]));
    hops.insert(
        17,
        Hop::Device {
            index: 9,
            usable: true,
        },
    );
    hops.insert(1, Hop::Group(vec![100, 2]));
    hops.insert(
        100,
        Hop::Device {
            index: 7,
            usable: true,
        },
    );
    assert_eq!(
        nexthops::members(1, &hops),
        Coverage::Incomplete {
            value: BTreeSet::from([7]),
            reason: "nexthop depth limit (16) reached".into()
        }
    );

    let mut hops = BTreeMap::from([(1, Hop::Group((2..=4096).collect()))]);
    for id in 2..=4096 {
        hops.insert(
            id,
            Hop::Device {
                index: 7,
                usable: true,
            },
        );
    }
    assert_eq!(
        nexthops::members(1, &hops),
        Coverage::Complete(BTreeSet::from([7]))
    );
    hops.insert(1, Hop::Group((2..=4097).collect()));
    hops.insert(
        4097,
        Hop::Device {
            index: 9,
            usable: true,
        },
    );
    assert_eq!(
        nexthops::members(1, &hops),
        Coverage::Incomplete {
            value: BTreeSet::from([7]),
            reason: "nexthop visited-ID limit (4096) reached".into()
        }
    );
}

#[test]
fn linux_nexthops_wire_flat_mpath_resilient_groups_and_flags() {
    let mut bytes = nh_object(2, 0, 10, &attr(5, &7_u32.to_ne_bytes()));
    bytes.extend(nh_object(10, 0, 11, &attr(5, &9_u32.to_ne_bytes())));
    bytes.extend(nh_object(0, 0, 20, &nh_group(&[10, 11])));
    let mut resilient = nh_group(&[10, 11]);
    resilient.extend(attr(3, &1_u16.to_ne_bytes()));
    resilient.extend(attr(12 | 0x8000, &attr(1, &64_u16.to_ne_bytes())));
    resilient.extend(attr(6000, &[0xff]));
    bytes.extend(nh_object(0, 0, 21, &resilient));
    bytes.extend(nh_object(2, 1, 30, &attr(5, &17_u32.to_ne_bytes())));
    bytes.extend(nh_object(10, 16, 31, &attr(5, &19_u32.to_ne_bytes())));
    bytes.extend(nh_object(0, 0, 32, &attr(4, &[]))); // Blackhole is known nonforwarding.
    let Coverage::Complete(hops) = nexthops::decode(&bytes) else {
        panic!("valid UAPI dump must decode");
    };
    assert_eq!(
        nexthops::members(20, &hops),
        Coverage::Complete(BTreeSet::from([7, 9]))
    );
    assert_eq!(
        nexthops::members(21, &hops),
        Coverage::Complete(BTreeSet::from([7, 9]))
    );
    for id in [30, 31, 32] {
        assert_eq!(
            nexthops::members(id, &hops),
            Coverage::Complete(BTreeSet::new())
        );
    }
}

#[test]
fn linux_nexthops_malformed_arrays_keep_known_ids_with_incomplete_warning() {
    let mut bytes = nh_object(2, 0, 10, &attr(5, &7_u32.to_ne_bytes()));
    let mut group = 10_u32.to_ne_bytes().to_vec();
    group.extend([0, 0, 0, 0, 0xff]); // One complete eight-byte entry + malformed tail.
    bytes.extend(nh_object(0, 0, 20, &attr(2, &group)));
    let Coverage::Incomplete {
        value: hops,
        reason,
    } = nexthops::decode(&bytes)
    else {
        panic!("malformed array must be explicit");
    };
    assert_eq!(reason, "malformed nexthop group 20 array");
    assert_eq!(
        nexthops::members(20, &hops),
        Coverage::Complete(BTreeSet::from([7]))
    );
    let result = super::defaults_with(|kind, payload| match (kind, payload[0]) {
        (26, 2) => Ok(route(2, 0, 254, 1, &attr(30, &20_u32.to_ne_bytes()))),
        (26, 10) => Ok(Vec::new()),
        (106, 0) => Ok(bytes.clone()),
        _ => panic!("unexpected dump"),
    });
    assert_eq!(
        result.v4,
        Coverage::Incomplete {
            value: BTreeSet::from([7]),
            reason: "nexthop dump: malformed nexthop group 20 array".into()
        }
    );
    assert_eq!(result.v6, Coverage::Complete(BTreeSet::new()));
}

#[test]
fn linux_nexthops_malformed_objects_and_unsupported_objects_cannot_disappear() {
    let valid = nh_object(2, 0, 10, &attr(5, &7_u32.to_ne_bytes()));
    for bad in [
        message(104, 7, &[0; 7]),
        nh_object(2, 0, 11, &attr(5, &[9; 3])),
        nh_object(0, 0, 20, &attr(2, &[])),
        nh_object(0, 0, 20, &attr(3, &[1])),
        nh_object(2, 0, 0, &attr(5, &9_u32.to_ne_bytes())),
        message(104, 7, &[2, 0, 4, 0, 0, 0, 0, 0, 3, 0, 1, 0]),
        vec![0; 15],
    ] {
        let mut bytes = valid.clone();
        bytes.extend(&bad);
        assert!(
            matches!(nexthops::decode(&bytes), Coverage::Incomplete { value, reason } if value.get(&10) == Some(&nexthops::Hop::Device { index: 7, usable: true }) && !reason.is_empty()),
            "bad object: {bad:?}"
        );
    }
    let mut unknown_group = nh_group(&[10]);
    unknown_group.extend(attr(3, &2_u16.to_ne_bytes()));
    for object in [
        nh_object(0, 0, 20, &unknown_group),
        nh_object(99, 0, 20, &attr(5, &9_u32.to_ne_bytes())),
        nh_object(0, 0, 20, &attr(11, &[])),
        nh_object(2, 0, 20, &[]),
    ] {
        let hops = match nexthops::decode(&object) {
            Coverage::Complete(hops) | Coverage::Incomplete { value: hops, .. } => hops,
            Coverage::Unavailable(reason) => panic!("unexpected {reason}"),
        };
        assert_eq!(
            nexthops::members(20, &hops),
            Coverage::Incomplete {
                value: BTreeSet::new(),
                reason: "unsupported nexthop ID 20".into()
            }
        );
    }
}

#[test]
fn linux_nexthops_routes_resolve_ids_and_preserve_direct_members_on_missing_ids() {
    let mut bytes = route(2, 0, 254, 1, &attr(4, &2_u32.to_ne_bytes()));
    bytes.extend(route(2, 0, 100, 1, &attr(30, &20_u32.to_ne_bytes())));
    assert_eq!(
        routes::decode(&bytes, &hop_fixtures()),
        Coverage::Complete(BTreeSet::from([2, 7, 9]))
    );
    assert_eq!(
        routes::decode(&bytes, &BTreeMap::new()),
        Coverage::Incomplete {
            value: BTreeSet::from([2]),
            reason: "missing nexthop ID 20".into()
        }
    );
}

#[test]
fn linux_nexthops_query_uses_unfiltered_unspec_object_dump_only_when_referenced() {
    let mut calls = Vec::new();
    let mut objects = nh_object(2, 0, 10, &attr(5, &7_u32.to_ne_bytes()));
    objects.extend(nh_object(10, 0, 11, &attr(5, &9_u32.to_ne_bytes())));
    objects.extend(nh_object(0, 0, 20, &nh_group(&[10, 11])));
    let result = super::defaults_with(|kind, payload| {
        calls.push((kind, payload.to_vec()));
        match (kind, payload[0]) {
            (26, 2) | (26, 10) => Ok(route(
                payload[0],
                0,
                100,
                1,
                &attr(30, &20_u32.to_ne_bytes()),
            )),
            (106, 0) => Ok(objects.clone()),
            _ => panic!("unexpected dump"),
        }
    });
    assert_eq!(
        calls,
        vec![
            (26, vec![2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (26, vec![10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            (106, vec![0; 8])
        ]
    );
    assert_eq!(result.v4, Coverage::Complete(BTreeSet::from([7, 9])));
    assert_eq!(result.v6, Coverage::Complete(BTreeSet::from([7, 9])));

    // Nondefault and nonforwarding routes must not trigger optional dumps.
    let mut ignored = route(2, 24, 254, 1, &attr(30, &20_u32.to_ne_bytes()));
    ignored.extend(route(2, 0, 254, 6, &attr(30, &20_u32.to_ne_bytes())));
    let result = super::defaults_with(|kind, _| {
        assert_eq!(kind, 26);
        Ok(ignored.clone())
    });
    assert_eq!(result.v4, Coverage::Complete(BTreeSet::new()));
    assert_eq!(result.v6, Coverage::Complete(BTreeSet::new()));
}

#[test]
fn linux_nexthops_unavailable_object_dump_is_explicit_only_for_affected_family() {
    let mut v4 = route(2, 0, 254, 1, &attr(4, &2_u32.to_ne_bytes()));
    v4.extend(route(2, 0, 100, 1, &attr(30, &20_u32.to_ne_bytes())));
    let result = super::defaults_with(|kind, payload| match (kind, payload[0]) {
        (26, 2) => Ok(v4.clone()),
        (26, 10) => Ok(route(10, 0, 254, 1, &attr(4, &9_u32.to_ne_bytes()))),
        (106, 0) => Err(CollectError("not supported".into())),
        _ => panic!("unexpected dump"),
    });
    assert_eq!(
        result.v4,
        Coverage::Incomplete {
            value: BTreeSet::from([2]),
            reason: "missing nexthop ID 20; nexthop dump: not supported".into()
        }
    );
    assert_eq!(result.v6, Coverage::Complete(BTreeSet::from([9])));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_routes_native_defaults() {
    let result = super::defaults();
    for (family, coverage) in [("IPv4", result.v4), ("IPv6", result.v6)] {
        eprintln!("native default membership {family}: {coverage:?}");
        match coverage {
            Coverage::Complete(indices) => assert!(indices.iter().all(|index| *index > 0)),
            Coverage::Incomplete { reason, .. } | Coverage::Unavailable(reason) => {
                panic!("native {family} discovery was not complete: {reason}");
            }
        }
    }
}
