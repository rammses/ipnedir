//! Read-only native observations, not fixture or cross-compilation evidence.
use std::{collections::BTreeSet, time::Instant};

use ipnedir::{
    model::{Coverage, Snapshot},
    platform::{Collector, NativeCollector},
};

fn check_inventory(snapshot: &Snapshot, started: Instant, finished: Instant) {
    let mut indices = BTreeSet::new();
    let mut names = BTreeSet::new();
    for interface in &snapshot.interfaces {
        assert!(interface.id.index > 0 && indices.insert(interface.id.index));
        assert!(!interface.id.name.is_empty() && interface.id.name.len() < libc::IFNAMSIZ);
        assert!(!interface.id.name.contains(&0));
        assert!(
            names.insert(interface.id.name.clone()),
            "duplicate raw name"
        );
        assert!(interface.mtu.is_none_or(|mtu| mtu > 0));
        assert!(interface.speed_bps.is_none_or(|speed| speed > 0));
        if let Some(counters) = &interface.counters {
            assert!(started <= counters.at && counters.at <= finished);
            // A narrowing of either owned field is a compile failure, not an
            // assertion that u32-sized traffic happens to fit today's host.
            let _: Option<u64> = counters.rx_bytes;
            let _: Option<u64> = counters.tx_bytes;
        }
        for address in &interface.addresses {
            assert!(
                address
                    .prefix
                    .is_none_or(|prefix| { prefix <= if address.ip.is_ipv4() { 32 } else { 128 } })
            );
            if let Some(scope) = address.scope_id {
                assert_eq!(scope, interface.id.index);
                assert!(address.ip.is_ipv6());
            }
        }
    }
    assert!(
        snapshot.interfaces.iter().any(|interface| {
            interface
                .addresses
                .iter()
                .any(|address| address.ip.is_loopback())
        }),
        "native environment must have an addressed loopback"
    );
}

#[test]
fn native_owned_snapshots_are_sane_twice() {
    #[cfg(target_os = "macos")]
    verify_selected_sdk();

    let mut collector = NativeCollector;
    // The second collection also demonstrates that no getifaddrs/netlink-owned
    // storage escapes into the first owned result. No topology stability or
    // traffic delta is required, and unsupported optional values remain valid.
    let started = Instant::now();
    let first = collector.snapshot().expect("first native inventory");
    let middle = Instant::now();
    let second = collector.snapshot().expect("second native inventory");
    let finished = Instant::now();
    check_inventory(&first, started, middle);
    check_inventory(&second, middle, finished);
    for (sample, snapshot) in [(1, first), (2, second)] {
        let counters = snapshot
            .interfaces
            .iter()
            .filter(|i| i.counters.is_some())
            .count();
        let wide = snapshot
            .interfaces
            .iter()
            .filter(|i| {
                i.counters.as_ref().is_some_and(|c| {
                    c.rx_bytes.is_some_and(|v| v > u64::from(u32::MAX))
                        || c.tx_bytes.is_some_and(|v| v > u64::from(u32::MAX))
                })
            })
            .count();
        let speeds: Vec<_> = snapshot
            .interfaces
            .iter()
            .filter_map(|i| i.speed_bps)
            .collect();
        eprintln!(
            "native sample {sample}: interfaces={}, valid_counters={counters}, above_32bit={wide}, driver_speeds_bps={speeds:?}",
            snapshot.interfaces.len()
        );
        if wide == 0 {
            eprintln!(
                "no native counter above 2^32 observed; width remains an ABI/fixture gate, not a generated-traffic observation"
            );
        }
        if speeds.is_empty() {
            eprintln!(
                "driver speed not corroborated on this environment (optional unsupported data)"
            );
        }
    }
}

#[test]
fn native_defaults_preserve_explicit_per_family_coverage() {
    #[cfg(target_os = "macos")]
    verify_selected_sdk();

    let defaults = NativeCollector.defaults();
    for (family, coverage) in [("IPv4", defaults.v4), ("IPv6", defaults.v6)] {
        match &coverage {
            Coverage::Complete(indices) => assert!(indices.iter().all(|index| *index > 0)),
            Coverage::Incomplete { value, reason } => {
                assert!(value.iter().all(|index| *index > 0));
                assert!(!reason.is_empty());
            }
            Coverage::Unavailable(reason) => assert!(!reason.is_empty()),
        }
        eprintln!("native {family} defaults: {coverage:?}");
    }
    eprintln!(
        "no assertion of Internet, a default route, Wi-Fi, or physical Ethernet; scoped/point-to-point behavior requires an environment that actually exposes it"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_native_loopback_exposes_owned_64_bit_socket_counters() {
    let snapshot = NativeCollector.snapshot().expect("native Linux inventory");
    let loopback = snapshot
        .interfaces
        .iter()
        .find(|i| i.id.name == b"lo")
        .expect("Linux loopback");
    let counters = loopback
        .counters
        .as_ref()
        .expect("native RTM_GETLINK/IFLA_STATS64 loopback counters");
    let rx: u64 = counters.rx_bytes.expect("64-bit RX");
    let tx: u64 = counters.tx_bytes.expect("64-bit TX");
    assert!(loopback.mtu.is_some_and(|mtu| mtu > 0));
    eprintln!(
        "native Linux loopback: RX={rx}, TX={tx}; actual netlink/ioctl provenance and absence of wrong-view sysfs fallback are separately gated by CI traces"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_selected_sdk_headers_match_native_contract() {
    verify_selected_sdk();
}

#[cfg(target_os = "macos")]
fn verify_selected_sdk() {
    use std::{
        fs,
        mem::{offset_of, size_of},
        path::Path,
        process::Command,
        sync::OnceLock,
    };

    static CHECKED: OnceLock<()> = OnceLock::new();
    CHECKED.get_or_init(|| {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/native-evidence");
        fs::create_dir_all(&directory).expect("SDK evidence directory");
        let sdk = Command::new("xcrun")
            .args(["--sdk", "macosx", "--show-sdk-path"])
            .output()
            .expect("selected native SDK required (no installation attempted)");
        assert!(
            sdk.status.success(),
            "xcrun SDK selection failed: {}",
            String::from_utf8_lossy(&sdk.stderr)
        );
        let sdk = String::from_utf8(sdk.stdout).unwrap();
        let sdk = sdk.trim();
        assert!(Path::new(sdk).is_absolute());
        fs::write(
            directory.join("sdk-selection.txt"),
            format!("selected SDK: {sdk}\nMACOSX_DEPLOYMENT_TARGET=15.0\n"),
        )
        .unwrap();
        let source = directory.join("sdk-probe.c");
        let executable = directory.join("sdk-probe");
        fs::write(&source, SDK_PROBE).unwrap();
        let build = Command::new("xcrun")
            .args([
                "--sdk",
                "macosx",
                "clang",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-mmacosx-version-min=15.0",
                "-isysroot",
            ])
            .arg(sdk)
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .expect("native SDK C compiler required");
        fs::write(
            directory.join("sdk-probe-build.log"),
            [&build.stdout[..], &build.stderr[..]].concat(),
        )
        .unwrap();
        assert!(
            build.status.success(),
            "actual selected SDK ABI mismatch or compiler failure, BEFORE adapter calls: {}",
            String::from_utf8_lossy(&build.stderr)
        );
        let values = Command::new(&executable)
            .output()
            .expect("execute native SDK/layout probe");
        assert!(values.status.success(), "SDK probe failed");
        fs::write(directory.join("sdk-probe-values.txt"), &values.stdout).unwrap();
        let values = String::from_utf8(values.stdout).unwrap();
        let measured: std::collections::BTreeMap<_, _> = values
            .lines()
            .map(|line| {
                let (key, value) = line.split_once('=').expect("SDK key=value output");
                (
                    key,
                    value.parse::<usize>().expect("SDK numeric measurement"),
                )
            })
            .collect();
        // These are measurements from the actually selected C headers, NOT a
        // comparison of Rust libc to another assumed Rust layout.
        for (key, rust) in [
            ("ifaddrs.size", size_of::<libc::ifaddrs>()),
            ("ifaddrs.next", offset_of!(libc::ifaddrs, ifa_next)),
            ("ifaddrs.name", offset_of!(libc::ifaddrs, ifa_name)),
            ("ifaddrs.flags", offset_of!(libc::ifaddrs, ifa_flags)),
            ("ifaddrs.addr", offset_of!(libc::ifaddrs, ifa_addr)),
            ("ifaddrs.netmask", offset_of!(libc::ifaddrs, ifa_netmask)),
            ("ifaddrs.dstaddr", offset_of!(libc::ifaddrs, ifa_dstaddr)),
            ("ifaddrs.data", offset_of!(libc::ifaddrs, ifa_data)),
            ("ifmibdata.size", size_of::<libc::ifmibdata>()),
            ("if_data64.size", size_of::<libc::if_data64>()),
            ("rt_msghdr.size", size_of::<libc::rt_msghdr>()),
            ("SIOCGIFMEDIA", libc::SIOCGIFMEDIA as usize),
            ("SIOCGIFXMEDIA", libc::SIOCGIFXMEDIA as usize),
        ] {
            assert_eq!(measured.get(key), Some(&rust), "actual SDK vs libc: {key}");
        }
        eprintln!(
            "selected SDK {sdk}; compiled/ran native header probe before adapter calls:\n{values}"
        );
    });
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_native_loopback_counters_match_read_only_ifmib() {
    verify_selected_sdk();

    fn reference(index: u32) -> (u64, u64, u32) {
        // SAFETY: ifmibdata consists of integer/byte fields, all-zero is valid;
        // the selected SDK probe above validated its packed size/offsets first.
        let mut data: libc::ifmibdata = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&data);
        let mut mib = [
            libc::CTL_NET,
            libc::PF_LINK,
            libc::NETLINK_GENERIC,
            libc::IFMIB_IFDATA,
            i32::try_from(index).unwrap(),
            libc::IFDATA_GENERAL,
        ];
        // SAFETY: MIB, output and length point at live, correctly sized storage;
        // null newp and zero newlen make this an exclusively read-only sysctl.
        let result = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                (&mut data as *mut libc::ifmibdata).cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        assert_eq!(
            result,
            0,
            "native loopback IFMIB reference: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(length, std::mem::size_of_val(&data));
        let name: Vec<_> = data
            .ifmd_name
            .into_iter()
            .map(|b| b as u8)
            .take_while(|b| *b != 0)
            .collect();
        assert_eq!(name, b"lo0");
        // Packed fields are copied by value, never borrowed.
        let counters = data.ifmd_data;
        (counters.ifi_ibytes, counters.ifi_obytes, counters.ifi_mtu)
    }

    let name = c"lo0";
    // SAFETY: literal is a valid, NUL-terminated C string.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    assert_ne!(index, 0);
    let before = reference(index);
    let snapshot = NativeCollector.snapshot().expect("native Darwin inventory");
    let after = reference(index);
    let loopback = snapshot
        .interfaces
        .iter()
        .find(|i| i.id.index == index && i.id.name == b"lo0")
        .expect("same native loopback identity");
    let sample = loopback
        .counters
        .as_ref()
        .expect("validated native 64-bit IFMIB sample");
    let rx: u64 = sample.rx_bytes.unwrap();
    let tx: u64 = sample.tx_bytes.unwrap();
    if before.0 <= after.0 && before.1 <= after.1 {
        assert!((before.0..=after.0).contains(&rx));
        assert!((before.1..=after.1).contains(&tx));
    } else {
        eprintln!(
            "native reference counters reset during observation; delta/range not corroborated"
        );
    }
    if before.2 == after.2 {
        assert_eq!(loopback.mtu, Some(after.2));
    }
    eprintln!(
        "native Darwin loopback IFMIB: before={before:?}, owned RX={rx}/TX={tx}, after={after:?}"
    );
}

// Developer-only C probe. No network/native adapter calls: the native compiler
// checks the ACTUAL selected SDK's headers against the accepted R2/XNU contract.
// A missing header, changed selector or ABI is a failed gate, never a waiver.
#[cfg(target_os = "macos")]
const SDK_PROBE: &str = r#"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/sockio.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_mib.h>
#include <net/if_media.h>
#include <net/route.h>
#include <netinet/in.h>
#define CHECK(x) _Static_assert((x), #x)
#define OFF(t, f, n) CHECK(offsetof(struct t, f) == (n))
CHECK(sizeof(int) == 4 && sizeof(void *) == 8);
CHECK(IFNAMSIZ == 16 && IFF_UP == 1);
CHECK(AF_INET == 2 && AF_INET6 == 30 && AF_LINK == 18);
CHECK(CTL_NET == 4 && PF_LINK == 18 && NETLINK_GENERIC == 0);
CHECK(IFMIB_IFDATA == 2 && IFDATA_GENERAL == 1);
CHECK(sizeof(struct ifmibdata) == 180 && _Alignof(struct ifmibdata) == 4);
OFF(ifmibdata, ifmd_name, 0); OFF(ifmibdata, ifmd_data, 52);
CHECK(sizeof(struct if_data64) == 128 && _Alignof(struct if_data64) == 4);
OFF(if_data64, ifi_mtu, 8); OFF(if_data64, ifi_ibytes, 64); OFF(if_data64, ifi_obytes, 72);
CHECK(sizeof(((struct if_data64 *)0)->ifi_ibytes) == 8);
CHECK(sizeof(((struct if_data64 *)0)->ifi_obytes) == 8);
CHECK(sizeof(((struct if_data *)0)->ifi_ibytes) == 4);
CHECK(sizeof(struct ifmediareq) == 44 && _Alignof(struct ifmediareq) == 4);
OFF(ifmediareq, ifm_name, 0); OFF(ifmediareq, ifm_current, 16); OFF(ifmediareq, ifm_mask, 20);
OFF(ifmediareq, ifm_status, 24); OFF(ifmediareq, ifm_active, 28);
OFF(ifmediareq, ifm_count, 32); OFF(ifmediareq, ifm_ulist, 36);
CHECK(SIOCGIFMEDIA == 0xc02c6938UL && SIOCGIFXMEDIA == 0xc02c6948UL);
CHECK(IFM_AVALID == 1 && IFM_ACTIVE == 2 && IFM_ETHER == 0x20);
CHECK(IFM_NMASK == 0xe0 && IFM_TMASK == 0x000f001f && IFM_TMASK_EXT_SHIFT == 11);
#define MEDIA(name, n) CHECK((name) == IFM_X_SUBTYPE(n))
MEDIA(IFM_10_T, 3); MEDIA(IFM_10_2, 4); MEDIA(IFM_10_5, 5);
MEDIA(IFM_10_STP, 12); MEDIA(IFM_10_FL, 13);
MEDIA(IFM_100_TX, 6); MEDIA(IFM_100_FX, 7); MEDIA(IFM_100_T4, 8);
MEDIA(IFM_100_VG, 9); MEDIA(IFM_100_T2, 10);
MEDIA(IFM_1000_SX, 11); MEDIA(IFM_1000_LX, 14); MEDIA(IFM_1000_CX, 15);
MEDIA(IFM_1000_T, 16); MEDIA(IFM_1000_CX_SGMII, 24); MEDIA(IFM_1000_KX, 25);
MEDIA(IFM_2500_T, 22); MEDIA(IFM_2500_SX, 32); MEDIA(IFM_2500_KX, 36); MEDIA(IFM_2500_X, 63);
MEDIA(IFM_5000_T, 23); MEDIA(IFM_5000_KR, 64); MEDIA(IFM_5000_KR_S, 69); MEDIA(IFM_5000_KR1, 70);
MEDIA(IFM_10G_SR, 18); MEDIA(IFM_10G_LR, 19); MEDIA(IFM_10G_CX4, 20); MEDIA(IFM_10G_T, 21);
MEDIA(IFM_10G_KX4, 26); MEDIA(IFM_10G_KR, 27); MEDIA(IFM_10G_CR1, 28); MEDIA(IFM_10G_ER, 29);
MEDIA(IFM_10G_TWINAX, 33); MEDIA(IFM_10G_TWINAX_LONG, 34); MEDIA(IFM_10G_LRM, 35);
MEDIA(IFM_10G_SFI, 42); MEDIA(IFM_10G_AOC, 59); MEDIA(IFM_20G_KR2, 30);
CHECK(sizeof(struct sockaddr_in) == 16); OFF(sockaddr_in, sin_addr, 4);
CHECK(sizeof(struct sockaddr_in6) == 28); OFF(sockaddr_in6, sin6_addr, 8); OFF(sockaddr_in6, sin6_scope_id, 24);
OFF(sockaddr, sa_len, 0); OFF(sockaddr, sa_family, 1);
OFF(sockaddr_dl, sdl_len, 0); OFF(sockaddr_dl, sdl_family, 1); OFF(sockaddr_dl, sdl_index, 2);
OFF(sockaddr_dl, sdl_nlen, 5); OFF(sockaddr_dl, sdl_alen, 6); OFF(sockaddr_dl, sdl_slen, 7); OFF(sockaddr_dl, sdl_data, 8);
CHECK(sizeof(struct rt_msghdr) == 92 && _Alignof(struct rt_msghdr) == 4);
CHECK(sizeof(struct rt_metrics) == 56 && sizeof(uint32_t) == 4);
OFF(rt_msghdr, rtm_msglen, 0); OFF(rt_msghdr, rtm_version, 2); OFF(rt_msghdr, rtm_type, 3);
OFF(rt_msghdr, rtm_index, 4); OFF(rt_msghdr, rtm_flags, 8); OFF(rt_msghdr, rtm_addrs, 12);
OFF(rt_msghdr, rtm_errno, 24); OFF(rt_msghdr, rtm_rmx, 36);
CHECK(PF_ROUTE == 17 && NET_RT_DUMP == 1 && RTM_VERSION == 5 && RTM_GET == 4 && RTM_GET2 != 4);
CHECK(RTF_UP == 1 && RTF_GATEWAY == 2);
CHECK((RTF_HOST | RTF_REJECT | RTF_BLACKHOLE | RTF_LOCAL | RTF_BROADCAST | RTF_MULTICAST | RTF_CONDEMNED | RTF_DEAD) == 0x22e0100c);
CHECK((RTF_IFSCOPE & 0x22e0100c) == 0);
CHECK(RTAX_MAX == 8 && RTAX_DST == 0 && RTAX_GATEWAY == 1 && RTAX_NETMASK == 2);
CHECK(RTAX_GENMASK == 3 && RTAX_IFP == 4 && RTAX_IFA == 5 && RTAX_AUTHOR == 6 && RTAX_BRD == 7);
#define VALUE(name, value) printf(name "=%zu\n", (size_t)(value))
int main(void) {
    VALUE("ifaddrs.size", sizeof(struct ifaddrs));
    VALUE("ifaddrs.next", offsetof(struct ifaddrs, ifa_next));
    VALUE("ifaddrs.name", offsetof(struct ifaddrs, ifa_name));
    VALUE("ifaddrs.flags", offsetof(struct ifaddrs, ifa_flags));
    VALUE("ifaddrs.addr", offsetof(struct ifaddrs, ifa_addr));
    VALUE("ifaddrs.netmask", offsetof(struct ifaddrs, ifa_netmask));
    VALUE("ifaddrs.dstaddr", offsetof(struct ifaddrs, ifa_dstaddr));
    VALUE("ifaddrs.data", offsetof(struct ifaddrs, ifa_data));
    VALUE("ifmibdata.size", sizeof(struct ifmibdata));
    VALUE("if_data64.size", sizeof(struct if_data64));
    VALUE("rt_msghdr.size", sizeof(struct rt_msghdr));
    VALUE("SIOCGIFMEDIA", SIOCGIFMEDIA); VALUE("SIOCGIFXMEDIA", SIOCGIFXMEDIA);
    return 0;
}
"#;
