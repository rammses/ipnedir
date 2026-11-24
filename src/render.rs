use std::{collections::BTreeSet, net::IpAddr};

use crate::model::{Address, Coverage, Interface, PublicValue, Report, State};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Style {
    pub color: bool,
}

impl Style {
    pub fn detect(terminal: bool, no_color_present: bool, term_dumb: bool) -> Style {
        Style {
            color: terminal && !no_color_present && !term_dumb,
        }
    }
}

pub fn text(report: &Report, style: Style) -> String {
    let mut output = String::from("Interfaces\n");
    let mut interfaces: Vec<_> = report.after.interfaces.iter().collect();
    interfaces.sort_by_key(|interface| &interface.id);
    if interfaces.is_empty() {
        output.push_str("  No interfaces found.\n");
    }
    for interface in interfaces {
        let (badge, color) = match interface.state {
            State::Up => ("[UP]", "\x1b[32m"),
            State::Down => ("[DOWN]", "\x1b[31m"),
            State::Unknown => ("[UNKNOWN]", "\x1b[33m"),
        };
        let badge = if style.color {
            format!("{color}{badge}\x1b[0m")
        } else {
            badge.into()
        };
        output.push_str(&format!(
            "{} (index {}) {badge}",
            escape(&interface.id.name),
            interface.id.index
        ));
        if member(&report.defaults.v4, interface.id.index) {
            output.push_str(" * default IPv4");
        }
        if member(&report.defaults.v6, interface.id.index) {
            output.push_str(" * default IPv6");
        }
        output.push('\n');
        let mut addresses: Vec<_> = interface.addresses.iter().collect();
        addresses.sort_by_key(|address| (address.ip, address.scope_id, address.prefix));
        if addresses.is_empty() {
            output.push_str("  Addresses: none\n");
        }
        for address in addresses {
            let family = if address.ip.is_ipv4() { "IPv4" } else { "IPv6" };
            output.push_str(&format!(
                "  {family}: {}\n",
                address_text(address, interface)
            ));
        }
        let link = interface
            .link_address
            .as_ref()
            .filter(|bytes| {
                !bytes.is_empty()
                    && bytes.iter().any(|b| *b != 0)
                    && bytes.iter().any(|b| *b != 255)
            })
            .map(|bytes| {
                bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            })
            .unwrap_or_else(|| "unavailable".into());
        let mtu = interface
            .mtu
            .filter(|mtu| *mtu > 0)
            .map(|mtu| mtu.to_string())
            .unwrap_or_else(|| "unavailable".into());
        let speed = bit_rate(
            interface
                .speed_bps
                .filter(|speed| *speed > 0)
                .map(|speed| speed as f64),
        );
        let rates = report.rates.get(&interface.id);
        output.push_str(&format!("  Link address: {link}\n  MTU: {mtu}\n  Link speed (driver): {speed}\n  RX: {}\n  TX: {}\n", bit_rate(rates.and_then(|r| r.rx)), bit_rate(rates.and_then(|r| r.tx))));
    }
    output.push_str(&coverage_text("IPv4", &report.defaults.v4));
    output.push_str(&coverage_text("IPv6", &report.defaults.v6));
    output.push_str(&format!(
        "\nPublic egress (icanhazip)\n  IPv4: {}\n  IPv6: {}\n",
        public_text(&report.public.v4),
        public_text(&report.public.v6)
    ));
    output.push_str("\nLegend: * default marks configured route membership, not a winning route.\nRX/TX: best-effort snapshot deltas over actual elapsed time (~1 s sample);\nnot a bandwidth-capacity measurement or proof of device-lifetime continuity.\n");
    output
}

fn member(coverage: &Coverage<BTreeSet<u32>>, index: u32) -> bool {
    match coverage {
        Coverage::Complete(value) | Coverage::Incomplete { value, .. } => value.contains(&index),
        Coverage::Unavailable(_) => false,
    }
}

fn coverage_text(family: &str, coverage: &Coverage<BTreeSet<u32>>) -> String {
    match coverage {
        Coverage::Complete(_) => String::new(),
        Coverage::Incomplete { reason, .. } => format!(
            "Default {family} coverage: incomplete ({})\n",
            escape(reason.as_bytes())
        ),
        Coverage::Unavailable(reason) => format!(
            "Default {family} coverage: unavailable ({})\n",
            escape(reason.as_bytes())
        ),
    }
}

fn address_text(address: &Address, interface: &Interface) -> String {
    let mut text = address.ip.to_string();
    if let IpAddr::V6(ip) = address.ip {
        if let Some(scope) = address.scope_id.filter(|scope| *scope > 0) {
            text.push_str(&format!("%{scope}"));
        } else if ip.is_unicast_link_local() || (ip.is_multicast() && ip.octets()[1] & 0x0f <= 2) {
            let zone = if interface.id.name.is_empty() {
                interface.id.index.to_string()
            } else {
                escape(&interface.id.name)
            };
            text.push_str(&format!("%{zone}"));
        }
    }
    if let Some(prefix) = address
        .prefix
        .filter(|prefix| *prefix <= if address.ip.is_ipv4() { 32 } else { 128 })
    {
        text.push_str(&format!("/{prefix}"));
    } else {
        text.push_str(" (prefix unavailable)");
    }
    text
}

fn bit_rate(value: Option<f64>) -> String {
    let Some(value) = value.filter(|value| value.is_finite() && *value >= 0.0) else {
        return "unavailable".into();
    };
    let (scale, unit) = if value >= 1e9 {
        (1e9, "Gbit/s")
    } else if value >= 1e6 {
        (1e6, "Mbit/s")
    } else if value >= 1e3 {
        (1e3, "Kbit/s")
    } else {
        (1.0, "bit/s")
    };
    format!("{:.1} {unit}", value / scale)
}

fn public_text(value: &PublicValue) -> String {
    match value {
        PublicValue::Ready(ip) => ip.to_string(),
        PublicValue::Unavailable => "unavailable".into(),
        PublicValue::Disabled => "disabled (--offline)".into(),
    }
}

/// Lossless, bytewise escaping for invalid UTF-8 and terminal controls, including
/// C1 and Unicode direction/format controls; readable ordinary UTF-8 stays intact.
pub(crate) fn escape(mut bytes: &[u8]) -> String {
    let mut output = String::new();
    while !bytes.is_empty() {
        let (valid, invalid) = match std::str::from_utf8(bytes) {
            Ok(text) => (text, 0),
            Err(error) => (
                std::str::from_utf8(&bytes[..error.valid_up_to()]).expect("validated UTF-8 prefix"),
                error
                    .error_len()
                    .unwrap_or(bytes.len() - error.valid_up_to()),
            ),
        };
        for c in valid.chars() {
            if c.is_control()
                || matches!(c, '\u{00ad}' | '\u{034f}' | '\u{061c}' | '\u{180e}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}' | '\u{fff9}'..='\u{fffb}' | '\u{e0000}'..='\u{e007f}')
            {
                for byte in c.encode_utf8(&mut [0; 4]).bytes() {
                    output.push_str(&format!("\\x{byte:02x}"));
                }
            } else {
                output.push(c);
            }
        }
        bytes = &bytes[valid.len()..];
        for byte in &bytes[..invalid] {
            output.push_str(&format!("\\x{byte:02x}"));
        }
        bytes = &bytes[invalid..];
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use std::collections::BTreeMap;

    fn interface(index: u32, name: &[u8]) -> Interface {
        Interface {
            id: InterfaceId {
                index,
                name: name.into(),
            },
            state: State::Up,
            addresses: vec![
                Address {
                    ip: "192.0.2.9".parse().unwrap(),
                    prefix: Some(24),
                    scope_id: None,
                },
                Address {
                    ip: "fe80::1".parse().unwrap(),
                    prefix: Some(64),
                    scope_id: Some(index),
                },
                Address {
                    ip: "2001:db8::2".parse().unwrap(),
                    prefix: Some(128),
                    scope_id: None,
                },
                Address {
                    ip: "192.0.2.10".parse().unwrap(),
                    prefix: Some(32),
                    scope_id: None,
                },
            ],
            link_address: Some(vec![2, 0xaa, 0xbb, 0xcc, 0xdd, 1]),
            mtu: Some(1500),
            speed_bps: Some(2_500_000_000),
            counters: None,
        }
    }

    fn report(interfaces: Vec<Interface>) -> Report {
        Report {
            after: Snapshot { interfaces },
            rates: BTreeMap::new(),
            defaults: Defaults {
                v4: Coverage::Complete([2].into()),
                v6: Coverage::Complete([2].into()),
            },
            public: PublicReport {
                v4: PublicValue::Ready("203.0.113.1".parse().unwrap()),
                v6: PublicValue::Unavailable,
            },
        }
    }

    fn plain(report: &Report) -> String {
        text(report, Style { color: false })
    }

    // Wrong color policy, omitted fields, byte/bit confusion, unsafe text and
    // overclaimed route coverage should each fail a consumer-visible assertion.
    #[test]
    fn render_style_requires_tty_and_respects_both_color_overrides() {
        for terminal in [false, true] {
            for no_color in [false, true] {
                for dumb in [false, true] {
                    assert_eq!(
                        Style::detect(terminal, no_color, dumb).color,
                        terminal && !no_color && !dumb
                    );
                }
            }
        }
    }

    #[test]
    fn render_all_addresses_scopes_metadata_defaults_and_public_families() {
        let output = plain(&report(vec![interface(2, b"en0")]));
        for expected in [
            "en0",
            "[UP]",
            "* default IPv4",
            "* default IPv6",
            "192.0.2.9/24",
            "192.0.2.10/32",
            "fe80::1%2/64",
            "2001:db8::2/128",
            "02:aa:bb:cc:dd:01",
            "MTU: 1500",
            "Link speed (driver): 2.5 Gbit/s",
            "RX: unavailable",
            "TX: unavailable",
            "Public egress (icanhazip)",
            "IPv4: 203.0.113.1",
            "IPv6: unavailable",
            "snapshot",
            "* default",
        ] {
            assert!(output.contains(expected), "missing {expected}: {output}");
        }
        assert!(!output.contains('\x1b'));
    }

    #[test]
    fn render_empty_inventory_is_distinct_from_no_ip_down_interface() {
        let empty = plain(&report(vec![]));
        assert!(empty.contains("No interfaces found"));
        let mut item = interface(3, b"no-ip");
        item.addresses.clear();
        item.state = State::Down;
        let output = plain(&report(vec![item]));
        assert!(output.contains("no-ip"));
        assert!(output.contains("[DOWN]"));
        assert!(output.contains("Addresses: none"));
        assert!(!output.contains("No interfaces found"));
    }

    #[test]
    fn render_scaled_bit_rates_include_true_zero_and_reject_nonfinite_or_negative() {
        for (value, expected) in [
            (Some(0.0), "0.0 bit/s"),
            (Some(999.0), "999.0 bit/s"),
            (Some(1000.0), "1.0 Kbit/s"),
            (Some(1_500_000.0), "1.5 Mbit/s"),
            (Some(2_000_000_000.0), "2.0 Gbit/s"),
            (None, "unavailable"),
            (Some(-1.0), "unavailable"),
            (Some(f64::NAN), "unavailable"),
            (Some(f64::INFINITY), "unavailable"),
            (Some(f64::NEG_INFINITY), "unavailable"),
        ] {
            let item = interface(2, b"rates");
            let id = item.id.clone();
            let mut fixture = report(vec![item]);
            fixture.rates.insert(
                id,
                Rates {
                    rx: value,
                    tx: value,
                },
            );
            let output = plain(&fixture);
            assert!(output.contains(&format!("RX: {expected}")), "{output}");
            assert!(output.contains(&format!("TX: {expected}")), "{output}");
        }
    }

    #[test]
    fn render_unknown_or_zero_metadata_does_not_invent_values() {
        for (mtu, speed, link) in [(None, None, None), (Some(0), Some(0), Some(vec![0; 6]))] {
            let mut item = interface(2, b"unknown");
            item.mtu = mtu;
            item.speed_bps = speed;
            item.link_address = link;
            item.state = State::Unknown;
            let output = plain(&report(vec![item]));
            for expected in [
                "[UNKNOWN]",
                "MTU: unavailable",
                "Link speed (driver): unavailable",
                "Link address: unavailable",
            ] {
                assert!(output.contains(expected), "{output}");
            }
        }
    }

    #[test]
    fn render_missing_invalid_prefix_keeps_address_and_scoped_fallback() {
        let mut item = interface(9, b"vpn-zone");
        item.addresses = vec![
            Address {
                ip: "192.0.2.5".parse().unwrap(),
                prefix: None,
                scope_id: None,
            },
            Address {
                ip: "192.0.2.6".parse().unwrap(),
                prefix: Some(33),
                scope_id: None,
            },
            Address {
                ip: "fe80::1".parse().unwrap(),
                prefix: Some(129),
                scope_id: None,
            },
        ];
        let output = plain(&report(vec![item]));
        for address in [
            "192.0.2.5 (prefix unavailable)",
            "192.0.2.6 (prefix unavailable)",
            "fe80::1%vpn-zone (prefix unavailable)",
        ] {
            assert!(output.contains(address), "{output}");
        }
        assert!(!output.contains("/0"));
    }

    #[test]
    fn render_interface_and_address_order_is_stable_without_hiding_any() {
        let mut items = vec![
            interface(9, b"last"),
            interface(2, b"zeta"),
            interface(2, b"alpha"),
        ];
        let first = plain(&report(items.clone()));
        items.reverse();
        for item in &mut items {
            item.addresses.reverse();
        }
        assert_eq!(first, plain(&report(items)));
        assert!(first.find("alpha").unwrap() < first.find("zeta").unwrap());
        assert!(first.find("zeta").unwrap() < first.find("last").unwrap());
    }

    #[test]
    fn render_names_and_coverage_diagnostics_escape_controls_and_invalid_utf8() {
        let mut name = b"vpn\x1b[31m\n\r\t\0\x7f\xff".to_vec();
        name.extend_from_slice("-Türkçe-\u{009b}\u{202e}".as_bytes());
        let mut fixture = report(vec![interface(2, &name)]);
        fixture.defaults.v4 = Coverage::Unavailable("bad\x1b\n\u{009b}\u{202e}".into());
        let output = plain(&fixture);
        assert!(
            output.contains(
                "vpn\\x1b[31m\\x0a\\x0d\\x09\\x00\\x7f\\xff-Türkçe-\\xc2\\x9b\\xe2\\x80\\xae"
            ),
            "{output}"
        );
        assert!(output.contains("bad\\x1b\\x0a\\xc2\\x9b\\xe2\\x80\\xae"));
        assert!(!output.contains('\x1b'));
        assert!(!output.contains('\u{009b}'));
        assert!(!output.contains('\u{202e}'));
        assert!(output.chars().all(|c| !c.is_control() || c == '\n'));
    }

    #[test]
    fn render_incomplete_and_unavailable_coverage_are_visible_without_false_markers() {
        let mut fixture = report(vec![interface(2, b"known"), interface(3, b"other")]);
        fixture.defaults.v4 = Coverage::Incomplete {
            value: [2].into(),
            reason: "missing nexthop".into(),
        };
        fixture.defaults.v6 = Coverage::Unavailable("route query failed".into());
        fixture.public = PublicReport {
            v4: PublicValue::Disabled,
            v6: PublicValue::Disabled,
        };
        let output = plain(&fixture);
        assert_eq!(output.matches("* default IPv4").count(), 1);
        assert!(!output.contains("* default IPv6"));
        for expected in [
            "Default IPv4 coverage: incomplete",
            "missing nexthop",
            "Default IPv6 coverage: unavailable",
            "route query failed",
        ] {
            assert!(output.contains(expected), "{output}");
        }
        assert_eq!(output.matches("disabled (--offline)").count(), 2);
    }

    #[test]
    fn render_color_changes_only_state_badges_and_preserves_plain_meaning() {
        let mut down = interface(3, b"down");
        down.state = State::Down;
        let mut unknown = interface(4, b"unknown");
        unknown.state = State::Unknown;
        let fixture = report(vec![interface(2, b"up"), down, unknown]);
        let colored = text(&fixture, Style { color: true });
        for badge in [
            "\x1b[32m[UP]\x1b[0m",
            "\x1b[31m[DOWN]\x1b[0m",
            "\x1b[33m[UNKNOWN]\x1b[0m",
        ] {
            assert!(colored.contains(badge), "{colored:?}");
        }
        let stripped = colored
            .replace("\x1b[32m", "")
            .replace("\x1b[31m", "")
            .replace("\x1b[33m", "")
            .replace("\x1b[0m", "");
        assert_eq!(stripped, plain(&fixture));
    }
}
