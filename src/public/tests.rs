use std::{
    net::IpAddr,
    sync::{
        Condvar, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

use crate::model::{Family, PublicReport, PublicValue};

use super::{Completion, PublicSource, PublicWorkers, http};

#[test]
fn public_http_policy_is_direct_https_and_verified() {
    let c = http::config(Family::V4);
    assert!(c.https_only());
    assert!(c.proxy().is_none());
    assert_eq!(c.max_redirects(), 0);
    assert_eq!(c.ip_family(), ureq::config::IpFamily::Ipv4Only);
    assert!(!c.tls_config().disable_verification());
    assert!(matches!(
        c.tls_config().root_certs(),
        ureq::tls::RootCerts::WebPki
    ));
    assert_eq!(c.tls_config().provider(), ureq::tls::TlsProvider::Rustls);
    assert_eq!(
        http::parse_body(Family::V4, b"203.0.113.9\n"),
        Some("203.0.113.9".parse().unwrap())
    );
    assert_eq!(http::parse_body(Family::V4, b"::1\n"), None);
}

#[test]
fn public_http_policy_uses_verified_ipv6_only() {
    let c = http::config(Family::V6);
    assert_eq!(c.ip_family(), ureq::config::IpFamily::Ipv6Only);
    assert!(c.https_only());
    assert!(c.proxy().is_none());
    assert_eq!(c.max_redirects(), 0);
    assert_eq!(c.tls_config().provider(), ureq::tls::TlsProvider::Rustls);
    assert!(!c.tls_config().disable_verification());
    assert!(matches!(
        c.tls_config().root_certs(),
        ureq::tls::RootCerts::WebPki
    ));
}

#[test]
fn public_http_policy_bounds_headers_and_worker_phases() {
    for family in [Family::V4, Family::V6] {
        let c = http::config(family);
        assert_eq!(c.max_response_header_size(), 8192);
        let timeouts = c.timeouts();
        assert_eq!(timeouts.connect, Some(Duration::from_millis(500)));
        assert_eq!(timeouts.recv_response, Some(Duration::from_millis(500)));
        assert_eq!(timeouts.recv_body, Some(Duration::from_millis(500)));
        // Finite DNS/global/per-call budgets would enable ureq's resolver helper thread.
        assert_eq!(timeouts.resolve, None);
        assert_eq!(timeouts.global, None);
        assert_eq!(timeouts.per_call, None);
    }
}

#[test]
fn public_http_body_accepts_literal_single_addresses() {
    let cases: &[(Family, &[u8], &str)] = &[
        (Family::V4, b"203.0.113.9\n", "203.0.113.9"),
        (Family::V4, b" \t198.51.100.17\r\n", "198.51.100.17"),
        (Family::V6, b"2001:db8::9\n", "2001:db8::9"),
        (Family::V6, b"\t2001:0DB8:0:0::17 \r\n", "2001:db8::17"),
        (Family::V6, b"::ffff:203.0.113.9\n", "::ffff:cb00:7109"),
    ];
    for &(family, body, want) in cases {
        assert_eq!(http::parse_body(family, body), Some(want.parse().unwrap()));
    }
}

#[test]
fn public_http_ascii_whitespace_preserves_literal_addresses() {
    let cases: &[(Family, &[u8], &str)] = &[
        (
            Family::V4,
            b" \t\r\n\x0c203.0.113.9 \t\r\n\x0c",
            "203.0.113.9",
        ),
        (
            Family::V6,
            b" \t\r\n\x0c2001:db8::9 \t\r\n\x0c",
            "2001:db8::9",
        ),
    ];
    for &(family, body, literal) in cases {
        let want = Some(literal.parse().unwrap());
        assert_eq!(http::parse_body(family, body), want);
        assert_eq!(http::response_ip(200, family, body), want);
    }
}

const UNICODE_WHITESPACE_V4_BODIES: [&[u8]; 2] = [
    b"\xc2\xa0203.0.113.9\xc2\xa0",
    b"\xe2\x80\x83203.0.113.9\xe2\x80\x83",
];
const UNICODE_WHITESPACE_V6_BODIES: [&[u8]; 2] = [
    b"\xc2\xa02001:db8::9\xc2\xa0",
    b"\xe2\x80\x832001:db8::9\xe2\x80\x83",
];

#[test]
fn public_http_body_rejects_unicode_whitespace_v4() {
    for body in UNICODE_WHITESPACE_V4_BODIES {
        assert_eq!(http::parse_body(Family::V4, body), None);
    }
}

#[test]
fn public_http_body_rejects_unicode_whitespace_v6() {
    for body in UNICODE_WHITESPACE_V6_BODIES {
        assert_eq!(http::parse_body(Family::V6, body), None);
    }
}

#[test]
fn public_http_response_rejects_unicode_whitespace_v4() {
    for body in UNICODE_WHITESPACE_V4_BODIES {
        assert_eq!(http::response_ip(200, Family::V4, body), None);
    }
}

#[test]
fn public_http_response_rejects_unicode_whitespace_v6() {
    for body in UNICODE_WHITESPACE_V6_BODIES {
        assert_eq!(http::response_ip(200, Family::V6, body), None);
    }
}

#[test]
fn public_http_body_checks_128_bytes_before_trimming() {
    for (family, literal) in [(Family::V4, "203.0.113.9"), (Family::V6, "2001:db8::9")] {
        let mut body = vec![b' '; 128];
        body[..literal.len()].copy_from_slice(literal.as_bytes());
        assert_eq!(
            http::parse_body(family, &body),
            Some(literal.parse().unwrap())
        );
        body.push(b'\n');
        assert_eq!(http::parse_body(family, &body), None);
    }
}

#[test]
fn public_http_body_rejects_non_ip_bytes_and_extra_tokens() {
    let bodies: &[&[u8]] = &[
        b"",
        b" \r\n\t",
        b"\xff203.0.113.9\n",
        b"203.0.113.9\xff",
        b"<html>203.0.113.9</html>",
        b"203.0.113.9 extra\n",
        b"203.0.113.9\n198.51.100.17\n",
        b"2001:db8::9 2001:db8::17",
        b"203.0.113.9\0",
        b"203.0.113.9/24",
        b"203.000.113.9",
        b"https://203.0.113.9/",
        b"[2001:db8::9]",
    ];
    for body in bodies {
        for family in [Family::V4, Family::V6] {
            assert_eq!(http::parse_body(family, body), None, "{family:?}");
        }
    }
}

#[test]
fn public_http_body_rejects_wrong_family_and_scope_suffixes() {
    for body in [b"::1\n".as_slice(), b"::ffff:203.0.113.9\n"] {
        assert_eq!(http::parse_body(Family::V4, body), None);
    }
    assert_eq!(http::parse_body(Family::V6, b"203.0.113.9\n"), None);
    for body in [b"fe80::1%en0\n".as_slice(), b"fe80::1%3\n"] {
        assert_eq!(http::parse_body(Family::V6, body), None);
    }
}

#[test]
fn public_http_response_requires_exact_200_and_valid_body() {
    let v4: IpAddr = "203.0.113.9".parse().unwrap();
    let v6: IpAddr = "2001:db8::9".parse().unwrap();
    for (status, want_v4, want_v6) in [
        (200, Some(v4), Some(v6)),
        (201, None, None),
        (204, None, None),
        (301, None, None),
        (400, None, None),
        (500, None, None),
    ] {
        assert_eq!(
            http::response_ip(status, Family::V4, b"203.0.113.9\n"),
            want_v4,
            "status {status}"
        );
        assert_eq!(
            http::response_ip(status, Family::V6, b"2001:db8::9\n"),
            want_v6,
            "status {status}"
        );
    }
    assert_eq!(http::response_ip(200, Family::V4, b"::1\n"), None);
    assert_eq!(http::response_ip(200, Family::V6, b"203.0.113.9\n"), None);
    assert_eq!(
        http::response_ip(200, Family::V4, b"<html>error</html>"),
        None
    );
    assert_eq!(http::response_ip(200, Family::V6, &[b' '; 129]), None);
}

fn unavailable() -> PublicReport {
    PublicReport {
        v4: PublicValue::Unavailable,
        v6: PublicValue::Unavailable,
    }
}

fn no_lookup(_family: Family) -> Option<IpAddr> {
    None
}

fn queued(completions: impl IntoIterator<Item = Completion>) -> PublicWorkers {
    let source = PublicWorkers::new(no_lookup);
    for completion in completions {
        assert!(source.sender.as_ref().unwrap().try_send(completion).is_ok());
    }
    source
}

// Watchdogs and blocking observations are test-only: a broken recv/join path must fail,
// not strand the test runner. No production timeout or cleanup wait is needed.
fn observe<T: Send + 'static>(action: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let _ = sender.try_send(action());
    });
    receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("public operation must not wait for senders or workers")
}

#[test]
fn public_queue_accepts_both_families_before_cutoff() {
    let cutoff = Instant::now();
    let mut source = queued([
        Completion {
            family: Family::V4,
            completed_at: cutoff - Duration::from_millis(1),
            value: Some("203.0.113.9".parse().unwrap()),
        },
        Completion {
            family: Family::V6,
            completed_at: cutoff - Duration::from_millis(1),
            value: Some("2001:db8::9".parse().unwrap()),
        },
    ]);
    assert_eq!(
        source.take_ready(cutoff),
        PublicReport {
            v4: PublicValue::Ready("203.0.113.9".parse().unwrap()),
            v6: PublicValue::Ready("2001:db8::9".parse().unwrap()),
        }
    );
    assert_eq!(source.take_ready(cutoff), unavailable());
}

#[test]
fn public_queue_accepts_completion_exactly_at_cutoff() {
    let cutoff = Instant::now();
    let mut source = queued([
        Completion {
            family: Family::V4,
            completed_at: cutoff,
            value: Some("198.51.100.17".parse().unwrap()),
        },
        Completion {
            family: Family::V6,
            completed_at: cutoff,
            value: Some("2001:db8::17".parse().unwrap()),
        },
    ]);
    assert_eq!(
        source.take_ready(cutoff),
        PublicReport {
            v4: PublicValue::Ready("198.51.100.17".parse().unwrap()),
            v6: PublicValue::Ready("2001:db8::17".parse().unwrap()),
        }
    );
}

#[test]
fn public_queue_rejects_completions_after_cutoff() {
    let cutoff = Instant::now();
    let mut source = queued([
        Completion {
            family: Family::V4,
            completed_at: cutoff + Duration::from_nanos(1),
            value: Some("203.0.113.9".parse().unwrap()),
        },
        Completion {
            family: Family::V6,
            completed_at: cutoff + Duration::from_nanos(1),
            value: Some("2001:db8::9".parse().unwrap()),
        },
    ]);
    assert_eq!(source.take_ready(cutoff), unavailable());
    assert!(source.receiver.try_recv().is_err());
}

#[test]
fn public_queue_one_family_does_not_fill_the_other() {
    let cutoff = Instant::now();
    for (family, value, want) in [
        (
            Family::V4,
            "203.0.113.9",
            PublicReport {
                v4: PublicValue::Ready("203.0.113.9".parse().unwrap()),
                v6: PublicValue::Unavailable,
            },
        ),
        (
            Family::V6,
            "2001:db8::9",
            PublicReport {
                v4: PublicValue::Unavailable,
                v6: PublicValue::Ready("2001:db8::9".parse().unwrap()),
            },
        ),
    ] {
        let mut source = queued([Completion {
            family,
            completed_at: cutoff,
            value: Some(value.parse().unwrap()),
        }]);
        assert_eq!(source.take_ready(cutoff), want);
    }
}

#[test]
fn public_queue_revalidates_family_instead_of_trusting_callback() {
    let cutoff = Instant::now();
    let mut source = queued([
        Completion {
            family: Family::V4,
            completed_at: cutoff,
            value: Some("::ffff:203.0.113.9".parse().unwrap()),
        },
        Completion {
            family: Family::V6,
            completed_at: cutoff,
            value: Some("203.0.113.9".parse().unwrap()),
        },
    ]);
    assert_eq!(source.take_ready(cutoff), unavailable());
}

#[test]
fn public_queue_none_is_unavailable_not_disabled() {
    let cutoff = Instant::now();
    let mut source = queued([
        Completion {
            family: Family::V4,
            completed_at: cutoff,
            value: None,
        },
        Completion {
            family: Family::V6,
            completed_at: cutoff,
            value: None,
        },
    ]);
    assert_eq!(source.take_ready(cutoff), unavailable());
}

#[test]
fn public_queue_duplicate_family_does_not_replace_first_completion() {
    let cutoff = Instant::now();
    for duplicate in [None, Some("198.51.100.17".parse().unwrap())] {
        let mut source = queued([
            Completion {
                family: Family::V4,
                completed_at: cutoff,
                value: Some("203.0.113.9".parse().unwrap()),
            },
            Completion {
                family: Family::V4,
                completed_at: cutoff,
                value: duplicate,
            },
        ]);
        assert_eq!(
            source.take_ready(cutoff),
            PublicReport {
                v4: PublicValue::Ready("203.0.113.9".parse().unwrap()),
                v6: PublicValue::Unavailable,
            }
        );
    }
}

#[test]
fn public_queue_reads_at_most_two_already_queued_completions() {
    let cutoff = Instant::now();
    let (sender, receiver) = mpsc::sync_channel(3);
    for (family, value) in [
        (Family::V4, "203.0.113.9"),
        (Family::V4, "198.51.100.17"),
        (Family::V6, "2001:db8::9"),
    ] {
        assert!(
            sender
                .try_send(Completion {
                    family,
                    completed_at: cutoff,
                    value: Some(value.parse().unwrap()),
                })
                .is_ok()
        );
    }
    // A larger fixture channel exposes over-draining; production new() must still use 2.
    let mut source = PublicWorkers {
        lookup: no_lookup,
        sender: Some(sender),
        receiver,
    };
    assert_eq!(
        source.take_ready(cutoff),
        PublicReport {
            v4: PublicValue::Ready("203.0.113.9".parse().unwrap()),
            v6: PublicValue::Unavailable,
        }
    );
    let remaining = source.receiver.try_recv().unwrap();
    assert_eq!(remaining.family, Family::V6);
    assert_eq!(remaining.value, Some("2001:db8::9".parse().unwrap()));
    assert!(source.receiver.try_recv().is_err());
}

#[test]
fn public_queue_channel_capacity_is_two() {
    let source = PublicWorkers::new(no_lookup);
    let sender = source.sender.as_ref().unwrap();
    for _ in 0..2 {
        assert!(
            sender
                .try_send(Completion {
                    family: Family::V4,
                    completed_at: Instant::now(),
                    value: None,
                })
                .is_ok()
        );
    }
    assert!(matches!(
        sender.try_send(Completion {
            family: Family::V6,
            completed_at: Instant::now(),
            value: None,
        }),
        Err(TrySendError::Full(_))
    ));
}

#[test]
fn public_queue_empty_returns_without_sender_cleanup_or_grace() {
    let report = observe(|| {
        let mut source = PublicWorkers::new(no_lookup);
        let started = Instant::now();
        let report = source.take_ready(Instant::now());
        assert!(started.elapsed() < Duration::from_millis(100));
        // Sender is deliberately still alive: blocking recv would never return.
        assert!(source.sender.is_some());
        report
    });
    assert_eq!(report, unavailable());
}

type WorkerEvent = (Family, thread::ThreadId, Instant);
static WORKER_EVENTS: OnceLock<SyncSender<WorkerEvent>> = OnceLock::new();
static V4_CALLS: AtomicUsize = AtomicUsize::new(0);
static V6_CALLS: AtomicUsize = AtomicUsize::new(0);

fn observed_lookup(family: Family) -> Option<IpAddr> {
    let value = match family {
        Family::V4 => {
            V4_CALLS.fetch_add(1, Ordering::SeqCst);
            "203.0.113.9"
        }
        Family::V6 => {
            V6_CALLS.fetch_add(1, Ordering::SeqCst);
            "2001:db8::9"
        }
    };
    WORKER_EVENTS
        .get()
        .unwrap()
        .try_send((family, thread::current().id(), Instant::now()))
        .unwrap();
    Some(value.parse().unwrap())
}

#[test]
fn public_queue_workers_start_once_and_timestamp_after_callback() {
    let (events, observations) = mpsc::sync_channel(4);
    WORKER_EVENTS.set(events).unwrap();
    let mut source = PublicWorkers::new(observed_lookup);
    let injector = source.sender.as_ref().unwrap().clone();
    assert_eq!(source.take_ready(Instant::now()), unavailable());
    assert_eq!(V4_CALLS.load(Ordering::SeqCst), 0);
    assert_eq!(V6_CALLS.load(Ordering::SeqCst), 0);
    source.start();
    source.start();
    let caller = thread::current().id();
    let first = source
        .receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    let second = source
        .receiver
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    assert_ne!(first.family, second.family);
    let mut worker_ids = Vec::new();
    for _ in 0..2 {
        let (family, worker, inside_callback) =
            observations.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_ne!(worker, caller);
        worker_ids.push(worker);
        let completion = if first.family == family {
            &first
        } else {
            &second
        };
        assert!(completion.completed_at >= inside_callback);
    }
    assert_ne!(worker_ids[0], worker_ids[1]);
    let cutoff = Instant::now();
    assert!(injector.try_send(first).is_ok());
    assert!(injector.try_send(second).is_ok());
    assert_eq!(
        source.take_ready(cutoff),
        PublicReport {
            v4: PublicValue::Ready("203.0.113.9".parse().unwrap()),
            v6: PublicValue::Ready("2001:db8::9".parse().unwrap()),
        }
    );
    source.start();
    assert!(
        source
            .receiver
            .recv_timeout(Duration::from_millis(100))
            .is_err()
    );
    assert_eq!(V4_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(V6_CALLS.load(Ordering::SeqCst), 1);
    assert!(observations.try_recv().is_err());
}

static BLOCKED_EVENTS: OnceLock<SyncSender<Family>> = OnceLock::new();
static BLOCKED_GATE: (Mutex<bool>, Condvar) = (Mutex::new(false), Condvar::new());

fn blocked_lookup(family: Family) -> Option<IpAddr> {
    BLOCKED_EVENTS.get().unwrap().try_send(family).unwrap();
    let (lock, wake) = &BLOCKED_GATE;
    let mut released = lock.lock().unwrap();
    while !*released {
        released = wake.wait(released).unwrap();
    }
    None
}

struct ReleaseBlocked;

impl Drop for ReleaseBlocked {
    fn drop(&mut self) {
        let (lock, wake) = &BLOCKED_GATE;
        *lock.lock().unwrap() = true;
        wake.notify_all();
    }
}

#[test]
fn public_queue_blocked_workers_do_not_delay_start_ready_or_drop() {
    let (events, observations) = mpsc::sync_channel(4);
    BLOCKED_EVENTS.set(events).unwrap();
    let release_on_failure = ReleaseBlocked;
    let (finished, result) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut source = PublicWorkers::new(blocked_lookup);
        source.start();
        source.start();
        let started = Instant::now();
        let report = source.take_ready(Instant::now());
        drop(source);
        let _ = finished.try_send((report, started.elapsed()));
    });
    let first = observations.recv_timeout(Duration::from_secs(2)).unwrap();
    let second = observations.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_ne!(first, second);
    let (report, elapsed) = result
        .recv_timeout(Duration::from_secs(2))
        .expect("source must drop while both callbacks are still blocked");
    assert_eq!(report, unavailable());
    assert!(elapsed < Duration::from_millis(100));
    assert!(
        observations
            .recv_timeout(Duration::from_millis(100))
            .is_err()
    );
    drop(release_on_failure);
}
