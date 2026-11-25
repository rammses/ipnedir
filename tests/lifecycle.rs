mod support;

use std::{
    ffi::OsString,
    fs::File,
    io::{self, BufWriter, ErrorKind, Write},
    net::IpAddr,
    os::fd::{FromRawFd, OwnedFd},
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};

use ipnedir::{
    app,
    model::*,
    public::{LookupFn, PublicWorkers},
    render::Style,
};
use support::{FailureWriter, Phase, Rig};

// These assertions catch eager factories, skipped sampling, an enlarged cutoff,
// dropped optional inventory, and incorrect output/error branches in the real run.
#[test]
fn app_help_version_and_usage_prevent_initialization() {
    for (args, status, expected) in [
        (vec!["--help"], 0, "Usage:"),
        (vec!["-h"], 0, "--offline"),
        (vec!["--version"], 0, "ipnedir 0.1.0"),
        (vec!["-V"], 0, "ipnedir 0.1.0"),
        (vec!["--bad"], 2, "Usage:"),
        (vec!["file"], 2, "Usage:"),
        (vec!["--offline", "--help"], 2, "Usage:"),
    ] {
        let mut rig = Rig::new();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(rig.run(&args, &mut out, &mut err), status);
        let printed = if status == 2 { &err } else { &out };
        assert!(String::from_utf8_lossy(printed).contains(expected));
        assert!(if status == 2 {
            out.is_empty()
        } else {
            err.is_empty()
        });
        assert!(rig.events.borrow().is_empty());
        assert!(rig.clock.sleeps.is_empty());
        if args == ["--help"] {
            let help = String::from_utf8(out).unwrap();
            for note in [
                "icanhazip",
                "HTTPS",
                "egress",
                "unavailable",
                "--offline",
                "index/name",
                "nondecreasing counters",
                "indistinguishable",
            ] {
                assert!(help.contains(note), "help missing {note}");
            }
        }
    }
}

#[test]
fn app_non_utf8_usage_does_not_initialize_or_echo_raw_bytes() {
    use std::os::unix::ffi::OsStringExt;
    let mut clock = support::FakeClock::new();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = app::run::<support::FakeCollector, support::FakePublic>(
        &[OsString::from_vec(vec![0xff, 0x1b])],
        || panic!("collector initialized"),
        || panic!("public initialized"),
        &mut clock,
        Style { color: false },
        &mut out,
        &mut err,
    );
    assert_eq!(status, 2);
    assert!(out.is_empty());
    assert!(!err.contains(&0x1b));
    assert!(String::from_utf8(err).unwrap().contains("UTF-8"));
}

#[test]
fn app_offline_samples_once_without_public_factory() {
    let mut rig = Rig::new();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(rig.run(&["--offline"], &mut out, &mut err), 0);
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("eth-test"));
    assert!(text.contains("192.0.2.2/24"));
    assert!(text.contains("RX: 1.0 Mbit/s"));
    assert!(text.contains("TX: 0.0 bit/s"));
    assert_eq!(text.matches("disabled (--offline)").count(), 2);
    assert!(err.is_empty());
    assert_eq!(rig.clock.sleeps, [Duration::from_secs(1)]);
    assert_eq!(
        *rig.events.borrow(),
        [
            "collector",
            "snapshot",
            "sleep",
            "snapshot",
            "now",
            "defaults",
            "drop_collector"
        ]
    );
}

#[test]
fn app_online_starts_after_first_snapshot_and_cuts_off_before_defaults() {
    let mut rig = Rig::new();
    let initial = rig.clock.time.get();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(rig.run(&[], &mut out, &mut err), 0);
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("203.0.113.10"));
    assert!(text.contains("2001:db8::10"));
    assert!(err.is_empty());
    assert_eq!(rig.cutoff.get(), Some(initial + Duration::from_secs(1)));
    assert_eq!(rig.clock.sleeps, [Duration::from_secs(1)]);
    let events = rig.events.borrow();
    assert_eq!(
        &events[..9],
        [
            "collector",
            "snapshot",
            "public",
            "start",
            "sleep",
            "snapshot",
            "now",
            "take_ready",
            "defaults"
        ]
    );
    assert!(events.contains(&"drop_public"));
    assert!(events.contains(&"drop_collector"));
}

#[test]
fn app_first_inventory_failure_is_fatal_before_public_and_sleep() {
    let mut rig = Rig::new();
    rig.snapshots = vec![Err(CollectError(
        "inventory\x1b[31m\nfailed\u{202e}".into(),
    ))];
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(rig.run(&[], &mut out, &mut err), 1);
    assert!(out.is_empty());
    let diagnostic = String::from_utf8(err).unwrap();
    assert!(diagnostic.contains("inventory\\x1b[31m\\x0afailed"));
    assert!(!diagnostic.contains('\u{202e}'));
    assert_eq!(diagnostic.lines().count(), 1);
    assert_eq!(
        *rig.events.borrow(),
        ["collector", "snapshot", "drop_collector"]
    );
    assert!(rig.clock.sleeps.is_empty());
}

#[test]
fn app_second_inventory_failure_drops_started_public_without_results_or_defaults() {
    let mut rig = Rig::new();
    rig.snapshots[1] = Err(CollectError("second inventory unavailable".into()));
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(rig.run(&[], &mut out, &mut err), 1);
    assert!(out.is_empty());
    assert!(
        String::from_utf8(err)
            .unwrap()
            .contains("second inventory unavailable")
    );
    let events = rig.events.borrow();
    assert_eq!(
        &events[..6],
        [
            "collector",
            "snapshot",
            "public",
            "start",
            "sleep",
            "snapshot"
        ]
    );
    assert!(events.contains(&"drop_public"));
    assert!(!events.contains(&"defaults"));
    assert!(!events.contains(&"take_ready"));
}

#[test]
fn app_optional_defaults_failure_preserves_inventory_and_addresses() {
    let mut rig = Rig::new();
    rig.defaults = Defaults {
        v4: Coverage::Unavailable("route\x1b query failed".into()),
        v6: Coverage::Incomplete {
            value: [7].into(),
            reason: "partial\nroute dump".into(),
        },
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(rig.run(&["--offline"], &mut out, &mut err), 0);
    let text = String::from_utf8(out).unwrap();
    for expected in [
        "eth-test",
        "192.0.2.2/24",
        "fe80::1%7/64",
        "* default IPv6",
        "unavailable",
        "incomplete",
        "route\\x1b query failed",
        "partial\\x0aroute dump",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(!text.contains('\x1b'));
    assert!(err.is_empty());
}

#[test]
fn app_stdout_write_and_flush_broken_pipe_are_quiet_success() {
    for phase in [Phase::Write, Phase::Flush] {
        let mut rig = Rig::new();
        let mut out = FailureWriter::new(phase, ErrorKind::BrokenPipe);
        let mut err = Vec::new();
        assert_eq!(rig.run(&[], &mut out, &mut err), 0);
        assert!(out.writes > 0);
        if phase == Phase::Flush {
            assert_eq!(out.flushes, 1);
        }
        assert!(err.is_empty());
        assert!(rig.events.borrow().contains(&"drop_public"));
    }
}

#[test]
fn app_other_stdout_write_and_flush_errors_return_one_without_raw_error() {
    for phase in [Phase::Write, Phase::Flush] {
        let mut rig = Rig::new();
        let mut out = FailureWriter::new(phase, ErrorKind::PermissionDenied);
        let mut err = Vec::new();
        assert_eq!(rig.run(&["--offline"], &mut out, &mut err), 1);
        assert!(out.writes > 0);
        if phase == Phase::Flush {
            assert_eq!(out.flushes, 1);
        }
        let diagnostic = String::from_utf8(err).unwrap();
        assert!(diagnostic.contains("output"));
        assert!(!diagnostic.contains("PRIVATE"));
        assert!(!diagnostic.contains('\x1b'));
    }
}

#[test]
fn app_early_output_errors_are_mapped_without_initialization() {
    for arg in ["--help", "--version"] {
        for phase in [Phase::Write, Phase::Flush] {
            for (kind, expected) in [(ErrorKind::BrokenPipe, 0), (ErrorKind::Other, 1)] {
                let mut rig = Rig::new();
                let mut out = FailureWriter::new(phase, kind);
                let mut err = Vec::new();
                assert_eq!(rig.run(&[arg], &mut out, &mut err), expected);
                assert!(rig.events.borrow().is_empty());
                if expected == 0 {
                    assert!(err.is_empty());
                }
            }
        }
    }
}

#[test]
fn app_usage_output_write_or_flush_failure_returns_one() {
    for phase in [Phase::Write, Phase::Flush] {
        let mut rig = Rig::new();
        let mut out = Vec::new();
        let mut err = FailureWriter::new(phase, ErrorKind::Other);
        assert_eq!(rig.run(&["--bad"], &mut out, &mut err), 1);
        assert!(err.writes > 0);
        if phase == Phase::Flush {
            assert_eq!(err.flushes, 1);
        }
        assert!(out.is_empty());
        assert!(rig.events.borrow().is_empty());
    }
}

// Test-binary-only state. A separate executable invocation isolates each case;
// no release flag, callback environment hook, timeout or release signal exists.
static ENTERED_V4: AtomicUsize = AtomicUsize::new(0);
static ENTERED_V6: AtomicUsize = AtomicUsize::new(0);

fn park_external_operation(family: Family) -> Option<IpAddr> {
    match family {
        Family::V4 => &ENTERED_V4,
        Family::V6 => &ENTERED_V6,
    }
    .fetch_add(1, Ordering::SeqCst);
    loop {
        thread::park();
    }
}

// These named boundaries replace only the slow operation, not HTTP configuration
// or the production queue/coordinator/ownership. They are not live DNS/TLS tests.
fn blocked_dns(family: Family) -> Option<IpAddr> {
    park_external_operation(family)
}
fn blocked_connect(family: Family) -> Option<IpAddr> {
    park_external_operation(family)
}
fn blocked_tls(family: Family) -> Option<IpAddr> {
    park_external_operation(family)
}
fn blocked_body(family: Family) -> Option<IpAddr> {
    park_external_operation(family)
}

fn closed_pipe_writer() -> File {
    let mut fds = [-1; 2];
    // SAFETY: pipe writes exactly two valid owned descriptors on success.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: each newly created descriptor has exactly one owner here.
    let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: the distinct write descriptor is valid and uniquely owned.
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    drop(read);
    File::from(write)
}

struct ObservedWriter {
    inner: Box<dyn Write>,
    attempted: Vec<u8>,
    write_error: Option<ErrorKind>,
    flush_error: Option<ErrorKind>,
}

impl Write for ObservedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.attempted.extend_from_slice(bytes);
        let result = self.inner.write(bytes);
        if let Err(error) = &result {
            self.write_error = Some(error.kind());
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        let result = self.inner.flush();
        if let Err(error) = &result {
            self.flush_error = Some(error.kind());
        }
        result
    }
}

fn run_blocked_child(case: &str) {
    let lookup: LookupFn = match case {
        "dns" | "second-error" | "pipe-write" | "pipe-flush" => blocked_dns,
        "connect" => blocked_connect,
        "tls" => blocked_tls,
        "body" => blocked_body,
        _ => panic!("unknown test case"),
    };
    let mut rig = Rig::new();
    if case == "second-error" {
        rig.snapshots[1] = Err(CollectError("second inventory unavailable".into()));
    }
    let snapshots = std::mem::take(&mut rig.snapshots).into();
    let defaults = rig.defaults.clone();
    let events = rig.events.clone();
    let time = rig.clock.time.clone();
    let inner: Box<dyn Write> = match case {
        "pipe-write" => Box::new(closed_pipe_writer()),
        // The bounded fixture fits in this buffer, so only flush touches the pipe.
        "pipe-flush" => Box::new(BufWriter::with_capacity(65_536, closed_pipe_writer())),
        _ => Box::new(Vec::<u8>::new()),
    };
    let mut out = ObservedWriter {
        inner,
        attempted: Vec::new(),
        write_error: None,
        flush_error: None,
    };
    let mut err = Vec::new();
    let start = Instant::now();
    let status = app::run(
        &[],
        || support::FakeCollector {
            snapshots,
            defaults,
            events,
            time,
        },
        || PublicWorkers::new(lookup),
        &mut app::SystemClock,
        Style { color: false },
        &mut out,
        &mut err,
    );
    assert!(
        start.elapsed() >= Duration::from_secs(1),
        "real sampling sleep skipped"
    );
    assert_eq!(
        ENTERED_V4.load(Ordering::SeqCst),
        1,
        "IPv4 worker did not enter"
    );
    assert_eq!(
        ENTERED_V6.load(Ordering::SeqCst),
        1,
        "IPv6 worker did not enter"
    );
    assert!(rig.events.borrow().contains(&"drop_collector"));
    if case == "second-error" {
        assert_eq!(status, 1);
        assert!(out.attempted.is_empty());
        assert!(!rig.events.borrow().contains(&"defaults"));
        assert_eq!(
            String::from_utf8(err).unwrap(),
            "ipnedir: local inventory failed: second inventory unavailable\n"
        );
        println!("second inventory unavailable; status=1; workers-entered=1,1");
    } else {
        assert_eq!(status, 0);
        assert!(err.is_empty());
        let report = String::from_utf8(out.attempted.clone()).unwrap();
        assert!(report.len() < 4096);
        for expected in [
            "eth-test",
            "192.0.2.2/24",
            "RX: 1.0 Mbit/s",
            "IPv4: unavailable",
            "IPv6: unavailable",
        ] {
            assert!(report.contains(expected), "missing {expected}");
        }
        match case {
            "pipe-write" => {
                assert_eq!(out.write_error, Some(ErrorKind::BrokenPipe));
                assert_eq!(out.flush_error, None);
            }
            "pipe-flush" => {
                assert_eq!(out.write_error, None);
                assert_eq!(out.flush_error, Some(ErrorKind::BrokenPipe));
            }
            _ => {
                assert_eq!(out.write_error, None);
                assert_eq!(out.flush_error, None);
            }
        }
        println!("{report}status=0; workers-entered=1,1; case={case}");
    }
    // All coordinator/public state has left app::run; our writer, clock,
    // collector fixtures and buffers also drop normally on this function return.
}

fn run_lazy_child() {
    // Creating/dropping the real worker object alone must not auto-start work.
    drop(PublicWorkers::new(blocked_dns));
    for (arg, expected, failed_inventory) in [
        ("--help", 0, false),
        ("--version", 0, false),
        ("--bad", 2, false),
        ("--offline", 0, false),
        ("", 1, true),
    ] {
        let mut rig = Rig::new();
        if failed_inventory {
            rig.snapshots[0] = Err(CollectError("first inventory unavailable".into()));
        }
        let snapshots = std::mem::take(&mut rig.snapshots).into();
        let defaults = rig.defaults.clone();
        let events = rig.events.clone();
        let time = rig.clock.time.clone();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let args = if arg.is_empty() {
            Vec::new()
        } else {
            vec![OsString::from(arg)]
        };
        let public_factories = std::cell::Cell::new(0);
        let collector_factories = std::cell::Cell::new(0);
        let status = app::run(
            &args,
            || {
                collector_factories.set(collector_factories.get() + 1);
                support::FakeCollector {
                    snapshots,
                    defaults,
                    events,
                    time,
                }
            },
            || {
                public_factories.set(public_factories.get() + 1);
                PublicWorkers::new(blocked_dns)
            },
            &mut rig.clock,
            Style { color: false },
            &mut out,
            &mut err,
        );
        assert_eq!(status, expected);
        assert_eq!(public_factories.get(), 0);
        assert_eq!(
            collector_factories.get(),
            usize::from(arg == "--offline" || failed_inventory)
        );
        let printed = String::from_utf8(if expected == 0 { out } else { err }).unwrap();
        let expected_text = match arg {
            "--help" | "--bad" => "Usage:",
            "--version" => "ipnedir 0.1.0",
            "--offline" => "disabled (--offline)",
            _ => "first inventory unavailable",
        };
        assert!(printed.contains(expected_text));
    }
    assert_eq!(ENTERED_V4.load(Ordering::SeqCst), 0);
    assert_eq!(ENTERED_V6.load(Ordering::SeqCst), 0);
    println!("lazy modes output/status verified; workers-entered=0,0");
}

#[test]
fn child_entry() {
    let Ok(case) = std::env::var("IPNEDIR_TEST_LIFECYCLE_CASE") else {
        return;
    };
    if case == "lazy" {
        run_lazy_child();
    } else {
        run_blocked_child(&case);
    }
    // No process::exit: helpers' owned state has dropped, then this test returns
    // to the actual harness while both injected operations remain parked forever.
    println!("normal-cleanup-return case={case}");
}

fn assert_lifecycle_child(case: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
        .env("IPNEDIR_TEST_LIFECYCLE_CASE", case)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let mut timed_out = false;
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() >= Duration::from_secs(3) {
            child.kill().unwrap();
            child.wait().unwrap();
            timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    // Read only once the child has exited or has been killed+reaped. Reports
    // stay below pipe capacity, so neither success nor watchdog can drain-hang.
    let output = child.wait_with_output().unwrap();
    assert!(
        !timed_out,
        "{case}: 3s watchdog killed+reaped child: {output:?}"
    );
    assert!(output.status.success(), "{case}: {output:?}");
    assert!(output.stderr.is_empty(), "{case}: {output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.len() < 8192);
    assert!(
        stdout.contains(&format!("normal-cleanup-return case={case}")),
        "{stdout}"
    );
    assert!(stdout.contains("1 passed; 0 failed"), "{stdout}");
    assert!(!stdout.contains("panicked"));
    if case == "lazy" {
        assert!(stdout.contains("workers-entered=0,0"));
    } else {
        assert!(stdout.contains("workers-entered=1,1"));
        if case == "second-error" {
            assert!(stdout.contains("status=1"));
        } else {
            for expected in [
                "eth-test",
                "IPv4: unavailable",
                "IPv6: unavailable",
                "status=0",
            ] {
                assert!(
                    stdout.contains(expected),
                    "{case}: missing {expected}: {stdout}"
                );
            }
        }
    }
    println!(
        "{case}: child returned normally in {:?}; watchdog 3s (10ms poll)",
        start.elapsed()
    );
}

#[test]
fn lifecycle_dns_does_not_gate_exit() {
    assert_lifecycle_child("dns");
}
#[test]
fn lifecycle_connect_does_not_gate_exit() {
    assert_lifecycle_child("connect");
}
#[test]
fn lifecycle_tls_does_not_gate_exit() {
    assert_lifecycle_child("tls");
}
#[test]
fn lifecycle_body_does_not_gate_exit() {
    assert_lifecycle_child("body");
}
#[test]
fn lifecycle_second_inventory_failure_does_not_wait() {
    assert_lifecycle_child("second-error");
}
#[test]
fn lifecycle_closed_pipe_write_does_not_wait() {
    assert_lifecycle_child("pipe-write");
}
#[test]
fn lifecycle_closed_pipe_flush_does_not_wait() {
    assert_lifecycle_child("pipe-flush");
}
#[test]
fn lifecycle_lazy_modes_prevent_real_workers() {
    assert_lifecycle_child("lazy");
}
