use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    ffi::OsString,
    io::{self, Write},
    rc::Rc,
    time::{Duration, Instant},
};

use ipnedir::{
    app::{self, Clock},
    model::*,
    platform::Collector,
    public::PublicSource,
    render::Style,
};

type Events = Rc<RefCell<Vec<&'static str>>>;

pub struct FakeClock {
    pub time: Rc<Cell<Instant>>,
    pub sleeps: Vec<Duration>,
    pub events: Events,
}

impl FakeClock {
    pub fn new() -> Self {
        Self {
            time: Rc::new(Cell::new(Instant::now())),
            sleeps: Vec::new(),
            events: Events::default(),
        }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.events.borrow_mut().push("now");
        self.time.get()
    }
    fn sleep(&mut self, duration: Duration) {
        self.events.borrow_mut().push("sleep");
        self.sleeps.push(duration);
        self.time.set(self.time.get() + duration);
    }
}

pub struct FakeCollector {
    pub snapshots: VecDeque<Result<Snapshot, CollectError>>,
    pub defaults: Defaults,
    pub events: Events,
    pub time: Rc<Cell<Instant>>,
}

impl Collector for FakeCollector {
    fn snapshot(&mut self) -> Result<Snapshot, CollectError> {
        self.events.borrow_mut().push("snapshot");
        self.snapshots.pop_front().expect("extra snapshot")
    }
    fn defaults(&mut self) -> Defaults {
        self.events.borrow_mut().push("defaults");
        // A slow local route query must not enlarge the public-result window.
        self.time.set(self.time.get() + Duration::from_secs(5));
        self.defaults.clone()
    }
}

impl Drop for FakeCollector {
    fn drop(&mut self) {
        self.events.borrow_mut().push("drop_collector");
    }
}

pub struct FakePublic {
    pub events: Events,
    pub cutoff: Rc<Cell<Option<Instant>>>,
}

impl PublicSource for FakePublic {
    fn start(&mut self) {
        self.events.borrow_mut().push("start");
    }
    fn take_ready(&mut self, cutoff: Instant) -> PublicReport {
        self.events.borrow_mut().push("take_ready");
        assert!(
            self.cutoff.replace(Some(cutoff)).is_none(),
            "extra take_ready"
        );
        PublicReport {
            v4: PublicValue::Ready("203.0.113.10".parse().unwrap()),
            v6: PublicValue::Ready("2001:db8::10".parse().unwrap()),
        }
    }
}

impl Drop for FakePublic {
    fn drop(&mut self) {
        self.events.borrow_mut().push("drop_public");
    }
}

pub fn snapshot(at: Instant, rx_bytes: u64) -> Snapshot {
    Snapshot {
        interfaces: vec![Interface {
            id: InterfaceId {
                index: 7,
                name: b"eth-test".to_vec(),
            },
            state: State::Up,
            addresses: vec![
                Address {
                    ip: "192.0.2.2".parse().unwrap(),
                    prefix: Some(24),
                    scope_id: None,
                },
                Address {
                    ip: "fe80::1".parse().unwrap(),
                    prefix: Some(64),
                    scope_id: Some(7),
                },
            ],
            link_address: Some(vec![2, 0, 0, 0, 0, 7]),
            mtu: Some(1500),
            speed_bps: Some(1_000_000_000),
            counters: Some(Counters {
                at,
                rx_bytes: Some(rx_bytes),
                tx_bytes: Some(0),
            }),
        }],
    }
}

pub fn defaults() -> Defaults {
    Defaults {
        v4: Coverage::Complete([7].into()),
        v6: Coverage::Complete([7].into()),
    }
}

pub struct Rig {
    pub clock: FakeClock,
    pub events: Events,
    pub snapshots: Vec<Result<Snapshot, CollectError>>,
    pub defaults: Defaults,
    pub cutoff: Rc<Cell<Option<Instant>>>,
}

impl Rig {
    pub fn new() -> Self {
        let clock = FakeClock::new();
        let at = clock.time.get();
        Self {
            events: clock.events.clone(),
            clock,
            snapshots: vec![
                Ok(snapshot(at, 0)),
                Ok(snapshot(at + Duration::from_secs(1), 125_000)),
            ],
            defaults: defaults(),
            cutoff: Rc::new(Cell::new(None)),
        }
    }
    pub fn run(&mut self, args: &[&str], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
        let snapshots = std::mem::take(&mut self.snapshots).into();
        let defaults = self.defaults.clone();
        let events = self.events.clone();
        let public_events = events.clone();
        let time = self.clock.time.clone();
        let cutoff = self.cutoff.clone();
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        app::run(
            &args,
            move || {
                events.borrow_mut().push("collector");
                FakeCollector {
                    snapshots,
                    defaults,
                    events,
                    time,
                }
            },
            move || {
                public_events.borrow_mut().push("public");
                FakePublic {
                    events: public_events,
                    cutoff,
                }
            },
            &mut self.clock,
            Style { color: false },
            out,
            err,
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Phase {
    Write,
    Flush,
}

pub struct FailureWriter {
    phase: Phase,
    kind: io::ErrorKind,
    pub writes: usize,
    pub flushes: usize,
}

impl FailureWriter {
    pub fn new(phase: Phase, kind: io::ErrorKind) -> Self {
        Self {
            phase,
            kind,
            writes: 0,
            flushes: 0,
        }
    }
}

impl Write for FailureWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.phase == Phase::Write {
            Err(io::Error::new(self.kind, "PRIVATE\x1b[31m"))
        } else {
            Ok(bytes.len())
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.phase == Phase::Flush {
            Err(io::Error::new(self.kind, "PRIVATE\x1b[31m"))
        } else {
            Ok(())
        }
    }
}
