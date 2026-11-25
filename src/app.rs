use std::{
    ffi::OsString,
    io::{self, Write},
    time::{Duration, Instant},
};

use crate::{
    VERSION,
    cli::{self, Action},
    model::{PublicReport, PublicValue, Report},
    platform::Collector,
    public::PublicSource,
    render::{self, Style},
    sample,
};

const USAGE: &str = "Usage: ipnedir [--offline | --help | --version]\n";
const HELP: &str = "ipnedir - one-shot native network report\n\nUsage: ipnedir [--offline | --help | --version]\n\n  --offline       Local sample only; no public HTTP or DNS work\n  --help, -h      Show this help without collection or network work\n  --version, -V   Show version without collection or network work\n\nDefault mode contacts IPv4/IPv6 icanhazip endpoints over HTTPS, revealing\nthe respective egress IP to that service. Requests are direct (no proxies);\nVPN/system routing still applies. Failed or unfinished lookups are unavailable\nand do not delay the local report. RX/TX are best-effort one-second snapshot\ndeltas, not a bandwidth-capacity measurement. A replacement reusing the same\nindex/name with nondecreasing counters is indistinguishable from a continuing\ndevice. Use --offline for no requests.\n";

pub trait Clock {
    fn now(&self) -> Instant;
    fn sleep(&mut self, duration: Duration);
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

pub fn run<C: Collector, P: PublicSource>(
    args: &[OsString],
    make_collector: impl FnOnce() -> C,
    make_public: impl FnOnce() -> P,
    clock: &mut dyn Clock,
    style: Style,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let offline = match cli::parse(args) {
        Ok(Action::Help) => return output(out, err, HELP),
        Ok(Action::Version) => return output(out, err, &format!("ipnedir {VERSION}\n")),
        Ok(Action::Run { offline }) => offline,
        Err(error) => {
            let diagnostic = format!("ipnedir: {}\n{USAGE}", render::escape(error.0.as_bytes()));
            return if write_and_flush(err, &diagnostic).is_ok() {
                2
            } else {
                1
            };
        }
    };

    let mut collector = make_collector();
    let before = match collector.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return inventory_error(err, &error.0),
    };
    let mut public = if offline {
        None
    } else {
        let mut source = make_public();
        source.start();
        Some(source)
    };
    clock.sleep(Duration::from_secs(1));
    let after = match collector.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return inventory_error(err, &error.0),
    };
    // Close the network result window before any optional local route queries.
    let cutoff = clock.now();
    let public_report = public.as_mut().map_or(
        PublicReport {
            v4: PublicValue::Disabled,
            v6: PublicValue::Disabled,
        },
        |source| source.take_ready(cutoff),
    );
    let defaults = collector.defaults();
    let rates = sample::combine(&before, &after);
    let report = Report {
        after,
        rates,
        defaults,
        public: public_report,
    };
    output(out, err, &render::text(&report, style))
}

fn write_and_flush(out: &mut dyn Write, text: &str) -> io::Result<()> {
    out.write_all(text.as_bytes())?;
    out.flush()
}

fn output(out: &mut dyn Write, err: &mut dyn Write, text: &str) -> u8 {
    match write_and_flush(out, text) {
        Ok(()) => 0,
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => 0,
        Err(_) => {
            let _ = write_and_flush(err, "ipnedir: output failed\n");
            1
        }
    }
}

fn inventory_error(err: &mut dyn Write, diagnostic: &str) -> u8 {
    let diagnostic = format!(
        "ipnedir: local inventory failed: {}\n",
        render::escape(diagnostic.as_bytes())
    );
    let _ = write_and_flush(err, &diagnostic);
    1
}
