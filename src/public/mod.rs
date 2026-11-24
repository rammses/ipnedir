use std::{
    net::IpAddr,
    sync::mpsc::{self, Receiver, SyncSender},
    thread,
    time::Instant,
};

use crate::model::{Family, PublicReport, PublicValue};

pub mod http;

pub type LookupFn = fn(Family) -> Option<IpAddr>;

/// Optional public lookups; draining ready values never waits for work to finish.
pub trait PublicSource {
    fn start(&mut self);
    fn take_ready(&mut self, cutoff: Instant) -> PublicReport;
}

struct Completion {
    family: Family,
    completed_at: Instant,
    value: Option<IpAddr>,
}

pub struct PublicWorkers {
    lookup: LookupFn,
    sender: Option<SyncSender<Completion>>,
    receiver: Receiver<Completion>,
}

impl PublicWorkers {
    /// Creates only a bounded channel. No callback or network initialization occurs yet.
    pub fn new(lookup: LookupFn) -> Self {
        let (sender, receiver) = mpsc::sync_channel(2);
        Self {
            lookup,
            sender: Some(sender),
            receiver,
        }
    }
}

impl PublicSource for PublicWorkers {
    fn start(&mut self) {
        let Some(sender) = self.sender.take() else {
            return;
        };
        for family in [Family::V4, Family::V6] {
            let sender = sender.clone();
            let lookup = self.lookup;
            // Dropping the handle detaches; spawn failure simply leaves a family unavailable.
            let _ = thread::Builder::new().spawn(move || {
                let value = lookup(family);
                let completed_at = Instant::now();
                let _ = sender.try_send(Completion {
                    family,
                    completed_at,
                    value,
                });
            });
        }
    }

    fn take_ready(&mut self, cutoff: Instant) -> PublicReport {
        let mut report = PublicReport {
            v4: PublicValue::Unavailable,
            v6: PublicValue::Unavailable,
        };
        let (mut seen_v4, mut seen_v6) = (false, false);
        for _ in 0..2 {
            let Ok(completion) = self.receiver.try_recv() else {
                break;
            };
            let (seen, slot) = match completion.family {
                Family::V4 => (&mut seen_v4, &mut report.v4),
                Family::V6 => (&mut seen_v6, &mut report.v6),
            };
            // Each worker sends once. Never let duplicate-family data replace its first result.
            if *seen {
                continue;
            }
            *seen = true;
            if completion.completed_at > cutoff {
                continue;
            }
            if let Some(ip) = completion.value.filter(|ip| match completion.family {
                Family::V4 => ip.is_ipv4(),
                Family::V6 => ip.is_ipv6(),
            }) {
                *slot = PublicValue::Ready(ip);
            }
        }
        report
    }
}

#[cfg(test)]
mod tests;
