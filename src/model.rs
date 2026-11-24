use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    time::Instant,
};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct InterfaceId {
    pub index: u32,
    pub name: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Up,
    Down,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address {
    pub ip: IpAddr,
    pub prefix: Option<u8>,
    pub scope_id: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct Counters {
    pub at: Instant,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Interface {
    pub id: InterfaceId,
    pub state: State,
    pub addresses: Vec<Address>,
    pub link_address: Option<Vec<u8>>,
    pub mtu: Option<u32>,
    pub speed_bps: Option<u64>,
    pub counters: Option<Counters>,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub interfaces: Vec<Interface>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Coverage<T> {
    Complete(T),
    Incomplete { value: T, reason: String },
    Unavailable(String),
}

#[derive(Clone, Debug)]
pub struct Defaults {
    pub v4: Coverage<BTreeSet<u32>>,
    pub v6: Coverage<BTreeSet<u32>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    V4,
    V6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicValue {
    Ready(IpAddr),
    Unavailable,
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicReport {
    pub v4: PublicValue,
    pub v6: PublicValue,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rates {
    pub rx: Option<f64>,
    pub tx: Option<f64>,
}

#[derive(Debug)]
pub struct CollectError(pub String);

pub struct Report {
    pub after: Snapshot,
    pub rates: BTreeMap<InterfaceId, Rates>,
    pub defaults: Defaults,
    pub public: PublicReport,
}
