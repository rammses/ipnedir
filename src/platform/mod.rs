// Keep the Linux wire decoders available to tests on the Darwin host too.
#[cfg(any(target_os = "linux", test))]
pub mod linux;

// Darwin's byte decoders and result assembly are portable; only FFI is native.
#[cfg(any(target_os = "macos", test))]
pub mod macos;

use crate::model::{CollectError, Defaults, Snapshot};

pub trait Collector {
    fn snapshot(&mut self) -> Result<Snapshot, CollectError>;
    fn defaults(&mut self) -> Defaults;
}

pub struct NativeCollector;

#[cfg(target_os = "linux")]
use linux as native;
#[cfg(target_os = "macos")]
use macos as native;

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Collector for NativeCollector {
    fn snapshot(&mut self) -> Result<Snapshot, CollectError> {
        native::snapshot()
    }
    fn defaults(&mut self) -> Defaults {
        native::defaults()
    }
}
