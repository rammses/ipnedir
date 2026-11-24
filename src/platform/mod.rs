// Keep the Linux wire decoders available to tests on the Darwin host too.
#[cfg(any(target_os = "linux", test))]
pub mod linux;
