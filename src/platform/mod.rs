// Keep the Linux wire decoders available to tests on the Darwin host too.
#[cfg(any(target_os = "linux", test))]
pub mod linux;

// Darwin's byte decoders and result assembly are portable; only FFI is native.
#[cfg(any(target_os = "macos", test))]
pub mod macos;
