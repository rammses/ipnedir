//! Darwin inventory. Native SDK/runtime verification remains a separate gate.

mod inventory;
mod media;
mod wire;

/// Copy a read-only native inventory and best-effort IFMIB/media observations.
/// This entry point is deliberately absent from non-Darwin production builds.
#[cfg(target_os = "macos")]
pub fn snapshot() -> Result<crate::model::Snapshot, crate::model::CollectError> {
    inventory::native::snapshot()
}

#[cfg(test)]
mod tests;
