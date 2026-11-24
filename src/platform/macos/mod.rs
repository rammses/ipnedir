//! Darwin inventory/defaults. Native SDK/runtime verification is a separate gate.

mod inventory;
mod media;
mod routes;
mod wire;

/// Copy a read-only native inventory and best-effort IFMIB/media observations.
/// This entry point is deliberately absent from non-Darwin production builds.
#[cfg(target_os = "macos")]
pub fn snapshot() -> Result<crate::model::Snapshot, crate::model::CollectError> {
    inventory::native::snapshot()
}

/// All usable configured default-route memberships, queried per address family.
#[cfg(target_os = "macos")]
pub fn defaults() -> crate::model::Defaults {
    routes::native::defaults()
}

#[cfg(test)]
mod tests;
