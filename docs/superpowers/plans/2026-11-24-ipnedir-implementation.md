# ipnedir Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify a standalone Rust `ipnedir` for Linux/macOS, with native interface information, sampled bit rates, non-waiting public-IP lookups, and release-ready Homebrew packaging.

**Architecture:** A small library owns domain calculations, native OS adapters, worker-local HTTPS, and report orchestration; the binary only supplies real dependencies and exit status. Two detached lookup workers communicate through a capacity-two channel; neither DNS nor client teardown is owned or awaited by main. Native data is decoded behind checked, OS-specific boundaries; release tooling is a separate developer-only workspace package.

**Tech Stack:** Rust **1.100.0**, edition 2024; `libc = "=0.2.191"`; `ureq = { version = "=3.5.2", default-features = false, features = ["rustls"] }`; standard-library tests/tooling. No other production dependencies.

**Spec:** `docs/superpowers/specs/2026-11-24-ipnedir-design.md`, **R2**, explicitly approved in chat with “i approve.” Full substantive review IPN-SR2 checkpoint `c5167d6850f2aa6fad05adba14bef2561ae7ca9f0d135ded6a997e3deb4bf9d9`; approval-record checkpoint `1f054186ac1911f57e4978cb1c56630c43e41b7eda8660f8fb97dac3f6ffdc9f`. Subsequent ledger-only status changes do not alter the approved substantive design.

## Global Constraints

- “V1 is a single invocation, one report, and normal process exit.” No watch/TUI/JSON/filter/config/cache/custom-interval/Windows features.
- “No root privileges, packet capture, traffic generation to measure bandwidth, or runtime shell-outs.” Native data describes the current process's network namespace/environment.
- “Rates are **best-effort snapshot deltas**, not proof of device-lifetime continuity.” Preserve the documented same-index/name replacement limitation.
- “Collect **cumulative 64-bit** byte counters with a monotonic timestamp for each valid sample.” Missing/reset/observable replacement is unavailable, not guessed zero or wraparound.
- “No sysfs-derived interface fields in v1.” Linux inventory, statistics, routes and speed come from namespace-local sockets only.
- “Use bit/s, Kbit/s, Mbit/s, Gbit/s with base 1000 and one decimal place.” RX/TX and `Link speed (driver)` are separate.
- “No scoped threads, join-on-drop pool, `join()`, blocking receive, or shared network-client destructor on main's path.” At most two application lookup workers, no process-wide async runtime.
- “Take **at most two** already-queued results with nonblocking receives”; accept only validated results completed by the post-sample cutoff. No network grace period.
- “Fixed HTTPS endpoints: `https://ipv4.icanhazip.com/` and `https://ipv6.icanhazip.com/`.” HTTPS-only, direct/proxy-disabled, verified TLS/WebPKI roots, correct connection family, no redirects/application retries/compression/cookies.
- “Require HTTP 200 and at most **128 response-body bytes**”; exactly one syntactically valid address in the expected family, no unvalidated content in output.
- “`--offline` starts no workers/resolver/client”; help/version/usage errors also return before collectors or network initialization.
- Honor terminal stdout, any `NO_COLOR` presence and `TERM=dumb`; escape untrusted interface/diagnostic control characters. Quiet exit 0 for BrokenPipe; usage 2; mandatory inventory/other output errors 1; optional unavailable data 0.
- Four artifact names are exactly `ipnedir-aarch64-apple-darwin.tar.gz`, `ipnedir-x86_64-apple-darwin.tar.gz`, `ipnedir-aarch64-unknown-linux-gnu.tar.gz`, `ipnedir-x86_64-unknown-linux-gnu.tar.gz`.
- Package/binary `ipnedir`, initial version `0.1.0`, MIT. Intended remotes `rammses/ipnedir` and `rammses/homebrew-tap`; eventual install `brew install rammses/tap/ipnedir`.
- “Actual macOS runtime evidence is required”; Linux-only tests or cross-compilation cannot establish complete acceptance.
- “Creating remote repositories, pushing branches/tags, configuring credentials, publishing releases, and modifying the existing tap are **separate release operations**.” Do not install locally or change the existing alias/prototype without separate approval.

## Review Focus

The following implicit failure classes are explicitly assigned tests below, rather than left to reviewer intuition:

1. **RF1 — hostile or interrupted native dumps:** malformed lengths, wrong sequence/source, nested nexthop cycles and error-bearing completion must terminate with error/visible incomplete coverage, not loop or claim an exhaustive empty inventory. Tasks 2–3.
2. **RF2 — packed Darwin ABI and successful-but-invalid data:** counters above 4 GiB, zero-filled IFMIB and four-byte sockaddr alignment must not turn into truncated counts, false identity, or out-of-bounds reads. Tasks 4–5.
3. **RF3 — a stuck network worker plus an early output error:** main must exit without joining on every path, including second-inventory failure and a closed consumer. Tasks 6–7.
4. **RF4 — unusual names/addresses and optional metadata:** non-UTF-8/control-byte names, IPv6 zones, invalid netmasks and no-IP interfaces remain identifiable and safely readable, never silently dropped. Tasks 1, 4, 7.
5. **RF5 — release inputs that nearly match:** wrong tag, one missing/duplicate architecture, renamed/tampered archives, incorrect checksums or an unapproved publication event must fail closed. Tasks 8–9.

---

## 1. Execution ownership, baseline and gates

Plan revision **P1**, 2026-11-24, with bounded execution correction **C1** authorized 2026-11-25. **Independent full review passed; user approved this plan and selected sequential subagent-driven execution with “go with subagent.”** Annotation was attempted but timed out without a decision; the later explicit chat instruction is the approval source. C1 adds only the Task9 CI-only shared-helper file listed below after the user requested “fix blockers” in response to the exact correction proposal. Builder may execute the approved implementation scope using that method. Planner stops at handoff; publication, Git writes and alias migration remain separately gated below.

Builder is the sole implementation/integration owner. Absolute workspace and command cwd: **`/home/rammses/Belgeler/ipnedir`**, unless Builder first documents an explicitly isolated execution workspace and remaps every command to it. Current baseline is a dedicated **docs-only, non-Git** directory containing the spec and this plan; there is no Rust app, Cargo.lock or baseline Rust test suite. There is no HEAD/index/branch to describe yet. Planner must not initialize Git or run plan steps.

Before implementation, Builder loads the required isolation/execution skills, inventories existing files and records spec/plan hashes. Preserve both documents; stop on unexplained source/config files or a changed substantive spec. If local Git is initialized during approved execution, Builder owns its index/HEAD exclusively. **Do not commit, stage, amend, push or create a PR unless explicitly authorized**; the per-task checkpoint is a diff/hash report when commit permission is absent. Never reset/stash unrelated changes or change Git configuration.

Protected outside-workspace state: `/home/rammses/.zshrc`, `/home/rammses/.local/share/ipnedir/`, existing applications, other repositories and the remote tap. The alias shadows a future binary: all tests use `target/.../ipnedir` explicitly. Do not reopen the interrupted Python work.

Delegation mode is already **auto**, with explicit approval to use the available capable-tier workers. The user separately selected **subagent-driven, sequential by task** with “go with subagent.” Follow that skill's required fresh implementer/spec/quality reviews; do not regroup tasks or run concurrent writers to shared Cargo files, index/HEAD or verification directories. Native was offered but not selected; do not switch execution methods without user authorization. Independent read-only review can overlap inspection, never implementation state mutation.

Real code dependencies: 2→1; 3→2; 4→1; 5→4; 6→1; 7→1–6; 8→7; 9→8. The default task order below is sequential, not a claim that macOS code semantically depends on Linux code. Shared files are explicit in each task; Builder owns integration edits to `src/lib.rs`, `src/platform/mod.rs`, `Cargo.toml`, `Cargo.lock`, `README.md`, workflow files and the final evidence report.

### Toolchain and native validation matrix

Pin `rust-toolchain.toml` to 1.100.0 with minimal profile plus rustfmt/clippy; set package `rust-version = "1.100"`, not an untested lower MSRV. Lock the dependency graph and use `--locked` thereafter. Developer tools may use Cargo, native headers, tar, SHA256 tools, Ruby and Homebrew; **the shipped executable may not shell out to any of them**.

| Native target | GitHub-hosted runner | Declared initial binary validation baseline |
| --- | --- | --- |
| x86_64-unknown-linux-gnu | ubuntu-22.04 | Ubuntu 22.04-equivalent GNU userspace, glibc 2.35; record actual runner kernel |
| aarch64-unknown-linux-gnu | ubuntu-22.04-arm | Same glibc baseline; native ARM64 execution |
| x86_64-apple-darwin | macos-15-intel | macOS 15; `MACOSX_DEPLOYMENT_TARGET=15.0` |
| aarch64-apple-darwin | macos-15 | macOS 15; `MACOSX_DEPLOYMENT_TARGET=15.0` |

Do not promise older macOS/Linux runtime compatibility or an independently tested minimum kernel. These labels were checked against current GitHub documentation on 2026-11-24; Builder must fail/report a retired/unavailable label, not silently substitute cross-compilation. Broader compatibility is a later design decision.

Known environment limits: local Linux x86-64 with Rust/Cargo 1.100.0 and Plannotator; `gh` absent, no authenticated new-repo access proven, no macOS/Homebrew runtime proven. Code/test preparation can proceed locally after execution approval, but four-target runtime and Homebrew release acceptance remain blocked until real runner/tool access is supplied. Ask for specific missing access at that stage; never create/push a repository just to unblock verification without permission.

### Common per-task verification/checkpoint

All commands are from the absolute workspace cwd above. Implementers own focused RED/GREEN and report exact failures; Builder reruns the complete current suite and records new versus pre-existing failures. Required recurring checks once Cargo files exist:

```sh
cargo +1.100.0 fmt --all --check
cargo +1.100.0 test --workspace --all-targets --locked
cargo +1.100.0 clippy --workspace --all-targets --locked -- -D warnings
```

Run syntax/compilation first if needed to establish a discoverable test, then obtain a **behavioral** RED for each calculation/parser/side effect before implementation. A misspelled import or unknown API is not the desired RED. No full-suite-green claim if a command was skipped. Native runtime gates assigned to Task 8 remain explicitly pending during host-only parser work, not quietly satisfied.

Record each checkpoint and review outcome in `docs/superpowers/plans/2026-11-24-ipnedir-build-evidence.md` during Builder execution: files/revision, focused RED/GREEN, complete commands/cwd/platform, prior/new failures, pending native/release gates. Do not fill this file with fabricated future results. If commits are later authorized, inspect status/diff/log and stage only the completed task's owned files; otherwise do not execute Git write commands.

## 2. File map and shared contracts

| Owner/task | Files and responsibility |
| --- | --- |
| 1 | `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.gitignore`, `LICENSE`, `README.md`; `src/lib.rs`, `src/model.rs`, `src/cli.rs`, `src/sample.rs`; initial domain/argument contract |
| 2 | `src/platform/mod.rs`; `src/platform/linux/{mod.rs,netlink.rs,inventory.rs,ethtool.rs,tests.rs}`; Linux inventory, transport and counter/speed decoding |
| 3 | `src/platform/linux/{routes.rs,nexthops.rs}` plus Linux module/tests; default membership and route coverage |
| 4 | `src/platform/macos/{mod.rs,wire.rs,inventory.rs,media.rs,tests.rs}`; portable byte decoders and Darwin-only FFI |
| 5 | `src/platform/macos/routes.rs` plus macOS wire/module/tests; scoped/default route inventory |
| 6 | `src/public/{mod.rs,http.rs,tests.rs}`; secure worker-local request and nonblocking ready-result boundary |
| 7 | `src/{app.rs,render.rs,main.rs}`; integration edits to lib/platform; `tests/{cli_process.rs,lifecycle.rs,support/mod.rs}`; README complete usage/privacy/migration |
| 8 | `release/targets.tsv`, `xtask/{Cargo.toml,src/main.rs,src/lib.rs,src/targets.rs}`; `.github/workflows/ci.yml`; `tests/native_smoke.rs`; workspace/lock/README updates |
| 9 | `xtask/src/{package.rs,formula.rs}`, xtask dispatch/tests; `.github/workflows/release.yml`, CI packaging extension; C1 shared CI-only `.github/scripts/artifacts.py`; `docs/releases.md`, README release links |

The examples below define contracts, not permission to start later tasks early. Preserve byte-level decoder tests on either OS by keeping portable wire logic free of target-specific libc imports; gate only actual FFI by target OS. `src/platform/mod.rs` exposes Linux parsers with `cfg(any(test, target_os = "linux"))` and Darwin parsers with `cfg(any(test, target_os = "macos"))`, while each native syscall implementation remains gated to its actual target OS.

### Model contract established by Task 1

Use the following owned types; derives may be added for tests without changing semantics:

```rust
use std::{collections::{BTreeMap, BTreeSet}, net::IpAddr, time::Instant};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct InterfaceId { pub index: u32, pub name: Vec<u8> }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State { Up, Down, Unknown }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Address { pub ip: IpAddr, pub prefix: Option<u8>, pub scope_id: Option<u32> }
#[derive(Clone, Debug)]
pub struct Counters { pub at: Instant, pub rx_bytes: Option<u64>, pub tx_bytes: Option<u64> }
#[derive(Clone, Debug)]
pub struct Interface {
    pub id: InterfaceId, pub state: State, pub addresses: Vec<Address>,
    pub link_address: Option<Vec<u8>>, pub mtu: Option<u32>,
    pub speed_bps: Option<u64>, pub counters: Option<Counters>,
}
#[derive(Clone, Debug)]
pub struct Snapshot { pub interfaces: Vec<Interface> }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Coverage<T> {
    Complete(T), Incomplete { value: T, reason: String }, Unavailable(String),
}
#[derive(Clone, Debug)]
pub struct Defaults {
    pub v4: Coverage<BTreeSet<u32>>, pub v6: Coverage<BTreeSet<u32>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family { V4, V6 }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PublicValue { Ready(IpAddr), Unavailable, Disabled }
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicReport { pub v4: PublicValue, pub v6: PublicValue }
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rates { pub rx: Option<f64>, pub tx: Option<f64> }
#[derive(Debug)]
pub struct CollectError(pub String);
pub struct Report {
    pub after: Snapshot, pub rates: BTreeMap<InterfaceId, Rates>,
    pub defaults: Defaults, pub public: PublicReport,
}
```

`InterfaceId.name` preserves raw OS bytes for correlation; rendering escapes them rather than changing identity through lossy UTF-8. Prefix validity is family-specific; absent/invalid prefixes stay `None`. Nonempty meaningful link-layer bytes render as hex, not arbitrary text. Never borrow kernel buffers into these models.

Library interfaces, implemented in their named tasks:

```text
cli::parse(args: &[OsString]) -> Result<Action, UsageError>                  [1]
cli::Action = Help | Version | Run { offline: bool }; UsageError(String)   [1]
sample::rates(before: &Interface, after: &Interface) -> Rates               [1]
sample::combine(before: &Snapshot, after: &Snapshot)
    -> BTreeMap<InterfaceId, Rates>                                       [1]
platform::linux::snapshot() -> Result<Snapshot, CollectError>              [2]
platform::linux::defaults() -> Defaults                                   [3]
platform::macos::snapshot() -> Result<Snapshot, CollectError>              [4]
platform::macos::defaults() -> Defaults                                   [5]
public::LookupFn = fn(Family) -> Option<IpAddr>                            [6]
public::PublicSource { start(&mut self); take_ready(&mut self, Instant)
    -> PublicReport; }                                                   [6]
public::PublicWorkers::new(lookup: LookupFn) -> PublicWorkers               [6]
public::http::lookup(family: Family) -> Option<IpAddr>                      [6]
render::Style { color: bool }; Style::detect(terminal: bool,
    no_color_present: bool, term_dumb: bool) -> Style                      [7]
render::text(report: &Report, style: Style) -> String                      [7]
platform::Collector { snapshot(&mut self) -> Result<Snapshot, CollectError>;
    defaults(&mut self) -> Defaults; }; platform::NativeCollector          [7]
app::Clock { now(&self) -> Instant; sleep(&mut self, Duration); };
    app::SystemClock                                                     [7]
```

`app::run<C: Collector, P: PublicSource>` consumes `args: &[OsString]`, `make_collector: impl FnOnce() -> C`, `make_public: impl FnOnce() -> P`, `clock: &mut dyn Clock`, `style: Style`, and `out/err: &mut dyn std::io::Write`; returns `u8` exit status. Factory closures must remain unevaluated for help/version/usage errors, and the public factory remains unevaluated offline. This is a narrow test seam, not a plugin API or new user-configurable endpoint.

## Task 1: Establish tested domain and argument contracts

**Owner:** one Implementer/Builder. **Dependencies:** approved artifacts only. **Files:** Task-1 rows above; unit tests inside cli/sample/model modules. Initial package is library-only until Task 7 creates `src/main.rs`; do not add a fake collector/binary to fill the gap.

**Produces:** all model types, `cli::parse`, `sample::rates`, `sample::combine`; crate `VERSION: &str = env!("CARGO_PKG_VERSION")`. No OS/HTTP side effects.

- [ ] **1.1 Establish the minimal build and discoverable failing tests.** Create the exact Cargo dependencies/toolchain/version/license above, `.gitignore` entries `/target/` and `/dist/`, and module declarations. Generate `Cargo.lock` once with `cargo +1.100.0 generate-lockfile`; review its actual graph. Use the full standard MIT text with `Copyright (c) 2026 rammses`. CLI accepts only the documented options/aliases; reject positional/non-UTF-8/unknown arguments, allow repeated `--offline`, reject combinations of distinct action modes. Add RF4 cases without parsing arguments by substring.

```rust
#[test]
fn cli_defaults_public_and_rejects_positional() {
    use std::ffi::OsString;
    assert_eq!(crate::cli::parse(&[]).unwrap(), crate::cli::Action::Run { offline: false });
    assert!(crate::cli::parse(&[OsString::from("eth0")]).is_err());
}
```

- [ ] **1.2 Observe focused RED**, then implement argument behavior and owned model validation. Run `cargo +1.100.0 test --locked cli_`; record the wrong/missing behavior that fails, not only an import error. Add tests for `--offline`, `-h`, `-V`, `--offline --help` usage error, and invalid OS-string bytes using Unix `OsStringExt`.
- [ ] **1.3 Write rate tests before calculation.** Literal fixture: same index/name, counters RX 100→250100 and TX 500→1000 over **2 seconds**, expected RX **1,000,000 bit/s**, TX **2,000 bit/s**. Mutate index, raw name, missing samples/directions, zero/earlier time and decreasing counters; invalidate only the affected valid direction when identity/time remain valid. New devices in `after` remain with unavailable rates. Same-index/name, nondecreasing-counter replacement is deliberately indistinguishable and must not produce a claim of proven continuity.

```rust
#[test]
fn sample_rates_use_bits_and_actual_elapsed() {
    use crate::model::{Counters, Interface, InterfaceId, Rates, State};
    use std::time::{Duration, Instant};
    let at = Instant::now();
    let before = Interface {
        id: InterfaceId { index: 7, name: b"eth0".to_vec() },
        state: State::Up, addresses: vec![], link_address: None,
        mtu: Some(1500), speed_bps: None,
        counters: Some(Counters { at, rx_bytes: Some(100), tx_bytes: Some(500) }),
    };
    let mut after = before.clone();
    after.counters = Some(Counters {
        at: at + Duration::from_secs(2), rx_bytes: Some(250100), tx_bytes: Some(1000),
    });
    assert_eq!(super::rates(&before, &after),
               Rates { rx: Some(1_000_000.0), tx: Some(2_000.0) });
}
```

- [ ] **1.4 Run `cargo +1.100.0 test --locked sample_` RED; implement rates/merge.** Compare full `InterfaceId`; use `Instant::checked_duration_since`, require positive duration, subtract before conversion/multiplication, and reject nonfinite results. Merge only after-inventory entries; no saturating-reset-to-zero behavior. Check `u64::MAX` counter values do not overflow integer multiplication.
- [ ] **1.5 Run GREEN and common full checks.** Seed README with purpose, supported OS/architectures and the snapshot limitation, not a claim the app/release already exists. Record checkpoint/review before advancing.

**Acceptance:** pure domain and CLI tests pass; graph has only approved production dependencies; no net/OS collection exists yet. Bootstrap compilation is not reported as complete application behavior.

## Task 2: Linux inventory, native counter transport and driver speed

**Owner:** one Implementer/Builder. **Depends:** 1. **Files:** `src/platform/mod.rs`, `src/platform/linux/{mod.rs,netlink.rs,inventory.rs,ethtool.rs,tests.rs}`; lib module registration. **Consumes:** owned model types. **Produces:** `linux::snapshot`, `netlink::dump(kind: u16, payload: &[u8]) -> Result<Vec<u8>, CollectError>` containing validated complete native messages, and portable checked decoder functions `decode_stats64(&[u8]) -> Option<(u64,u64)>`, `decode_links(&[u8], Instant) -> Result<Vec<Interface>, CollectError>`, `attach_addresses(&mut [Interface], &[u8]) -> Result<(), CollectError>`. Actual sockets are Linux-only; wire functions compile in host tests on either OS.

- [ ] **2.1 Add literal native-byte decoder regressions (RF1/RF4).** Native-endian fixture encoding helpers in `tests.rs`: `attr(kind,payload)` emits a four-byte rtattr header plus payload with zero padding to a four-byte boundary; `message(kind,seq,payload)` emits a 16-byte nlmsghdr with exact payload length. Each helper checks overflow. Expected results must be literals, not generated by the decoder under test.

```rust
#[test]
fn linux_snapshot_stats64_accepts_64_bit_prefix_and_growing_tail() {
    let bytes: Vec<u8> = [7_u64, 9, 4_294_967_396, 8_589_934_792]
        .into_iter().flat_map(u64::to_ne_bytes).collect();
    assert_eq!(super::inventory::decode_stats64(&bytes),
               Some((4_294_967_396, 8_589_934_792)));
    assert_eq!(super::inventory::decode_stats64(&bytes[..31]), None);
}
```

Add link-only/down/UNKNOWN/tunnel/bridge fixtures; preserve raw names, reject zero/negative indices, decode MTU/link address optionally. Add multiple v4/v6 prefixes and scoped IPv6; prefer `IFA_LOCAL` to point-to-point peer `IFA_ADDRESS`; retain every actual assigned address. Unknown link/address attributes may be skipped only after bounds validation.
- [ ] **2.2 Observe RED:** `cargo +1.100.0 test --locked linux_snapshot_`. Implement portable decoding with checked lengths and native-endian integer reads, never references into possibly unaligned netlink bytes. `IFLA_STATS64` RX/TX offsets are **16/24**, needing at least **32 payload bytes**, not full current-struct equality. Missing stats stay unavailable; no sysfs/32-bit fallback.
- [ ] **2.3 Add transport error tests before socket implementation.** Exercise datagram batches through an internal receive seam, with explicit sender/sequence/message flags supplied: kernel sender sockaddr pid 0, expected request sequence; zero-error ACK, nonzero ERROR, error-bearing DONE, interrupted flag on any message, MSG_TRUNC, EOF, malformed length/alignment, mismatched sender/sequence, timeout/EINTR. A partial inventory dump is an error. Unknown unrelated messages cannot reset the deadline or make an infinite loop.
- [ ] **2.4 Implement bounded transport and native snapshots.** Use `OwnedFd`/RAII and a fresh bound NETLINK_ROUTE socket in the calling thread; nonzero sequence, expected family, checked completion. Validate the recvmsg sender sockaddr as kernel-owned separately from the message header's port ID (the latter need not be zero). Return complete framed expected reply messages, excluding consumed ACK/DONE control messages. One whole-dump deadline **1 second**, at most **one retry** after interrupted dump; cap **4 MiB/datagram**, **16 MiB/dump**. Poll/retry respects the original deadline. GETLINK and GETADDR collect complete inventory; a failed address dump must not masquerade as “all interfaces have no addresses.” Return an explicit inventory error rather than silently incomplete IP data. Tag counter samples near their collection with `Instant`.
- [ ] **2.5 Add ethtool handshake/identity/sentinel tests before ioctls.** `ETHTOOL_GLINKSETTINGS=0x4c`, fixed header **48 bytes**; initial nwords=0 can succeed with a negative required count and invalid speed. Widen the signed value before negation; accept magnitude **1..127**, reject -128; allocate `48 + 3*nwords*4` (max **1572**) and validate returned command/positive count. `ETHTOOL_GSET=1` fallback uses **44-byte** legacy layout and speed low/high at **12/28**. Test no-support/permission failures, zero/u32::MAX/legacy unknown, changed name/index; Mbps→bps uses checked multiplication. Positive down-link values remain driver reports, not a negotiated-live-link claim.
- [ ] **2.6 Observe RED with `cargo +1.100.0 test --locked linux_ethtool_`; implement Linux-only socket/ioctl access.** Use libc's `ifreq.ifru_data`, local checked ABI definitions only where libc lacks them; never call setters. Reconfirm name/index before and after. Data-provenance fixtures pair matching index/name with contradictory socket-native and wrong-view sysfs sample values: only native input is eligible, and absent native statistics/speed remains unavailable despite the tempting filesystem value. This tests source selection, not a mock's mere presence. Do not add a production filesystem fallback or test-only file-access method. Task8 adds a real syscall-trace gate to corroborate that the compiled binary never obtains interface data from sysfs; fixtures alone are not claimed as proof of filesystem behavior.
- [ ] **2.7 GREEN, complete checks and native read-only unit smoke.** On Linux, a `linux_snapshot_native` test calls `snapshot()` and validates unique positive indices, valid scopes/prefix bounds and loopback inventory without generating traffic. Record native-versus-fixture evidence. macOS syscall execution remains pending Task 8; record checkpoint/review.

**Acceptance:** host-portable decoder/error tests and actual Linux snapshot smoke pass; complete inventory or explicit error; no sysfs-derived field. Target ABI evidence and safety comments accompany each unsafe call.

## Task 3: Linux all-table, multipath and nexthop-object defaults

**Owner:** one Implementer/Builder. **Depends:** 2 for complete netlink transport. **Files:** `src/platform/linux/{routes.rs,nexthops.rs}` and Linux module/tests. **Consumes:** Task-2 `dump`, model `Defaults/Coverage`. **Produces:** `linux::defaults() -> Defaults`; portable `routes::decode(&[u8], &BTreeMap<u32, nexthops::Hop>) -> Coverage<BTreeSet<u32>>`; `Hop = Device { index: u32, usable: bool } | Group(Vec<u32>) | Unsupported`.

- [ ] **3.1 Write all-table/native-wire tests (RF1).** Literal fixture set: IPv4 table 254 default→2; table 100 default→7; IPv6 inline multipath→7,9; no-gateway point-to-point default→11. Expected v4 `{2,7,11}`, v6 `{7,9}`; do not collapse table IDs or require gateway. Exclude non-default prefixes and reject/blackhole/unreachable/prohibit routes/dead/linkdown nexthops. Include source-specific defaults as configured membership, without claiming a winning route.
- [ ] **3.2 Observe RED:** `cargo +1.100.0 test --locked linux_routes_`. Decode `rtmsg` **12-byte** header, four-byte route attributes; payload zero destination prefix and unicast forwarding type. Read table override `RTA_TABLE`, direct `RTA_OIF`, and each aligned **8-byte** rtnexthop prefix in `RTA_MULTIPATH`. Family is from the route header; IP byte order is not native integer order. Route/netlink errors produce visible `Incomplete`/`Unavailable`, never complete empty success.
- [ ] **3.3 Add nexthop-ID regressions before resolution.** Linux missing libc bindings are locally scoped from versioned UAPI: `RTA_NH_ID=30`, `RTM_GETNEXTHOP=106`, reply 104; nhmsg **8 bytes**; `NHA_ID=1`, `GROUP=2`, `GROUP_TYPE=3`, `BLACKHOLE=4`, `OIF=5`. GROUP is a flat array of **8-byte** nexthop_grp records (ID at0), not nested attrs. Test direct/group/resilient members, missing IDs, cycles, malformed arrays and unavailable object dump. Preserve discovered known members with an incomplete warning when any member cannot be resolved.

```rust
// Portable resolver regression in nexthops.rs tests.
let hops = std::collections::BTreeMap::from([
    (10, super::Hop::Device { index: 7, usable: true }),
    (11, super::Hop::Device { index: 9, usable: true }),
    (20, super::Hop::Group(vec![10, 11])),
]);
let result = super::members(20, &hops); // contract: Coverage<BTreeSet<u32>>
assert_eq!(result, crate::model::Coverage::Complete(std::collections::BTreeSet::from([7, 9])));
```

`nexthops::members(id:u32, hops:&BTreeMap<u32,Hop>) -> Coverage<BTreeSet<u32>>` uses visited IDs, depth **16**, visited-ID cap **4096**; reaching a bound is incomplete, not a silent omission. Add cycle 20→21→20 and dead-device cases with literal expected warnings/sets.
- [ ] **3.4 Observe RED:** `cargo +1.100.0 test --locked linux_nexthops_`; implement object parsing/resolution and GETROUTE dumps for both families with **no main-table filter**. Query objects only when NH IDs are present. Unsupported family/kernel/objects degrade the relevant default coverage, not mandatory local inventory. Unknown optional route attributes do not alone imply missing membership; recognized unsupported forwarding objects do.
- [ ] **3.5 GREEN and full checks.** A Linux native defaults smoke reads actual routes only; no route/rule/namespace modifications. Review verifies table-all request construction as well as supplied-fixture parsing. Record checkpoint/review.

**Acceptance:** every usable configured default member in supported direct/inline/object fixtures is marked; incomplete discovery is explicit. No single-destination lookup, external `ip`, or privileged networking changes.

## Task 4: Darwin inventory, IFMIB64 and valid media semantics

**Owner:** one Implementer/Builder. **Depends:** 1; portable model only. **Files:** `src/platform/macos/{mod.rs,wire.rs,inventory.rs,media.rs,tests.rs}` and platform module registration. **Produces:** `macos::snapshot`; portable `wire::ifmib_counters(bytes:&[u8], expected_name:&[u8]) -> Option<(u64,u64)>`, `wire::prefix(mask:&[u8]) -> Option<u8>`, `media::state(admin_up:bool,status:Option<u32>) -> State`, `media::speed(active:u32,status:u32) -> Option<u64>`.

- [ ] **4.1 Write packed/zero-data and name/address tests (RF2/RF4).** Versioned ABI: libc **0.2.191** exports `ifmibdata` **180 bytes**, alignment4; `ifmd_data` at52; RX/TX absolute offsets **116/124**, each native-endian u64. Initialize a 180-byte literal fixture, name `en0\0`, RX **4,294,967,396**, TX **8,589,934,792**; assert those exact parsed values. All-zero success, wrong/unterminated name and truncated fields must return unavailable. Test short/long/noncontiguous masks: valid contiguous masks yield prefixes, otherwise None without dropping IP.

```rust
#[test]
fn darwin_inventory_zero_filled_ifmib_is_not_a_valid_zero_sample() {
    assert_eq!(super::wire::ifmib_counters(&[0_u8; 180], b"en0"), None);
}
```

- [ ] **4.2 Observe RED:** `cargo +1.100.0 test --locked darwin_inventory_`; implement byte decoders with checked slices/read_unaligned. No reference to packed u64 fields, no widened `if_data` counters, no cached counter fallback.
- [ ] **4.3 Implement target-gated getifaddrs/IFMIB snapshot.** RAII-free the list once; preserve AF_LINK-only entries and variable-length `sockaddr_dl` using its actual length/name/address extents (not fixed sdl_data[12] as a cap). Copy v4/v6/netmask and scope data, merge by index/raw name, no lossy identity conversion. IFMIB is `[CTL_NET,PF_LINK,NETLINK_GENERIC,IFMIB_IFDATA,index,IFDATA_GENERAL]`; use exported libc types/selectors and read-only sysctl. Validate returned size and matching name; reconfirm index/name around the query. MTU comes from validated native data; missing optional fields remain None. Mandatory inventory/address decoding failures are explicit errors.
- [ ] **4.4 Add state/speed/ABI tests before media ioctl.** Admin-down always DOWN; otherwise AVALID(1)+ACTIVE(2) is UP, valid inactive DOWN, absent/invalid status UNKNOWN regardless of IFF_RUNNING. `ifmediareq` local representation is `repr(C, packed(4))`: name16, five i32s, pointer at36, size44/alignment4. Use exported SIOCGIFXMEDIA first, compatibility SIOCGIFMEDIA only if unsupported. Selected/auto/nominal baudrate are not inferred live speeds.
- [ ] **4.5 Observe RED:** `cargo +1.100.0 test --locked darwin_media_`; implement recognized active Ethernet subtype speeds only. IFM type mask `0xe0`, Ethernet `0x20`, subtype mask `0x000f001f`; translate extended subtype number n with `(n & 0x1f) | ((n & 0x1e0) << 11)`. Recognize numeric subtypes 3/4/5/12/13→10M, 6/7/8/9/10→100M, 11/14/15/16/24/25→1G, 22/extended32/36/63→2.5G, 23/extended64/69/70→5G, 18/19/20/21/26/27/28/29/extended33/34/35/42/59→10G, 30→20G; other recognized Ethernet groups may be added only from the pinned SDK header with a literal test. Unknown/auto/other/non-Ethernet/invalid or inactive media speed is unavailable. No Wi-Fi/CoreWLAN probing.
- [ ] **4.6 GREEN portable tests and common checks on host; add native-only layout/snapshot tests for Task 8.** On Darwin assert actual `size_of`/`align_of`/`offset_of` against the values above and selected SDK headers, plus read-only loopback inventory and IFMIB observations. If SDK layout differs, stop: do not cast anyway. Record native test status **pending** until it actually runs; host decoder success is this task's local acceptance, not complete macOS support.

**Acceptance:** portable Darwin parsing/state tests pass, native calls are correctly target-gated and documented, mandatory native runtime evidence is scheduled and unresolved until Task 8.

## Task 5: Darwin scoped/gateway-free default-route inventory

**Owner:** one Implementer/Builder. **Depends:** 4 for checked Darwin wire utilities. **Files:** `src/platform/macos/routes.rs`, macOS mod/wire/tests. **Produces:** `macos::defaults`; portable `routes::decode(bytes:&[u8], family:Family) -> Coverage<BTreeSet<u32>>`. **Consumes:** libc target route headers only on Darwin; model coverage elsewhere.

- [ ] **5.1 Add native-layout fixtures (RF2).** `NET_RT_DUMP` headers are **92 bytes**, RTM_VERSION **5**, RTM_GET **4**; sockaddr entries follow RTAX bitmap order with **4-byte ROUNDUP32** stride, including **4 for zero sa_len**. Include multiple same-family defaults scoped to en0/utun, IPv4 and IPv6, interface via header index or applicable AF_LINK field, zero/short netmask, gateway-free point-to-point default; expect literal index sets. Include nondefault destinations/masks, reject/blackhole/dead/down routes, wrong version/type, short header, impossible msglen and malformed sockaddr lengths.

```rust
#[test]
fn darwin_routes_zero_length_sockaddr_advances_four_on_lp64() {
    assert_eq!(super::wire::sockaddr_stride(0), Some(4));
    assert_eq!(super::wire::sockaddr_stride(5), Some(8));
}
```

`wire::sockaddr_stride(length:usize) -> Option<usize>` uses checked add/rounding, never sizeof(long). A shortened mask is padded with zeroes only to interpret its actual bits; do not demand a full ordinary sockaddr for netmask records.
- [ ] **5.2 Observe RED:** `cargo +1.100.0 test --locked darwin_routes_`; implement bounds-checked portable route decoding and bitmap iteration. Preserve every usable default, not only a gateway route or one selected egress; wrong/partial data produces visible coverage failure for the relevant family. Respect RTM_GET versus GET2 layouts; use DUMP/GET consistently, not mixed headers.
- [ ] **5.3 Implement target-gated sysctl size/query loop.** MIB `[CTL_NET,PF_ROUTE,0,family,NET_RT_DUMP,0]`, v4/v6 separately; no setters. At most **3 attempts** for growth races, max **16 MiB** buffer; zero-length successful dump can mean complete empty routes, but an unsuccessful/truncated dump cannot. Preserve useful known members only with an incomplete warning. Add controlled native-boundary tests for each error/resize result.
- [ ] **5.4 GREEN and common checks; add Darwin native read-only defaults/layout tests for Task 8.** No external `route` invocation and no host routes modified. Record pending native SDK/runtime gate and checkpoint/review.

**Acceptance:** all portable scoped/gateway-free/malformed fixtures pass and the native boundary is target-gated with explicit failure coverage.

## Task 6: Secure public lookup workers and a nonblocking result boundary

**Owner:** one Implementer/Builder. **Depends:** 1. **Files:** `src/public/{mod.rs,http.rs,tests.rs}`, lib module registration. **Consumes:** model Family/PublicReport. **Produces:** §2-contract-table `PublicSource`, `PublicWorkers::new`, `LookupFn`; `http::lookup`; internal `http::config(Family) -> ureq::config::Config`, `http::parse_body(Family,&[u8]) -> Option<IpAddr>`, `http::response_ip(status:u16,family:Family,body:&[u8]) -> Option<IpAddr>` and `public::Completion { family:Family, completed_at:Instant, value:Option<IpAddr> }`.

- [ ] **6.1 Add strict family/body/config tests before HTTP wiring.** Public values are parsed independently from literals, rejecting >128 bytes before trimming, invalid UTF-8, HTML, extra tokens, wrong family, IPv6 scope suffixes, and mapped IPv6 as an IPv4 response. HTTP status must equal200, not merely avoid 4xx/5xx. Test the actual ureq configuration object, not a duplicate policy model.

```rust
#[test]
fn public_http_policy_is_direct_https_and_verified() {
    let c = super::http::config(crate::model::Family::V4);
    assert!(c.https_only());
    assert!(c.proxy().is_none());
    assert_eq!(c.max_redirects(), 0);
    assert_eq!(c.ip_family(), ureq::config::IpFamily::Ipv4Only);
    assert!(!c.tls_config().disable_verification());
    assert!(matches!(c.tls_config().root_certs(), ureq::tls::RootCerts::WebPki));
    assert_eq!(super::http::parse_body(crate::model::Family::V4, b"203.0.113.9\n"),
               Some("203.0.113.9".parse().unwrap()));
    assert_eq!(super::http::parse_body(crate::model::Family::V4, b"::1\n"), None);
}
```

- [ ] **6.2 Observe RED:** `cargo +1.100.0 test --locked public_http_`; construct config with explicit HTTPS/family/proxy(None)/redirect0/WebPKI/Rustls settings; timeout_connect/recv_response/recv_body **500 ms** each. Do not rely on any timeout for main's exit; no need to set a DNS timeout that spawns additional application helper work. Inside `lookup` only, create Agent, issue exactly one GET to the fixed family host, reject non200 before consuming a body, read strict bytes using `.with_config().limit(128).read_to_vec()`, then call `response_ip`, which enforces status200 and delegates to `parse_body`. Literal response tests cover status200/201/204/301/400/500 against the actual validation function used in lookup. All failure results are None; no logs/raw response output, retries, main-owned Agent, or network work in config creation. Bound headers to **8192 bytes**.
- [ ] **6.3 Add cutoff/queue tests and observe RED:** `cargo +1.100.0 test --locked public_queue_`. `Completion` fixtures before/at/after cutoff with literal family addresses exercise validation/duplicate family handling; empty channel is immediately unavailable, one valid family preserves the other unavailable. At most two nonblocking receives. Tests fail if `recv`, a timeout/grace loop, acceptance of late data, or waiting for sender cleanup is introduced.
- [ ] **6.4 Implement workers.** Channel capacity2, one `thread::Builder::spawn` per family; dropping JoinHandle detaches. Capture only function pointer/family/sender; invoke the entire `lookup` callback **inside** worker, then timestamp and `try_send` a single Completion. `start` is single-use; spawn failure leaves that family unavailable. `take_ready` never starts work, joins or uses a main-held network lock. Drop receiver without joining. Main must not own Agent/configuration requiring network cleanup. Normal errors cannot panic/log; don't install a process-wide panic hook to hide defects.
- [ ] **6.5 GREEN plus common full checks and feature graph inspection.** Run `cargo +1.100.0 tree --locked -e features`; confirm no native/platform TLS verifier, async runtime, proxy enablement or decompression feature was pulled in. Record this as evidence, not a source-string test. Task7 owns executable blocked-worker teardown coverage.

**Acceptance:** real policy/parser/queue tests pass without internet; callbacks run only in detached workers and no join/blocking receive path exists.

## Task 7: Integrate real CLI/report and executable no-wait regressions

**Owner:** Builder/integrating Implementer. **Depends:** 1–6 (actual functions, not placeholder adapters). **Files:** `src/{app.rs,render.rs,main.rs}`, lib/platform composition; `tests/{cli_process.rs,lifecycle.rs,support/mod.rs}`; README. **Produces:** runnable binary, Collector/Clock/Style contracts and `app::run` exactly as §2 defines. `NativeCollector` delegates to only the current OS's complete snapshot/default functions.

- [ ] **7.1 Write report and orchestration tests first (RF3/RF4).** A test-only `FakeCollector` owns a queue of `Result<Snapshot,CollectError>` and exact Defaults; test-only `FakeClock` owns an Instant advanced by sleep; `FakePublic` records starts/cutoff and returns literal PublicReport. Define these helpers in `tests/support/mod.rs` using the model types; no test-only cleanup/control methods on production structs. Verify factory invocation counts as **side-effect prevention**, as well as returned output/status. Help/version/invalid usage never evaluate either factory; offline never evaluates public factory. Required second snapshot error returns1 with no public join; optional default failure preserves all interfaces/addresses and says unavailable.
- [ ] **7.2 Observe RED:** `cargo +1.100.0 test --locked app_`; implement this fixed flow:

```text
parse action -> early usage/help/version result if applicable
make collector -> first snapshot (mandatory)
if online: make public source and start (no Agent on main)
clock.sleep(Duration::from_secs(1))
second snapshot (mandatory) -> cutoff = clock.now()
online take_ready(cutoff), or offline Disabled/Disabled
collect default inventory -> combine per-interface rates -> render
fallible write_all and flush -> return mapped exit code
```

Keep factories lazy, use the real production coordinator in all lifecycle tests, and flush inside the error-mapped path. A BrokenPipe from write **or flush** is quiet0; another I/O error is1. Drop public source on every path without waiting. Query defaults after cutoff so local route-collection time cannot enlarge the public result window.
- [ ] **7.3 Write rendering tests, then implement `render::text` and Style.** Test both families/default markers, every address including zones, empty inventory versus no-IP interfaces, rates0/unavailable and scaled units, unknown/invalid MTU/speed, conservative states, deterministic ordering, default coverage warnings. Escape all ASCII controls/ESC/DEL and invalid bytes in names (e.g. bytewise `\x1b`), preserving readable normal UTF-8 without emitting terminal-control Unicode. Mask failures show `prefix unavailable`, not `/0`. Match plain/colored reports by semantic labels, not a brittle whole-output golden for every spacing choice. RF4 expected: interface raw name `b"vpn\x1b[31m"` displays literal escaped bytes, never a terminal color sequence from that name; scoped `fe80::1` keeps the interface/zone.
- [ ] **7.4 Add thin main wiring and process regressions.** App/output behavior already has RED/GREEN above; main only forwards `OsString` arguments excluding argv0, real factories, `SystemClock`, detected Style and locked stdout/stderr, then returns `ExitCode::from(app_status)` without panic printers. `tests/cli_process.rs` invokes `env!("CARGO_BIN_EXE_ipnedir")` for help/version/offline/usage and checks real exit/status/no ANSI. Establish the named binary before counting behavioral results; missing-binary compile errors are not RED evidence. Early-close stdout immediately in a pipe: ensure no stderr/panic and exit0. Test other output errors with a deliberately failing `Write` in app unit tests before implementing the corresponding mapping.
- [ ] **7.5 Implement executable blocked-worker tests (RF3), not a thread demo.** In `tests/lifecycle.rs`, a `child_entry` test is inert normally. The parent re-execs `std::env::current_exe()` with `--exact child_entry --nocapture --test-threads=1` and a **test-binary-only** case environment. Child calls the same `app::run`, real `PublicWorkers`, and an injected LookupFn parked forever at a named DNS/connect/TLS/body boundary; it verifies each worker entered via test-only atomics. These callbacks replace only the slow external operation, not coordinator/queue/drop/render. Include failing second snapshot and BrokenPipe cases after worker start. Crucially, child **drops all app/public state normally and returns** to the harness; no `process::exit` to bypass destructors and no scoped worker join. No environment override or hidden flag enters the release binary.

Parent watchdog uses `Child::try_wait` at10ms intervals up to **3 seconds** for the real1s sample, drains stdout/stderr without blocking on a hung child, and kills+waits on failure. Blocking lookups never receive a release signal: a faulty join cannot pass by reaching a worker timeout. Unit fake-clock tests separately assert exactly one1s sleep and no network grace. DNS/connect/TLS/body cases establish the production ownership boundary with injected blocking; HTTP configuration/security remains tested in Task6, not claimed to be live-provider verification. Output must include local report/unavailable public results and no panic. Ensure tests do not deadlock their own stdout pipe by keeping fixture reports bounded.
- [ ] **7.6 Run focused RED/GREEN and complete checks**, then `cargo +1.100.0 build --locked --bin ipnedir` and `./target/debug/ipnedir --offline`; compare local live fields against native OS observations without generating traffic. Do not invoke the shell alias or make a live icanhazip request as an automatic test. README now covers all flags, privacy/direct-proxy policy, sample limitation, unknown native metadata, OS baselines and manual alias migration advice without editing user files. Record checkpoint/review.

**Acceptance:** runnable local binary and process/error/lifecycle regressions pass on host; network completion never gates local output or exit. Actual macOS/native architecture gates remain Task8, not a Linux-only all-platform claim.

## Task 8: Execute native four-platform verification through read-only CI

**Owner:** Builder for CI/integration; owner supplies authorized remote/native runner access. **Depends:** 7. **Files:** `release/targets.tsv`, `xtask/{Cargo.toml,src/lib.rs,src/main.rs,src/targets.rs}`, workspace/lock, `.github/workflows/ci.yml`, `tests/native_smoke.rs`, README compatibility/evidence. **Produces:** one target manifest, `xtask matrix` JSON, native verification evidence for each platform; no publication.

- [ ] **8.1 Write manifest-validation tests (RF5).** TSV columns `target`, `runner`, `archive`; four literal rows exactly matching §1 matrix/spec artifacts. `xtask::targets::parse(&str) -> Result<Vec<Target>,String>` rejects missing/duplicate/extra targets, path traversal/unsafe names and mismatched filename/runner architecture. `Target { target:String, runner:String, archive:String }`; `matrix(&[Target]) -> String` produces JSON `{"include":[...]}` using validated ASCII fields. Test actual parser/JSON output with literal expectations, not grep for workflow text.
- [ ] **8.2 Observe RED:** after adding std-only tooling package `xtask` (dependency `ipnedir={path=".."}` only to consume `VERSION`), update workspace `members=[".","xtask"]` and regenerate/review lockfile once. Run `cargo +1.100.0 test --locked -p xtask`; implement manifest/parser/matrix and CLI `cargo +1.100.0 run --locked -p xtask -- matrix` (stdout JSON only). Unknown commands exit2; tool errors nonzero. This is developer tooling, not another installed user app.
- [ ] **8.3 Add native-smoke integration tests and ABI checks.** On each OS collect twice; assert sane inventory, unique indices/raw names, valid scopes/prefixes, loopback exists, optional unsupported values allowed, bytes are actual u64 not32-bit. Validate Darwin packed layouts/selectors/native reads; confirm Linux counters/ioctl source path. On Linux CI, supply the developer-only `strace` tool (install in the ephemeral runner if absent), run `strace -f -e trace=%file -o native-files.trace "./target/$TARGET/release/ipnedir" --offline`, and reject interface-data file access under `/sys` rather than assuming fixtures prove its absence. A trace-tool failure is a gate failure, not empty evidence. Assert native-data unavailable paths do not read wrong-view sysfs fields. No host networking changes, required Internet for app tests, or assumptions that CI has Wi-Fi/physical Ethernet. Read-only OS reference commands may be used in CI evidence, not in app runtime. Identify any field that cannot be corroborated rather than manufacturing a value.
- [ ] **8.4 Implement `ci.yml` with push branches/pull_request/workflow_dispatch/workflow_call, contents:read and no secrets.** Matrix-generation job runs xtask; four native jobs use its rows. Pin Rust1.100.0, fmt/test/clippy all workspace targets with --locked, release-build `--package ipnedir --bin ipnedir --target "$TARGET"`, run the target binary's version and offline smoke on that native runner, record rustc/OS/architecture/glibc or deployment target. No `pull_request_target`, remote writes or release environment. Each matrix leg fails independently; no continue-on-error/skip replacing native evidence.

Resolved official-action pins, checked via remote tag refs 2026-11-24:

```yaml
- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
  with:
    persist-credentials: false
- uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7
- uses: actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8
```

Upload only explicit verification/artifact paths, no home directories/secrets; `if-no-files-found: error`. Preserve selected runner images/commit in evidence. A retired pin/runner is a reported environment blocker requiring an reviewed compatible update, not silently ignored checks.
- [ ] **8.5 Run complete local suite plus xtask matrix validation.** Obtain actual four-runner results only through an owner-authorized repository/native environment. The local absence of gh or remote permission is not permission to install/authenticate/create/push; stop and request that specific capability. If access is not provided, report **verification blocked**, keep native matrix gates pending and do not claim v1 ready or start publication. Native task4/5 pending gates close only with real Darwin evidence.

**Acceptance:** all four native build/test/smoke legs green with exact revision evidence; no publication credentials or user-network mutations. Preparing YAML alone does not meet this task's final acceptance.

## Task 9: Prepare verified binary archives, formula and gated release workflow

**Owner:** Builder for tooling/code; Release Owner for later authorized publication/tap operations. **Depends:** 8 verified targets. **Files:** `xtask/src/{package.rs,formula.rs}`, xtask dispatch/tests, CI packaging extension, `.github/workflows/release.yml`, C1 shared CI-only `.github/scripts/artifacts.py`, `docs/releases.md`, README. **Consumes:** Target manifest, `ipnedir::VERSION`, verified native binaries. **Produces:** exact archives/checksums and generated formula artifact; safe release workflow/runbook. Shared artifact-download/provenance/digest/ZIP validation must have one tested implementation in the C1 helper, imported by both workflows; differing selection/caller wiring stays in each workflow. This adds no app runtime dependency, public app/developer CLI interface, or publication permission. Do not write into or change the live tap during implementation.

- [ ] **9.1 Write release-gate/manifest tests before tooling (RF5).** `xtask::package::verify_tag(tag:&str,version:&str) -> Result<(),String>` accepts only exact `v{version}`. `Archive { target:String, file:String, sha256:String, version:String, source_revision:String }`; validate four unique complete manifest members, strict64-character lowercase checksum, safe names, current version and identical source revision. Native CI records its actual `GITHUB_SHA`; local uncommitted preparation may record `local-uncommitted` but can never pass publication checks. Recompute checksums against actual bytes before formula generation; reject missing/renamed/tampered archive. Do not embed placeholder SHA256 values or fixed fake URLs into a distributable formula.

```rust
#[test]
fn release_tag_must_match_package_version_exactly() {
    assert!(super::verify_tag("v0.1.0", "0.1.0").is_ok());
    assert!(super::verify_tag("v0.1.1", "0.1.0").is_err());
    assert!(super::verify_tag("0.1.0", "0.1.0").is_err());
}
```

- [ ] **9.2 Observe RED:** `cargo +1.100.0 test --locked -p xtask release_`; implement commands:

```text
xtask matrix
xtask verify-tag <tag>
xtask package <target> <dist-directory>
xtask prepare-release <tag> <dist-directory>
xtask check-publish <event> <requested> <enabled> <tag> <dist-directory>
```

These are tooling arguments, not app flags. `package` validates target matches the current native OS/architecture, runs the exact source binary's version/offline smoke and verifies version equals `ipnedir::VERSION`, then takes `target/<target>/release/ipnedir`, includes exactly root `ipnedir`, `LICENSE`, `README.md`, and invokes build-time tar to produce manifest's filename. `package::check_arch(target:&str, bytes:&[u8]) -> Result<(),String>` checks actual executable headers: little-endian ELF64 with machine62 (x86-64) or183 (AArch64), or Mach-O64 magic0xfeedfacf with CPU0x01000007 (x86-64) or0x0100000c (ARM64); wrong/truncated/fat/unexpected headers fail rather than being mislabeled. Record target/version/source revision in checksum metadata. SHA256 is computed from actual archive bytes using `sha256sum` on Linux or `shasum -a 256` on macOS; fail on tool/parse errors. Use temp directories under the chosen dist directory with atomic final replacement only after success; reject symlinks/traversal. A tiny known file `abc` must hash to literal `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`, independent of another helper under test. Tests create/clean their own scoped fixtures; production package code has no test-only cleanup API.
- [ ] **9.3 Implement aggregate verification and formula generation.** `prepare-release` checks tag/version, all four exact archives, archive entry names/types (no absolute/../symlink entries), recalculated hashes, target/version/source-revision manifest consistency and actual archived binary headers through `check_arch`; only safely extract to its private temporary directory after entry validation. Outputs `dist/checksums.txt` and `dist/Formula/ipnedir.rb` only when the set is complete. Formula class `Ipnedir`, homepage rammses/ipnedir, MIT, current version; on_macos/on_linux and on_arm/on_intel blocks select exact target URL `https://github.com/rammses/ipnedir/releases/download/<tag>/<archive>` plus actual hash, `bin.install "ipnedir"`; tests assert version and a real `--offline` local report. Generation tests compare all four URL/name/checksum associations and fail on swaps, duplicate/missing targets or unsafe version/URL input. No network required to generate/check fixture formulas.
- [ ] **9.4 Package/test each native binary in CI.** Extend reusable ci.yml with boolean `package` defaultfalse; package each successful native binary and upload archive plus its checksum record, then aggregate only after all four jobs pass. Recompute actual SHA256 in aggregate; a single failed/missing target stops formula/release preparation. Smoke each local archive's extracted binary by explicit path with --version/--offline before upload; developer packaging may use tar/sha commands, app runtime still must not.
- [ ] **9.5 Add fail-closed `release.yml` preparation/publication split.** Tag push `v*` prepares verified candidates; workflow_dispatch on the selected tag can request `publish` (boolean defaultfalse). The build/preparation jobs remain contents:read, no tap secret. Publication requires **all**: successful four-target preparation; workflow_dispatch, exact tag/version/ref; input publish true; repository variable `IPN_RELEASE_ENABLED == 'true'`; and protected environment `release` with owner-configured required reviewer. Only the publication job gets contents:write and uses runner gh CLI to create the release from the same verified tag/artifact set. No PR/untrusted-code event receives write credentials. Owner must configure/approve that environment and variable separately; lack of protection blocks publication. Do not automatically enable or test a live publish path during implementation.

Publication command in the gated job, **not a Planner/Builder command to run now**:

```sh
gh release create "$GITHUB_REF_NAME" dist/*.tar.gz dist/checksums.txt \
  --repo "$GITHUB_REPOSITORY" --verify-tag --generate-notes
```

`GH_TOKEN` is supplied only by that job's scoped GitHub token. Pass untrusted refs through environment/quoted arguments, never inline shell-code interpolation. Do not overwrite an existing tag/release/assets silently; fail and require owner judgment. Prepare and upload formula as a separate artifact; no automatic cross-repository push or deploy-key creation.
- [ ] **9.6 Verify offline tooling/release controls and document owner runbook.** Run whole workspace tests, native package/version/offline smoke, checksum+tar-list checks and formula-generation fixtures. Unit-test the actual `publication_allowed(event:&str,requested:bool,enabled:bool,tag_ok:bool,builds_ok:bool) -> bool` used by `xtask check-publish` (all true and exact workflow_dispatch event required); call that command in the gated job immediately before release creation with actual event/input/variable/tag/dist values. `builds_ok` includes four hashes/versions/architectures and source_revision matching the clean checked-out selected tag commit, not `local-uncommitted` or an arbitrary input SHA. Also independently review the actual workflow job condition/environment/permissions and have owner confirm environment protection before any real release. Do not pretend a predicate test proves GitHub settings are configured. `docs/releases.md` lists separate owner authorization, remote/name/access check using gh, tag/version review, four CI URLs, environment approval, release-assets checksum verification, formula diff restricted to `Formula/ipnedir.rb`, then Homebrew install/test/audit on supported macOS/Linux. Actual tap writes/commit/PR/push and credential setup remain outside this implementation approval.
- [ ] **9.7 Homebrew acceptance, only with owner-authorized published candidates/tools.** Formula runtime tests are offline; downloading release assets for package installation naturally requires authorized network access. After the real formula is installed in the owner's tap, run `brew install rammses/tap/ipnedir`, `brew test rammses/tap/ipnedir`, and `brew audit --strict rammses/tap/ipnedir` on macOS/Linux; compare invoked binary version and offline output. No ghost Homebrew-success claim when tools/assets/tap are absent. Complete local preparation may be reported separately from this blocked publication-dependent acceptance.

**Acceptance:** reproducible verified candidates/formula and fail-closed workflow/runbook pass local+native gates; actual publication/tap installation remain separately authorized and explicitly tracked. No existing bgp-display formula, credentials, user alias or local installation is changed.

## 3. Spec coverage, whole-change acceptance and handoff

| Spec sections | Primary implementation/check ownership |
| --- | --- |
| §§1–2 approval/scope/runtime independence | All task constraints, Builder baseline/review gates; no undeclared product surface |
| §3 flags/exit/report/style/escaping | 1 CLI; 7 actual factories/output/process tests |
| §4 architecture/dependency boundary | 1 models/graph; 2–6 native/public modules; 7 composition |
| §5 shared snapshots/rates | 1 rates; 2/4 samples; 7 merge/report |
| §5 Linux provenance/default completeness | 2 native-only data; 3 all-table/inline/object defaults |
| §5 Darwin 64-bit/media/scoped routes | 4 inventory/media; 5 native routes; 8 actual SDK/runtime |
| §§6–7 no-wait HTTP/lifecycle/privacy | 6 secure policy/queue; 7 shared-production-coordinator process tests/README |
| §8 four-target release/tap safety | 8 native manifest/matrix; 9 archive/formula/gated publication preparation |
| §9 verification/error classes | Focused RED/GREEN every task, full host suite, 8 all-native runtime, 9 archive/formula gates |
| §§10–12 state/migration/evidence/approval | Baseline/handoff ledger and Builder evidence; no implicit alias migration/publication |

Builder's final verification, cwd `/home/rammses/Belgeler/ipnedir` (or recorded isolated equivalent):

```sh
cargo +1.100.0 fmt --all --check
cargo +1.100.0 test --workspace --all-targets --locked
cargo +1.100.0 clippy --workspace --all-targets --locked -- -D warnings
cargo +1.100.0 build --release --locked --package ipnedir --bin ipnedir
./target/release/ipnedir --version
./target/release/ipnedir --help
./target/release/ipnedir --offline
cargo +1.100.0 run --locked -p xtask -- matrix
cargo +1.100.0 tree --locked -e features
```

All four native jobs additionally use their manifest target in build/smoke/package commands; no foreign-target execution on the Linux primary host. Record precise revision, OS, architecture, tool versions, output/exit results and prior-vs-new failures. Read-only live public lookup smoke is optional only with explicit consent; it is not a deterministic acceptance gate. Whole-change review must inspect all changes/interfaces and all pending platform/release limitations, not only the last task. Do not bypass selected SDD sequencing/reviews or claim all-platform readiness with a missing macOS leg.

### Builder handoff constraints

- Artifacts travel together: approved R2 spec and this reviewed/approved plan's exact revisions/hashes, plus review/annotation/approval ledger. Read source references, not old memory as permission.
- Builder owns execution/workspace isolation, all code/tests/tooling, sole shared-state integration, review follow-up and evidence. Planner stops at this handoff; no plan task is started by writing this document.
- Stop for changed substantive artifacts, incompatible ABI, unapproved dependencies/features, missing required review capability, unexplained dirty files, or impossible safety/timing acceptance. Report narrowly what access or decision is needed; don't silently weaken a gate.
- Current environmental blockers are remote/native/Homebrew access and later release protection/credentials; repo availability is unverified. These do not authorize remote writes/tool installation. Native/tap/publication acceptance can remain explicitly pending, never marked passing.
- No local installation/alias migration, Git commits/remote pushes, tap changes or publication without their specific authorization. User's `auto` choice and spec approval do not supply those permissions.
- This handoff preserves the absolute cwd, docs-only/non-Git baseline and protected paths, all required commands/gate owners, and remaining environment blockers above. User selected sequential subagent-driven execution; Builder must load that execution skill, begin with Task1, and retain all task-by-task gates. Planner has not started any task or dispatched an implementation worker for this Rust plan.

## 4. Planning evidence and review/approval ledger

- User approved written spec R2 in chat. Prior Plannotator spec round timed out without a decision; explicit later chat approval is the approval source, not that timeout.
- Native binding evidence IPN-E3: libc **0.2.191**, Linux **v6.12** UAPI, XNU **xnu-12377.1.9**, all checked 2026-11-24. Exact references: <https://github.com/rust-lang/libc/tree/0.2.191>, <https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/ethtool.h>, <https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/nexthop.h>, <https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/bsd/net/if_mib.h>, <https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/bsd/net/if.h>, <https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/bsd/net/if_media.h>, <https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.1.9/bsd/net/rtsock.c>. Header/source evidence is not runtime or target-SDK verification.
- ureq **3.5.2** actual config/TLS/body APIs were checked: <https://docs.rs/ureq/3.5.2/ureq/config/struct.Config.html>, <https://docs.rs/ureq/3.5.2/ureq/tls/struct.TlsConfig.html>, <https://docs.rs/ureq/3.5.2/ureq/struct.BodyWithConfig.html>. No live icanhazip calls.
- GitHub labels/protected environments: <https://docs.github.com/en/actions/reference/runners/github-hosted-runners>, <https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments>. Action pins resolved from the documented official v7/v7/v8 tags with read-only `git ls-remote`; no remote mutations. Availability/settings must be rechecked at execution, not assumed from public docs.
- **P1:** Planner self-review completed: spec-to-task coverage table, all five Review Focus assignments, type/signature/caller consistency, source/toolchain/ABI details, RED/GREEN/full-suite gates, shared-state ownership and approval limits checked.
- **P1 full review IPN-PR1**, checkpoint SHA256 `7526ed9c243d9825f64e4ef6b85e4d67d459df53d5295be88ec4603b3494f4c7`: Approved, no findings. Fresh reviewer covered all 490 plan lines and approved R2 reference, including native/HTTP sources. Subsequent edits only record review/approval status; no substantive plan change.
- Last full-review revision: P1/IPN-PR1 at that checkpoint. Scoped delta coverage: none. Outstanding substantive review coverage gap: none.
- Plan annotation round: ran `plannotator annotate /home/rammses/Belgeler/ipnedir/docs/superpowers/plans/2026-11-24-ipnedir-implementation.md --gate --json` after independent review. The shell tool timed out after 1,200,000 ms with no decision/feedback; subsequent `plannotator sessions` reported no active sessions. This is interrupted annotation, not approval or dismissal. No material changes resulted; no blind retry was made.
- User subsequently replied **“go with subagent”** to the request to approve this reviewed plan and choose execution. This approves P1's reviewed substantive scope and selects **sequential subagent-driven execution**; auto/capable-worker approval is retained independently. No material plan change resulted. Builder owns authorized implementation; Planner ends at this handoff. No commits/staging/pushes, remote creation, publication, credential changes, local install or alias migration are authorized by that reply.
- **C1, 2026-11-25:** after Task9 source review identified duplicated security validators, Builder proposed adding exactly `.github/scripts/artifacts.py` to the Task9 file list; user replied **“fix blockers.”** This authorizes that bounded file-map/shared-implementation correction and the existing subprocess-timeout fix. Only this helper placement/ownership is corrected; R2, interfaces, dependency policy, runtime/security/verification gates and separate publication authority remain unchanged. C1 is carried into Task9 Fix1 and its required fresh scoped re-review; no completed task is reopened or whole plan silently replaced.
