# ipnedir — cross-platform Rust CLI design

Design revision: **R2**, 2026-11-24. Owner: Planner.

## 1. Intent and approval boundary

Build a pleasant, one-shot interface/IP overview named `ipnedir`, implemented in Rust for Linux and macOS. Preserve the useful local information from the installed Python prototype, add best-effort public IPv4/IPv6 information, and prepare distribution through the user's existing Homebrew tap.

Confirmed by the user:

- Both operating systems, with all interfaces and addresses, not just the primary connection.
- Current RX/TX in decimal **bits per second**, automatically scaled; link speed is a separate value.
- Public-IP requests enabled by default, concurrent with the approximately one-second traffic sample. Include responses already available when sampling finishes; do not extend the run for a slow response. Skipping a slow otherwise-valid response is acceptable.
- Project location `/home/rammses/Belgeler/ipnedir` and intended GitHub owner `rammses`.
- Native-backed standalone binary, no Python or external network-command dependency, MIT license, offline/help/version flags, tests on both OSes, and four binary release targets.

The user approved the overall direction with “looks good,” then explicitly approved this reviewed written R2 spec with **“i approve.”** Approval covers the R2 substantive design, including the snapshot-continuity limitation. It permits preparing/reviewing the implementation plan, not implementation or publication; Builder execution requires the reviewed plan and an explicitly selected execution method.

## 2. Scope and non-goals

V1 is a single invocation, one report, and normal process exit. No watch/TUI mode, JSON/export format, custom sampling interval, interface filtering, configuration file, cache, history, speed test, router configuration, or Windows support. Do not add these to the implementation plan without a design revision.

No root privileges, packet capture, traffic generation to measure bandwidth, or runtime shell-outs. OS-local enumeration is scoped to the current process's network namespace/environment. Public requests use the system's routing choice, not one request per interface: they describe **public egress observed by icanhazip**, not a public address assigned to every NIC. VPN/NAT egress is expected.

Preparing release automation and the future formula is in scope. Creating remote repositories, pushing branches/tags, configuring credentials, publishing releases, and modifying the existing tap are **separate release operations**, not authorized by this design or the planning session.

## 3. CLI and report contract

Executable/package/repository name: `ipnedir`; intended repository `https://github.com/rammses/ipnedir`; license MIT. Initial package version `0.1.0` does not itself authorize tagging a release.

| Invocation | Behavior |
| --- | --- |
| `ipnedir` | Sample local traffic and attempt public IPv4/IPv6 concurrently; print once. |
| `ipnedir --offline` | Same local sample/report, but never start public HTTP or DNS work. Public section says `disabled (--offline)`. |
| `ipnedir --help` / `-h` | Usage and privacy/availability note; no sampling, network work, or collector initialization. |
| `ipnedir --version` / `-V` | Package version, immediately, with no collection/network work. |
| Unknown options or positional arguments | Concise usage error to stderr, exit 2; no collection/network work. |

Success is exit 0 even if optional fields/public lookups are unavailable. Failure to enumerate the local interface inventory is exit 1 with a concise diagnostic, not an empty success report. A genuinely empty, successfully enumerated inventory is reported explicitly. Optional collector failures preserve the inventory and identify unavailable information. Early-closed stdout pipes exit quietly with 0; other output errors exit 1 without a panic.

Report:

- Stable ordering by interface index, then name. Never suppress down/no-IP interfaces.
- Name and `UP`, `DOWN`, or `UNKNOWN` operational badge. Add `* default IPv4`, `* default IPv6`, or both when the interface occurs in the corresponding default-route inventory.
- Every assigned IPv4/IPv6 address with prefix length, and an IPv6 zone/interface identifier for scoped addresses. If an OS supplies an invalid/missing netmask, show the address with `prefix unavailable`; do not invent `/0` or drop the address.
- MAC/link-layer address when meaningfully available, MTU, and separately labeled `Link speed (driver)`.
- RX and TX values; `0.0 bit/s` is a real zero, not missing data. Use bit/s, Kbit/s, Mbit/s, Gbit/s with base 1000 and one decimal place. Unsupported or inconsistent values say `unavailable`.
- A separate `Public egress (icanhazip)` section with IPv4 and IPv6 result/unavailable/disabled, plus a brief legend for default markers and the sample.
- Green UP, red DOWN, yellow UNKNOWN badges only on terminal stdout. Any `NO_COLOR` presence, `TERM=dumb`, or non-terminal stdout suppresses ANSI. Meaning remains readable without color; do not require a Nerd Font or emoji.
- Escape control characters in interface names and diagnostics. Do not print arbitrary HTTP bodies, HTML, or raw OS error buffers as terminal content.

## 4. Architecture and data boundaries

A binary crate with a small internal library separates four responsibilities:

1. **Platform collector**: owned local interface snapshots and default-route membership, with typed unavailable/partial outcomes. Linux and macOS adapters implement one common interface. OS-specific FFI and binary decoding stay inside these adapters.
2. **Sampling/domain layer**: interface identity, counter validity, actual elapsed time and rate calculation. No network or rendering dependencies.
3. **Public-IP workers**: at most two detached native threads, one per IP family. Each owns its HTTP client, DNS work, TLS state, and response parsing. Communication to main is by a bounded, nonblocking result channel.
4. **CLI/report layer**: option parsing, sample orchestration, result cutoff, formatting and fallible output. Only this layer writes stdout/stderr.

Avoid a process-wide async runtime: it is unnecessary for a one-shot sample and may wait for blocking DNS on shutdown. No scoped threads, join-on-drop pool, `join()`, blocking receive, or shared network-client destructor on main's path. Do not introduce general framework/plugin abstractions.

Use standard-library CLI/thread/channel/time/terminal facilities. The intended external surface is `libc` for native Unix APIs and **ureq 3.5.2**, `default-features = false`, `features = ["rustls"]`, for worker-local HTTPS with bundled WebPKI roots. No native TLS/platform verifier, decompression, proxy, JSON, or async-runtime dependency is needed. Exact resolved versions belong in committed `Cargo.lock`; implementation must confirm the selected graph supports all targets rather than silently changing TLS/lifecycle behavior.

Builder selects and verifies a concrete Rust toolchain/MSRV supported by the locked graph; the local observed toolchain is Rust/Cargo 1.100.0. The implementation plan must state the concrete toolchain and checks; no untested lower-MSRV claim. Any additional production dependency or substitution affecting OS data/lifecycle needs Planner review before implementation.

## 5. Native local-data semantics

### Shared rules

Inventory is link/interface-based, not address-based. Copy owned data before releasing OS buffers. Correlate records by interface index and name, never only a reused name. Re-enumerate at the second sample: newly appearing devices remain visible with unavailable rates, removed devices disappear, and observable replacements do not inherit old counters.

Rates are **best-effort snapshot deltas**, not proof of device-lifetime continuity. Both adapters can detect changed index/name, missing samples and counter decreases. Neither two-snapshot adapter can universally detect a delete/recreate operation that reuses the same index/name with nondecreasing counters. Do not claim otherwise, or add lifecycle-event monitoring to v1 without a design revision. A fully indistinguishable replacement may therefore produce an apparently valid delta; document this narrow limitation in README/help. This is a deliberate correction of R1's unsupported unconditional replacement guarantee and requires the user's written-spec approval.

Collect **cumulative 64-bit** byte counters with a monotonic timestamp for each valid sample. Reject counter decreases, identity changes, missing values, nonpositive/nonfinite elapsed times, and any collector known to return truncated data. Do not silently saturate a reset into zero or infer counter wrap. Independently valid RX/TX may be retained; unavailable directions remain explicitly unavailable.

Calculate `(after_bytes - before_bytes) * 8 / actual_elapsed_seconds`, with overflow-safe arithmetic. Sleep for approximately one second, but never divide by an assumed exact second. Addresses/MTU/speed/defaults are snapshot observations, not transactionally consistent network state.

A default marker means **a usable forwarding default route is configured for that device in the inspected inventory**; it does not assert that device wins every source/mark/process routing policy. Exclude reject/blackhole/unreachable/dead routes/nexthops. No gateway requirement: point-to-point/on-link defaults count. Route-query failure/partial decoding must be visible as incomplete/unavailable per family, never silently “no default.”

### Linux

- Use local `NETLINK_ROUTE` dumps (`RTM_GETLINK`, `RTM_GETADDR`) for inventory/addresses/metadata; retain no-address interfaces and kernel operational state. Kernel UP maps to UP, DOWN maps to DOWN, and other kernel states map conservatively to UNKNOWN. Never treat administrative `IFF_UP` alone as carrier-up.
- Use `IFLA_STATS64` counters from the namespace-local link dump. Missing or invalid 64-bit statistics are unavailable; no widening a truncated 32-bit field and no sysfs-counter fallback.
- Query driver speed through a namespace-local socket and read-only `SIOCETHTOOL`/`ETHTOOL_GLINKSETTINGS` (or supported legacy `ETHTOOL_GSET`), validating returned lengths/commands and Mbps values. Reject nonpositive/unknown sentinel/out-of-range values. Reconfirm index/name around name-addressed ioctls; detectable replacement/failure is unavailable. Do not label a virtual driver's synthetic speed as measured physical bandwidth.
- **No sysfs-derived interface fields in v1.** A retained sysfs mount may describe another network namespace even when index/name match; those matches cannot prove provenance. Netlink/ioctl sockets are created in the collecting thread's current network namespace; the app never calls `setns` or changes namespace. Missing socket-native data stays unavailable rather than consulting an unproven sysfs view.
- Dump IPv4 and IPv6 routes **across all tables**, identifying zero-prefix forwarding defaults. Collect direct output-interface indices, all usable inline multipath nexthops, and resolve `RTA_NH_ID` nexthop objects/groups through `RTM_GETNEXTHOP` where present. Recursive/group decoding must be bounded and cycle-safe; unsupported objects make coverage explicitly incomplete. Do not replace this with a single kernel destination lookup or a crate's single `default` boolean.
- Netlink request/response handling must validate lengths, alignment, family, sequence/source, multipart completion, error and interrupted/truncated dumps. Bound allocation/retries and local receive waits; close sockets on every error path. Never accept a partial dump as exhaustive.

### macOS

- Inventory/addresses use `getifaddrs` and link information; link-only entries preserve no-IP interfaces. Copy addresses/netmasks/scopes and free the list exactly once.
- Use native interface/sysctl data for index, link-layer address and MTU. Query the **per-interface IFMIB/IFDATA_GENERAL 64-bit counters** rather than widening 32-bit `getifaddrs` counters. Read errors are unavailable, not stale/zero success values.
- `IFF_UP` is administrative and `IFF_RUNNING` means resources allocated, not reliable carrier. An administratively down interface is DOWN; otherwise valid active media maps to UP, valid inactive media maps to DOWN, and invalid/unavailable media status maps to UNKNOWN. Loopback/tunnels/etc. with no media status are not falsely DOWN. This conservative mapping is intentional.
- Media/link metadata can provide driver speed where valid, or unavailable. No CoreWLAN/private APIs, location prompts, or extra Wi-Fi dependency in v1. Do not substitute measured RX/TX for capacity or assume nominal `ifi_baudrate` is current negotiated speed.
- Use a read-only `PF_ROUTE` sysctl routing dump covering IPv4 and IPv6. Preserve default routes scoped to interfaces, including gateway-free defaults; do not reduce to `route get default`. Identify the interface from native route fields/link sockaddr where applicable. Do not invent Linux-style routing-table semantics on macOS.
- Validate native message/sockaddr sizes, version, alignment and progress. Retry size races only within a fixed bound and mark persistent truncation/failure explicitly. Native adapters use target definitions, not Linux layouts cast onto Darwin.

All unsafe operations have local safety comments and checked ownership/length/validity boundaries. Decode bytes with alignment-safe reads; malformed data cannot cause panic, overread or an infinite loop. Native calls must remain read-only/unprivileged.

## 6. Sampling and public-lookup lifecycle

1. Parse CLI completely; help/version/invalid usage return before any collector or worker is created.
2. Collect first local identity/counter samples. Start one worker per family unless offline. Thread creation failure is optional public-data unavailability, not a fatal local-report error.
3. Complete the approximately one-second local sampling window and second local snapshot. Both HTTP requests run independently of main's sleep/collection.
4. Close the result window at a recorded monotonic cutoff once second sampling completes. Take **at most two** already-queued results with nonblocking receives; accept only fully validated results completed no later than the cutoff. A result not queued by collection time may conservatively be omitted. No retry or grace wait for results, no repeated polling until completion.
5. Render and flush output once, then return from main. Worker threads cannot own stdout/stderr or any main-held lock required for progress. Do not join workers or await their cleanup, even on an error path.

Rust documents that process termination ends remaining native threads; main-thread completion does not wait for detached workers. Therefore an OS DNS lookup stuck in a worker does not extend program completion. Cancellation here means abandoning pending results and ending remaining work at process exit; it is **not** a claim that Rust can safely interrupt a running native thread mid-call or run its destructors. Workers must be read-only and not own persistent files requiring cleanup.

Worker-local HTTP timeouts are defense-in-depth, not the timing guarantee. Client creation, DNS, TLS verification, body reads, and teardown all stay off main. No absolute wall-clock guarantee is possible under arbitrary OS scheduling or a blocked output consumer; the contract is **no added wait/dependency on public-network completion**. Optional local route/media queries can take local collection time, but never trigger a public-request wait.

## 7. Public response and privacy contract

- Fixed HTTPS endpoints: `https://ipv4.icanhazip.com/` and `https://ipv6.icanhazip.com/`, as documented by Cloudflare. No user-configured URL or fallback service in v1.
- One application request per family; constrain connection resolution to the corresponding family (`IpFamily::Ipv4Only` / `Ipv6Only`). DNS itself can use either transport family and make normal system-resolver queries; this is not a two-DNS-packet guarantee.
- Explicit direct requests (`proxy(None)`), HTTPS-only, certificate/hostname verification on, bundled WebPKI roots, no redirects, no application retries, no cookies, no compression. Environment/system proxies are not used in v1; VPN/system routing still applies. Document this choice rather than calling the result a guaranteed direct physical-interface IP.
- Require HTTP 200 and at most **128 response-body bytes**, strict UTF-8/ASCII IP syntax after trimming surrounding ASCII whitespace, exactly one address, and the expected IP family. Reject HTML, extra tokens, wrong family and malformed/oversized bodies. MIME type is not an acceptance requirement because the operator does not document a strict MIME contract. Never print unvalidated server content.
- Any HTTP/DNS/TLS/status/validation failure or unfinished response renders `unavailable`, not a fatal error or an external-response dump.
- `--offline` starts no workers/resolver/client and sends no application external traffic. Help/version also do not contact the network. Default behavior and third-party visibility of egress IP are disclosed in README/help; no other telemetry, public-IP caching, persistence or background service.

## 8. Distribution and release preparation

Intended install after a separately authorized release: `brew install rammses/tap/ipnedir`.

Prepare four consistently named tarballs, containing the executable at archive root plus license/readme as desired:

| Target | Release artifact |
| --- | --- |
| `aarch64-apple-darwin` | `ipnedir-aarch64-apple-darwin.tar.gz` |
| `x86_64-apple-darwin` | `ipnedir-x86_64-apple-darwin.tar.gz` |
| `aarch64-unknown-linux-gnu` | `ipnedir-aarch64-unknown-linux-gnu.tar.gz` |
| `x86_64-unknown-linux-gnu` | `ipnedir-x86_64-unknown-linux-gnu.tar.gz` |

Prefer native architecture runners so tests execute, not cross-compilation alone. Record the selected deployment baseline for macOS and Linux/glibc in the implementation plan and README. Do not promise support on older systems merely because they share an instruction set. Homebrew installation has no build-time Rust dependency when using these prebuilt assets.

Release-tag workflow: verify tag/version alignment, build/test all four targets with `--locked`, package exact names, compute checksums from the actual archives, publish assets, then prepare the SHA256-pinned `Formula/ipnedir.rb` update. Never publish missing-target formulas, zero/example checksums, or changed URLs pointing to an old version. A failure must stop downstream publication. Tap changes must be limited to the new formula and must not alter `bgp-link-manager.rb`.

Follow the existing tap's binary-distribution convention. At the pinned `bgp-display` revision, Rust target triples contain `unknown-linux-gnu` while its matrix intentionally gives archives shorter names without `unknown`; packaging/download/update consistently use those shorter names. `ipnedir` chooses the full-triple filenames above. Use one artifact manifest/naming contract for every stage rather than inferring filenames from a target. Offline formula tests must check version and an offline local invocation rather than depending on icanhazip or merely checking executable bits.

Cross-repository credentials must be least-privilege and supplied separately by the owner, never embedded in code/artifacts/logs. Prepare formula/update content without assuming the existing secret is available to the new repository. Do not create/overwrite deploy keys, grant permissions, auto-push tap changes, or fetch secrets during implementation without explicit authorization. GitHub Actions publication must stay gated; tests/preparation may run without release credentials.

## 9. Verification and acceptance evidence

Builder owns implementation verification and reports baseline versus new failures by command/platform. No production code has been written or run for this Rust design. Mandatory verification includes:

- Formatting, locked build, Clippy with warnings denied, complete test suite, and package/release archive smoke checks.
- Shared fixtures: all IPs/prefixes/scopes, multiple same-family addresses, no-IP/down/UNKNOWN/virtual devices, unavailable MAC/MTU/speed, rate arithmetic/overflow/reset/observable replacement, genuine zero, output ordering, no color in pipes/NO_COLOR/TERM=dumb, quiet early pipe close, all exit paths. Explicitly cover same-index/name, nondecreasing-counter reuse as observationally indistinguishable: the implementation must not claim that matching snapshots prove continuity or that it detects this history.
- Linux fixtures/native tests: complete/multipart netlink data, all tables and both families, on-link defaults, inline multipath and nexthop-ID groups, exclusions, partial/interrupted/truncated/errors; driver-speed ioctl success/fallback/unknown. Include a mismatched-sysfs-view data-provenance case: wrong-view index/name can match, but no counter/metadata/speed may be sourced from that view. Socket-native sources must remain authoritative, and missing native data must not fall back to sysfs. Use controlled boundary fixtures; privileged namespace creation is not required and host network settings must not change.
- macOS fixtures/native tests: link-only inventory, address masks/scopes, flag/media distinction, counter values above 4 GiB from IFMIB, no read-failure-to-zero/stale fallback, scoped/gateway-free defaults, malformed/size-racing messages. **Actual macOS runtime evidence is required**; cross-compiling on Linux is not equivalent.
- Public fixtures: IPv4/IPv6 success and wrong-family, failed HTTP status, redirects not followed, strict body limit/syntax, TLS verification configuration, direct/proxy-disabled configuration, one-family-only availability, and no external work in offline/help/version/usage-error paths. Tests must not require live icanhazip or public internet.
- A deterministic executable-level no-wait regression with injected blocked DNS, blocked connect/TLS, and never-completing/slow-body workers. Assert report and process exit while the worker remains blocked, with a watchdog that kills a faulty test child. Exercise the **same production coordinator/lifecycle**, not an unrelated thread demo or a hidden release-binary backdoor. Document a bounded CI scheduling allowance; never give the implementation a network grace period to pass tests.
- Publication checks compare every formula URL/checksum/architecture to the actual archive manifest and verify tag/version consistency. Do not rely on prior successful `bgp-display` releases as proof.

Native captures and deterministic fixtures cover malformed/synthetic conditions; live read-only smoke tests compare meaningful runtime fields on both OSes. Missing runner/hardware/credential/tool capability is an explicit blocked gate or stated release limit, not silently waived acceptance.

## 10. Existing state, ownership and migration

Workspace `/home/rammses/Belgeler/ipnedir` did not exist before planning. Planner may create **only** `docs/superpowers/specs/` and `docs/superpowers/plans/` artifacts. No Git initialization, production scaffolding, dependency installation, test execution or remote mutation is part of Planner work. There is no Rust baseline test suite to rerun and no Git revision yet; document hashes/revision IDs provide the artifact checkpoint.

The installed prototype is separate and protected:

- `/home/rammses/.zshrc` contains `alias ipnedir='python3 "$HOME/.local/share/ipnedir/ipnedir.py"'`; original pre-append 113 lines hash `28d2e479c98a4e162c4c1e593e51f43c0c3ca576938ad903256211c1b00eb593`.
- `/home/rammses/.local/share/ipnedir/ipnedir.py` and `test_ipnedir.py` are not Rust source. Their review/fix work was interrupted by the user's Rust pivot. Do not claim those latest edits fully accepted or resume that work as part of this project.
- Do not modify `.zshrc`, remove the prototype, or replace local executables as a side effect of implementing/building. The alias will shadow a future `ipnedir` binary; test the new executable by explicit path. Explain migration instructions and request separate approval before changing the alias or installing locally.

`gh` is currently absent; Rust/Cargo 1.100.0 and `plannotator` are present. macOS and Homebrew execution are not available from the observed Linux session. Remote `rammses/ipnedir` availability/ownership/access is **unverified**: `git ls-remote` failed requesting credentials; do not infer that the repository name is free. Remote creation/authentication is a later owner-approved task.

Builder will own implementation, isolated workspace/Git setup after approval, all test/runtime gates, and integration. The eventual plan must state exact files/interfaces, shared-file ownership, dependencies, commands/cwd and stop conditions. Unresolved release credentials or unavailable macOS runners must block the relevant acceptance/publication stage, not local planning.

## 11. Evidence and alternatives

Evidence checked 2026-11-24; online `main` references can move. Runtime claims below are not Rust-app test evidence.

- Rust native-thread lifecycle: <https://doc.rust-lang.org/std/thread/index.html> and <https://doc.rust-lang.org/std/thread/struct.JoinHandle.html>. Dropping a handle detaches; program termination ends remaining threads without guaranteed worker destructors.
- ureq **3.5.2** features/MSRV: <https://docs.rs/crate/ureq/3.5.2/source/Cargo.toml>; config/family/body limits: <https://docs.rs/ureq/3.5.2/ureq/config/struct.ConfigBuilder.html>, <https://docs.rs/ureq/3.5.2/ureq/config/enum.IpFamily.html>, <https://docs.rs/ureq/3.5.2/ureq/struct.BodyWithConfig.html>. Explicit proxy configuration takes precedence over environment defaults. Bundled-root Rustls avoids native platform-verifier network work.
- Cloudflare operator-documented endpoints: <https://developers.cloudflare.com/cloudflare-one/traffic-controls/egress-policies/dedicated-egress-ips/#verify-egress-ips>. No public-IP request was made during planning.
- Linux native structures: <https://man7.org/linux/man-pages/man7/rtnetlink.7.html>, <https://docs.kernel.org/netlink/specs/rt-nexthop.html>, <https://docs.kernel.org/networking/operstates.html>, <https://docs.kernel.org/networking/statistics.html>, <https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net>.
- Namespace-provenance correction: Linux sysfs mount context captures a network namespace, and iproute2 remounts `/sys` when switching namespaces: <https://raw.githubusercontent.com/torvalds/linux/master/fs/sysfs/mount.c>, <https://raw.githubusercontent.com/iproute2/iproute2/main/lib/namespace.c>. These are moving upstream sources, inspected 2026-11-24; Builder must use target headers/native APIs, not import their code. Native ethtool interface: <https://www.kernel.org/doc/html/latest/networking/ethtool-netlink.html> and the target SDK's `linux/ethtool.h` ioctl definitions.
- Apple native sysctl/media/route definitions: <https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/sysctl.3.html>, <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if.h>, <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_media.h>, <https://keith.github.io/xcode-man-pages/route.8.html>. XNU/main and archived manuals require target-SDK verification by Builder, not assumed support for every macOS release.
- Counter pitfall and IFMIB path confirmed in **sysinfo 0.40.4** source: <https://docs.rs/sysinfo/0.40.4/x86_64-apple-darwin/src/sysinfo/unix/apple/macos/network.rs.html>. The **netdev 0.48.0** stats source explicitly documents macOS 32-bit wrap: <https://docs.rs/netdev/0.48.0/src/netdev/stats/counters.rs.html>.
- netdev **0.48.0** default selection is not exhaustive route membership: <https://docs.rs/netdev/0.48.0/src/netdev/os/linux/netlink.rs.html> and <https://docs.rs/crate/netdev/0.48.0/source/src/os/macos/interface.rs>. Using general network crates alone was rejected for these semantic gaps, not because they lack all useful interface fields.
- Async-HTTP alternative not selected: reqwest **0.13.5** default resolver and Tokio **1.54.1** blocking-task/runtime shutdown docs show that abort/timeout alone does not stop running native DNS: <https://docs.rs/reqwest/0.13.5/src/reqwest/async_impl/client.rs.html>, <https://docs.rs/tokio/1.54.1/tokio/task/fn.spawn_blocking.html>, <https://docs.rs/tokio/1.54.1/tokio/runtime/struct.Runtime.html>. Detached, read-only worker threads keep that complexity out of main.
- Existing release precedent, exact observed revisions: `rammses/bgp-display` **ee44f9a327488e897614f5c49c2667779e01b3c8**, `.github/workflows/release.yml`; `rammses/homebrew-tap` **8d18628c3035415fbdc5778e86f24d58f41c5d19**, `Formula/bgp-link-manager.rb`. Read public source; no credentials or GitHub mutations. <https://github.com/rammses/bgp-display>, <https://github.com/rammses/homebrew-tap>.
- Homebrew tap/formula guidance: <https://docs.brew.sh/How-to-Create-and-Maintain-a-Tap>, <https://docs.brew.sh/Formula-Cookbook>, <https://docs.brew.sh/Language-Specific-Formulae>. Existing binary-tap convention is selected over a Rust source-build formula for v1 distribution; no homebrew-core submission is implied.

## 12. Review, annotation and approval ledger

- **R1**, SHA256 `dfb3f9e00fb0e885af29609722da9f103ff3db90b3495c3dbef1cfeac9d016cc`: Planner self-review and fresh full independent review **IPN-SR1** completed. Verdict NEEDS_REVISION. Findings: F01 sysfs namespace provenance (Important), F02 unsupported unconditional lifetime-continuity guarantee (Important), F03 incorrect pinned-workflow filename claim (Minor).
- **R2**: resolves F01 using namespace-local socket sources only, F02 by explicitly limiting snapshot continuity claims and corresponding acceptance, and F03 by correcting the pinned-source explanation. Changed §§5, 8, 9, 11 and this ledger; other requirements/architecture remain unchanged. Planner self-review completed. Because F02 materially changes a validity guarantee/acceptance, a full fresh re-review was selected instead of a scoped delta.
- **R2 full review IPN-SR2**, checkpoint SHA256 `c5167d6850f2aa6fad05adba14bef2561ae7ca9f0d135ded6a997e3deb4bf9d9`: READY_FOR_USER_REVIEW; no findings, all three R1 findings resolved in the revised design. Reviewer covered all 193 lines and primary-source cross-references. Only this ledger was updated after that review; no substantive design change.
- Last full-review revision: R2/IPN-SR2 at the checkpoint above. Scoped delta coverage: none. Outstanding substantive review coverage gap: none. User explicitly approved written R2 in chat with “i approve,” after the request to approve this file; this includes the snapshot limitation. Subsequent edits record approval status only.
- Plannotator annotation: launched for this exact path after IPN-SR2. The shell tool timed out after 1,200,000 ms without returning a decision or feedback; `plannotator sessions` subsequently reported no active sessions. That interrupted round was not approval or a recorded dismissal. No substantive revision resulted. Written-spec approval was subsequently obtained explicitly in chat, as recorded above.
- Implementation plan: `../plans/2026-11-24-ipnedir-implementation.md` P1 written/self-reviewed; full fresh IPN-PR1 at checkpoint `7526ed9c243d9825f64e4ef6b85e4d67d459df53d5295be88ec4603b3494f4c7` Approved without findings. Plan annotation timed out without decision; user subsequently approved the reviewed plan and selected sequential subagent-driven execution with **“go with subagent.”** Builder may implement that approved scope with its required reviews; Planner stops at handoff. No publication, Git write, installation or alias-migration approval is implied.
