# ipnedir

`ipnedir` is a one-shot native network-interface and traffic report for macOS
and GNU/Linux. It takes two local snapshots about one second apart, prints one
report, and exits. No root, packet capture, shell-outs, or generated traffic is
needed to measure the counter deltas.

## Current status

The CLI, native collectors, optional public lookup workers, and report are
implemented. Host verification is currently **x86-64 GNU/Linux only**. Actual
macOS SDK/runtime and native ARM verification, release artifacts, and Homebrew
publication remain separate gates; there is no published install promised here.

## Usage

Build the local executable with `cargo +1.100.0 build --locked --bin ipnedir`.
Invoke it by its explicit path until any existing shell alias has been reviewed:

```sh
./target/debug/ipnedir --offline
./target/debug/ipnedir --help
./target/debug/ipnedir --version
```

| Arguments | Behavior |
| --- | --- |
| No arguments | Local sample plus concurrent public IPv4/IPv6 HTTPS attempts. |
| `--offline` | Same local report, no workers, DNS, or HTTP; public results say `disabled (--offline)`. |
| `--help`, `-h` | Usage/privacy note, with no collector or network initialization. |
| `--version`, `-V` | Version only, with no collector or network initialization. |

Unknown options, positional arguments, and combinations of distinct modes are
usage errors (exit **2**, stderr). Exit **1** means mandatory local inventory
failure or a non-BrokenPipe output error. Optional unavailable data is exit **0**.
An early-closed stdout pipe exits quietly with **0**, including failure at flush.
There are no watch, JSON, filtering, configuration, or custom-interval modes.

## Reading the report

Interfaces are ordered by index then raw name. Down/no-IP interfaces remain
visible, with conservative `UP`, `DOWN`, or `UNKNOWN` badges. Every assigned
IPv4/IPv6 address is shown with its CIDR prefix; scoped IPv6 addresses keep their
zone/interface identifier. Invalid or missing masks say `prefix unavailable`
rather than inventing `/0`. A successful empty inventory is explicitly reported.

`* default IPv4` and `* default IPv6` denote configured default-route membership,
not a route-selection prediction. All usable configured memberships may be
marked; incomplete/unavailable route coverage is disclosed. Policy routing,
VPNs, and the destination can affect actual egress.

Link address, MTU, RX, TX, and **Link speed (driver)** are separate fields. Driver
speed is nominal metadata, not measured throughput. Unknown/unsupported native
metadata remains `unavailable`, not zero or a guessed capacity. Virtual/tunnel
interfaces commonly lack speed or a meaningful link address. Linux collection
uses namespace-local native sockets, not sysfs-derived interface fields; local
data describes this process's network environment/namespace.

Rates and driver speed use decimal **bit/s, Kbit/s, Mbit/s, Gbit/s**, base 1000,
with one decimal place. `0.0 bit/s` is a valid unchanged counter; `unavailable`
is not zero. Color affects only badges on terminal stdout, never pipes/files;
any `NO_COLOR` presence (even empty) or `TERM=dumb` disables it. No special font
is needed. Untrusted names/diagnostics escape control characters and invalid
UTF-8 bytes, preserving readable ordinary UTF-8 without terminal control effects.

## Privacy and public lookup availability

**Default mode makes external requests.** One application lookup per family
contacts the fixed endpoints `https://ipv4.icanhazip.com/` and
`https://ipv6.icanhazip.com/`. The service sees the respective egress IP; normal
system DNS resolution can also occur. Use **`--offline`** to prevent application
external traffic. Help, version, and invalid usage also do no collection/network
work. There is no other telemetry, public-IP cache, persistence, or daemon.

Requests are HTTPS-only with verified certificates/hostnames and bundled WebPKI
roots. Environment/system proxies are deliberately **not used** (`proxy(None)`);
VPN/system routing still applies, so this is not necessarily a physical-interface
IP. Connections are constrained to the expected family, with no redirects,
application retries, cookies, or compression. Only HTTP 200 with at most 128
body bytes containing exactly one valid address of the expected family is
accepted. Raw server content is never included in reports or diagnostics.

Both lookups run independently during local sampling. Only already-queued,
validated results completed by the post-second-snapshot cutoff are eligible.
There is no public-network grace period or join, including on inventory/output
errors. DNS/connect/TLS/body failures and unfinished results say `unavailable`.
The process abandons outstanding read-only workers on exit; this does not mean
it interrupts native calls or runs their destructors. Local collection and a
blocked output consumer can still take time: this is **no added dependency on
public-network completion**, not an absolute wall-clock performance guarantee.

## Snapshot limitation

RX and TX rates are best-effort deltas of cumulative byte counters over the
actual monotonic elapsed time, expressed in bits per second. A valid unchanged
counter yields zero; missing or decreasing counters, changed interface identity,
or nonpositive elapsed time yield unavailable rates rather than guessed values.
Only interfaces present in the later snapshot remain in the combined result.

Matching the full interface index and raw name does **not** prove device-lifetime
continuity: a replacement with the same index/name and nondecreasing counters is
indistinguishable from a continuing device. These are snapshot observations, not
proof of continuity or a bandwidth-capacity measurement.

## Intended compatibility (verification pending)

Planned deployment baselines are **macOS 15** and **GNU/Linux with glibc 2.35**
(Ubuntu 22.04 equivalent); older systems and musl are not promised. The intended
targets are:

- `aarch64-apple-darwin` (Apple Silicon)
- `x86_64-apple-darwin` (Intel Mac)
- `aarch64-unknown-linux-gnu` (ARM64)
- `x86_64-unknown-linux-gnu` (x86-64)

These are intended targets, **not** a verified four-platform runtime matrix.
Portable decoder fixtures and Linux host tests do not replace actual macOS SDK
and native-architecture execution. Any eventual
`brew install rammses/tap/ipnedir` requires separately authorized release/tap
publication; it is not a current installation instruction.

## Manual migration from a prototype or alias

No installer or invocation edits your shell configuration or prototype. Review
your existing alias/function and prototype path yourself (`type -a ipnedir` can
help), back up your configuration, and compare the explicit binary's offline
report before changing anything. If you choose to migrate, manually remove or
rename the old alias/function, keep the prototype until satisfied, and verify
which executable your shell resolves in a new session. Do not overwrite a
prototype merely because its command name matches. No automatic `.zshrc` edits
or local installation are performed by this project.

## Development

Rust 1.100.0 is pinned in `rust-toolchain.toml`, including rustfmt and clippy.
Run `cargo +1.100.0 test --workspace --all-targets --locked`,
`cargo +1.100.0 fmt --all --check`, and
`cargo +1.100.0 clippy --workspace --all-targets --locked -- -D warnings`.
CLI process tests invoke only offline/help/version/invalid modes. Lifecycle
process tests use the real coordinator and worker queue with injected, permanently
blocked lookup operations; they do not contact or verify a live public provider.

Licensed under the MIT license; see [LICENSE](LICENSE).
