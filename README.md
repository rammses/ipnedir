# ipnedir

`ipnedir` is being built as a one-shot native network-interface and traffic
report for macOS and Linux. The intended targets are macOS on Apple Silicon
(`aarch64-apple-darwin`) and Intel (`x86_64-apple-darwin`), and GNU/Linux on
ARM64 (`aarch64-unknown-linux-gnu`) and x86-64 (`x86_64-unknown-linux-gnu`).

## Current status

This initial library-only foundation defines the owned domain models, argument
parser, and pure snapshot-rate calculations. There is no executable, native OS
collector, public-IP lookup, or published release yet. It does not collect local
data or make network requests.

The planned CLI accepts no arguments for the default report, `--offline` to
disable public-IP work, `--help` / `-h`, and `--version` / `-V`. Other options and
positional arguments are not supported. In the eventual default mode, public
IPv4/IPv6 lookups will contact icanhazip over HTTPS, disclosing the respective
egress IP to that service; offline, help, and version modes will not do so.

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

## Development

Rust 1.100.0 is pinned in `rust-toolchain.toml`, including rustfmt and clippy.
Run the foundation tests with `cargo +1.100.0 test --workspace --all-targets --locked`.

Licensed under the MIT license; see [LICENSE](LICENSE).
