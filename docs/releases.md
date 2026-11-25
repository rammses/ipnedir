# Release preparation and owner-only publication

**Status:** tooling and fail-closed workflow preparation, not a published release
or Homebrew installation. Task9 still requires a new successful **four-native
candidate** CI run and Builder review. The earlier native verification run is
binary/test evidence, not release archives. Nothing here authorizes creating a
tag, changing GitHub settings, publishing assets, or writing to a tap.

## Local, offline preparation

`xtask` is std-only workspace developer tooling; it is not shipped in `ipnedir`.
The installed application's runtime/dependencies are unchanged. Packaging uses
developer `tar`, `gzip`, and the platform SHA256 tool (`sha256sum` on GNU/Linux,
`shasum -a 256` on macOS). Formula syntax checking uses Ruby, not Homebrew.

The only target/runner/archive naming source is
[`release/targets.tsv`](../release/targets.tsv). From a native source checkout:

```sh
cargo +1.100.0 run --locked -p xtask -- matrix
cargo +1.100.0 run --locked -p xtask -- verify-tag v0.1.0
cargo +1.100.0 build --release --locked --package ipnedir --bin ipnedir --target x86_64-unknown-linux-gnu
./target/x86_64-unknown-linux-gnu/release/ipnedir --version
./target/x86_64-unknown-linux-gnu/release/ipnedir --offline
cargo +1.100.0 run --locked -p xtask -- package x86_64-unknown-linux-gnu dist/my-fresh-native-candidate
```

Use your manifest's native target, not a foreign target. `package` checks the
current OS/machine architecture (including rejecting Rosetta), executable
ELF64/Mach-O64 headers, exact version, and offline report. It repeats the smoke
on the actual archive's validated, privately unpacked binary before succeeding.
No default-mode public endpoint is contacted. Only root `ipnedir`, `LICENSE`,
and `README.md` regular files are permitted in an archive.

Each native candidate consists of its exact `.tar.gz` and `.tar.gz.record` TSV
sidecar. The sidecar has header
`target\tfile\tsha256\tversion\tsource_revision` and exactly one data row.
SHA256 is lowercase and computed from actual bytes; it is not a placeholder.
CI requires a clean checkout equal to actual `GITHUB_SHA`. Dirty local
preparation is explicitly `local-uncommitted` and **cannot be published**.
Local clean commits are also not proof that native CI ran.

Collect the four archive/record pairs from the **same successful source/run**
into a fresh directory. Then:

```sh
cargo +1.100.0 run --locked -p xtask -- prepare-release v0.1.0 dist/my-fresh-candidate-set
ruby -c dist/my-fresh-candidate-set/Formula/ipnedir.rb
```

`v0.1.0` is version metadata during preparation; **no Git tag is required**.
The generator recomputes hashes, checks every sidecar's target/name/version/
identical source, and validates the actual archived executable headers. It
rejects missing, renamed, swapped, tampered or extra inputs; symlinks, links,
PAX/GNU extensions, paths, duplicate entries and malformed tar headers fail.
Archive input is capped at 32 MiB compressed / 64 MiB decompressed, binaries
at 48 MiB and each document at 1 MiB. Subprocess output and wall-clock time are
bounded. Validation precedes any private extraction; foreign binaries are
never run by aggregation. Staging is privately owned below the chosen dist
directory and cleaned on success/error. Existing outputs are not overwritten;
use a fresh directory on retry. Only a complete set creates `checksums.txt`
and `Formula/ipnedir.rb`. This verifies candidate bytes, not bit-for-bit
reproducibility of independent compiler runs.

## Read-only Actions candidate gate (no tag needed)

[`ci.yml`](../.github/workflows/ci.yml) exposes the same boolean **`package`**,
default **false**, on both `workflow_dispatch` and `workflow_call`.
Ordinary branch/PR CI retains its existing native evidence and never packages
or publishes by default. Builder may separately push/review and invoke a
feature-branch dispatch with `package=true`; the worker does not push/dispatch.

All four existing native jobs must succeed. Each packages, reopens and smokes
its native archive before uploading a `candidate-<target>-<sha>-<attempt>`
Actions artifact. Aggregation uses read-only GitHub API metadata: exact artifact
ID, current run ID, repository/head-repository IDs, actual commit, attempt's
artifact name, and server SHA256 ZIP digest. It hashes the downloaded ZIP
itself (not a warning-only action check), validates bounded flat regular ZIP
members before writing them, and then runs `prepare-release`. In CI, archive
source records must equal the clean actual checkout/GitHub SHA. A missing leg,
unknown schema, absent digest or API permission error stops preparation.

Outputs are **Actions artifacts**, not releases:

- `verified-candidates-<sha>-<attempt>`: four archives, four records, checksums.
- `candidate-formula-<sha>-<attempt>`: generated `ipnedir.rb`, separately retained.
- Existing `native-verification-*` artifacts and evidence remain separate.

Review the four native job URLs and aggregate log/artifact IDs/digests for the
exact new commit. A locally generated fixture formula, Ruby syntax success or
YAML parsing is **not** four-native candidate evidence or actual GitHub
environment-protection verification.

## Release-owner authorization and fail-closed controls

Publication/tap operations are **separate approvals**, not a side effect of
preparation. The release owner must review/authorize the exact source, version,
tag and destination before creating/pushing any real tag. Do not run a live
publish path merely to test it.

[`release.yml`](../.github/workflows/release.yml) handles `v*` tag pushes by
preparing candidates only. A later `workflow_dispatch` must select that exact
tag ref and explicitly set `publish=true` (default false). All of these must
hold before `gh release create`:

1. Repository is exactly `rammses/ipnedir`; selected ref is the exact `vVERSION`
   tag; four native jobs and aggregate verification passed for that run/SHA.
2. Event is exactly `workflow_dispatch`, input `publish` is true, and repository
   variable `IPN_RELEASE_ENABLED` is exactly the string `true`.
3. The owner has **separately** configured the `release` environment with a
   nonempty required-reviewer protection rule and approves the deployment.
   An environment called `release` **alone is not protection**. Configure and
   review allowed deploy refs/reviewer/self-review/bypass policy as appropriate;
   this implementation does not change any settings or assert they exist.
4. The conditional job's read-only `GET /repos/rammses/ipnedir/environments/release`
   succeeds immediately before the final gate. Its actual response must identify
   this repository/environment and a valid, nonempty required-reviewer rule.
   Missing protection, a 403/404, unexpected schema or malformed response blocks
   publication. Fixture tests exercise that actual workflow validator, not the
   live settings. Owner confirmation and GitHub approval are still required.
5. The same prepared artifact ID/digest is independently checked against current
   server run/repository/commit metadata and safely recovered. The actual
   `xtask check-publish <event> <requested> <enabled> <tag> <dist>` command then
   rehashes all four archives, checks versions/architectures/checksums and matches
   source to a **clean checkout and the selected local tag commit**, equal to
   actual `GITHUB_SHA`. `local-uncommitted`/arbitrary input SHAs fail.

Preparation has `contents:read` (aggregation also `actions:read`); only the
conditional protected publication job has `contents:write`. No PR-target event,
inherited secrets, local OAuth token, tap credential, deploy key or cross-repo
push is used. `GH_TOKEN` in Actions is only that job's scoped GitHub token.
Refs/inputs reach commands through quoted environment arguments, not injected
shell expressions. Publication uses `gh release create --verify-tag` without
any overwrite/clobber operation; existing releases/errors require owner judgment.
Partial GitHub release/upload failure is not atomic: inspect remotely before
any separately authorized recovery, never silently rerun to replace assets.

## Owner runbook — later, only after explicit authorization

1. **Access/name/remote check:** owner uses `git remote -v`,
   `gh repo view rammses/ipnedir --json nameWithOwner,url,viewerPermission` and
   `gh repo view rammses/homebrew-tap --json nameWithOwner,url,viewerPermission`.
   Confirm intended remotes/access without printing credentials. Do not change
   existing repository visibility, aliases, local installs or `bgp-display`.
2. **Source/tag review:** review exact commit, version/Cargo lock/toolchain,
   manifest baselines, tag/version agreement, clean source and tag destination;
   obtain separate permission for tag creation/push. Record tag and commit.
3. **Four-native proof:** record the four new native candidate job URLs plus
   aggregate run URL, actual SHA, run/attempt, artifact IDs and ZIP digests.
   Download/check candidate archives/records/checksums and generated formula.
   Task8's historical binary evidence does not replace this gate.
4. **Protection and authorization:** owner confirms actual `release` required
   reviewers and repository variable, obtains explicit publication authorization,
   then dispatches on the selected tag with publish true and approves the
   protected deployment. No environment/variable setup is authorized now.
5. **Published asset verification:** after actual authorized publication, inspect
   `gh release view <tag> --repo rammses/ipnedir`, download assets to a fresh
   private directory and run platform checksum verification (`sha256sum -c
   checksums.txt` or `shasum -a 256 -c checksums.txt`), tar-list/header checks and
   native explicit-path version/offline smoke. Compare exact published hashes
   with the retained generated formula and source/run evidence.
6. **Tap review:** obtain separate tap-write/commit/PR/push approval. Review a
   diff restricted to **`Formula/ipnedir.rb`** in `rammses/homebrew-tap`; all
   four URL/hash/architecture associations must match the verified published
   assets. Do not edit an existing `bgp-display` formula or automate tap pushes,
   deploy keys or credential setup. Stop on unexpected changes.
7. **Conditional Homebrew acceptance (9.7, currently pending):** only with real
   authorized published assets, owner-installed tap formula and available brew,
   run on supported macOS **and** GNU/Linux:

   ```sh
   brew install rammses/tap/ipnedir
   brew test rammses/tap/ipnedir
   brew audit --strict rammses/tap/ipnedir
   ```

   Check the resolved binary/version and offline report, without replacing an
   existing alias/prototype. Formula runtime tests use only version/offline;
   downloading/installing assets itself needs authorized network access.

**Explicitly pending:** actual new four-native candidates and aggregate evidence;
owner protection/settings confirmation and approval; authorized real
tag/publication/published-assets verification; tap diff/publication; Homebrew
install/test/audit on macOS/Linux. No absent tool, unpublished asset or pending
owner action is recorded as a passing check.
