use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    os::{fd::AsRawFd, unix::process::CommandExt},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const ARCHIVE_LIMIT: usize = 32 * 1024 * 1024;
const TAR_LIMIT: usize = 64 * 1024 * 1024;
const BINARY_LIMIT: usize = 48 * 1024 * 1024;
const DOCUMENT_LIMIT: usize = 1024 * 1024;
const RECORD_HEADER: &str = "target\tfile\tsha256\tversion\tsource_revision\n";
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn manifest() -> Result<Vec<crate::targets::Target>, String> {
    crate::targets::parse(include_str!("../../release/targets.tsv"))
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Archive {
    pub target: String,
    pub file: String,
    pub sha256: String,
    pub version: String,
    pub source_revision: String,
}

pub fn verify_tag(tag: &str, version: &str) -> Result<(), String> {
    let parts: Vec<_> = version.split('.').collect();
    if parts.len() != 3
        || parts.iter().any(|p| {
            p.is_empty()
                || p.len() > 10
                || !p.bytes().all(|b| b.is_ascii_digit())
                || (p.len() > 1 && p.starts_with('0'))
        })
    {
        return Err("version must be a safe three-component release version".into());
    }
    if tag != format!("v{version}") {
        return Err(format!("tag must equal v{version} exactly"));
    }
    Ok(())
}

pub fn check_arch(target: &str, bytes: &[u8]) -> Result<(), String> {
    if !manifest()?.iter().any(|row| row.target == target) {
        return Err("unknown executable target".into());
    }
    let little_u16 = |offset| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    let little_u32 = |offset| {
        u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("checked header"),
        )
    };
    let valid = if target.ends_with("-unknown-linux-gnu") {
        bytes.len() >= 64
            && bytes[..7] == *b"\x7fELF\x02\x01\x01"
            && matches!(little_u16(16), 2 | 3)
            && little_u16(18)
                == if target.starts_with("x86_64-") {
                    62
                } else {
                    183
                }
            && little_u32(20) == 1
            && little_u16(52) == 64
    } else {
        bytes.len() >= 32
            && little_u32(0) == 0xfeedfacf
            && little_u32(4)
                == if target.starts_with("x86_64-") {
                    0x01000007
                } else {
                    0x0100000c
                }
            && little_u32(12) == 2
            && little_u32(20) as usize <= bytes.len() - 32
    };
    if !valid {
        return Err(format!("wrong/truncated executable header for {target}"));
    }
    Ok(())
}

pub fn validate_archives(archives: &[Archive], version: &str) -> Result<(), String> {
    verify_tag(&format!("v{version}"), version)?;
    let targets = manifest()?;
    let mut seen = BTreeSet::new();
    if archives.len() != targets.len() {
        return Err("need all four archive records".into());
    }
    for archive in archives {
        if !targets
            .iter()
            .any(|row| row.target == archive.target && row.archive == archive.file)
            || !seen.insert(&archive.target)
            || !lowercase_hex(&archive.sha256, 64)
            || archive.version != version
            || !(lowercase_hex(&archive.source_revision, 40)
                || archive.source_revision == "local-uncommitted")
            || archive.source_revision != archives[0].source_revision
        {
            return Err(
                "archive metadata has invalid target/name/hash/version/source revision".into(),
            );
        }
    }
    Ok(())
}

// ABI checked against rust-lang/libc 0.2.191: src/unix/mod.rs (pid_t,
// fcntl/kill), linux_like/mod.rs and bsd/apple/mod.rs (F_GETFL=3,
// F_SETFL=4, SIGKILL=9), linux/gnu/b64/{x86_64,aarch64}/mod.rs
// (O_NONBLOCK=2048), bsd/mod.rs (O_NONBLOCK=4). No libc dependency is added.
unsafe extern "C" {
    fn fcntl(fd: std::ffi::c_int, command: std::ffi::c_int, ...) -> std::ffi::c_int;
    fn kill(pid: i32, signal: std::ffi::c_int) -> std::ffi::c_int;
}

fn nonblocking(pipe: &impl AsRawFd) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    const NONBLOCK: std::ffi::c_int = 2048;
    #[cfg(target_os = "macos")]
    const NONBLOCK: std::ffi::c_int = 4;
    // SAFETY: pipe owns a live descriptor throughout both calls. F_GETFL has
    // no vararg; F_SETFL takes exactly c_int and preserves all existing flags.
    let flags = unsafe { fcntl(pipe.as_raw_fd(), 3) };
    if flags < 0 || unsafe { fcntl(pipe.as_raw_fd(), 4, flags | NONBLOCK) } < 0 {
        return Err(format!(
            "nonblocking pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// One deadline covers child execution AND both pipe EOFs. No shell or reader
/// threads: nonblocking, bounded chunks cannot be held in an EOF join by a helper.
pub(crate) fn run_bounded(
    command: &mut Command,
    limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let start = Instant::now();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("start {command:?}: {e}"))?;
    fn read_chunk(
        stream: &mut impl Read,
        bytes: &mut Vec<u8>,
        limit: usize,
    ) -> Result<bool, String> {
        let mut buffer = [0; 8192];
        let count = buffer
            .len()
            .min(limit.saturating_sub(bytes.len()).saturating_add(1));
        match stream.read(&mut buffer[..count]) {
            Ok(0) => Ok(true),
            Ok(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                if bytes.len() > limit {
                    return Err("tool exceeded output bound".into());
                }
                Ok(false)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(format!("read tool pipe: {e}")),
        }
    }
    let mut stdout = child.stdout.take().expect("piped");
    let mut stderr = child.stderr.take().expect("piped");
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut reaped = false;
    let result = (|| {
        nonblocking(&stdout)?;
        nonblocking(&stderr)?;
        let (mut out_eof, mut err_eof) = (false, false);
        loop {
            if start.elapsed() >= timeout {
                return Err("tool exceeded time bound (including pipe drain)".to_string());
            }
            let before = (out.len(), err.len());
            if !out_eof {
                out_eof = read_chunk(&mut stdout, &mut out, limit)?;
            }
            if !err_eof {
                err_eof = read_chunk(&mut stderr, &mut err, 64 * 1024)?;
            }
            // Do NOT reap while a pipe is retained. Keeping our direct child
            // waitable reserves its PID/PGID until error cleanup, even if it
            // exited successfully. A reused unrelated group is never signaled.
            if out_eof && err_eof {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        reaped = true;
                        if !status.success() || !err.is_empty() {
                            return Err(format!(
                                "tool failed ({status}): {}",
                                String::from_utf8_lossy(&err)
                            ));
                        }
                        return Ok(());
                    }
                    Ok(None) => {}
                    Err(e) => {
                        // An unexpected external reaper would invalidate PID
                        // ownership; fail without signaling a possibly reused ID.
                        reaped = true;
                        return Err(format!("wait for tool: {e}"));
                    }
                }
            }
            if before == (out.len(), err.len()) {
                thread::sleep(
                    timeout
                        .saturating_sub(start.elapsed())
                        .min(Duration::from_millis(5)),
                );
            }
        }
    })();
    if !reaped {
        let group = i32::try_from(child.id()).expect("supported Unix pid_t fits i32");
        // SAFETY: process_group(0) created exactly this child's fresh group.
        // The child has NOT been reaped, reserving its positive PID (>1).
        // Only this owned group receives SIGKILL; never PID 0/-1 or our group.
        if group > 1 && unsafe { kill(-group, 9) } != 0 {
            let _ = child.kill();
        }
        child
            .wait()
            .map_err(|e| format!("reap stopped tool: {e}"))?;
    }
    result?;
    Ok(out)
}

pub fn sha256(path: &Path) -> Result<String, String> {
    regular_file(path, ARCHIVE_LIMIT)?;
    let parent = path.parent().ok_or("hash file has no parent")?;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("hash file has unsafe name")?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
    {
        return Err("unsafe hash filename".into());
    }
    let mut command = if cfg!(target_os = "macos") {
        let mut c = Command::new("shasum");
        c.args(["-a", "256"]);
        c
    } else {
        Command::new("sha256sum")
    };
    command.current_dir(parent).arg("--").arg(name);
    let bytes = run_bounded(&mut command, 4096, Duration::from_secs(20))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "non-UTF8 hash output")?;
    let (hash, suffix) = text.split_at_checked(64).ok_or("truncated hash output")?;
    if !lowercase_hex(hash, 64) || suffix != format!("  {name}\n") {
        return Err("invalid SHA256 tool output".into());
    }
    Ok(hash.into())
}

fn regular_file(path: &Path, limit: usize) -> Result<fs::Metadata, String> {
    safe_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(format!("not a bounded regular file: {}", path.display()));
    }
    Ok(metadata)
}

fn safe_components(path: &Path) -> Result<(), String> {
    let mut prefix = PathBuf::new();
    for part in path.components() {
        if matches!(part, Component::ParentDir) {
            return Err("parent traversal is forbidden".into());
        }
        prefix.push(part.as_os_str());
        match fs::symlink_metadata(&prefix) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err("symlink path component is forbidden".into());
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

pub fn publication_allowed(
    event: &str,
    requested: bool,
    enabled: bool,
    tag_ok: bool,
    builds_ok: bool,
) -> bool {
    event == "workflow_dispatch" && requested && enabled && tag_ok && builds_ok
}

fn parse_record(text: &str) -> Result<Archive, String> {
    let row = text
        .strip_prefix(RECORD_HEADER)
        .and_then(|s| s.strip_suffix('\n'))
        .ok_or("invalid record header/terminator")?;
    if row.contains(['\n', '\r']) {
        return Err("record must have exactly one row".into());
    }
    let fields: Vec<_> = row.split('\t').collect();
    if fields.len() != 5 {
        return Err("record must have five fields".into());
    }
    Ok(Archive {
        target: fields[0].into(),
        file: fields[1].into(),
        sha256: fields[2].into(),
        version: fields[3].into(),
        source_revision: fields[4].into(),
    })
}

fn record_text(archive: &Archive) -> String {
    format!(
        "{RECORD_HEADER}{}\t{}\t{}\t{}\t{}\n",
        archive.target, archive.file, archive.sha256, archive.version, archive.source_revision
    )
}

/// Strict USTAR, three root regular files only. Extensions, links, prefixes,
/// sparse files, duplicate entries and nonzero trailers are never extracted.
fn tar_entries(bytes: &[u8], target: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    fn octal(field: &[u8]) -> Result<usize, String> {
        let text = std::str::from_utf8(field)
            .map_err(|_| "non-ASCII tar number")?
            .trim_matches(['\0', ' ']);
        if text.is_empty() || !text.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return Err("invalid tar octal number".into());
        }
        usize::from_str_radix(text, 8).map_err(|_| "overflowing tar number".into())
    }
    if bytes.len() > TAR_LIMIT || !bytes.len().is_multiple_of(512) {
        return Err("tar size exceeds bound or is not block aligned".into());
    }
    let mut offset: usize = 0;
    let mut entries = Vec::new();
    let mut seen = BTreeSet::new();
    loop {
        let h = bytes
            .get(offset..offset + 512)
            .ok_or("truncated tar header/trailer")?;
        if h.iter().all(|b| *b == 0) {
            let tail = bytes.get(offset..).ok_or("missing tar trailer")?;
            if tail.len() < 1024 || tail.iter().any(|b| *b != 0) || seen.len() != 3 {
                return Err("invalid/incomplete tar trailer or file set".into());
            }
            return Ok(entries);
        }
        let checksum: usize = h
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *b as usize
                }
            })
            .sum();
        if octal(&h[148..156])? != checksum
            || &h[257..265] != b"ustar\x0000"
            || h[157..257].iter().any(|b| *b != 0)
            || h[345..500].iter().any(|b| *b != 0)
            || !matches!(h[156], 0 | b'0')
            || octal(&h[100..108])? & 0o7000 != 0
        {
            return Err("invalid tar checksum/format/type/link/prefix/mode".into());
        }
        let name_end = h[..100]
            .iter()
            .position(|b| *b == 0)
            .ok_or("unterminated tar name")?;
        if h[name_end..100].iter().any(|b| *b != 0) {
            return Err("nonzero tar name suffix".into());
        }
        let name = std::str::from_utf8(&h[..name_end]).map_err(|_| "non-UTF8 tar name")?;
        if !matches!(name, "ipnedir" | "LICENSE" | "README.md") || !seen.insert(name.to_string()) {
            return Err("unsafe/unexpected/duplicate archive entry".into());
        }
        let size = octal(&h[124..136])?;
        let limit = if name == "ipnedir" {
            BINARY_LIMIT
        } else {
            DOCUMENT_LIMIT
        };
        if size == 0 || size > limit {
            return Err("empty or oversized archive entry".into());
        }
        let start = offset.checked_add(512).ok_or("tar offset overflow")?;
        let end = start.checked_add(size).ok_or("tar size overflow")?;
        let data = bytes.get(start..end).ok_or("truncated tar entry")?;
        offset = end.checked_add(511).ok_or("tar alignment overflow")? / 512 * 512;
        if bytes
            .get(end..offset)
            .ok_or("truncated tar padding")?
            .iter()
            .any(|b| *b != 0)
        {
            return Err("nonzero tar padding".into());
        }
        if name == "ipnedir" {
            if octal(&h[100..108])? & 0o111 == 0 {
                return Err("archive binary is not executable".into());
            }
            check_arch(target, data)?;
        }
        entries.push((name.into(), data.to_vec()));
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(parent: &Path) -> Result<Self, String> {
        use std::os::unix::fs::DirBuilderExt;
        safe_components(parent)?;
        if !parent.is_dir() {
            return Err("temporary parent is not an existing directory".into());
        }
        for _ in 0..100 {
            let path = parent.join(format!(
                ".ipnedir-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("unable to create a private staging directory".into())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn read_file(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    regular_file(path, limit)?;
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("file grew beyond bound".into());
    }
    Ok(bytes)
}

fn text_file(path: &Path, limit: usize) -> Result<String, String> {
    String::from_utf8(read_file(path, limit)?).map_err(|_| "metadata is not UTF8".into())
}

fn unpack_verified(
    path: &Path,
    archive: &Archive,
    temp: &TempDir,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    // Freeze bytes before hashing/decompression; never use an untrusted path for
    // extraction and never execute a foreign-target archive's binary.
    let snapshot = temp.0.join(&archive.file);
    fs::write(&snapshot, read_file(path, ARCHIVE_LIMIT)?).map_err(|e| e.to_string())?;
    if sha256(&snapshot)? != archive.sha256 {
        return Err(format!("checksum mismatch: {}", archive.file));
    }
    let tar = run_bounded(
        Command::new("gzip").args(["-dc", "--"]).arg(&snapshot),
        TAR_LIMIT,
        Duration::from_secs(20),
    )?;
    tar_entries(&tar, &archive.target)
}

pub fn verify_set(tag: &str, dist: &Path) -> Result<Vec<Archive>, String> {
    verify_tag(tag, ipnedir::VERSION)?;
    safe_components(dist)?;
    if !dist.is_dir() {
        return Err("candidate directory is missing".into());
    }
    let targets = manifest()?;
    let mut allowed: BTreeSet<String> = targets
        .iter()
        .flat_map(|r| [r.archive.clone(), format!("{}.record", r.archive)])
        .collect();
    allowed.extend(["checksums.txt".into(), "Formula".into()]);
    for entry in fs::read_dir(dist).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        if !allowed.contains(&entry.file_name().to_string_lossy().to_string())
            || entry.file_type().map_err(|e| e.to_string())?.is_symlink()
        {
            return Err("unexpected or symlink candidate entry".into());
        }
    }
    let archives = targets
        .iter()
        .map(|r| {
            parse_record(&text_file(
                &dist.join(format!("{}.record", r.archive)),
                4096,
            )?)
        })
        .collect::<Result<Vec<_>, String>>()?;
    validate_archives(&archives, ipnedir::VERSION)?;
    // Bind every record to its actual expected sidecar name, not just the set.
    for (row, archive) in targets.iter().zip(&archives) {
        if row.target != archive.target || row.archive != archive.file {
            return Err("renamed/swapped archive record".into());
        }
    }
    let temp = TempDir::new(dist)?;
    for archive in &archives {
        unpack_verified(&dist.join(&archive.file), archive, &temp)?;
    }
    Ok(archives)
}

fn checksums(archives: &[Archive]) -> String {
    archives
        .iter()
        .map(|a| format!("{}  {}\n", a.sha256, a.file))
        .collect()
}

pub fn prepare_release(tag: &str, dist: &Path) -> Result<Vec<Archive>, String> {
    let archives = verify_set(tag, dist)?;
    write_preparation(tag, dist, archives)
}

pub(crate) fn prepare_with_source(
    root: &Path,
    tag: &str,
    dist: &Path,
    ci_sha: Option<&str>,
) -> Result<Vec<Archive>, String> {
    let Some(sha) = ci_sha else {
        return prepare_release(tag, dist);
    };
    let actual = source_revision(root, Some(sha))?;
    let archives = verify_set(tag, dist)?;
    if archives.iter().any(|a| a.source_revision != actual) {
        return Err("CI candidates must all record the actual clean GITHUB_SHA".into());
    }
    write_preparation(tag, dist, archives)
}

fn write_preparation(
    tag: &str,
    dist: &Path,
    archives: Vec<Archive>,
) -> Result<Vec<Archive>, String> {
    let sums = dist.join("checksums.txt");
    let formula_dir = dist.join("Formula");
    if sums.try_exists().map_err(|e| e.to_string())?
        || formula_dir.try_exists().map_err(|e| e.to_string())?
    {
        return Err("prepared outputs already exist; use a fresh candidate directory".into());
    }
    let temp = TempDir::new(dist)?;
    fs::write(temp.0.join("checksums.txt"), checksums(&archives)).map_err(|e| e.to_string())?;
    fs::write(
        temp.0.join("ipnedir.rb"),
        crate::formula::generate(tag, &archives)?,
    )
    .map_err(|e| e.to_string())?;
    // No-clobber hard links publish complete files on the same filesystem.
    fs::create_dir(&formula_dir).map_err(|e| e.to_string())?;
    let result = fs::hard_link(temp.0.join("ipnedir.rb"), formula_dir.join("ipnedir.rb"))
        .and_then(|()| fs::hard_link(temp.0.join("checksums.txt"), &sums));
    if let Err(e) = result {
        let _ = fs::remove_file(formula_dir.join("ipnedir.rb"));
        let _ = fs::remove_dir(&formula_dir);
        return Err(e.to_string());
    }
    Ok(archives)
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let bytes = run_bounded(
        Command::new("git")
            .arg("--no-optional-locks")
            .current_dir(root)
            .args(args),
        1024 * 1024,
        Duration::from_secs(20),
    )?;
    String::from_utf8(bytes).map_err(|_| "non-UTF8 Git output".into())
}

fn source_revision(root: &Path, ci_sha: Option<&str>) -> Result<String, String> {
    let head = git(root, &["rev-parse", "HEAD"])?;
    let head = head.trim_end_matches('\n');
    if !lowercase_hex(head, 40) {
        return Err("invalid checkout commit".into());
    }
    let clean = git(
        root,
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    )?
    .is_empty();
    match ci_sha {
        Some(sha) if clean && sha == head => Ok(head.into()),
        Some(_) => Err("CI requires a clean checkout matching its actual GITHUB_SHA".into()),
        None if clean => Ok(head.into()),
        None => Ok("local-uncommitted".into()),
    }
}

fn native_target(target: &str) -> Result<(), String> {
    let row = manifest()?
        .into_iter()
        .find(|r| r.target == target)
        .ok_or("unknown native target")?;
    let os = if row.target.ends_with("-apple-darwin") {
        "macos"
    } else {
        "linux"
    };
    let arch = row.target.split('-').next().ok_or("target missing arch")?;
    if os != std::env::consts::OS || arch != std::env::consts::ARCH {
        return Err("package requires the matching native OS and architecture".into());
    }
    let actual = run_bounded(Command::new("uname").arg("-m"), 128, Duration::from_secs(5))?;
    let expected = if os == "macos" && arch == "aarch64" {
        "arm64\n"
    } else if arch == "aarch64" {
        "aarch64\n"
    } else {
        "x86_64\n"
    };
    if actual != expected.as_bytes() {
        return Err("native machine architecture differs from target".into());
    }
    if cfg!(target_os = "macos") {
        // A translated process may report x86_64; explicitly reject Rosetta.
        let translated = run_bounded(
            Command::new("sysctl").args(["-in", "sysctl.proc_translated"]),
            128,
            Duration::from_secs(5),
        )?;
        if !translated.is_empty() && translated != b"0\n" {
            return Err("translated macOS process is not native".into());
        }
    }
    Ok(())
}

fn smoke(binary: &Path) -> Result<(), String> {
    let version = run_bounded(
        Command::new(binary)
            .arg("--version")
            .env("NO_COLOR", "1")
            .env("TERM", "dumb"),
        4096,
        Duration::from_secs(20),
    )?;
    if version != format!("ipnedir {}\n", ipnedir::VERSION).as_bytes() {
        return Err("binary version differs from ipnedir::VERSION".into());
    }
    let offline = run_bounded(
        Command::new(binary)
            .arg("--offline")
            .env("NO_COLOR", "1")
            .env("TERM", "dumb"),
        DOCUMENT_LIMIT,
        Duration::from_secs(20),
    )?;
    let text = std::str::from_utf8(&offline).map_err(|_| "non-UTF8 offline report")?;
    if text.matches("disabled (--offline)").count() != 2
        || !text.contains("RX")
        || !text.contains("TX")
        || offline.contains(&0x1b)
    {
        return Err("binary did not produce a plain offline local report".into());
    }
    Ok(())
}

pub fn package(
    root: &Path,
    target: &str,
    dist: &Path,
    ci_sha: Option<&str>,
) -> Result<Archive, String> {
    use std::os::unix::fs::PermissionsExt;
    native_target(target)?;
    let row = manifest()?
        .into_iter()
        .find(|r| r.target == target)
        .ok_or("unknown target")?;
    let binary = read_file(
        &root.join("target").join(target).join("release/ipnedir"),
        BINARY_LIMIT,
    )?;
    check_arch(target, &binary)?;
    let license = read_file(&root.join("LICENSE"), DOCUMENT_LIMIT)?;
    let readme = read_file(&root.join("README.md"), DOCUMENT_LIMIT)?;
    let source_revision = source_revision(root, ci_sha)?;
    safe_components(dist)?;
    fs::create_dir_all(dist).map_err(|e| e.to_string())?;
    let dest = dist.join(&row.archive);
    let record_dest = dist.join(format!("{}.record", row.archive));
    if dest.try_exists().map_err(|e| e.to_string())?
        || record_dest.try_exists().map_err(|e| e.to_string())?
    {
        return Err("archive/record already exists; use a fresh dist directory".into());
    }
    let temp = TempDir::new(dist)?;
    let staged_binary = temp.0.join("ipnedir");
    fs::write(&staged_binary, binary).map_err(|e| e.to_string())?;
    fs::set_permissions(&staged_binary, fs::Permissions::from_mode(0o755))
        .map_err(|e| e.to_string())?;
    fs::write(temp.0.join("LICENSE"), license).map_err(|e| e.to_string())?;
    fs::write(temp.0.join("README.md"), readme).map_err(|e| e.to_string())?;
    smoke(&staged_binary)?;
    let tar = temp.0.join("archive.tar");
    run_bounded(
        Command::new("tar")
            .env("COPYFILE_DISABLE", "1")
            .current_dir(&temp.0)
            .args(["--format=ustar", "-cf"])
            .arg(&tar)
            .args(["ipnedir", "LICENSE", "README.md"]),
        4096,
        Duration::from_secs(20),
    )?;
    regular_file(&tar, TAR_LIMIT)?;
    let compressed = run_bounded(
        Command::new("gzip").args(["-c", "--"]).arg(&tar),
        ARCHIVE_LIMIT,
        Duration::from_secs(20),
    )?;
    let archive_path = temp.0.join(&row.archive);
    fs::write(&archive_path, compressed).map_err(|e| e.to_string())?;
    let archive = Archive {
        target: target.into(),
        file: row.archive,
        sha256: sha256(&archive_path)?,
        version: ipnedir::VERSION.into(),
        source_revision,
    };
    // Validate the actual produced archive, then smoke its safely unpacked bytes.
    let extracted = TempDir::new(&temp.0)?;
    for (name, bytes) in unpack_verified(&archive_path, &archive, &extracted)? {
        let path = extracted.0.join(name);
        fs::write(&path, bytes).map_err(|e| e.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    }
    smoke(&extracted.0.join("ipnedir"))?;
    let record_path = temp.0.join("checksum.record");
    fs::write(&record_path, record_text(&archive)).map_err(|e| e.to_string())?;
    fs::hard_link(&archive_path, &dest).map_err(|e| e.to_string())?;
    if let Err(e) = fs::hard_link(record_path, record_dest) {
        let _ = fs::remove_file(dest);
        return Err(e.to_string());
    }
    Ok(archive)
}

pub(crate) fn check_publish(
    root: &Path,
    event: &str,
    requested: bool,
    enabled: bool,
    tag: &str,
    dist: &Path,
    context: &crate::Context,
) -> Result<(), String> {
    let tag_ok = verify_tag(tag, ipnedir::VERSION).is_ok();
    if !publication_allowed(event, requested, enabled, tag_ok, true) {
        return Err("publication is disabled by event/request/enable/tag gates".into());
    }
    let sha = context
        .ci_sha
        .as_deref()
        .ok_or("publication requires actual CI commit context")?;
    if context.reference != format!("refs/tags/{tag}") || context.repository != "rammses/ipnedir" {
        return Err("publication requires the selected tag in rammses/ipnedir".into());
    }
    let head = source_revision(root, Some(sha))?;
    let selected = git(
        root,
        &[
            "rev-parse",
            "--verify",
            &format!("refs/tags/{tag}^{{commit}}"),
        ],
    )?;
    if selected.trim_end_matches('\n') != head {
        return Err("selected tag is not the clean checked-out source commit".into());
    }
    let archives = verify_set(tag, dist)?;
    let builds_ok = archives
        .iter()
        .all(|a| a.source_revision == head && a.source_revision != "local-uncommitted")
        && text_file(&dist.join("checksums.txt"), 4096)? == checksums(&archives);
    if !publication_allowed(event, requested, enabled, tag_ok, builds_ok) {
        return Err(
            "publication requires four verified candidates from the clean selected tag commit"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    pub(crate) struct Fixture(pub PathBuf);

    impl Fixture {
        pub(crate) fn new() -> Self {
            let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/task9-tests");
            fs::create_dir_all(&parent).unwrap();
            let path = parent.join(format!(
                "fixture-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    pub(crate) fn archives() -> Vec<Archive> {
        [
            (
                "x86_64-unknown-linux-gnu",
                "ipnedir-x86_64-unknown-linux-gnu.tar.gz",
                '1',
            ),
            (
                "aarch64-unknown-linux-gnu",
                "ipnedir-aarch64-unknown-linux-gnu.tar.gz",
                '2',
            ),
            (
                "aarch64-apple-darwin",
                "ipnedir-aarch64-apple-darwin.tar.gz",
                '3',
            ),
            (
                "x86_64-apple-darwin",
                "ipnedir-x86_64-apple-darwin.tar.gz",
                '4',
            ),
        ]
        .into_iter()
        .map(|(target, file, hash)| Archive {
            target: target.into(),
            file: file.into(),
            sha256: hash.to_string().repeat(64),
            version: "0.1.0".into(),
            source_revision: "f5494bd2e7939fd99ca475c40561fed38ab2bea3".into(),
        })
        .collect()
    }

    // Independently encoded executable wire headers, not the checker under test.
    pub(crate) fn header(target: &str) -> Vec<u8> {
        if target.contains("linux") {
            let mut bytes = vec![0; 64];
            bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
            bytes[16] = 2;
            bytes[18] = if target.starts_with("x86_64") {
                62
            } else {
                183
            };
            bytes[20] = 1;
            bytes[52] = 64;
            bytes
        } else {
            let mut bytes = vec![0; 32];
            bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
            bytes[4..8].copy_from_slice(if target.starts_with("x86_64") {
                &[7, 0, 0, 1]
            } else {
                &[12, 0, 0, 1]
            });
            bytes[12] = 2;
            bytes
        }
    }

    #[test]
    fn release_tag_must_match_package_version_exactly() {
        assert!(verify_tag("v0.1.0", "0.1.0").is_ok());
        for tag in [
            "v0.1.1",
            "0.1.0",
            "refs/tags/v0.1.0",
            "v0.1.0\n",
            "v0.1.0/evil",
        ] {
            assert!(verify_tag(tag, "0.1.0").is_err());
        }
        for version in ["", "01.1.0", "0.1.0\n", "0.1.0\";evil", "../x", "0.1.0-pre"] {
            assert!(verify_tag(&format!("v{version}"), version).is_err());
        }
    }

    #[test]
    fn release_headers_require_correct_native_executable_architecture() {
        for archive in archives() {
            let bytes = header(&archive.target);
            assert!(
                check_arch(&archive.target, &bytes).is_ok(),
                "{}",
                archive.target
            );
            for other in archives()
                .into_iter()
                .filter(|a| a.target != archive.target)
            {
                assert!(check_arch(&other.target, &bytes).is_err());
            }
            for length in 0..bytes.len() {
                assert!(check_arch(&archive.target, &bytes[..length]).is_err());
            }
            for (offset, value) in if archive.target.contains("linux") {
                vec![(0, 0), (4, 1), (5, 2), (6, 0), (16, 1), (18, 0), (52, 0)]
            } else {
                vec![(0, 0xca), (4, 0), (7, 0), (12, 1), (20, 255)]
            } {
                let mut bad = bytes.clone();
                bad[offset] = value;
                assert!(
                    check_arch(&archive.target, &bad).is_err(),
                    "{} offset {offset}",
                    archive.target
                );
            }
        }
        assert!(check_arch("riscv64gc-unknown-linux-gnu", &[0; 64]).is_err());
        assert!(check_arch("x86_64-apple-darwin", &[0xca, 0xfe, 0xba, 0xbe]).is_err());
    }

    #[test]
    fn release_manifest_rejects_missing_swapped_duplicate_and_unsafe_records() {
        let valid = archives();
        assert!(validate_archives(&valid, "0.1.0").is_ok());
        assert!(validate_archives(&valid[..3], "0.1.0").is_err());
        let mut duplicate = valid.clone();
        duplicate[3] = duplicate[0].clone();
        assert!(validate_archives(&duplicate, "0.1.0").is_err());
        for field in ["target", "file", "sha256", "version", "source_revision"] {
            for bad in [
                "",
                "../escape",
                "/absolute",
                "x\ty",
                "x\ny",
                "local-uncommitted\n",
            ] {
                let mut records = valid.clone();
                match field {
                    "target" => records[0].target = bad.into(),
                    "file" => records[0].file = bad.into(),
                    "sha256" => records[0].sha256 = bad.into(),
                    "version" => records[0].version = bad.into(),
                    _ => records[0].source_revision = bad.into(),
                }
                assert!(
                    validate_archives(&records, "0.1.0").is_err(),
                    "{field}: {bad:?}"
                );
            }
        }
        for hash in [
            "A".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
        ] {
            let mut records = valid.clone();
            records[0].sha256 = hash;
            assert!(validate_archives(&records, "0.1.0").is_err());
        }
        let mut swapped = valid.clone();
        swapped[0].file = valid[1].file.clone();
        assert!(validate_archives(&swapped, "0.1.0").is_err());
        let mut local = valid;
        for archive in &mut local {
            archive.source_revision = "local-uncommitted".into();
        }
        assert!(validate_archives(&local, "0.1.0").is_ok());
    }

    #[test]
    fn release_sha256_matches_independent_abc_vector_and_missing_file_fails() {
        let fixture = Fixture::new();
        let path = fixture.0.join("abc");
        fs::write(&path, b"abc").unwrap();
        assert_eq!(
            sha256(&path).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(sha256(&fixture.0.join("missing")).is_err());
    }

    #[test]
    fn release_publication_requires_every_gate_and_exact_manual_event() {
        assert!(publication_allowed(
            "workflow_dispatch",
            true,
            true,
            true,
            true
        ));
        for event in [
            "push",
            "pull_request",
            "pull_request_target",
            "workflow_call",
            "",
            "workflow_dispatch\n",
        ] {
            assert!(!publication_allowed(event, true, true, true, true));
        }
        for mask in 0..15 {
            assert!(!publication_allowed(
                "workflow_dispatch",
                mask & 1 != 0,
                mask & 2 != 0,
                mask & 4 != 0,
                mask & 8 != 0
            ));
        }
    }

    #[test]
    fn release_record_round_trip_is_strict_and_preserves_source() {
        let text = "target\tfile\tsha256\tversion\tsource_revision\nx86_64-unknown-linux-gnu\tipnedir-x86_64-unknown-linux-gnu.tar.gz\t1111111111111111111111111111111111111111111111111111111111111111\t0.1.0\tf5494bd2e7939fd99ca475c40561fed38ab2bea3\n";
        assert_eq!(parse_record(text).unwrap(), archives()[0]);
        assert_eq!(record_text(&archives()[0]), text);
        for bad in [
            text.repeat(2),
            text.replace("target\tfile", "file\ttarget"),
            text.replace("\t0.1.0\t", "\t0.1.0\textra\t"),
            text.replace("\n", "\r\n"),
        ] {
            assert!(parse_record(&bad).is_err());
        }
    }

    // Test-only USTAR encoder: no package/parser helper determines these bytes.
    pub(crate) fn tar(files: &[(&str, u8, Vec<u8>)]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (name, kind, data) in files {
            let mut h = [0; 512];
            h[..name.len()].copy_from_slice(name.as_bytes());
            h[100..108].copy_from_slice(b"0000755\0");
            h[108..116].copy_from_slice(b"0000000\0");
            h[116..124].copy_from_slice(b"0000000\0");
            h[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
            h[136..148].copy_from_slice(b"00000000000\0");
            h[148..156].fill(b' ');
            h[156] = *kind;
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
            let sum: u32 = h.iter().map(|b| *b as u32).sum();
            h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            tar.extend_from_slice(&h);
            tar.extend_from_slice(data);
            tar.resize(tar.len().next_multiple_of(512), 0);
        }
        tar.resize(tar.len() + 1024, 0);
        tar
    }

    pub(crate) fn files(target: &str) -> Vec<(&'static str, u8, Vec<u8>)> {
        vec![
            ("ipnedir", b'0', header(target)),
            ("LICENSE", b'0', b"MIT fixture\n".to_vec()),
            ("README.md", b'0', b"fixture documentation\n".to_vec()),
        ]
    }

    #[test]
    fn release_tar_validates_every_header_name_type_size_and_arch_before_extraction() {
        let target = "x86_64-unknown-linux-gnu";
        let valid = files(target);
        let parsed = tar_entries(&tar(&valid), target).unwrap();
        assert_eq!(parsed[0], ("ipnedir".into(), header(target)));
        assert_eq!(parsed[1], ("LICENSE".into(), b"MIT fixture\n".to_vec()));
        assert_eq!(parsed.len(), 3);
        for name in [
            "../escape",
            "/ipnedir",
            "x/ipnedir",
            "./ipnedir",
            "ipnedir/",
            "ipnedir\\evil",
            "other",
            "",
        ] {
            let mut bad = valid.clone();
            bad[0].0 = name;
            assert!(tar_entries(&tar(&bad), target).is_err(), "name={name:?}");
        }
        for kind in *b"123456xgLKS" {
            let mut bad = valid.clone();
            bad[0].1 = kind;
            assert!(tar_entries(&tar(&bad), target).is_err(), "type={kind}");
        }
        assert!(tar_entries(&tar(&valid[..2]), target).is_err());
        let mut extra = valid.clone();
        extra.push(valid[0].clone());
        assert!(tar_entries(&tar(&extra), target).is_err());
        let mut wrong_arch = valid.clone();
        wrong_arch[0].2 = header("aarch64-unknown-linux-gnu");
        assert!(tar_entries(&tar(&wrong_arch), target).is_err());
        let bytes = tar(&valid);
        for length in [0, 511, 512, 576, bytes.len() - 1, bytes.len() - 1024] {
            assert!(
                tar_entries(&bytes[..length], target).is_err(),
                "length {length}"
            );
        }
        let mut bad_checksum = bytes.clone();
        bad_checksum[100] ^= 1;
        assert!(tar_entries(&bad_checksum, target).is_err());
        let mut trailing = bytes;
        trailing.extend_from_slice(&[1; 512]);
        assert!(tar_entries(&trailing, target).is_err());
    }

    pub(crate) fn candidate_set(fixture: &Fixture) -> Vec<Archive> {
        let mut records = archives();
        for record in &mut records {
            let raw = fixture.0.join("raw.tar");
            fs::write(&raw, tar(&files(&record.target))).unwrap();
            let compressed = std::process::Command::new("gzip")
                .args(["-c", "--"])
                .arg(&raw)
                .output()
                .unwrap();
            assert!(compressed.status.success());
            fs::remove_file(raw).unwrap();
            fs::write(fixture.0.join(&record.file), compressed.stdout).unwrap();
            record.sha256 = sha256(&fixture.0.join(&record.file)).unwrap();
            fs::write(
                fixture.0.join(format!("{}.record", record.file)),
                record_text(record),
            )
            .unwrap();
        }
        records
    }

    #[test]
    fn release_prepare_rehashes_real_archives_then_writes_checksums_and_formula() {
        let fixture = Fixture::new();
        let records = candidate_set(&fixture);
        assert_eq!(prepare_release("v0.1.0", &fixture.0).unwrap(), records);
        let sums = fs::read_to_string(fixture.0.join("checksums.txt")).unwrap();
        for record in &records {
            assert!(sums.contains(&format!("{}  {}\n", record.sha256, record.file)));
        }
        let formula = fs::read_to_string(fixture.0.join("Formula/ipnedir.rb")).unwrap();
        assert!(formula.contains(&format!("sha256 \"{}\"", records[0].sha256)));
        // Existing prepared outputs are never silently overwritten.
        assert!(prepare_release("v0.1.0", &fixture.0).is_err());
        assert_eq!(
            fs::read_to_string(fixture.0.join("Formula/ipnedir.rb")).unwrap(),
            formula
        );
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 10);
    }

    #[test]
    fn release_aggregate_failure_leaves_no_outputs_or_temp_debris() {
        for fault in [
            "missing",
            "renamed",
            "tampered",
            "wrong_header",
            "traversal",
            "symlink_entry",
            "extra_entry",
            "extra_file",
            "wrong_source",
            "bad_version",
            "swapped_hash",
        ] {
            let fixture = Fixture::new();
            let mut records = candidate_set(&fixture);
            let path = fixture.0.join(&records[0].file);
            match fault {
                "missing" => fs::remove_file(&path).unwrap(),
                "renamed" => fs::rename(&path, fixture.0.join("renamed.tar.gz")).unwrap(),
                "tampered" => {
                    fs::write(&path, b"not the hashed bytes").unwrap();
                }
                "extra_file" => fs::write(fixture.0.join("unexpected"), b"extra").unwrap(),
                "wrong_source" => {
                    records[0].source_revision = "a".repeat(40);
                    fs::write(
                        fixture.0.join(format!("{}.record", records[0].file)),
                        record_text(&records[0]),
                    )
                    .unwrap();
                }
                "bad_version" => {
                    records[0].version = "0.1.1".into();
                    fs::write(
                        fixture.0.join(format!("{}.record", records[0].file)),
                        record_text(&records[0]),
                    )
                    .unwrap();
                }
                "swapped_hash" => {
                    records[0].sha256 = records[1].sha256.clone();
                    fs::write(
                        fixture.0.join(format!("{}.record", records[0].file)),
                        record_text(&records[0]),
                    )
                    .unwrap();
                }
                _ => {
                    let mut entries = files(&records[0].target);
                    match fault {
                        "wrong_header" => entries[0].2 = header("aarch64-apple-darwin"),
                        "traversal" => entries[0].0 = "../escaped",
                        "symlink_entry" => entries[0].1 = b'2',
                        _ => entries.push(("extra", b'0', vec![1])),
                    }
                    let raw = fixture.0.join("raw.tar");
                    fs::write(&raw, tar(&entries)).unwrap();
                    let output = std::process::Command::new("gzip")
                        .args(["-c", "--"])
                        .arg(&raw)
                        .output()
                        .unwrap();
                    assert!(output.status.success());
                    fs::remove_file(raw).unwrap();
                    fs::write(&path, output.stdout).unwrap();
                    records[0].sha256 = sha256(&path).unwrap();
                    fs::write(
                        fixture.0.join(format!("{}.record", records[0].file)),
                        record_text(&records[0]),
                    )
                    .unwrap();
                }
            }
            let before = fs::read_dir(&fixture.0).unwrap().count();
            assert!(
                prepare_release("v0.1.0", &fixture.0).is_err(),
                "accepted {fault}"
            );
            assert!(!fixture.0.join("checksums.txt").exists());
            assert!(!fixture.0.join("Formula").exists());
            assert!(!fixture.0.parent().unwrap().join("escaped").exists());
            assert_eq!(
                fs::read_dir(&fixture.0).unwrap().count(),
                before,
                "debris for {fault}"
            );
        }
    }

    #[test]
    fn release_symlink_archive_record_and_dist_are_rejected_without_following() {
        use std::os::unix::fs::symlink;
        for name in [
            "ipnedir-x86_64-unknown-linux-gnu.tar.gz",
            "ipnedir-x86_64-unknown-linux-gnu.tar.gz.record",
        ] {
            let fixture = Fixture::new();
            let outside = Fixture::new();
            candidate_set(&fixture);
            let path = fixture.0.join(name);
            let saved = outside.0.join("saved");
            fs::rename(&path, &saved).unwrap();
            symlink(&saved, &path).unwrap();
            assert!(verify_set("v0.1.0", &fixture.0).is_err());
            assert!(saved.exists());
        }
        let fixture = Fixture::new();
        let link = fixture.0.join("link");
        symlink(&fixture.0, &link).unwrap();
        assert!(prepare_release("v0.1.0", &link).is_err());
        assert!(prepare_release("v0.1.0", &fixture.0.join("../other")).is_err());
    }

    #[test]
    fn release_package_rejects_foreign_target_and_missing_binary_without_artifacts() {
        let fixture = Fixture::new();
        let dist = fixture.0.join("dist");
        for target in [
            "not-a-target",
            if cfg!(target_os = "linux") {
                "aarch64-apple-darwin"
            } else {
                "aarch64-unknown-linux-gnu"
            },
        ] {
            assert!(package(&fixture.0, target, &dist, None).is_err());
            assert!(!dist.exists());
        }
        let host = if cfg!(target_os = "linux") {
            if cfg!(target_arch = "x86_64") {
                "x86_64-unknown-linux-gnu"
            } else {
                "aarch64-unknown-linux-gnu"
            }
        } else if cfg!(target_arch = "x86_64") {
            "x86_64-apple-darwin"
        } else {
            "aarch64-apple-darwin"
        };
        assert!(package(&fixture.0, host, &dist, None).is_err());
        assert!(!dist.exists() || fs::read_dir(dist).unwrap().next().is_none());
    }

    pub(crate) fn init_git(fixture: &Fixture) -> String {
        fn call(root: &Path, args: &[&str]) -> String {
            let out = Command::new("git")
                .current_dir(root)
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            String::from_utf8(out.stdout).unwrap()
        }
        call(
            &fixture.0,
            &["-c", "init.defaultBranch=fixture", "init", "--quiet"],
        );
        fs::write(fixture.0.join("tracked"), "fixture\n").unwrap();
        fs::write(fixture.0.join(".gitignore"), "target/\ndist/\n").unwrap();
        call(&fixture.0, &["add", "."]);
        call(
            &fixture.0,
            &[
                "-c",
                "user.name=Release Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "--quiet",
                "-m",
                "fixture",
            ],
        );
        call(&fixture.0, &["tag", "v0.1.0"]);
        call(&fixture.0, &["rev-parse", "HEAD"]).trim().into()
    }

    pub(crate) fn write_revision(fixture: &Fixture, sha: &str) {
        for row in archives() {
            let path = fixture.0.join(format!("{}.record", row.file));
            let mut record = parse_record(&fs::read_to_string(&path).unwrap()).unwrap();
            record.source_revision = sha.into();
            fs::write(path, record_text(&record)).unwrap();
        }
    }

    fn host_target() -> &'static str {
        if cfg!(target_os = "linux") {
            if cfg!(target_arch = "x86_64") {
                "x86_64-unknown-linux-gnu"
            } else {
                "aarch64-unknown-linux-gnu"
            }
        } else if cfg!(target_arch = "x86_64") {
            "x86_64-apple-darwin"
        } else {
            "aarch64-apple-darwin"
        }
    }

    #[test]
    fn release_package_smokes_exact_bytes_checks_version_and_cleans_failures() {
        for (version, offline, succeeds) in [
            (
                "ipnedir 0.1.0\n",
                "RX TX disabled (--offline) disabled (--offline)\n",
                true,
            ),
            (
                "ipnedir 0.1.1\n",
                "RX TX disabled (--offline) disabled (--offline)\n",
                false,
            ),
            (
                "ipnedir 0.1.0\n",
                "RX TX public lookup not disabled\n",
                false,
            ),
        ] {
            let root = Fixture::new();
            fs::write(root.0.join("LICENSE"), "MIT\n").unwrap();
            fs::write(root.0.join("README.md"), "fixture\n").unwrap();
            let source = format!(
                "fn main() {{ match std::env::args().nth(1).as_deref() {{ Some(\"--version\") => print!({version:?}), Some(\"--offline\") => print!({offline:?}), _ => std::process::exit(2) }} }}"
            );
            fs::write(root.0.join("fixture.rs"), source).unwrap();
            let build = root.0.join("target").join(host_target()).join("release");
            fs::create_dir_all(&build).unwrap();
            let out = Command::new("rustc")
                .arg("--crate-name=candidate_fixture")
                .arg(root.0.join("fixture.rs"))
                .arg("-o")
                .arg(build.join("ipnedir"))
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let sha = init_git(&root);
            let dist = root.0.join("dist");
            let result = package(&root.0, host_target(), &dist, Some(&sha));
            assert_eq!(result.is_ok(), succeeds, "{result:?}");
            if succeeds {
                let record = result.unwrap();
                assert_eq!(record.source_revision, sha);
                assert_eq!(fs::read_dir(&dist).unwrap().count(), 2);
                let bytes = fs::read(dist.join(&record.file)).unwrap();
                assert!(
                    package(&root.0, host_target(), &dist, Some(&record.source_revision)).is_err()
                );
                assert_eq!(fs::read(dist.join(&record.file)).unwrap(), bytes);
            } else {
                assert_eq!(fs::read_dir(&dist).unwrap().count(), 0);
            }
        }
    }

    #[test]
    fn release_ci_source_revision_cannot_be_dirty_or_arbitrary() {
        let root = Fixture::new();
        let sha = init_git(&root);
        assert_eq!(source_revision(&root.0, Some(&sha)).unwrap(), sha);
        assert!(source_revision(&root.0, Some(&"a".repeat(40))).is_err());
        fs::write(root.0.join("tracked"), "modified\n").unwrap();
        assert_eq!(source_revision(&root.0, None).unwrap(), "local-uncommitted");
        assert!(source_revision(&root.0, Some(&sha)).is_err());
    }

    #[test]
    fn release_tool_processes_are_output_and_time_bounded() {
        assert_eq!(
            run_bounded(Command::new("uname").arg("-s"), 128, Duration::from_secs(2)).unwrap(),
            if cfg!(target_os = "linux") {
                b"Linux\n".as_slice()
            } else {
                b"Darwin\n".as_slice()
            }
        );
        let start = Instant::now();
        assert!(run_bounded(&mut Command::new("yes"), 1024, Duration::from_secs(2)).is_err());
        assert!(
            run_bounded(
                Command::new("sleep").arg("5"),
                1024,
                Duration::from_millis(30)
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(
            run_bounded(
                &mut Command::new("ipnedir-nonexistent-fixture-command"),
                1024,
                Duration::from_secs(1)
            )
            .is_err()
        );
    }

    #[test]
    fn release_tool_inherited_pipe_child() {
        use std::os::unix::process::CommandExt;
        let Ok(case) = std::env::var("IPN_T9_PIPE_CASE") else {
            return;
        };
        let directory = PathBuf::from(std::env::var_os("IPN_T9_PIPE_DIR").unwrap());
        let script = r#"
import os, subprocess, sys, time
from pathlib import Path
stream, ending = sys.argv[1].split('-')
holder = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
    stdout=None if stream == 'stdout' else subprocess.DEVNULL,
    stderr=None if stream == 'stderr' else subprocess.DEVNULL)
Path('holder-pid').write_text(str(holder.pid))
Path('tool-group').write_text(str(os.getpid()))
Path('ready').write_text(ending)
if ending == 'exit': os._exit(0)
time.sleep(30)
"#;
        let start = Instant::now();
        // A separate fixture group also exists on the unfixed helper, so the
        // outer watchdog can clean up this exact owned tree after a RED hang.
        let result = run_bounded(
            Command::new("python3")
                .arg("-c")
                .arg(script)
                .arg(&case)
                .current_dir(&directory)
                .process_group(0),
            4096,
            Duration::from_millis(500),
        );
        let elapsed = start.elapsed();
        let ready = fs::read_to_string(directory.join("ready")).unwrap();
        // Observe termination, not just a returned error. A fix that simply
        // drops/detaches blocked readers while leaving the holder alive fails.
        let cleanup = r#"
import os, signal, subprocess, time
from pathlib import Path
pid = Path('holder-pid').read_text().strip()
deadline = time.monotonic() + 1
while True:
    state = subprocess.run(['ps', '-o', 'stat=', '-p', pid], capture_output=True, check=False).stdout.strip()
    if not state or state.startswith(b'Z'): break
    if time.monotonic() >= deadline:
        os.killpg(int(Path('tool-group').read_text()), signal.SIGKILL)
        raise AssertionError('owned pipe holder was not terminated')
    time.sleep(.01)
"#;
        let status = Command::new("python3")
            .arg("-c")
            .arg(cleanup)
            .current_dir(&directory)
            .status()
            .unwrap();
        assert!(
            result.is_err(),
            "retained {case} must exhaust the operation deadline"
        );
        assert!(
            elapsed < Duration::from_millis(1500),
            "pipe drain exceeded deadline: {case}"
        );
        assert_eq!(ready, case.split_once('-').unwrap().1);
        assert!(status.success(), "owned holder cleanup failed for {case}");
    }

    #[test]
    fn release_tool_inherited_pipes_obey_deadline_under_outer_watchdog() {
        use std::os::unix::process::CommandExt;
        let mut failures = Vec::new();
        for case in ["stdout-exit", "stderr-exit", "stdout-kill", "stderr-kill"] {
            let fixture = Fixture::new();
            let mut driver = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "package::tests::release_tool_inherited_pipe_child",
                    "--nocapture",
                ])
                .env("IPN_T9_PIPE_CASE", case)
                .env("IPN_T9_PIPE_DIR", &fixture.0)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .spawn()
                .unwrap();
            let started = Instant::now();
            let completed = loop {
                if let Some(status) = driver.try_wait().unwrap() {
                    break Some(status);
                }
                if started.elapsed() >= Duration::from_secs(4) {
                    break None;
                }
                thread::sleep(Duration::from_millis(10));
            };
            match completed {
                None => {
                    // These IDs belong only to this live, isolated fixture. The
                    // holder is sleeping for 30s, retaining the group until cleanup.
                    let group = fs::read_to_string(fixture.0.join("tool-group")).unwrap();
                    let cleanup = Command::new("python3")
                        .args([
                            "-c",
                            "import os,signal,sys; os.killpg(int(sys.argv[1]),signal.SIGKILL)",
                            group.trim(),
                        ])
                        .status()
                        .unwrap();
                    assert!(cleanup.success());
                    driver.kill().unwrap();
                    driver.wait().unwrap();
                    failures.push(format!("{case}: actual run_bounded exceeded 4s outer watchdog (500ms operation deadline)"));
                }
                Some(status) if !status.success() => {
                    failures.push(format!("{case}: bounded-helper child regression failed"));
                }
                Some(_) => {}
            }
            let output = driver.wait_with_output().unwrap();
            if !output.stdout.is_empty() {
                println!("{case}: {}", String::from_utf8_lossy(&output.stdout));
            }
            if !output.stderr.is_empty() {
                println!("{case}: {}", String::from_utf8_lossy(&output.stderr));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn release_aggregate_bounds_compressed_and_decompressed_input_and_cleans_up() {
        for fault in ["compressed-limit", "decompressed-limit", "not-gzip"] {
            let fixture = Fixture::new();
            let mut records = candidate_set(&fixture);
            let path = fixture.0.join(&records[0].file);
            match fault {
                "compressed-limit" => fs::File::create(&path)
                    .unwrap()
                    .set_len(32 * 1024 * 1024 + 1)
                    .unwrap(),
                "decompressed-limit" => {
                    let raw = fixture.0.join("bomb");
                    fs::File::create(&raw)
                        .unwrap()
                        .set_len(64 * 1024 * 1024 + 512)
                        .unwrap();
                    let output = Command::new("gzip")
                        .args(["-c", "--"])
                        .arg(&raw)
                        .output()
                        .unwrap();
                    assert!(output.status.success());
                    fs::remove_file(raw).unwrap();
                    fs::write(&path, output.stdout).unwrap();
                    records[0].sha256 = sha256(&path).unwrap();
                }
                _ => {
                    fs::write(&path, b"not gzip").unwrap();
                    records[0].sha256 = sha256(&path).unwrap();
                }
            }
            fs::write(
                fixture.0.join(format!("{}.record", records[0].file)),
                record_text(&records[0]),
            )
            .unwrap();
            let before = fs::read_dir(&fixture.0).unwrap().count();
            assert!(prepare_release("v0.1.0", &fixture.0).is_err(), "{fault}");
            assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), before);
            assert!(!fixture.0.join("Formula").exists());
        }
    }

    fn run_artifact_fixture(body: &str) {
        let fixture = Fixture::new();
        let module_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join(".github/scripts");
        let output = run_bounded(
            Command::new("python3")
                .arg("-B")
                .arg("-c")
                .arg(body)
                .current_dir(&fixture.0)
                .env("PYTHONPATH", module_path)
                .env("GITHUB_SHA", "f5494bd2e7939fd99ca475c40561fed38ab2bea3")
                .env("GITHUB_RUN_ID", "123")
                .env("GITHUB_REPOSITORY_ID", "456")
                .env("GITHUB_REPOSITORY", "rammses/ipnedir"),
            65536,
            Duration::from_secs(10),
        );
        assert!(
            output.is_ok(),
            "shared CI helper fixture failed: {output:?}"
        );
    }

    #[test]
    fn release_actual_workflow_environment_validator_rejects_missing_rules_and_schema() {
        run_artifact_fixture(
            r#"
import copy
from artifacts import require_protection
valid = {'id': 10, 'name': 'release', 'url': 'https://api.github.com/repos/rammses/ipnedir/environments/release', 'protection_rules': [{'id': 20, 'type': 'required_reviewers', 'prevent_self_review': False, 'reviewers': [{'type': 'User', 'reviewer': {'id': 30, 'login': 'owner'}}]}]}
require_protection(valid)
for key, value in [('id', False), ('name', 'staging'), ('url', 'https://evil.test/release'), ('protection_rules', []), ('protection_rules', None)]:
    bad = copy.deepcopy(valid); bad[key] = value
    try: require_protection(bad)
    except (ValueError, KeyError, TypeError): pass
    else: raise AssertionError(('accepted', key, value))
for value in [[], None, [{'type': 'User', 'reviewer': {'id': 0, 'login': 'owner'}}], [{'type': 'Bot', 'reviewer': {'id': 30, 'login': 'owner'}}]]:
    bad = copy.deepcopy(valid); bad['protection_rules'][0]['reviewers'] = value
    try: require_protection(bad)
    except (ValueError, KeyError, TypeError): pass
    else: raise AssertionError(('accepted reviewers', value))
for key in ['id', 'type', 'prevent_self_review', 'reviewers']:
    bad = copy.deepcopy(valid); del bad['protection_rules'][0][key]
    try: require_protection(bad)
    except (ValueError, KeyError, TypeError): pass
    else: raise AssertionError(('accepted missing', key))
"#,
        );
    }

    #[test]
    fn release_actual_shared_artifact_validator_binds_server_digest_run_sha_and_safe_zip() {
        run_artifact_fixture(
            r#"
import copy, hashlib, zipfile
from pathlib import Path
from artifacts import verify_subject, extract_zip
valid = {'id': 10, 'name': 'candidate-test', 'size_in_bytes': 100, 'digest': 'sha256:' + 'a'*64, 'expired': False, 'workflow_run': {'id': 123, 'repository_id': 456, 'head_repository_id': 456, 'head_sha': 'f5494bd2e7939fd99ca475c40561fed38ab2bea3'}}
assert verify_subject(valid, 'candidate-test') == (10, 'a'*64)
for key, value in [('id', False), ('name', 'other'), ('size_in_bytes', 200*1024*1024), ('digest', None), ('digest', 'sha256:' + 'A'*64), ('expired', True), ('workflow_run', None)]:
    bad = copy.deepcopy(valid); bad[key] = value
    try: verify_subject(bad, 'candidate-test')
    except (ValueError, KeyError, TypeError): pass
    else: raise AssertionError(('accepted', key, value))
for key, value in [('id', 999), ('repository_id', 999), ('head_repository_id', 999), ('head_sha', 'b'*40)]:
    bad = copy.deepcopy(valid); bad['workflow_run'][key] = value
    try: verify_subject(bad, 'candidate-test')
    except (ValueError, KeyError, TypeError): pass
    else: raise AssertionError(('accepted association', key))
expected = {'ipnedir-x86_64-unknown-linux-gnu.tar.gz', 'ipnedir-x86_64-unknown-linux-gnu.tar.gz.record'}
for fault in ['valid', 'bad-digest', 'traversal', 'symlink', 'duplicate', 'missing', 'extra', 'oversized']:
    path = Path(fault + '.zip')
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        names = sorted(expected)
        if fault == 'traversal': names[0] = '../escape'
        if fault == 'missing': names.pop()
        if fault == 'extra': names.append('extra')
        for i, name in enumerate(names):
            entry = zipfile.ZipInfo(name)
            entry.compress_type = zipfile.ZIP_DEFLATED
            if fault == 'symlink' and i == 0: entry.external_attr = 0o120777 << 16
            z.writestr(entry, b'x'*5000 if fault == 'oversized' and name.endswith('.record') else b'abc')
    if fault == 'duplicate':
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with zipfile.ZipFile(path, 'a') as z: z.writestr(sorted(expected)[0], b'abc')
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if fault == 'bad-digest': digest = '0'*64
    destination = Path('out-' + fault)
    try: extract_zip(path, digest, destination, expected)
    except (ValueError, KeyError, TypeError):
        assert fault != 'valid'
        assert not destination.exists(), ('partial extraction', fault)
    else:
        assert fault == 'valid', ('accepted ZIP', fault)
        assert sorted(p.name for p in destination.iterdir()) == sorted(expected)
        assert all(p.read_bytes() == b'abc' for p in destination.iterdir())
assert not Path('escape').exists()
"#,
        );
    }

    #[test]
    fn release_actual_shared_download_process_bounds_output_errors_and_retained_pipes() {
        run_artifact_fixture(
            r#"
import os, signal, subprocess, sys, threading, time
from pathlib import Path
from artifacts import _run_bounded
assert _run_bounded([sys.executable, '-c', 'import os; os.write(1,b"abc")'], 3, 1) == b'abc'
for code in ['import sys; sys.exit(17)', 'import os; os.write(1,b"abcd")', 'import time; time.sleep(3)']:
    started = time.monotonic()
    try: _run_bounded([sys.executable, '-c', code], 3, .1)
    except ValueError: pass
    else: raise AssertionError('failed/open-ended download process accepted')
    assert time.monotonic() - started < 1
for ending in ['exit', 'kill']:
    code = '''import os,subprocess,sys,time
from pathlib import Path
holder = subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])
Path('group').write_text(str(os.getpid()))
Path('holder').write_text(str(holder.pid))
if sys.argv[1] == 'exit': os._exit(0)
time.sleep(30)
'''
    started = time.monotonic()
    def watchdog_cleanup():
        pid = Path('holder').read_text().strip()
        state = subprocess.run(['ps','-o','stat=','-p',pid], capture_output=True).stdout.strip()
        if state and not state.startswith(b'Z'):
            os.killpg(int(Path('group').read_text()), signal.SIGKILL)
    watchdog = threading.Timer(2, watchdog_cleanup)
    watchdog.start()
    try:
        try: _run_bounded([sys.executable, '-c', code, ending], 1024, .3)
        except ValueError: pass
        else: raise AssertionError('retained download pipe accepted')
        assert time.monotonic() - started < 1.5
    finally:
        watchdog.cancel()
        watchdog.join()
        # The known holder reserves this fixture group while alive; never signal
        # an ID after observing termination/reuse is possible.
        pid = Path('holder').read_text().strip()
        for attempt in range(100):
            state = subprocess.run(['ps','-o','stat=','-p',pid], capture_output=True).stdout.strip()
            if not state or state.startswith(b'Z'): break
            if attempt == 99:
                os.killpg(int(Path('group').read_text()), signal.SIGKILL)
                raise AssertionError('download holder not terminated')
            time.sleep(.01)
"#,
        );
    }
}
