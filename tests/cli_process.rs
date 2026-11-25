use std::{
    io::{self, Read, Write},
    os::fd::{AsRawFd, OwnedFd},
    process::{Child, Command, Output, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ipnedir"));
    // Even empty NO_COLOR is presence; piped stdout independently forbids color.
    command.env("NO_COLOR", "").env("TERM", "xterm-256color");
    command
}

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            // Only our direct child; also clean up setup/read errors and panic.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn drain(pipe: &mut Option<impl Read>, bytes: &mut Vec<u8>) -> io::Result<()> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(());
    };
    // Limit each turn even for continuous output or interrupted reads, so both
    // streams and the watchdog keep making progress. Handles are nonblocking.
    for _ in 0..16 {
        let mut chunk = [0; 8192];
        match reader.read(&mut chunk) {
            Ok(0) => {
                *pipe = None;
                break;
            }
            Ok(len) => bytes.extend_from_slice(&chunk[..len]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn wait_bounded(child: Child) -> Output {
    let mut owner = OwnedChild(child);
    let deadline = Instant::now() + Duration::from_secs(3);
    let result = (|| -> io::Result<Output> {
        let child = &mut owner.0;
        drop(child.stdin.take());
        let (mut stdout, mut stderr) = (child.stdout.take(), child.stderr.take());
        for fd in stdout
            .iter()
            .map(AsRawFd::as_raw_fd)
            .chain(stderr.iter().map(AsRawFd::as_raw_fd))
        {
            // SAFETY: these are borrowed live owned pipe readers. F_GETFL has
            // no third argument; F_SETFL takes integer flags, preserving all
            // existing flags and changing only this reader's nonblocking mode.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let (mut out, mut err) = (Vec::new(), Vec::new());
        loop {
            drain(&mut stdout, &mut out)?;
            drain(&mut stderr, &mut err)?;
            if let Some(status) = child.try_wait()?
                && stdout.is_none()
                && stderr.is_none()
            {
                return Ok(Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "CLI exceeded 3s capture watchdog (stdout={} bytes, stderr={} bytes)",
                        out.len(),
                        err.len()
                    ),
                ));
            }
            thread::sleep(Duration::from_millis(10).min(deadline - now));
        }
    })();
    // No blocking EOF read or reader thread/join, even after direct-child exit.
    // On failure owner kills/reaps the child as this function unwinds.
    result.expect("bounded CLI capture failed")
}

fn invoke(args: &[&str]) -> Output {
    wait_bounded(
        binary()
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}

fn capture_fixture(case: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "cli_process_capture_fixture", "--nocapture"])
        .env("IPNEDIR_TEST_CAPTURE_CASE", case)
        .stdout(if case == "quiet" {
            Stdio::null()
        } else {
            Stdio::piped()
        })
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn cli_process_capture_fixture() {
    match std::env::var("IPNEDIR_TEST_CAPTURE_CASE").as_deref() {
        Ok("large") => {
            // Real writes to both pipes, each far beyond Linux/Darwin pipe
            // capacity. This hook exists only in this test binary, not ipnedir.
            io::stdout().write_all(&vec![b'O'; 1_048_576]).unwrap();
            io::stderr().write_all(&vec![b'E'; 1_048_576]).unwrap();
        }
        Ok("stall") => loop {
            thread::park();
        },
        _ => {}
    }
}

#[test]
fn cli_process_capture_large_stdout_and_stderr_without_false_watchdog() {
    let output = wait_bounded(capture_fixture("large"));
    assert!(output.status.success());
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'O').count(),
        1_048_576
    );
    assert_eq!(output.stderr, vec![b'E'; 1_048_576]);
}

#[test]
fn cli_process_capture_watchdog_kills_and_reaps_its_owned_child() {
    let child = capture_fixture("stall");
    let pid = i32::try_from(child.id()).unwrap();
    let started = Instant::now();
    let result = std::panic::catch_unwind(|| wait_bounded(child));
    assert!(result.is_err(), "stalled child must trip the watchdog");
    assert!(started.elapsed() < Duration::from_millis(4500));
    let mut status = 0;
    // SAFETY: only query this fixture's direct-child PID; WNOHANG never waits
    // or signals any process. ECHILD proves the helper already reaped it.
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn cli_process_capture_pipe_eof_obeys_the_same_deadline_after_child_exit() {
    let (reader, writer) = io::pipe().unwrap();
    let mut child = capture_fixture("quiet");
    // Replace only this owned child's read handle with our owned CLOEXEC pipe.
    // The writer deliberately remains open after the direct child has exited.
    child.stdout = Some(OwnedFd::from(reader).into());
    let (release, retained) = mpsc::channel();
    let holder = thread::spawn(move || {
        // A 5s outer bound makes a blocking-EOF regression fail, not hang the
        // suite forever. Success releases and joins this finite writer holder.
        let _ = retained.recv_timeout(Duration::from_secs(5));
        drop(writer);
    });
    let started = Instant::now();
    let result = std::panic::catch_unwind(|| wait_bounded(child));
    let elapsed = started.elapsed();
    let _ = release.send(());
    holder.join().unwrap();
    assert!(
        result.is_err(),
        "retained EOF must exhaust the capture deadline"
    );
    assert!(
        elapsed < Duration::from_millis(4500),
        "EOF wait took {elapsed:?}"
    );
}

#[test]
fn cli_process_help_discloses_privacy_without_ansi_or_errors() {
    for arg in ["--help", "-h"] {
        let output = invoke(&[arg]);
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert!(!output.stdout.contains(&0x1b));
        let help = String::from_utf8(output.stdout).unwrap();
        for expected in [
            "Usage:",
            "--offline",
            "icanhazip",
            "HTTPS",
            "egress",
            "unavailable",
        ] {
            assert!(help.contains(expected), "missing {expected}");
        }
        let prose = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            prose.contains("A replacement reusing the same index/name with nondecreasing counters is indistinguishable from a continuing device."),
            "help must disclose the snapshot-continuity limitation: {help}"
        );
    }
}

#[test]
fn cli_process_version_uses_package_version_without_ansi_or_errors() {
    for arg in ["--version", "-V"] {
        let output = invoke(&[arg]);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, b"ipnedir 0.1.0\n");
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn cli_process_bad_usage_is_stderr_and_two() {
    for args in [
        vec!["--unknown"],
        vec!["positional"],
        vec!["--offline", "--help"],
    ] {
        let output = invoke(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.contains(&0x1b));
        let diagnostic = String::from_utf8(output.stderr).unwrap();
        assert!(diagnostic.contains("Usage:"));
        assert!(!diagnostic.contains("panicked"));
    }
}

#[test]
fn cli_process_offline_has_real_local_report_and_disabled_public_results() {
    let output = invoke(&["--offline"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.contains(&0x1b));
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("Interfaces"));
    // Native inventory may legitimately be empty, but never silently so.
    assert!(report.contains("RX:") || report.contains("No interfaces found"));
    assert!(report.contains("Public egress (icanhazip)"));
    assert_eq!(report.matches("disabled (--offline)").count(), 2);
}

#[test]
fn cli_process_early_closed_stdout_is_quiet_zero() {
    // Offline's actual 1s sample gives the parent time to close its read end.
    let mut child = binary()
        .arg("--offline")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take().unwrap());
    let output = wait_bounded(child);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
}
