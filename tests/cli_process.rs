use std::{
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

fn binary() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ipnedir"));
    // Even empty NO_COLOR is presence; piped stdout independently forbids color.
    command.env("NO_COLOR", "").env("TERM", "xterm-256color");
    command
}

fn wait_bounded(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut timed_out = false;
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    // Fixtures/help reports are bounded; never drain a still-running child.
    let output = child.wait_with_output().unwrap();
    assert!(!timed_out, "CLI exceeded 3s watchdog: {output:?}");
    output
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
