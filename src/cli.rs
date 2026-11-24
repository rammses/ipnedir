use std::ffi::OsString;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Help,
    Version,
    Run { offline: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageError(pub String);

pub fn parse(args: &[OsString]) -> Result<Action, UsageError> {
    let mut action = None;
    for arg in args {
        let next = match arg
            .to_str()
            .ok_or_else(|| UsageError("arguments must be UTF-8".into()))?
        {
            "--offline" => Action::Run { offline: true },
            "--help" | "-h" => Action::Help,
            "--version" | "-V" => Action::Version,
            _ => return Err(UsageError("unknown option or positional argument".into())),
        };
        if action.is_some_and(|current| current != next) {
            return Err(UsageError(
                "distinct action modes cannot be combined".into(),
            ));
        }
        action = Some(next);
    }
    Ok(action.unwrap_or(Action::Run { offline: false }))
}

#[cfg(test)]
mod tests {
    use super::{Action, parse};
    use std::ffi::OsString;

    #[test]
    fn cli_defaults_public_and_rejects_positional() {
        assert_eq!(parse(&[]).unwrap(), Action::Run { offline: false });
        assert!(parse(&[OsString::from("eth0")]).is_err());
    }

    #[test]
    fn cli_offline_can_be_repeated() {
        for args in [vec!["--offline"], vec!["--offline", "--offline"]] {
            let args: Vec<OsString> = args.into_iter().map(OsString::from).collect();
            assert_eq!(parse(&args).unwrap(), Action::Run { offline: true });
        }
    }

    #[test]
    fn cli_help_and_version_accept_documented_aliases_and_same_mode_repetition() {
        for (args, expected) in [
            (vec!["--help"], Action::Help),
            (vec!["-h"], Action::Help),
            (vec!["--help", "-h"], Action::Help),
            (vec!["--version"], Action::Version),
            (vec!["-V"], Action::Version),
            (vec!["--version", "-V"], Action::Version),
        ] {
            let args: Vec<OsString> = args.into_iter().map(OsString::from).collect();
            assert_eq!(parse(&args).unwrap(), expected, "args: {args:?}");
        }
    }

    #[test]
    fn cli_rejects_distinct_action_modes_in_either_order() {
        for args in [
            ["--offline", "--help"],
            ["--help", "--offline"],
            ["--offline", "-V"],
            ["-V", "--offline"],
            ["-h", "--version"],
            ["--version", "-h"],
        ] {
            let args = args.map(OsString::from);
            assert!(parse(&args).is_err(), "args: {args:?}");
        }
    }

    #[test]
    fn cli_rejects_unknown_options_and_substring_lookalikes_even_with_help() {
        for invalid in [
            "",
            "--",
            "-o",
            "-v",
            "-hV",
            "--watch",
            "--json",
            "--interval=2",
            "--offline=true",
            "prefix--offline",
            "--offline-suffix",
            "--help=1",
            "--versioned",
            "--HELP",
        ] {
            for args in [
                vec![invalid],
                vec!["--help", invalid],
                vec![invalid, "--help"],
            ] {
                let args: Vec<OsString> = args.into_iter().map(OsString::from).collect();
                assert!(parse(&args).is_err(), "args: {args:?}");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn cli_rejects_non_utf8_arguments() {
        use std::os::unix::ffi::OsStringExt;

        for bytes in [vec![0xff], b"--offline\xff".to_vec()] {
            let invalid = OsString::from_vec(bytes);
            assert!(parse(std::slice::from_ref(&invalid)).is_err());
            assert!(parse(&[OsString::from("--help"), invalid]).is_err());
        }
    }
}
