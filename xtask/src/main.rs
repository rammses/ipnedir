use std::{ffi::OsString, io::Write};

fn output(args: &[OsString]) -> Result<String, (u8, String)> {
    let context = xtask::Context {
        ci_sha: (std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true"))
            .then(|| std::env::var("GITHUB_SHA").unwrap_or_default()),
        reference: std::env::var("GITHUB_REF").unwrap_or_default(),
        repository: std::env::var("GITHUB_REPOSITORY").unwrap_or_default(),
    };
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    xtask::command(root, args, &context)
}

fn main() -> std::process::ExitCode {
    match output(&std::env::args_os().skip(1).collect::<Vec<_>>()) {
        Ok(json) => match writeln!(std::io::stdout().lock(), "{json}") {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("ipnedir {} xtask: stdout: {error}", ipnedir::VERSION);
                std::process::ExitCode::FAILURE
            }
        },
        Err((code, message)) => {
            eprintln!("{message}");
            std::process::ExitCode::from(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::output;

    #[test]
    fn matrix_command_returns_the_actual_manifest_json() {
        let result = output(&["matrix".into()]).unwrap();
        assert_eq!(
            result,
            concat!(
                r#"{"include":[{"target":"x86_64-unknown-linux-gnu","runner":"ubuntu-22.04","archive":"ipnedir-x86_64-unknown-linux-gnu.tar.gz"},"#,
                r#"{"target":"aarch64-unknown-linux-gnu","runner":"ubuntu-22.04-arm","archive":"ipnedir-aarch64-unknown-linux-gnu.tar.gz"},"#,
                r#"{"target":"aarch64-apple-darwin","runner":"macos-15","archive":"ipnedir-aarch64-apple-darwin.tar.gz"},"#,
                r#"{"target":"x86_64-apple-darwin","runner":"macos-15-intel","archive":"ipnedir-x86_64-apple-darwin.tar.gz"}]}"#,
            )
        );
    }

    #[test]
    fn missing_unknown_and_extra_commands_are_usage_errors_with_version_context() {
        for args in [
            vec![],
            vec!["unknown".into()],
            vec!["matrix".into(), "extra".into()],
        ] {
            let (code, message) = output(&args).unwrap_err();
            assert_eq!(code, 2);
            assert!(message.contains("ipnedir 0.1.0 xtask"));
            assert!(message.contains("matrix"));
        }
    }
}
