use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Target {
    pub target: String,
    pub runner: String,
    pub archive: String,
}

pub fn parse(input: &str) -> Result<Vec<Target>, String> {
    let mut lines = input.lines();
    if lines.next() != Some("target\trunner\tarchive") {
        return Err("expected TSV header: target, runner, archive".into());
    }
    let mut seen = BTreeSet::new();
    let mut targets = Vec::new();
    for (index, line) in lines.enumerate() {
        let line_number = index + 2;
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 3 {
            return Err(format!("line {line_number}: expected three TSV fields"));
        }
        if !fields.iter().all(|field| {
            !field.is_empty()
                && !field.contains("..")
                && field.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-._".contains(&byte)
                })
        }) {
            return Err(format!("line {line_number}: unsafe or non-ASCII field"));
        }
        let [target, runner, archive] = [fields[0], fields[1], fields[2]];
        // This is the release policy validator, not a second matrix source.
        // Job rows and archive names are emitted only from the TSV's contents.
        let expected_runner = match target {
            "x86_64-unknown-linux-gnu" => "ubuntu-22.04",
            "aarch64-unknown-linux-gnu" => "ubuntu-22.04-arm",
            "aarch64-apple-darwin" => "macos-15",
            "x86_64-apple-darwin" => "macos-15-intel",
            _ => return Err(format!("line {line_number}: unexpected target")),
        };
        if !seen.insert(target) {
            return Err(format!("line {line_number}: duplicate target"));
        }
        if runner != expected_runner {
            return Err(format!(
                "line {line_number}: runner does not match native target/baseline"
            ));
        }
        if archive != format!("ipnedir-{target}.tar.gz") {
            return Err(format!("line {line_number}: archive does not match target"));
        }
        targets.push(Target {
            target: target.into(),
            runner: runner.into(),
            archive: archive.into(),
        });
    }
    if seen.len() != 4 {
        return Err("manifest must contain all four native targets exactly once".into());
    }
    Ok(targets)
}

/// Serialize rows returned by `parse`, whose fields are restricted to safe ASCII.
pub fn matrix(targets: &[Target]) -> String {
    let rows = targets
        .iter()
        .map(|row| {
            format!(
                r#"{{"target":"{}","runner":"{}","archive":"{}"}}"#,
                row.target, row.runner, row.archive
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(r#"{{"include":[{rows}]}}"#)
}

#[cfg(test)]
mod tests {
    use super::{Target, matrix, parse};

    const VALID: &str = "target\trunner\tarchive\n\
x86_64-unknown-linux-gnu\tubuntu-22.04\tipnedir-x86_64-unknown-linux-gnu.tar.gz\n\
aarch64-unknown-linux-gnu\tubuntu-22.04-arm\tipnedir-aarch64-unknown-linux-gnu.tar.gz\n\
aarch64-apple-darwin\tmacos-15\tipnedir-aarch64-apple-darwin.tar.gz\n\
x86_64-apple-darwin\tmacos-15-intel\tipnedir-x86_64-apple-darwin.tar.gz\n";

    #[test]
    fn parses_the_four_literal_native_rows_in_manifest_order() {
        assert_eq!(
            parse(VALID).unwrap(),
            vec![
                Target {
                    target: "x86_64-unknown-linux-gnu".into(),
                    runner: "ubuntu-22.04".into(),
                    archive: "ipnedir-x86_64-unknown-linux-gnu.tar.gz".into(),
                },
                Target {
                    target: "aarch64-unknown-linux-gnu".into(),
                    runner: "ubuntu-22.04-arm".into(),
                    archive: "ipnedir-aarch64-unknown-linux-gnu.tar.gz".into(),
                },
                Target {
                    target: "aarch64-apple-darwin".into(),
                    runner: "macos-15".into(),
                    archive: "ipnedir-aarch64-apple-darwin.tar.gz".into(),
                },
                Target {
                    target: "x86_64-apple-darwin".into(),
                    runner: "macos-15-intel".into(),
                    archive: "ipnedir-x86_64-apple-darwin.tar.gz".into(),
                },
            ]
        );
    }

    #[test]
    fn emits_literal_github_include_json_without_other_output() {
        let target = Target {
            target: "aarch64-apple-darwin".into(),
            runner: "macos-15".into(),
            archive: "ipnedir-aarch64-apple-darwin.tar.gz".into(),
        };
        assert_eq!(
            matrix(&[target]),
            r#"{"include":[{"target":"aarch64-apple-darwin","runner":"macos-15","archive":"ipnedir-aarch64-apple-darwin.tar.gz"}]}"#
        );
        assert_eq!(matrix(&[]), r#"{"include":[]}"#);
    }

    #[test]
    fn checked_in_manifest_produces_the_literal_four_job_matrix() {
        assert_eq!(
            matrix(&parse(include_str!("../../release/targets.tsv")).unwrap()),
            concat!(
                r#"{"include":[{"target":"x86_64-unknown-linux-gnu","runner":"ubuntu-22.04","archive":"ipnedir-x86_64-unknown-linux-gnu.tar.gz"},"#,
                r#"{"target":"aarch64-unknown-linux-gnu","runner":"ubuntu-22.04-arm","archive":"ipnedir-aarch64-unknown-linux-gnu.tar.gz"},"#,
                r#"{"target":"aarch64-apple-darwin","runner":"macos-15","archive":"ipnedir-aarch64-apple-darwin.tar.gz"},"#,
                r#"{"target":"x86_64-apple-darwin","runner":"macos-15-intel","archive":"ipnedir-x86_64-apple-darwin.tar.gz"}]}"#,
            )
        );
    }

    #[test]
    fn rejects_missing_duplicate_and_extra_targets() {
        let without_arm = VALID
            .lines()
            .filter(|line| !line.starts_with("aarch64-unknown"))
            .collect::<Vec<_>>()
            .join("\n");
        let duplicate = format!(
            "{VALID}x86_64-unknown-linux-gnu\tubuntu-22.04\tipnedir-x86_64-unknown-linux-gnu.tar.gz\n"
        );
        let extra = format!(
            "{VALID}riscv64gc-unknown-linux-gnu\tubuntu-22.04\tipnedir-riscv64gc-unknown-linux-gnu.tar.gz\n"
        );
        let duplicate_instead_of_missing = VALID.replace(
            "aarch64-unknown-linux-gnu\tubuntu-22.04-arm\tipnedir-aarch64-unknown-linux-gnu.tar.gz",
            "x86_64-unknown-linux-gnu\tubuntu-22.04\tipnedir-x86_64-unknown-linux-gnu.tar.gz",
        );
        for input in [without_arm, duplicate, extra, duplicate_instead_of_missing] {
            assert!(
                parse(&input).is_err(),
                "accepted invalid manifest: {input:?}"
            );
        }
    }

    #[test]
    fn rejects_wrong_runner_architecture_os_or_baseline() {
        for (old, new) in [
            ("ubuntu-22.04-arm", "ubuntu-22.04"),
            ("ubuntu-22.04", "ubuntu-24.04"),
            ("macos-15-intel", "macos-15"),
            ("macos-15\t", "ubuntu-22.04\t"),
        ] {
            assert!(parse(&VALID.replace(old, new)).is_err(), "accepted {new}");
        }
    }

    #[test]
    fn rejects_wrong_archive_architecture_os_or_name() {
        for archive in [
            "ipnedir-aarch64-unknown-linux-gnu.tar.gz",
            "ipnedir-x86_64-apple-darwin.tar.gz",
            "other-x86_64-unknown-linux-gnu.tar.gz",
            "ipnedir-x86_64-unknown-linux-gnu.zip",
        ] {
            assert!(
                parse(&VALID.replace("ipnedir-x86_64-unknown-linux-gnu.tar.gz", archive)).is_err()
            );
        }
    }

    #[test]
    fn rejects_unsafe_non_ascii_or_json_injection_in_every_column() {
        for original in [
            "x86_64-unknown-linux-gnu",
            "ubuntu-22.04",
            "ipnedir-x86_64-unknown-linux-gnu.tar.gz",
        ] {
            for unsafe_value in [
                "../escape",
                "/absolute",
                "a\\b",
                "a..b",
                "a\"b",
                "a b",
                "a\0b",
                "a\u{1b}b",
                "aé",
                "a\rb",
                "a\tb",
                "a\nb",
                "",
            ] {
                assert!(
                    parse(&VALID.replacen(original, unsafe_value, 1)).is_err(),
                    "accepted {unsafe_value:?} in {original}"
                );
            }
        }
    }

    #[test]
    fn rejects_bad_headers_column_counts_and_empty_rows() {
        for input in [
            String::new(),
            VALID.replacen("target\trunner\tarchive\n", "", 1),
            VALID.replacen("target\trunner\tarchive", "runner\ttarget\tarchive", 1),
            VALID.replacen("ubuntu-22.04\t", "", 1),
            VALID.replacen("ubuntu-22.04\t", "ubuntu-22.04\textra\t", 1),
            format!("{VALID}\n"),
        ] {
            assert!(parse(&input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn accepts_crlf_and_unterminated_last_row_without_reordering() {
        let mut rows: Vec<_> = VALID.trim_end().lines().collect();
        rows.swap(1, 4);
        let parsed = parse(&rows.join("\r\n")).unwrap();
        assert_eq!(parsed[0].target, "x86_64-apple-darwin");
        assert_eq!(parsed[3].target, "x86_64-unknown-linux-gnu");
    }
}
