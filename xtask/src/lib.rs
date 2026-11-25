pub mod formula;
pub mod package;
pub mod targets;

pub use targets::matrix;

#[derive(Default)]
pub struct Context {
    pub ci_sha: Option<String>,
    pub reference: String,
    pub repository: String,
}

pub fn command(
    root: &std::path::Path,
    args: &[std::ffi::OsString],
    context: &Context,
) -> Result<String, (u8, String)> {
    let usage = || {
        (
            2,
            format!(
                "ipnedir {} xtask: usage: xtask matrix | verify-tag <tag> | package <target> <dist-directory> | prepare-release <tag> <dist-directory> | check-publish <event> <requested> <enabled> <tag> <dist-directory>",
                ipnedir::VERSION
            ),
        )
    };
    let args = args
        .iter()
        .map(|s| s.to_str().ok_or_else(usage))
        .collect::<Result<Vec<_>, _>>()?;
    let dist_path = |value: &str| {
        let path = std::path::Path::new(value);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            root.join(path)
        }
    };
    let result = match args.as_slice() {
        ["matrix"] => targets::parse(include_str!("../../release/targets.tsv")).map(|rows| matrix(&rows)),
        ["verify-tag", tag] => package::verify_tag(tag, ipnedir::VERSION).map(|()| format!("verified {tag}")),
        ["package", target, dist] => package::package(root, target, &dist_path(dist), context.ci_sha.as_deref()).map(|a| format!("created {} sha256={} version={} source_revision={}", a.file, a.sha256, a.version, a.source_revision)),
        ["prepare-release", tag, dist] => package::prepare_with_source(root, tag, &dist_path(dist), context.ci_sha.as_deref()).map(|rows| format!("verified {} candidates; wrote checksums.txt and Formula/ipnedir.rb (not published)", rows.len())),
        ["check-publish", event, requested, enabled, tag, dist] => {
            let boolean = |s| match s { "true" => Ok(true), "false" => Ok(false), _ => Err("gate booleans must be exactly true or false".to_string()) };
            boolean(requested).and_then(|requested| boolean(enabled).and_then(|enabled| package::check_publish(root, event, requested, enabled, tag, &dist_path(dist), context))).map(|()| "publication inputs verified; server environment protection must also pass".into())
        }
        _ => return Err(usage()),
    };
    result.map_err(|e| (1, format!("ipnedir {} xtask: {e}", ipnedir::VERSION)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::tests::{Fixture, candidate_set, init_git, write_revision};

    #[test]
    fn release_commands_dispatch_real_tag_validation_and_usage_errors() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        assert_eq!(
            command(
                root,
                &["verify-tag".into(), "v0.1.0".into()],
                &Context::default()
            )
            .unwrap(),
            "verified v0.1.0"
        );
        assert_eq!(
            command(
                root,
                &["verify-tag".into(), "v0.1.1".into()],
                &Context::default()
            )
            .unwrap_err()
            .0,
            1
        );
        for args in [
            vec![],
            vec!["package".into()],
            vec!["matrix".into(), "extra".into()],
            vec!["unknown".into()],
        ] {
            assert_eq!(command(root, &args, &Context::default()).unwrap_err().0, 2);
        }
    }

    #[test]
    fn release_prepare_command_in_ci_requires_its_actual_clean_checkout_source() {
        let root = Fixture::new();
        let sha = init_git(&root);
        let dist = Fixture::new();
        candidate_set(&dist);
        let args = vec![
            "prepare-release".into(),
            "v0.1.0".into(),
            dist.0.clone().into(),
        ];
        let context = Context {
            ci_sha: Some(sha.clone()),
            ..Context::default()
        };
        assert!(command(&root.0, &args, &context).is_err());
        assert!(!dist.0.join("checksums.txt").exists());
        assert!(!dist.0.join("Formula").exists());
        write_revision(&dist, &sha);
        assert_eq!(
            command(&root.0, &args, &context).unwrap(),
            "verified 4 candidates; wrote checksums.txt and Formula/ipnedir.rb (not published)"
        );
        let syntax = std::process::Command::new("ruby")
            .arg("-c")
            .arg(dist.0.join("Formula/ipnedir.rb"))
            .output()
            .unwrap();
        assert!(
            syntax.status.success(),
            "{}",
            String::from_utf8_lossy(&syntax.stderr)
        );
        assert_eq!(syntax.stdout, b"Syntax OK\n");
    }

    #[test]
    fn release_check_publish_command_binds_actual_clean_tag_commit_and_complete_bytes() {
        let root = Fixture::new();
        let sha = init_git(&root);
        let dist = Fixture::new();
        candidate_set(&dist);
        write_revision(&dist, &sha);
        crate::package::prepare_release("v0.1.0", &dist.0).unwrap();
        let mut context = Context {
            ci_sha: Some(sha.clone()),
            reference: "refs/tags/v0.1.0".into(),
            repository: "rammses/ipnedir".into(),
        };
        let args: Vec<std::ffi::OsString> = vec![
            "check-publish".into(),
            "workflow_dispatch".into(),
            "true".into(),
            "true".into(),
            "v0.1.0".into(),
            dist.0.clone().into(),
        ];
        assert_eq!(
            command(&root.0, &args, &context).unwrap(),
            "publication inputs verified; server environment protection must also pass"
        );
        for (index, value) in [
            (1, "push"),
            (1, "pull_request_target"),
            (2, "false"),
            (3, "false"),
            (2, "TRUE"),
            (3, "1"),
            (4, "v0.1.1"),
        ] {
            let mut bad = args.clone();
            bad[index] = value.into();
            assert!(
                command(&root.0, &bad, &context).is_err(),
                "{index}: {value}"
            );
        }
        context.reference = "refs/heads/ipnedir-p1".into();
        assert!(command(&root.0, &args, &context).is_err());
        context.reference = "refs/tags/v0.1.0".into();
        context.ci_sha = Some("a".repeat(40));
        assert!(command(&root.0, &args, &context).is_err());
        context.ci_sha = Some(sha);
        context.repository = "other/ipnedir".into();
        assert!(command(&root.0, &args, &context).is_err());
        context.repository = "rammses/ipnedir".into();
        let checksums_path = dist.0.join("checksums.txt");
        let checksums = std::fs::read(&checksums_path).unwrap();
        std::fs::write(&checksums_path, "tampered\n").unwrap();
        assert!(command(&root.0, &args, &context).is_err());
        std::fs::write(&checksums_path, checksums).unwrap();
        let archive_path = dist.0.join("ipnedir-x86_64-unknown-linux-gnu.tar.gz");
        let archive_bytes = std::fs::read(&archive_path).unwrap();
        std::fs::write(&archive_path, "tampered archive\n").unwrap();
        assert!(command(&root.0, &args, &context).is_err());
        std::fs::remove_file(&archive_path).unwrap();
        assert!(command(&root.0, &args, &context).is_err());
        std::fs::write(&archive_path, archive_bytes).unwrap();
        std::fs::write(root.0.join("tracked"), "dirty").unwrap();
        assert!(command(&root.0, &args, &context).is_err());
        std::fs::write(root.0.join("tracked"), "fixture\n").unwrap();
        assert!(command(&root.0, &args, &context).is_ok());
        write_revision(&dist, "local-uncommitted");
        assert!(command(&root.0, &args, &context).is_err());
        assert_eq!(std::fs::read_dir(&dist.0).unwrap().count(), 10);
    }

    #[test]
    fn release_check_publish_command_rejects_missing_tag_or_tag_on_another_commit() {
        let root = Fixture::new();
        init_git(&root);
        let git = |args: &[&str]| {
            let result = std::process::Command::new("git")
                .current_dir(&root.0)
                .args(args)
                .output()
                .unwrap();
            assert!(result.status.success());
            String::from_utf8(result.stdout).unwrap()
        };
        std::fs::write(root.0.join("tracked"), "next fixture revision\n").unwrap();
        git(&["add", "tracked"]);
        git(&[
            "-c",
            "user.name=Release Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "next fixture",
        ]);
        let sha = git(&["rev-parse", "HEAD"]).trim().to_string();
        let dist = Fixture::new();
        candidate_set(&dist);
        write_revision(&dist, &sha);
        crate::package::prepare_release("v0.1.0", &dist.0).unwrap();
        let context = Context {
            ci_sha: Some(sha),
            reference: "refs/tags/v0.1.0".into(),
            repository: "rammses/ipnedir".into(),
        };
        let args = vec![
            "check-publish".into(),
            "workflow_dispatch".into(),
            "true".into(),
            "true".into(),
            "v0.1.0".into(),
            dist.0.clone().into(),
        ];
        assert!(command(&root.0, &args, &context).is_err());
        git(&["tag", "-d", "v0.1.0"]);
        assert!(command(&root.0, &args, &context).is_err());
    }
}
