use crate::package::Archive;

/// Called only after prepare-release has rehashed the complete on-disk set.
pub fn generate(tag: &str, archives: &[Archive]) -> Result<String, String> {
    crate::package::verify_tag(tag, ipnedir::VERSION)?;
    crate::package::validate_archives(archives, ipnedir::VERSION)?;
    let mut formula = format!(
        "class Ipnedir < Formula\n  desc \"One-shot native network-interface and traffic report\"\n  homepage \"https://github.com/rammses/ipnedir\"\n  version \"{}\"\n  license \"MIT\"\n",
        ipnedir::VERSION
    );
    for (os, suffix) in [("macos", "-apple-darwin"), ("linux", "-unknown-linux-gnu")] {
        formula.push_str(&format!("\n  on_{os} do\n"));
        for (arch, prefix) in [("arm", "aarch64-"), ("intel", "x86_64-")] {
            let archive = archives
                .iter()
                .find(|a| a.target.starts_with(prefix) && a.target.ends_with(suffix))
                .ok_or("missing formula target")?;
            formula.push_str(&format!("    on_{arch} do\n      url \"https://github.com/rammses/ipnedir/releases/download/{tag}/{}\"\n      sha256 \"{}\"\n    end\n", archive.file, archive.sha256));
        }
        formula.push_str("  end\n");
    }
    formula.push_str("\n  def install\n    bin.install \"ipnedir\"\n  end\n\n  test do\n    assert_equal \"ipnedir #{version}\\n\", shell_output(\"#{bin}/ipnedir --version\")\n    report = shell_output(\"#{bin}/ipnedir --offline\")\n    assert_equal 2, report.scan(\"disabled (--offline)\").length\n    assert_match \"RX\", report\n    assert_match \"TX\", report\n  end\nend\n");
    Ok(formula)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::package::tests::archives;

    #[test]
    fn release_formula_associates_each_os_arch_url_and_actual_hash() {
        let formula = generate("v0.1.0", &archives()).unwrap();
        for (os, arch, name, hash) in [
            (
                "linux",
                "intel",
                "ipnedir-x86_64-unknown-linux-gnu.tar.gz",
                "1111111111111111111111111111111111111111111111111111111111111111",
            ),
            (
                "linux",
                "arm",
                "ipnedir-aarch64-unknown-linux-gnu.tar.gz",
                "2222222222222222222222222222222222222222222222222222222222222222",
            ),
            (
                "macos",
                "arm",
                "ipnedir-aarch64-apple-darwin.tar.gz",
                "3333333333333333333333333333333333333333333333333333333333333333",
            ),
            (
                "macos",
                "intel",
                "ipnedir-x86_64-apple-darwin.tar.gz",
                "4444444444444444444444444444444444444444444444444444444444444444",
            ),
        ] {
            let block = format!(
                "    on_{arch} do\n      url \"https://github.com/rammses/ipnedir/releases/download/v0.1.0/{name}\"\n      sha256 \"{hash}\"\n    end"
            );
            let os_block = formula
                .split(&format!("  on_{os} do\n"))
                .nth(1)
                .unwrap()
                .split("\n  end")
                .next()
                .unwrap();
            assert!(os_block.contains(&block), "missing {os}/{arch}: {formula}");
        }
        assert!(formula.starts_with("class Ipnedir < Formula\n"));
        assert!(formula.contains("homepage \"https://github.com/rammses/ipnedir\""));
        assert!(formula.contains("license \"MIT\""));
        assert!(formula.contains("version \"0.1.0\""));
        assert!(formula.contains("bin.install \"ipnedir\""));
        assert!(formula.contains("shell_output(\"#{bin}/ipnedir --offline\")"));
        assert!(formula.contains("disabled (--offline)"));
    }

    #[test]
    fn release_formula_refuses_incomplete_swapped_and_injectable_metadata() {
        assert!(generate("v0.1.0", &archives()[..3]).is_err());
        for tag in [
            "v0.1.1",
            "v0.1.0\"",
            "v0.1.0/../../evil",
            "https://evil.test",
        ] {
            assert!(generate(tag, &archives()).is_err());
        }
        let mut swapped = archives();
        swapped[0].file = swapped[1].file.clone();
        assert!(generate("v0.1.0", &swapped).is_err());
        let mut duplicate = archives();
        duplicate[1] = duplicate[0].clone();
        assert!(generate("v0.1.0", &duplicate).is_err());
    }
}
