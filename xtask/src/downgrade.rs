//! Fails when `Cargo.lock` lowers a locked package version or moves it from a release to a prerelease.
//!
//! The check reads `git diff -U0 <base> -- Cargo.lock`.
//! Within a hunk, a removed and an added `version = "…"` line describe one package change when the nearest `name = "…"` line above each, in the base and current lockfile respectively, is the same.
//! The change fails when its `x.y.z` triple decreases, or when the new version is a prerelease and the old one isn't.
//! Prerelease identifiers and build metadata aren't compared otherwise.
//!
//! Out of scope: added or removed package blocks, git and path sources, and `Cargo.toml` requirement strings.

use std::{path::Path, process::Command};

use crate::Result;

pub(crate) fn check(root: &Path, base: &str) -> Result<()> {
    let git = |args: &[&str]| -> Result<String> {
        let output = Command::new("git").current_dir(root).args(args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("git {} failed: {stderr}", args.join(" ")).into());
        }
        Ok(String::from_utf8(output.stdout)?)
    };
    let diff = git(&["diff", "-U0", base, "--", "Cargo.lock"])?;
    let old = git(&["show", &format!("{base}:Cargo.lock")])?;
    let new = std::fs::read_to_string(root.join("Cargo.lock"))?;
    let failures = violations(&diff, &old, &new)?;
    if failures.is_empty() {
        return Ok(());
    }
    Err(format!(
        "Cargo.lock changes not allowed against {base}:\n{}",
        failures.join("\n")
    )
    .into())
}

fn violations(diff: &str, old: &str, new: &str) -> Result<Vec<String>> {
    let old: Vec<_> = old.lines().collect();
    let new: Vec<_> = new.lines().collect();
    let (mut old_index, mut new_index) = (0, 0);
    let mut removed = Vec::new();
    let mut failures = Vec::new();
    for line in diff.lines().skip_while(|line| !line.starts_with("@@ ")) {
        if let Some(header) = line.strip_prefix("@@ -") {
            let (old_range, rest) = header.split_once(" +").ok_or("malformed hunk header")?;
            old_index = start(old_range)?;
            new_index = start(rest.split(' ').next().unwrap_or_default())?;
            removed.clear();
        } else if let Some(text) = line.strip_prefix('-') {
            if let Some(version) = quoted(text, "version") {
                removed.push((package(&old, old_index)?, version));
            }
            old_index += 1;
        } else if let Some(text) = line.strip_prefix('+') {
            if let Some(new_version) = quoted(text, "version") {
                let name = package(&new, new_index)?;
                if let Some((_, old_version)) = removed.iter().find(|(old_name, _)| *old_name == name) {
                    let (old_triple, old_prerelease) = parse(old_version)?;
                    let (new_triple, new_prerelease) = parse(new_version)?;
                    if new_triple < old_triple || (new_prerelease && !old_prerelease) {
                        failures.push(format!("{name}: {old_version} -> {new_version}"));
                    }
                }
            }
            new_index += 1;
        }
    }
    Ok(failures)
}

/// Returns the zero-based index of the first line of a `start[,count]` hunk range.
fn start(range: &str) -> Result<usize> {
    let start = range.split_once(',').map_or(range, |(start, _)| start);
    Ok(start.parse::<usize>()?.saturating_sub(1))
}

fn package<'a>(lines: &[&'a str], index: usize) -> Result<&'a str> {
    let above = &lines[..index.min(lines.len())];
    let name = above.iter().rev().find_map(|line| quoted(line, "name"));
    name.ok_or_else(|| format!("no package name above Cargo.lock line {}", index + 1).into())
}

fn quoted<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)?.strip_prefix(" = \"")?.strip_suffix('"')
}

/// Splits a version into its `x.y.z` triple and whether it is a prerelease.
fn parse(version: &str) -> Result<([u64; 3], bool)> {
    let end = version.find(['-', '+']).unwrap_or(version.len());
    let parts = version[..end]
        .split('.')
        .map(str::parse)
        .collect::<std::result::Result<Vec<u64>, _>>()?;
    let triple = parts.try_into().map_err(|_| format!("version {version} isn't x.y.z"))?;
    Ok((triple, version[end..].starts_with('-')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(a: &str, b: &str) -> String {
        format!("[[package]]\nname = \"a\"\nversion = \"{a}\"\n\n[[package]]\nname = \"b\"\nversion = \"{b}\"\n")
    }

    fn change_a(old: &str, new: &str) -> Vec<String> {
        let diff =
            format!("--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -3 +3 @@\n-version = \"{old}\"\n+version = \"{new}\"\n");
        violations(&diff, &lock(old, "1.0.0"), &lock(new, "1.0.0")).unwrap()
    }

    #[test]
    fn compares_versions() {
        for (old, new, allowed) in [
            ("1.2.3", "1.2.4", true),
            ("1.2.3", "1.10.0", true),
            ("1.2.3", "1.2.3+build", true),
            ("1.2.3", "1.2.2", false),
            ("1.2.3", "0.9.9", false),
            ("1.2.3", "1.2.4-rc.1", false),
            ("1.2.3-rc.1", "1.2.3-rc.2", true),
            ("1.2.3-rc.1", "1.2.3", true),
            ("1.2.3-rc.1", "1.2.2-rc.1", false),
        ] {
            let failures = change_a(old, new);
            assert_eq!(failures.is_empty(), allowed, "{old} -> {new}: {failures:?}");
        }
    }

    #[test]
    fn names_the_package_in_each_hunk() {
        let diff = "@@ -3 +3 @@\n-version = \"1.0.0\"\n+version = \"1.1.0\"\n@@ -7 +7 @@\n-version = \"2.0.0\"\n+version = \"1.0.0\"\n";
        let failures = violations(diff, &lock("1.0.0", "2.0.0"), &lock("1.1.0", "1.0.0")).unwrap();
        assert_eq!(failures, ["b: 2.0.0 -> 1.0.0"]);
    }

    #[test]
    fn ignores_replaced_and_added_blocks() {
        let old = "[[package]]\nname = \"a\"\nversion = \"2.0.0\"\n";
        let new =
            "[[package]]\nname = \"c\"\nversion = \"1.0.0-rc.1\"\n\n[[package]]\nname = \"d\"\nversion = \"0.1.0\"\n";
        let diff = "@@ -2,2 +2,2 @@\n-name = \"a\"\n-version = \"2.0.0\"\n+name = \"c\"\n+version = \"1.0.0-rc.1\"\n@@ -3,0 +4,4 @@\n+\n+[[package]]\n+name = \"d\"\n+version = \"0.1.0\"\n";
        assert!(violations(diff, old, new).unwrap().is_empty());
    }

    #[test]
    fn rejects_malformed_versions() {
        assert!(parse("1.2").is_err());
        assert!(parse("1.x.3").is_err());
    }
}
