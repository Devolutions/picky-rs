//! Checks the conformance suite's vectors against `picky-crypto-testsuite/vectors/manifest.toml`.
//!
//! Every file under `vectors/`, outside the Wycheproof submodule, has exactly one `[[file]]` entry.
//! Its blob ID (`git hash-object --no-filters`) equals the entry's `blob`, which equals `upstream` unless the entry has an `extract` rule.
//! An entry has `lines` exactly when it has `extract`: ascending, non-overlapping 1-based inclusive ranges of upstream lines (`"a-b, c-d"`) whose total equals the vendored file's line count, and its `blob` differs from `upstream`.
//! The submodule commit recorded in the index and the commit checked out both equal `[wycheproof] commit`, every listed file exists in the checkout's commit, and none is locally modified.
//!
//! The manifest is read line by line: `[section]` headers, `key = "value"` pairs and `files = [ … ]` arrays with one quoted path per line.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

use crate::Result;

const VECTORS: &str = "picky-crypto-testsuite/vectors";
const FILE_KEYS: [&str; 5] = ["path", "source", "version", "upstream", "blob"];

pub(crate) fn check(root: &Path) -> Result<()> {
    let vectors = root.join(VECTORS);
    let manifest = parse(&std::fs::read_to_string(vectors.join("manifest.toml"))?)?;
    let mut failures = Vec::new();

    let mut on_disk = Vec::new();
    list(&vectors, &vectors, &manifest.wycheproof_path, &mut on_disk)?;
    let listed: Vec<&str> = manifest.files.iter().map(|entry| entry["path"].as_str()).collect();
    for path in &on_disk {
        match listed.iter().filter(|listed| **listed == path).count() {
            0 => failures.push(format!("{path}: no manifest entry")),
            1 => {}
            _ => failures.push(format!("{path}: several manifest entries")),
        }
    }
    for path in listed.iter().filter(|path| !on_disk.contains(&path.to_string())) {
        failures.push(format!("{path}: listed but missing"));
    }

    let present: Vec<_> = manifest
        .files
        .iter()
        .filter(|entry| on_disk.contains(&entry["path"]))
        .collect();
    if !present.is_empty() {
        let mut args = vec!["hash-object", "--no-filters", "--"];
        let paths: Vec<_> = present
            .iter()
            .map(|entry| format!("{VECTORS}/{}", entry["path"]))
            .collect();
        args.extend(paths.iter().map(String::as_str));
        for (entry, blob) in present.iter().zip(git(root, &args)?.lines()) {
            let path = &entry["path"];
            if blob != entry["blob"] {
                failures.push(format!("{path}: blob {blob}, manifest {}", entry["blob"]));
            }
            if !entry.contains_key("extract") && entry["blob"] != entry["upstream"] {
                failures.push(format!("{path}: blob differs from upstream without an extract rule"));
            }
            let lines = line_count(&std::fs::read(vectors.join(path))?);
            failures.extend(check_extract(entry, lines).into_iter().map(|f| format!("{path}: {f}")));
        }
    }

    failures.extend(check_wycheproof(root, &manifest)?);
    if failures.is_empty() {
        return Ok(());
    }
    Err(format!("{VECTORS} doesn't match manifest.toml:\n{}", failures.join("\n")).into())
}

fn check_wycheproof(root: &Path, manifest: &Manifest) -> Result<Vec<String>> {
    let submodule = format!("{VECTORS}/{}", manifest.wycheproof_path);
    let commit = &manifest.wycheproof_commit;
    let mut failures = Vec::new();
    let staged = git(root, &["ls-files", "--stage", "--", &submodule])?;
    match staged.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["160000", recorded, ..] if recorded == commit => {}
        ["160000", recorded, ..] => failures.push(format!("{submodule}: submodule at {recorded}, manifest {commit}")),
        _ => failures.push(format!("{submodule}: not a submodule")),
    }
    let checkout = root.join(&submodule);
    if !checkout.join(".git").exists() {
        failures.push(format!(
            "{submodule}: not checked out; run `git submodule update --init {submodule}`"
        ));
        return Ok(failures);
    }
    let head = git(&checkout, &["rev-parse", "HEAD"])?;
    if head.trim() != commit {
        failures.push(format!(
            "{submodule}: checked out at {}, manifest {commit}",
            head.trim()
        ));
    }
    let mut args = vec!["ls-tree", "--name-only", "HEAD", "--"];
    args.extend(manifest.wycheproof_files.iter().map(String::as_str));
    let found = git(&checkout, &args)?;
    for file in &manifest.wycheproof_files {
        if !found.lines().any(|line| line == file) {
            failures.push(format!("{submodule}/{file}: missing at {}", head.trim()));
        }
    }
    args[0..3].copy_from_slice(&["status", "--porcelain", "--untracked-files=no"]);
    for line in git(&checkout, &args)?.lines() {
        failures.push(format!("{submodule}: locally modified: {line}"));
    }
    Ok(failures)
}

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git").current_dir(dir).args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git {} failed: {stderr}", args.join(" ")).into());
    }
    Ok(String::from_utf8(output.stdout)?)
}

/// Counts runs of bytes ending in `\n`; a last run without one also counts.
fn line_count(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == b'\n').count() + usize::from(bytes.last().is_some_and(|byte| *byte != b'\n'))
}

/// Parses `"a-b, c-d"` into 1-based inclusive line ranges, requiring them ascending and non-overlapping.
fn parse_ranges(text: &str) -> std::result::Result<Vec<(usize, usize)>, String> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for item in text.split(',') {
        let range = item
            .trim()
            .split_once('-')
            .and_then(|(start, end)| Some((start.parse::<usize>().ok()?, end.parse::<usize>().ok()?)));
        let Some((start, end)) = range.filter(|(start, end)| 1 <= *start && start <= end) else {
            return Err(format!("`lines` has an invalid range `{}`", item.trim()));
        };
        if ranges.last().is_some_and(|(_, previous)| start <= *previous) {
            return Err(format!("`lines` range `{start}-{end}` isn't after the previous one"));
        }
        ranges.push((start, end));
    }
    Ok(ranges)
}

/// Checks an entry's extraction metadata against its vendored file's line count.
fn check_extract(entry: &BTreeMap<String, String>, lines: usize) -> Vec<String> {
    let mut failures = Vec::new();
    match (entry.contains_key("extract"), entry.get("lines")) {
        (false, None) => return failures,
        (true, None) => failures.push("`extract` without `lines`".to_owned()),
        (false, Some(_)) => failures.push("`lines` without `extract`".to_owned()),
        (true, Some(ranges)) => match parse_ranges(ranges) {
            Ok(ranges) => {
                let total: usize = ranges.iter().map(|(start, end)| end - start + 1).sum();
                if total != lines {
                    failures.push(format!("{lines} lines, `lines` covers {total}"));
                }
            }
            Err(failure) => failures.push(failure),
        },
    }
    if entry.contains_key("extract") && entry["blob"] == entry["upstream"] {
        failures.push("an extract identical to upstream".to_owned());
    }
    failures
}

/// Collects the paths of files under `dir`, relative to `base` with `/` separators, except the manifest and the submodule.
fn list(base: &Path, dir: &Path, submodule: &str, out: &mut Vec<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path: PathBuf = entry?.path();
        let relative = path
            .strip_prefix(base)?
            .components()
            .map(|component| component.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if relative == "manifest.toml" || relative == submodule {
            continue;
        }
        if path.is_dir() {
            list(base, &path, submodule, out)?;
        } else {
            out.push(relative);
        }
    }
    Ok(())
}

#[derive(Debug)]
struct Manifest {
    wycheproof_path: String,
    wycheproof_commit: String,
    wycheproof_files: Vec<String>,
    files: Vec<BTreeMap<String, String>>,
}

fn parse(text: &str) -> Result<Manifest> {
    let mut wycheproof = BTreeMap::new();
    let mut wycheproof_files = Vec::new();
    let mut files: Vec<BTreeMap<String, String>> = Vec::new();
    let mut section = "";
    let mut in_array = false;
    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        let error = || format!("manifest.toml line {}: unexpected `{raw}`", number + 1);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if in_array {
            if line == "]" {
                in_array = false;
            } else {
                let item = line.strip_suffix(',').unwrap_or(line);
                wycheproof_files.push(unquote(item).ok_or_else(error)?.to_owned());
            }
            continue;
        }
        match line {
            "[wycheproof]" => section = "wycheproof",
            "[[file]]" => {
                section = "file";
                files.push(BTreeMap::new());
            }
            "files = [" if section == "wycheproof" => in_array = true,
            _ => {
                let (key, value) = line.split_once(" = ").ok_or_else(error)?;
                let value = unquote(value).ok_or_else(error)?.to_owned();
                let table = match section {
                    "wycheproof" => &mut wycheproof,
                    "file" => files.last_mut().ok_or_else(error)?,
                    _ => return Err(error().into()),
                };
                if table.insert(key.to_owned(), value).is_some() {
                    return Err(format!("manifest.toml line {}: duplicate `{key}`", number + 1).into());
                }
            }
        }
    }
    if in_array {
        return Err("manifest.toml: unterminated `files` array".into());
    }
    for entry in &files {
        if let Some(key) = FILE_KEYS
            .iter()
            .find(|key| entry.get(**key).is_none_or(String::is_empty))
        {
            return Err(format!("manifest.toml: a [[file]] entry has no `{key}`").into());
        }
    }
    if wycheproof_files.is_empty() || files.is_empty() {
        return Err("manifest.toml: [wycheproof] files and [[file]] entries must not be empty".into());
    }
    let mut take = |key: &str| {
        wycheproof
            .remove(key)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("manifest.toml: [wycheproof] has no `{key}`"))
    };
    take("source")?;
    Ok(Manifest {
        wycheproof_path: take("path")?,
        wycheproof_commit: take("commit")?,
        wycheproof_files,
        files,
    })
}

fn unquote(value: &str) -> Option<&str> {
    value.strip_prefix('"')?.strip_suffix('"')
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"# comment

[wycheproof]
path = "wycheproof"
source = "https://example.org/wycheproof"
commit = "abc"
files = [
    "testvectors_v1/a.json",
    "testvectors_v1/b.json",
]

[[file]]
path = "nist/a.rsp"
source = "https://example.org/a.zip"
version = "a"
upstream = "1"
blob = "1"

[[file]]
path = "nist/b.rsp"
source = "https://example.org/b.zip"
version = "b"
upstream = "2"
blob = "3"
extract = "groups"
lines = "1-2, 5-6"
"#;

    #[test]
    fn parses_sections() {
        let manifest = parse(MANIFEST).unwrap();
        assert_eq!(manifest.wycheproof_path, "wycheproof");
        assert_eq!(manifest.wycheproof_commit, "abc");
        assert_eq!(
            manifest.wycheproof_files,
            ["testvectors_v1/a.json", "testvectors_v1/b.json"]
        );
        assert_eq!(manifest.files.len(), 2);
        assert_eq!(manifest.files[1]["extract"], "groups");
        assert_eq!(manifest.files[1]["lines"], "1-2, 5-6");
    }

    #[test]
    fn counts_lines() {
        assert_eq!(line_count(b""), 0);
        assert_eq!(line_count(b"\n"), 1);
        assert_eq!(line_count(b"a\r\nb\n"), 2);
        assert_eq!(line_count(b"a\n\x0c"), 2);
    }

    #[test]
    fn parses_ranges() {
        assert_eq!(parse_ranges("1-9").unwrap(), [(1, 9)]);
        assert_eq!(parse_ranges("1-1, 3-4,7-9").unwrap(), [(1, 1), (3, 4), (7, 9)]);
        for invalid in ["", "1", "1-", "0-2", "3-2", "a-b", "1-2; 4-5", "1-2,", "-1-2"] {
            assert!(parse_ranges(invalid).is_err(), "{invalid}");
        }
        for unordered in ["1-5, 5-7", "1-5, 3-7", "6-7, 1-2"] {
            assert!(
                parse_ranges(unordered).unwrap_err().contains("isn't after"),
                "{unordered}"
            );
        }
    }

    #[test]
    fn checks_extracts() {
        let manifest = parse(MANIFEST).unwrap();
        let (whole, extract) = (&manifest.files[0], &manifest.files[1]);
        assert!(check_extract(whole, 100).is_empty());
        assert!(check_extract(extract, 4).is_empty());
        assert_eq!(check_extract(extract, 5), ["5 lines, `lines` covers 4"]);
        let mut entry = extract.clone();
        entry.insert("blob".to_owned(), "2".to_owned());
        assert_eq!(check_extract(&entry, 4), ["an extract identical to upstream"]);
        entry.insert("lines".to_owned(), "2-1".to_owned());
        assert_eq!(check_extract(&entry, 4).len(), 2);
        let mut entry = extract.clone();
        entry.remove("lines");
        assert_eq!(check_extract(&entry, 4), ["`extract` without `lines`"]);
        let mut entry = whole.clone();
        entry.insert("lines".to_owned(), "1-100".to_owned());
        assert_eq!(check_extract(&entry, 100), ["`lines` without `extract`"]);
    }

    #[test]
    fn rejects_incomplete_entries() {
        assert!(parse(&MANIFEST.replace("blob = \"3\"\n", "")).is_err());
        assert!(parse(&MANIFEST.replace("commit = \"abc\"\n", "")).is_err());
        assert!(parse(&MANIFEST.replace("version = \"a\"", "version = \"a\"\nversion = \"c\"")).is_err());
        assert!(parse(&MANIFEST.replace("path = \"nist/a.rsp\"", "path = nist/a.rsp")).is_err());
        // An array left open at the end of the file must fail on its own, not through an empty section.
        let (wycheproof, files) = MANIFEST.split_once("\n[[file]]").unwrap();
        let unterminated = format!("[[file]]{files}\n{}", wycheproof.trim_end().trim_end_matches(']'));
        assert!(parse(&unterminated).unwrap_err().to_string().contains("unterminated"));
        assert!(parse(&MANIFEST.replace("source = \"https://example.org/wycheproof\"\n", "")).is_err());
        let no_files = MANIFEST.replace("    \"testvectors_v1/a.json\",\n    \"testvectors_v1/b.json\",\n", "");
        assert!(parse(&no_files).is_err());
        assert!(parse(MANIFEST.split("\n[[file]]").next().unwrap()).is_err());
    }
}
