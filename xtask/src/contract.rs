use crate::Result;
use std::{collections::BTreeSet, fs, path::Path};

// Every literal CONTRACT.md section citation in picky-crypto/src/**/*.rs must
// name an existing numbered ## or ### heading. Macro citations are literal
// arguments, not concat! fragments; rustdoc checks item links separately.

fn section_prefix(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut end = bytes.iter().take_while(|byte| byte.is_ascii_digit()).count();
    if end == 0 {
        return None;
    }
    while bytes.get(end) == Some(&b'.') && bytes.get(end + 1).is_some_and(u8::is_ascii_digit) {
        end += 1;
        end += bytes[end..].iter().take_while(|byte| byte.is_ascii_digit()).count();
    }
    Some(&text[..end])
}

fn section_heading(line: &str) -> Option<&str> {
    let (text, subsection) = match line.strip_prefix("## ") {
        Some(text) => (text, false),
        None => (line.strip_prefix("### ")?, true),
    };
    let token = text.split_whitespace().next()?;
    let number = section_prefix(token)?;
    if subsection {
        (number == token && number.contains('.')).then_some(number)
    } else {
        (token.strip_suffix('.') == Some(number) && !number.contains('.')).then_some(number)
    }
}

fn citations(line: &str) -> Result<Vec<&str>> {
    let mut sections = Vec::new();
    for (offset, matched) in line.match_indices("CONTRACT.md section") {
        let text = &line[offset + matched.len()..];
        let text = text.strip_prefix('s').unwrap_or(text);
        if !text.starts_with(char::is_whitespace) {
            return Err("malformed section citation: expected a section number".into());
        }
        let mut text = text.trim_start();
        loop {
            let section = section_prefix(text).ok_or("malformed section citation: expected a section number")?;
            let rest = &text[section.len()..];
            let suffix = rest.strip_prefix('.').unwrap_or(rest);
            if suffix
                .chars()
                .next()
                .is_some_and(|c| !c.is_whitespace() && !",;:)".contains(c))
            {
                return Err(format!("malformed section citation: invalid suffix after {section}").into());
            }
            sections.push(section);
            let next = rest
                .strip_prefix(", and ")
                .or_else(|| rest.strip_prefix(", "))
                .or_else(|| rest.strip_prefix(" and "));
            match next {
                Some(next) if section_prefix(next).is_some() => text = next,
                _ => break,
            }
        }
    }
    Ok(sections)
}

fn source_citations(source: &str, path: &Path, sections: &BTreeSet<&str>) -> (usize, Vec<String>) {
    let mut count = 0;
    let mut errors = Vec::new();
    for (line, text) in source.lines().enumerate() {
        let location = format!("{}:{}", path.display(), line + 1);
        // Rust string delimiters are not part of the documentation.
        let fragments: Vec<_> = if text.trim_start().starts_with("//") || !text.contains('"') {
            vec![text]
        } else {
            text.split('"').collect()
        };
        for fragment in fragments {
            let listed = match citations(fragment) {
                Ok(listed) => listed,
                Err(error) => {
                    errors.push(format!("{location}: {error}"));
                    continue;
                }
            };
            for section in listed {
                count += 1;
                if !sections.contains(section) {
                    errors.push(format!("{location}: nonexistent section {section}"));
                }
            }
        }
    }
    (count, errors)
}

fn check_sources(directory: &Path, sections: &BTreeSet<&str>) -> Result<(usize, Vec<String>)> {
    let mut count = 0;
    let mut errors = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let (found, source_errors) = if entry.file_type()?.is_dir() {
            check_sources(&path, sections)?
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            source_citations(&fs::read_to_string(&path)?, &path, sections)
        } else {
            continue;
        };
        count += found;
        errors.extend(source_errors);
    }
    Ok((count, errors))
}

pub(crate) fn check(root: &Path) -> Result<()> {
    let crate_path = root.join("picky-crypto");
    let contract = fs::read_to_string(crate_path.join("CONTRACT.md"))?;
    let sections: BTreeSet<_> = contract.lines().filter_map(section_heading).collect();
    let (count, mut errors) = check_sources(&crate_path.join("src"), &sections)?;
    if !errors.is_empty() {
        errors.sort();
        return Err(errors.join("\n").into());
    }
    println!("contract: {count} section citations passed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_headings() {
        let fixture = "# Contract\n## 2. General rules\n### 6.11 Key agreement\n#### FFDH\n## Appendix A. Public API\n";
        assert_eq!(
            fixture.lines().filter_map(section_heading).collect::<BTreeSet<_>>(),
            BTreeSet::from(["2", "6.11"])
        );
        for text in [
            "## 2 Rules",
            "## 2.foo",
            "### 6..11 Rules",
            "### 6 Rules",
            "#### 6.11 Rules",
        ] {
            assert_eq!(section_heading(text), None, "{text}");
        }
    }

    #[test]
    fn section_citations() {
        assert_eq!(
            citations("/// See CONTRACT.md sections 6.15 and 7.").unwrap(),
            ["6.15", "7"]
        );
        assert_eq!(
            citations("See CONTRACT.md section 8.1. See CONTRACT.md section 10.").unwrap(),
            ["8.1", "10"]
        );
        for (text, expected) in [
            ("See CONTRACT.md section 6.1.", vec!["6.1"]),
            ("See CONTRACT.md section 6.1. Next", vec!["6.1"]),
            ("See CONTRACT.md section 6.1)", vec!["6.1"]),
            ("See CONTRACT.md sections 6.1, 7", vec!["6.1", "7"]),
            ("See CONTRACT.md sections 6.1, 999.", vec!["6.1", "999"]),
            ("See CONTRACT.md sections 6.1 and 8.", vec!["6.1", "8"]),
            ("See CONTRACT.md sections 6.1, 8 and 9.", vec!["6.1", "8", "9"]),
            ("See CONTRACT.md sections 6.1, 8, and 9.", vec!["6.1", "8", "9"]),
            ("See CONTRACT.md sections 6.1, 8, and 999.", vec!["6.1", "8", "999"]),
            ("See CONTRACT.md sections 6.1, 8, and 999", vec!["6.1", "8", "999"]),
            ("See CONTRACT.md sections 6.1, 8, 9.", vec!["6.1", "8", "9"]),
            ("See CONTRACT.md sections 6.1,\t8\tand\t9.", vec!["6.1"]),
            ("See CONTRACT.md section 6.1 for the hash context rules.", vec!["6.1"]),
            ("See CONTRACT.md sections 6.1 and 7", vec!["6.1", "7"]),
            ("See CONTRACT.md section 6.1 and the hash context rules.", vec!["6.1"]),
            ("See CONTRACT.md sections 6.1, prose follows.", vec!["6.1"]),
            ("See CONTRACT.md sections 6.1,", vec!["6.1"]),
            ("See CONTRACT.md sections 6.1 and", vec!["6.1"]),
            ("See CONTRACT.md sections 6.1, 8 and nonsense", vec!["6.1", "8"]),
        ] {
            assert_eq!(citations(text).unwrap(), expected, "{text}");
        }
        for text in [
            "CONTRACT.md sections nonsense",
            "CONTRACT.md section",
            "CONTRACT.md sections 6..1",
            "CONTRACT.md section 6.1x",
            "CONTRACT.md sections 6.1, 8x",
            "CONTRACT.md section 6.1_",
            "CONTRACT.md section 6.1.foo",
            "CONTRACT.md section 6.1...x",
            "CONTRACT.md section 6.1..",
            "CONTRACT.md sections 6.1, 7.foo",
            "CONTRACT.md section 6.1.\"",
        ] {
            assert!(citations(text).is_err(), "{text}");
        }
        assert!(citations("No citation here").unwrap().is_empty());
    }

    #[test]
    fn source_citations_include_macro_literals_and_locations() {
        let fixture = r#"/// See CONTRACT.md section 6.1 for the hash context rules.
capability!(Hash, HashAlgorithm, "See CONTRACT.md section 3.", {});
#[doc = "See CONTRACT.md sections 6.1 and 7."]
/// See CONTRACT.md sections 6.1, 8, and 999.
/// See CONTRACT.md section 6.1x
"#;
        let path = Path::new("traits.rs");
        let (count, errors) = source_citations(fixture, path, &BTreeSet::from(["3", "6.1", "7", "8"]));
        assert_eq!(count, 7);
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[0], "traits.rs:4: nonexistent section 999");
        assert_eq!(
            errors[1],
            "traits.rs:5: malformed section citation: invalid suffix after 6.1"
        );
    }

    #[test]
    fn source_citations_exclude_string_delimiters() {
        let fixture = r#"#[doc = "See CONTRACT.md section 6.1"]
capability!(Hash, HashAlgorithm, "See CONTRACT.md section 6.1.", {});
#[doc = "See CONTRACT.md section 6.1. Next"] #[doc = "See CONTRACT.md section 7."]
#[doc = "\" See CONTRACT.md section 6.1."]
"#;
        let (count, errors) = source_citations(fixture, Path::new("traits.rs"), &BTreeSet::from(["6.1", "7"]));
        assert_eq!(count, 5);
        assert!(errors.is_empty());
        let (_, errors) = source_citations(
            "/// See CONTRACT.md section 6.1.\"",
            Path::new("traits.rs"),
            &BTreeSet::from(["6.1"]),
        );
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn malformed_citation_suffix_reports_the_source_location() {
        let fixture = "/// Description.\n/// See CONTRACT.md section 6.1x";
        let (_, errors) = source_citations(fixture, Path::new("error.rs"), &BTreeSet::from(["6.1"]));
        assert_eq!(
            errors,
            ["error.rs:2: malformed section citation: invalid suffix after 6.1"]
        );
    }

    #[test]
    fn oxford_comma_citations_check_the_final_section() {
        let fixture = "/// See CONTRACT.md sections 6.1, 8, and 999.";
        let (count, errors) = source_citations(fixture, Path::new("traits.rs"), &BTreeSet::from(["6.1", "8"]));
        assert_eq!(count, 3);
        assert_eq!(errors, ["traits.rs:1: nonexistent section 999"]);
    }
}
