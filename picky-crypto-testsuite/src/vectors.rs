use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use serde::Deserialize;
use serde_json::Value;

pub fn read(file: &str) -> String {
    let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/vectors")).join(file);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        if file.starts_with("wycheproof") {
            panic!(
                "cannot read {}: {e}; run git submodule update --init picky-crypto-testsuite/vectors/wycheproof",
                path.display()
            );
        }
        panic!("cannot read published vector {}: {e}", path.display());
    })
}

pub fn bytes(text: &str) -> Vec<u8> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    let padded = if clean.len() % 2 == 1 {
        format!("0{clean}")
    } else {
        clean
    };
    hex::decode(&padded).unwrap_or_else(|e| panic!("invalid published hex: {e}"))
}

pub fn field(value: &Value, name: &str) -> Vec<u8> {
    bytes(string(value, name))
}

pub fn string<'a>(value: &'a Value, name: &str) -> &'a str {
    value[name]
        .as_str()
        .unwrap_or_else(|| panic!("missing vector string {name}"))
}

pub fn number(value: &Value, name: &str) -> usize {
    value[name]
        .as_u64()
        .unwrap_or_else(|| panic!("missing vector number {name}")) as usize
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Wycheproof {
    pub number_of_tests: usize,
    pub test_groups: Vec<Value>,
}

pub fn wycheproof(file: &str) -> Wycheproof {
    let vectors: Wycheproof = serde_json::from_str(&read(&format!("wycheproof/testvectors_v1/{file}")))
        .unwrap_or_else(|e| panic!("{file}: {e}"));
    assert_eq!(
        vectors.number_of_tests,
        vectors.test_groups.iter().map(|g| tests(g).len()).sum::<usize>(),
        "{file}: numberOfTests mismatch"
    );
    for group in &vectors.test_groups {
        for test in tests(group) {
            assert!(
                matches!(string(test, "result"), "valid" | "invalid" | "acceptable"),
                "{file}: unknown label"
            );
            assert!(test["tcId"].is_u64(), "{file}: missing test identifier");
        }
    }
    vectors
}

pub fn tests(group: &Value) -> &[Value] {
    group["tests"].as_array().expect("missing published tests")
}

/// Returns the hex fields of `testGroups[group].privateKey` in a Wycheproof `testvectors_v1` file, decoded exactly as published.
///
/// `file` is a file name such as `rsa_oaep_misc_test.json`, listed in `vectors/manifest.toml`.
/// Leading zero bytes are kept.
/// The file goes through the same schema and test-count checks as the suite's own vectors.
///
/// # Panics
///
/// Panics if the file isn't listed in the manifest or fails those checks, if the group or its `privateKey` is missing, or if a field isn't even-length hex.
pub fn wycheproof_private_key(file: &str, group: usize) -> BTreeMap<String, Vec<u8>> {
    assert!(
        read("manifest.toml").contains(&format!("\"testvectors_v1/{file}\"")),
        "{file} is not listed in vectors/manifest.toml"
    );
    let vectors = wycheproof(file);
    let key = vectors
        .test_groups
        .get(group)
        .unwrap_or_else(|| panic!("{file}: no test group {group}"))["privateKey"]
        .as_object()
        .unwrap_or_else(|| panic!("{file}: test group {group} has no privateKey"));
    key.iter()
        .map(|(name, value)| {
            let text = value
                .as_str()
                .unwrap_or_else(|| panic!("{file}: privateKey.{name} is not a string"));
            let decoded = hex::decode(text).unwrap_or_else(|e| panic!("{file}: privateKey.{name}: {e}"));
            (name.clone(), decoded)
        })
        .collect()
}

pub fn id(algorithm: impl std::fmt::Debug, file: &str, test: &Value) -> String {
    format!(
        "{algorithm:?}/{file}/tcId={}/{}",
        number(test, "tcId"),
        string(test, "comment")
    )
}

pub fn flag(test: &Value, flag: &str) -> bool {
    test["flags"]
        .as_array()
        .is_some_and(|flags| flags.iter().any(|f| f == flag))
}

#[derive(Clone, Debug)]
pub struct Record {
    pub group: String,
    pub fields: BTreeMap<String, String>,
}

impl Record {
    pub fn text(&self, name: &str) -> &str {
        self.fields
            .get(name)
            .unwrap_or_else(|| panic!("{}: missing {name}", self.group))
    }
    pub fn bytes(&self, name: &str) -> Vec<u8> {
        bytes(self.text(name))
    }
    pub fn number(&self, name: &str) -> usize {
        self.text(name).parse().expect("published integer")
    }
    pub fn id(&self, file: &str) -> String {
        format!(
            "{file}/{} /{}",
            self.group,
            self.fields
                .get("COUNT")
                .or_else(|| self.fields.get("Count"))
                .or_else(|| self.fields.get("Len"))
                .map_or("", String::as_str)
        )
    }
}

pub fn response(file: &str) -> Vec<Record> {
    let mut group = String::new();
    let mut defaults = BTreeMap::new();
    let mut fields = BTreeMap::new();
    let mut result = Vec::new();
    let mut active = false;
    for line in read(file).lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if active {
                result.push(Record {
                    group: group.clone(),
                    fields: std::mem::take(&mut fields),
                });
                active = false;
            }
            let header = line.trim_matches(['[', ']']);
            if header.starts_with("PRF=") {
                defaults.clear();
                group.clear();
            }
            if header.contains(" - ") || matches!(header, "ENCRYPT" | "DECRYPT") {
                defaults.clear();
                group.clear();
            }
            if !group.is_empty() {
                group.push(';');
            }
            group.push_str(header);
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let (k, v) = (k.trim(), v.trim());
            if matches!(k, "COUNT" | "Count" | "Len") {
                if active {
                    result.push(Record {
                        group: group.clone(),
                        fields: std::mem::take(&mut fields),
                    });
                }
                fields = defaults.clone();
                active = true;
            }
            if active {
                fields.insert(k.to_owned(), v.to_owned());
            } else {
                defaults.insert(k.to_owned(), v.to_owned());
            }
        }
    }
    if active {
        result.push(Record { group, fields });
    }
    assert!(!result.is_empty(), "{file}: no parsed records");
    result
}

pub fn hex_lines(text: &str) -> Vec<u8> {
    bytes(
        &text
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                (!line.is_empty() && line.chars().all(|c| c.is_ascii_hexdigit() || c.is_whitespace())).then_some(line)
            })
            .collect::<String>(),
    )
}

pub fn between<'a>(text: &'a str, begin: &str, end: &str) -> &'a str {
    text.split_once(begin)
        .unwrap_or_else(|| panic!("missing RFC anchor {begin}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing RFC anchor {end}"))
        .0
}

pub fn md(rfc: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let text = read(&format!("rfc/rfc{rfc}.txt"));
    let lines: Vec<_> = text.lines().collect();
    let mut records = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with("MD4 (") || line.starts_with("MD5 (") {
            let (line, next) = if line.contains("\") =") {
                ((*line).to_owned(), i + 1)
            } else {
                (format!("{line}{}", lines[i + 1]), i + 2)
            };
            let message = between(&line, "(\"", "\")").as_bytes().to_vec();
            let output = line.split_once('=').unwrap().1.trim();
            records.push((
                message,
                bytes(if output.is_empty() { lines[next].trim() } else { output }),
            ));
        }
    }
    assert_eq!(records.len(), 7, "RFC {rfc} appendix A.5");
    records
}

pub fn rc2() -> Vec<Record> {
    let text = read("rfc/rfc2268.txt");
    let mut records = Vec::new();
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        if let Some((k, v)) = line.trim().split_once(" = ") {
            if matches!(
                k,
                "Key length (bytes)" | "Effective key length (bits)" | "Key" | "Plaintext" | "Ciphertext"
            ) {
                fields.insert(k.to_owned(), v.to_owned());
                if k == "Ciphertext" {
                    fields.insert("COUNT".to_owned(), records.len().to_string());
                    records.push(Record {
                        group: "section 5".to_owned(),
                        fields: std::mem::take(&mut fields),
                    });
                }
            }
        }
    }
    assert_eq!(records.len(), 8, "RFC 2268 section 5");
    records
        .into_iter()
        .filter(|r| r.number("Key length (bytes)") * 8 == r.number("Effective key length (bits)"))
        .collect()
}

pub fn rc4() -> Vec<(Vec<u8>, usize, Vec<u8>)> {
    let mut key = Vec::new();
    let mut records = Vec::new();
    for line in read("rfc/rfc6229.txt").lines() {
        let line = line.trim();
        if let Some(hex) = line.strip_prefix("key: 0x") {
            key = bytes(hex);
        }
        if let Some(line) = line.strip_prefix("DEC ") {
            let (offset, rest) = line.split_once("HEX").expect("RC4 offset");
            let (_, output) = rest.split_once(':').expect("RC4 keystream");
            records.push((key.clone(), offset.trim().parse().unwrap(), bytes(output)));
        }
    }
    assert_eq!(records.len(), 252, "RFC 6229");
    records
}

#[derive(Clone)]
pub struct EdVector {
    pub seed: Vec<u8>,
    pub public: Vec<u8>,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn ed25519() -> &'static [EdVector] {
    static CACHE: OnceLock<Vec<EdVector>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let text = read("rfc/rfc8032.txt");
        let section = between(&text, "-----TEST 1", "7.2.  Test Vectors for Ed25519ctx");
        let cases: Vec<_> = section
            .split("SECRET KEY:")
            .skip(1)
            .map(|s| {
                let seed = hex_lines(s.split_once("PUBLIC KEY:").unwrap().0);
                let public = hex_lines(between(s, "PUBLIC KEY:", "MESSAGE"));
                let msg = s.split_once("MESSAGE").unwrap().1.split_once(':').unwrap().1;
                let message = hex_lines(msg.split_once("SIGNATURE:").unwrap().0);
                let signature_text = s.split_once("SIGNATURE:").unwrap().1;
                let signature = hex_lines(signature_text.split("-----").next().unwrap());
                assert_eq!(seed.len(), 32);
                assert_eq!(public.len(), 32);
                assert_eq!(signature.len(), 64);
                EdVector {
                    seed,
                    public,
                    message,
                    signature,
                }
            })
            .collect();
        assert_eq!(cases.len(), 5, "RFC 8032 section 7.1");
        cases
    })
}

pub fn pem(text: &str, label: &str) -> Vec<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    text.split(&begin)
        .skip(1)
        .map(|s| base64(s.split_once(&end).unwrap().0))
        .collect()
}

pub fn ed8410() -> Vec<Vec<u8>> {
    let text = read("rfc/rfc8410.txt");
    let start = text.rfind("10.3.  Examples").unwrap();
    let section = text[start..].split_once("11.  IANA Considerations").unwrap().0;
    let keys = pem(section, "PRIVATE KEY");
    assert_eq!(keys.len(), 2, "RFC 8410 section 10.3");
    keys
}

fn base64(text: &str) -> Vec<u8> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut acc = 0u32;
    let mut bits = 0;
    let mut out = Vec::new();
    for c in text.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        acc = (acc << 6) | alphabet.iter().position(|v| *v == c).expect("published PEM base64") as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

pub fn x25519_rfc() -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let text = read("rfc/rfc7748.txt");
    let section = text
        .split_once("Input scalar:")
        .unwrap()
        .1
        .split_once("   X448:")
        .unwrap()
        .0;
    let cases: Vec<_> = std::iter::once(section)
        .chain(section.split("Input scalar:").skip(1))
        .map(|s| {
            (
                hex_lines(s.split_once("Input scalar as a number").unwrap().0),
                hex_lines(between(s, "Input u-coordinate:", "Input u-coordinate as a number")),
                hex_lines(
                    s.split_once("Output u-coordinate:")
                        .unwrap()
                        .1
                        .split("Input scalar:")
                        .next()
                        .unwrap(),
                ),
            )
        })
        .collect();
    assert_eq!(cases.len(), 2, "RFC 7748 section 5.2");
    cases
}

pub fn x25519_iterations() -> (Vec<u8>, Vec<(usize, Vec<u8>)>) {
    let text = read("rfc/rfc7748.txt");
    let s = text.split_once("Initially, set k").unwrap().1;
    let seed = hex_lines(between(s, "For X25519:", "For X448:"));
    let s = between(s, "   X25519:", "   X448:");
    let cases = s
        .split("After ")
        .skip(1)
        .map(|s| {
            let (count, rest) = s.split_once(" iteration").unwrap();
            let count = if count == "one" {
                1
            } else {
                count.replace(',', "").parse().unwrap()
            };
            let expected = hex_lines(rest.split_once(':').unwrap().1);
            assert_eq!(expected.len(), 32);
            (count, expected)
        })
        .collect::<Vec<_>>();
    assert_eq!(seed.len(), 32);
    assert_eq!(cases.len(), 3, "RFC 7748 iteration results");
    (seed, cases)
}

type X25519Dh = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
pub fn x25519_dh() -> X25519Dh {
    let text = read("rfc/rfc7748.txt");
    let s = &text[text.rfind("6.1.  Curve25519").unwrap()..];
    let s = s
        .split_once("Test vector:")
        .unwrap()
        .1
        .split_once("6.2.  Curve448")
        .unwrap()
        .0;
    (
        hex_lines(between(s, "Alice's private key, a:", "Alice's public key")),
        hex_lines(between(s, "Alice's public key, X25519(a, 9):", "Bob's private key")),
        hex_lines(between(s, "Bob's private key, b:", "Bob's public key")),
        hex_lines(between(s, "Bob's public key, X25519(b, 9):", "Their shared secret")),
        hex_lines(s.split_once("Their shared secret, K:").unwrap().1),
    )
}

pub fn assignment_hex(text: &str) -> BTreeMap<String, Vec<u8>> {
    let mut fields = BTreeMap::new();
    let mut current = String::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some((k, v)) = line.split_once('=') {
            if !k.trim().is_empty() && v.chars().all(|c| c.is_ascii_hexdigit() || c.is_whitespace()) {
                current = k.trim().to_owned();
                fields.insert(current.clone(), bytes(v));
                continue;
            }
        }
        if !line.is_empty() && line.chars().all(|c| c.is_ascii_hexdigit() || c.is_whitespace()) {
            if let Some(value) = fields.get_mut(&current) {
                value.extend(bytes(line));
            }
        }
    }
    fields
}

pub fn rfc5114(section: usize) -> BTreeMap<String, Vec<u8>> {
    let text = read("rfc/rfc5114.txt");
    let anchor = format!("A.{section}.  ");
    let start = text.rfind(&anchor).expect("RFC 5114 appendix");
    let rest = &text[start..];
    let end = rest.find(&format!("A.{}.  ", section + 1)).unwrap_or(rest.len());
    assignment_hex(&rest[..end])
}

pub fn pbkdf2_rfc() -> Vec<Record> {
    let text = read("rfc/rfc6070.txt");
    let records: Vec<_> = text
        .split("Input:")
        .skip(1)
        .enumerate()
        .map(|(index, case)| {
            let mut fields = BTreeMap::new();
            fields.insert("COUNT".to_owned(), index.to_string());
            for line in case.lines() {
                if let Some((k, value)) = line.trim().split_once(" = ") {
                    if matches!(k, "P" | "S") {
                        let quoted = between(value, "\"", "\"").replace("\\0", "\0");
                        fields.insert(k.to_owned(), hex::encode(quoted.as_bytes()));
                    } else if matches!(k, "c" | "dkLen") {
                        fields.insert(k.to_owned(), value.trim().to_owned());
                    }
                }
            }
            let expected = case.split_once("DK = ").unwrap().1;
            let expected = expected
                .split_once("(20 octets)")
                .or_else(|| expected.split_once("(25 octets)"))
                .or_else(|| expected.split_once("(16 octets)"))
                .unwrap()
                .0;
            fields.insert("DK".to_owned(), hex::encode(hex_lines(expected)));
            Record {
                group: "section 2".to_owned(),
                fields,
            }
        })
        .collect();
    assert_eq!(records.len(), 6, "RFC 6070");
    for r in &records {
        assert_eq!(r.bytes("DK").len(), r.number("dkLen"));
    }
    records
}

pub fn hmac_rfc() -> Vec<Record> {
    let text = read("rfc/rfc4231.txt");
    let start = text.rfind("4.2.  Test Case 1").unwrap();
    let section = &text[start..text.rfind("5.  Security Considerations").unwrap()];
    let mut records = Vec::new();
    let mut fields = BTreeMap::<String, String>::new();
    let mut current = String::new();
    for line in section.lines() {
        let line = line.trim();
        if line.starts_with("4.") && line.contains("Test Case") {
            if !fields.is_empty() {
                records.push(Record {
                    group: current.clone(),
                    fields: std::mem::take(&mut fields),
                });
            }
            current = line.to_owned();
            continue;
        }
        let assignment = line
            .split_once('=')
            .or_else(|| line.strip_prefix("Key ").map(|value| ("Key", value)));
        if let Some((name, value)) = assignment {
            let name = name.trim();
            if matches!(
                name,
                "Key" | "Data" | "HMAC-SHA-224" | "HMAC-SHA-256" | "HMAC-SHA-384" | "HMAC-SHA-512"
            ) {
                fields.insert("current".to_owned(), name.to_owned());
                let hex = value.split('(').next().unwrap().trim();
                fields.insert(name.to_owned(), hex.to_owned());
            }
        } else if !line.split('(').next().unwrap().trim().is_empty()
            && line
                .split('(')
                .next()
                .unwrap()
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c.is_whitespace())
        {
            let name = fields.get("current").cloned().unwrap();
            fields
                .get_mut(&name)
                .unwrap()
                .push_str(line.split('(').next().unwrap().trim());
        }
    }
    if !fields.is_empty() {
        records.push(Record { group: current, fields });
    }
    assert_eq!(records.len(), 7, "RFC 4231");
    for (record, (key, data)) in
        records
            .iter()
            .zip([(20, 8), (4, 28), (20, 50), (25, 50), (20, 20), (131, 54), (131, 152)])
    {
        assert_eq!(record.bytes("Key").len(), key);
        assert_eq!(record.bytes("Data").len(), data);
    }
    records
}

#[derive(Clone)]
pub struct DhGroup {
    pub id: String,
    pub p: Vec<u8>,
    pub g: Vec<u8>,
    pub q: Option<Vec<u8>>,
}

impl DhGroup {
    pub fn parameters(&self) -> picky_crypto::FfdhParameters<'_> {
        picky_crypto::FfdhParameters::new(&self.p, &self.g, self.q.as_deref())
    }
}

pub fn dh_groups() -> Vec<DhGroup> {
    let mut result = Vec::new();
    let rfc = read("rfc/rfc5114.txt");
    for section in 1..=3 {
        let start = rfc.rfind(&format!("2.{section}.  ")).unwrap();
        let end = rfc[start..].find(&format!("2.{}.  ", section + 1)).unwrap();
        let fields = assignment_hex(&rfc[start..start + end]);
        result.push(DhGroup {
            id: format!("rfc/rfc5114.txt/2.{section}"),
            p: fields["p"].clone(),
            g: fields["g"].clone(),
            q: Some(fields["q"].clone()),
        });
    }
    let rfc = read("rfc/rfc3526.txt");
    for (section, bits) in [(3, 2048), (4, 3072), (5, 4096)] {
        let start = rfc.rfind(&format!("{section}.  {bits}-bit MODP Group")).unwrap();
        let end = rfc[start..].find(&format!("{}.  ", section + 1)).unwrap();
        let s = &rfc[start..start + end];
        let p = hex_lines(between(s, "Its hexadecimal value is:", "The generator is:"));
        let g = bytes(between(s, "The generator is:", ".").trim());
        assert_eq!(p.len() * 8, bits);
        result.push(DhGroup {
            id: format!("rfc/rfc3526.txt/{section}"),
            p,
            g,
            q: None,
        });
    }
    let rfc = read("rfc/rfc7919.txt");
    for (section, bits) in [(1, 2048), (2, 3072), (3, 4096)] {
        let start = rfc.rfind(&format!("A.{section}.  ffdhe{bits}")).unwrap();
        let end = rfc[start..].find(&format!("A.{}.  ", section + 1)).unwrap();
        let s = &rfc[start..start + end];
        let p = hex_lines(between(
            s,
            "The hexadecimal representation of p is:",
            "The generator is:",
        ));
        let q = hex_lines(
            s.split_once("The hexadecimal representation of q is:")
                .unwrap()
                .1
                .split("The estimated")
                .next()
                .unwrap(),
        );
        let g = bytes(between(s, "The generator is: g =", "\n").trim());
        assert_eq!(p.len() * 8, bits);
        assert_eq!(q.len(), p.len());
        result.push(DhGroup {
            id: format!("rfc/rfc7919.txt/A.{section}"),
            p,
            g,
            q: Some(q),
        });
    }
    assert_eq!(result.len(), 9);
    result
}

#[derive(Clone)]
pub struct RsaOaep {
    pub fields: Vec<Vec<u8>>,
    pub cases: Vec<(Vec<u8>, Vec<u8>)>,
}

pub fn rsa_labs() -> Vec<RsaOaep> {
    let text = read("rsa-labs/oaep-vect.txt");
    let mut records = Vec::new();
    for chunk in text.split("# Example ").skip(1) {
        if !chunk.lines().next().unwrap_or("").contains("RSA key pair") {
            continue;
        }
        let private = chunk.split_once("# Private key").unwrap().1;
        let mut fields = Vec::new();
        for (name, end) in [
            ("# Modulus:", "# Public exponent:"),
            ("# Public exponent:", "# Exponent:"),
            ("# Exponent:", "# Prime 1:"),
            ("# Prime 1:", "# Prime 2:"),
            ("# Prime 2:", "# Prime exponent 1:"),
            ("# Prime exponent 1:", "# Prime exponent 2:"),
            ("# Prime exponent 2:", "# Coefficient:"),
        ] {
            fields.push(hex_lines(between(private, name, end)));
        }

        fields.push(hex_lines(
            private
                .split_once("# Coefficient:")
                .unwrap()
                .1
                .split("# OAEP Example")
                .next()
                .unwrap(),
        ));
        let cases = private
            .split("# Message:")
            .skip(1)
            .map(|s| {
                let message = hex_lines(s.split_once("# Seed:").unwrap().0);
                let ciphertext = hex_lines(s.split_once("# Encryption:").unwrap().1.split('#').next().unwrap());
                (message, ciphertext)
            })
            .collect::<Vec<_>>();
        assert_eq!(fields.len(), 8);
        assert_eq!(cases.len(), 6);
        records.push(RsaOaep { fields, cases });
    }
    assert_eq!(records.len(), 10, "RSA Laboratories OAEP v2.1");
    records
}

#[cfg(test)]
type EcEncodingControl = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
#[cfg(test)]
pub fn ec9500() -> Vec<EcEncodingControl> {
    let text = read("rfc/rfc9500.txt");
    let start = text.rfind("2.3.  ECDLP Keys").unwrap();
    let section = &text[start..];
    let keys = pem(section, "EC PRIVATE KEY");
    let raw: Vec<_> = section
        .split("/* qx */")
        .skip(1)
        .map(|s| {
            let component = |source: &str| {
                let values = between(source, "{", "}");
                values
                    .split(',')
                    .map(|v| u8::from_str_radix(v.trim().trim_start_matches("0x"), 16).unwrap())
                    .collect::<Vec<_>>()
            };
            let x = component(s);
            let y = component(s.split_once("/* qy */").unwrap().1);
            let scalar = component(s.split_once("/* d */").unwrap().1);
            (scalar, x, y)
        })
        .collect();
    assert_eq!(raw.len(), 3, "RFC 9500 section 2.3 raw keys");
    assert_eq!(keys.len(), 3, "RFC 9500 section 2.3 SEC1 keys");
    raw.into_iter()
        .zip(keys)
        .map(|((d, x, y), encoded)| (d, x, y, encoded))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const CRT_FIELDS: [&str; 8] = [
        "coefficient",
        "exponent1",
        "exponent2",
        "modulus",
        "prime1",
        "prime2",
        "privateExponent",
        "publicExponent",
    ];

    #[rstest]
    #[case("rsa_oaep_misc_test.json", 0, true)]
    #[case("rsa_oaep_misc_test.json", 127, true)]
    #[case("rsa_oaep_2048_sha1_mgf1sha1_test.json", 0, true)]
    #[case("rsa_oaep_2048_sha224_mgf1sha1_test.json", 0, true)]
    #[case("rsa_oaep_3072_sha256_mgf1sha1_test.json", 0, true)]
    #[case("rsa_oaep_4096_sha256_mgf1sha1_test.json", 0, true)]
    #[case("rsa_pkcs1_2048_sig_gen_test.json", 0, false)]
    fn wycheproof_private_key_fields(#[case] file: &str, #[case] group: usize, #[case] crt: bool) {
        let key = wycheproof_private_key(file, group);
        let expected: Vec<_> = if crt {
            CRT_FIELDS.to_vec()
        } else {
            vec!["modulus", "privateExponent", "publicExponent"]
        };
        assert_eq!(key.keys().map(String::as_str).collect::<Vec<_>>(), expected);
        let published = &wycheproof(file).test_groups[group];
        for (name, bytes) in &key {
            let text = string(&published["privateKey"], name);
            assert_eq!(bytes.len() * 2, text.len(), "{file}/{group}/{name}");
            assert_eq!(hex::encode(bytes), text.to_ascii_lowercase(), "{file}/{group}/{name}");
        }
        let modulus = &key["modulus"];
        let significant = modulus.iter().skip_while(|b| **b == 0).count();
        assert!(
            modulus.len() > significant,
            "{file}/{group}: published leading zero byte kept"
        );
        assert_eq!(
            crate::der::bit_length(modulus),
            number(published, "keySize"),
            "{file}/{group}: modulus size"
        );
    }

    #[test]
    #[should_panic(expected = "no test group")]
    fn wycheproof_private_key_rejects_missing_group() {
        wycheproof_private_key("rsa_pkcs1_2048_sig_gen_test.json", 8);
    }

    #[test]
    #[should_panic(expected = "not listed")]
    fn wycheproof_private_key_rejects_unlisted_file() {
        wycheproof_private_key("rsa_oaep_2048_sha512_mgf1sha1_test.json", 0);
    }

    #[test]
    #[should_panic(expected = "has no privateKey")]
    fn wycheproof_private_key_rejects_groups_without_private_key() {
        wycheproof_private_key("rsa_signature_2048_sha256_test.json", 0);
    }

    #[rstest]
    #[case("nist/shs/SHA1ShortMsg.rsp", 65)]
    #[case("nist/shs/SHA224ShortMsg.rsp", 65)]
    #[case("nist/shs/SHA256ShortMsg.rsp", 65)]
    #[case("nist/shs/SHA384ShortMsg.rsp", 129)]
    #[case("nist/shs/SHA512ShortMsg.rsp", 129)]
    #[case("nist/sha3/SHA3_384ShortMsg.rsp", 105)]
    #[case("nist/sha3/SHA3_512ShortMsg.rsp", 73)]
    #[case("nist/shs/SHA1Monte.rsp", 100)]
    #[case("nist/shs/SHA224Monte.rsp", 100)]
    #[case("nist/shs/SHA256Monte.rsp", 100)]
    #[case("nist/shs/SHA384Monte.rsp", 100)]
    #[case("nist/shs/SHA512Monte.rsp", 100)]
    #[case("nist/sha3/SHA3_384Monte.rsp", 100)]
    #[case("nist/sha3/SHA3_512Monte.rsp", 100)]
    #[case("nist/aes/CBCGFSbox128.rsp", 14)]
    #[case("nist/aes/CBCGFSbox192.rsp", 12)]
    #[case("nist/aes/CBCGFSbox256.rsp", 10)]
    #[case("nist/aes/CBCKeySbox128.rsp", 42)]
    #[case("nist/aes/CBCKeySbox192.rsp", 48)]
    #[case("nist/aes/CBCKeySbox256.rsp", 32)]
    #[case("nist/aes/CBCMMT128.rsp", 20)]
    #[case("nist/aes/CBCMMT192.rsp", 20)]
    #[case("nist/aes/CBCMMT256.rsp", 20)]
    #[case("nist/tdes/TCBCMMT2.rsp", 10)]
    #[case("nist/tdes/TCBCMMT3.rsp", 20)]
    #[case("nist/kbkdf/KDFCTR_gen.rsp", 160)]
    #[case("nist/kas/KASValidityTest_ECCEphemeralUnified_KDFConcat_NOKC_init.fax", 180)]
    #[case("nist/kas/KASValidityTest_FFCStatic_NOKC_ZZOnly_init.fax", 48)]
    fn response_count(#[case] file: &str, #[case] count: usize) {
        assert_eq!(response(file).len(), count, "{file}");
    }

    #[test]
    fn rfc_parsers() {
        md(1320);
        md(1321);
        assert_eq!(rc2().len(), 3);
        rc4();
        ed25519();
        x25519_rfc();
        x25519_iterations();
        let (a, ap, b, bp, s) = x25519_dh();
        for value in [a, ap, b, bp, s] {
            assert_eq!(value.len(), 32);
        }
        pbkdf2_rfc();
        hmac_rfc();
        dh_groups();
        rsa_labs();
        ec9500();
        for section in [1, 2, 3, 6, 7, 8] {
            assert!(!rfc5114(section).is_empty());
        }
    }

    #[rstest]
    #[case("hmac_sha1_test.json")]
    #[case("hmac_sha224_test.json")]
    #[case("hmac_sha256_test.json")]
    #[case("hmac_sha384_test.json")]
    #[case("hmac_sha512_test.json")]
    #[case("pbkdf2_hmacsha1_test.json")]
    #[case("pbkdf2_hmacsha224_test.json")]
    #[case("pbkdf2_hmacsha256_test.json")]
    #[case("pbkdf2_hmacsha384_test.json")]
    #[case("pbkdf2_hmacsha512_test.json")]
    #[case("aes_gcm_test.json")]
    #[case("aes_wrap_test.json")]
    #[case("x25519_test.json")]
    #[case("ed25519_test.json")]
    #[case("ecdsa_secp256r1_sha256_p1363_test.json")]
    #[case("ecdsa_secp384r1_sha384_p1363_test.json")]
    #[case("ecdsa_secp521r1_sha512_p1363_test.json")]
    #[case("ecdh_secp256r1_ecpoint_test.json")]
    #[case("ecdh_secp384r1_ecpoint_test.json")]
    #[case("ecdh_secp521r1_ecpoint_test.json")]
    #[case("rsa_signature_2048_sha224_test.json")]
    #[case("rsa_signature_2048_sha256_test.json")]
    #[case("rsa_signature_2048_sha384_test.json")]
    #[case("rsa_signature_2048_sha512_test.json")]
    #[case("rsa_signature_2048_sha3_384_test.json")]
    #[case("rsa_signature_2048_sha3_512_test.json")]
    #[case("rsa_signature_3072_sha256_test.json")]
    #[case("rsa_signature_4096_sha512_test.json")]
    #[case("rsa_pkcs1_2048_sig_gen_test.json")]
    #[case("rsa_pkcs1_3072_sig_gen_test.json")]
    #[case("rsa_pkcs1_4096_sig_gen_test.json")]
    #[case("rsa_pkcs1_2048_test.json")]
    #[case("rsa_oaep_2048_sha1_mgf1sha1_test.json")]
    #[case("rsa_oaep_2048_sha256_mgf1sha256_test.json")]
    #[case("rsa_oaep_3072_sha256_mgf1sha256_test.json")]
    #[case("rsa_oaep_4096_sha256_mgf1sha256_test.json")]
    fn wycheproof_schema(#[case] file: &str) {
        let parsed = wycheproof(file);
        for group in parsed.test_groups {
            for test in tests(&group) {
                for name in [
                    "msg", "tag", "ct", "key", "iv", "aad", "password", "salt", "dk", "public", "private", "shared",
                    "sig",
                ] {
                    if test[name].is_string() {
                        field(test, name);
                    }
                }
                for name in ["privateKeyPkcs8", "publicKeyDer", "publicKeyAsn", "keyDer", "keyAsn"] {
                    if group[name].is_string() {
                        let bytes = field(&group, name);
                        let parts = crate::der::children(&bytes);
                        assert_eq!(
                            crate::der::sequence(&parts.iter().map(|p| p.encoded.to_vec()).collect::<Vec<_>>()),
                            bytes
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn assembled_inputs() {
        for a in crate::algorithms::CIPHERS {
            let records = crate::symmetric::cipher_records(a);
            assert!(!records.is_empty());
            for (_, key, iv, plaintext, ciphertext, _) in records {
                assert!(!key.is_empty());
                assert!(matches!(iv.len(), 8 | 16));
                assert_eq!(plaintext.len(), ciphertext.len());
                assert_eq!(plaintext.len() % iv.len(), 0);
            }
        }
        for (kind, _, width, r) in crate::asymmetric::ecc_cases() {
            let public = crate::der::point(&r.bytes("QeIUTx"), &r.bytes("QeIUTy"), width);
            let pkcs8 = crate::der::ec(kind, &r.bytes("deIUT"), Some(&public), None);
            let parts = crate::der::children(&pkcs8);
            let inner = crate::der::children(parts[2].value);
            assert_eq!(inner[1].value, crate::der::padded(&r.bytes("deIUT"), width));
            assert_eq!(crate::der::parse(inner[2].value).unwrap()[0].value[1..], public);
            for name in ["QeCAVSx", "QeCAVSy", "OI", "DKM", "Z"] {
                r.bytes(name);
            }
        }
        let groups = dh_groups();
        for (i, g) in groups.iter().take(3).enumerate() {
            let fields = rfc5114(i + 1);
            for name in ["xA", "yA", "xB", "yB", "Z"] {
                assert!(!fields[name].is_empty());
            }
            assert_eq!(g.p.len(), if i == 0 { 128 } else { 256 });
        }
        let base = &crate::symmetric::cipher_records(crate::algorithms::CIPHERS[3])[0].1;
        let derived = crate::symmetric::weak_tdes_key(base);
        assert_eq!(derived.len(), 24);
        assert_eq!(&derived[8..], &base[8..]);
    }
}
