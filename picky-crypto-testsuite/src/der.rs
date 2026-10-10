use picky_crypto::KeyType;

use crate::algorithms::{CURVES, ecdsa_file};
use crate::keys::{RSA_DECRYPT_FILES, RSA_SIGN_FILES};
use crate::vectors;

pub const RSA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1];
pub const EC_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1];
pub const ED_OID: &[u8] = &[0x2b, 0x65, 0x70];
pub fn curve_oid(curve: KeyType) -> &'static [u8] {
    match curve {
        KeyType::EcP256 => &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7],
        KeyType::EcP384 => &[0x2b, 0x81, 4, 0, 0x22],
        KeyType::EcP521 => &[0x2b, 0x81, 4, 0, 0x23],
        _ => panic!("not a named curve"),
    }
}
pub fn width(curve: KeyType) -> usize {
    match curve {
        KeyType::EcP256 => 32,
        KeyType::EcP384 => 48,
        KeyType::EcP521 => 66,
        _ => panic!("not EC"),
    }
}

#[derive(Clone, Copy)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    pub encoded: &'a [u8],
}

pub fn parse(bytes: &[u8]) -> Result<Vec<Tlv<'_>>, &'static str> {
    let mut result = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        if rest.len() < 2 {
            return Err("truncated TLV");
        }
        let first = rest[1];
        let (len, prefix) = if first < 128 {
            (usize::from(first), 2)
        } else {
            let count = usize::from(first & 127);
            if count == 0 || count > std::mem::size_of::<usize>() || rest.len() < 2 + count {
                return Err("invalid DER length");
            }
            if rest[2] == 0 {
                return Err("nonminimal DER length");
            }
            let len = rest[2..2 + count]
                .iter()
                .try_fold(0usize, |a, b| a.checked_mul(256)?.checked_add(usize::from(*b)))
                .ok_or("length overflow")?;
            if len < 128 {
                return Err("nonminimal DER length");
            }
            (len, 2 + count)
        };
        let end = prefix.checked_add(len).ok_or("length overflow")?;
        if end > rest.len() {
            return Err("truncated DER value");
        }
        result.push(Tlv {
            tag: rest[0],
            value: &rest[prefix..end],
            encoded: &rest[..end],
        });
        rest = &rest[end..];
    }
    Ok(result)
}

pub fn children(bytes: &[u8]) -> Vec<Tlv<'_>> {
    let outer = parse(bytes).expect("published DER");
    assert_eq!(outer.len(), 1);
    assert_eq!(outer[0].tag, 0x30);
    parse(outer[0].value).expect("published sequence")
}

pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let len = value.len().to_be_bytes();
        let start = len.iter().position(|b| *b != 0).unwrap();
        out.push(0x80 | (len.len() - start) as u8);
        out.extend(&len[start..]);
    }
    out.extend(value);
    out
}

pub fn sequence(fields: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &fields.concat())
}
pub fn integer(value: &[u8]) -> Vec<u8> {
    let value = unsigned(value);
    let mut out = Vec::new();
    if value.is_empty() || value[0] & 128 != 0 {
        out.push(0);
    }
    out.extend(value);
    tlv(2, &out)
}
pub fn unsigned(value: &[u8]) -> &[u8] {
    &value[value.iter().position(|b| *b != 0).unwrap_or(value.len())..]
}
/// Compares unsigned big-endian integers, ignoring leading zeros.
pub fn less(a: &[u8], b: &[u8]) -> bool {
    let (a, b) = (unsigned(a), unsigned(b));
    (a.len(), a) < (b.len(), b)
}
pub fn bit_length(value: &[u8]) -> usize {
    let value = unsigned(value);
    value
        .first()
        .map_or(0, |first| value.len() * 8 - first.leading_zeros() as usize)
}
pub fn padded(value: &[u8], width: usize) -> Vec<u8> {
    let value = unsigned(value);
    assert!(value.len() <= width, "published integer exceeds fixed width");
    let mut out = vec![0; width - value.len()];
    out.extend(value);
    out
}
pub fn point(x: &[u8], y: &[u8], width: usize) -> Vec<u8> {
    [vec![4], padded(x, width), padded(y, width)].concat()
}
pub fn algorithm(curve: KeyType) -> Vec<u8> {
    sequence(&[tlv(6, EC_OID), tlv(6, curve_oid(curve))])
}
pub fn pkcs8(algorithm: Vec<u8>, private: &[u8]) -> Vec<u8> {
    sequence(&[integer(&[0]), algorithm, tlv(4, private)])
}
pub fn rsa(inner: &[u8]) -> Vec<u8> {
    pkcs8(sequence(&[tlv(6, RSA_OID), tlv(5, &[])]), inner)
}
pub fn ec_inner(curve: KeyType, scalar: &[u8], public: Option<&[u8]>, parameters: Option<KeyType>) -> Vec<u8> {
    let mut fields = vec![integer(&[1]), tlv(4, &padded(scalar, width(curve)))];
    if let Some(parameters) = parameters {
        fields.push(tlv(0xa0, &tlv(6, curve_oid(parameters))));
    }
    if let Some(public) = public {
        fields.push(tlv(0xa1, &tlv(3, &[&[0][..], public].concat())));
    }
    sequence(&fields)
}
pub fn ec(curve: KeyType, scalar: &[u8], public: Option<&[u8]>, parameters: Option<KeyType>) -> Vec<u8> {
    pkcs8(algorithm(curve), &ec_inner(curve, scalar, public, parameters))
}
pub fn ed(seed: &[u8], public: Option<&[u8]>) -> Vec<u8> {
    let mut fields = vec![
        integer(&[u8::from(public.is_some())]),
        sequence(&[tlv(6, ED_OID)]),
        tlv(4, &tlv(4, seed)),
    ];
    if let Some(public) = public {
        fields.push(tlv(0x81, &[&[0][..], public].concat()));
    }
    sequence(&fields)
}
pub fn spki_public(spki: &[u8]) -> Vec<u8> {
    let parts = children(spki);
    assert_eq!(parts[1].tag, 3);
    assert_eq!(parts[1].value[0], 0);
    parts[1].value[1..].to_vec()
}
pub fn rebuild(bytes: &[u8]) -> Vec<u8> {
    parse(bytes)
        .expect("published DER")
        .iter()
        .flat_map(|p| tlv(p.tag, p.value))
        .collect()
}
pub fn rsa_fields(pkcs8: &[u8]) -> Vec<Vec<u8>> {
    let parts = children(pkcs8);
    children(parts[2].value).iter().map(|p| p.encoded.to_vec()).collect()
}
pub fn rsa_public(pkcs8: &[u8]) -> Vec<u8> {
    let fields = rsa_fields(pkcs8);
    sequence(&[fields[1].clone(), fields[2].clone()])
}
pub fn encoded_public(kind: KeyType, pkcs8: &[u8]) -> Option<Vec<u8>> {
    let fields = children(pkcs8);
    match kind {
        KeyType::Rsa => Some(rsa_public(pkcs8)),
        KeyType::Ed25519 => fields.iter().find(|f| f.tag == 0x81).map(|f| f.value[1..].to_vec()),
        KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 => {
            let inner = children(fields[2].value);
            inner
                .iter()
                .find(|f| f.tag == 0xa1)
                .map(|f| parse(f.value).unwrap()[0].value[1..].to_vec())
        }
        _ => None,
    }
}

fn single(bytes: &[u8], tag: u8) -> Result<Tlv<'_>, &'static str> {
    let fields = parse(bytes)?;
    if fields.len() != 1 || fields[0].tag != tag {
        return Err("unexpected DER tag or field count");
    }
    Ok(fields[0])
}

fn sequence_fields(bytes: &[u8]) -> Result<Vec<Tlv<'_>>, &'static str> {
    parse(single(bytes, 0x30)?.value)
}

fn tags(fields: &[Tlv<'_>], expected: &[u8]) -> Result<(), &'static str> {
    if fields.len() != expected.len() || fields.iter().zip(expected).any(|(field, tag)| field.tag != *tag) {
        return Err("incorrect mandatory tags or field order");
    }
    Ok(())
}

pub fn generated_public(kind: KeyType, bits: usize, encoded: &[u8]) -> Result<Vec<u8>, &'static str> {
    let outer = sequence_fields(encoded)?;
    let version = if kind == KeyType::Ed25519 {
        tags(&outer, &[2, 0x30, 4, 0x81])?;
        1
    } else {
        tags(&outer, &[2, 0x30, 4])?;
        0
    };
    if outer[0].value != [version] {
        return Err("incorrect PKCS#8 version");
    }
    let alg = parse(outer[1].value)?;
    match kind {
        KeyType::Rsa => {
            tags(&alg, &[6, 5])?;
            if alg[0].value != RSA_OID || !alg[1].value.is_empty() {
                return Err("incorrect RSA AlgorithmIdentifier");
            }
            let rsa = sequence_fields(outer[2].value)?;
            tags(&rsa, &[2; 9])?;
            if rsa[0].value != [0] {
                return Err("RSA key must be two-prime version 0");
            }
            for field in &rsa[1..] {
                let value = field.value;
                if value.is_empty()
                    || value[0] & 128 != 0
                    || value.iter().all(|b| *b == 0)
                    || value.len() > 1 && value[0] == 0 && value[1] & 128 == 0
                {
                    return Err("noncanonical or nonpositive RSA INTEGER");
                }
            }
            if bit_length(rsa[1].value) != bits
                || unsigned(rsa[2].value) != [1, 0, 1]
                || bit_length(rsa[4].value) != bits / 2
                || bit_length(rsa[5].value) != bits / 2
            {
                return Err("incorrect generated RSA size, exponent or prime sizes");
            }
            Ok(sequence(&[rsa[1].encoded.to_vec(), rsa[2].encoded.to_vec()]))
        }
        KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 => {
            tags(&alg, &[6, 6])?;
            if alg[0].value != EC_OID || alg[1].value != curve_oid(kind) {
                return Err("incorrect EC AlgorithmIdentifier");
            }
            let inner = sequence_fields(outer[2].value)?;
            if inner.len() == 4 {
                tags(&inner, &[2, 4, 0xa0, 0xa1])?;
            } else {
                tags(&inner, &[2, 4, 0xa1])?;
            }
            if inner[0].value != [1] || inner[1].value.len() != width(kind) {
                return Err("incorrect ECPrivateKey version or scalar width");
            }
            if inner.len() == 4 && single(inner[2].value, 6)?.value != curve_oid(kind) {
                return Err("mismatched EC parameters");
            }
            let point = single(inner.last().ok_or("missing EC publicKey")?.value, 3)?.value;
            if point.len() != 2 + 2 * width(kind) || point[0] != 0 || point[1] != 4 {
                return Err("incorrect EC publicKey BIT STRING");
            }
            Ok(point[1..].to_vec())
        }
        KeyType::Ed25519 => {
            tags(&alg, &[6])?;
            if alg[0].value != ED_OID {
                return Err("incorrect Ed25519 AlgorithmIdentifier");
            }
            if single(outer[2].value, 4)?.value.len() != 32 {
                return Err("incorrect Ed25519 seed OCTET STRING");
            }
            let public = outer[3].value;
            if public.len() != 33 || public[0] != 0 {
                return Err("incorrect Ed25519 outer publicKey BIT STRING");
            }
            Ok(public[1..].to_vec())
        }
        _ => Err("key type has no generator"),
    }
}
pub fn inconsistent_rsa(base: &[u8], other: Option<&[u8]>) -> Vec<Vec<u8>> {
    let fields = rsa_fields(base);
    assert_eq!(rsa(&sequence(&fields)), base, "published RSA split/reassemble control");
    let mut variants = Vec::new();
    for (a, b) in [(6, 7), (4, 5)] {
        let mut changed = fields.clone();
        changed.swap(a, b);
        variants.push(rsa(&sequence(&changed)));
    }
    if let Some(other) = other {
        let other_fields = rsa_fields(other);
        assert_eq!(
            bit_length(parse(&fields[1]).unwrap()[0].value),
            bit_length(parse(&other_fields[1]).unwrap()[0].value),
            "RSA substitution must preserve modulus size"
        );
        let mut changed = fields;
        changed[8] = other_fields[8].clone();
        variants.push(rsa(&sequence(&changed)));
    }
    variants
}
pub fn rsa_must(pkcs8: &[u8]) -> bool {
    let fields = rsa_fields(pkcs8);
    let n = parse(&fields[1]).unwrap()[0].value;
    let e = parse(&fields[2]).unwrap()[0].value;
    let p = parse(&fields[4]).unwrap()[0].value;
    let q = parse(&fields[5]).unwrap()[0].value;
    matches!(bit_length(n), 2048 | 3072 | 4096) && unsigned(e) == [1, 0, 1] && bit_length(p) == bit_length(q)
}

/// Checks that the re-encoding code reproduces every published dual-form key encoding byte for byte.
/// It needs no provider, and a failed control panics naming its source.
pub fn encoding_controls() {
    for file in RSA_SIGN_FILES
        .into_iter()
        .chain(RSA_DECRYPT_FILES.map(|(file, _)| file))
    {
        rsa_control(file);
    }
    ed25519_control();
    ec_control();
}

fn rsa_control(file: &str) {
    for group in vectors::wycheproof(file).test_groups {
        let expected = vectors::field(&group, "privateKeyPkcs8");
        let inner = children(&expected)[2].value.to_vec();
        assert_eq!(rsa(&inner), expected, "{file}");
        let fields = rsa_fields(&expected);
        assert_eq!(rsa(&sequence(&fields)), expected);
        assert_eq!(rebuild(&expected), expected);
        let raw = &group["privateKey"];
        let names = [
            "modulus",
            "publicExponent",
            "privateExponent",
            "prime1",
            "prime2",
            "exponent1",
            "exponent2",
            "coefficient",
        ];
        if raw["prime1"].is_string() {
            let mut encoded = vec![integer(&[0])];
            encoded.extend(names.map(|name| integer(&vectors::field(raw, name))));
            assert_eq!(rsa(&sequence(&encoded)), expected, "{file}: components");
        } else {
            let pem = vectors::pem(vectors::string(&group, "privateKeyPem"), "RSA PRIVATE KEY");
            assert_eq!(pem.len(), 1);
            assert_eq!(rsa(&pem[0]), expected);
            for (name, index) in [("modulus", 1), ("publicExponent", 2), ("privateExponent", 3)] {
                assert_eq!(integer(&vectors::field(raw, name)), fields[index]);
            }
        }
    }
}

fn ed25519_control() {
    let text = vectors::read("rfc/rfc8410.txt");
    let section = &text[text.rfind("10.3.  Examples").unwrap()..];
    let keys = vectors::ed8410();
    assert_eq!(keys.len(), 2);
    let seed = vectors::hex_lines(vectors::between(
        section,
        "Note that the value of the private key is:",
        "An example",
    ));
    assert_eq!(ed(&seed, None), keys[0]);
    let parts = children(&keys[1]);
    let public = &parts.iter().find(|p| p.tag == 0x81).unwrap().value[1..];
    let generated = ed(&seed, Some(public));
    let mut fields = children(&generated)
        .iter()
        .map(|p| p.encoded.to_vec())
        .collect::<Vec<_>>();
    fields.insert(3, parts.iter().find(|p| p.tag == 0xa0).unwrap().encoded.to_vec());
    assert_eq!(sequence(&fields), keys[1]);
    for key in keys {
        assert_eq!(rebuild(&key), key);
    }
}

fn ec_control() {
    for ((curve, _, _, _, name), (scalar, x, y, published)) in CURVES.into_iter().zip(vectors::ec9500()) {
        let parts = children(&published);
        let public = point(&x, &y, width(curve));
        assert_eq!(parts[1].value, scalar);
        let parameters = parts.iter().any(|p| p.tag == 0xa0).then_some(curve);
        assert_eq!(ec_inner(curve, &scalar, Some(&public), parameters), published);
        assert_eq!(rebuild(&published), published);
        let g = &vectors::wycheproof(&ecdsa_file(curve, name)).test_groups[0];
        let spki = vectors::field(g, "publicKeyDer");
        assert_eq!(algorithm(curve), children(&spki)[0].encoded);
    }
}
