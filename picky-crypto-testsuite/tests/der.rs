use picky_crypto::KeyType;
use picky_crypto_testsuite::algorithms::CURVES;
use picky_crypto_testsuite::der::*;
use picky_crypto_testsuite::vectors;

fn generated_examples() -> Vec<(KeyType, usize, Vec<u8>)> {
    let mut examples = Vec::new();
    for (bits, file) in [2048, 3072, 4096]
        .into_iter()
        .zip(picky_crypto_testsuite::asymmetric::RSA_SIGN_FILES)
    {
        let corpus = vectors::wycheproof(file);
        let group = corpus
            .test_groups
            .iter()
            .find(|g| rsa_must(&vectors::field(g, "privateKeyPkcs8")))
            .unwrap();
        examples.push((KeyType::Rsa, bits, vectors::field(group, "privateKeyPkcs8")));
    }
    for ((kind, _, _, size, _), (scalar, x, y, _)) in CURVES.into_iter().zip(vectors::ec9500()) {
        examples.push((
            kind,
            if size == 66 { 521 } else { size * 8 },
            ec(kind, &scalar, Some(&point(&x, &y, size)), Some(kind)),
        ));
    }
    let t = &vectors::ed25519()[0];
    examples.push((KeyType::Ed25519, 255, ed(&t.seed, Some(&t.public))));
    examples
}

#[test]
fn generated_key_structure_controls() {
    for (kind, bits, encoded) in generated_examples() {
        assert_eq!(
            generated_public(kind, bits, &encoded).unwrap(),
            encoded_public(kind, &encoded).expect("key has no PKCS#8 public field")
        );
        let fields = children(&encoded);
        assert_eq!(
            sequence(&fields.iter().map(|f| f.encoded.to_vec()).collect::<Vec<_>>()),
            encoded
        );
        for index in 0..fields.len() {
            let mut malformed = fields.iter().map(|f| f.encoded.to_vec()).collect::<Vec<_>>();
            malformed[index] = tlv(5, fields[index].value);
            assert!(
                generated_public(kind, bits, &sequence(&malformed)).is_err(),
                "{kind:?}/outer tag {index}"
            );
        }
        for (left, right) in [(0, 1), (1, 2)] {
            let mut reordered = fields.iter().map(|f| f.encoded.to_vec()).collect::<Vec<_>>();
            reordered.swap(left, right);
            assert!(
                generated_public(kind, bits, &sequence(&reordered)).is_err(),
                "{kind:?}/outer field order"
            );
        }
        let inner = if kind == KeyType::Ed25519 {
            parse(fields[2].value).unwrap()
        } else {
            children(fields[2].value)
        };
        for index in 0..inner.len() {
            let mut malformed = inner.iter().map(|f| f.encoded.to_vec()).collect::<Vec<_>>();
            malformed[index] = tlv(5, inner[index].value);
            let payload = if kind == KeyType::Ed25519 {
                malformed.concat()
            } else {
                sequence(&malformed)
            };
            let mut outer = fields.iter().map(|f| f.encoded.to_vec()).collect::<Vec<_>>();
            outer[2] = tlv(4, &payload);
            assert!(
                generated_public(kind, bits, &sequence(&outer)).is_err(),
                "{kind:?}/inner tag {index}"
            );
        }
        if matches!(kind, KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521) {
            let mut missing = inner.iter().map(|f| f.encoded.to_vec()).collect::<Vec<_>>();
            missing.pop();
            let mut outer = fields.iter().map(|f| f.encoded.to_vec()).collect::<Vec<_>>();
            outer[2] = tlv(4, &sequence(&missing));
            assert!(
                generated_public(kind, bits, &sequence(&outer)).is_err(),
                "{kind:?}/missing publicKey"
            );
            let mut wrong_bit = inner.iter().map(|f| f.encoded.to_vec()).collect::<Vec<_>>();
            let point = parse(inner.last().unwrap().value).unwrap()[0];
            *wrong_bit.last_mut().unwrap() = tlv(0xa1, &tlv(4, point.value));
            outer[2] = tlv(4, &sequence(&wrong_bit));
            assert!(
                generated_public(kind, bits, &sequence(&outer)).is_err(),
                "{kind:?}/publicKey tag"
            );
        }
        for length in [0, 1, encoded.len() - 1] {
            assert!(
                generated_public(kind, bits, &encoded[..length]).is_err(),
                "{kind:?}/truncated DER"
            );
        }
    }
}

#[test]
fn published_encodings_are_reproduced() {
    encoding_controls();
}

#[test]
fn derived_key_controls() {
    for file in picky_crypto_testsuite::asymmetric::RSA_SIGN_FILES
        .into_iter()
        .chain(picky_crypto_testsuite::asymmetric::RSA_DECRYPT_FILES.map(|(file, _)| file))
    {
        let vectors = vectors::wycheproof(file);
        let base = vectors::field(&vectors.test_groups[0], "privateKeyPkcs8");
        let other = vectors
            .test_groups
            .iter()
            .find(|g| {
                vectors::field(g, "privateKeyPkcs8") != base
                    && vectors::number(g, "keySize") == vectors::number(&vectors.test_groups[0], "keySize")
            })
            .map(|g| vectors::field(g, "privateKeyPkcs8"));
        let fields = rsa_fields(&base);
        for (i, changed) in inconsistent_rsa(&base, other.as_deref()).iter().enumerate() {
            let actual = rsa_fields(changed);
            match i {
                0 => {
                    assert_eq!(actual[6], fields[7]);
                    assert_eq!(actual[7], fields[6]);
                }
                1 => {
                    assert_eq!(actual[4], fields[5]);
                    assert_eq!(actual[5], fields[4]);
                    assert_eq!(actual[8], fields[8]);
                }
                2 => {
                    assert_eq!(actual[8], rsa_fields(other.as_ref().unwrap())[8]);
                }
                _ => unreachable!(),
            }
        }
    }
    for (kind, _, size, r) in picky_crypto_testsuite::asymmetric::ecc_cases()
        .into_iter()
        .filter(|(_, _, _, r)| r.text("Result").starts_with('P'))
    {
        let own = point(&r.bytes("QeIUTx"), &r.bytes("QeIUTy"), size);
        let peer = point(&r.bytes("QeCAVSx"), &r.bytes("QeCAVSy"), size);
        assert_ne!(own, peer, "public-key substitution must change the field");
        let base = ec(kind, &r.bytes("deIUT"), Some(&own), None);
        assert_eq!(rebuild(&base), base);
        for params in [
            None,
            Some(kind),
            Some(if kind == KeyType::EcP256 {
                KeyType::EcP384
            } else {
                KeyType::EcP256
            }),
        ] {
            let encoded = ec(kind, &r.bytes("deIUT"), Some(&own), params);
            let outer = children(&encoded);
            assert_eq!(outer[1].encoded, algorithm(kind));
            let inner = children(outer[2].value);
            assert_eq!(inner[1].value, padded(&r.bytes("deIUT"), size));
            let public = inner.iter().find(|f| f.tag == 0xa1).unwrap();
            assert_eq!(parse(public.value).unwrap()[0].value[1..], own);
            if let Some(params) = params {
                assert_eq!(
                    inner.iter().find(|f| f.tag == 0xa0).unwrap().value,
                    tlv(6, curve_oid(params))
                );
            }
        }
    }
    for t in vectors::ed25519() {
        for public in vectors::ed25519().iter().map(|t| &t.public) {
            let encoded = ed(&t.seed, Some(public));
            let fields = children(&encoded);
            assert_eq!(parse(fields[2].value).unwrap()[0].value, t.seed);
            assert_eq!(fields[3].value[1..], *public);
            assert_eq!(rebuild(&encoded), encoded);
        }
    }
    let corpus = vectors::wycheproof("ed25519_test.json");
    let test = picky_crypto_testsuite::select::ed25519_small_order_r(&corpus);
    let (group, _) = picky_crypto_testsuite::select::signature_control("ed25519_test.json", &corpus);
    let published = vectors::field(group, "publicKeyDer");
    let fields = children(&published);
    let public = vectors::field(&group["publicKey"], "pk");
    assert_eq!(
        sequence(&[fields[0].encoded.to_vec(), tlv(3, &[&[0][..], &public].concat())]),
        published
    );
    assert_eq!(vectors::field(test, "sig")[..32].len(), public.len());
}
