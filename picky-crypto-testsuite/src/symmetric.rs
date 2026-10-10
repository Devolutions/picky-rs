use picky_crypto::*;

use crate::algorithms::*;
use crate::harness::{CheckedResult, Checks, Expect};
use crate::{Options, select, vectors as v};

pub fn hash(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for (index, a) in HASHES.into_iter().enumerate() {
        let entry = match helpers::hash(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::Hash(a), result);
                continue;
            }
        };
        let stem = match a {
            HashAlgorithm::Sha1 => Some("nist/shs/SHA1"),
            HashAlgorithm::Sha224 => Some("nist/shs/SHA224"),
            HashAlgorithm::Sha256 => Some("nist/shs/SHA256"),
            HashAlgorithm::Sha384 => Some("nist/shs/SHA384"),
            HashAlgorithm::Sha512 => Some("nist/shs/SHA512"),
            HashAlgorithm::Sha3_384 => Some("nist/sha3/SHA3_384"),
            HashAlgorithm::Sha3_512 => Some("nist/sha3/SHA3_512"),
            _ => None,
        };
        let cases = if index < 2 {
            v::md(if index == 0 { 1320 } else { 1321 })
                .into_iter()
                .enumerate()
                .map(|(i, (m, d))| {
                    (
                        format!("{a:?}/rfc{}/A.5/{i}", if index == 0 { 1320 } else { 1321 }),
                        m,
                        d,
                    )
                })
                .collect::<Vec<_>>()
        } else {
            let file = format!("{}ShortMsg.rsp", stem.expect("NIST hash file stem"));
            v::response(&file)
                .into_iter()
                .map(|r| {
                    let mut msg = r.bytes("Msg");
                    assert_eq!(r.number("Len") % 8, 0);
                    msg.truncate(r.number("Len") / 8);
                    (format!("{a:?}/{}", r.id(&file)), msg, r.bytes("MD"))
                })
                .collect()
        };
        for (id, msg, digest) in cases {
            if let Some(out) = c.call(&id, Expect::Success, || helpers::digest(p, a, &msg)) {
                c.bytes(&id, &out, &digest);
            }
            for zero_updates in [false, true] {
                if !msg.is_empty() && zero_updates {
                    continue;
                }
                if let Some(out) = c.call(&format!("{id}/streaming/{zero_updates}"), Expect::Success, || {
                    let mut ctx = entry.start()?;
                    if !zero_updates {
                        ctx.update(&[])?;
                        for chunk in msg.chunks(7) {
                            ctx.update(chunk)?;
                            ctx.update(&[])?;
                        }
                    }
                    ctx.finish()
                }) {
                    c.bytes(&id, &out, &digest);
                    c.check(&id, out.len() == a.output_len(), "output_len mismatch");
                }
            }
        }
        if let Some(stem) = stem {
            let file = format!("{stem}Monte.rsp");
            let records = v::response(&file);
            let mut seed = select::monte_seed(&file, &records);
            for r in records {
                let id = format!("{a:?}/{}", r.id(&file));
                let next = c.call(&id, Expect::Success, || {
                    if matches!(a, HashAlgorithm::Sha3_384 | HashAlgorithm::Sha3_512) {
                        let mut out = seed.clone();
                        for _ in 0..1000 {
                            out = helpers::digest(p, a, &out).checked()?.into_inner().to_vec();
                        }
                        Ok(OutputBytes::new(Zeroizing::new(out)))
                    } else {
                        let mut digests = [seed.clone(), seed.clone(), seed.clone()];
                        for _ in 0..1000 {
                            let next = helpers::digest(p, a, &digests.concat()).checked()?;
                            digests.rotate_left(1);
                            digests[2] = next.into_inner().to_vec();
                        }
                        Ok(OutputBytes::new(Zeroizing::new(digests[2].clone())))
                    }
                });
                if let Some(out) = next {
                    c.bytes(&id, &out, &r.bytes("MD"));
                }
                seed = r.bytes("MD");
            }
        }
    }
    c.finish();
}

pub fn mac(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for (index, (a, sha)) in MACS.into_iter().zip(SHAS).enumerate() {
        let e = match helpers::mac(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::Mac(a), result);
                continue;
            }
        };
        let Some(protections) = c.metadata(&format!("{a:?}/supports"), || {
            [e.supports(Protection::Apply), e.supports(Protection::Process)]
        }) else {
            continue;
        };
        for (protection, supported) in [Protection::Apply, Protection::Process].into_iter().zip(protections) {
            c.direction(p, Algorithm::Mac(a), protection, supported);
        }
        let file = format!("hmac_{sha}_test.json");
        for group in v::wycheproof(&file).test_groups {
            for t in v::tests(&group) {
                let id = v::id(a, &file, t);
                let (key, msg, tag) = (v::field(t, "key"), v::field(t, "msg"), v::field(t, "tag"));
                let valid = v::string(t, "result") != "invalid";
                let len = v::number(&group, "tagSize") / 8;
                mac_case(
                    &mut c,
                    p,
                    e,
                    a,
                    protections,
                    HASHES[index + 2].output_len(),
                    &id,
                    &key,
                    &msg,
                    &tag,
                    len,
                    valid,
                );
            }
        }
        if a != MacAlgorithm::HmacSha1 {
            for r in v::hmac_rfc() {
                let id = format!("{a:?}/{}", r.id("rfc/rfc4231.txt"));
                let tag = r.bytes(&format!("HMAC-SHA-{}", sha.trim_start_matches("sha")));
                mac_case(
                    &mut c,
                    p,
                    e,
                    a,
                    protections,
                    HASHES[index + 2].output_len(),
                    &id,
                    &r.bytes("Key"),
                    &r.bytes("Data"),
                    &tag,
                    tag.len(),
                    true,
                );
            }
        }
    }
    c.finish();
}

#[allow(clippy::too_many_arguments)]
fn mac_case(
    c: &mut Checks,
    p: &CryptoProvider,
    e: &dyn Mac,
    a: MacAlgorithm,
    protections: [bool; 2],
    full_len: usize,
    id: &str,
    key: &[u8],
    msg: &[u8],
    tag: &[u8],
    len: usize,
    valid: bool,
) {
    let mut generated = None;
    if protections[0] {
        if let Some(tagged) = c.call(id, Expect::Success, || helpers::compute_mac(p, a, key, msg)) {
            let bytes = tagged.into_inner();
            c.check(id, bytes.len() == full_len, "generation must return the full tag");
            if valid {
                c.check(
                    id,
                    bytes.get(..len) == Some(tag),
                    "generated tag disagrees with published prefix",
                );
            }
            generated = Some(bytes);
        }
    } else {
        c.call(id, Expect::Error(Error::Unsupported(Algorithm::Mac(a))), || {
            e.start(key, Protection::Apply)
        });
    }
    if protections[1] {
        let verifier = c.call(id, Expect::Success, || {
            let mut context = MacVerification::start(e, key)?;
            context.update(&[])?;
            for chunk in msg.chunks(7) {
                context.update(chunk)?;
            }
            context.finish()
        });
        if let Some(verifier) = verifier {
            c.debug(id, &verifier, tag);
            c.check(
                id,
                verifier.verify(tag, len) == valid,
                "streaming verifier disagrees with vector label",
            );
            let correct = generated
                .as_deref()
                .map(Vec::as_slice)
                .or_else(|| (valid && tag.len() == full_len).then_some(tag));
            if let Some(correct) = correct {
                c.debug(id, &verifier, correct);
                c.check(
                    id,
                    verifier.verify(correct, correct.len()),
                    "MacTag bytes do not verify",
                );
                for length in [0, correct.len() + 1, 8, 12, correct.len()] {
                    let prefix = &correct[..length.min(correct.len())];
                    c.check(
                        id,
                        verifier.verify(prefix, length) == (length > 0 && length <= correct.len()),
                        "prefix or length check",
                    );
                    if length > 0 && length <= correct.len() {
                        let wrong = vec![0; length];
                        if wrong != prefix {
                            c.check(id, !verifier.verify(&wrong, length), "wrong prefix verified");
                        }
                        c.check(
                            id,
                            !verifier.verify(&prefix[..length - 1], length),
                            "mismatched expected length verified",
                        );
                    }
                }
            }
        }
        if let Some(verified) = c.call(id, Expect::Success, || helpers::verify_mac(p, a, key, msg, tag, len)) {
            c.check(id, verified == valid, "one-shot verifier disagrees with vector label");
        }
    } else {
        c.call(id, Expect::Error(Error::Unsupported(Algorithm::Mac(a))), || {
            e.start(key, Protection::Process)
        });
    }
}

fn maximum(hlen: usize) -> Option<usize> {
    usize::try_from(u32::MAX).ok()?.checked_mul(hlen)?.checked_add(1)
}

pub fn password_kdf(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for (index, (a, sha)) in PASSWORD_KDFS.into_iter().zip(SHAS).enumerate() {
        let e = match helpers::password_kdf(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::PasswordKdf(a), result);
                continue;
            }
        };
        let file = format!("pbkdf2_hmac{sha}_test.json");
        for group in v::wycheproof(&file).test_groups {
            for t in v::tests(&group) {
                let id = v::id(a, &file, t);
                let iterations = v::number(t, "iterationCount");
                if iterations > 10_000_000 && !extended() {
                    continue;
                }
                let expected = v::field(t, "dk");
                let outside = (iterations > 10_000_000 || v::number(t, "dkLen") > 1024)
                    .then_some((Algorithm::PasswordKdf(a), false));
                if let Some(out) = c.outcome(&id, Expect::Success, outside, || {
                    e.derive(
                        &v::field(t, "password"),
                        &v::field(t, "salt"),
                        iterations as u32,
                        v::number(t, "dkLen"),
                    )
                }) {
                    c.bytes(&id, &out, &expected);
                }
            }
        }
        for (iterations, length) in [(0, 1), (1, 0)]
            .into_iter()
            .chain(maximum(HASHES[index + 2].output_len()).map(|n| (1, n)))
        {
            c.call(
                &format!("{a:?}/bounds/{iterations}/{length}"),
                Expect::Error(Error::InvalidInput),
                || e.derive(&[], &[], iterations, length),
            );
        }
        if a == PasswordKdfAlgorithm::Pbkdf2HmacSha1 {
            for r in v::pbkdf2_rfc() {
                let iterations = r.number("c") as u32;
                if iterations > 10_000_000 && !extended() {
                    continue;
                }
                let id = format!("{a:?}/{}/iterations={iterations}", r.id("rfc/rfc6070.txt"));
                if let Some(out) = c.outcome(
                    &id,
                    Expect::Success,
                    (iterations > 10_000_000).then_some((Algorithm::PasswordKdf(a), false)),
                    || e.derive(&r.bytes("P"), &r.bytes("S"), iterations, r.number("dkLen")),
                ) {
                    c.bytes(&id, &out, &r.bytes("DK"));
                }
            }
        }
    }
    c.finish();
}

pub fn kdf(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let counter = "nist/kbkdf/KDFCTR_gen.rsp";
    let ecc = "nist/kas/KASValidityTest_ECCEphemeralUnified_KDFConcat_NOKC_init.fax";
    for (index, a) in KDFS.into_iter().enumerate() {
        let e = match helpers::kdf(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::Kdf(a), result);
                continue;
            }
        };
        let digest_length = [20, 32, 48, 64][index % 4];
        let records = if index >= 4 {
            v::response(counter)
        } else {
            v::response(ecc)
        };
        for r in records {
            let (secret, info, expected, id) = if index >= 4 {
                let name = ["HMAC_SHA1", "HMAC_SHA256", "HMAC_SHA384", "HMAC_SHA512"][index - 4];
                if !r.group.contains(&format!("PRF={name};")) {
                    continue;
                }
                (r.bytes("KI"), r.bytes("FixedInputData"), r.bytes("KO"), r.id(counter))
            } else {
                if index == 0 || !r.group.contains(["SHA1", "SHA256", "SHA384", "SHA512"][index]) {
                    continue;
                }
                // Changed Z, OtherInfo, or DKM no longer forms a known-answer pair.
                let reason = r.text("Result");
                if reason.contains("Z changed")
                    || reason.contains("OI changed")
                    || reason.contains("DKM changed")
                    || reason.contains("fails PKV")
                {
                    continue;
                }
                (r.bytes("Z"), r.bytes("OI"), r.bytes("DKM"), r.id(ecc))
            };
            if let Some(out) = c.outcome(
                &format!("{a:?}/{id}"),
                Expect::Success,
                (expected.len() > 64).then_some((Algorithm::Kdf(a), false)),
                || e.derive(&secret, &info, expected.len()),
            ) {
                c.bytes(&id, &out, &expected);
            }
        }
        for (secret, length) in [(vec![], 1), (vec![1], 0)]
            .into_iter()
            .chain(maximum(digest_length).map(|n| (vec![1], n)))
        {
            c.call(
                &format!("{a:?}/bounds/{length}"),
                Expect::Error(Error::InvalidInput),
                || e.derive(&secret, &[], length),
            );
        }
    }
    c.finish();
}

pub type CipherVector = (String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, bool);
pub fn cipher_records(a: CipherAlgorithm) -> Vec<CipherVector> {
    let mut result = Vec::new();
    if a == CipherAlgorithm::Rc2Cbc {
        for r in v::rc2() {
            result.push((
                r.id("rfc/rfc2268.txt"),
                r.bytes("Key"),
                vec![0; 8],
                r.bytes("Plaintext"),
                r.bytes("Ciphertext"),
                false,
            ));
        }
    } else {
        let files = if a == CipherAlgorithm::TdesEde3Cbc {
            vec!["nist/tdes/TCBCMMT3.rsp".to_owned(), "nist/tdes/TCBCMMT2.rsp".to_owned()]
        } else {
            let bits = match a {
                CipherAlgorithm::Aes128Cbc => 128,
                CipherAlgorithm::Aes192Cbc => 192,
                _ => 256,
            };
            ["GFSbox", "KeySbox", "MMT"]
                .map(|name| format!("nist/aes/CBC{name}{bits}.rsp"))
                .to_vec()
        };
        for file in files {
            for r in v::response(&file) {
                let key = if a == CipherAlgorithm::TdesEde3Cbc {
                    [r.bytes("KEY1"), r.bytes("KEY2"), r.bytes("KEY3")].concat()
                } else {
                    r.bytes("KEY")
                };
                result.push((
                    r.id(&file),
                    key,
                    r.bytes("IV"),
                    r.bytes("PLAINTEXT"),
                    r.bytes("CIPHERTEXT"),
                    file.contains("MMT2"),
                ));
            }
        }
    }
    select::cbc_control(a, &result);
    result
}

pub fn cipher(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    for a in CIPHERS {
        let e = match helpers::cipher(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::Cipher(a), result);
                continue;
            }
        };
        let Some(protections) = c.metadata(&format!("{a:?}/supports"), || {
            [e.supports(Protection::Apply), e.supports(Protection::Process)]
        }) else {
            continue;
        };
        let records = cipher_records(a);
        for (protection, supported) in [Protection::Apply, Protection::Process].into_iter().zip(protections) {
            c.direction(p, Algorithm::Cipher(a), protection, supported);
        }
        for (id, key, iv, plaintext, ciphertext, variable) in &records {
            for protection in [Protection::Apply, Protection::Process] {
                let supported = protections[usize::from(protection == Protection::Process)];
                let expected = if !supported {
                    Expect::Error(Error::Unsupported(Algorithm::Cipher(a)))
                } else if *variable {
                    Expect::Either(Error::InvalidKey)
                } else {
                    Expect::Success
                };
                let result = c.call(&format!("{a:?}/{id}/{protection:?}"), expected, || {
                    if protection == Protection::Apply {
                        e.encrypt(key, iv, plaintext)
                    } else {
                        e.decrypt(key, iv, ciphertext)
                    }
                });
                if let Some(result) = result {
                    c.bytes(
                        id,
                        &result,
                        if protection == Protection::Apply {
                            ciphertext
                        } else {
                            plaintext
                        },
                    );
                }
            }
        }
        let (id, key, iv, data, _, _) = select::cbc_control(a, &records);
        for protection in [Protection::Apply, Protection::Process] {
            if !protections[usize::from(protection == Protection::Process)] {
                continue;
            }
            for (k, i, d, error) in [
                (&[][..], &iv[..], &data[..], Error::InvalidKey),
                (&key[..], &[][..], &data[..], Error::InvalidInput),
                (&key[..], &iv[..], &[0][..], Error::InvalidInput),
                (&[][..], &[][..], &[0][..], Error::InvalidKey),
            ] {
                c.call(
                    &format!("{a:?}/{id}/length/{protection:?}"),
                    Expect::Error(error),
                    || {
                        if protection == Protection::Apply {
                            e.encrypt(k, i, d)
                        } else {
                            e.decrypt(k, i, d)
                        }
                    },
                );
            }
            if matches!(
                a,
                CipherAlgorithm::Aes128Cbc | CipherAlgorithm::Aes192Cbc | CipherAlgorithm::Aes256Cbc
            ) {
                let empty = &select::ed25519_empty().message;
                if let Some(out) = c.call(&format!("{a:?}/{id}/empty"), Expect::Success, || {
                    if protection == Protection::Apply {
                        e.encrypt(key, iv, empty)
                    } else {
                        e.decrypt(key, iv, empty)
                    }
                }) {
                    c.check(id, out.is_empty(), "empty CBC result must be empty");
                }
            }
            for length in [0, 1, 15, 16, 17, 23, 24, 25, 31, 32, 33, 129] {
                let valid = match a {
                    CipherAlgorithm::Aes128Cbc => length == 16,
                    CipherAlgorithm::Aes192Cbc => length == 24,
                    CipherAlgorithm::Aes256Cbc => length == 32,
                    CipherAlgorithm::TdesEde3Cbc => length == 24,
                    CipherAlgorithm::Rc2Cbc => (1..=128).contains(&length),
                    _ => false,
                };
                if valid {
                    continue;
                }
                c.call(
                    &format!("{a:?}/{protection:?}/key length={length}"),
                    Expect::Error(Error::InvalidKey),
                    || {
                        if protection == Protection::Apply {
                            e.encrypt(&vec![0; length], iv, data)
                        } else {
                            e.decrypt(&vec![0; length], iv, data)
                        }
                    },
                );
            }
        }
        if a == CipherAlgorithm::TdesEde3Cbc {
            weak_tdes_checks(&mut c, e, select::cbc_control(a, &records), protections);
        }
    }
    c.finish();
}

fn weak_tdes_checks(c: &mut Checks, e: &dyn Cipher, record: &CipherVector, protections: [bool; 2]) {
    let (base_id, base, iv, plain, encrypted, _) = record;
    let weak = weak_tdes_key(base);
    let id = format!("{base_id}/KEY1 from rfc/rfc2268.txt/section 5/all-one key");
    if protections[0] {
        if let Some(out) = c.call(&id, Expect::Either(Error::InvalidKey), || e.encrypt(&weak, iv, plain)) {
            c.check(&id, out.len() == plain.len(), "weak-key CBC length");
            if protections[1] {
                if let Some(restored) = c.call(&id, Expect::Either(Error::InvalidKey), || e.decrypt(&weak, iv, &out)) {
                    c.bytes(&id, &restored, plain);
                }
            }
        }
    }
    if protections[1] {
        if let Some(out) = c.call(&id, Expect::Either(Error::InvalidKey), || {
            e.decrypt(&weak, iv, encrypted)
        }) {
            c.check(&id, out.len() == encrypted.len(), "weak-key CBC length");
            if protections[0] {
                if let Some(restored) = c.call(&id, Expect::Either(Error::InvalidKey), || e.encrypt(&weak, iv, &out)) {
                    c.bytes(&id, &restored, encrypted);
                }
            }
        }
    }
}

pub fn weak_tdes_key(base: &[u8]) -> Vec<u8> {
    let fields = base.chunks_exact(8).map(<[u8]>::to_vec).collect::<Vec<_>>();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields.concat(), base, "TCBCMMT3 split/reassemble control");
    let published = select::weak_des_component();
    [published, fields[1].clone(), fields[2].clone()].concat()
}

pub fn stream_cipher(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let a = StreamCipherAlgorithm::Rc4;
    match helpers::stream_cipher(p, a) {
        Err(error) => c.absent::<()>(p, Algorithm::StreamCipher(a), Err(error)),
        Ok(e) => {
            for (key, offset, expected) in v::rc4() {
                let id = format!("{a:?}/rfc/rfc6229.txt/keyBits={}/offset={offset}", key.len() * 8);
                if let Some(out) = c.call(&id, Expect::Success, || {
                    let mut ctx = e.start(&key)?;
                    ctx.apply(&vec![0; offset]).checked()?;
                    ctx.apply(&vec![0; expected.len()])
                }) {
                    c.bytes(&id, &out, &expected);
                }
            }
            for length in [0, 257] {
                c.call(
                    &format!("{a:?}/key length={length}"),
                    Expect::Error(Error::InvalidKey),
                    || e.start(&vec![0; length]),
                );
            }
        }
    }
    c.finish();
}

pub fn aead(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let file = "aes_gcm_test.json";
    let vectors = v::wycheproof(file);
    for (index, a) in AEADS.into_iter().enumerate() {
        let e = match helpers::aead(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::Aead(a), result);
                continue;
            }
        };
        let Some(protections) = c.metadata(&format!("{a:?}/supports"), || {
            [e.supports(Protection::Apply), e.supports(Protection::Process)]
        }) else {
            continue;
        };
        for (protection, supported) in [Protection::Apply, Protection::Process].into_iter().zip(protections) {
            c.direction(p, Algorithm::Aead(a), protection, supported);
        }
        for g in &vectors.test_groups {
            if v::number(g, "keySize") != [128, 192, 256][index] {
                continue;
            }
            for t in v::tests(g) {
                let id = v::id(a, file, t);
                let (key, nonce, aad, plaintext) = (
                    v::field(t, "key"),
                    v::field(t, "iv"),
                    v::field(t, "aad"),
                    v::field(t, "msg"),
                );
                let encrypted = [v::field(t, "ct"), v::field(t, "tag")].concat();
                for protection in [Protection::Apply, Protection::Process] {
                    let supported = protections[usize::from(protection == Protection::Process)];
                    if !supported {
                        c.call(
                            &format!("{id}/{protection:?}"),
                            Expect::Error(Error::Unsupported(Algorithm::Aead(a))),
                            || {
                                if protection == Protection::Apply {
                                    e.seal(&key, &aad, &plaintext).checked().map(|s| s.nonce)
                                } else {
                                    e.open(&key, &nonce, &aad, &encrypted)
                                }
                            },
                        );
                        continue;
                    }
                    if protection == Protection::Process {
                        let expected = if nonce.len() != 12 || encrypted.len() < 16 {
                            Expect::Error(Error::InvalidInput)
                        } else if v::number(g, "tagSize") != 128 || v::string(t, "result") == "invalid" {
                            Expect::Error(Error::VerificationFailed)
                        } else {
                            Expect::Success
                        };
                        if let Some(out) = c.call(&id, expected, || e.open(&key, &nonce, &aad, &encrypted)) {
                            c.bytes(&id, &out, &plaintext);
                        }
                    } else if let Some(sealed) = c.call(&id, Expect::Success, || e.seal(&key, &aad, &plaintext)) {
                        c.check(&id, sealed.nonce.len() == 12, "seal nonce length");
                        c.check(
                            &id,
                            sealed.ciphertext_and_tag.len() == plaintext.len() + 16,
                            "seal ciphertext length",
                        );
                        c.debug(&id, &sealed, &sealed.nonce);
                        c.debug(&id, &sealed, &sealed.ciphertext_and_tag);
                        if protections[1] {
                            if let Some(out) = c.call(&id, Expect::Success, || {
                                e.open(&key, &sealed.nonce, &aad, &sealed.ciphertext_and_tag)
                            }) {
                                c.bytes(&id, &out, &plaintext);
                            }
                        }
                    }
                }
            }
        }
        let valid = select::gcm_control(&vectors, [128, 192, 256][index]);
        let key = v::field(valid, "key");
        let nonce = v::field(valid, "iv");
        let data = [v::field(valid, "ct"), v::field(valid, "tag")].concat();
        if protections[0] {
            c.call(
                &format!("{a:?}/seal invalid key"),
                Expect::Error(Error::InvalidKey),
                || e.seal(&[], &[], &[]),
            );
        }
        if protections[1] {
            for (k, n, d, error) in [
                (&[][..], &nonce[..], &data[..], Error::InvalidKey),
                (&key[..], &[][..], &data[..], Error::InvalidInput),
                (&key[..], &nonce[..], &[0][..], Error::InvalidInput),
            ] {
                c.call(&format!("{a:?}/open lengths"), Expect::Error(error), || {
                    e.open(k, n, &[], d)
                });
            }
        }
    }
    c.finish();
}

pub fn key_wrap(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let file = "aes_wrap_test.json";
    let vectors = v::wycheproof(file);
    for (index, a) in WRAPS.into_iter().enumerate() {
        let e = match helpers::key_wrap(p, a) {
            Ok(e) => e,
            result => {
                c.absent(p, Algorithm::KeyWrap(a), result);
                continue;
            }
        };
        let Some(protections) = c.metadata(&format!("{a:?}/supports"), || {
            [e.supports(Protection::Apply), e.supports(Protection::Process)]
        }) else {
            continue;
        };
        for (protection, supported) in [Protection::Apply, Protection::Process].into_iter().zip(protections) {
            c.direction(p, Algorithm::KeyWrap(a), protection, supported);
        }
        for g in &vectors.test_groups {
            if v::number(g, "keySize") != [128, 192, 256][index] {
                continue;
            }
            for t in v::tests(g) {
                let id = v::id(a, file, t);
                let (key, plaintext, ciphertext) = (v::field(t, "key"), v::field(t, "msg"), v::field(t, "ct"));
                for protection in [Protection::Apply, Protection::Process] {
                    let supported = protections[usize::from(protection == Protection::Process)];
                    let len = if protection == Protection::Apply {
                        plaintext.len()
                    } else {
                        ciphertext.len()
                    };
                    let lengths = if protection == Protection::Apply {
                        [16, 24, 32]
                    } else {
                        [24, 32, 40]
                    };
                    let expected = if !supported {
                        Expect::Error(Error::Unsupported(Algorithm::KeyWrap(a)))
                    } else if key.len() != [16, 24, 32][index] {
                        Expect::Error(Error::InvalidKey)
                    } else if !lengths.contains(&len) {
                        Expect::Error(Error::InvalidInput)
                    } else if protection == Protection::Process && v::string(t, "result") == "invalid" {
                        Expect::Error(Error::VerificationFailed)
                    } else {
                        Expect::Success
                    };
                    if let Some(out) = c.call(&format!("{id}/{protection:?}"), expected, || {
                        if protection == Protection::Apply {
                            e.wrap(&key, &plaintext)
                        } else {
                            e.unwrap(&key, &ciphertext)
                        }
                    }) {
                        if protection == Protection::Process || v::string(t, "result") == "valid" {
                            c.bytes(
                                &id,
                                &out,
                                if protection == Protection::Apply {
                                    &ciphertext
                                } else {
                                    &plaintext
                                },
                            );
                        } else {
                            c.debug(&id, &out, &out);
                        }
                    }
                }
            }
        }
        let base = select::wrap_control(&vectors, [128, 192, 256][index]);
        let key = v::field(base, "key");
        for protection in [Protection::Apply, Protection::Process] {
            if !protections[usize::from(protection == Protection::Process)] {
                continue;
            }
            for length in [0, 1, 8, 15, 17, 23, 25, 31, 33, 39, 41] {
                if (protection == Protection::Apply && [16, 24, 32].contains(&length))
                    || (protection == Protection::Process && [24, 32, 40].contains(&length))
                {
                    continue;
                }
                c.call(
                    &format!("{a:?}/{protection:?}/length={length}"),
                    Expect::Error(Error::InvalidInput),
                    || {
                        if protection == Protection::Apply {
                            e.wrap(&key, &vec![0; length])
                        } else {
                            e.unwrap(&key, &vec![0; length])
                        }
                    },
                );
            }
            c.call(
                &format!("{a:?}/{protection:?}/bad KEK"),
                Expect::Error(Error::InvalidKey),
                || {
                    if protection == Protection::Apply {
                        e.wrap(&[], &v::field(base, "msg"))
                    } else {
                        e.unwrap(&[], &v::field(base, "ct"))
                    }
                },
            );
        }
    }
    c.finish();
}

pub fn random(p: &CryptoProvider, _: Options) {
    let mut c = Checks::default();
    let a = Algorithm::Random(RandomAlgorithm::SecureRandom);
    match helpers::secure_random(p, RandomAlgorithm::SecureRandom) {
        Err(error) => {
            c.absent::<()>(p, a, Err(error));
            c.call(
                "random_x25519_private_key/absent",
                Expect::Error(Error::Unsupported(a)),
                || helpers::random_x25519_private_key(p),
            );
        }
        Ok(e) => {
            for length in [0, 1, 32, 65_536] {
                c.call(&format!("random/fill/{length}"), Expect::Success, || {
                    e.fill(&mut vec![0; length])
                });
            }
            if let Some((a, b)) = c.call("random/independent fills", Expect::Success, || {
                let mut a = [0; 32];
                let mut b = [0; 32];
                e.fill(&mut a)?;
                e.fill(&mut b)?;
                Ok((a, b))
            }) {
                c.check("random", a != b, "two random fills were identical");
            }
            if let Some(key) = c.call("random/clamping", Expect::Success, || {
                helpers::random_x25519_private_key(p)
            }) {
                c.check(
                    "random/clamping",
                    key[0] & 7 == 0 && key[31] & 128 == 0 && key[31] & 64 != 0,
                    "scalar not clamped",
                );
                c.debug("random/clamping", &key, &key[..]);
            }
        }
    }
    c.finish();
}
