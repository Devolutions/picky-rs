use crate::{algorithms::*, asymmetric::ECC_FILE, vectors as v};

pub type Pair = (String, Vec<u8>, Vec<u8>);
pub type Triple = (String, Vec<u8>, Vec<u8>, Vec<u8>);
pub type Password = (String, Vec<u8>, Vec<u8>, u32);

pub fn messages() -> Vec<(String, Vec<u8>)> {
    v::md(1320)
        .into_iter()
        .enumerate()
        .map(|(i, (msg, _))| (format!("rfc/rfc1320.txt/A.5/{i}"), msg))
        .chain(
            v::ed25519()
                .iter()
                .enumerate()
                .map(|(i, t)| (format!("rfc/rfc8032.txt/7.1/{i}"), t.message.clone())),
        )
        .collect()
}

pub fn mac(index: usize) -> Vec<Triple> {
    let file = format!("hmac_{}_test.json", SHAS[index]);
    v::wycheproof(&file)
        .test_groups
        .into_iter()
        .flat_map(|g| v::tests(&g).to_vec())
        .filter(|t| v::string(t, "result") == "valid" && v::field(t, "key").len() <= 1024)
        .map(|t| {
            (
                v::id(MACS[index], &file, &t),
                v::field(&t, "key"),
                v::field(&t, "msg"),
                v::field(&t, "tag"),
            )
        })
        .collect()
}

pub fn empty_mac(index: usize) -> Pair {
    let inputs = mac(index);
    let source = inputs
        .iter()
        .find(|(_, _, msg, _)| msg.is_empty())
        .expect("published empty HMAC message");
    let message = inputs
        .iter()
        .find(|(_, _, msg, _)| !msg.is_empty())
        .expect("published nonempty HMAC message");
    (
        format!("{}/msg as key; message from {}", source.0, message.0),
        source.2.clone(),
        message.2.clone(),
    )
}

pub fn password(index: usize) -> Vec<Password> {
    let file = format!("pbkdf2_hmac{}_test.json", SHAS[index]);
    v::wycheproof(&file)
        .test_groups
        .into_iter()
        .flat_map(|g| v::tests(&g).to_vec())
        .filter(|t| {
            v::string(t, "result") == "valid"
                && v::number(t, "iterationCount") <= 10_000_000
                && v::field(t, "password").len() <= 1024
                && v::field(t, "salt").len() <= 1024
        })
        .map(|t| {
            (
                v::id(PASSWORD_KDFS[index], &file, &t),
                v::field(&t, "password"),
                v::field(&t, "salt"),
                v::number(&t, "iterationCount") as u32,
            )
        })
        .collect()
}

pub fn kdf(index: usize) -> Vec<Pair> {
    if (1..4).contains(&index) {
        v::response(ECC_FILE)
            .into_iter()
            .filter(|r| {
                r.group.contains(["SHA1", "SHA256", "SHA384", "SHA512"][index]) && r.text("Result").starts_with('P')
            })
            .map(|r| (r.id(ECC_FILE), r.bytes("Z"), r.bytes("OI")))
            .collect()
    } else {
        let file = "nist/kbkdf/KDFCTR_gen.rsp";
        let prf = ["HMAC_SHA1", "HMAC_SHA256", "HMAC_SHA384", "HMAC_SHA512"][index.saturating_sub(4)];
        v::response(file)
            .into_iter()
            .filter(|r| r.group.contains(&format!("PRF={prf};")))
            .map(|r| (r.id(file), r.bytes("KI"), r.bytes("FixedInputData")))
            .collect()
    }
}

pub fn aead(index: usize) -> Vec<Triple> {
    let file = "aes_gcm_test.json";
    v::wycheproof(file)
        .test_groups
        .into_iter()
        .filter(|g| {
            v::number(g, "keySize") == [128, 192, 256][index]
                && v::number(g, "ivSize") == 96
                && v::number(g, "tagSize") == 128
        })
        .flat_map(|g| v::tests(&g).to_vec())
        .filter(|t| v::string(t, "result") == "valid")
        .map(|t| {
            (
                v::id(AEADS[index], file, &t),
                v::field(&t, "key"),
                v::field(&t, "aad"),
                v::field(&t, "msg"),
            )
        })
        .collect()
}

pub fn wrap(index: usize) -> Vec<Pair> {
    let file = "aes_wrap_test.json";
    v::wycheproof(file)
        .test_groups
        .into_iter()
        .filter(|g| v::number(g, "keySize") == [128, 192, 256][index])
        .flat_map(|g| v::tests(&g).to_vec())
        .filter(|t| v::string(t, "result") == "valid" && [16, 24, 32].contains(&v::field(t, "msg").len()))
        .map(|t| (v::id(WRAPS[index], file, &t), v::field(&t, "key"), v::field(&t, "msg")))
        .collect()
}

pub fn rc4() -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let messages = messages();
    v::rc4()
        .into_iter()
        .filter(|(_, offset, _)| *offset == 0)
        .enumerate()
        .flat_map(|(i, (key, _, _))| {
            messages
                .iter()
                .map(move |(id, msg)| (format!("rfc/rfc6229.txt/key={i}/{id}"), key.clone(), msg.clone()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    #[case(4)]
    fn source_inputs(#[case] index: usize) {
        assert!(!mac(index).is_empty());
        assert!(!password(index).is_empty());
        let (id, key, data) = empty_mac(index);
        let source = mac(index);
        let original = source.iter().find(|(_, _, msg, _)| msg.is_empty()).unwrap();
        assert_eq!(key, original.2);
        assert!(key.is_empty());
        assert!(source.iter().any(|(_, _, msg, _)| msg == &data));
        assert!(id.contains("tcId="));
        if index < 3 {
            assert!(!aead(index).is_empty());
            assert!(!wrap(index).is_empty());
        }
    }

    #[test]
    fn kdf_and_stream_inputs() {
        for index in 0..8 {
            let inputs = kdf(index);
            assert!(!inputs.is_empty());
            for (_, secret, info) in inputs {
                assert!(!secret.is_empty());
                assert!(secret.len() <= 1024 && info.len() <= 1024);
            }
        }
        assert!(!rc4().is_empty());
    }
}
