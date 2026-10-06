#![cfg(feature = "ssh")]

#[cfg(feature = "fips")]
use base64::Engine as _;
#[cfg(feature = "fips")]
use picky::hash::HashAlgorithm;
use picky::signature::SignatureAlgorithm;
use picky::signature::SignatureError;
use picky::ssh::certificate::{
    SshCertKeyType, SshCertType, SshCertificate, SshCertificateBuilder, SshCertificateGenerationError,
    SshSignatureFormat,
};
use picky::ssh::private_key::{SshBasePrivateKey, SshPrivateKey};
#[cfg(feature = "fips")]
use std::ops::Range;
use std::str::FromStr as _;

#[test]
fn ssh_critical_options_use_nested_strings_and_empty_flags() {
    use picky::ssh::certificate::{SshCriticalOption, SshCriticalOptionType};
    use picky::ssh::decode::SshComplexTypeDecode as _;
    use picky::ssh::encode::SshComplexTypeEncode as _;

    for (option_type, data, expected) in [
        (
            SshCriticalOptionType::ForceCommand,
            "echo hello",
            &b"\0\0\0\x23\0\0\0\x0dforce-command\0\0\0\x0e\0\0\0\x0aecho hello"[..],
        ),
        (
            SshCriticalOptionType::SourceAddress,
            "192.0.2.0/24",
            &b"\0\0\0\x26\0\0\0\x0esource-address\0\0\0\x10\0\0\0\x0c192.0.2.0/24"[..],
        ),
        (
            SshCriticalOptionType::VerifyRequired,
            "",
            &b"\0\0\0\x17\0\0\0\x0fverify-required\0\0\0\0"[..],
        ),
    ] {
        let option = SshCriticalOption {
            option_type,
            data: data.to_owned(),
        };
        let options = vec![option];
        let mut encoded = Vec::new();
        options.encode(&mut encoded).unwrap();
        assert_eq!(encoded, expected);
        let mut reader = expected;
        assert_eq!(Vec::<SshCriticalOption>::decode(&mut reader).unwrap(), options);
        assert!(reader.is_empty());
    }
}

#[test]
fn ssh_critical_options_reject_unwrapped_data_and_nonempty_flags() {
    use picky::ssh::certificate::{SshCriticalOption, SshCriticalOptionType};
    use picky::ssh::decode::SshComplexTypeDecode as _;
    use picky::ssh::encode::SshComplexTypeEncode as _;
    for encoded in [
        &b"\0\0\0\x1f\0\0\0\x0dforce-command\0\0\0\x0aecho hello"[..],
        &b"\0\0\0\x18\0\0\0\x0fverify-required\0\0\0\x01x"[..],
        &b"\0\0\0\x24\0\0\0\x0dforce-command\0\0\0\x0f\0\0\0\x0aecho hellox"[..],
    ] {
        assert!(Vec::<SshCriticalOption>::decode(encoded).is_err());
    }
    assert!(
        vec![SshCriticalOption {
            option_type: SshCriticalOptionType::VerifyRequired,
            data: "unexpected".to_owned(),
        }]
        .encode(Vec::new())
        .is_err()
    );
}

#[cfg(feature = "fips")]
#[test]
fn fips_public_keys_reject_legacy_fingerprints() {
    let key = picky::ssh::SshPublicKey::from_str(picky_test_data::SSH_PUBLIC_KEY_RSA).unwrap();
    assert!(key.fingerprint_md5().is_err());
    assert!(key.fingerprint_sha1().is_err());
    assert_ne!(key.fingerprint_sha256().unwrap(), [0; 32]);
}

#[derive(Clone, Copy, Debug)]
enum ExpectedPrivateKeyKind {
    Rsa,
    Ec,
    Ed25519,
}

fn assert_unencrypted_private_key_roundtrip(pem: &str, expected_kind: ExpectedPrivateKeyKind) {
    let key = SshPrivateKey::from_pem_str(pem, None).expect("approved unencrypted key should parse");

    assert_eq!(key.cipher_name, "none");
    assert_eq!(key.kdf.name, "none");
    assert!(key.passphrase.is_none());
    match (expected_kind, key.base_key()) {
        (ExpectedPrivateKeyKind::Rsa, SshBasePrivateKey::Rsa(_))
        | (ExpectedPrivateKeyKind::Ec, SshBasePrivateKey::Ec(_))
        | (ExpectedPrivateKeyKind::Ed25519, SshBasePrivateKey::Ed(_)) => {}
        (expected, actual) => panic!("expected {expected:?}, got {actual:?}"),
    }

    assert_eq!(key.to_string().unwrap(), pem);
}

fn assert_certificate_roundtrip(
    encoded: &str,
    expected_key_type: SshCertKeyType,
    expected_signature_format: SshSignatureFormat,
) {
    let certificate = SshCertificate::from_str(encoded).expect("approved certificate should parse");

    assert_eq!(certificate.cert_key_type, expected_key_type);
    assert_eq!(certificate.signature.format, expected_signature_format);
    assert_eq!(certificate.key_id, "abcd");
    assert_eq!(certificate.valid_principals, ["server.example.com"]);
    assert_eq!(certificate.to_string().unwrap(), encoded);
}

fn build_host_certificate(
    private_key_pem: &str,
    key_type: SshCertKeyType,
    signature_algorithm: Option<SignatureAlgorithm>,
) -> Result<SshCertificate, SshCertificateGenerationError> {
    let private_key = SshPrivateKey::from_pem_str(private_key_pem, None).unwrap();
    let builder = SshCertificateBuilder::init();
    builder
        .cert_key_type(key_type)
        .key(private_key.public_key().clone())
        .serial(42)
        .cert_type(SshCertType::Host)
        .key_id("fips-policy".to_owned())
        .principals(vec!["host.example.com".to_owned()])
        .valid_after(1)
        .valid_before(2)
        .signature_key(private_key)
        .comment("fips-policy".to_owned());
    if let Some(algorithm) = signature_algorithm {
        builder.signature_algo(algorithm);
    }
    builder.build()
}

fn assert_fips_certificate_sign_and_verify(private_key: &str, key_type: SshCertKeyType) {
    let certificate = build_host_certificate(private_key, key_type, None).unwrap();
    certificate.verify_signature().unwrap();

    let encoded = certificate.to_string().unwrap();
    let parsed = SshCertificate::from_str(&encoded).unwrap();
    parsed.verify_signature().unwrap();

    let mut tampered = parsed;
    tampered.key_id.push_str("-tampered");
    assert!(matches!(
        tampered.verify_signature(),
        Err(picky::ssh::certificate::SshCertificateError::SignatureError(
            SignatureError::BadSignature
        ))
    ));
}

#[cfg(feature = "fips")]
fn decode_pem_payload(pem: &str) -> Vec<u8> {
    let encoded: String = pem.lines().filter(|line| !line.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(encoded).unwrap()
}

#[cfg(feature = "fips")]
fn encode_pem_payload(payload: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload);
    let mut pem = String::from("-----BEGIN OPENSSH PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(70) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END OPENSSH PRIVATE KEY-----\n");
    pem
}

#[cfg(feature = "fips")]
fn replace_all_bytes(payload: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let mut replacements = 0;
    for offset in 0..=payload.len() - from.len() {
        if &payload[offset..offset + from.len()] == from {
            payload[offset..offset + to.len()].copy_from_slice(to);
            replacements += 1;
        }
    }
    assert!(replacements >= 2, "public and private key type should both be replaced");
}

#[cfg(feature = "fips")]
fn replace_length_prefixed_strings(payload: &mut Vec<u8>, from: &[u8], to: &[u8]) -> usize {
    let mut pattern = (from.len() as u32).to_be_bytes().to_vec();
    pattern.extend_from_slice(from);
    let mut replacement = (to.len() as u32).to_be_bytes().to_vec();
    replacement.extend_from_slice(to);
    let mut offset = 0;
    let mut replacements = 0;
    while offset + pattern.len() <= payload.len() {
        if payload[offset..offset + pattern.len()] == pattern {
            payload.splice(offset..offset + pattern.len(), replacement.iter().copied());
            replacements += 1;
            offset += replacement.len();
        } else {
            offset += 1;
        }
    }
    replacements
}

#[cfg(feature = "fips")]
fn mutate_certificate_blob(encoded: &str, mutation: impl FnOnce(&mut Vec<u8>)) -> String {
    let mut fields = encoded.trim_end().splitn(3, ' ');
    let key_type = fields.next().unwrap();
    let mut blob = base64::engine::general_purpose::STANDARD
        .decode(fields.next().unwrap())
        .unwrap();
    let comment = fields.next().unwrap_or_default();
    mutation(&mut blob);
    format!(
        "{key_type} {} {comment}\n",
        base64::engine::general_purpose::STANDARD.encode(blob)
    )
}

#[cfg(feature = "fips")]
#[derive(Clone)]
struct WireField {
    length_offset: usize,
    data: Range<usize>,
}

#[cfg(feature = "fips")]
fn read_wire_field(data: &[u8], position: &mut usize) -> WireField {
    let length_offset = *position;
    let len = u32::from_be_bytes(data[*position..*position + 4].try_into().unwrap()) as usize;
    *position += 4;
    let start = *position;
    *position += len;
    assert!(*position <= data.len());
    WireField {
        length_offset,
        data: start..*position,
    }
}

#[cfg(feature = "fips")]
fn replace_wire_field(data: &mut Vec<u8>, field: WireField, replacement: &[u8]) {
    let mut encoded = (replacement.len() as u32).to_be_bytes().to_vec();
    encoded.extend_from_slice(replacement);
    data.splice(field.length_offset..field.data.end, encoded);
}

#[cfg(feature = "fips")]
fn mutate_private_blob(pem: &str, mutation: impl FnOnce(&mut Vec<u8>)) -> String {
    let mut payload = decode_pem_payload(pem);
    let mut position = b"openssh-key-v1\0".len();
    read_wire_field(&payload, &mut position);
    read_wire_field(&payload, &mut position);
    read_wire_field(&payload, &mut position);
    position += 4;
    read_wire_field(&payload, &mut position);
    let private_field = read_wire_field(&payload, &mut position);
    assert_eq!(position, payload.len());
    let mut private = payload[private_field.data.clone()].to_vec();
    mutation(&mut private);
    replace_wire_field(&mut payload, private_field, &private);
    encode_pem_payload(&payload)
}

#[cfg(feature = "fips")]
fn certificate_subject_fields(blob: &[u8]) -> (SshCertKeyType, Vec<WireField>) {
    let mut position = 0;
    let key_type_field = read_wire_field(blob, &mut position);
    let key_type = std::str::from_utf8(&blob[key_type_field.data]).unwrap();
    let key_type = match key_type {
        "rsa-sha2-256-cert-v01@openssh.com" => SshCertKeyType::RsaSha2_256V01,
        "ecdsa-sha2-nistp256-cert-v01@openssh.com" => SshCertKeyType::EcdsaSha2Nistp256V01,
        "ssh-ed25519-cert-v01@openssh.com" => SshCertKeyType::SshEd25519V01,
        other => panic!("unexpected certificate type {other}"),
    };
    read_wire_field(blob, &mut position);
    let fields = match key_type {
        SshCertKeyType::RsaSha2_256V01 => vec![
            read_wire_field(blob, &mut position),
            read_wire_field(blob, &mut position),
        ],
        SshCertKeyType::EcdsaSha2Nistp256V01 => vec![
            read_wire_field(blob, &mut position),
            read_wire_field(blob, &mut position),
        ],
        SshCertKeyType::SshEd25519V01 => vec![read_wire_field(blob, &mut position)],
        _ => unreachable!(),
    };
    (key_type, fields)
}

#[test]
fn fips_openssh_private_key_rsa_parse_serialize() {
    assert_unencrypted_private_key_roundtrip(picky_test_data::SSH_PRIVATE_KEY_RSA, ExpectedPrivateKeyKind::Rsa);
}

#[test]
fn fips_openssh_private_key_ecdsa_p256_parse_serialize() {
    assert_unencrypted_private_key_roundtrip(picky_test_data::SSH_PRIVATE_KEY_EC_P256, ExpectedPrivateKeyKind::Ec);
}

#[test]
fn fips_openssh_private_key_ecdsa_p384_parse_serialize() {
    assert_unencrypted_private_key_roundtrip(picky_test_data::SSH_PRIVATE_KEY_EC_P384, ExpectedPrivateKeyKind::Ec);
}

#[test]
fn fips_openssh_private_key_ecdsa_p521_parse_serialize() {
    assert_unencrypted_private_key_roundtrip(picky_test_data::SSH_PRIVATE_KEY_EC_P521, ExpectedPrivateKeyKind::Ec);
}

#[test]
fn fips_openssh_private_key_ed25519_parse_serialize() {
    assert_unencrypted_private_key_roundtrip(
        picky_test_data::SSH_PRIVATE_KEY_ED25519,
        ExpectedPrivateKeyKind::Ed25519,
    );
}

#[cfg(feature = "fips")]
#[test]
fn fips_unencrypted_private_key_ignores_supplied_passphrase() {
    let key = SshPrivateKey::from_pem_str(
        picky_test_data::SSH_PRIVATE_KEY_RSA,
        Some("irrelevant passphrase".to_owned()),
    )
    .unwrap();

    assert_eq!(key.cipher_name, "none");
    assert_eq!(key.kdf.name, "none");
    assert!(key.passphrase.is_none());
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_mismatched_rsa_ec_and_ed25519_private_components() {
    let rsa = mutate_private_blob(picky_test_data::SSH_PRIVATE_KEY_RSA, |private| {
        let mut position = 8;
        read_wire_field(private, &mut position);
        read_wire_field(private, &mut position);
        read_wire_field(private, &mut position);
        let private_exponent = read_wire_field(private, &mut position);
        private[private_exponent.data.end - 1] ^= 1;
    });
    let ec = mutate_private_blob(picky_test_data::SSH_PRIVATE_KEY_EC_P256, |private| {
        let mut position = 8;
        read_wire_field(private, &mut position);
        read_wire_field(private, &mut position);
        read_wire_field(private, &mut position);
        let scalar = read_wire_field(private, &mut position);
        private[scalar.data.end - 1] ^= 1;
    });
    let ed = mutate_private_blob(picky_test_data::SSH_PRIVATE_KEY_ED25519, |private| {
        let mut position = 8;
        read_wire_field(private, &mut position);
        read_wire_field(private, &mut position);
        let combined = read_wire_field(private, &mut position);
        private[combined.data.start] ^= 1;
    });

    for malformed in [rsa, ec, ed] {
        assert!(SshPrivateKey::from_pem_str(&malformed, None).is_err());
    }
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_oversized_rsa_before_crt_arithmetic() {
    let oversized = mutate_private_blob(picky_test_data::SSH_PRIVATE_KEY_RSA, |private| {
        let mut position = 8;
        read_wire_field(private, &mut position);
        let modulus = read_wire_field(private, &mut position);
        replace_wire_field(private, modulus, &vec![0x7f; 1025]);
    });

    assert!(SshPrivateKey::from_pem_str(&oversized, None).is_err());
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_invalid_private_key_padding_and_none_kdf_options() {
    let bad_padding = mutate_private_blob(picky_test_data::SSH_PRIVATE_KEY_RSA, |private| {
        *private.last_mut().unwrap() = 0;
    });
    let misaligned = mutate_private_blob(picky_test_data::SSH_PRIVATE_KEY_RSA, |private| {
        private.pop().unwrap();
    });
    let mut payload = decode_pem_payload(picky_test_data::SSH_PRIVATE_KEY_RSA);
    let mut position = b"openssh-key-v1\0".len();
    read_wire_field(&payload, &mut position);
    read_wire_field(&payload, &mut position);
    let options = read_wire_field(&payload, &mut position);
    replace_wire_field(&mut payload, options, &[0; 8]);
    let none_options = encode_pem_payload(&payload);

    for malformed in [bad_padding, misaligned, none_options] {
        assert!(SshPrivateKey::from_pem_str(&malformed, None).is_err());
    }
}

#[test]
fn fips_ssh_certificate_rsa_parse_serialize() {
    let certificate = build_host_certificate(
        picky_test_data::SSH_PRIVATE_KEY_RSA,
        SshCertKeyType::RsaSha2_256V01,
        None,
    )
    .unwrap();
    let encoded = certificate.to_string().unwrap();
    let reparsed = SshCertificate::from_str(&encoded).unwrap();

    assert_eq!(reparsed.cert_key_type, SshCertKeyType::RsaSha2_256V01);
    assert_eq!(reparsed.signature.format, SshSignatureFormat::RsaSha256);
    assert_eq!(reparsed.serial, 42);
    assert_eq!(reparsed.cert_type, SshCertType::Host);
    assert_eq!(reparsed.key_id, "fips-policy");
    assert_eq!(reparsed.valid_principals, ["host.example.com"]);
    assert_eq!(reparsed.valid_after.secs(), 1);
    assert_eq!(reparsed.valid_before.secs(), 2);
    assert_eq!(reparsed.comment, "fips-policy");
}

#[test]
fn fips_ssh_certificate_ecdsa_p256_parse_serialize() {
    assert_certificate_roundtrip(
        picky_test_data::SSH_CERT_EC_P256,
        SshCertKeyType::EcdsaSha2Nistp256V01,
        SshSignatureFormat::EcdsaSha2Nistp256,
    );
}

#[test]
fn fips_ssh_certificate_ecdsa_p384_parse_serialize() {
    assert_certificate_roundtrip(
        picky_test_data::SSH_CERT_EC_P384,
        SshCertKeyType::EcdsaSha2Nistp384V01,
        SshSignatureFormat::EcdsaSha2Nistp256,
    );
}

#[test]
fn fips_ssh_certificate_ecdsa_p521_parse_serialize() {
    let certificate = build_host_certificate(
        picky_test_data::SSH_PRIVATE_KEY_EC_P521,
        SshCertKeyType::EcdsaSha2Nistp521V01,
        None,
    )
    .unwrap();
    let encoded = certificate.to_string().unwrap();
    let reparsed = SshCertificate::from_str(&encoded).unwrap();

    assert_eq!(reparsed.cert_key_type, SshCertKeyType::EcdsaSha2Nistp521V01);
    assert_eq!(reparsed.signature.format, SshSignatureFormat::EcdsaSha2Nistp521);
    assert_eq!(reparsed.serial, 42);
    assert_eq!(reparsed.cert_type, SshCertType::Host);
    assert_eq!(reparsed.key_id, "fips-policy");
    assert_eq!(reparsed.valid_principals, ["host.example.com"]);
    assert_eq!(reparsed.valid_after.secs(), 1);
    assert_eq!(reparsed.valid_before.secs(), 2);
    assert_eq!(reparsed.comment, "fips-policy");
}

#[test]
fn fips_ssh_certificate_ed25519_parse_serialize() {
    assert_certificate_roundtrip(
        picky_test_data::SSH_CERT_ED25519,
        SshCertKeyType::SshEd25519V01,
        SshSignatureFormat::SshEd25519,
    );
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_invalid_rsa_ec_and_ed25519_certificate_subject_keys() {
    let rsa = build_host_certificate(
        picky_test_data::SSH_PRIVATE_KEY_RSA,
        SshCertKeyType::RsaSha2_256V01,
        None,
    )
    .unwrap()
    .to_string()
    .unwrap();
    let invalid_rsa = mutate_certificate_blob(&rsa, |blob| {
        let (_, fields) = certificate_subject_fields(blob);
        let modulus = &fields[1];
        blob[modulus.data.end - 1] &= 0xfe;
    });
    let invalid_ec = mutate_certificate_blob(picky_test_data::SSH_CERT_EC_P256, |blob| {
        let (_, fields) = certificate_subject_fields(blob);
        let point = &fields[1];
        blob[point.data.start] = 0x05;
    });
    let invalid_ed = mutate_certificate_blob(picky_test_data::SSH_CERT_ED25519, |blob| {
        let (_, fields) = certificate_subject_fields(blob);
        let public = fields[0].clone();
        let shortened = blob[public.data.start..public.data.end - 1].to_vec();
        replace_wire_field(blob, public, &shortened);
    });

    for malformed in [invalid_rsa, invalid_ec, invalid_ed] {
        assert!(SshCertificate::from_str(&malformed).is_err());
    }
}

#[test]
fn fips_ssh_certificate_rsa_sha2_sign_verify_and_reject_tampering() {
    assert_fips_certificate_sign_and_verify(picky_test_data::SSH_PRIVATE_KEY_RSA, SshCertKeyType::RsaSha2_256V01);
}

#[cfg(feature = "fips")]
#[test]
fn fips_ssh_certificate_rsa_sha512_sign_verify() {
    let certificate = build_host_certificate(
        picky_test_data::SSH_PRIVATE_KEY_RSA,
        SshCertKeyType::RsaSha2_512v01,
        Some(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_512)),
    )
    .unwrap();

    assert_eq!(certificate.signature.format, SshSignatureFormat::RsaSha512);
    certificate.verify_signature().unwrap();
    SshCertificate::from_str(&certificate.to_string().unwrap())
        .unwrap()
        .verify_signature()
        .unwrap();
}

#[cfg(feature = "fips")]
#[test]
fn fips_standard_rsa_certificates_allow_sha2_but_not_sha1_signatures() {
    for hash in [HashAlgorithm::SHA2_256, HashAlgorithm::SHA2_512] {
        let certificate = build_host_certificate(
            picky_test_data::SSH_PRIVATE_KEY_RSA,
            SshCertKeyType::SshRsaV01,
            Some(SignatureAlgorithm::RsaPkcs1v15(hash)),
        )
        .unwrap();
        let encoded = certificate.to_string().unwrap();
        assert!(encoded.starts_with("ssh-rsa-cert-v01@openssh.com "));
        let parsed = SshCertificate::from_str(&encoded).unwrap();
        assert_eq!(parsed.cert_key_type, SshCertKeyType::SshRsaV01);
        parsed.verify_signature().unwrap();
    }
    assert!(matches!(
        build_host_certificate(
            picky_test_data::SSH_PRIVATE_KEY_RSA,
            SshCertKeyType::SshRsaV01,
            Some(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1)),
        ),
        Err(SshCertificateGenerationError::SignatureError(
            SignatureError::AlgorithmDisabledByPolicy { .. }
        ))
    ));
}

#[cfg(all(feature = "fips", feature = "jwe-crypto"))]
#[test]
fn fips_ssh_short_ec_scalars_support_ecdh_jwe() {
    use picky::jose::jwe::{Jwe, JweAlg, JweEnc};
    use picky::key::PrivateKey;
    use picky_asn1_x509::oids;

    for (curve_oid, agreement, width) in [
        (oids::secp256r1(), &aws_lc_rs::agreement::ECDH_P256, 32),
        (oids::secp384r1(), &aws_lc_rs::agreement::ECDH_P384, 48),
        (oids::secp521r1(), &aws_lc_rs::agreement::ECDH_P521, 66),
    ] {
        let mut scalar = vec![0; width];
        scalar[width - 1] = 1;
        let provider_key = aws_lc_rs::agreement::PrivateKey::from_private_key(agreement, &scalar).unwrap();
        let public = provider_key.compute_public_key().unwrap();
        let key = PrivateKey::from_ec_encoded_components(curve_oid, &[1], Some(public.as_ref()));
        let ssh = SshPrivateKey::try_from(key).unwrap().to_string().unwrap();
        let imported = SshPrivateKey::from_pem_str(&ssh, None).unwrap();
        for algorithm in [JweAlg::EcdhEs, JweAlg::EcdhEsAesKeyWrap128, JweAlg::EcdhEsAesKeyWrap256] {
            let payload = b"SSH scalar-width regression".to_vec();
            let encoded = Jwe::new(algorithm, JweEnc::Aes256Gcm, payload.clone())
                .encode(imported.public_key().inner_key())
                .unwrap();
            let decoded = Jwe::decode(&encoded, imported.inner_key().unwrap()).unwrap();
            assert_eq!(decoded.payload, payload);
        }
    }
}

#[test]
#[ignore = "requires OpenSSH ssh-keygen on PATH"]
fn fips_standard_rsa_certificate_options_interoperate_with_openssh() {
    use picky::ssh::certificate::{SshCriticalOption, SshCriticalOptionType};
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let key = SshPrivateKey::from_pem_str(picky_test_data::SSH_PRIVATE_KEY_RSA, None).unwrap();
    let certificate = SshCertificateBuilder::init()
        .cert_key_type(SshCertKeyType::SshRsaV01)
        .key(key.public_key().clone())
        .cert_type(SshCertType::Client)
        .key_id("OpenSSH interoperability".to_owned())
        .valid_after(1)
        .valid_before(u64::MAX)
        .critical_options(vec![
            SshCriticalOption {
                option_type: SshCriticalOptionType::ForceCommand,
                data: "echo hello".to_owned(),
            },
            SshCriticalOption {
                option_type: SshCriticalOptionType::SourceAddress,
                data: "192.0.2.0/24".to_owned(),
            },
            SshCriticalOption {
                option_type: SshCriticalOptionType::VerifyRequired,
                data: String::new(),
            },
        ])
        .signature_key(key)
        .build()
        .unwrap();
    let encoded = certificate.to_string().unwrap();
    let parsed = SshCertificate::from_str(&encoded).unwrap();
    assert_eq!(parsed.critical_options, certificate.critical_options);
    parsed.verify_signature().unwrap();
    let mut child = Command::new("ssh-keygen")
        .args(["-L", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(encoded.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let output = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "rsa-sha2-256",
        "force-command echo hello",
        "source-address 192.0.2.0/24",
        "verify-required",
    ] {
        assert!(output.contains(expected), "{output}");
    }
}

#[test]
fn fips_ssh_certificate_ecdsa_p256_sign_verify_and_reject_tampering() {
    assert_fips_certificate_sign_and_verify(
        picky_test_data::SSH_PRIVATE_KEY_EC_P256,
        SshCertKeyType::EcdsaSha2Nistp256V01,
    );
}

#[test]
fn fips_ssh_certificate_ecdsa_p384_sign_verify_and_reject_tampering() {
    assert_fips_certificate_sign_and_verify(
        picky_test_data::SSH_PRIVATE_KEY_EC_P384,
        SshCertKeyType::EcdsaSha2Nistp384V01,
    );
}

#[test]
fn fips_ssh_certificate_ecdsa_p521_sign_verify_and_reject_tampering() {
    assert_fips_certificate_sign_and_verify(
        picky_test_data::SSH_PRIVATE_KEY_EC_P521,
        SshCertKeyType::EcdsaSha2Nistp521V01,
    );
}

#[test]
fn fips_ssh_certificate_ed25519_sign_verify_and_reject_tampering() {
    assert_fips_certificate_sign_and_verify(picky_test_data::SSH_PRIVATE_KEY_ED25519, SshCertKeyType::SshEd25519V01);
}

#[test]
fn ssh_ecdsa_certificate_signatures_use_r_and_s_mpints() {
    use picky::ssh::certificate::SshSignatureBlob;
    use picky::ssh::decode::SshReadExt as _;

    for (pem, key_type, width) in [
        (
            picky_test_data::SSH_PRIVATE_KEY_EC_P256,
            SshCertKeyType::EcdsaSha2Nistp256V01,
            32,
        ),
        (
            picky_test_data::SSH_PRIVATE_KEY_EC_P384,
            SshCertKeyType::EcdsaSha2Nistp384V01,
            48,
        ),
        (
            picky_test_data::SSH_PRIVATE_KEY_EC_P521,
            SshCertKeyType::EcdsaSha2Nistp521V01,
            66,
        ),
    ] {
        let certificate = build_host_certificate(pem, key_type, None).unwrap();
        let encoded = certificate.to_string().unwrap();
        let parsed = SshCertificate::from_str(&encoded).unwrap();
        assert_eq!(parsed.signature, certificate.signature);
        let SshSignatureBlob::Standard(signature) = &parsed.signature.blob else {
            panic!("ECDSA certificates must have standard signatures");
        };
        let mut signature = signature.as_slice();
        for component in [
            signature.read_ssh_mpint_bytes().unwrap(),
            signature.read_ssh_mpint_bytes().unwrap(),
        ] {
            assert!(!component.is_empty() && component.len() <= width);
        }
        assert!(signature.is_empty(), "ECDSA signatures contain exactly two SSH mpints");
        parsed.verify_signature().unwrap();
    }
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_bcrypt_aes_encrypted_private_keys() {
    for encrypted in [
        picky_test_data::SSH_PRIVATE_KEY_EC_P256_ENCRYPTED,
        picky_test_data::SSH_PRIVATE_KEY_ED25519_ENCRYPTED,
    ] {
        assert!(SshPrivateKey::from_pem_str(encrypted, Some("test".to_owned())).is_err());
    }
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_sha1_ssh_rsa_certificate_signature() {
    let result = build_host_certificate(
        picky_test_data::SSH_PRIVATE_KEY_RSA,
        SshCertKeyType::RsaSha2_256V01,
        Some(SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA1)),
    );

    assert!(matches!(
        result,
        Err(SshCertificateGenerationError::SignatureError(
            SignatureError::AlgorithmDisabledByPolicy { ref algorithm }
        )) if algorithm == "RsaPkcs1v15(SHA1)"
    ));
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_rsa_pss_certificate_signature() {
    let result = build_host_certificate(
        picky_test_data::SSH_PRIVATE_KEY_RSA,
        SshCertKeyType::RsaSha2_256V01,
        Some(SignatureAlgorithm::RsaPss(HashAlgorithm::SHA2_256)),
    );

    assert!(matches!(
        result,
        Err(SshCertificateGenerationError::IncorrectSignatureAlgorithm(ref message))
            if message == "RSA-PSS signatures are not defined for OpenSSH certificates"
    ));
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_dss_private_key_and_certificate_type() {
    let mut dss_key = decode_pem_payload(picky_test_data::SSH_PRIVATE_KEY_ED25519);
    assert_eq!(
        replace_length_prefixed_strings(&mut dss_key, b"ssh-ed25519", b"ssh-dss"),
        2
    );
    let dss_key = encode_pem_payload(&dss_key);
    let certificate_result =
        build_host_certificate(picky_test_data::SSH_PRIVATE_KEY_RSA, SshCertKeyType::SshDssV01, None);

    assert!(SshPrivateKey::from_pem_str(&dss_key, None).is_err());
    assert!(matches!(
        certificate_result,
        Err(SshCertificateGenerationError::UnsupportedCertificateKeyType(ref key_type))
            if key_type == "ssh-dss-cert-v01@openssh.com"
    ));
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_security_key_private_key_types() {
    assert!(SshPrivateKey::from_pem_str(picky_test_data::SSH_PRIVATE_KEY_SK_ECDSA, None).is_err());
    assert!(SshPrivateKey::from_pem_str(picky_test_data::SSH_PRIVATE_KEY_SK_ED25519, None).is_err());
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_security_key_certificate_types() {
    assert!(SshCertificate::from_str(picky_test_data::SSH_CERT_SK_ECDSA_SIG_EC).is_err());
    assert!(SshCertificate::from_str(picky_test_data::SSH_CERT_SK_ED25519_SIG_EC).is_err());
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_malformed_private_key_and_certificate_data() {
    let mut malformed_key = decode_pem_payload(picky_test_data::SSH_PRIVATE_KEY_RSA);
    malformed_key.truncate(24);
    let malformed_key = encode_pem_payload(&malformed_key);
    let malformed_certificate = mutate_certificate_blob(picky_test_data::SSH_CERT_EC_P256, |blob| {
        blob.truncate(12);
    });

    assert!(SshPrivateKey::from_pem_str(&malformed_key, None).is_err());
    assert!(SshCertificate::from_str(&malformed_certificate).is_err());
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_trailing_private_key_and_certificate_data() {
    let mut trailing_key = decode_pem_payload(picky_test_data::SSH_PRIVATE_KEY_RSA);
    trailing_key.extend_from_slice(b"trailing");
    let trailing_key = encode_pem_payload(&trailing_key);
    let trailing_certificate = mutate_certificate_blob(picky_test_data::SSH_CERT_EC_P256, |blob| {
        blob.extend_from_slice(b"trailing");
    });

    assert!(SshPrivateKey::from_pem_str(&trailing_key, None).is_err());
    assert!(SshCertificate::from_str(&trailing_certificate).is_err());
}

#[cfg(feature = "fips")]
#[test]
fn fips_rejects_unsupported_private_key_and_certificate_algorithms() {
    let mut unsupported_key = decode_pem_payload(picky_test_data::SSH_PRIVATE_KEY_ED25519);
    replace_all_bytes(&mut unsupported_key, b"ssh-ed25519", b"ssh-unknown");
    let unsupported_key = encode_pem_payload(&unsupported_key);
    let unsupported_certificate = mutate_certificate_blob(picky_test_data::SSH_CERT_EC_P256, |blob| {
        assert_eq!(
            replace_length_prefixed_strings(
                blob,
                b"ecdsa-sha2-nistp256-cert-v01@openssh.com",
                b"unsupported-cert-v01@openssh.com",
            ),
            1
        );
    })
    .replacen(
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "unsupported-cert-v01@openssh.com",
        1,
    );

    assert!(SshPrivateKey::from_pem_str(&unsupported_key, None).is_err());
    assert!(SshCertificate::from_str(&unsupported_certificate).is_err());
}

#[cfg(feature = "rustcrypto")]
#[test]
fn rustcrypto_preserves_encrypted_bcrypt_aes_private_key_behavior() {
    for encrypted in [
        picky_test_data::SSH_PRIVATE_KEY_EC_P256_ENCRYPTED,
        picky_test_data::SSH_PRIVATE_KEY_ED25519_ENCRYPTED,
    ] {
        let key = SshPrivateKey::from_pem_str(encrypted, Some("test".to_owned())).unwrap();

        assert_eq!(key.kdf.name, "bcrypt");
        assert_eq!(key.cipher_name, "aes256-ctr");
        assert_eq!(key.to_string().unwrap(), encrypted);
    }
}

#[cfg(feature = "rustcrypto")]
#[test]
fn rustcrypto_preserves_security_key_private_key_and_certificate_api() {
    let ecdsa_key = SshPrivateKey::from_pem_str(picky_test_data::SSH_PRIVATE_KEY_SK_ECDSA, None).unwrap();
    let ed25519_key = SshPrivateKey::from_pem_str(picky_test_data::SSH_PRIVATE_KEY_SK_ED25519, None).unwrap();
    let ecdsa_certificate = SshCertificate::from_str(picky_test_data::SSH_CERT_SK_ECDSA_SIG_EC).unwrap();
    let ed25519_certificate = SshCertificate::from_str(picky_test_data::SSH_CERT_SK_ED25519_SIG_EC).unwrap();

    assert!(matches!(
        ecdsa_key.base_key(),
        SshBasePrivateKey::SkEcdsaSha2NistP256 { .. }
    ));
    assert!(matches!(ed25519_key.base_key(), SshBasePrivateKey::SkEd25519 { .. }));
    assert_eq!(ecdsa_certificate.cert_key_type, SshCertKeyType::SkSshSha2Nistp256V01);
    assert_eq!(ed25519_certificate.cert_key_type, SshCertKeyType::SkSshEd25519V01);
    assert_eq!(
        ecdsa_certificate.to_string().unwrap(),
        picky_test_data::SSH_CERT_SK_ECDSA_SIG_EC
    );
    assert_eq!(
        ed25519_certificate.to_string().unwrap(),
        picky_test_data::SSH_CERT_SK_ED25519_SIG_EC
    );
}
