use super::{EcCurve, EdAlgorithm, KeyError, PrivateKey};
use crate::hash::HashAlgorithm;
use crate::signature::SignatureAlgorithm;
use picky_asn1::wrapper::OctetStringAsn1Container;
use picky_asn1_x509::PrivateKeyValue;

#[test]
fn generates_approved_rsa_key() {
    let key = PrivateKey::generate_rsa(2048).unwrap();
    let public_key = key.to_public_key().unwrap();
    let algorithm = SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256);
    let signature = algorithm.sign(b"generated RSA", &key).unwrap();

    algorithm.verify(&public_key, b"generated RSA", &signature).unwrap();
}

#[test]
fn rejects_unsupported_rsa_generation_size() {
    let error = PrivateKey::generate_rsa(1024).unwrap_err();

    assert!(matches!(
        error,
        KeyError::AlgorithmDisabledByPolicy { ref algorithm }
            if algorithm.contains("2048, 3072, 4096, or 8192")
    ));
}

#[test]
fn generates_approved_ec_keys() {
    for (curve, hash) in [
        (EcCurve::NistP256, HashAlgorithm::SHA2_256),
        (EcCurve::NistP384, HashAlgorithm::SHA2_384),
        (EcCurve::NistP521, HashAlgorithm::SHA2_512),
    ] {
        let key = PrivateKey::generate_ec(curve).unwrap();
        let public_key = key.to_public_key().unwrap();
        let algorithm = SignatureAlgorithm::Ecdsa(hash);
        let signature = algorithm.sign(b"generated EC", &key).unwrap();

        algorithm.verify(&public_key, b"generated EC", &signature).unwrap();
    }
}

#[test]
fn derives_missing_ec_public_points_on_import() {
    for pem in [
        picky_test_data::EC_NIST256_PK_1,
        picky_test_data::EC_NIST384_PK_1,
        picky_test_data::EC_NIST521_PK_1,
    ] {
        let key = PrivateKey::from_pem_str(pem).unwrap();
        let expected_public_key = key.to_public_key().unwrap();
        let mut private_key_info = key.as_inner().clone();
        let PrivateKeyValue::EC(OctetStringAsn1Container(ec_private_key)) = &mut private_key_info.private_key else {
            panic!("test fixture is not an EC private key");
        };
        ec_private_key.public_key = Default::default();

        let encoded = picky_asn1_der::to_vec(&private_key_info).unwrap();
        let imported = PrivateKey::from_pkcs8(&encoded).unwrap();

        assert_eq!(imported.to_public_key().unwrap(), expected_public_key);
    }
}

#[test]
fn generates_approved_ed25519_key() {
    let key = PrivateKey::generate_ed(EdAlgorithm::Ed25519, true).unwrap();
    let public_key = key.to_public_key().unwrap();
    let signature = SignatureAlgorithm::Ed25519.sign(b"generated Ed25519", &key).unwrap();

    SignatureAlgorithm::Ed25519
        .verify(&public_key, b"generated Ed25519", &signature)
        .unwrap();
}

#[test]
fn rejects_x25519_generation() {
    let error = PrivateKey::generate_ed(EdAlgorithm::X25519, false).unwrap_err();

    assert!(matches!(
        error,
        KeyError::AlgorithmDisabledByPolicy { ref algorithm } if algorithm == "X25519 key generation"
    ));
}
