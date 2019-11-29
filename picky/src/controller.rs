use crate::{
    error::{Error, Result},
    models::{
        certificate::{Cert, CertificateBuilder},
        csr::Csr,
        date::UTCDate,
        key::{PrivateKey, PublicKey},
        name::Name,
        signature::SignatureHashType,
    },
    oids,
    serde::{extension::KeyUsage, name::GeneralName},
};
use serde_asn1_der::asn1_wrapper::Asn1SequenceOf;

const ROOT_DURATION_DAYS: i64 = 3650;
const INTERMEDIATE_DURATION_DAYS: i64 = 1825;
const LEAF_DURATION_DAYS: i64 = 365;

pub struct Picky;

impl Picky {
    pub fn generate_root(
        name: &str,
        key: &PrivateKey,
        signature_hash_type: SignatureHashType,
    ) -> Result<Cert> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(ROOT_DURATION_DAYS));

        let mut key_usage = KeyUsage::default();
        key_usage.set_key_cert_sign(true);
        key_usage.set_crl_sign(true);

        CertificateBuilder::new()
            .valididy(valid_from, valid_to)
            .self_signed(Name::new_common_name(name), &key)
            .signature_hash_type(signature_hash_type)
            .ca(true)
            .key_usage(key_usage)
            .build()
    }

    pub fn generate_intermediate(
        intermediate_name: &str,
        intermediate_key: PublicKey,
        issuer_cert: &Cert,
        issuer_key: &PrivateKey,
        signature_hash_type: SignatureHashType,
    ) -> Result<Cert> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(INTERMEDIATE_DURATION_DAYS));

        let subject_name = Name::new_common_name(intermediate_name);
        let issuer_name = issuer_cert.subject_name();
        let aki = issuer_cert.subject_key_identifier()?;

        let mut key_usage = KeyUsage::default();
        key_usage.set_digital_signature(true);
        key_usage.set_key_cert_sign(true);
        key_usage.set_crl_sign(true);

        CertificateBuilder::new()
            .valididy(valid_from, valid_to)
            .subject(subject_name, intermediate_key)
            .issuer(issuer_name, issuer_key, aki.to_vec())
            .signature_hash_type(signature_hash_type)
            .key_usage(key_usage)
            .pathlen(0)
            .ca(true)
            .build()
    }

    pub fn generate_leaf_from_csr(
        csr: Csr,
        issuer_cert: &Cert,
        issuer_key: &PrivateKey,
        signature_hash_type: SignatureHashType,
        dns_name: Option<&str>,
    ) -> Result<Cert> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(LEAF_DURATION_DAYS));

        let issuer_name = issuer_cert.subject_name();
        let aki = issuer_cert.subject_key_identifier()?;

        let mut key_usage = KeyUsage::default();
        key_usage.set_digital_signature(true);
        key_usage.set_key_encipherment(true);

        let eku = vec![oids::kp_server_auth(), oids::kp_client_auth()];

        let builder = CertificateBuilder::new();

        builder
            .valididy(valid_from, valid_to)
            .subject_from_csr(csr)
            .issuer(issuer_name, issuer_key, aki.to_vec())
            .signature_hash_type(signature_hash_type)
            .key_usage(key_usage)
            .extended_key_usage(eku.into());

        if let Some(dns_name) = dns_name {
            // TODO: simplify this
            let san = Asn1SequenceOf(vec![GeneralName::new_dns_name(dns_name).map_err(|e| {
                Error::InvalidCharSet {
                    input: dns_name.to_owned(),
                    source: e,
                }
            })?]);
            builder.subject_alt_name(san);
        }

        builder.build()
    }

    pub fn verify_chain<'a, Chain: Iterator<Item = &'a Cert>>(
        leaf: &Cert,
        chain: Chain,
    ) -> Result<()> {
        leaf.verify_chain(chain, &UTCDate::now())
    }
}
