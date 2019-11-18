use crate::{
    error::Result,
    models::{
        certificate::{Cert, CertificateBuilder},
        csr::Csr,
        date::UTCDate,
        key::{PrivateKey, PublicKey},
        name::Name,
        signature::SignatureHashType,
    },
};

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

        CertificateBuilder::new()
            .valididy(valid_from, valid_to)
            .self_signed(Name::new_common_name(name), &key)
            .signature_hash_type(signature_hash_type)
            .ca(true)
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

        let builder = CertificateBuilder::new();
        builder
            .valididy(valid_from, valid_to)
            .subject(subject_name, intermediate_key)
            .issuer(issuer_name, issuer_key, aki.to_vec())
            .signature_hash_type(signature_hash_type)
            .ca(true);

        if let Some(pathlen) = issuer_cert
            .basic_constraints()
            .map(|bc| bc.1)
            .unwrap_or(None)
        {
            builder.pathlen(pathlen + 1);
        }

        builder.build()
    }

    pub fn generate_leaf_from_csr(
        csr: Csr,
        issuer_cert: &Cert,
        issuer_key: &PrivateKey,
        signature_hash_type: SignatureHashType,
    ) -> Result<Cert> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(LEAF_DURATION_DAYS));

        let issuer_name = issuer_cert.subject_name();
        let aki = issuer_cert.subject_key_identifier()?;

        let builder = CertificateBuilder::new();
        builder
            .valididy(valid_from, valid_to)
            .subject_from_csr(csr)
            .issuer(issuer_name, issuer_key, aki.to_vec())
            .signature_hash_type(signature_hash_type);

        if let Some(pathlen) = issuer_cert
            .basic_constraints()
            .map(|bc| bc.1)
            .unwrap_or(None)
        {
            builder.pathlen(pathlen + 1);
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
