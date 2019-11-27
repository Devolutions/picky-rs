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
    serde::name::GeneralName,
};
use serde_asn1_der::asn1_wrapper::Asn1SequenceOf;

const ROOT_DURATION_DAYS: i64 = 3650;
const INTERMEDIATE_DURATION_DAYS: i64 = 1825;
const LEAF_DURATION_DAYS: i64 = 365;

pub struct Picky;

impl Picky {
    pub fn generate_root(
        dns_name: &str,
        key: &PrivateKey,
        signature_hash_type: SignatureHashType,
    ) -> Result<Cert> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(ROOT_DURATION_DAYS));

        // TODO: simplify this
        let san = Asn1SequenceOf(vec![GeneralName::new_dns_name(dns_name).map_err(|e| {
            Error::InvalidCharSet {
                input: dns_name.to_owned(),
                source: e,
            }
        })?]);

        CertificateBuilder::new()
            .valididy(valid_from, valid_to)
            .self_signed(Name::new_common_name(dns_name), &key)
            .signature_hash_type(signature_hash_type)
            .ca(true)
            .default_key_usage()
            .subject_alt_name(san)
            .build()
    }

    pub fn generate_intermediate(
        intermediate_dns_name: &str,
        intermediate_key: PublicKey,
        issuer_cert: &Cert,
        issuer_key: &PrivateKey,
        signature_hash_type: SignatureHashType,
    ) -> Result<Cert> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(INTERMEDIATE_DURATION_DAYS));

        let subject_name = Name::new_common_name(intermediate_dns_name);

        let issuer_name = issuer_cert.subject_name();
        let aki = issuer_cert.subject_key_identifier()?;

        // TODO: simplify this
        let san = Asn1SequenceOf(vec![GeneralName::new_dns_name(intermediate_dns_name)
            .map_err(|e| Error::InvalidCharSet {
                input: intermediate_dns_name.to_owned(),
                source: e,
            })?]);

        let builder = CertificateBuilder::new();
        builder
            .valididy(valid_from, valid_to)
            .subject(subject_name, intermediate_key)
            .issuer(issuer_name, issuer_key, aki.to_vec())
            .signature_hash_type(signature_hash_type)
            .ca(true)
            .default_key_usage()
            .subject_alt_name(san);

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

        let subject_name = csr.subject_name();

        let builder = CertificateBuilder::new();
        builder
            .valididy(valid_from, valid_to)
            .subject_from_csr(csr)
            .issuer(issuer_name, issuer_key, aki.to_vec())
            .signature_hash_type(signature_hash_type)
            .default_key_usage();

        if let Some(subject_common_name) = subject_name.find_common_name().map(ToString::to_string) {
            // TODO: simplify this
            let san = Asn1SequenceOf(vec![GeneralName::new_dns_name(&subject_common_name)
                .map_err(|e| Error::InvalidCharSet {
                    input: subject_common_name,
                    source: e,
                })?]);
            builder.subject_alt_name(san);
        }

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
