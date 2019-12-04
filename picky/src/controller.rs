use crate::{
    key::{PrivateKey, PublicKey},
    oids,
    signature::SignatureHashType,
    x509::{
        certificate::{Cert, CertError, CertificateBuilder},
        csr::Csr,
        date::UTCDate,
        extension::KeyUsage,
        name::{DirectoryName, GeneralNames},
    },
};
use picky_asn1::restricted_string::{CharSetError, IA5String};
use snafu::{ResultExt, Snafu};

const ROOT_DURATION_DAYS: i64 = 3650;
const INTERMEDIATE_DURATION_DAYS: i64 = 1825;
const LEAF_DURATION_DAYS: i64 = 365;

#[derive(Debug, Snafu)]
pub enum PickyError {
    /// certificate error
    #[snafu(display("certificate error: {}", source))]
    Certificate { source: CertError },

    /// input has invalid charset
    #[snafu(display("input has invalid charset: {}", input))]
    InvalidCharSet { input: String, source: CharSetError },
}

impl From<CertError> for PickyError {
    fn from(source: CertError) -> Self {
        Self::Certificate { source }
    }
}

pub struct Picky;

impl Picky {
    pub fn generate_root(
        name: &str,
        key: &PrivateKey,
        signature_hash_type: SignatureHashType,
    ) -> Result<Cert, PickyError> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(ROOT_DURATION_DAYS));

        let mut key_usage = KeyUsage::default();
        key_usage.set_key_cert_sign(true);
        key_usage.set_crl_sign(true);

        CertificateBuilder::new()
            .valididy(valid_from, valid_to)
            .self_signed(DirectoryName::new_common_name(name), &key)
            .signature_hash_type(signature_hash_type)
            .ca(true)
            .key_usage(key_usage)
            .build()
            .context(Certificate)
    }

    pub fn generate_intermediate(
        intermediate_name: &str,
        intermediate_key: PublicKey,
        issuer_cert: &Cert,
        issuer_key: &PrivateKey,
        signature_hash_type: SignatureHashType,
    ) -> Result<Cert, PickyError> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(INTERMEDIATE_DURATION_DAYS));

        let subject_name = DirectoryName::new_common_name(intermediate_name);

        let mut key_usage = KeyUsage::default();
        key_usage.set_digital_signature(true);
        key_usage.set_key_cert_sign(true);
        key_usage.set_crl_sign(true);

        CertificateBuilder::new()
            .valididy(valid_from, valid_to)
            .subject(subject_name, intermediate_key)
            .issuer_cert(issuer_cert, issuer_key)
            .signature_hash_type(signature_hash_type)
            .key_usage(key_usage)
            .pathlen(0)
            .ca(true)
            .build()
            .context(Certificate)
    }

    pub fn generate_leaf_from_csr(
        csr: Csr,
        issuer_cert: &Cert,
        issuer_key: &PrivateKey,
        signature_hash_type: SignatureHashType,
        dns_name: Option<&str>,
    ) -> Result<Cert, PickyError> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(LEAF_DURATION_DAYS));

        let mut key_usage = KeyUsage::default();
        key_usage.set_digital_signature(true);
        key_usage.set_key_encipherment(true);

        let eku = vec![oids::kp_server_auth(), oids::kp_client_auth()];

        let builder = CertificateBuilder::new();

        builder
            .valididy(valid_from, valid_to)
            .subject_from_csr(csr)
            .issuer_cert(issuer_cert, issuer_key)
            .signature_hash_type(signature_hash_type)
            .key_usage(key_usage)
            .extended_key_usage(eku.into());

        if let Some(dns_name) = dns_name {
            let san = GeneralNames::new_dns_name(IA5String::from_string(dns_name.into()).context(
                InvalidCharSet {
                    input: dns_name.to_owned(),
                },
            )?);
            builder.subject_alt_name(san);
        }

        builder.build().context(Certificate)
    }

    pub fn verify_chain<'a, Chain: Iterator<Item = &'a Cert>>(
        leaf: &Cert,
        chain: Chain,
    ) -> Result<(), CertError> {
        leaf.verify_chain(chain, &UTCDate::now())
    }
}
