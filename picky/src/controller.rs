use crate::{
    error::Result,
    models::{
        certificate::Cert, csr::Csr, date::UTCDate, key::PrivateKey, name::Name,
        signature::SignatureHashType,
    },
};

const ROOT_DURATION_DAYS: i64 = 3650;
const INTERMEDIATE_DURATION_DAYS: i64 = 1825;
const LEAF_DURATION_DAYS: i64 = 365;

pub struct Picky;

impl Picky {
    pub fn generate_root(
        realm_name: &str,
        signature_hash_type: SignatureHashType,
        private_key: &PrivateKey,
    ) -> Result<Cert> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(ROOT_DURATION_DAYS));

        Cert::generate_root(
            realm_name,
            signature_hash_type,
            private_key,
            valid_from,
            valid_to,
        )
    }

    pub fn generate_intermediate(
        realm_name: Name,
        realm_key: &PrivateKey,
        intermediate_name: &str,
        signature_hash_type: SignatureHashType,
        private_key: &PrivateKey,
    ) -> Result<Cert> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(INTERMEDIATE_DURATION_DAYS));

        Cert::generate_intermediate(
            realm_name,
            realm_key,
            intermediate_name,
            signature_hash_type,
            private_key,
            valid_from,
            valid_to,
        )
    }

    pub fn generate_leaf_from_csr(
        csr: Csr,
        authority_name: Name,
        authority_key: &PrivateKey,
        signature_hash_type: SignatureHashType,
    ) -> Result<Cert> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(LEAF_DURATION_DAYS));

        Cert::generate_leaf_from_csr(
            csr,
            authority_name,
            authority_key,
            signature_hash_type,
            valid_from,
            valid_to,
        )
    }

    pub fn verify_chain<'a, Chain: Iterator<Item = &'a Cert>>(
        leaf: &Cert,
        chain: Chain,
    ) -> Result<()> {
        leaf.verify_chain(chain, &UTCDate::now())
    }
}
