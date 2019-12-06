use picky::{
    key::{KeyError, PrivateKey, PublicKey},
    oids,
    pem::PemError,
    signature::SignatureHashType,
    x509::{
        certificate::{Cert, CertError, CertificateBuilder},
        csr::Csr,
        date::UTCDate,
        extension::KeyUsage,
        name::{DirectoryName, GeneralName, GeneralNames},
    },
};
use picky_asn1::restricted_string::CharSetError;
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

    /// couldn't generate private key
    #[snafu(display("couldn't generate private key: {}", source))]
    PrivateKeyGeneration { source: KeyError },

    /// no pre-generated private key for given size
    #[snafu(display("no {}-bits pre-generated private key available", num_bits))]
    NoPreGenKey { num_bits: usize },

    /// couldn't parse private key der (two sources)
    #[snafu(display(
        "couldn't parse private key as pkcs8: {} ; couldn't parse private key as raw der-encoded RSA key either: {}",
        pkcs8_err, rsa_der_err
    ))]
    PrivateKeyParsing {
        pkcs8_err: KeyError,
        rsa_der_err: KeyError,
    },

    /// couldn't parse private key pem
    #[snafu(display("couldn't parse private key pem: {}", source))]
    PrivateKeyPem { source: PemError },
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
        dns_name: &str,
    ) -> Result<Cert, PickyError> {
        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = UTCDate::from(now);
        let valid_to = UTCDate::from(now + chrono::Duration::days(LEAF_DURATION_DAYS));

        let mut key_usage = KeyUsage::default();
        key_usage.set_digital_signature(true);
        key_usage.set_key_encipherment(true);

        let eku = vec![oids::kp_server_auth(), oids::kp_client_auth()];

        let dns_gn = GeneralName::new_dns_name(dns_name).context(InvalidCharSet {
            input: dns_name.to_owned(),
        })?;
        let san = GeneralNames::new(dns_gn);

        CertificateBuilder::new()
            .valididy(valid_from, valid_to)
            .subject_from_csr(csr)
            .issuer_cert(issuer_cert, issuer_key)
            .signature_hash_type(signature_hash_type)
            .key_usage(key_usage)
            .extended_key_usage(eku.into())
            .subject_alt_name(san)
            .build()
            .context(Certificate)
    }

    /// This function is also used by tests in release mode.
    #[cfg(not(any(feature = "pre-gen-pk", all(debug_assertions, test))))]
    pub fn generate_private_key(bits: usize) -> Result<PrivateKey, PickyError> {
        PrivateKey::generate_rsa(bits).context(PrivateKeyGeneration)
    }

    /// !!! DEBUGGING PURPOSE ONLY !!!
    /// Private Key generation is insanely slow on debug builds.
    /// Therefore this function (only to be used in debug profile please) doesn't generate new private keys.
    /// It returns a random pre-generated private key from a pool: security-wise, this is extremely bad.
    #[cfg(any(feature = "pre-gen-pk", all(debug_assertions, test)))]
    pub fn generate_private_key(bits: usize) -> Result<PrivateKey, PickyError> {
        use crate::test_files::*;
        use picky::pem::Pem;
        use rand::prelude::*;

        warn!(
            "FETCHING A PRE-GENERATED PRIVATE KEY. \
             THIS BUILD IS FOR DEBUG PURPOSE ONLY, DON'T USE THIS BUILD IN PRODUCTION."
        );

        const RSA_2048_POOL: [&str; 6] = [
            RSA_2048_PK_1,
            RSA_2048_PK_2,
            RSA_2048_PK_3,
            RSA_2048_PK_4,
            RSA_2048_PK_5,
            RSA_2048_PK_6,
        ];
        const RSA_4096_POOL: [&str; 2] = [RSA_4096_PK_1, RSA_4096_PK_2]; //, RSA_4096_PK_3]; The third key isn't supported by current RSA implementation.

        let choice: usize = random();
        let pk_pem_str = match bits {
            2048 => {
                info!(
                    "Selected pk number {} from RSA_2048_POOL",
                    choice % RSA_2048_POOL.len()
                );
                RSA_2048_POOL[choice % RSA_2048_POOL.len()]
            }
            4096 => {
                info!(
                    "Selected pk number {} from RSA_4096_POOL",
                    choice % RSA_4096_POOL.len()
                );
                RSA_4096_POOL[choice % RSA_4096_POOL.len()]
            }
            num_bits => {
                return Err(PickyError::NoPreGenKey { num_bits });
            }
        };

        let pem = pk_pem_str.parse::<Pem>().context(PrivateKeyPem)?;
        PrivateKey::from_pkcs8(pem.data()).context(PrivateKeyGeneration)
    }

    pub fn parse_pk_from_magic_der(der: &[u8]) -> Result<PrivateKey, PickyError> {
        match PrivateKey::from_pkcs8(&der) {
            Ok(pk) => Ok(pk),
            Err(pkcs8_err) => {
                PrivateKey::from_rsa_der(der).map_err(|rsa_der_err| PickyError::PrivateKeyParsing {
                    pkcs8_err,
                    rsa_der_err,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky::pem::Pem;

    const RAW_RSA_KEY_PEM: &str =
        "-----BEGIN RSA PRIVATE KEY-----\n\
         MIIEpAIBAAKCAQEA5Kz4i/+XZhiE+fyrgtx/4yI3i6C6HXbC4QJYpDuSUEKN2bO9\n\
         RsE+Fnds/FizHtJVWbvya9ktvKdDPBdy58+CIM46HEKJhYLnBVlkEcg9N2RNgR3x\n\
         HnpRbKfv+BmWjOpSmWrmJSDLY0dbw5X5YL8TU69ImoouCUfStyCgrpwkctR0GD3G\n\
         fcGjbZRucV7VvVH9bS1jyaT/9yORyzPOSTwb+K9vOr6XlJX0CGvzQeIOcOimejHx\n\
         ACFOCnhEKXiwMsmL8FMz0drkGeMuCODY/OHVmAdXDE5UhroL0oDhSmIrdZ8CxngO\n\
         xHr1WD2yC0X0jAVP/mrxjSSfBwmmqhSMmONlvQIDAQABAoIBAQCJrBl3L8nWjayB\n\
         VL1ta5MTC+alCX8DfhyVmvQC7FqKN4dvKecqUe0vWXcj9cLhK4B3JdAtXfNLQOgZ\n\
         pYRoS2XsmjwiB20EFGtBrS+yBPvV/W0r7vrbfojHAdRXahBZhjl0ZAdrEvNgMfXt\n\
         Kr2YoXDhUQZFBCvzKmqSFfKnLRpEhsCBOsp+Sx0ZbP3yVPASXnqiZmKblpY4qcE5\n\
         KfYUO0nUWBSzY8I5c/29IY5oBbOUGS1DTMkx3R7V0BzbH/xmskVACn+cMzf467vp\n\
         yupTKG9hIX8ff0QH4Ggx88uQTRTI9IvfrAMnICFtR6U7g70hLN6j9ujXkPNhmycw\n\
         E5nQCmuBAoGBAPVbYtGBvnlySN73UrlyJ1NItUmOGhBt/ezpRjMIdMkJ6dihq7i2\n\
         RpE76sRvwHY9Tmw8oxR/V1ITK3dM2jZP1SRcm1mn5Y1D3K38jwFS0C47AXzIN2N+\n\
         LExekI1J4YOPV9o378vUKQuWpbQrQOOvylQBkRJ0Cd8DI3xhiBT/AVGbAoGBAO6Y\n\
         WBP3GMloO2v6PHijhRqrNdaI0qht8tDhO5L1troFLst3sfpK9fUP/KTlhHOzNVBF\n\
         fIJnNdcYAe9BISBbfSat+/R9F+GoUvpoC4j8ygHTQkT6ZMcMDfR8RQ4BlqGHIDKZ\n\
         YaAJoPZVkg7hNRMcvIruYpzFrheDE/4xvnC51GeHAoGAHzCFyFIw72lKwCU6e956\n\
         B0lH2ljZEVuaGuKwjM43YlMDSgmLNcjeAZpXRq9aDO3QKUwwAuwJIqLTNLAtURgm\n\
         5R9slCIWuTV2ORvQ5f8r/aR8lOsyt1ATu4WN5JgOtdWj+laAAi4vJYz59YRGFGuF\n\
         UdZ9JZZgptvUR/xx+xFLjp8CgYBMRzghaeXqvgABTUb36o8rL4FOzP9MCZqPXPKG\n\
         0TdR0UZcli+4LS7k4e+LaDUoKCrrNsvPhN+ZnHtB2jiU96rTKtxaFYQFCKM+mvTV\n\
         HrwWSUvucX62hAwSFYieKbPWgDSy+IZVe76SAllnmGg3bAB7CitMo4Y8zhMeORkB\n\
         QOe/EQKBgQDgeNgRud7S9BvaT3iT7UtizOr0CnmMfoF05Ohd9+VE4ogvLdAoDTUF\n\
         JFtdOT/0naQk0yqIwLDjzCjhe8+Ji5Y/21pjau8bvblTnASq26FRRjv5+hV8lmcR\n\
         zzk3Y05KXvJL75ksJdomkzZZb0q+Omf3wyjMR8Xl5WueJH1fh4hpBw==\n\
         -----END RSA PRIVATE KEY-----";

    #[test]
    fn parse_pk_from_raw_rsa_der_fallback() {
        let pem = RAW_RSA_KEY_PEM
            .parse::<Pem>()
            .expect("couldn't parse pk pem");
        Picky::parse_pk_from_magic_der(pem.data()).unwrap();
    }

    const GARBAGE_KEY_PEM: &str =
        "-----BEGIN RSA PRIVATE KEY-----GARBAGE-----END RSA PRIVATE KEY-----";

    #[test]
    fn parse_pk_from_garbage_error() {
        let pem = GARBAGE_KEY_PEM
            .parse::<Pem>()
            .expect("couldn't parse pk pem");
        let err = Picky::parse_pk_from_magic_der(pem.data()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "couldn't parse private key as pkcs8: (asn1) couldn't deserialize private key info (pkcs8): InvalidData ; \
             couldn't parse private key as raw der-encoded RSA key either: (asn1) couldn't deserialize rsa private key: InvalidData"
        );
    }
}
