use crate::{
    error::{Error, Result},
    models::{
        csr::Csr,
        date::UTCDate,
        key::{PrivateKey, PublicKey},
        key_id_gen_method::{KeyIdGenMethod, KeyIdHashAlgo},
        name::Name,
        signature::SignatureHashType,
    },
    pem::Pem,
    serde::{
        certificate::TBSCertificate,
        extension::{Extension, Extensions, KeyIdentifier, KeyUsage},
        Certificate, Validity, Version,
    },
};
use err_ctx::ResultExt;
use num_bigint_dig::{BigInt, Sign};
use rand::{rngs::OsRng, RngCore};
use serde_asn1_der::bit_string::BitString;
use std::cell::RefCell;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertType {
    Root,
    Intermediate,
    Leaf,
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Cert(Certificate);

impl Cert {
    pub fn new(certificate: Certificate) -> Self {
        Self(certificate)
    }

    pub fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self> {
        Ok(Self::new(serde_asn1_der::from_bytes(der.as_ref())?))
    }

    pub fn to_der(&self) -> serde_asn1_der::Result<Vec<u8>> {
        self.0.to_der()
    }

    pub fn to_pem(&self) -> serde_asn1_der::Result<Pem<'static>> {
        Ok(Pem::new("CERTIFICATE", self.0.to_der()?))
    }

    pub fn into_inner(self) -> Certificate {
        self.0
    }

    pub fn view_inner(&self) -> &Certificate {
        &self.0
    }

    pub fn ty(&self) -> CertType {
        let (ca, len) = self.basic_constraints().unwrap_or((None, None));
        match ca {
            Some(true) => {
                if let Some(0) = len {
                    CertType::Root
                } else {
                    CertType::Intermediate
                }
            }
            Some(false) => CertType::Leaf,
            None => CertType::Unknown,
        }
    }

    pub fn subject_key_identifier(&self) -> Result<&[u8]> {
        self.0.subject_key_identifier()
    }

    pub fn authority_key_identifier(&self) -> Result<&[u8]> {
        self.0.authority_key_identifier()
    }

    pub fn basic_constraints(&self) -> Result<(Option<bool>, Option<u8>)> {
        self.0.basic_constraints()
    }

    pub fn subject_name(&self) -> Name {
        self.0.tbs_certificate.subject.clone().into()
    }

    pub fn issuer_name(&self) -> Name {
        self.0.tbs_certificate.issuer.clone().into()
    }

    pub fn verify(&self, now: &UTCDate) -> Result<()> {
        let validity = &self.0.tbs_certificate.validity;
        let not_before: UTCDate = validity.not_before.clone().into();
        let not_after: UTCDate = validity.not_after.clone().into();

        if not_before.gt(now) {
            return Err(Error::CertificateNotYetValid {
                not_before,
                now: now.clone(),
            });
        }

        if not_after.lt(now) {
            return Err(Error::CertificateExpired {
                not_after,
                now: now.clone(),
            });
        }

        Ok(())
    }

    pub fn verify_chain<'a, Chain: Iterator<Item = &'a Cert>>(
        &self,
        chain: Chain,
        now: &UTCDate,
    ) -> Result<()> {
        self.verify(now).ctx("invalid certificate")?;

        let mut current_cert = self;
        let mut current_pathlen = self.basic_constraints().map(|bc| bc.1).unwrap_or(None);
        let mut root_ca_not_found = true;

        for parent_cert in chain {
            if let Some(0) = current_pathlen {
                return Err(Error::CAChainTooDeep);
            }

            parent_cert.verify(now).ctx("invalid parent certificate")?;

            // check current cert aki match parent ski
            let parent_ski = parent_cert
                .subject_key_identifier()
                .ctx("couldn't fetch parent ski")?;
            let current_aki = current_cert
                .authority_key_identifier()
                .ctx("couldn't fetch child aki")?;
            if parent_ski != current_aki {
                return Err(Error::AuthorityKeyIdMismatch {
                    expected: current_aki.to_vec(),
                    actual: parent_ski.to_vec(),
                });
            }

            // validate current cert signature using parent public key
            let hash_type =
                SignatureHashType::from_algorithm_identifier(&current_cert.0.signature_algorithm)
                    .ok_or(Error::UnsupportedAlgorithm("unknown identifier"))?;
            let public_key = &parent_cert.0.tbs_certificate.subject_public_key_info;
            let msg = serde_asn1_der::to_vec(&current_cert.0.tbs_certificate)
                .ctx("couldn't serialize child certificate to der")?;
            hash_type.verify(
                &public_key.clone().into(),
                &msg,
                current_cert.0.signature_value.0.payload_view(),
            )?;

            // update pathlen tracking
            match (
                current_pathlen,
                parent_cert
                    .basic_constraints()
                    .map(|bc| bc.1)
                    .unwrap_or(None),
            ) {
                (None, parent_pathlen) => current_pathlen = parent_pathlen,
                (Some(current_value), Some(parent_value)) if parent_value < current_value => {
                    current_pathlen = Some(parent_value)
                }
                (Some(current_value), _) => current_pathlen = Some(current_value - 1),
            }

            // check if this is a root CA
            let parent_aki = parent_cert
                .authority_key_identifier()
                .ctx("couldn't fetch parent aki")?;
            if parent_ski == parent_aki {
                root_ca_not_found = false;
                break;
            }

            current_cert = parent_cert;
        }

        if root_ca_not_found {
            return Err(Error::CAChainNoRoot);
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
enum SubjectInfos {
    Csr(Csr),
    NameAndPublicKey { name: Name, public_key: PublicKey },
}

#[derive(Clone, Debug)]
enum IssuerInfos<'a> {
    SelfSigned {
        name: Name,
        key: &'a PrivateKey,
    },
    Authority {
        issuer_name: Name,
        issuer_key: &'a PrivateKey,
        aki: Vec<u8>,
    },
}

#[derive(Default, Clone, Debug)]
struct CertificateBuilderInner<'a> {
    valid_from: Option<UTCDate>,
    valid_to: Option<UTCDate>,
    subject_infos: Option<SubjectInfos>,
    issuer_infos: Option<IssuerInfos<'a>>,
    ca: Option<bool>,
    pathlen: Option<u8>,
    signature_hash_type: Option<SignatureHashType>,
    key_id_gen_method: Option<KeyIdGenMethod>,
}

#[derive(Default, Clone, Debug)]
pub struct CertificateBuilder<'a> {
    inner: RefCell<CertificateBuilderInner<'a>>,
}

impl<'a> CertificateBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Required
    pub fn valididy(&self, valid_from: UTCDate, valid_to: UTCDate) -> &Self {
        let mut inner_mut = self.inner.borrow_mut();
        inner_mut.valid_from = Some(valid_from);
        inner_mut.valid_to = Some(valid_to);
        drop(inner_mut);
        self
    }

    /// Required (alternatives: `subject_from_csr`, `self_signed`)
    pub fn subject(&self, subject_name: Name, public_key: PublicKey) -> &Self {
        self.inner.borrow_mut().subject_infos = Some(SubjectInfos::NameAndPublicKey {
            name: subject_name,
            public_key,
        });
        self
    }

    /// Required (alternatives: `subject`, `self_signed`)
    pub fn subject_from_csr(&self, csr: Csr) -> &Self {
        self.inner.borrow_mut().subject_infos = Some(SubjectInfos::Csr(csr));
        self
    }

    /// Required (alternative: `self_signed`)
    pub fn issuer(
        &'a self,
        issuer_name: Name,
        issuer_key: &'a PrivateKey,
        aki: Vec<u8>,
    ) -> &'a Self {
        self.inner.borrow_mut().issuer_infos = Some(IssuerInfos::Authority {
            issuer_name,
            issuer_key,
            aki,
        });
        self
    }

    /// Required (alternative: `issuer`)
    pub fn self_signed(&'a self, name: Name, key: &'a PrivateKey) -> &'a Self {
        self.inner.borrow_mut().issuer_infos = Some(IssuerInfos::SelfSigned { name, key });
        self.inner.borrow_mut().pathlen = Some(0);
        self
    }

    /// Optional
    pub fn ca(&self, ca: bool) -> &Self {
        self.inner.borrow_mut().ca = Some(ca);
        self
    }

    /// Optional (automatically set to 0 by `self_signed`)
    pub fn pathlen(&self, pathlen: u8) -> &Self {
        self.inner.borrow_mut().pathlen = Some(pathlen);
        self
    }

    /// Optional.
    pub fn signature_hash_type(&self, signature_hash_type: SignatureHashType) -> &Self {
        self.inner.borrow_mut().signature_hash_type = Some(signature_hash_type);
        self
    }

    /// Optional.
    pub fn key_id_gen_method(&self, key_id_gen_method: KeyIdGenMethod) -> &Self {
        self.inner.borrow_mut().key_id_gen_method = Some(key_id_gen_method);
        self
    }

    pub fn build(&self) -> Result<Cert> {
        let mut inner = self.inner.borrow_mut();

        let valid_from = inner
            .valid_from
            .take()
            .ok_or(Error::MissingBuilderArgument("valid_from"))?;
        let valid_to = inner
            .valid_to
            .take()
            .ok_or(Error::MissingBuilderArgument("valid_to"))?;

        let signature_hash_type = inner
            .signature_hash_type
            .take()
            .unwrap_or(SignatureHashType::RsaSha256);

        let key_id_gen_method = inner
            .key_id_gen_method
            .take()
            .unwrap_or(KeyIdGenMethod::SPKFullDER(KeyIdHashAlgo::Sha256));

        let issuer_infos = inner
            .issuer_infos
            .take()
            .ok_or(Error::MissingBuilderArgument("issuer_infos"))?;
        let (issuer_name, issuer_key, aki, subject_infos) = match issuer_infos {
            IssuerInfos::SelfSigned { name, key } => {
                let aki = key_id_gen_method.generate_from(&key.to_public_key())?;
                let subject_infos = SubjectInfos::NameAndPublicKey {
                    name: name.clone(),
                    public_key: key.to_public_key(),
                };
                (name, key, aki, subject_infos)
            }
            IssuerInfos::Authority {
                issuer_name,
                issuer_key,
                aki,
            } => {
                let subject_infos = inner
                    .subject_infos
                    .take()
                    .ok_or(Error::MissingBuilderArgument("subject_infos"))?;
                (issuer_name, issuer_key, aki, subject_infos)
            }
        };
        let (subject_name, subject_public_key) = match subject_infos {
            SubjectInfos::Csr(csr) => {
                csr.verify()?;
                csr.into_subject_infos()
            }
            SubjectInfos::NameAndPublicKey { name, public_key } => (name, public_key),
        };

        let ca = inner.ca.take().unwrap_or(false);
        let pathlen = inner.pathlen.take();

        drop(inner);

        let serial_number = BigInt::from_bytes_be(Sign::Plus, &generate_serial_number());

        let validity = Validity {
            not_before: valid_from.into(),
            not_after: valid_to.into(),
        };

        // https://tools.ietf.org/html/rfc4055#section-1.2
        // If the keyUsage extension is present in an end-entity certificate
        // that conveys an RSA public key with the id-RSASSA-PSS object
        // identifier, then the keyUsage extension MUST contain one or both of
        // the following values:
        //
        //      nonRepudiation; and
        //      digitalSignature.
        //
        // If the keyUsage extension is present in a certification authority
        // certificate that conveys an RSA public key with the id-RSASSA-PSS
        // object identifier, then the keyUsage extension MUST contain one or
        // more of the following values:
        //
        //      nonRepudiation;
        //      digitalSignature;
        //      keyCertSign; and
        //      cRLSign.
        //
        // When a certificate conveys an RSA public key with the id-RSASSA-PSS
        // object identifier, the certificate user MUST only use the certified
        // RSA public key for RSASSA-PSS operations, and, if RSASSA-PSS-params
        // is present, the certificate user MUST perform those operations using
        // the one-way hash function, mask generation function, and trailer
        // field identified in the subject public key algorithm identifier
        // parameters within the certificate.
        //
        // If the keyUsage extension is present in a certificate conveys an RSA
        // public key with the id-RSAES-OAEP object identifier, then the
        // keyUsage extension MUST contain only the following values:
        //
        //      keyEncipherment; and
        //      dataEncipherment.
        //
        // However, both keyEncipherment and dataEncipherment SHOULD NOT be
        // present.
        let mut key_usage = KeyUsage::new(7);
        if ca {
            key_usage.set_digital_signature(true);
            key_usage.set_key_encipherment(true);
            key_usage.set_key_cert_sign(true);
            key_usage.set_crl_sign(true);
            key_usage.set_key_agreement(true);
        } else {
            key_usage.set_digital_signature(true);
            key_usage.set_key_encipherment(true);
        };

        let ski = key_id_gen_method.generate_from(&subject_public_key)?;

        let extensions = Extensions(vec![
            Extension::new_basic_constraints(false, ca, pathlen),
            Extension::new_key_usage(key_usage),
            Extension::new_subject_key_identifier(ski),
            Extension::new_authority_key_identifier(KeyIdentifier::from(aki), None, None),
        ]);

        let tbs_certificate = TBSCertificate {
            version: Version::V3.into(),
            serial_number: serial_number.into(),
            signature: signature_hash_type.into(),
            issuer: issuer_name.into(),
            validity,
            subject: subject_name.into(),
            subject_public_key_info: subject_public_key.into(),
            extensions: extensions.into(),
        };

        let tbs_der = serde_asn1_der::to_vec(&tbs_certificate)
            .ctx("couldn't serialize tbs certificate into der")?;
        let signature_value =
            BitString::with_bytes(signature_hash_type.sign(&tbs_der, issuer_key)?);

        Ok(Cert(Certificate {
            tbs_certificate,
            signature_algorithm: signature_hash_type.into(),
            signature_value: signature_value.into(),
        }))
    }
}

fn generate_serial_number() -> Vec<u8> {
    let mut rng = OsRng::new().expect("couldn't fetch OsRng");
    let x = rng.next_u32();
    let b1 = ((x >> 24) & 0xff) as u8;
    let b2 = ((x >> 16) & 0xff) as u8;
    let b3 = ((x >> 8) & 0xff) as u8;
    let b4 = (x & 0xff) as u8;
    vec![b1, b2, b3, b4]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pem::Pem;

    #[test]
    fn get_identifier() {
        let pem = crate::test_files::RSA_2048_PK_1
            .parse::<Pem>()
            .expect("couldn't parse pem");
        let private_key =
            PrivateKey::from_pkcs8(pem.data()).expect("couldn't extract private key from pkcs8");

        // validity
        let valid_from = UTCDate::ymd(2019, 10, 10).unwrap();
        let valid_to = UTCDate::ymd(2019, 10, 11).unwrap();

        let root = CertificateBuilder::new()
            .valididy(valid_from, valid_to)
            .self_signed(Name::new_common_name("test"), &private_key)
            .ca(true)
            .build()
            .expect("couldn't generate root ca");

        root.subject_key_identifier()
            .expect("couldn't get subject key identifier");
        root.authority_key_identifier()
            .expect("couldn't get authority key identifier");

        assert_eq!(root.ty(), CertType::Root);
    }

    #[test]
    fn key_id_and_cert() {
        let kid = "9a3e5270e7b8635c86b6012973b780dbe03427f6";
        let pem = crate::test_files::ROOT_CA
            .parse::<Pem>()
            .expect("couldn't parse PEM");
        let cert = Cert::from_der(pem.data()).expect("couldn't deserialize certificate");
        assert_eq!(cert.ty(), CertType::Root);
        let key_id = cert
            .subject_key_identifier()
            .expect("couldn't get subject key identifier");
        pretty_assertions::assert_eq!(hex::encode(&key_id), kid);
    }

    fn parse_key(pem_str: &str) -> PrivateKey {
        let pem = pem_str.parse::<Pem>().unwrap();
        PrivateKey::from_pkcs8(pem.data()).unwrap()
    }

    #[test]
    fn valid_ca_chain() {
        let root_key = parse_key(crate::test_files::RSA_2048_PK_1);
        let intermediate_key = parse_key(crate::test_files::RSA_2048_PK_2);
        let leaf_key = parse_key(crate::test_files::RSA_2048_PK_3);

        let root = CertificateBuilder::new()
            .valididy(
                UTCDate::ymd(2065, 6, 15).unwrap(),
                UTCDate::ymd(2070, 6, 15).unwrap(),
            )
            .self_signed(
                Name::new_common_name("TheFuture.usodakedo Root CA"),
                &root_key,
            )
            .ca(true)
            .signature_hash_type(SignatureHashType::RsaSha512)
            .key_id_gen_method(KeyIdGenMethod::SPKFullDER(KeyIdHashAlgo::Sha384))
            .build()
            .expect("couldn't build root ca");

        let intermediate = CertificateBuilder::new()
            .valididy(
                UTCDate::ymd(2068, 1, 1).unwrap(),
                UTCDate::ymd(2071, 1, 1).unwrap(),
            )
            .subject(
                Name::new_common_name("TheFuture.usodakedo Authority"),
                intermediate_key.to_public_key(),
            )
            .issuer(
                root.issuer_name(),
                &root_key,
                root.subject_key_identifier().unwrap().to_vec(),
            )
            .signature_hash_type(SignatureHashType::RsaSha224)
            .key_id_gen_method(KeyIdGenMethod::SPKValueHashedLeftmost160(
                KeyIdHashAlgo::Sha1,
            ))
            .ca(true)
            .pathlen(1)
            .build()
            .expect("couldn't build intermediate root ca");

        let csr = Csr::generate(
            Name::new_common_name("ChillingInTheFuture.usobakkari"),
            &leaf_key,
            SignatureHashType::RsaSha1,
        )
        .unwrap();

        let signed_leaf = CertificateBuilder::new()
            .valididy(
                UTCDate::ymd(2069, 1, 1).unwrap(),
                UTCDate::ymd(2072, 1, 1).unwrap(),
            )
            .subject_from_csr(csr)
            .issuer(
                intermediate.issuer_name(),
                &intermediate_key,
                intermediate.subject_key_identifier().unwrap().to_vec(),
            )
            .signature_hash_type(SignatureHashType::RsaSha384)
            .key_id_gen_method(KeyIdGenMethod::SPKFullDER(KeyIdHashAlgo::Sha512))
            .pathlen(2)
            .build()
            .expect("couldn't build signed leaf");

        let chain = [intermediate, root];

        signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2069, 10, 1).unwrap())
            .expect("couldn't verify chain");

        let expired_err = signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2080, 10, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            expired_err.to_string(),
            "invalid certificate: certificate expired (not after: 2072-01-01 00:00:00, now: 2080-10-01 00:00:00)"
        );

        let intermediate_expired_err = signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2071, 6, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            intermediate_expired_err.to_string(),
            "invalid parent certificate: certificate expired (not after: 2071-01-01 00:00:00, now: 2071-06-01 00:00:00)"
        );

        let root_expired_err = signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2070, 6, 16).unwrap())
            .unwrap_err();
        assert_eq!(
            root_expired_err.to_string(),
            "invalid parent certificate: certificate expired (not after: 2070-06-15 00:00:00, now: 2070-06-16 00:00:00)"
        );

        let still_in_2019_err = signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2019, 11, 14).unwrap())
            .unwrap_err();
        assert_eq!(
            still_in_2019_err.to_string(),
            "invalid certificate: certificate is not yet valid (not before: 2069-01-01 00:00:00, now: 2019-11-14 00:00:00)"
        );
    }

    #[test]
    fn malicious_ca_chain() {
        let root_key = parse_key(crate::test_files::RSA_2048_PK_1);
        let intermediate_key = parse_key(crate::test_files::RSA_2048_PK_2);
        let leaf_key = parse_key(crate::test_files::RSA_2048_PK_3);
        let malicious_root_key = parse_key(crate::test_files::RSA_2048_PK_4);

        let root = CertificateBuilder::new()
            .valididy(
                UTCDate::ymd(2065, 6, 15).unwrap(),
                UTCDate::ymd(2070, 6, 15).unwrap(),
            )
            .self_signed(Name::new_common_name("VerySafe Root CA"), &root_key)
            .ca(true)
            .signature_hash_type(SignatureHashType::RsaSha1)
            .key_id_gen_method(KeyIdGenMethod::SPKFullDER(KeyIdHashAlgo::Sha224))
            .build()
            .expect("couldn't build root ca");

        let intermediate = CertificateBuilder::new()
            .valididy(
                UTCDate::ymd(2068, 1, 1).unwrap(),
                UTCDate::ymd(2071, 1, 1).unwrap(),
            )
            .subject(
                Name::new_common_name("V.E.R.Y Legitimate VerySafe Authority"),
                intermediate_key.to_public_key(),
            )
            .issuer(
                root.issuer_name(),
                &malicious_root_key,
                root.subject_key_identifier().unwrap().to_vec(),
            )
            .signature_hash_type(SignatureHashType::RsaSha512)
            .key_id_gen_method(KeyIdGenMethod::SPKValueHashedLeftmost160(
                KeyIdHashAlgo::Sha384,
            ))
            .ca(true)
            .pathlen(1)
            .build()
            .expect("couldn't build intermediate root ca");

        let csr = Csr::generate(
            Name::new_common_name("I Trust This V.E.R.Y Legitimate Intermediate Certificate"),
            &leaf_key,
            SignatureHashType::RsaSha1,
        )
        .unwrap();

        let signed_leaf_builder = CertificateBuilder::new();
        signed_leaf_builder
            .valididy(
                UTCDate::ymd(2069, 1, 1).unwrap(),
                UTCDate::ymd(2072, 1, 1).unwrap(),
            )
            .subject_from_csr(csr)
            .issuer(
                intermediate.issuer_name(),
                &intermediate_key,
                intermediate.subject_key_identifier().unwrap().to_vec(),
            )
            .signature_hash_type(SignatureHashType::RsaSha224)
            .key_id_gen_method(KeyIdGenMethod::SPKFullDER(KeyIdHashAlgo::Sha384));

        let signed_leaf = signed_leaf_builder
            .clone()
            .pathlen(2)
            .build()
            .expect("couldn't build signed leaf");

        let chain = [intermediate, root];

        let root_missing_err = signed_leaf
            .verify_chain(chain[..1].iter(), &UTCDate::ymd(2069, 10, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            root_missing_err.to_string(),
            "CA chain is missing a root certificate"
        );

        let invalid_sig_err = signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2069, 10, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            invalid_sig_err.to_string(),
            "couldn\'t verify signature: invalid signature"
        );

        let signed_leaf_with_invalid_pathlen = signed_leaf_builder
            .pathlen(1)
            .build()
            .expect("couldn't build invalid pathlen signed leaf");
        let invalid_pathlen_err = signed_leaf_with_invalid_pathlen
            .verify_chain(chain.iter(), &UTCDate::ymd(2069, 10, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            invalid_pathlen_err.to_string(),
            "CA chain depth does\'t satisfy basic constraints extension"
        );
    }
}
