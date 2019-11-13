use crate::{
    error::{Error, Result},
    models::{
        csr::Csr,
        key_id_gen_method::{KeyIdGenMethod, KeyIdHashAlgo},
        private_key::PrivateKey,
        signature::SignatureHashType,
    },
    pem::Pem,
    serde::{
        certificate::TBSCertificate,
        extension::{Extension, Extensions, KeyIdentifier, KeyUsage},
        name::{new_common_name, Name},
        Certificate, SubjectPublicKeyInfo, Validity, Version,
    },
};
use err_ctx::ResultExt;
use num_bigint_dig::{BigInt, Sign};
use rand::{rngs::OsRng, RngCore};
use serde_asn1_der::{bit_string::BitString, date::GeneralizedTime};
use std::cell::RefCell;

const DEFAULT_DURATION: i64 = 26280;
const ROOT_DURATION: i64 = 87600;
const INTERMEDIATE_DURATION: i64 = 43800;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateType {
    Root,
    Intermediate,
    Leaf,
}

#[derive(Debug, Clone)]
pub struct Cert {
    ty: CertificateType,
    inner: Certificate,
}

impl Cert {
    pub fn new(ty: CertificateType, certificate: Certificate) -> Self {
        Self {
            ty,
            inner: certificate,
        }
    }

    pub fn from_certificate(certificate: Certificate) -> Result<Self> {
        let (ca, len) = certificate.basic_constraints()?;
        let ty = if let Some(true) = ca {
            if let Some(0) = len {
                CertificateType::Root
            } else {
                CertificateType::Intermediate
            }
        } else {
            CertificateType::Leaf
        };
        Ok(Self::new(ty, certificate))
    }

    pub fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self> {
        Ok(Self::from_certificate(serde_asn1_der::from_bytes(
            der.as_ref(),
        )?)?)
    }

    pub fn ty(&self) -> CertificateType {
        self.ty
    }

    pub fn to_der(&self) -> serde_asn1_der::Result<Vec<u8>> {
        self.inner.to_der()
    }

    pub fn to_pem(&self) -> serde_asn1_der::Result<Pem<'static>> {
        Ok(Pem::new("CERTIFICATE", self.inner.to_der()?))
    }

    pub fn into_inner(self) -> Certificate {
        self.inner
    }

    pub fn view_inner(&self) -> &Certificate {
        &self.inner
    }

    pub fn subject_key_identifier(&self) -> Result<&[u8]> {
        self.inner.subject_key_identifier()
    }

    pub fn authority_key_identifier(&self) -> Result<&[u8]> {
        self.inner.authority_key_identifier()
    }

    pub fn basic_constraints(&self) -> Result<(Option<bool>, Option<u8>)> {
        self.inner.basic_constraints()
    }

    pub fn subject_name(&self) -> &Name {
        &self.inner.tbs_certificate.subject
    }

    pub fn issuer_name(&self) -> &Name {
        &self.inner.tbs_certificate.issuer
    }

    pub fn generate_root(
        realm_name: &str,
        signature_hash_type: SignatureHashType,
        private_key: &PrivateKey,
    ) -> Result<Self> {
        let common_name = new_common_name(realm_name);

        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = GeneralizedTime::from(now);
        let valid_to = GeneralizedTime::from(now + chrono::Duration::seconds(ROOT_DURATION));

        let root = CertificateBuilder::new(signature_hash_type)
            .valididy(valid_from, valid_to)
            .subject(
                common_name.clone(),
                private_key.to_subject_public_key_info(),
            )
            .issuer(common_name, &private_key)
            .ca(true)
            .pathlen(0)
            .build()?;

        Ok(Self::new(CertificateType::Root, root))
    }

    pub fn generate_intermediate(
        realm_name: Name,
        realm_key: &PrivateKey,
        intermediate_name: &str,
        signature_hash_type: SignatureHashType,
        private_key: &PrivateKey,
    ) -> Result<Self> {
        let subject_name = new_common_name(intermediate_name);
        let issuer_name = realm_name;

        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = GeneralizedTime::from(now);
        let valid_to =
            GeneralizedTime::from(now + chrono::Duration::seconds(INTERMEDIATE_DURATION));

        let intermediate = CertificateBuilder::new(signature_hash_type)
            .valididy(valid_from, valid_to)
            .subject(subject_name, private_key.to_subject_public_key_info())
            .issuer(issuer_name, realm_key)
            .pathlen(1)
            .ca(true)
            .build()?;

        Ok(Self::new(CertificateType::Intermediate, intermediate))
    }

    pub fn generate_leaf_from_csr(
        csr: Csr,
        authority_name: Name,
        authority_key: &PrivateKey,
        signature_hash_type: SignatureHashType,
    ) -> Result<Self> {
        csr.verify()?;

        let (subject_name, subject_public_key) = csr.into_subject_infos();

        // validity
        let now = chrono::offset::Utc::now();
        let valid_from = GeneralizedTime::from(now);
        let valid_to = GeneralizedTime::from(now + chrono::Duration::seconds(DEFAULT_DURATION));

        let leaf = CertificateBuilder::new(signature_hash_type)
            .valididy(valid_from, valid_to)
            .subject(subject_name, subject_public_key)
            .issuer(authority_name, authority_key)
            .build()?;

        Ok(Self::new(CertificateType::Leaf, leaf))
    }
}

struct CertificateBuilderInner<'a> {
    signature_hash_type: SignatureHashType,
    valid_from: Option<GeneralizedTime>,
    valid_to: Option<GeneralizedTime>,
    subject_name: Option<Name>,
    subject_public_key_info: Option<SubjectPublicKeyInfo>,
    issuer_name: Option<Name>,
    issuer_key: Option<&'a PrivateKey>,
    ca: Option<bool>,
    pathlen: Option<u8>,
    key_id_gen_method: Option<KeyIdGenMethod>,
}

pub struct CertificateBuilder<'a> {
    inner: RefCell<CertificateBuilderInner<'a>>,
}

impl<'a> CertificateBuilder<'a> {
    pub fn new(signature_hash_type: SignatureHashType) -> Self {
        Self {
            inner: RefCell::new(CertificateBuilderInner {
                signature_hash_type,
                valid_from: None,
                valid_to: None,
                subject_name: None,
                subject_public_key_info: None,
                issuer_name: None,
                issuer_key: None,
                ca: None,
                pathlen: None,
                key_id_gen_method: None,
            }),
        }
    }

    /// Required
    pub fn valididy(&self, valid_from: GeneralizedTime, valid_to: GeneralizedTime) -> &Self {
        let mut inner_mut = self.inner.borrow_mut();
        inner_mut.valid_from = Some(valid_from);
        inner_mut.valid_to = Some(valid_to);
        drop(inner_mut);
        self
    }

    /// Required
    pub fn subject(
        &self,
        subject_name: Name,
        subject_public_key_info: SubjectPublicKeyInfo,
    ) -> &Self {
        let mut inner_mut = self.inner.borrow_mut();
        inner_mut.subject_name = Some(subject_name);
        inner_mut.subject_public_key_info = Some(subject_public_key_info);
        self
    }

    /// Required
    pub fn issuer(&'a self, issuer_name: Name, issuer_key: &'a PrivateKey) -> &'a Self {
        let mut inner_mut = self.inner.borrow_mut();
        inner_mut.issuer_name = Some(issuer_name);
        inner_mut.issuer_key = Some(issuer_key);
        self
    }

    /// Optional
    pub fn ca(&self, ca: bool) -> &Self {
        self.inner.borrow_mut().ca = Some(ca);
        self
    }

    /// Optional.
    pub fn pathlen(&self, pathlen: u8) -> &Self {
        self.inner.borrow_mut().pathlen = Some(pathlen);
        self
    }

    /// Optional.
    pub fn key_id_gen_method(&self, key_id_gen_method: KeyIdGenMethod) -> &Self {
        self.inner.borrow_mut().key_id_gen_method = Some(key_id_gen_method);
        self
    }

    pub fn build(&self) -> Result<Certificate> {
        let mut inner = self.inner.borrow_mut();
        let signature_hash_type = inner.signature_hash_type;
        let valid_from = inner
            .valid_from
            .take()
            .ok_or(Error::MissingBuilderArgument("valid_from"))?;
        let valid_to = inner
            .valid_to
            .take()
            .ok_or(Error::MissingBuilderArgument("valid_to"))?;
        let subject_name = inner
            .subject_name
            .take()
            .ok_or(Error::MissingBuilderArgument("subject_name"))?;
        let subject_public_key_info = inner
            .subject_public_key_info
            .take()
            .ok_or(Error::MissingBuilderArgument("subject_public_key_info"))?;
        let issuer_name = inner
            .issuer_name
            .take()
            .ok_or(Error::MissingBuilderArgument("issuer_name"))?;
        let issuer_key = inner
            .issuer_key
            .take()
            .ok_or(Error::MissingBuilderArgument("issuer_key"))?;
        let ca = inner.ca.take().unwrap_or(false);
        let pathlen = inner.pathlen.take();
        let key_id_gen_method = inner
            .key_id_gen_method
            .take()
            .unwrap_or(KeyIdGenMethod::SPKFullDER(KeyIdHashAlgo::Sha256));
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

        let ski = key_id_gen_method.generate_from(&subject_public_key_info)?;
        let aki = key_id_gen_method.generate_from(&issuer_key.to_subject_public_key_info())?;

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
            issuer: issuer_name,
            validity,
            subject: subject_name,
            subject_public_key_info,
            extensions: extensions.into(),
        };

        let tbs_der = serde_asn1_der::to_vec(&tbs_certificate)
            .ctx("couldn't serialize tbs certificate into der")?;
        let signature_value =
            BitString::with_bytes(signature_hash_type.sign(&tbs_der, issuer_key)?);

        Ok(Certificate {
            tbs_certificate,
            signature_algorithm: signature_hash_type.into(),
            signature_value: signature_value.into(),
        })
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

        let root = Cert::generate_root("test", SignatureHashType::RsaSha256, &private_key)
            .expect("couldn't generate root ca");
        root.subject_key_identifier()
            .expect("couldn't get subject key identifier");
        root.authority_key_identifier()
            .expect("couldn't get authority key identifier");
    }

    #[test]
    fn key_id_and_cert() {
        let kid = "9a3e5270e7b8635c86b6012973b780dbe03427f6";
        let pem = crate::test_files::ROOT_CA
            .parse::<Pem>()
            .expect("couldn't parse PEM");
        let cert = Cert::from_der(pem.data()).expect("couldn't deserialize certificate");
        assert_eq!(cert.ty(), CertificateType::Root);
        let key_id = cert
            .subject_key_identifier()
            .expect("couldn't get subject key identifier");
        pretty_assertions::assert_eq!(hex::encode(&key_id), kid);
    }
}
