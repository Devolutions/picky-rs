use crate::{
    key::{OwnedPublicKey, PrivateKey, PublicKey},
    oids,
    pem::Pem,
    signature::{SignatureError, SignatureHashType},
    x509::{
        csr::{Csr, CsrError},
        date::UTCDate,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, ExtensionView, KeyIdentifier, KeyUsage,
        },
        key_id_gen_method::{KeyIdGenError, KeyIdGenMethod, KeyIdHashAlgo},
        name::{DirectoryName, GeneralNames},
        private::{certificate::TBSCertificate, Certificate, Validity, Version},
        Extension, Extensions,
    },
    AlgorithmIdentifier,
};
use picky_asn1::{bit_string::BitString, wrapper::IntegerAsn1};
use picky_asn1_der::Asn1DerError;
use snafu::{ResultExt, Snafu};
use std::cell::RefCell;

#[derive(Debug, Snafu)]
pub enum CertError {
    /// couldn't generate certificate
    #[snafu(display("couldn't generate certificate: {}", source))]
    CertGeneration {
        #[snafu(source(from(CertError, Box::new)))]
        source: Box<CertError>,
    },

    /// invalid certificate
    #[snafu(display("invalid certificate '{}': {}", id, source))]
    InvalidCertificate {
        id: String,
        #[snafu(source(from(CertError, Box::new)))]
        source: Box<CertError>,
    },

    /// asn1 serialization error
    #[snafu(display("(asn1) couldn't serialize {}: {}", element, source))]
    Asn1Serialization {
        element: &'static str,
        source: Asn1DerError,
    },

    /// asn1 deserialization error
    #[snafu(display("(asn1) couldn't deserialize {}: {}", element, source))]
    Asn1Deserialization {
        element: &'static str,
        source: Asn1DerError,
    },

    /// signature error
    #[snafu(display("signature error: {}", source))]
    Signature { source: SignatureError },

    /// key id generation error
    #[snafu(display("key id generation error: {}", source))]
    KeyIdGen { source: KeyIdGenError },

    /// CA chain error
    #[snafu(display("CA chain error: {}", source))]
    InvalidChain { source: CaChainError },

    /// CSR error
    #[snafu(display("CSR error: {}", source))]
    InvalidCsr { source: CsrError },

    /// extension not found
    #[snafu(display("extension not found: {}", name))]
    ExtensionNotFound { name: &'static str },

    /// missing required builder argument
    #[snafu(display("missing required builder argument `{}`", arg))]
    MissingBuilderArgument { arg: &'static str },

    /// certificate is not yet valid
    #[snafu(display("certificate is not yet valid (not before: {}, now: {})", not_before, now))]
    CertificateNotYetValid { not_before: UTCDate, now: UTCDate },

    /// certificate expired
    #[snafu(display("certificate expired (not after: {}, now: {})", not_after, now))]
    CertificateExpired { not_after: UTCDate, now: UTCDate },

    /// invalid PEM label error
    #[snafu(display("invalid PEM label: {}", label))]
    InvalidPemLabel { label: String },
}

#[derive(Debug, Snafu)]
pub enum CaChainError {
    /// chain depth does't satisfy basic constraints extension
    #[snafu(display(
        "chain depth doesn't satisfy basic constraints extension: certificate '{}' has pathlen of {}",
        cert_id,
        pathlen
    ))]
    TooDeep { cert_id: String, pathlen: u8 },

    /// chain is missing a root certificate
    NoRoot,

    /// issuer certificate is not a CA
    #[snafu(display("issuer certificate '{}' is not a CA", issuer_id))]
    IssuerIsNotCA { issuer_id: String },

    /// authority key id doesn't match
    #[snafu(display("authority key id doesn't match (expected: {:?}, got: {:?})", expected, actual))]
    AuthorityKeyIdMismatch { expected: Vec<u8>, actual: Vec<u8> },

    /// issuer name doesn't match
    #[snafu(display("issuer name doesn't match (expected: {}, got: {})", expected, actual))]
    IssuerNameMismatch { expected: String, actual: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertType {
    Root,
    Intermediate,
    Leaf,
    Unknown,
}

const CERT_PEM_LABEL: &str = "CERTIFICATE";

#[derive(Clone, Debug, PartialEq)]
pub struct Cert(Certificate);

impl From<Certificate> for Cert {
    fn from(certificate: Certificate) -> Self {
        Self(certificate)
    }
}

macro_rules! find_ext {
    ($oid:expr, $certificate:ident, $ext_name:literal) => {{
        let key_identifier_oid = $oid;
        ($certificate.tbs_certificate.extensions.0)
            .0
            .iter()
            .find(|ext| ext.extn_id() == &key_identifier_oid)
            .ok_or(CertError::ExtensionNotFound { name: $ext_name })
    }};
}

impl Cert {
    pub fn from_der<T: ?Sized + AsRef<[u8]>>(der: &T) -> Result<Self, CertError> {
        Ok(Self(
            picky_asn1_der::from_bytes(der.as_ref()).context(Asn1Deserialization { element: "certificate" })?,
        ))
    }

    pub fn from_pem(pem: &Pem) -> Result<Self, CertError> {
        match pem.label() {
            CERT_PEM_LABEL => Self::from_der(pem.data()),
            _ => Err(CertError::InvalidPemLabel {
                label: pem.label().to_owned(),
            }),
        }
    }

    pub fn to_der(&self) -> Result<Vec<u8>, CertError> {
        picky_asn1_der::to_vec(&self.0).context(Asn1Serialization { element: "certificate" })
    }

    pub fn to_pem(&self) -> Result<Pem<'static>, CertError> {
        Ok(Pem::new(CERT_PEM_LABEL, self.to_der()?))
    }

    pub fn ty(&self) -> CertType {
        if let Some(ca) = self.basic_constraints().map(|bc| bc.ca()).unwrap_or(None) {
            if ca {
                if self.subject_name() == self.issuer_name() {
                    CertType::Root
                } else {
                    CertType::Intermediate
                }
            } else {
                CertType::Leaf
            }
        } else {
            CertType::Unknown
        }
    }

    pub fn serial_number(&self) -> &IntegerAsn1 {
        &self.0.tbs_certificate.serial_number
    }

    pub fn signature_algorithm(&self) -> &AlgorithmIdentifier {
        &self.0.tbs_certificate.signature
    }

    pub fn valid_not_before(&self) -> UTCDate {
        self.0.tbs_certificate.validity.not_before.clone().into()
    }

    pub fn valid_not_after(&self) -> UTCDate {
        self.0.tbs_certificate.validity.not_after.clone().into()
    }

    pub fn subject_key_identifier(&self) -> Result<&[u8], CertError> {
        let certificate = &self.0;

        let ext = find_ext!(oids::subject_key_identifier(), certificate, "subject key identifier")?;
        match ext.extn_value() {
            ExtensionView::SubjectKeyIdentifier(ski) => Ok(&ski.0),
            _ => unreachable!("invalid extension (expected subject key identifier)"),
        }
    }

    pub fn authority_key_identifier(&self) -> Result<&AuthorityKeyIdentifier, CertError> {
        let certificate = &self.0;

        let ext = find_ext!(
            oids::authority_key_identifier(),
            certificate,
            "authority key identifier"
        )?;
        match ext.extn_value() {
            ExtensionView::AuthorityKeyIdentifier(aki) => Ok(aki),
            _ => unreachable!("invalid extension (expected authority key identifier)"),
        }
    }

    pub fn basic_constraints(&self) -> Result<&BasicConstraints, CertError> {
        let certificate = &self.0;
        let ext = find_ext!(oids::basic_constraints(), certificate, "basic constraints")?;
        match ext.extn_value() {
            ExtensionView::BasicConstraints(bc) => Ok(bc),
            _ => unreachable!("invalid extension (expected basic constraints)"),
        }
    }

    pub fn subject_name(&self) -> DirectoryName {
        self.0.tbs_certificate.subject.clone().into()
    }

    pub fn issuer_name(&self) -> DirectoryName {
        self.0.tbs_certificate.issuer.clone().into()
    }

    pub fn extensions(&self) -> &[Extension] {
        (self.0.tbs_certificate.extensions.0).0.as_slice()
    }

    pub fn public_key(&self) -> PublicKey {
        (&self.0.tbs_certificate.subject_public_key_info).into()
    }

    pub fn verify(&self, now: &UTCDate) -> Result<(), CertError> {
        let validity = &self.0.tbs_certificate.validity;
        let not_before: UTCDate = validity.not_before.clone().into();
        let not_after: UTCDate = validity.not_after.clone().into();

        if not_before.gt(now) {
            return Err(CertError::CertificateNotYetValid {
                not_before,
                now: now.clone(),
            });
        }

        if not_after.lt(now) {
            return Err(CertError::CertificateExpired {
                not_after,
                now: now.clone(),
            });
        }

        Ok(())
    }

    pub fn is_parent_of(&self, other: &Cert) -> Result<(), CertError> {
        if let Ok(other_aki) = other.authority_key_identifier() {
            if let Some(other_aki) = other_aki.key_identifier() {
                let parent_ski = self.subject_key_identifier().with_context(|| InvalidCertificate {
                    id: self.subject_name().to_string(),
                })?;

                if parent_ski != other_aki {
                    return Err(CaChainError::AuthorityKeyIdMismatch {
                        expected: other_aki.to_vec(),
                        actual: parent_ski.to_vec(),
                    })
                    .context(InvalidChain)
                    .context(InvalidCertificate {
                        id: other.subject_name().to_string(),
                    });
                }
            }
        }

        let other_issuer_name = other.issuer_name();
        let self_subject_name = self.subject_name();
        if other_issuer_name != self_subject_name {
            return Err(CaChainError::IssuerNameMismatch {
                expected: other_issuer_name.to_string(),
                actual: self_subject_name.to_string(),
            })
            .context(InvalidChain)
            .context(InvalidCertificate {
                id: other.subject_name().to_string(),
            });
        }

        Ok(())
    }

    pub fn verify_chain<'a, Chain: Iterator<Item = &'a Cert>>(
        &self,
        chain: Chain,
        now: &UTCDate,
    ) -> Result<(), CertError> {
        self.verify(now).with_context(|| InvalidCertificate {
            id: self.subject_name().to_string(),
        })?;

        let mut current_cert = self;

        for (number_certs, parent_cert) in chain.enumerate() {
            // check basic constraints
            match parent_cert
                .basic_constraints()
                .map(|bc| (bc.ca(), bc.pathlen()))
                .unwrap_or((None, None))
            {
                (Some(false), _) => {
                    return Err(CaChainError::IssuerIsNotCA {
                        issuer_id: parent_cert.subject_name().to_string(),
                    })
                    .context(InvalidChain);
                }
                (_, Some(pathlen)) if usize::from(pathlen) < number_certs => {
                    return Err(CaChainError::TooDeep {
                        cert_id: parent_cert.subject_name().to_string(),
                        pathlen,
                    })
                    .context(InvalidChain);
                }
                _ => {}
            }

            // verify parent
            parent_cert.verify(now).with_context(|| InvalidCertificate {
                id: parent_cert.subject_name().to_string(),
            })?;

            // check parent_cert is the parent of current_cert
            parent_cert.is_parent_of(current_cert)?;

            // validate current cert signature using parent public key
            let hash_type =
                SignatureHashType::from_algorithm_identifier(&current_cert.0.signature_algorithm).context(Signature)?;
            let public_key = &parent_cert.0.tbs_certificate.subject_public_key_info;
            let msg = picky_asn1_der::to_vec(&current_cert.0.tbs_certificate)
                .context(Asn1Serialization {
                    element: "tbs certificate",
                })
                .with_context(|| InvalidCertificate {
                    id: current_cert.subject_name().to_string(),
                })?;
            hash_type
                .verify(
                    &public_key.clone().into(),
                    &msg,
                    current_cert.0.signature_value.0.payload_view(),
                )
                .context(Signature)
                .with_context(|| InvalidCertificate {
                    id: current_cert.subject_name().to_string(),
                })?;

            current_cert = parent_cert;
        }

        // make sure `current_cert` (the last certificate of the chain) is a root CA
        if current_cert.ty() != CertType::Root {
            return Err(CaChainError::NoRoot).context(InvalidChain);
        }

        Ok(())
    }
}

#[derive(Clone, Debug)]
enum SubjectInfos {
    Csr(Csr),
    NameAndPublicKey {
        name: DirectoryName,
        public_key: OwnedPublicKey,
    },
}

#[derive(Clone, Debug)]
struct IssuerInfos<'a> {
    name: DirectoryName,
    key: &'a PrivateKey,
    self_signed: bool,
}

// Statically checks the field actually exists and returns a &'static str of the field name
macro_rules! field_str {
    ($field:ident) => {{
        ::static_assertions::assert_fields!(CertificateBuilderInner: $field);
        stringify!($field)
    }};
}

#[derive(Default, Clone, Debug)]
struct CertificateBuilderInner<'a> {
    valid_from: Option<UTCDate>,
    valid_to: Option<UTCDate>,
    subject_infos: Option<SubjectInfos>,
    issuer_infos: Option<IssuerInfos<'a>>,
    authority_key_identifier: Option<Vec<u8>>,
    ca: Option<bool>,
    pathlen: Option<u8>,
    signature_hash_type: Option<SignatureHashType>,
    key_id_gen_method: Option<KeyIdGenMethod>,
    key_usage: Option<KeyUsage>,
    extended_key_usage: Option<ExtendedKeyUsage>,
    subject_alt_name: Option<GeneralNames>,
    issuer_alt_name: Option<GeneralNames>,
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
    #[inline]
    pub fn valididy(&self, valid_from: UTCDate, valid_to: UTCDate) -> &Self {
        let mut inner_mut = self.inner.borrow_mut();
        inner_mut.valid_from = Some(valid_from);
        inner_mut.valid_to = Some(valid_to);
        drop(inner_mut);
        self
    }

    /// Required (alternatives: `subject_from_csr`, `self_signed`)
    #[inline]
    pub fn subject(&self, subject_name: DirectoryName, public_key: OwnedPublicKey) -> &Self {
        self.inner.borrow_mut().subject_infos = Some(SubjectInfos::NameAndPublicKey {
            name: subject_name,
            public_key,
        });
        self
    }

    /// Required (alternatives: `subject`, `self_signed`)
    #[inline]
    pub fn subject_from_csr(&self, csr: Csr) -> &Self {
        self.inner.borrow_mut().subject_infos = Some(SubjectInfos::Csr(csr));
        self
    }

    /// Required (alternative: `self_signed`, `issuer_cert`)
    #[inline]
    pub fn issuer(&self, issuer_name: DirectoryName, issuer_key: &'a PrivateKey) -> &Self {
        self.inner.borrow_mut().issuer_infos = Some(IssuerInfos {
            name: issuer_name,
            key: issuer_key,
            self_signed: false,
        });
        self
    }

    /// Required (alternative: `issuer`, `issuer_cert`)
    #[inline]
    pub fn self_signed(&self, name: DirectoryName, key: &'a PrivateKey) -> &Self {
        self.inner.borrow_mut().issuer_infos = Some(IssuerInfos {
            name,
            key,
            self_signed: true,
        });
        self
    }

    /// Required (alternative: `issuer`, `self_signed`)
    #[inline]
    pub fn issuer_cert(&self, issuer_cert: &Cert, issuer_key: &'a PrivateKey) -> &Self {
        let builder = self.issuer(issuer_cert.subject_name(), &issuer_key);

        if let Ok(issuer_ski) = issuer_cert.subject_key_identifier() {
            self.authority_key_identifier(issuer_ski.to_vec())
        } else {
            builder
        }
    }

    /// Optional (alternative: `issuer_cert`, `self_signed`)
    #[inline]
    pub fn authority_key_identifier(&self, aki: Vec<u8>) -> &Self {
        self.inner.borrow_mut().authority_key_identifier = Some(aki);
        self
    }

    /// Optional
    #[inline]
    pub fn ca(&self, ca: bool) -> &Self {
        self.inner.borrow_mut().ca = Some(ca);
        self
    }

    /// Optional
    #[inline]
    pub fn pathlen(&self, pathlen: u8) -> &Self {
        self.inner.borrow_mut().pathlen = Some(pathlen);
        self
    }

    /// Optional
    #[inline]
    pub fn signature_hash_type(&self, signature_hash_type: SignatureHashType) -> &Self {
        self.inner.borrow_mut().signature_hash_type = Some(signature_hash_type);
        self
    }

    /// Optional
    #[inline]
    pub fn key_id_gen_method(&self, key_id_gen_method: KeyIdGenMethod) -> &Self {
        self.inner.borrow_mut().key_id_gen_method = Some(key_id_gen_method);
        self
    }

    /// Optional
    #[inline]
    pub fn key_usage(&self, key_usage: KeyUsage) -> &Self {
        self.inner.borrow_mut().key_usage = Some(key_usage);
        self
    }

    /// Optional
    #[inline]
    pub fn extended_key_usage(&self, extended_key_usage: ExtendedKeyUsage) -> &Self {
        self.inner.borrow_mut().extended_key_usage = Some(extended_key_usage);
        self
    }

    /// Optional
    #[inline]
    pub fn subject_alt_name(&self, subject_alt_name: GeneralNames) -> &Self {
        self.inner.borrow_mut().subject_alt_name = Some(subject_alt_name);
        self
    }

    /// Optional
    #[inline]
    pub fn issuer_alt_name(&self, issuer_alt_name: GeneralNames) -> &Self {
        self.inner.borrow_mut().issuer_alt_name = Some(issuer_alt_name);
        self
    }

    pub fn build(&self) -> Result<Cert, CertError> {
        let mut inner = self.inner.borrow_mut();

        let valid_from = inner.valid_from.take().ok_or(CertError::MissingBuilderArgument {
            arg: field_str!(valid_from),
        })?;
        let valid_to = inner.valid_to.take().ok_or(CertError::MissingBuilderArgument {
            arg: field_str!(valid_to),
        })?;

        let signature_hash_type = inner.signature_hash_type.take().unwrap_or(SignatureHashType::RsaSha256);

        let key_id_gen_method = inner
            .key_id_gen_method
            .take()
            .unwrap_or(KeyIdGenMethod::SPKFullDER(KeyIdHashAlgo::Sha256));

        let issuer_infos = inner.issuer_infos.take().ok_or(CertError::MissingBuilderArgument {
            arg: field_str!(issuer_infos),
        })?;
        let (issuer_name, issuer_key, aki, subject_infos) = {
            let (aki, subject_infos) = if issuer_infos.self_signed {
                let public_key = issuer_infos.key.to_public_key();
                let aki = key_id_gen_method
                    .generate_from(&public_key)
                    .context(KeyIdGen)
                    .context(CertGeneration)?;
                let subject_infos = SubjectInfos::NameAndPublicKey {
                    name: issuer_infos.name.clone(),
                    public_key,
                };
                (aki, subject_infos)
            } else {
                let aki = inner
                    .authority_key_identifier
                    .take()
                    .ok_or(CertError::MissingBuilderArgument {
                        arg: field_str!(authority_key_identifier),
                    })?;
                let subject_infos = inner.subject_infos.take().ok_or(CertError::MissingBuilderArgument {
                    arg: field_str!(subject_infos),
                })?;
                (aki, subject_infos)
            };

            (issuer_infos.name, issuer_infos.key, aki, subject_infos)
        };
        let (subject_name, subject_public_key) = match subject_infos {
            SubjectInfos::Csr(csr) => {
                csr.verify().context(InvalidCsr)?;
                csr.into_subject_infos()
            }
            SubjectInfos::NameAndPublicKey { name, public_key } => (name, public_key),
        };

        let ca = inner.ca.take().unwrap_or(false);
        let pathlen = inner.pathlen.take();
        let key_usage_opt = inner.key_usage.take();
        let extended_key_usage_opt = inner.extended_key_usage.take();
        let subject_alt_name_opt = inner.subject_alt_name.take();
        let issuer_alt_name_opt = inner.issuer_alt_name.take();

        drop(inner);

        let serial_number = generate_serial_number();

        let validity = Validity {
            not_before: valid_from.into(),
            not_after: valid_to.into(),
        };

        let extensions = {
            let mut extensions = Vec::new();

            // key usage + basic constraints
            if let Some(key_usage) = key_usage_opt {
                if key_usage.digital_signature() {
                    extensions.push(Extension::new_basic_constraints(ca, pathlen).into_critical());
                } else {
                    extensions.push(Extension::new_basic_constraints(ca, pathlen).into_non_critical());
                }
                extensions.push(Extension::new_key_usage(key_usage));
            } else {
                extensions.push(Extension::new_basic_constraints(ca, pathlen).into_non_critical());
            }

            // eku
            if let Some(extended_key_usage) = extended_key_usage_opt {
                extensions.push(Extension::new_extended_key_usage(extended_key_usage));
            }

            // san
            if let Some(san) = subject_alt_name_opt {
                extensions.push(Extension::new_subject_alt_name(san));
            }

            // ian
            if let Some(ian) = issuer_alt_name_opt {
                extensions.push(Extension::new_issuer_alt_name(ian));
            }

            // ski
            let ski = key_id_gen_method
                .generate_from(&subject_public_key)
                .context(KeyIdGen)
                .context(CertGeneration)?;
            extensions.push(Extension::new_subject_key_identifier(ski));

            // aki
            extensions.push(Extension::new_authority_key_identifier(
                KeyIdentifier::from(aki),
                None,
                None,
            ));

            Extensions(extensions)
        };

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

        let tbs_der = picky_asn1_der::to_vec(&tbs_certificate)
            .context(Asn1Serialization {
                element: "tbs certificate",
            })
            .context(CertGeneration)?;
        let signature_value = BitString::with_bytes(
            signature_hash_type
                .sign(&tbs_der, issuer_key)
                .context(Signature)
                .context(CertGeneration)?,
        );

        Ok(Cert(Certificate {
            tbs_certificate,
            signature_algorithm: signature_hash_type.into(),
            signature_value: signature_value.into(),
        }))
    }
}

fn generate_serial_number() -> Vec<u8> {
    let x = rand::random::<u32>();
    let b1 = ((x >> 24) & 0xff) as u8;
    let b2 = ((x >> 16) & 0xff) as u8;
    let b3 = ((x >> 8) & 0xff) as u8;
    let b4 = (x & 0xff) as u8;
    vec![b1, b2, b3, b4]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pem::{parse_pem, Pem};

    #[test]
    fn read_pem_and_parse_certificate() {
        let pem = parse_pem(crate::test_files::INTERMEDIATE_CA.as_bytes()).unwrap();
        let cert = Cert::from_der(pem.data()).unwrap();

        assert_eq!(cert.serial_number(), &vec![1]);
        assert_eq!(
            Into::<String>::into(cert.signature_algorithm().oid()).as_str(),
            oids::SHA1_WITH_RSA_ENCRYPTION
        );
        assert_eq!(cert.valid_not_before(), UTCDate::new(2011, 2, 12, 14, 44, 6).unwrap());
        assert_eq!(cert.valid_not_after(), UTCDate::new(2021, 2, 12, 14, 44, 6).unwrap());

        assert_eq!(cert.issuer_name().to_string(), "C=NL,O=PolarSSL,CN=PolarSSL Test CA");
    }

    #[test]
    fn get_identifier() {
        let pem = crate::test_files::RSA_2048_PK_1
            .parse::<Pem>()
            .expect("couldn't parse pem");
        let private_key = PrivateKey::from_pkcs8(pem.data()).expect("couldn't extract private key from pkcs8");

        // validity
        let valid_from = UTCDate::ymd(2019, 10, 10).unwrap();
        let valid_to = UTCDate::ymd(2019, 10, 11).unwrap();

        let root = CertificateBuilder::new()
            .valididy(valid_from, valid_to)
            .self_signed(DirectoryName::new_common_name("test"), &private_key)
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
        let kid = "c4a7b1a47b2c71fadbe14b9075ffc41560858910";
        let pem = crate::test_files::ROOT_CA.parse::<Pem>().expect("couldn't parse PEM");
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
            .valididy(UTCDate::ymd(2065, 6, 15).unwrap(), UTCDate::ymd(2070, 6, 15).unwrap())
            .self_signed(DirectoryName::new_common_name("TheFuture.usodakedo Root CA"), &root_key)
            .ca(true)
            .signature_hash_type(SignatureHashType::RsaSha512)
            .key_id_gen_method(KeyIdGenMethod::SPKFullDER(KeyIdHashAlgo::Sha384))
            .build()
            .expect("couldn't build root ca");
        assert_eq!(root.ty(), CertType::Root);

        let intermediate = CertificateBuilder::new()
            .valididy(UTCDate::ymd(2068, 1, 1).unwrap(), UTCDate::ymd(2071, 1, 1).unwrap())
            .subject(
                DirectoryName::new_common_name("TheFuture.usodakedo Authority"),
                intermediate_key.to_public_key(),
            )
            .issuer_cert(&root, &root_key)
            .signature_hash_type(SignatureHashType::RsaSha224)
            .key_id_gen_method(KeyIdGenMethod::SPKValueHashedLeftmost160(KeyIdHashAlgo::Sha1))
            .ca(true)
            .pathlen(0)
            .build()
            .expect("couldn't build intermediate ca");
        assert_eq!(intermediate.ty(), CertType::Intermediate);

        let csr = Csr::generate(
            DirectoryName::new_common_name("ChillingInTheFuture.usobakkari"),
            &leaf_key,
            SignatureHashType::RsaSha1,
        )
        .unwrap();

        let signed_leaf = CertificateBuilder::new()
            .valididy(UTCDate::ymd(2069, 1, 1).unwrap(), UTCDate::ymd(2072, 1, 1).unwrap())
            .subject_from_csr(csr)
            .issuer_cert(&intermediate, &intermediate_key)
            .signature_hash_type(SignatureHashType::RsaSha384)
            .key_id_gen_method(KeyIdGenMethod::SPKFullDER(KeyIdHashAlgo::Sha512))
            .pathlen(0) // not meaningful in non-CA certificates
            .build()
            .expect("couldn't build signed leaf");
        assert_eq!(signed_leaf.ty(), CertType::Leaf);

        let chain = [intermediate, root];

        signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2069, 10, 1).unwrap())
            .expect("couldn't verify chain");

        let expired_err = signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2080, 10, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            expired_err.to_string(),
            "invalid certificate \'CN=ChillingInTheFuture.usobakkari\': \
             certificate expired (not after: 2072-01-01 00:00:00, now: 2080-10-01 00:00:00)"
        );

        let intermediate_expired_err = signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2071, 6, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            intermediate_expired_err.to_string(),
            "invalid certificate \'CN=TheFuture.usodakedo Authority\': \
             certificate expired (not after: 2071-01-01 00:00:00, now: 2071-06-01 00:00:00)"
        );

        let root_expired_err = signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2070, 6, 16).unwrap())
            .unwrap_err();
        assert_eq!(
            root_expired_err.to_string(),
            "invalid certificate \'CN=TheFuture.usodakedo Root CA\': \
             certificate expired (not after: 2070-06-15 00:00:00, now: 2070-06-16 00:00:00)"
        );

        let still_in_2019_err = signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2019, 11, 14).unwrap())
            .unwrap_err();
        assert_eq!(
            still_in_2019_err.to_string(),
            "invalid certificate \'CN=ChillingInTheFuture.usobakkari\': \
             certificate is not yet valid (not before: 2069-01-01 00:00:00, now: 2019-11-14 00:00:00)"
        );
    }

    #[test]
    fn malicious_ca_chain() {
        let root_key = parse_key(crate::test_files::RSA_2048_PK_1);
        let intermediate_key = parse_key(crate::test_files::RSA_2048_PK_2);
        let leaf_key = parse_key(crate::test_files::RSA_2048_PK_3);
        let malicious_root_key = parse_key(crate::test_files::RSA_2048_PK_4);

        let root = CertificateBuilder::new()
            .valididy(UTCDate::ymd(2065, 6, 15).unwrap(), UTCDate::ymd(2070, 6, 15).unwrap())
            .self_signed(DirectoryName::new_common_name("VerySafe Root CA"), &root_key)
            .ca(true)
            .pathlen(1)
            .signature_hash_type(SignatureHashType::RsaSha1)
            .key_id_gen_method(KeyIdGenMethod::SPKFullDER(KeyIdHashAlgo::Sha224))
            .build()
            .expect("couldn't build root ca");

        let intermediate = CertificateBuilder::new()
            .valididy(UTCDate::ymd(2068, 1, 1).unwrap(), UTCDate::ymd(2071, 1, 1).unwrap())
            .subject(
                DirectoryName::new_common_name("V.E.R.Y Legitimate VerySafe Authority"),
                intermediate_key.to_public_key(),
            )
            .issuer_cert(&root, &malicious_root_key)
            .signature_hash_type(SignatureHashType::RsaSha512)
            .key_id_gen_method(KeyIdGenMethod::SPKValueHashedLeftmost160(KeyIdHashAlgo::Sha384))
            .ca(true)
            .pathlen(0)
            .build()
            .expect("couldn't build intermediate ca");

        let csr = Csr::generate(
            DirectoryName::new_common_name("I Trust This V.E.R.Y Legitimate Intermediate Certificate"),
            &leaf_key,
            SignatureHashType::RsaSha1,
        )
        .unwrap();

        let signed_leaf = CertificateBuilder::new()
            .valididy(UTCDate::ymd(2069, 1, 1).unwrap(), UTCDate::ymd(2072, 1, 1).unwrap())
            .subject_from_csr(csr)
            .issuer_cert(&intermediate, &intermediate_key)
            .signature_hash_type(SignatureHashType::RsaSha224)
            .key_id_gen_method(KeyIdGenMethod::SPKFullDER(KeyIdHashAlgo::Sha384))
            .build()
            .expect("couldn't build signed leaf");

        let chain = [intermediate, root];

        let root_missing_err = signed_leaf
            .verify_chain(chain[..1].iter(), &UTCDate::ymd(2069, 10, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            root_missing_err.to_string(),
            "CA chain error: chain is missing a root certificate"
        );

        let invalid_sig_err = signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2069, 10, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            invalid_sig_err.to_string(),
            "invalid certificate \'CN=V.E.R.Y Legitimate VerySafe Authority\': signature error: invalid signature"
        );
    }

    #[test]
    fn invalid_basic_constraints_chain() {
        let root_key = parse_key(crate::test_files::RSA_2048_PK_1);
        let intermediate_key = parse_key(crate::test_files::RSA_2048_PK_2);
        let leaf_key = parse_key(crate::test_files::RSA_2048_PK_3);

        let root = CertificateBuilder::new()
            .valididy(UTCDate::ymd(2065, 6, 15).unwrap(), UTCDate::ymd(2070, 6, 15).unwrap())
            .self_signed(DirectoryName::new_common_name("VerySafe Root CA"), &root_key)
            .ca(true)
            .pathlen(0)
            .build()
            .expect("couldn't build root ca");

        let intermediate = CertificateBuilder::new()
            .valididy(UTCDate::ymd(2068, 1, 1).unwrap(), UTCDate::ymd(2071, 1, 1).unwrap())
            .subject(
                DirectoryName::new_common_name("V.E.R.Y Legitimate VerySafe Authority"),
                intermediate_key.to_public_key(),
            )
            .issuer_cert(&root, &root_key)
            .ca(true)
            .pathlen(0)
            .build()
            .expect("couldn't build intermediate ca");

        let csr = Csr::generate(
            DirectoryName::new_common_name("I Trust This V.E.R.Y Legitimate Intermediate Certificate"),
            &leaf_key,
            SignatureHashType::RsaSha1,
        )
        .unwrap();

        let signed_leaf = CertificateBuilder::new()
            .valididy(UTCDate::ymd(2069, 1, 1).unwrap(), UTCDate::ymd(2072, 1, 1).unwrap())
            .subject_from_csr(csr.clone())
            .issuer_cert(&intermediate, &intermediate_key)
            .build()
            .expect("couldn't build signed leaf");

        let chain = [intermediate.clone(), root.clone()];

        let invalid_pathlen_err = signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2069, 10, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            invalid_pathlen_err.to_string(),
            "CA chain error: chain depth doesn\'t satisfy basic constraints extension: \
             certificate \'CN=VerySafe Root CA\' has pathlen of 0"
        );

        let invalid_issuer_signed_leaf = CertificateBuilder::new()
            .valididy(UTCDate::ymd(2069, 1, 1).unwrap(), UTCDate::ymd(2072, 1, 1).unwrap())
            .subject_from_csr(csr)
            .issuer_cert(&signed_leaf, &leaf_key)
            .build()
            .expect("couldn't build invalid issuer signed leaf");

        let chain = [signed_leaf, intermediate.clone(), root.clone()];

        let invalid_issuer_err = invalid_issuer_signed_leaf
            .verify_chain(chain.iter(), &UTCDate::ymd(2069, 10, 1).unwrap())
            .unwrap_err();
        assert_eq!(
            invalid_issuer_err.to_string(),
            "CA chain error: issuer certificate \'CN=I Trust This V.E.R.Y Legitimate Intermediate Certificate\' is not a CA"
        );
    }
}
