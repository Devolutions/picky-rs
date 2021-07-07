use crate::hash::{HashAlgorithm, UnsupportedHashAlgorithmError};
use crate::key::PrivateKey;
use crate::pem::Pem;
use crate::signature::{SignatureAlgorithm, SignatureError};
use crate::x509::certificate::{Cert, CertError, ValidityCheck};
use crate::x509::date::UTCDate;
use crate::x509::extension::ExtendedKeyUsage;
use crate::x509::pkcs7::{self, Pkcs7, PKCS7_PEM_LABEL};
use crate::x509::utils::{from_der, from_pem, to_der, to_pem};
use picky_asn1::restricted_string::CharSetError;
use picky_asn1::tag::Tag;
use picky_asn1::wrapper::{Asn1SetOf, ExplicitContextTag0, ExplicitContextTag1};
use picky_asn1_der::Asn1DerError;
use picky_asn1_x509::algorithm_identifier::{AlgorithmIdentifier, UnsupportedAlgorithmError};
use picky_asn1_x509::cmsversion::CmsVersion;
use picky_asn1_x509::extension::ExtensionView;
use picky_asn1_x509::pkcs7::content_info::{
    ContentValue, EncapsulatedContentInfo, SpcAttributeAndOptionalValue, SpcIndirectDataContent, SpcLink,
    SpcPeImageData, SpcPeImageFlags, SpcSpOpusInfo, SpcString,
};
use picky_asn1_x509::pkcs7::crls::RevocationInfoChoices;
use picky_asn1_x509::pkcs7::signed_data::{CertificateSet, DigestAlgorithmIdentifiers, SignedData, SignersInfos};
use picky_asn1_x509::pkcs7::signer_info::{
    Attributes, CertificateSerialNumber, DigestAlgorithmIdentifier, IssuerAndSerialNumber,
    SignatureAlgorithmIdentifier, SignatureValue, SignerIdentifier, SignerInfo,
};
use picky_asn1_x509::pkcs7::Pkcs7Certificate;
use picky_asn1_x509::{oids, Attribute, AttributeValues, Certificate, DigestInfo, Name, ShaVariant};

use std::cell::RefCell;
use std::convert::TryFrom;
use thiserror::Error;

#[cfg(feature = "ctl")]
use crate::x509::pkcs7::ctl::{self, CertificateTrustList};
#[cfg(feature = "ctl")]
use picky_asn1_x509::pkcs7::ctl::CTLEntryAttributeValues;

#[derive(Debug, Error)]
pub enum AuthenticodeError {
    #[error(transparent)]
    Asn1DerError(#[from] Asn1DerError),
    #[error("The Authenticode signature CA is not trusted")]
    CAIsNotTrusted,
    #[error("CA certificate was revoked")]
    CaCertificateRevoked,
    #[error("CA certificate was revoked(since: {not_after}, now: {now})")]
    CaCertificateExpired { not_after: UTCDate, now: UTCDate },
    #[error("CA certificate is not yet valid(not before:  {not_before}, now: {now})")]
    CaCertificateNotYetValid { not_before: UTCDate, now: UTCDate },
    #[error(transparent)]
    CertError(#[from] CertError),
    #[error("Digest algorithm mismatch: {description}")]
    DigestAlgorithmMismatch { description: String },
    #[error("SignerInfo encrypted_digest does not match hash of authenticated attributes of ContentInfo")]
    HashMismatch,
    #[error("Authenticode signatures support only one signer, digestAlgorithms must contain only one digestAlgorithmIdentifier, but {incorrect_count} entries present")]
    IncorrectDigestAlgorithmsCount { incorrect_count: usize },
    #[error(
        "Authenticode use issuerAndSerialNumber to identifier signer, but got subjectKeyIdentifier identification"
    )]
    IncorrectSignerIdentifier,
    #[error("Incorrect version. Expected: {expected}, but got {got}")]
    IncorrectVersion { expected: u32, got: u32 },
    #[error("Authenticode must contain only one SingerInfo, but got {count}")]
    MultipleSingerInfo { count: usize },
    #[error("EncapsulatedContentInfo is missing")]
    NoEncapsulatedContentInfo,
    #[error("EncapsulatedContentInfo should contain SpcIndirectDataContent")]
    NoSpcIndirectDataContent,
    #[error("Certificates must contain at least Leaf and Intermediate certificates, but got no certificates")]
    NoCertificates,
    #[error("No Intermediate certificate")]
    NoIntermediateCertificate,
    #[error("The signing certificate must contain the extended key usage (EKU) value for code signing")]
    NoEKUCodeSigning,
    #[error("PKCS9_MESSAGE_DIGEST attribute is absent")]
    NoMessageDigest,
    #[error("Can't find certificate which the issuer is {issuer:?} and serial_number is {serial_number:?}")]
    NoCertificatesAssociatedWithIssuerAndSerialNumber { issuer: Name, serial_number: Vec<u8> },
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
    #[error("the program name has invalid charset")]
    ProgramNameCharSet(#[from] CharSetError),
    #[error(transparent)]
    UnsupportedHashAlgorithmError(UnsupportedHashAlgorithmError),
    #[error(transparent)]
    UnsupportedAlgorithmError(UnsupportedAlgorithmError),
    #[cfg(feature = "ctl")]
    #[error(transparent)]
    CtlError(#[from] ctl::CtlError),
}

type AuthenticodeResult<T> = Result<T, AuthenticodeError>;

#[derive(Clone, Debug, PartialEq)]
pub struct AuthenticodeSignature(pub Pkcs7);

impl AuthenticodeSignature {
    pub fn new(
        pkcs7: Pkcs7,
        file_hash: &[u8],
        hash_algo: ShaVariant,
        private_key: &PrivateKey,
        program_name: Option<String>,
    ) -> Result<Self, AuthenticodeError> {
        let Pkcs7Certificate { oid, signed_data } = pkcs7.0;

        let SignedData { certificates, .. } = signed_data.0;

        let digest_algorithm = AlgorithmIdentifier::new_sha(hash_algo);

        let data = SpcAttributeAndOptionalValue {
            ty: oids::spc_pe_image_dataobj().into(),
            value: SpcPeImageData {
                flags: SpcPeImageFlags::default(),
                file: Default::default(),
            },
        };

        let message_digest = DigestInfo {
            oid: digest_algorithm.clone(),
            digest: file_hash.to_vec().into(),
        };

        let program_name = program_name
            .map(SpcString::try_from)
            .transpose()?
            .map(ExplicitContextTag0);

        let mut raw_spc_indirect_data_content = picky_asn1_der::to_vec(&data)?;

        let mut raw_message_digest = picky_asn1_der::to_vec(&message_digest)?;

        raw_spc_indirect_data_content.append(&mut raw_message_digest);

        let message_digest_value = HashAlgorithm::try_from(hash_algo)
            .map_err(AuthenticodeError::UnsupportedHashAlgorithmError)?
            .digest(raw_spc_indirect_data_content.as_ref());

        let authenticated_attributes = vec![
            Attribute {
                ty: oids::content_type().into(),
                value: AttributeValues::ContentType(Asn1SetOf(vec![oids::spc_indirect_data_objid().into()])),
            },
            Attribute {
                ty: oids::spc_sp_opus_info_objid().into(),
                value: AttributeValues::SpcSpOpusInfo(Asn1SetOf(vec![SpcSpOpusInfo {
                    program_name,
                    more_info: Some(ExplicitContextTag1(SpcLink::default())),
                }])),
            },
            Attribute {
                ty: oids::message_digest().into(),
                value: AttributeValues::MessageDigest(Asn1SetOf(vec![message_digest_value.into()])),
            },
        ];

        let content = SpcIndirectDataContent { data, message_digest };

        let content_info = EncapsulatedContentInfo {
            content_type: oids::spc_indirect_data_objid().into(),
            content: Some(ContentValue::SpcIndirectDataContent(content).into()),
        };

        // The signing certificate must contain either the extended key usage (EKU) value for code signing,
        // or the entire certificate chain must contain no EKUs
        let certificates = certificates
            .0
            .into_iter()
            .filter_map(|cert| Cert::try_from(cert).ok())
            .collect::<Vec<Cert>>();
        check_eku_code_signing(&certificates)?;

        let certificates = certificates
            .into_iter()
            .map(Certificate::from)
            .collect::<Vec<Certificate>>();

        let signing_cert = certificates.get(0).ok_or(AuthenticodeError::NoCertificates)?;

        let issuer_and_serial_number = IssuerAndSerialNumber {
            issuer: signing_cert.tbs_certificate.issuer.clone(),
            serial_number: CertificateSerialNumber(signing_cert.tbs_certificate.serial_number.clone()),
        };

        let digest_encryption_algorithm = AlgorithmIdentifier::new_rsa_encryption_with_sha(hash_algo)
            .map_err(AuthenticodeError::UnsupportedAlgorithmError)?;

        let signature_algo = SignatureAlgorithm::from_algorithm_identifier(&digest_encryption_algorithm)?;

        let mut auth_raw_data = picky_asn1_der::to_vec(&authenticated_attributes)?;
        // According to the RFC:
        //
        // "[...] The Attributes value's tag is SET OF, and the DER encoding ofs
        // the SET OF tag, rather than of the IMPLICIT [0] tag [...]"
        auth_raw_data[0] = Tag::SET.number();

        let encrypted_digest = SignatureValue(signature_algo.sign(auth_raw_data.as_ref(), private_key)?.into());

        let singer_info = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial_number),
            digest_algorithm: DigestAlgorithmIdentifier(digest_algorithm.clone()),
            signed_attrs: Attributes(authenticated_attributes).into(),
            signature_algorithm: SignatureAlgorithmIdentifier(AlgorithmIdentifier::new_rsa_encryption()),
            signature: encrypted_digest,
        };

        // certificates contains the signer certificate and any intermediate certificates,
        // but typically does not contain the root certificate
        let certificates = CertificateSet(certificates.into_iter().take(2).collect::<Vec<Certificate>>());

        let signed_data = SignedData {
            version: CmsVersion::V1,
            digest_algorithms: DigestAlgorithmIdentifiers(vec![digest_algorithm].into()),
            content_info,
            certificates,
            crls: Some(RevocationInfoChoices::default()),
            signers_infos: SignersInfos(vec![singer_info].into()),
        };

        Ok(AuthenticodeSignature(Pkcs7::from(Pkcs7Certificate {
            oid,
            signed_data: signed_data.into(),
        })))
    }

    pub fn from_der<V: ?Sized + AsRef<[u8]>>(data: &V) -> AuthenticodeResult<Self> {
        Ok(from_der::<Pkcs7Certificate, V>(data, pkcs7::ELEMENT_NAME)
            .map(Pkcs7::from)
            .map(Self)?)
    }

    pub fn from_pem(pem: &Pem) -> AuthenticodeResult<Self> {
        Ok(from_pem::<Pkcs7Certificate>(pem, PKCS7_PEM_LABEL, pkcs7::ELEMENT_NAME)
            .map(Pkcs7::from)
            .map(Self)?)
    }

    pub fn to_der(&self) -> AuthenticodeResult<Vec<u8>> {
        Ok(to_der(&self.0 .0, pkcs7::ELEMENT_NAME)?)
    }

    pub fn to_pem(&self) -> AuthenticodeResult<Pem> {
        Ok(to_pem(&self.0 .0, PKCS7_PEM_LABEL, pkcs7::ELEMENT_NAME)?)
    }

    pub fn signing_certificate(&self) -> Result<Cert, AuthenticodeError> {
        let signer_infos = &self.0 .0.signed_data.signers_infos.0;

        let signer_info = signer_infos.first().ok_or(AuthenticodeError::MultipleSingerInfo {
            count: signer_infos.len(),
        })?;

        let issuer_and_serial_number = match &signer_info.sid {
            SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial_number) => issuer_and_serial_number,
            SignerIdentifier::SubjectKeyIdentifier(_) => return Err(AuthenticodeError::IncorrectSignerIdentifier),
        };

        self.0
            .certificates()
            .iter()
            .find(|&cert| {
                Name::from(cert.issuer_name()) == issuer_and_serial_number.issuer
                    && cert.serial_number() == &issuer_and_serial_number.serial_number.0
            })
            .cloned()
            .ok_or_else(
                || AuthenticodeError::NoCertificatesAssociatedWithIssuerAndSerialNumber {
                    issuer: issuer_and_serial_number.issuer.clone(),
                    serial_number: issuer_and_serial_number.serial_number.0 .0.clone(),
                },
            )
    }

    pub fn authenticode_verifier(&self) -> AuthenticodeValidator {
        AuthenticodeValidator {
            authenticode_signature: self,
            inner: RefCell::new(AuthenticodeValidatorInner {
                strictness: Default::default(),
                excluded_cert_authorities: Vec::new(),
                now: None,
            }),
        }
    }
}

impl From<Pkcs7> for AuthenticodeSignature {
    fn from(pkcs7: Pkcs7) -> Self {
        AuthenticodeSignature(pkcs7)
    }
}

impl From<AuthenticodeSignature> for Pkcs7 {
    fn from(authenticode_signature: AuthenticodeSignature) -> Self {
        authenticode_signature.0
    }
}

#[derive(Debug, Clone)]
struct AuthenticodeStrictness {
    require_basic_authenticode_validation: bool,
    require_signing_certificate_check: bool,
    require_chain_check: bool,
    require_not_before_check: bool,
    require_not_after_check: bool,
    require_ca_verification_against_ctl: bool,
    exclude_specific_cert_authorities: bool,
}

impl Default for AuthenticodeStrictness {
    fn default() -> Self {
        AuthenticodeStrictness {
            require_basic_authenticode_validation: true,
            require_signing_certificate_check: false,
            require_not_before_check: false,
            require_not_after_check: false,
            require_chain_check: false,
            require_ca_verification_against_ctl: false,
            exclude_specific_cert_authorities: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthenticodeValidatorInner<'a> {
    strictness: AuthenticodeStrictness,
    excluded_cert_authorities: Vec<Name>,
    now: Option<ValidityCheck<'a>>,
}

pub struct AuthenticodeValidator<'a> {
    authenticode_signature: &'a AuthenticodeSignature,
    inner: RefCell<AuthenticodeValidatorInner<'a>>,
}

impl<'a> AuthenticodeValidator<'a> {
    #[inline]
    pub fn exact_date(&self, exact: &'a UTCDate) -> &Self {
        self.inner.borrow_mut().now = Some(ValidityCheck::Exact(exact));
        self
    }

    #[inline]
    pub fn interval_date(&self, lower: &'a UTCDate, upper: &'a UTCDate) -> &Self {
        self.inner.borrow_mut().now = Some(ValidityCheck::Interval { lower, upper });
        self
    }

    #[inline]
    pub fn require_not_before_check(&self) -> &Self {
        self.inner.borrow_mut().strictness.require_not_before_check = true;
        self
    }

    #[inline]
    pub fn ignore_not_before_check(&self) -> &Self {
        self.inner.borrow_mut().strictness.require_not_before_check = false;
        self
    }

    #[inline]
    pub fn require_not_after_check(&self) -> &Self {
        self.inner.borrow_mut().strictness.require_not_after_check = true;
        self
    }

    #[inline]
    pub fn ignore_not_after_check(&self) -> &Self {
        self.inner.borrow_mut().strictness.require_not_after_check = false;
        self
    }

    #[inline]
    pub fn require_signing_certificate_check(&self) -> &Self {
        self.inner.borrow_mut().strictness.require_signing_certificate_check = true;
        self
    }

    #[inline]
    pub fn require_certificates_chain_check(&self) -> &Self {
        self.inner.borrow_mut().strictness.require_chain_check = true;
        self
    }

    #[cfg(feature = "ctl")]
    #[inline]
    pub fn require_ca_against_ctl_check(&self) -> &Self {
        self.inner.borrow_mut().strictness.require_ca_verification_against_ctl = true;
        self
    }

    #[inline]
    pub fn exclude_cert_authorities(&self, excluded_cert_authorities: &'a [Name]) -> &Self {
        self.inner.borrow_mut().strictness.exclude_specific_cert_authorities = true;
        self.inner
            .borrow_mut()
            .excluded_cert_authorities
            .extend_from_slice(excluded_cert_authorities);

        self
    }

    fn verify_authenticode_basic(&self) -> AuthenticodeResult<()> {
        // 1. SignedData version field must be set to 1.
        let version = self.authenticode_signature.0 .0.signed_data.version;
        if version != CmsVersion::V2 {
            return Err(AuthenticodeError::IncorrectVersion {
                expected: 1,
                got: version as u32,
            });
        }

        // 2. It must contain only one singer info.
        let signer_infos = self.authenticode_signature.0.singer_infos();
        if signer_infos.len() != 1 {
            return Err(AuthenticodeError::MultipleSingerInfo {
                count: signer_infos.len(),
            });
        }

        // 3. Signature::digest_algorithm must match ContentInfo::digest_algorithm and SignerInfo::digest_algorithm.
        let content_info = self.authenticode_signature.0.encapsulated_content_info();
        let message_digest = match &content_info.content {
            Some(content_value) => match &content_value.0 {
                ContentValue::SpcIndirectDataContent(spc_indirect_data_content) => {
                    &spc_indirect_data_content.message_digest
                }
                _ => return Err(AuthenticodeError::NoSpcIndirectDataContent),
            },
            None => return Err(AuthenticodeError::NoEncapsulatedContentInfo),
        };

        let signing_certificate = self.authenticode_signature.signing_certificate()?;

        // 5. Authenticode signatures support only one signer, digestAlgorithms must contain only one digestAlgorithmIdentifier.
        let digest_algorithms = self.authenticode_signature.0.digest_algorithms();
        if digest_algorithms.len() != 1 {
            return Err(AuthenticodeError::IncorrectDigestAlgorithmsCount {
                incorrect_count: digest_algorithms.len(),
            });
        }

        // 6. Given the x509 certificate, compare SignerInfo::encrypted_digest against hash of authenticated attributes and hash of ContentInfo
        let digest_algorithm = digest_algorithms
            .first()
            .expect("One digest algorithm should exists at this point");
        if digest_algorithm != &message_digest.oid {
            return Err(AuthenticodeError::DigestAlgorithmMismatch {
                description: "Signature digest algorithm does not match EncapsulatedContentInfo digest algorithm"
                    .to_string(),
            });
        }

        let signer_info = signer_infos
            .first()
            .expect("One SignerInfo should exists at this point");
        if digest_algorithm != &signer_info.digest_algorithm.0 {
            return Err(AuthenticodeError::DigestAlgorithmMismatch {
                description: "Signature digest algorithm does not match SignerInfo digest algorithm".to_string(),
            });
        }

        let public_key = signing_certificate.public_key();

        let authenticated_attributes = &signer_info.signed_attrs.0 .0;
        let raw_attributes = picky_asn1_der::to_vec(&authenticated_attributes)?;

        let signature_algorithm = SignatureAlgorithm::from_algorithm_identifier(digest_algorithm)?;
        signature_algorithm
            .verify(public_key, &raw_attributes, &signer_info.signature.0 .0)
            .map_err(AuthenticodeError::SignatureError)?;

        // 7. PKCS9_MESSAGE_DIGEST attribute exists and that its value matches hash of ContentInfo.
        let message_digest_attr = authenticated_attributes
            .iter()
            .find(|attr| matches!(attr.value, AttributeValues::MessageDigest(_)))
            .ok_or(AuthenticodeError::NoMessageDigest)?;

        if let AttributeValues::MessageDigest(message_digest_attr_val) = &message_digest_attr.value {
            if message_digest_attr_val
                .0
                .first()
                .expect("At least one element is always present in Asn1SetOf AttributeValues")
                != &message_digest.digest.0
            {
                return Err(AuthenticodeError::HashMismatch);
            }
        }

        // 8. The signing certificate must contain either the extended key usage (EKU) value for code signing,
        // or the entire certificate chain must contain no EKUs
        let certificates = self.authenticode_signature.0.certificates();
        check_eku_code_signing(&certificates)?;

        Ok(())
    }

    fn verify_certificates_chain(&self) -> AuthenticodeResult<()> {
        let signing_certificate = self.authenticode_signature.signing_certificate()?;

        let mut certificates = self.authenticode_signature.0.certificates();
        if let Some(pos) = certificates.iter().position(|cert| cert == &signing_certificate) {
            certificates.remove(pos);
        }

        let cert_validator = signing_certificate.verifier();
        let inner = self.inner.borrow_mut();
        let cert_validator = if inner.strictness.require_chain_check {
            cert_validator.require_chain_check().chain(certificates.iter())
        } else {
            &cert_validator
        };

        let cert_validator = match inner.now {
            Some(ValidityCheck::Exact(exact)) => cert_validator.exact_date(exact),
            Some(ValidityCheck::Interval { lower, upper }) => cert_validator.interval_date(lower, upper),
            None => cert_validator,
        };

        let cert_validator = if inner.strictness.require_not_after_check {
            cert_validator.require_not_after_check()
        } else {
            cert_validator
        };

        let cert_validator = if inner.strictness.require_not_before_check {
            cert_validator.require_not_before_check()
        } else {
            cert_validator
        };

        cert_validator.verify()?;

        Ok(())
    }

    #[cfg(feature = "ctl")]
    fn verify_ca_certificate_against_ctl(&self, ca_name: &Name) -> AuthenticodeResult<()> {
        use chrono::{DateTime, Duration, NaiveDate, Utc};
        use picky_asn1::wrapper::OctetStringAsn1;
        use std::ops::Add;

        // In CTL time in a OctetString encoded as 64 bits Windows FILETIME LE
        let time_octet_string_to_utc_time = |time: &OctetStringAsn1| -> DateTime<Utc> {
            let since: DateTime<Utc> = DateTime::from_utc(NaiveDate::from_ymd(1601, 1, 1).and_hms(0, 0, 0), Utc);
            since.add(Duration::seconds(
                i64::from_le_bytes([
                    time.0[0], time.0[1], time.0[2], time.0[3], time.0[4], time.0[5], time.0[6], time.0[7],
                ]) / 10_000_000,
            ))
        };

        let raw_ca_name = picky_asn1_der::to_vec(ca_name)?;
        let ca_name_md5_digest = HashAlgorithm::MD5.digest(&raw_ca_name);

        let ctl = CertificateTrustList::new()?;
        let clt_entries = ctl.ctl_entries()?;

        // find the CA certificate info by its md5 name digest
        let ca_ctl_entry_attributes = clt_entries
            .iter()
            .find(|&ctl_entry| {
                ctl_entry.attributes.0.iter().any(|attr| match &attr.value {
                    CTLEntryAttributeValues::CertSubjectNameMd5HashPropId(ca_cert_md5_hash) => {
                        match &ca_cert_md5_hash.0.first() {
                            Some(ca_cert_md5_hash) => ca_cert_md5_hash.0 == ca_name_md5_digest,
                            None => false,
                        }
                    }
                    _ => false,
                })
            })
            .ok_or(AuthenticodeError::CAIsNotTrusted)?;

        // check if the CA certificate was revoked
        if let Some(CTLEntryAttributeValues::CertDisallowedFiletimePropId(when_ca_cert_was_revoked)) =
            ca_ctl_entry_attributes
                .attributes
                .0
                .iter()
                .find(|attr| matches!(attr.value, CTLEntryAttributeValues::CertDisallowedFiletimePropId(_)))
                .map(|attr| &attr.value)
        {
            let when_ca_cert_was_revoked = when_ca_cert_was_revoked
                .0
                .first()
                .expect("Asn1SetOf CertDisallowedFiletimePropId should contain exactly one value");

            if when_ca_cert_was_revoked.0.is_empty() || when_ca_cert_was_revoked.0.len() < 8 {
                return Err(AuthenticodeError::CaCertificateRevoked);
            }

            let not_after = time_octet_string_to_utc_time(when_ca_cert_was_revoked);
            let now = Utc::now();
            if not_after < now {
                return Err(AuthenticodeError::CaCertificateExpired {
                    not_after: not_after.into(),
                    now: now.into(),
                });
            }
        }

        // check if the CA certificate is not yet valid
        if let Some(CTLEntryAttributeValues::UnknownReservedPropId126(not_before)) = ca_ctl_entry_attributes
            .attributes
            .0
            .iter()
            .find(|attr| matches!(attr.value, CTLEntryAttributeValues::UnknownReservedPropId126(_)))
            .map(|attr| &attr.value)
        {
            let not_before = not_before
                .0
                .first()
                .expect("Asn1SetOf UnknownReservedPropId126 should contain exactly one value");

            let not_before = time_octet_string_to_utc_time(&not_before);
            let now = Utc::now();

            if not_before > now {
                // UnknownReservedPropId127 appears to be set of EKUs for which the NotBefore-ing applies.
                // check if it contains code signing oid
                if let Some(CTLEntryAttributeValues::UnknownReservedPropId127(set_of_eku_oids)) =
                    ca_ctl_entry_attributes
                        .attributes
                        .0
                        .iter()
                        .find(|attr| matches!(attr.value, CTLEntryAttributeValues::UnknownReservedPropId126(_)))
                        .map(|attr| &attr.value)
                {
                    let set_of_eku_oids = set_of_eku_oids.0.first().expect(
                        "
                    Asn1SetOf UnknownReservedPropId127 should contain exactly one value",
                    );
                    let eku_code_signing_oid = oids::kp_code_signing();
                    if set_of_eku_oids
                        .0
                         .0
                        .iter()
                        .any(|kp_oid| kp_oid == &eku_code_signing_oid)
                    {
                        return Err(AuthenticodeError::CaCertificateNotYetValid {
                            not_before: not_before.into(),
                            now: now.into(),
                        });
                    }
                } else {
                    return Err(AuthenticodeError::CaCertificateNotYetValid {
                        not_before: not_before.into(),
                        now: now.into(),
                    });
                }
            }
        }

        Ok(())
    }

    pub fn verify(&self) -> AuthenticodeResult<()> {
        let inner = self.inner.borrow();
        if inner.strictness.require_basic_authenticode_validation {
            self.verify_authenticode_basic()?;
        }

        if inner.strictness.require_signing_certificate_check {
            self.verify_certificates_chain()?;
        }

        #[cfg(feature = "ctl")]
        if inner.strictness.require_ca_verification_against_ctl {
            let directory_name = match (
                self.authenticode_signature.0.root_certificate(),
                self.authenticode_signature.0.intermediate_certificate(),
            ) {
                (Some(root_certificate), _) => root_certificate.subject_name(),
                (None, Some(intermediate_certificate)) => intermediate_certificate.issuer_name(),
                _ => {
                    let signing_certificate = self.authenticode_signature.signing_certificate()?;
                    signing_certificate.issuer_name()
                }
            };

            let ca_name = Name::from(directory_name);

            match self.verify_ca_certificate_against_ctl(&ca_name) {
                Ok(()) => {}
                Err(err) => {
                    if !inner.strictness.exclude_specific_cert_authorities
                        || !inner.excluded_cert_authorities.contains(&ca_name)
                    {
                        return Err(err);
                    }
                }
            }
        }

        Ok(())
    }
}

pub(crate) fn check_eku_code_signing(certificates: &[Cert]) -> AuthenticodeResult<()> {
    let code_signing_ext_key_usage: ExtendedKeyUsage = vec![oids::kp_code_signing()].into();

    if certificates
        .iter()
        .flat_map(|cert| cert.extensions().iter())
        .any(|extension| matches!(extension.extn_value(), ExtensionView::ExtendedKeyUsage(_)))
    {
        let signing_cert = certificates.first().ok_or(AuthenticodeError::NoCertificates)?;

        if !signing_cert
            .extensions()
            .iter()
            .any(|extension| extension.extn_value() == ExtensionView::ExtendedKeyUsage(&code_signing_ext_key_usage))
        {
            return Err(AuthenticodeError::NoEKUCodeSigning);
        }
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::pem::parse_pem;
    use crate::x509::certificate::CertType;
    use picky_asn1_x509::Extension;

    const RSA_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
                                   MIIEpAIBAAKCAQEA0vg4PmmJdy1W/ayyuP3ovRBbggAZ98dEY5uzEU23ENaN3jsx\n\
                                   R9zEAAmQ9OZbbJXN33l+PMKY7+5izgI/RlGSNF2s0mdyWEhoRMTxuwpJoFgBkYEE\n\
                                   Jwr40xoLCbw9TpBooJgdYg/n/Fu4NGM7YJdcfKjf3/le7kNTZYPBx09wBkHvkuTD\n\
                                   gpdDDnb5R6sTouD0bCPjC/gZCoRAAlzfuAmAAHVb+i8fkTV32OzokLYcneuLZU/+\n\
                                   FBpR2w9UprfDLWFbPxuOBf+mIGp4WWVN82+3SdEkp/5BRQ//MhGhj7NhEYp+KyWJ\n\
                                   Hm+1iGvrxsgQH+4MQTJGdp838sl+w77QGFZU9QIDAQABAoIBAEBWNkDCSouvpgHC\n\
                                   ctZ7iEhv/pgMk96+RBrkVp2GR7e41pbZElRJ/PPN9wjYXzUkEh5+nILHDYDOAA+3\n\
                                   G7jEE4QotRWNOo+1tSaTsOxLXNyrOf83ix6k9/DY1ljnsQKOg3nGKd/H3gVVqz0+\n\
                                   rdLtFeVmUq+pCsw6d+pTXfr8PLuLPfe8r9fu/BGU2wtINAEuQ4x3/S/JPTm6XnsV\n\
                                   NUW62K/lB7RjXlEqnKMwxcVCu/m0C1HdlwTlHyzktIydjL9Bk1GjGQVt0zC/rfvA\n\
                                   zrlsTPg4UTL6zs4D9B5PPaZMJeBieXaQ0JdqKdJkRm+mPCOEGf+BLz1zHVAVZaSZ\n\
                                   PK8E7NkCgYEA+e7WUOlr4nR6fqvte0ZTewIeG/j2m5gSVjjy8Olh2D3v8q4hZj5s\n\
                                   2jaFJJ7RUGXZdiySodlEpLR2nrrUURC6fGukvbFCW2j/0SotBl53Wa2zJdrU3AZc\n\
                                   b9j7MOyJbJDKJYqdivYJXp7ra4vCs0xAMXfuQD1AWaKlCQxbeyrKWxcCgYEA2BdA\n\
                                   fB7IL0ec3WOsLyGGhcCrGDWIiOlXzk5Fuus+NOEp70/bYCqGpu+tNAxtbY4e+zHp\n\
                                   5gXApKU6PSQ/I/eG/o0WGQCZazfhIGpwORrWHAVxDlxJ+/hlZd6DmTjaIJw1k2gr\n\
                                   D849l1WIEr2Ps8Bv3Y7XeLpnUAQFv1ekfMKxZ9MCgYEA2vtNYfUypmZh0Uy4NZNn\n\
                                   n1Y6pU2cXLWAE3WwPi5toTabXuj8sIWvf/3W6EASqzuhri3dh9tCjoDjka2mSyS6\n\
                                   EDuMSvvdZRP5V/15F6R7M+LCHT+/0svr/7+ATtxgh/PQedYatN9fVD0vjboVrFz5\n\
                                   vZ4T7Mr978tWiDgAi0jxpZ8CgYA/AOiIR+FOB68wzXLSew/hx38bG+CnKoGzYRbr\n\
                                   nNMST+QOJlZr/3orCg6R8l2lZ56Y1sC/lEXKu3HzibHvJqhxZ2ld+NLCdBRrgx0d\n\
                                   STnMCbog2b+oe4/015+++NiAUYs9Y03K2fMTQJjf/ez8F8uF6bPhO1gL+GBEnaUT\n\
                                   yyA2iQKBgQD1KfqZeJtPCwmfdPokblKgorstuMKjMegD/6ztjIFw4c9XkvUAvlD5\n\
                                   MvS4rPuhVYrvouZHJ50bcwccByJ8aCOJxLdH7+bjojMSAgV2kGq+FNh7F1wRcwx8\n\
                                   8Z+DBbeVaCpYSQa5bCr5jG6nIX5v/KbS3HCmAkUzwqGoEsk53yFmKw==\n\
                                   -----END RSA PRIVATE KEY-----";

    const FILE_HASH: [u8; 32] = [
        0xa7, 0x38, 0xda, 0x44, 0x46, 0xa4, 0xe7, 0x8a, 0xb6, 0x47, 0xdb, 0x7e, 0x53, 0x42, 0x7e, 0xb0, 0x79, 0x61,
        0xc9, 0x94, 0x31, 0x7f, 0x4c, 0x59, 0xd7, 0xed, 0xbe, 0xa5, 0xcc, 0x78, 0x6d, 0x80,
    ];

    #[test]
    fn decoding_into_authenticode_signature() {
        let pem = parse_pem(crate::test_files::PKCS7.as_bytes()).unwrap();
        let pkcs7 = Pkcs7::from_pem(&pem).unwrap();
        let hash_type = ShaVariant::SHA2_256;
        let private_key = PrivateKey::from_pem_str(RSA_PRIVATE_KEY).unwrap();
        let program_name = "decoding_into_authenticode_signature".to_string();

        let authenticode_signature =
            AuthenticodeSignature::new(pkcs7, FILE_HASH.as_ref(), hash_type, &private_key, Some(program_name)).unwrap();

        let pkcs7certificate = authenticode_signature.0 .0;

        let Pkcs7Certificate { signed_data, .. } = pkcs7certificate;

        let content_info = &signed_data.content_info;

        assert_eq!(
            Into::<String>::into(&content_info.content_type.0).as_str(),
            oids::SPC_INDIRECT_DATA_OBJID
        );

        let spc_indirect_data_content = content_info.content.as_ref().unwrap();
        let message_digest = match &spc_indirect_data_content.0 {
            ContentValue::SpcIndirectDataContent(SpcIndirectDataContent {
                data: _,
                message_digest,
            }) => message_digest.clone(),
            _ => panic!("Expected ContentValue with SpcIndirectDataContent, but got something else"),
        };

        let hash_algo = AlgorithmIdentifier::new_sha(hash_type);
        assert_eq!(message_digest.oid, hash_algo);

        pretty_assertions::assert_eq!(message_digest.digest.0, FILE_HASH);

        assert_eq!(signed_data.signers_infos.0 .0.len(), 1);

        let singer_info = signed_data.signers_infos.0 .0.first().unwrap();
        assert_eq!(singer_info.digest_algorithm.0, hash_algo);

        let authenticated_attributes = &singer_info.signed_attrs.0 .0;

        if !authenticated_attributes
            .iter()
            .any(|attr| matches!(attr.value, AttributeValues::ContentType(_)))
        {
            panic!("ContentType attribute is missing");
        }

        if !authenticated_attributes
            .iter()
            .any(|attr| matches!(attr.value, AttributeValues::MessageDigest(_)))
        {
            panic!("MessageDigest attribute is missing");
        }

        if !authenticated_attributes
            .iter()
            .any(|attr| matches!(attr.value, AttributeValues::SpcSpOpusInfo(_)))
        {
            panic!("SpcSpOpusInfo attribute is missing");
        }

        assert_eq!(
            singer_info.signature_algorithm,
            SignatureAlgorithmIdentifier(AlgorithmIdentifier::new_rsa_encryption())
        );

        let signature_algo =
            SignatureAlgorithm::from_algorithm_identifier(&AlgorithmIdentifier::new_sha256_with_rsa_encryption())
                .unwrap();

        let certificate = signed_data
            .certificates
            .0
            .clone()
            .into_iter()
            .filter_map(|cert| Cert::try_from(cert).ok())
            .find(|certificate| matches!(certificate.ty(), CertType::Intermediate))
            .map(Certificate::from)
            .unwrap();

        let code_signing_ext_key_usage = Extension::new_extended_key_usage(vec![oids::kp_code_signing()]);
        assert!(!certificate
            .tbs_certificate
            .extensions
            .0
             .0
            .iter()
            .any(|extension| extension == &code_signing_ext_key_usage));

        let public_key = certificate.tbs_certificate.subject_public_key_info;
        let encrypted_digest = singer_info.signature.0 .0.as_ref();

        let mut auth_raw_data = picky_asn1_der::to_vec(&authenticated_attributes).unwrap();
        auth_raw_data[0] = Tag::SET.number();

        assert!(signature_algo
            .verify(&public_key.into(), auth_raw_data.as_ref(), encrypted_digest)
            .is_ok());
    }

    #[test]
    fn into_authenticate_signature_from_pkcs7_with_x509_root_chain() {
        let pem = "-----BEGIN PKCS7-----\
                     MIIKDgYJKoZIhvcNAQcCoIIJ/zCCCfsCAQExADALBgkqhkiG9w0BBwGgggnhMIIE\
                     NjCCAh4CAWUwDQYJKoZIhvcNAQELBQAwYTELMAkGA1UEBhMCSUkxCzAJBgNVBAgM\
                     AklJMQswCQYDVQQHDAJJSTELMAkGA1UECgwCSUkxCzAJBgNVBAsMAklJMQswCQYD\
                     VQQDDAJJSTERMA8GCSqGSIb3DQEJARYCSUkwHhcNMjEwNDI5MTAxNTM3WhcNMjQw\
                     MTI0MTAxNTM3WjBhMQswCQYDVQQGEwJTUzELMAkGA1UECAwCU1MxCzAJBgNVBAcM\
                     AlNTMQswCQYDVQQKDAJTUzELMAkGA1UECwwCU1MxCzAJBgNVBAMMAlNTMREwDwYJ\
                     KoZIhvcNAQkBFgJTUzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALFT\
                     ERznf389kwmFdy3RFeSQKRiU5Sr8k5ChXp+74u2kKVcbQixS2KQti3KopB8Xkly4\
                     31TBDRHRqR5H/x+KY/Pjp/iTFX6AXom4mxAglPxGeKdNuWesBdIf6hZcIJ2rZv94\
                     G67m4ggCS0oDB3qYykw02wO6QeEZHA0AiLRusR4SQZZNZc3Z6JUSijTJZE+TKxL8\
                     eoVNI5P4/+aSY4wdLPK+qEfzsumxVSbqQWO7aWWd6yYYCsGhd/k9pVJMmqXH+rkL\
                     lVcxtYkAnH1TOuvsAn+FBMwr/lXuenT3DiFTDJtm/Mu4ZM2lD60o6aDCSdYSOh/w\
                     amTGCX3WWMmpqfBFRy8CAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAy51uXBnzdU1d\
                     U8K3kh1naldLG6/UF8jJhiN7vmltPuYSvPeIzNk/g4UXUACHnUzg7JWRobf0VBHw\
                     /I8xGXjnRRo2s9w2ZyF4CyDC7YVZWK/bvUe/7qMteZPBXC1Fgz03UC0Y/Y9jqCUJ\
                     ev0bl+u9jRkoE5aMiJhQOzn+CDGxKXvefDpDtvt8nuqNnY9vP7fo3wTLhWF4RUFA\
                     p8iNQu4Pw1XaHhJ467c5kFZLBz+E75myIRJfRYYmBw6nWLSDNueI/Jw+N6jxTKw6\
                     +PtqGx91YTgUK61HHTe8qY7HYCt8ZNmJWvzYpBjUCMEx0BS3sQ7KLc8piD7C5aH7\
                     YzS1PLA2hk4nAk1+uDlQrbfZl+p3ED8NTIvbL9GPBqTQAjOwVkspuidfabgsg/yk\
                     0Nh+3AFMkAy3MoSHmf0AugWyd1F37xx8SePY7NSznWbd7z6UP0WpS4k3BaYWxll1\
                     Q4jXPVghHuQBgmsamx6uXI950DszVvvzubmoVFGsOhdq6BLoZ4dx2mh2teLyPOH0\
                     77nEEOREhilxLMunGUZsZ5rcZuLgMKwOMxY7Sk3x4ETLG9R5Fhe+w70xZfWkKEt0\
                     o7cjRnNM3njJs+TKSZYXcv/9AKhWNUyqhrgUtbsWjTBnXaRyBtDZR3iQx9t0QQZ/\
                     cX0bsED8y9zkFxTIYcSbJuYtcO2ldm8wggWjMIIDi6ADAgECAhRf5s94qhLBW634\
                     aeLH/M67kmZ+8TANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJTUzELMAkGA1UE\
                     CAwCUlIxCzAJBgNVBAcMAlJSMQswCQYDVQQKDAJSUjELMAkGA1UECwwCUlIxCzAJ\
                     BgNVBAMMAlJSMREwDwYJKoZIhvcNAQkBFgJSUjAeFw0yMTA0MjkxMDA0MzZaFw0y\
                     NjA0MjkxMDA0MzZaMGExCzAJBgNVBAYTAlNTMQswCQYDVQQIDAJSUjELMAkGA1UE\
                     BwwCUlIxCzAJBgNVBAoMAlJSMQswCQYDVQQLDAJSUjELMAkGA1UEAwwCUlIxETAP\
                     BgkqhkiG9w0BCQEWAlJSMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA\
                     2AXxt6RZbLKqkw+9Y0FbT+hMS/MpPMEnCINTHK3gzhjP3hhOKfVhHekfWoZ07gZz\
                     IcJMfcXTLFbsFDuZssj63YXiKkk5AXstgd+8F2nW4xNLdXiAD6/vQQYzX/KJO1+T\
                     5y1vAuAvO4xybe0HHMsIcLlUv45BaEBOFizUwMsDnE+GEVfsfFNhxxvLz0daGrSF\
                     c7C0DgG4qNC9ONrOThZhBeDud8g6LLYSTHnIblEfbsVPUlNI+mk8vFNoQYAoz74M\
                     dIfJZQ3+yoqqDAlVAERo9bD8ejnB296OVIpzjHr8v4Y1hxB1UIE7P9LIYhl2FOI1\
                     F57MyGM+qUD86s4ycxq1emrjurhG8xzUttUAg4RRogtJdJrGu9AX2RbnWV6yLfZl\
                     bE6NG2LBuxihZ40vMYFNt3CgZ/7MUc7mJcPsg+5uu86jMWWJ3/0kBIhGIEVsyDsy\
                     RyAE1trB5Zs1yvuEVx8UDs6nrXns+q7lexliomVGPQGf4eoJaNGXqR4xB8oKqCCJ\
                     pMdNARAYOEAjtYvkoZVSgQb0HoScZmlXywwlRVMiDToSsE7pheiv5WEyiBSoMMnI\
                     OMFyIu9YP5DBjVweggqJDvg6n+iRqsTckRbY/wxUIcMpczkhTPAI0zCHLbtkCA7S\
                     caZjpPP7Q1I2XtquR08vflsGrwcVl9OSOVqJ4AN5xiMCAwEAAaNTMFEwHQYDVR0O\
                     BBYEFFbRR8T+Mn5/zWJ4dRa4o7oqzWK3MB8GA1UdIwQYMBaAFFbRR8T+Mn5/zWJ4\
                     dRa4o7oqzWK3MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAL+5\
                     oOOyd1M14xbdyxKTJyQQbR/3Fu+ycLoKqHI8xDtqpxQz39r6TjZVzRPGmkaO2LFr\
                     jS6vatIG+X2A8qsKS6Oab0BMj/0uKpibS8sm/4wJCUVj5fRHRAfTHOeis6efYgB4\
                     t/Er3WKbpfnySPKtxr5vO6KpYk+cRz6aIs5zD3I/5LXdyn4BD4O4RH8w5m55xs0G\
                     pZWH1K1SZmv6bmWmnKM5x5kECbsJQDA9oNCV2Vqg3y52dxmvuworzMlu2gnpdQQT\
                     6Ibh65SYtfYBQTn2bPQB+YPfWqGoWSDUq7CHybUNCgKqYw7+4X/cJB0IkUMZt+Pw\
                     kS3YiYP8hRM4lQAs6ITiB1GSpPuL9cCRcOjHvjilLiZJGfskGy8ucqlj24LEvtb6\
                     DWu45SyjuQ08r6ORxkVg/cz1ztx0BrIVMQMxpIYUi1xPHPpz60j4Y1v1O2XvRJMu\
                     Xg6ulyYWYaw+V+VopcQWBvAe1gYUk0CVzneBEjauzT1qX8K/Fu6f5ltQEJ5XGuYY\
                     pHEn99xhnRUSThoBvOwQj8JjD8uiCJvvOVugF1wEh4RIcCKj7r4u91c41ndg7FU0\
                     kxVRpfjDmxxzQib3Q/z4ZAoqW7+Hjq6gqim2ngrB9Co9pv4ckJ5APDx6x9WF8gpc\
                     Ydn+09ezBdJ4Zgn5U7GdrkNAgOzXtBwbiKxlGcWWoQAxAA==\
                     -----END PKCS7-----";

        let pkcs7 = Pkcs7::from_pem_str(pem).unwrap();
        let private_key = PrivateKey::from_pem_str(RSA_PRIVATE_KEY).unwrap();

        let authenticode_signature = AuthenticodeSignature::new(
            pkcs7,
            FILE_HASH.as_ref(),
            ShaVariant::SHA2_256,
            &private_key,
            Some("into_authenticate_signature_from_pkcs7_with_x509_root_chain".to_string()),
        );

        assert!(authenticode_signature.is_ok());
    }
}
