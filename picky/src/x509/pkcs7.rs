use crate::hash::{HashAlgorithm, UnsupportedHashAlgorithmError};
use crate::pem::Pem;
use crate::signature::{SignatureAlgorithm, SignatureError};
use crate::x509::certificate::{Cert, CertError, CertType, ValidityCheck};
use crate::x509::date::UTCDate;
use crate::x509::extension::ExtendedKeyUsage;
use crate::x509::pkcs7::AuthenticodeError::DigestAlgorithmMismatch;
use crate::x509::utils::{from_der, from_pem, from_pem_str, to_der, to_pem};
use crate::AlgorithmIdentifier;
use picky_asn1::restricted_string::CharSetError;
use picky_asn1::wrapper::OctetStringAsn1;
use picky_asn1_der::Asn1DerError;
use picky_asn1_x509::algorithm_identifier::UnsupportedAlgorithmError;
use picky_asn1_x509::cmsversion::CmsVersion;
use picky_asn1_x509::content_info::{ContentValue, EncapsulatedContentInfo};
use picky_asn1_x509::extension::ExtensionView;
use picky_asn1_x509::pkcs7::ctl::{CTLEntry, CTLEntryAttributeValues};
use picky_asn1_x509::pkcs7::Pkcs7Certificate;
use picky_asn1_x509::signer_info::{SignerIdentifier, SignerInfo};
use picky_asn1_x509::{oids, AttributeValues, Name};
use std::cell::RefCell;
use std::io::{self, Cursor, Read};

use thiserror::Error;

type Pkcs7Result<T> = Result<T, Pkcs7Error>;

const ELEMENT_NAME: &str = "pkcs7 certificate";

#[derive(Debug, Error)]
pub enum Pkcs7Error {
    #[error(transparent)]
    Cert(#[from] CertError),
    #[error(transparent)]
    Asn1DerError(#[from] Asn1DerError),
    #[error(transparent)]
    SignatureError(#[from] crate::signature::SignatureError),
    #[error("the program name has invalid charset")]
    ProgramNameCharSet(#[from] CharSetError),
    #[error(transparent)]
    UnsupportedHashAlgorithmError(UnsupportedHashAlgorithmError),
    #[error(transparent)]
    UnsupportedAlgorithmError(UnsupportedAlgorithmError),
    #[error("Certificates must contain at least Leaf and Intermediate certificates, but got no certificates")]
    NoCertificates,
}

const PKCS7_PEM_LABEL: &str = "PKCS7";

#[derive(Clone, Debug, PartialEq)]
pub struct Pkcs7(pub(crate) Pkcs7Certificate);

impl Pkcs7 {
    pub fn from_der<V: ?Sized + AsRef<[u8]>>(data: &V) -> Pkcs7Result<Self> {
        Ok(from_der(data, ELEMENT_NAME).map(Self)?)
    }

    pub fn from_pem(pem: &Pem) -> Pkcs7Result<Self> {
        Ok(from_pem(pem, PKCS7_PEM_LABEL, ELEMENT_NAME).map(Self)?)
    }

    pub fn from_pem_str(pem_str: &str) -> Pkcs7Result<Self> {
        Ok(from_pem_str(pem_str, PKCS7_PEM_LABEL, ELEMENT_NAME).map(Self)?)
    }

    pub fn to_der(&self) -> Pkcs7Result<Vec<u8>> {
        Ok(to_der(&self.0, ELEMENT_NAME)?)
    }

    pub fn to_pem(&self) -> Pkcs7Result<Pem> {
        Ok(to_pem(&self.0, PKCS7_PEM_LABEL, ELEMENT_NAME)?)
    }

    pub fn digest_algorithms(&self) -> &[AlgorithmIdentifier] {
        self.0.signed_data.digest_algorithms.0 .0.as_slice()
    }

    pub fn singer_infos(&self) -> &[SignerInfo] {
        &self.0.signed_data.signers_infos.0
    }

    pub fn encapsulated_content_info(&self) -> &EncapsulatedContentInfo {
        &self.0.signed_data.0.content_info
    }

    pub fn certificates(&self) -> Vec<Cert> {
        self.0
            .signed_data
            .certificates
            .0
            .iter()
            .cloned()
            .map(Cert::from)
            .collect::<Vec<Cert>>()
    }

    pub fn signing_certificate(&self) -> Result<Cert, AuthenticodeError> {
        let signer_infos = &self.0.signed_data.signers_infos.0;

        let signer_info = signer_infos.first().ok_or(AuthenticodeError::MultipleSingerInfo {
            count: signer_infos.len(),
        })?;

        let issuer_and_serial_number = match &signer_info.sid {
            SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial_number) => issuer_and_serial_number,
            SignerIdentifier::SubjectKeyIdentifier(_) => return Err(AuthenticodeError::IncorrectSignerIdentifier),
        };

        self.certificates()
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

    pub fn intermediate_certificate(&self) -> Option<Cert> {
        self.certificates()
            .into_iter()
            .map(Cert::from)
            .find(|cert| cert.ty() == CertType::Intermediate)
    }

    pub fn root_certificate(&self) -> Option<Cert> {
        self.certificates()
            .into_iter()
            .map(Cert::from)
            .find(|cert| cert.ty() == CertType::Root)
    }

    pub fn authenticode_verifier(&self) -> AuthenticodeValidator {
        AuthenticodeValidator {
            pkcs7: self,
            inner: RefCell::new(AuthenticodeValidatorInner {
                strictness: Default::default(),
                excluded_cert_authorities: Vec::new(),
                now: None,
            }),
        }
    }
}

#[derive(Debug, Error)]
pub enum CtlError {
    #[error("Failed to download CTL:  {description}")]
    DownloadError { description: String },
    #[error("{description}")]
    ExtractingError { description: String },
    #[error("Failed to parse CertificateTrustList: {0}")]
    FailedToParseCtl(Pkcs7Error),
    #[error(transparent)]
    IoError(#[from] io::Error),
    #[error("For CTL we expects CertificateTrustList content in EncapsulatedContentInfo, but something else")]
    IncorrectContentValue,
}

struct CertificateTrustList {
    pkcs7: Pkcs7,
}

impl CertificateTrustList {
    pub fn new() -> Result<Self, CtlError> {
        let ctl_url: &str =
            "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab";

        let mut cab = reqwest::blocking::get(ctl_url).map_err(|err| CtlError::DownloadError {
            description: err.to_string(),
        })?;

        if !cab.status().is_success() {
            return Err(CtlError::DownloadError {
                description: format!("Response status code is {}", cab.status()),
            });
        }

        let mut buffer = Vec::new();
        cab.copy_to(&mut buffer).map_err(|err| CtlError::ExtractingError {
            description: format!("Failed to copy Response body to Vec: {}", err),
        })?;

        let mut cabinet = cab::Cabinet::new(Cursor::new(&mut buffer)).map_err(|err| CtlError::ExtractingError {
            description: format!("Failed to parse Cabinet file: {}", err),
        })?;

        let mut authroot = cabinet
            .read_file("authroot.stl")
            .expect("authroot.stl should be present in authrootstl.cab");

        let mut ctl_buffer = Vec::new();
        authroot.read_to_end(&mut ctl_buffer)?;

        let pkcs7: Pkcs7 = Pkcs7::from_der(&ctl_buffer).map_err(CtlError::FailedToParseCtl)?;

        Ok(Self { pkcs7 })
    }

    pub fn ctl_entries(&self) -> Result<Vec<CTLEntry>, CtlError> {
        let content_value = self
            .pkcs7
            .0
            .signed_data
            .content_info
            .content
            .as_ref()
            .expect("CTL Content should be present in EncapsulatedContentInfo");

        let ctl = match &content_value.0 {
            ContentValue::CertificateTrustList(ctl) => ctl,
            _ => return Err(CtlError::IncorrectContentValue),
        };

        Ok(ctl.crl_entries.0.clone())
    }
}

#[derive(Debug, Error)]
pub enum AuthenticodeError {
    // TODO: sort out this enum variants
    #[error("Incorrect version. Expected: {expected}, but got {got}")]
    IncorrectVersion { expected: u32, got: u32 },
    #[error("Authenticode must contain only one SingerInfo, but got {count}")]
    MultipleSingerInfo { count: usize },
    #[error("EncapsulatedContentInfo is missing")]
    NoEncapsulatedContentInfo,
    #[error("EncapsulatedContentInfo should contain SpcIndirectDataContent")]
    NoSpcIndirectDataContent,
    #[error("Digest algorithm mismatch: {description}")]
    DigestAlgorithmMismatch { description: String },
    #[error("CertificateSet is empty")]
    NoCertificates,
    #[error("No Intermediate certificate")]
    NoIntermediateCertificate,
    #[error("The signing certificate must contain the extended key usage (EKU) value for code signing")]
    NoEKUCodeSigning,
    #[error("PKCS9_MESSAGE_DIGEST attribute is absent")]
    NoMessageDigest,
    #[error("SignerInfo encrypted_digest does not match hash of authenticated attributes of ContentInfo")]
    HashMismatch,
    #[error("Authenticode signatures support only one signer, digestAlgorithms must contain only one digestAlgorithmIdentifier, but {incorrect_count} entries present")]
    IncorrectDigestAlgorithmsCount { incorrect_count: usize },
    #[error(
        "Authenticode use issuerAndSerialNumber to identifier signer, but got subjectKeyIdentifier identification"
    )]
    IncorrectSignerIdentifier,
    #[error("The Authenticode signature CA is not trusted")]
    CAIsNotTrusted,
    #[error("Can't find certificate which the issuer is {issuer:?} and serial_number is {serial_number:?}")]
    NoCertificatesAssociatedWithIssuerAndSerialNumber { issuer: Name, serial_number: Vec<u8> },
    #[error("CA certificate was revoked")]
    CaCertificateRevoked,
    #[error("CA certificate was revoked(since: {not_after}, now: {now})")]
    CaCertificateExpired { not_after: UTCDate, now: UTCDate },
    #[error("CA certificate is not yet valid(not before:  {not_before}, now: {now})")]
    CaCertificateNotYetValid { not_before: UTCDate, now: UTCDate },
    #[error(transparent)]
    CertError(#[from] CertError),
    #[error(transparent)]
    CtlError(#[from] CtlError),
    #[error(transparent)]
    Asn1DerError(#[from] Asn1DerError),
    #[error(transparent)]
    SignatureVerifyError(#[from] SignatureError),
}

type AuthenticodeValidatorResult<T> = Result<T, AuthenticodeError>;

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
struct AuthenticodeValidatorInner<'a> {
    strictness: AuthenticodeStrictness,
    excluded_cert_authorities: Vec<Name>,
    now: Option<ValidityCheck<'a>>,
}

pub struct AuthenticodeValidator<'a> {
    pkcs7: &'a Pkcs7,
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

    fn verify_authenticode_basic(&self) -> AuthenticodeValidatorResult<()> {
        // 1. SignedData version field must be set to 1.
        let version = self.pkcs7.0.signed_data.version;
        if version != CmsVersion::V2 {
            return Err(AuthenticodeError::IncorrectVersion {
                expected: 1,
                got: version as u32,
            });
        }

        // 2. It must contain only one singer info.
        let signer_infos = self.pkcs7.singer_infos();
        if signer_infos.len() != 1 {
            return Err(AuthenticodeError::MultipleSingerInfo {
                count: signer_infos.len(),
            });
        }

        // 3. Signature::digest_algorithm must match ContentInfo::digest_algorithm and SignerInfo::digest_algorithm.
        let content_info = self.pkcs7.encapsulated_content_info();
        let message_digest = match &content_info.content {
            Some(content_value) => match &content_value.0 {
                ContentValue::SpcIndirectDataContent(spc_indirect_data_content) => {
                    &spc_indirect_data_content.message_digest
                }
                _ => return Err(AuthenticodeError::NoSpcIndirectDataContent),
            },
            None => return Err(AuthenticodeError::NoEncapsulatedContentInfo),
        };

        let signing_certificate = self.pkcs7.signing_certificate()?;

        // 5. Authenticode signatures support only one signer, digestAlgorithms must contain only one digestAlgorithmIdentifier.
        let digest_algorithms = self.pkcs7.digest_algorithms();
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
            return Err(DigestAlgorithmMismatch {
                description: "Signature digest algorithm does not match EncapsulatedContentInfo digest algorithm"
                    .to_string(),
            });
        }

        let signer_info = signer_infos
            .first()
            .expect("One SignerInfo should exists at this point");
        if digest_algorithm != &signer_info.digest_algorithm.0 {
            return Err(DigestAlgorithmMismatch {
                description: "Signature digest algorithm does not match SignerInfo digest algorithm".to_string(),
            });
        }

        let public_key = signing_certificate.public_key();

        let authenticated_attributes = &signer_info.signed_attrs.0 .0;
        let raw_attributes = picky_asn1_der::to_vec(&authenticated_attributes)?;

        let signature_algorithm = SignatureAlgorithm::from_algorithm_identifier(&digest_algorithm)?;
        signature_algorithm
            .verify(public_key, &raw_attributes, &signer_info.signature.0 .0)
            .map_err(AuthenticodeError::SignatureVerifyError)?;

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
        let certificates = self.pkcs7.certificates();
        check_eku_code_signing(&certificates)?;

        Ok(())
    }

    fn verify_certificates_chain(&self) -> AuthenticodeValidatorResult<()> {
        let signing_certificate = self.pkcs7.signing_certificate()?;

        let mut certificates = self.pkcs7.certificates();
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

    fn verify_ca_certificate(&self, ca_name: &Name) -> AuthenticodeValidatorResult<()> {
        use chrono::{DateTime, Duration, NaiveDate, Utc};
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

    pub fn verify(&self) -> AuthenticodeValidatorResult<()> {
        let inner = self.inner.borrow();
        if inner.strictness.require_basic_authenticode_validation {
            self.verify_authenticode_basic()?;
        }

        if inner.strictness.require_signing_certificate_check {
            self.verify_certificates_chain()?;
        }

        if inner.strictness.require_ca_verification_against_ctl {
            let directory_name = match (self.pkcs7.root_certificate(), self.pkcs7.intermediate_certificate()) {
                (Some(root_certificate), _) => root_certificate.subject_name(),
                (None, Some(intermediate_certificate)) => intermediate_certificate.issuer_name(),
                _ => {
                    let signing_certificate = self.pkcs7.signing_certificate()?;
                    signing_certificate.issuer_name()
                }
            };

            let ca_name = Name::from(directory_name);

            match self.verify_ca_certificate(&ca_name) {
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

pub(super) fn check_eku_code_signing(certificates: &[Cert]) -> AuthenticodeValidatorResult<()> {
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
mod tests {
    use super::*;
    use crate::pem::parse_pem;

    #[test]
    fn read_pem_and_parse_certificate() {
        let pem = parse_pem(crate::test_files::PKCS7.as_bytes()).unwrap();
        let decoded = Pkcs7::from_pem(&pem);
        assert!(decoded.is_ok());
    }

    #[test]
    fn parse_certificate_trust_list_in_der() {
        let pkcs7 = Pkcs7::from_der(crate::test_files::CERTIFICATE_TRUST_LIST);
        assert!(pkcs7.is_ok());
    }

    #[test]
    fn create_ctl() {
        let ctl = CertificateTrustList::new();
        assert!(ctl.is_ok());
    }
}
