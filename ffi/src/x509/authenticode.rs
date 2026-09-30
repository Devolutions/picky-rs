#[diplomat::bridge]
pub mod ffi {
    use picky::x509::pkcs7::timestamp::Timestamper;

    use crate::date::ffi::UtcDate;
    use crate::error::ffi::PickyError;
    use crate::hash::ffi::HashAlgorithm;
    use crate::key::ffi::PrivateKey;
    use crate::pem::ffi::Pem;
    use crate::pkcs7::ffi::Pkcs7;
    use crate::utils::ffi::{RsString, VecU8};
    use crate::x509::attribute::ffi::{
        Attribute, AttributeIterator, SignedData, UnsignedAttribute, UnsignedAttributeIterator,
    };
    use crate::x509::ffi::{Cert, CertIterator};
    use crate::x509::name::ffi::DirectoryNameIterator;

    #[diplomat::opaque_mut]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct AuthenticodeSignature(pub picky::x509::pkcs7::authenticode::AuthenticodeSignature);

    #[diplomat::enum_convert(picky_asn1_x509::ShaVariant)]
    pub enum ShaVariant {
        MD5,
        SHA1,
        SHA2_224,
        SHA2_256,
        SHA2_384,
        SHA2_512,
        SHA2_512_224,
        SHA2_512_256,
        SHA3_224,
        SHA3_256,
        SHA3_384,
        SHA3_512,
        SHAKE128,
        SHAKE256,
    }

    impl AuthenticodeSignature {
        pub fn new(
            pkcs7: &crate::pkcs7::ffi::Pkcs7,
            file_hash: &VecU8,
            hash_algorithm: ShaVariant,
            private_key: &PrivateKey,
            program_name: Option<&RsString>,
        ) -> Result<Box<AuthenticodeSignature>, Box<PickyError>> {
            let inner = picky::x509::pkcs7::authenticode::AuthenticodeSignature::new(
                &pkcs7.0,
                file_hash.0.clone(),
                hash_algorithm.into(),
                &private_key.0,
                program_name.map(|s| s.0.clone()),
            )?;
            Ok(Box::new(AuthenticodeSignature(inner)))
        }

        pub fn timestamp(
            &mut self,
            timestamper: &mut AuthenticodeTimestamper,
            hash_algo: HashAlgorithm,
        ) -> Result<(), Box<PickyError>> {
            let timestamper = &timestamper.0;
            self.0.timestamp(
                timestamper,
                hash_algo.try_into().map_err(|_| "not a valid hash algorithm")?,
            )?;
            Ok(())
        }

        pub fn from_der(der: &VecU8) -> Result<Box<AuthenticodeSignature>, Box<PickyError>> {
            let inner = picky::x509::pkcs7::authenticode::AuthenticodeSignature::from_der(&der.0)?;
            Ok(Box::new(AuthenticodeSignature(inner)))
        }

        pub fn from_pem(pem: &Pem) -> Result<Box<AuthenticodeSignature>, Box<PickyError>> {
            let inner = picky::x509::pkcs7::authenticode::AuthenticodeSignature::from_pem(&pem.0)?;
            Ok(Box::new(AuthenticodeSignature(inner)))
        }

        pub fn from_pem_str(pem: &str) -> Result<Box<AuthenticodeSignature>, Box<PickyError>> {
            let inner = picky::x509::pkcs7::authenticode::AuthenticodeSignature::from_pem_str(pem)?;
            Ok(Box::new(AuthenticodeSignature(inner)))
        }

        pub fn to_der(&self) -> Result<Box<VecU8>, Box<PickyError>> {
            let der = self.0.to_der()?;
            Ok(Box::new(VecU8(der)))
        }

        pub fn to_pem(&self) -> Result<Box<Pem>, Box<PickyError>> {
            let pem = self.0.to_pem()?;
            Ok(Box::new(Pem(pem)))
        }

        pub fn signing_certificate(&self, cert: &CertIterator) -> Result<Box<Cert>, Box<PickyError>> {
            let cert = self.0.signing_certificate(&cert.0)?;
            Ok(Box::new(Cert(cert.clone())))
        }

        pub fn authenticode_verifier(&self) -> Box<AuthenticodeValidator> {
            Box::new(AuthenticodeValidator {
                signature: self.0.clone(),
                steps: Vec::new(),
            })
        }

        pub fn file_hash(&self) -> Option<Box<VecU8>> {
            self.0.file_hash().map(VecU8).map(Box::new)
        }

        pub fn authenticate_attributes(&self) -> Box<AttributeIterator> {
            Box::new(AttributeIterator(
                self.0
                    .authenticated_attributes()
                    .iter()
                    .map(|attr| Attribute(attr.clone()))
                    .collect(),
            ))
        }

        pub fn unauthenticated_attributes(&self) -> Box<UnsignedAttributeIterator> {
            Box::new(UnsignedAttributeIterator(
                self.0
                    .unauthenticated_attributes()
                    .iter()
                    .map(|attr| UnsignedAttribute(attr.clone()))
                    .collect(),
            ))
        }
    }

    // Holds a copy of the signature plus the requested settings, and only builds picky's borrowing
    // validator inside `verify`. Nothing is borrowed across calls, so the signature and the dates
    // passed in can be disposed at any time.
    #[diplomat::opaque_mut]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct AuthenticodeValidator {
        signature: picky::x509::pkcs7::authenticode::AuthenticodeSignature,
        steps: Vec<super::ValidatorStep>,
    }

    impl AuthenticodeValidator {
        pub fn exact_date(&mut self, exact: &UtcDate) {
            self.steps.push(super::ValidatorStep::ExactDate(exact.0.clone()));
        }

        pub fn interval_date(&mut self, lower: &UtcDate, upper: &UtcDate) {
            self.steps.push(super::ValidatorStep::IntervalDate {
                lower: lower.0.clone(),
                upper: upper.0.clone(),
            });
        }

        pub fn require_not_before_check(&mut self) {
            self.steps.push(super::ValidatorStep::RequireNotBeforeCheck);
        }

        pub fn require_not_after_check(&mut self) {
            self.steps.push(super::ValidatorStep::RequireNotAfterCheck);
        }

        pub fn ignore_not_before_check(&mut self) {
            self.steps.push(super::ValidatorStep::IgnoreNotBeforeCheck);
        }

        pub fn ignore_not_after_check(&mut self) {
            self.steps.push(super::ValidatorStep::IgnoreNotAfterCheck);
        }

        pub fn require_signing_certificate_check(&mut self) {
            self.steps.push(super::ValidatorStep::RequireSigningCertificateCheck);
        }

        pub fn ignore_signing_certificate_check(&mut self) {
            self.steps.push(super::ValidatorStep::IgnoreSigningCertificateCheck);
        }

        pub fn require_basic_authenticode_validation(&mut self, expected_file_hash: &VecU8) {
            self.steps
                .push(super::ValidatorStep::RequireBasicAuthenticodeValidation(
                    expected_file_hash.0.clone(),
                ));
        }

        pub fn ignore_basic_authenticode_validation(&mut self) {
            self.steps.push(super::ValidatorStep::IgnoreBasicAuthenticodeValidation);
        }

        pub fn require_chain_check(&mut self) {
            self.steps.push(super::ValidatorStep::RequireChainCheck);
        }

        pub fn ignore_chain_check(&mut self) {
            self.steps.push(super::ValidatorStep::IgnoreChainCheck);
        }

        pub fn exclude_cert_authorities(&mut self, cert_auths: &DirectoryNameIterator) {
            let cert_auths = cert_auths.0.iter().map(|dn| dn.0.clone()).collect();
            self.steps
                .push(super::ValidatorStep::ExcludeCertAuthorities(cert_auths));
        }

        pub fn verify(&self) -> Result<(), Box<PickyError>> {
            let validator = self.signature.authenticode_verifier();
            for step in &self.steps {
                step.apply(&validator);
            }
            Ok(validator.verify()?)
        }
    }

    #[diplomat::opaque_mut]
    #[diplomat::attr(dotnet, manually_disposable)]
    pub struct AuthenticodeTimestamper(pub picky::x509::pkcs7::timestamp::http_timestamp::AuthenticodeTimestamper);

    impl AuthenticodeTimestamper {
        pub fn new(url: &str) -> Result<Box<AuthenticodeTimestamper>, Box<PickyError>> {
            let inner = picky::x509::pkcs7::timestamp::http_timestamp::AuthenticodeTimestamper::new(url)?;
            Ok(Box::new(AuthenticodeTimestamper(inner)))
        }

        pub fn timestamp(&self, digest: &VecU8, hash_algo: HashAlgorithm) -> Result<Box<Pkcs7>, Box<PickyError>> {
            Ok(self
                .0
                .timestamp(
                    digest.0.clone(),
                    hash_algo.try_into().map_err(|_| "not a valid hash algorithm")?,
                )
                .map(Pkcs7)
                .map(Box::new)?)
        }

        pub fn modify_signed_data(&self, token: &Pkcs7, signed_data: &mut SignedData) {
            self.0.modify_signed_data(token.0.clone(), &mut signed_data.0)
        }
    }
}

/// A setting recorded on `ffi::AuthenticodeValidator`, replayed in call order onto picky's validator.
enum ValidatorStep {
    ExactDate(picky::x509::date::UtcDate),
    IntervalDate {
        lower: picky::x509::date::UtcDate,
        upper: picky::x509::date::UtcDate,
    },
    RequireNotBeforeCheck,
    IgnoreNotBeforeCheck,
    RequireNotAfterCheck,
    IgnoreNotAfterCheck,
    RequireSigningCertificateCheck,
    IgnoreSigningCertificateCheck,
    RequireBasicAuthenticodeValidation(Vec<u8>),
    IgnoreBasicAuthenticodeValidation,
    RequireChainCheck,
    IgnoreChainCheck,
    ExcludeCertAuthorities(Vec<picky::x509::name::DirectoryName>),
}

impl ValidatorStep {
    fn apply<'a>(&'a self, validator: &picky::x509::pkcs7::authenticode::AuthenticodeValidator<'a>) {
        match self {
            Self::ExactDate(exact) => validator.exact_date(exact),
            Self::IntervalDate { lower, upper } => validator.interval_date(lower, upper),
            Self::RequireNotBeforeCheck => validator.require_not_before_check(),
            Self::IgnoreNotBeforeCheck => validator.ignore_not_before_check(),
            Self::RequireNotAfterCheck => validator.require_not_after_check(),
            Self::IgnoreNotAfterCheck => validator.ignore_not_after_check(),
            Self::RequireSigningCertificateCheck => validator.require_signing_certificate_check(),
            Self::IgnoreSigningCertificateCheck => validator.ignore_signing_certificate_check(),
            Self::RequireBasicAuthenticodeValidation(hash) => {
                validator.require_basic_authenticode_validation(hash.clone())
            }
            Self::IgnoreBasicAuthenticodeValidation => validator.ignore_basic_authenticode_validation(),
            Self::RequireChainCheck => validator.require_chain_check(),
            Self::IgnoreChainCheck => validator.ignore_chain_check(),
            Self::ExcludeCertAuthorities(cert_auths) => validator.exclude_cert_authorities(cert_auths),
        };
    }
}
