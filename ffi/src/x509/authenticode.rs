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

    #[diplomat::opaque]
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
            program_name: Option<Box<RsString>>,
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

        pub fn authenticode_verifier(&self) -> Box<AuthenticodeValidator<'_>> {
            let verifier = self.0.authenticode_verifier();
            Box::new(AuthenticodeValidator::new(verifier))
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

    #[diplomat::opaque]
    pub struct AuthenticodeValidator<'a> {
        pub inner: picky::x509::pkcs7::authenticode::AuthenticodeValidator<'a>,
        //'exclude_cert_authorities' method down there a few lines takes a reference to a Vec<DirectoryName>,
        // which I have to store in the struct so it have the same lifetime as the inner struct
        pub excluded_cert_authorities: Option<Vec<picky::x509::name::DirectoryName>>,
    }

    impl<'a> AuthenticodeValidator<'a> {
        pub fn exact_date(&'a self, exact: &'a UtcDate) {
            self.inner.exact_date(&exact.0);
        }

        pub fn interval_date(&'a self, lower: &'a UtcDate, upper: &'a UtcDate) {
            self.inner.interval_date(&lower.0, &upper.0);
        }

        pub fn require_not_before_check(&'a self) {
            self.inner.require_not_before_check();
        }

        pub fn require_not_after_check(&'a self) {
            self.inner.require_not_after_check();
        }

        pub fn ignore_not_before_check(&'a self) {
            self.inner.ignore_not_before_check();
        }

        pub fn ignore_not_after_check(&'a self) {
            self.inner.ignore_not_after_check();
        }

        pub fn require_signing_certificate_check(&'a self) {
            self.inner.require_signing_certificate_check();
        }

        pub fn ignore_signing_certificate_check(&'a self) {
            self.inner.ignore_signing_certificate_check();
        }

        pub fn require_basic_authenticode_validation(&'a self, expected_file_hash: &'a VecU8) {
            self.inner
                .require_basic_authenticode_validation(expected_file_hash.0.clone());
        }

        pub fn ignore_basic_authenticode_validation(&'a self) {
            self.inner.ignore_basic_authenticode_validation();
        }

        pub fn require_chain_check(&'a self) {
            self.inner.require_chain_check();
        }

        pub fn ignore_chain_check(&'a self) {
            self.inner.ignore_chain_check();
        }

        pub fn exclude_cert_authorities(&'a mut self, cert_auths: &'a DirectoryNameIterator) {
            let vec: Vec<picky::x509::name::DirectoryName> = cert_auths.0.iter().map(|dn| dn.0.clone()).collect();
            self.excluded_cert_authorities = Some(vec);
            self.inner
                .exclude_cert_authorities(self.excluded_cert_authorities.as_ref().unwrap());
        }

        pub fn verify(&self) -> Result<(), Box<PickyError>> {
            Ok(self.inner.verify()?)
        }
    }

    #[diplomat::opaque]
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

impl<'a> ffi::AuthenticodeValidator<'a> {
    pub fn new(inner: picky::x509::pkcs7::authenticode::AuthenticodeValidator<'a>) -> Self {
        Self {
            inner,
            excluded_cert_authorities: None,
        }
    }
}
