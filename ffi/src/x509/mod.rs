use picky::x509::certificate;

pub mod algorithm_identifier;
pub mod attribute;
pub mod authenticode;
pub mod extension;
pub mod name;
pub mod singer_info;
pub mod string;
pub mod time;

impl From<ffi::CertType> for certificate::CertType {
    fn from(ty: ffi::CertType) -> Self {
        match ty {
            ffi::CertType::Root => certificate::CertType::Root,
            ffi::CertType::Intermediate => certificate::CertType::Intermediate,
            ffi::CertType::Leaf => certificate::CertType::Leaf,
            ffi::CertType::Unknown => certificate::CertType::Unknown,
        }
    }
}

impl From<certificate::CertType> for ffi::CertType {
    fn from(ty: certificate::CertType) -> Self {
        match ty {
            certificate::CertType::Root => ffi::CertType::Root,
            certificate::CertType::Intermediate => ffi::CertType::Intermediate,
            certificate::CertType::Leaf => ffi::CertType::Leaf,
            certificate::CertType::Unknown => ffi::CertType::Unknown,
        }
    }
}

struct CertificateBuilderInner {
    valid_from: Option<picky::x509::date::UtcDate>,
    valid_to: Option<picky::x509::date::UtcDate>,
    subject_dns_name: Option<String>,
    issuer_common_name: Option<String>,
    issuer_key: Option<picky::key::PrivateKey>,
    self_signed: bool,
    enable_ku_digital_signature: bool,
    enable_kp_server_auth: bool,
}

#[diplomat::bridge]
pub mod ffi {
    use std::cell::RefCell;
    use std::fmt::Write;

    use diplomat_runtime::DiplomatWriteable;
    use picky::x509::certificate;

    use crate::date::ffi::UtcDate;
    use crate::error::ffi::PickyError;
    use crate::key::ffi::{PrivateKey, PublicKey};
    use crate::pem::ffi::Pem;

    pub enum CertType {
        Root,
        Intermediate,
        Leaf,
        Unknown,
    }

    #[diplomat::opaque]
    pub struct Cert(pub certificate::Cert);

    impl Cert {
        /// Parses a X509 certificate from its DER representation.
        pub fn from_der(der: &[u8]) -> Result<Box<Cert>, Box<PickyError>> {
            let cert = certificate::Cert::from_der(der)?;
            Ok(Box::new(Self(cert)))
        }

        /// Extracts X509 certificate from PEM object.
        pub fn from_pem(pem: &Pem) -> Result<Box<Cert>, Box<PickyError>> {
            let cert = certificate::Cert::from_pem(&pem.0)?;
            Ok(Box::new(Self(cert)))
        }

        /// Exports the X509 certificate into a PEM object
        pub fn to_pem(&self) -> Result<Box<Pem>, Box<PickyError>> {
            let pem = self.0.to_pem()?;
            Ok(Box::new(Pem(pem)))
        }

        pub fn get_ty(&self) -> CertType {
            self.0.ty().into()
        }

        pub fn get_public_key(&self) -> Box<PublicKey> {
            Box::new(PublicKey(self.0.public_key().clone()))
        }

        pub fn get_cert_type(&self) -> CertType {
            self.0.ty().into()
        }

        pub fn get_valid_not_before(&self) -> Box<UtcDate> {
            Box::new(UtcDate(self.0.valid_not_before()))
        }

        pub fn get_valid_not_after(&self) -> Box<UtcDate> {
            Box::new(UtcDate(self.0.valid_not_after()))
        }

        pub fn get_subject_key_id_hex(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let ski = self.0.subject_key_identifier()?;
            let ski = hex::encode(ski);
            writeable.write_str(&ski)?;
            writeable.flush();
            Ok(())
        }

        pub fn get_subject_name(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            write!(writeable, "{}", self.0.subject_name())?;
            writeable.flush();
            Ok(())
        }

        pub fn get_issuer_name(&self, writeable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            write!(writeable, "{}", self.0.issuer_name())?;
            writeable.flush();
            Ok(())
        }
    }

    #[diplomat::opaque]
    pub struct CertificateBuilder(RefCell<super::CertificateBuilderInner>);

    impl CertificateBuilder {
        pub fn new() -> Box<CertificateBuilder> {
            Box::new(Self(RefCell::new(super::CertificateBuilderInner {
                valid_from: None,
                valid_to: None,
                subject_dns_name: None,
                issuer_common_name: None,
                issuer_key: None,
                self_signed: false,
                enable_ku_digital_signature: false,
                enable_kp_server_auth: false,
            })))
        }

        pub fn set_valid_from(&self, valid_from: &UtcDate) {
            self.0.borrow_mut().valid_from = Some(valid_from.0.clone());
        }

        pub fn set_valid_to(&self, valid_to: &UtcDate) {
            self.0.borrow_mut().valid_to = Some(valid_to.0.clone());
        }

        pub fn set_issuer_common_name(&self, name: &str) {
            self.0.borrow_mut().issuer_common_name = Some(name.to_owned());
        }

        pub fn set_subject_dns_name(&self, name: &str) {
            self.0.borrow_mut().subject_dns_name = Some(name.to_owned());
        }

        pub fn set_issuer_key(&self, key: &PrivateKey) {
            self.0.borrow_mut().issuer_key = Some(key.0.clone());
        }

        pub fn set_self_signed(&self, is_self_signed: bool) {
            self.0.borrow_mut().self_signed = is_self_signed;
        }

        pub fn set_ku_digital_signature(&self, enable: bool) {
            self.0.borrow_mut().enable_ku_digital_signature = enable;
        }

        pub fn set_kp_server_auth(&self, enable: bool) {
            self.0.borrow_mut().enable_kp_server_auth = enable;
        }

        pub fn build(&self) -> Result<Box<Cert>, Box<PickyError>> {
            let mut inner = self.0.borrow_mut();

            if !inner.self_signed {
                return Err("only self signed certificates are supported by the .NET wrapper".into());
            }

            let valid_from = inner.valid_from.take().ok_or("valid from date is missing")?;
            let valid_to = inner.valid_to.take().ok_or("valid to date is missing")?;
            let issuer_common_name = inner.issuer_common_name.take().ok_or("issuer name is missing")?;
            let issuer_key = inner.issuer_key.take().ok_or("issuer key is missing")?;
            let subject_dns_name = inner.subject_dns_name.take().ok_or("subject dns name is missing")?;

            let common_name = picky::x509::name::DirectoryName::new_common_name(issuer_common_name);
            let dns_name = picky::x509::name::GeneralNames::new_dns_name(
                picky_asn1::restricted_string::Ia5String::from_string(subject_dns_name)
                    .map_err(|_| "invalid charset for DNS name (issuer name)")?,
            );

            let mut key_usage = picky::x509::extension::KeyUsage::default();

            if inner.enable_ku_digital_signature {
                key_usage.set_digital_signature(true);
            }

            let mut extended_usages = Vec::new();

            if inner.enable_kp_server_auth {
                extended_usages.push(picky::oids::kp_server_auth());
            }

            let extended_key_usage = picky::x509::extension::ExtendedKeyUsage::new(extended_usages);

            let cert = certificate::CertificateBuilder::new()
                .validity(valid_from, valid_to)
                .self_signed(common_name, &issuer_key)
                .signature_hash_type(picky::signature::SignatureAlgorithm::RsaPkcs1v15(
                    picky::hash::HashAlgorithm::SHA2_512,
                ))
                .key_id_gen_method(picky::x509::KeyIdGenMethod::SPKFullDER(
                    picky::hash::HashAlgorithm::SHA2_512,
                ))
                .subject_alt_name(dns_name)
                .key_usage(key_usage)
                .extended_key_usage(extended_key_usage)
                .build()?;

            Ok(Box::new(Cert(cert)))
        }
    }

    #[diplomat::opaque]
    pub struct CertIterator(pub Vec<certificate::Cert>);

    impl CertIterator {
        pub fn next(&mut self) -> Option<Box<Cert>> {
            self.0.pop().map(|cert| Box::new(Cert(cert)))
        }
    }
}
