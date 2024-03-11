#![allow(clippy::needless_lifetimes)] // Diplomat requires explicit lifetimes
use picky::x509::certificate;

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

    #[diplomat::opaque]
    pub struct EncapsulatedContentInfo(pub picky_asn1_x509::content_info::EncapsulatedContentInfo);

    impl EncapsulatedContentInfo {
        pub fn content_type(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let oid: String = self.0.content_type.0.clone().into();
            write!(writable, "{}", oid)?;
            Ok(())
        }
    }

    #[diplomat::opaque]
    pub struct SignerInfo(pub picky_asn1_x509::signer_info::SignerInfo);

    pub enum CmsVersion {
        V0,
        V1,
        V2,
        V3,
        V4,
        V5,
    }

    impl SignerInfo {
        pub fn get_version(&self) -> CmsVersion {
            self.0.version.into()
        }

        pub fn get_sid(&self) -> Box<SingerIdentifier> {
            Box::new(SingerIdentifier(self.0.sid.clone()))
        }

        pub fn get_digest_algorithm(&self) -> Box<AlgorithmIdentifier> {
            Box::new(AlgorithmIdentifier(self.0.digest_algorithm.0.clone()))
        }

        pub fn get_signature_algorithm(&self) -> Box<AlgorithmIdentifier> {
            Box::new(AlgorithmIdentifier(self.0.signature_algorithm.0.clone()))
        }

        pub fn get_signature(&self) -> Box<crate::buffer::ffi::Buffer> {
            Box::new(crate::buffer::ffi::Buffer::from(&self.0.signature.0))
        }

        pub fn get_unsigned_attributes(&self) -> Box<UnsignedAttributeIterator> {
            Box::new(UnsignedAttributeIterator(
                self.0
                    .unsigned_attrs
                    .0
                    .clone()
                    .0
                    .into_iter()
                    .map(UnsignedAttribute)
                    .collect(),
            ))
        }

        //TODO: pub signed_attrs: Optional<Attributes>,
    }

    #[diplomat::opaque]
    pub struct UnsignedAttribute(pub picky_asn1_x509::signer_info::UnsignedAttribute);

    impl UnsignedAttribute {
        pub fn get_type(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let oid: String = self.0.ty.0.clone().into();
            write!(writable, "{}", oid)?;
            Ok(())
        }

        pub fn get_values(&self) -> Box<UnsignedAttributeValue> {
            Box::new(UnsignedAttributeValue(self.0.value.clone()))
        }
    }

    #[diplomat::opaque]
    pub struct UnsignedAttributeValue(pub picky_asn1_x509::signer_info::UnsignedAttributeValue);

    pub enum UnsignedAttributeValueType {
        MsCounterSign,
        CounterSign,
    }

    impl UnsignedAttributeValue {
        pub fn get_type(&self) -> UnsignedAttributeValueType {
            match &self.0 {
                picky_asn1_x509::signer_info::UnsignedAttributeValue::MsCounterSign(_) => {
                    UnsignedAttributeValueType::MsCounterSign
                }
                picky_asn1_x509::signer_info::UnsignedAttributeValue::CounterSign(_) => {
                    UnsignedAttributeValueType::CounterSign
                }
            }
        }

        pub fn to_ms_counter_sign(&self) -> Option<Box<MsCounterSignIterator>> {
            match &self.0 {
                picky_asn1_x509::signer_info::UnsignedAttributeValue::MsCounterSign(ms_counter_sign) => {
                    let vec: Vec<MsCounterSign> = ms_counter_sign.0.clone().into_iter().map(MsCounterSign).collect();
                    Some(Box::new(MsCounterSignIterator(vec)))
                }
                _ => None,
            }
        }

        pub fn to_counter_sign(&self) -> Option<Box<SignerInfoIterator>> {
            match &self.0 {
                picky_asn1_x509::signer_info::UnsignedAttributeValue::CounterSign(counter_sign) => Some(Box::new(
                    SignerInfoIterator(counter_sign.0.clone().into_iter().map(SignerInfo).collect()),
                )),
                _ => None,
            }
        }
    }

    #[diplomat::opaque]
    pub struct MsCounterSignIterator(pub Vec<MsCounterSign>);

    impl MsCounterSignIterator {
        pub fn next(&mut self) -> Option<Box<MsCounterSign>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct MsCounterSign(picky_asn1_x509::Pkcs7Certificate);

    impl MsCounterSign {
        pub fn get_oid(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let oid_string: String = self.0.oid.0.clone().into();
            write!(writable, "{}", oid_string)?;
            Ok(())
        }

        pub fn get_signed_data(&self) -> Box<SignedData> {
            Box::new(SignedData(self.0.signed_data.0.clone()))
        }
    }

    #[diplomat::opaque]
    pub struct SignedData(pub picky_asn1_x509::pkcs7::signed_data::SignedData);

    impl SignedData {
        pub fn get_version(&self) -> CmsVersion {
            self.0.version.into()
        }

        pub fn get_digest_algorithms(&self) -> Box<AlgorithmIdentifierIterator> {
            let vec: Vec<_> = self.0.digest_algorithms.0.iter().cloned().collect();
            Box::new(AlgorithmIdentifierIterator(vec))
        }

        pub fn get_content_info(&self) -> Box<EncapsulatedContentInfo> {
            Box::new(EncapsulatedContentInfo(self.0.content_info.clone()))
        }
        //TODO: pub certificates: Optional<CertificateSet>,
        //TODO: pub crls: Option<RevocationInfoChoices>,
        pub fn get_signers_infos(&self) -> Box<SignerInfoIterator> {
            let signer_infos = &self.0.signers_infos;
            let vec_signer_infos: Vec<_> = signer_infos.0.iter().cloned().map(SignerInfo).collect();
            Box::new(SignerInfoIterator(vec_signer_infos))
        }
    }

    #[diplomat::opaque]
    pub struct UnsignedAttributeIterator(pub Vec<UnsignedAttribute>);

    impl UnsignedAttributeIterator {
        pub fn next(&mut self) -> Option<Box<UnsignedAttribute>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct SingerIdentifier(pub picky_asn1_x509::signer_info::SignerIdentifier);

    impl SingerIdentifier {
        pub fn get_issure_and_serial_number(&self) -> Option<Box<IssuerAndSerialNumber>> {
            match &self.0 {
                picky_asn1_x509::signer_info::SignerIdentifier::IssuerAndSerialNumber(issuer_and_serial_number) => {
                    Some(Box::new(IssuerAndSerialNumber(issuer_and_serial_number.clone())))
                }
                _ => None,
            }
        }

        pub fn get_subject_key_identifier(&self) -> Option<Box<crate::buffer::ffi::Buffer>> {
            let picky_asn1_x509::signer_info::SignerIdentifier::SubjectKeyIdentifier(subject_key_identifier) = &self.0 else {
                return None;
            };

            let buffer = crate::buffer::ffi::Buffer::from(&subject_key_identifier.0);
            Some(Box::new(buffer))
        }
    }

    #[diplomat::opaque]
    pub struct IssuerAndSerialNumber(pub picky_asn1_x509::signer_info::IssuerAndSerialNumber);

    impl IssuerAndSerialNumber {
        pub fn get_issuer(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let name_string = format!("{}", self.0.issuer);
            write!(writable, "{}", name_string)?;
            Ok(())
        }
    }

    #[diplomat::opaque]
    pub struct SignerInfoIterator(pub Vec<SignerInfo>);

    impl SignerInfoIterator {
        pub fn next(&mut self) -> Option<Box<SignerInfo>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct AlgorithmIdentifier(pub picky::AlgorithmIdentifier);

    impl AlgorithmIdentifier {
        pub fn is_a(&self, other: &str) -> Result<bool, Box<PickyError>> {
            Ok(self
                .0
                .is_a(picky::oid::ObjectIdentifier::try_from(other).map_err(|_| "invalid OID")?))
        }

        pub fn get_oid(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let string: String = self.0.oid().into();
            write!(writable, "{}", string)?;
            Ok(())
        }

        pub fn get_parameters<'a>(&'a self) -> Box<AlgorithmIdentifierParameters<'a>> {
            Box::new(AlgorithmIdentifierParameters(self.0.parameters()))
        }
    }

    #[diplomat::opaque]
    pub struct AlgorithmIdentifierParameters<'a>(pub &'a picky::x509::AlgorithmIdentifierParameters);

    pub enum AlgorithmIdentifierParametersType {
        None,
        Null,
        Aes,
        Ec,
        RsassaPss,
    }

    impl AlgorithmIdentifierParameters<'_> {
        pub fn get_type(&self) -> AlgorithmIdentifierParametersType {
            match self.0 {
                picky::x509::AlgorithmIdentifierParameters::None => AlgorithmIdentifierParametersType::None,
                picky::x509::AlgorithmIdentifierParameters::Null => AlgorithmIdentifierParametersType::Null,
                picky::x509::AlgorithmIdentifierParameters::Aes(_) => AlgorithmIdentifierParametersType::Aes,
                picky::x509::AlgorithmIdentifierParameters::Ec(_) => AlgorithmIdentifierParametersType::Ec,
                picky::x509::AlgorithmIdentifierParameters::RsassaPss(_) => {
                    AlgorithmIdentifierParametersType::RsassaPss
                }
            }
        }

        pub fn to_aes(&self) -> Option<Box<AesParameters>> {
            match self.0 {
                picky::x509::AlgorithmIdentifierParameters::Aes(ref params) => {
                    Some(Box::new(AesParameters(params.clone())))
                }
                _ => None,
            }
        }

        pub fn to_ec(&self) -> Option<Box<EcParameters>> {
            match self.0 {
                picky::x509::AlgorithmIdentifierParameters::Ec(ref params) => {
                    Some(Box::new(EcParameters(params.clone())))
                }
                _ => None,
            }
        }

        pub fn to_rsassa_pss(&self) -> Option<Box<RsassaPssParameters>> {
            match self.0 {
                picky::x509::AlgorithmIdentifierParameters::RsassaPss(ref params) => {
                    Some(Box::new(RsassaPssParameters(params.clone())))
                }
                _ => None,
            }
        }
    }

    #[diplomat::opaque]
    pub struct AesParameters(pub picky_asn1_x509::AesParameters);

    #[diplomat::opaque]
    pub struct EcParameters(pub picky_asn1_x509::EcParameters);

    #[diplomat::opaque]
    pub struct RsassaPssParameters(pub picky_asn1_x509::RsassaPssParams);

    pub enum AesParametersType {
        Null,
        InitializationVector,
        AuthenticatedEncryptionParameters,
    }

    impl AesParameters {
        pub fn get_type(&self) -> AesParametersType {
            match self.0 {
                picky_asn1_x509::AesParameters::Null => AesParametersType::Null,
                picky_asn1_x509::AesParameters::InitializationVector(_) => AesParametersType::InitializationVector,
                picky_asn1_x509::AesParameters::AuthenticatedEncryptionParameters(_) => {
                    AesParametersType::AuthenticatedEncryptionParameters
                }
            }
        }

        pub fn to_initialization_vector(&self) -> Option<Box<crate::buffer::ffi::Buffer>> {
            match &self.0 {
                picky_asn1_x509::AesParameters::InitializationVector(iv) => Some(Box::new(iv.into())),
                _ => None,
            }
        }

        pub fn to_authenticated_encryption_parameters(&self) -> Option<Box<AesAuthEncParams>> {
            match &self.0 {
                picky_asn1_x509::AesParameters::AuthenticatedEncryptionParameters(params) => {
                    Some(Box::new(AesAuthEncParams(params.clone())))
                }
                _ => None,
            }
        }
    }

    #[diplomat::opaque]
    pub struct AesAuthEncParams(pub picky_asn1_x509::AesAuthEncParams);

    #[diplomat::opaque]
    pub struct AlgorithmIdentifierIterator(pub Vec<picky::AlgorithmIdentifier>);

    impl AlgorithmIdentifierIterator {
        pub fn next(&mut self) -> Option<Box<AlgorithmIdentifier>> {
            self.0.pop().map(|algo| Box::new(AlgorithmIdentifier(algo)))
        }
    }
}

impl From<picky_asn1_x509::cmsversion::CmsVersion> for ffi::CmsVersion {
    fn from(value: picky_asn1_x509::cmsversion::CmsVersion) -> Self {
        match value {
            picky_asn1_x509::cmsversion::CmsVersion::V0 => ffi::CmsVersion::V0,
            picky_asn1_x509::cmsversion::CmsVersion::V1 => ffi::CmsVersion::V1,
            picky_asn1_x509::cmsversion::CmsVersion::V2 => ffi::CmsVersion::V2,
            picky_asn1_x509::cmsversion::CmsVersion::V3 => ffi::CmsVersion::V3,
            picky_asn1_x509::cmsversion::CmsVersion::V4 => ffi::CmsVersion::V4,
            picky_asn1_x509::cmsversion::CmsVersion::V5 => ffi::CmsVersion::V5,
        }
    }
}

impl From<ffi::CmsVersion> for picky_asn1_x509::cmsversion::CmsVersion {
    fn from(val: ffi::CmsVersion) -> Self {
        match val {
            ffi::CmsVersion::V0 => picky_asn1_x509::cmsversion::CmsVersion::V0,
            ffi::CmsVersion::V1 => picky_asn1_x509::cmsversion::CmsVersion::V1,
            ffi::CmsVersion::V2 => picky_asn1_x509::cmsversion::CmsVersion::V2,
            ffi::CmsVersion::V3 => picky_asn1_x509::cmsversion::CmsVersion::V3,
            ffi::CmsVersion::V4 => picky_asn1_x509::cmsversion::CmsVersion::V4,
            ffi::CmsVersion::V5 => picky_asn1_x509::cmsversion::CmsVersion::V5,
        }
    }
}
