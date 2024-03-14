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
    use crate::utils::ffi::{Buffer, BufferIterator, StringIterator, StringNestedIterator};

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

        pub fn get_signature(&self) -> Box<crate::utils::ffi::Buffer> {
            Box::new(crate::utils::ffi::Buffer::from(&self.0.signature.0))
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

        pub fn get_signed_attributes(&self) -> Box<AttributeIterator> {
            let attributes = self.0.signed_attrs.0.clone();
            let vec = attributes.0 .0.into_iter().map(Attribute).collect();
            Box::new(AttributeIterator(vec))
        }
    }

    #[diplomat::opaque]
    pub struct Attribute(pub picky_asn1_x509::Attribute);

    impl Attribute {
        pub fn get_type(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let oid: String = self.0.ty.0.clone().into();
            write!(writable, "{}", oid)?;
            Ok(())
        }

        pub fn get_values(&self) -> Box<AttributeValues> {
            Box::new(AttributeValues(self.0.value.clone()))
        }
    }

    #[diplomat::opaque]
    pub struct AttributeValues(pub picky_asn1_x509::AttributeValues);

    pub enum AttributeValueType {
        Extensions,
        ContentType,
        SpcStatementType,
        MessageDigest,
        SigningTime,
        SpcSpOpusInfo,
        Custom,
    }

    impl AttributeValues {
        pub fn get_type(&self) -> AttributeValueType {
            match &self.0 {
                picky_asn1_x509::AttributeValues::Extensions(_) => AttributeValueType::Extensions,
                picky_asn1_x509::AttributeValues::ContentType(_) => AttributeValueType::ContentType,
                picky_asn1_x509::AttributeValues::SpcStatementType(_) => AttributeValueType::SpcStatementType,
                picky_asn1_x509::AttributeValues::MessageDigest(_) => AttributeValueType::MessageDigest,
                picky_asn1_x509::AttributeValues::SigningTime(_) => AttributeValueType::SigningTime,
                picky_asn1_x509::AttributeValues::SpcSpOpusInfo(_) => AttributeValueType::SpcSpOpusInfo,
                picky_asn1_x509::AttributeValues::Custom(_) => AttributeValueType::Custom,
            }
        }

        pub fn to_extensions(&self) -> Option<Box<ExtensionIterator>> {
            match &self.0 {
                picky_asn1_x509::AttributeValues::Extensions(extensions) => {
                    // the set will always have 1 element in this variant
                    let Some(extetions) = extensions.0.first() else {
                        return None;
                    };

                    let vec: Vec<Extension> = extetions.0.clone().into_iter().map(Extension).collect();

                    Some(Box::new(ExtensionIterator(vec)))
                }
                _ => None,
            }
        }

        pub fn to_content_type(&self) -> Option<Box<StringIterator>> {
            match &self.0 {
                picky_asn1_x509::AttributeValues::ContentType(oids) => {
                    let string_vec = oids.0.clone().into_iter().map(|oid| oid.0.into()).collect();
                    Some(Box::new(StringIterator(string_vec)))
                }
                _ => None,
            }
        }

        pub fn to_spc_statement_type(&self) -> Option<Box<StringNestedIterator>> {
            match &self.0 {
                picky_asn1_x509::AttributeValues::SpcStatementType(oid_array_set) => {
                    let string_vec_vec: Vec<Vec<String>> = oid_array_set
                        .0
                        .clone()
                        .into_iter()
                        .map(|oid_array| oid_array.0.into_iter().map(|oid| oid.0.into()).collect())
                        .collect();

                    Some(Box::new(StringNestedIterator(string_vec_vec)))
                }
                _ => None,
            }
        }

        pub fn to_message_digest(&self) -> Option<Box<StringIterator>> {
            match &self.0 {
                picky_asn1_x509::AttributeValues::MessageDigest(digests) => {
                    let string_vec = digests
                        .0
                        .clone()
                        .into_iter()
                        .map(|digest| hex::encode(digest.0))
                        .collect();
                    Some(Box::new(StringIterator(string_vec)))
                }
                _ => None,
            }
        }

        pub fn to_signing_time(&self) -> Option<Box<UTCTimeIterator>> {
            match &self.0 {
                picky_asn1_x509::AttributeValues::SigningTime(times) => {
                    let time_vec = times.0.clone().into_iter().map(|time| UTCTime(time.0)).collect();
                    Some(Box::new(UTCTimeIterator(time_vec)))
                }
                _ => None,
            }
        }

        pub fn to_spc_sp_opus_info(&self) -> Option<Box<SpcSpOpusInfoIterator>> {
            match &self.0 {
                picky_asn1_x509::AttributeValues::SpcSpOpusInfo(spc_sp_opus_info) => {
                    let vec = spc_sp_opus_info.0.clone().into_iter().map(SpcSpOpusInfo).collect();
                    Some(Box::new(SpcSpOpusInfoIterator(vec)))
                }
                _ => None,
            }
        }

        pub fn to_custom(&self) -> Option<Box<Buffer>> {
            match &self.0 {
                picky_asn1_x509::AttributeValues::Custom(der) => Some(Buffer::from_bytes(&der.0).boxed()),
                _ => None,
            }
        }
    }
    #[diplomat::opaque] //TODO:
    pub struct SpcSpOpusInfo(picky_asn1_x509::pkcs7::content_info::SpcSpOpusInfo);

    impl SpcSpOpusInfo {
        pub fn get_program_name(&self) -> Option<Box<SpcString>> {
            self.0
                .program_name
                .as_ref()
                .map(|program_name| Box::new(SpcString(program_name.0.clone())))
        }

        pub fn get_more_info(&self) -> Option<Box<SpcLink>> {
            self.0
                .more_info
                .as_ref()
                .map(|more_info| Box::new(SpcLink(more_info.0.clone())))
        }
    }

    #[diplomat::opaque]
    pub struct SpcString(picky_asn1_x509::pkcs7::content_info::SpcString);

    pub enum SpcStringType {
        Unicode,
        Ancii,
    }

    impl SpcString {
        pub fn get_type(&self) -> SpcStringType {
            match &self.0 {
                picky_asn1_x509::pkcs7::content_info::SpcString::Unicode(_) => SpcStringType::Unicode,
                picky_asn1_x509::pkcs7::content_info::SpcString::Ancii(_) => SpcStringType::Ancii,
            }
        }

        pub fn get_as_string(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            match &self.0 {
                picky_asn1_x509::pkcs7::content_info::SpcString::Unicode(unicode) => {
                    write!(writable, "{}", unicode.0 .0 .0)?;
                }
                picky_asn1_x509::pkcs7::content_info::SpcString::Ancii(ancii) => {
                    write!(writable, "{}", ancii.0 .0 .0)?;
                }
            };
            Ok(())
        }

        pub fn get_as_bytes(&self) -> Box<Buffer> {
            match &self.0 {
                picky_asn1_x509::pkcs7::content_info::SpcString::Unicode(unicode) => {
                    Buffer::from_bytes(&unicode.0 .0 .0).boxed()
                }
                picky_asn1_x509::pkcs7::content_info::SpcString::Ancii(ancii) => {
                    Buffer::from_bytes(&ancii.0 .0 .0).boxed()
                }
            }
        }
    }

    #[diplomat::opaque] // TODO
    pub struct SpcLink(picky_asn1_x509::pkcs7::content_info::SpcLink);

    pub enum SpcLinkType {
        Url,
        Moniker,
        File,
    }

    impl SpcLink {
        pub fn get_type(&self) -> SpcLinkType {
            match &self.0 {
                picky_asn1_x509::pkcs7::content_info::SpcLink::Url(_) => SpcLinkType::Url,
                picky_asn1_x509::pkcs7::content_info::SpcLink::Moniker(_) => SpcLinkType::Moniker,
                picky_asn1_x509::pkcs7::content_info::SpcLink::File(_) => SpcLinkType::File,
            }
        }

        pub fn get_url(&self) -> Option<Box<Buffer>> {
            match &self.0 {
                picky_asn1_x509::pkcs7::content_info::SpcLink::Url(url) => {
                    let clone = url.0.clone();
                    Some(Buffer::from_bytes(&clone.0 .0).boxed())
                }
                _ => None,
            }
        }

        pub fn get_moniker(&self) -> Option<Box<SpcSerializedObject>> {
            match &self.0 {
                picky_asn1_x509::pkcs7::content_info::SpcLink::Moniker(moniker) => {
                    Some(Box::new(SpcSerializedObject(moniker.0.clone().0 .0)))
                }
                _ => None,
            }
        }

        pub fn get_file(&self) -> Option<Box<SpcString>> {
            match &self.0 {
                picky_asn1_x509::pkcs7::content_info::SpcLink::File(file) => {
                    let clone = file.0.clone();
                    Some(Box::new(SpcString(clone.0)))
                }
                _ => None,
            }
        }
    }

    #[diplomat::opaque]
    pub struct SpcSerializedObject(picky_asn1_x509::pkcs7::content_info::SpcSerializedObject);

    impl SpcSerializedObject {
        pub fn get_class_id(&self) -> Box<Buffer> {
            Buffer::from_bytes(&self.0.class_id.0 .0).boxed()
        }

        pub fn get_object_id(&self) -> Box<Buffer> {
            Buffer::from_bytes(&self.0.serialized_data.0).boxed()
        }
    }

    #[diplomat::opaque]
    pub struct SpcSpOpusInfoIterator(pub Vec<SpcSpOpusInfo>);

    impl SpcSpOpusInfoIterator {
        pub fn next(&mut self) -> Option<Box<SpcSpOpusInfo>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque] // TODO
    pub struct UTCTime(picky_asn1::date::UTCTime);

    impl UTCTime {
        pub fn get_year(&self) -> u16 {
            self.0.year()
        }

        pub fn get_month(&self) -> u8 {
            self.0.month()
        }

        pub fn get_day(&self) -> u8 {
            self.0.day()
        }

        pub fn get_hour(&self) -> u8 {
            self.0.hour()
        }

        pub fn get_minute(&self) -> u8 {
            self.0.minute()
        }

        pub fn get_second(&self) -> u8 {
            self.0.second()
        }
    }

    #[diplomat::opaque]
    pub struct UTCTimeIterator(pub Vec<UTCTime>);

    impl UTCTimeIterator {
        pub fn next(&mut self) -> Option<Box<UTCTime>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct AttributeIterator(pub Vec<Attribute>);

    impl AttributeIterator {
        pub fn next(&mut self) -> Option<Box<Attribute>> {
            self.0.pop().map(Box::new)
        }
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

        pub fn get_crls(&self) -> Option<Box<RevocationInfoChoiceIterator>> {
            self.0
                .crls
                .as_ref()
                .map(|crls| Box::new(RevocationInfoChoiceIterator(crls.clone())))
        }

        pub fn get_certificates(&self) -> Box<CertificateChoicesIterator> {
            Box::new(CertificateChoicesIterator(self.0.certificates.0.clone()))
        }

        pub fn get_signers_infos(&self) -> Box<SignerInfoIterator> {
            let signer_infos = &self.0.signers_infos;
            let vec_signer_infos: Vec<_> = signer_infos.0.iter().cloned().map(SignerInfo).collect();
            Box::new(SignerInfoIterator(vec_signer_infos))
        }
    }

    #[diplomat::opaque]
    pub struct CertificateChoicesIterator(pub picky_asn1_x509::signed_data::CertificateSet);

    impl CertificateChoicesIterator {
        pub fn next(&mut self) -> Option<Box<CertificateChoices>> {
            self.0 .0.pop().map(|cert| Box::new(CertificateChoices(cert)))
        }
    }

    #[diplomat::opaque]
    pub struct CertificateChoices(pub picky_asn1_x509::signed_data::CertificateChoices);

    impl CertificateChoices {
        pub fn get_certificate(&self) -> Option<Box<Buffer>> {
            match &self.0 {
                picky_asn1_x509::signed_data::CertificateChoices::Certificate(der) => {
                    Some(Buffer::from_bytes(&der.0).boxed())
                }
                _ => None,
            }
        }

        pub fn get_other(&self) -> Option<Box<Buffer>> {
            match &self.0 {
                picky_asn1_x509::signed_data::CertificateChoices::Other(der) => {
                    Some(Buffer::from_bytes(&der.0).boxed())
                }
                _ => None,
            }
        }

        pub fn is_certificate(&self) -> bool {
            matches!(
                &self.0,
                picky_asn1_x509::signed_data::CertificateChoices::Certificate(_)
            )
        }
    }

    #[diplomat::opaque]
    pub struct RevocationInfoChoiceIterator(pub picky_asn1_x509::crls::RevocationInfoChoices);

    impl RevocationInfoChoiceIterator {
        pub fn next(&mut self) -> Option<Box<RevocationInfoChoice>> {
            self.0 .0.pop().map(|v| Box::new(RevocationInfoChoice(v)))
        }
    }

    #[diplomat::opaque]
    pub struct RevocationInfoChoice(pub picky_asn1_x509::crls::RevocationInfoChoice);

    impl RevocationInfoChoice {
        pub fn get_crl(&self) -> Option<Box<CertificateList>> {
            match &self.0 {
                picky_asn1_x509::crls::RevocationInfoChoice::Crl(crl) => Some(Box::new(CertificateList(crl.clone()))),
                _ => None,
            }
        }
    }

    #[diplomat::opaque]
    pub struct CertificateList(pub picky_asn1_x509::crls::CertificateList);

    impl CertificateList {
        pub fn get_tbs_cert_list(&self) -> Box<TbsCertList> {
            Box::new(TbsCertList(self.0.tbs_cert_list.clone()))
        }

        pub fn get_signature_algorithm(&self) -> Box<AlgorithmIdentifier> {
            Box::new(AlgorithmIdentifier(self.0.signature_algorithm.clone()))
        }

        pub fn get_signature_value(&self) -> Box<Buffer> {
            Buffer::from_bytes(self.0.signature_value.clone().payload_view()).boxed()
        }
    }
    #[diplomat::opaque]
    pub struct TbsCertList(pub picky_asn1_x509::crls::TbsCertList);

    impl TbsCertList {
        pub fn get_version(&self) -> Version {
            match self.0.version.clone().map(|v| match v {
                picky_asn1_x509::Version::V1 => Version::V1,
                picky_asn1_x509::Version::V2 => Version::V2,
                picky_asn1_x509::Version::V3 => Version::V3,
            }) {
                Some(v) => v,
                None => Version::None,
            }
        }

        pub fn get_signature_algorithm(&self) -> Box<AlgorithmIdentifier> {
            Box::new(AlgorithmIdentifier(self.0.signature.clone()))
        }

        pub fn get_issuer(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let name_string = format!("{}", self.0.issuer);
            write!(writable, "{}", name_string)?;
            Ok(())
        }

        pub fn get_this_upate(&self) -> Box<Time> {
            Box::new(Time(self.0.this_update.clone()))
        }

        pub fn get_next_update(&self) -> Option<Box<Time>> {
            self.0.next_update.clone().map(Time).map(Box::new)
        }

        pub fn get_revoked_certificates(&self) -> Option<Box<RevokedCertificateIterator>> {
            self.0.revoked_certificates.as_ref().map(|revoked_certificates| {
                let mut vec = vec![];
                revoked_certificates.0.iter().for_each(|revoked_certificate| {
                    vec.push(RevokedCertificate(revoked_certificate.clone()));
                });
                Box::new(RevokedCertificateIterator(vec))
            })
        }

        pub fn get_extenstions(&self) -> Option<Box<ExtensionIterator>> {
            self.0.crl_extension.as_ref().map(|extensions| {
                Box::new(ExtensionIterator(
                    extensions
                        .0
                        .iter()
                        .map(|extension| Extension(extension.clone()))
                        .collect(),
                ))
            })
        }
    }

    #[diplomat::opaque]
    pub struct Time(picky_asn1_x509::validity::Time);

    impl Time {
        pub fn get_year(&self) -> u16 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.year(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.year(),
            }
        }

        pub fn get_month(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.month(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.month(),
            }
        }

        pub fn get_day(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.day(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.day(),
            }
        }

        pub fn get_hour(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.hour(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.hour(),
            }
        }

        pub fn get_minute(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.minute(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.minute(),
            }
        }

        pub fn get_second(&self) -> u8 {
            match &self.0 {
                picky_asn1_x509::validity::Time::Utc(utc_time) => utc_time.0.second(),
                picky_asn1_x509::validity::Time::Generalized(generalized_time) => generalized_time.0.second(),
            }
        }

        pub fn is_utc(&self) -> bool {
            matches!(&self.0, picky_asn1_x509::validity::Time::Utc(_))
        }

        pub fn is_generalized(&self) -> bool {
            matches!(&self.0, picky_asn1_x509::validity::Time::Generalized(_))
        }
    }

    /// Diplomat does not allow Option wrapped enums, so we have to use a None variant
    pub enum Version {
        None,
        V1,
        V2,
        V3,
    }

    #[diplomat::opaque]
    pub struct RevokedCertificate(picky_asn1_x509::crls::RevokedCertificate);

    impl RevokedCertificate {
        pub fn get_user_certificate(&self) -> Box<Buffer> {
            let vec = self.0.user_certificate.0 .0.clone();
            Buffer::from_bytes(&vec).boxed()
        }

        pub fn get_revocation_date(&self) -> Box<Time> {
            Box::new(Time(self.0.revocation_data.clone()))
        }

        pub fn get_extensions(&self) -> Option<Box<ExtensionIterator>> {
            self.0.crl_entry_extensions.as_ref().map(|extensions| {
                Box::new(ExtensionIterator(
                    extensions
                        .0
                        .iter()
                        .map(|extension| Extension(extension.clone()))
                        .collect(),
                ))
            })
        }
    }

    #[diplomat::opaque]
    pub struct RevokedCertificateIterator(pub Vec<RevokedCertificate>);

    impl RevokedCertificateIterator {
        pub fn next(&mut self) -> Option<Box<RevokedCertificate>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct Extension(pub picky_asn1_x509::extension::Extension);

    impl Extension {
        pub fn get_extn_id(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let oid: String = self.0.extn_id().0.clone().into();
            write!(writable, "{}", oid)?;
            Ok(())
        }

        pub fn get_critical(&self) -> bool {
            self.0.critical()
        }

        pub fn get_value<'a>(&'a self) -> Box<ExtensionView<'a>> {
            let value = self.0.extn_value();
            Box::new(ExtensionView(value))
        }
    }

    #[diplomat::opaque]
    pub struct ExtensionView<'a>(pub picky_asn1_x509::extension::ExtensionView<'a>);

    pub enum ExtensionViewType {
        AuthorityKeyIdentifier,
        SubjectKeyIdentifier,
        KeyUsage,
        SubjectAltName,
        IssuerAltName,
        BasicConstraints,
        ExtendedKeyUsage,
        Generic,
        CrlNumber,
    }

    impl<'a> ExtensionView<'a> {
        pub fn get_type(&'a self) -> ExtensionViewType {
            match self.0 {
                picky_asn1_x509::extension::ExtensionView::AuthorityKeyIdentifier(_) => {
                    ExtensionViewType::AuthorityKeyIdentifier
                }
                picky_asn1_x509::extension::ExtensionView::SubjectKeyIdentifier(_) => {
                    ExtensionViewType::SubjectKeyIdentifier
                }
                picky_asn1_x509::extension::ExtensionView::KeyUsage(_) => ExtensionViewType::KeyUsage,
                picky_asn1_x509::extension::ExtensionView::SubjectAltName(_) => ExtensionViewType::SubjectAltName,
                picky_asn1_x509::extension::ExtensionView::IssuerAltName(_) => ExtensionViewType::IssuerAltName,
                picky_asn1_x509::extension::ExtensionView::BasicConstraints(_) => ExtensionViewType::BasicConstraints,
                picky_asn1_x509::extension::ExtensionView::ExtendedKeyUsage(_) => ExtensionViewType::ExtendedKeyUsage,
                picky_asn1_x509::extension::ExtensionView::Generic(_) => ExtensionViewType::Generic,
                picky_asn1_x509::extension::ExtensionView::CrlNumber(_) => ExtensionViewType::CrlNumber,
            }
        }

        pub fn to_authority_key_identifier(&'a self) -> Option<Box<AuthorityKeyIdentifier>> {
            match self.0 {
                picky_asn1_x509::extension::ExtensionView::AuthorityKeyIdentifier(value) => {
                    Some(Box::new(AuthorityKeyIdentifier(value.clone())))
                }
                _ => None,
            }
        }

        pub fn to_subject_key_identifier(&'a self) -> Option<Box<crate::utils::ffi::Buffer>> {
            match self.0 {
                picky_asn1_x509::extension::ExtensionView::SubjectKeyIdentifier(value) => {
                    let buffer = crate::utils::ffi::Buffer::from_bytes(&value.0).boxed();
                    Some(buffer)
                }
                _ => None,
            }
        }

        pub fn to_key_usage(&'a self) -> Option<Box<Buffer>> {
            match self.0 {
                picky_asn1_x509::extension::ExtensionView::KeyUsage(value) => {
                    Some(Buffer::from_bytes(value.as_bytes()).boxed())
                }
                _ => None,
            }
        }

        pub fn to_subject_alt_name(&'a self) -> Option<Box<crate::x509::ffi::GeneralNameIterator>> {
            match &self.0 {
                picky_asn1_x509::extension::ExtensionView::SubjectAltName(value) => Some(Box::new(
                    crate::x509::ffi::GeneralNameIterator(value.clone().0.into_iter().map(GeneralName).collect()),
                )),
                _ => None,
            }
        }

        pub fn to_issuer_alt_name(&'a self) -> Option<Box<crate::x509::ffi::GeneralNameIterator>> {
            match &self.0 {
                picky_asn1_x509::extension::ExtensionView::IssuerAltName(value) => Some(Box::new(
                    crate::x509::ffi::GeneralNameIterator(value.clone().0.into_iter().map(GeneralName).collect()),
                )),
                _ => None,
            }
        }

        pub fn to_basic_constraints(&'a self) -> Option<Box<BasicConstraints>> {
            match self.0 {
                picky_asn1_x509::extension::ExtensionView::BasicConstraints(value) => {
                    Some(Box::new(BasicConstraints(value.clone())))
                }
                _ => None,
            }
        }

        pub fn to_extended_key_usage(&'a self) -> Option<Box<crate::x509::ffi::OidIterator>> {
            match self.0 {
                picky_asn1_x509::extension::ExtensionView::ExtendedKeyUsage(value) => {
                    let vec = value.iter().map(|oid| oid.0.clone().into()).collect();

                    Some(Box::new(crate::x509::ffi::OidIterator(vec)))
                }
                _ => None,
            }
        }

        pub fn to_generic(&'a self) -> Option<Box<crate::utils::ffi::Buffer>> {
            match &self.0 {
                picky_asn1_x509::extension::ExtensionView::Generic(value) => Some(Buffer::from_bytes(&value.0).boxed()),
                _ => None,
            }
        }

        pub fn to_crl_number(&'a self) -> Option<Box<crate::utils::ffi::Buffer>> {
            match &self.0 {
                picky_asn1_x509::extension::ExtensionView::CrlNumber(value) => {
                    Some(Buffer::from_bytes(&value.0).boxed())
                }
                _ => None,
            }
        }
    }

    #[diplomat::opaque]
    pub struct OidIterator(pub Vec<String>);

    impl OidIterator {
        pub fn next(&mut self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let oid = self.0.pop().ok_or("no more OIDs")?;
            write!(writable, "{}", oid)?;
            Ok(())
        }
    }

    #[diplomat::opaque]
    pub struct BasicConstraints(pub picky_asn1_x509::BasicConstraints);

    impl BasicConstraints {
        pub fn get_ca(&self) -> Option<bool> {
            self.0.ca()
        }

        pub fn get_pathlen(&self) -> Option<u8> {
            self.0.pathlen()
        }
    }

    #[diplomat::opaque]
    pub struct GeneralNameIterator(pub Vec<GeneralName>);

    impl GeneralNameIterator {
        pub fn next(&mut self) -> Option<Box<GeneralName>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct GeneralName(pub picky_asn1_x509::name::GeneralName);

    impl GeneralName {
        pub fn get_type(&self) -> GeneralNameType {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::OtherName(_) => GeneralNameType::OtherName,
                picky_asn1_x509::name::GeneralName::Rfc822Name(_) => GeneralNameType::Rfc822Name,
                picky_asn1_x509::name::GeneralName::DnsName(_) => GeneralNameType::DnsName,
                picky_asn1_x509::name::GeneralName::DirectoryName(_) => GeneralNameType::DirectoryName,
                picky_asn1_x509::name::GeneralName::EdiPartyName(_) => GeneralNameType::EdiPartyName,
                picky_asn1_x509::name::GeneralName::Uri(_) => GeneralNameType::Uri,
                picky_asn1_x509::name::GeneralName::IpAddress(_) => GeneralNameType::IpAddress,
                picky_asn1_x509::name::GeneralName::RegisteredId(_) => GeneralNameType::RegisteredId,
            }
        }

        pub fn to_other_name(&self) -> Option<Box<OtherName>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::OtherName(other_name) => {
                    Some(Box::new(OtherName(other_name.clone())))
                }
                _ => None,
            }
        }

        pub fn to_rfc822_name(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::Rfc822Name(rfc822_name) => {
                    write!(writable, "{}", rfc822_name.0)?;
                    Ok(())
                }
                _ => Err("not an RFC822 name".into()),
            }
        }

        pub fn to_dns_name(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::DnsName(dns_name) => {
                    write!(writable, "{}", dns_name.0)?;
                    Ok(())
                }
                _ => Err("not a DNS name".into()),
            }
        }

        pub fn to_directory_name(&self) -> Option<AttributeTypeAndValueNestedIterator> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::DirectoryName(directory_name) => {
                    let mut vec = vec![];
                    let clone = directory_name.0.clone();
                    for names in clone.0 {
                        vec.push(AttributeTypeAndValueIterator(
                            names.0.clone().into_iter().map(AttributeTypeAndValue).collect(),
                        ));
                    }
                    Some(AttributeTypeAndValueNestedIterator(vec))
                }
                _ => None,
            }
        }

        pub fn to_edi_party_name(&self) -> Option<Box<EdiPartyName>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::EdiPartyName(edi_party_name) => {
                    Some(Box::new(EdiPartyName(edi_party_name.clone())))
                }
                _ => None,
            }
        }

        pub fn to_uri(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::Uri(uri) => {
                    write!(writable, "{}", uri.0)?;
                    Ok(())
                }
                _ => Err("not a URI".into()),
            }
        }

        pub fn to_ip_address(&self) -> Option<Box<Buffer>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::IpAddress(ip_address) => {
                    Some(Buffer::from_bytes(&ip_address.0).boxed())
                }
                _ => None,
            }
        }

        pub fn to_registered_id(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            match &self.0 {
                picky_asn1_x509::name::GeneralName::RegisteredId(registered_id) => {
                    let oid: String = registered_id.0.clone().into();
                    write!(writable, "{}", oid)?;
                    Ok(())
                }
                _ => Err("not a registered ID".into()),
            }
        }
    }

    #[diplomat::opaque]
    pub struct AttributeTypeAndValueIterator(pub Vec<AttributeTypeAndValue>);

    impl AttributeTypeAndValueIterator {
        pub fn next(&mut self) -> Option<Box<AttributeTypeAndValue>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct AttributeTypeAndValueNestedIterator(pub Vec<AttributeTypeAndValueIterator>);

    impl AttributeTypeAndValueNestedIterator {
        pub fn next(&mut self) -> Option<Box<AttributeTypeAndValueIterator>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct AttributeTypeAndValue(pub picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValue);

    impl AttributeTypeAndValue {
        pub fn get_type_id(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let oid: String = self.0.ty.0.clone().into();
            write!(writable, "{}", oid)?;
            Ok(())
        }

        pub fn get_value(&self) -> Box<AttributeTypeAndValueParameters> {
            Box::new(AttributeTypeAndValueParameters(self.0.value.clone()))
        }
    }

    #[diplomat::opaque]
    pub struct AttributeTypeAndValueParameters(
        pub picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters,
    );

    pub enum AttributeTypeAndValueParametersType {
        CommonName,
        Surname,
        SerialNumber,
        CountryName,
        LocalityName,
        StateOrProvinceName,
        StreetName,
        OrganizationName,
        OrganizationalUnitName,
        EmailAddress,
        GivenName,
        Phone,
        Custom,
    }

    impl AttributeTypeAndValueParameters {
        pub fn get_type(&self) -> AttributeTypeAndValueParametersType {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::CommonName(_) => {
                    AttributeTypeAndValueParametersType::CommonName
                }
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::Surname(_) => {
                    AttributeTypeAndValueParametersType::Surname
                }
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::SerialNumber(_) => {
                    AttributeTypeAndValueParametersType::SerialNumber
                }
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::CountryName(_) => {
                    AttributeTypeAndValueParametersType::CountryName
                }
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::LocalityName(_) => {
                    AttributeTypeAndValueParametersType::LocalityName
                }
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::StateOrProvinceName(_) => {
                    AttributeTypeAndValueParametersType::StateOrProvinceName
                }
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::StreetName(_) => {
                    AttributeTypeAndValueParametersType::StreetName
                }
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::OrganizationName(_) => {
                    AttributeTypeAndValueParametersType::OrganizationName
                }
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::OrganizationalUnitName(
                    _,
                ) => AttributeTypeAndValueParametersType::OrganizationalUnitName,
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::GivenName(_) => {
                    AttributeTypeAndValueParametersType::GivenName
                }
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::Phone(_) => {
                    AttributeTypeAndValueParametersType::Phone
                }
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::Custom(_) => {
                    AttributeTypeAndValueParametersType::Custom
                }
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::EmailAddress(_) => {
                    AttributeTypeAndValueParametersType::EmailAddress
                }
            }
        }

        pub fn to_common_name(&self) -> Option<Box<DirectoryString>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::CommonName(common_name) => {
                    Some(Box::new(DirectoryString(common_name.clone())))
                }
                _ => None,
            }
        }

        pub fn to_surname(&self) -> Option<Box<DirectoryString>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::Surname(surname) => {
                    Some(Box::new(DirectoryString(surname.clone())))
                }
                _ => None,
            }
        }

        pub fn to_serial_number(&self) -> Option<Box<DirectoryString>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::SerialNumber(
                    serial_number,
                ) => Some(Box::new(DirectoryString(serial_number.clone()))),
                _ => None,
            }
        }

        pub fn to_country_name(&self) -> Option<Box<DirectoryString>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::CountryName(
                    country_name,
                ) => Some(Box::new(DirectoryString(country_name.clone()))),
                _ => None,
            }
        }

        pub fn to_locality_name(&self) -> Option<Box<DirectoryString>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::LocalityName(
                    locality_name,
                ) => Some(Box::new(DirectoryString(locality_name.clone()))),
                _ => None,
            }
        }

        pub fn to_state_or_province_name(&self) -> Option<Box<DirectoryString>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::StateOrProvinceName(
                    state_or_province_name,
                ) => Some(Box::new(DirectoryString(state_or_province_name.clone()))),
                _ => None,
            }
        }

        pub fn to_street_name(&self) -> Option<Box<DirectoryString>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::StreetName(street_name) => {
                    Some(Box::new(DirectoryString(street_name.clone())))
                }
                _ => None,
            }
        }

        pub fn to_organization_name(&self) -> Option<Box<DirectoryString>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::OrganizationName(
                    organization_name,
                ) => Some(Box::new(DirectoryString(organization_name.clone()))),
                _ => None,
            }
        }

        pub fn to_organizational_unit_name(&self) -> Option<Box<DirectoryString>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::OrganizationalUnitName(
                    organizational_unit_name,
                ) => Some(Box::new(DirectoryString(organizational_unit_name.clone()))),
                _ => None,
            }
        }

        pub fn to_email_address(&self) -> Option<Box<Buffer>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::EmailAddress(
                    email_address,
                ) => Some(Buffer::from_bytes(email_address.as_bytes()).boxed()),
                _ => None,
            }
        }

        pub fn to_given_name(&self) -> Option<Box<DirectoryString>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::GivenName(given_name) => {
                    Some(Box::new(DirectoryString(given_name.clone())))
                }
                _ => None,
            }
        }

        pub fn to_phone(&self) -> Option<Box<DirectoryString>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::Phone(phone) => {
                    Some(Box::new(DirectoryString(phone.clone())))
                }
                _ => None,
            }
        }

        pub fn to_custom(&self) -> Option<Box<Buffer>> {
            match &self.0 {
                picky_asn1_x509::attribute_type_and_value::AttributeTypeAndValueParameters::Custom(custom) => {
                    Some(Buffer::from_bytes(&custom.0).boxed())
                }
                _ => None,
            }
        }
    }

    #[diplomat::opaque]
    pub struct DirectoryString(pub picky_asn1_x509::directory_string::DirectoryString);

    pub enum DirectoryStringType {
        PrintableString,
        Utf8String,
        BmpString,
    }

    impl DirectoryString {
        pub fn get_type(&self) -> DirectoryStringType {
            match &self.0 {
                picky_asn1_x509::directory_string::DirectoryString::PrintableString(_) => {
                    DirectoryStringType::PrintableString
                }
                picky_asn1_x509::directory_string::DirectoryString::Utf8String(_) => DirectoryStringType::Utf8String,
                picky_asn1_x509::directory_string::DirectoryString::BmpString(_) => DirectoryStringType::BmpString,
            }
        }

        pub fn get_as_string(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let string: String = self.0.clone().into();
            write!(writable, "{}", string)?;
            Ok(())
        }

        pub fn get_as_bytes(&self) -> Box<Buffer> {
            match &self.0 {
                picky_asn1_x509::directory_string::DirectoryString::PrintableString(string) => {
                    Buffer::from_bytes(string.as_bytes()).boxed()
                }
                picky_asn1_x509::directory_string::DirectoryString::Utf8String(string) => {
                    Buffer::from_bytes(string.as_bytes()).boxed()
                }
                picky_asn1_x509::directory_string::DirectoryString::BmpString(string) => {
                    Buffer::from_bytes(string.as_bytes()).boxed()
                }
            }
        }
    }

    #[diplomat::opaque]
    pub struct EdiPartyName(pub picky_asn1_x509::name::EdiPartyName);

    impl EdiPartyName {
        pub fn get_name_assigner(&self) -> Option<Box<DirectoryString>> {
            self.0
                .name_assigner
                .as_ref()
                .map(|name_assigner| Box::new(DirectoryString(name_assigner.0.clone())))
        }

        pub fn get_party_name(&self) -> Box<DirectoryString> {
            Box::new(DirectoryString(self.0.party_name.0.clone()))
        }
    }

    #[diplomat::opaque]
    pub struct OtherName(pub picky_asn1_x509::name::OtherName);

    impl OtherName {
        pub fn get_type_id(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let oid: String = self.0.type_id.0.clone().into();
            write!(writable, "{}", oid)?;
            Ok(())
        }

        pub fn get_value(&self) -> Box<crate::utils::ffi::Buffer> {
            Buffer::from_bytes(&self.0.value.0 .0).boxed()
        }
    }

    pub enum GeneralNameType {
        OtherName,
        Rfc822Name,
        DnsName,
        DirectoryName,
        EdiPartyName,
        Uri,
        IpAddress,
        RegisteredId,
    }

    #[diplomat::opaque]
    pub struct AuthorityKeyIdentifier(pub picky_asn1_x509::AuthorityKeyIdentifier);

    impl AuthorityKeyIdentifier {
        pub fn get_key_identifier(&self) -> Option<Box<crate::utils::ffi::Buffer>> {
            self.0
                .key_identifier()
                .map(|key_identifier| Buffer::from_bytes(&key_identifier).boxed())
        }

        pub fn get_authority_cert_issuer(&self) -> Option<Box<GeneralName>> {
            self.0
                .authority_cert_issuer()
                .map(|general_name| Box::new(GeneralName(general_name.clone())))
        }

        pub fn get_authority_cert_serial_number(&self) -> Option<Box<crate::utils::ffi::Buffer>> {
            self.0
                .authority_cert_serial_number()
                .map(|serial_number| Buffer::from_bytes(&serial_number.0).boxed())
        }
    }

    #[diplomat::opaque]
    pub struct ExtensionIterator(pub Vec<Extension>);

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

        pub fn get_subject_key_identifier(&self) -> Option<Box<crate::utils::ffi::Buffer>> {
            let picky_asn1_x509::signer_info::SignerIdentifier::SubjectKeyIdentifier(subject_key_identifier) = &self.0 else {
                return None;
            };

            let buffer = crate::utils::ffi::Buffer::from(&subject_key_identifier.0);
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
    pub struct AlgorithmIdentifierParameters<'a>(pub &'a picky_asn1_x509::AlgorithmIdentifierParameters);

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
                picky_asn1_x509::AlgorithmIdentifierParameters::None => AlgorithmIdentifierParametersType::None,
                picky_asn1_x509::AlgorithmIdentifierParameters::Null => AlgorithmIdentifierParametersType::Null,
                picky_asn1_x509::AlgorithmIdentifierParameters::Aes(_) => AlgorithmIdentifierParametersType::Aes,
                picky_asn1_x509::AlgorithmIdentifierParameters::Ec(_) => AlgorithmIdentifierParametersType::Ec,
                picky_asn1_x509::AlgorithmIdentifierParameters::RsassaPss(_) => {
                    AlgorithmIdentifierParametersType::RsassaPss
                }
            }
        }

        pub fn to_aes(&self) -> Option<Box<AesParameters>> {
            match self.0 {
                picky_asn1_x509::AlgorithmIdentifierParameters::Aes(ref params) => {
                    Some(Box::new(AesParameters(params.clone())))
                }
                _ => None,
            }
        }

        pub fn to_ec(&self) -> Option<Box<EcParameters>> {
            match self.0 {
                picky_asn1_x509::AlgorithmIdentifierParameters::Ec(ref params) => {
                    Some(Box::new(EcParameters(params.clone())))
                }
                _ => None,
            }
        }

        pub fn to_rsassa_pss(&self) -> Option<Box<RsassaPssParameters>> {
            match self.0 {
                picky_asn1_x509::AlgorithmIdentifierParameters::RsassaPss(ref params) => {
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

        pub fn to_initialization_vector(&self) -> Option<Box<crate::utils::ffi::Buffer>> {
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
