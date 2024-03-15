#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::utils::ffi::{Buffer, StringIterator, StringNestedIterator};
    use crate::x509::algorithm_identifier::ffi::{AlgorithmIdentifier, AlgorithmIdentifierIterator};
    use crate::x509::extension::ffi::{Extension, ExtensionIterator};
    use crate::x509::singer_info::ffi::{CmsVersion, SignerInfo, SignerInfoIterator};
    use crate::x509::string::ffi::DirectoryString;
    use crate::x509::time::ffi::Time;
    use crate::x509::time::ffi::{UTCTime, UTCTimeIterator};
    use diplomat_runtime::DiplomatWriteable;
    use std::fmt::Write;

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
    pub struct AttributeIterator(pub Vec<Attribute>);

    impl AttributeIterator {
        pub fn next(&mut self) -> Option<Box<Attribute>> {
            self.0.pop().map(Box::new)
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

        pub fn to_custom(&self) -> Option<Box<Buffer>> {
            match &self.0 {
                picky_asn1_x509::AttributeValues::Custom(der) => Some(Buffer::from_bytes(&der.0).boxed()),
                _ => None,
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
                    let string_itr = oids.0.clone().into_iter().map(|oid| oid.0.into()).into_iter();
                    Some(Box::new(StringIterator(Box::new(string_itr))))
                }
                _ => None,
            }
        }

        pub fn to_spc_statement_type(&self) -> Option<Box<StringNestedIterator>> {
            match &self.0 {
                picky_asn1_x509::AttributeValues::SpcStatementType(oid_array_set) => {
                    let string_vec_vec: Vec<StringIterator> = oid_array_set
                        .0
                        .clone()
                        .into_iter()
                        .map(|oid_array| StringIterator(Box::new(oid_array.0.into_iter().map(|oid| oid.0.into()))))
                        .collect();

                    Some(Box::new(StringNestedIterator(string_vec_vec)))
                }
                _ => None,
            }
        }

        pub fn to_message_digest(&self) -> Option<Box<StringIterator>> {
            match &self.0 {
                picky_asn1_x509::AttributeValues::MessageDigest(digests) => {
                    let string_itr = digests.0.clone().into_iter().map(|digest| hex::encode(digest.0));
                    Some(Box::new(StringIterator(Box::new(string_itr))))
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
    }

    #[diplomat::opaque]
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

    //====================================================================
    // AttributeTypeAndValue

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

    // ====================================================================
    // UnsignedAttribute

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
    pub struct UnsignedAttributeIterator(pub Vec<UnsignedAttribute>);

    impl UnsignedAttributeIterator {
        pub fn next(&mut self) -> Option<Box<UnsignedAttribute>> {
            self.0.pop().map(Box::new)
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
    pub struct EncapsulatedContentInfo(pub picky_asn1_x509::content_info::EncapsulatedContentInfo);

    impl EncapsulatedContentInfo {
        pub fn content_type(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let oid: String = self.0.content_type.0.clone().into();
            write!(writable, "{}", oid)?;
            Ok(())
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
            match self.0.version.map(|v| match v {
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

    /// TODO: this could be lifted in future diplomat-tool, Diplomat does not allow Option wrapped enums, so we have to use a None variant
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
}
