#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::x509::algorithm_identifier::ffi::AlgorithmIdentifier;
    use crate::x509::attribute::ffi::{Attribute, AttributeIterator, UnsignedAttribute, UnsignedAttributeIterator};
    use diplomat_runtime::DiplomatWriteable;
    use std::fmt::Write;

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
