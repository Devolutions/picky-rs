#![allow(clippy::needless_lifetimes)] // Diplomat requires explicit lifetimes

#[diplomat::bridge]
pub mod ffi {

    use crate::error::ffi::PickyError;
    use crate::utils::ffi::Buffer;
    use crate::x509::name::ffi::{GeneralName, GeneralNameIterator};
    use diplomat_runtime::DiplomatWriteable;
    use std::fmt::Write;

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
    pub struct ExtensionIterator(pub Vec<Extension>);

    impl ExtensionIterator {
        pub fn next(&mut self) -> Option<Box<Extension>> {
            self.0.pop().map(Box::new)
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

        pub fn to_subject_alt_name(&'a self) -> Option<Box<GeneralNameIterator>> {
            match &self.0 {
                picky_asn1_x509::extension::ExtensionView::SubjectAltName(value) => Some(Box::new(
                    GeneralNameIterator(value.clone().0.into_iter().map(GeneralName).collect()),
                )),
                _ => None,
            }
        }

        pub fn to_issuer_alt_name(&'a self) -> Option<Box<GeneralNameIterator>> {
            match &self.0 {
                picky_asn1_x509::extension::ExtensionView::IssuerAltName(value) => Some(Box::new(GeneralNameIterator(
                    value.clone().0.into_iter().map(GeneralName).collect(),
                ))),
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

        pub fn to_extended_key_usage(&'a self) -> Option<Box<OidIterator>> {
            match self.0 {
                picky_asn1_x509::extension::ExtensionView::ExtendedKeyUsage(value) => {
                    let vec = value.iter().map(|oid| oid.0.clone().into()).collect();

                    Some(Box::new(OidIterator(vec)))
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
    pub struct AuthorityKeyIdentifier(pub picky_asn1_x509::AuthorityKeyIdentifier);

    impl AuthorityKeyIdentifier {
        pub fn get_key_identifier(&self) -> Option<Box<crate::utils::ffi::Buffer>> {
            self.0
                .key_identifier()
                .map(|key_identifier| Buffer::from_bytes(key_identifier).boxed())
        }

        pub fn get_authority_cert_issuer(&self) -> Option<Box<GeneralName>> {
            self.0
                .authority_cert_issuer()
                .map(|general_name| Box::new(GeneralName(general_name)))
        }

        pub fn get_authority_cert_serial_number(&self) -> Option<Box<crate::utils::ffi::Buffer>> {
            self.0
                .authority_cert_serial_number()
                .map(|serial_number| Buffer::from_bytes(&serial_number.0).boxed())
        }
    }
}
