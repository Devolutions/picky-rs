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

#[diplomat::bridge]
pub mod ffi {
    use crate::date::ffi::UtcDate;
    use crate::error::ffi::PickyError;
    use crate::key::ffi::PublicKey;
    use crate::pem::ffi::Pem;
    use diplomat_runtime::DiplomatWriteable;
    use picky::x509::certificate;
    use std::fmt::Write;

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
}
