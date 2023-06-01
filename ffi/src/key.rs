use self::ffi::{EcCurve, EdAlgorithm};

impl From<picky::key::EcCurve> for EcCurve {
    fn from(value: picky::key::EcCurve) -> Self {
        match value {
            picky::key::EcCurve::NistP256 => Self::NistP256,
            picky::key::EcCurve::NistP384 => Self::NistP384,
        }
    }
}

impl From<EcCurve> for picky::key::EcCurve {
    fn from(value: EcCurve) -> Self {
        match value {
            EcCurve::NistP256 => Self::NistP256,
            EcCurve::NistP384 => Self::NistP384,
        }
    }
}

impl From<picky::key::EdAlgorithm> for EdAlgorithm {
    fn from(value: picky::key::EdAlgorithm) -> Self {
        match value {
            picky::key::EdAlgorithm::Ed25519 => Self::Ed25519,
            picky::key::EdAlgorithm::X25519 => Self::X25519,
        }
    }
}

impl From<EdAlgorithm> for picky::key::EdAlgorithm {
    fn from(value: EdAlgorithm) -> Self {
        match value {
            EdAlgorithm::Ed25519 => Self::Ed25519,
            EdAlgorithm::X25519 => Self::X25519,
        }
    }
}

#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::pem::ffi::Pem;
    use diplomat_runtime::DiplomatResult;

    /// Known elliptic curve name used for ECDSA arithmetic operations
    #[derive(Clone, Copy)]
    pub enum EcCurve {
        /// NIST P-256
        NistP256,
        /// NIST P-384
        NistP384,
    }

    /// Known Edwards curve-based algorithm name
    #[derive(Clone, Copy)]
    pub enum EdAlgorithm {
        /// Ed25519 signing algorithm
        Ed25519,
        /// X25519 key agreement algorithm
        X25519,
    }

    #[diplomat::opaque]
    pub struct PrivateKey(pub picky::key::PrivateKey);

    impl PrivateKey {
        /// Extracts private key from PEM object.
        pub fn from_pem(pem: &Pem) -> DiplomatResult<Box<PrivateKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PrivateKey::from_pem(&pem.0));
            Ok(Box::new(PrivateKey(key))).into()
        }

        /// Reads a private key from its PKCS8 storage.
        pub fn from_pkcs8(pkcs8: &[u8]) -> DiplomatResult<Box<PrivateKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PrivateKey::from_pkcs8(pkcs8));
            Ok(Box::new(PrivateKey(key))).into()
        }

        /// Generates a new RSA private key.
        ///
        /// This is slow in debug builds.
        pub fn generate_rsa(bits: usize) -> DiplomatResult<Box<PrivateKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PrivateKey::generate_rsa(bits));
            Ok(Box::new(PrivateKey(key))).into()
        }

        /// Generates a new EC private key.
        pub fn generate_ec(curve: EcCurve) -> DiplomatResult<Box<PrivateKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PrivateKey::generate_ec(curve.into()));
            Ok(Box::new(PrivateKey(key))).into()
        }

        // Generates new ed key pair with specified supported algorithm.
        // `write_public_key` specifies whether to include public key in the private key file.
        // Note that OpenSSL does not support ed keys with public key included.
        pub fn generate_ed(
            algorithm: EdAlgorithm,
            write_public_key: bool,
        ) -> DiplomatResult<Box<PrivateKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PrivateKey::generate_ed(algorithm.into(), write_public_key));
            Ok(Box::new(PrivateKey(key))).into()
        }

        /// Exports the private key into a PEM object
        pub fn to_pem(&self) -> DiplomatResult<Box<Pem>, Box<PickyError>> {
            let pem = err_check!(self.0.to_pem());
            Ok(Box::new(Pem(pem))).into()
        }

        /// Extracts the public part of this private key
        pub fn to_public_key(&self) -> DiplomatResult<Box<PublicKey>, Box<PickyError>> {
            let key = err_check!(self.0.to_public_key());
            Ok(Box::new(PublicKey(key))).into()
        }
    }

    #[diplomat::opaque]
    pub struct PublicKey(pub picky::key::PublicKey);

    impl PublicKey {
        /// Extracts public key from PEM object.
        pub fn from_pem(pem: &Pem) -> DiplomatResult<Box<PublicKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PublicKey::from_pem(&pem.0));
            Ok(Box::new(PublicKey(key))).into()
        }

        /// Reads a public key from its DER encoding.
        pub fn from_der(der: &[u8]) -> DiplomatResult<Box<PublicKey>, Box<PickyError>> {
            let key = err_check!(picky::key::PublicKey::from_der(der));
            Ok(Box::new(PublicKey(key))).into()
        }

        /// Exports the public key into a PEM object
        pub fn to_pem(&self) -> DiplomatResult<Box<Pem>, Box<PickyError>> {
            let pem = err_check!(self.0.to_pem());
            Ok(Box::new(Pem(pem))).into()
        }
    }
}
