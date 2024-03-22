use crate::error::ffi::PickyError;

use self::ffi::{EcCurve, EdAlgorithm, KeyKind};

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

impl From<KeyKind> for picky::key::KeyKind {
    fn from(value: KeyKind) -> Self {
        match value {
            KeyKind::Rsa => picky::key::KeyKind::Rsa,
            KeyKind::Ec => picky::key::KeyKind::Ec,
            KeyKind::Ed => picky::key::KeyKind::Ed,
        }
    }
}

impl From<picky::key::KeyKind> for KeyKind {
    fn from(value: picky::key::KeyKind) -> Self {
        match value {
            picky::key::KeyKind::Rsa => KeyKind::Rsa,
            picky::key::KeyKind::Ec => KeyKind::Ec,
            picky::key::KeyKind::Ed => KeyKind::Ed,
        }
    }
}

#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::pem::ffi::Pem;

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

    /// Known key kinds
    #[derive(Clone, Copy)]
    pub enum KeyKind {
        /// RSA (Rivest–Shamir–Adleman)
        Rsa,
        /// Elliptic-curve
        Ec,
        /// Edwards-curve
        Ed,
    }

    #[diplomat::opaque]
    pub struct PrivateKey(pub picky::key::PrivateKey);

    impl PrivateKey {
        /// Extracts private key from PEM object.
        pub fn from_pem(pem: &Pem) -> Result<Box<PrivateKey>, Box<PickyError>> {
            let key = picky::key::PrivateKey::from_pem(&pem.0)?;
            Ok(Box::new(PrivateKey(key)))
        }

        /// Reads a private key from its PKCS8 storage.
        pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Box<PrivateKey>, Box<PickyError>> {
            let key = picky::key::PrivateKey::from_pkcs8(pkcs8)?;
            Ok(Box::new(PrivateKey(key)))
        }

        pub fn from_pem_str(pem: &str) -> Result<Box<PrivateKey>, Box<PickyError>> {
            let key = picky::key::PrivateKey::from_pem_str(pem)?;
            Ok(Box::new(PrivateKey(key)))
        }

        /// Generates a new RSA private key.
        ///
        /// This is slow in debug builds.
        pub fn generate_rsa(bits: usize) -> Result<Box<PrivateKey>, Box<PickyError>> {
            let key = picky::key::PrivateKey::generate_rsa(bits)?;
            Ok(Box::new(PrivateKey(key)))
        }

        /// Generates a new EC private key.
        pub fn generate_ec(curve: EcCurve) -> Result<Box<PrivateKey>, Box<PickyError>> {
            let key = picky::key::PrivateKey::generate_ec(curve.into())?;
            Ok(Box::new(PrivateKey(key)))
        }

        /// Generates new ed key pair with specified supported algorithm.
        ///
        /// `write_public_key` specifies whether to include public key in the private key file.
        /// Note that OpenSSL does not support ed keys with public key included.
        pub fn generate_ed(algorithm: EdAlgorithm, write_public_key: bool) -> Result<Box<PrivateKey>, Box<PickyError>> {
            let key = picky::key::PrivateKey::generate_ed(algorithm.into(), write_public_key)?;
            Ok(Box::new(PrivateKey(key)))
        }

        /// Exports the private key into a PEM object
        pub fn to_pem(&self) -> Result<Box<Pem>, Box<PickyError>> {
            let pem = self.0.to_pem()?;
            Ok(Box::new(Pem(pem)))
        }

        /// Extracts the public part of this private key
        pub fn to_public_key(&self) -> Result<Box<PublicKey>, Box<PickyError>> {
            let key = self.0.to_public_key()?;
            Ok(Box::new(PublicKey(key)))
        }

        /// Retrieves the key kind for this private key.
        pub fn get_kind(&self) -> KeyKind {
            self.0.kind().into()
        }
    }

    #[diplomat::opaque]
    pub struct PublicKey(pub picky::key::PublicKey);

    impl PublicKey {
        /// Extracts public key from PEM object.
        pub fn from_pem(pem: &Pem) -> Result<Box<PublicKey>, Box<PickyError>> {
            let key = picky::key::PublicKey::from_pem(&pem.0)?;
            Ok(Box::new(PublicKey(key)))
        }

        /// Reads a public key from its DER encoding (i.e.: SubjectPublicKeyInfo structure).
        pub fn from_der(der: &[u8]) -> Result<Box<PublicKey>, Box<PickyError>> {
            let key = picky::key::PublicKey::from_der(der)?;
            Ok(Box::new(PublicKey(key)))
        }

        /// Reads a RSA public key from its DER encoding (i.e.: PKCS1).
        pub fn from_pkcs1(der: &[u8]) -> Result<Box<PublicKey>, Box<PickyError>> {
            let key = picky::key::PublicKey::from_pkcs1(der)?;
            Ok(Box::new(PublicKey(key)))
        }

        /// Exports the public key into a PEM object.
        pub fn to_pem(&self) -> Result<Box<Pem>, Box<PickyError>> {
            let pem = self.0.to_pem()?;
            Ok(Box::new(Pem(pem)))
        }

        /// Retrieves the key kind for this public key.
        pub fn get_kind(&self) -> KeyKind {
            self.0.kind().into()
        }
    }
}

/// Returns the required space in bytes to write the DER representation of the PKCS1 archive.
///
/// When an error occurs, 0 is returned.
///
/// # Safety
///
/// - `public_key` must be a pointer to a valid memory location containing a `PublicKey` object.
#[no_mangle]
pub unsafe extern "C" fn PublicKey_pkcs1_encoded_len(public_key: Option<&ffi::PublicKey>) -> usize {
    if let Some(data) = public_key.and_then(|k| k.0.to_pkcs1().ok()) {
        data.len()
    } else {
        0
    }
}

/// Serializes an RSA public key into a PKCS1 archive (DER representation).
///
/// Returns 0 (NULL) on success or a pointer to a `PickyError` on failure.
///
/// # Safety
///
/// - `public_key` must be a pointer to a valid memory location containing a `PublicKey` object.
/// - `dst` must be valid for writes of `count` bytes.
#[no_mangle]
pub unsafe extern "C" fn PublicKey_to_pkcs1(
    public_key: Option<&ffi::PublicKey>,
    dst: *mut u8,
    count: usize,
) -> Option<Box<PickyError>> {
    let Some(public_key) = public_key else {
        return Some("received a null pointer".into());
    };

    let data = match public_key.0.to_pkcs1() {
        Ok(data) => data,
        Err(e) => return Some(e.into()),
    };

    let data_len = data.len();

    if data_len > count {
        return Some("not enough space to fit the DER-encoded PKCS1".into());
    }

    // Safety:
    // - `src` is valid for reads of `data_len` bytes.
    // - `dst` is valid for writes of `data_len` bytes, because it is valid for `count` bytes (caller is responsible for this invariant).
    // - Both `src` and `dst` are always properly aligned: u8 aligment is 1.
    // - Memory regions are not overlapping, `data` is created by us just above.
    std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data_len);

    None
}
