use picky::hash::HashAlgorithm;

impl TryFrom<ffi::PickyHashAlgorithm> for HashAlgorithm {
    type Error = ();

    fn try_from(ty: ffi::PickyHashAlgorithm) -> Result<Self, ()> {
        match ty {
            ffi::PickyHashAlgorithm::MD5 => Ok(HashAlgorithm::MD5),
            ffi::PickyHashAlgorithm::SHA1 => Ok(HashAlgorithm::SHA1),
            ffi::PickyHashAlgorithm::SHA2_224 => Ok(HashAlgorithm::SHA2_224),
            ffi::PickyHashAlgorithm::SHA2_256 => Ok(HashAlgorithm::SHA2_256),
            ffi::PickyHashAlgorithm::SHA2_384 => Ok(HashAlgorithm::SHA2_384),
            ffi::PickyHashAlgorithm::SHA2_512 => Ok(HashAlgorithm::SHA2_512),
            ffi::PickyHashAlgorithm::SHA3_384 => Ok(HashAlgorithm::SHA3_384),
            ffi::PickyHashAlgorithm::SHA3_512 => Ok(HashAlgorithm::SHA3_512),
            ffi::PickyHashAlgorithm::Unknown => Err(()),
        }
    }
}

impl From<HashAlgorithm> for ffi::PickyHashAlgorithm {
    fn from(ty: HashAlgorithm) -> Self {
        match ty {
            HashAlgorithm::MD5 => ffi::PickyHashAlgorithm::MD5,
            HashAlgorithm::SHA1 => ffi::PickyHashAlgorithm::SHA1,
            HashAlgorithm::SHA2_224 => ffi::PickyHashAlgorithm::SHA2_224,
            HashAlgorithm::SHA2_256 => ffi::PickyHashAlgorithm::SHA2_256,
            HashAlgorithm::SHA2_384 => ffi::PickyHashAlgorithm::SHA2_384,
            HashAlgorithm::SHA2_512 => ffi::PickyHashAlgorithm::SHA2_512,
            HashAlgorithm::SHA3_384 => ffi::PickyHashAlgorithm::SHA3_384,
            HashAlgorithm::SHA3_512 => ffi::PickyHashAlgorithm::SHA3_512,
            _ => ffi::PickyHashAlgorithm::Unknown,
        }
    }
}

#[diplomat::bridge]
pub mod ffi {
    pub enum PickyHashAlgorithm {
        MD5,
        SHA1,
        SHA2_224,
        SHA2_256,
        SHA2_384,
        SHA2_512,
        SHA3_384,
        SHA3_512,
        Unknown,
    }
}
