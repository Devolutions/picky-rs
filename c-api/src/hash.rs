use picky::hash::HashAlgorithm;

impl TryFrom<ffi::HashAlgorithm> for HashAlgorithm {
    type Error = ();

    fn try_from(ty: ffi::HashAlgorithm) -> Result<Self, ()> {
        match ty {
            ffi::HashAlgorithm::MD5 => Ok(HashAlgorithm::MD5),
            ffi::HashAlgorithm::SHA1 => Ok(HashAlgorithm::SHA1),
            ffi::HashAlgorithm::SHA2_224 => Ok(HashAlgorithm::SHA2_224),
            ffi::HashAlgorithm::SHA2_256 => Ok(HashAlgorithm::SHA2_256),
            ffi::HashAlgorithm::SHA2_384 => Ok(HashAlgorithm::SHA2_384),
            ffi::HashAlgorithm::SHA2_512 => Ok(HashAlgorithm::SHA2_512),
            ffi::HashAlgorithm::SHA3_384 => Ok(HashAlgorithm::SHA3_384),
            ffi::HashAlgorithm::SHA3_512 => Ok(HashAlgorithm::SHA3_512),
            ffi::HashAlgorithm::Unknown => Err(()),
        }
    }
}

impl From<HashAlgorithm> for ffi::HashAlgorithm {
    fn from(ty: HashAlgorithm) -> Self {
        match ty {
            HashAlgorithm::MD5 => ffi::HashAlgorithm::MD5,
            HashAlgorithm::SHA1 => ffi::HashAlgorithm::SHA1,
            HashAlgorithm::SHA2_224 => ffi::HashAlgorithm::SHA2_224,
            HashAlgorithm::SHA2_256 => ffi::HashAlgorithm::SHA2_256,
            HashAlgorithm::SHA2_384 => ffi::HashAlgorithm::SHA2_384,
            HashAlgorithm::SHA2_512 => ffi::HashAlgorithm::SHA2_512,
            HashAlgorithm::SHA3_384 => ffi::HashAlgorithm::SHA3_384,
            HashAlgorithm::SHA3_512 => ffi::HashAlgorithm::SHA3_512,
            _ => ffi::HashAlgorithm::Unknown,
        }
    }
}

#[diplomat::bridge]
pub mod ffi {
    pub enum HashAlgorithm {
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
