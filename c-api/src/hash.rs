use crate::error::picky_status_t;
use crate::helper::copy_slice_to_c;
use anyhow::Context;
use picky::hash::HashAlgorithm;
use std::os::raw::c_int;

/// See PICKY_HASH_* constants for possible values.
#[derive(PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[repr(transparent)]
pub struct picky_hash_algorithm_t {
    pub id: c_int,
}

pub const PICKY_HASH_MD5: picky_hash_algorithm_t = picky_hash_algorithm_t { id: 0 };
pub const PICKY_HASH_SHA1: picky_hash_algorithm_t = picky_hash_algorithm_t { id: 1 };
pub const PICKY_HASH_SHA2_224: picky_hash_algorithm_t = picky_hash_algorithm_t { id: 2 };
pub const PICKY_HASH_SHA2_256: picky_hash_algorithm_t = picky_hash_algorithm_t { id: 3 };
pub const PICKY_HASH_SHA2_384: picky_hash_algorithm_t = picky_hash_algorithm_t { id: 4 };
pub const PICKY_HASH_SHA2_512: picky_hash_algorithm_t = picky_hash_algorithm_t { id: 5 };
pub const PICKY_HASH_SHA3_384: picky_hash_algorithm_t = picky_hash_algorithm_t { id: 6 };
pub const PICKY_HASH_SHA3_512: picky_hash_algorithm_t = picky_hash_algorithm_t { id: 7 };

impl TryFrom<picky_hash_algorithm_t> for HashAlgorithm {
    type Error = anyhow::Error;

    fn try_from(value: picky_hash_algorithm_t) -> Result<Self, Self::Error> {
        let algo = match value {
            PICKY_HASH_MD5 => HashAlgorithm::MD5,
            PICKY_HASH_SHA1 => HashAlgorithm::SHA1,
            PICKY_HASH_SHA2_224 => HashAlgorithm::SHA2_224,
            PICKY_HASH_SHA2_256 => HashAlgorithm::SHA2_256,
            PICKY_HASH_SHA2_384 => HashAlgorithm::SHA2_384,
            PICKY_HASH_SHA2_512 => HashAlgorithm::SHA2_512,
            PICKY_HASH_SHA3_384 => HashAlgorithm::SHA3_384,
            PICKY_HASH_SHA3_512 => HashAlgorithm::SHA3_512,
            _ => anyhow::bail!("unknown hash algorithm code"),
        };
        Ok(algo)
    }
}

/// Compute the digest of a given message using the specified hash algorithm.
#[allow(clippy::missing_safety_doc)]
#[no_mangle]
pub unsafe extern "C" fn picky_digest(
    algorithm: picky_hash_algorithm_t,
    input: *const u8,
    input_sz: c_int,
    digest: *mut u8,
    digest_sz: c_int,
) -> picky_status_t {
    let algorithm = err_check!(HashAlgorithm::try_from(algorithm).context("bad `algorithm` argument"));
    let input = ptr_to_buffer!(@u8 input, input_sz);
    let digest = ptr_to_buffer!(mut @u8 digest, digest_sz);
    err_check!(copy_slice_to_c(algorithm.digest(input), digest));
    picky_status_t::ok()
}

/// Get the length required to write the digest using the specified hash algorithm.
///
/// Returns the number of required bytes, or `-1` if there was an error.
#[no_mangle]
pub extern "C" fn picky_digest_length(algorithm: picky_hash_algorithm_t) -> c_int {
    let algorithm = err_check!(
        HashAlgorithm::try_from(algorithm).context("bad `algorithm` argument"),
        -1
    );
    let length = algorithm.output_size();
    err_check!(c_int::try_from(length), -1)
}
