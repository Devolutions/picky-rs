use digest::{block_api::EagerHash, typenum::Unsigned};
use picky_crypto::{Algorithm, Entry, Error, OutputBytes, PasswordKdf, PasswordKdfAlgorithm, ProviderBuilder};
use std::{marker::PhantomData, sync::Arc};

const MUST_SUPPORT_MAX_OUTPUT_LEN: usize = 1024;
/// This backend's capacity limit on derived output (2^31 − 1 bytes), far above the 1024-byte must-support maximum.
const OUTPUT_SIZE_LIMIT: usize = i32::MAX as usize;

struct Pbkdf2<D>(PasswordKdfAlgorithm, PhantomData<D>);
impl<D: EagerHash + Send + Sync> PasswordKdf for Pbkdf2<D> {
    fn algorithm(&self) -> PasswordKdfAlgorithm {
        self.0
    }
    fn fips(&self) -> bool {
        false
    }
    fn derive(&self, password: &[u8], salt: &[u8], iterations: u32, output_len: usize) -> Result<OutputBytes, Error> {
        if iterations == 0
            || output_len == 0
            || output_len as u128 > u128::from(u32::MAX) * u128::from(D::OutputSize::U64)
        {
            return Err(Error::InvalidInput);
        }
        // UNTESTED: output lengths beyond the capacity limit return `Unsupported` before any allocation.
        // Rule 4 orders capacity limits after standard ranges, and reaching this branch needs an output too large for
        // a test.
        // When changing it, keep it after the standard-range check and before the allocation.
        if output_len > OUTPUT_SIZE_LIMIT {
            return Err(Error::Unsupported(Algorithm::PasswordKdf(self.0)));
        }
        // UNTESTED: an allocation failure returns `Unsupported` only beyond the must-support maximum, and
        // `ProviderFailure` otherwise.
        // `Unsupported` is not allowed inside the must-support set, and no test makes the allocation fail.
        // When changing it, keep the comparison with the must-support maximum.
        let mut output = crate::util::buffer(output_len).map_err(|_| {
            if output_len > MUST_SUPPORT_MAX_OUTPUT_LEN {
                Error::Unsupported(Algorithm::PasswordKdf(self.0))
            } else {
                Error::ProviderFailure
            }
        })?;
        pbkdf2::pbkdf2::<hmac::Hmac<D>>(password, salt, iterations, &mut output).map_err(|_| Error::InvalidKey)?;
        Ok(OutputBytes::new(output))
    }
}
pub(crate) fn entries(builder: ProviderBuilder) -> ProviderBuilder {
    macro_rules! add {
        ($($algorithm:ident => $digest:ty),+ $(,)?) => {
            builder $(.with(Entry::PasswordKdf(Arc::new(Pbkdf2::<$digest>(PasswordKdfAlgorithm::$algorithm, PhantomData)))))+
        };
    }
    add!(Pbkdf2HmacSha1 => sha1::Sha1, Pbkdf2HmacSha224 => sha2::Sha224,
        Pbkdf2HmacSha256 => sha2::Sha256, Pbkdf2HmacSha384 => sha2::Sha384, Pbkdf2HmacSha512 => sha2::Sha512)
}
