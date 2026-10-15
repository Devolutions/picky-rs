use aes_gcm::{
    AesGcm,
    aead::{AeadInOut, Generate, Key, KeyInit, Nonce, consts::U12},
};
use picky_crypto::{Aead, AeadAlgorithm, Entry, Error, OutputBytes, Protection, ProviderBuilder, Sealed, Zeroizing};
use std::sync::Arc;

struct Gcm(AeadAlgorithm);

/// This backend's capacity limit on `ciphertext || tag`, the contract's must-support maximum (2^31 − 1 bytes).
// UNTESTED: sealing and opening return `Unsupported` beyond this limit, before any allocation or copy.
// Reaching these branches needs data too large for a test.
// When changing the seal or open path, keep the check after the fixed-length checks and before the buffer is made.
const SIZE_LIMIT: usize = i32::MAX as usize;
const TAG_LEN: usize = 16;

impl Gcm {
    fn seal_with<C: AeadInOut + KeyInit>(
        algorithm: AeadAlgorithm,
        key: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Sealed, Error> {
        let key: &Key<C> = key.try_into().map_err(|_| Error::InvalidKey)?;
        check_lengths(aad.len(), plaintext.len())?;
        if plaintext.len() > SIZE_LIMIT - TAG_LEN {
            return Err(Error::Unsupported(picky_crypto::Algorithm::Aead(algorithm)));
        }
        let cipher = C::new(key);
        let nonce = Zeroizing::new(
            Nonce::<C>::try_generate_from_rng(&mut getrandom::SysRng).map_err(|_| Error::ProviderFailure)?,
        );
        let mut output = crate::util::buffer(plaintext.len() + TAG_LEN)?;
        output.truncate(plaintext.len());
        output.copy_from_slice(plaintext);
        cipher
            .encrypt_in_place(&nonce, aad, &mut *output)
            .map_err(|_| Error::InvalidInput)?;
        Ok(Sealed::new(crate::util::output(&nonce)?, OutputBytes::new(output)))
    }

    fn open_with<C: AeadInOut + KeyInit>(
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<OutputBytes, Error> {
        let key: &Key<C> = key.try_into().map_err(|_| Error::InvalidKey)?;
        if ciphertext.len() < TAG_LEN {
            return Err(Error::InvalidInput);
        }
        check_lengths(aad.len(), ciphertext.len() - TAG_LEN)?;
        let nonce = nonce.try_into().map_err(|_| Error::InvalidInput)?;
        if ciphertext.len() > SIZE_LIMIT {
            return Err(Error::Unsupported(picky_crypto::Algorithm::Aead(algorithm)));
        }
        let cipher = C::new(key);
        let mut output = crate::util::output(ciphertext)?.into_inner();
        cipher
            .decrypt_in_place(nonce, aad, &mut *output)
            .map_err(|_| Error::VerificationFailed)?;
        Ok(OutputBytes::new(output))
    }
}

fn check_lengths(aad: usize, plaintext: usize) -> Result<(), Error> {
    if aad as u128 > u128::from(aes_gcm::A_MAX) || plaintext as u128 > u128::from(aes_gcm::P_MAX) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
impl Aead for Gcm {
    fn algorithm(&self) -> AeadAlgorithm {
        self.0
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, protection: Protection) -> bool {
        crate::util::both(protection)
    }
    fn seal(&self, key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, Error> {
        match self.0 {
            AeadAlgorithm::Aes128Gcm => Self::seal_with::<AesGcm<aes::Aes128, U12>>(self.0, key, aad, plaintext),
            AeadAlgorithm::Aes192Gcm => Self::seal_with::<AesGcm<aes::Aes192, U12>>(self.0, key, aad, plaintext),
            AeadAlgorithm::Aes256Gcm => Self::seal_with::<AesGcm<aes::Aes256, U12>>(self.0, key, aad, plaintext),
            _ => Err(Error::Unsupported(picky_crypto::Algorithm::Aead(self.0))),
        }
    }
    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<OutputBytes, Error> {
        match self.0 {
            AeadAlgorithm::Aes128Gcm => {
                Self::open_with::<AesGcm<aes::Aes128, U12>>(self.0, key, nonce, aad, ciphertext)
            }
            AeadAlgorithm::Aes192Gcm => {
                Self::open_with::<AesGcm<aes::Aes192, U12>>(self.0, key, nonce, aad, ciphertext)
            }
            AeadAlgorithm::Aes256Gcm => {
                Self::open_with::<AesGcm<aes::Aes256, U12>>(self.0, key, nonce, aad, ciphertext)
            }
            _ => Err(Error::Unsupported(picky_crypto::Algorithm::Aead(self.0))),
        }
    }
}
pub(crate) fn entries(builder: ProviderBuilder) -> ProviderBuilder {
    [
        AeadAlgorithm::Aes128Gcm,
        AeadAlgorithm::Aes192Gcm,
        AeadAlgorithm::Aes256Gcm,
    ]
    .into_iter()
    .fold(builder, |builder, algorithm| {
        builder.with(Entry::Aead(Arc::new(Gcm(algorithm))))
    })
}
