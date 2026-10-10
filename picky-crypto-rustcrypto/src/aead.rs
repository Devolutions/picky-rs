use aes_gcm::{
    AesGcm,
    aead::{AeadInOut, Generate, Key, KeyInit, Nonce, consts::U12},
};
use picky_crypto::{Aead, AeadAlgorithm, Entry, Error, OutputBytes, Protection, ProviderBuilder, Sealed, Zeroizing};
use std::sync::Arc;

struct Gcm(AeadAlgorithm);
impl Gcm {
    fn seal_with<C: AeadInOut + KeyInit>(key: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Sealed, Error> {
        let key: &Key<C> = key.try_into().map_err(|_| Error::InvalidKey)?;
        check_lengths(aad.len(), plaintext.len())?;
        let cipher = C::new(key);
        let nonce = Zeroizing::new(
            Nonce::<C>::try_generate_from_rng(&mut getrandom::SysRng).map_err(|_| Error::ProviderFailure)?,
        );
        let capacity = plaintext.len().checked_add(16).ok_or(Error::InvalidInput)?;
        let mut output = crate::util::buffer(capacity)?;
        output.truncate(plaintext.len());
        output.copy_from_slice(plaintext);
        cipher
            .encrypt_in_place(&nonce, aad, &mut *output)
            .map_err(|_| Error::InvalidInput)?;
        Ok(Sealed::new(crate::util::output(&nonce)?, OutputBytes::new(output)))
    }

    fn open_with<C: AeadInOut + KeyInit>(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<OutputBytes, Error> {
        let key: &Key<C> = key.try_into().map_err(|_| Error::InvalidKey)?;
        if ciphertext.len() < 16 {
            return Err(Error::InvalidInput);
        }
        check_lengths(aad.len(), ciphertext.len() - 16)?;
        let nonce = nonce.try_into().map_err(|_| Error::InvalidInput)?;
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
            AeadAlgorithm::Aes128Gcm => Self::seal_with::<AesGcm<aes::Aes128, U12>>(key, aad, plaintext),
            AeadAlgorithm::Aes192Gcm => Self::seal_with::<AesGcm<aes::Aes192, U12>>(key, aad, plaintext),
            AeadAlgorithm::Aes256Gcm => Self::seal_with::<AesGcm<aes::Aes256, U12>>(key, aad, plaintext),
            _ => Err(Error::Unsupported(picky_crypto::Algorithm::Aead(self.0))),
        }
    }
    fn open(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<OutputBytes, Error> {
        match self.0 {
            AeadAlgorithm::Aes128Gcm => Self::open_with::<AesGcm<aes::Aes128, U12>>(key, nonce, aad, ciphertext),
            AeadAlgorithm::Aes192Gcm => Self::open_with::<AesGcm<aes::Aes192, U12>>(key, nonce, aad, ciphertext),
            AeadAlgorithm::Aes256Gcm => Self::open_with::<AesGcm<aes::Aes256, U12>>(key, nonce, aad, ciphertext),
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
