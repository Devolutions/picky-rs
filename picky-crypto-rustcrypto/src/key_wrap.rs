use aes_kw::{
    AesKw, KeyInit,
    cipher::{BlockCipherDecrypt, BlockCipherEncrypt, Key, consts::U16},
};
use picky_crypto::{Entry, Error, KeyWrap, KeyWrapAlgorithm, OutputBytes, Protection, ProviderBuilder};
use std::sync::Arc;

struct Kw(KeyWrapAlgorithm);
impl Kw {
    fn run<C: BlockCipherEncrypt<BlockSize = U16> + BlockCipherDecrypt + KeyInit>(
        kek: &[u8],
        data: &[u8],
        wrap: bool,
    ) -> Result<OutputBytes, Error> {
        let kek: &Key<C> = kek.try_into().map_err(|_| Error::InvalidKey)?;
        let len = if wrap {
            if !matches!(data.len(), 16 | 24 | 32) {
                return Err(Error::InvalidInput);
            }
            data.len() + 8
        } else {
            if !matches!(data.len(), 24 | 32 | 40) {
                return Err(Error::InvalidInput);
            }
            data.len() - 8
        };
        let cipher = AesKw::<C>::new(kek);
        let mut output = crate::util::buffer(len)?;
        if wrap {
            cipher.wrap_key(data, &mut output).map_err(|_| Error::InvalidInput)?;
        } else {
            cipher.unwrap_key(data, &mut output).map_err(|error| match error {
                aes_kw::Error::IntegrityCheckFailed => Error::VerificationFailed,
                _ => Error::InvalidInput,
            })?;
        }
        Ok(OutputBytes::new(output))
    }
    fn transform(&self, kek: &[u8], data: &[u8], wrap: bool) -> Result<OutputBytes, Error> {
        match self.0 {
            KeyWrapAlgorithm::Aes128Kw => Self::run::<aes::Aes128>(kek, data, wrap),
            KeyWrapAlgorithm::Aes192Kw => Self::run::<aes::Aes192>(kek, data, wrap),
            KeyWrapAlgorithm::Aes256Kw => Self::run::<aes::Aes256>(kek, data, wrap),
            _ => Err(Error::Unsupported(picky_crypto::Algorithm::KeyWrap(self.0))),
        }
    }
}
impl KeyWrap for Kw {
    fn algorithm(&self) -> KeyWrapAlgorithm {
        self.0
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, protection: Protection) -> bool {
        crate::util::both(protection)
    }
    fn wrap(&self, kek: &[u8], data: &[u8]) -> Result<OutputBytes, Error> {
        self.transform(kek, data, true)
    }
    fn unwrap(&self, kek: &[u8], data: &[u8]) -> Result<OutputBytes, Error> {
        self.transform(kek, data, false)
    }
}
pub(crate) fn entries(builder: ProviderBuilder) -> ProviderBuilder {
    [
        KeyWrapAlgorithm::Aes128Kw,
        KeyWrapAlgorithm::Aes192Kw,
        KeyWrapAlgorithm::Aes256Kw,
    ]
    .into_iter()
    .fold(builder, |builder, algorithm| {
        builder.with(Entry::KeyWrap(Arc::new(Kw(algorithm))))
    })
}
