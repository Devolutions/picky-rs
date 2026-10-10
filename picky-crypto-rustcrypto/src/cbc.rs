use cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, InnerIvInit, KeyInit};
use picky_crypto::{Cipher, CipherAlgorithm, Entry, Error, OutputBytes, Protection, ProviderBuilder};
use std::sync::Arc;

struct Cbc(CipherAlgorithm);
impl Cbc {
    fn run(&self, key: &[u8], iv: &[u8], data: &[u8], encrypt: bool) -> Result<OutputBytes, Error> {
        macro_rules! fixed {
            ($cipher:ty, $key_len:expr, $block_len:expr) => {{
                check(key.len() == $key_len, data, $block_len)?;
                transform(
                    <$cipher>::new_from_slice(key).map_err(|_| Error::InvalidKey)?,
                    iv,
                    data,
                    encrypt,
                )
            }};
        }
        match self.0 {
            #[cfg(feature = "aes")]
            CipherAlgorithm::Aes128Cbc => fixed!(aes::Aes128, 16, 16),
            #[cfg(feature = "aes")]
            CipherAlgorithm::Aes192Cbc => fixed!(aes::Aes192, 24, 16),
            #[cfg(feature = "aes")]
            CipherAlgorithm::Aes256Cbc => fixed!(aes::Aes256, 32, 16),
            #[cfg(feature = "legacy")]
            CipherAlgorithm::TdesEde3Cbc => fixed!(des::TdesEde3, 24, 8),
            #[cfg(feature = "legacy")]
            CipherAlgorithm::Rc2Cbc => {
                check((1..=128).contains(&key.len()), data, 8)?;
                transform(rc2::Rc2::new_with_eff_key_len(key, 8 * key.len()), iv, data, encrypt)
            }
            _ => Err(Error::Unsupported(picky_crypto::Algorithm::Cipher(self.0))),
        }
    }
}

fn check(key_valid: bool, data: &[u8], block: usize) -> Result<(), Error> {
    if !key_valid {
        return Err(Error::InvalidKey);
    }
    if data.len() % block != 0 {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

fn transform<C: BlockCipherEncrypt + BlockCipherDecrypt>(
    cipher: C,
    iv: &[u8],
    data: &[u8],
    encrypt: bool,
) -> Result<OutputBytes, Error> {
    let iv = iv.try_into().map_err(|_| Error::InvalidInput)?;
    let mut output = crate::util::output(data)?.into_inner();
    let blocks = Block::<C>::slice_as_chunks_mut(&mut output).0;
    if encrypt {
        cbc::Encryptor::inner_iv_init(cipher, iv).encrypt_blocks(blocks);
    } else {
        cbc::Decryptor::inner_iv_init(cipher, iv).decrypt_blocks(blocks);
    }
    Ok(OutputBytes::new(output))
}

impl Cipher for Cbc {
    fn algorithm(&self) -> CipherAlgorithm {
        self.0
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, protection: Protection) -> bool {
        crate::util::both(protection)
    }
    fn encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<OutputBytes, Error> {
        self.run(key, iv, plaintext, true)
    }
    fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<OutputBytes, Error> {
        self.run(key, iv, ciphertext, false)
    }
}
pub(crate) fn entries(builder: ProviderBuilder) -> ProviderBuilder {
    #[cfg(feature = "aes")]
    let builder = [
        CipherAlgorithm::Aes128Cbc,
        CipherAlgorithm::Aes192Cbc,
        CipherAlgorithm::Aes256Cbc,
    ]
    .into_iter()
    .fold(builder, |builder, algorithm| {
        builder.with(Entry::Cipher(Arc::new(Cbc(algorithm))))
    });
    #[cfg(feature = "legacy")]
    let builder = [CipherAlgorithm::TdesEde3Cbc, CipherAlgorithm::Rc2Cbc]
        .into_iter()
        .fold(builder, |builder, algorithm| {
            builder.with(Entry::Cipher(Arc::new(Cbc(algorithm))))
        });
    builder
}
