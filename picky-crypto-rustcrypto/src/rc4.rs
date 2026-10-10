use cipher::{KeyInit, StreamCipher as _};
use picky_crypto::{
    Entry, Error, OutputBytes, ProviderBuilder, StreamCipher, StreamCipherAlgorithm, StreamCipherContext,
};
use std::sync::Arc;

struct Rc4;
struct Context {
    cipher: rc4::Rc4,
    poisoned: bool,
}
impl StreamCipher for Rc4 {
    fn algorithm(&self) -> StreamCipherAlgorithm {
        StreamCipherAlgorithm::Rc4
    }
    fn fips(&self) -> bool {
        false
    }
    fn start(&self, key: &[u8]) -> Result<Box<dyn StreamCipherContext>, Error> {
        let cipher = rc4::Rc4::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
        Ok(Box::new(Context {
            cipher,
            poisoned: false,
        }))
    }
}
impl StreamCipherContext for Context {
    fn apply(&mut self, data: &[u8]) -> Result<OutputBytes, Error> {
        if self.poisoned {
            return Err(Error::ProviderFailure);
        }
        let result = (|| {
            let mut output = crate::util::output(data)?.into_inner();
            self.cipher
                .try_apply_keystream(&mut output)
                .map_err(|_| Error::InvalidInput)?;
            Ok(OutputBytes::new(output))
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}
pub(crate) fn entries(builder: ProviderBuilder) -> ProviderBuilder {
    builder.with(Entry::StreamCipher(Arc::new(Rc4)))
}
