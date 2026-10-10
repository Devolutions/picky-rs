use digest::{block_api::EagerHash, typenum::Unsigned};
use hmac::{Hmac, KeyInit};
use picky_crypto::{
    Algorithm, Entry, Error, Mac, MacAlgorithm, MacContext, MacOutput, Protection, ProviderBuilder, Zeroizing,
};
use std::{marker::PhantomData, sync::Arc};

struct MacEntry<D>(MacAlgorithm, PhantomData<D>);
struct Context<D: EagerHash> {
    mac: Hmac<D>,
    length: crate::util::Length,
}

impl<D: EagerHash + Send + Sync + 'static> Mac for MacEntry<D>
where
    Hmac<D>: Send,
{
    fn algorithm(&self) -> MacAlgorithm {
        self.0
    }
    fn fips(&self) -> bool {
        false
    }
    fn supports(&self, protection: Protection) -> bool {
        crate::util::both(protection)
    }
    fn start(&self, key: &[u8], protection: Protection) -> Result<Box<dyn MacContext>, Error> {
        if !self.supports(protection) {
            return Err(Error::Unsupported(Algorithm::Mac(self.0)));
        }
        let limit = match self.0 {
            MacAlgorithm::HmacSha1 | MacAlgorithm::HmacSha224 | MacAlgorithm::HmacSha256 => {
                Some(u128::from(u64::MAX / 8))
            }
            MacAlgorithm::HmacSha384 | MacAlgorithm::HmacSha512 => Some(u128::MAX / 8),
            _ => None,
        };
        if limit.is_some_and(|limit| key.len() as u128 > limit) {
            return Err(Error::InvalidKey);
        }
        let limit = limit.map(|limit| limit - u128::from(D::BlockSize::U64));
        let mac = Hmac::<D>::new_from_slice(key).map_err(|_| Error::InvalidKey)?;
        Ok(Box::new(Context {
            mac,
            length: crate::util::Length::new(limit),
        }))
    }
}

impl<D: EagerHash> MacContext for Context<D>
where
    Hmac<D>: Send,
{
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.length.update(data.len())?;
        digest::Update::update(&mut self.mac, data);
        Ok(())
    }
    fn finish(self: Box<Self>) -> Result<MacOutput, Error> {
        self.length.check()?;
        let tag = Zeroizing::new(digest::FixedOutput::finalize_fixed(self.mac));
        Ok(MacOutput::new(crate::util::output(&tag)?.into_inner()))
    }
}

pub(crate) fn entries(builder: ProviderBuilder) -> ProviderBuilder {
    macro_rules! add {
        ($($algorithm:ident => $digest:ty),+ $(,)?) => {
            builder $(.with(Entry::Mac(Arc::new(MacEntry::<$digest>(MacAlgorithm::$algorithm, PhantomData)))))+
        };
    }
    add!(HmacSha1 => sha1::Sha1, HmacSha224 => sha2::Sha224,
        HmacSha256 => sha2::Sha256, HmacSha384 => sha2::Sha384, HmacSha512 => sha2::Sha512)
}
