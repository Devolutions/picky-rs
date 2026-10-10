use digest::Digest;
use picky_crypto::{Entry, Error, Hash, HashAlgorithm, HashContext, OutputBytes, ProviderBuilder, Zeroizing};
use std::{marker::PhantomData, sync::Arc};

struct HashEntry<D>(HashAlgorithm, PhantomData<D>);
struct Context<D> {
    digest: D,
    length: crate::util::Length,
}

impl<D: Digest + Default + Send + Sync + 'static> Hash for HashEntry<D> {
    fn algorithm(&self) -> HashAlgorithm {
        self.0
    }
    fn fips(&self) -> bool {
        false
    }
    fn start(&self) -> Result<Box<dyn HashContext>, Error> {
        let limit = match self.0 {
            HashAlgorithm::Md4
            | HashAlgorithm::Md5
            | HashAlgorithm::Sha1
            | HashAlgorithm::Sha224
            | HashAlgorithm::Sha256 => Some(u128::from(u64::MAX / 8)),
            HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => Some(u128::MAX / 8),
            _ => None,
        };
        Ok(Box::new(Context {
            digest: D::default(),
            length: crate::util::Length::new(limit),
        }))
    }
}

impl<D: Digest + Send> HashContext for Context<D> {
    fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.length.update(data.len())?;
        self.digest.update(data);
        Ok(())
    }
    fn finish(self: Box<Self>) -> Result<OutputBytes, Error> {
        self.length.check()?;
        let digest = Zeroizing::new(self.digest.finalize());
        crate::util::output(&digest)
    }
}

pub(crate) fn entries(builder: ProviderBuilder) -> ProviderBuilder {
    macro_rules! add {
        ($builder:ident, $($algorithm:ident => $digest:ty),+ $(,)?) => {
            $builder $(.with(Entry::Hash(Arc::new(HashEntry::<$digest>(
                HashAlgorithm::$algorithm, PhantomData
            )))))+
        };
    }
    #[cfg(feature = "digest")]
    let builder = add!(builder,
        Sha1 => sha1::Sha1, Sha224 => sha2::Sha224, Sha256 => sha2::Sha256,
        Sha384 => sha2::Sha384, Sha512 => sha2::Sha512,
        Sha3_384 => sha3::Sha3_384, Sha3_512 => sha3::Sha3_512
    );
    #[cfg(feature = "legacy")]
    let builder = add!(builder, Md4 => md4::Md4, Md5 => md5::Md5);
    builder
}
