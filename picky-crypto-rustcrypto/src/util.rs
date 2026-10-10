use picky_crypto::{Error, Zeroizing};

pub(crate) fn buffer(len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut output = Zeroizing::new(Vec::new());
    output.try_reserve_exact(len).map_err(|_| Error::ProviderFailure)?;
    output.resize(len, 0);
    Ok(output)
}

#[cfg(any(
    feature = "digest",
    feature = "aes",
    feature = "aead",
    feature = "rsa",
    feature = "nist-ec",
    feature = "curve25519",
    feature = "legacy"
))]
pub(crate) fn output(data: &[u8]) -> Result<picky_crypto::OutputBytes, Error> {
    let mut output = buffer(data.len())?;
    output.copy_from_slice(data);
    Ok(picky_crypto::OutputBytes::new(output))
}

#[cfg(any(
    feature = "digest",
    feature = "aes",
    feature = "aead",
    feature = "key-wrap",
    feature = "legacy"
))]
pub(crate) fn both(protection: picky_crypto::Protection) -> bool {
    matches!(
        protection,
        picky_crypto::Protection::Apply | picky_crypto::Protection::Process
    )
}

#[cfg(any(feature = "digest", feature = "legacy"))]
pub(crate) struct Length {
    remaining: Option<u128>,
    poisoned: bool,
}

#[cfg(any(feature = "digest", feature = "legacy"))]
impl Length {
    pub(crate) fn new(remaining: Option<u128>) -> Self {
        Self {
            remaining,
            poisoned: false,
        }
    }

    pub(crate) fn update(&mut self, len: usize) -> Result<(), Error> {
        self.check()?;
        if let Some(remaining) = self.remaining {
            let next = remaining.checked_sub(len as u128);
            if next.is_none() {
                self.poisoned = true;
                return Err(Error::InvalidInput);
            }
            self.remaining = next;
        }
        Ok(())
    }

    pub(crate) fn check(&self) -> Result<(), Error> {
        if self.poisoned {
            Err(Error::ProviderFailure)
        } else {
            Ok(())
        }
    }
}

#[cfg(all(test, any(feature = "digest", feature = "legacy")))]
mod tests {
    use super::*;

    #[test]
    fn length_limit_poisoning() {
        let mut length = Length::new(Some(2));
        assert_eq!(length.update(2), Ok(()));
        assert_eq!(length.update(1), Err(Error::InvalidInput));
        assert_eq!(length.update(0), Err(Error::ProviderFailure));
        assert_eq!(length.check(), Err(Error::ProviderFailure));
        assert_eq!(Length::new(Some(u128::MAX / 8)).update(usize::MAX), Ok(()));
    }
}
