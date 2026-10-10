use picky_crypto::{Error, RandomAlgorithm, SecureRandom};

pub(crate) struct Random;
impl SecureRandom for Random {
    fn algorithm(&self) -> RandomAlgorithm {
        RandomAlgorithm::SecureRandom
    }
    fn fips(&self) -> bool {
        false
    }
    fn fill(&self, dest: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(dest).map_err(|_| Error::ProviderFailure)
    }
}
