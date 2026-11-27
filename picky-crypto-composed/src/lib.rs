//! Key-based KDF entries for the picky cryptographic provider contract, built from another provider's entries.
//! The one-step KDF comes from hash entries and the counter-mode KDF from HMAC entries.
//! CONTRACT.md sections 6.4 and 11 define these entries and why they live outside a backend.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use picky_crypto::{
    Algorithm, CryptoProvider, Entry, Error, Hash, HashAlgorithm, Kdf, KdfAlgorithm, Mac, MacAlgorithm, MacGeneration,
    OutputBytes, Protection, Zeroizing,
};
use std::sync::Arc;

/// The must-support maximum output length of CONTRACT.md section 6.4, in bytes.
const MUST_SUPPORT_MAX_OUTPUT_LEN: usize = 64;
/// This provider's capacity limit on derived output (2^31 − 1 bytes), far above the must-support maximum.
const OUTPUT_SIZE_LIMIT: usize = i32::MAX as usize;

/// Each hash with its one-step KDF, and the HMAC over the same hash with its counter-mode KDF.
const ALGORITHMS: [(HashAlgorithm, KdfAlgorithm, MacAlgorithm, KdfAlgorithm); 4] = [
    (
        HashAlgorithm::Sha1,
        KdfAlgorithm::OneStepSha1,
        MacAlgorithm::HmacSha1,
        KdfAlgorithm::CounterHmacSha1,
    ),
    (
        HashAlgorithm::Sha256,
        KdfAlgorithm::OneStepSha256,
        MacAlgorithm::HmacSha256,
        KdfAlgorithm::CounterHmacSha256,
    ),
    (
        HashAlgorithm::Sha384,
        KdfAlgorithm::OneStepSha384,
        MacAlgorithm::HmacSha384,
        KdfAlgorithm::CounterHmacSha384,
    ),
    (
        HashAlgorithm::Sha512,
        KdfAlgorithm::OneStepSha512,
        MacAlgorithm::HmacSha512,
        KdfAlgorithm::CounterHmacSha512,
    ),
];

/// Builds a provider of key-based KDF entries over `base`'s entries.
/// Each SHA-1, SHA-256, SHA-384 or SHA-512 hash entry of `base` yields the one-step KDF over that hash.
/// Each HMAC-SHA-1, HMAC-SHA-256, HMAC-SHA-384 or HMAC-SHA-512 entry of `base` that supports tag generation yields the
/// counter-mode KDF over that HMAC.
/// The entries are taken when this function runs; neither `base` nor the process-wide default is consulted afterwards.
/// The provider is empty when `base` has none of these entries, and every entry reports `fips() == false`.
pub fn provider(base: &CryptoProvider) -> CryptoProvider {
    let hash = |algorithm| match base.get(Algorithm::Hash(algorithm)) {
        Some(Entry::Hash(entry)) => Some(Prf::Hash(Arc::clone(entry))),
        _ => None,
    };
    let mac = |algorithm| match base.get(Algorithm::Mac(algorithm)) {
        Some(Entry::Mac(entry)) if entry.supports(Protection::Apply) => Some(Prf::Mac(Arc::clone(entry))),
        _ => None,
    };
    let mut builder = CryptoProvider::builder();
    for (digest, one_step, hmac, counter) in ALGORITHMS {
        for (algorithm, prf) in [(one_step, hash(digest)), (counter, mac(hmac))] {
            if let Some(prf) = prf {
                builder = builder.with(Entry::Kdf(Arc::new(ComposedKdf {
                    algorithm,
                    prf,
                    block_len: digest.output_len(),
                })));
            }
        }
    }
    builder.build().expect("one entry per distinct KDF algorithm")
}

/// The underlying entry that computes each block.
enum Prf {
    /// One-step KDF, NIST SP 800-56C rev. 2 section 4.1, option 1.
    Hash(Arc<dyn Hash>),
    /// Counter-mode KDF, NIST SP 800-108 rev. 1 section 4.1.
    Mac(Arc<dyn Mac>),
}

struct ComposedKdf {
    algorithm: KdfAlgorithm,
    prf: Prf,
    /// The digest length of the underlying hash, which is also the HMAC tag length.
    block_len: usize,
}

impl ComposedKdf {
    fn block(&self, counter: u32, secret: &[u8], fixed_info: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        match &self.prf {
            Prf::Hash(hash) => {
                let mut context = hash.start()?;
                context.update(&counter.to_be_bytes())?;
                context.update(secret)?;
                context.update(fixed_info)?;
                Ok(context.finish()?.into_inner())
            }
            Prf::Mac(mac) => {
                let mut context = MacGeneration::start(&**mac, secret)?;
                context.update(&counter.to_be_bytes())?;
                context.update(fixed_info)?;
                Ok(context.finish()?.into_inner())
            }
        }
    }
}

impl Kdf for ComposedKdf {
    fn algorithm(&self) -> KdfAlgorithm {
        self.algorithm
    }

    fn fips(&self) -> bool {
        false
    }

    fn derive(&self, secret: &[u8], fixed_info: &[u8], output_len: usize) -> Result<OutputBytes, Error> {
        // At most 2^32 − 1 blocks exactly when the output is at most (2^32 − 1) × the block length.
        let blocks = u32::try_from(output_len.div_ceil(self.block_len)).map_err(|_| Error::InvalidInput)?;
        if secret.is_empty() || blocks == 0 {
            return Err(Error::InvalidInput);
        }
        // UNTESTED: output lengths above the capacity limit return `Unsupported` before any allocation.
        // Reaching the limit needs an output too large for a test; the conformance bounds checks cover only its
        // placement after the standard-range check.
        // When changing it, keep it after the standard-range check and before the allocation.
        if output_len > OUTPUT_SIZE_LIMIT {
            return Err(Error::Unsupported(Algorithm::Kdf(self.algorithm)));
        }
        // UNTESTED: an allocation failure returns `Unsupported` only beyond the must-support maximum, and
        // `ProviderFailure` otherwise.
        // `Unsupported` is not allowed inside the must-support set, and no test makes the allocation fail.
        // When changing it, keep the comparison with the must-support maximum.
        let mut output = Zeroizing::new(Vec::new());
        output.try_reserve_exact(output_len).map_err(|_| {
            if output_len > MUST_SUPPORT_MAX_OUTPUT_LEN {
                Error::Unsupported(Algorithm::Kdf(self.algorithm))
            } else {
                Error::ProviderFailure
            }
        })?;
        for counter in 1..=blocks {
            // UNTESTED: the output and every block stay in `Zeroizing` storage.
            // Derived output is key material, and a copy left in freed memory can leak through a later read or a memory
            // dump.
            // When changing this loop, keep `block` and `output` in `Zeroizing`, and keep the exact reservation above
            // so that extending `output` never reallocates.
            let block = self.block(counter, secret, fixed_info).map_err(|error| match error {
                Error::Unsupported(_) => Error::Unsupported(Algorithm::Kdf(self.algorithm)),
                error => error,
            })?;
            if block.len() != self.block_len {
                return Err(Error::ProviderFailure);
            }
            let take = (output_len - output.len()).min(self.block_len);
            output.extend_from_slice(&block[..take]);
        }
        Ok(OutputBytes::new(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky_crypto::{HashContext, MacContext, MacOutput};

    /// A hash and HMAC entry whose blocks repeat the low byte of their 32-bit counter.
    #[derive(Clone)]
    struct Mock {
        hash: HashAlgorithm,
        mac: MacAlgorithm,
        /// The only protection the HMAC entry supports.
        protection: Protection,
        block_len: usize,
        error: Option<Error>,
    }

    impl Mock {
        fn new(hash: HashAlgorithm, mac: MacAlgorithm) -> Self {
            Self {
                hash,
                mac,
                protection: Protection::Apply,
                block_len: hash.output_len(),
                error: None,
            }
        }

        fn context(&self) -> Result<Box<Context>, Error> {
            match self.error {
                Some(error) => Err(error),
                None => Ok(Box::new(Context {
                    data: Vec::new(),
                    block_len: self.block_len,
                })),
            }
        }
    }

    struct Context {
        data: Vec<u8>,
        block_len: usize,
    }

    impl Context {
        fn block(self) -> Zeroizing<Vec<u8>> {
            Zeroizing::new(vec![self.data.get(3).copied().unwrap_or_default(); self.block_len])
        }
    }

    impl HashContext for Context {
        fn update(&mut self, data: &[u8]) -> Result<(), Error> {
            self.data.extend_from_slice(data);
            Ok(())
        }

        fn finish(self: Box<Self>) -> Result<OutputBytes, Error> {
            Ok(OutputBytes::new(self.block()))
        }
    }

    impl MacContext for Context {
        fn update(&mut self, data: &[u8]) -> Result<(), Error> {
            HashContext::update(self, data)
        }

        fn finish(self: Box<Self>) -> Result<MacOutput, Error> {
            Ok(MacOutput::new(self.block()))
        }
    }

    impl Hash for Mock {
        fn algorithm(&self) -> HashAlgorithm {
            self.hash
        }

        fn fips(&self) -> bool {
            true
        }

        fn start(&self) -> Result<Box<dyn HashContext>, Error> {
            Ok(self.context()?)
        }
    }

    impl Mac for Mock {
        fn algorithm(&self) -> MacAlgorithm {
            self.mac
        }

        fn fips(&self) -> bool {
            true
        }

        fn supports(&self, protection: Protection) -> bool {
            protection == self.protection
        }

        fn start(&self, _key: &[u8], protection: Protection) -> Result<Box<dyn MacContext>, Error> {
            if !self.supports(protection) {
                return Err(Error::Unsupported(Algorithm::Mac(self.mac)));
            }
            Ok(self.context()?)
        }
    }

    fn base(entries: impl IntoIterator<Item = Entry>) -> CryptoProvider {
        entries
            .into_iter()
            .fold(CryptoProvider::builder(), |builder, entry| builder.with(entry))
            .build()
            .unwrap()
    }

    fn kdf(provider: &CryptoProvider, algorithm: KdfAlgorithm) -> &dyn Kdf {
        picky_crypto::helpers::kdf(provider, algorithm).unwrap()
    }

    // Faults: a KDF entry exists without its base entry, is built from an HMAC entry that cannot generate tags, or
    // copies the base entry's FIPS report.
    // The conformance suite runs this provider over a base with every entry, whose HMAC entries support both
    // protections and whose FIPS reports are false.
    #[test]
    fn entries_follow_base_entries() {
        let mut verify_only = Mock::new(HashAlgorithm::Sha256, MacAlgorithm::HmacSha256);
        verify_only.protection = Protection::Process;
        let composed = provider(&base([
            Entry::Hash(Arc::new(Mock::new(HashAlgorithm::Sha384, MacAlgorithm::HmacSha384))),
            Entry::Mac(Arc::new(Mock::new(HashAlgorithm::Sha1, MacAlgorithm::HmacSha1))),
            Entry::Mac(Arc::new(verify_only)),
        ]));
        assert_eq!(composed.entries().count(), 2);
        assert!(
            composed
                .entries()
                .all(|entry| !picky_crypto::helpers::entry_fips(entry))
        );
        for algorithm in [KdfAlgorithm::OneStepSha384, KdfAlgorithm::CounterHmacSha1] {
            assert!(kdf(&composed, algorithm).derive(&[1], &[], 1).is_ok());
        }
    }

    // Fault: a one-step block after the first hashes a counter other than its index.
    // Every published one-step vector fits in one block.
    #[test]
    fn one_step_counter_advances_per_block() {
        let hash = Mock::new(HashAlgorithm::Sha256, MacAlgorithm::HmacSha256);
        let composed = provider(&base([Entry::Hash(Arc::new(hash))]));
        let output = kdf(&composed, KdfAlgorithm::OneStepSha256)
            .derive(&[1], &[], 33)
            .unwrap();
        assert_eq!(output.as_ref(), [&[1; 32][..], &[2]].concat());
    }

    // Faults: `Unsupported` from a base entry keeps the base algorithm's name, another base error is replaced, or a
    // block of the wrong length is accepted.
    #[test]
    fn base_entry_failures() {
        let mock = Mock::new(HashAlgorithm::Sha256, MacAlgorithm::HmacSha256);
        for (error, block_len, expected) in [
            (
                Some(Error::Unsupported(Algorithm::Hash(HashAlgorithm::Sha256))),
                32,
                [
                    Error::Unsupported(Algorithm::Kdf(KdfAlgorithm::OneStepSha256)),
                    Error::Unsupported(Algorithm::Kdf(KdfAlgorithm::CounterHmacSha256)),
                ],
            ),
            (Some(Error::InvalidKey), 32, [Error::InvalidKey; 2]),
            (None, 31, [Error::ProviderFailure; 2]),
            (None, 33, [Error::ProviderFailure; 2]),
        ] {
            let failing = Mock {
                error,
                block_len,
                ..mock.clone()
            };
            let composed = provider(&base([
                Entry::Hash(Arc::new(failing.clone())),
                Entry::Mac(Arc::new(failing)),
            ]));
            let actual = [KdfAlgorithm::OneStepSha256, KdfAlgorithm::CounterHmacSha256]
                .map(|algorithm| kdf(&composed, algorithm).derive(&[1], &[], 1).err());
            assert_eq!(actual, expected.map(Some));
        }
    }

    // Fault: the block count is truncated to 32 bits instead of bounded by the 32-bit counter.
    // The conformance suite probes one byte above the maximum, whose 2^32 blocks truncate to zero and fail anyway.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn block_count_bound() {
        let hash = Mock::new(HashAlgorithm::Sha1, MacAlgorithm::HmacSha1);
        let composed = provider(&base([Entry::Hash(Arc::new(hash))]));
        let output_len = (u32::MAX as usize + 2) * 20;
        assert_eq!(
            kdf(&composed, KdfAlgorithm::OneStepSha1)
                .derive(&[1], &[], output_len)
                .err(),
            Some(Error::InvalidInput)
        );
    }
}
