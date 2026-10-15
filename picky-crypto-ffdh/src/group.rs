//! Domain parameters, value checks and exponentiation, as CONTRACT.md section 6.11 specifies them.

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, CtLt, Limb};
use picky_crypto::{Algorithm, Error, FfdhParameters, OutputBytes, SecureRandom, Zeroizing};

/// Capacity limit on the modulus, in bits: the largest RFC 3526 MODP group.
const MAX_MODULUS_BITS: usize = 8192;
/// The smallest valid modulus, in bits.
const MIN_MODULUS_BITS: usize = 1024;
/// Candidate draws before ephemeral generation gives up, so that a broken generator cannot hang the call.
const MAX_DRAWS: usize = 64;

/// Checked domain parameters.
/// Every value it holds is public.
pub(crate) struct Group {
    params: BoxedMontyParams,
    /// The generator g, in Montgomery form.
    generator: BoxedMontyForm,
    /// The subgroup order q, when given.
    order: Option<BoxedUint>,
    /// The exponent bound B: q, or q' = (p − 1) / 2 when q is absent.
    bound: BoxedUint,
    /// The bit length of B, which bounds the bit length of every valid exponent.
    bound_bits: u32,
    one: BoxedUint,
    p_minus_one: BoxedUint,
    /// The bit length of p.
    bits: usize,
    /// The byte length of p, the width of public values and shared secrets.
    width: usize,
    /// INVARIANT: a whole number of limbs and at least 8 × (width + 1) bits, shared by every integer of the group.
    precision: u32,
}

impl Group {
    /// Checks the domain parameters.
    /// An encoding longer than the byte length of p plus one byte returns `invalid`, before any other check.
    /// A modulus beyond the capacity limit then returns `Unsupported` naming `unsupported`.
    /// Any other invalid parameter returns `invalid`.
    pub(crate) fn new(parameters: FfdhParameters<'_>, unsupported: Algorithm, invalid: Error) -> Result<Self, Error> {
        let bits = bit_length(parameters.p);
        let width = bits.div_ceil(8);
        let encodings = [Some(parameters.p), Some(parameters.g), parameters.q];
        // The encoding bound is a length the operation fixes, so it takes precedence over the capacity limit.
        if encodings.into_iter().flatten().any(|encoding| !within(encoding, width)) {
            return Err(invalid);
        }
        if bits > MAX_MODULUS_BITS {
            return Err(Error::Unsupported(unsupported));
        }
        if bits < MIN_MODULUS_BITS {
            return Err(invalid);
        }
        // Per the capacity limit, `width` is at most 1024, so the precision fits easily.
        let precision = (8 * (width as u32 + 1)).next_multiple_of(Limb::BITS);
        let parse = |encoding: &[u8]| BoxedUint::from_be_slice(encoding, precision).map_err(|_| invalid);
        let p = parse(parameters.p)?.into_odd().into_option().ok_or(invalid)?;
        let one = BoxedUint::one_with_precision(precision);
        let p_minus_one = p.wrapping_sub(&one);
        let g = parse(parameters.g)?;
        if g <= one || g >= p_minus_one {
            return Err(invalid);
        }
        let order = parameters.q.map(parse).transpose()?;
        if order.as_ref().is_some_and(|q| *q < BoxedUint::from(5u8) || *q >= *p) {
            return Err(invalid);
        }
        let bound = order.clone().unwrap_or_else(|| p_minus_one.wrapping_shr_vartime(1));
        let bound_bits = bound.bits_vartime();
        // p is public, so its Montgomery parameters may be computed in variable time.
        let params = BoxedMontyParams::new_vartime(p);
        Ok(Self {
            generator: BoxedMontyForm::new(g, &params),
            params,
            order,
            bound,
            bound_bits,
            one,
            p_minus_one,
            bits,
            width,
            precision,
        })
    }

    /// The bit length of p.
    pub(crate) fn bits(&self) -> usize {
        self.bits
    }

    /// The generator g, in Montgomery form.
    pub(crate) fn generator(&self) -> &BoxedMontyForm {
        &self.generator
    }

    /// Parses a static private value x and checks `1 <= x <= B − 1`, without reducing it.
    pub(crate) fn private_value(&self, encoding: &[u8]) -> Result<Zeroizing<BoxedUint>, Error> {
        // The encoding length is public; only the value is secret.
        if !within(encoding, self.width) {
            return Err(Error::InvalidKey);
        }
        let x = Zeroizing::new(BoxedUint::from_be_slice(encoding, self.precision).map_err(|_| Error::InvalidKey)?);
        // UNTESTED: the range check of x runs in constant time and reveals only whether x is valid.
        // A comparison that branches on x leaks bits of a static private exponent through timing.
        // When changing it, keep `is_nonzero` and `ct_lt` on the full-precision value with one `to_bool` at the end,
        // never `cmp_vartime`, `Ord`, `bits_vartime` or a trimmed encoding of x.
        if x.is_nonzero().and(x.ct_lt(&self.bound)).to_bool() {
            Ok(x)
        } else {
            Err(Error::InvalidKey)
        }
    }

    /// Draws an ephemeral exponent from `random` by testing candidates, NIST SP 800-56A rev. 3 section 5.6.1.1.4.
    pub(crate) fn sample(&self, random: &dyn SecureRandom) -> Result<Zeroizing<BoxedUint>, Error> {
        // UNTESTED: the exponent is uniform in [1, B − 1], and its timing reveals only whether each candidate is
        // accepted.
        // CONTRACT.md section 12 leaves the distribution to review because outputs cannot show it, and a biased or
        // leaked exponent weakens every agreement made with it.
        // When changing it, draw exactly the bit length of B, keep rejection rather than reduction, compare with
        // `ct_lt` on the full-precision candidate, and keep the draw buffer and the candidate in `Zeroizing`.
        let limit = self.bound.wrapping_sub(&self.one);
        let len = self.bound_bits.div_ceil(8);
        let excess = 8 * len - self.bound_bits;
        let mut draw = Zeroizing::new(vec![0; len as usize]);
        for _ in 0..MAX_DRAWS {
            random.fill(&mut draw)?;
            if let Some(first) = draw.first_mut() {
                *first &= u8::MAX >> excess;
            }
            let candidate =
                Zeroizing::new(BoxedUint::from_be_slice(&draw, self.precision).map_err(|_| Error::ProviderFailure)?);
            // c <= B − 2 exactly when c < B − 1.
            if candidate.ct_lt(&limit).to_bool() {
                return Ok(Zeroizing::new(candidate.wrapping_add(&self.one)));
            }
        }
        Err(Error::ProviderFailure)
    }

    /// Parses a peer public value y and checks `1 < y < p − 1`, and `y^q mod p == 1` when q is given.
    pub(crate) fn peer(&self, encoding: &[u8]) -> Result<BoxedMontyForm, Error> {
        if !within(encoding, self.width) {
            return Err(Error::InvalidInput);
        }
        let y = BoxedUint::from_be_slice(encoding, self.precision).map_err(|_| Error::InvalidInput)?;
        if y <= self.one || y >= self.p_minus_one {
            return Err(Error::InvalidInput);
        }
        let y = BoxedMontyForm::new(y, &self.params);
        if let Some(q) = &self.order {
            // y and q are public, so the exponent length may show in the timing.
            if y.pow_bounded_exp(q, q.bits_vartime()).retrieve() != self.one {
                return Err(Error::InvalidInput);
            }
        }
        Ok(y)
    }

    /// Computes `base^exponent mod p` for a secret exponent in [1, B − 1], left-padded to the byte length of p.
    pub(crate) fn power(&self, base: &BoxedMontyForm, exponent: &BoxedUint) -> OutputBytes {
        // UNTESTED: the exponentiation and the serialization take no branch and no memory access that depends on the
        // exponent or the result.
        // The exponent is a private value and the result may be the shared secret.
        // When changing it, keep `pow_bounded_exp` with the public bit length of B, never `pow_vartime`, and keep the
        // fixed-width `to_be_bytes`, never `to_be_bytes_trimmed_vartime`; keep every intermediate in `Zeroizing`.
        let result = Zeroizing::new(base.pow_bounded_exp(exponent, self.bound_bits));
        let value = Zeroizing::new(result.retrieve());
        let encoded = Zeroizing::new(value.to_be_bytes());
        // INVARIANT: value < p < 2^(8 × width), and encoded holds at least width + 1 bytes, so every byte before its
        // last width bytes is zero.
        OutputBytes::new(Zeroizing::new(encoded[encoded.len() - self.width..].to_vec()))
    }
}

/// Whether an integer encoding is at most one byte longer than the byte length of p.
/// An empty encoding reads as zero, which every range check rejects.
fn within(encoding: &[u8], width: usize) -> bool {
    encoding.len() <= width + 1
}

/// The bit length of an unsigned big-endian integer, ignoring leading zero bytes.
fn bit_length(encoding: &[u8]) -> usize {
    match encoding.iter().position(|&byte| byte != 0) {
        Some(first) => (encoding.len() - first).saturating_mul(8) - encoding[first].leading_zeros() as usize,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{Scripted, structural_modulus};
    use picky_crypto::KeyAgreementAlgorithm;

    // Faults: a draw keeps bits above the bit length of B, a candidate outside [0, B − 2] is accepted, the exponent
    // misses the added one, rejection has no limit or another limit, or drawing continues after a generator error.
    // Outputs of the conformance suite cannot show how an exponent was drawn.
    #[test]
    fn sampling() {
        let p = structural_modulus(1024);
        let group = Group::new(
            FfdhParameters::new(&p, &[2], Some(&[5])),
            Algorithm::KeyAgreement(KeyAgreementAlgorithm::Ffdh),
            Error::InvalidInput,
        )
        .unwrap();
        // With q = 5, a candidate is the low three bits of one byte, and only 0 to 3 are accepted.
        for (draws, expected, calls) in [
            (vec![Ok(vec![0xFC]), Ok(vec![0x0B])], Ok(4u8), 2),
            (vec![Ok(vec![0xF8])], Ok(1), 1),
            (vec![Ok(vec![0xFF]); 64], Err(Error::ProviderFailure), 64),
            (vec![Err(Error::ProviderFailure)], Err(Error::ProviderFailure), 1),
        ] {
            let random = Scripted::new(draws);
            match (group.sample(&random), expected) {
                (Ok(exponent), Ok(x)) => assert!(*exponent == BoxedUint::from(x)),
                (actual, expected) => assert_eq!(actual.err(), expected.err()),
            }
            assert_eq!(random.calls(), calls);
        }
    }
}
