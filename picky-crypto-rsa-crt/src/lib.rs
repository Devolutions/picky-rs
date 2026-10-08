#![no_std]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

extern crate alloc;

use alloc::boxed::Box;
use core::fmt;
use crypto_bigint::{BoxedUint, ConcatenatingMul, CtEq, NonZero, Odd};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Maximum modulus encoding length: 16384 bits plus one sign byte.
pub const MAX_MODULUS_LEN: usize = 2049;

/// Zeroizing, unsigned big-endian CRT parameters for a two-prime RSA private key.
pub struct CrtParams {
    dp: Zeroizing<Box<[u8]>>,
    dq: Zeroizing<Box<[u8]>>,
    qinv: Zeroizing<Box<[u8]>>,
}

impl CrtParams {
    /// Return `d mod (p − 1)`, padded to the input `p` encoding length.
    pub fn dp(&self) -> &[u8] {
        &self.dp
    }

    /// Return `d mod (q − 1)`, padded to the input `q` encoding length.
    pub fn dq(&self) -> &[u8] {
        &self.dq
    }

    /// Return `q⁻¹ mod p`, padded to the input `p` encoding length.
    pub fn qinv(&self) -> &[u8] {
        &self.qinv
    }
}

impl ZeroizeOnDrop for CrtParams {}

impl fmt::Debug for CrtParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CrtParams { [REDACTED] }")
    }
}

/// An invalid input length or inconsistent RSA key components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The modulus is empty or too long, or another input is longer than the modulus.
    InvalidLength,
    /// The components fail one or more key consistency checks.
    InconsistentKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLength => "invalid RSA component encoding length",
            Self::InconsistentKey => "inconsistent RSA key components",
        })
    }
}

impl core::error::Error for Error {}

/// Complete CRT parameters from unsigned big-endian RSA key components.
///
/// Leading zero bytes are accepted.
/// The length and consistency checks are described in the crate documentation.
pub fn complete_crt_params(n: &[u8], e: &[u8], d: &[u8], p: &[u8], q: &[u8]) -> Result<CrtParams, Error> {
    let (p_len, q_len) = (p.len(), q.len());
    if n.is_empty() || n.len() > MAX_MODULUS_LEN || [e, d, p, q].iter().any(|v| v.len() > n.len()) {
        return Err(Error::InvalidLength);
    }

    // The public length bound makes the precision conversion and all allocations bounded.
    let precision = (n.len() * 8) as u32;
    let n = BoxedUint::from_be_slice(n, precision).map_err(|_| Error::InvalidLength)?;
    let e = BoxedUint::from_be_slice(e, precision).map_err(|_| Error::InvalidLength)?;
    let d = Zeroizing::new(BoxedUint::from_be_slice(d, precision).map_err(|_| Error::InvalidLength)?);
    let p = Zeroizing::new(BoxedUint::from_be_slice(p, precision).map_err(|_| Error::InvalidLength)?);
    let q = Zeroizing::new(BoxedUint::from_be_slice(q, precision).map_err(|_| Error::InvalidLength)?);
    let one = BoxedUint::one_with_precision(precision);

    // Odd and NonZero substitute one for invalid inputs in constant time.
    // Keep their validity bits while borrowing their safe placeholders without branching.
    let odd_p = Odd::new((*p).clone()).map(Zeroizing::new);
    let odd_q = Odd::new((*q).clone()).map(Zeroizing::new);
    let p_minus_one = NonZero::new(p.wrapping_sub(&one)).map(Zeroizing::new);
    let q_minus_one = NonZero::new(q.wrapping_sub(&one)).map(Zeroizing::new);
    let mut valid = odd_p.is_some() & odd_q.is_some() & p_minus_one.is_some() & q_minus_one.is_some();

    let product = p.checked_mul(&*q).map(Zeroizing::new);
    valid &= product.is_some() & product.as_inner_unchecked().ct_eq(&n);

    let (quotient, dp) = d.div_rem(&**p_minus_one.as_inner_unchecked());
    let (_quotient, dp) = (Zeroizing::new(quotient), Zeroizing::new(dp));
    let (quotient, dq) = d.div_rem(&**q_minus_one.as_inner_unchecked());
    let (_quotient, dq) = (Zeroizing::new(quotient), Zeroizing::new(dq));

    let p_nonzero = Zeroizing::new((**odd_p.as_inner_unchecked()).clone().into_nz());
    let (quotient, reduced_q) = q.div_rem(&*p_nonzero);
    let (_quotient, reduced_q) = (Zeroizing::new(quotient), Zeroizing::new(reduced_q));
    let qinv = reduced_q.invert_odd_mod(odd_p.as_inner_unchecked()).map(Zeroizing::new);
    valid &= qinv.is_some();

    // Widen the exponent products to 2W; mixed-precision division returns a W-bit remainder.
    let edp = Zeroizing::new(e.concatenating_mul(&*dp));
    let edq = Zeroizing::new(e.concatenating_mul(&*dq));
    let (quotient, remainder) = edp.div_rem(&**p_minus_one.as_inner_unchecked());
    let (_quotient, remainder) = (Zeroizing::new(quotient), Zeroizing::new(remainder));
    valid &= remainder.ct_eq(&one);
    let (quotient, remainder) = edq.div_rem(&**q_minus_one.as_inner_unchecked());
    let (_quotient, remainder) = (Zeroizing::new(quotient), Zeroizing::new(remainder));
    valid &= remainder.ct_eq(&one);

    if !valid.to_bool() {
        return Err(Error::InconsistentKey);
    }

    Ok(CrtParams {
        dp: encode(&dp, p_len)?,
        dq: encode(&dq, q_len)?,
        qinv: encode(qinv.as_inner_unchecked(), p_len)?,
    })
}

fn encode(value: &BoxedUint, len: usize) -> Result<Zeroizing<Box<[u8]>>, Error> {
    let bytes = Zeroizing::new(value.to_be_bytes());
    // Precision is at least n.len() bytes, and output lengths cannot exceed n.len().
    let start = bytes.len().checked_sub(len).ok_or(Error::InvalidLength)?;
    let bytes = bytes.get(start..).ok_or(Error::InvalidLength)?;
    Ok(Zeroizing::new(bytes.into()))
}
