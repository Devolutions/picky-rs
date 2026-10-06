use super::SshPrivateKeyError;
use crate::key::{PrivateKey, RsaPrivateKeyComponents};

pub(super) fn import(
    n: &[u8],
    e: &[u8],
    d: &[u8],
    iqmp: &[u8],
    p: &[u8],
    q: &[u8],
) -> Result<PrivateKey, SshPrivateKeyError> {
    let modulus_len = trim_unsigned(n).len();
    if !matches!(modulus_len, 256 | 384 | 512 | 1024)
        || e.is_empty()
        || e.len() > 5
        || d.is_empty()
        || d.len() > modulus_len
        || iqmp.is_empty()
        || iqmp.len() > modulus_len
        || p.is_empty()
        || p.len() > modulus_len / 2 + 1
        || q.is_empty()
        || q.len() > modulus_len / 2 + 1
    {
        return Err(SshPrivateKeyError::InvalidKeyFormat);
    }
    // OpenSSH omits CRT exponents; reconstruct only these bounded integer fields.
    let dp = modulo(d, &subtract_one(p)?)?;
    let dq = modulo(d, &subtract_one(q)?)?;
    let key = PrivateKey::from_rsa_encoded_components(RsaPrivateKeyComponents {
        modulus: n,
        public_exponent: e,
        private_exponent: d,
        prime_1: p,
        prime_2: q,
        exponent_1: &dp,
        exponent_2: &dq,
        coefficient: iqmp,
    });
    aws_lc_rs::signature::RsaKeyPair::from_der(&key.to_pkcs1()?).map_err(|_| SshPrivateKeyError::InvalidKeyFormat)?;
    Ok(key)
}

fn trim_unsigned(mut value: &[u8]) -> &[u8] {
    while value.first() == Some(&0) {
        value = &value[1..];
    }
    value
}

fn subtract_one(value: &[u8]) -> Result<Vec<u8>, SshPrivateKeyError> {
    let mut value = trim_unsigned(value).to_vec();
    if value.is_empty() {
        return Err(SshPrivateKeyError::InvalidKeyFormat);
    }
    for byte in value.iter_mut().rev() {
        if *byte != 0 {
            *byte -= 1;
            return Ok(trim_unsigned(&value).to_vec());
        }
        *byte = 0xff;
    }
    Err(SshPrivateKeyError::InvalidKeyFormat)
}

fn modulo(value: &[u8], divisor: &[u8]) -> Result<Vec<u8>, SshPrivateKeyError> {
    let divisor = trim_unsigned(divisor);
    if divisor.is_empty() {
        return Err(SshPrivateKeyError::InvalidKeyFormat);
    }
    let mut remainder = Vec::new();
    for byte in trim_unsigned(value) {
        for bit in (0..8).rev() {
            shift_left_add(&mut remainder, (byte >> bit) & 1);
            if compare_unsigned(&remainder, divisor) != std::cmp::Ordering::Less {
                subtract_assign(&mut remainder, divisor);
            }
        }
    }
    Ok(remainder)
}

fn shift_left_add(value: &mut Vec<u8>, bit: u8) {
    let mut carry = bit;
    for byte in value.iter_mut().rev() {
        let next = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
    if carry != 0 {
        value.insert(0, carry);
    } else if value.is_empty() && bit != 0 {
        value.push(bit);
    }
}

fn compare_unsigned(left: &[u8], right: &[u8]) -> std::cmp::Ordering {
    let left = trim_unsigned(left);
    let right = trim_unsigned(right);
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn subtract_assign(left: &mut Vec<u8>, right: &[u8]) {
    let mut borrow = 0i16;
    for offset in 0..left.len() {
        let li = left.len() - 1 - offset;
        let rhs = right
            .len()
            .checked_sub(offset + 1)
            .map(|index| right[index] as i16)
            .unwrap_or(0);
        let result = left[li] as i16 - rhs - borrow;
        if result < 0 {
            left[li] = (result + 256) as u8;
            borrow = 1;
        } else {
            left[li] = result as u8;
            borrow = 0;
        }
    }
    let first = left.iter().position(|byte| *byte != 0).unwrap_or(left.len());
    left.drain(..first);
}
