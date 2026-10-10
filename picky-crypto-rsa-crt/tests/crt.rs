#[path = "support/vectors.rs"]
mod vectors;

use picky_crypto_rsa_crt::{CrtParams, Error, MAX_MODULUS_LEN, complete_crt_params};
use rstest::rstest;
use vectors::*;

fn integer(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

fn complete(key: &Key) -> Result<CrtParams, Error> {
    complete_crt_params(&key.n, &key.e, &key.d, &key.p, &key.q)
}

#[rstest]
#[case::rsa_1024_smallest(RSA_1024)]
#[case::rsa_2048_substitution_base(RSA_2048)]
#[case::rsa_3104_unaligned_modulus(RSA_3104)]
#[case::rsa_4032_unaligned_primes(RSA_4032)]
#[case::rsa_8192_largest(RSA_8192)]
fn published_crt_parameters(#[case] source: Source) {
    let key = source.key();
    let params = complete(&key).expect("consistent published key");
    assert_eq!(integer(params.dp()), integer(&key.dp));
    assert_eq!(integer(params.dq()), integer(&key.dq));
    assert_eq!(integer(params.qinv()), integer(&key.qinv));
    assert_eq!(params.dp().len(), key.p.len());
    assert_eq!(params.dq().len(), key.q.len());
    assert_eq!(params.qinv().len(), key.p.len());
}

// Every published key has p > q, so swapping them is the only case that reduces q modulo a smaller p.
#[test]
fn swapped_primes() {
    let key = RSA_3104.key();
    let mut swapped = RSA_3104.key();
    core::mem::swap(&mut swapped.p, &mut swapped.q);
    let params = complete(&swapped).expect("consistent swapped primes");
    assert_eq!(integer(params.dp()), integer(&key.dq));
    assert_eq!(integer(params.dq()), integer(&key.dp));
    assert_eq!(params.dp().len(), key.q.len());
    assert_eq!(params.dq().len(), key.p.len());
    assert_eq!(params.qinv().len(), key.q.len());
}

// All checks share one error and a substituted prime also breaks p·q = n.
// The parity, size and invertibility cases exercise their checks without isolating them.
#[rstest]
#[case::other_n(Key { n: RSA_2048_OTHER.key().n, ..RSA_2048.key() }, Error::InconsistentKey)]
// The published RSA_1024 coefficient (qinv) ends in 04, so it is even.
#[case::even_p(Key { p: RSA_1024.key().qinv, ..RSA_2048.key() }, Error::InconsistentKey)]
#[case::equal_primes(Key { q: RSA_2048.key().p, ..RSA_2048.key() }, Error::InconsistentKey)]
// e_three() is a published signature-generation key's publicExponent (3).
#[case::e_three(Key { e: e_three(), ..RSA_2048.key() }, Error::InconsistentKey)]
#[case::long_d(Key { d: RSA_8192.key().d, ..RSA_2048.key() }, Error::InvalidLength)]
fn substituted_components(#[case] key: Key, #[case] error: Error) {
    assert_eq!(complete(&key).expect_err("inconsistent substituted key"), error);
}

// Structural input with a specified error outcome; not a test vector.
#[rstest]
#[case::empty_n(Some(vec![]), None, None, Error::InvalidLength)]
#[case::oversized_n(Some(vec![0xff; MAX_MODULUS_LEN]), None, None, Error::InvalidLength)]
#[case::zero_p(None, Some(vec![0x00]), None, Error::InconsistentKey)]
#[case::one_p(None, Some(vec![0x01]), None, Error::InconsistentKey)]
#[case::zero_q(None, None, Some(vec![0x00]), Error::InconsistentKey)]
#[case::one_q(None, None, Some(vec![0x01]), Error::InconsistentKey)]
fn structural_inputs(
    #[case] n: Option<Vec<u8>>,
    #[case] p: Option<Vec<u8>>,
    #[case] q: Option<Vec<u8>>,
    #[case] error: Error,
) {
    let base = RSA_2048.key();
    let key = Key {
        n: n.unwrap_or_else(|| base.n.clone()),
        p: p.unwrap_or_else(|| base.p.clone()),
        q: q.unwrap_or_else(|| base.q.clone()),
        ..base
    };
    assert_eq!(complete(&key).expect_err("structural input"), error);
}

#[test]
fn redacted_debug_and_error_traits() {
    fn zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    zeroizes_on_drop::<CrtParams>();
    let params = complete(&RSA_2048.key()).expect("consistent published key");
    assert_eq!(format!("{params:?}"), "CrtParams { [REDACTED] }");
    assert_eq!(
        Error::InvalidLength.to_string(),
        "invalid RSA component encoding length"
    );
    assert_eq!(Error::InconsistentKey.to_string(), "inconsistent RSA key components");
    let error: &dyn core::error::Error = &Error::InconsistentKey;
    assert!(error.source().is_none());
}
