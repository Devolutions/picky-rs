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
#[case::rsa_1024(RSA_1024)]
#[case::rsa_1536(RSA_1536)]
#[case::rsa_2048(RSA_2048)]
#[case::rsa_2048_other(RSA_2048_OTHER)]
#[case::rsa_2688(RSA_2688)]
#[case::rsa_3072(RSA_3072)]
#[case::rsa_3104(RSA_3104)]
#[case::rsa_4032(RSA_4032)]
#[case::rsa_4096(RSA_4096)]
#[case::rsa_8192(RSA_8192)]
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

#[rstest]
#[case::rsa_2048(RSA_2048)]
#[case::rsa_3104(RSA_3104)]
fn swapped_primes(#[case] source: Source) {
    let key = source.key();
    let mut swapped = source.key();
    core::mem::swap(&mut swapped.p, &mut swapped.q);
    let params = complete(&swapped).expect("consistent swapped primes");
    assert_eq!(integer(params.dp()), integer(&key.dq));
    assert_eq!(integer(params.dq()), integer(&key.dp));
    assert_eq!(params.dp().len(), key.q.len());
    assert_eq!(params.dq().len(), key.p.len());
    assert_eq!(params.qinv().len(), key.q.len());
}

#[rstest]
#[case::other_p(Key { p: RSA_2048_OTHER.key().p, ..RSA_2048.key() }, Error::InconsistentKey)]
#[case::other_q(Key { q: RSA_2048_OTHER.key().q, ..RSA_2048.key() }, Error::InconsistentKey)]
// The published RSA_1024 coefficient (qinv) ends in 04, so it is even.
#[case::even_p(Key { p: RSA_1024.key().qinv, ..RSA_2048.key() }, Error::InconsistentKey)]
// The published RSA_1024 coefficient (qinv) ends in 04, so it is even.
#[case::even_q(Key { q: RSA_1024.key().qinv, ..RSA_2048.key() }, Error::InconsistentKey)]
// e_three() is a published signature-generation key's publicExponent (3).
#[case::small_p(Key { p: e_three(), ..RSA_2048.key() }, Error::InconsistentKey)]
// e_three() is a published signature-generation key's publicExponent (3).
#[case::small_q(Key { q: e_three(), ..RSA_2048.key() }, Error::InconsistentKey)]
#[case::other_n(Key { n: RSA_2048_OTHER.key().n, ..RSA_2048.key() }, Error::InconsistentKey)]
#[case::other_d(Key { d: RSA_2048_OTHER.key().d, ..RSA_2048.key() }, Error::InconsistentKey)]
#[case::other_e(Key { e: e_three(), ..RSA_2048.key() }, Error::InconsistentKey)]
#[case::equal_primes(Key { q: RSA_2048.key().p, ..RSA_2048.key() }, Error::InconsistentKey)]
#[case::long_d(Key { d: RSA_4096.key().d, ..RSA_2048.key() }, Error::InvalidLength)]
#[case::long_p(Key { p: RSA_8192.key().p, ..RSA_2048.key() }, Error::InvalidLength)]
#[case::long_q(Key { q: RSA_8192.key().q, ..RSA_2048.key() }, Error::InvalidLength)]
#[case::short_n(Key { n: RSA_1024.key().n, ..RSA_2048.key() }, Error::InvalidLength)]
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
