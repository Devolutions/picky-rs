#[path = "support/vectors.rs"]
mod vectors;

use crypto_bigint::{BoxedUint, NonZero};
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
    assert_eq!(failed_checks(&key.n, &key.e, &key.d, &key.p, &key.q), []);
    let params = complete(&key).expect("consistent published key");
    assert_eq!(integer(params.dp()), integer(&key.dp));
    assert_eq!(integer(params.dq()), integer(&key.dq));
    assert_eq!(integer(params.qinv()), integer(&key.qinv));
    assert_eq!(params.dp().len(), key.p.len());
    assert_eq!(params.dq().len(), key.q.len());
    assert_eq!(params.qinv().len(), key.p.len());
}

// The published dP, dQ and qInv of this key have their prime's encoding length, so outputs compare byte for byte.
// One extra leading zero on p must pad dP and qInv by one byte and leave dQ unchanged.
#[rstest]
#[case::published_lengths(0)]
#[case::p_with_extra_leading_zero(1)]
fn output_padding(#[case] extra: usize) {
    let key = RSA_1536_EQUAL_LENGTHS.key();
    let pad = |bytes: &[u8]| [vec![0; extra], bytes.to_vec()].concat();
    let params = complete_crt_params(&key.n, &key.e, &key.d, &pad(&key.p), &key.q).expect("consistent published key");
    assert_eq!(params.dp(), pad(&key.dp));
    assert_eq!(params.dq(), key.dq);
    assert_eq!(params.qinv(), pad(&key.qinv));
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

#[rstest]
#[case::other_n(Key { n: RSA_2048_OTHER.key().n, ..RSA_2048.key() }, Error::InconsistentKey)]
// e_three() is a published signature-generation key's publicExponent (3).
#[case::e_three(Key { e: e_three(), ..RSA_2048.key() }, Error::InconsistentKey)]
#[case::long_d(Key { d: RSA_8192.key().d, ..RSA_2048.key() }, Error::InvalidLength)]
fn substituted_components(#[case] key: Key, #[case] error: Error) {
    assert_eq!(complete(&key).expect_err("inconsistent substituted key"), error);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Check {
    OddP,
    OddQ,
    PAtLeastThree,
    QAtLeastThree,
    Product,
    InvertibleQ,
    ExponentP,
    ExponentQ,
}

/// Returns the documented consistency checks a key fails, evaluated at a precision where no product wraps.
fn failed_checks(n: &[u8], e: &[u8], d: &[u8], p: &[u8], q: &[u8]) -> Vec<Check> {
    let len = [n, e, d, p, q].iter().map(|v| v.len()).max().unwrap_or(0);
    let bits = u32::try_from(16 * len + 64).expect("small precision");
    let int = |bytes: &[u8]| BoxedUint::from_be_slice(bytes, bits).expect("fits the precision");
    let (n, e, d, p, q) = (int(n), int(e), int(d), int(p), int(q));
    let (one, three) = (int(&[1]), int(&[3]));
    let exponent = |prime: &BoxedUint| {
        NonZero::new(prime.wrapping_sub(&one))
            .into_option()
            .filter(|_| *prime >= one)
            .is_some_and(|m| e.wrapping_mul(d.rem(&m)).rem(&m) == one)
    };
    let invertible = NonZero::new(p.clone())
        .into_option()
        .is_some_and(|m| q.invert_mod(&m).is_some().to_bool());
    [
        (Check::OddP, p.to_odd().is_some().to_bool()),
        (Check::OddQ, q.to_odd().is_some().to_bool()),
        (Check::PAtLeastThree, p >= three),
        (Check::QAtLeastThree, q >= three),
        (Check::Product, p.wrapping_mul(&q) == n),
        (Check::InvertibleQ, invertible),
        (Check::ExponentP, exponent(&p)),
        (Check::ExponentQ, exponent(&q)),
    ]
    .into_iter()
    .filter(|(_, holds)| !holds)
    .map(|(check, _)| check)
    .collect()
}

// Structural input with a specified error outcome; not a test vector.
// Keys derived from published ones (q = p, or p with its low bit cleared) also fail p·q = n.
// Each small key instead fails only its targeted check, which `failed_checks` confirms before the crate runs.
#[rstest]
// Targets: p is odd.
// The crate also rejects an even p through its inversion step, which then runs modulo a placeholder of one.
#[case::even_p(&[12], &[1], &[1], &[4], &[3], Check::OddP)]
// Targets: q is odd.
#[case::even_q(&[12], &[1], &[1], &[3], &[4], Check::OddQ)]
// Targets: q is invertible modulo p.
#[case::non_invertible_q(&[9], &[1], &[1], &[3], &[3], Check::InvertibleQ)]
// Targets: e·dP ≡ 1 (mod p − 1).
#[case::e_dp(&[15], &[1], &[3], &[5], &[3], Check::ExponentP)]
// Targets: e·dQ ≡ 1 (mod q − 1).
#[case::e_dq(&[15], &[1], &[3], &[3], &[5], Check::ExponentQ)]
// Targets: p·q = n.
// (2^32 + 1)(2^32 + 3) = 2^64 + n, so the product matches n only modulo the crate's 64-bit precision.
#[case::product_overflow(&[0, 0, 0, 4, 0, 0, 0, 3], &[1], &[1], &[1, 0, 0, 0, 1], &[1, 0, 0, 0, 3], Check::Product)]
fn single_failed_check(
    #[case] n: &[u8],
    #[case] e: &[u8],
    #[case] d: &[u8],
    #[case] p: &[u8],
    #[case] q: &[u8],
    #[case] check: Check,
) {
    assert_eq!(failed_checks(n, e, d, p, q), [check]);
    assert_eq!(
        complete_crt_params(n, e, d, p, q).expect_err("structural input"),
        Error::InconsistentKey
    );
}

// Structural input with a specified error outcome; not a test vector.
// The other inputs are empty, so only the modulus bounds apply.
#[rstest]
#[case::empty_n(&[])]
#[case::n_above_limit(&[0; MAX_MODULUS_LEN + 1])]
// A 2049-byte modulus must start with a zero sign byte.
#[case::oversized_n(&[0xff; MAX_MODULUS_LEN])]
fn modulus_length_bounds(#[case] n: &[u8]) {
    assert_eq!(
        complete_crt_params(n, &[], &[], &[], &[]).expect_err("structural input"),
        Error::InvalidLength
    );
}

// Structural input with a specified error outcome; not a test vector.
// Targets: p ≥ 3 or q ≥ 3, substituted into a published key.
// The other checks cannot all hold, because a prime below 3 also breaks p·q = n and its exponent check.
#[rstest]
#[case::zero_p(Some(vec![0x00]), None, Check::PAtLeastThree)]
#[case::one_p(Some(vec![0x01]), None, Check::PAtLeastThree)]
#[case::zero_q(None, Some(vec![0x00]), Check::QAtLeastThree)]
#[case::one_q(None, Some(vec![0x01]), Check::QAtLeastThree)]
fn small_primes(#[case] p: Option<Vec<u8>>, #[case] q: Option<Vec<u8>>, #[case] check: Check) {
    let base = RSA_2048.key();
    let key = Key {
        p: p.unwrap_or_else(|| base.p.clone()),
        q: q.unwrap_or_else(|| base.q.clone()),
        ..base
    };
    assert!(failed_checks(&key.n, &key.e, &key.d, &key.p, &key.q).contains(&check));
    assert_eq!(complete(&key).expect_err("structural input"), Error::InconsistentKey);
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
