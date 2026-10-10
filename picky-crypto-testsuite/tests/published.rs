use picky_crypto_testsuite::published::*;
use rstest::rstest;

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(4)]
fn source_inputs(#[case] index: usize) {
    assert!(!mac(index).is_empty());
    assert!(!password(index).is_empty());
    let (id, key, data) = empty_mac(index);
    let source = mac(index);
    let original = source.iter().find(|(_, _, msg, _)| msg.is_empty()).unwrap();
    assert_eq!(key, original.2);
    assert!(key.is_empty());
    assert!(source.iter().any(|(_, _, msg, _)| msg == &data));
    assert!(id.contains("tcId="));
    if index < 3 {
        assert!(!aead(index).is_empty());
        assert!(!wrap(index).is_empty());
    }
}

#[test]
fn kdf_and_stream_inputs() {
    for index in 0..8 {
        let inputs = kdf(index);
        assert!(!inputs.is_empty());
        for (_, secret, info) in inputs {
            assert!(!secret.is_empty());
            assert!(secret.len() <= 1024 && info.len() <= 1024);
        }
    }
    assert!(!rc4().is_empty());
}
