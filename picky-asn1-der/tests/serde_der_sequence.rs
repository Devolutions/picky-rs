use picky_asn1_der::{from_bytes, to_vec, Asn1DerError};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
struct TestStruct {
    number: u8,
    #[serde(with = "serde_bytes")]
    vec: Vec<u8>,
    tuple: (usize, ()),
}

#[test]
fn test() {
    // Nested tuple
    let plain = (7u8, "Testolope".to_string(), (4usize, ()));
    let der = b"\x30\x15\x02\x01\x07\x0c\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x30\x05\x02\x01\x04\x05\x00";

    let encoded = to_vec(&plain).unwrap();
    assert_eq!(encoded, der.as_ref());

    let decoded: (u8, String, (usize, ())) = from_bytes(&encoded).unwrap();
    assert_eq!(decoded, plain);

    // Test struct
    let plain = TestStruct {
        number: 7,
        vec: b"Testolope".to_vec(),
        tuple: (4, ()),
    };
    let der = b"\x30\x15\x02\x01\x07\x04\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x30\x05\x02\x01\x04\x05\x00";

    let encoded = to_vec(&plain).unwrap();
    assert_eq!(encoded, der.as_ref());

    let decoded: TestStruct = from_bytes(&encoded).unwrap();
    assert_eq!(decoded, plain);
}

#[test]
fn test_err() {
    // Invalid tag
    let der = b"\xFF\x15\x02\x01\x07\x04\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x30\x05\x02\x01\x04\x05\x00";
    match from_bytes::<TestStruct>(der) {
        Err(Asn1DerError::InvalidData) => (),
        result => panic!("invalid tag => invalid result: {:?}", result),
    }

    // Truncated data
    let der = b"\x30\x15\x02\x01\x07\x04\x09\x54\x65\x73\x74\x6f\x6c\x6f\x70\x65\x30\x05\x02\x01\x04\x05";
    match from_bytes::<TestStruct>(der) {
        Err(Asn1DerError::TruncatedData) => (),
        result => panic!("truncated data => invalid result: {:?}", result),
    }
}
