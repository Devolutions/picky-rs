mod read_test_vectors;

use picky_asn1_der::{from_bytes, to_vec};
use read_test_vectors::*;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use std::fmt::Debug;

struct Primitive<T> {
    line: usize,
    value: T,
    der__: Vec<u8>,
}

impl<T> Primitive<T> {
    fn ser(&self) -> &Self
    where
        T: Serialize + Debug,
    {
        let ser = to_vec(&self.value).unwrap_or_else(|_| panic!("Failed to serialize value @{}", self.line));
        assert_eq!(ser, self.der__, "Invalid serialized value @{}", self.line);
        self
    }
    //noinspection RsNeedlessLifetimes
    fn de<'a>(&'a self)
    where
        T: Deserialize<'a> + Debug + PartialEq + 'a,
    {
        let de: T = from_bytes(&self.der__).unwrap_or_else(|_| panic!("Failed to deserialize value @{}", self.line));
        assert_eq!(de, self.value, "Invalid serialized value @{}", self.line);
    }
}

#[test]
fn test() {
    /// Tests a primitive against it's test vector
    macro_rules! test {
		($name:expr => $type:ty) => ({
			let v: Vec<Primitive<$type>> = read_test_vectors!(
				concat!("./test_vectors/serde_primitive_", $name, ".txt")
					=> Primitive{ line, value, der__ }
			);
			v.into_iter().for_each(|v| v.ser().de())
		});
		($($name:expr => $type:ty),+) => ($( test!($name => $type); )+)
	}
    test!(
        "boolean" => bool, "integer" => u128, "null" => (),
        "octet_string" => ByteBuf, "utf8_string" => String
    );
}

struct PrimitiveErr {
    line: usize,
    der__: Vec<u8>,
    error: &'static str,
}

impl PrimitiveErr {
    fn test(&self, r#type: &'static str) {
        match r#type {
            "Boolean" => self.de::<bool>(),
            "Integer" => self.de::<u128>(),
            "Null" => self.de::<()>(),
            "OctetString" => self.de::<ByteBuf>(),
            "UTF8String" => self.de::<String>(),
            _ => unreachable!("Invalid test type \"{}\"", r#type),
        }
    }
    //noinspection RsNeedlessLifetimes
    fn de<'a, T>(&'a self)
    where
        T: Deserialize<'a> + Debug + PartialEq + 'a,
    {
        let err = from_bytes::<T>(&self.der__)
            .err()
            .unwrap_or_else(|| panic!("Illegal successful deserialization @{}", self.line));
        assert_eq!(format!("{:?}", err), self.error, "Invalid error @{}", self.line);
    }
}

#[test]
fn test_err() {
    /// Tests deserialization of invalid data
    macro_rules! test {
		($name:expr => $type:expr) => ({
			let v: Vec<PrimitiveErr> = read_test_vectors!(
				concat!("test_vectors/serde_primitive_", $name, "_err.txt")
					=> PrimitiveErr{ line, der__, error }
			);
			v.into_iter().for_each(|v| v.test($type))
		});
		($($name:expr => $type:expr),+) => ($( test!($name => $type); )+)
	}
    test!(
        "boolean" => "Boolean", "integer" => "Integer", "null" => "Null",
        "octet_string" => "OctetString", "utf8_string" => "UTF8String"
    );
}
