use multibase::Base;
use multihash::{Code as Hash, Multihash};

pub const CANONICAL_HASH: Hash = Hash::Sha2_256;
pub const CANONICAL_BASE: Base = Base::Base64Url;

pub fn encode_to_canonical_address(data: &[u8]) -> String {
    let hash = CANONICAL_HASH.digest(data);
    multibase::encode(CANONICAL_BASE, hash.as_bytes())
}

const ALTERNATIVE_HASHES: [Hash; 1] = [Hash::Sha1];
pub fn encode_to_alternative_addresses(data: &[u8]) -> Result<Vec<String>, String> {
    let mut addresses = Vec::with_capacity(ALTERNATIVE_HASHES.len());

    for hash in ALTERNATIVE_HASHES.iter() {
        let address = hash.digest(data);
        addresses.push(multibase::encode(CANONICAL_BASE, address.as_bytes()))
    }

    Ok(addresses)
}

pub fn convert_to_canonical_base(multibase_multihash_address: &str) -> Result<(String, Hash), String> {
    let (_, raw_multi) = multibase::decode(multibase_multihash_address).map_err(|e| e.to_string())?;
    let multi = Multihash::from_bytes(raw_multi).map_err(|e| e.to_string())?;
    Ok((multibase::encode(CANONICAL_BASE, multi.as_bytes()), multi.algorithm()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alternate_to_canonical_table(alternate: &str) -> Option<&'static str> {
        match alternate {
            "uERSIwvEfss45KstbKYbmQCEcRpAHPg" => Some("uEiCcvAfD-ZFyWDajqipYHKICkZiqQgudmbwOEx2fPiy-Rw"),
            _ => None,
        }
    }

    #[test]
    fn encode_canonical() {
        let address = encode_to_canonical_address(b"multihash");
        assert_eq!(address, "uEiCcvAfD-ZFyWDajqipYHKICkZiqQgudmbwOEx2fPiy-Rw");
    }

    #[test]
    fn convert_to_canonical() {
        let sha1_hash = multihash::Sha1::digest(b"multihash");
        let base58btc_sha1_hash = multibase::encode(Base::Base58Btc, sha1_hash.as_bytes());

        let (base64url_sha1_hash, algorithm) = convert_to_canonical_base(&base58btc_sha1_hash).expect("convert");
        assert_eq!(algorithm, Hash::Sha1);
        let base64url_sha256_hash = alternate_to_canonical_table(&base64url_sha1_hash).expect("table");
        assert_eq!(base64url_sha256_hash, "uEiCcvAfD-ZFyWDajqipYHKICkZiqQgudmbwOEx2fPiy-Rw");
    }

    #[test]
    fn encode_alternatives() {
        for alternative in encode_to_alternative_addresses(b"multihash").expect("encode to alternative") {
            let canonical = alternate_to_canonical_table(&alternative).expect("table");
            assert_eq!(canonical, "uEiCcvAfD-ZFyWDajqipYHKICkZiqQgudmbwOEx2fPiy-Rw");
        }
    }
}
