use multibase::Base;
use multihash::{Code as Hash, Multihash, MultihashDigest};

pub const CANONICAL_HASH: Hash = Hash::Sha2_256;
pub const CANONICAL_BASE: Base = Base::Base64Url;
pub const CANONICAL_HASH_CODE: u64 = SHA2_256_HASH_CODE;
pub const SHA1_HASH_CODE: u64 = 0x11;
pub const SHA2_256_HASH_CODE: u64 = 0x12;

pub fn encode_to_canonical_address(data: &[u8]) -> String {
    let hash = CANONICAL_HASH.digest(data);
    multibase::encode(CANONICAL_BASE, hash.to_bytes())
}

pub fn encode_to_alternative_addresses(data: &[u8]) -> Result<Vec<String>, String> {
    use multihash::StatefulHasher as _;

    const ALTERNATIVE_SECUSE_HASHES: [Hash; 0] = [];

    let mut addresses = Vec::with_capacity(ALTERNATIVE_SECUSE_HASHES.len());

    for hash in ALTERNATIVE_SECUSE_HASHES.iter() {
        let address = hash.digest(data);
        addresses.push(multibase::encode(CANONICAL_BASE, address.to_bytes()))
    }

    // Also support SHA1 (unsecure hash algorithm, not provided in multihash::Code [Hash] enum)
    let mut sha1_hash = multihash::Sha1::default();
    sha1_hash.update(data);
    let sha1_hash = Multihash::wrap(SHA1_HASH_CODE, sha1_hash.finalize().as_ref()).map_err(|e| e.to_string())?;
    addresses.push(multibase::encode(CANONICAL_BASE, sha1_hash.to_bytes()));

    Ok(addresses)
}

pub fn convert_to_canonical_base(multibase_multihash_address: &str) -> Result<(String, u64), String> {
    let (_, hash) = multibase::decode(multibase_multihash_address).map_err(|e| e.to_string())?;
    let hash = Multihash::from_bytes(&hash).map_err(|e| e.to_string())?;
    Ok((multibase::encode(CANONICAL_BASE, hash.to_bytes()), hash.code()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use multihash::StatefulHasher;

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
        let mut sha1_hash = multihash::Sha1::default();
        sha1_hash.update(b"multihash");
        let sha1_hash = Multihash::wrap(SHA1_HASH_CODE, sha1_hash.finalize().as_ref()).unwrap();
        let base58btc_sha1_hash = multibase::encode(Base::Base58Btc, sha1_hash.to_bytes());

        let (base64url_sha1_hash, algorithm) = convert_to_canonical_base(&base58btc_sha1_hash).expect("convert");
        assert_eq!(algorithm, SHA1_HASH_CODE);
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
