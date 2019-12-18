use multihash::{encode, to_hex, Hash};

const PICKY_HASH: Hash = Hash::SHA2256;
const SHA256_MULTIHASH_PREFIX: &str = "1220";

pub fn multihash_encode(value: &[u8]) -> Result<String, String> {
    match encode(PICKY_HASH, value) {
        Ok(result) => Ok(to_hex(&result)),
        Err(e) => Err(e.to_string()),
    }
}

pub fn sha256_to_multihash(hash: &str) -> Result<String, String> {
    let hash = format!("{}{}", SHA256_MULTIHASH_PREFIX, hash);
    Ok(hash)
}
