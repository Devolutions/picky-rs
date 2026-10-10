//! Published RSA private keys read from the pinned Wycheproof submodule.
//!
//! Each source names a file in `picky-crypto-testsuite/vectors/wycheproof/testvectors_v1` and the index of a test group whose `privateKey` is used verbatim.

use picky_crypto_testsuite::wycheproof_private_key;

#[derive(Clone, Copy)]
pub struct Source {
    pub file: &'static str,
    pub group: usize,
}

pub struct Key {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub d: Vec<u8>,
    pub p: Vec<u8>,
    pub q: Vec<u8>,
    pub dp: Vec<u8>,
    pub dq: Vec<u8>,
    pub qinv: Vec<u8>,
}

impl Source {
    pub fn key(self) -> Key {
        let mut fields = wycheproof_private_key(self.file, self.group);
        let mut take = |name: &str| {
            fields
                .remove(name)
                .unwrap_or_else(|| panic!("{}: testGroups[{}].privateKey.{name} is missing", self.file, self.group))
        };
        Key {
            n: take("modulus"),
            e: take("publicExponent"),
            d: take("privateExponent"),
            p: take("prime1"),
            q: take("prime2"),
            dp: take("exponent1"),
            dq: take("exponent2"),
            qinv: take("coefficient"),
        }
    }
}

/// rsa_oaep_misc_test.json, testGroups[0], tcId 1..=3.
pub const RSA_1024: Source = Source {
    file: "rsa_oaep_misc_test.json",
    group: 0,
};
/// rsa_oaep_misc_test.json, testGroups[35], tcId 106..=108.
/// Its dP and qInv are published at the encoding length of p, and dQ at that of q.
pub const RSA_1536_EQUAL_LENGTHS: Source = Source {
    file: "rsa_oaep_misc_test.json",
    group: 35,
};
/// rsa_oaep_2048_sha1_mgf1sha1_test.json, testGroups[0], tcId 1..=36.
pub const RSA_2048: Source = Source {
    file: "rsa_oaep_2048_sha1_mgf1sha1_test.json",
    group: 0,
};
/// rsa_oaep_2048_sha224_mgf1sha1_test.json, testGroups[0], tcId 1..=31.
pub const RSA_2048_OTHER: Source = Source {
    file: "rsa_oaep_2048_sha224_mgf1sha1_test.json",
    group: 0,
};
/// rsa_oaep_misc_test.json, testGroups[127], tcId 392..=395.
pub const RSA_3104: Source = Source {
    file: "rsa_oaep_misc_test.json",
    group: 127,
};
/// rsa_oaep_misc_test.json, testGroups[126], tcId 385..=391.
pub const RSA_4032: Source = Source {
    file: "rsa_oaep_misc_test.json",
    group: 126,
};
/// rsa_oaep_misc_test.json, testGroups[110], tcId 331..=333.
pub const RSA_8192: Source = Source {
    file: "rsa_oaep_misc_test.json",
    group: 110,
};

/// rsa_pkcs1_2048_sig_gen_test.json, testGroups[5], tcId 154: `privateKey.publicExponent` (3).
pub fn e_three() -> Vec<u8> {
    let mut fields = wycheproof_private_key("rsa_pkcs1_2048_sig_gen_test.json", 5);
    fields.remove("publicExponent").expect("published publicExponent")
}
