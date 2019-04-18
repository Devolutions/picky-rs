extern crate mbedtls;

extern crate rand;
extern crate rand_chacha;
extern crate rand_core;

extern crate core;

use mbedtls::pk::Pk;
use mbedtls::rng::os_entropy::*;
use mbedtls::rng::{CtrDrbg};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Keys{
    pub key_pem: String,
}

impl Keys{
    pub fn new(key_type: mbedtls::pk::Type, bits: u32) -> Self{
        let mut entropy = OsEntropy::new();
        let mut rng = CtrDrbg::new(&mut entropy, None).unwrap();
        let mut pk = Pk::generate_rsa(&mut rng, bits, 0x10001).unwrap();
        Self::new_from_pk(&mut pk)
    }

    pub fn new_from_pk(pk: &mut Pk) -> Self{
        Keys{
            key_pem: {
                pk.write_private_pem_string().unwrap()
            }
        }
    }

    pub fn new_from_pk_public(pk: &mut Pk) -> Self{
        Keys{
            key_pem: {
                pk.write_public_pem_string().unwrap()
            }
        }
    }

    pub fn get_pk_from_public(key: &[u8]) -> Pk{
        Pk::from_public_key(key).unwrap()
    }

    pub fn get_pk_from_private(key: &[u8]) -> Pk{
        Pk::from_private_key(key, None).unwrap()
    }
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_key(){
        let mut entropy = OsEntropy::new();
        let mut rng = CtrDrbg::new(&mut entropy, None).unwrap();

        let mut pk = Pk::generate_rsa(&mut rng, 4096, 0x10001).unwrap();
        let key = Keys::new_from_pk(&mut pk);

        let pub_key = pk.write_public_pem_string().unwrap();
        let private_key = pk.write_private_pem_string().unwrap();

        let key_pk = Keys::get_pk_from_public(key.key_pem.as_bytes());

        assert_eq!(private_key, key.key_pem);
        assert_eq!(key_pk.rsa_public_exponent().unwrap(), 0x10001);
    }
}

