use crate::db::memory::memory_repo::MemoryRepo;
use std::collections::HashMap;
use crate::utils;
use crate::db::backend::{BackendStorage, Storage, Repo};

#[derive(Clone)]
pub struct MemoryRepos{
    pub name: MemoryRepo,
    pub cert: MemoryRepo,
    pub keys: MemoryRepo,
    pub key_identifiers: MemoryRepo
}

impl MemoryRepos{
    pub fn new() -> Self{
        MemoryRepos{
            name:MemoryRepo{
                repo: HashMap::new()
            },

            cert:MemoryRepo{
                repo: HashMap::new()
            },

            keys:MemoryRepo{
                repo: HashMap::new()
            },

            key_identifiers:MemoryRepo{
                repo: HashMap::new()
            }
        }
    }
}

impl BackendStorage for MemoryRepos{
    fn init(&mut self) -> Result<(), String>{
        self.name = MemoryRepo{
            repo: HashMap::new()
        };

        self.keys = MemoryRepo{
            repo: HashMap::new()
        };

        self.cert = MemoryRepo{
            repo: HashMap::new()
        };

        self.key_identifiers = MemoryRepo{
            repo: HashMap::new()
        };

        Ok(())
    }

    fn store(&mut self, name :&str, cert: &str, key: &str, key_identifier: &str) -> Result<bool, String>{
        if let Ok(der_cert) = utils::pem_to_der(cert){
            if let Ok(der_cert_hash) = utils::multihash_encode(der_cert.as_slice()){
                if let Ok(der_key) = utils::pem_to_der(key){
                    self.name.store(name, &der_cert_hash).expect("Error storing name");
                    self.cert.store(&der_cert_hash, &utils::der_to_string(der_cert.as_slice())).expect("Error storing cert");
                    self.keys.store(&der_cert_hash, &utils::der_to_string(der_key.as_slice())).expect("Error storing keys");
                    self.key_identifiers.store(key_identifier, &der_cert_hash).expect("Error storing key identifier");
                }
                return Ok(true);
            }
            return Err("Can\'t encode certificate".to_string());
        }
        Err("Invalide certificate".to_string())
    }

    fn find(&self, name: &str) -> Result<Vec<Storage>, String>{
        let mut model_vec = Vec::new();

        if let Some(model) = self.name.get_collection()?.get(name){
            model_vec.push(Storage{
                key: name.to_string(),
                value: model.to_string()
            });
            return Ok(model_vec);
        }

        Err("not found".to_string())
    }

    fn get_key_identifier_from_hash(&self, hash: &str) -> Result<String, String>{
        let mut key_identifier: Option<String> = None;
        self.key_identifiers.get_collection()?.keys().for_each(|k|{
            if let Some(v) = self.key_identifiers.repo.get(k){
                if v == hash{
                    key_identifier = Some(k.to_string());
                }
            }
        });

        if let Some(k) = key_identifier{
            return Ok(k);
        }

        Err("key identifier not found".to_string())
    }

    fn get_hash_from_key_identifier(&self, key_identifier: &str) -> Result<String, String>{
        if let Some(h) = self.key_identifiers.get_collection()?.get(key_identifier){
            return Ok(h.to_string());
        }

        Err("Hash not found".to_string())
    }

    fn get_cert(&self, hash: &str, format: Option<u8>) -> Result<String, String>{
        if let Some(c) = self.cert.get_collection()?.get(hash){
            let cert;
            if let Some(f) = format{
                if f == 1{
                    cert = utils::der_to_pem(c.as_bytes());
                    return Ok(cert);
                }
            }
            return Ok(c.to_string());
        }

        Err("Cert not found".to_string())
    }

    fn get_key(&self, hash: &str) -> Result<String, String>{
        if let Some(k) = self.keys.get_collection()?.get(hash){
            let key = utils::der_to_pem(k.as_bytes());
            return Ok(key);
        }

        Err("Key not found".to_string())
    }

    fn clone_box(&self) -> Box<BackendStorage>{
        Box::new(self.clone())
    }

    fn rebuild(&mut self) -> Result<Vec<(String, String, String)>, ()>{
        Err(())
    }
}