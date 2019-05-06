use crate::db::memory::memory_repo::MemoryRepo;
use std::collections::HashMap;
use crate::utils;
use crate::db::backend::{BackendStorage, Model, Repo};

#[derive(Clone)]
pub struct MemoryRepos{
    pub name: MemoryRepo<String>,
    pub cert: MemoryRepo<String>,
    pub keys: MemoryRepo<String>,
    pub key_identifiers: MemoryRepo<String>
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
        if let Ok(cert_hash) = utils::multihash_encode(cert){
            self.name.insert(name, cert_hash.clone())?;
            self.cert.insert(&cert_hash, cert.to_string())?;
            self.keys.insert(&cert_hash, key.to_string())?;
            self.key_identifiers.insert(key_identifier, cert_hash)?;
            return Ok(true);
        }
        Err("Can\'t encode certificate".to_string())
    }

    fn find(&self, name: &str) -> Result<Vec<Model<String>>, String>{
        let mut model_vec = Vec::new();

        if let Some(model) = self.name.get_collection()?.get(name){
            model_vec.push(Model{
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

    fn get_cert(&self, hash: &str) -> Result<String, String>{
        if let Some(c) = self.cert.get_collection()?.get(hash){

        }

        Err("Cert not found".to_string())
    }

    fn get_key(&self, hash: &str) -> Result<String, String>{
        if let Some(k) = self.keys.get_collection()?.get(hash){
            return Ok(k.to_string());
        }

        Err("Key not found".to_string())
    }

    fn clone_box(&self) -> Box<BackendStorage>{
        Box::new(self.clone())
    }
}