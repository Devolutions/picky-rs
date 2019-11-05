use crate::db::memory::memory_repo::MemoryRepo;
use std::collections::HashMap;
use crate::utils;
use crate::db::backend::{BackendStorage, Model, Repo};
use std::sync::{RwLock};

pub struct MemoryRepos{
    pub name: RwLock<MemoryRepo<String>>,
    pub cert: RwLock<MemoryRepo<Vec<u8>>>,
    pub keys: RwLock<MemoryRepo<Vec<u8>>>,
    pub key_identifiers: RwLock<MemoryRepo<String>>
}

impl MemoryRepos{
    pub fn new() -> Self{
        MemoryRepos{
            name: RwLock::new(MemoryRepo{
                repo: HashMap::new()
            }),

            cert: RwLock::new(MemoryRepo{
                repo: HashMap::new()
            }),

            keys: RwLock::new(MemoryRepo{
                repo:HashMap::new()
            }),

            key_identifiers: RwLock::new(MemoryRepo{
                repo: HashMap::new()
            })
        }
    }
}

impl BackendStorage for MemoryRepos {
    fn init(&mut self) -> Result<(), String>{
        self.name.write().unwrap().repo = HashMap::new();

        self.keys.write().unwrap().repo = HashMap::new();

        self.cert.write().unwrap().repo = HashMap::new();

        self.key_identifiers.write().unwrap().repo = HashMap::new();

        Ok(())
    }

    fn store(&self, name :&str, cert: &[u8], key: Option<&[u8]>, key_identifier: &str) -> Result<bool, String>{
        if let Ok(cert_hash) = utils::multihash_encode(cert){
            self.name.write().unwrap().insert(name, &cert_hash.clone())?;
            self.cert.write().unwrap().insert(&cert_hash, &cert.to_vec())?;

            if let Some(key) = key {
                self.keys.write().unwrap().insert(&cert_hash, &key.to_vec())?;
            }

            self.key_identifiers.write().unwrap().insert(key_identifier, &cert_hash)?;
            return Ok(true);
        }
        Err("Can\'t encode certificate".to_string())
    }

    fn find(&self, name: &str) -> Result<Vec<Model<String>>, String>{
        let mut model_vec = Vec::new();

        if let Some(model) = self.name.read().unwrap().repo.get(name){
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
        self.key_identifiers.read().unwrap().repo.keys().for_each(|k|{
            if let Some(v) = self.key_identifiers.read().unwrap().repo.get(k){
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
        if let Some(h) = self.key_identifiers.read().unwrap().repo.get(key_identifier){
            return Ok(h.to_string());
        }

        Err("Hash not found".to_string())
    }

    fn get_cert(&self, hash: &str) -> Result<Vec<u8>, String>{
        if let Some(c) = self.cert.read().unwrap().repo.get(hash){
            return Ok(c.clone());
        }

        Err("Cert not found".to_string())
    }

    fn get_key(&self, hash: &str) -> Result<Vec<u8>, String>{
        if let Some(k) = self.keys.read().unwrap().get_collection()?.get(hash){
            return Ok(k.clone());
        }

        Err("Key not found".to_string())
    }

    fn health(&self) -> Result<(), String> {
        Ok(())
    }
}