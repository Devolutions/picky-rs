use crate::{
    db::{CertificateEntry, PickyStorage, StorageError},
    multihash::multihash_encode,
};
use snafu::Snafu;
use std::{
    collections::HashMap,
    hash::Hash,
    sync::{RwLock, RwLockReadGuard},
};

#[derive(Debug, Snafu)]
pub enum MemoryStorageError {
    #[snafu(display("generic error: {}", description))]
    Other { description: String },
}

impl From<String> for MemoryStorageError {
    fn from(e: String) -> Self {
        Self::Other { description: e }
    }
}

#[derive(Debug, Default)]
struct MemoryRepository<T> {
    repo: RwLock<HashMap<String, T>>,
}

impl<'a, T> MemoryRepository<T>
where
    T: Eq + Clone + Hash,
{
    fn get_collection(&'a self) -> RwLockReadGuard<'a, HashMap<String, T>> {
        self.repo.read().expect("couldn't get read lock on repo (poisoned)")
    }

    fn insert(&self, key: String, value: T) {
        if self
            .repo
            .write()
            .expect("couldn't get write lock on repo (poisoned)")
            .insert(key, value)
            .is_some()
        {
            info!("Key was updated because it was already stored");
        }
    }
}

#[derive(Debug, Default)]
pub struct MemoryStorage {
    name: MemoryRepository<String>,
    cert: MemoryRepository<Vec<u8>>,
    keys: MemoryRepository<Vec<u8>>,
    key_identifiers: MemoryRepository<String>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PickyStorage for MemoryStorage {
    fn health(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn store(&self, entry: CertificateEntry) -> Result<(), StorageError> {
        let name = entry.name;
        let cert = entry.cert;
        let key_identifier = entry.key_identifier;
        let key = entry.key;

        let cert_hash = multihash_encode(&cert).map_err(|e| MemoryStorageError::Other {
            description: format!("couldn't hash certificate: {}", e),
        })?;

        self.name.insert(name, cert_hash.clone());
        self.cert.insert(cert_hash.clone(), cert);
        if let Some(key) = key {
            self.keys.insert(cert_hash.clone(), key);
        }
        self.key_identifiers.insert(key_identifier, cert_hash);

        Ok(())
    }

    fn get_hash_by_name(&self, name: &str) -> Result<String, StorageError> {
        let hash = self
            .name
            .get_collection()
            .get(name)
            .cloned()
            .ok_or_else(|| MemoryStorageError::Other {
                description: format!("hash not found using name {}", name),
            })?;
        Ok(hash)
    }

    fn get_cert_by_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let cert = self
            .cert
            .get_collection()
            .get(hash)
            .cloned()
            .ok_or_else(|| MemoryStorageError::Other {
                description: "cert not found".to_owned(),
            })?;
        Ok(cert)
    }

    fn get_key_by_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let key = self
            .keys
            .get_collection()
            .get(hash)
            .cloned()
            .ok_or_else(|| MemoryStorageError::Other {
                description: "key not found".to_owned(),
            })?;
        Ok(key)
    }

    fn get_key_identifier_by_hash(&self, hash: &str) -> Result<String, StorageError> {
        let key_identifier = self
            .key_identifiers
            .get_collection()
            .keys()
            .find(|key| hash.eq(key.as_str()))
            .cloned()
            .ok_or_else(|| MemoryStorageError::Other {
                description: "key identifier not found".to_owned(),
            })?;
        Ok(key_identifier)
    }

    fn get_hash_by_key_identifier(&self, key_identifier: &str) -> Result<String, StorageError> {
        let hash = self
            .key_identifiers
            .get_collection()
            .get(key_identifier)
            .cloned()
            .ok_or_else(|| MemoryStorageError::Other {
                description: "hash not found".to_owned(),
            })?;
        Ok(hash)
    }
}
