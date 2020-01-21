use crate::{
    addressing::{encode_to_alternative_addresses, encode_to_canonical_address},
    db::{CertificateEntry, PickyStorage, StorageError},
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
    hash_lookup: MemoryRepository<String>,
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

        let addressing_hash = encode_to_canonical_address(&cert).map_err(|e| MemoryStorageError::Other {
            description: format!("couldn't hash certificate: {}", e),
        })?;

        let alternative_addresses = encode_to_alternative_addresses(&cert).map_err(|e| MemoryStorageError::Other {
            description: format!("couldn't encode alternative addresses: {}", e),
        })?;

        self.name.insert(name, addressing_hash.clone());
        self.cert.insert(addressing_hash.clone(), cert);
        self.key_identifiers.insert(key_identifier, addressing_hash.clone());

        for alternative_address in alternative_addresses.into_iter() {
            self.hash_lookup.insert(alternative_address, addressing_hash.clone());
        }

        if let Some(key) = key {
            self.keys.insert(addressing_hash, key);
        }

        Ok(())
    }

    fn get_cert_by_addressing_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        Ok(self
            .cert
            .get_collection()
            .get(hash)
            .cloned()
            .ok_or_else(|| MemoryStorageError::Other {
                description: "cert not found".to_owned(),
            })?)
    }

    fn get_key_by_addressing_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        Ok(self
            .keys
            .get_collection()
            .get(hash)
            .cloned()
            .ok_or_else(|| MemoryStorageError::Other {
                description: "key not found".to_owned(),
            })?)
    }

    fn get_addressing_hash_by_name(&self, name: &str) -> Result<String, StorageError> {
        Ok(self
            .name
            .get_collection()
            .get(name)
            .cloned()
            .ok_or_else(|| MemoryStorageError::Other {
                description: format!("hash not found using name {}", name),
            })?)
    }

    fn get_addressing_hash_by_key_identifier(&self, key_identifier: &str) -> Result<String, StorageError> {
        Ok(self
            .key_identifiers
            .get_collection()
            .get(key_identifier)
            .cloned()
            .ok_or_else(|| MemoryStorageError::Other {
                description: "hash not found".to_owned(),
            })?)
    }

    fn lookup_addressing_hash(&self, lookup_key: &str) -> Result<String, StorageError> {
        Ok(self
            .hash_lookup
            .get_collection()
            .get(lookup_key)
            .cloned()
            .ok_or_else(|| MemoryStorageError::Other {
                description: "hash not found".to_owned(),
            })?)
    }
}
