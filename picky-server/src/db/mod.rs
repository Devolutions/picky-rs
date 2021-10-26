mod config;
mod file;
mod memory;
pub mod mongodb;

use crate::config::{BackendType, Config};
use crate::db::file::{FileStorage, FileStorageError};
use crate::db::memory::{MemoryStorage, MemoryStorageError};
use crate::db::mongodb::{MongoStorage, MongoStorageError};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const SCHEMA_LAST_VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("mongo storage error: {}", source)]
    Mongo { source: MongoStorageError },

    #[error("file storage error: {}", source)]
    File { source: FileStorageError },

    #[error("memory storage error: {}", source)]
    Memory { source: MemoryStorageError },
}

impl From<MongoStorageError> for StorageError {
    fn from(source: MongoStorageError) -> Self {
        Self::Mongo { source }
    }
}

impl From<FileStorageError> for StorageError {
    fn from(source: FileStorageError) -> Self {
        Self::File { source }
    }
}

impl From<MemoryStorageError> for StorageError {
    fn from(source: MemoryStorageError) -> Self {
        Self::Memory { source }
    }
}

pub type BoxedPickyStorage = Box<dyn PickyStorage>;

pub async fn get_storage(config: &Config) -> BoxedPickyStorage {
    match config.backend {
        BackendType::MongoDb => {
            let client = mongodb::build_client(&config.database_url).await.expect("mongo client");
            let db = client.database(&config.database_name);
            Box::new(MongoStorage::new(db).await)
        }
        BackendType::Memory => Box::new(MemoryStorage::new()),
        BackendType::File => Box::new(FileStorage::new(config)),
    }
}

#[derive(Debug, Clone)]
pub struct CertificateEntry {
    pub name: String,
    pub cert: Vec<u8>,
    pub key_identifier: String,
    pub key: Option<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub enum SshKeyType {
    Host,
    Client,
}

impl ToString for SshKeyType {
    fn to_string(&self) -> String {
        match self {
            SshKeyType::Client => "client".to_owned(),
            SshKeyType::Host => "host".to_owned(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct SshKeyEntry {
    pub key_type: SshKeyType,
    pub key: String,
}

impl Default for SshKeyEntry {
    fn default() -> Self {
        SshKeyEntry {
            key_type: SshKeyType::Host,
            key: "".to_owned(),
        }
    }
}

impl AsRef<[u8]> for SshKeyEntry {
    fn as_ref(&self) -> &[u8] {
        self.key.as_ref()
    }
}

impl SshKeyEntry {
    pub fn new(key_type: SshKeyType, key: String) -> Self {
        Self { key_type, key }
    }
    pub fn key_type(&self) -> &SshKeyType {
        &self.key_type
    }
}

pub trait PickyStorage: Send + Sync {
    fn health(&self) -> BoxFuture<'_, Result<(), StorageError>>;
    fn store(&self, entry: CertificateEntry) -> BoxFuture<'_, Result<(), StorageError>>;
    fn get_cert_by_addressing_hash<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, Result<Vec<u8>, StorageError>>;
    fn get_key_by_addressing_hash<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, Result<Vec<u8>, StorageError>>;
    fn get_addressing_hash_by_name<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<String, StorageError>>;
    fn increase_issued_authenticode_timestamps_counter(&self) -> BoxFuture<'_, Result<(), StorageError>>;
    fn get_addressing_hash_by_key_identifier<'a>(
        &'a self,
        key_identifier: &'a str,
    ) -> BoxFuture<'a, Result<String, StorageError>>;
    fn lookup_addressing_hash<'a>(&'a self, lookup_key: &'a str) -> BoxFuture<'a, Result<String, StorageError>>;
    fn store_private_ssh_key(&self, key: SshKeyEntry) -> BoxFuture<Result<(), StorageError>>;
    fn get_ssh_private_key_by_type(&self, key_type: SshKeyType) -> BoxFuture<Result<SshKeyEntry, StorageError>>;
}
