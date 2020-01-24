mod config;
mod file;
mod memory;
mod mongodb;

use crate::{
    config::{BackendType, Config},
    db::{
        file::{FileStorage, FileStorageError},
        memory::{MemoryStorage, MemoryStorageError},
        mongodb::{MongoStorage, MongoStorageError},
    },
};
use snafu::Snafu;

pub const SCHEMA_LAST_VERSION: u8 = 1;

#[derive(Debug, Snafu)]
pub enum StorageError {
    #[snafu(display("mongo storage error: {}", source))]
    Mongo { source: MongoStorageError },

    #[snafu(display("file storage error: {}", source))]
    File { source: FileStorageError },

    #[snafu(display("memory storage error: {}", source))]
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

pub fn get_storage(config: &Config) -> BoxedPickyStorage {
    match config.backend {
        BackendType::MongoDb => Box::new(MongoStorage::new(config)),
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

pub trait PickyStorage: Send + Sync {
    fn health(&self) -> Result<(), StorageError>;
    fn store(&self, entry: CertificateEntry) -> Result<(), StorageError>;
    fn get_cert_by_addressing_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError>;
    fn get_key_by_addressing_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError>;
    fn get_addressing_hash_by_name(&self, name: &str) -> Result<String, StorageError>;
    fn get_addressing_hash_by_key_identifier(&self, key_identifier: &str) -> Result<String, StorageError>;
    fn lookup_addressing_hash(&self, lookup_key: &str) -> Result<String, StorageError>;
}
