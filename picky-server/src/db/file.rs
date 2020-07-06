use crate::{
    addressing::{encode_to_alternative_addresses, encode_to_canonical_address},
    config::Config,
    db::{config::DatabaseConfig, CertificateEntry, PickyStorage, StorageError, SCHEMA_LAST_VERSION},
};
use futures::{future::BoxFuture, FutureExt};
use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FileStorageError {
    #[error("generic error: {}", description)]
    Other { description: String },
}

impl From<String> for FileStorageError {
    fn from(e: String) -> Self {
        Self::Other { description: e }
    }
}

#[derive(Clone)]
struct FileRepo<T> {
    folder_path: PathBuf,
    _pd: std::marker::PhantomData<T>,
}

impl<T> FileRepo<T>
where
    T: Eq + Clone + AsRef<[u8]>,
{
    fn new(db_folder_path: &Path, name: &str) -> Result<Self, FileStorageError> {
        let folder_path = db_folder_path.join(name);
        std::fs::create_dir_all(&folder_path)
            .map_err(|e| format!("couldn't create folder '{}': {}", folder_path.to_string_lossy(), e))?;
        Ok(Self {
            folder_path,
            _pd: std::marker::PhantomData,
        })
    }

    async fn get_collection(&self) -> Result<Vec<String>, FileStorageError> {
        // This isn't an efficient way to proceed.
        // Implementing a lazy wrapper would be a better approach should this be used in production.
        let mut coll = Vec::new();
        let mut d = tokio::fs::read_dir(&self.folder_path)
            .await
            .map_err(|e| format!("repository folder not found: {}", e))?;

        while let Some(f) = d
            .next_entry()
            .await
            .map_err(|e| format!("couldn't read entry: {}", e))?
        {
            coll.push(
                f.file_name()
                    .into_string()
                    .map_err(|e| format!("error writing filename from OsString: {}", e.to_string_lossy()))?,
            );
        }
        Ok(coll)
    }

    async fn insert(&self, key: &str, value: &T) -> Result<(), FileStorageError> {
        let mut file = File::create(self.folder_path.join(key)).map_err(|e| {
            format!(
                "couldn't open file ({}{}): {}",
                self.folder_path.to_string_lossy(),
                key,
                e
            )
        })?;
        file.write_all(value.as_ref())
            .map_err(|e| format!("Error writing data to {}: {}", key, e))?;
        Ok(())
    }
}

const REPO_CERTIFICATE_OLD: &str = "CertificateStore/";

const REPO_CERTIFICATE: &str = "certificate_store/";
const REPO_KEY: &str = "key_store/";
const REPO_CERT_NAME: &str = "name_store/";
const REPO_KEY_IDENTIFIER: &str = "key_identifier_store/";
const REPO_HASH_LOOKUP_TABLE: &str = "hash_lookup_store/";
const TXT_EXT: &str = ".txt";
const DER_EXT: &str = ".der";

const CONFIG_FILE_NAME: &str = "config.json";

pub struct FileStorage {
    name: FileRepo<String>,
    cert: FileRepo<Vec<u8>>,
    keys: FileRepo<Vec<u8>>,
    key_identifiers: FileRepo<String>,
    hash_lookup: FileRepo<String>,
}

impl FileStorage {
    pub fn new(config: &Config) -> Self {
        std::fs::create_dir_all(&config.file_backend_path).expect("create file backend directory");

        let config_path = config.file_backend_path.join(CONFIG_FILE_NAME);
        if config_path.exists() {
            let json = std::fs::read_to_string(config_path).expect("read config file");
            let db_config: DatabaseConfig = serde_json::from_str(&json).expect("decode json config");
            match db_config.schema_version {
                SCHEMA_LAST_VERSION => {
                    // supported schema version, we're cool.
                }
                unsupported => panic!("unsupported schema version: {}", unsupported),
            }
        } else if config.file_backend_path.join(REPO_CERTIFICATE_OLD).exists() {
            // v0 schema, unsupported for file backend
            panic!("detected schema version 0 that isn't supported anymore by file backend");
        } else {
            // fresh new database, insert last schema version
            let db_config = DatabaseConfig {
                schema_version: SCHEMA_LAST_VERSION,
            };
            let json = serde_json::to_string_pretty(&db_config).expect("encode json config");
            std::fs::write(config_path, json).expect("write json config");
        }

        FileStorage {
            name: FileRepo::new(&config.file_backend_path, REPO_CERT_NAME).expect("couldn't initialize name repo"),
            cert: FileRepo::new(&config.file_backend_path, REPO_CERTIFICATE).expect("couldn't initialize cert repo"),
            keys: FileRepo::new(&config.file_backend_path, REPO_KEY).expect("couldn't initialize keys repo"),
            key_identifiers: FileRepo::new(&config.file_backend_path, REPO_KEY_IDENTIFIER)
                .expect("couldn't initialize key identifiers repo"),
            hash_lookup: FileRepo::new(&config.file_backend_path, REPO_HASH_LOOKUP_TABLE)
                .expect("couldn't initialize hash lookup table repo"),
        }
    }

    async fn h_get<'a>(
        &'a self,
        hash: &'a str,
        repo: &'a FileRepo<Vec<u8>>,
        type_err: &'static str,
    ) -> Result<Vec<u8>, FileStorageError> {
        let hash = format!("{}{}", hash, DER_EXT);
        let repo_collection = if let Ok(repo_collection) = repo.get_collection().await {
            repo_collection
        } else {
            return Err(FileStorageError::Other {
                description: format!("{} not found", type_err),
            });
        };

        let mut found_item = Vec::new();
        for item in repo_collection {
            if hash.eq(&item) {
                if let Ok(mut file) = File::open(repo.folder_path.join(item)) {
                    file.read_to_end(&mut found_item)
                        .map_err(|e| format!("Error reading file: {}", e))?;
                    break;
                }
            }
        }

        if found_item.is_empty() {
            Err(FileStorageError::Other {
                description: format!("{} file not found", type_err),
            })
        } else {
            Ok(found_item)
        }
    }
}

impl PickyStorage for FileStorage {
    fn health(&self) -> BoxFuture<'_, Result<(), StorageError>> {
        async { Ok(()) }.boxed()
    }

    fn store(&self, entry: CertificateEntry) -> BoxFuture<'_, Result<(), StorageError>> {
        let name = entry.name;
        let cert = entry.cert;
        let key_identifier = entry.key_identifier;
        let key = entry.key;

        async move {
            let addressing_hash = encode_to_canonical_address(&cert).map_err(|e| FileStorageError::Other {
                description: format!("couldn't hash certificate der: {}", e),
            })?;

            let alternative_addresses =
                encode_to_alternative_addresses(&cert).map_err(|e| FileStorageError::Other {
                    description: format!("couldn't encode alternative addresses: {}", e),
                })?;

            self.name
                .insert(&format!("{}{}", name.replace(" ", "_"), TXT_EXT), &addressing_hash)
                .await?;
            self.cert
                .insert(&format!("{}{}", addressing_hash, DER_EXT), &cert.to_vec())
                .await?;
            self.key_identifiers
                .insert(&format!("{}{}", key_identifier, TXT_EXT), &addressing_hash)
                .await?;

            for alternative_address in alternative_addresses.into_iter() {
                self.hash_lookup
                    .insert(&format!("{}{}", alternative_address, TXT_EXT), &addressing_hash)
                    .await?;
            }

            if let Some(key) = key {
                self.keys
                    .insert(&format!("{}{}", addressing_hash, DER_EXT), &key.to_vec())
                    .await?;
            }

            Ok(())
        }
        .boxed()
    }

    fn get_cert_by_addressing_hash<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, Result<Vec<u8>, StorageError>> {
        async move {
            let cert = self.h_get(hash, &self.cert, "Cert").await?;
            Ok(cert)
        }
        .boxed()
    }

    fn get_key_by_addressing_hash<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, Result<Vec<u8>, StorageError>> {
        async move {
            let key = self.h_get(hash, &self.keys, "Key").await?;
            Ok(key)
        }
        .boxed()
    }

    fn get_addressing_hash_by_name(&self, name: &str) -> BoxFuture<'_, Result<String, StorageError>> {
        let name = format!("{}{}", name, TXT_EXT).replace(" ", "_");
        async move {
            let file = self
                .name
                .get_collection()
                .await?
                .into_iter()
                .find(|filename| filename.eq(&name))
                .ok_or_else(|| FileStorageError::Other {
                    description: format!("'{}' not found", name),
                })?;
            let file_path = self.name.folder_path.join(file);
            Ok(tokio::fs::read_to_string(&file_path)
                .await
                .map_err(|e| FileStorageError::Other {
                    description: format!("error reading file '{}': {}", file_path.to_string_lossy(), e),
                })?)
        }
        .boxed()
    }

    fn get_addressing_hash_by_key_identifier(
        &self,
        key_identifier: &str,
    ) -> BoxFuture<'_, Result<String, StorageError>> {
        let key_identifier = format!("{}{}", key_identifier, TXT_EXT);
        async move {
            let file = self
                .key_identifiers
                .get_collection()
                .await?
                .into_iter()
                .find(|filename| filename.eq(&key_identifier))
                .ok_or_else(|| FileStorageError::Other {
                    description: format!("'{}' not found", key_identifier),
                })?;
            let file_path = self.key_identifiers.folder_path.join(file);
            Ok(tokio::fs::read_to_string(&file_path)
                .await
                .map_err(|e| FileStorageError::Other {
                    description: format!("error reading file '{}': {}", file_path.to_string_lossy(), e),
                })?)
        }
        .boxed()
    }

    fn lookup_addressing_hash(&self, lookup_key: &str) -> BoxFuture<'_, Result<String, StorageError>> {
        let lookup_key_file = format!("{}{}", lookup_key, TXT_EXT);
        async move {
            let file = self
                .hash_lookup
                .get_collection()
                .await?
                .into_iter()
                .find(|filename| filename.eq(&lookup_key_file))
                .ok_or_else(|| FileStorageError::Other {
                    description: format!("'{}' not found", lookup_key_file),
                })?;
            let file_path = self.hash_lookup.folder_path.join(file);
            Ok(tokio::fs::read_to_string(&file_path)
                .await
                .map_err(|e| FileStorageError::Other {
                    description: format!("error reading file '{}': {}", file_path.to_string_lossy(), e),
                })?)
        }
        .boxed()
    }
}
