use crate::addressing::{encode_to_alternative_addresses, encode_to_canonical_address};
use crate::config::Config;
use crate::db::config::DatabaseConfig;
use crate::db::{CertificateEntry, PickyStorage, SshKeyEntry, SshKeyType, StorageError, SCHEMA_LAST_VERSION};
use futures::future::BoxFuture;
use futures::FutureExt;
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FileStorageError {
    #[error("generic error: {}", description)]
    Other { description: String },
    #[error(transparent)]
    Io(#[from] io::Error),
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

    async fn get(&self, key: &str, buf: &mut [u8]) -> Result<(), FileStorageError> {
        let file_to_open = self.folder_path.join(key);
        let mut file = File::open(file_to_open.as_path()).map_err(FileStorageError::Io)?;

        file.read_exact(buf).map_err(FileStorageError::Io)
    }
}

const REPO_CERTIFICATE_OLD: &str = "CertificateStore/";

const REPO_CERTIFICATE: &str = "certificate_store/";
const REPO_SSH_KEY: &str = "ssh_key_store/";
const REPO_KEY: &str = "key_store/";
const REPO_CERT_NAME: &str = "name_store/";
const REPO_KEY_IDENTIFIER: &str = "key_identifier_store/";
const REPO_HASH_LOOKUP_TABLE: &str = "hash_lookup_store/";
const REPO_AUTHENTICODE_TIMESTAMP: &str = "timestamp_counter_store/";
const TXT_EXT: &str = ".txt";
const DER_EXT: &str = ".der";

const CONFIG_FILE_NAME: &str = "config.json";

pub struct FileStorage {
    name: FileRepo<String>,
    cert: FileRepo<Vec<u8>>,
    keys: FileRepo<Vec<u8>>,
    ssh_keys: FileRepo<SshKeyEntry>,
    key_identifiers: FileRepo<String>,
    hash_lookup: FileRepo<String>,
    issued_timestamps_counter: FileRepo<[u8; 4]>,
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
            ssh_keys: FileRepo::new(&config.file_backend_path, REPO_SSH_KEY)
                .expect("couldn't initialize ssh keys repo"),
            key_identifiers: FileRepo::new(&config.file_backend_path, REPO_KEY_IDENTIFIER)
                .expect("couldn't initialize key identifiers repo"),
            hash_lookup: FileRepo::new(&config.file_backend_path, REPO_HASH_LOOKUP_TABLE)
                .expect("couldn't initialize hash lookup table repo"),
            issued_timestamps_counter: FileRepo::new(&config.file_backend_path, REPO_AUTHENTICODE_TIMESTAMP)
                .expect("couldn't initialize authenticode timestamp counter repo"),
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
            let addressing_hash = encode_to_canonical_address(&cert);

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

    fn increase_issued_authenticode_timestamps_counter(&self) -> BoxFuture<'_, Result<(), StorageError>> {
        let name = format!("{}{}", "timestamp_counter_store", TXT_EXT);

        async move {
            let mut content = [0; 4];
            if let Err(err) = self.issued_timestamps_counter.get(&name, &mut content).await {
                if let FileStorageError::Io(io_error) = &err {
                    if io_error.kind() != ErrorKind::NotFound {
                        return Err(err.into());
                    }
                }
            }

            let mut counter = u32::from_le_bytes([content[0], content[1], content[2], content[3]]);
            counter += 1;
            self.issued_timestamps_counter
                .insert(&name, &counter.to_le_bytes())
                .await?;

            Ok(())
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

    fn store_private_ssh_key(&self, key: SshKeyEntry) -> BoxFuture<Result<(), StorageError>> {
        async move {
            self.ssh_keys.insert(&key.key_type().to_string(), &key).await?;
            Ok(())
        }
        .boxed()
    }

    fn get_ssh_private_key_by_type(&self, key_type: SshKeyType) -> BoxFuture<Result<SshKeyEntry, StorageError>> {
        async move {
            let key_type_str = key_type.as_str();
            let filename = self
                .ssh_keys
                .get_collection()
                .await?
                .into_iter()
                .find(|filename| filename.as_str() == key_type_str)
                .ok_or_else(|| FileStorageError::Other {
                    description: format!("ssh key '{}' not found", key_type_str),
                })?;

            let filepath = self.ssh_keys.folder_path.join(filename);
            let key = tokio::fs::read_to_string(&filepath)
                .await
                .map_err(|e| FileStorageError::Other {
                    description: format!("error reading file '{:?}': '{}'", filepath.as_path(), e),
                })?;
            Ok(SshKeyEntry::new(key_type, key))
        }
        .boxed()
    }

    fn remove_ssh_private_key_by_type(&self, key_type: SshKeyType) -> BoxFuture<Result<(), StorageError>> {
        async move {
            let key_type_str = key_type.as_str();
            let filename = self
                .ssh_keys
                .get_collection()
                .await?
                .into_iter()
                .find(|filename| filename.as_str() == key_type_str)
                .ok_or_else(|| FileStorageError::Other {
                    description: format!("ssh key '{}' not found", key_type_str),
                })?;

            let filepath = self.ssh_keys.folder_path.join(filename);
            tokio::fs::OpenOptions::new()
                .write(true) // we need set write to true to truncate
                .truncate(true)
                .open(filepath)
                .await
                .map_err(FileStorageError::Io)?;

            Ok(())
        }
        .boxed()
    }
}
