use crate::{
    addressing::{encode_to_alternative_addresses, encode_to_canonical_address},
    configuration::ServerConfig,
    db::{CertificateEntry, PickyStorage, StorageError, SCHEMA_LAST_VERSION},
};
use snafu::Snafu;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

#[derive(Debug, Snafu)]
pub enum FileStorageError {
    #[snafu(display("generic error: {}", description))]
    Other { description: String },
}

impl From<String> for FileStorageError {
    fn from(e: String) -> Self {
        Self::Other { description: e }
    }
}

#[derive(Clone)]
struct FileRepo<T> {
    folder_path: String,
    _pd: std::marker::PhantomData<T>,
}

impl<T> FileRepo<T>
where
    T: Eq + Clone + AsRef<[u8]>,
{
    fn new(mut db_folder_path: String, name: &str) -> Result<Self, FileStorageError> {
        if !db_folder_path.ends_with('/') {
            db_folder_path.push('/');
        }
        db_folder_path.push_str(name);

        std::fs::create_dir_all(&db_folder_path)
            .map_err(|e| format!("couldn't create folder '{}': {}", db_folder_path, e))?;

        Ok(Self {
            folder_path: db_folder_path,
            _pd: std::marker::PhantomData,
        })
    }

    fn get_collection(&self) -> Result<Vec<String>, FileStorageError> {
        // This isn't an efficient way to proceed.
        // Implementing a lazy wrapper would be a better approach should this be used in production.
        let mut coll = Vec::new();
        let d = std::fs::read_dir(&self.folder_path).map_err(|e| format!("repository folder not found: {}", e))?;
        for f in d {
            let f = f.map_err(|e| format!("error looking for directory: {}", e))?;
            coll.push(
                f.file_name()
                    .into_string()
                    .map_err(|e| format!("error writing filename from OsString: {}", e.to_string_lossy()))?,
            );
        }
        Ok(coll)
    }

    fn insert(&self, key: &str, value: &T) -> Result<(), FileStorageError> {
        let mut file = File::create(format!("{}{}", self.folder_path, key))
            .map_err(|e| format!("couldn't open file ({}{}): {}", self.folder_path, key, e))?;
        file.write_all(value.as_ref())
            .map_err(|e| format!("Error writing data to {}: {}", key, e))?;
        Ok(())
    }
}

const REPO_CERTIFICATE_OLD: &str = "CertificateStore/";

const DEFAULT_BASE_PATH: &str = "database/";
const REPO_CERTIFICATE: &str = "certificate_store/";
const REPO_KEY: &str = "key_store/";
const REPO_CERT_NAME: &str = "name_store/";
const REPO_KEY_IDENTIFIER: &str = "key_identifier_store/";
const REPO_HASH_LOOKUP_TABLE: &str = "hash_lookup_store/";
const REPO_CONFIG: &str = "config_store/";
const TXT_EXT: &str = ".txt";
const DER_EXT: &str = ".der";

pub struct FileStorage {
    name: FileRepo<String>,
    cert: FileRepo<Vec<u8>>,
    keys: FileRepo<Vec<u8>>,
    key_identifiers: FileRepo<String>,
    hash_lookup: FileRepo<String>,
}

impl FileStorage {
    pub fn new(config: &ServerConfig) -> Self {
        let path = if config.save_file_path.eq("") {
            DEFAULT_BASE_PATH.to_owned()
        } else {
            format!("{}{}", &config.save_file_path, DEFAULT_BASE_PATH)
        };

        let config_repo: FileRepo<String> =
            FileRepo::new(path.clone(), REPO_CONFIG).expect("couldn't initialize config repo");
        let schema_version = config_repo
            .get_collection()
            .expect("config collection")
            .into_iter()
            .find(|filename| filename.eq("schema_version.txt"))
            .map(|version_file| {
                let file_path = format!("{}{}", config_repo.folder_path, version_file);
                let version = std::fs::read_to_string(file_path).expect("read schema version file");
                version.parse::<u8>().expect("parse schema version")
            });
        match schema_version {
            None => {
                if Path::new(&format!("{}{}", DEFAULT_BASE_PATH, REPO_CERTIFICATE_OLD)).exists() {
                    // v0 schema, unsupported for file backend
                    panic!("detected schema version 0 that isn't supported anymore by file backend");
                } else {
                    // fresh new database, insert last schema version
                    config_repo
                        .insert("schema_version.txt", &SCHEMA_LAST_VERSION.to_string())
                        .expect("insert schema version");
                }
            }
            Some(SCHEMA_LAST_VERSION) => {
                // supported schema version, we're cool.
            }
            Some(unsupported) => {
                panic!("unsupported schema version: {}", unsupported);
            }
        }

        FileStorage {
            name: FileRepo::new(path.clone(), REPO_CERT_NAME).expect("couldn't initialize name repo"),
            cert: FileRepo::new(path.clone(), REPO_CERTIFICATE).expect("couldn't initialize cert repo"),
            keys: FileRepo::new(path.clone(), REPO_KEY).expect("couldn't initialize keys repo"),
            key_identifiers: FileRepo::new(path.clone(), REPO_KEY_IDENTIFIER)
                .expect("couldn't initialize key identifiers repo"),
            hash_lookup: FileRepo::new(path, REPO_HASH_LOOKUP_TABLE)
                .expect("couldn't initialize hash lookup table repo"),
        }
    }

    fn h_get(&self, hash: &str, repo: &FileRepo<Vec<u8>>, type_err: &'static str) -> Result<Vec<u8>, FileStorageError> {
        let hash = format!("{}{}", hash, DER_EXT);
        let repo_collection = if let Ok(repo_collection) = repo.get_collection() {
            repo_collection
        } else {
            return Err(FileStorageError::Other {
                description: format!("{} not found", type_err),
            });
        };

        let mut found_item = Vec::new();
        for item in repo_collection {
            if hash.eq(&item) {
                if let Ok(mut file) = File::open(format!("{}{}", repo.folder_path, item)) {
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
    fn health(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn store(&self, entry: CertificateEntry) -> Result<(), StorageError> {
        let name = entry.name;
        let cert = entry.cert;
        let key_identifier = entry.key_identifier;
        let key = entry.key;

        let addressing_hash = encode_to_canonical_address(&cert).map_err(|e| FileStorageError::Other {
            description: format!("couldn't hash certificate der: {}", e),
        })?;

        let alternative_addresses = encode_to_alternative_addresses(&cert).map_err(|e| FileStorageError::Other {
            description: format!("couldn't encode alternative addresses: {}", e),
        })?;

        self.name
            .insert(&format!("{}{}", name.replace(" ", "_"), TXT_EXT), &addressing_hash)?;
        self.cert
            .insert(&format!("{}{}", addressing_hash, DER_EXT), &cert.to_vec())?;
        self.key_identifiers
            .insert(&format!("{}{}", key_identifier, TXT_EXT), &addressing_hash)?;

        for alternative_address in alternative_addresses.into_iter() {
            self.hash_lookup
                .insert(&format!("{}{}", alternative_address, TXT_EXT), &addressing_hash)?;
        }

        if let Some(key) = key {
            self.keys
                .insert(&format!("{}{}", addressing_hash, DER_EXT), &key.to_vec())?;
        }

        Ok(())
    }

    fn get_cert_by_addressing_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let cert = self.h_get(hash, &self.cert, "Cert")?;
        Ok(cert)
    }

    fn get_key_by_addressing_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let key = self.h_get(hash, &self.keys, "Key")?;
        Ok(key)
    }

    fn get_addressing_hash_by_name(&self, name: &str) -> Result<String, StorageError> {
        let name = format!("{}{}", name, TXT_EXT).replace(" ", "_");
        let file = self
            .name
            .get_collection()?
            .into_iter()
            .find(|filename| filename.eq(&name))
            .ok_or_else(|| FileStorageError::Other {
                description: format!("'{}' not found", name),
            })?;
        let file_path = format!("{}{}", self.name.folder_path, file);
        Ok(std::fs::read_to_string(file_path).map_err(|e| FileStorageError::Other {
            description: format!("error reading file '{}': {}", file, e),
        })?)
    }

    fn get_addressing_hash_by_key_identifier(&self, key_identifier: &str) -> Result<String, StorageError> {
        let key_identifier = format!("{}{}", key_identifier, TXT_EXT);
        let file = self
            .key_identifiers
            .get_collection()?
            .into_iter()
            .find(|filename| filename.eq(&key_identifier))
            .ok_or_else(|| FileStorageError::Other {
                description: format!("'{}' not found", key_identifier),
            })?;
        let file_path = format!("{}{}", self.key_identifiers.folder_path, file);
        Ok(std::fs::read_to_string(file_path).map_err(|e| FileStorageError::Other {
            description: format!("error reading file '{}': {}", file, e),
        })?)
    }

    fn lookup_addressing_hash(&self, lookup_key: &str) -> Result<String, StorageError> {
        let lookup_key_file = format!("{}{}", lookup_key, TXT_EXT);
        let file = self
            .hash_lookup
            .get_collection()?
            .into_iter()
            .find(|filename| filename.eq(&lookup_key_file))
            .ok_or_else(|| FileStorageError::Other {
                description: format!("'{}' not found", lookup_key_file),
            })?;
        let file_path = format!("{}{}", self.hash_lookup.folder_path, file);
        Ok(std::fs::read_to_string(file_path).map_err(|e| FileStorageError::Other {
            description: format!("error reading file '{}': {}", file, e),
        })?)
    }
}
