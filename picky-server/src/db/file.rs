use crate::{
    configuration::ServerConfig,
    db::{CertificateEntry, PickyStorage, StorageError},
    multihash::multihash_encode,
};
use snafu::Snafu;
use std::{
    fs::File,
    io::{Read, Write},
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
        let d = std::fs::read_dir(&self.folder_path)
            .map_err(|e| format!("repository folder not found: {}", e))?;
        for f in d {
            let f = f.map_err(|e| format!("error looking for directory: {}", e))?;
            coll.push(f.file_name().into_string().map_err(|e| {
                format!(
                    "error writing filename from OsString: {}",
                    e.to_string_lossy()
                )
            })?);
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

const DEFAULT_FILEBASE_PATH: &str = "database/";
const REPO_CERTIFICATE: &str = "CertificateStore/";
const REPO_KEY: &str = "KeyStore/";
const REPO_CERTNAME: &str = "NameStore/";
const REPO_KEYIDENTIFIER: &str = "KeyIdentifierStore/";
const TXT_EXT: &str = ".txt";
const DER_EXT: &str = ".der";

pub struct FileStorage {
    name: FileRepo<String>,
    cert: FileRepo<Vec<u8>>,
    keys: FileRepo<Vec<u8>>,
    key_identifiers: FileRepo<String>,
}

impl FileStorage {
    pub fn new(config: &ServerConfig) -> Self {
        let path = if config.save_file_path.eq("") {
            DEFAULT_FILEBASE_PATH.to_owned()
        } else {
            format!("{}{}", &config.save_file_path, DEFAULT_FILEBASE_PATH)
        };

        FileStorage {
            name: FileRepo::new(path.clone(), REPO_CERTNAME)
                .expect("couldn't initialize name repo"),
            cert: FileRepo::new(path.clone(), REPO_CERTIFICATE)
                .expect("couldn't initialize cert repo"),
            keys: FileRepo::new(path.clone(), REPO_KEY).expect("couldn't initialize keys repo"),
            key_identifiers: FileRepo::new(path, REPO_KEYIDENTIFIER)
                .expect("couldn't initialize key identifiers repo"),
        }
    }

    fn h_get(
        &self,
        hash: &str,
        repo: &FileRepo<Vec<u8>>,
        type_err: &'static str,
    ) -> Result<Vec<u8>, FileStorageError> {
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

        let cert_hash = multihash_encode(&cert).map_err(|e| FileStorageError::Other {
            description: format!("couldn't hash certificate der: {}", e),
        })?;

        self.name.insert(
            &format!("{}{}", name.replace(" ", "_"), TXT_EXT),
            &cert_hash,
        )?;

        self.cert
            .insert(&format!("{}{}", cert_hash, DER_EXT), &cert.to_vec())?;

        if let Some(key) = key {
            self.keys
                .insert(&format!("{}{}", cert_hash, DER_EXT), &key.to_vec())?;
        }

        self.key_identifiers
            .insert(&format!("{}{}", key_identifier, TXT_EXT), &cert_hash)?;

        Ok(())
    }

    fn get_hash_by_name(&self, name: &str) -> Result<String, StorageError> {
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

        let hash = std::fs::read_to_string(file_path).map_err(|e| FileStorageError::Other {
            description: format!("error reading file '{}': {}", file, e),
        })?;
        Ok(hash)
    }

    fn get_cert_by_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let cert = self.h_get(hash, &self.cert, "Cert")?;
        Ok(cert)
    }

    fn get_key_by_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let key = self.h_get(hash, &self.keys, "Key")?;
        Ok(key)
    }

    fn get_key_identifier_by_hash(&self, _: &str) -> Result<String, StorageError> {
        unimplemented!()
    }

    fn get_hash_by_key_identifier(&self, key_identifier: &str) -> Result<String, StorageError> {
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

        let hash = std::fs::read_to_string(file_path).map_err(|e| FileStorageError::Other {
            description: format!("error reading file '{}': {}", file, e),
        })?;
        Ok(hash)
    }
}
