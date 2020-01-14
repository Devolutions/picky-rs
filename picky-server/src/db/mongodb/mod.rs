mod mongo_connection;
mod mongo_repository;

use crate::{
    configuration::ServerConfig,
    db::{
        mongodb::{
            mongo_connection::MongoConnection,
            mongo_repository::{
                CertificateModel, CertificateStoreRepository, KeyIdentifierModel, KeyIdentifierStoreRepository,
                KeyModel, KeyStoreRepository, NameModel, NameStoreRepository, CERTIFICATE_COLLECTION_NAME,
                KEY_IDENTIFIER_COLLECTION_NAME, KEY_STORE_COLLECTION_NAME, NAME_STORE_COLLECTION_NAME,
            },
        },
        CertificateEntry, PickyStorage, StorageError,
    },
    multihash::multihash_encode,
};
use bson::{spec::BinarySubtype, Bson};
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum MongoStorageError {
    #[snafu(display("bson encode error: {}", source))]
    BsonEncodeError {
        source: bson::EncoderError,
    },

    #[snafu(display("bson decode error: {}", source))]
    BsonDecodeError {
        source: bson::DecoderError,
    },

    #[snafu(display("mongo error: {}", source))]
    MongoError {
        source: mongodb::Error,
    },

    // insert error
    InsertError,

    /// update error
    UpdateError,

    #[snafu(display("generic error: {}", description))]
    Other {
        description: String,
    },
}

impl From<String> for MongoStorageError {
    fn from(description: String) -> Self {
        MongoStorageError::Other { description }
    }
}

impl From<bson::EncoderError> for MongoStorageError {
    fn from(source: bson::EncoderError) -> Self {
        MongoStorageError::BsonEncodeError { source }
    }
}

impl From<bson::DecoderError> for MongoStorageError {
    fn from(source: bson::DecoderError) -> Self {
        MongoStorageError::BsonDecodeError { source }
    }
}

impl From<mongodb::Error> for MongoStorageError {
    fn from(source: mongodb::Error) -> Self {
        MongoStorageError::MongoError { source }
    }
}

impl From<bson::EncoderError> for StorageError {
    fn from(source: bson::EncoderError) -> Self {
        StorageError::Mongo {
            source: MongoStorageError::BsonEncodeError { source },
        }
    }
}

impl From<bson::DecoderError> for StorageError {
    fn from(source: bson::DecoderError) -> Self {
        StorageError::Mongo {
            source: MongoStorageError::BsonDecodeError { source },
        }
    }
}

impl From<mongodb::Error> for StorageError {
    fn from(source: mongodb::Error) -> Self {
        StorageError::Mongo {
            source: MongoStorageError::MongoError { source },
        }
    }
}

pub struct MongoStorage {
    mongo_conn: MongoConnection,
    certificate_store: CertificateStoreRepository,
    key_identifier_store: KeyIdentifierStoreRepository,
    key_store: KeyStoreRepository,
    name_store: NameStoreRepository,
}

impl MongoStorage {
    pub fn new(config: &ServerConfig) -> Self {
        let db = MongoConnection::new(&config.database_url).expect("couldn't build mongo connection");

        MongoStorage {
            mongo_conn: db.clone(),
            certificate_store: CertificateStoreRepository::new(db.clone(), CERTIFICATE_COLLECTION_NAME),
            key_identifier_store: KeyIdentifierStoreRepository::new(db.clone(), KEY_IDENTIFIER_COLLECTION_NAME),
            key_store: KeyStoreRepository::new(db.clone(), KEY_STORE_COLLECTION_NAME),
            name_store: NameStoreRepository::new(db, NAME_STORE_COLLECTION_NAME),
        }
    }
}

impl PickyStorage for MongoStorage {
    fn health(&self) -> Result<(), StorageError> {
        self.mongo_conn.ping().map_err(|e| MongoStorageError::Other {
            description: format!("ping to mongo connexion failed: {}", e),
        })?;
        Ok(())
    }

    fn store(&self, entry: CertificateEntry) -> Result<(), StorageError> {
        let name = entry.name;
        let cert = entry.cert;
        let key_identifier = entry.key_identifier;
        let key = entry.key;

        let cert_hash = multihash_encode(&cert).map_err(|e| MongoStorageError::Other {
            description: format!("couldn't get certificate multihash: {}", e),
        })?;

        let name_doc = doc!("key": name.clone());
        let name_item = NameModel::new(name, cert_hash.clone());
        self.name_store.update_with_options(name_doc, name_item, true)?;

        let certificate_doc = doc!("key": cert_hash.clone());
        let certificate_item = CertificateModel::new(cert_hash.clone(), Bson::Binary(BinarySubtype::Generic, cert));
        self.certificate_store
            .update_with_options(certificate_doc, certificate_item, true)?;

        if let Some(key) = key {
            let key_doc = doc!("key": cert_hash.clone());
            let key_item = KeyModel::new(cert_hash.clone(), Bson::Binary(BinarySubtype::Generic, key));
            self.key_store.update_with_options(key_doc, key_item, true)?;
        }

        let key_identifier_doc = doc!("key": key_identifier.clone());
        let key_identifier_item = KeyIdentifierModel::new(key_identifier, cert_hash);
        self.key_identifier_store
            .update_with_options(key_identifier_doc, key_identifier_item, true)?;

        Ok(())
    }

    fn get_hash_by_name(&self, name: &str) -> Result<String, StorageError> {
        let hash = self
            .name_store
            .get(doc!("key": name))?
            .map(|model| model.value)
            .ok_or_else(|| MongoStorageError::Other {
                description: format!("couldn't not find hash by name '{}'", name),
            })?;
        Ok(hash)
    }

    fn get_cert_by_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let cert = self
            .certificate_store
            .get(doc!("key": hash))?
            .ok_or_else(|| MongoStorageError::Other {
                description: "cert not found".to_owned(),
            })?;

        match cert.value {
            Bson::Binary(BinarySubtype::Generic, bin) => Ok(bin),
            unexpected => Err(MongoStorageError::Other {
                description: format!("expected binary DB content but got {}", unexpected),
            }
            .into()),
        }
    }

    fn get_key_by_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        let key = self
            .key_store
            .get(doc!("key": hash))?
            .ok_or_else(|| MongoStorageError::Other {
                description: "key not found".to_owned(),
            })?;
        match key.value {
            Bson::Binary(BinarySubtype::Generic, bin) => Ok(bin),
            unexpected => Err(MongoStorageError::Other {
                description: format!("expected binary DB content but got {}", unexpected),
            }
            .into()),
        }
    }

    fn get_key_identifier_by_hash(&self, hash: &str) -> Result<String, StorageError> {
        if let Some(key_identifier) = self.key_identifier_store.get(doc!("value": hash))? {
            Ok(key_identifier.key)
        } else {
            Err(MongoStorageError::Other {
                description: "Key identifier not found".to_owned(),
            }
            .into())
        }
    }

    fn get_hash_by_key_identifier(&self, key_identifier: &str) -> Result<String, StorageError> {
        if let Some(key_identifier) = self.key_identifier_store.get(doc!("key": key_identifier))? {
            Ok(key_identifier.value)
        } else {
            Err(MongoStorageError::Other {
                description: "Key identifier not found".to_owned(),
            }
            .into())
        }
    }
}
