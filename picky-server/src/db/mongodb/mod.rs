mod mongo_connection;
mod mongo_repository;

use crate::{
    addressing::{encode_to_alternative_addresses, encode_to_canonical_address},
    configuration::ServerConfig,
    db::{
        mongodb::{
            mongo_connection::MongoConnection,
            mongo_repository::{
                CertificateModel, CertificateStoreRepository, ConfigModel, ConfigStoreRepository,
                HashLookupTableStoreRepository, KeyIdentifierModel, KeyIdentifierStoreRepository, KeyModel,
                KeyStoreRepository, NameModel, NameStoreRepository, CERTIFICATE_COLLECTION_NAME,
                CONFIG_COLLECTION_NAME, HASH_LOOKUP_TABLE_COLLECTION_NAME, KEY_IDENTIFIER_COLLECTION_NAME,
                KEY_STORE_COLLECTION_NAME, NAME_STORE_COLLECTION_NAME,
            },
        },
        CertificateEntry, PickyStorage, StorageError, SCHEMA_LAST_VERSION,
    },
};
use bson::{bson, doc, from_bson, spec::BinarySubtype, Bson};
use picky::x509::Cert;
use snafu::Snafu;
use std::{collections::HashMap, convert::TryFrom};

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
    hash_lookup: HashLookupTableStoreRepository,
}

impl MongoStorage {
    pub fn new(config: &ServerConfig) -> Self {
        let db = MongoConnection::new(&config.database_url).expect("build mongo connection");

        let storage = MongoStorage {
            mongo_conn: db.clone(),
            certificate_store: CertificateStoreRepository::new(db.clone(), CERTIFICATE_COLLECTION_NAME),
            key_identifier_store: KeyIdentifierStoreRepository::new(db.clone(), KEY_IDENTIFIER_COLLECTION_NAME),
            key_store: KeyStoreRepository::new(db.clone(), KEY_STORE_COLLECTION_NAME),
            name_store: NameStoreRepository::new(db.clone(), NAME_STORE_COLLECTION_NAME),
            hash_lookup: HashLookupTableStoreRepository::new(db.clone(), HASH_LOOKUP_TABLE_COLLECTION_NAME),
        };

        let config = ConfigStoreRepository::new(db, CONFIG_COLLECTION_NAME);

        let schema_version_filter_doc = doc!("key": "schema_version");
        if let Some(schema_version) = config
            .get(schema_version_filter_doc.clone())
            .expect("access schema version")
        {
            match schema_version.value {
                Bson::I32(supported) if supported == i32::from(SCHEMA_LAST_VERSION) => {
                    log::info!("detected database using supported v{} schema", supported);
                }
                Bson::I32(unsupported) => {
                    panic!("unsupported schema version: v{}", unsupported);
                }
                invalid => {
                    panic!("invalid schema version config format: {:?}", invalid);
                }
            }
        } else {
            let cert_collection = storage
                .certificate_store
                .get_collection()
                .expect("access certificate store collection");
            let certs_count = cert_collection
                .count(None, None)
                .expect("count number of certificates in store");

            if certs_count != 0 {
                log::info!("detected v0 schema: migrate database to v{}...", SCHEMA_LAST_VERSION);

                let key_identifier_collection = storage
                    .key_identifier_store
                    .get_collection()
                    .expect("access key identifier store collection");
                let key_collection = storage.key_store.get_collection().expect("access key store collection");
                let name_collection = storage
                    .name_store
                    .get_collection()
                    .expect("access name store collection");
                let hash_lookup_collection = storage
                    .hash_lookup
                    .get_collection()
                    .expect("access hash lookup store collection");

                let mut original_data =
                    HashMap::with_capacity(usize::try_from(certs_count).expect("try from certs count"));

                for doc in cert_collection.find(None, None).expect("find certificates") {
                    let doc = doc.expect("unwrap cert doc");
                    let cert_model: CertificateModel =
                        from_bson(Bson::Document(doc)).expect("cert model from cert bson doc");
                    if let Bson::Binary(BinarySubtype::Generic, bin) = cert_model.value {
                        original_data.insert(cert_model.key, (bin, None));
                    }
                }

                for doc in key_collection.find(None, None).expect("find private keys") {
                    let doc = doc.expect("unwrap key doc");
                    let key_model: KeyModel = from_bson(Bson::Document(doc)).expect("key model from key bson doc");
                    if let Bson::Binary(BinarySubtype::Generic, bin) = key_model.value {
                        original_data
                            .entry(key_model.key)
                            .and_modify(|entry| entry.1 = Some(bin));
                    }
                }

                // clean all
                cert_collection.drop().expect("drop certificate store");
                key_identifier_collection.drop().expect("drop key identifier store");
                key_collection.drop().expect("drop key store");
                name_collection.drop().expect("drop name store");
                hash_lookup_collection.drop().expect("drop hash lookup table");

                for (_, (cert_der, key_pkcs10)) in original_data.into_iter() {
                    let cert = Cert::from_der(&cert_der).expect("decode cert from der");
                    storage
                        .store(CertificateEntry {
                            name: cert
                                .subject_name()
                                .find_common_name()
                                .expect("cert common name")
                                .to_string(),
                            cert: cert_der,
                            key_identifier: hex::encode(cert.subject_key_identifier().expect("cert key id")),
                            key: key_pkcs10,
                        })
                        .expect("couldn't store certificate (migration from v0 schema)");
                }

                log::info!("migrated to v{} successfully!", SCHEMA_LAST_VERSION);
            } else {
                log::info!("fresh new database using v{} schema", SCHEMA_LAST_VERSION);
            }

            // insert last schema version
            config
                .update_with_options(
                    schema_version_filter_doc,
                    ConfigModel::new("schema_version".to_owned(), Bson::I32(SCHEMA_LAST_VERSION.into())),
                    true,
                )
                .expect("update config collection");
        }

        storage
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

        let addressing_hash = encode_to_canonical_address(&cert).map_err(|e| MongoStorageError::Other {
            description: format!("couldn't get certificate multihash: {}", e),
        })?;

        let alternative_addresses = encode_to_alternative_addresses(&cert).map_err(|e| MongoStorageError::Other {
            description: format!("couldn't encode alternative addresses: {}", e),
        })?;

        let name_doc = doc!("key": name.clone());
        let name_item = NameModel::new(name, addressing_hash.clone());
        self.name_store.update_with_options(name_doc, name_item, true)?;

        let certificate_doc = doc!("key": addressing_hash.clone());
        let certificate_item =
            CertificateModel::new(addressing_hash.clone(), Bson::Binary(BinarySubtype::Generic, cert));
        self.certificate_store
            .update_with_options(certificate_doc, certificate_item, true)?;

        let key_identifier_doc = doc!("key": key_identifier.clone());
        let key_identifier_item = KeyIdentifierModel::new(key_identifier, addressing_hash.clone());
        self.key_identifier_store
            .update_with_options(key_identifier_doc, key_identifier_item, true)?;

        for alternative_address in alternative_addresses.into_iter() {
            let alternative_hash_doc = doc!("key": alternative_address.clone());
            let alternative_hash_item = KeyIdentifierModel::new(alternative_address, addressing_hash.clone());
            self.hash_lookup
                .update_with_options(alternative_hash_doc, alternative_hash_item, true)?;
        }

        if let Some(key) = key {
            let key_doc = doc!("key": addressing_hash.clone());
            let key_item = KeyModel::new(addressing_hash, Bson::Binary(BinarySubtype::Generic, key));
            self.key_store.update_with_options(key_doc, key_item, true)?;
        }

        Ok(())
    }

    fn get_addressing_hash_by_name(&self, name: &str) -> Result<String, StorageError> {
        let hash = self
            .name_store
            .get(doc!("key": name))?
            .map(|model| model.value)
            .ok_or_else(|| MongoStorageError::Other {
                description: format!("couldn't not find hash by name '{}'", name),
            })?;
        Ok(hash)
    }

    fn get_cert_by_addressing_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
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

    fn get_key_by_addressing_hash(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
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

    fn get_addressing_hash_by_key_identifier(&self, key_identifier: &str) -> Result<String, StorageError> {
        Ok(self
            .key_identifier_store
            .get(doc!("key": key_identifier))?
            .ok_or_else(|| MongoStorageError::Other {
                description: format!("addressing hash not found by key identifier \"{}\"", key_identifier),
            })?
            .value)
    }

    fn lookup_addressing_hash(&self, lookup_key: &str) -> Result<String, StorageError> {
        Ok(self
            .hash_lookup
            .get(doc!("key": lookup_key))?
            .ok_or_else(|| MongoStorageError::Other {
                description: format!("addressing hash not found using lookup key \"{}\"", lookup_key),
            })?
            .value)
    }
}
