mod mongo_connection;
mod mongo_repository;

use crate::{
    addressing::{encode_to_alternative_addresses, encode_to_canonical_address},
    config::Config,
    db::{
        mongodb::{
            mongo_connection::MongoConnection,
            mongo_repository::{
                CertificateModel, CertificateStoreRepository, ConfigStoreRepository, HashLookupTableStoreRepository,
                KeyIdentifierModel, KeyIdentifierStoreRepository, KeyModel, KeyStoreRepository, NameModel,
                NameStoreRepository, CERTIFICATE_COLLECTION_NAME, CONFIG_COLLECTION_NAME,
                HASH_LOOKUP_TABLE_COLLECTION_NAME, KEY_IDENTIFIER_COLLECTION_NAME, KEY_STORE_COLLECTION_NAME,
                NAME_STORE_COLLECTION_NAME,
            },
        },
        CertificateEntry, PickyStorage, StorageError, SCHEMA_LAST_VERSION,
    },
};
use bson::{doc, from_bson, spec::BinarySubtype, Bson};
use futures::{future::BoxFuture, FutureExt};
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
    pub async fn new(config: &Config) -> Self {
        let db = MongoConnection::new(&config.database_url, &config.database_name).expect("build mongo connection");

        let storage = MongoStorage {
            mongo_conn: db.clone(),
            certificate_store: CertificateStoreRepository::new(db.clone(), CERTIFICATE_COLLECTION_NAME),
            key_identifier_store: KeyIdentifierStoreRepository::new(db.clone(), KEY_IDENTIFIER_COLLECTION_NAME),
            key_store: KeyStoreRepository::new(db.clone(), KEY_STORE_COLLECTION_NAME),
            name_store: NameStoreRepository::new(db.clone(), NAME_STORE_COLLECTION_NAME),
            hash_lookup: HashLookupTableStoreRepository::new(db.clone(), HASH_LOOKUP_TABLE_COLLECTION_NAME),
        };

        let config = ConfigStoreRepository::new(db, CONFIG_COLLECTION_NAME);
        let config_collection = config.get_collection().await.expect("config collection");
        let mut config_cursor = config_collection.find(None, None).expect("find config doc");
        if let Some(config_doc) = config_cursor.next() {
            let config_doc = config_doc.expect("config doc");
            if config_cursor.has_next().expect("collection cursor next") {
                panic!("multiple config doc found in database!");
            }

            match config_doc.get("schema_version") {
                Some(Bson::I32(supported)) if supported == &i32::from(SCHEMA_LAST_VERSION) => {
                    log::info!("detected database using supported v{} schema", supported);
                }
                Some(Bson::I32(unsupported)) => {
                    panic!("unsupported schema version: v{}", unsupported);
                }
                Some(invalid) => {
                    panic!("invalid schema version config format: {:?}", invalid);
                }
                None => {
                    panic!("'schema_version' field not found in config doc");
                }
            }
        } else {
            // no config doc found

            let cert_collection = storage
                .certificate_store
                .get_collection()
                .await
                .expect("access certificate store collection");
            let certs_count = cert_collection
                .count(None, None)
                .expect("count number of certificates in store");

            if certs_count != 0 {
                log::info!("detected v0 schema: migrate database to v{}...", SCHEMA_LAST_VERSION);

                let key_identifier_collection = storage
                    .key_identifier_store
                    .get_collection()
                    .await
                    .expect("access key identifier store collection");
                let key_collection = storage
                    .key_store
                    .get_collection()
                    .await
                    .expect("access key store collection");
                let name_collection = storage
                    .name_store
                    .get_collection()
                    .await
                    .expect("access name store collection");
                let hash_lookup_collection = storage
                    .hash_lookup
                    .get_collection()
                    .await
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
                        .await
                        .expect("couldn't store certificate (migration from v0 schema)");
                }

                log::info!("migrated to v{} successfully!", SCHEMA_LAST_VERSION);
            } else {
                log::info!("fresh new database using v{} schema", SCHEMA_LAST_VERSION);
            }

            config_collection
                .insert_one(doc!("schema_version": 1), None)
                .expect("insert config doc");
        }

        storage
    }
}

impl PickyStorage for MongoStorage {
    fn health(&self) -> BoxFuture<'_, Result<(), StorageError>> {
        async move {
            let shallow_clone = self.mongo_conn.clone();
            tokio::task::spawn_blocking(move || shallow_clone.ping())
                .await
                .map_err(|e| MongoStorageError::Other {
                    description: format!("couldn't join ping task: {}", e),
                })?
                .map_err(|e| MongoStorageError::Other {
                    description: format!("ping to mongo connexion failed: {}", e),
                })?;
            Ok(())
        }
        .boxed()
    }

    fn store(&self, entry: CertificateEntry) -> BoxFuture<'_, Result<(), StorageError>> {
        let name = entry.name;
        let cert = entry.cert;
        let key_identifier = entry.key_identifier;
        let key = entry.key;

        async move {
            let addressing_hash = encode_to_canonical_address(&cert).map_err(|e| MongoStorageError::Other {
                description: format!("couldn't get certificate multihash: {}", e),
            })?;

            let alternative_addresses =
                encode_to_alternative_addresses(&cert).map_err(|e| MongoStorageError::Other {
                    description: format!("couldn't encode alternative addresses: {}", e),
                })?;

            let name_doc = doc!("key": name.clone());
            let name_item = NameModel::new(name, addressing_hash.clone());
            self.name_store.update_with_options(name_doc, name_item, true).await?;

            let certificate_doc = doc!("key": addressing_hash.clone());
            let certificate_item =
                CertificateModel::new(addressing_hash.clone(), Bson::Binary(BinarySubtype::Generic, cert));
            self.certificate_store
                .update_with_options(certificate_doc, certificate_item, true)
                .await?;

            let key_identifier_doc = doc!("key": key_identifier.clone());
            let key_identifier_item = KeyIdentifierModel::new(key_identifier, addressing_hash.clone());
            self.key_identifier_store
                .update_with_options(key_identifier_doc, key_identifier_item, true)
                .await?;

            for alternative_address in alternative_addresses.into_iter() {
                let alternative_hash_doc = doc!("key": alternative_address.clone());
                let alternative_hash_item = KeyIdentifierModel::new(alternative_address, addressing_hash.clone());
                self.hash_lookup
                    .update_with_options(alternative_hash_doc, alternative_hash_item, true)
                    .await?;
            }

            if let Some(key) = key {
                let key_doc = doc!("key": addressing_hash.clone());
                let key_item = KeyModel::new(addressing_hash, Bson::Binary(BinarySubtype::Generic, key));
                self.key_store.update_with_options(key_doc, key_item, true).await?;
            }

            Ok(())
        }
        .boxed()
    }

    fn get_addressing_hash_by_name<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<String, StorageError>> {
        async move {
            let hash = self
                .name_store
                .get(doc!("key": name))
                .await?
                .map(|model| model.value)
                .ok_or_else(|| MongoStorageError::Other {
                    description: format!("couldn't not find hash by name '{}'", name),
                })?;
            Ok(hash)
        }
        .boxed()
    }

    fn get_cert_by_addressing_hash<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, Result<Vec<u8>, StorageError>> {
        async move {
            let cert =
                self.certificate_store
                    .get(doc!("key": hash))
                    .await?
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
        .boxed()
    }

    fn get_key_by_addressing_hash<'a>(&'a self, hash: &'a str) -> BoxFuture<'a, Result<Vec<u8>, StorageError>> {
        async move {
            let key = self
                .key_store
                .get(doc!("key": hash))
                .await?
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
        .boxed()
    }

    fn get_addressing_hash_by_key_identifier<'a>(
        &'a self,
        key_identifier: &'a str,
    ) -> BoxFuture<'a, Result<String, StorageError>> {
        async move {
            Ok(self
                .key_identifier_store
                .get(doc!("key": key_identifier))
                .await?
                .ok_or_else(|| MongoStorageError::Other {
                    description: format!("addressing hash not found by key identifier \"{}\"", key_identifier),
                })?
                .value)
        }
        .boxed()
    }

    fn lookup_addressing_hash<'a>(&'a self, lookup_key: &'a str) -> BoxFuture<'a, Result<String, StorageError>> {
        async move {
            Ok(self
                .hash_lookup
                .get(doc!("key": lookup_key))
                .await?
                .ok_or_else(|| MongoStorageError::Other {
                    description: format!("addressing hash not found using lookup key \"{}\"", lookup_key),
                })?
                .value)
        }
        .boxed()
    }
}
