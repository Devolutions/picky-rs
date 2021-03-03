mod model;

use crate::addressing::{encode_to_alternative_addresses, encode_to_canonical_address};
use crate::db::{CertificateEntry, PickyStorage, StorageError, SCHEMA_LAST_VERSION};
use futures::future::BoxFuture;
use futures::stream::StreamExt;
use futures::FutureExt;
use model::*;
use mongodm::mongo::bson::oid::ObjectId;
use mongodm::mongo::bson::spec::BinarySubtype;
use mongodm::mongo::bson::{doc, Binary, Bson};
use mongodm::mongo::options::{ClientOptions, ReadPreference, ReplaceOptions, SelectionCriteria};
use mongodm::mongo::{Client, Database};
use mongodm::{f, ToRepository};
use picky::x509::Cert;
use std::collections::HashMap;
use std::convert::TryFrom;
use thiserror::Error;

const DB_CONNECTION_TIMEOUT_SECS: u64 = 15;

pub async fn build_client(mongo_url: &str) -> mongodm::mongo::error::Result<Client> {
    let mut client_options = ClientOptions::parse(mongo_url).await?;
    client_options.app_name = Some(String::from("Picky"));
    client_options.selection_criteria = Some(SelectionCriteria::ReadPreference(ReadPreference::SecondaryPreferred {
        options: Default::default(),
    }));
    client_options.connect_timeout = Some(std::time::Duration::from_secs(DB_CONNECTION_TIMEOUT_SECS));

    Client::with_options(client_options)
}

#[derive(Debug, Error)]
pub enum MongoStorageError {
    #[error("mongo error: {}", source)]
    MongoError { source: mongodm::mongo::error::Error },

    #[error("generic error: {}", description)]
    Other { description: String },
}

impl From<String> for MongoStorageError {
    fn from(description: String) -> Self {
        MongoStorageError::Other { description }
    }
}

impl From<mongodm::mongo::error::Error> for MongoStorageError {
    fn from(source: mongodm::mongo::error::Error) -> Self {
        MongoStorageError::MongoError { source }
    }
}

impl From<mongodm::mongo::error::Error> for StorageError {
    fn from(source: mongodm::mongo::error::Error) -> Self {
        StorageError::Mongo {
            source: MongoStorageError::MongoError { source },
        }
    }
}

pub struct MongoStorage {
    db: Database,
}

impl ToRepository for MongoStorage {
    fn repository<M: mongodm::Model>(&self) -> mongodm::Repository<M> {
        self.db.repository()
    }

    fn repository_with_options<M: mongodm::Model>(
        &self,
        options: mongodm::mongo::options::CollectionOptions,
    ) -> mongodm::Repository<M> {
        self.db.repository_with_options(options)
    }
}

impl MongoStorage {
    pub async fn new(db: Database) -> Self {
        let storage = MongoStorage { db };

        let config_repo = storage.repository::<Config>();
        let config_opt = config_repo.find_one(doc!(), None).await.expect("config repo");

        const SUPPORTED: i32 = SCHEMA_LAST_VERSION as i32;
        match config_opt {
            Some(Config {
                schema_version: SUPPORTED,
                ..
            }) => {
                log::info!("detected database using supported v{} schema", SUPPORTED);
            }
            Some(Config {
                schema_version: unsupported,
                ..
            }) => {
                panic!("unsupported schema version: v{}", unsupported);
            }
            None => {
                // no config doc found

                let cert_collection = storage.repository::<Certificate>();
                let certs_count = cert_collection
                    .estimated_document_count(None)
                    .await
                    .expect("count number of certificates in store");

                if certs_count > 0 {
                    log::info!("detected v0 schema: migrate database to v{}...", SCHEMA_LAST_VERSION);

                    let key_identifier_collection = storage.repository::<KeyIdentifier>();
                    let key_collection = storage.repository::<Key>();
                    let name_collection = storage.repository::<Name>();
                    let hash_lookup_collection = storage.repository::<HashLookupEntry>();

                    let mut original_data =
                        HashMap::with_capacity(usize::try_from(certs_count).expect("try from certs count"));

                    let mut certs_cursor = cert_collection.find(doc!(), None).await.expect("certs cursor");
                    while let Some(cert_model) = certs_cursor.next().await {
                        let cert_model = cert_model.expect("unwrap cert model");
                        if let Bson::Binary(Binary {
                            subtype: BinarySubtype::Generic,
                            bytes: bin,
                        }) = cert_model.value
                        {
                            original_data.insert(cert_model.key, (bin, None));
                        }
                    }

                    let mut keys_cursor = key_collection.find(doc!(), None).await.expect("find private keys");
                    while let Some(key_model) = keys_cursor.next().await {
                        let key_model = key_model.expect("unwrap key model");
                        if let Bson::Binary(Binary {
                            subtype: BinarySubtype::Generic,
                            bytes: bin,
                        }) = key_model.value
                        {
                            original_data
                                .entry(key_model.key)
                                .and_modify(|entry| entry.1 = Some(bin));
                        }
                    }

                    // clean all
                    cert_collection.drop(None).await.expect("drop certificate store");
                    key_identifier_collection
                        .drop(None)
                        .await
                        .expect("drop key identifier store");
                    key_collection.drop(None).await.expect("drop key store");
                    name_collection.drop(None).await.expect("drop name store");
                    hash_lookup_collection.drop(None).await.expect("drop hash lookup table");

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

                let config = Config {
                    id: ObjectId::new(),
                    schema_version: i32::from(SCHEMA_LAST_VERSION),
                };

                config_repo.insert_one(&config, None).await.expect("insert config doc");
            }
        }

        storage
    }
}

impl PickyStorage for MongoStorage {
    fn health(&self) -> BoxFuture<'_, Result<(), StorageError>> {
        async move {
            self.db
                .list_collection_names(None)
                .await
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
            let addressing_hash = encode_to_canonical_address(&cert);

            let alternative_addresses =
                encode_to_alternative_addresses(&cert).map_err(|e| MongoStorageError::Other {
                    description: format!("couldn't encode alternative addresses: {}", e),
                })?;

            let query = doc! {f!(key in Name): &name};
            let name = Name {
                key: name,
                value: addressing_hash.clone(),
            };
            self.repository::<Name>()
                .replace_one(query, &name, Some(ReplaceOptions::builder().upsert(true).build()))
                .await?;

            let query = doc! {f!(key in Certificate): &addressing_hash };
            let certificate = Certificate {
                key: addressing_hash.clone(),
                value: Bson::Binary(Binary {
                    subtype: BinarySubtype::Generic,
                    bytes: cert,
                }),
            };
            self.repository::<Certificate>()
                .replace_one(
                    query,
                    &certificate,
                    Some(ReplaceOptions::builder().upsert(true).build()),
                )
                .await?;

            let query = doc! { f!(key in KeyIdentifier): &key_identifier };
            let key_identifier = KeyIdentifier {
                key: key_identifier,
                value: addressing_hash.clone(),
            };
            self.repository::<KeyIdentifier>()
                .replace_one(
                    query,
                    &key_identifier,
                    Some(ReplaceOptions::builder().upsert(true).build()),
                )
                .await?;

            for alternative_address in alternative_addresses.into_iter() {
                let query = doc! { f!(key in HashLookupEntry): &alternative_address };
                let alternative_key_identifier = HashLookupEntry {
                    key: alternative_address,
                    value: addressing_hash.clone(),
                };
                self.repository::<HashLookupEntry>()
                    .replace_one(
                        query,
                        &alternative_key_identifier,
                        Some(ReplaceOptions::builder().upsert(true).build()),
                    )
                    .await?;
            }

            if let Some(key) = key {
                let query = doc! {f!(key in Key): &addressing_hash};
                let key = Key {
                    key: addressing_hash,
                    value: Bson::Binary(Binary {
                        subtype: BinarySubtype::Generic,
                        bytes: key,
                    }),
                };
                self.repository::<Key>()
                    .replace_one(query, &key, Some(ReplaceOptions::builder().upsert(true).build()))
                    .await?;
            }

            Ok(())
        }
        .boxed()
    }

    fn get_addressing_hash_by_name<'a>(&'a self, name: &'a str) -> BoxFuture<'a, Result<String, StorageError>> {
        async move {
            let hash = self
                .repository::<Name>()
                .find_one(doc!(f!(key in Name): name), None)
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
            let cert = self
                .repository::<Certificate>()
                .find_one(doc!(f!(key in Certificate): hash), None)
                .await?
                .ok_or_else(|| MongoStorageError::Other {
                    description: "cert not found".to_owned(),
                })?;

            match cert.value {
                Bson::Binary(Binary {
                    subtype: BinarySubtype::Generic,
                    bytes: bin,
                }) => Ok(bin),
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
                .repository::<Key>()
                .find_one(doc!(f!(key in Key): hash), None)
                .await?
                .ok_or_else(|| MongoStorageError::Other {
                    description: "key not found".to_owned(),
                })?;

            match key.value {
                Bson::Binary(Binary {
                    subtype: BinarySubtype::Generic,
                    bytes: bin,
                }) => Ok(bin),
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
            let addressing_hash = self
                .repository::<KeyIdentifier>()
                .find_one(doc!(f!(key in KeyIdentifier): key_identifier), None)
                .await?
                .ok_or_else(|| MongoStorageError::Other {
                    description: format!("addressing hash not found by key identifier \"{}\"", key_identifier),
                })?
                .value;
            Ok(addressing_hash)
        }
        .boxed()
    }

    fn lookup_addressing_hash<'a>(&'a self, lookup_key: &'a str) -> BoxFuture<'a, Result<String, StorageError>> {
        async move {
            let addressing_hash = self
                .repository::<HashLookupEntry>()
                .find_one(doc!(f!(key in HashLookupEntry): lookup_key), None)
                .await?
                .ok_or_else(|| MongoStorageError::Other {
                    description: format!("addressing hash not found using lookup key \"{}\"", lookup_key),
                })?
                .value;
            Ok(addressing_hash)
        }
        .boxed()
    }
}
