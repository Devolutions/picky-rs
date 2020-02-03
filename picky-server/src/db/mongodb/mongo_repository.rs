use crate::db::mongodb::{mongo_connection::MongoConnection, MongoStorageError};
use bson::{from_bson, oid::ObjectId, to_bson, Bson, Document};
use mongodb::{coll::options::ReplaceOptions, db::ThreadedDatabase};
use serde::{Deserialize, Serialize};

pub type NameModel = Model<String>;
pub type NameStoreRepository = MongoRepository<NameModel>;
pub const NAME_STORE_COLLECTION_NAME: &str = "name_store";

pub type KeyModel = Model<Bson>;
pub type KeyStoreRepository = MongoRepository<KeyModel>;
pub const KEY_STORE_COLLECTION_NAME: &str = "key_store";

pub type KeyIdentifierModel = Model<String>;
pub type KeyIdentifierStoreRepository = MongoRepository<KeyIdentifierModel>;
pub const KEY_IDENTIFIER_COLLECTION_NAME: &str = "key_identifier_store";

pub type CertificateModel = Model<Bson>;
pub type CertificateStoreRepository = MongoRepository<CertificateModel>;
pub const CERTIFICATE_COLLECTION_NAME: &str = "certificate_store";

pub type ConfigModel = Model<Bson>;
pub type ConfigStoreRepository = MongoRepository<ConfigModel>;
pub const CONFIG_COLLECTION_NAME: &str = "configuration";

pub type HashLookupTableModel = Model<String>;
pub type HashLookupTableStoreRepository = MongoRepository<HashLookupTableModel>;
pub const HASH_LOOKUP_TABLE_COLLECTION_NAME: &str = "hash_lookup_table";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Model<T> {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub key: String,
    pub value: T,
}

impl<T> Model<T> {
    pub fn new(key: String, value: T) -> Self {
        Self {
            id: ObjectId::new().expect("should never happen"),
            key,
            value,
        }
    }
}

pub struct MongoRepository<Model> {
    mongo_conn: MongoConnection,
    collection_name: &'static str,
    _pd: std::marker::PhantomData<Model>,
}

impl<Model> MongoRepository<Model> {
    pub fn new(mongo_conn: MongoConnection, collection_name: &'static str) -> Self {
        MongoRepository {
            mongo_conn,
            collection_name,
            _pd: std::marker::PhantomData,
        }
    }
}

impl<Model: serde::ser::Serialize> MongoRepository<Model> {
    pub async fn get_collection(&self) -> Result<mongodb::coll::Collection, MongoStorageError> {
        let shallow_clone = self.mongo_conn.clone();
        let connection = tokio::task::spawn_blocking(move || shallow_clone.get())
            .await
            .map_err(|e| MongoStorageError::Other {
                description: format!("couldn't join replace_one mongo task: {}", e),
            })??;

        Ok(connection.collection(self.collection_name))
    }

    pub async fn update_with_options(
        &self,
        doc: Document,
        model: Model,
        upsert: bool,
    ) -> Result<(), MongoStorageError> {
        let serialized_model = to_bson(&model)?;

        if let Bson::Document(mut document) = serialized_model {
            // if there is an id field removes it. Replace one does
            // not work on data targeting the id field index
            document.remove("_id");

            let col = self.get_collection().await?;
            tokio::task::spawn_blocking(move || {
                col.replace_one(
                    doc,
                    document,
                    Some(ReplaceOptions {
                        upsert: Some(upsert),
                        ..ReplaceOptions::new()
                    }),
                )
            })
            .await
            .map_err(|e| MongoStorageError::Other {
                description: format!("couldn't join replace_one mongo task: {}", e),
            })??;

            Ok(())
        } else {
            Err(MongoStorageError::UpdateError)
        }
    }
}

impl<Model: serde::de::DeserializeOwned + serde::ser::Serialize> MongoRepository<Model> {
    pub async fn get(&self, doc: Document) -> Result<Option<Model>, MongoStorageError> {
        let col = self.get_collection().await?;

        let document_opt = tokio::task::spawn_blocking(move || col.find_one(Some(doc), None))
            .await
            .map_err(|e| MongoStorageError::Other {
                description: format!("couldn't join find_one mongo task: {}", e),
            })??;

        if let Some(doc) = document_opt {
            let model = from_bson(Bson::Document(doc))?;
            Ok(Some(model))
        } else {
            Ok(None)
        }
    }
}
