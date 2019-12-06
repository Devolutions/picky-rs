use crate::db::mongodb::{
    model::{Repository, RepositoryError},
    mongo_connection::MongoConnection,
};
use bson::oid::ObjectId;
use mongodb::{coll::Collection, db::ThreadedDatabase};
use serde::{Deserialize, Serialize};

const COLLECTION_NAME: &str = "key_identifier_store";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyIdentifierStore {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub key: String,
    pub value: String,
}

impl KeyIdentifierStore {
    pub fn new(key: &str, value: &str) -> Self {
        KeyIdentifierStore {
            id: ObjectId::new().expect("Should never happen"),
            key: key.into(),
            value: value.into(),
        }
    }
}

#[derive(Clone, Default)]
pub struct KeyIdentifierStoreRepository {
    db_instance: Option<MongoConnection>,
}

impl Repository for KeyIdentifierStoreRepository {
    type Model = KeyIdentifierStore;

    fn init(&mut self, db_instance: MongoConnection) -> Result<(), RepositoryError> {
        self.db_instance = Some(db_instance);
        Ok(())
    }

    fn get_collection(&self) -> Result<Collection, RepositoryError> {
        if let Some(ref db) = self.db_instance {
            Ok(db.get()?.collection(COLLECTION_NAME))
        } else {
            Err(RepositoryError::UninitializedRepoError)
        }
    }
}
