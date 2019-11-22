use mongodb::db::ThreadedDatabase;
use mongodb::coll::Collection;
use bson::oid::ObjectId;
use crate::db::mongodb::model::{Repository, RepositoryError};
use crate::db::mongodb::mongo_connection::MongoConnection;
use crate::db::backend::Model;

const COLLECTION_NAME: &str = "name_store";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NameStore {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub key: String,
    pub value: String,
}

impl NameStore {
    pub fn new(key: &str, value: &str) -> Self {
        NameStore {
            id: ObjectId::new().expect("Should never happen"),
            key: key.to_string(),
            value: value.to_string(),
        }
    }
}

impl From<NameStore> for Model<String> {
    fn from(item: NameStore) -> Self {
        Model {
            key: item.key,
            value: item.value,
        }
    }
}

#[derive(Clone, Default)]
pub struct NameStoreRepository {
    db_instance: Option<MongoConnection>,
}

impl Repository for NameStoreRepository {
    type Model = NameStore;

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
