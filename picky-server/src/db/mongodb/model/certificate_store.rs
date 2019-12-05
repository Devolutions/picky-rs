use crate::db::mongodb::{
    model::{Repository, RepositoryError},
    mongo_connection::MongoConnection,
};
use bson::{oid::ObjectId, Bson};
use mongodb::{coll::Collection, db::ThreadedDatabase};

const COLLECTION_NAME: &str = "certificate_store";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CertificateStore {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub key: String,
    pub value: Bson,
}

impl CertificateStore {
    pub fn new(key: &str, value: Bson) -> Self {
        CertificateStore {
            id: ObjectId::new().expect("Should never happen"),
            key: key.into(),
            value,
        }
    }
}

#[derive(Clone, Default)]
pub struct CertificateStoreRepository {
    db_instance: Option<MongoConnection>,
}

impl Repository for CertificateStoreRepository {
    type Model = CertificateStore;

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
