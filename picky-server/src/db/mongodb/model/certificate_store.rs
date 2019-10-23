use bson::Bson;
use mongodb::db::ThreadedDatabase;
use mongodb::coll::Collection;
use bson::oid::ObjectId;
use crate::db::mongodb::model::{Repository, RepositoryError};
use crate::db::mongodb::mongo_connection::MongoConnection;

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
        let _ = db_instance.get()?.create_collection(COLLECTION_NAME, None);
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
