/*use crate::controllers::db_controller::{Repo, Storage};
use crate::db::mongodb::mongo_repos::RepositoryError;
use crate::db::mongodb::mongo_connection::MongoConnection;
use mongodb::coll::Collection;
use bson::Bson;
use bson::Document;
use bson::{to_bson, from_bson};
use serde::{Deserialize, Serialize};

pub struct MongoCertificate{
    db_instance: Option<MongoConnection>
}

impl Clone for MongoCertificate{
    fn clone(&self) -> Self{
        if let Some(ref db) = self.db_instance{
            MongoCertificate{
                db_instance: Some(db.clone())
            }
        } else {
            MongoCertificate{
                db_instance: None
            }
        }
    }
}

impl Default for MongoCertificate{
    fn default() -> Self{
        MongoCertificate{
            db_instance: None
        }
    }
}

impl Repo for MongoCertificate{
    type Instance = MongoConnection;
    type RepoError = RepositoryError;
    type RepoCollection = Collection;

    fn init(&mut self, db_instance: Instance) -> Result<(), RepoError>{
        self.db_instance = Some(db_instance);
        Ok(())
    }

    fn get_collection(&self, collection: &str) -> Result<RepoCollection, RepoErro>{
        if let Some(ref db) = self.db_instance{
            Ok(db.get()?.collection(collection))
        } else {
            Err(RepositoryError::UninitializedRepoError)
        }
    }

    fn store(&self, key: &str, value: &str) -> Result<(), RepoError>{
        let model = Storage{
            key: key.to_string(),
            value: value.to_string()
        };

        let serialized_model = to_bson(&model)?;

        if let Bson::Document(document) = serialized_model {
            self.get_collection()?.insert_one(document, None)?;
            Ok(())
        } else {
            Err(RepositoryError::InsertError)
        }
    }
}*/