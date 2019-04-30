use crate::db::backend::{Repo, Storage};
use crate::db::mongodb::mongo_repos::RepositoryError;
use crate::db::mongodb::mongo_connection::MongoConnection;
use mongodb::coll::Collection;
use mongodb::db::ThreadedDatabase;
use bson::Bson;
use bson::Document;
use bson::{to_bson, from_bson};
use serde::{Deserialize, Serialize};

pub struct MongoRepo{
    db_instance: Option<MongoConnection>,
    repo_name: String
}

impl MongoRepo{
    pub fn new(name: &str) -> Self{
        MongoRepo{
            db_instance: None,
            repo_name: name.to_string()
        }
    }
}

impl Clone for MongoRepo{
    fn clone(&self) -> Self{
        if let Some(ref db) = self.db_instance{
            MongoRepo{
                db_instance: Some(db.clone()),
                repo_name: self.repo_name.clone()
            }
        } else {
            MongoRepo{
                db_instance: None,
                repo_name: self.repo_name.clone()
            }
        }
    }
}

impl Default for MongoRepo{
    fn default() -> Self{
        MongoRepo{
            db_instance: None,
            repo_name: String::default()
        }
    }
}

impl Repo for MongoRepo{
    type Instance = MongoConnection;
    type RepoError = RepositoryError;
    type RepoCollection = Collection;

    fn init(&mut self, db_instance: Self::Instance, name: &str) -> Result<(), String>{
        self.db_instance = Some(db_instance);
        self.repo_name = name.to_string();
        Ok(())
    }

    fn get_collection(&self) -> Result<Self::RepoCollection, String>{
        if let Some(ref db) = self.db_instance{
            Ok(db.get()?.collection(&self.repo_name.clone()))
        } else {
            Err(format!{"{:?}",RepositoryError::UninitializedRepoError})
        }
    }

    fn store(&mut self, key: &str, value: &str) -> Result<(), String>{
        let model = Storage{
            key: key.to_string(),
            value: value.to_string()
        };

        let serialized_model = match to_bson(&model){
            Ok(bson) => bson,
            Err(e) => return Err(e.to_string())
        };

        if let Bson::Document(document) = serialized_model {
            if let Ok(cursor) = self.get_collection()?.find(Some(document.clone()), None){
                info!("Data already found in database...");
                return Ok(())
            }

            if let Err(e) = self.get_collection()?.insert_one(document.clone(), None){
                return Err(e.to_string());
            }
            Ok(())
        } else {
            Err(format!{"{:?}",RepositoryError::InsertError})
        }
    }
}