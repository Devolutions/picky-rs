use crate::db::backend::{Repo, Model};
use crate::db::mongodb::mongo_repos::RepositoryError;
use crate::db::mongodb::mongo_connection::MongoConnection;
use mongodb::coll::Collection;
use mongodb::db::ThreadedDatabase;
use bson::Bson;
use bson::to_bson;
use serde::Serialize;
use std::marker::PhantomData;

pub struct MongoRepo<T>{
    db_instance: Option<MongoConnection>,
    repo_name: String,
    pd: PhantomData<T>
}

impl <T>Clone for MongoRepo<T>{
    fn clone(&self) -> Self{
        if let Some(ref db) = self.db_instance{
            MongoRepo{
                db_instance: Some(db.clone()),
                repo_name: self.repo_name.clone(),
                pd: PhantomData
            }
        } else {
            MongoRepo{
                db_instance: None,
                repo_name: self.repo_name.clone(),
                pd: PhantomData
            }
        }
    }
}

impl <T>Default for MongoRepo<T>{
    fn default() -> Self{
        MongoRepo{
            db_instance: None,
            repo_name: String::default(),
            pd: PhantomData
        }
    }
}

impl<T> Repo<T> for MongoRepo<T> where T: Clone + Serialize{
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

    fn insert(&mut self, key: &str, value: &T) -> Result<(), String>{
        let model = Model{
            key: key.to_string(),
            value
        };

        let serialized_model = match to_bson(&model){
            Ok(bson) => bson,
            Err(e) => return Err(e.to_string())
        };

        if let Bson::Document(document) = serialized_model {
            if let Ok(cursor) = self.get_collection()?.find(Some(document.clone()), None){
                if cursor.count() > 0{
                    info!("Data already found in database...");
                    return Ok(())
                }
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