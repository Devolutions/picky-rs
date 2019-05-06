use std::collections::HashMap;
use std::fmt::Error;
use crate::db::backend::Repo;
use std::hash::Hash;

#[derive(Clone)]
pub struct MemoryRepo<T>{
    pub repo: HashMap<String, T>
}

impl<T> Repo<T> for MemoryRepo<T> where T: Eq + Clone + Hash{
    type Instance = Option<String>;
    type RepoError = Error;
    type RepoCollection = HashMap<String, T>;

    fn init(&mut self, db_instance: Option<String>, name: &str) -> Result<(), String>{
        Ok(())
    }

    fn get_collection(&self) -> Result<Self::RepoCollection, String>{
        Ok(self.repo.clone())
    }

    fn insert(&mut self, key: &str, value: &T) -> Result<(), String>{
        if let Some(e) = self.repo.insert(key.to_string(), value.clone()){
            info!("Key was updated because it was already stored");
        }

        Ok(())
    }
}