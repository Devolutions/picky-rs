use std::collections::HashMap;
use std::fmt::Error;
use crate::db::backend::Repo;

#[derive(Clone)]
pub struct MemoryRepo{
    pub repo: HashMap<String, String>
}

impl Repo for MemoryRepo{
    type Instance = Option<String>;
    type RepoError = Error;
    type RepoCollection = HashMap<String, String>;

    fn init(&mut self, db_instance: Option<String>, name: &str) -> Result<(), String>{
        Ok(())
    }

    fn get_collection(&self) -> Result<Self::RepoCollection, String>{
        Ok(self.repo.clone())
    }

    fn store(&mut self, key: &str, value: &str) -> Result<(), String>{
        if let Some(e) = self.repo.insert(key.to_string(), value.to_string()){
            info!("Key was updated because it was already stored");
        }

        Ok(())
    }
}