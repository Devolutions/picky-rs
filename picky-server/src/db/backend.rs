use crate::{
    configuration::{BackendType, ServerConfig},
    db::{
        file::file_repos::FileRepos,
        memory::memory_repos::MemoryRepos,
        mongodb::{model::RepositoryCollection, mongo_connection::MongoConnection},
    },
};
use serde::{Deserialize, Serialize};

pub const DEFAULT_FILEBASE_PATH: &str = "database/";

pub struct Backend {
    pub db: Box<dyn BackendStorage>,
}

impl Backend {
    pub fn new<T: BackendStorage + 'static>(db: T) -> Result<Self, String> {
        let mut backend = Backend { db: Box::new(db) };
        backend.db.init()?;
        Ok(backend)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Model<T> {
    pub key: String,
    pub value: T,
}

pub trait BackendStorage: Send + Sync {
    fn init(&mut self) -> Result<(), String>;
    fn store(
        &self,
        name: &str,
        cert: &[u8],
        key: Option<&[u8]>,
        key_identifier: &str,
    ) -> Result<bool, String>;
    fn find(&self, name: &str) -> Result<Vec<Model<String>>, String>;
    fn get_cert(&self, hash: &str) -> Result<Vec<u8>, String>;
    fn get_key(&self, hash: &str) -> Result<Vec<u8>, String>;
    fn get_key_identifier_from_hash(&self, hash: &str) -> Result<String, String>;
    fn get_hash_from_key_identifier(&self, key_identifier: &str) -> Result<String, String>;
    fn health(&self) -> Result<(), String>;
}

impl From<&ServerConfig> for Backend {
    fn from(config: &ServerConfig) -> Self {
        match config.backend {
            BackendType::MongoDb => {
                let conn = MongoConnection::new(&config.database.url).expect("Invalid server url");
                Backend::new(RepositoryCollection::new(conn)).expect("Wrong server configuration")
            }
            BackendType::Memory => Backend::new(MemoryRepos::new()).expect("Bad configuration"),
            BackendType::File => {
                let save_file_path = if config.save_file_path.eq("") {
                    DEFAULT_FILEBASE_PATH.to_owned()
                } else {
                    format!("{}{}", &config.save_file_path, DEFAULT_FILEBASE_PATH)
                };

                Backend::new(FileRepos::new(save_file_path.as_str()))
                    .expect("Error creating backend for file base")
            }
            _ => panic!("not yet implemented"),
        }
    }
}

pub trait Repo<T> {
    type Instance;
    type RepoError;
    type RepoCollection;

    fn init(&mut self, db_instance: Self::Instance, name: &str) -> Result<(), String>;
    fn get_collection(&self) -> Result<Self::RepoCollection, String>;
    fn insert(&mut self, key: &str, value: &T) -> Result<(), String>;
}
