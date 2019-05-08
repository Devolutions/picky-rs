use crate::configuration::{BackendType, ServerConfig};
use crate::db::mongodb::mongo_repos::MongoRepos;
use crate::db::mongodb::mongo_connection::MongoConnection;
use crate::db::memory::memory_repos::MemoryRepos;
use crate::db::file::file_repos::FileRepos;

pub const DEFAULT_FILEBASE_PATH: &str = "../filebase/";

pub struct Backend {
    pub db: Box<BackendStorage>
}

impl Backend {
    pub fn new(db: Box<BackendStorage>) -> Result<Self, String> {
        let mut backend = Backend{
            db
        };

        if let Err(e) = backend.db.init(){
            return Err(e);
        }

        Ok(backend)
    }

    pub fn store(&mut self, name: &str, cert: &str, key: &str, key_identifier: &str) -> Result<bool, String>{
        self.db.store(name, cert, key, key_identifier)
    }

    pub fn get_cert(&self, hash: &str) -> Result<String, String>{
        self.db.get_cert(hash)
    }

    pub fn get_key(&self, hash: &str) -> Result<String, String>{
        self.db.get_key(hash)
    }

    pub fn find(&self, name: &str) -> Result<Vec<Model<String>>, String>{
        self.db.find(name)
    }

    pub fn init(&mut self) -> Result<(), String>{
        self.db.init()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Model<T> {
    pub key: String,
    pub value: T
}

pub trait BackendStorage: Send + Sync{
    fn init(&mut self) -> Result<(), String>;
    fn store(&mut self, name: &str, cert: &str, key: &str, key_identifier: &str) -> Result<bool, String>;
    fn find(&self, name: &str) -> Result<Vec<Model<String>>, String>;
    fn get_cert(&self, hash: &str) -> Result<String, String>;
    fn get_key(&self, hash: &str) -> Result<String, String>;
    fn get_key_identifier_from_hash(&self, hash: &str) -> Result<String, String>;
    fn get_hash_from_key_identifier(&self, hash: &str) -> Result<String, String>;
    fn clone_box(&self) -> Box<BackendStorage>;
}

impl Clone for Box<BackendStorage>{
    fn clone(&self) -> Self{
        self.clone_box()
    }
}

impl From<&ServerConfig> for Backend{
    fn from(config: &ServerConfig) -> Self{
        match config.backend {
            BackendType::MongoDb => {
                        let conn= MongoConnection::new(&config.database.url).expect("Invalid server url");
                        let dbstorage = Box::new(MongoRepos::new(conn));
                        return Backend::new(dbstorage).expect("Wrong server configuration");
                },
            BackendType::Memory => {
                return Backend::new(Box::new(MemoryRepos::new())).expect("Bad configuration");
            },
            BackendType::File => {
                return Backend::new(Box::new(FileRepos::new(DEFAULT_FILEBASE_PATH))).expect("Error creating backend for file base");
            },
            _ => panic!("not yet implemented")
        }
    }
}

pub trait Repo<T>{
    type Instance;
    type RepoError;
    type RepoCollection;

    fn init(&mut self, db_instance: Self::Instance, name: &str) -> Result<(), String>;
    fn get_collection(&self) -> Result<Self::RepoCollection, String>;
    fn insert(&mut self, key: &str, value: &T) -> Result<(), String>;
}

#[cfg(test)]
mod tests{
    use super::*;
    use crate::Server;
    use std::env;

    #[test]
    fn server_with_memory_backend_test(){
        env::set_var("PICKY_BACKEND", "memory");
        let conf = ServerConfig::new();

        Server::run(conf);
    }
}