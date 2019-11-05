use crate::configuration::{BackendType, ServerConfig};
use crate::db::memory::memory_repos::MemoryRepos;
use crate::db::file::file_repos::FileRepos;
use crate::db::mongodb::mongo_connection::MongoConnection;
use crate::db::mongodb::model::RepositoryCollection;

pub const DEFAULT_FILEBASE_PATH: &str = "../filebase/";

pub struct Backend {
    pub db: Box<dyn BackendStorage>
}

impl Backend {
    pub fn new(db: Box<dyn BackendStorage>) -> Result<Self, String> {
        let mut backend = Backend{
            db
        };

        if let Err(e) = backend.db.init(){
            return Err(e);
        }

        Ok(backend)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Model<T> {
    pub key: String,
    pub value: T
}

pub trait BackendStorage: Send + Sync{
    fn init(&mut self) -> Result<(), String>;
    fn store(&self, name: &str, cert: &[u8], key: Option<&[u8]>, key_identifier: &str) -> Result<bool, String>;
    fn find(&self, name: &str) -> Result<Vec<Model<String>>, String>;
    fn get_cert(&self, hash: &str) -> Result<Vec<u8>, String>;
    fn get_key(&self, hash: &str) -> Result<Vec<u8>, String>;
    fn get_key_identifier_from_hash(&self, hash: &str) -> Result<String, String>;
    fn get_hash_from_key_identifier(&self, key_identifier: &str) -> Result<String, String>;
    fn health(&self) -> Result<(), String>;
}

impl From<&ServerConfig> for Backend{
    fn from(config: &ServerConfig) -> Self{
        match config.backend {
            BackendType::MongoDb => {
                        let conn= MongoConnection::new(&config.database.url).expect("Invalid server url");
                        let dbstorage = Box::new(RepositoryCollection::new(conn));
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