use log::LevelFilter;
use mbedtls::hash::Type as HashType;
use mbedtls::pk::Type as KeyType;
use std::env;
use clap::App;
use crate::db::backend::Backend;
use std::error::Error;

const DEFAULT_PICKY_REALM: &'static str = "Picky";

const PICKY_REALM_ENV: &'static str = "PICKY_REALM";
const PICKY_DATABASE_URL_ENV: &'static str = "PICKY_DATABASE_URL";
const PICKY_API_KEY_ENV: &'static str = "PICKY_API_KEY";
const PICKY_BACKEND_ENV: &'static str = "PICKY_BACKEND";
const PICKY_ROOT_CERT_ENV: &'static str = "PICKY_ROOT_CERT";
const PICKY_ROOT_KEY_ENV: &'static str = "PICKY_ROOT_KEY";
const PICKY_INTERMEDIATE_CERT_ENV: &'static str = "PICKY_INTERMEDIATE_CERT";
const PICKY_INTERMEDIATE_KEY_ENV: &'static str = "PICKY_INTERMEDIATE_KEY";

#[derive(PartialEq, Clone)]
pub enum BackendType{
    MySQL,
    SQLite,
    MongoDb,
    Memory,
    File
}

impl From<&str> for BackendType{
    fn from(backend: &str) -> Self{
        match backend{
            "mysql" => BackendType::MySQL,
            "sqlite" => BackendType::SQLite,
            "mongodb" => BackendType::MongoDb,
            "memory" => BackendType::Memory,
            "file" => BackendType::File,
            _ => BackendType::default()
        }
    }
}

impl Default for BackendType{
    fn default() -> Self{
        BackendType::MongoDb
    }
}

#[derive(Clone)]
pub struct ServerConfig{
    pub log_level: String,
    pub api_key: String,
    pub database: Database,
    pub realm: String,
    pub key_config: KeyConfig,
    pub backend: BackendType,
    pub root_cert: String,
    pub root_key: String,
    pub intermediate_cert: String,
    pub intermediate_key: String
}

impl ServerConfig{
    pub fn new() -> Self{
        let mut config = ServerConfig::default();
        config.load_cli();
        config.load_env();
        config
    }

    pub fn level_filter(&self) -> LevelFilter {
        match self.log_level.to_lowercase().as_str() {
            "off" => LevelFilter::Off,
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => LevelFilter::Off,
        }
    }

    fn load_cli(&mut self) {
        let yaml = load_yaml!("cli.yml");
        let app = App::from_yaml(yaml);
        let matches = app.get_matches();

        match matches.value_of("log-level"){
            Some(v) => self.log_level = v.to_string(),
            None => ()
        }

        match matches.value_of("realm"){
            Some(v) => self.realm = v.to_string(),
            None => ()
        }

        match matches.value_of("db-url"){
            Some(v) => self.database.url = v.to_string(),
            None => ()
        }

        match matches.value_of("api-key"){
            Some(v) => self.api_key = v.to_string(),
            None => ()
        }

        match matches.value_of("backend"){
            Some(v) => {
                self.backend = BackendType::from(v);
            },
            None => ()
        }
    }

    fn load_env(&mut self) {
        if let Ok(val) = env::var(PICKY_REALM_ENV){
            self.realm = val;
        }

        if let Ok(val) = env::var(PICKY_API_KEY_ENV){
            self.api_key = val;
        }

        if let Ok(val) = env::var(PICKY_DATABASE_URL_ENV){
            self.database.url = val;
        }

        if let Ok(val) = env::var(PICKY_BACKEND_ENV){
            self.backend = BackendType::from(val.as_str());
        }

        if let Ok(val) = env::var(PICKY_ROOT_CERT_ENV){
            self.root_cert = val;
        }

        if let Ok(val) = env::var(PICKY_ROOT_KEY_ENV){
            self.root_key = val;
        }

        if let Ok(val) = env::var(PICKY_INTERMEDIATE_CERT_ENV){
            self.intermediate_cert = val;
        }

        if let Ok(val) = env::var(PICKY_INTERMEDIATE_KEY_ENV){
            self.intermediate_key = val;
        }
    }
}

impl Default for ServerConfig{
    fn default() -> Self {
        ServerConfig{
            log_level: "info".to_string(),
            api_key: String::default(),
            database: Database::default(),
            realm: DEFAULT_PICKY_REALM.to_string(),
            key_config: KeyConfig::default(),
            backend: BackendType::default(),
            root_cert: String::default(),
            root_key: String::default(),
            intermediate_cert: String::default(),
            intermediate_key: String::default()
        }
    }
}

#[derive(Clone)]
pub struct Database {
    pub url: String,
}

impl Default for Database {
    fn default() -> Self {
        Database {
            url: "mongodb://127.0.0.1:27017".to_string()
        }
    }
}

#[derive(Clone)]
pub struct KeyConfig{
    pub hash_type: HashType,
    pub key_type: KeyType
}

impl Default for KeyConfig{
    fn default() -> Self {
        KeyConfig{
            hash_type: mbedtls::hash::Type::Sha256,
            key_type: mbedtls::pk::Type::Rsa
        }
    }
}

#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn get_root_n_intermediate(){
        let mut conf = ServerConfig::new();
        conf.load_cli();
        conf.load_env();
    }
}