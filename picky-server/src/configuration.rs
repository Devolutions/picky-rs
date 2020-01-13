use clap::App;
use log::LevelFilter;
use picky::{key::PublicKey, pem::Pem, signature::SignatureHashType};
use std::env;

const DEFAULT_PICKY_REALM: &str = "Picky";

const PICKY_REALM_ENV: &str = "PICKY_REALM";
const PICKY_DATABASE_URL_ENV: &str = "PICKY_DATABASE_URL";
const PICKY_API_KEY_ENV: &str = "PICKY_API_KEY";
const PICKY_BACKEND_ENV: &str = "PICKY_BACKEND";
const PICKY_ROOT_CERT_ENV: &str = "PICKY_ROOT_CERT";
const PICKY_ROOT_KEY_ENV: &str = "PICKY_ROOT_KEY";
const PICKY_INTERMEDIATE_CERT_ENV: &str = "PICKY_INTERMEDIATE_CERT";
const PICKY_INTERMEDIATE_KEY_ENV: &str = "PICKY_INTERMEDIATE_KEY";
const PICKY_SAVE_CERTIFICATE_ENV: &str = "PICKY_SAVE_CERTIFICATE";
const PICKY_BACKEND_FILE_PATH_ENV: &str = "PICKY_BACKEND_FILE_PATH";
const PICKY_DEN_PUBLIC_KEY_FILE_ENV: &str = "PICKY_DEN_PUBLIC_KEY_FILE";
const PICKY_DEN_PUBLIC_KEY_DATA_ENV: &str = "PICKY_DEN_PUBLIC_KEY_DATA";

#[derive(PartialEq, Clone)]
pub enum BackendType {
    MongoDb,
    Memory,
    File,
}

impl Default for BackendType {
    fn default() -> Self {
        BackendType::MongoDb
    }
}

impl From<&str> for BackendType {
    fn from(backend: &str) -> Self {
        match backend {
            "mongodb" => BackendType::MongoDb,
            "memory" => BackendType::Memory,
            "file" => BackendType::File,
            _ => BackendType::default(),
        }
    }
}

#[derive(Clone)]
pub struct ServerConfig {
    pub log_level: String,
    pub api_key: String,
    pub database_url: String,
    pub realm: String,
    pub key_config: SignatureHashType,
    pub backend: BackendType,
    pub root_cert: String,
    pub root_key: String,
    pub intermediate_cert: String,
    pub intermediate_key: String,
    pub save_file_path: String,
    pub save_certificate: bool,
    pub den_public_key: Option<PublicKey>,
}

impl ServerConfig {
    pub fn new() -> Self {
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

        if let Some(v) = matches.value_of("log-level") {
            self.log_level = v.to_owned();
        }

        if let Some(v) = matches.value_of("realm") {
            self.realm = v.to_string();
        }

        if let Some(v) = matches.value_of("db-url") {
            self.database_url = v.to_string();
        }

        if let Some(v) = matches.value_of("api-key") {
            self.api_key = v.to_string();
        }

        if let Some(v) = matches.value_of("backend") {
            self.backend = BackendType::from(v);
        }

        if matches.is_present("save-certificate") {
            self.save_certificate = true;
        }
    }

    fn load_env(&mut self) {
        if let Ok(val) = env::var(PICKY_REALM_ENV) {
            self.realm = val;
        }

        if let Ok(val) = env::var(PICKY_API_KEY_ENV) {
            self.api_key = val;
        }

        if let Ok(val) = env::var(PICKY_DATABASE_URL_ENV) {
            self.database_url = val;
        }

        if let Ok(val) = env::var(PICKY_BACKEND_ENV) {
            self.backend = BackendType::from(val.as_str());
        }

        if let Ok(val) = env::var(PICKY_ROOT_CERT_ENV) {
            self.root_cert = val;
        }

        if let Ok(val) = env::var(PICKY_ROOT_KEY_ENV) {
            self.root_key = val;
        }

        if let Ok(val) = env::var(PICKY_INTERMEDIATE_CERT_ENV) {
            self.intermediate_cert = val;
        }

        if let Ok(val) = env::var(PICKY_INTERMEDIATE_KEY_ENV) {
            self.intermediate_key = val;
        }

        if let Ok(val) = env::var(PICKY_BACKEND_FILE_PATH_ENV) {
            self.save_file_path = val;
        }

        if let Ok(val) = env::var(PICKY_SAVE_CERTIFICATE_ENV) {
            if let Ok(save_certificate) = val.parse::<bool>() {
                self.save_certificate = save_certificate;
            }
        }

        let den_public_key = if let Ok(val) = env::var(PICKY_DEN_PUBLIC_KEY_DATA_ENV) {
            Some(val)
        } else if let Ok(val) = env::var(PICKY_DEN_PUBLIC_KEY_FILE_ENV) {
            Some(std::fs::read_to_string(val).expect("couldn't read den public key file"))
        } else {
            None
        };
        if let Some(den_public_key) = den_public_key {
            let pem = den_public_key
                .parse::<Pem>()
                .expect("couldn't parse den public key pem");
            let public_key = PublicKey::from_pem(&pem).expect("couldn't parse den public key");
            self.den_public_key = Some(public_key);
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            log_level: "info".to_string(),
            api_key: String::default(),
            database_url: "mongodb://127.0.0.1:27017".to_owned(),
            realm: DEFAULT_PICKY_REALM.to_string(),
            key_config: SignatureHashType::RsaSha256,
            backend: BackendType::default(),
            root_cert: String::default(),
            root_key: String::default(),
            intermediate_cert: String::default(),
            intermediate_key: String::default(),
            save_file_path: String::default(),
            save_certificate: false,
            den_public_key: None,
        }
    }
}
