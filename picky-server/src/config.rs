use crate::utils::PathOr;
use clap::App;
use log::LevelFilter;
use picky::{
    hash::HashAlgorithm,
    key::{PrivateKey, PublicKey},
    pem::Pem,
    signature::SignatureAlgorithm,
    x509::Cert,
};
use serde::{Deserialize, Serialize};
use std::{
    env,
    path::{Path, PathBuf},
};

const YAML_CONF_PATH: &str = "picky_server_conf.yaml";

const PICKY_REALM_ENV: &str = "PICKY_REALM";
const PICKY_SAVE_CERTIFICATE_ENV: &str = "PICKY_SAVE_CERTIFICATE";
const PICKY_BACKEND_ENV: &str = "PICKY_BACKEND";
const PICKY_FILE_BACKEND_PATH_ENV: &str = "PICKY_FILE_BACKEND_PATH";
const PICKY_DATABASE_URL_ENV: &str = "PICKY_DATABASE_URL";
const PICKY_DATABASE_NAME_ENV: &str = "PICKY_DATABASE_NAME";

const PICKY_ROOT_CERT_ENV: &str = "PICKY_ROOT_CERT";
const PICKY_ROOT_CERT_PATH_ENV: &str = "PICKY_ROOT_CERT_PATH";
const PICKY_ROOT_KEY_ENV: &str = "PICKY_ROOT_KEY";
const PICKY_ROOT_KEY_PATH_ENV: &str = "PICKY_ROOT_KEY_PATH";

const PICKY_INTERMEDIATE_CERT_ENV: &str = "PICKY_INTERMEDIATE_CERT";
const PICKY_INTERMEDIATE_CERT_PATH_ENV: &str = "PICKY_INTERMEDIATE_CERT_PATH";
const PICKY_INTERMEDIATE_KEY_ENV: &str = "PICKY_INTERMEDIATE_KEY";
const PICKY_INTERMEDIATE_KEY_PATH_ENV: &str = "PICKY_INTERMEDIATE_KEY_PATH";

const PICKY_PROVISIONER_PUBLIC_KEY_ENV: &str = "PICKY_PROVISIONER_PUBLIC_KEY";
const PICKY_PROVISIONER_PUBLIC_KEY_PATH_ENV: &str = "PICKY_PROVISIONER_PUBLIC_KEY_PATH";

fn default_picky_realm() -> String {
    String::from("Picky")
}

fn default_database_url() -> String {
    String::from("mongodb://127.0.0.1:27017")
}

fn default_database_name() -> String {
    String::from("picky")
}

fn default_file_backend_path() -> PathBuf {
    Path::new("database/").to_owned()
}

const fn default_save_certificate() -> bool {
    false
}

const fn default_log_level() -> LevelFilter {
    LevelFilter::Info
}

const fn default_signing_algorithm() -> SignatureAlgorithm {
    SignatureAlgorithm::RsaPkcs1v15(HashAlgorithm::SHA2_256)
}

fn parse_level_filter(s: &str) -> LevelFilter {
    match s.to_lowercase().as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Off,
    }
}

#[derive(PartialEq, Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
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
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "mongodb" => Self::MongoDb,
            "memory" => Self::Memory,
            "file" => Self::File,
            _ => Self::default(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CertKeyPair {
    pub cert: PathOr<Cert>,
    pub key: PathOr<PrivateKey>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Config {
    #[serde(default = "default_picky_realm")]
    pub realm: String,
    #[serde(default = "default_save_certificate")]
    pub save_certificate: bool,
    #[serde(default = "default_log_level")]
    pub log_level: LevelFilter,
    #[serde(default = "default_signing_algorithm")]
    pub signing_algorithm: SignatureAlgorithm,

    #[serde(default)]
    pub backend: BackendType,
    #[serde(default = "default_file_backend_path")]
    pub file_backend_path: PathBuf,
    #[serde(default = "default_database_url")]
    pub database_url: String,
    #[serde(default = "default_database_name")]
    pub database_name: String,

    #[serde(default)]
    pub root: Option<CertKeyPair>,
    #[serde(default)]
    pub intermediate: Option<CertKeyPair>,
    #[serde(default)]
    pub provisioner_public_key: Option<PathOr<PublicKey>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            realm: default_picky_realm(),
            save_certificate: default_save_certificate(),
            log_level: default_log_level(),
            signing_algorithm: default_signing_algorithm(),
            backend: BackendType::default(),
            file_backend_path: default_file_backend_path(),
            database_url: default_database_url(),
            database_name: default_database_name(),
            root: None,
            intermediate: None,
            provisioner_public_key: None,
        }
    }
}

impl Config {
    pub fn startup_init() -> Self {
        let mut config = if let Ok(yaml_conf) = std::fs::read_to_string(YAML_CONF_PATH) {
            serde_yaml::from_str(&yaml_conf).expect("yaml conf")
        } else {
            Config::default()
        };

        config.inject_env();
        config.inject_cli();

        config
    }

    pub fn init_yaml() -> Result<Self, String> {
        let yaml_conf =
            std::fs::read_to_string(YAML_CONF_PATH).map_err(|e| format!("couldn't read yaml config: {}", e))?;
        Ok(serde_yaml::from_str(&yaml_conf).map_err(|e| format!("invalid yaml conf: {}", e))?)
    }

    fn inject_cli(&mut self) {
        let yaml = clap::load_yaml!("cli.yml");
        let app = App::from_yaml(yaml);
        let matches = app.get_matches();

        if let Some(v) = matches.value_of("realm") {
            self.realm = v.to_string();
        }

        if matches.is_present("save-certificate") {
            self.save_certificate = true;
        }

        if let Some(v) = matches.value_of("log-level") {
            self.log_level = parse_level_filter(v);
        }

        if let Some(v) = matches.value_of("backend") {
            self.backend = BackendType::from(v);
        }

        if let Some(v) = matches.value_of("db-url") {
            self.database_url = v.to_string();
        }

        if let Some(v) = matches.value_of("db-name") {
            self.database_name = v.to_string();
        }

        if matches.is_present("dump-config") {
            let yaml_conf = serde_yaml::to_string(&self).expect("conf to yaml");
            if let Err(e) = std::fs::write(YAML_CONF_PATH, yaml_conf) {
                println!("failed to write yaml config: {}", e);
            }
        }

        if matches.is_present("show-config") {
            println!("{:#?}", self);
        }
    }

    fn inject_env(&mut self) {
        if let Ok(val) = env::var(PICKY_REALM_ENV) {
            self.realm = val;
        }

        if let Ok(val) = env::var(PICKY_SAVE_CERTIFICATE_ENV) {
            self.save_certificate = val.parse::<bool>().expect("save certificate env variable");
        }

        if let Ok(val) = env::var(PICKY_BACKEND_ENV) {
            self.backend = BackendType::from(val.as_str());
        }

        self.file_backend_path = env::var(PICKY_FILE_BACKEND_PATH_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_file_backend_path());

        if let Ok(val) = env::var(PICKY_DATABASE_URL_ENV) {
            self.database_url = val;
        }

        if let Ok(val) = env::var(PICKY_DATABASE_NAME_ENV) {
            self.database_name = val;
        }

        if !inject_cert_key_pair(&mut self.root, PICKY_ROOT_CERT_ENV, PICKY_ROOT_KEY_ENV) {
            inject_cert_key_pair_path(&mut self.root, PICKY_ROOT_CERT_PATH_ENV, PICKY_ROOT_KEY_PATH_ENV);
        }

        if !inject_cert_key_pair(
            &mut self.intermediate,
            PICKY_INTERMEDIATE_CERT_ENV,
            PICKY_INTERMEDIATE_KEY_ENV,
        ) {
            inject_cert_key_pair_path(
                &mut self.intermediate,
                PICKY_INTERMEDIATE_CERT_PATH_ENV,
                PICKY_INTERMEDIATE_KEY_PATH_ENV,
            );
        }

        if let Ok(pem_str) = env::var(PICKY_PROVISIONER_PUBLIC_KEY_ENV) {
            let pem = pem_str
                .parse::<Pem>()
                .expect("couldn't parse provisioner public key pem");
            let public_key = PublicKey::from_pem(&pem).expect("couldn't parse provisioner public key");
            self.provisioner_public_key = Some(PathOr::Some(public_key));
        } else if let Ok(val) = env::var(PICKY_PROVISIONER_PUBLIC_KEY_PATH_ENV) {
            self.provisioner_public_key = Some(PathOr::Path(val.into()));
        }
    }
}

fn inject_cert_key_pair(pair: &mut Option<CertKeyPair>, cert_pem_env: &str, key_pem_env: &str) -> bool {
    if let Ok(cert_pem_str) = env::var(cert_pem_env) {
        if let Ok(key_pem_str) = env::var(key_pem_env) {
            *pair = Some(CertKeyPair {
                cert: PathOr::Some({
                    let pem = cert_pem_str.parse::<Pem>().expect("cert pem");
                    Cert::from_pem(&pem).expect("cert")
                }),
                key: PathOr::Some({
                    let pem = key_pem_str.parse::<Pem>().expect("key pem");
                    PrivateKey::from_pem(&pem).expect("key")
                }),
            });

            return true;
        }
    }

    false
}

fn inject_cert_key_pair_path(pair: &mut Option<CertKeyPair>, cert_path_env: &str, key_path_env: &str) -> bool {
    if let Ok(cert_path) = env::var(cert_path_env) {
        if let Ok(key_path) = env::var(key_path_env) {
            *pair = Some(CertKeyPair {
                cert: PathOr::Path(cert_path.into()),
                key: PathOr::Path(key_path.into()),
            });

            return true;
        }
    }

    false
}
