use bson::Bson;
use bson::Document;
use bson::{to_bson, from_bson};
use serde::{Deserialize, Serialize};

use crate::utils;
use crate::controllers::db_controller::{DbStorage, Repo, Storage};
use crate::db::mongodb::mongo_connection::MongoConnection;
use crate::db::mongodb::mongo_repo::MongoRepo;
use crate::utils::pem_to_der;

const REPO_CERTIFICATE: &str = "Certificate Store";
const REPO_KEY: &str = "Key Store";
const REPO_CERTNAME: &str = "Name_Store";
const REPO_CERTKEY: &str = "Linked Store";

#[allow(dead_code)]
#[derive(Debug)]
pub enum RepositoryError {
    BsonEncodeError(bson::EncoderError),
    BsonDecodeError(bson::DecoderError),
    MongoError(mongodb::Error),
    UninitializedRepoError,
    InsertError,
    UpdateError,
    Other(String),
}

impl From<String> for RepositoryError {
    fn from(e: String) -> Self {
        RepositoryError::Other(e)
    }
}

impl From<bson::EncoderError> for RepositoryError {
    fn from(e: bson::EncoderError) -> Self {
        RepositoryError::BsonEncodeError(e)
    }
}

impl From<bson::DecoderError> for RepositoryError {
    fn from(e: bson::DecoderError) -> Self {
        RepositoryError::BsonDecodeError(e)
    }
}

impl From<mongodb::Error> for RepositoryError {
    fn from(e: mongodb::Error) -> Self {
        RepositoryError::MongoError(e)
    }
}

#[derive(Clone)]
pub struct MongoRepos{
    db_instance: MongoConnection,
    pub name: MongoRepo,
    pub certificates: MongoRepo,
    pub keys: MongoRepo,
    pub linked: MongoRepo
}

impl MongoRepos{
    pub fn new(db: MongoConnection) -> Self{
        MongoRepos{
            db_instance: db,
            name: Default::default(),
            certificates: Default::default(),
            keys: Default::default(),
            linked: Default::default()
        }
    }

    pub fn load_repositories(&mut self) -> Result<(), RepositoryError> {
        self.name.init(self.db_instance.clone(), REPO_CERTNAME)?;
        self.certificates.init(self.db_instance.clone(), REPO_CERTIFICATE)?;
        self.keys.init(self.db_instance.clone(), REPO_KEY)?;
        self.linked.init(self.db_instance.clone(), REPO_CERTKEY)?;
        Ok(())
    }

    pub fn get_parent(&self, child: &str) -> Result<(String, String), String>{
        let mut chain = String::default();

        if let Ok(doc_cursor) = self.linked.get_collection()?.find(Some(doc!{"key": child}), None){
            for doc_res in doc_cursor{
                if let Ok(model_document) = doc_res {
                    if let Ok(model) = from_bson(Bson::Document(model_document)) {
                        let model: Storage = model;
                        if let Ok(Some(parent))=self.get(&model.value){
                            return Ok((model.value, parent.0));
                        }
                    }
                }
            }
        }

        Err("No parent found".to_string())
    }
}

impl DbStorage for MongoRepos{
    fn init(&mut self) -> Result<(), String>{
        if let Err(e) = self.load_repositories(){
            return Err(format!("{:?}", e));
        }
        Ok(())
    }

    fn store(&self, name: &str, cert: &str, key: &str) -> Result<bool, String>{
        let test = 1;
        if let Ok(der_cert) = utils::pem_to_der(cert){
            if let Ok(der_cert_hash) = utils::multihash_encode(der_cert.as_slice()){
                if let Ok(der_key) = utils::pem_to_der(key){
                    self.name.store(name, &der_cert_hash);
                    self.certificates.store(&der_cert_hash, &utils::der_to_string(der_cert.as_slice()));
                    self.keys.store(&der_cert_hash, &utils::der_to_string(der_key.as_slice()));
                }
                return Ok(true);
            }
            return Err("Can\'t encode certificate".to_string());
        }
        Err("Invalid certificate".to_string())
    }

    fn get(&self, key: &str) -> Result<Option<(String, String)>, String>{
        let key = key.to_string();
        let cert_doc = doc!{"key": key.clone()};
        let key_doc = doc!{"key": key.clone()};

        let cert_opt: Option<Document> = match self.certificates.get_collection()?.find_one(Some(cert_doc), None){
            Ok(cert) => cert,
            Err(e) => return Err(e.to_string())
        };

        let key_opt: Option<Document> = match self.keys.get_collection()?.find_one(Some(key_doc), None){
            Ok(key) => key,
            Err(e) => return Err(e.to_string())
        };

        if let Some(cert_doc) = cert_opt{
            if let Some(key_doc) = key_opt{
                let cert_model: Storage = match from_bson(Bson::Document(cert_doc)) {
                    Ok(c) => c,
                    Err(e) => return Err(e.to_string())
                };

                let key_model: Storage = match from_bson(Bson::Document(key_doc)) {
                    Ok(k) => k,
                    Err(e) => return Err(e.to_string())
                };

                return Ok(Some((utils::der_to_pem(cert_model.value.as_bytes()), utils::der_to_pem(key_model.value.as_bytes()))));
            }
            Err("No key found for certificate".to_string())
        } else {
            Ok(None)
        }
    }

    fn find(&self, name: &str) -> Result<Vec<Storage>, String>{
        let doc = doc!{"key": name};
        let mut model_vec = Vec::new();
        let document_cursor = match self.name.get_collection()?.find(Some(doc), None){
            Ok(d) => d,
            Err(e) => return Err(e.to_string())
        };

        for doc_res in document_cursor{
            if let Ok(model_document) = doc_res {
                if let Ok(model) = from_bson(Bson::Document(model_document)) {
                    model_vec.push(model);
                }
            }
        }
        Ok(model_vec)
    }

    fn link_cert(&self, child: &str, parent: &str) -> Result<bool, String>{
        let child_der = utils::multihash_encode(&utils::pem_to_der(child)?)?;
        let parent_der = utils::multihash_encode(&utils::pem_to_der(parent)?)?;
        if let Ok(_) = self.linked.store(&child_der, &parent_der){
            return Ok(true);
        }

        Err("Couldn\'t linked certificate in database".to_string())
    }
}