use bson::Bson;
use bson::from_bson;

use crate::utils;
use crate::db::backend::{BackendStorage, Repo, Model};
use crate::db::mongodb::mongo_connection::MongoConnection;
use crate::db::mongodb::mongo_repo::MongoRepo;
use bson::spec::BinarySubtype;
use bson::spec::ElementType::Binary;
use crate::utils::pem_to_der;

const REPO_CERTIFICATE: &str = "Certificate Store";
const REPO_KEY: &str = "Key Store";
const REPO_CERTNAME: &str = "Name Store";
const REPO_CERTKEY: &str = "Key Identifier Store";

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
    pub name: MongoRepo<String>,
    pub certificates: MongoRepo<Bson>,
    pub keys: MongoRepo<Bson>,
    pub key_identifiers: MongoRepo<String>
}

impl MongoRepos{
    pub fn new(db: MongoConnection) -> Self{
        MongoRepos{
            db_instance: db,
            name: Default::default(),
            certificates: Default::default(),
            keys: Default::default(),
            key_identifiers: Default::default()
        }
    }

    pub fn load_repositories(&mut self) -> Result<(), RepositoryError> {
        self.name.init(self.db_instance.clone(), REPO_CERTNAME)?;
        self.certificates.init(self.db_instance.clone(), REPO_CERTIFICATE)?;
        self.keys.init(self.db_instance.clone(), REPO_KEY)?;
        self.key_identifiers.init(self.db_instance.clone(), REPO_CERTKEY)?;
        Ok(())
    }
}

impl BackendStorage for MongoRepos{
    fn init(&mut self) -> Result<(), String>{
        if let Err(e) = self.load_repositories(){
            return Err(format!("{:?}", e));
        }

        Ok(())
    }

    fn store(&mut self, name: &str, cert: &[u8], key: Option<&[u8]>, key_identifier: &str) -> Result<bool, String>{
        if let Ok(cert_hash) = utils::multihash_encode(cert){
            self.name.insert(name, &cert_hash.clone())?;
            self.certificates.insert(&cert_hash.clone(), &Bson::Binary(BinarySubtype::Generic, cert.to_vec()))?;

            if let Some(key) = key{
                self.keys.insert(&cert_hash.clone(), &Bson::Binary(BinarySubtype::Generic, key.to_vec()))?;
            }
            self.key_identifiers.insert(key_identifier, &cert_hash)?;
            return Ok(true);
        }

        Err("Can\'t encode certificate".to_string())
    }

    fn find(&self, name: &str) -> Result<Vec<Model<String>>, String>{
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

    fn get_cert(&self, hash: &str) -> Result<Vec<u8>, String>{
        let doc = doc!{"key": hash};
        let mut model_vec: Vec<Model<Vec<u8>>> = Vec::new();
        let document_cursor = match self.certificates.get_collection()?.find(Some(doc), None){
            Ok(d) => d,
            Err(e) => return Err(e.to_string())
        };

        for doc_res in document_cursor{
            if let Ok(model_document) = doc_res {
                if let Some(&Bson::Binary(BinarySubtype::Generic, ref bin)) = model_document.get("value"){
                    let model = Model{key: hash.to_string(), value: bin.clone().to_owned()};
                    model_vec.push(model);
                }
            }
        }

        if model_vec.len() > 0 {
            return Ok(model_vec[0].value.clone());
        }

        Err("Error finding cert".to_string())
    }

    fn get_key(&self, hash: &str) -> Result<Vec<u8>, String>{
        let doc = doc!{"key": hash};
        let mut model_vec: Vec<Model<Vec<u8>>> = Vec::new();
        let document_cursor = match self.keys.get_collection()?.find(Some(doc), None){
            Ok(d) => d,
            Err(e) => return Err(e.to_string())
        };

        for doc_res in document_cursor{
            if let Ok(model_document) = doc_res {
                if let Some(&Bson::Binary(BinarySubtype::Generic, ref bin)) = model_document.get("value"){
                    let model = Model{key: hash.to_string(), value: bin.clone().to_owned()};
                    model_vec.push(model);
                }
            }
        }

        if model_vec.len() > 0 {
            return Ok(model_vec[0].value.clone());
        }

        Err("Error finding key".to_string())
    }

    fn get_key_identifier_from_hash(&self, hash: &str) -> Result<String, String>{
        let hash = hash.to_string();
        let storage: Model<String>;
        let doc = doc!{"value": hash};

        let opt = match self.key_identifiers.get_collection()?.find_one(Some(doc), None){
            Ok(hash) => hash,
            Err(e) => return Err(e.to_string())
        };

        if let Some(model_doc) = opt{
            if let Ok(model) = from_bson(Bson::Document(model_doc)){
                storage = model;
                return Ok(storage.key);
            }
        }

        Err("No key identifier found".to_string())
    }

    fn get_hash_from_key_identifier(&self, key_identifier: &str) -> Result<String, String>{
        let key_identifier= key_identifier.to_string();
        let storage: Model<String>;
        let doc = doc!{"key": key_identifier};

        let opt = match self.key_identifiers.get_collection()?.find_one(Some(doc), None){
            Ok(hash) => hash,
            Err(e) => return Err(e.to_string())
        };

        if let Some(model_doc) = opt{
            if let Ok(model) = from_bson(Bson::Document(model_doc)){
                storage = model;
                return Ok(storage.value);
            }
        }

        Err("No hash found".to_string())
    }

    fn clone_box(&self) -> Box<BackendStorage> {
        Box::new(self.clone())
    }
}