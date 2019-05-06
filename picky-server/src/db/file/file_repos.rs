use crate::db::file::file_repo::FileRepo;
use crate::db::backend::{BackendStorage, Model, Repo};
use crate::utils;
use std::marker::PhantomData;
use std::fs::File;
use std::io::Read;

const REPO_CERTIFICATE: &str = "CertificateStore/";
const REPO_KEY: &str = "KeyStore/";
const REPO_CERTNAME: &str = "NameStore/";
const REPO_KEYIDENTIFIER: &str = "KeyIdentifierStore/";

#[derive(Clone)]
pub struct FileRepos{
    pub path: String,
    pub name: FileRepo<String>,
    pub cert: FileRepo<String>,
    pub keys: FileRepo<String>,
    pub key_identifiers: FileRepo<String>
}

impl FileRepos{
    pub fn new(path: &str) -> Self{
        FileRepos{
            path: path.to_string(),
            name: FileRepo{
                repo: String::default(),
                phantom_data: PhantomData
            },
            cert: FileRepo{
                repo: String::default(),
                phantom_data: PhantomData
            },
            keys: FileRepo{
                repo: String::default(),
                phantom_data: PhantomData
            },
            key_identifiers: FileRepo{
                repo: String::default(),
                phantom_data: PhantomData
            }
        }
    }
}

impl BackendStorage for FileRepos{
    fn init(&mut self) -> Result<(), String> {
        self.name.init(Some(self.path.clone()), REPO_CERTNAME)?;
        self.cert.init(Some(self.path.clone()), REPO_CERTIFICATE)?;
        self.keys.init(Some(self.path.clone()), REPO_KEY)?;
        self.key_identifiers.init(Some(self.path.clone()), REPO_KEYIDENTIFIER)?;
        Ok(())
    }

    fn store(&mut self, name: &str, cert: &str, key: &str, key_identifier: &str) -> Result<bool, String> {
        if let Ok(cert_hash) = utils::multihash_encode(cert){
            self.name.insert(&format!("{}{}", name.replace(" ", "_").to_string(), ".txt"), &cert_hash)?;
            self.cert.insert(&format!("{}{}",cert_hash,".pem"), &cert.to_string())?;
            self.keys.insert(&format!("{}{}",cert_hash, ".pem"), &key.to_string())?;
            self.key_identifiers.insert(&format!("{}{}", key_identifier, ".txt"), &cert_hash)?;
            return Ok(true);
        }
        Err("Could not encode certificate".to_string())
    }

    fn find(&self, name: &str) -> Result<Vec<Model<String>>, String> {
        let mut model_vec = Vec::new();
        let name = format!("{}{}", name, ".txt").replace(" ", "_");
        if let Ok(model) = self.name.get_collection(){
            for n in model{
                if name.eq(&n){
                    let test = format!("{}{}",self.name.repo, &n);
                    if let Ok(mut file) = File::open(format!("{}{}",self.name.repo, n)){
                        let mut buf = String::default();
                        let res = file.read_to_string(&mut buf).expect("Error reading file");
                        model_vec.push(Model{
                            key: name.to_string(),
                            value: buf
                        })
                    }
                }
            }

            return Ok(model_vec);
        }

        Err("Not found".to_string())
    }

    fn get_cert(&self, hash: &str) -> Result<String, String> {
        let mut cert= String::default();
        let hash = format!("{}{}", hash, ".pem");
        if let Ok(certs) = self.cert.get_collection(){
            for c in certs{
                if hash.eq(&c){
                    if let Ok(mut file) = File::open(format!("{}{}", self.cert.repo, c)){
                        let mut buf = String::default();
                        let res = file.read_to_string(&mut buf).expect("Error reading file");
                        cert = buf;
                    }
                }
            }

            if !cert.is_empty(){
                return Ok(cert);
            }
        }

        Err("Cert not found".to_string())
    }

    fn get_key(&self, hash: &str) -> Result<String, String> {
        let mut key = String::default();
        let hash = format!("{}{}", hash, ".pem");
        if let Ok(keys) = self.keys.get_collection(){
            for k in keys{
                if hash.eq(&k) {
                    if let Ok(mut file) = File::open(format!("{}{}", self.keys.repo, k)){
                        let mut buf = String::default();
                        let res = file.read_to_string(&mut buf).expect("Error reading file");
                        key = buf;
                    }
                }
            }
        }

        if !key.is_empty(){
            return Ok(key);
        }

        Err("Key not found".to_string())
    }

    fn get_key_identifier_from_hash(&self, hash: &str) -> Result<String, String> {
        unimplemented!()
    }

    fn get_hash_from_key_identifier(&self, key_identifier: &str) -> Result<String, String> {
        let mut hash = String::default();
        let key_identifier = format!("{}{}", key_identifier, ".txt");
        if let Ok(key_identifiers) = self.key_identifiers.get_collection(){
            for kid in key_identifiers{
                if key_identifier.eq(&kid) {
                    if let Ok(mut file) = File::open(format!("{}{}", self.key_identifiers.repo, kid)){
                        let mut buf = String::default();
                        let res = file.read_to_string(&mut buf).expect("Error reading file");
                        hash = buf;
                    }
                }
            }
        }

        if !hash.is_empty(){
            return Ok(hash);
        }

        Err("Hash not found".to_string())
    }

    fn clone_box(&self) -> Box<BackendStorage> {
        Box::new(self.clone())
    }
}