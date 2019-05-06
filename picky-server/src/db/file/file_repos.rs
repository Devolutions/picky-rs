use crate::db::file::file_repo::FileRepo;
use crate::db::backend::{BackendStorage, Model, Repo};
use crate::utils;
use std::marker::PhantomData;
use std::fs::File;
use std::io::Read;

const REPO_CERTIFICATE: &str = "CertificateStore";
const REPO_KEY: &str = "KeyStore";
const REPO_CERTNAME: &str = "NameStore";
const REPO_KEYIDENTIFIER: &str = "KeyIdentifierStore";

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
            self.name.insert(&name.to_string(), &cert_hash)?;
            self.cert.insert(&cert_hash, &cert.to_string())?;
            self.keys.insert(&cert_hash, &key.to_string())?;
            self.key_identifiers.insert(key_identifier, &cert_hash)?;
            return Ok(true);
        }
        Err("Could not encore certificate".to_string())
    }

    fn find(&self, name: &str) -> Result<Vec<Model<String>>, String> {
        let mut model_vec = Vec::new();
        if let Ok(model) = self.name.get_collection(){
            model.iter().map(|n|{
                if name.eq(n) {
                    if let Ok(mut file)= File::open(format!("{}{}",self.name.repo, n)){
                        let mut buf = String::default();
                        let res = file.read_to_string(&mut buf).expect("Error reading file");
                        model_vec.push(Model{
                            key: name.to_string(),
                            value: buf
                        })
                    }
                }
            });

            return Ok(model_vec);
        }

        Err("Not found".to_string())
    }

    fn get_cert(&self, hash: &str) -> Result<String, String> {
        let mut cert= String::default();
        if let Ok(c) = self.cert.get_collection(){
            c.iter().map(|h|{
                if hash.eq(h){
                    if let Ok(mut file) = File::open(format!("{}{}", self.cert.repo, h)){
                        let mut buf = String::default();
                        let res = file.read_to_string(&mut buf).expect("Error reading file");
                        cert = buf;
                    }
                }
            });
            if !cert.is_empty(){
                return Ok(cert);
            }
        }

        Err("Cert not found".to_string())
    }

    fn get_key(&self, hash: &str) -> Result<String, String> {
        let mut key = String::default();
        self.keys.get_collection()?.iter().map(|h|{
            if hash.eq(h) {
                if let Ok(mut file) = File::open(format!("{}{}", self.keys.repo, h)){
                    let mut buf = String::default();
                    let res = file.read_to_string(&mut buf).expect("Error reading file");
                    key = buf;
                }
            }
        });

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
        self.key_identifiers.get_collection()?.iter().map(|kid|{
            if key_identifier.eq(kid) {
                if let Ok(mut file) = File::open(format!("{}{}", self.keys.repo, kid)){
                    let mut buf = String::default();
                    let res = file.read_to_string(&mut buf).expect("Error reading file");
                    hash = buf;
                }
            }
        });

        if !hash.is_empty(){
            return Ok(hash);
        }

        Err("Hash not found".to_string())
    }

    fn clone_box(&self) -> Box<BackendStorage> {
        Box::new(self.clone())
    }
}