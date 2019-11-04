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
const TXT_EXT: &str = ".txt";
const DER_EXT: &str = ".der";

#[derive(Clone)]
pub struct FileRepos{
    pub path: String,
    pub name: FileRepo<String>,
    pub cert: FileRepo<Vec<u8>>,
    pub keys: FileRepo<Vec<u8>>,
    pub key_identifiers: FileRepo<String>
}

impl FileRepos {
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

    #[inline]
    fn __helper_get(&self, hash: &str, collection: &FileRepo<Vec<u8>>, type_err: &'static str) -> Result<Vec<u8>, String> {
        let hash = format!("{}{}", hash, DER_EXT);
        let certs = if let Ok(certs) = collection.get_collection() {
            certs
        } else {
            return Err(format!("{} not found", type_err));
        };

        let mut cert = Vec::new();
        for c in certs {
            if hash.eq(&c) {
                if let Ok(mut file) = File::open(format!("{}{}", self.cert.repo, c)) {
                    file.read_to_end(&mut cert).map_err(|e| format!("Error reading file: {}", e))?;
                    break;
                }
            }
        }

        if cert.is_empty() {
            Err(format!("{} file not found", type_err))
        } else {
            Ok(cert)
        }
    }
}

impl BackendStorage for FileRepos {
    fn init(&mut self) -> Result<(), String> {
        self.name.init(Some(self.path.clone()), REPO_CERTNAME)?;
        self.cert.init(Some(self.path.clone()), REPO_CERTIFICATE)?;
        self.keys.init(Some(self.path.clone()), REPO_KEY)?;
        self.key_identifiers.init(Some(self.path.clone()), REPO_KEYIDENTIFIER)?;
        Ok(())
    }

    fn store(&mut self, name: &str, cert: &[u8], key: Option<&[u8]>, key_identifier: &str) -> Result<bool, String> {
        if let Ok(cert_hash) = utils::multihash_encode(cert){
            self.name.insert(&format!("{}{}", name.replace(" ", "_").to_string(), TXT_EXT), &cert_hash)?;
            self.cert.insert(&format!("{}{}",cert_hash, DER_EXT), &cert.to_vec())?;

            if let Some(key) = key {
                self.keys.insert(&format!("{}{}",cert_hash, DER_EXT), &key.to_vec())?;
            }

            self.key_identifiers.insert(&format!("{}{}", key_identifier, TXT_EXT), &cert_hash)?;
            return Ok(true);
        }
        Err("Could not encode certificate".to_string())
    }

    fn find(&self, name: &str) -> Result<Vec<Model<String>>, String> {
        let mut model_vec = Vec::new();
        let name = format!("{}{}", name, TXT_EXT).replace(" ", "_");
        if let Ok(model) = self.name.get_collection(){
            for n in model{
                if name.eq(&n){
                    if let Ok(mut file) = File::open(format!("{}{}",self.name.repo, n)){
                        let mut buf = String::default();
                        let _res = file.read_to_string(&mut buf).expect("Error reading file");
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

    fn get_cert(&self, hash: &str) -> Result<Vec<u8>, String> {
        self.__helper_get(hash, &self.cert, "Cert")
    }

    fn get_key(&self, hash: &str) -> Result<Vec<u8>, String> {
        self.__helper_get(hash, &self.keys, "Key")
    }

    fn get_key_identifier_from_hash(&self, _hash: &str) -> Result<String, String> {
        unimplemented!()
    }

    fn get_hash_from_key_identifier(&self, key_identifier: &str) -> Result<String, String> {
        let mut hash = String::default();
        let key_identifier = format!("{}{}", key_identifier, TXT_EXT);
        if let Ok(key_identifiers) = self.key_identifiers.get_collection(){
            for kid in key_identifiers{
                if key_identifier.eq(&kid) {
                    if let Ok(mut file) = File::open(format!("{}{}", self.key_identifiers.repo, kid)){
                        let mut buf = String::default();
                        let _res = file.read_to_string(&mut buf).expect("Error reading file");
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

    fn clone_box(&self) -> Box<dyn BackendStorage> {
        Box::new(self.clone())
    }

    fn health(&self) -> Result<(), String> {
        Ok(())
    }
}