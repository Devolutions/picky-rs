use crate::{
    db::{
        backend::{BackendStorage, Model, Repo},
        file::file_repo::FileRepo,
    },
    multihash,
};
use std::{fs::File, io::Read, marker::PhantomData, sync::RwLock};

const REPO_CERTIFICATE: &str = "CertificateStore/";
const REPO_KEY: &str = "KeyStore/";
const REPO_CERTNAME: &str = "NameStore/";
const REPO_KEYIDENTIFIER: &str = "KeyIdentifierStore/";
const TXT_EXT: &str = ".txt";
const DER_EXT: &str = ".der";

pub struct FileRepos {
    pub path: String,
    pub name: RwLock<FileRepo<String>>,
    pub cert: RwLock<FileRepo<Vec<u8>>>,
    pub keys: RwLock<FileRepo<Vec<u8>>>,
    pub key_identifiers: RwLock<FileRepo<String>>,
}

impl FileRepos {
    pub fn new(path: &str) -> Self {
        FileRepos {
            path: path.to_string(),
            name: RwLock::new(FileRepo {
                repo: String::default(),
                phantom_data: PhantomData,
            }),
            cert: RwLock::new(FileRepo {
                repo: String::default(),
                phantom_data: PhantomData,
            }),
            keys: RwLock::new(FileRepo {
                repo: String::default(),
                phantom_data: PhantomData,
            }),
            key_identifiers: RwLock::new(FileRepo {
                repo: String::default(),
                phantom_data: PhantomData,
            }),
        }
    }

    fn __helper_get(
        &self,
        hash: &str,
        collection: &FileRepo<Vec<u8>>,
        type_err: &'static str,
    ) -> Result<Vec<u8>, String> {
        let hash = format!("{}{}", hash, DER_EXT);
        let repo_collection = if let Ok(repo_collection) = collection.get_collection() {
            repo_collection
        } else {
            return Err(format!("{} not found", type_err));
        };

        let mut found_item = Vec::new();
        for item in repo_collection {
            if hash.eq(&item) {
                if let Ok(mut file) = File::open(format!("{}{}", collection.repo, item)) {
                    file.read_to_end(&mut found_item)
                        .map_err(|e| format!("Error reading file: {}", e))?;
                    break;
                }
            }
        }

        if found_item.is_empty() {
            Err(format!("{} file not found", type_err))
        } else {
            Ok(found_item)
        }
    }
}

impl BackendStorage for FileRepos {
    fn init(&mut self) -> Result<(), String> {
        self.name
            .write()
            .unwrap()
            .init(Some(self.path.clone()), REPO_CERTNAME)?;
        self.cert
            .write()
            .unwrap()
            .init(Some(self.path.clone()), REPO_CERTIFICATE)?;
        self.keys
            .write()
            .unwrap()
            .init(Some(self.path.clone()), REPO_KEY)?;
        self.key_identifiers
            .write()
            .unwrap()
            .init(Some(self.path.clone()), REPO_KEYIDENTIFIER)?;
        Ok(())
    }

    fn store(
        &self,
        name: &str,
        cert: &[u8],
        key: Option<&[u8]>,
        key_identifier: &str,
    ) -> Result<bool, String> {
        if let Ok(cert_hash) = multihash::multihash_encode(cert) {
            self.name.write().unwrap().insert(
                &format!("{}{}", name.replace(" ", "_"), TXT_EXT),
                &cert_hash,
            )?;
            self.cert
                .write()
                .unwrap()
                .insert(&format!("{}{}", cert_hash, DER_EXT), &cert.to_vec())?;

            if let Some(key) = key {
                self.keys
                    .write()
                    .unwrap()
                    .insert(&format!("{}{}", cert_hash, DER_EXT), &key.to_vec())?;
            }

            self.key_identifiers
                .write()
                .unwrap()
                .insert(&format!("{}{}", key_identifier, TXT_EXT), &cert_hash)?;
            return Ok(true);
        }
        Err("Could not encode certificate".to_string())
    }

    fn find(&self, name: &str) -> Result<Vec<Model<String>>, String> {
        let mut model_vec = Vec::new();
        let name = format!("{}{}", name, TXT_EXT).replace(" ", "_");
        if let Ok(model) = self.name.read().unwrap().get_collection() {
            for n in model {
                if name.eq(&n) {
                    if let Ok(mut file) =
                        File::open(format!("{}{}", self.name.read().unwrap().repo, n))
                    {
                        let mut buf = String::default();
                        let _res = file.read_to_string(&mut buf).expect("Error reading file");
                        model_vec.push(Model {
                            key: name.to_string(),
                            value: buf,
                        })
                    }
                }
            }

            return Ok(model_vec);
        }

        Err("Not found".to_string())
    }

    fn get_cert(&self, hash: &str) -> Result<Vec<u8>, String> {
        self.__helper_get(hash, &self.cert.read().unwrap(), "Cert")
    }

    fn get_key(&self, hash: &str) -> Result<Vec<u8>, String> {
        self.__helper_get(hash, &self.keys.read().unwrap(), "Key")
    }

    fn get_key_identifier_from_hash(&self, _hash: &str) -> Result<String, String> {
        unimplemented!()
    }

    fn get_hash_from_key_identifier(&self, key_identifier: &str) -> Result<String, String> {
        let mut hash = String::default();
        let key_identifier = format!("{}{}", key_identifier, TXT_EXT);
        if let Ok(key_identifiers) = self.key_identifiers.read().unwrap().get_collection() {
            for kid in key_identifiers {
                if key_identifier.eq(&kid) {
                    if let Ok(mut file) = File::open(format!(
                        "{}{}",
                        self.key_identifiers.read().unwrap().repo,
                        kid
                    )) {
                        let mut buf = String::default();
                        let _res = file.read_to_string(&mut buf).expect("Error reading file");
                        hash = buf;
                    }
                }
            }
        }

        if !hash.is_empty() {
            return Ok(hash);
        }

        Err("Hash not found".to_string())
    }

    fn health(&self) -> Result<(), String> {
        Ok(())
    }
}
