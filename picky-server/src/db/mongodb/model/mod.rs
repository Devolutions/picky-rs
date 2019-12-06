pub mod certificate_store;
pub mod key_identifier_store;
pub mod key_store;
pub mod name_store;

use crate::{
    db::{
        backend::{BackendStorage, Model},
        mongodb::{
            model::{
                certificate_store::CertificateStore, key_identifier_store::KeyIdentifierStore,
                key_store::KeyStore, name_store::NameStore,
            },
            mongo_connection::MongoConnection,
        },
    },
    multihash,
};
use bson::{from_bson, oid::ObjectId, spec::BinarySubtype, to_bson, Bson, Document};
use mongodb::coll::{
    options::{
        AggregateOptions, FindOneAndUpdateOptions, FindOptions, ReplaceOptions, UpdateOptions,
    },
    results::{DeleteResult, InsertManyResult, UpdateResult},
};
use std::{
    error::Error,
    fmt,
    fmt::{Display, Formatter},
};

#[allow(dead_code)]
#[derive(Debug)]
pub enum RepositoryError {
    BsonEncodeError(::bson::EncoderError),
    BsonDecodeError(::bson::DecoderError),
    MongoError(::mongodb::Error),
    UninitializedRepoError,
    InsertError,
    UpdateError,
    Other(String),
}

impl Error for RepositoryError {}

impl Display for RepositoryError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            RepositoryError::BsonEncodeError(e) => write!(f, "Bson encode error: {}", e),
            RepositoryError::BsonDecodeError(e) => write!(f, "Bson decode error: {}", e),
            RepositoryError::MongoError(e) => write!(f, "Mongo error: {}", e),
            RepositoryError::UninitializedRepoError => write!(f, "Repository not initialized."),
            RepositoryError::InsertError => write!(f, "Insert error"),
            RepositoryError::UpdateError => write!(f, "Update error"),
            RepositoryError::Other(s) => write!(f, "Other error: {}", s),
        }
    }
}

impl From<String> for RepositoryError {
    fn from(e: String) -> Self {
        RepositoryError::Other(e)
    }
}

impl From<::bson::EncoderError> for RepositoryError {
    fn from(e: ::bson::EncoderError) -> Self {
        RepositoryError::BsonEncodeError(e)
    }
}

impl From<::bson::DecoderError> for RepositoryError {
    fn from(e: ::bson::DecoderError) -> Self {
        RepositoryError::BsonDecodeError(e)
    }
}

impl From<::mongodb::Error> for RepositoryError {
    fn from(e: ::mongodb::Error) -> Self {
        RepositoryError::MongoError(e)
    }
}

impl From<RepositoryError> for String {
    fn from(e: RepositoryError) -> Self {
        format!("RepositoryError: {}", e)
    }
}

#[derive(Clone)]
pub struct RepositoryCollection {
    db_instance: MongoConnection,
    pub certificate_store: certificate_store::CertificateStoreRepository,
    pub key_identifier_store: key_identifier_store::KeyIdentifierStoreRepository,
    pub key_store: key_store::KeyStoreRepository,
    pub name_store: name_store::NameStoreRepository,
}

impl RepositoryCollection {
    pub fn new(db: MongoConnection) -> Self {
        RepositoryCollection {
            db_instance: db,
            certificate_store: Default::default(),
            key_identifier_store: Default::default(),
            key_store: Default::default(),
            name_store: Default::default(),
        }
    }

    pub fn load_repositories(&mut self) -> Result<(), RepositoryError> {
        self.certificate_store.init(self.db_instance.clone())?;
        self.key_identifier_store.init(self.db_instance.clone())?;
        self.key_store.init(self.db_instance.clone())?;
        self.name_store.init(self.db_instance.clone())?;
        Ok(())
    }
}

impl BackendStorage for RepositoryCollection {
    fn init(&mut self) -> Result<(), String> {
        self.load_repositories().map_err(|e| e.to_string())
    }

    fn store(
        &self,
        name: &str,
        cert: &[u8],
        key: Option<&[u8]>,
        key_identifier: &str,
    ) -> Result<bool, String> {
        if let Ok(cert_hash) = multihash::multihash_encode(cert) {
            let name_item = NameStore::new(name, &cert_hash);
            self.name_store
                .update_with_options(doc!("key": name), name_item, true)?;

            let certificate_item = CertificateStore::new(
                &cert_hash,
                Bson::Binary(BinarySubtype::Generic, cert.to_vec()),
            );
            self.certificate_store.update_with_options(
                doc!("key": cert_hash.clone()),
                certificate_item,
                true,
            )?;

            if let Some(key) = key {
                let key_item = KeyStore::new(
                    &cert_hash,
                    Bson::Binary(BinarySubtype::Generic, key.to_vec()),
                );
                self.key_store.update_with_options(
                    doc!("key": cert_hash.clone()),
                    key_item,
                    true,
                )?;
            }

            let key_identifier_item = KeyIdentifierStore::new(key_identifier, &cert_hash);
            self.key_identifier_store.update_with_options(
                doc!("key": key_identifier),
                key_identifier_item,
                true,
            )?;

            return Ok(true);
        }

        Err("Can\'t encode certificate".to_string())
    }

    fn find(&self, name: &str) -> Result<Vec<Model<String>>, String> {
        let mut model_vec = Vec::new();

        if let Some(name_item) = self.name_store.get(doc!("key": name))? {
            model_vec.push(name_item.into())
        }

        Ok(model_vec)
    }

    fn get_cert(&self, hash: &str) -> Result<Vec<u8>, String> {
        if let Some(cert) = self.certificate_store.get(doc!("key": hash))? {
            match cert.value {
                Bson::Binary(BinarySubtype::Generic, bin) => Ok(bin),
                _ => Err("DB content is not binary".to_string()),
            }
        } else {
            Err("Cert not found".to_string())
        }
    }

    fn get_key(&self, hash: &str) -> Result<Vec<u8>, String> {
        if let Some(key) = self.key_store.get(doc!("key": hash))? {
            match key.value {
                Bson::Binary(BinarySubtype::Generic, bin) => Ok(bin),
                _ => Err("DB content is not binary".to_string()),
            }
        } else {
            Err("Key not found".to_string())
        }
    }

    fn get_key_identifier_from_hash(&self, hash: &str) -> Result<String, String> {
        if let Some(key_identifier) = self.key_identifier_store.get(doc!("value": hash))? {
            Ok(key_identifier.key)
        } else {
            Err("Key identifier not found".to_string())
        }
    }

    fn get_hash_from_key_identifier(&self, key_identifier: &str) -> Result<String, String> {
        if let Some(key_identifier) = self.key_identifier_store.get(doc!("key": key_identifier))? {
            Ok(key_identifier.value)
        } else {
            Err("Key identifier not found".to_string())
        }
    }

    fn health(&self) -> Result<(), String> {
        self.db_instance.ping()
    }
}

pub trait Repository {
    type Model;

    fn init(&mut self, db_instance: MongoConnection) -> Result<(), RepositoryError>;
    fn get_collection(&self) -> Result<mongodb::coll::Collection, RepositoryError>;

    fn insert(&self, model: <Self as Repository>::Model) -> Result<Option<Bson>, RepositoryError>
    where
        <Self as Repository>::Model: ::serde::Serialize,
    {
        let serialized_model = to_bson(&model)?;

        if let Bson::Document(document) = serialized_model {
            let inserted = self.get_collection()?.insert_one(document, None)?;
            match inserted.write_exception {
                Some(write_exception) => {
                    error!("Document can't be inserted: {}", write_exception.message);
                    Err(RepositoryError::InsertError)
                }
                None => Ok(inserted.inserted_id),
            }
        } else {
            Err(RepositoryError::InsertError)
        }
    }

    fn insert_many(&self, models: Vec<<Self as Repository>::Model>) -> InsertManyResult
    where
        <Self as Repository>::Model: ::serde::Serialize,
    {
        let mut documents = Vec::new();
        for model in models {
            match to_bson(&model) {
                Ok(serialized_model) => {
                    if let Bson::Document(document) = serialized_model {
                        documents.push(document);
                    }
                }
                Err(e) => {
                    error!("Model can't be serialized in bson: {:?}", e);
                }
            }
        }

        if let Ok(collection) = self.get_collection() {
            if let Ok(res) = collection.insert_many(documents, None) {
                return res;
            }
        }

        InsertManyResult::new(None, None)
    }

    fn update(
        &self,
        doc: Document,
        model: <Self as Repository>::Model,
    ) -> Result<(), RepositoryError>
    where
        <Self as Repository>::Model: ::serde::Serialize,
    {
        let serialized_model = to_bson(&model)?;

        if let Bson::Document(mut document) = serialized_model {
            let _res = document.remove("_id"); // if there is an id field removes it. Replace one does not work on data targeting the id field index
            self.get_collection()?.replace_one(doc, document, None)?;
            Ok(())
        } else {
            Err(RepositoryError::UpdateError)
        }
    }

    fn update_with_options(
        &self,
        doc: Document,
        model: <Self as Repository>::Model,
        upsert: bool,
    ) -> Result<(), RepositoryError>
    where
        <Self as Repository>::Model: ::serde::Serialize,
    {
        let serialized_model = to_bson(&model)?;

        if let Bson::Document(mut document) = serialized_model {
            let _res = document.remove("_id"); // if there is an id field removes it. Replace one does not work on data targeting the id field index
            let _result = self.get_collection()?.replace_one(
                doc,
                document,
                Some(ReplaceOptions {
                    upsert: Some(upsert),
                    ..ReplaceOptions::new()
                }),
            )?;
            Ok(())
        } else {
            Err(RepositoryError::UpdateError)
        }
    }

    fn update_by_id(
        &self,
        bson_id: ObjectId,
        model: <Self as Repository>::Model,
    ) -> Result<(), RepositoryError>
    where
        <Self as Repository>::Model: ::serde::Serialize,
    {
        self.update(doc! { "_id": bson_id }, model)
    }

    fn update_one(
        &self,
        filter: Document,
        update: Document,
    ) -> Result<UpdateResult, RepositoryError> {
        self.get_collection()?
            .update_one(filter, update, None)
            .map_err(|e| e.into())
    }

    fn update_one_with_options(
        &self,
        filter: Document,
        update: Document,
        upsert: bool,
    ) -> Result<UpdateResult, RepositoryError> {
        self.get_collection()?
            .update_one(
                filter,
                update,
                Some(UpdateOptions {
                    upsert: Some(upsert),
                    ..Default::default()
                }),
            )
            .map_err(|e| e.into())
    }

    fn update_many(
        &self,
        filter: Document,
        update: Document,
    ) -> Result<UpdateResult, RepositoryError> {
        self.get_collection()?
            .update_many(filter, update, None)
            .map_err(|e| e.into())
    }

    fn delete(&self, doc: Document) -> Result<DeleteResult, RepositoryError> {
        let result = self.get_collection()?.delete_one(doc, None)?;
        Ok(result)
    }

    fn delete_many(&self, doc: Document) -> Result<DeleteResult, RepositoryError> {
        let result = self.get_collection()?.delete_many(doc, None)?;
        Ok(result)
    }

    fn delete_by_id(&self, bson_id: ObjectId) -> Result<DeleteResult, RepositoryError> {
        self.delete(doc! { "_id": bson_id })
    }

    fn get(&self, doc: Document) -> Result<Option<<Self as Repository>::Model>, RepositoryError>
    where
        <Self as Repository>::Model: ::serde::Deserialize<'static>,
    {
        let document_opt = self.get_collection()?.find_one(Some(doc), None)?;

        if let Some(doc) = document_opt {
            let model = from_bson(Bson::Document(doc))?;
            Ok(Some(model))
        } else {
            Ok(None)
        }
    }

    fn get_by_id(
        &self,
        bson_id: ObjectId,
    ) -> Result<Option<<Self as Repository>::Model>, RepositoryError>
    where
        <Self as Repository>::Model: ::serde::Deserialize<'static>,
    {
        self.get(doc! { "_id": bson_id })
    }

    fn get_all(
        &self,
        options: Option<FindOptions>,
    ) -> Result<Vec<<Self as Repository>::Model>, RepositoryError>
    where
        <Self as Repository>::Model: ::serde::Deserialize<'static>,
    {
        let mut model_vec = Vec::new();
        let documents_cursor = self.get_collection()?.find(None, options)?;

        for doc_res in documents_cursor {
            if let Ok(model_document) = doc_res {
                if let Ok(model) = from_bson(Bson::Document(model_document)) {
                    model_vec.push(model);
                }
            }
        }

        Ok(model_vec)
    }

    fn find(
        &self,
        doc: Document,
        options: Option<FindOptions>,
    ) -> Result<Vec<<Self as Repository>::Model>, RepositoryError>
    where
        <Self as Repository>::Model: ::serde::Deserialize<'static>,
    {
        let mut model_vec = Vec::new();
        let documents_cursor = self.get_collection()?.find(Some(doc), options)?;

        for doc_res in documents_cursor {
            if let Ok(model_document) = doc_res {
                if let Ok(model) = from_bson(Bson::Document(model_document)) {
                    model_vec.push(model);
                }
            }
        }

        Ok(model_vec)
    }

    fn find_with_pipeline(
        &self,
        docs: Vec<Document>,
        options: Option<AggregateOptions>,
    ) -> Result<Vec<Document>, RepositoryError>
    where
        Document: ::serde::Deserialize<'static>,
    {
        let mut model_vec = Vec::new();
        let documents_cursor = self.get_collection()?.aggregate(docs, options);

        if let Ok(mut cursor) = documents_cursor {
            if let Ok(documents) = cursor.drain_current_batch() {
                for document in documents {
                    model_vec.push(document);
                }
            }
        }

        Ok(model_vec)
    }

    fn find_models_with_pipeline(
        &self,
        docs: Vec<Document>,
        options: Option<AggregateOptions>,
    ) -> Result<Vec<<Self as Repository>::Model>, RepositoryError>
    where
        <Self as Repository>::Model: ::serde::Deserialize<'static>,
    {
        let mut model_vec = Vec::new();
        let documents_cursor = self.get_collection()?.aggregate(docs, options);

        if let Ok(mut cursor) = documents_cursor {
            if let Ok(documents) = cursor.drain_current_batch() {
                for document in documents {
                    if let Ok(model) = from_bson(Bson::Document(document)) {
                        model_vec.push(model);
                    }
                }
            }
        }

        Ok(model_vec)
    }

    fn find_one_and_update(
        &self,
        filter: Document,
        update: Document,
        options: Option<FindOneAndUpdateOptions>,
    ) -> Result<Option<Document>, RepositoryError> {
        let result = self
            .get_collection()?
            .find_one_and_update(filter, update, options)?;
        Ok(result)
    }
}
