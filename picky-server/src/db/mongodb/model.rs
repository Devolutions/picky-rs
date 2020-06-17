use mongodm::{
    mongo::bson::{oid::ObjectId, Bson},
    Index, IndexOption, Indexes,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Name {
    pub key: String,
    pub value: String,
}

impl mongodm::Model for Name {
    fn coll_name() -> &'static str {
        "name_store"
    }

    fn indexes() -> Indexes {
        Indexes::new().with(Index::new("key").with_option(IndexOption::Unique))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Key {
    pub key: String,
    pub value: Bson,
}

impl mongodm::Model for Key {
    fn coll_name() -> &'static str {
        "key_store"
    }

    fn indexes() -> Indexes {
        Indexes::new().with(Index::new("key").with_option(IndexOption::Unique))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyIdentifier {
    pub key: String,
    pub value: String,
}

impl mongodm::Model for KeyIdentifier {
    fn coll_name() -> &'static str {
        "key_identifier_store"
    }

    fn indexes() -> Indexes {
        Indexes::new().with(Index::new("key").with_option(IndexOption::Unique))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Certificate {
    pub key: String,
    pub value: Bson,
}

impl mongodm::Model for Certificate {
    fn coll_name() -> &'static str {
        "certificate_store"
    }

    fn indexes() -> Indexes {
        Indexes::new().with(Index::new("key").with_option(IndexOption::Unique))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub schema_version: i32,
}

impl mongodm::Model for Config {
    fn coll_name() -> &'static str {
        "configuration"
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HashLookupEntry {
    pub key: String,
    pub value: String,
}

impl mongodm::Model for HashLookupEntry {
    fn coll_name() -> &'static str {
        "hash_lookup_table"
    }

    fn indexes() -> Indexes {
        Indexes::new().with(Index::new("key").with_option(IndexOption::Unique))
    }
}
