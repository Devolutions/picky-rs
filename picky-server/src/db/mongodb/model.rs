use crate::db::{SshKeyEntry, SshKeyType};
use mongodm::mongo::bson::oid::ObjectId;
use mongodm::mongo::bson::Bson;
use mongodm::{Index, IndexOption, Indexes};
use serde::{Deserialize, Serialize};
// == name == //

pub struct NameCollConf;

impl mongodm::CollectionConfig for NameCollConf {
    fn collection_name() -> &'static str {
        "name_store"
    }

    fn indexes() -> Indexes {
        Indexes::new().with(Index::new("key").with_option(IndexOption::Unique))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Name {
    pub key: String,
    pub value: String,
}

impl mongodm::Model for Name {
    type CollConf = NameCollConf;
}

// == key == //

pub struct KeyCollConf;

impl mongodm::CollectionConfig for KeyCollConf {
    fn collection_name() -> &'static str {
        "key_store"
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
    type CollConf = KeyCollConf;
}

// == ssh key == //

pub struct SshKeyCollConf;

impl mongodm::CollectionConfig for SshKeyCollConf {
    fn collection_name() -> &'static str {
        "ssh_key_store"
    }

    fn indexes() -> Indexes {
        Indexes::new().with(Index::new("ssh_key").with_option(IndexOption::Unique))
    }
}

impl mongodm::Model for SshKeyEntry {
    type CollConf = SshKeyCollConf;
}

impl From<SshKeyType> for Bson {
    fn from(key_type: SshKeyType) -> Self {
        Bson::String(key_type.to_string())
    }
}

// == key identifier == //

pub struct KeyIdCollConf;

impl mongodm::CollectionConfig for KeyIdCollConf {
    fn collection_name() -> &'static str {
        "key_identifier_store"
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
    type CollConf = KeyIdCollConf;
}

// == certificate == //

pub struct CertCollConf;

impl mongodm::CollectionConfig for CertCollConf {
    fn collection_name() -> &'static str {
        "certificate_store"
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
    type CollConf = CertCollConf;
}

// == config == //

pub struct ConfigCollConf;

impl mongodm::CollectionConfig for ConfigCollConf {
    fn collection_name() -> &'static str {
        "configuration"
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    #[serde(rename = "_id")]
    pub id: ObjectId,
    pub schema_version: i32,
}

impl mongodm::Model for Config {
    type CollConf = ConfigCollConf;
}

// == hash lookup entry == //

pub struct HashCollConf;

impl mongodm::CollectionConfig for HashCollConf {
    fn collection_name() -> &'static str {
        "hash_lookup_table"
    }

    fn indexes() -> Indexes {
        Indexes::new().with(Index::new("key").with_option(IndexOption::Unique))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HashLookupEntry {
    pub key: String,
    pub value: String,
}

impl mongodm::Model for HashLookupEntry {
    type CollConf = HashCollConf;
}

pub struct TimestampCollConf;

impl mongodm::CollectionConfig for TimestampCollConf {
    fn collection_name() -> &'static str {
        "timestamps_counter"
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IssuedTimestampsCounter {
    pub counter: i64,
}

impl mongodm::Model for IssuedTimestampsCounter {
    type CollConf = TimestampCollConf;
}
