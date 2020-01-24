use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub schema_version: u8,
}
