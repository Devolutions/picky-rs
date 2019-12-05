use mongodb::{
    common::{ReadMode, ReadPreference},
    connstring,
    db::ThreadedDatabase,
    r2d2_mongo, ClientOptions, CommandType,
};
use r2d2::Pool;
use std::time::Duration;

const CONNECTION_IDLE_TIMEOUT_SECS: u64 = 600;
const DB_CONNECTION_TIMEOUT_SECS: u64 = 15;
const DATABASE_NAME: &str = "picky";

#[derive(Clone)]
pub struct MongoConnection {
    pool: Pool<r2d2_mongo::MongoConnectionManager>,
}

impl MongoConnection {
    pub fn new(mongo_url: &str) -> Result<Self, String> {
        let conn_str = connstring::parse(mongo_url)
            .map_err(|e| format!("couldn't parse connection string: {}", e))?;

        let mut client_options = match conn_str
            .options
            .as_ref()
            .and_then(|options| options.options.get("ssl"))
        {
            Some(value) if value.eq("true") => ClientOptions::with_unauthenticated_ssl(None, false),
            _ => ClientOptions::new(),
        };
        client_options.idle_connection_timeout =
            Some(Duration::from_secs(CONNECTION_IDLE_TIMEOUT_SECS));
        client_options.pool_size = Some(1);
        client_options.read_preference =
            Some(ReadPreference::new(ReadMode::SecondaryPreferred, None));

        let manager =
            r2d2_mongo::MongoConnectionManager::new(conn_str, DATABASE_NAME, client_options);

        let pool = r2d2::Pool::builder()
            .max_size(20)
            .min_idle(Some(5))
            .idle_timeout(Some(Duration::from_secs(CONNECTION_IDLE_TIMEOUT_SECS)))
            .connection_timeout(Duration::from_secs(DB_CONNECTION_TIMEOUT_SECS))
            .build(manager)
            .map_err(|e| format!("couldn't create r2d2 connection pool: {}", e))?;

        Ok(MongoConnection { pool })
    }

    pub fn get(
        &self,
    ) -> Result<r2d2::PooledConnection<r2d2_mongo::MongoConnectionManager>, String> {
        self.pool
            .get()
            .map_err(|e| format!("couldn't get mongo connection from r2d2: {}", e))
    }

    pub fn ping(&self) -> Result<(), String> {
        let cmd = doc! { "ping": 1 };
        self.get()?
            .command(cmd, CommandType::Suppressed, None)
            .map_err(|e| format!("couldn't ping: {}", e))?;
        Ok(())
    }
}
