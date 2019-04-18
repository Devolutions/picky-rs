const DATABASE_NAME: &'static str = "picky";

use mongodb::{CommandType, Client, ThreadedClient, ClientOptions, connstring};
use mongodb::db::{ThreadedDatabase, Database};
use std::time::Duration;

#[derive(Clone)]
pub struct MongoConnection {
    db: Database
}

impl MongoConnection {
    pub fn new(mongo_url: &str) -> Result<Self, String> {
        let parsed_conn_string = match connstring::parse(mongo_url) {
            Ok(parsed) => {
                parsed
            }
            Err(e) => return Err(e.to_string()),
        };

        let host = parsed_conn_string.hosts[0].host_name.clone();
        let port = parsed_conn_string.hosts[0].port.clone();
        let user = parsed_conn_string.user.clone();
        let pass = parsed_conn_string.password.clone();
        let db_name = DATABASE_NAME.to_string();

        let mut client_options = match parsed_conn_string.options.clone().and_then(|options| {
            options.options.get("ssl").cloned()
        }) {
            Some(ref value) if value.eq("true") => {
                ClientOptions::with_unauthenticated_ssl(None, false)
            }
            _ => {
                ClientOptions::new()
            }
        };

        client_options.idle_connection_timeout = Some(Duration::from_secs(600));
        client_options.pool_size = Some(15);

        let client = Client::connect_with_options(&host, port, client_options).expect("Bad client");

        if let (Some(username), Some(password)) = (user, pass) {
            let auth_db = client.db("admin");

            auth_db.auth(
                &username,
                &password,
            ).map_err(|e| e.to_string())?;
        }

        let db = client.db(db_name.as_str());

        let coll = db.collection("connection_test");

        let doc = doc! { "test": 1 };

        if let Ok(_) = coll.insert_one(doc, None) {
            return Ok(MongoConnection{
                db
            });
        }

        Err("Unable to connect to mongo db".to_string())
    }

    pub fn get(&self) -> Result<Database, String> {
        Ok(self.db.clone())
    }

    pub fn _ping(&self) -> Result<(), String> {
        let cmd = doc! { "ping": 1 };
        self.get()?.command(cmd, CommandType::Suppressed, None).map_err(|e| { e.to_string() }).map(|_| { () })
    }
}

unsafe impl Send for MongoConnection {}

unsafe impl Sync for MongoConnection {}