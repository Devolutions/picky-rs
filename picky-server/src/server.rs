use crate::configuration::ServerConfig;
use crate::db::mongodb::mongo_connection::MongoConnection;
use crate::db::mongodb::mongo_repos::MongoRepos;

use saphir::{Middleware, SyncRequest, SyncResponse, RequestContinuation, StatusCode, header};
use saphir::Server as SaphirServer;
use crate::controllers::server_controller::{ServerController, generate_root_ca, generate_intermediate};
use crate::db::backend::Backend;
use std::sync::Arc;

pub struct Server{
}

impl Server{
    pub fn run(config: ServerConfig) {
        /// Todo check for type of backend
        /*let mongo = MongoConnection::new(&config.database.url).expect("Cannot start Picky without a database");
        lest mut repos = MongoRepos::new(mongo.clone());*/
        let mut repos = Backend::from(&config).db;
        repos.init().expect("Picky cannot start without fully initializing its repos");


        info!("Creating root...");
        generate_root_ca(&config, &mut repos).and_then(|created|{
            if created {
                info!("Root CA Created");
            } else {
                info!("Root CA already exists");
            }
            info!("Creating intermediate...");
            generate_intermediate(&config, &mut repos)
        }).map(|created|{
            if created {
                info!("Intermediate Created");
            } else {
                info!("Intermediate already exists");
            }
        }).expect("Unable to configure picky");

        let _server = SaphirServer::builder()
            .configure_middlewares(|middle_stack|{
                middle_stack.apply(AuthMiddleware::new(config.clone()), ["/"].to_vec(), Some(vec![r"^/chain", r"^/json-chain", r"^/health", r"^/authority"]))
            }).configure_router(|router|{
            let controller = ServerController::new(repos.clone(), config.clone());
            router.add(controller)
        }).configure_listener(|listener_config|{
            listener_config.set_uri("http://0.0.0.0:12345")
        }).build()
            .run();
    }
}

pub struct AuthMiddleware{
    config: ServerConfig
}

impl AuthMiddleware{
    pub fn new(config: ServerConfig) -> Self{
        AuthMiddleware{
            config
        }
    }
}

impl Middleware for AuthMiddleware{
    fn resolve(&self, req: &mut SyncRequest, res: &mut SyncResponse) -> RequestContinuation{
        res.status(StatusCode::UNAUTHORIZED);

        let header = match req.headers_map().get(header::AUTHORIZATION){
            Some(h) => h.clone(),
            None => {
                res.status(StatusCode::UNAUTHORIZED);
                return RequestContinuation::Stop;
            }
        };

        let auth_str = match header.to_str() {
            Ok(s) => s,
            Err(_e) => {
                res.status(StatusCode::UNAUTHORIZED);
                return RequestContinuation::Stop;
            }
        };

        validate_api_key(&self.config, auth_str, res)
    }
}

fn validate_api_key(config: &ServerConfig, auth_str: &str, res: &mut SyncResponse) -> RequestContinuation{
    let auth_vec = auth_str.split(' ').collect::<Vec<&str>>();

    if auth_vec.len() != 2{
        res.status(StatusCode::UNAUTHORIZED);
        return RequestContinuation::Stop;
    }

    let method = auth_vec[0].to_lowercase();
    let api_key = auth_vec[1];
    if let "bearer" = method.as_str() {
        if api_key.eq(config.api_key.as_str()) {
            return RequestContinuation::Continue;
        }
    }

    res.status(StatusCode::UNAUTHORIZED);
    RequestContinuation::Stop
}