use crate::configuration::ServerConfig;
use crate::http::controllers::server_controller::{generate_root_ca, generate_intermediate, check_certs_in_env};
use crate::db::backend::Backend;
use crate::http::http_server::HttpServer;

pub struct Server{
}

impl Server{
    pub fn run(config: ServerConfig) {
        let mut repos = Backend::from(&config).db;
        repos.init().expect("Picky cannot start without fully initializing its repos");
        if let Err(e) = check_certs_in_env(&config, &mut repos){
            error!("Error loading certificates in environment: {}", e);
        }

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

        info!("Starting http server ...");
        let http_server = HttpServer::new(config.clone(), repos.clone());
        http_server.run();
    }
}