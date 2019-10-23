use saphir::Server as SaphirServer;
use crate::http::middlewares::auth::AuthMiddleware;
use crate::http::controllers::server_controller::ServerController;
use crate::configuration::ServerConfig;
use crate::db::backend::BackendStorage;

pub struct HttpServer {
    pub server: SaphirServer,
}

impl HttpServer {
    pub fn new(config: ServerConfig, repos: Box<dyn BackendStorage>) -> Self {

        let server = SaphirServer::builder()
            .configure_middlewares(|middle_stack|{
                middle_stack.apply(AuthMiddleware::new(config.clone()), ["/"].to_vec(), Some(vec!["/chain", "/json-chain", "/health", "/authority"]))
            }).configure_router(|router|{
            let controller = ServerController::new(repos.clone(), config.clone());
            router.add(controller)
        }).configure_listener(|listener_config|{
            listener_config.set_uri("http://0.0.0.0:12345")
        }).build();

        HttpServer {
            server
        }
    }

    pub fn run(&self) {
        if let Err(e) = self.server.run(){
            error!("{}", e);
        }
    }
}