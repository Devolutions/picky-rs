use crate::{
    configuration::ServerConfig,
    http::{controllers::server_controller::ServerController, middlewares::auth::AuthMiddleware},
};
use saphir::{router::Builder, Server as SaphirServer};

pub struct HttpServer {
    pub server: SaphirServer,
}

impl HttpServer {
    pub fn new(config: ServerConfig) -> Self {
        let server = SaphirServer::builder()
            .configure_middlewares(|middle_stack| {
                middle_stack.apply(AuthMiddleware::new(config.clone()), vec!["/sign", "/signcert"], None)
            })
            .configure_router(|router: Builder| {
                let controller = ServerController::new(config);
                router.add(controller)
            })
            .configure_listener(|listener_config| listener_config.set_uri("http://0.0.0.0:12345"))
            .build();

        HttpServer { server }
    }

    pub fn run(&self) {
        if let Err(e) = self.server.run() {
            error!("{}", e);
        }
    }
}
