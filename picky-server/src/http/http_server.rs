use crate::{config::Config, http::controller::ServerController};
use log4rs::Handle;
use saphir::{router::Builder, Server as SaphirServer};

pub struct HttpServer {
    pub server: SaphirServer,
}

impl HttpServer {
    pub fn new(config: Config, log_handle: Handle) -> Self {
        let controller = match ServerController::new(config, log_handle) {
            Ok(controller) => controller,
            Err(e) => panic!("Couldn't build server controller: {}", e),
        };

        let server = SaphirServer::builder()
            .configure_router(|router: Builder| router.add(controller))
            .configure_listener(|listener_config| listener_config.set_uri("http://0.0.0.0:12345"))
            .build();

        HttpServer { server }
    }

    pub fn run(&self) {
        if let Err(e) = self.server.run() {
            log::error!("{}", e);
        }
    }
}
