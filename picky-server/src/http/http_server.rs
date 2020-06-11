use crate::{
    config::Config,
    http::{controller::ServerController, middleware},
};
use log4rs::Handle;
use saphir::server::Server as SaphirServer;

pub struct HttpServer {
    pub server: SaphirServer,
}

impl HttpServer {
    pub async fn new(config: Config, log_handle: Handle) -> Self {
        let controller = match ServerController::new(config, log_handle).await {
            Ok(controller) => controller,
            Err(e) => panic!("Couldn't build server controller: {}", e),
        };

        let server = SaphirServer::builder()
            .configure_router(|r| r.controller(controller))
            .configure_listener(|l| l.interface("0.0.0.0:12345"))
            .configure_middlewares(|m| {
                m.apply(middleware::log_middleware, vec!["/"], None).apply(
                    middleware::cors_middleware,
                    vec!["/sign"],
                    None,
                )
            })
            .build();

        HttpServer { server }
    }

    pub async fn run(self) {
        if let Err(e) = self.server.run().await {
            log::error!("{:?}", e);
        }
    }
}
