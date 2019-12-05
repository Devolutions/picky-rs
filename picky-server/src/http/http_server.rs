use crate::{configuration::ServerConfig, http::middlewares::auth::AuthMiddleware};
use saphir::{router::Builder, Server as SaphirServer};

pub struct HttpServer {
    pub server: SaphirServer,
}

impl HttpServer {
    pub fn new<F>(config: ServerConfig, route_configurator: F) -> Self
    where
        F: Fn(Builder) -> Builder,
    {
        let server = SaphirServer::builder()
            .configure_middlewares(|middle_stack| {
                middle_stack.apply(
                    AuthMiddleware::new(config.clone()),
                    ["/"].to_vec(),
                    Some(vec!["/chain", "/json-chain", "/health", "/authority"]),
                )
            })
            .configure_router(route_configurator)
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
