mod addressing;
mod config;
mod db;
mod http;
mod logging;
mod picky_controller;
mod utils;

use crate::config::Config;
use crate::http::http_server::HttpServer;

#[tokio::main]
async fn main() {
    let conf = Config::startup_init();
    let log_handle = logging::init_logs(&conf);

    log::info!("building http server ...");
    let http_server = HttpServer::new(conf, log_handle).await;

    log::info!("starting http server ...");
    http_server.run().await;
}

