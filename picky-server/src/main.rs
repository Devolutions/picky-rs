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

#[cfg(any(feature = "pre-gen-pk", all(debug_assertions, test)))]
pub mod test_files {
    pub const RSA_2048_PK_1: &str = include_str!("../../test_assets/private_keys/rsa-2048-pk_1.key");
    pub const RSA_2048_PK_2: &str = include_str!("../../test_assets/private_keys/rsa-2048-pk_2.key");
    pub const RSA_2048_PK_3: &str = include_str!("../../test_assets/private_keys/rsa-2048-pk_3.key");
    pub const RSA_2048_PK_4: &str = include_str!("../../test_assets/private_keys/rsa-2048-pk_4.key");
    pub const RSA_2048_PK_5: &str = include_str!("../../test_assets/private_keys/rsa-2048-pk_5.key");
    pub const RSA_2048_PK_6: &str = include_str!("../../test_assets/private_keys/rsa-2048-pk_6.key");
    pub const RSA_2048_PK_7: &str = include_str!("../../test_assets/private_keys/rsa-2048-pk_7.key");
    pub const RSA_4096_PK_1: &str = include_str!("../../test_assets/private_keys/rsa-4096-pk_1.key");
    pub const RSA_4096_PK_2: &str = include_str!("../../test_assets/private_keys/rsa-4096-pk_2.key");
    pub const RSA_4096_PK_3: &str = include_str!("../../test_assets/private_keys/rsa-4096-pk_3.key");
}
