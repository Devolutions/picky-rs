#[macro_use]
extern crate clap;
#[macro_use(bson, doc)]
extern crate bson;
#[macro_use]
extern crate log;

mod configuration;
mod db;
mod http;
mod multihash;
mod picky_controller;

use crate::{configuration::ServerConfig, http::http_server::HttpServer};
use log::LevelFilter;

fn main() {
    let conf = ServerConfig::new();

    init_logs(&conf);

    info!("Building http server ...");
    let http_server = HttpServer::new(conf);
    info!("Starting http server ...");
    http_server.run();
}

fn init_logs(config: &ServerConfig) {
    use log4rs::{
        append::console::ConsoleAppender,
        config::{Appender, Config as ConfigLog4rs, Logger, Root},
    };
    let console_appender = ConsoleAppender::builder().build();

    let config = ConfigLog4rs::builder()
        .appender(Appender::builder().build("stdout", Box::new(console_appender)))
        .logger(Logger::builder().build("poston", LevelFilter::Off))
        .logger(Logger::builder().build("mio", LevelFilter::Off))
        .logger(Logger::builder().build("mio_extras", LevelFilter::Off))
        .logger(Logger::builder().build("hyper", LevelFilter::Off))
        .logger(Logger::builder().build("r2d2", LevelFilter::Warn))
        .logger(Logger::builder().build("tokio_io", LevelFilter::Off))
        .logger(Logger::builder().build("tokio_reactor", LevelFilter::Off))
        .logger(Logger::builder().build("tokio_threadpool", LevelFilter::Off))
        .logger(Logger::builder().build("tokio_core", LevelFilter::Off))
        .build(Root::builder().appender("stdout").build(config.level_filter()))
        .expect("Unable to configure logger");

    if let Err(e) = log4rs::init_config(config) {
        println!("Can't init log4rs: {}", e);
    }
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
