#[macro_use]
extern crate clap;
#[macro_use(bson, doc)]
extern crate bson;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;

mod configuration;
mod db;
mod http;
mod server;
mod utils;

use crate::configuration::ServerConfig;
use crate::server::Server;
use log::LevelFilter;

#[cfg(any(feature = "pre-gen-pk", all(debug_assertions, test)))]
pub mod test_files {
    pub const RSA_2048_PK_1: &str =
        include_str!("../../test_assets/private_keys/rsa-2048-pk_1.key");
    pub const RSA_2048_PK_2: &str =
        include_str!("../../test_assets/private_keys/rsa-2048-pk_2.key");
    pub const RSA_2048_PK_3: &str =
        include_str!("../../test_assets/private_keys/rsa-2048-pk_3.key");
    pub const RSA_2048_PK_4: &str =
        include_str!("../../test_assets/private_keys/rsa-2048-pk_4.key");
    pub const RSA_2048_PK_5: &str =
        include_str!("../../test_assets/private_keys/rsa-2048-pk_5.key");
    pub const RSA_2048_PK_6: &str =
        include_str!("../../test_assets/private_keys/rsa-2048-pk_6.key");
    pub const RSA_4096_PK_1: &str =
        include_str!("../../test_assets/private_keys/rsa-4096-pk_1.key");
    pub const RSA_4096_PK_2: &str =
        include_str!("../../test_assets/private_keys/rsa-4096-pk_2.key");
    //pub const RSA_4096_PK_3: &str = include_str!("../../test_assets/private_keys/rsa-4096-pk_3.key");
}

fn main() {
    let conf = ServerConfig::new();

    init_logs(&conf);

    Server::run(conf);
}

fn init_logs(config: &ServerConfig) {
    use log4rs::append::console::ConsoleAppender;
    use log4rs::config::{Appender, Config as ConfigLog4rs, Logger, Root};
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
        .build(
            Root::builder()
                .appender("stdout")
                .build(config.level_filter()),
        )
        .expect("Unable to configure logger");

    if let Err(e) = log4rs::init_config(config) {
        println!("Can't init log4rs: {}", e);
    }
}
