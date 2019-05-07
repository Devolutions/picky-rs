#[macro_use]
extern crate clap;

#[macro_use(bson, doc)]
extern crate bson;

#[macro_use]
extern crate log;

#[macro_use]
extern crate serde_derive;

#[macro_use(json)]
extern crate serde_json;

mod db;
mod configuration;
mod server;
mod controllers;
mod utils;

use log::LevelFilter;

use crate::configuration::ServerConfig;
use crate::server::Server;

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
        .build(Root::builder().appender("stdout").build(config.level_filter()))
        .expect("Unable to configure logger");

    if let Err(e) = log4rs::init_config(config) {
        println!("Can't init log4rs: {}", e);
    }
}