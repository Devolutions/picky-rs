use crate::config::Config as ServerConfig;
use log::LevelFilter;
use log4rs::config::Config as LoggerConfig;
use log4rs::Handle;

pub fn init_logs(config: &ServerConfig) -> Handle {
    let config = build_logger_config(config).expect("unable to configure logger");
    log4rs::init_config(config).expect("can't init log4rs")
}

pub fn build_logger_config(config: &ServerConfig) -> Result<LoggerConfig, log4rs::config::runtime::ConfigErrors> {
    use log4rs::append::console::ConsoleAppender;
    use log4rs::config::{Appender, Logger, Root};

    LoggerConfig::builder()
        .appender(Appender::builder().build("stdout", Box::new(ConsoleAppender::builder().build())))
        .logger(Logger::builder().build("poston", LevelFilter::Off))
        .logger(Logger::builder().build("mio", LevelFilter::Off))
        .logger(Logger::builder().build("mio_extras", LevelFilter::Off))
        .logger(Logger::builder().build("hyper", LevelFilter::Off))
        .logger(Logger::builder().build("r2d2", LevelFilter::Warn))
        .logger(Logger::builder().build("tokio_io", LevelFilter::Off))
        .logger(Logger::builder().build("tokio_reactor", LevelFilter::Off))
        .logger(Logger::builder().build("tokio_threadpool", LevelFilter::Off))
        .logger(Logger::builder().build("tokio_core", LevelFilter::Off))
        .build(Root::builder().appender("stdout").build(config.log_level))
}
