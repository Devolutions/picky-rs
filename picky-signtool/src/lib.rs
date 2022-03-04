use anyhow::anyhow;
use lief::LogLevel;
use std::path::Path;

pub mod config;
pub mod sign;
pub mod utils;
pub mod verify;

use config::{
    ARG_LOGGING_CRITICAL, ARG_LOGGING_DEBUG, ARG_LOGGING_ERR, ARG_LOGGING_INFO, ARG_LOGGING_TRACE, ARG_LOGGING_WARN,
};

#[inline]
pub fn get_utf8_file_name(file: &Path) -> anyhow::Result<&str> {
    file.file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("Invalid file name: {:?}", file))
}

#[inline]
pub fn lief_logging(log_level: Option<&str>) {
    match log_level {
        Some(log_level) => {
            let log_level = match log_level {
                ARG_LOGGING_TRACE => LogLevel::LogTrace,
                ARG_LOGGING_DEBUG => LogLevel::LogDebug,
                ARG_LOGGING_INFO => LogLevel::LogInfo,
                ARG_LOGGING_WARN => LogLevel::LogWarn,
                ARG_LOGGING_ERR => LogLevel::LogErr,
                ARG_LOGGING_CRITICAL => LogLevel::LogCritical,
                _ => unreachable!("Unexpected log level value"),
            };
            lief::enable_logging(log_level);
        }
        None => lief::disable_logging(),
    }
}
