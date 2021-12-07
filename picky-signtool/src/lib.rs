use anyhow::anyhow;
use std::path::Path;

pub mod config;
pub mod sign;
pub mod utils;
pub mod verify;

#[inline]
pub fn get_utf8_file_name(file: &Path) -> anyhow::Result<&str> {
    file.file_name()
        .map(|name| name.to_str())
        .flatten()
        .ok_or_else(|| anyhow!("Invalid file name: {:?}", file))
}
