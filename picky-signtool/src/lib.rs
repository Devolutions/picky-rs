use anyhow::anyhow;
use std::path::Path;

pub mod config;
pub mod sign;
pub mod verify;

#[inline]
pub fn file_name_from_path(file: &Path) -> anyhow::Result<String> {
    file.file_name()
        .map(|name| name.to_str())
        .flatten()
        .map(|name| name.to_owned())
        .ok_or_else(|| anyhow!("File name should be present for {:?} path", file))
}
