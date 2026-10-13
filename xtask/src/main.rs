mod contract;
mod downgrade;
mod vectors;

use std::{error::Error, path::Path, process::ExitCode};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask must belong to the repository workspace")?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["check-contract"] => contract::check(root),
        ["check-no-downgrade", "--base", base] => downgrade::check(root, base),
        ["check-vectors"] => vectors::check(root),
        _ => Err("usage: cargo xtask check-contract | check-no-downgrade --base <rev> | check-vectors".into()),
    }
}
