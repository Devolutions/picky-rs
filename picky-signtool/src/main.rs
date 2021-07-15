use std::path::{Path, PathBuf};

use anyhow::bail;
use picky_signtool::{config::*, sign::sign, verify::verify};
use walkdir::{DirEntry, WalkDir};

fn main() -> anyhow::Result<()> {
    let matches = config();

    let files_to_process: Vec<PathBuf> = match (matches.is_present(ARG_BINARY), matches.is_present(ARG_PS_SCRIPT)) {
        (true, false) => {
            let binary_path = matches
                .value_of(ARG_INPUT)
                .expect("Path to a Windows executable is required");

            vec![PathBuf::from(binary_path)]
        }
        (false, true) => {
            let ps_file = matches
                .value_of(ARG_SCRIPT_PATH)
                .expect("The PowerShell file path was not specified");

            let ps_file = Path::new(ps_file);
            match ps_file.extension().map(|ext| ext.to_str()).flatten() {
                Some("ps1") => {
                    vec![ps_file.to_path_buf()]
                }
                Some("psm1") => {
                    let is_ps_file = |entry: &DirEntry| -> bool {
                        entry
                            .file_name()
                            .to_str()
                            .map(|s| s.ends_with(".ps1") || s.ends_with(".psm1") || s.ends_with(".psd1"))
                            .unwrap_or(false)
                    };

                    WalkDir::new(ps_file)
                        .into_iter()
                        .filter_entry(|entry| !is_ps_file(entry))
                        .filter_map(|entry| entry.ok().map(|entry| entry.into_path()))
                        .collect::<Vec<PathBuf>>()
                }
                _ => bail!("Unexpected PowerShell file type was specified"),
            }
        }
        (true, true) => bail!("Do not know what to process exactly(`binary` and `script` both are specified)"),
        (false, false) => bail!("Do not known what to process(`binary` or `script` is not specified)"),
    };

    if matches.is_present(ARG_SIGN) && !files_to_process.is_empty() {
        if let (Some(certfile), Some(private_key)) = (matches.value_of(ARG_CERTFILE), matches.value_of(ARG_PRIVATE_KEY))
        {
            sign(
                &matches,
                PathBuf::from(certfile),
                PathBuf::from(private_key),
                &files_to_process,
            )?;
        }
    }

    if matches.is_present(ARG_VERIFY) && !files_to_process.is_empty() {
        verify(&matches, &files_to_process)?
    }

    Ok(())
}
