use std::fs::OpenOptions;
use std::io::Read;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context};
use lief::Binary;

use crate::config::{
    ARG_BINARY, ARG_PS_SCRIPT, ARG_VERIFY, ARG_VERIFY_CA, ARG_VERIFY_DEFAULT, ARG_VERIFY_SIGNING_CERTIFICATE,
    PS_AUTHENTICODE_FOOTER, PS_AUTHENTICODE_HEADER, PS_AUTHENTICODE_LINES_SPLITTER,
};
use clap::ArgMatches;
use picky::x509::date::UTCDate;
use picky::x509::pkcs7::authenticode::{AuthenticodeSignature, AuthenticodeValidator};
use picky::x509::wincert::WinCertificate;

pub fn verify(matches: &ArgMatches, files: &[PathBuf]) -> anyhow::Result<()> {
    let flags = matches
        .values_of(ARG_VERIFY)
        .unwrap()
        .map(ToString::to_string)
        .collect::<Vec<String>>();

    let authenticode_signatures = match (matches.is_present(ARG_BINARY), matches.is_present(ARG_PS_SCRIPT)) {
        (true, false) => {
            let binary_path = files[0].clone();
            let authenticode_signature = extract_authenticode_signature_from_binary(binary_path)?;
            vec![authenticode_signature]
        }
        (false, true) => extract_authenticode_signature_ps_files(files)?,
        (true, true) => bail!("Do not know what to verify exactly(`binary` and `script` both are specified)"),
        (false, false) => bail!("Do not know what to verify(`binary` or `script` is not specified)"),
    };

    let flags = flags
        .iter()
        .filter(|flag| match flag.as_str() {
            ARG_VERIFY_DEFAULT | ARG_VERIFY_SIGNING_CERTIFICATE | ARG_VERIFY_CA => true,
            other => {
                println!("Skipping unknown flag `{}`", other);
                false
            }
        })
        .cloned()
        .collect::<Vec<String>>();

    for (authenticode_signature, file_name) in authenticode_signatures {
        let validator = authenticode_signature.authenticode_verifier();

        let now = UTCDate::now();
        let validator = apply_flags(&validator, &flags, &now);

        match validator.verify() {
            Ok(()) => println!("{} has valid digital signature", file_name),
            Err(err) => println!("{} has invalid digital signature: {}", file_name, err.to_string()),
        }
    }

    Ok(())
}

fn extract_authenticode_signature_from_binary(binary_path: PathBuf) -> anyhow::Result<(AuthenticodeSignature, String)> {
    let binary = Binary::new(binary_path.clone()).map_err(|err| anyhow!("Failed to load the executable: {}", err))?;

    let authenticode_data = binary
        .get_authenticode_data()
        .map_err(|err| anyhow!("Failed to extract Authenticode signature from target binary: {}", err))?;

    let wincert = WinCertificate::decode(&authenticode_data)
        .map_err(|err| anyhow!("Failed to decode authenticode data: {}", err))?;

    let authenticode_signature = AuthenticodeSignature::from_der(wincert.get_certificate())
        .context("Failed to deserialize Authenticode signature")?;

    let binary_name = binary_path
        .as_path()
        .file_name()
        .map(|name| name.to_str())
        .flatten()
        .map(|name| name.to_owned())
        .expect("Binary file name should be present");

    Ok((authenticode_signature, binary_name))
}

pub fn extract_authenticode_signature_ps_files(
    ps_files: &[PathBuf],
) -> anyhow::Result<Vec<(AuthenticodeSignature, String)>> {
    let mut authenticode_signatures = Vec::with_capacity(ps_files.len());

    for file_path in ps_files {
        let mut file = OpenOptions::new()
            .read(true)
            .open(file_path.as_path())
            .with_context(|| format!("Failed to open {:?} for reading", file_path))?;

        let mut buffer = String::new();
        file.read_to_string(&mut buffer)
            .with_context(|| format!("Failed to read {:?}", file_path))?;

        let signature = extract_ps_authenticode_signature(buffer)
            .with_context(|| format!("Failed to extract Authenticode signature from {:?}", file_path))?;

        let der_signature = base64::decode(signature).context("Failed to convert signature to DER")?;

        let authenticode_signature = AuthenticodeSignature::from_der(&der_signature)
            .with_context(|| format!("Failed to deserialize Authenticode signature for {:?}", file_path))?;

        let file_name = file_path
            .as_path()
            .file_name()
            .map(|name| name.to_str())
            .flatten()
            .map(|name| name.to_owned())
            .expect("Binary file name should be present");

        authenticode_signatures.push((authenticode_signature, file_name));
    }

    Ok(authenticode_signatures)
}

fn extract_ps_authenticode_signature(content: String) -> anyhow::Result<String> {
    let index = content
        .find(PS_AUTHENTICODE_LINES_SPLITTER)
        .ok_or_else(|| anyhow!("File is not digital signed"))?;

    let (_, signature) = content.split_at(index);
    let mut out = String::new();
    for line in signature.lines() {
        if line.contains(PS_AUTHENTICODE_HEADER) || line.contains(PS_AUTHENTICODE_FOOTER) {
            continue;
        }

        if line.contains(PS_AUTHENTICODE_LINES_SPLITTER) {
            out.push_str(line.replace(PS_AUTHENTICODE_LINES_SPLITTER, "").trim_end_matches('\r'));
        }
    }

    Ok(out)
}

fn apply_flags<'a>(
    validator: &'a AuthenticodeValidator<'a>,
    flags: &[String],
    time: &'a UTCDate,
) -> &'a AuthenticodeValidator<'a> {
    let validator = if flags.iter().any(|flag| flag.as_str() == ARG_VERIFY_DEFAULT) {
        validator.require_basic_authenticode_validation()
    } else {
        &validator
    };

    let validator = if flags.iter().any(|flag| flag.as_str() == ARG_VERIFY_SIGNING_CERTIFICATE) {
        validator
            .require_signing_certificate_check()
            .require_not_after_check()
            .require_not_before_check()
            .exact_date(&time)
    } else {
        &validator
    };

    if flags.iter().any(|flag| flag.as_str() == ARG_VERIFY_CA) {
        validator.require_ca_against_ctl_check()
    } else {
        &validator
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_to_extract_ps_authenticode_signature() {
        let ps_authenticode_signature = "                     # SIG # Begin signature block\r\n# MIIFjAYJKoZIhvcNAQcCoIIFfTCCBXkCAQExDzANBglghkgBZQMEAgEFADB5Bgor\r\n# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG\r\n# SIG # End signature block\r\n";

        let ps_authenticode_signature =
            extract_ps_authenticode_signature(ps_authenticode_signature.to_string()).unwrap();
        assert_eq!(ps_authenticode_signature.as_str(), "MIIFjAYJKoZIhvcNAQcCoIIFfTCCBXkCAQExDzANBglghkgBZQMEAgEFADB5BgorBgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG");
    }
}
