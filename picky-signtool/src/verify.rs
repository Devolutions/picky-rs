use std::convert::TryFrom;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use clap::ArgMatches;
use encoding::DecoderTrap;
use lief::Binary;

use picky::hash::HashAlgorithm;
use picky::x509::date::UTCDate;
use picky::x509::pkcs7::authenticode::{AuthenticodeSignature, AuthenticodeValidator, ShaVariant};
use picky::x509::wincert::WinCertificate;

use crate::config::{
    ARG_BINARY, ARG_PS_SCRIPT, ARG_VERIFY, ARG_VERIFY_BASIC, ARG_VERIFY_CA, ARG_VERIFY_CHAIN,
    ARG_VERIFY_SIGNING_CERTIFICATE, PS_AUTHENTICODE_FOOTER, PS_AUTHENTICODE_HEADER, PS_AUTHENTICODE_LINES_SPLITTER,
};
use crate::get_utf8_file_name;
use crate::sign::compute_ps_file_checksum_from_content;

pub fn verify(matches: &ArgMatches, files: &[PathBuf]) -> anyhow::Result<()> {
    let flags = matches
        .values_of(ARG_VERIFY)
        .unwrap()
        .map(ToString::to_string)
        .collect::<Vec<String>>();

    let authenticode_signatures = match (matches.is_present(ARG_BINARY), matches.is_present(ARG_PS_SCRIPT)) {
        (true, false) => {
            let binary_path = files[0].clone();
            let binary =
                Binary::new(binary_path.clone()).map_err(|err| anyhow!("Failed to load the executable: {}", err))?;

            let authenticode_signature = extract_authenticode_signature_from_binary(&binary)?;
            let binary_name = get_utf8_file_name(&binary_path)?;
            let file_hash = binary
                .get_file_hash_sha256()
                .map_err(|err| anyhow!("Failed to compute file hash for target binary: {}", err.to_string()))?;

            vec![(authenticode_signature, binary_name.to_owned(), file_hash)]
        }
        (false, true) => {
            let mut authenticode_signatures = Vec::with_capacity(files.len());

            for file_path in files {
                let authenticode_signature = match authenticode_signature_ps_from_file(file_path) {
                    Ok(authenticode_signature) => authenticode_signature,
                    Err(err) => {
                        eprintln!("{} -> {}\n", err.to_string(), err.root_cause());
                        continue;
                    }
                };

                let algorithm_identifier_oid = authenticode_signature
                    .0
                    .digest_algorithms()
                    .first()
                    .expect("AlgorithmIdentifier should be present")
                    .oid_asn1()
                    .clone();

                let sha_variant = ShaVariant::try_from(algorithm_identifier_oid)
                    .with_context(|| format!("Failed compute checksum for {:?}", file_path))?;

                let hash = HashAlgorithm::try_from(sha_variant)
                    .with_context(|| format!("Failed compute checksum for {:?}", file_path))?;

                let ps_file_name = get_utf8_file_name(file_path.as_path())?;

                let file_hash = compute_ps_file_checksum_from_content(file_path, hash)
                    .with_context(|| format!("Failed to compute {:?} checksum for {:?}", hash, file_path.as_path()))?;

                authenticode_signatures.push((authenticode_signature, ps_file_name.to_owned(), file_hash))
            }
            authenticode_signatures
        }
        (true, true) => bail!("Do not know what to verify exactly(`binary` and `script` both are specified)"),
        (false, false) => bail!("Do not know what to verify(`binary` or `script` is not specified)"),
    };

    let flags = flags
        .iter()
        .filter(|flag| match flag.as_str() {
            ARG_VERIFY_BASIC | ARG_VERIFY_SIGNING_CERTIFICATE | ARG_VERIFY_CHAIN | ARG_VERIFY_CA => true,
            other => {
                eprintln!("Skipping unknown flag `{}`", other);
                false
            }
        })
        .cloned()
        .collect::<Vec<String>>();

    for (authenticode_signature, file_name, file_hash) in authenticode_signatures {
        let validator = authenticode_signature.authenticode_verifier();

        let now = UTCDate::now();
        let validator = apply_flags(&validator, &flags, &now, file_hash);

        match validator.verify() {
            Ok(()) => println!("{} has valid digital signature", file_name),
            Err(err) => eprintln!("{} has invalid digital signature: {}", file_name, err.to_string()),
        }
    }

    Ok(())
}

fn extract_authenticode_signature_from_binary(binary: &Binary) -> anyhow::Result<AuthenticodeSignature> {
    let authenticode_data = binary
        .get_authenticode_data()
        .map_err(|err| anyhow!("Failed to extract Authenticode signature from target binary: {}", err))?;

    let wincert = WinCertificate::decode(&authenticode_data)
        .map_err(|err| anyhow!("Failed to decode authenticode data: {}", err))?;

    let authenticode_signature = AuthenticodeSignature::from_der(wincert.get_certificate())
        .context("Failed to deserialize Authenticode signature")?;

    Ok(authenticode_signature)
}

pub fn authenticode_signature_ps_from_file(file_path: &Path) -> anyhow::Result<AuthenticodeSignature> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(file_path)
        .with_context(|| format!("Failed to open {:?} for reading", file_path))?;

    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    let (decoded, _) = encoding::decode(
        &buffer,
        DecoderTrap::Strict,
        encoding::all::UTF_8 as encoding::EncodingRef,
    );

    let buffer = decoded.map_err(|err| anyhow!("Failed to decoded {:?} ps file: {}", file_path, err))?;

    let signature = extract_ps_authenticode_signature(buffer)
        .with_context(|| format!("Failed to extract Authenticode signature from {:?}", file_path))?;

    let der_signature = base64::decode(signature).context("Failed to convert signature to DER")?;

    let authenticode_signature = AuthenticodeSignature::from_der(&der_signature)
        .with_context(|| format!("Failed to deserialize Authenticode signature for {:?}", file_path))?;

    Ok(authenticode_signature)
}

fn extract_ps_authenticode_signature(content: String) -> anyhow::Result<String> {
    let index = content
        .find(PS_AUTHENTICODE_HEADER)
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
    file_hash: Vec<u8>,
) -> &'a AuthenticodeValidator<'a> {
    let validator = validator
        .ignore_basic_authenticode_validation()
        .ignore_signing_certificate_check()
        .ignore_chain_check()
        .ignore_ca_against_ctl_check()
        .ignore_not_before_check()
        .ignore_not_after_check()
        .ignore_excluded_cert_authorities();

    let validator = if flags.iter().any(|flag| flag.as_str() == ARG_VERIFY_BASIC) {
        validator.require_basic_authenticode_validation(file_hash)
    } else {
        &validator
    };

    let validator = if flags.iter().any(|flag| flag.as_str() == ARG_VERIFY_SIGNING_CERTIFICATE) {
        validator
            .require_signing_certificate_check()
            .require_not_after_check()
            .require_not_before_check()
            .require_chain_check()
            .exact_date(time)
    } else {
        &validator
    };

    let validator = if flags.iter().any(|flag| flag.as_str() == ARG_VERIFY_CHAIN) {
        validator.require_chain_check()
    } else {
        &validator
    };

    if flags.iter().any(|flag| flag.as_str() == ARG_VERIFY_CA) {
        validator.require_ca_against_ctl_check()
    } else {
        validator
    }
}

pub fn extract_signed_ps_file_content(raw_content: String) -> String {
    let end = match raw_content.find(PS_AUTHENTICODE_HEADER) {
        Some(index) => index - 2, // -2 to remove \r\n from the `# SIG # Begin signature block` line
        None => return raw_content,
    };

    let (raw_content, _) = raw_content.split_at(end);
    raw_content.to_string()
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
