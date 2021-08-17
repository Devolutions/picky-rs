use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use clap::ArgMatches;
use encoding::DecoderTrap;
use lief::{Binary, LogLevel};

use picky::hash::HashAlgorithm;
use picky::key::PrivateKey;
use picky::x509::pkcs7::authenticode::{AuthenticodeSignature, ShaVariant};
use picky::x509::pkcs7::Pkcs7;
use picky::x509::wincert::{CertificateType, WinCertificate};

use crate::config::{
    ARG_BINARY, ARG_LOGGING, ARG_LOGGING_CRITICAL, ARG_LOGGING_DEBUG, ARG_LOGGING_ERR, ARG_LOGGING_INFO,
    ARG_LOGGING_TRACE, ARG_LOGGING_WARN, ARG_OUTPUT, ARG_PS_SCRIPT, CRLF, PS_AUTHENTICODE_FOOTER,
    PS_AUTHENTICODE_HEADER, PS_AUTHENTICODE_LINES_SPLITTER,
};
use crate::get_utf8_file_name;
use crate::verify::extract_signed_ps_file_content;
use picky::pem::Pem;

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
const UTF16_BE_BOM: [u8; 2] = [0xFE, 0xFF];
const UTF16_LE_BOM: [u8; 2] = [0xFF, 0xFE];

pub fn sign(
    matches: &ArgMatches,
    certfile_path: PathBuf,
    private_key_path: PathBuf,
    files: &[PathBuf],
) -> anyhow::Result<()> {
    let certfile = Pem::read_from(&mut BufReader::new(
        File::open(certfile_path.as_path())
            .with_context(|| format!("Failed to open: {:?}", certfile_path.as_path()))?,
    ))
    .context("Failed to read the certificate")?;

    let private_key = Pem::read_from(&mut BufReader::new(
        File::open(private_key_path.as_path())
            .with_context(|| format!("Failed to open: {:?}", private_key_path.as_path()))?,
    ))
    .context("Failed to read the private key")?;

    let private_key = PrivateKey::from_pem(&private_key).context("Failed to parse RSA Private key")?;
    let pkcs7 = Pkcs7::from_pem(&certfile).context("Failed to parse Pkcs7 certificate")?;

    if matches.is_present(ARG_PS_SCRIPT) {
        for ps_file in files.iter() {
            sign_script(&pkcs7, &private_key, ps_file.as_path())?;

            let file_name = get_utf8_file_name(ps_file.as_path())?;
            println!("Signed {} successfully", file_name);
        }

        return Ok(());
    }

    if matches.is_present(ARG_BINARY) {
        let file = files[0].clone();
        let output_path = matches
            .value_of(ARG_OUTPUT)
            .context("Output path for signed binary is not specified")?;

        let binary_name = get_utf8_file_name(file.as_path())?;

        match matches.value_of(ARG_LOGGING) {
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

        sign_binary(
            &pkcs7,
            &private_key,
            file.clone(),
            PathBuf::from(output_path),
            binary_name.to_owned(),
        )?;

        println!("Signed {} successfully!", binary_name);
    }

    Ok(())
}

fn sign_script(pkcs7: &Pkcs7, private_key: &PrivateKey, file_path: &Path) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .read(true)
        .open(file_path)
        .with_context(|| format!("Failed to open {:?}", file_path))?;

    let checksum = compute_ps_file_checksum_from_content(file_path, HashAlgorithm::SHA2_256)
        .with_context(|| format!("Failed to compute checksum for {:?}", file))?;

    let authenticode_signature = AuthenticodeSignature::new(pkcs7, checksum, ShaVariant::SHA2_256, private_key, None)
        .with_context(|| format!("Failed to create authenticode signature for {:?}", file))?
        .to_pem()
        .context("Failed convert to authenticode signature to PEM format")?
        .to_string();

    let mut ps_authenticode_signature = String::new();
    ps_authenticode_signature.push_str(CRLF);
    ps_authenticode_signature.push_str(PS_AUTHENTICODE_HEADER);
    ps_authenticode_signature.push_str(CRLF);

    for line in authenticode_signature.lines() {
        if line != "-----END PKCS7-----" && line != "-----BEGIN PKCS7-----" {
            ps_authenticode_signature.push_str(PS_AUTHENTICODE_LINES_SPLITTER);
            ps_authenticode_signature.push_str(line);
            ps_authenticode_signature.push_str(CRLF);
        }
    }

    ps_authenticode_signature.push_str(PS_AUTHENTICODE_FOOTER);

    writeln!(file, "{}", ps_authenticode_signature)
        .with_context(|| format!("Failed to write PowerShell Authenticode signature to {:?}", file_path))
}

fn sign_binary(
    pkcs7: &Pkcs7,
    private_key: &PrivateKey,
    binary_path: PathBuf,
    output_path: PathBuf,
    binary_name: String,
) -> anyhow::Result<()> {
    let binary = Binary::new(binary_path).map_err(|err| anyhow!("Failed to load the executable: {}", err))?;

    let file_hash = binary
        .get_file_hash_sha256()
        .map_err(|err| anyhow!("Failed to compute file hash: {}", err))?;

    let authenticode_signature =
        AuthenticodeSignature::new(pkcs7, file_hash, ShaVariant::SHA2_256, private_key, Some(binary_name))
            .context("Failed to create authenticode signature for")?
            .to_der()
            .context("Failed to convert authenticode signature to der")?;

    let wincert = WinCertificate::from_certificate(authenticode_signature, CertificateType::WinCertTypePkcsSignedData)
        .encode()
        .map_err(|err| anyhow!("Failed to wrap authenticode signature in WinCertificate: {}", err))?;

    binary
        .set_authenticode_data(wincert)
        .map_err(|err| anyhow!("Failed to set authenticode data to target binary: {}", err))?;

    binary
        .build(output_path, false)
        .map_err(|err| anyhow!("Failed to build the signed executable, {}", err))
}

// PowerShell file checksum is encoded in Utf16-Le encoding
pub fn compute_ps_file_checksum_from_content(path: &Path, hash: HashAlgorithm) -> anyhow::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("Failed to open {:?} for reading", path))?;

    let mut content_buffer = Vec::new();
    file.read_to_end(&mut content_buffer).unwrap();

    let (decoded, _) = encoding::decode(
        &content_buffer,
        DecoderTrap::Strict,
        encoding::all::UTF_8 as encoding::EncodingRef,
    );

    let raw_content = decoded.map_err(|err| anyhow!("Failed to decoded {:?} ps file: {}", path, err))?;

    let content = extract_signed_ps_file_content(raw_content);

    let mut buffer = Vec::with_capacity(content.len() * 2);

    // We need to add Utf16-Le BOM([0xFF, 0xFE]) to the target buffer to produce right PowerShell file checksum
    // if the file has a BOM
    if content_buffer.starts_with(&UTF16_LE_BOM)
        || content_buffer.starts_with(&UTF8_BOM)
        || content_buffer.starts_with(&UTF16_BE_BOM)
    {
        buffer.extend_from_slice(&UTF16_LE_BOM);
    }

    content.as_str().encode_utf16().for_each(|word| {
        let bytes = word.to_le_bytes();
        buffer.push(bytes[0]);
        buffer.push(bytes[1]);
    });

    Ok(hash.digest(&buffer))
}
