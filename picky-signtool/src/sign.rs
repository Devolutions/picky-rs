use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use lief::{Binary, LogLevel};
use picky::key::PrivateKey;
use picky::x509::pkcs7::{authenticode::AuthenticodeSignature, Pkcs7};

use picky::hash::HashAlgorithm;

use crate::config::{
    ARG_BINARY, ARG_LOGGING, ARG_LOGGING_CRITICAL, ARG_LOGGING_DEBUG, ARG_LOGGING_ERR, ARG_LOGGING_INFO,
    ARG_LOGGING_TRACE, ARG_LOGGING_WARN, ARG_OUTPUT, ARG_PS_SCRIPT, CRLF, PS_AUTHENTICODE_FOOTER,
    PS_AUTHENTICODE_HEADER, PS_AUTHENTICODE_LINES_SPLITTER,
};
use clap::ArgMatches;

use picky::x509::pkcs7::authenticode::ShaVariant;
use picky::x509::wincert::{CertificateType, WinCertificate};

pub fn sign(matches: &ArgMatches, certfile: PathBuf, private_key: PathBuf, files: &[PathBuf]) -> anyhow::Result<()> {
    let certfile = read_file_into_vec(certfile)?;
    let private_key = read_file_into_vec(private_key)?;

    let private_key = PrivateKey::from_rsa_der(&private_key).context("Failed to parse RSA Private key")?;
    let pkcs7 = Pkcs7::from_der(&certfile).context("Failed to parse Pkcs7 certificate")?;

    if matches.is_present(ARG_PS_SCRIPT) {
        for ps_file in files.iter() {
            println!("Signing {:?}...", ps_file.as_path());

            sign_script(&pkcs7, &private_key, ps_file.as_path())?;

            println!("Signed {:?} successfully", ps_file.as_path());
        }

        return Ok(());
    }

    if matches.is_present(ARG_BINARY) {
        let file = files[0].clone();
        let output_path = matches
            .value_of(ARG_OUTPUT)
            .context("Output path for signed binary is not specified")?;

        let binary_name = file
            .as_path()
            .file_name()
            .map(|name| name.to_str())
            .flatten()
            .map(|name| name.to_owned())
            .expect("Binary file name should be present");

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

        println!("Signing {:?} ...", binary_name);

        sign_binary(
            &pkcs7,
            &private_key,
            file,
            PathBuf::from(output_path),
            binary_name.clone(),
        )?;

        println!("Signed {} successfully!", binary_name);
    }

    Ok(())
}

fn sign_script(pkcs7: &Pkcs7, private_key: &PrivateKey, file: &Path) -> anyhow::Result<()> {
    let checksum =
        compute_ps_file_checksum(file).with_context(|| format!("Failed to compute checksum for {:?}", file))?;

    let authenticode_signature =
        AuthenticodeSignature::new(&pkcs7, &checksum, ShaVariant::SHA2_256, &private_key, None)
            .with_context(|| format!("Failed to create authenticode signature for {:?}", file))?
            .to_pem()
            .context("Failed convert to authenticode signature to PEM format")?
            .to_string();

    let mut ps_authenticode_signature = String::new();
    ps_authenticode_signature.push_str(PS_AUTHENTICODE_HEADER);
    ps_authenticode_signature.push_str(CRLF);

    for line in authenticode_signature.lines() {
        ps_authenticode_signature.push_str(PS_AUTHENTICODE_LINES_SPLITTER);
        ps_authenticode_signature.push_str(line);
        ps_authenticode_signature.push_str(CRLF);
    }

    ps_authenticode_signature.push_str(PS_AUTHENTICODE_FOOTER);
    ps_authenticode_signature.push_str(CRLF);

    let mut file = OpenOptions::new()
        .append(true)
        .open(file)
        .with_context(|| format!("Failed to open {:?}", file))?;

    writeln!(file, "{}", ps_authenticode_signature)
        .with_context(|| format!("Failed to write PowerShell Authenticode signature to {:?}", file))
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

    let authenticode_signature = AuthenticodeSignature::new(
        &pkcs7,
        &file_hash,
        ShaVariant::SHA2_256,
        &private_key,
        Some(binary_name),
    )
    .context("Failed to create authenticode signature for")?
    .to_der()
    .context("Failed to convert authenticode signature to der")?;

    let wincert = WinCertificate::from_certificate(authenticode_signature, CertificateType::WinCertTypePkcsSignedData)
        .encode()
        .map_err(|err| anyhow!("Failed wrap authenticode signature in WinCertificate: {}", err))?;

    binary
        .set_authenticode_data(wincert)
        .map_err(|err| anyhow!("Failed to set authenticode data to target binary: {}", err))?;

    binary
        .build(output_path, false)
        .map_err(|err| anyhow!("Failed to build the signed executable, {}", err))
}

pub fn compute_ps_file_checksum<T: AsRef<Path>>(file_path: T) -> anyhow::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(file_path.as_ref())
        .with_context(|| format!("Failed to open {:?}", file_path.as_ref()))?;

    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("Failed to read {:?} contents", file_path.as_ref()))?;

    let mut buffer = Vec::with_capacity(contents.len() * 2);
    contents.as_str().encode_utf16().for_each(|word| {
        let bytes = word.to_le_bytes();
        buffer.push(bytes[0]);
        buffer.push(bytes[1]);
    });

    Ok(HashAlgorithm::SHA2_256.digest(&buffer))
}

pub fn read_file_into_vec<T: AsRef<Path>>(file_path: T) -> anyhow::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(file_path.as_ref())
        .with_context(|| format!("Failed to open {:?}", file_path.as_ref()))?;
    let mut data = Vec::new();

    file.read_to_end(&mut data)
        .with_context(|| format!("Failed to read {:?}", file_path.as_ref()))?;

    Ok(data)
}
