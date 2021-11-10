use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context};
use clap::ArgMatches;
use lief::Binary;

use picky::hash::HashAlgorithm;
use picky::key::PrivateKey;
use picky::x509::pkcs7::authenticode::{AuthenticodeSignature, ShaVariant};
use picky::x509::pkcs7::timestamp::Timestamper;
use picky::x509::pkcs7::Pkcs7;
use picky::x509::wincert::{CertificateType, WinCertificate};

use crate::config::{
    ARG_BINARY, ARG_OUTPUT, ARG_PS_SCRIPT, ARG_TIMESTAMP, CRLF, PS_AUTHENTICODE_FOOTER, PS_AUTHENTICODE_HEADER,
    PS_AUTHENTICODE_LINES_SPLITTER,
};

use crate::get_utf8_file_name;
use crate::utils::str_to_utf16_bytes;
use crate::verify::extract_signed_ps_file_content_bytes;
use picky::pem::Pem;
use picky::x509::pkcs7::timestamp::http_timestamp::AuthenticodeTimestamper;

pub const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
pub const UTF16_BE_BOM: [u8; 2] = [0xFE, 0xFF];
pub const UTF16_LE_BOM: [u8; 2] = [0xFF, 0xFE];

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

    let timestamper = if let Some(url) = matches.value_of(ARG_TIMESTAMP) {
        Some(AuthenticodeTimestamper::new(url)?)
    } else {
        None
    };

    if matches.is_present(ARG_PS_SCRIPT) {
        for ps_file in files.iter() {
            sign_script(&pkcs7, &private_key, ps_file.as_path(), timestamper.as_ref())?;

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

        sign_binary(
            &pkcs7,
            &private_key,
            file.clone(),
            PathBuf::from(output_path),
            binary_name.to_owned(),
            timestamper.as_ref(),
        )?;

        println!("Signed {} successfully!", binary_name);
    }

    Ok(())
}

fn sign_script(
    pkcs7: &Pkcs7,
    private_key: &PrivateKey,
    file_path: &Path,
    timestamper: Option<&impl Timestamper>,
) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .read(true)
        .open(file_path)
        .with_context(|| format!("Failed to open {:?}", file_path))?;

    let checksum = compute_ps_file_checksum_from_content(file_path, HashAlgorithm::SHA2_256)
        .with_context(|| format!("Failed to compute checksum for {:?}", file))?;

    let mut authenticode_signature =
        AuthenticodeSignature::new(pkcs7, checksum, ShaVariant::SHA2_256, private_key, None)
            .with_context(|| format!("Failed to create authenticode signature for {:?}", file))?;

    if timestamper.is_some() {
        authenticode_signature.timestamp(timestamper.unwrap(), HashAlgorithm::SHA2_256)?;
    }

    let raw_authenticode_signature = authenticode_signature
        .to_pem()
        .context("Failed convert to authenticode signature to PEM format")?
        .to_string();

    let mut ps_authenticode_signature = String::new();
    ps_authenticode_signature.push_str(CRLF);
    ps_authenticode_signature.push_str(PS_AUTHENTICODE_HEADER);
    ps_authenticode_signature.push_str(CRLF);

    for line in raw_authenticode_signature.lines() {
        if line != "-----END PKCS7-----" && line != "-----BEGIN PKCS7-----" {
            ps_authenticode_signature.push_str(PS_AUTHENTICODE_LINES_SPLITTER);
            ps_authenticode_signature.push_str(line);
            ps_authenticode_signature.push_str(CRLF);
        }
    }

    ps_authenticode_signature.push_str(PS_AUTHENTICODE_FOOTER);
    ps_authenticode_signature.push_str(CRLF);

    let mut buffer = Vec::with_capacity(ps_authenticode_signature.len() * 2);

    let mut bom_buffer = [0u8; 2];
    file.read_exact(&mut bom_buffer)
        .with_context(|| format!("Failed to detect BOM of {:?}", file_path))?;

    // We need to write authenticate signature in the same encoding as the file is
    if bom_buffer.starts_with(&UTF16_LE_BOM) || bom_buffer.starts_with(&UTF16_BE_BOM) {
        str_to_utf16_bytes(ps_authenticode_signature.as_str(), &mut buffer);
    } else {
        buffer.extend_from_slice(ps_authenticode_signature.as_bytes());
    }

    file.write_all(&buffer)
        .with_context(|| format!("Failed to write PowerShell Authenticode signature to {:?}", file_path))
}

fn sign_binary(
    pkcs7: &Pkcs7,
    private_key: &PrivateKey,
    binary_path: PathBuf,
    output_path: PathBuf,
    binary_name: String,
    timestamper: Option<&impl Timestamper>,
) -> anyhow::Result<()> {
    let binary = Binary::new(binary_path).map_err(|err| anyhow!("Failed to load the executable: {}", err))?;

    let file_hash = binary
        .get_file_hash_sha256()
        .map_err(|err| anyhow!("Failed to compute file hash: {}", err))?;

    let mut authenticode_signature =
        AuthenticodeSignature::new(pkcs7, file_hash, ShaVariant::SHA2_256, private_key, Some(binary_name))
            .context("Failed to create authenticode signature for")?;

    if timestamper.is_some() {
        authenticode_signature.timestamp(timestamper.unwrap(), HashAlgorithm::SHA2_256)?;
    }

    let raw_authenticode_signature = authenticode_signature
        .to_der()
        .context("Failed to convert authenticode signature to der")?;

    let wincert =
        WinCertificate::from_certificate(raw_authenticode_signature, CertificateType::WinCertTypePkcsSignedData)
            .encode()
            .map_err(|err| anyhow!("Failed to wrap authenticode signature in WinCertificate: {}", err))?;

    binary
        .set_authenticode_data(wincert)
        .map_err(|err| anyhow!("Failed to set authenticode data to target binary: {}", err))?;

    binary
        .build(output_path, false)
        .map_err(|err| anyhow!("Failed to build the signed executable, {}", err))
}

// PowerShell file checksum is encoded in Utf16-LE encoding
pub fn compute_ps_file_checksum_from_content(path: &Path, hash: HashAlgorithm) -> anyhow::Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("Failed to open {:?} for reading", path))?;

    let mut content_buffer = Vec::new();
    file.read_to_end(&mut content_buffer).unwrap();

    let bytes_utf16 = if content_buffer.starts_with(&UTF8_BOM) {
        // decode as UTF-8 with replacing invalid characters with �
        let (content, ..) = encoding_rs::UTF_8.decode(&content_buffer);

        let mut buff = Vec::with_capacity(UTF16_LE_BOM.len() + content.len() * 2);
        buff.extend_from_slice(&UTF16_LE_BOM);
        str_to_utf16_bytes(content.as_ref(), &mut buff);
        buff
    } else if content_buffer.starts_with(&UTF16_LE_BOM) {
        content_buffer
    } else {
        // if our file does not have any BOM then we parse it as UTF-8, if it is valid, or as Windows 1252, if it is not UTF-8
        match std::str::from_utf8(&content_buffer) {
            Ok(content) => {
                let mut buff = Vec::with_capacity(content.len() * 2);
                str_to_utf16_bytes(content, &mut buff);
                buff
            }
            Err(_) => {
                let (content, ..) = encoding_rs::WINDOWS_1252.decode(&content_buffer);
                let mut buff = Vec::with_capacity(content.len() * 2);
                str_to_utf16_bytes(content.as_ref(), &mut buff);
                buff
            }
        }
    };

    let buffer_content = extract_signed_ps_file_content_bytes(&bytes_utf16);

    Ok(hash.digest(buffer_content))
}

#[cfg(test)]
pub mod tests {
    use crate::sign::compute_ps_file_checksum_from_content;
    use picky::hash::HashAlgorithm;
    use std::fs::{remove_file, File};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn write_to_temp_file(data: &[u8]) -> PathBuf {
        let since_the_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let filename = std::env::temp_dir().join(format!("temp.{}.psd1", since_the_epoch.as_nanos()));
        let mut file = File::create(&filename).unwrap();
        file.write_all(data).unwrap();
        file.flush().unwrap();
        filename
    }

    fn remove_temp_file(filename: &PathBuf) {
        remove_file(filename).unwrap();
    }

    fn string_hex_to_bytes(hash: &str) -> Vec<u8> {
        hash.chars()
            .collect::<Vec<char>>()
            .chunks(2)
            .map(|c| c.iter().collect::<String>())
            .map(|n| u8::from_str_radix(&n, 16).unwrap())
            .collect::<Vec<u8>>()
    }

    #[test]
    fn hash_valid_utf16() {
        // not all characters in examples are readable
        let file_data = [
            0xFF, 0xFE, 0x23, 0x00, 0x20, 0x00, 0x53, 0x00, 0x63, 0x00, 0x72, 0x00, 0x69, 0x00, 0x70, 0x00, 0x74, 0x00,
            0x20, 0x00, 0x6D, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x75, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x20, 0x00, 0x6F, 0x00,
            0x72, 0x00, 0x20, 0x00, 0x62, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x61, 0x00, 0x72, 0x00, 0x79, 0x00, 0x20, 0x00,
            0x6D, 0x00, 0x6F, 0x00, 0x64, 0x00, 0x75, 0x00, 0x6C, 0x00, 0x65, 0x00, 0x0D, 0x00, 0x0A, 0x00,
        ];
        let filename = write_to_temp_file(&file_data);
        let expected_hash = string_hex_to_bytes("94BAF89A8396E99AB8D183979CEA4C529C0DF118DBB65D51DCA80DC5EF9AD4F6");

        let file_hash = compute_ps_file_checksum_from_content(Path::new(&filename), HashAlgorithm::SHA2_256).unwrap();

        remove_temp_file(&filename);
        assert_eq!(file_hash, expected_hash);
    }

    #[test]
    fn hash_invalid_utf16() {
        let file_data = [
            255, 254, 35, 0, 32, 0, 83, 0, 99, 0, 114, 0, 105, 0, 112, 0, 116, 0, 32, 0, 109, 0, 111, 0, 100, 0, 117,
            0, 108, 0, 101, 0, 32, 0, 111, 0, 114, 220, 32, 0, 98, 0, 105, 0, 110, 0, 97, 0, 114, 0, 121, 0, 32, 0,
            109, 0, 111, 0, 100, 0, 117, 0, 108, 0, 101, 0, 13, 0, 10, 0,
        ];
        let filename = write_to_temp_file(&file_data);
        let expected_hash = string_hex_to_bytes("B7E7A76A5F05B18B468D0BB9B70ED65438DB607B4FF2910D2B9FC7CFFE277C08");

        let file_hash = compute_ps_file_checksum_from_content(Path::new(&filename), HashAlgorithm::SHA2_256).unwrap();

        remove_temp_file(&filename);
        assert_eq!(file_hash, expected_hash);
    }

    #[test]
    fn hash_valid_utf8_with_bom() {
        let file_data = [
            0xEF, 0xBB, 0xBF, 0x23, 0x20, 0x53, 0x65, 0x65, 0x22, 0x20, 0xC2, 0x96, 0x6D, 0x6F, 0x64, 0x75, 0x6C, 0x65,
            0x0D, 0x0A,
        ];
        let filename = write_to_temp_file(&file_data);
        let expected_hash = string_hex_to_bytes("7A4640B752BE1FF7A0F46131C98E1D9419CA6061A5EF0F49BA73FF7C6C8109D0");

        let file_hash = compute_ps_file_checksum_from_content(Path::new(&filename), HashAlgorithm::SHA2_256).unwrap();

        remove_temp_file(&filename);
        assert_eq!(file_hash, expected_hash);
    }

    #[test]
    fn hash_invalid_utf8_with_bom() {
        let file_data = [
            0xEF, 0xBB, 0xBF, 0x23, 0x20, 0x53, 0x96, 0x65, 0x22, 0x20, 0xE2, 0x96, 0x6D, 0x6F, 0x54, 0x75, 0x6C, 0x65,
            0x0D, 0x0A,
        ];
        let filename = write_to_temp_file(&file_data);
        let expected_hash = string_hex_to_bytes("AB5999547F444B507298791C1AC1C9B9DA87B87A34C9529FBECCC43BE321DECF");

        let file_hash = compute_ps_file_checksum_from_content(Path::new(&filename), HashAlgorithm::SHA2_256).unwrap();

        remove_temp_file(&filename);
        assert_eq!(file_hash, expected_hash);
    }

    #[test]
    fn hash_valid_utf8_without_bom() {
        let file_data = [
            0x23, 0x20, 0x53, 0x65, 0x65, 0x22, 0x20, 0xE2, 0x97, 0x8E, 0x6F, 0x64, 0x75, 0x6C, 0x65, 0x0D, 0x0A,
        ];
        let filename = write_to_temp_file(&file_data);
        let expected_hash = string_hex_to_bytes("1719FE80516E870F367ED5E6AFD363A66B3CF394867952392ABDE8284BAD8494");

        let file_hash = compute_ps_file_checksum_from_content(Path::new(&filename), HashAlgorithm::SHA2_256).unwrap();

        remove_temp_file(&filename);
        assert_eq!(file_hash, expected_hash);
    }

    #[test]
    fn hash_invalid_utf8_without_bom() {
        let file_data = [
            0x23, 0x20, 0x53, 0x65, 0x65, 0xC2, 0x20, 0x74, 0x20, 0x6D, 0x88, 0x64, 0x75, 0x6C, 0x96, 0x0D, 0x0A,
        ];
        let filename = write_to_temp_file(&file_data);
        let expected_hash = string_hex_to_bytes("2EDAEA35E4F86B52E74185D43222B68A524CF55EF132DAA1D751AE46F5F3ED20");

        let file_hash = compute_ps_file_checksum_from_content(Path::new(&filename), HashAlgorithm::SHA2_256).unwrap();

        remove_temp_file(&filename);
        assert_eq!(file_hash, expected_hash);
    }
}
