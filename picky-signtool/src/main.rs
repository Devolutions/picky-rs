use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg, ArgMatches};
use lief::{Binary, LogLevel, VerificationChecks};

const ARG_INPUT: &str = "input";
const ARG_OUTPUT: &str = "output";
const ARG_SIGN: &str = "sign";
const ARG_CERTFILE: &str = "certfile";
const ARG_PRIVATE_KEY: &str = "private-key";

const ARG_VERIFY: &str = "verify";
const ARG_VERIFY_DEFAULT: &str = "default";
const ARG_VERIFY_HASH_ONLY: &str = "hash-only";
const ARG_VERIFY_LIFETIME_SIGNING: &str = "lifetime-signing";
const ARG_VERIFY_SKIP_CERT_TIME: &str = "skip-cert-time";

const ARG_LOGGING: &str = "logging";
const ARG_LOGGING_TRACE: &str = "trace";
const ARG_LOGGING_DEBUG: &str = "debug";
const ARG_LOGGING_INFO: &str = "info";
const ARG_LOGGING_WARN: &str = "warn";
const ARG_LOGGING_ERR: &str = "err";
const ARG_LOGGING_CRITICAL: &str = "critical";

fn main() -> anyhow::Result<()> {
    let matches = config();

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

    let binary_path = matches
        .value_of(ARG_INPUT)
        .expect("Path to a Windows executable is required");

    let binary_path = PathBuf::from(binary_path);
    let binary_name = binary_path
        .as_path()
        .file_name()
        .map(|name| name.to_str())
        .flatten()
        .map(|name| name.to_owned())
        .expect("file name should be present");

    let binary = Binary::new(binary_path).map_err(|err| anyhow!("Failed to load the executable: {}", err))?;

    if let Some(verification_checks) = matches.value_of(ARG_VERIFY) {
        let check_flag = match verification_checks {
            ARG_VERIFY_DEFAULT => VerificationChecks::DEFAULT,
            ARG_VERIFY_HASH_ONLY => VerificationChecks::HASH_ONLY,
            ARG_VERIFY_LIFETIME_SIGNING => VerificationChecks::LIFETIME_SIGNING,
            ARG_VERIFY_SKIP_CERT_TIME => VerificationChecks::SKIP_CERT_TIME,
            _ => unreachable!("Unexpected verification option"),
        };

        let check_result = binary
            .check_signature(check_flag)
            .map_err(|err| anyhow!("Failed to check signature: {}", err))?;

        println!("Verify the executable signature result: {:?}", check_result);
    }

    if matches.is_present(ARG_SIGN) {
        if let (Some(certfile), Some(private_key), Some(output_path)) = (
            matches.value_of(ARG_CERTFILE),
            matches.value_of(ARG_PRIVATE_KEY),
            matches.value_of(ARG_OUTPUT),
        ) {
            let certfile = read_file_into_vec(PathBuf::from(certfile))?;
            let private_key = read_file_into_vec(PathBuf::from(private_key))?;

            binary
                .set_authenticode(certfile, private_key, Some(binary_name.clone()))
                .map_err(|err| anyhow!("Failed to check signature: {}", err))?;

            binary
                .build(PathBuf::from(output_path), false)
                .map_err(|err| anyhow!("Failed to build the signed executable: {}", err))?;

            println!("Signed {} successfully!", binary_name);
        }
    }

    Ok(())
}

fn config() -> ArgMatches<'static> {
    let validate_executable_postfix =
        |file: String| match Path::new(file.as_str()).extension().map(|ext| ext.to_str()).flatten() {
            Some("exe") => Ok(()),
            _ => Err(String::from("The input file is not an Windows executable")),
        };

    App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name(ARG_INPUT)
                .short("i")
                .long(ARG_INPUT)
                .value_name("EXECUTABLE")
                .help("Path to a Windows executable")
                .takes_value(true)
                .required(true)
                .validator(validate_executable_postfix)
                .display_order(0),
        )
        .arg(
            Arg::with_name(ARG_OUTPUT)
                .short("o")
                .long(ARG_OUTPUT)
                .value_name("EXECUTABLE")
                .help("Path where to save the signed binary")
                .takes_value(true)
                .validator(validate_executable_postfix)
                .display_order(1),
        )
        .arg(
            Arg::with_name(ARG_SIGN)
                .short(ARG_SIGN)
                .long("sign")
                .help("Sign the input file")
                .requires_all(&[ARG_CERTFILE, ARG_PRIVATE_KEY, ARG_OUTPUT])
                .display_order(2),
        )
        .arg(
            Arg::with_name(ARG_CERTFILE)
                .short("cert")
                .long(ARG_CERTFILE)
                .value_name("CERTIFICATE")
                .help("Path to a PKCS7 certificate to use in signing")
                .takes_value(true)
                .display_order(3),
        )
        .arg(
            Arg::with_name(ARG_PRIVATE_KEY)
                .short("key")
                .long(ARG_PRIVATE_KEY)
                .value_name("PRIVATE_KEY")
                .help("The private key associated with the certificate")
                .takes_value(true)
                .display_order(4),
        )
        .arg(
            Arg::with_name(ARG_VERIFY)
                .short("v")
                .long(ARG_VERIFY)
                .value_name("FLAG")
                .help("Verify input file")
                .long_help(format!("`{}` - {}\n`{}` - {}\n`{}` - {}\n`{}` - {}\n",
                                     ARG_VERIFY_DEFAULT, "Default behavior that tries to follow the Microsoft verification process as close as possible",
                                     ARG_VERIFY_HASH_ONLY, "Only check that Binary::authentihash matches ContentInfo::digest regardless of the signature's validity",
                                     ARG_VERIFY_LIFETIME_SIGNING, "Same semantic as [WTD_LIFETIME_SIGNING_FLAG](https://docs.microsoft.com/en-us/windows/win32/api/wintrust/ns-wintrust-wintrust_data#WTD_LIFETIME_SIGNING_FLAG)",
                                     ARG_VERIFY_SKIP_CERT_TIME, "Skip the verification of the certificates time validities so that even though a certificate expired, it returns VERIFICATION_FLAGS::OK)",
                ).as_str())
                .possible_values(&[
                    ARG_VERIFY_DEFAULT,
                    ARG_VERIFY_HASH_ONLY,
                    ARG_VERIFY_LIFETIME_SIGNING,
                    ARG_VERIFY_SKIP_CERT_TIME,
                ])
                .display_order(5),
        )
        .arg(
            Arg::with_name(ARG_LOGGING)
                .short("l")
                .long(ARG_LOGGING)
                .value_name("LOG_LEVEL")
                .help("Turn on logging with provided level")
                .takes_value(true)
                .possible_values(&[
                    ARG_LOGGING_TRACE,
                    ARG_LOGGING_DEBUG,
                    ARG_LOGGING_INFO,
                    ARG_LOGGING_WARN,
                    ARG_LOGGING_ERR,
                    ARG_LOGGING_CRITICAL,
                ])
                .display_order(6),
        )
        .set_term_width(190)
        .get_matches()
}

fn read_file_into_vec(file: PathBuf) -> anyhow::Result<Vec<u8>> {
    let mut file = File::open(file.as_path()).map_err(|err| anyhow!("Failed to open {:?}: `{}`", file, err))?;

    let mut data = Vec::new();

    file.read_to_end(&mut data)
        .map_err(|err| anyhow!("Failed to read file: {}", err))?;

    Ok(data)
}
