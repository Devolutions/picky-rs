use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg, ArgMatches};
use std::path::Path;

pub const PS_AUTHENTICODE_HEADER: &str = "# SIG # Begin signature block";
pub const PS_AUTHENTICODE_FOOTER: &str = "# SIG # End signature block";
pub const PS_AUTHENTICODE_LINES_SPLITTER: &str = "# ";
pub const CRLF: &str = "\r\n";

pub const ARG_BINARY: &str = "binary";
pub const ARG_PS_SCRIPT: &str = "script";

pub const ARG_SCRIPTS_PATH: &str = "scripts-path";
pub const ARG_INPUT: &str = "input";
pub const ARG_OUTPUT: &str = "output";
pub const ARG_SIGN: &str = "sign";

pub const ARG_CERTFILE: &str = "certfile";
pub const ARG_PRIVATE_KEY: &str = "rsa-private-key";
pub const ARG_TIMESTAMP: &str = "timestamp";

pub const ARG_VERIFY: &str = "verify";
pub const ARG_VERIFY_BASIC: &str = "basic";
pub const ARG_VERIFY_SIGNING_CERTIFICATE: &str = "signing-certificate";
pub const ARG_VERIFY_CHAIN: &str = "chain";
pub const ARG_VERIFY_CA: &str = "ca";

pub const ARG_LOGGING: &str = "logging";
pub const ARG_LOGGING_TRACE: &str = "trace";
pub const ARG_LOGGING_DEBUG: &str = "debug";
pub const ARG_LOGGING_INFO: &str = "info";
pub const ARG_LOGGING_WARN: &str = "warn";
pub const ARG_LOGGING_ERR: &str = "err";
pub const ARG_LOGGING_CRITICAL: &str = "critical";

pub fn config() -> ArgMatches<'static> {
    let validate_executable_postfix =
        |file: String| match Path::new(file.as_str()).extension().map(|ext| ext.to_str()).flatten() {
            Some("exe") => Ok(()),
            _ => Err(format!("`{}` is not a Windows executable", file)),
        };

    let validate_ps_path = |file: String| {
        let path = Path::new(file.as_str());
        let is_ps_file = path
            .extension()
            .map(|ext| {
                ext.to_str()
                    .map(|ext| matches!(ext, "ps1" | "psm1" | "psd1"))
                    .unwrap_or(false)
            })
            .unwrap_or(false);

        if !path.is_file() || is_ps_file {
            Ok(())
        } else {
            Err(format!("{} is not a folder not a PowerShell file", file))
        }
    };

    App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(
            Arg::with_name(ARG_BINARY)
                .short("b")
                .long(ARG_BINARY)
                .help("Specify a PE binary to sign")
                .display_order(0),
        )
        .arg(
            Arg::with_name(ARG_INPUT)
                .short("i")
                .long(ARG_INPUT)
                .value_name("EXECUTABLE")
                .help("Path to a Windows executable")
                .takes_value(true)
                .required(false)
                .requires_all(&[ARG_BINARY, ARG_OUTPUT])
                .validator(validate_executable_postfix)
                .display_order(1),
        )
        .arg(
            Arg::with_name(ARG_OUTPUT)
                .short("o")
                .long(ARG_OUTPUT)
                .value_name("EXECUTABLE")
                .help("Path where to save the signed binary")
                .takes_value(true)
                .requires_all(&[ARG_BINARY, ARG_INPUT])
                .validator(validate_executable_postfix)
                .display_order(2),
        )
        .arg(
            Arg::with_name(ARG_PS_SCRIPT)
                .long(ARG_PS_SCRIPT)
                .help("Specify a PowerShell script or module to sign or verify")
                .display_order(3),
        )
        .arg(
            Arg::with_name(ARG_SCRIPTS_PATH)
                .long(ARG_SCRIPTS_PATH)
                .value_name("FOLDER")
                .help("A path to a folder with PowerShell files or a PowerShell file path to process")
                .takes_value(true)
                .requires(ARG_PS_SCRIPT)
                .validator(validate_ps_path)
                .display_order(4),
        )
        .arg(
            Arg::with_name(ARG_SIGN)
                .short(ARG_SIGN)
                .long("sign")
                .help("Specify input file(files) to sign input")
                .requires_all(&[ARG_CERTFILE, ARG_PRIVATE_KEY])
                .display_order(5),
        )
        .arg(
            Arg::with_name(ARG_CERTFILE)
                .short("cert")
                .long(ARG_CERTFILE)
                .value_name("CERTIFICATE")
                .help("Path to a PKCS7 certificate to use in signing")
                .takes_value(true)
                .requires_all(&[ARG_SIGN, ARG_PRIVATE_KEY])
                .display_order(6),
        )
        .arg(
            Arg::with_name(ARG_PRIVATE_KEY)
                .short("key")
                .long(ARG_PRIVATE_KEY)
                .value_name("RSA PRIVATE_KEY")
                .help("The rsa private key associated with the certificate")
                .takes_value(true)
                .requires_all(&[ARG_SIGN, ARG_CERTFILE])
                .display_order(7),
        )
        .arg(Arg::with_name(ARG_TIMESTAMP)
            .short("t")
            .long(ARG_TIMESTAMP)
            .value_name("URL")
            .help("Specify url of a Authenticode TSA server to timestamp")
            .takes_value(true)
            .requires(ARG_SIGN)
            .display_order(8)
        )
        .arg(
            Arg::with_name(ARG_VERIFY)
                .short("v")
                .long(ARG_VERIFY)
                .value_name("FLAG")
                .takes_value(true)
                .multiple(true)
                .help("Verify input file")
                .long_help(
                    format!(
                        "`{}` - {}\n`{}` - {}\n`{}` - {}\n`{}` - {}\n",
                        ARG_VERIFY_BASIC,
                        "Default behavior that tries to follow the Microsoft verification process as close as possible.",
                        ARG_VERIFY_SIGNING_CERTIFICATE,
                        "Requires checking signing certificate validity.",
                        ARG_VERIFY_CHAIN,
                        "Requires X509 certificates chain validation additionally to signing certificate validation",
                        ARG_VERIFY_CA,
                        "Verify that the intermediate certificate of the signature was issued by a CA that Windows trust",
                )
                    .as_str(),
                )
                .possible_values(&[
                    ARG_VERIFY_BASIC,
                    ARG_VERIFY_SIGNING_CERTIFICATE,
                    ARG_VERIFY_CHAIN,
                    ARG_VERIFY_CA,
                ])
                .display_order(9),
        )
        .arg(
            Arg::with_name(ARG_LOGGING)
                .short("l")
                .long(ARG_LOGGING)
                .value_name("LOG_LEVEL")
                .help("Turn on binary signing logging with provided level")
                .takes_value(true)
                .requires(ARG_BINARY)
                .possible_values(&[
                    ARG_LOGGING_TRACE,
                    ARG_LOGGING_DEBUG,
                    ARG_LOGGING_INFO,
                    ARG_LOGGING_WARN,
                    ARG_LOGGING_ERR,
                    ARG_LOGGING_CRITICAL,
                ])
                .display_order(10),
        )
        .get_matches()
}
