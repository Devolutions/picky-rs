pub mod certificate;
pub mod decode;
pub mod encode;
pub mod private_key;
pub mod public_key;

pub use certificate::{SshCertKeyType, SshCertType, SshCertificate, SshCertificateBuilder};
pub use private_key::SshPrivateKey;
pub use public_key::SshPublicKey;

use byteorder::ReadBytesExt;
use std::io::{self, Read};

pub(crate) type Base64Writer<'a, T, E> = base64::write::EncoderWriter<'a, T, E>;
pub(crate) type Base64Reader<'a, T, E> = base64::read::DecoderReader<'a, T, E>;

const SSH_RSA_KEY_TYPE: &str = "ssh-rsa";

fn read_to_buffer_until_whitespace(stream: &mut dyn Read, buffer: &mut Vec<u8>) -> io::Result<()> {
    loop {
        match stream.read_u8() {
            Ok(symbol) => {
                if symbol as char == ' ' {
                    break;
                } else {
                    buffer.push(symbol);
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                break;
            }
            Err(e) => return Err(e),
        };
    }

    Ok(())
}
