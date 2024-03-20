#[diplomat::bridge]
pub mod ffi {
    use crate::error::ffi::PickyError;
    use crate::utils::ffi::RsBuffer;
    use diplomat_runtime::DiplomatWriteable;
    use std::fmt::Write;

    #[diplomat::opaque]
    pub struct DirectoryString(pub picky_asn1_x509::directory_string::DirectoryString);

    pub enum DirectoryStringType {
        PrintableString,
        Utf8String,
        BmpString,
    }

    impl DirectoryString {
        pub fn get_type(&self) -> DirectoryStringType {
            match &self.0 {
                picky_asn1_x509::directory_string::DirectoryString::PrintableString(_) => {
                    DirectoryStringType::PrintableString
                }
                picky_asn1_x509::directory_string::DirectoryString::Utf8String(_) => DirectoryStringType::Utf8String,
                picky_asn1_x509::directory_string::DirectoryString::BmpString(_) => DirectoryStringType::BmpString,
            }
        }

        pub fn get_as_string(&self, writable: &mut DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let string: String = self.0.clone().into();
            write!(writable, "{}", string)?;
            Ok(())
        }

        pub fn get_as_bytes(&self) -> Box<RsBuffer> {
            match &self.0 {
                picky_asn1_x509::directory_string::DirectoryString::PrintableString(string) => {
                    RsBuffer::from_bytes(string.as_bytes()).boxed()
                }
                picky_asn1_x509::directory_string::DirectoryString::Utf8String(string) => {
                    RsBuffer::from_bytes(string.as_bytes()).boxed()
                }
                picky_asn1_x509::directory_string::DirectoryString::BmpString(string) => {
                    RsBuffer::from_bytes(string.as_bytes()).boxed()
                }
            }
        }
    }
}
