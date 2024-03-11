#[diplomat::bridge]
pub mod ffi {

    #[diplomat::opaque]
    pub struct Buffer(pub Vec<u8>);

    impl Buffer {
        pub fn from_bytes(bytes: &[u8]) -> Self {
            Self(bytes.to_vec())
        }

        pub fn get_length(&self) -> usize {
            self.0.len()
        }

        pub fn fill(&self, buffer: &mut [u8]) -> Result<(), OctectStringAsn1Error> {
            if buffer.len() < self.0.len() {
                return Err(OctectStringAsn1Error::BufferTooSmall);
            }

            buffer.copy_from_slice(&self.0);
            Ok(())
        }
    }

    pub enum OctectStringAsn1Error {
        BufferTooSmall,
    }
}

impl From<&picky_asn1::wrapper::OctetStringAsn1> for ffi::Buffer {
    fn from(octet_string: &picky_asn1::wrapper::OctetStringAsn1) -> Self {
        Self(octet_string.0.as_slice().to_vec())
    }
}
