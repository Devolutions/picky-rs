#[diplomat::bridge]
pub mod ffi {

    #[diplomat::opaque]
    pub struct OctetStringAsn1(pub picky_asn1::wrapper::OctetStringAsn1);

    impl OctetStringAsn1 {
        pub fn from_bytes(bytes: &[u8]) -> Self {
            Self(picky_asn1::wrapper::OctetStringAsn1(bytes.to_vec()))
        }

        pub fn get_length(&self) -> usize {
            self.0 .0.len()
        }

        pub fn fill(&self, buffer: &mut [u8]) -> Result<(), OctectStringAsn1Error> {
            if buffer.len() < self.0 .0.len() {
                return Err(OctectStringAsn1Error::BufferTooSmall);
            }

            buffer[..self.0 .0.len()].copy_from_slice(&self.0 .0);

            Ok(())
        }
    }

    pub enum OctectStringAsn1Error {
        BufferTooSmall,
    }
}
