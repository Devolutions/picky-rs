use self::ffi::RsBuffer;

#[diplomat::bridge]
pub mod ffi {
    use diplomat_runtime::DiplomatWriteable;

    use crate::error::ffi::PickyError;
    use std::fmt::Write;

    #[diplomat::opaque] // Named RsBuffer to avoid conflict with the Diplomat runtime Buffer
    pub struct RsBuffer(pub Vec<u8>);

    impl RsBuffer {
        pub fn get_length(&self) -> usize {
            self.0.len()
        }

        pub fn fill(&self, buffer: &mut [u8]) -> Result<(), Box<BufferTooSmallError>> {
            if buffer.len() < self.0.len() {
                return Err(Box::new(BufferTooSmallError));
            }

            buffer.copy_from_slice(&self.0);
            Ok(())
        }
    }

    #[diplomat::opaque]
    pub struct BufferTooSmallError;

    impl BufferTooSmallError {
        pub fn to_display(&self, writeable: &mut DiplomatWriteable) {
            let _ = write!(writeable, "Buffer too small");
            writeable.flush();
        }
    }

    #[diplomat::opaque]
    pub struct BufferIterator(pub Vec<RsBuffer>);

    impl BufferIterator {
        pub fn next(&mut self) -> Option<Box<RsBuffer>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct StringIterator(pub Box<dyn Iterator<Item = String>>);

    impl StringIterator {
        pub fn next(&mut self, writable: &mut diplomat_runtime::DiplomatWriteable) -> Result<(), Box<PickyError>> {
            let next = self.0.next();
            if let Some(next) = next {
                let _ = write!(writable, "{}", next);
                writable.flush();
                return Ok(());
            }

            Err("No more elements".into())
        }
    }

    #[diplomat::opaque]
    pub struct StringNestedIterator(pub Vec<StringIterator>);

    impl StringNestedIterator {
        pub fn next(&mut self) -> Option<Box<StringIterator>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct RsString(pub String); // The reason we use this is to use string as optional in the bridge, this could be removed with future diplomat versions

    impl RsString {
        pub fn from_string(s: &str) -> Box<RsString> {
            Box::new(RsString(s.to_string()))
        }
    }
}

impl From<&picky_asn1::wrapper::OctetStringAsn1> for ffi::RsBuffer {
    fn from(octet_string: &picky_asn1::wrapper::OctetStringAsn1) -> Self {
        Self(octet_string.0.as_slice().to_vec())
    }
}

impl RsBuffer {
    pub fn boxed(self) -> Box<RsBuffer> {
        Box::new(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}
