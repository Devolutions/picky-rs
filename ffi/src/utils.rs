use self::ffi::Buffer;

#[diplomat::bridge]
pub mod ffi {
    use std::fmt::Write;

    #[diplomat::opaque]
    pub struct Buffer(pub Vec<u8>);

    impl Buffer {
        pub fn from_bytes(bytes: &[u8]) -> Self {
            Self(bytes.to_vec())
        }

        pub fn get_length(&self) -> usize {
            self.0.len()
        }

        pub fn fill(&self, buffer: &mut [u8]) -> Result<(), BufferError> {
            if buffer.len() < self.0.len() {
                return Err(BufferError::BufferTooSmall);
            }

            buffer.copy_from_slice(&self.0);
            Ok(())
        }
    }

    pub enum BufferError {
        BufferTooSmall,
    }

    #[diplomat::opaque]
    pub struct BufferIterator(pub Vec<Buffer>);

    impl BufferIterator {
        pub fn next(&mut self) -> Option<Box<Buffer>> {
            self.0.pop().map(Box::new)
        }
    }

    #[diplomat::opaque]
    pub struct StringIterator(pub Vec<String>);

    impl StringIterator {
        pub fn have_next(&self) -> bool {
            !self.0.is_empty()
        }

        pub fn next(&mut self, writable: &mut diplomat_runtime::DiplomatWriteable) {
            let next = self.0.pop();
            if let Some(next) = next {
                let _ = write!(writable, "{}", next);
                writable.flush();
            }
        }
    }

    #[diplomat::opaque]
    pub struct StringNestedIterator(pub Vec<Vec<String>>);

    impl StringNestedIterator {
        pub fn next(&mut self) -> Option<Box<StringIterator>> {
            self.0.pop().map(StringIterator).map(Box::new)
        }
    }
}

impl From<&picky_asn1::wrapper::OctetStringAsn1> for ffi::Buffer {
    fn from(octet_string: &picky_asn1::wrapper::OctetStringAsn1) -> Self {
        Self(octet_string.0.as_slice().to_vec())
    }
}

impl Buffer {
    pub fn boxed(self) -> Box<Buffer> {
        Box::new(self)
    }
}
