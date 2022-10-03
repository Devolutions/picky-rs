use std::io::{self, Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};

pub mod data_types;
pub mod messages;

/// [2.2.3 Constants](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// #define MESSAGE_SIGNATURE 0x535458454f47454ei64 // "NEGOEXTS"
/// ```
pub const SIGNATURE: u64 = 0x535458454f47454e;

/// [2.2.3 Constants](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// #define CHECKSUM_SCHEME_RFC3961 1
/// ```
pub const CHECKSUM_SCHEME_RFC3961: u32 = 0x1;

/// [2.2.6.3 NEGO_MESSAGE](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ProtocolVersion: A ULONG64 type that indicates the numbered version of this protocol. This field contains 0.
pub const PROTOCOL_VERSION: u64 = 0;

/// [2.2.4 Random array](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NEGOEX/%5bMS-NEGOEX%5d.pdf)
/// ```not_rust
/// UCHAR Random[32];
/// ```
pub const RANDOM_ARRAY_SIZE: usize = 32;

pub trait NegoexMessage
where
    Self: Sized,
{
    type Error;

    fn decode(from: impl Read, message: &[u8]) -> Result<Self, Self::Error>;
    fn encode(&self, to: impl Write) -> Result<(), Self::Error>;
}

pub trait NegoexDataType
where
    Self: Sized,
{
    type Error;

    fn size(&self) -> usize;

    fn decode(from: impl Read, message: &[u8]) -> Result<Self, Self::Error>;

    fn encode(&self, to: impl Write) -> Result<(), Self::Error>;
    fn encode_with_data(&self, offset: &mut usize, to: impl Write, data: impl Write) -> Result<(), Self::Error>;
}

impl NegoexDataType for u8 {
    type Error = io::Error;

    fn size(&self) -> usize {
        1
    }

    fn decode(mut from: impl Read, _message: &[u8]) -> Result<Self, Self::Error> {
        from.read_u8()
    }

    fn encode_with_data(&self, offset: &mut usize, mut to: impl Write, _data: impl Write) -> Result<(), Self::Error> {
        to.write_u8(*self)?;
        *offset += 1;

        Ok(())
    }

    fn encode(&self, to: impl Write) -> Result<(), Self::Error> {
        let mut offset = 0;

        self.encode_with_data(&mut offset, to, &mut [] as &mut [u8])
    }
}

impl<T: NegoexDataType<Error = io::Error>> NegoexDataType for Vec<T> {
    type Error = io::Error;

    fn size(&self) -> usize {
        8 + if self.len() == 0 { 0 } else { self[0].size() * self.len() }
    }

    fn decode(mut from: impl Read, message: &[u8]) -> Result<Self, Self::Error> {
        let message_offset = from.read_u32::<LittleEndian>()? as usize;

        let count = from.read_u32::<LittleEndian>()? as usize;

        let mut reader: Box<dyn Read> = Box::new(&message[message_offset..]);

        let mut elements = Vec::with_capacity(count);

        for _ in 0..count {
            elements.push(T::decode(&mut reader, message)?);
        }

        Ok(elements)
    }

    fn encode_with_data(
        &self,
        offset: &mut usize,
        mut to: impl Write,
        mut data: impl Write,
    ) -> Result<(), Self::Error> {
        if self.is_empty() {
            to.write_u32::<LittleEndian>(0)?;
        } else {
            to.write_u32::<LittleEndian>(*offset as u32)?;
        }

        to.write_u32::<LittleEndian>(self.len() as u32)?;

        let mut elements_headers = Vec::new();
        let mut elements_data = Vec::new();

        for element in self.iter() {
            *offset += element.size();
            element.encode_with_data(offset, &mut elements_headers, &mut elements_data)?;
        }

        data.write_all(&elements_headers)?;
        data.write_all(&elements_data)?;

        Ok(())
    }

    fn encode(&self, mut to: impl Write) -> Result<(), Self::Error> {
        let mut offset = 0;

        let mut header = Vec::new();
        let mut data = Vec::new();

        self.encode_with_data(&mut offset, &mut header, &mut data)?;

        to.write_all(&mut header)?;
        to.write_all(&mut data)?;

        Ok(())
    }
}
