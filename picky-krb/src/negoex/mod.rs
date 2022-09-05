use std::io::{Read, Write, self};

use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

pub mod data_types;
pub mod messages;

pub trait NegoexMessage
where
    Self: Sized,
{
    type Error;

    fn size(&self) -> usize;

    fn decode(offset: &mut usize, from: impl Read, message: &[u8]) -> Result<Self, Self::Error>;

    fn encode(&self, offset: &mut usize, to: impl Write) -> Result<(), Self::Error>;
    fn encode_with_data(&self, offset: &mut usize, to: impl Write, data: impl Write) -> Result<(), Self::Error>;
}

impl NegoexMessage for u8 {
    type Error = io::Error;

    fn size(&self) -> usize {
        1
    }

    fn decode(offset: &mut usize, mut from: impl Read, _message: &[u8]) -> Result<Self, Self::Error> {
        *offset += 1;

        from.read_u8()
    }

    fn encode_with_data(&self, offset: &mut usize, mut to: impl Write, _data: impl Write) -> Result<(), Self::Error> {
        to.write_u8(*self)?;
        *offset += 1;

        Ok(())
    }

    fn encode(&self, offset: &mut usize, to: impl Write) -> Result<(), Self::Error> {
        self.encode_with_data(offset, to, &mut [] as &mut [u8])
    }
}

impl<T: NegoexMessage<Error = io::Error>> NegoexMessage for Vec<T> {
    type Error = io::Error;

    fn size(&self) -> usize {
        // count with padding
        8 + 4 + if self.len() == 0 { 0 } else { self[1].size() }
    }

    fn decode(offset: &mut usize, mut from: impl Read, message: &[u8]) -> Result<Self, Self::Error> {
        let message_offset = from.read_u32::<BigEndian>()? as usize;
        *offset += 4;

        if message_offset < *offset {
            panic!("bad offset");
        }

        let count = from.read_u32::<BigEndian>()? as usize;
        *offset += 4;

        // padding is not described in specification but present in real messages
        // let _padding = from.read_u16::<BigEndian>()?;

        let mut reader: Box<dyn Read> = Box::new(&message[message_offset..]);

        let mut elements = Vec::with_capacity(count);

        for _ in 0..count {
            elements.push(T::decode(offset, &mut reader, message)?);
        }

        Ok(elements)
    }

    // fn encode(&self, offset: &mut usize, )

    fn encode_with_data(&self, offset: &mut usize, mut to: impl Write, mut data: impl Write) -> Result<(), Self::Error> {
        *offset += 4 + 4 + 4;
        to.write_u32::<BigEndian>(*offset as u32)?;

        to.write_u32::<BigEndian>(self.len() as u32)?;

        // 0 = 4 byte padding that is not described in specification but present in real messages
        // to.write_u32::<BigEndian>(0)?;

        let mut elements_headers = Vec::new();
        let mut elements_data = Vec::new();

        for element in self.iter() {
            element.encode_with_data(offset, &mut elements_headers, &mut elements_data)?;
        }

        data.write_all(&elements_headers)?;
        data.write_all(&elements_data)?;

        Ok(())
    }

    fn encode(&self, offset: &mut usize, mut to: impl Write) -> Result<(), Self::Error> {
        let mut header = Vec::new();
        let mut data = Vec::new();

        self.encode_with_data(offset, &mut header, &mut data)?;

        to.write_all(&mut header)?;
        to.write_all(&mut data)?;

        Ok(())
    }
}
