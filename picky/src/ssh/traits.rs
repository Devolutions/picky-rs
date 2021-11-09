use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_bigint_dig::BigUint;
use std::io::{self, Read, Write};

pub trait SshParser {
    type Error: From<std::io::Error>;

    fn decode(stream: impl Read) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn encode(&self, stream: impl Write) -> Result<(), Self::Error>;
}

pub trait SshStringEncoder {
    type Error;

    fn ssh_string_encode(&self, stream: impl Write) -> Result<(), Self::Error>;
}

impl<T> SshStringEncoder for T
where
    T: AsRef<str>,
{
    type Error = io::Error;

    fn ssh_string_encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        let string_slice = self.as_ref();
        stream.write_u32::<BigEndian>(string_slice.len() as u32)?;
        stream.write_all(string_slice.as_bytes())
    }
}

pub trait SshStringDecoder {
    type Error;

    fn ssh_string_decode(&mut self) -> Result<String, Self::Error>;
}

impl<T> SshStringDecoder for T
where
    T: Read,
{
    type Error = io::Error;

    fn ssh_string_decode(&mut self) -> Result<String, Self::Error> {
        let size = self.read_u32::<BigEndian>()? as usize;
        let mut buffer = vec![0; size];
        self.read_exact(&mut buffer)?;

        Ok(String::from_utf8_lossy(&buffer).to_string())
    }
}

pub trait SshByteArrayEncoder {
    type Error;

    fn ssh_byte_array_encode(&self, stream: impl Write) -> Result<(), Self::Error>;
}

impl<T> SshByteArrayEncoder for T
where
    T: AsRef<[u8]>,
{
    type Error = io::Error;

    fn ssh_byte_array_encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        stream.write_u32::<BigEndian>(self.as_ref().len() as u32)?;
        stream.write_all(self.as_ref())
    }
}

pub trait SshByteArrayDecoder {
    type Error;

    fn ssh_byte_array_decode(&mut self) -> Result<Vec<u8>, Self::Error>;
}

impl<T> SshByteArrayDecoder for T
where
    T: Read,
{
    type Error = io::Error;

    fn ssh_byte_array_decode(&mut self) -> Result<Vec<u8>, Self::Error> {
        let size = self.read_u32::<BigEndian>()? as usize;
        let mut buffer = vec![0; size];
        self.read_exact(&mut buffer)?;

        Ok(buffer)
    }
}

pub trait SshMpintEncoder {
    type Error;

    fn ssh_mpint_encode(&self, stream: impl Write) -> Result<(), Self::Error>;
}

impl SshMpintEncoder for BigUint {
    type Error = io::Error;

    fn ssh_mpint_encode(&self, mut stream: impl Write) -> Result<(), Self::Error> {
        let data = self.to_bytes_be();
        let size = data.len() as u32;
        // If the most significant bit would be set for
        // a positive number, the number MUST be preceded by a zero byte.
        if size > 0 && data[0] & 0b10000000 != 0 {
            stream.write_u32::<BigEndian>(size + 1)?;
            stream.write_u8(0)?;
        } else {
            stream.write_u32::<BigEndian>(size)?;
        }
        stream.write_all(&data)
    }
}

pub trait SshMpintDecoder {
    type Error;

    fn ssh_mpint_decode(&mut self) -> Result<BigUint, Self::Error>;
}

impl<T> SshMpintDecoder for T
where
    T: Read,
{
    type Error = io::Error;

    fn ssh_mpint_decode(&mut self) -> Result<BigUint, Self::Error> {
        let size = self.read_u32::<BigEndian>()? as usize;
        let mut buffer = vec![0; size];
        self.read_exact(&mut buffer)?;

        if buffer[0] == 0 {
            buffer.remove(0);
        }

        Ok(BigUint::from_bytes_be(&buffer))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn ssh_string_decode() {
        let mut cursor = Cursor::new([0, 0, 0, 5, 112, 105, 99, 107, 121].to_vec());

        let ssh_string = cursor.ssh_string_decode().unwrap();

        assert_eq!(5, ssh_string.len());
        assert_eq!("picky".to_owned(), ssh_string);
        assert_eq!(9, cursor.position());

        let mut cursor = Cursor::new([0, 0, 0, 0].to_vec());

        let ssh_string = cursor.ssh_string_decode().unwrap();

        assert_eq!(0, ssh_string.len());
        assert_eq!("".to_owned(), ssh_string);
        assert_eq!(4, cursor.position());
    }

    #[test]
    fn ssh_string_encode() {
        let mut res = Vec::new();
        let ssh_string = "picky".to_owned();

        ssh_string.ssh_string_encode(&mut res).unwrap();

        assert_eq!(vec![0, 0, 0, 5, 112, 105, 99, 107, 121], res);

        res.clear();
        let ssh_string = "".to_owned();

        ssh_string.ssh_string_encode(&mut res).unwrap();

        assert_eq!(vec![0, 0, 0, 0], res);
    }

    #[test]
    fn byte_array_decode() {
        let mut cursor = Cursor::new([0, 0, 0, 5, 1, 2, 3, 4, 5].to_vec());

        let byte_array = cursor.ssh_byte_array_decode().unwrap();

        assert_eq!(5, byte_array.len());
        assert_eq!([1, 2, 3, 4, 5].to_vec(), byte_array);
        assert_eq!(9, cursor.position());

        let mut cursor = Cursor::new([0, 0, 0, 0].to_vec());

        let byte_array = cursor.ssh_byte_array_decode().unwrap();

        assert_eq!(0, byte_array.len());
        assert_eq!(Vec::<u8>::new(), byte_array);
        assert_eq!(4, cursor.position());
    }

    #[test]
    fn byte_array_encode() {
        let mut res = Vec::new();
        let byte_array = vec![1, 2, 3, 4, 5, 6];

        byte_array.ssh_byte_array_encode(&mut res).unwrap();

        assert_eq!(vec![0, 0, 0, 6, 1, 2, 3, 4, 5, 6], res);

        res.clear();
        let byte_array = Vec::new();

        byte_array.ssh_byte_array_encode(&mut res).unwrap();

        assert_eq!(vec![0, 0, 0, 0], res);
    }

    #[test]
    fn mpint_decoding() {
        let mut cursor = Cursor::new(vec![
            0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7,
        ]);
        let mpint = cursor.ssh_mpint_decode().unwrap();
        assert_eq!(
            mpint.to_bytes_be(),
            vec![0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]
        );

        let mut cursor = Cursor::new(vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x80]);
        let mpint = cursor.ssh_mpint_decode().unwrap();
        assert_eq!(mpint.to_bytes_be(), vec![0x80]);

        let mut cursor = Cursor::new(vec![0x00, 0x00, 0x00, 0x02, 0xed, 0xcc]);
        let mpint = cursor.ssh_mpint_decode().unwrap();
        assert_eq!(mpint.to_bytes_be(), vec![0xed, 0xcc]);
    }

    #[test]
    fn mpint_encoding() {
        let mpint = BigUint::from_bytes_be(&[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]);
        let mut res = Vec::new();
        mpint.ssh_mpint_encode(&mut res).unwrap();

        assert_eq!(
            res,
            vec![0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7],
        );

        let mpint = BigUint::from_bytes_be(&[0x80]);
        let mut res = Vec::new();
        mpint.ssh_mpint_encode(&mut res).unwrap();

        assert_eq!(res, vec![0x00, 0x00, 0x00, 0x02, 0x00, 0x80]);
    }
}
