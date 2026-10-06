use std::io;

pub(crate) struct Reader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub(crate) fn remaining(&self) -> &'a [u8] {
        &self.input[self.position..]
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.position == self.input.len()
    }

    pub(crate) fn read_u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn read_u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub(crate) fn read_u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub(crate) fn read_bytes(&mut self) -> io::Result<&'a [u8]> {
        let len = self.read_u32()? as usize;
        self.take(len)
    }

    pub(crate) fn read_string(&mut self) -> io::Result<&'a str> {
        std::str::from_utf8(self.read_bytes()?).map_err(|_| invalid_data())
    }

    pub(crate) fn read_mpint(&mut self) -> io::Result<&'a [u8]> {
        let value = self.read_bytes()?;
        if value.is_empty() {
            return Ok(value);
        }
        if value[0] & 0x80 != 0 {
            return Err(invalid_data());
        }
        if value[0] == 0 {
            if value.len() == 1 || value[1] & 0x80 == 0 {
                return Err(invalid_data());
            }
            Ok(&value[1..])
        } else {
            Ok(value)
        }
    }

    pub(crate) fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self.position.checked_add(len).ok_or_else(invalid_data)?;
        if end > self.input.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated SSH data"));
        }
        let value = &self.input[self.position..end];
        self.position = end;
        Ok(value)
    }
}

pub(crate) fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn write_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn write_bytes(output: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    let len = u32::try_from(value.len()).map_err(|_| invalid_data())?;
    write_u32(output, len);
    output.extend_from_slice(value);
    Ok(())
}

pub(crate) fn write_string(output: &mut Vec<u8>, value: &str) -> io::Result<()> {
    write_bytes(output, value.as_bytes())
}

pub(crate) fn write_mpint(output: &mut Vec<u8>, value: &[u8]) -> io::Result<()> {
    let value = trim_unsigned(value);
    if value.is_empty() {
        return write_bytes(output, value);
    }
    if value[0] & 0x80 == 0 {
        write_bytes(output, value)
    } else {
        let len = value.len().checked_add(1).ok_or_else(invalid_data)?;
        write_u32(output, u32::try_from(len).map_err(|_| invalid_data())?);
        output.push(0);
        output.extend_from_slice(value);
        Ok(())
    }
}

pub(crate) fn trim_unsigned(mut value: &[u8]) -> &[u8] {
    while value.first() == Some(&0) {
        value = &value[1..];
    }
    value
}

pub(crate) fn invalid_data() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid SSH data")
}
