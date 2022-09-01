use std::io::{Read, Write};

use uuid::Uuid;

pub mod data_types;
pub mod messages;

pub trait NegoexDecode
where
    Self: Sized,
{
    type Error;

    fn decode(from: impl Read) -> Result<Self, Self::Error>;
}

pub trait NegoexEncode
where
    Self: Sized,
{
    type Error;

    fn encode(&self, to: impl Write) -> Result<(), Self::Error>;
}

pub trait NegoexReadExt {
    type Error;

    fn read_uuid(&mut self) -> Result<Uuid, Self::Error>;
}
