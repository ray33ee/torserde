mod tests;

use std::io::{Write, Read};

use bincode::config::{WithOtherEndian, BigEndian, WithOtherIntEncoding, FixintEncoding};
use bincode::{DefaultOptions, Options};

use lazy_static::lazy_static;
use std::borrow::{BorrowMut};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use chrono::{DateTime, Local, TimeZone};

pub type Result<T> = std::result::Result<T, ErrorKind>;

#[derive(Debug)]
pub enum ErrorKind {
    /// An bad discriminant was found when trying to deserialise an enum. Value of the discriminant
    BadDiscriminant(u128),

    ///Raised when a cell has been discarded (due to bad discriminant). Value of the bad discriminant
    DiscardedCell(u128),

    /// A predicted digest does not match the actual. Predicted and actual digests
    BadDigest(u32, u32),

    /// A serialised relay cell is not the required 509 bytes. Contains the length of the serialised entire relay call, command, recognised, stream_id, digest, data, padding
    InvalidRelayLength(u32, u32, u32, u32, u32, u32, u32),

    /// There are fewer bytes of padding than there should be to make up the 509 bytes. Number of bytes expected, number of bytes read
    NotEnoughPadding(usize, usize),

    /// A call to a bincode function failed
    BincodeError(bincode::ErrorKind),

    /// A Read/Write/Seek call failed (write_all is used in the for Strings)
    StdIoError(std::io::ErrorKind),
}

impl From<Box<bincode::ErrorKind>> for ErrorKind {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        ErrorKind::BincodeError(*error)
    }
}

impl From<std::io::Error> for ErrorKind {
    fn from(error: std::io::Error) -> Self {
        ErrorKind::StdIoError(error.kind())
    }
}

lazy_static! {
    /// Represents options for the bincode functions that serialise data into a format compatible with the Tor specification
    static ref BINCODE_OPTIONS: WithOtherEndian<WithOtherIntEncoding<DefaultOptions, FixintEncoding>, BigEndian> = bincode::config::DefaultOptions::new().with_fixint_encoding().with_big_endian();
}

///TorSerde trait exposes functions that serialise and deserialise data in accordance with the Tor specification
pub trait TorSerde {

    ///Return the length of the data when serialised, in bytes. Used when the length of the payload is required
    fn bin_serialise_into<W: Write>(&self, stream: W) -> Result<u32>;

    fn bin_deserialise_from<R: Read>(stream: R) -> Result<Self> where Self: Sized;

    fn serialised_length(&self) -> u32;
}

///A wrapper used to handle the Versions cell payload, which (unlike pretty much all other variable length cell payloads) does not contain its own length
#[derive(Debug, Clone)]
pub struct VersionsVector(pub Vec<u16>);

///A thin wrapper around Vec that allows us to specify the number of bytes to serialise the length of the vector into (N)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NLengthVector<T: TorSerde, const N: usize>(pub Vec<T>);

impl From<Vec<u16>> for VersionsVector {
    fn from(v: Vec<u16>) -> Self {
        Self(v)
    }
}

impl<T: TorSerde, const N: usize> From<Vec<T>> for NLengthVector<T, N> {
    fn from(v: Vec<T>) -> Self {
        Self(v)
    }
}

impl From<VersionsVector> for Vec<u16> {
    fn from(v: VersionsVector) -> Self {
        v.0
    }
}

impl<T: TorSerde, const N: usize> From<NLengthVector<T, N>> for Vec<T> {
    fn from(v: NLengthVector<T, N>) -> Self {
        v.0
    }
}

impl TorSerde for u8 {
    fn bin_serialise_into<W: Write>(&self, stream: W) -> Result<u32> {
        BINCODE_OPTIONS.serialize_into(stream, &self)?;
        Ok(self.serialised_length())
    }

    fn bin_deserialise_from<R: Read>(stream: R) -> Result<Self> {
        let res: Self = BINCODE_OPTIONS.deserialize_from(stream)?;
        Ok(res)
    }

    fn serialised_length(&self) -> u32 {
        1
    }

}

impl TorSerde for u16 {
    fn bin_serialise_into<W: Write>(&self, stream: W) -> Result<u32> {
        BINCODE_OPTIONS.serialize_into(stream, &self)?;
        Ok(self.serialised_length())
    }

    fn bin_deserialise_from<R: Read>(stream: R) -> Result<Self> {
        let res: Self = BINCODE_OPTIONS.deserialize_from(stream)?;
        Ok(res)
    }

    fn serialised_length(&self) -> u32 {
        2
    }
}

impl TorSerde for u32 {
    fn bin_serialise_into<W: Write>(&self, stream: W) -> Result<u32> {
        BINCODE_OPTIONS.serialize_into(stream, &self)?;
        Ok(self.serialised_length())
    }

    fn bin_deserialise_from<R: Read>(stream: R) -> Result<Self> {
        let res: Self = BINCODE_OPTIONS.deserialize_from(stream)?;
        Ok(res)
    }

    fn serialised_length(&self) -> u32 {
        4
    }
}

impl TorSerde for u64 {
    fn bin_serialise_into<W: Write>(&self, stream: W) -> Result<u32> {
        BINCODE_OPTIONS.serialize_into(stream, &self)?;
        Ok(self.serialised_length())
    }

    fn bin_deserialise_from<R: Read>(stream: R) -> Result<Self> {
        let res: Self = BINCODE_OPTIONS.deserialize_from(stream)?;
        Ok(res)
    }

    fn serialised_length(&self) -> u32 {
        8
    }
}

impl TorSerde for u128 {
    fn bin_serialise_into<W: Write>(&self, stream: W) -> Result<u32> {
        BINCODE_OPTIONS.serialize_into(stream, &self)?;
        Ok(self.serialised_length())
    }

    fn bin_deserialise_from<R: Read>(stream: R) -> Result<Self> {
        let res: Self = BINCODE_OPTIONS.deserialize_from(stream)?;
        Ok(res)
    }

    fn serialised_length(&self) -> u32 {
        16
    }
}

impl<T: TorSerde, const N: usize> TorSerde for NLengthVector<T, N> {
    fn bin_serialise_into<W: Write>(&self, mut stream: W) -> Result<u32> {
        //let mut total = N as u32;

        let mut total = match N {
            1 => (self.0.len() as u8).bin_serialise_into(stream.borrow_mut())?,
            2 => (self.0.len() as u16).bin_serialise_into(stream.borrow_mut())?,
            4 => (self.0.len() as u32).bin_serialise_into(stream.borrow_mut())?,
            _ => unreachable!()
        };

        for item in self.0.iter() {
            total += item.bin_serialise_into(stream.borrow_mut())?;
        }

        Ok(total)
    }

    fn bin_deserialise_from<R: Read>(mut stream: R) -> Result<Self> {
        let length = match N {
            1 => u8::bin_deserialise_from(stream.borrow_mut())? as u32,
            2 => u16::bin_deserialise_from(stream.borrow_mut())? as u32,
            4 => u32::bin_deserialise_from(stream.borrow_mut())?,
            _ => unreachable!()
        };

        let mut list = Vec::with_capacity(length as usize);

        for _ in 0..length {
            list.push(T::bin_deserialise_from(stream.borrow_mut())?);
        }

        Ok(Self(list))
    }

    fn serialised_length(&self) -> u32 {
        self.0.iter().fold(N as u32, |acc, x| acc + x.serialised_length())
    }
}

impl TorSerde for VersionsVector {
    fn bin_serialise_into<W: Write>(&self, mut stream: W) -> Result<u32> {
        ((self.0.len()*2) as u16).bin_serialise_into(stream.borrow_mut())?;

        for item in self.0.iter() {
            item.bin_serialise_into(stream.borrow_mut())?;
        }

        Ok(self.serialised_length())
    }

    fn bin_deserialise_from<R: Read>(mut stream: R) -> Result<Self> {
        let length = u16::bin_deserialise_from(stream.borrow_mut())? / 2;
        let mut list = Vec::with_capacity(length as usize);

        for _ in 0..length {
            list.push(u16::bin_deserialise_from(stream.borrow_mut())?);
        }

        Ok(Self(list))
    }

    fn serialised_length(&self) -> u32 {
        (self.0.len() * 2) as u32
    }
}

impl TorSerde for DateTime<Local> {
    fn bin_serialise_into<W: Write>(&self, stream: W) -> Result<u32> {
        (self.timestamp() as u32).bin_serialise_into(stream)
    }

    fn bin_deserialise_from<R: Read>(stream: R) -> Result<Self> {
        let timestamp = u32::bin_deserialise_from(stream)?;

        Ok(Local.timestamp(timestamp as i64, 0))
    }

    fn serialised_length(&self) -> u32 {
        4
    }
}

impl TorSerde for Ipv4Addr {
    fn bin_serialise_into<W: Write>(&self, stream: W) -> Result<u32> {
        let bytes = u32::from(self.clone());

        bytes.bin_serialise_into(stream)
    }

    fn bin_deserialise_from<R: Read>(stream: R) -> Result<Self> {
        let bytes = u32::bin_deserialise_from(stream)?;

        Ok(Self::from(bytes))
    }

    fn serialised_length(&self) -> u32 {
        4
    }
}

impl TorSerde for Ipv6Addr {
    fn bin_serialise_into<W: Write>(&self, stream: W) -> Result<u32> {
        let bytes = u128::from(self.clone());

        bytes.bin_serialise_into(stream)
    }

    fn bin_deserialise_from<R: Read>(stream: R) -> Result<Self> {
        let bytes = u128::bin_deserialise_from(stream)?;

        Ok(Self::from(bytes))
    }

    fn serialised_length(&self) -> u32 {
        16
    }
}

impl TorSerde for IpAddr {
    fn bin_serialise_into<W: Write>(&self, mut stream: W) -> Result<u32> {
        Ok(match self {
            IpAddr::V4(ipv4) => {
                4u8.bin_serialise_into(stream.borrow_mut())? + //Address type (4 for ipv4, 6 for ipv6)
                4u8.bin_serialise_into(stream.borrow_mut())? + //Address length (4 for ipv4, 16 for ipv6)
                ipv4.bin_serialise_into(stream.borrow_mut())?
            }
            IpAddr::V6(ipv6) => {
                6u8.bin_serialise_into(stream.borrow_mut())? + //Address type (4 for ipv4, 6 for ipv6)
                16u8.bin_serialise_into(stream.borrow_mut())? + //Address length (4 for ipv4, 16 for ipv6)
                ipv6.bin_serialise_into(stream.borrow_mut())?
            }
        })
    }

    fn bin_deserialise_from<R: Read>(mut stream: R) -> Result<Self> {
        let atype = u8::bin_deserialise_from(stream.borrow_mut())?;

        let _alen = u8::bin_deserialise_from(stream.borrow_mut())?;

        Ok(match atype {
            4 => { Self::V4(Ipv4Addr::bin_deserialise_from(stream.borrow_mut())?) }
            6 => { Self::V6(Ipv6Addr::bin_deserialise_from(stream.borrow_mut())?) }
            _ => unreachable!()
        })
    }

    fn serialised_length(&self) -> u32 {
        2 + match &self {
            IpAddr::V4(ipv4) => {ipv4.serialised_length()}
            IpAddr::V6(ipv6) => {ipv6.serialised_length()}
        }
    }
}

impl TorSerde for String {
    fn bin_serialise_into<W: Write>(&self, mut stream: W) -> Result<u32> {
        //Write the contents of the string to the stream
        stream.borrow_mut().write_all(self.as_bytes())?;

        //Append the stream with the null terminator
        0u8.bin_serialise_into(stream.borrow_mut())?;

        Ok(self.serialised_length())
    }

    fn bin_deserialise_from<R: Read>(mut stream: R) -> Result<Self> {
        let mut string = Vec::new();

        loop {
            let byte = u8::bin_deserialise_from(stream.borrow_mut())?;

            if byte == 0 {
                break;
            }

            string.push(byte);
        }

        unsafe {
            Ok(Self::from_utf8_unchecked(string))
        }
    }

    fn serialised_length(&self) -> u32 {
        1 + self.len() as u32
    }
}

impl<const N: usize> TorSerde for [u8; N] {
    fn bin_serialise_into<W: Write>(&self, mut stream: W) -> Result<u32> {
        for item in self.iter() {
            item.bin_serialise_into(stream.borrow_mut())?;
        }

        Ok(N as u32)
    }

    fn bin_deserialise_from<R: Read>(mut stream: R) -> Result<Self> {
        let mut array = [0u8; N];

        for item in array.iter_mut() {
            *item = u8::bin_deserialise_from(stream.borrow_mut())?;
        }

        Ok(array)
    }

    fn serialised_length(&self) -> u32 {
        self.len() as u32
    }
}
