mod tests;

use std::io::{Write, Read};

use bincode::config::{WithOtherEndian, BigEndian, WithOtherIntEncoding, FixintEncoding};
use bincode::{DefaultOptions, Options};

use lazy_static::lazy_static;
use std::borrow::{BorrowMut};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use chrono::{DateTime, Local, TimeZone};

//BINCODE_OPTIONS represents options for the bincode functions that serialise data into a format compatible with the Tor specification
lazy_static! {
    static ref BINCODE_OPTIONS: WithOtherEndian<WithOtherIntEncoding<DefaultOptions, FixintEncoding>, BigEndian> = bincode::config::DefaultOptions::new().with_fixint_encoding().with_big_endian();
}

//TorSerde trait exposes functions that serialise and deserialise data in accordance with the Tor specification
pub trait TorSerde {

    fn bin_serialise_into<W: Write>(&self, stream: W);

    //The payload_length argument is literally only needed for the Versions cell since its length is not a part  of the payload
    fn bin_deserialise_from<R: Read>(stream: R, payload_length: Option<u32>) -> Self;

    //Return the length of the data when serialised, in bytes. Used when the length of the payload is required
    fn serialised_length(&self) -> u32;
}

//A wrapper used to handle the Versions cell payload, which (unlike pretty much all other variable length cell payloads) does not contain its own length
#[derive(Debug, Clone)]
pub struct VersionsVector(Vec<u16>);

//A thin wrapper around Vec that allows us to specify the number of bytes to serialise the length of the vector into (N)
#[derive(Debug, Clone)]
pub struct NLengthVector<T: TorSerde, const N: usize>(Vec<T>);

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
    fn bin_serialise_into<W: Write>(&self, stream: W) {
        BINCODE_OPTIONS.serialize_into(stream, &self).unwrap();
    }

    fn bin_deserialise_from<R: Read>(stream: R, _payload_length: Option<u32>) -> Self {
        BINCODE_OPTIONS.deserialize_from(stream).unwrap()
    }

    fn serialised_length(&self) -> u32 { 1 }
}

impl TorSerde for u16 {
    fn bin_serialise_into<W: Write>(&self, stream: W) {
        BINCODE_OPTIONS.serialize_into(stream, &self).unwrap();
    }

    fn bin_deserialise_from<R: Read>(stream: R, _payload_length: Option<u32>) -> Self {
        BINCODE_OPTIONS.deserialize_from(stream).unwrap()
    }

    fn serialised_length(&self) -> u32 { 2 }
}

impl TorSerde for u32 {
    fn bin_serialise_into<W: Write>(&self, stream: W) {
        BINCODE_OPTIONS.serialize_into(stream, &self).unwrap();
    }

    fn bin_deserialise_from<R: Read>(stream: R, _payload_length: Option<u32>) -> Self {
        BINCODE_OPTIONS.deserialize_from(stream).unwrap()
    }

    fn serialised_length(&self) -> u32 { 4 }
}

impl TorSerde for u128 {
    fn bin_serialise_into<W: Write>(&self, stream: W) {
        BINCODE_OPTIONS.serialize_into(stream, &self).unwrap();
    }

    fn bin_deserialise_from<R: Read>(stream: R, _payload_length: Option<u32>) -> Self {
        BINCODE_OPTIONS.deserialize_from(stream).unwrap()
    }

    fn serialised_length(&self) -> u32 { 16 }
}

impl<T: TorSerde, const N: usize> TorSerde for NLengthVector<T, N> {
    fn bin_serialise_into<W: Write>(&self, mut stream: W) {
        match N {
            1 => (self.0.len() as u8).bin_serialise_into(stream.borrow_mut()),
            2 => (self.0.len() as u16).bin_serialise_into(stream.borrow_mut()),
            4 => (self.0.len() as u8).bin_serialise_into(stream.borrow_mut()),
            _ => unreachable!()
        }

        for item in self.0.iter() {
            item.bin_serialise_into(stream.borrow_mut());
        }
    }

    fn bin_deserialise_from<R: Read>(mut stream: R, _payload_length: Option<u32>) -> Self {
        let length = match N {
            1 => u8::bin_deserialise_from(stream.borrow_mut(), None) as u32,
            2 => u16::bin_deserialise_from(stream.borrow_mut(), None) as u32,
            4 => u32::bin_deserialise_from(stream.borrow_mut(), None),
            _ => unreachable!()
        };

        let mut list = Vec::with_capacity(length as usize);

        for _ in 0..length {
            list.push(T::bin_deserialise_from(stream.borrow_mut(), None));
        }

        Self(list)
    }

    fn serialised_length(&self) -> u32 {
        let mut total = N as u32;

        for item in self.0.iter() {
            total += item.serialised_length();
        }

        total
    }
}

impl TorSerde for VersionsVector {
    fn bin_serialise_into<W: Write>(&self, mut stream: W) {
        for item in self.0.iter() {
            item.bin_serialise_into(stream.borrow_mut())
        }
    }

    fn bin_deserialise_from<R: Read>(mut stream: R, payload_length: Option<u32>) -> Self {
        let mut list = Vec::with_capacity(payload_length.unwrap() as usize);

        for _ in 0..payload_length.unwrap() {
            list.push(u16::bin_deserialise_from(stream.borrow_mut(), None));
        }

        Self(list)
    }

    fn serialised_length(&self) -> u32 {
        (self.0.len() * 2) as u32
    }
}

impl TorSerde for DateTime<Local> {
    fn bin_serialise_into<W: Write>(&self, stream: W) {
        (self.timestamp() as u32).bin_serialise_into(stream)
    }

    fn bin_deserialise_from<R: Read>(stream: R, _payload_length: Option<u32>) -> Self {
        let timestamp = u32::bin_deserialise_from(stream, None);

        Local.timestamp(timestamp as i64, 0)
    }

    fn serialised_length(&self) -> u32 {
        4
    }
}

impl TorSerde for Ipv4Addr {
    fn bin_serialise_into<W: Write>(&self, stream: W) {
        let bytes = u32::from(self.clone());

        bytes.bin_serialise_into(stream)
    }

    fn bin_deserialise_from<R: Read>(stream: R, _payload_length: Option<u32>) -> Self {
        let bytes = u32::bin_deserialise_from(stream, None);

        Self::from(bytes)
    }

    fn serialised_length(&self) -> u32 {
        4
    }
}

impl TorSerde for Ipv6Addr {
    fn bin_serialise_into<W: Write>(&self, stream: W) {
        let bytes = u128::from(self.clone());

        bytes.bin_serialise_into(stream)
    }

    fn bin_deserialise_from<R: Read>(stream: R, _payload_length: Option<u32>) -> Self {
        let bytes = u128::bin_deserialise_from(stream, None);

        Self::from(bytes)
    }

    fn serialised_length(&self) -> u32 {
        16
    }
}

impl TorSerde for IpAddr {
    fn bin_serialise_into<W: Write>(&self, mut stream: W) {
        match self {
            IpAddr::V4(ipv4) => {
                4u8.bin_serialise_into(stream.borrow_mut()); //Address type (4 for ipv4, 6 for ipv6)
                4u8.bin_serialise_into(stream.borrow_mut()); //Address length (4 for ipv4, 16 for ipv6)
                ipv4.bin_serialise_into(stream.borrow_mut());
            }
            IpAddr::V6(ipv6) => {
                6u8.bin_serialise_into(stream.borrow_mut()); //Address type (4 for ipv4, 6 for ipv6)
                16u8.bin_serialise_into(stream.borrow_mut()); //Address length (4 for ipv4, 16 for ipv6)
                ipv6.bin_serialise_into(stream.borrow_mut());
            }
        }
    }

    fn bin_deserialise_from<R: Read>(mut stream: R, _payload_length: Option<u32>) -> Self {
        let atype = u8::bin_deserialise_from(stream.borrow_mut(), None);

        let _alen = u8::bin_deserialise_from(stream.borrow_mut(), None);

        match atype {
            4 => { Self::V4(Ipv4Addr::bin_deserialise_from(stream.borrow_mut(), None)) }
            6 => { Self::V6(Ipv6Addr::bin_deserialise_from(stream.borrow_mut(), None)) }
            _ => unreachable!()
        }
    }

    fn serialised_length(&self) -> u32 {
        2 + match self {
            IpAddr::V4(ipv4) => {ipv4.serialised_length()}
            IpAddr::V6(ipv6) => {ipv6.serialised_length()}
        }
    }
}

impl TorSerde for String {
    fn bin_serialise_into<W: Write>(&self, mut stream: W) {
        //Write the contents of the string to the stream
        stream.borrow_mut().write_all(self.as_bytes()).unwrap();

        //Append the stream with the null terminator
        0u8.bin_serialise_into(stream.borrow_mut())
    }

    fn bin_deserialise_from<R: Read>(mut stream: R, _payload_length: Option<u32>) -> Self {
        let mut string = Vec::new();

        loop {
            let byte = u8::bin_deserialise_from(stream.borrow_mut(), None);

            if byte == 0 {
                break;
            }

            string.push(byte);
        }

        unsafe {
            Self::from_utf8_unchecked(string)
        }
    }

    fn serialised_length(&self) -> u32 {
        self.len() as u32 + 1
    }
}

impl<const N: usize> TorSerde for [u8; N] {
    fn bin_serialise_into<W: Write>(&self, mut stream: W) {
        for item in self.iter() {
            item.bin_serialise_into(stream.borrow_mut())
        }
    }

    fn bin_deserialise_from<R: Read>(mut stream: R, _payload_length: Option<u32>) -> Self {
        let mut array = [0u8; N];

        for item in array.iter_mut() {
            *item = u8::bin_deserialise_from(stream.borrow_mut(), None);
        }

        array
    }

    fn serialised_length(&self) -> u32 {
        let mut total = N as u32;

        for item in self.iter() {
            total += item.serialised_length();
        }

        total
    }
}
