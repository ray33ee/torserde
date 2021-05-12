#[cfg(test)]
mod tests {

    use crate::{TorSerde, VersionsVector};
    use chrono::{DateTime, Local, TimeZone};
    use std::net::{Ipv4Addr, IpAddr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_u8() {
        let mut buffer = Vec::new();

        let number = 0x45u8;

        number.bin_serialise_into(& mut buffer);

        assert_eq!(buffer, [0x45]);

        let d_result = u8::bin_deserialise_from(buffer.as_slice(), None);

        assert_eq!(d_result, number);
    }

    #[test]
    fn test_u16() {
        let mut buffer = Vec::new();

        let number = 0x39e3u16;

        number.bin_serialise_into(& mut buffer);

        assert_eq!(buffer, [0x39, 0xe3]);

        let d_result = u16::bin_deserialise_from(buffer.as_slice(), None);

        assert_eq!(d_result, number);
    }

    #[test]
    fn test_u32() {
        let mut buffer = Vec::new();

        let number = 0x7e38d1a0u32;

        number.bin_serialise_into(&mut buffer);

        assert_eq!(buffer, [0x7e, 0x38, 0xd1, 0xa0]);

        let d_result = u32::bin_deserialise_from(buffer.as_slice(), None);

        assert_eq!(d_result, number);
    }


    #[test]
    fn test_u128() {
        let mut buffer = Vec::new();

        let number = 0x298bf077459127438fe12329707bcd4bu128;

        number.bin_serialise_into(& mut buffer);

        assert_eq!(buffer, [0x29, 0x8b, 0xf0, 0x77, 0x45, 0x91, 0x27, 0x43, 0x8f, 0xe1, 0x23, 0x29, 0x70, 0x7b, 0xcd, 0x4b]);

        let d_result = u128::bin_deserialise_from(buffer.as_slice(), None);

        assert_eq!(d_result, number);
    }


    #[test]
    fn test_timestamp() {
        let mut buffer = Vec::new();

        let time = Local.timestamp(1431648000, 0);

        time.bin_serialise_into(& mut buffer);

        assert_eq!(buffer, [85, 85, 55, 0]);

        let d_time = DateTime::<Local>::bin_deserialise_from(buffer.as_slice(), None);

        assert_eq!(d_time, time);
    }

    #[test]
    fn test_timestamp_list() {
        use crate::NLengthVector;

        let wrap = NLengthVector::<_, 1>::from(vec![0u16, 23, 86, 35, 96, 83]);

        let mut buffer = Vec::new();

        wrap.bin_serialise_into(& mut buffer);

        assert_eq!(buffer, [6u8, 0, 0, 0, 23, 0, 86, 0, 35, 0, 96, 0, 83]);

        let d_wrap = NLengthVector::<u16, 1>::bin_deserialise_from(buffer.as_slice(), None);

        assert_eq!(Vec::from(wrap), Vec::from(d_wrap))

    }

    #[test]
    fn test_array() {
        let mut buffer = Vec::new();

        let array = [0u8, 54, 34, 85, 78, 45, 8];

        array.bin_serialise_into(& mut buffer);

        assert_eq!(buffer, array);

        let d_array = <[u8; 7]>::bin_deserialise_from(buffer.as_slice(), None);

        assert_eq!(d_array, array)

    }

    #[test]
    fn test_ipv4() {
        let mut buffer = Vec::new();

        let ipv4 = Ipv4Addr::new(245, 67, 12, 34);

        ipv4.bin_serialise_into(& mut buffer);

        assert_eq!(buffer, [245, 67, 12, 34]);

        let d_ipv4 = Ipv4Addr::bin_deserialise_from(buffer.as_slice(), None);

        assert_eq!(d_ipv4, ipv4);
    }

    #[test]
    fn test_ipv6() {
        let mut buffer = Vec::new();

        let ipv6 = Ipv6Addr::from_str("fc86:6e01:204f:498a:33cf:b30a:6171:e74f").unwrap();

        ipv6.bin_serialise_into(& mut buffer);

        assert_eq!(buffer, [0xfc, 0x86, 0x6e, 0x01, 0x20, 0x4f, 0x49, 0x8a, 0x33, 0xcf, 0xb3, 0x0a, 0x61, 0x71, 0xe7, 0x4f]);

        let d_ipv6 = Ipv6Addr::bin_deserialise_from(buffer.as_slice(), None);

        assert_eq!(d_ipv6, ipv6);
    }

    #[test]
    fn test_ipaddr() {
        let mut buffer = Vec::new();

        let ip = IpAddr::V4(Ipv4Addr::from_str("227.82.127.3").unwrap());

        ip.bin_serialise_into(& mut buffer);

        assert_eq!(buffer, [4, 4, 227, 82, 127, 3]);

        let d_ip = IpAddr::bin_deserialise_from(buffer.as_slice(), None);

        assert_eq!(ip, d_ip);
    }

    #[test]
    fn test_string() {
        let mut buffer = Vec::new();

        let string = String::from("abcdefg");

        string.bin_serialise_into(& mut buffer);

        assert_eq!(buffer, [97, 98, 99, 100, 101, 102, 103, 0]);

        let d_string = String::bin_deserialise_from(buffer.as_slice(), None);

        assert_eq!(string, d_string);
    }

    #[test]
    fn test_versions_vector() {
        let mut buffer = Vec::new();

        let list = vec![3, 4];

        let length = list.len();

        let wrap = VersionsVector::from(list);

        wrap.bin_serialise_into(& mut buffer);

        assert_eq!(buffer, [0, 3, 0, 4]);

        let d_wrap = VersionsVector::bin_deserialise_from(buffer.as_slice(), Some(length as u32));

        assert_eq!(Vec::from(wrap), Vec::from(d_wrap));
    }


}