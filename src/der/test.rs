use der::{Tag, FromTlv, FromValue, DerResult};
use der::reader::DerReader;

#[derive(Debug, PartialEq)]
struct OctetString(Vec<u8>);
from_value!(OctetString: Tag::OctetString);
impl FromValue for OctetString {
    fn from_value(value: &[u8]) -> DerResult<OctetString> {
        Ok(OctetString(value.to_vec()))
    }
}

#[derive(Debug, PartialEq)]
struct Null;
from_value!(Null: Tag::Null);
impl FromValue for Null {
    fn from_value(value: &[u8]) -> DerResult<Null> {
        assert_eq!(value.len(), 0);
        Ok(Null)
    }
}

sequence_opts!(#[derive(PartialEq)] struct DefaultOptional {
    default(DEFAULT false, Tag::Boolean): bool,
    optional(OPTIONAL Tag::OctetString): Option<OctetString>,
    null(): Null,
});

#[test]
fn test_default_optional() {
    let ders: Vec<(Vec<u8>, DefaultOptional)> = vec![
        (vec![0x30, 0x02, 0x05, 0x00], DefaultOptional {
            default: false,
            optional: None,
            null: Null,
        }),
        (vec![0x30, 0x05, 0x01, 0x01, 0xFF, 0x05, 0x00], DefaultOptional {
            default: true,
            optional: None,
            null: Null,
        }),
        (vec![0x30, 0x05, 0x04, 0x01, 0x12, 0x05, 0x00], DefaultOptional {
            default: false,
            optional: Some(OctetString(vec!(0x12))),
            null: Null,
        }),
        (vec![0x30, 0x08, 0x01, 0x01, 0xFF, 0x04, 0x01, 0x12, 0x05, 0x00], DefaultOptional {
            default: true,
            optional: Some(OctetString(vec!(0x12))),
            null: Null,
        }),
    ];

    for &(ref der, ref expected) in ders.iter() {
        let mut reader = DerReader::new(&der[]);
        let (tag, value) = reader.next_tlv().unwrap();
        let actual: DefaultOptional = FromTlv::from_tlv(tag, value).unwrap();
        assert_eq!(expected, &actual);
        assert!(reader.is_eof());
    }
}
