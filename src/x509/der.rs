use std::io;

// TODO just use TlsError?
#[deriving(Show, PartialEq)]
pub enum DerError {
    IoError(io::IoError),
    InvalidValue,
}

macro_rules! iotry(
    ($e:expr) => ({
        match $e {
            Ok(ok) => ok,
            Err(io_err) => return Err(IoError(io_err)),
        }
    })
)

pub type DerResult<T> = Result<T, DerError>;

#[deriving(Show, PartialEq)]
pub enum TagClass {
    Universal = 0b00,
    Application = 0b01,
    ContextSpecific = 0b10,
    Private = 0b11,
}

#[deriving(Show, PartialEq)]
pub enum Element {
    // primitives
    Boolean(bool), // 0x01
    Integer(Vec<u8>), // 0x02
    BitString(u8, Vec<u8>), // 0x03; (number of unused bits, bytes)
    OctetString(Vec<u8>),
    Null, // 0x05
    ObjectIdentifier(Vec<u64>), // 0x06

    Utf8String(String), // 0x0c
    PrintableString(Vec<Ascii>), // 0x13
    IA5String(Vec<Ascii>), // 0x16

    UtcTime(Vec<u8>), // 0x17

    // constructed
    Sequence(Vec<SpannedElement>), // 0x10
    Set(Vec<SpannedElement>), // 0x11

    UnknownPrimitive(u64, TagClass, Vec<u8>), // tag, tag_class, content
    UnknownConstructed(u64, TagClass, Vec<SpannedElement>), //tag, tag_class, content
}

#[deriving(Show)]
pub struct SpannedElement {
    pub elem: Element,
    pub start: uint, // inclusive
    pub end: uint, // exclusive
}

impl PartialEq for SpannedElement {
    fn eq(&self, b: &SpannedElement) -> bool {
        self.elem == b.elem
    }
}

impl SpannedElement {
    fn new(elem: Element, start: uint, end: uint) -> SpannedElement {
        SpannedElement {
            elem: elem,
            start: start,
            end: end,
        }
    }
}

pub struct DerReader<'a, R: 'a> {
    reader: &'a mut R,
    offset: uint,
}

impl<'a, R: Reader> DerReader<'a, R> {
    pub fn new(reader: &'a mut R, offset: uint) -> DerReader<'a, R> {
        DerReader {
            reader: reader,
            offset: offset,
        }
    }

    fn read_u8(&mut self) -> io::IoResult<u8> {
        let v = try!(self.reader.read_u8());
        self.offset += 1;
        Ok(v)
    }
    fn read_exact(&mut self, len: uint) -> io::IoResult<Vec<u8>> {
        let content = try!(self.reader.read_exact(len as uint));
        self.offset += len;
        Ok(content)
    }

    pub fn read_element(&mut self) -> DerResult<SpannedElement> {
        let start = self.offset;

        let (tag_class, is_constructed, tag) = {
            let b0 = iotry!(self.read_u8());
            let class = match b0 >> 6 {
                0b00 => Universal,
                0b01 => Application,
                0b10 => ContextSpecific,
                0b11 => Private,
                _ => unreachable!(),
            };
            let is_constructed = (b0 >> 5) & 0b1 == 0b1;

            let tag = if b0 & 0b1_1111 == 0b1_1111 {
                let mut tag = 0u64;
                loop {
                    let next = iotry!(self.read_u8());
                    tag = (tag << 7) | (next & 0b111_1111) as u64;

                    if next >> 7 == 0 {
                        break;
                    }
                }
                tag
            } else {
                (b0 & 0b1_1111) as u64
            };

            (class, is_constructed, tag)
        };

        let len = {
            let b0 = iotry!(self.read_u8());
            if b0 == 0b1000_0000 {
                // indefinite form is not permitted in DER
                return Err(InvalidValue);
            } else if b0 >> 7 == 1 {
                let lenlen = b0 & 0b111_1111;
                if lenlen == 0b111_1111 {
                    return Err(InvalidValue);
                }
                let mut len = 0u64;
                for _i in range(0u, lenlen as uint) {
                    let next = iotry!(self.read_u8());
                    len = (len << 8) | (next as u64);
                }
                len
            } else {
                b0 as u64
            }
        };

        let content = if !is_constructed {
            // primitives
            let content = iotry!(self.read_exact(len as uint)); // TODO 32-bit issue

            if tag_class != Universal {
                let elem = UnknownPrimitive(tag, tag_class, content);
                return Ok(SpannedElement::new(elem, start, self.offset));
            }

            let len = content.len();
            match tag {
                // EndOfContents doesn't exist in DER
                0x00 => return Err(InvalidValue),

                0x01 => {
                    if len != 1 {
                        return Err(InvalidValue);
                    }

                    let tf = match content[0] {
                        0x00 => false,
                        0xFF => true,
                        _ => return Err(InvalidValue),
                    };
                    Boolean(tf)
                }

                0x02 => {
                    {
                        let content = content.as_slice();

                        let first = match content.get(0) {
                            Some(first) => *first,
                            None => return Err(InvalidValue),
                        };

                        match content.get(1) {
                            Some(&second) => {
                                if first == 0 && second >> 7 == 0 {
                                    return Err(InvalidValue);
                                }
                                if first == 0xFF && second >> 7 == 1 {
                                    return Err(InvalidValue);
                                }
                            }
                            _ => {}
                        }
                    }

                    Integer(content)
                }

                0x03 => {
                    let mut content = content;
                    let unused_bits = match content.remove(0) {
                        Some(c) => c,
                        None => return Err(InvalidValue),
                    };
                    BitString(unused_bits, content)
                }

                0x04 => OctetString(content),

                0x05 => {
                    if len != 0 {
                        return Err(InvalidValue);
                    }
                    Null
                }

                0x06 => {
                    if len == 0 {
                        return Err(InvalidValue);
                    }

                    let content = content.as_slice();

                    let first_two = content[0];
                    let (first, second) = if first_two >= 40 * 2 {
                        (2u64, first_two as u64 - 40 * 2)
                    } else if first_two >= 40 {
                        (1u64, first_two as u64 - 40)
                    } else {
                        (0u64, first_two as u64)
                    };
                    let mut nums = vec!(first, second);

                    let mut i = 1;
                    while i < len {
                        let mut next = content[i];
                        let mut val = (next & 0b0111_1111) as u64;
                        while next >> 7 == 1 {
                            i += 1;
                            next = content[i];
                            val = (val << 7) | (next & 0b0111_1111) as u64;
                        }
                        nums.push(val);
                        i += 1;
                    }

                    ObjectIdentifier(nums)
                }

                0x0c => {
                    match String::from_utf8(content) {
                        Err(_) => return Err(InvalidValue),
                        Ok(content) => Utf8String(content),
                    }
                }
                0x13 => {
                    match content.as_slice().to_ascii_opt() {
                        None => return Err(InvalidValue),
                        Some(content) => PrintableString(Vec::from_slice(content)),
                    }
                }
                0x16 => {
                    match content.as_slice().to_ascii_opt() {
                        None => return Err(InvalidValue),
                        Some(content) => IA5String(Vec::from_slice(content)),
                    }
                }

                0x17 => {
                    // TODO
                    UtcTime(content)
                }

                0x07 | 0x09 | 0x0A | 0x14..0x1E => unimplemented!(),

                _ => {
                    return Err(InvalidValue);
                }
            }
        } else {
            let children = {
                let mut children = Vec::new();
                let mut sub_reader = DerReader::new(self.reader, self.offset);
                while (sub_reader.offset as u64) < self.offset as u64 + len {
                    let child = match sub_reader.read_element() {
                        Ok(child) => child,
                        Err(err) => return Err(err),
                    };
                    children.push(child);
                }
                self.offset = sub_reader.offset;
                children
            };

            if tag_class != Universal {
                let elem = UnknownConstructed(tag, tag_class, children);
                return Ok(SpannedElement::new(elem, start, self.offset));
            }

            match tag {
                0x10 => Sequence(children),
                0x11 => Set(children),

                0x08 | 0x0B => unimplemented!(),

                // some elements can be constructed in BER, but not in DER
                _ => return Err(InvalidValue),
            }
        };

        Ok(SpannedElement::new(content, start, self.offset))
    }
}

#[cfg(test)]
mod test {
    use std::io::BufReader;

    use super::{Element, SpannedElement, DerReader};

    fn parse(input: &[u8]) -> super::DerResult<SpannedElement> {
        let mut mem = BufReader::new(input);
        let mut reader = DerReader::new(&mut mem, 0);
        reader.read_element()
    }

    fn check(input: &[u8], expected: Element) {
        let elem = parse(input).unwrap();
        assert_eq!(elem.elem, expected);
    }

    fn check_eof(input: &[u8]) {
        use std::io;

        let elem = parse(input);
        match elem {
            Err(super::IoError(err)) => {
                if err.kind != io::EndOfFile {
                    fail!("expected EOF, found {}", err);
                }
            }
            other => {
                fail!("expected EOF, found {}", other);
            }
        }
    }

    fn check_invalid(input: &[u8]) {
        let elem = parse(input);
        match elem {
            Err(super::InvalidValue) => {}
            other => {
                fail!("expected InvalidValue, found {}", other);
            }
        }
    }

    #[test]
    fn test_bad_len() {
        check_eof(b"\x00\x01");
        check_eof(b"\x00\x02");

        check_eof(b"\x00\x71");
        check_eof(b"\x00\x72\x00");

        let mut long = vec!(0x00, 0xFF);
        for _ in range(0u, 0x7F) {
            long.push(0x00);
        }
        check_invalid(long.as_slice());

        // indefinite
        check_invalid(b"\x00\x80");
    }

    #[test]
    fn test_boolean() {
        check(b"\x01\x01\xFF", super::Boolean(true));
        check(b"\x01\x01\x00", super::Boolean(false));

        check_invalid(b"\x01\x00");
        check_invalid(b"\x01\x02\x00\x00");
        check_invalid(b"\x01\x01\x01");
    }

    #[test]
    fn test_integer() {
        check(b"\x02\x01\x01", super::Integer(vec!(1)));
        check(b"\x02\x01\xFF", super::Integer(vec!(-1)));

        check_invalid(b"\x02\x00");
        check_invalid(b"\x02\x02\x00\x00");
        check_invalid(b"\x02\x02\xFF\x80");
    }

    #[test]
    fn test_bit_string() {
        check(b"\x03\x07\x04\x0A\x3B\x5F\x29\x1C\xD0",
              super::BitString(4, Vec::from_slice(b"\x0A\x3B\x5F\x29\x1C\xD0")));

        check_invalid(b"\x03\x00");
    }

    #[test]
    fn test_null() {
        check(b"\x05\x00", super::Null);

        check_invalid(b"\x05\x01\x00");
    }

    #[test]
    fn test_object_identifier() {
        let sha256: Vec<u64> = vec!(2, 16, 840, 1, 101, 3, 4, 2, 1);
        check(b"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01", super::ObjectIdentifier(sha256));

        let rsa_sha1: Vec<u64> = vec!(1, 2, 840, 113549, 1, 1, 5);
        check(b"\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05", super::ObjectIdentifier(rsa_sha1));

        check_invalid(b"\x06\x00");
    }

    #[test]
    fn test_sequence() {
        let der = b"\x30\x0A\x16\x05Smith\x01\x01\xFF";
        let elem = parse(der).unwrap();
        assert_eq!(elem.start, 0);
        assert_eq!(elem.end, 12);
        match elem.elem {
            super::Sequence(ref seq) => {
                assert_eq!(seq.get(0).start, 2);
                assert_eq!(seq.get(0).end, 9);
                assert_eq!(seq.get(0).elem, super::IA5String("Smith".to_ascii().to_owned()));

                assert_eq!(seq.get(1).start, 9);
                assert_eq!(seq.get(1).end, 12);
                assert_eq!(seq.get(1).elem, super::Boolean(true));
            }
            _ => fail!("expected sequence"),
        }
    }
}
