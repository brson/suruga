use self::der::{Element, DerResult};

pub mod der;

pub mod alg_id;
pub mod cert;

pub trait FromElem {
    // return `Some(value)` if `elem` is a valid variant for `Self`.
    // return `None` if `elem` is not matched.
    fn from_elem_opt(elem: &Element) -> DerResult<Option<Self>>;

    fn from_elem(elem: &Element) -> DerResult<Self> {
        match try!(FromElem::from_elem_opt(elem)) {
            Some(val) => Ok(val),
            None => return Err(der::InvalidValue),
        }
    }
}

impl FromElem for bool {
    fn from_elem_opt(elem: &Element) -> DerResult<Option<bool>> {
        match elem {
            &der::Boolean(val) => Ok(Some(val)),
            _ => Ok(None),
        }
    }
}

#[deriving(Clone, PartialEq, Show)]
pub struct BitString {
    pub unused_bits: u8,
    pub data: Vec<u8>,
}

impl BitString {
    pub fn new(unused_bits: u8, data: Vec<u8>) -> BitString {
        BitString {
            unused_bits: unused_bits,
            data: data,
        }
    }
}

impl FromElem for BitString {
    fn from_elem_opt(elem: &Element) -> DerResult<Option<BitString>> {
        match elem {
            &der::BitStringElem(ref bs) => Ok(Some(bs.clone())),
            _ => Ok(None),
        }
    }
}

// object id
#[deriving(Clone, PartialEq, Show)]
pub struct Oid {
    pub value: Vec<u64>,
}

impl Oid {
    pub fn new(value: Vec<u64>) -> Oid {
        Oid {
            value: value,
        }
    }
}

impl FromElem for Oid {
    fn from_elem_opt(elem: &Element) -> DerResult<Option<Oid>> {
        match elem {
            &der::ObjectIdentifier(ref oid) => Ok(Some(oid.clone())),
            _ => Ok(None),
        }
    }
}
