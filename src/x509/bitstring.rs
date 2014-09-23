// TODO rename to bit_string.rs?

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
