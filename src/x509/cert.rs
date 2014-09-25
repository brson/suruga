// Construct certificate struct from asn.1 tree
//
// http://tools.ietf.org/html/rfc5280
// http://tools.ietf.org/html/rfc6818
//
// TODO
// more tests!
// http://csrc.nist.gov/groups/ST/crypto_apps_infra/pki/pkitesting.html
// check ff/chrome testsuite
// "round trip" test? well..
// should Certificate struct "preserve" all information?
// is it important to preserve actual String type? PrintableString, UTF8String, ...

use std::io::BufReader;

use super::{FromElem, BitString, Oid};
use super::der;
use super::der::{Element, DerResult};
use super::alg_id::AlgId;

// Name is actually CHOICE, but there is only one possibility in X.501 / RFC 5280:
// Name ::= CHOICE { rdnSequence  RDNSequence }
// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
#[deriving(Show)]
pub struct Name {
    seq: Vec<RelativeDistinguishedName>,
}

#[deriving(Show)]
pub struct RelativeDistinguishedName {
    set: Vec<AttributeTypeAndValue>,
}

// TODO this should be an enum?
#[deriving(Show)]
pub struct AttributeTypeAndValue {
    attr_type: Oid, // oid
    attr_value: Vec<u8>, // "ANY"
}

// pub enum DirectoryString {
//     // Teletex(der::TeletexString),
//     Printable(PrintableString),
//     // Universal(UniversalString),
//     Utf8(UTF8String),
//     // Bmp(BMPString),
// }

impl Name {
    fn from_seq(children: &[Element]) -> DerResult<Name> {
        let mut seq = Vec::new();
        for elem in children.iter() {
            match elem {
                &der::Set(ref elems) => {
                    debug!("Name: set elems: {}", elems);
                    // TODO
                }
                _ => return Err(der::InvalidValue),
            }
        }

        Ok(Name {
            seq: seq
        })
    }
}

#[deriving(Show)]
pub enum Version {
    Version1,
    Version2,
    Version3,
}

impl Version {
    pub fn from_integer(integer: &[u8]) -> DerResult<Version> {
        if integer.len() != 1 {
            return Err(der::InvalidValue);
        }
        let val = match integer[0] {
            0 => Version1,
            1 => Version2,
            2 => Version3,
            _ => return Err(der::InvalidValue),
        };
        Ok(val)
    }
}

#[deriving(Show)]
pub enum Time {
    UtcTime(Vec<u8>), // TODO raw value
    // GeneralizedTime(der::GeneralizedTime), // TODO
}

impl Time {
    // no fallback
    pub fn from_element(elem: &Element) -> DerResult<Time> {
        let value = match elem {
            &der::UtcTime(ref data) => UtcTime(data.clone()),
            _what => {
                debug!("what: {}", _what);
                return Err(der::InvalidValue);
            }
        };
        Ok(value)
    }
}

macro_rules! seq(
    (
        struct $name:ident {
            $(
                $field:ident: $field_ty:ident
            ),+
        }
    ) => (
        #[deriving(Show)]
        pub struct $name {
            $(
                $field: $field_ty,
            )+
        }

        impl $name {
            pub fn from_elem(elem: &Element) -> DerResult<$name> {
                match elem {
                    &der::Sequence(ref children) => $name::from_seq(children.as_slice()),
                    _ => return Err(der::InvalidValue),
                }
            }

            pub fn from_seq(children: &[Element]) -> DerResult<$name> {
                let mut iter = children.iter();
                $(
                    let $field: $field_ty = match iter.next() {
                        Some(elem) => try!($field_ty::from_element(elem)),
                        None => return Err(der::InvalidValue),
                    };
                )+

                Ok($name {
                    $(
                        $field: $field,
                    )+
                })
            }
        }
    )
)

seq!(struct Validity {
    notBefore: Time,
    notAfter: Time
})

#[deriving(Show)]
pub struct SubjectPublicKeyInfo {
    alg: AlgId,
    subject_pub_key: BitString,
}

impl SubjectPublicKeyInfo {
    pub fn from_seq(children: &[Element]) -> DerResult<SubjectPublicKeyInfo> {
        let mut iter = children.iter();
        let alg: AlgId = match iter.next() {
            Some(elem) => try!(FromElem::from_elem(elem)),
            _ => return Err(der::InvalidValue),
        };

        let subject_pub_key = match iter.next() {
            Some(&der::BitStringElem(ref elem)) => elem.clone(),
            _ => return Err(der::InvalidValue),
        };

        Ok(SubjectPublicKeyInfo {
            alg: alg,
            subject_pub_key: subject_pub_key,
        })
    }
}

#[deriving(Show)]
pub struct Extension {
    extnID: Oid, // OBJECT IDENTIFIER,
    critical: bool, // DEFAULT FALSE,
    extnValue: Vec<u8>, // OCTET STRING
// -- contains the DER encoding of an ASN.1 value
// -- corresponding to the extension type identified
// -- by extnID
}

// impl FromElem for Extension {
//     fn from_elem_opt(elem: &Element) -> DerResult<Option<Extension>> {
//         match elem {
//             &der::Sequence(ref children) => {
//                 let mut iter = children.iter();
//             }
//         }
//     }
// }

#[deriving(Show)]
pub struct TbsCertificate {
    version: Version,
    serial_number: Vec<u8>,
    signature: AlgId,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_pub_key_info: SubjectPublicKeyInfo,

    // If present, version MUST be v2 or v3
    issuer_unique_id: Option<BitString>,
    subject_unique_id:  Option<BitString>,

    // simplified version of:
    // extensions: Option<Extensions>, // If present, version MUST be v3
    // Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
    extensions: Vec<Extension>,
}

impl TbsCertificate {
    pub fn from_seq(children: &[Element]) -> DerResult<TbsCertificate> {
        let mut iter = children.iter().peekable();

        let (version, matched): (Version, bool) = match iter.peek() {
            Some(&&der::UnknownConstructed(0, der::ContextSpecific, ref elems)) => {
                // real routine starts here

                if elems.len() != 1 {
                    return Err(der::InvalidValue);
                }

                let val = match elems.get(0) {
                    &der::Integer(ref vals) => try!(Version::from_integer(vals.as_slice())),
                    _ => return Err(der::InvalidValue),
                };

                // real routine ends here

                (val, true)
            },
            // default
            _ => (Version1, false),
        };
        if matched {
            iter.next();
        }
        debug!("version: {}", version);

        let serial_number: Vec<u8> = match iter.next() {
            Some(&der::Integer(ref vals)) => {
                vals.clone()
            }
            _ => return Err(der::InvalidValue),
        };
        debug!("serial_number: {}", serial_number);

        let signature: AlgId = match iter.next() {
            Some(elem) => try!(FromElem::from_elem(elem)),
            _ => return Err(der::InvalidValue),
        };
        debug!("signature: {}", signature);

        let issuer: Name = match iter.next() {
            Some(&der::Sequence(ref children)) => try!(Name::from_seq(children.as_slice())),
            _ => return Err(der::InvalidValue),
        };
        debug!("issuer: {}", issuer);

        let validity: Validity = match iter.next() {
            Some(&der::Sequence(ref children)) => try!(Validity::from_seq(children.as_slice())),
            _ => return Err(der::InvalidValue),
        };
        debug!("validity: {}", validity);

        let subject: Name = match iter.next() {
            Some(&der::Sequence(ref children)) => try!(Name::from_seq(children.as_slice())),
            _ => return Err(der::InvalidValue),
        };
        debug!("subject: {}", subject);

        let subject_pub_key_info: SubjectPublicKeyInfo = match iter.next() {
            Some(&der::Sequence(ref children)) => try!(SubjectPublicKeyInfo::from_seq(children.as_slice())),
            _ => return Err(der::InvalidValue),
        };
        debug!("subject_pub_key_info: {}", subject_pub_key_info);

        // TODO should not exist for version 1
        let issuer_unique_id: Option<BitString> = match iter.peek() {
            Some(&&der::BitStringElem(ref bitstring)) => Some(bitstring.clone()),
            _ => None,
        };
        match issuer_unique_id {
            Some(..) => { iter.next(); }
            None => {}
        }
        debug!("issuer_unique_id: {}", issuer_unique_id);

        // TODO should not exist for version 1
        let subject_unique_id: Option<BitString> = match iter.peek() {
            Some(&&der::BitStringElem(ref bitstring)) => Some(bitstring.clone()),
            _ => None,
        };
        match subject_unique_id {
            Some(..) => { iter.next(); }
            None => {}
        }
        debug!("subject_unique_id: {}", subject_unique_id);

        // TODO only for version 3
        let mut extensions = Vec::new();
        match iter.next() {
            // [3] EXPLICIT
            Some(&der::UnknownConstructed(3, der::ContextSpecific, ref elems)) => {
                // TODO right?
                if elems.len() != 1 {
                    return Err(der::InvalidValue);
                }
                match elems[0] {
                    der::Sequence(ref children) => {
                        for child in children.iter() {
                            debug!("child: {}", child);
                        }
                    }
                    _ => return Err(der::InvalidValue),
                }
            }
            Some(..) => return Err(der::InvalidValue),
            None => {}
        }

        match iter.next() {
            Some(..) => debug!("ERROR: value remains"),
            _ => {}
        }

        Ok(TbsCertificate {
            version: version,
            serial_number: serial_number,
            signature: signature,
            issuer: issuer,
            validity: validity,
            subject: subject,
            subject_pub_key_info: subject_pub_key_info,
            issuer_unique_id: issuer_unique_id,
            subject_unique_id: subject_unique_id,
            extensions: extensions,
        })
    }
}

#[deriving(Show)]
pub struct Certificate {
    tbs_cert: TbsCertificate,
    sig_alg: AlgId,
    sig_val: BitString,
}

impl Certificate {
    pub fn from_seq(children: &[Element]) -> DerResult<Certificate> {
        let mut iter = children.iter();

        let tbs_cert: TbsCertificate = match iter.next() {
            Some(&der::Sequence(ref children)) => {
                match TbsCertificate::from_seq(children.as_slice()) {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(der::InvalidValue),
        };

        let sig_alg: AlgId = match iter.next() {
            Some(elem) => try!(FromElem::from_elem(elem)),
            _ => return Err(der::InvalidValue),
        };

        if sig_alg != tbs_cert.signature {
            // TODO better error msg
            return Err(der::InvalidValue);
        }

        let sig_val: BitString = match iter.next() {
            Some(&der::BitStringElem(ref bitstring)) => {
                bitstring.clone()
            }
            _ => return Err(der::InvalidValue),
        };

        // too long
        match iter.next() {
            Some(..) => return Err(der::InvalidValue),
            None => {}
        }

        Ok(Certificate {
            tbs_cert: tbs_cert,
            sig_alg: sig_alg,
            sig_val: sig_val,
        })
    }
}

// TODO DerResult? TlsResult?
pub fn parse_certificate(cert: &[u8]) -> DerResult<Certificate> {
    let cert_tree = {
        let mut mem = BufReader::new(cert);
        let mut reader = der::DerReader::new(&mut mem, 0);

        let cert_tree = try!(reader.read_element());
        cert_tree
    };

    // TODO: compute length of TbsCertificate

    let certificate = match cert_tree {
        der::Sequence(ref children) => {
            Certificate::from_seq(children.as_slice())
        }
        _ => {
            debug!("cert parse err");
            return Err(der::InvalidValue);
        }
    };

    // TODO

    certificate
}
