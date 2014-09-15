// Construct certificate struct from asn.1 tree
//
// http://tools.ietf.org/html/rfc5280
// http://tools.ietf.org/html/rfc6818

use std::io::BufReader;

use super::FromAsnTree;
use super::der;
use super::der::{Element, DerResult};
use super::alg_id::AlgorithmIdentifier;

// Name is actually CHOICE, but there is only one possibility in RFC 5280:
// Name ::= CHOICE { rdnSequence  RDNSequence }
// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
#[deriving(Show)]
pub struct Name {
    seq: Vec<RelativeDistinguishedName>,
}

// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
#[deriving(Show)]
pub struct RelativeDistinguishedName {
    // TODO 1..MAX
    set: Vec<AttributeTypeAndValue>,
}

#[deriving(Show)]
pub struct AttributeTypeAndValue {
    attr_type: Vec<u8>, // oid
    attr_value: Vec<u8>, // "ANY"
}

impl FromAsnTree for Name {
    fn from_asn(children: &[Element]) -> DerResult<Name> {
        let mut seq = Vec::new();
        for elem in children.iter() {
            match elem {
                &der::Set(ref elems) => {
                    debug!("set elems: {}", elems);
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

#[deriving(Show)]
pub struct Validity {
    notBefore: Time,
    notAfter: Time,
}

impl Validity {
    pub fn from_seq(children: &[Element]) -> DerResult<Validity> {
        let mut iter = children.iter();
        let notBefore = match iter.next() {
            Some(&der::UtcTime(ref data)) => UtcTime(data.clone()),
            _what => {
                debug!("what: {}", _what);
                return Err(der::InvalidValue);
            }
        };

        let notAfter = match iter.next() {
            Some(&der::UtcTime(ref data)) => UtcTime(data.clone()),
            _ => return Err(der::InvalidValue),
        };

        Ok(Validity {
            notBefore: notBefore,
            notAfter: notAfter,
        })
    }
}

pub struct TbsCertificate {
    version: Version,
    serial_number: Vec<u8>,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    // subjectPublicKeyInfo: SubjectPublicKeyInfo,
    // issuerUniqueID: Option<UniqueIdentifier>, // If present, version MUST be v2 or v3
    // subjectUniqueID:  Option<UniqueIdentifier>, // If present, version MUST be v2 or v3
    // extensions: Option<Extensions>, // If present, version MUST be v3
}

impl FromAsnTree for TbsCertificate {
    fn from_asn(children: &[Element]) -> DerResult<TbsCertificate> {
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
            None => (Version1, false),
            _ => return Err(der::InvalidValue),
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

        let signature: AlgorithmIdentifier = match iter.next() {
            Some(&der::Sequence(ref children)) => try!(FromAsnTree::from_asn(children.as_slice())),
            _ => return Err(der::InvalidValue),
        };
        debug!("signature: {}", signature);

        let issuer: Name = match iter.next() {
            Some(&der::Sequence(ref children)) => try!(FromAsnTree::from_asn(children.as_slice())),
            _ => return Err(der::InvalidValue),
        };
        debug!("issuer: {}", issuer);

        let validity: Validity = match iter.next() {
            Some(&der::Sequence(ref children)) => try!(Validity::from_seq(children.as_slice())),
            _ => return Err(der::InvalidValue),
        };
        debug!("validity: {}", validity);

        let subject: Name = match iter.next() {
            Some(&der::Sequence(ref children)) => try!(FromAsnTree::from_asn(children.as_slice())),
            _ => return Err(der::InvalidValue),
        };
        debug!("subject: {}", subject);

        match iter.next() {
            Some(_) => debug!("ERROR: value remains"),
            _ => {}
        }

        Ok(TbsCertificate {
            version: version,
            serial_number: serial_number,
            signature: signature,
            issuer: issuer,
            validity: validity,
            subject: subject,
        })
    }
}

pub struct Certificate {
    tbs_cert: TbsCertificate,
    sig_alg: AlgorithmIdentifier,
    sig_val: Vec<u8>,
}

impl FromAsnTree for Certificate {
    fn from_asn(children: &[Element]) -> DerResult<Certificate> {
        let mut idx = 0;

        let tbs_cert: TbsCertificate = match children.get(idx) {
            Some(&der::Sequence(ref children)) => {
                idx += 1;
                match FromAsnTree::from_asn(children.as_slice()) {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(der::InvalidValue),
        };

        let sig_alg: AlgorithmIdentifier = match children.get(idx) {
            Some(&der::Sequence(ref children)) => {
                idx += 1;
                match FromAsnTree::from_asn(children.as_slice()) {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(der::InvalidValue),
        };

        let sig_val: Vec<u8> = match children.get(idx) {
            Some(&der::BitString(n, ref c)) => {
                idx += 1;
                if n != 0 {
                    unimplemented!();
                }
                c.clone()
            }
            _ => return Err(der::InvalidValue),
        };

        if idx != children.len() {
            // too long
            return Err(der::InvalidValue);
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
            FromAsnTree::from_asn(children.as_slice())
        }
        _ => {
            debug!("cert parse err");
            return Err(der::InvalidValue);
        }
    };

    // TODO

    certificate
}
