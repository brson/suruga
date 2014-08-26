// Construct certificate struct from asn.1 tree
//
// http://tools.ietf.org/html/rfc5280
// http://tools.ietf.org/html/rfc6818

use std::io::BufReader;

use super::FromAsnTree;
use super::der;
use super::der::{Element, DerResult};
use super::alg_id::AlgorithmIdentifier;

// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
// RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
// AttributeTypeAndValue ::= SEQUENCE {
// type     AttributeType,
// value    AttributeValue }
// AttributeType ::= OBJECT IDENTIFIER
// AttributeValue ::= ANY -- DEFINED BY AttributeType
pub struct Name {
    //rdnSequence(RDNSequence),
    // TODO dummy
    vals: int,
}

impl FromAsnTree for Name {
    fn from_asn(children: &[Element]) -> DerResult<Name> {
        //unimplemented!();
        // TODO
        Ok(Name {
            vals: 1,
        })
    }
}

pub enum Version {
    Version1,
    Version2,
    Version3,
}

impl Version {
    pub fn default() -> Version {
        Version1
    }
}

pub struct TbsCertificate {
    version: Version,
    serial_number: Vec<u8>,
    signature: AlgorithmIdentifier,
    issuer: Name,
    // validity: Validity,
    // subject: Name,
    // subjectPublicKeyInfo: SubjectPublicKeyInfo,
    // issuerUniqueID: Option<UniqueIdentifier>, // If present, version MUST be v2 or v3
    // subjectUniqueID:  Option<UniqueIdentifier>, // If present, version MUST be v2 or v3
    // extensions: Option<Extensions>, // If present, version MUST be v3
}

impl FromAsnTree for TbsCertificate {
    fn from_asn(children: &[Element]) -> DerResult<TbsCertificate> {
        let mut index = 0u;

        let version: Version = match children.get(index) {
            Some(&der::UnknownConstructed(0, der::ContextSpecific, ref elems)) => {
                index += 1;

                // real routine here

                if elems.len() != 1 {
                    return Err(der::InvalidValue);
                }

                let val = match elems.get(0) {
                    &der::Integer(ref vals) => {
                        if vals.len() != 1 {
                            return Err(der::InvalidValue);
                        }
                        let val = *vals.get(0);
                        let val = match val {
                            0 => Version1,
                            1 => Version2,
                            2 => Version3,
                            _ => return Err(der::InvalidValue),
                        };
                        val
                    }
                    _ => return Err(der::InvalidValue),
                };

                // real routine ends here

                val
            },
            None => Version::default(),
            _ => return Err(der::InvalidValue),
        };

        match children.get(index) {
            Some(&der::UnknownConstructed(0, der::ContextSpecific, ref elems)) => {
                index += 1;

                if elems.len() != 1 {
                    return Err(der::InvalidValue);
                }
                match elems.get(0) {
                    &der::Integer(ref vals) => {
                        if vals.len() != 1 {
                            return Err(der::InvalidValue);
                        }
                        *vals.get(0)
                    }
                    _ => return Err(der::InvalidValue),
                }
            }
            // default
            _ => {
                1u8
            }
        };

        let serial_number: Vec<u8> = match children.get(index) {
            Some(&der::Integer(ref vals)) => {
                index += 1;
                vals.clone()
            }
            _ => return Err(der::InvalidValue),
        };

        let signature: AlgorithmIdentifier = match children.get(index) {
            Some(&der::Sequence(ref children)) => {
                index += 1;
                match FromAsnTree::from_asn(children.as_slice()) {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(der::InvalidValue),
        };

        let issuer: Name = match children.get(index) {
            Some(&der::Sequence(ref children)) => {
                index += 1;
                match FromAsnTree::from_asn(children.as_slice()) {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(der::InvalidValue),
        };

        if index != children.len() {
            debug!("ERROR: value remains");
        }

        Ok(TbsCertificate {
            version: version,
            serial_number: serial_number,
            signature: signature,
            issuer: issuer,
        })
    }
}

// macro_rules! foo(
//     (
//         struct $name:ident {
//             $(
//                 $elem:ident: $ty:ty $asn_ty:ident
//             ),+
//         }
//     ) => (
//         pub struct $name {
//             $(
//                 $elem: $ty,
//             )+
//         }

//         impl FromAsnTree for $name {
//             fn from_asn(children: $[Element] -> DerResult<$name> {
//                 let mut idx = 0;
//                 $(
//                     let $elem: $ty = match children.get(idx) {
//                         Some(&bar!($asn_ty, children))
//                     }
//                 )+
//             }
//         }
//     )
// )

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
        _ => return Err(der::InvalidValue),
    };

    // TODO

    certificate
}
