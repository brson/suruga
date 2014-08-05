// http://tools.ietf.org/html/rfc5280
// http://tools.ietf.org/html/rfc6818

// TODO: just a hack for now

use std::io::BufReader;

use super::der;
use super::der::{Element, SpannedElement};

#[inline(always)]
fn get_elem<'a>(s: Option<&'a SpannedElement>) -> Option<&'a Element> {
    match s {
        Some(sp) => Some(&sp.elem),
        None => None,
    }
}

// TODO parameters..
macro_rules! alg_identifier(
    ($(
        $id:ident = [$($v:expr),+]
    ),+) => (
        #[allow(non_camel_case_types)]
        pub enum AlgorithmIdentifier {
            $(
                $id,
            )+
        }

        impl AlgorithmIdentifier {
            pub fn from_obj_id(s: &[u64]) -> Option<AlgorithmIdentifier> {
                $({
                    let expected = [$($v),+];
                    if s == expected.as_slice() {
                        return Some($id);
                    }
                })+
                return None;
            }
        }
    )
)

// "Encryption" means signature.
alg_identifier!(
    // TODO incomplete
    // RFC 3279
    rsaEncryption = [1, 2, 840, 113549, 1, 1, 1],
    md5WithRSAEncryption = [1, 2, 840, 113549, 1, 1, 4],

    // RFC 4055
    sha256WithRSAEncryption = [1, 2, 840, 113549, 1, 1, 11],
    sha384WithRSAEncryption = [1, 2, 840, 113549, 1, 1, 12],
    sha512WithRSAEncryption = [1, 2, 840, 113549, 1, 1, 13],
    sha224WithRSAEncryption = [1, 2, 840, 113549, 1, 1, 14]
)

impl AlgorithmIdentifier {
    fn parse_elem(children: &[SpannedElement]) -> der::DerResult<AlgorithmIdentifier> {
        let mut iter = children.iter();
        let mut next = iter.next();
        let mut _consumed = false;

        let algorithm: &[u64] = match get_elem(next) {
            Some(&der::ObjectIdentifier(ref oid)) => oid.as_slice(),
            _ => return Err(der::InvalidValue),
        };
        next = iter.next();

        // TODO: parameter
        match get_elem(next) {
            Some(&der::Null) => {},
            _ => unimplemented!(),
        }
        next = iter.next();

        match AlgorithmIdentifier::from_obj_id(algorithm) {
            Some(alg) => Ok(alg),
            None => return Err(der::InvalidValue),
        }
    }
}

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

impl Name {
    fn parse_elem(children: &[SpannedElement]) -> der::DerResult<Name> {
        //unimplemented!();
        // TODO
        Ok(Name {
            vals: 1,
        })
    }
}

pub struct TbsCertificate {
    version: u8,
    serial_number: Vec<u8>,
    signature: AlgorithmIdentifier,
    issuer: Name,
    //validity: Validity,
    //subject: Name,
    //subjectPublicKeyInfo: SubjectPublicKeyInfo,
    //issuerUniqueID: Option<UniqueIdentifier>, // If present, version MUST be v2 or v3
    //subjectUniqueID:  Option<UniqueIdentifier>, // If present, version MUST be v2 or v3
    //extensions: Option<Extensions>, // If present, version MUST be v3
}

impl TbsCertificate {
    fn parse_elem(children: &[SpannedElement]) -> der::DerResult<TbsCertificate> {
        let mut iter = children.iter();
        let mut next = iter.next();

        let version: u8 = {
            let mut consumed = false;
            let value = match get_elem(next) {
                Some(&der::UnknownConstructed(0, der::ContextSpecific, ref elems)) => {
                    consumed = true;

                    if elems.len() != 1 {
                        return Err(der::InvalidValue);
                    }
                    match elems.get(0).elem {
                        der::Integer(ref vals) => {
                            if vals.len() != 1 {
                                return Err(der::InvalidValue);
                            }
                            *vals.get(0)
                        }
                        _ => return Err(der::InvalidValue),
                    }
                }
                _ => 1u8,
            };
            if consumed {
                next = iter.next();
            }
            value
        };

        let serial_number: Vec<u8> = match get_elem(next) {
            Some(&der::Integer(ref vals)) => vals.clone(),
            _ => return Err(der::InvalidValue),
        };
        next = iter.next();

        let signature: AlgorithmIdentifier = match get_elem(next) {
            Some(&der::Sequence(ref children)) => {
                match AlgorithmIdentifier::parse_elem(children.as_slice()) {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(der::InvalidValue),
        };
        next = iter.next();

        let issuer: Name = match get_elem(next) {
            Some(&der::Sequence(ref children)) => {
                match Name::parse_elem(children.as_slice()) {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(der::InvalidValue),
        };
        next = iter.next();

        // if next != None {
        //  ....
        // }

        Ok(TbsCertificate {
            version: version,
            serial_number: serial_number,
            signature: signature,
            issuer: issuer,
        })
    }
}

pub struct Certificate {
    tbs_cert: TbsCertificate,
    sig_alg: AlgorithmIdentifier,
    sig_val: Vec<u8>,
}

impl Certificate {
    fn parse_elem(children: &[SpannedElement]) -> der::DerResult<Certificate> {
        let mut iter = children.iter();
        let mut next = iter.next();
        let mut _consumed = false;

        let tbs_cert: TbsCertificate = match get_elem(next) {
            Some(&der::Sequence(ref children)) => {
                match TbsCertificate::parse_elem(children.as_slice()) {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(der::InvalidValue),
        };
        next = iter.next();

        let sig_alg: AlgorithmIdentifier = match get_elem(next) {
            Some(&der::Sequence(ref children)) => {
                match AlgorithmIdentifier::parse_elem(children.as_slice()) {
                    Ok(s) => s,
                    Err(e) => return Err(e),
                }
            }
            _ => return Err(der::InvalidValue),
        };
        next = iter.next();

        let sig_val: Vec<u8> = match get_elem(next) {
            Some(&der::BitString(n, ref c)) => {
                if n != 0 {
                    unimplemented!();
                }
                c.clone()
            }
            _ => return Err(der::InvalidValue),
        };
        next = iter.next();

        Ok(Certificate {
            tbs_cert: tbs_cert,
            sig_alg: sig_alg,
            sig_val: sig_val,
        })
    }
}

// TODO DerResult? TlsResult?
pub fn parse_certificate(cert: &[u8]) -> der::DerResult<Certificate> {
    let cert_tree = {
        let mut mem = BufReader::new(cert);
        let mut reader = der::DerReader::new(&mut mem, 0);

        let cert_tree = try!(reader.read_element());
        cert_tree
    };

    let certificate = match cert_tree.elem {
        der::Sequence(ref children) => {
            Certificate::parse_elem(children.as_slice())
        }
        _ => return Err(der::InvalidValue),
    };

    // TODO

    certificate
}
