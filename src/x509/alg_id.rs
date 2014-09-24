use super::der::{Element, DerResult};
use super::der;
use super::{FromElem, Oid};

#[deriving(Clone, PartialEq, Show)]
pub struct AlgId {
    pub alg: Oid,
    // pub params: Vec<u8>, // TODO
}

impl AlgId {
    pub fn new(alg: Oid) -> AlgId {
        AlgId {
            alg: alg,
        }
    }
}

impl FromElem for AlgId {
    fn from_elem_opt(elem: &Element) -> DerResult<Option<AlgId>> {
        match elem {
            &der::Sequence(ref children) => {
                let mut iter = children.iter();
                let alg: Oid = match iter.next() {
                    Some(next) => try!(FromElem::from_elem(next)),
                    None => return Err(der::InvalidValue),
                };

                // TODO params
                let _ = iter.next();

                match iter.next() {
                    Some(..) => return Err(der::InvalidValue),
                    None => {}
                }

                Ok(Some(AlgId {
                    alg: alg,
                }))
            }
            _ => Ok(None),
        }
    }
}

// "Encryption" means signature.
// alg_identifier!(
//     // TODO incomplete
//     // RFC 3279
//     rsaEncryption = [1, 2, 840, 113549, 1, 1, 1],
//     md5WithRSAEncryption = [1, 2, 840, 113549, 1, 1, 4],
//     sha1WithRSAEncryption = [1, 2, 840, 113549, 1, 1, 5],
//     // RFC 4055
//     sha256WithRSAEncryption = [1, 2, 840, 113549, 1, 1, 11],
//     sha384WithRSAEncryption = [1, 2, 840, 113549, 1, 1, 12],
//     sha512WithRSAEncryption = [1, 2, 840, 113549, 1, 1, 13],
//     sha224WithRSAEncryption = [1, 2, 840, 113549, 1, 1, 14]
// )

// impl AlgorithmIdentifier {
//     pub fn from_seq(children: &[Element]) -> DerResult<AlgorithmIdentifier> {
//         let mut iter = children.iter();

//         let algorithm: &[u64] = match iter.next() {
//             Some(&der::ObjectIdentifier(ref oid)) => oid.as_slice(),
//             _ => return Err(der::InvalidValue),
//         };
//         debug!("algorithm: {}", algorithm);

//         // TODO: parameter
//         match iter.next() {
//             Some(&der::Null) => {},
//             _ => unimplemented!(),
//         }

//         // TODO more more

//         match AlgorithmIdentifier::from_obj_id(algorithm) {
//             Some(alg) => Ok(alg),
//             None => return Err(der::InvalidValue),
//         }
//     }
// }
