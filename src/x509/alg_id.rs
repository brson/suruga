use super::der::{Element, DerResult};
use super::der;
use super::FromAsnTree;

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

impl FromAsnTree for AlgorithmIdentifier {
    fn from_asn(children: &[Element]) -> DerResult<AlgorithmIdentifier> {
        let mut iter = children.iter();
        let mut next = iter.next();
        let mut _consumed = false;

        let algorithm: &[u64] = match next {
            Some(&der::ObjectIdentifier(ref oid)) => oid.as_slice(),
            _ => return Err(der::InvalidValue),
        };
        next = iter.next();

        // TODO: parameter
        match next {
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
