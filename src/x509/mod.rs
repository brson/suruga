use self::der::{Element, DerResult};

pub mod der;

pub mod alg_id;
pub mod cert;

// TODO: rename to "FromAsnSeq"? what about Set/UnknownConstructed?
pub trait FromAsnTree {
    fn from_asn(children: &[Element]) -> DerResult<Self>;
}
