use crate::common::data::core::hash::hash256::Hash256;

pub trait QPHashable {
    fn get_qp_hash(&self) -> Hash256;
}