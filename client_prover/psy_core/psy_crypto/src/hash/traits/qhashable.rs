use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;

use super::hasher::FieldQHasher;

pub trait QFieldHashable<F: RichField> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F>;
}
