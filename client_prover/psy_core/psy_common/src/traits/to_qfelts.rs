use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::target::Target,
};

use crate::data::qhashout::QHashOut;

pub trait QFeltSized {
    fn q_felt_size() -> usize;
    fn self_qsize(&self) -> usize {
        Self::q_felt_size()
    }
}
pub trait ToQFelts<F> {
    fn to_qfelts(&self) -> Vec<F>;
    fn from_qfelts(felts: &[F]) -> Self;
}

impl<F: RichField> ToQFelts<F> for HashOut<F> {
    fn to_qfelts(&self) -> Vec<F> {
        self.elements.to_vec()
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 4 {
            panic!("Invalid number of elements for HashOut");
        }
        Self {
            elements: [felts[0], felts[1], felts[2], felts[3]],
        }
    }
}
impl<F: RichField> ToQFelts<F> for QHashOut<F> {
    fn to_qfelts(&self) -> Vec<F> {
        self.0.elements.to_vec()
    }
    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 4 {
            panic!("Invalid number of elements for QHashOut");
        }
        QHashOut(HashOut {
            elements: [felts[0], felts[1], felts[2], felts[3]],
        })
    }
}
impl ToQFelts<Target> for HashOutTarget {
    fn to_qfelts(&self) -> Vec<Target> {
        self.elements.to_vec()
    }
    fn from_qfelts(felts: &[Target]) -> Self {
        if felts.len() != 4 {
            panic!("Invalid number of elements for QHashOut");
        }
        HashOutTarget {
            elements: [felts[0], felts[1], felts[2], felts[3]],
        }
    }
}

impl<F: RichField> ToQFelts<F> for F {
    fn to_qfelts(&self) -> Vec<F> {
        vec![*self]
    }
    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 1 {
            panic!("Invalid number of elements for Felt");
        }
        felts[0]
    }
}

impl<F: RichField, const N: usize> ToQFelts<F> for [F; N] {
    fn to_qfelts(&self) -> Vec<F> {
        self.to_vec()
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != N {
            panic!("Invalid number of elements for array");
        }
        core::array::from_fn(|i| felts[i])
    }
}
impl<F: RichField, const N: usize> QFeltSized for [F; N] {
    fn q_felt_size() -> usize {
        N
    }
}

impl<F: RichField> QFeltSized for HashOut<F> {
    fn q_felt_size() -> usize {
        4
    }
}
impl<F: RichField> QFeltSized for QHashOut<F> {
    fn q_felt_size() -> usize {
        4
    }
}
