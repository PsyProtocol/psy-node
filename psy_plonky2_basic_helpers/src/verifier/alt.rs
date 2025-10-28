use parth_core::{pgoldilocks::QHashOut, utils::math::log2_strict};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::{hash_types::RichField, merkle_tree::MerkleCap},
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct AltVerifierOnlyCircuitData<F: RichField> {
    pub constants_sigmas_cap: Vec<QHashOut<F>>,
    pub circuit_digest: QHashOut<F>,
}

impl<F: RichField> AltVerifierOnlyCircuitData<F> {
    pub fn new_from_verifier_data<C: GenericConfig<D, F = F>, const D: usize>(verifier_data: &VerifierOnlyCircuitData<C, D>) -> Self
    where
        C::Hasher: AlgebraicHasher<F>,
        F: Extendable<D>,
    {
        verifier_data.into()
    }
    pub fn to_verifier_data<C: GenericConfig<D, F = F>, const D: usize>(&self) -> VerifierOnlyCircuitData<C, D>
    where
        C::Hasher: AlgebraicHasher<F>,
        F: Extendable<D>,
    {
        VerifierOnlyCircuitData {
            constants_sigmas_cap: MerkleCap(self.constants_sigmas_cap.iter().map(|x| x.0).collect()),
            circuit_digest: self.circuit_digest.0,
        }
    }
    pub fn get_cap_height(&self) -> usize {
        log2_strict(self.constants_sigmas_cap.len())
    }
}
impl<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, C: GenericConfig<D, F = F, Hasher = H>, const D: usize> From<&VerifierOnlyCircuitData<C, D>>
    for AltVerifierOnlyCircuitData<F>
{
    fn from(value: &VerifierOnlyCircuitData<C, D>) -> Self {
        Self {
            constants_sigmas_cap: value.constants_sigmas_cap.0.iter().map(|x| QHashOut(*x)).collect(),
            circuit_digest: QHashOut(value.circuit_digest),
        }
    }
}
impl<F: RichField + Extendable<D>, H: AlgebraicHasher<F>, C: GenericConfig<D, F = F, Hasher = H>, const D: usize> From<VerifierOnlyCircuitData<C, D>>
    for AltVerifierOnlyCircuitData<F>
{
    fn from(value: VerifierOnlyCircuitData<C, D>) -> Self {
        Self {
            constants_sigmas_cap: value.constants_sigmas_cap.0.iter().map(|x| QHashOut(*x)).collect(),
            circuit_digest: QHashOut(value.circuit_digest),
        }
    }
}
