use jsonrpsee::http_client::HttpClient;
use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleZeroHasher},
    felt::QFelt64,
    pgoldilocks::QHashOut,
    protocol::core_types::{QFHashBase, QNetworkTypesConfig},
};
use plonky2::{
    hash::hash_types::HashOut,
    plonk::config::{AlgebraicHasher, GenericConfig},
};
use psy_dummy_prover::helper::{create_dummy_prover_helper, PsyUPSDummyProverHelper};

use crate::end_cap::dummy::DummyUPSStandardEndCapCircuit;

pub fn create_plonky2_dummy_end_cap_prover<N: QNetworkTypesConfig<QHash = QHashOut<C::F>, F = C::F>, C: GenericConfig<D> + 'static, const D: usize>(
    api_url: &str,
) -> anyhow::Result<PsyUPSDummyProverHelper<N, HttpClient, DummyUPSStandardEndCapCircuit<C, D>>>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + FieldQHasher<C::F, QHashOut<C::F>>,
    C::F: QFelt64,
    QHashOut<C::F>: QFHashBase<C::F>,
{
    let prover = DummyUPSStandardEndCapCircuit::<C, D>::new_with_config(false);
    create_dummy_prover_helper::<N, DummyUPSStandardEndCapCircuit<C, D>>(api_url, prover)
}
