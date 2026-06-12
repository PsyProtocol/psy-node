use std::{collections::HashMap, marker::PhantomData};

use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::PrimeField64},
    hash::hash_types::{HashOut, RichField},
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{
    data::qhashout::QHashOut,
    job::{id::QProvingJobDataID, traits::QProofStore},
};
use psy_config::get_default_worker_public_key;
use psy_crypto::hash::{merkle::utils::sub_tree_nca::PartialUpdateNearestCommonAncestorProof, traits::hasher::MerkleZeroHasherWithMarkedLeaf};
use psy_client_data::{
    guta::{
        api::{SubmitUserEndCapProofAPIInput, SubmitUserEndCapProofIDAPIInput},
        proof_input::{VerifyEndCapSimpleStandardInput, VerifyTwoEndCapCircuitInput, VerifyTwoEndCapCircuitWithIdsInput},
    },
    qdata::checkpoint::PsyBlockState,
    traits::qdatastore::qtreedata::PsyComboDataStoreReaderWriterSync,
};
use psy_network_circuit::guta::guta_helper::PsyGUTACircuitManager;

pub struct PsyMemPoolUpdates {}
pub struct SimpleAPI<
    PS: QProofStore,
    SS: PsyComboDataStoreReaderWriterSync<F>,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    const D: usize,
> where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    proof_store: PS,
    state_store: SS,
    pub guta_circuits: PsyGUTACircuitManager<C, D>,

    next_block_mempool_updates: HashMap<u64, SubmitUserEndCapProofIDAPIInput<F>>,

    latest_block_state: PsyBlockState,

    _f: PhantomData<F>,
}

impl<
        PS: QProofStore,
        SS: PsyComboDataStoreReaderWriterSync<F>,
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F> + 'static,
        const D: usize,
    > SimpleAPI<PS, SS, F, C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    pub async fn new(proof_store: PS, state_store: SS, guta_circuits: PsyGUTACircuitManager<C, D>) -> anyhow::Result<Self> {
        let latest_block_state = state_store.get_latest_block_state().await?;

        Ok(Self {
            proof_store,
            state_store,
            guta_circuits,
            latest_block_state,
            _f: PhantomData,
            next_block_mempool_updates: HashMap::new(),
        })
    }
}
type F = GoldilocksField;
const D: usize = 2;
impl<PS: QProofStore, SS: PsyComboDataStoreReaderWriterSync<F>, C: GenericConfig<D, F = F> + 'static> SimpleAPI<PS, SS, F, C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    pub fn submit_proof(&mut self, proof_input: SubmitUserEndCapProofAPIInput<F, C, D>) -> anyhow::Result<()> {
        let user_id = proof_input.input.core.state_transition.user_id.to_canonical_u64();
        let proof_id = QProvingJobDataID::end_cap_proof(self.latest_block_state.checkpoint_id, 0, 0, user_id as u32);
        self.proof_store.set_proof_by_id(proof_id, &proof_input.proof)?;

        let new_checkpoint_id = self.latest_block_state.checkpoint_id + 1;

        for u in proof_input.input.contract_state_updates.iter() {
            let contract_id = u.user_contract_tree_update_proof.index as u32;
            for update in u.contract_state_tree_updates.iter() {
                match update {
                    psy_client_data::guta::api::ContractStateUpdate::Positional { delta_proof } => {
                        let height = delta_proof.siblings.len() as u8;
                        self.state_store.set_user_state_tree_leaf_hash(
                            new_checkpoint_id,
                            user_id,
                            contract_id,
                            height,
                            delta_proof.index,
                            delta_proof.new_value,
                        )?;
                    }
                    psy_client_data::guta::api::ContractStateUpdate::IMT { update } => match update {
                        psy_client_data::qdata::imt_proof::IMTContractStateUpdate::Update { delta_proof, .. } => {
                            let height = delta_proof.siblings.len() as u8;
                            self.state_store.set_user_state_tree_leaf_hash(
                                new_checkpoint_id,
                                user_id,
                                contract_id,
                                height,
                                delta_proof.index,
                                delta_proof.new_value,
                            )?;
                        }
                        psy_client_data::qdata::imt_proof::IMTContractStateUpdate::Insert {
                            predecessor_delta_proof,
                            new_leaf_delta_proof,
                            ..
                        } => {
                            let height = predecessor_delta_proof.siblings.len() as u8;
                            self.state_store.set_user_state_tree_leaf_hash(
                                new_checkpoint_id,
                                user_id,
                                contract_id,
                                height,
                                predecessor_delta_proof.index,
                                predecessor_delta_proof.new_value,
                            )?;
                            self.state_store.set_user_state_tree_leaf_hash(
                                new_checkpoint_id,
                                user_id,
                                contract_id,
                                height,
                                new_leaf_delta_proof.index,
                                new_leaf_delta_proof.new_value,
                            )?;
                        }
                    },
                }
            }
        }

        let update = SubmitUserEndCapProofIDAPIInput {
            input: proof_input.input,
            proof_id,
        };
        self.next_block_mempool_updates.insert(user_id, update);
        Ok(())
    }
    pub async fn get_start_witnesses(
        &mut self,
    ) -> anyhow::Result<(Vec<VerifyTwoEndCapCircuitWithIdsInput<F>>, Option<SubmitUserEndCapProofIDAPIInput<F>>)> {
        let mut results = self.next_block_mempool_updates.drain().map(|(_, v)| v).collect::<Vec<_>>();
        results.sort_by(|a, b| {
            a.input
                .core
                .state_transition
                .user_id
                .to_canonical_u64()
                .cmp(&b.input.core.state_transition.user_id.to_canonical_u64())
        });
        let good_pairs = results.len() / 2;
        let mut verify_two_end_cap_inputs = Vec::with_capacity(good_pairs);
        for i in 0..good_pairs {
            let checkpoint_proof = self
                .state_store
                .get_checkpoint_tree_merkle_proof(
                    self.latest_block_state.checkpoint_id,
                    results[i * 2].input.core.checkpoint_id.to_canonical_u64(),
                )
                .await?;

            let a_end_cap = VerifyEndCapSimpleStandardInput {
                guta_stats: results[i * 2].input.core.stats,
                checkpoint_root: results[i * 2].input.core.state_transition.checkpoint_tree_root_hash,
                checkpoint_historical_merkle_proof: checkpoint_proof,
            };
            let dmp_a = self.state_store.set_user_tree_leaf_hash(
                self.latest_block_state.checkpoint_id,
                results[i * 2].input.core.state_transition.user_id.to_canonical_u64(),
                results[i * 2].input.core.state_transition.end_user_leaf_hash,
            )?;

            let checkpoint_proof = self
                .state_store
                .get_checkpoint_tree_merkle_proof(
                    self.latest_block_state.checkpoint_id,
                    results[i * 2 + 1].input.core.checkpoint_id.to_canonical_u64(),
                )
                .await?;

            let b_end_cap = VerifyEndCapSimpleStandardInput {
                guta_stats: results[i * 2 + 1].input.core.stats,
                checkpoint_root: results[i * 2 + 1].input.core.state_transition.checkpoint_tree_root_hash,
                checkpoint_historical_merkle_proof: checkpoint_proof,
            };
            let dmp_b = self.state_store.set_user_tree_leaf_hash(
                self.latest_block_state.checkpoint_id,
                results[i * 2 + 1].input.core.state_transition.user_id.to_canonical_u64(),
                results[i * 2 + 1].input.core.state_transition.end_user_leaf_hash,
            )?;
            let nca_proof = PartialUpdateNearestCommonAncestorProof::from_delta_merkle_proof_pair::<C::Hasher>(&dmp_a, &dmp_b);

            let input = VerifyTwoEndCapCircuitWithIdsInput {
                input: VerifyTwoEndCapCircuitInput {
                    guta_circuit_whitelist: self.guta_circuits.guta_circuit_whitelist_root,
                    a_end_cap,
                    b_end_cap,
                    nca_proof,
                },
                proof_a_id: QProvingJobDataID::end_cap_proof(
                    self.latest_block_state.checkpoint_id,
                    0,
                    0,
                    results[i * 2].input.core.state_transition.user_id.to_canonical_u64() as u32,
                ),
                proof_b_id: QProvingJobDataID::end_cap_proof(
                    self.latest_block_state.checkpoint_id,
                    0,
                    0,
                    results[i * 2 + 1].input.core.state_transition.user_id.to_canonical_u64() as u32,
                ),
            };
            verify_two_end_cap_inputs.push(input)
        }
        self.next_block_mempool_updates.clear();

        Ok((
            verify_two_end_cap_inputs,
            if results.len() == good_pairs * 2 {
                None
            } else {
                Some(results.pop().unwrap())
            },
        ))
    }

    pub fn proof_start_dbg(
        &self,
        ex_input: VerifyTwoEndCapCircuitWithIdsInput<F>,
        end_cap_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.guta_circuits.verify_two_end_cap.prove_base(
            get_default_worker_public_key(),
            &ex_input.input,
            &self.proof_store.get_proof_by_id(ex_input.proof_a_id)?,
            &self.proof_store.get_proof_by_id(ex_input.proof_b_id)?,
            end_cap_verifier_data,
        )
    }
}
