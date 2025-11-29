use async_trait::async_trait;
use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, tag_tree::hash_tag_tree_node, traits::{FieldQHasher, MerkleZeroHasher, QFieldHashable}}, felt::{QFelt64, ZeroableFelt}, pgoldilocks::QHashOut, protocol::core_types::{Q256BitHash, QFHashBase}};
use plonky2::{
    field::types::Field, hash::hash_types::{HashOut, HashOutTarget}, iop::witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{guta::{header::GlobalUserTreeAggregatorHeader, stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition}, proof_input::guta::GUTANoChangeFullInput, v1::qdata::checkpoint::PQEDCheckpointLeafCompactWithStateRoots, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse};
use psy_plonky2_basic_helpers::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::{CircuitBuilderQEDCommonGates, pad_circuit_degree}}, verifier::circuit_library::CircuitInfoLibrary,
   
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{guta::gadgets::guta_no_change_gadget::GUTANoChangeGadget, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QStandardCircuitProvableWithRawProofsAndRefLibrary, proof_store::QProofStoreReaderAsync}};

#[derive(Debug)]
pub struct GUTANoChangeCircuit<C: GenericConfig<D>, const D: usize> {
    no_change_gadget: GUTANoChangeGadget,
    guta_circuit_whitelist: HashOutTarget,
    worker_rewards_tree_tag: HashOutTarget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for GUTANoChangeCircuit<C, D>
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTANoChange
    }
}
impl<C: GenericConfig<D>, const D: usize> GUTANoChangeCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(checkpoint_tree_height: usize) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let guta_circuit_whitelist = builder.add_virtual_hash();

        let no_change_gadget = GUTANoChangeGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            guta_circuit_whitelist,
            checkpoint_tree_height,
        );

        let worker_rewards_tree_tag = builder.add_virtual_hash();
        let public_inputs_hash = no_change_gadget
            .new_guta_header.get_public_inputs_hash_no_children::<C::Hasher, C::F, D>(&mut builder, worker_rewards_tree_tag);

        builder.register_public_inputs(&public_inputs_hash.elements);
        builder.add_qed_type_c_common_gates();
        pad_circuit_degree(&mut builder, 12);

        //builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(builder.config.num_constants)));
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            no_change_gadget,
            guta_circuit_whitelist,
            worker_rewards_tree_tag,

            circuit_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        worker_rewards_tree_tag: QHashOut<C::F>,
        guta_circuit_whitelist_root: QHashOut<C::F>,
        checkpoint_tree_proof: &MerkleProofCore<QHashOut<C::F>>,
        checkpoint_leaf: &PQEDCheckpointLeafCompactWithStateRoots<QHashOut<C::F>>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        pw.set_hash_target(self.guta_circuit_whitelist, guta_circuit_whitelist_root.0)?;
        pw.set_hash_target(self.worker_rewards_tree_tag, worker_rewards_tree_tag.0)?;


        self.no_change_gadget.set_witness_params(
            &mut pw,
            checkpoint_tree_proof,
            checkpoint_leaf,
        )?;

        let proof = self.circuit_data.prove(pw)?;
        println!(
            "GUTANoChangeCircuit generated public inputs hash: {}",
            hex::encode(&QHashOut::from_felt_slice(&proof.public_inputs).to_le_bytes())
        );
        println!("GUTANoChangeCircuit proof generated with public inputs {:?}", proof.public_inputs);
        Ok(proof)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for GUTANoChangeCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}

#[async_trait]
impl<
        S: QProofStoreReaderAsync + Send + Sync,
        L: CircuitInfoLibrary<C, D> + Send + Sync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QStandardCircuitProvableWithProofStoreAndRefLibraryAsync<S, L, C, D>
    for GUTANoChangeCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        library: &L,
        job_id: QProvingJobDataID,
        worker_rewards_tree_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let r: GUTANoChangeFullInput<QHashOut<C::F>> =
            bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?)
                .map_err(|e| anyhow::anyhow!(e))?;

        let guta_whitelist_root: QHashOut<C::F> = library
            .get_group_inclusion_proof(
                ProvingJobCircuitType::GUTATwoGUTA,
                ProvingJobCircuitType::GUTATwoGUTA,
            )?
            .root;

        let result = self.prove_base(
            worker_rewards_tree_tag,
            guta_whitelist_root,
            &r.checkpoint_tree_proof,
            &r.checkpoint_leaf,
        )?;

        Ok(result)
    }
}





impl<
        L: CircuitInfoLibrary<C, D>,
        C: GenericConfig<D>,
        const D: usize,
    > QStandardCircuitProvableWithRawProofsAndRefLibrary<L, C, D>
    for GUTANoChangeCircuit<C, D>
where
     C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + FieldQHasher<C::F, QHashOut<C::F>>, QHashOut<C::F>: Q256BitHash + QFHashBase<C::F>, C::F: QFelt64,
{

    fn prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>{


        let witness = GUTANoChangeFullInput::<QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;
        

        let guta_whitelist_root: QHashOut<C::F> =
            library.get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTATwoGUTA)?.root;
        let expected_public_inputs_hash = witness.get_public_inputs_hash_no_rewards_tag::<C::F, C::Hasher>(guta_whitelist_root);
        println!(
            "GUTANoChangeCircuit expected public inputs hash: {:?}",
            hex::encode(&expected_public_inputs_hash.into_owned_32bytes())
        );

        let guta_header = GlobalUserTreeAggregatorHeader::<C::F, QHashOut<C::F>> {
            guta_circuit_whitelist: guta_whitelist_root,
            checkpoint_tree_root: witness.checkpoint_tree_proof.root,
            state_transition: SubTreeNodeStateTransition{
                old_node_value: witness.checkpoint_leaf.global_state_roots.user_tree_root,
                new_node_value: witness.checkpoint_leaf.global_state_roots.user_tree_root,
                node_index: C::F::ZERO_VALUE,
                node_level: C::F::ZERO_VALUE,
            },
            stats: GUTAStats {
                fees_collected: C::F::ZERO_VALUE,
                user_ops_processed: C::F::ZERO_VALUE,
                total_transactions: C::F::ZERO_VALUE,
                slots_modified: C::F::ZERO_VALUE,
            },
            total_aggregation_proofs_generated: C::F::from_noncanonical_u64(1),
        };
        println!("guta_header: {:#?}", guta_header);

        
        let expected_guta_header_hash = guta_header.qfhash::<C::Hasher>();
        println!("expected_guta_header_hash: {:?} ({})", expected_guta_header_hash, hex::encode(&expected_guta_header_hash.to_le_bytes()));

        let reward_tree_value = hash_tag_tree_node::<QHashOut<C::F>, C::Hasher>(&QHashOut::ZERO, &QHashOut::ZERO, &worker_reward_tag);

        println!("worker_reward_tag: {:?} ({})", worker_reward_tag, hex::encode(&worker_reward_tag.to_le_bytes()));
        println!("reward_tree_value: {:?} ({})", reward_tree_value, hex::encode(&reward_tree_value.to_le_bytes()));
        let expected_final_public_inputs_hash = C::Hasher::q_two_to_one(expected_public_inputs_hash, reward_tree_value);
        println!("expected_final_public_inputs_hash: {:?} ({})", expected_final_public_inputs_hash, hex::encode(&expected_final_public_inputs_hash.to_le_bytes()));

        self.prove_base(
            worker_reward_tag,
            guta_whitelist_root,
            &witness.checkpoint_tree_proof,
            &witness.checkpoint_leaf,
        )
    }
}
