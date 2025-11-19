use async_trait::async_trait;
use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, pgoldilocks::QHashOut};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{proof_input::guta::GUTANoChangeFullInput, v1::qdata::checkpoint::PQEDCheckpointLeafCompactWithStateRoots};
use psy_plonky2_basic_helpers::{
    builder::pad_circuit::{pad_circuit_degree, CircuitBuilderQEDCommonGates}, verifier::circuit_library::CircuitInfoLibrary,
   
};

use crate::{guta::gadgets::guta_no_change_gadget::GUTANoChangeGadget, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{proof_store::QProofStoreReaderAsync, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QPsyNetworkCircuitWithType}};

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
            .new_guta_header
            .get_public_inputs_hash_no_children::<C::Hasher, C::F, D>(&mut builder, worker_rewards_tree_tag);

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

        self.circuit_data.prove(pw)
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
