use async_trait::async_trait;
use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher},
    data::proof_input::CircuitInputWithDependencies,
    pgoldilocks::QHashOut,
};
use plonky2::{
    gates::{constant::ConstantGate, gate::GateRef},
    hash::hash_types::{HashOut, HashOutTarget},
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_core::
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID}
;
use psy_data::{
    guta::header::GlobalUserTreeAggregatorHeader,
    proof_input::guta::
        VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple
    ,
};
use psy_plonky2_basic_helpers::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::pad_circuit_degree,
    },
    verifier::circuit_library::CircuitInfoLibrary,
};
use psy_plonky2_common_circuits::{hash::merkle::gadgets::historical_root_merkle_proof::HistoricalRootMerkleProofGadget, traits::ToTargets};

use crate::{
    gadgets::qdata::pm_jobs_completed_stats::PMJobsCompletedStatsGadget,
    guta::gadgets::
        verify_guta_proof_to_line::VerifyGUTAProofToLineGadget
    ,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::{proof_store::QProofStoreReaderAsync, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QPsyNetworkCircuitWithType},
};

#[derive(Debug)]
pub struct GUTAVerifyGUTAToCapUpgradeCheckpointCircuit<C: GenericConfig<D>, const D: usize> {
    pub verify_to_line_gadget: VerifyGUTAProofToLineGadget<D>,
    pub upgrade_checkpoint_historical_merkle_proof_gadget: HistoricalRootMerkleProofGadget,
    pub worker_public_key_target: HashOutTarget,
    pub pm_jobs_completed: PMJobsCompletedStatsGadget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}


impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for GUTAVerifyGUTAToCapUpgradeCheckpointCircuit<C, D>
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade
    }
}

impl<C: GenericConfig<D>, const D: usize> GUTAVerifyGUTAToCapUpgradeCheckpointCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    pub fn new(
        guta_proof_common_data: &CommonCircuitData<C::F, D>,
        guta_proof_verifier_data_cap_height: usize,
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let verify_to_line_gadget = VerifyGUTAProofToLineGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            global_user_tree_realm_height,
            global_user_tree_height,
            guta_circuit_whitelist_tree_height,
        );

        tracing::debug!("📈 GUTA To Cap Upgrade Checkpoint - verify_to_line_gadget: {:?}", verify_to_line_gadget);
        let upgrade_checkpoint_historical_merkle_proof_gadget =
            HistoricalRootMerkleProofGadget::add_virtual_to_zero_gt::<C::Hasher, C::F, D>(&mut builder, checkpoint_tree_height);

        // sanity check: ensure the checkpoint leaf is non-zero
        builder.ensure_hash_is_non_zero(upgrade_checkpoint_historical_merkle_proof_gadget.current_value);

        let mut computed_header_line = verify_to_line_gadget.get_guta_header_line();

        // ensure the computed header has a root which equals the historical checkpoint
        // root proof
        builder.connect_hashes(
            computed_header_line.checkpoint_tree_root,
            upgrade_checkpoint_historical_merkle_proof_gadget.historical_root,
        );

        // now we can modify the computed header to have the new checkpoint root
        computed_header_line.checkpoint_tree_root = upgrade_checkpoint_historical_merkle_proof_gadget.current_root;

        // let public_inputs_hash =
        // verify_to_line_gadget.get_guta_header_line().to_hash::<C::Hasher, C::F,
        // D>(&mut builder);
        let public_inputs_hash = computed_header_line.to_hash::<C::Hasher, C::F, D>(&mut builder);

        let worker_public_key = builder.add_virtual_hash();

        // builder.assert_non_zero_hash(worker_public_key);

        let child_commitment = HashOutTarget {
            elements: [
                verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[0],
                verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[1],
                verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[2],
                verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[3],
            ],
        };
        let child_worker_public_key = HashOutTarget {
            elements: [
                verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[4],
                verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[5],
                verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[6],
                verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[7],
            ],
        };

        let child_pm_jobs_completed = [
            verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[8],
            verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[9],
            verify_to_line_gadget.verify_guta_proof_gadget.proof_target.public_inputs[10],
        ];

        let one = builder.one();
        let final_gutas = builder.add(child_pm_jobs_completed[2], one);
        let pm_jobs_completed = PMJobsCompletedStatsGadget {
            deploy_contracts_completed: child_pm_jobs_completed[0],
            register_users_completed: child_pm_jobs_completed[1],
            gutas_completed: final_gutas,
        };

        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let commitment = builder.hash_two_to_one::<C::Hasher>(child_commitment, child_worker_public_key);
        let final_commitment = builder.hash_two_to_one::<C::Hasher>(commitment, zero_hash);

        builder.register_public_inputs(&final_commitment.elements);
        builder.register_public_inputs(&worker_public_key.elements);
        builder.register_public_inputs(&pm_jobs_completed.to_targets());
        builder.register_public_inputs(&public_inputs_hash.elements);

        builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(builder.config.num_constants)));
        pad_circuit_degree(&mut builder, 12);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            circuit_data,
            fingerprint,
            verify_to_line_gadget,
            upgrade_checkpoint_historical_merkle_proof_gadget,
            worker_public_key_target: worker_public_key,
            pm_jobs_completed,
        }
    }

    pub fn prove_base(
        &self,
        guta_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<C::F, QHashOut<C::F>>,
        proof: &ProofWithPublicInputs<C::F, C, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        top_line_siblings: &[QHashOut<C::F>],
        worker_public_key: QHashOut<C::F>,
        checkpoint_historical_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        tracing::debug!(
            "📈 GUTA To Cap Upgrade Checkpoint set_witness - guta_proof_header: {}, checkpoint_historical_proof: {}",
            serde_json::to_string_pretty(guta_proof_header).unwrap(),
            serde_json::to_string_pretty(checkpoint_historical_merkle_proof).unwrap()
        );

        self.verify_to_line_gadget.set_witness(
            &mut pw,
            guta_whitelist_merkle_proof,
            guta_proof_header,
            proof,
            verifier_data,
            top_line_siblings,
        )?;
        self.upgrade_checkpoint_historical_merkle_proof_gadget
            .set_witness_proof_core(&mut pw, checkpoint_historical_merkle_proof)?;

        pw.set_hash_target(self.worker_public_key_target, worker_public_key.0)?;

        self.circuit_data.prove(pw)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for GUTAVerifyGUTAToCapUpgradeCheckpointCircuit<C, D>
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
impl<S: QProofStoreReaderAsync + Send + Sync, L: CircuitInfoLibrary<C, D> + Send + Sync, C: GenericConfig<D> + 'static, const D: usize>
    QStandardCircuitProvableWithProofStoreAndRefLibraryAsync<S, L, C, D> for GUTAVerifyGUTAToCapUpgradeCheckpointCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        library: &L,
        job_id: QProvingJobDataID,
        worker_public_key: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let r: CircuitInputWithDependencies<VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<C::F, QHashOut<C::F>>, QProvingJobDataID> =
            bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
        tracing::debug!("GUTAVerifyGUTAToCapUpgradeCheckpointCircuitInput: {}", serde_json::to_string_pretty(&r)?);

        if r.dependencies.len() != 1 {
            anyhow::bail!("invalid dependency count in guta to cap input");
        }

        let child_a_proof = store.get_proof_by_id(r.dependencies[0]).await?;

        let dep_a_type = r.dependencies[0].circuit_type;

        let child_a_verifier_data = library.get_verifier_data(dep_a_type)?;

        let guta_inclusion_proof_a = library.get_group_inclusion_proof(job_id.circuit_type, dep_a_type)?;

        let result = self.prove_base(
            &guta_inclusion_proof_a,
            &r.input.guta_proof_header,
            &child_a_proof,
            &child_a_verifier_data,
            &r.input.top_line_siblings,
            worker_public_key,
            &r.input.historical_checkpoint_proof,
        )?;

        Ok(result)
    }
}
