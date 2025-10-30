use async_trait::async_trait;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::proof_input::CircuitInputWithDependencies,
    pgoldilocks::{QHashOut, QRichField},
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
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::
    proof_input::guta::{
        VerifyTwoGUTAProofUpgradeCheckpointStandardInput,
        VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple,
    }
;
use psy_plonky2_basic_helpers::{
    builder::hash::core::CircuitBuilderHashCore,
    verifier::circuit_library::CircuitInfoLibrary,
};
use psy_plonky2_common_circuits::{hash::merkle::gadgets::historical_root_merkle_proof::HistoricalRootMerkleProofGadget, traits::ToTargets};

use crate::{
    gadgets::qdata::pm_jobs_completed_stats::PMJobsCompletedStatsGadget,
    guta::gadgets::{
        helpers::ToGUTAHeader, two_nca_state_transition::TwoNCAStateTransitionGadget, verify_guta_proof::VerifyGUTAProofGadget,
    },
    proof_minifier::{pm_chain_dynamic::QEDProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic},
    qstandard::{proof_store::QProofStoreReaderAsync, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QPsyNetworkCircuitWithType},
};

#[derive(Debug)]
pub struct GUTAVerifyTwoGUTAUpgradeCheckpointCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub a_guta_gadget: VerifyGUTAProofGadget<D>,
    pub b_guta_gadget: VerifyGUTAProofGadget<D>,
    pub historical_checkpoint_proof_a: HistoricalRootMerkleProofGadget,
    pub historical_checkpoint_proof_b: HistoricalRootMerkleProofGadget,
    pub nca_state_transition_gadget: TwoNCAStateTransitionGadget,
    pub worker_public_key: HashOutTarget,
    pub commitment: HashOutTarget,
    pub pm_jobs_completed: PMJobsCompletedStatsGadget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,

    pub minifier_chain: QEDProofMinifierDynamicChain<D, C::F, C>,
}


impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for GUTAVerifyTwoGUTAUpgradeCheckpointCircuit<C, D> where
    C::Hasher:AlgebraicHasher<C::F>,
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> GUTAVerifyTwoGUTAUpgradeCheckpointCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>, C::F: QRichField,
{
    pub fn new(
        guta_proof_common_data: &CommonCircuitData<C::F, D>,
        guta_proof_verifier_data_cap_height: usize,
        global_user_tree_height: usize,

        guta_circuit_whitelist_tree_height: u8,
        checkpoint_tree_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let a_guta_gadget = VerifyGUTAProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
        );

        let b_guta_gadget = VerifyGUTAProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
        );

        tracing::debug!(
            "🔄 Two GUTA Upgrade Checkpoint - a_guta_gadget: {:?}, b_guta_gadget: {:?}",
            a_guta_gadget,
            b_guta_gadget
        );

        let historical_checkpoint_proof_a =
            HistoricalRootMerkleProofGadget::add_virtual_to_zero_gt::<C::Hasher, C::F, D>(&mut builder, checkpoint_tree_height);

        let historical_checkpoint_proof_b =
            HistoricalRootMerkleProofGadget::add_virtual_to_zero_gt::<C::Hasher, C::F, D>(&mut builder, checkpoint_tree_height);

        // ensure we are syncing both proofs to the same checkpoint root
        builder.connect_hashes(historical_checkpoint_proof_a.current_root, historical_checkpoint_proof_b.current_root);

        // sanity check: ensure we are not referencing a checkpoint proof with a zero
        // checkpoint leaf
        builder.ensure_hash_is_non_zero(historical_checkpoint_proof_a.current_value);
        builder.ensure_hash_is_non_zero(historical_checkpoint_proof_b.current_value);

        let mut a_guta_header = a_guta_gadget.get_guta_header::<C::Hasher, C::F>(
            &mut builder,
            a_guta_gadget.guta_proof_header_gadget.guta_circuit_whitelist,
            //a_guta_gadget.guta_whitelist_merkle_proof.root,
        );

        let mut b_guta_header =
            b_guta_gadget.get_guta_header::<C::Hasher, C::F>(&mut builder, b_guta_gadget.guta_proof_header_gadget.guta_circuit_whitelist);

        // ensure that the guta proof headers match our historical checkpoint tree
        // proofs historical roots
        builder.connect_hashes(a_guta_header.checkpoint_tree_root, historical_checkpoint_proof_a.historical_root);
        builder.connect_hashes(b_guta_header.checkpoint_tree_root, historical_checkpoint_proof_b.historical_root);

        // AFTER we have connected the historical roots, we can now override the
        // checkpoint tree roots in the guta headers to be the current roots from the
        // historical proofs
        a_guta_header.checkpoint_tree_root = historical_checkpoint_proof_a.current_root;
        b_guta_header.checkpoint_tree_root = historical_checkpoint_proof_b.current_root;

        let nca_state_transition_gadget = TwoNCAStateTransitionGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            a_guta_header,
            b_guta_header,
            global_user_tree_height as u8,
        );

        let worker_public_key = builder.add_virtual_hash();

        // builder.assert_non_zero_hash(worker_public_key);

        let a_commitment = HashOutTarget {
            elements: [
                a_guta_gadget.proof_target.public_inputs[0],
                a_guta_gadget.proof_target.public_inputs[1],
                a_guta_gadget.proof_target.public_inputs[2],
                a_guta_gadget.proof_target.public_inputs[3],
            ],
        };
        let a_worker_public_key = HashOutTarget {
            elements: [
                a_guta_gadget.proof_target.public_inputs[4],
                a_guta_gadget.proof_target.public_inputs[5],
                a_guta_gadget.proof_target.public_inputs[6],
                a_guta_gadget.proof_target.public_inputs[7],
            ],
        };
        let a_pm_jobs_completed = [
            a_guta_gadget.proof_target.public_inputs[8],
            a_guta_gadget.proof_target.public_inputs[9],
            a_guta_gadget.proof_target.public_inputs[10],
        ];

        let b_commitment = HashOutTarget {
            elements: [
                b_guta_gadget.proof_target.public_inputs[0],
                b_guta_gadget.proof_target.public_inputs[1],
                b_guta_gadget.proof_target.public_inputs[2],
                b_guta_gadget.proof_target.public_inputs[3],
            ],
        };
        let b_worker_public_key = HashOutTarget {
            elements: [
                b_guta_gadget.proof_target.public_inputs[4],
                b_guta_gadget.proof_target.public_inputs[5],
                b_guta_gadget.proof_target.public_inputs[6],
                b_guta_gadget.proof_target.public_inputs[7],
            ],
        };
        let b_pm_jobs_completed = [
            b_guta_gadget.proof_target.public_inputs[8],
            b_guta_gadget.proof_target.public_inputs[9],
            b_guta_gadget.proof_target.public_inputs[10],
        ];

        let combined_deploy_contracts = builder.add(a_pm_jobs_completed[0], b_pm_jobs_completed[0]);
        let combined_register_users = builder.add(a_pm_jobs_completed[1], b_pm_jobs_completed[1]);
        let combined_gutas = builder.add(a_pm_jobs_completed[2], b_pm_jobs_completed[2]);

        let one = builder.one();
        let final_gutas = builder.add(combined_gutas, one);
        let pm_jobs_completed = PMJobsCompletedStatsGadget {
            deploy_contracts_completed: combined_deploy_contracts,
            register_users_completed: combined_register_users,
            gutas_completed: final_gutas,
        };

        let a_final_commitment = builder.hash_two_to_one::<C::Hasher>(a_commitment, a_worker_public_key);
        let b_final_commitment = builder.hash_two_to_one::<C::Hasher>(b_commitment, b_worker_public_key);
        let commitment = builder.hash_two_to_one::<C::Hasher>(a_final_commitment, b_final_commitment);

        let public_inputs_hash = nca_state_transition_gadget.new_guta_header.to_hash::<C::Hasher, C::F, D>(&mut builder);

        builder.register_public_inputs(&commitment.elements);
        builder.register_public_inputs(&worker_public_key.elements);
        builder.register_public_inputs(&pm_jobs_completed.to_targets());
        builder.register_public_inputs(&public_inputs_hash.elements);

        builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(builder.config.num_constants)));
        // pad_circuit_degree(&mut builder, 12);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        let minifier_chain = QEDProofMinifierDynamicChain::<D, C::F, C>::new_with_dynamic_constant_verifier(
            &circuit_data.verifier_only,
            &circuit_data.common,
            &[true],
        );

        Self {
            a_guta_gadget,
            b_guta_gadget,
            historical_checkpoint_proof_a,
            historical_checkpoint_proof_b,
            nca_state_transition_gadget,
            pm_jobs_completed,
            worker_public_key,
            commitment,
            circuit_data,
            fingerprint,
            minifier_chain,
        }
    }

    pub fn prove_base(
        &self,
        worker_public_key: QHashOut<C::F>,
        input: &VerifyTwoGUTAProofUpgradeCheckpointStandardInput<C::F, QHashOut<C::F>>,
        child_a_proof: &ProofWithPublicInputs<C::F, C, D>,
        child_a_verifier_data: &VerifierOnlyCircuitData<C, D>,
        child_b_proof: &ProofWithPublicInputs<C::F, C, D>,
        child_b_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.worker_public_key, worker_public_key.0)?;

        tracing::debug!(
            "🔄 Two GUTA Upgrade Checkpoint set_witness - worker_public_key: {}, checkpoint_proof_a: {}, checkpoint_proof_b: {}",
            serde_json::to_string_pretty(&worker_public_key).unwrap(),
            serde_json::to_string_pretty(&input.historical_checkpoint_proof_a).unwrap(),
            serde_json::to_string_pretty(&input.historical_checkpoint_proof_b).unwrap()
        );

        self.historical_checkpoint_proof_a
            .set_witness_proof_core(&mut pw, &input.historical_checkpoint_proof_a)?;
        self.historical_checkpoint_proof_b
            .set_witness_proof_core(&mut pw, &input.historical_checkpoint_proof_b)?;


        self.a_guta_gadget.set_witness(
            &mut pw,
            &input.guta_inclusion_proof_a,
            &input.get_guta_header_a::<C::Hasher>(),
            child_a_proof,
            child_a_verifier_data,
        )?;
        self.b_guta_gadget.set_witness(
            &mut pw,
            &input.guta_inclusion_proof_b,
            &input.get_guta_header_b::<C::Hasher>(),
            child_b_proof,
            child_b_verifier_data,
        )?;

        self.nca_state_transition_gadget.set_witness_partial(&mut pw, &input.nca_proof)?;

        let base_proof = self.circuit_data.prove(pw)?;
        self.minifier_chain.prove(&base_proof)
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D> for GUTAVerifyTwoGUTAUpgradeCheckpointCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.minifier_chain.get_common_data()
    }
}

#[async_trait]
impl<S: QProofStoreReaderAsync + Send + Sync, L: CircuitInfoLibrary<C, D> + Send + Sync, C: GenericConfig<D> + 'static, const D: usize>
    QStandardCircuitProvableWithProofStoreAndRefLibraryAsync<S, L, C, D> for GUTAVerifyTwoGUTAUpgradeCheckpointCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>, C::F: QRichField,
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        library: &L,
        job_id: QProvingJobDataID,
        worker_public_key: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let r: CircuitInputWithDependencies<VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<C::F, QHashOut<C::F>>, QProvingJobDataID> =
            bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?).map_err(|e| anyhow::anyhow!(e))?;
        tracing::debug!("GUTAVerifyTwoGUTAUpgradeCheckpointCircuitInput: {}", serde_json::to_string_pretty(&r)?);

        if r.dependencies.len() != 2 {
            anyhow::bail!("invalid dependency count in two end guta input");
        }

        let child_a_proof = store.get_proof_by_id(r.dependencies[0]).await?;
        let child_b_proof = store.get_proof_by_id(r.dependencies[1]).await?;

        let dep_a_type = r.dependencies[0].circuit_type;
        let dep_b_type = r.dependencies[1].circuit_type;

        let child_a_verifier_data = library.get_verifier_data(dep_a_type)?;
        let guta_inclusion_proof_a = library.get_group_inclusion_proof(job_id.circuit_type, dep_a_type)?;
        let child_b_verifier_data = library.get_verifier_data(dep_b_type)?;
        let guta_inclusion_proof_b = library.get_group_inclusion_proof(job_id.circuit_type, dep_b_type)?;
        let result = self.prove_base(
            worker_public_key,
            &VerifyTwoGUTAProofUpgradeCheckpointStandardInput {
                historical_checkpoint_proof_a: r.input.historical_checkpoint_proof_a,
                historical_checkpoint_proof_b: r.input.historical_checkpoint_proof_b,
                stats_a: r.input.stats_a,
                stats_b: r.input.stats_b,
                nca_proof: r.input.nca_proof,
                guta_inclusion_proof_a,
                guta_inclusion_proof_b,
            },
            &child_a_proof,
            &child_a_verifier_data,
            &child_b_proof,
            &child_b_verifier_data,
        )?;

        Ok(result)
    }
}
