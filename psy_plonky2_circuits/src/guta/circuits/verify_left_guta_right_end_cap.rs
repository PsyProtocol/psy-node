use async_trait::async_trait;
use plonky2::{
    gates::{constant::ConstantGate, gate::GateRef}, hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher, data::proof_input::CircuitInputWithDependencies, pgoldilocks::{QHashOut, QRichField}
};
use psy_core::
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID}
;
use psy_data::
    proof_input::guta::{VerifyLeftGUTARightEndCapInput, VerifyLeftGUTARightEndCapInputSimple}
    
;
use psy_plonky2_basic_helpers::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::pad_circuit_degree,
    },
    verifier::circuit_library::CircuitInfoLibrary,
};
use psy_plonky2_common_circuits::traits::ToTargets;

use crate::{
    gadgets::qdata::pm_jobs_completed_stats::PMJobsCompletedStatsGadget,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::{proof_store::QProofStoreReaderAsync, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QPsyNetworkCircuitWithType},
};

use crate::{guta::gadgets::{helpers::ToGUTAHeader, two_nca_state_transition::TwoNCAStateTransitionGadget, verify_end_cap::VerifyEndCapProofGadget, verify_guta_proof::VerifyGUTAProofGadget}};

#[derive(Debug)]
pub struct GUTAVerifyLeftGUTARightEndCapCircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher:AlgebraicHasher<C::F>,
{
    pub a_guta_gadget: VerifyGUTAProofGadget<D>,
    pub b_end_cap_gadget: VerifyEndCapProofGadget<D>,
    pub nca_state_transition_gadget: TwoNCAStateTransitionGadget,
    pub worker_public_key: HashOutTarget,
    pub pm_jobs_completed: PMJobsCompletedStatsGadget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for GUTAVerifyLeftGUTARightEndCapCircuit<C, D> where
    C::Hasher:AlgebraicHasher<C::F>,
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTALeftGUTARightEndCap
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> GUTAVerifyLeftGUTARightEndCapCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>, C::F: QRichField {
        pub fn new(
            guta_proof_common_data: &CommonCircuitData<C::F, D>,
            guta_proof_verifier_data_cap_height: usize,
            end_cap_proof_common_data: &CommonCircuitData<C::F, D>,
            end_cap_proof_verifier_data_cap_height: usize,
            known_end_cap_fingerprint: QHashOut<C::F>,
            global_user_tree_height: usize,
            guta_circuit_whitelist_tree_height: u8,
            checkpoint_tree_height: usize,
        ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let known_end_cap_fingerprint_hash = builder.constant_qhash(known_end_cap_fingerprint);

        let a_guta_gadget = VerifyGUTAProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            guta_proof_common_data,
            guta_proof_verifier_data_cap_height,
            guta_circuit_whitelist_tree_height,
        );

        let b_end_cap_gadget = VerifyEndCapProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            end_cap_proof_common_data,
            end_cap_proof_verifier_data_cap_height,
            checkpoint_tree_height,
            global_user_tree_height,
            known_end_cap_fingerprint_hash,
        );

        let a_guta_header = a_guta_gadget.get_guta_header::<C::Hasher, C::F>(
            &mut builder,
            a_guta_gadget.guta_proof_header_gadget.guta_circuit_whitelist,
        );
        tracing::debug!("📊 a_guta_header: {:?}", a_guta_header);

        let b_guta_header = b_end_cap_gadget.get_guta_header::<C::Hasher, C::F>(
            &mut builder,
            a_guta_gadget.guta_proof_header_gadget.guta_circuit_whitelist,
            global_user_tree_height as u8,
        );
        tracing::debug!("📊 b_guta_header: {:?}", b_guta_header);

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
            ]
        };
        let a_worker_public_key = HashOutTarget {
            elements: [
                a_guta_gadget.proof_target.public_inputs[4],
                a_guta_gadget.proof_target.public_inputs[5],
                a_guta_gadget.proof_target.public_inputs[6],
                a_guta_gadget.proof_target.public_inputs[7],
            ]
        };

        let b_commitment = builder.constant_hash(HashOut::ZERO);

        let a_pm_jobs_completed = [
            a_guta_gadget.proof_target.public_inputs[8],
            a_guta_gadget.proof_target.public_inputs[9],
            a_guta_gadget.proof_target.public_inputs[10],
        ];

        let one = builder.one();
        let final_gutas = builder.add(a_pm_jobs_completed[2], one);
        let pm_jobs_completed = PMJobsCompletedStatsGadget {
            deploy_contracts_completed: a_pm_jobs_completed[0],
            register_users_completed: a_pm_jobs_completed[1],
            gutas_completed: final_gutas,
        };

        let a_final_commitment = builder.hash_two_to_one::<C::Hasher>(a_commitment, a_worker_public_key);
        let commitment = builder.hash_two_to_one::<C::Hasher>(a_final_commitment, b_commitment);

        let public_inputs_hash = nca_state_transition_gadget.new_guta_header.to_hash::<C::Hasher, C::F, D>(&mut builder);

        builder.register_public_inputs(&commitment.elements);
        builder.register_public_inputs(&worker_public_key.elements);
        builder.register_public_inputs(&pm_jobs_completed.to_targets());
        builder.register_public_inputs(&public_inputs_hash.elements);

        builder.add_gate_to_gate_set(GateRef::new(ConstantGate::new(builder.config.num_constants)));
        pad_circuit_degree(&mut builder, 12);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));
        Self {
            a_guta_gadget,
            b_end_cap_gadget,
            nca_state_transition_gadget,
            worker_public_key,
            pm_jobs_completed,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        worker_public_key: QHashOut<C::F>,
        input: &VerifyLeftGUTARightEndCapInput<C::F, QHashOut<C::F>>,
        child_a_proof: &ProofWithPublicInputs<C::F, C, D>,
        child_a_verifier_data: &VerifierOnlyCircuitData<C, D>,
        child_b_proof: &ProofWithPublicInputs<C::F, C, D>,
        end_cap_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.worker_public_key, worker_public_key.0)?;

        self.a_guta_gadget.set_witness(
            &mut pw,
            &input.guta_inclusion_proof_a,

            &input.get_guta_header_a(),
            child_a_proof,
            child_a_verifier_data
        )?;
        self.b_end_cap_gadget.set_witness(
            &mut pw,
            &input.get_end_result_b(),
            &input.b_end_cap.guta_stats,
            &input.b_end_cap.checkpoint_historical_merkle_proof,
            child_b_proof,
            end_cap_verifier_data
        )?;

        self.nca_state_transition_gadget.set_witness_partial(
            &mut pw,
            &input.nca_proof
        )?;

        self.circuit_data.prove(pw)
    }
}


impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for GUTAVerifyLeftGUTARightEndCapCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F>,
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
    for GUTAVerifyLeftGUTARightEndCapCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>, C::F: QRichField,
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        library: &L,
        job_id: QProvingJobDataID,
        worker_public_key: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let r: CircuitInputWithDependencies<VerifyLeftGUTARightEndCapInputSimple<C::F, QHashOut<C::F>>, QProvingJobDataID> =
            bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?)
                .map_err(|e| anyhow::anyhow!(e))?;
        tracing::debug!("GUTAVerifyLeftGUTARightEndCapCircuitInput: {}", serde_json::to_string_pretty(&r)?);

        if r.dependencies.len() != 2 {
            anyhow::bail!("invalid dependency count in left guta right end cap input");
        }


        let child_a_proof = store.get_proof_by_id(r.dependencies[0]).await?;
        let child_b_proof = store.get_proof_by_id(r.dependencies[1]).await?;

        let dep_a_type = r.dependencies[0].circuit_type;
        let dep_b_type = r.dependencies[1].circuit_type;

        let child_a_verifier_data = library.get_verifier_data(dep_a_type)?;
        let guta_inclusion_proof_a =
            library.get_group_inclusion_proof(job_id.circuit_type, dep_a_type)?;
        let child_b_verifier_data = library.get_verifier_data(dep_b_type)?;



        let result = self.prove_base(
            worker_public_key,
            &VerifyLeftGUTARightEndCapInput { checkpoint_tree_root: r.input.checkpoint_tree_root, stats_a:r.input.stats_a, b_end_cap: r.input.b_end_cap, nca_proof: r.input.nca_proof, guta_inclusion_proof_a},
            &child_a_proof,
            &child_a_verifier_data,
            &child_b_proof,
            &child_b_verifier_data
        )?;

        Ok(result)
    }
}
