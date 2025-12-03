use async_trait::async_trait;
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use parth_core::{
    crypto::hash::{tag_tree::{hash_tag_tree_node, hash_tag_tree_node_single}, traits::{FieldQHasher, MerkleZeroHasher, QFieldHashable}}, data::proof_input::CircuitInputWithDependencies, felt::QFelt64, pgoldilocks::{QHashOut, QRichField}, protocol::core_types::{Q256BitHash, QFHashBase, QHashBase}
};
use psy_core::
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID}
;
use psy_data::{
    proof_input::guta::VerifySingleEndCapInputV2, v1::qdata::user_end_cap_result::PUPSEndCapResultCompact, worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse
};
use psy_plonky2_basic_helpers::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::pad_circuit_degree,
    },
    verifier::circuit_library::CircuitInfoLibrary,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    guta::gadgets::{helpers::ToGUTAHeader, single_variable_height_state_transition::SingleVariableHeightStateTransitionGadget}, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{QPsyNetworkCircuitWithType, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QStandardCircuitProvableWithRawProofsAndRefLibrary, proof_store::QProofStoreReaderAsync}, utils::proof_library::get_single_child_proof_for_api_response_with_inclusion_proof
};

use crate::guta::gadgets::verify_end_cap::VerifyEndCapProofGadget;


#[derive(Debug)]
pub struct GUTAVerifySingleEndCapCircuitV2<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher:AlgebraicHasher<C::F>,
{
    pub guta_circuit_whitelist_root_hash: HashOutTarget,
    pub a_end_cap_gadget: VerifyEndCapProofGadget<D>,
    pub svh_state_transition_gadget: SingleVariableHeightStateTransitionGadget,
    pub worker_rewards_tree_tag: HashOutTarget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for GUTAVerifySingleEndCapCircuitV2<C, D> where
    C::Hasher:AlgebraicHasher<C::F>,
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::GUTASingleEndCap
    }
}
impl<C: GenericConfig<D> + 'static, const D: usize> GUTAVerifySingleEndCapCircuitV2<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>, C::F: QRichField {
        pub fn new(
            end_cap_proof_common_data: &CommonCircuitData<C::F, D>,
            end_cap_proof_verifier_data_cap_height: usize,
            known_end_cap_fingerprint: QHashOut<C::F>,
            global_user_tree_height: usize,
            realm_user_tree_height: usize,
            _guta_circuit_whitelist_tree_height: u8,
            checkpoint_tree_height: usize,
        ) -> Self {

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let known_end_cap_fingerprint_hash = builder.constant_qhash(known_end_cap_fingerprint);

        let guta_circuit_whitelist_root_hash = builder.add_virtual_hash();

        let a_end_cap_gadget = VerifyEndCapProofGadget::<D>::add_virtual_to::<C, C::F>(
            &mut builder,
            end_cap_proof_common_data,
            end_cap_proof_verifier_data_cap_height,
            checkpoint_tree_height,
            global_user_tree_height,
            known_end_cap_fingerprint_hash,
        );

        let a_end_cap_guta_header = a_end_cap_gadget.get_guta_header::<C::Hasher, C::F>(
            &mut builder,
            guta_circuit_whitelist_root_hash,
            global_user_tree_height as u8,
        );
        let svh_state_transition_gadget =
            SingleVariableHeightStateTransitionGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                a_end_cap_guta_header,
                realm_user_tree_height,
                global_user_tree_height
            );

        tracing::debug!("📊 a_end_cap_guta_header: {:?}", a_end_cap_guta_header);

        let worker_rewards_tree_tag = builder.add_virtual_hash();

        // because we are still generating a proof, it needs to be counted
        let final_guta_header = svh_state_transition_gadget.new_guta_header;
        let public_inputs_hash = final_guta_header.get_public_inputs_hash_no_children::<C::Hasher, C::F, D>(&mut builder, worker_rewards_tree_tag);

        let guta_hash =final_guta_header.to_hash::<C::Hasher, C::F, D>(&mut builder);
        //builder.register_public_inputs(&public_inputs_hash.elements);
        builder.register_public_inputs(&[
        public_inputs_hash.elements[0],
        public_inputs_hash.elements[1],
        public_inputs_hash.elements[2],
        public_inputs_hash.elements[3],
        ]);
        pad_circuit_degree(&mut builder, 12);
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            guta_circuit_whitelist_root_hash,
            a_end_cap_gadget,
            svh_state_transition_gadget,
            worker_rewards_tree_tag,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        worker_rewards_tree_tag: QHashOut<C::F>,
        input: &VerifySingleEndCapInputV2<C::F, QHashOut<C::F>>,
        child_a_proof: &ProofWithPublicInputs<C::F, C, D>,
        end_cap_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.guta_circuit_whitelist_root_hash, input.guta_circuit_whitelist.0)?;
        pw.set_hash_target(self.worker_rewards_tree_tag, worker_rewards_tree_tag.0)?;


        self.a_end_cap_gadget.set_witness(
            &mut pw,
            &input.get_end_result_a(),
            &input.core.guta_stats,
            &input.core.checkpoint_historical_merkle_proof,
            child_a_proof,
            end_cap_verifier_data
        )?;

        self.svh_state_transition_gadget.set_witness(&mut pw, &input.global_user_tree_sub_root_transition)?;

        self.circuit_data.prove(pw)
    }
}


impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for GUTAVerifySingleEndCapCircuitV2<C, D>
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
    for GUTAVerifySingleEndCapCircuitV2<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>, C::F: QRichField,
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        library: &L,
        job_id: QProvingJobDataID,
        worker_rewards_tree_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let r: CircuitInputWithDependencies<VerifySingleEndCapInputV2<C::F, QHashOut<C::F>>, QProvingJobDataID> =
            bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?)
                .map_err(|e| anyhow::anyhow!(e))?;
        tracing::debug!("GUTAVerifySingleEndCapCircuitV2Input: {}", serde_json::to_string_pretty(&r)?);

        if r.dependencies.len() != 1 {
            anyhow::bail!("invalid dependency count in two end guta input");
        }

        let child_a_proof = store.get_proof_by_id(r.dependencies[0]).await?;

        let dep_a_type = r.dependencies[0].circuit_type;

        let child_a_verifier_data = library.get_verifier_data(dep_a_type)?;

        let result = self.prove_base(
            worker_rewards_tree_tag,
            &r.input,
            &child_a_proof,
            &child_a_verifier_data,
        )?;

        Ok(result)
    }
}


impl<
        L: CircuitInfoLibrary<C, D>,
        C: GenericConfig<D>,
        const D: usize,
    > QStandardCircuitProvableWithRawProofsAndRefLibrary<L, C, D>
    for GUTAVerifySingleEndCapCircuitV2<C, D>
where
     C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + FieldQHasher<C::F,QHashOut<C::F>>, QHashOut<C::F>: Q256BitHash + QFHashBase<C::F>, C::F: QFelt64 + QRichField,
{

    fn prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<QHashOut<C::F>, QProvingJobDataID>,
        worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>{

        let child_proof_result = get_single_child_proof_for_api_response_with_inclusion_proof::<L, C, D>(
            library,
            &input,
        )?;



        let metadata_expected_public_inputs = input.base.job.metadata.expected_public_inputs_hash;
        println!("GUTAVerifySingleEndCapCircuitV2 metadata_expected_public_inputs: {:#?}", metadata_expected_public_inputs);



        let witness = VerifySingleEndCapInputV2::<C::F, QHashOut<C::F>>::psy_ser_from_slice(&input.base.witness)?;

        let expected_compact = witness.get_end_result_a();

        
        let expected_stats_hash = witness.core.guta_stats.qfhash::<C::Hasher>();
        let expected_guta_hash = expected_compact.qfhash_with_guta_height::<C::Hasher>(32);

        let expected_dummy_public_inputs = C::Hasher::q_two_to_one(
            expected_guta_hash,
            expected_stats_hash,
        );
        println!("GUTAVerifySingleEndCapCircuitV2 witness: {:#?}", witness);
        println!("expected_compact: {:#?}", expected_compact);
        println!("expected_stats_hash: {:#?}", expected_stats_hash);
        println!("expected_guta_hash: {:#?}", expected_guta_hash);
        println!("expected_dummy_public_inputs: {:#?}", expected_dummy_public_inputs);
        println!("child proof pubs: {:#?}", child_proof_result.zk_proof.public_inputs);

        let expecteed_new_guta = witness.get_new_guta_header(32);
        println!("expecteed_new_guta: {:#?}", expecteed_new_guta);
        let expected_new_public_inputs = witness.get_public_inputs_hash_no_rewards_tag::<C::Hasher>(32);

        let new_tag_root = hash_tag_tree_node::<QHashOut<C::F>, C::Hasher>(&QHashOut::<C::F>::ZERO, &QHashOut::<C::F>::ZERO, &worker_reward_tag);


        println!("expected_new_public_inputs_no_tag: {:#?}", expected_new_public_inputs);

        let expected_new_public_inputs_with_tag = C::Hasher::q_two_to_one(
            expected_new_public_inputs,
            new_tag_root,
        );
        println!("expected_new_public_inputs_with_tag: {:#?}", expected_new_public_inputs_with_tag);
        let proof = self.prove_base(
            worker_reward_tag,
            &witness,
            &child_proof_result.zk_proof,
            &child_proof_result.verifier_data,
        )?;
        println!("GUTAVerifySingleEndCapCircuitV2 proof pubs: {:#?}", proof.public_inputs);
        Ok(proof)

    }
}
