use async_trait::async_trait;
use parth_core::{crypto::hash::{spiderman::SpidermanUpdateProof, traits::MerkleZeroHasher}, pgoldilocks::QHashOut};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::{PartialWitness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use psy_core::{constants::protocol::get_default_worker_public_key, job::job_id::{ProvingJobCircuitType, QProvingJobDataID}};
use psy_data::protocol::circuit_inputs::append_user_registration_tree::QCAppendUserRegistrationTreeCircuitInput;
use psy_plonky2_basic_helpers::{
    builder::{hash::core::CircuitBuilderHashCore, pad_circuit::CircuitBuilderQEDCommonGates}, verifier::circuit_library::CircuitInfoLibrary,
   
};
use crate::{proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{proof_store::{QProofStoreReaderAsync, QProofStoreReaderSync}, provable::QStandardCircuitProvable, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QStandardCircuitProvableWithProofStoreSync, QPsyNetworkCircuitWithType}};

use crate::coordinator::gadgets::append_user_registration_tree::BatchAppendUserRegistrationTreeGadget;

#[derive(Debug)]
pub struct AggDepositsWithdrawalsCircuit<C: GenericConfig<D>, const D: usize>
{
    pub batch_append_gadget: BatchAppendUserRegistrationTreeGadget,
    pub register_users_circuit_whitelist: HashOutTarget,
    pub worker_public_key: HashOutTarget,
    pub commitment: HashOutTarget,

    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for AggDepositsWithdrawalsCircuit<C, D>
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::AggAddProcessL1WithdrawalAddL1Deposit
    }
}
impl<C: GenericConfig<D>, const D: usize> AggDepositsWithdrawalsCircuit<C, D>
where
    C::Hasher:AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> {
        pub fn new(
            user_registration_tree_height: usize,
            batch_sub_tree_height: usize,
            max_sub_trees: usize,
        ) -> Self {


        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);


        let register_users_circuit_whitelist = builder.add_virtual_hash();
        let worker_public_key = builder.add_virtual_hash();


        let batch_append_gadget = BatchAppendUserRegistrationTreeGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            user_registration_tree_height,
            batch_sub_tree_height,
            max_sub_trees,
        );
        let state_transition_hash = builder.hash_two_to_one::<C::Hasher>(
            batch_append_gadget.old_root,
            batch_append_gadget.new_root,
        );

        let zero_hash = builder.constant_hash(HashOut::ZERO);
        let commitment = builder.hash_two_to_one::<C::Hasher>(zero_hash, zero_hash);

        builder.register_public_inputs(&commitment.elements);
        builder.register_public_inputs(&worker_public_key.elements);
        builder.register_public_inputs(&register_users_circuit_whitelist.elements);
        builder.register_public_inputs(&state_transition_hash.elements);

        builder.add_qed_type_d_common_gates();
        let circuit_data = builder.build::<C>();

        let fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &circuit_data.verifier_only,
        ));

        Self {
            register_users_circuit_whitelist,
            worker_public_key,
            commitment,
            batch_append_gadget,
            circuit_data,
            fingerprint,
        }
    }

    pub fn prove_base(
        &self,
        register_users_circuit_whitelist: QHashOut<C::F>,
        worker_public_key: QHashOut<C::F>,
        spiderman_append_proofs: &[SpidermanUpdateProof<QHashOut<C::F>>],

    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        pw.set_hash_target(self.register_users_circuit_whitelist, register_users_circuit_whitelist.0)?;
        pw.set_hash_target(self.worker_public_key, worker_public_key.0)?;
        self.batch_append_gadget.set_witness_params(
            &mut pw,
            spiderman_append_proofs
        )?;

        self.circuit_data.prove(pw)
    }
}


impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for AggDepositsWithdrawalsCircuit<C, D>
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


impl<C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvable<QCAppendUserRegistrationTreeCircuitInput<QHashOut<C::F>>, C, D> for AggDepositsWithdrawalsCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_standard(
        &self,
        input: &QCAppendUserRegistrationTreeCircuitInput<QHashOut<C::F>>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_base(
            input.register_users_circuit_whitelist,
            get_default_worker_public_key(),
            &input.spiderman_append_proofs,
        )
    }
}

impl<S: QProofStoreReaderSync, C: GenericConfig<D>, const D: usize>
    QStandardCircuitProvableWithProofStoreSync<S, QCAppendUserRegistrationTreeCircuitInput<QHashOut<C::F>>, C, D>
    for AggDepositsWithdrawalsCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    fn prove_with_proof_store_sync(
        &self,
        _store: &S,
        input: &QCAppendUserRegistrationTreeCircuitInput<QHashOut<C::F>>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.prove_standard(input)
    }
}



#[async_trait]
impl<
        S: QProofStoreReaderAsync + Send + Sync,
        L: CircuitInfoLibrary<C, D> + Send + Sync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QStandardCircuitProvableWithProofStoreAndRefLibraryAsync<S, L, C, D>
    for AggDepositsWithdrawalsCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>,
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        _library: &L,
        job_id: QProvingJobDataID,
        worker_public_key: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let input: QCAppendUserRegistrationTreeCircuitInput<QHashOut<C::F>> = bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?)
                .map_err(|e| anyhow::anyhow!(e))?;

        let result = self.prove_base(
            input.register_users_circuit_whitelist,
            worker_public_key,
            &input.spiderman_append_proofs,
        )?;

        Ok(result)
    }
}
