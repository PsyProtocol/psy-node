use async_trait::async_trait;
use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, data::proof_input::CircuitInputWithDependencies, pgoldilocks::{QHashOut, QRichField}};
use plonky2::{
    hash::hash_types::{HashOut, HashOutTarget}, iop::
        witness::PartialWitness, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{agg::{AggStateTransition, TPAltCircuitFingerprintConfig}, guta::header::GlobalUserTreeAggregatorHeader, protocol::circuit_inputs::agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput};
use psy_plonky2_basic_helpers::{
    builder::hash::core::CircuitBuilderHashCore, verifier::circuit_library::CircuitInfoLibrary,
   
};
use psy_plonky2_common_circuits::traits::ToTargets;
use crate::{proof_minifier::{pm_chain_dynamic::QEDProofMinifierDynamicChain, pm_core::get_circuit_fingerprint_generic}, qstandard::{proof_store::QProofStoreReaderAsync, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync, QPsyNetworkCircuitWithType}};


use crate::{coordinator::gadgets::verify_agg_user_registration_deploy_guta::VerifyAggUserRegistartionDeployContractsGUTAGadget};

#[derive(Debug)]
pub struct VerifyAggUserRegistartionDeployContractsGUTACircuit<C: GenericConfig<D>, const D: usize>
where C::Hasher:AlgebraicHasher<C::F>,
{
    pub verifier_gadget: VerifyAggUserRegistartionDeployContractsGUTAGadget<D>,

    pub base_circuit_data: CircuitData<C::F, C, D>,
    pub base_fingerprint: QHashOut<C::F>,
    pub minifier_chain: Option<QEDProofMinifierDynamicChain<D, C::F, C>>,
    pub enable_minifier: bool,
}


impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType for VerifyAggUserRegistartionDeployContractsGUTACircuit<C, D> where C::Hasher:AlgebraicHasher<C::F>,
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::AggUserRegisterDeployContractsGUTA
    }
}
impl<C: GenericConfig<D>, const D: usize> VerifyAggUserRegistartionDeployContractsGUTACircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>+ MerkleZeroHasher<QHashOut<C::F>>, C::F: QRichField,
{
    pub fn new(
        user_reg_proof_common_data: &CommonCircuitData<C::F, D>,
        user_reg_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<C::F>>,

        deploy_contracts_proof_common_data: &CommonCircuitData<C::F, D>,
        deploy_contracts_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<C::F>>,

        guta_proof_common_data: &CommonCircuitData<C::F, D>,
        guta_verifier_data_cap_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        guta_circuit_whitelist_root: QHashOut<C::F>,
    ) -> Self {
        Self::new_with_config(user_reg_proof_common_data, user_reg_transition_circuit_config, deploy_contracts_proof_common_data, deploy_contracts_transition_circuit_config, guta_proof_common_data, guta_verifier_data_cap_height, guta_circuit_whitelist_tree_height, guta_circuit_whitelist_root, true)

    }
    pub fn new_with_config(
        user_reg_proof_common_data: &CommonCircuitData<C::F, D>,
        user_reg_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<C::F>>,

        deploy_contracts_proof_common_data: &CommonCircuitData<C::F, D>,
        deploy_contracts_transition_circuit_config: &TPAltCircuitFingerprintConfig<QHashOut<C::F>>,

        guta_proof_common_data: &CommonCircuitData<C::F, D>,
        guta_verifier_data_cap_height: usize,
        guta_circuit_whitelist_tree_height: u8,
        guta_circuit_whitelist_root: QHashOut<C::F>,

        has_minifier: bool,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let verifier_gadget =
            VerifyAggUserRegistartionDeployContractsGUTAGadget::<D>::add_virtual_to::<C, C::F>(
                &mut builder,
                user_reg_proof_common_data,
                user_reg_transition_circuit_config,
                deploy_contracts_proof_common_data,
                deploy_contracts_transition_circuit_config,
                guta_proof_common_data,
                guta_verifier_data_cap_height,
                guta_circuit_whitelist_root,
                guta_circuit_whitelist_tree_height,

            );
        tracing::debug!("verifier_gadget={:#?}", verifier_gadget);
        let state_transition_hash = verifier_gadget
            .header
            .get_combined_hash::<C::Hasher, C::F, D>(&mut builder);

        let register_users_commitment = HashOutTarget {
            elements: [
                verifier_gadget.verify_register_users_gadget.proof_target.public_inputs[0],
                verifier_gadget.verify_register_users_gadget.proof_target.public_inputs[1],
                verifier_gadget.verify_register_users_gadget.proof_target.public_inputs[2],
                verifier_gadget.verify_register_users_gadget.proof_target.public_inputs[3],
            ]
        };
        let register_users_worker_public_key = HashOutTarget {
            elements: [
                verifier_gadget.verify_register_users_gadget.proof_target.public_inputs[4],
                verifier_gadget.verify_register_users_gadget.proof_target.public_inputs[5],
                verifier_gadget.verify_register_users_gadget.proof_target.public_inputs[6],
                verifier_gadget.verify_register_users_gadget.proof_target.public_inputs[7],
            ]
        };
        let register_users_root = builder.hash_two_to_one::<C::Hasher>(register_users_commitment, register_users_worker_public_key);

        let deploy_contracts_commitment = HashOutTarget {
            elements: [
                verifier_gadget.verify_deploy_contract_gadget.proof_target.public_inputs[0],
                verifier_gadget.verify_deploy_contract_gadget.proof_target.public_inputs[1],
                verifier_gadget.verify_deploy_contract_gadget.proof_target.public_inputs[2],
                verifier_gadget.verify_deploy_contract_gadget.proof_target.public_inputs[3],
            ]
        };
        let deploy_contracts_worker_public_key = HashOutTarget {
            elements: [
                verifier_gadget.verify_deploy_contract_gadget.proof_target.public_inputs[4],
                verifier_gadget.verify_deploy_contract_gadget.proof_target.public_inputs[5],
                verifier_gadget.verify_deploy_contract_gadget.proof_target.public_inputs[6],
                verifier_gadget.verify_deploy_contract_gadget.proof_target.public_inputs[7],
            ]
        };
        let deploy_contracts_root = builder.hash_two_to_one::<C::Hasher>(deploy_contracts_commitment, deploy_contracts_worker_public_key);

        let gutas_commitment = HashOutTarget {
            elements: [
                verifier_gadget.verify_guta_gadget.proof_target.public_inputs[0],
                verifier_gadget.verify_guta_gadget.proof_target.public_inputs[1],
                verifier_gadget.verify_guta_gadget.proof_target.public_inputs[2],
                verifier_gadget.verify_guta_gadget.proof_target.public_inputs[3],
            ]
        };
        let gutas_worker_public_key = HashOutTarget {
            elements: [
                verifier_gadget.verify_guta_gadget.proof_target.public_inputs[4],
                verifier_gadget.verify_guta_gadget.proof_target.public_inputs[5],
                verifier_gadget.verify_guta_gadget.proof_target.public_inputs[6],
                verifier_gadget.verify_guta_gadget.proof_target.public_inputs[7],
            ]
        };
        let gutas_root = builder.hash_two_to_one::<C::Hasher>(gutas_commitment, gutas_worker_public_key);

        builder.register_public_inputs(&state_transition_hash.elements);
        builder.register_public_inputs(&register_users_root.elements);
        builder.register_public_inputs(&deploy_contracts_root.elements);
        builder.register_public_inputs(&gutas_root.elements);
        builder.register_public_inputs(&verifier_gadget.combined_pm_jobs_completed.to_targets());

        tracing::debug!("🔧 state_transition_hash targets: {:?}", state_transition_hash.elements);
        tracing::debug!("🔧 register_users_root targets: {:?}", register_users_root.elements);
        tracing::debug!("🔧 deploy_contracts_root targets: {:?}", deploy_contracts_root.elements);
        tracing::debug!("🔧 gutas_root targets: {:?}", gutas_root.elements);

        let base_circuit_data = builder.build::<C>();

        let base_fingerprint = QHashOut(get_circuit_fingerprint_generic(
            &base_circuit_data.verifier_only,
        ));
        //println!("base_fingerprint: {:?}",base_fingerprint);

        let minifier_chain = if has_minifier {
            Some(
                QEDProofMinifierDynamicChain::<D, C::F, C>::new_with_dynamic_constant_verifier(
                    &base_circuit_data.verifier_only,
                    &base_circuit_data.common,
                    &[false, false],
                ),
            )
        } else {
            None
        };

        Self {
            base_circuit_data,
            base_fingerprint,
            minifier_chain,
            verifier_gadget,
            enable_minifier: has_minifier,
        }
    }

    pub fn prove_base(
        &self,
        register_users_state_transition: &AggStateTransition<QHashOut<C::F>>,
        register_users_proof: &ProofWithPublicInputs<C::F, C, D>,
        register_users_verifier_data: &VerifierOnlyCircuitData<C, D>,

        deploy_contracts_state_transition: &AggStateTransition<QHashOut<C::F>>,
        deploy_contracts_proof: &ProofWithPublicInputs<C::F, C, D>,
        deploy_contracts_verifier_data: &VerifierOnlyCircuitData<C, D>,

        guta_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        guta_proof_header: &GlobalUserTreeAggregatorHeader<C::F, QHashOut<C::F>>,
        guta_proof: &ProofWithPublicInputs<C::F, C, D>,
        guta_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();

        tracing::debug!("register_users_state_transition: {}", register_users_state_transition.get_combined_hash::<C::Hasher>());
        tracing::debug!("deploy_contracts_state_transition: {}", deploy_contracts_state_transition.get_combined_hash::<C::Hasher>());

        self.verifier_gadget.set_witness_params(
            &mut pw,
            register_users_state_transition,
            register_users_proof,
            register_users_verifier_data,
            deploy_contracts_state_transition,
            deploy_contracts_proof,
            deploy_contracts_verifier_data,
            guta_whitelist_merkle_proof,
            guta_proof_header,
            guta_proof,
            guta_verifier_data,
        )?;

        let res = self.base_circuit_data.prove(pw)?;

        if self.enable_minifier {
            self.minifier_chain.as_ref().unwrap().prove(&res)
        }else{
            Ok(res)
        }

    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D>
    for VerifyAggUserRegistartionDeployContractsGUTACircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        if self.enable_minifier {
            QHashOut(self.minifier_chain.as_ref().unwrap().get_fingerprint())
        }else{
            self.base_fingerprint
        }
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        if self.enable_minifier {
            self.minifier_chain.as_ref().unwrap().get_verifier_data()
        }else{
            &self.base_circuit_data.verifier_only
        }
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        if self.enable_minifier {
            self.minifier_chain.as_ref().unwrap().get_common_data()
        }else{
            &self.base_circuit_data.common
        }
    }
}
#[async_trait]
impl<
        S: QProofStoreReaderAsync + Send + Sync,
        L: CircuitInfoLibrary<C, D> + Send + Sync,
        C: GenericConfig<D> + 'static,
        const D: usize,
    > QStandardCircuitProvableWithProofStoreAndRefLibraryAsync<S, L, C, D>
    for VerifyAggUserRegistartionDeployContractsGUTACircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>>+ MerkleZeroHasher<QHashOut<C::F>>, C::F: QRichField,
{
    async fn prove_with_proof_store_async(
        &self,
        store: &S,
        library: &L,
        job_id: QProvingJobDataID,
        worker_public_key: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let r: CircuitInputWithDependencies<QCAggUserRegistartionDeployContractsGUTAInput<C::F, QHashOut<C::F>>, QProvingJobDataID> =
            bincode::deserialize(&store.get_bytes_by_id(job_id.get_input_witness_id()).await?)
                .map_err(|e| anyhow::anyhow!(e))?;

        if r.dependencies.len() != 3 {
            anyhow::bail!("expected 3 dependencies");
        }


        let user_registration_proof = store.get_proof_by_id(r.dependencies[0]).await?;
        let deploy_contracts_proof = store.get_proof_by_id(r.dependencies[1]).await?;
        let guta_proof = store.get_proof_by_id(r.dependencies[2]).await?;

        let user_registration_type = r.dependencies[0].circuit_type;
        let deploy_contracts_type = r.dependencies[1].circuit_type;
        let guta_type = r.dependencies[2].circuit_type;

        let user_registration_verifier_data = library.get_verifier_data(user_registration_type)?;
        let deploy_contracts_verifier_data = library.get_verifier_data(deploy_contracts_type)?;
        let guta_verifier_data = library.get_verifier_data(guta_type)?;

        let guta_inclusion_proof =
            library.get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, guta_type)?;

        let result = self.prove_base(
            &r.input.register_users_state_transition,
            &user_registration_proof,
            &user_registration_verifier_data,
            &r.input.deploy_contracts_state_transition,
            &deploy_contracts_proof,
            &deploy_contracts_verifier_data,
            &guta_inclusion_proof,
            &r.input.guta_proof_header,
            &guta_proof,
            &guta_verifier_data,
        )?;
        Ok(result)
    }
}
