use anyhow;
use maybe_async::maybe_async;
use plonky2::{
    hash::hash_types::HashOut,
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::treeprover::qrecursion::standard::manager::portable::circuits::PortableQTreeRecursionCircuitsTrait;
use psy_crypto::{
    common::witnesses::qrecursion::proof_data::AggProofRecord,
    hash::traits::{hasher::MerkleZeroHasher, qhashable::QFieldHashable},
    signature::secp256k1::core::PsyCompressedSecp256K1Signature,
};
use psy_client_data::{
    qdata::contract::ContractCodeDefinition,
    qstore::controllers::session_info::SessionCircuitInfoStore,
    ups::{
        start_step::UPSStartStepInput,
        ups_cfc_standard_step::{UPSCFCDeferredTransactionCircuitInput, UPSCFCStandardTransactionCircuitInput},
    },
};
use psy_vm::vm::cfc_input::DapenContractFunctionCircuitInput;

use crate::request::{QSoftwareDefinedSignatureInput, QSoftwareDefinedSignatureWitnessInput};

#[derive(Debug)]
pub enum SoftwareDefinedSignatureWitnessInput {
    Psy(QSoftwareDefinedSignatureWitnessInput),
}

#[derive(Debug)]
pub enum SoftwareDefinedSignatureInput {
    Psy(QSoftwareDefinedSignatureInput),
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async(?Send))]
pub trait UPSCircuitManagerTrait<C: GenericConfig<D>, const D: usize>: PortableQTreeRecursionCircuitsTrait<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasher<QHashOut<C::F>>,
{
    async fn register_info(&self, info_store: &mut SessionCircuitInfoStore<C::F>);
    async fn prove_ups_start(&self, input: &UPSStartStepInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn register_contract_circuits(&self, contract_id: u64, contract_code: &ContractCodeDefinition) -> anyhow::Result<()>;

    async fn get_fn_id(&self, contract_id: u64, method_name: String) -> anyhow::Result<u64>;

    async fn get_contract_method_common_data(&self, contract_id: u64, fn_id: u32) -> anyhow::Result<(QHashOut<C::F>, VerifierOnlyCircuitData<C, D>)>;

    async fn prove_contract_call(
        &self,
        contract_id: u64,
        fn_id: u32,
        input: &DapenContractFunctionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn prove_ups_cfc_standard_tx(
        &self,
        input: &UPSCFCStandardTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn prove_ups_cfc_deferred_tx(
        &self,
        input: &UPSCFCDeferredTransactionCircuitInput<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn prove_zk_sign(&self, private_key: QHashOut<C::F>, sig_hash: QHashOut<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn prove_secp_sign(&self, signature: PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn register_software_defined_circuit(&self, input: SoftwareDefinedSignatureInput) -> anyhow::Result<QHashOut<C::F>>;

    async fn prove_software_defined_sign(
        &self,
        fingerprint: QHashOut<C::F>,
        private_key: QHashOut<C::F>,
        input: SoftwareDefinedSignatureWitnessInput,
        sig_hash: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn prove_ups_end_cap(
        &self,
        circuit_info: &SessionCircuitInfoStore<C::F>,
        end_cap_from_proof_tree_input: &psy_client_data::ups::ups_end_cap::UPSEndCapFromProofTreeGadgetInput<C::F>,
        agg_proof_record: &AggProofRecord<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>>;

    async fn ups_start_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn ups_start_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn ups_cfc_standard_tx_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn ups_cfc_standard_tx_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn ups_cfc_deferred_tx_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn ups_cfc_deferred_tx_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn ups_end_cap_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn ups_end_cap_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn ups_circuit_whitelist_root(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn zk_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn zk_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;

    async fn secp_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<C::F>>;

    async fn secp_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>>;
}
