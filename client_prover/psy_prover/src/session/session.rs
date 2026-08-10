use std::collections::BTreeMap;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

use dashmap::DashMap;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{
    args::{ContractCallArgs, ContractCallData, DPNSoftwareDefinedCallData, ViewCallData},
    data::{alt::AltVerifierOnlyCircuitData, qhashout::QHashOut},
    ups::circuits::LocalCircuitType,
};
use psy_client_data::{
    config::store_config::PsyHasher,
    guta::end_cap_input::SubmitUserEndCapNonProofInput,
    qblock::cmds::deploy_contract::{get_code_root_by_code_hashes, QBCDeployContract},
    qdata::{
        checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeafCompactWithStateRoots},
        contract::ContractCodeDefinition,
        user_contract_state::UserContractState,
    },
    qstore::{
        controllers::{
            proving_session::{PsyLocalProvingSessionStore, PsyReadLocalProvingSessionStore},
            session_info::SessionCircuitInfoStore,
        },
        imm::{
            cmd::{QSRCmdGetContractCodeDefinition, QSRMerkleCmd, QSRMerkleCmdGetUserRegistrationTreeMerkleProof},
            cmd_processor::{PsyReadCommandProcessorSync, PsyReadCommandProcessorSyncMut},
        },
    },
    traits::qdatastore::{
        qmetadata::QMetaDataStoreReaderSync,
        qtreedata::{PsyComboDataStoreReaderSync, QTreeDataStoreReaderSync},
    },
    ups::ups_context_input::UserProvingSessionHeader,
};
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_config::{
    network_constants::{
        CONTRACT_FUNCTION_TREE_HEIGHT, DEFAULT_CALLER_CONTRACT_ID_U64, MAX_CONTRACT_STATE_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT,
    },
    PSY_NETWORK_MAGIC,
};
use psy_crypto::{
    common::user_id::get_registration_id_from_user_id,
    hash::{
        merkle::core::MerkleProofCore,
        traits::{
            hasher::{FieldQHasher, MerkleZeroHasher, MerkleZeroHasherWithMarkedLeaf},
            qhashable::QFieldHashable,
        },
    },
    signature::zk::data::ZKPublicKeyInfo,
};
use psy_dpn_circuit::circuits::cfc::DapenContractFunctionCircuit;
pub use psy_provider::session::TxStatus;
use psy_provider::{
    provider::{ProveProxyRpcProvider, QUserRpcProvider, RpcProvider},
    request::{DPNSoftwareDefinedSignatureInput, QDeployContractRPCRequest, QRegisterUserRPCRequest, QSubmitEndCapRPCRequest},
};
use psy_ups_circuit::{circuit_manager::core::PsyUPSStepCircuitManager, session::UserProvingSessionManager};
use psy_vm::{
    dpn::{
        contract::{dapen_fc_to_cfc_code_definition, hash_dpn_function},
        ops::state_cmd::types::DPNStateCmdCore,
        vm::def::{derive_state_tree_height, DPNFunctionCircuitDefinition},
    },
    ups::{
        circuit_manager::UPSCircuitManager, sd_key::SDKeyCircuitWitnessInput, signature::Plonky2SoftwareDefinedSignatureInput,
        state_reader::StateReader,
    },
};
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use crate::trace::proof_schedule::{graph_id_from_trace, GraphId, JobManager, JobStatus, TraceProofJobId, TraceProofPlan};
use crate::{
    signature::{
        context::SignContext,
        traits::{SignatureCircuitInfo, SignatureResult},
    },
    trace::{
        proof_schedule::{StepSeed, TraceProofSchedule},
        proof_tree_meta::{LastStepProofInfo, ProofTreeMeta},
    },
    wallet::memory_wallet::{PsyMemoryWallet, PsyWalletLocalCircuits},
};

// trait UPSWithTreeRecursion<C: GenericConfig<D>, const D: usize>:
// UPSCircuitManager<C, D> + PortableQTreeRecursion<C, D> + Send + Sync where
//     C::Hasher: AlgebraicHasher<C::F> +
// MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> +
// MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>, {
// }

// impl<T, C: GenericConfig<D>, const D: usize> UPSWithTreeRecursion<C, D> for T
// where
//     T: UPSCircuitManager<C, D> + PortableQTreeRecursion<C, D> + Send + Sync,
//     C::Hasher: AlgebraicHasher<C::F> +
// MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> +
// MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>, {
// }

fn select_builtin_sign_circuit(
    fingerprint: QHashOut<F>,
    zk_fingerprint: QHashOut<F>,
    secp_fingerprint: QHashOut<F>,
    eth_personal_fingerprint: Option<QHashOut<F>>,
) -> Option<crate::trace::TraceSignCircuitSource> {
    if fingerprint == zk_fingerprint {
        Some(crate::trace::TraceSignCircuitSource::ZkBuiltin)
    } else if fingerprint == secp_fingerprint {
        Some(crate::trace::TraceSignCircuitSource::SecpBuiltin)
    } else if Some(fingerprint) == eth_personal_fingerprint {
        Some(crate::trace::TraceSignCircuitSource::EthPersonalSecpBuiltin)
    } else {
        None
    }
}

#[cfg(test)]
mod signer_mode_selection_tests {
    use super::*;

    #[test]
    fn selects_distinct_builtin_signer_modes() {
        let zk = QHashOut(HashOut {
            elements: [F::from_canonical_u64(1), F::from_canonical_u64(2), F::from_canonical_u64(3), F::from_canonical_u64(4)],
        });
        let secp = QHashOut(HashOut {
            elements: [F::from_canonical_u64(5), F::from_canonical_u64(6), F::from_canonical_u64(7), F::from_canonical_u64(8)],
        });
        let personal = QHashOut(HashOut {
            elements: [F::from_canonical_u64(9), F::from_canonical_u64(10), F::from_canonical_u64(11), F::from_canonical_u64(12)],
        });

        assert!(matches!(
            select_builtin_sign_circuit(zk, zk, secp, Some(personal)),
            Some(crate::trace::TraceSignCircuitSource::ZkBuiltin)
        ));
        assert!(matches!(
            select_builtin_sign_circuit(secp, zk, secp, Some(personal)),
            Some(crate::trace::TraceSignCircuitSource::SecpBuiltin)
        ));
        assert!(matches!(
            select_builtin_sign_circuit(personal, zk, secp, Some(personal)),
            Some(crate::trace::TraceSignCircuitSource::EthPersonalSecpBuiltin)
        ));
        assert!(select_builtin_sign_circuit(personal, zk, secp, None).is_none());
    }
}

pub fn gen_contract_deploy_and_circuits_for_functions<C: GenericConfig<D>, const D: usize>(
    deployer: QHashOut<C::F>,
    contract_state_tree_height: u8,
    defs: &[DPNFunctionCircuitDefinition],
) -> anyhow::Result<(Vec<DapenContractFunctionCircuit<C, D>>, QBCDeployContract<C::F>)>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    let code_defs = defs.iter().map(|x| dapen_fc_to_cfc_code_definition(x)).collect::<Vec<_>>();
    let mut whitelist_leaves = Vec::with_capacity(defs.len() * 2);
    let mut code_hashes = Vec::with_capacity(defs.len());
    let circuits = defs
        .iter()
        .map(|x| {
            let c = DapenContractFunctionCircuit::<C, D>::new(x, contract_state_tree_height as usize, UPS_SESSION_PROOF_TREE_HEIGHT as usize, false);
            whitelist_leaves.push(c.get_fingerprint());

            let inputs_outputs_combo = ((x.circuit_outputs.len() as u64) << 32u64) | (x.circuit_inputs.len() as u64);
            whitelist_leaves.push(QHashOut::from_values(x.method_id as u64, inputs_outputs_combo, 0, 0));
            let code_hash = hash_dpn_function::<C::F>(x);
            code_hashes.push(code_hash);
            c
        })
        .collect::<Vec<_>>();

    let deploy = QBCDeployContract {
        deployer,
        code_definition: ContractCodeDefinition {
            state_tree_height: contract_state_tree_height as u16,
            functions: code_defs,
        },
        function_whitelist: whitelist_leaves,
        code_root: get_code_root_by_code_hashes::<C::F, C::Hasher>(&code_hashes, CONTRACT_FUNCTION_TREE_HEIGHT - 1),
    };

    Ok((circuits, deploy))
}

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;
#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
pub async fn prove_func<R, CM: UPSCircuitManager<C, D> + ?Sized>(
    contract_code: ContractCodeDefinition,
    circuit_mgr: &CM,
    mgr: &mut UserProvingSessionManager<F, PoseidonHash, R, C, D>,
    contract_id: u64,
    fn_name: &str,
    inputs: Vec<F>,
) -> anyhow::Result<()>
where
    R: PsyReadCommandProcessorSync<F> + PsyComboDataStoreReaderSync<F> + psy_client_data::qstore::imm::cmd_processor::QUserIdManager + Send + Sync,
{
    let (fn_id, dapen_fc) = circuit_mgr
        .resolve_contract_function_by_method_name(contract_id, &contract_code, fn_name.to_string())
        .await?;

    mgr.prove_standard_call(circuit_mgr, F::from_canonical_u64(contract_id), fn_id as u32, &dapen_fc, inputs)
        .await
}

pub struct WalletSession {
    pub wallet: PsyMemoryWallet,
    pub circuit_info: SessionCircuitInfoStore<F>,
    pub st_provider: RpcProvider,
    #[cfg(not(target_arch = "wasm32"))]
    pub local_proving_job_manager: JobManager<TraceProofJobId, TraceProofJobOutput>,

    pub user_session_mgrs: DashMap<QHashOut<F>, UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProveError {
    #[error(
        "stale trace anchor: user {user_id} start_user_leaf_hash changed while proving; rebuild the trace against the latest state {start_user_leaf_hash:?} {latest_user_leaf_hash:?}"
    )]
    StaleTraceAnchor {
        user_id: u64,
        start_user_leaf_hash: QHashOut<F>,
        latest_user_leaf_hash: QHashOut<F>,
    },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl ProveError {
    fn from_anyhow(error: anyhow::Error) -> Self {
        match error.downcast::<ProveError>() {
            Ok(prove_error) => prove_error,
            Err(error) => Self::Other(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndCapContractSlotUpdate {
    pub contract_id: u32,
    pub slot: u64,
    pub old_value: u64,
    pub new_value: u64,
}

#[derive(Debug, thiserror::Error)]
#[error("end cap submission rejected after proving deterministic leaf {end_user_leaf_hash}: {source}")]
pub struct EndCapSubmissionError {
    pub end_user_leaf_hash: QHashOut<F>,
    pub contract_slot_updates: Vec<EndCapContractSlotUpdate>,
    #[source]
    pub source: anyhow::Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateTransferClaim {
    pub nullifier: [u64; 4],
    pub owner: [u64; 4],
    pub amount: u64,
    pub user_tree_root: [u64; 4],
    pub checkpoint_id: u64,
    pub note_root_slot: u64,
    pub token_contract_id: u64,
    pub random0: u64,
    pub random1: u64,
    pub note_proof_fingerprint: QHashOut<F>,
    pub note_proof: ProofWithPublicInputs<F, C, D>,
    pub note_verifier_data: AltVerifierOnlyCircuitData<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldDepositClaim {
    pub contract_id: u64,
    pub l2_token_contract_id: [u32; 8],
    pub nullifier_hash: QHashOut<F>,
    pub shield_address: QHashOut<F>,
    pub token_address: [u32; 8],
    pub amount: [u32; 8],
    pub source_chain_index: u32,
    pub deposit_root: QHashOut<F>,
    pub note_commitment: QHashOut<F>,
    pub deposit_index: u64,
    pub r0: u64,
    pub r1: u64,
    pub proof_fingerprint: QHashOut<F>,
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub verifier_data: AltVerifierOnlyCircuitData<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ClaimBatchItem {
    Public(ContractCallArgs),
    PrivateTransfer { contract_id: u64, claim: PrivateTransferClaim },
    ShieldDeposit(ShieldDepositClaim),
}

fn ensure_private_transfer_contract_matches(contract_id: u64, token_contract_id: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        contract_id == token_contract_id,
        "private transfer claim contract mismatch: item contract_id={}, proof token_contract_id={}",
        contract_id,
        token_contract_id
    );
    Ok(())
}

impl PrivateTransferClaim {
    pub fn to_contract_call_args(&self, contract_id: u64, proof_ref: &TraceExternalProofRef) -> anyhow::Result<ContractCallArgs> {
        ensure_private_transfer_contract_matches(contract_id, self.token_contract_id)?;
        Ok(ContractCallArgs {
            contract_id,
            method_name: "private_claim".to_string(),
            inputs: WalletSession::build_private_claim_inputs(
                self.nullifier,
                self.owner,
                self.amount,
                self.user_tree_root,
                self.checkpoint_id,
                self.note_root_slot,
                self.random0,
                self.random1,
                &proof_ref.leaf_proof,
                proof_ref.proof_index,
            ),
        })
    }
}

impl ShieldDepositClaim {
    pub fn to_contract_call_args(&self, proof_ref: &TraceExternalProofRef) -> ContractCallArgs {
        ContractCallArgs {
            contract_id: self.contract_id,
            method_name: "claim_deposit".to_string(),
            inputs: WalletSession::build_shield_deposit_claim_inputs(
                self.nullifier_hash,
                self.shield_address,
                self.token_address,
                self.amount,
                self.source_chain_index,
                self.deposit_root,
                self.note_commitment,
                self.deposit_index,
                self.r0,
                self.r1,
                &proof_ref.leaf_proof,
                proof_ref.proof_index,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceCfcStepKind {
    Standard,
    BurnFee,
    Inlined,
    Deferred,
}

struct TraceArenaBuilder {
    steps: Vec<crate::trace::TraceStep>,
}

impl TraceArenaBuilder {
    fn new() -> Self {
        Self { steps: Vec::new() }
    }

    fn alloc_cfc(
        &mut self,
        parent: Option<crate::trace::TraceStepId>,
        kind: TraceCfcStepKind,
        step: psy_ups_circuit::session::TracedCfcStep<F>,
    ) -> anyhow::Result<crate::trace::TraceStepId> {
        let id = crate::trace::TraceStepId::from(self.steps.len());
        let deferred_steps = step.deferred;
        let cfc = crate::trace::CfcStep {
            id,
            parent,
            inlined: Vec::new(),
            deferred: Vec::with_capacity(deferred_steps.len()),
            contract_id: step.contract_id,
            fn_id: step.fn_id,
            method_id: step.method_id,
            method_name: step.method_name,
            cfc_fingerprint: step.cfc_fingerprint,
            ups_fingerprint: step.ups_fingerprint,
            proof_tree_start_root: step.proof_tree_start_root,
            proof_tree_end_root: step.proof_tree_end_root,
            cfc_witness: step.cfc_witness,
            state_delta: step.state_delta.into(),
            cfc_inclusion_proof: step.cfc_inclusion_proof,
            end_header: step.end_header,
            debt_removal_proof: step.debt_removal_proof,
            proof: None,
        };
        let trace_step = match kind {
            TraceCfcStepKind::Standard => crate::trace::TraceStep::Standard(cfc),
            TraceCfcStepKind::BurnFee => crate::trace::TraceStep::BurnFee(cfc),
            TraceCfcStepKind::Inlined => crate::trace::TraceStep::Inlined(cfc),
            TraceCfcStepKind::Deferred => crate::trace::TraceStep::Deferred(cfc),
        };
        self.steps.push(trace_step);

        let mut deferred_ids = Vec::with_capacity(deferred_steps.len());
        for child in deferred_steps {
            deferred_ids.push(self.alloc_cfc(Some(id), TraceCfcStepKind::Deferred, child)?);
        }

        let cfc = self.steps[id.0]
            .as_cfc_mut()
            .ok_or_else(|| anyhow::anyhow!("trace arena step {} is not a CFC step", id.0))?;
        cfc.deferred = deferred_ids;
        Ok(id)
    }

    fn push_step(&mut self, step: crate::trace::TraceStep) {
        self.steps.push(step);
    }

    fn finish(self) -> Vec<crate::trace::TraceStep> {
        self.steps
    }
}

#[derive(Clone, Debug)]
pub struct TraceExternalProofRef {
    pub proof_index: u64,
    pub leaf_proof: MerkleProofCore<QHashOut<F>>,
}
#[derive(Default)]
struct SimulationCallClassification {
    call_count: usize,
    all_view: bool,
}

impl SimulationCallClassification {
    fn new() -> Self {
        Self {
            call_count: 0,
            all_view: true,
        }
    }

    fn observe(&mut self, is_view: bool) {
        self.call_count += 1;
        self.all_view &= is_view;
    }

    fn is_fee_free_view(&self) -> bool {
        self.call_count > 0 && self.all_view
    }
}

pub struct TraceBuildSession<'a> {
    wallet_session: &'a WalletSession,
    public_key: QHashOut<F>,
    user_session_mgr: UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
    trace_arena: TraceArenaBuilder,
    ups_start_witness_input: psy_client_data::ups::start_step::UPSStartStepInput<F>,
    ups_start_registration_proof: Option<psy_crypto::hash::merkle::core::MerkleProofCore<QHashOut<F>>>,
}
impl<'a> TraceBuildSession<'a> {
    pub async fn add_external_proof(
        &mut self,
        fingerprint: QHashOut<F>,
        proof: ProofWithPublicInputs<F, C, D>,
        verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<TraceExternalProofRef> {
        let (proof_index, leaf_proof) = WalletSession::push_external_proof_step(
            &mut self.user_session_mgr,
            &mut self.trace_arena,
            fingerprint,
            proof,
            verifier_data,
        )
        .await?;
        Ok(TraceExternalProofRef { proof_index, leaf_proof })
    }

    pub async fn trace_call(&mut self, contract_call_arg: ContractCallArgs) -> anyhow::Result<bool> {
        use psy_client_data::qstore::imm::cmd::QSRCmdGetContractCodeDefinition;

        let user_session_mgr = &mut self.user_session_mgr;
        let cm = self.wallet_session.wallet.random_circuit_manager();
        let contract_code = user_session_mgr
            .require_lps_mut()?
            .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition {
                contract_id: contract_call_arg.contract_id,
            })
            .await?;
        let (fn_id, fn_circuit_def) = cm
            .resolve_contract_function_by_method_name(contract_call_arg.contract_id, &contract_code, contract_call_arg.method_name.clone())
            .await?;
        let is_view = fn_circuit_def.is_view_function();
        let inputs: Vec<F> = contract_call_arg.inputs.iter().map(|x| F::from_noncanonical_u64(*x)).collect();
        let traced_step = user_session_mgr
            .trace_standard_call(
                cm.as_ref(),
                F::from_canonical_u64(contract_call_arg.contract_id),
                fn_id as u32,
                &fn_circuit_def,
                inputs,
            )
            .await
            .map_err(|e| anyhow::anyhow!("generate_tx_trace standard call failed: {:#}", e))?;
        self.trace_arena.alloc_cfc(None, TraceCfcStepKind::Standard, traced_step)?;
        Ok(is_view)
    }

    pub async fn finalize_tx_trace(self, software_defined_call: DPNSoftwareDefinedCallData) -> anyhow::Result<crate::trace::TxTrace> {
        self.finalize_tx_trace_with_opts(software_defined_call).await
    }

    pub async fn finalize_tx_trace_with_opts(mut self, software_defined_call: DPNSoftwareDefinedCallData) -> anyhow::Result<crate::trace::TxTrace> {
        use psy_client_data::qstore::imm::cmd::QSRCmdGetContractCodeDefinition;

        use crate::trace::*;

        if !self.trace_arena.steps.iter().any(|step| step.contract_id().is_some()) {
            anyhow::bail!("No contract calls to execute");
        }

        let user_session_mgr = &mut self.user_session_mgr;
        let cm = self.wallet_session.wallet.random_circuit_manager();

        let burn_contract_code = user_session_mgr
            .require_lps_mut()?
            .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition {
                contract_id: psy_config::network_constants::TOKEN_CONTRACT_ID as u64,
            })
            .await?;
        cm.register_contract_circuits(psy_config::network_constants::TOKEN_CONTRACT_ID as u64, &burn_contract_code)
            .await?;

        let burn_step = user_session_mgr.trace_burn_fee(cm.as_ref()).await?;
        self.trace_arena.alloc_cfc(None, TraceCfcStepKind::BurnFee, burn_step)?;

        let pk_info = self.wallet_session.wallet.get_public_key_info(&self.public_key).await?;
        let nonce = user_session_mgr.require_lps()?.get_nonce();
        let sig_hash = user_session_mgr.get_sighash(PSY_NETWORK_MAGIC, nonce);
        let zksign_start_root = user_session_mgr.proof_tree_state.get_proof_tree_root().await;

        let initial_circuit_manager = self.wallet_session.wallet.random_circuit_manager();
        let zk_builtin_fingerprint = initial_circuit_manager.zk_signature_minifier_fingerprint().await?;
        let secp_builtin_fingerprint = initial_circuit_manager.secp_circuit_fingerprint().await?;
        let eth_personal_builtin_fingerprint = match self
            .wallet_session
            .circuit_info
            .get_circuit_info_by_id(LocalCircuitType::EthPersonalSecp256K1.into())
        {
            Ok(_) => Some(crate::wallet::memory_wallet::get_eth_personal_secp256k1_fingerprint()),
            Err(_) => None,
        };
        let builtin_source = select_builtin_sign_circuit(
            pk_info.fingerprint,
            zk_builtin_fingerprint,
            secp_builtin_fingerprint,
            eth_personal_builtin_fingerprint,
        );
        let circuit_manager = if matches!(builtin_source, Some(TraceSignCircuitSource::EthPersonalSecpBuiltin)) {
            self.wallet_session.wallet.eth_personal_circuit_manager().await?
        } else {
            initial_circuit_manager
        };
        let (sign_circuit_source, zksign_fingerprint) = if let Some(source) = builtin_source {
            (source, pk_info.fingerprint)
        } else if self.wallet_session.wallet.has_psy_software_defined_circuit(&pk_info.fingerprint) {
            let sdc = self
                .wallet_session
                .wallet
                .get_psy_software_defined_circuit(&pk_info.fingerprint)
                .ok_or_else(|| anyhow::format_err!("PSY software defined circuit `{}` not found", pk_info.fingerprint))?;
            (
                TraceSignCircuitSource::PsySoftwareDefined {
                    circuit_def: bincode::serialize(&sdc.fn_def)?,
                    force_four_align: sdc.force_four_align,
                },
                pk_info.fingerprint,
            )
        } else if self.wallet_session.wallet.has_plonky2_software_defined_circuit(&pk_info.fingerprint) {
            (
                TraceSignCircuitSource::Plonky2SoftwareDefined {
                    contract_state_tree_height: MAX_CONTRACT_STATE_TREE_HEIGHT,
                    input_len: 0,
                },
                pk_info.fingerprint,
            )
        } else if self.wallet_session.wallet.has_sd_key_circuit(&pk_info.fingerprint) {
            let policy = self
                .wallet_session
                .wallet
                .get_sd_key_policy(&pk_info.fingerprint)
                .ok_or_else(|| anyhow::format_err!("SD key policy `{}` not found", pk_info.fingerprint))?;
            (
                TraceSignCircuitSource::SdKey {
                    allowed_contract_ids: policy.allowed_contract_ids,
                    allowed_method_ids: policy.allowed_method_ids,
                    expected_tx_count: policy.expected_tx_count,
                },
                pk_info.fingerprint,
            )
        } else {
            anyhow::bail!("unknown signing circuit for fingerprint {}", pk_info.fingerprint);
        };
        let (sign_witness, sign_verifier_data_alt) = match &sign_circuit_source {
            TraceSignCircuitSource::ZkBuiltin => (
                Vec::new(),
                AltVerifierOnlyCircuitData::from(&circuit_manager.zk_signature_minifier_verifier_config().await?),
            ),
            TraceSignCircuitSource::SecpBuiltin => (
                Vec::new(),
                AltVerifierOnlyCircuitData::from(&circuit_manager.secp_circuit_verifier_config().await?),
            ),
            TraceSignCircuitSource::EthPersonalSecpBuiltin => (
                Vec::new(),
                AltVerifierOnlyCircuitData::from(&circuit_manager.eth_personal_secp_circuit_verifier_config().await?),
            ),
            TraceSignCircuitSource::PsySoftwareDefined { .. } => {
                let sign_context = self
                    .wallet_session
                    .build_psy_software_defined_context(
                        &software_defined_call,
                        pk_info.fingerprint,
                        user_session_mgr,
                        SignContext::new(pk_info.fingerprint),
                    )
                    .await?;
                let witness = sign_context
                    .psy_signature_input
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("PSY software-defined witness missing after build"))?;
                let verifier = self
                    .wallet_session
                    .wallet
                    .get_psy_software_defined_circuit(&pk_info.fingerprint)
                    .ok_or_else(|| anyhow::format_err!("PSY software defined circuit `{}` not found", pk_info.fingerprint))?;
                (
                    bincode::serialize(witness)?,
                    AltVerifierOnlyCircuitData::from(
                        verifier
                            .get_verifier_config_ref()
                            .ok_or_else(|| anyhow::anyhow!("PSY software-defined verifier config missing"))?,
                    ),
                )
            }
            TraceSignCircuitSource::Plonky2SoftwareDefined { .. } => {
                let sign_context = self
                    .wallet_session
                    .build_plonky2_software_defined_context(&software_defined_call, pk_info.fingerprint, user_session_mgr)
                    .await?;
                let witness = sign_context
                    .plonky2_signature_input
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("PLONKY2 software-defined witness missing after build"))?;
                let verifier = self
                    .wallet_session
                    .wallet
                    .get_plonky2_software_defined_circuit(&pk_info.fingerprint)
                    .ok_or_else(|| anyhow::format_err!("PLONKY2 software defined circuit `{}` not found", pk_info.fingerprint))?;
                (
                    bincode::serialize(witness)?,
                    AltVerifierOnlyCircuitData::from(
                        verifier
                            .get_verifier_config_ref()
                            .ok_or_else(|| anyhow::anyhow!("PLONKY2 software-defined verifier config missing"))?,
                    ),
                )
            }
            TraceSignCircuitSource::SdKey { .. } => {
                let sign_context = self
                    .wallet_session
                    .build_sd_key_context(&software_defined_call, pk_info.fingerprint, user_session_mgr)
                    .await?;
                let witness = sign_context
                    .sd_key_signature_input
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("SD key witness missing after build"))?;
                let verifier = self
                    .wallet_session
                    .wallet
                    .get_sd_key_circuit(&pk_info.fingerprint)
                    .ok_or_else(|| anyhow::format_err!("SD key circuit `{}` not found", pk_info.fingerprint))?;
                (
                    bincode::serialize(witness)?,
                    AltVerifierOnlyCircuitData::from(
                        verifier
                            .get_verifier_config_ref()
                            .ok_or_else(|| anyhow::anyhow!("SD key verifier config missing"))?,
                    ),
                )
            }
        };

        user_session_mgr
            .proof_tree_state
            .injest_single_leaf_public_inputs_hash(zksign_fingerprint, PsyHasher::q_two_to_one(sig_hash, pk_info.public_key_param))
            .await;
        let zksign_end_root = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
        self.trace_arena.push_step(TraceStep::ZkSign(ZkSignStep {
            fingerprint: zksign_fingerprint,
            proof_tree_start_root: zksign_start_root,
            proof_tree_end_root: zksign_end_root,
            sign_circuit_source,
            sign_witness: sign_witness.clone(),
            public_key_param: pk_info.public_key_param,
            sign_verifier_data_alt,
        }));

        user_session_mgr.set_current_ups_header_nonce(nonce);
        let end_cap_input = user_session_mgr.get_api_input().await?;
        let tx_hash = end_cap_input.get_tx_hash()?;
        let start_checkpoint_id = user_session_mgr.require_lps()?.get_current_start_checkpoint_id_u64();
        let user_id = user_session_mgr.require_lps()?.get_current_user_id_64();
        let ups_header = user_session_mgr.get_current_ups_header().clone();
        let anchor_checkpoint_leaf = user_session_mgr.get_current_checkpoint_leaf().clone();
        let anchor_global_state_roots = user_session_mgr.get_current_global_state_roots().clone();

        let mut contract_codes = Vec::new();
        for step in &self.trace_arena.steps {
            if let Some(cid) = step.contract_id() {
                let code = user_session_mgr
                    .require_lps_mut()?
                    .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition { contract_id: cid })
                    .await?;
                let bytes = bincode::serialize(&code)?;
                contract_codes.push(TraceContractCode {
                    contract_id: cid,
                    code: bytes,
                });
            }
        }
        drop(user_session_mgr);

        Ok(TxTrace {
            meta: TraceMeta {
                network_magic: PSY_NETWORK_MAGIC,
                user_id,
                public_key: self.public_key,
            },
            anchor: SessionAnchor {
                start_checkpoint_id,
                checkpoint_leaf: anchor_checkpoint_leaf,
                global_state_roots: anchor_global_state_roots,
                ups_step_circuit_whitelist_root: ups_header.ups_step_circuit_whitelist_root,
            },
            ups_start_witness: UpsStartWitness {
                ups_header: self.ups_start_witness_input.ups_header,
                state_roots: self.ups_start_witness_input.state_roots,
                checkpoint_tree_proof: self.ups_start_witness_input.checkpoint_tree_proof,
                user_tree_proof: self.ups_start_witness_input.user_tree_proof,
                user_registration_tree_proof: self.ups_start_registration_proof,
                proof: None,
            },
            contract_codes,
            steps: self.trace_arena.finish(),
            finalization: TxFinalization {
                submit_end_cap_input: end_cap_input,
                nonce,
                software_defined_call,
                tx_hash,
                sig_hash,
            },
        })
    }

    pub async fn generate_tx_trace(self, call_data: ContractCallData) -> anyhow::Result<crate::trace::TxTrace> {
        self.generate_tx_trace_with_opts(call_data).await
    }

    pub async fn simulate_contract_call(self, call_data: ContractCallData) -> anyhow::Result<crate::trace::SimulatedTxJson> {
        self.simulate_contract_call_with_opts(call_data).await
    }

    pub async fn simulate_contract_call_with_opts(mut self, call_data: ContractCallData) -> anyhow::Result<crate::trace::SimulatedTxJson> {
        let mut classification = SimulationCallClassification::new();
        for contract_call_arg in call_data.contract_calls.clone() {
            classification.observe(self.trace_call(contract_call_arg).await?);
        }

        if classification.is_fee_free_view() {
            let user_id = self.user_session_mgr.require_lps()?.get_current_user_id_64();
            let metadata = crate::trace::SimulatedTxMetadata::from_view_steps(
                user_id,
                &self.trace_arena.steps,
                call_data.software_defined_call,
            )?;
            return Ok(crate::trace::SimulatedTxJson {
                generated: None,
                metadata,
            });
        }

        let call_data_json = serde_json::to_value(&call_data)?;
        let trace = self.finalize_tx_trace_with_opts(call_data.software_defined_call).await?;
        let generated = crate::trace::GeneratedTxTraceJson::from_trace(&trace, call_data_json)?;
        let metadata = crate::trace::TxMetadata::from_trace(&trace).into();
        Ok(crate::trace::SimulatedTxJson {
            generated: Some(generated),
            metadata,
        })
    }

    pub async fn generate_tx_trace_with_opts(mut self, call_data: ContractCallData) -> anyhow::Result<crate::trace::TxTrace> {
        for contract_call_arg in call_data.contract_calls.clone() {
            self.trace_call(contract_call_arg).await?;
        }
        self.finalize_tx_trace_with_opts(call_data.software_defined_call).await
    }
}

fn ensure_view_definition(contract_id: u64, method_name: &str, definition: &DPNFunctionCircuitDefinition) -> anyhow::Result<()> {
    anyhow::ensure!(
        definition.is_view_function(),
        "contract {} method {} is not read-only",
        contract_id,
        method_name
    );
    Ok(())
}

fn ensure_view_execution_effects(
    contract_id: u64,
    method_name: &str,
    witness: &psy_vm::vm::cfc_input::DapenContractFunctionCircuitInput<F>,
    user_contract_update: &psy_crypto::hash::merkle::core::DeltaMerkleProofCore<QHashOut<F>>,
) -> anyhow::Result<()> {
    let start = &witness.tx_input_ctx.transaction_call_start_ctx;
    let end = &witness.tx_input_ctx.transaction_end_ctx;
    anyhow::ensure!(witness.events.is_empty(), "view call {}::{} emitted events", contract_id, method_name);
    anyhow::ensure!(end.total_events_emitted == F::ZERO, "view call {}::{} reported emitted events", contract_id, method_name);
    anyhow::ensure!(end.total_balance_spent == F::ZERO, "view call {}::{} spent balance", contract_id, method_name);
    anyhow::ensure!(
        start.start_contract_state_tree_root == end.end_contract_state_tree_root,
        "view call {}::{} changed contract storage",
        contract_id,
        method_name
    );
    anyhow::ensure!(
        start.start_deferred_tx_debt_tree_root == end.end_deferred_tx_debt_tree_root,
        "view call {}::{} changed deferred transaction state",
        contract_id,
        method_name
    );
    anyhow::ensure!(
        user_contract_update.old_root == user_contract_update.new_root && user_contract_update.old_value == user_contract_update.new_value,
        "view call {}::{} changed user contract state",
        contract_id,
        method_name
    );
    anyhow::ensure!(
        witness.cmd_witnesses.iter().all(|command| command.state_cmd.is_read_only()),
        "view call {}::{} executed a non-read-only state command",
        contract_id,
        method_name
    );
    Ok(())
}

#[cfg(test)]
mod view_validation_tests {
    use super::*;
    use psy_vm::dpn::ops::{
        op_types::DPNEventRecord,
        state_cmd::data::DPNStateCmd,
    };

    fn definition(state_commands: Vec<DPNStateCmd<u64>>) -> DPNFunctionCircuitDefinition {
        DPNFunctionCircuitDefinition {
            name: "view_candidate".to_string(),
            method_id: 1,
            circuit_inputs: Vec::new(),
            circuit_outputs: Vec::new(),
            state_commands,
            state_command_resolution_indices: Vec::new(),
            assertions: Vec::new(),
            definitions: Vec::new(),
            events: Vec::new(),
        }
    }

    #[test]
    fn call_view_preflight_accepts_pure_and_rejects_event_or_write_definitions() {
        ensure_view_definition(7, "pure", &definition(Vec::new())).unwrap();

        let mut event_only = definition(Vec::new());
        event_only.events.push(DPNEventRecord {
            condition: 0,
            checkpoint_id: 0,
            user_id: 0,
            contract_id: 0,
            data: Vec::new(),
        });
        assert!(ensure_view_definition(7, "event_only", &event_only).is_err());

        let writer = definition(vec![DPNStateCmd::set_contract_state_slot_single(1, 0, 1)]);
        assert!(ensure_view_definition(7, "writer", &writer).is_err());
    }
}
#[cfg(test)]
mod personal_registration_tests {
    use super::*;

    #[test]
    fn personal_registration_challenge_rejects_zero_and_binds_address() {
        assert!(WalletSession::eth_personal_registration_challenge([0; 20]).is_err());
        let first = WalletSession::eth_personal_registration_challenge([1; 20]).unwrap();
        let second = WalletSession::eth_personal_registration_challenge([2; 20]).unwrap();
        assert_ne!(first, second);
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl WalletSession {
    async fn resolve_registered_user_id_with_hint(&self, public_key: QHashOut<F>, hinted_user_id: u64) -> anyhow::Result<u64> {
        let latest_checkpoint_id = self.st_provider.get_latest_block_state().await?.checkpoint_id;
        let registration_id = get_registration_id_from_user_id(hinted_user_id);
        let mp = self
            .st_provider
            .get_user_registration_tree_merkle_proof(latest_checkpoint_id, registration_id)
            .await?;
        anyhow::ensure!(
            mp.value == public_key,
            "hinted user_id {} does not match requested public key {} at checkpoint {}",
            hinted_user_id,
            public_key,
            latest_checkpoint_id
        );
        tracing::info!(
            public_key = %public_key,
            chosen_user_id = hinted_user_id,
            latest_checkpoint_id,
            "selected user id from explicit hint"
        );
        Ok(hinted_user_id)
    }

    async fn resolve_registered_user_id(&self, public_key: QHashOut<F>) -> anyhow::Result<u64> {
        let mut candidate_ids = self.st_provider.get_user_ids_for_public_key(public_key).await?;
        if candidate_ids.is_empty() {
            anyhow::bail!("no user_id found for public key {}", public_key);
        }
        candidate_ids.sort_unstable();
        candidate_ids.dedup();
        let latest_checkpoint_id = self.st_provider.get_latest_block_state().await?.checkpoint_id;
        tracing::info!(
            public_key = %public_key,
            latest_checkpoint_id,
            candidates = ?candidate_ids,
            "resolved user id candidates from registration index"
        );

        let mut valid_candidates = Vec::new();
        for user_id in candidate_ids {
            let registration_id = get_registration_id_from_user_id(user_id);
            match self
                .st_provider
                .get_user_registration_tree_merkle_proof(latest_checkpoint_id, registration_id)
                .await
            {
                Ok(mp) if mp.value == public_key => {
                    valid_candidates.push(user_id);
                }
                Ok(mp) => {
                    tracing::warn!(
                        public_key = %public_key,
                        user_id,
                        registration_id,
                        registration_leaf_value = %mp.value,
                        latest_checkpoint_id,
                        "dropping candidate: registration tree leaf value does not match requested public key"
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        public_key = %public_key,
                        user_id,
                        registration_id,
                        latest_checkpoint_id,
                        "dropping candidate: failed to fetch registration merkle proof: {}",
                        err
                    );
                }
            }
        }

        if valid_candidates.is_empty() {
            anyhow::bail!(
                "no valid user_id found for public key {} at checkpoint {}",
                public_key,
                latest_checkpoint_id
            );
        }

        let chosen = valid_candidates[0];
        tracing::info!(
            public_key = %public_key,
            valid_candidates = ?valid_candidates,
            chosen_user_id = chosen,
            "selected user id candidate"
        );
        Ok(chosen)
    }

    async fn resolve_registered_user_id_or_hint(&self, public_key: QHashOut<F>, hinted_user_id: Option<u64>) -> anyhow::Result<u64> {
        if let Some(user_id) = hinted_user_id {
            return self.resolve_registered_user_id_with_hint(public_key, user_id).await;
        }
        self.resolve_registered_user_id(public_key).await
    }

    async fn check_user_state(&self, user_id: u64, nonce: F) -> anyhow::Result<()> {
        match self
            .st_provider
            .with_user_id_owned(user_id)
            .get_tx_status(user_id, nonce.to_noncanonical_u64())
            .await?
        {
            TxStatus::Confirmed => {
                tracing::warn!("tx status is confirmed");
                Err(anyhow::format_err!(
                    "another similar tx is confirmed while building this tx, please rebuild the tx later"
                ))
            }
            TxStatus::Stale => {
                tracing::warn!("tx status is stale");
                Err(anyhow::format_err!(
                    "stale nonce: chain state advanced while building this tx, please rebuild the tx with the latest state"
                ))
            }
            TxStatus::Pending => {
                tracing::warn!("tx status is pending");
                Err(anyhow::format_err!("another similar tx is pending, please wait for it to be confirmed"))
            }
            TxStatus::Submittable => {
                tracing::debug!("tx status is submittable");
                Ok(())
            }
        }
    }

    async fn check_submit_anchor(&self, user_id: u64, start_user_leaf_hash: QHashOut<F>) -> anyhow::Result<()> {
        let checkpoint_id = self.st_provider.get_latest_block_state().await?.checkpoint_id;
        let latest_user_leaf = self.st_provider.get_user_leaf_data(checkpoint_id, user_id).await?;
        let latest_user_leaf_hash = latest_user_leaf.qfhash::<PsyHasher>();
        if start_user_leaf_hash != QHashOut::ZERO && latest_user_leaf_hash != start_user_leaf_hash {
            return Err(anyhow::Error::new(ProveError::StaleTraceAnchor {
                user_id,
                start_user_leaf_hash,
                latest_user_leaf_hash,
            }));
        }
        Ok(())
    }

    pub async fn is_endcap_included_at_checkpoint(
        &mut self,
        checkpoint_id: u64,
        user_id: u64,
        end_user_leaf_hash: QHashOut<F>,
    ) -> anyhow::Result<bool> {
        self.st_provider
            .with_user_id_owned(user_id)
            .is_endcap_included_at_checkpoint(checkpoint_id, user_id, end_user_leaf_hash)
            .await
    }

    pub async fn wait_for_endcap_inclusion(
        &mut self,
        user_id: u64,
        end_user_leaf_hash: QHashOut<F>,
        checkpoint_before: u64,
        timeout_secs: Option<u64>,
        poll_interval_secs: u64,
    ) -> anyhow::Result<u64> {
        self.st_provider
            .with_user_id_owned(user_id)
            .wait_for_endcap_inclusion(user_id, end_user_leaf_hash, checkpoint_before, timeout_secs, poll_interval_secs)
            .await
    }

    pub async fn new(rpc_config: &psy_config::NetworkConfigGoldilocks) -> anyhow::Result<Self> {
        tracing::info!("init rpc provider");
        let st_provider = RpcProvider::new_with_config(rpc_config)?;

        tracing::info!("init wallet");
        tracing::info!("init ups step circuit manager");
        let mut main_circuits: Vec<Box<dyn UPSCircuitManager<C, D> + Send + Sync>> = Vec::new();

        let proxy_urls: Vec<_> = rpc_config.prove_proxy_url.iter().map(|s| s.trim()).filter(|s| !s.is_empty()).collect();

        for proxy_url in &proxy_urls {
            match ProveProxyRpcProvider::new_with_config((*proxy_url).to_string()).await {
                Ok(main_circuit) => main_circuits.push(Box::new(main_circuit)),
                Err(e) => {
                    tracing::warn!("prove proxy url `{}` is invalid, skip: {}", proxy_url, e);
                }
            }
        }
        if main_circuits.is_empty() {
            if !proxy_urls.is_empty() {
                anyhow::bail!(
                    "prove proxy configured ({:?}) but none are reachable; refusing to fall back to local circuit manager",
                    proxy_urls
                );
            }
            tracing::warn!("no prove proxy configured, use local circuit manager");
            main_circuits.push(Box::new(PsyUPSStepCircuitManager::<C, D>::new_with_config(PSY_NETWORK_MAGIC)));
        }

        let mut canonical_eth_personal_metadata = None;
        for manager in &main_circuits {
            match (
                manager.eth_personal_secp_circuit_fingerprint().await,
                manager.eth_personal_secp_circuit_verifier_config().await,
            ) {
                (Ok(fingerprint), Ok(verifier))
                    if fingerprint == crate::wallet::memory_wallet::get_eth_personal_secp256k1_fingerprint() =>
                {
                    match &canonical_eth_personal_metadata {
                        None => canonical_eth_personal_metadata = Some((fingerprint, verifier)),
                        Some((_, canonical_verifier)) if verifier == *canonical_verifier => {}
                        Some(_) => tracing::warn!("prove manager EIP-191 verifier mismatches the selected compatible cohort"),
                    }
                }
                (Ok(fingerprint), Ok(_)) => {
                    tracing::warn!(?fingerprint, "prove manager EIP-191 fingerprint does not match this client build");
                }
                (fingerprint, verifier) => {
                    tracing::warn!(
                        fingerprint = ?fingerprint.ok(),
                        verifier_available = verifier.is_ok(),
                        "prove manager EIP-191 metadata is unavailable; classic signing remains available"
                    );
                }
            }
        }

        // Load the local base circuits from the embedded `local_circuits.json`
        // (zk-sign full + privacy compact) instead of building them.
        let local_circuits = PsyWalletLocalCircuits::from_embedded_bundle()?;
        let mut circuit_info = SessionCircuitInfoStore::new();

        tracing::info!("register ZKSignature circuit info");
        circuit_info.register_circuit(
            LocalCircuitType::SimpleZKSignature.into(),
            main_circuits[0].zk_signature_minifier_fingerprint().await?,
            main_circuits[0].zk_signature_minifier_verifier_config().await?.into(),
        );

        circuit_info.register_circuit(
            LocalCircuitType::SimpleSecp256K1.into(),
            main_circuits[0].secp_circuit_fingerprint().await?,
            main_circuits[0].secp_circuit_verifier_config().await?.into(),
        );

        if let Some((fingerprint, verifier_config)) = canonical_eth_personal_metadata {
            circuit_info.register_circuit(LocalCircuitType::EthPersonalSecp256K1.into(), fingerprint, verifier_config.into());
        } else {
            tracing::warn!("prove manager does not expose EIP-191 circuit metadata; personal signing is unavailable");
        }

        // Privacy circuits: the wallet produces base proofs; the (server-side) minifier
        // fingerprint/verifier come from the manager.
        circuit_info.register_circuit(
            LocalCircuitType::SimplePrivateNoteInclusion.into(),
            main_circuits[0].private_note_inclusion_minifier_fingerprint().await?,
            main_circuits[0].private_note_inclusion_minifier_verifier_config().await?.into(),
        );

        circuit_info.register_circuit(
            LocalCircuitType::SimpleShieldDepositClaim.into(),
            main_circuits[0].shield_deposit_claim_minifier_fingerprint().await?,
            main_circuits[0].shield_deposit_claim_minifier_verifier_config().await?.into(),
        );

        for main_circuit in main_circuits.iter() {
            main_circuit.as_ref().register_info(&mut circuit_info).await;
        }

        let wallet = PsyMemoryWallet::new_with_local_circuits(main_circuits, local_circuits);

        Ok(WalletSession {
            wallet,
            circuit_info,
            st_provider,
            #[cfg(not(target_arch = "wasm32"))]
            local_proving_job_manager: JobManager::empty(),
            user_session_mgrs: DashMap::new(),
        })
    }

    pub async fn prove_private_note_inclusion(
        &self,
        input: &psy_client_data::privacy::private_note_inclusion::PrivateNoteInclusionInput<F>,
    ) -> anyhow::Result<(QHashOut<F>, ProofWithPublicInputs<F, C, D>, AltVerifierOnlyCircuitData<F>)> {
        self.wallet.prove_private_note_inclusion(input).await
    }

    pub async fn prove_shield_deposit_claim(
        &self,
        input: &psy_client_data::privacy::deposit_inclusion::DepositInclusionInput<F>,
    ) -> anyhow::Result<(QHashOut<F>, ProofWithPublicInputs<F, C, D>, AltVerifierOnlyCircuitData<F>)> {
        self.wallet.prove_shield_deposit_claim(input).await
    }

    pub fn private_note_inclusion_fingerprint(&self) -> anyhow::Result<QHashOut<F>> {
        if let Ok(info) = self
            .circuit_info
            .get_circuit_info_by_id(LocalCircuitType::SimplePrivateNoteInclusion.into())
        {
            return Ok(info.fingerprint);
        }
        Ok(self.wallet.fallback_private_note_inclusion_minifier_fingerprint())
    }

    pub fn resolve_private_note_inclusion_verifier_data(&self, fingerprint: QHashOut<F>) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        if let Ok(info) = self.circuit_info.get_circuit_info_by_fingerprint(fingerprint) {
            return Ok(info.verifier_data.to_verifier_data::<C, D>());
        }

        if self.wallet.fallback_private_note_inclusion_minifier_fingerprint() == fingerprint {
            return Ok(self.wallet.fallback_private_note_inclusion_minifier_verifier_data());
        }

        anyhow::bail!(
            "PrivateNoteInclusion minifier verifier data for fingerprint {} is not registered in session info",
            fingerprint
        )
    }

    pub async fn register_user(&mut self, private_key: QHashOut<F>, fingerprint: QHashOut<F>) -> anyhow::Result<QHashOut<F>> {
        let pk_info = self.wallet.get_or_create_user(private_key, fingerprint).await?;
        let public_key = pk_info.qfhash::<PsyHasher>();

        if let Ok(user_id) = self.resolve_registered_user_id(public_key).await {
            tracing::info!("user `{}` already registered with id {}", public_key, user_id);
            return Ok(public_key);
        }

        self.st_provider.register_user(QRegisterUserRPCRequest { public_key: pk_info }).await?;

        tracing::info!("user `{}` registered", public_key);
        tracing::warn!("please add this user after 2 checkpoints!");
        Ok(public_key)
    }

    /// Returns the network- and address-bound EIP-191 registration challenge.
    pub fn eth_personal_registration_challenge(selected_evm_address: [u8; 20]) -> anyhow::Result<psy_client_common::data::base_types::hash256::Hash256> {
        anyhow::ensure!(selected_evm_address.iter().any(|byte| *byte != 0), "selected Ethereum address must not be the zero address");
        Ok(psy_crypto::signature::secp256k1::wallet::eth_personal_registration_challenge(
            PSY_NETWORK_MAGIC,
            selected_evm_address,
        ))
    }

    /// Mode-A (web/MetaMask): register a secp256k1 PUBLIC key as a Psy account
    /// WITHOUT a held private key. Installs a PK-only [`ExternalSecp256K1User`]
    /// for the derived `pk_hash` and submits the SAME
    /// `QRegisterUserRPCRequest { public_key }` the held-key [`register_user`]
    /// submits — so the registration is byte-identical to the classic secp256k1
    /// path, just sourced from an outside signer. Returns the derived
    /// `pk_hash`.
    ///
    /// After registration, the Mode-A lifecycle per transaction is:
    /// 1. `generate_tx_trace` (needs no signature) → read the session sighash
    /// 2. MetaMask signs that sighash
    /// 3. [`Self::inject_secp_signature`] with the fresh signature (replaces
    ///    the wallet user; on-chain registration is skipped as it exists)
    /// 4. prove / `sign_and_submit` the end cap
    pub async fn register_external_secp_user(
        &mut self,
        compressed_public_key: psy_client_common::data::secp256k1::CompressedPublicKey,
    ) -> anyhow::Result<QHashOut<F>> {
        let pk_info = self.wallet.register_external_secp_user(compressed_public_key).await?;
        self.register_external_pk_info_on_chain(pk_info, "external secp").await
    }
    /// Inject an externally produced (MetaMask `eth_sign`-style) signature over
    /// the session sighash: replaces `expected_public_key` with a
    /// signature-carrying wallet user. Rejects signatures from any other
    /// account. See [`Self::register_external_secp_user`] for the lifecycle.
    pub async fn inject_secp_signature(
        &mut self,
        expected_public_key: QHashOut<F>,
        signature: psy_crypto::signature::secp256k1::core::PsyCompressedSecp256K1Signature,
    ) -> anyhow::Result<QHashOut<F>> {
        self.wallet.inject_secp_signature(expected_public_key, signature).await?;
        Ok(expected_public_key)
    }

    /// Mode-A MetaMask `personal_sign` registration. The selected Ethereum
    /// address must authenticate the network-bound challenge with a canonical
    /// 65-byte low-S signature before the recovered public key is registered.
    pub async fn register_external_eth_personal_user(
        &mut self,
        selected_evm_address: [u8; 20],
        recovery_message: psy_client_common::data::base_types::hash256::Hash256,
        signature: [u8; 65],
    ) -> anyhow::Result<QHashOut<F>> {
        self.circuit_info
            .get_circuit_info_by_id(LocalCircuitType::EthPersonalSecp256K1.into())
            .map_err(|_| anyhow::anyhow!("external EIP-191 signing is unavailable because no compatible prove-manager cohort exposes circuit metadata"))?;
        let expected_challenge = Self::eth_personal_registration_challenge(selected_evm_address)?;
        anyhow::ensure!(
            recovery_message == expected_challenge,
            "external EIP-191 registration message does not match the network-bound account challenge"
        );
        let recovered = psy_crypto::signature::secp256k1::wallet::recover_eth_personal_signature(
            selected_evm_address,
            recovery_message,
            signature,
        )?;
        let pk_info = self
            .wallet
            .register_external_eth_personal_user(psy_client_common::data::secp256k1::CompressedPublicKey(recovered.public_key))
            .await?;
        self.register_external_pk_info_on_chain(pk_info, "external EIP-191").await
    }

    /// Inject a MetaMask `personal_sign` signature over the session sighash.
    /// The recovered address and low-S signature are validated on the host
    /// before the signature-carrying wallet user replaces the PK-only entry.
    pub async fn inject_eth_personal_signature(
        &mut self,
        expected_public_key: QHashOut<F>,
        selected_evm_address: [u8; 20],
        message: psy_client_common::data::base_types::hash256::Hash256,
        signature: [u8; 65],
    ) -> anyhow::Result<QHashOut<F>> {
        let recovered = psy_crypto::signature::secp256k1::wallet::recover_eth_personal_signature(
            selected_evm_address,
            message,
            signature,
        )?;
        self.wallet.inject_eth_personal_signature(expected_public_key, recovered).await?;
        Ok(expected_public_key)
    }

    /// Shared on-chain registration step for external (keyless) users: skips
    /// the RPC if the account is already registered.
    async fn register_external_pk_info_on_chain(&mut self, pk_info: ZKPublicKeyInfo<F>, label: &str) -> anyhow::Result<QHashOut<F>> {
        let public_key = pk_info.qfhash::<PsyHasher>();

        if let Ok(user_id) = self.resolve_registered_user_id(public_key).await {
            tracing::info!("{} user `{}` already registered with id {}", label, public_key, user_id);
            return Ok(public_key);
        }

        self.st_provider.register_user(QRegisterUserRPCRequest { public_key: pk_info }).await?;

        tracing::info!("{} user `{}` registered", label, public_key);
        Ok(public_key)
    }

    pub async fn add_user(&mut self, private_key: QHashOut<F>, fingerprint: QHashOut<F>) -> anyhow::Result<QHashOut<F>> {
        let pk_info = self.wallet.get_or_create_user(private_key, fingerprint).await?;
        println!("adding user {}", serde_json::to_string_pretty(&pk_info)?);
        let public_key = pk_info.qfhash::<PsyHasher>();
        println!("public_key: {}", public_key);

        let user_id = self
            .resolve_registered_user_id(public_key)
            .await
            .map_err(|e| anyhow::format_err!("User {} not registered. Please register first: {}", public_key, e))?;
        self.update_circuit_mgr(public_key).await?;
        tracing::info!("user {} with id {} added", public_key.to_string(), user_id);
        Ok(public_key)
    }

    pub async fn add_user_with_user_id(&mut self, private_key: QHashOut<F>, fingerprint: QHashOut<F>, user_id: u64) -> anyhow::Result<QHashOut<F>> {
        let pk_info = self.wallet.get_or_create_user(private_key, fingerprint).await?;
        println!("adding user {}", serde_json::to_string_pretty(&pk_info)?);
        let public_key = pk_info.qfhash::<PsyHasher>();
        println!("public_key: {}", public_key);

        let resolved_user_id = self
            .resolve_registered_user_id_or_hint(public_key, Some(user_id))
            .await
            .map_err(|e| anyhow::format_err!("User {} not registered for explicit user_id {}: {}", public_key, user_id, e))?;
        self.update_circuit_mgr_for_user_id(public_key, resolved_user_id).await?;
        tracing::info!("user {} with id {} added via explicit hint", public_key.to_string(), resolved_user_id);
        Ok(public_key)
    }

    pub async fn register_sd_key_circuit(
        &mut self,
        allowed_contract_ids: &[u64],
        allowed_method_ids: &[u32],
        expected_tx_count: u64,
    ) -> anyhow::Result<QHashOut<F>> {
        self.wallet
            .register_allow_method_sd_key_circuit(allowed_contract_ids, allowed_method_ids, expected_tx_count)
            .await
    }

    pub async fn update_circuit_mgr(&self, public_key: QHashOut<F>) -> anyhow::Result<()> {
        let user_id = self
            .resolve_registered_user_id(public_key)
            .await
            .map_err(|e| anyhow::format_err!("User {} not registered. Please register first: {}", public_key, e))?;
        self.update_circuit_mgr_for_user_id(public_key, user_id).await
    }

    async fn update_circuit_mgr_for_user_id(&self, public_key: QHashOut<F>, user_id: u64) -> anyhow::Result<()> {
        if let Some((_, existing_mgr)) = self.user_session_mgrs.remove(&public_key) {
            if existing_mgr.lps.is_some() {
                let cleaned_mgr = existing_mgr.into_clean_for_user(F::from_canonical_u64(user_id)).await?;
                self.user_session_mgrs.insert(public_key, cleaned_mgr);
                return Ok(());
            }
        }

        let mgr = self.create_clean_user_session(user_id).await?;

        self.user_session_mgrs.insert(public_key, mgr);
        Ok(())
    }
    async fn create_clean_user_session(
        &self,
        user_id: u64,
    ) -> anyhow::Result<UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>> {
        let rpc_provider = self.st_provider.with_user_id_owned(user_id);
        let lps = PsyLocalProvingSessionStore::new_at(
            rpc_provider,
            F::ZERO,
            F::from_canonical_u64(user_id),
            F::ZERO,
            F::ZERO,
            UPS_SESSION_PROOF_TREE_HEIGHT as usize,
        )
        .into_clean_for_user(F::from_canonical_u64(user_id))
        .await?;
        let circuit_mgr = self.wallet.random_circuit_manager();
        UserProvingSessionManager::<F, PoseidonHash, RpcProvider, C, D>::new(
            lps,
            self.circuit_info.clone(),
            circuit_mgr.ups_circuit_whitelist_root().await?,
        )
        .await
    }
    async fn build_transaction_preview_session(
        &self,
        public_key: QHashOut<F>,
    ) -> anyhow::Result<UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>> {
        let user_id = self
            .resolve_registered_user_id(public_key)
            .await
            .map_err(|e| anyhow::format_err!("User {} not registered. Please register first: {}", public_key, e))?;
        let mut user_session_mgr = self.create_clean_user_session(user_id).await?;
        self.initialize_transaction_session(public_key, &mut user_session_mgr).await?;
        Ok(user_session_mgr)
    }

    async fn initialize_transaction_session(
        &self,
        public_key: QHashOut<F>,
        user_session_mgr: &mut UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
    ) -> anyhow::Result<()> {
        let latest_block_state = user_session_mgr.require_lps()?.get_read_store().get_latest_block_state().await?;
        let global_latest_block_state = self.st_provider.get_coordinator_latest_block_state().await?;

        if latest_block_state.checkpoint_id <= global_latest_block_state.checkpoint_id {
            tracing::info!(
                "block state: realm latest checkpoint {}, coordinator checkpoint {}",
                latest_block_state.checkpoint_id,
                global_latest_block_state.checkpoint_id
            );
        } else {
            tracing::error!(
                "realm latest checkpoint {} is ahead coordinator checkpoint {}",
                latest_block_state.checkpoint_id,
                global_latest_block_state.checkpoint_id
            );
            anyhow::bail!(
                "realm latest checkpoint {} is ahead of coordinator checkpoint {}",
                latest_block_state.checkpoint_id,
                global_latest_block_state.checkpoint_id
            );
        }

        tracing::info!("local proving ups start");
        tracing::info!("user session manager nonce: {}", user_session_mgr.require_lps()?.get_nonce());
        user_session_mgr.prove_ups_start(self.wallet.random_circuit_manager().as_ref()).await?;

        let user_id = user_session_mgr.require_lps()?.get_current_user_id_64();
        let registration_id = get_registration_id_from_user_id(user_id);
        let checkpoint = user_session_mgr.require_lps()?.get_current_start_checkpoint_id_u64();
        tracing::info!(
            "check if user {}: {} is registered at checkpoint {}, registration_id: {}",
            user_id,
            public_key.to_string(),
            checkpoint,
            registration_id
        );
        let registration_leaf_hash = self
            .st_provider
            .with_user_id_owned(user_id)
            .get_user_registration_tree_leaf_hash(checkpoint, registration_id)
            .await?;
        anyhow::ensure!(
            registration_leaf_hash != QHashOut::ZERO,
            "user {}: {} of registration id {} is not registered at checkpoint {}, please check it first",
            user_id,
            public_key.to_string(),
            registration_id,
            checkpoint
        );

        let nonce = user_session_mgr.require_lps()?.get_nonce();
        self.check_user_state(user_id, nonce).await
    }

    /// Build (or reset) a clean step proving session for `public_key`, seeded
    /// entirely from the trace — user id, anchor checkpoint and ups_start
    /// header — with no RPC. Used by the legacy one-shot resume path before
    /// step proving was externalized into explicit
    /// `ProofTreeMeta`/baton/header parameters. Unlike `update_circuit_mgr`, it
    /// neither resolves the user id nor fetches the latest checkpoint from
    /// the chain Seed a fresh prove session from the trace anchor. No RPC
    /// calls here: the manager is initialized entirely from `trace.anchor`
    /// + `ups_start_witness`.
    async fn init_step_proving_session(&self, public_key: QHashOut<F>, trace: &crate::trace::TxTrace) -> anyhow::Result<()> {
        let mgr = UserProvingSessionManager::<F, PoseidonHash, RpcProvider, C, D>::new_from_trace_anchor(
            self.circuit_info.clone(),
            trace.ups_start_witness.ups_header.clone(),
            trace.anchor.checkpoint_leaf.clone(),
            trace.anchor.global_state_roots,
        )
        .await?;
        self.user_session_mgrs.insert(public_key, mgr);
        Ok(())
    }

    pub async fn exec_contract_call(&self, public_key: QHashOut<F>, call_data: ContractCallData) -> anyhow::Result<QHashOut<F>> {
        if call_data.contract_calls.is_empty() {
            anyhow::bail!("No contract calls to execute");
        }

        tracing::info!("exec contract call: {}", serde_json::to_string_pretty(&call_data.contract_calls)?);
        let pk_info = self.wallet.get_public_key_info(&public_key).await?;
        tracing::info!(
            "exec contract call for fingerprint {} (sign data provided: {:?})",
            pk_info.fingerprint,
            call_data.software_defined_call
        );
        let result = self.st_provider.get_latest_block_state().await?;
        tracing::info!("start session on global checkpoint: {}", result.checkpoint_id);
        self.start_session(public_key).await?;
        tracing::info!("prove contract calls");
        self.prove_contract_call(public_key, call_data.contract_calls).await?;
        tracing::info!("sign and submit on global checkpoint: {}", result.checkpoint_id);
        let tx_hash = self.sign_and_submit(public_key, call_data.software_defined_call).await?;
        Ok(tx_hash)
    }

    /// Add an external proof leaf into a user's UPS session proof tree.
    pub async fn add_external_proof(
        &self,
        public_key: QHashOut<F>,
        fingerprint: QHashOut<F>,
        proof: ProofWithPublicInputs<F, C, D>,
        verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<u64> {
        let mut user_session_mgr = self
            .user_session_mgrs
            .get_mut(&public_key)
            .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;

        let leaf_index = user_session_mgr.add_external_proof(fingerprint, proof, verifier_data).await;
        let proof_tree_root = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
        user_session_mgr.require_lps_mut()?.set_proof_tree_root(proof_tree_root);
        Ok(leaf_index)
    }

    /// Like `add_external_proof` but also returns the Merkle siblings for the
    /// injected leaf. Returns (leaf_index, siblings) where each sibling is
    /// [u64; 4].
    pub async fn add_external_proof_with_siblings(
        &self,
        public_key: QHashOut<F>,
        fingerprint: QHashOut<F>,
        proof: ProofWithPublicInputs<F, C, D>,
        verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<(u64, Vec<[u64; 4]>)> {
        use plonky2::field::types::PrimeField64;

        let mut user_session_mgr = self
            .user_session_mgrs
            .get_mut(&public_key)
            .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;

        let leaf_index = user_session_mgr.add_external_proof(fingerprint, proof, verifier_data).await;
        let proof_tree_root = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
        user_session_mgr.require_lps_mut()?.set_proof_tree_root(proof_tree_root);

        let leaf_proof = user_session_mgr.proof_tree_state.get_leaf_merkle_proof(leaf_index).await;
        if leaf_proof.root != proof_tree_root {
            anyhow::bail!(
                "external proof leaf_proof.root mismatch proof_tree_root: leaf={:?} tree={:?}",
                leaf_proof.root,
                proof_tree_root
            );
        }
        tracing::warn!(
            inserted_leaf0 = leaf_proof.value.0.elements[0].to_canonical_u64(),
            inserted_leaf1 = leaf_proof.value.0.elements[1].to_canonical_u64(),
            inserted_leaf2 = leaf_proof.value.0.elements[2].to_canonical_u64(),
            inserted_leaf3 = leaf_proof.value.0.elements[3].to_canonical_u64(),
            root0 = leaf_proof.root.0.elements[0].to_canonical_u64(),
            root1 = leaf_proof.root.0.elements[1].to_canonical_u64(),
            root2 = leaf_proof.root.0.elements[2].to_canonical_u64(),
            root3 = leaf_proof.root.0.elements[3].to_canonical_u64(),
            leaf_index,
            "add_external_proof leaf/root"
        );

        let siblings: Vec<[u64; 4]> = leaf_proof
            .siblings
            .iter()
            .map(|s| {
                let e = s.0.elements;
                [
                    e[0].to_canonical_u64(),
                    e[1].to_canonical_u64(),
                    e[2].to_canonical_u64(),
                    e[3].to_canonical_u64(),
                ]
            })
            .collect();

        Ok((leaf_index, siblings))
    }

    pub async fn start_session(&self, public_key: QHashOut<F>) -> anyhow::Result<()> {
        self.update_circuit_mgr(public_key).await?;
        let mut user_session_mgr = self
            .user_session_mgrs
            .get_mut(&public_key)
            .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;
        self.initialize_transaction_session(public_key, &mut user_session_mgr).await
    }

    pub async fn begin_trace_build(&self, public_key: QHashOut<F>) -> anyhow::Result<TraceBuildSession<'_>> {
        let mut user_session_mgr = self.build_transaction_preview_session(public_key).await?;
        let setup_result = async {
            let ups_start_witness_input = user_session_mgr.get_ups_start_witness().await?;
            let ups_start_registration_proof: Option<psy_crypto::hash::merkle::core::MerkleProofCore<QHashOut<F>>> =
                if user_session_mgr.require_lps()?.is_new_user() {
                    let start_checkpoint_id = user_session_mgr.require_lps()?.get_current_start_checkpoint_id_u64();
                    let user_id = user_session_mgr.require_lps()?.get_current_user_id_64();
                    Some(
                        user_session_mgr
                            .require_lps_mut()?
                            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserRegistrationTreeMerkleProof(
                                QSRMerkleCmdGetUserRegistrationTreeMerkleProof {
                                    checkpoint_id: start_checkpoint_id,
                                    leaf_index: get_registration_id_from_user_id(user_id),
                                },
                            ))
                            .await?,
                    )
                } else {
                    None
                };
            anyhow::Ok((ups_start_witness_input, ups_start_registration_proof))
        }
        .await;
        let (ups_start_witness_input, ups_start_registration_proof) = setup_result?;
        Ok(TraceBuildSession {
            wallet_session: self,
            public_key,
            user_session_mgr,
            trace_arena: TraceArenaBuilder::new(),
            ups_start_witness_input,
            ups_start_registration_proof,
        })
    }

    pub async fn prove_contract_call(&self, public_key: QHashOut<F>, contract_call_args: Vec<ContractCallArgs>) -> anyhow::Result<()> {
        let mut user_session_mgr = self
            .user_session_mgrs
            .get_mut(&public_key)
            .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;
        let total_contract_calls = contract_call_args.len();
        for (call_index, contract_call_arg) in contract_call_args.into_iter().enumerate() {
            tracing::info!(
                call_index,
                total_contract_calls,
                "prove contract call at contract {}, method {}",
                contract_call_arg.contract_id,
                contract_call_arg.method_name
            );
            let contract_code = user_session_mgr
                .require_lps_mut()?
                .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition {
                    contract_id: contract_call_arg.contract_id,
                })
                .await?;
            prove_func(
                contract_code,
                self.wallet.random_circuit_manager().as_ref(),
                &mut *user_session_mgr,
                contract_call_arg.contract_id,
                &contract_call_arg.method_name,
                contract_call_arg.inputs.iter().map(|x| F::from_noncanonical_u64(*x)).collect(),
            )
            .await
            .map_err(|err| {
                anyhow::anyhow!(
                    "prove contract call failed at call_index={} total_contract_calls={} contract_id={} method={} input_count={}: {:#}",
                    call_index,
                    total_contract_calls,
                    contract_call_arg.contract_id,
                    contract_call_arg.method_name,
                    contract_call_arg.inputs.len(),
                    err
                )
            })?;
        }
        user_session_mgr.prove_burn_fee(self.wallet.random_circuit_manager().as_ref()).await?;

        let user_id = user_session_mgr.require_lps()?.get_current_user_id_64();
        let nonce = user_session_mgr.require_lps()?.get_nonce();
        self.check_user_state(user_id, nonce).await?;

        Ok(())
    }

    fn qhash_to_u64x4(value: QHashOut<F>) -> [u64; 4] {
        [
            value.0.elements[0].to_canonical_u64(),
            value.0.elements[1].to_canonical_u64(),
            value.0.elements[2].to_canonical_u64(),
            value.0.elements[3].to_canonical_u64(),
        ]
    }

    fn qhash_to_internal_u32x8(value: QHashOut<F>) -> [u32; 8] {
        [
            (value.0.elements[0].to_canonical_u64() & 0xffff_ffff) as u32,
            (value.0.elements[0].to_canonical_u64() >> 32) as u32,
            (value.0.elements[1].to_canonical_u64() & 0xffff_ffff) as u32,
            (value.0.elements[1].to_canonical_u64() >> 32) as u32,
            (value.0.elements[2].to_canonical_u64() & 0xffff_ffff) as u32,
            (value.0.elements[2].to_canonical_u64() >> 32) as u32,
            (value.0.elements[3].to_canonical_u64() & 0xffff_ffff) as u32,
            (value.0.elements[3].to_canonical_u64() >> 32) as u32,
        ]
    }

    fn build_private_claim_inputs(
        nullifier: [u64; 4],
        owner: [u64; 4],
        amount: u64,
        user_tree_root: [u64; 4],
        checkpoint_id: u64,
        note_root_slot: u64,
        random0: u64,
        random1: u64,
        leaf_proof: &psy_crypto::hash::merkle::core::MerkleProofCore<QHashOut<F>>,
        leaf_index: u64,
    ) -> Vec<u64> {
        let mut inputs = Vec::new();
        inputs.extend_from_slice(&nullifier);
        inputs.extend_from_slice(&owner);
        inputs.push(amount);
        inputs.extend_from_slice(&user_tree_root);
        inputs.push(checkpoint_id);
        inputs.push(note_root_slot);
        inputs.push(random0);
        inputs.push(random1);
        for sibling in &leaf_proof.siblings {
            inputs.extend_from_slice(&Self::qhash_to_u64x4(*sibling));
        }
        inputs.push(leaf_index);
        inputs
    }

    fn build_shield_deposit_claim_inputs(
        nullifier_hash: QHashOut<F>,
        shield_address: QHashOut<F>,
        token_address: [u32; 8],
        amount: [u32; 8],
        source_chain_index: u32,
        deposit_root: QHashOut<F>,
        note_commitment: QHashOut<F>,
        deposit_index: u64,
        r0: u64,
        r1: u64,
        leaf_proof: &psy_crypto::hash::merkle::core::MerkleProofCore<QHashOut<F>>,
        proof_index: u64,
    ) -> Vec<u64> {
        let mut inputs = Vec::with_capacity(100);
        inputs.extend_from_slice(&Self::qhash_to_u64x4(nullifier_hash));
        inputs.extend_from_slice(&Self::qhash_to_u64x4(shield_address));
        inputs.extend(token_address.iter().map(|&v| v as u64));
        inputs.extend(amount.iter().map(|&v| v as u64));
        inputs.push(source_chain_index as u64);
        inputs.extend(Self::qhash_to_internal_u32x8(deposit_root).iter().map(|&v| v as u64));
        inputs.extend_from_slice(&Self::qhash_to_u64x4(note_commitment));
        inputs.push(deposit_index);
        inputs.push(r0);
        inputs.push(r1);
        for sibling in &leaf_proof.siblings {
            inputs.extend_from_slice(&Self::qhash_to_u64x4(*sibling));
        }
        inputs.push(proof_index);
        inputs
    }

    async fn prove_claim_batch_call(
        &self,
        user_session_mgr: &mut UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
        item_index: usize,
        total_items: usize,
        contract_id: u64,
        method_name: &str,
        inputs: Vec<u64>,
    ) -> anyhow::Result<()> {
        let proof_tree_root = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
        user_session_mgr.require_lps_mut()?.set_proof_tree_root(proof_tree_root);
        let contract_code = user_session_mgr
            .require_lps_mut()?
            .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition { contract_id })
            .await?;
        prove_func(
            contract_code,
            self.wallet.random_circuit_manager().as_ref(),
            user_session_mgr,
            contract_id,
            method_name,
            inputs.iter().map(|x| F::from_noncanonical_u64(*x)).collect(),
        )
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "prove claim batch failed at item_index={} total_items={} contract_id={} method={} input_count={}: {:#}",
                item_index,
                total_items,
                contract_id,
                method_name,
                inputs.len(),
                err
            )
        })
    }

    /// Claim public calls, private transfers, and shield deposits in one user
    /// transaction. Proof-backed claims must add their external proof and prove
    /// their contract call immediately, because every proof changes the proof
    /// tree root used by the next call.
    pub async fn claim_batch(&self, public_key: QHashOut<F>, claims: Vec<ClaimBatchItem>) -> anyhow::Result<QHashOut<F>> {
        if claims.is_empty() {
            anyhow::bail!("No claims to execute");
        }

        for claim_item in &claims {
            if let ClaimBatchItem::PrivateTransfer { contract_id, claim } = claim_item {
                ensure_private_transfer_contract_matches(*contract_id, claim.token_contract_id)?;
            }
        }

        let total_items = claims.len();
        self.start_session(public_key).await?;

        {
            let mut user_session_mgr = self
                .user_session_mgrs
                .get_mut(&public_key)
                .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;

            for (item_index, claim_item) in claims.into_iter().enumerate() {
                match claim_item {
                    ClaimBatchItem::Public(call) => {
                        self.prove_claim_batch_call(
                            &mut *user_session_mgr,
                            item_index,
                            total_items,
                            call.contract_id,
                            &call.method_name,
                            call.inputs,
                        )
                        .await?;
                        let proof_tree_root = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
                        user_session_mgr.require_lps_mut()?.set_proof_tree_root(proof_tree_root);
                    }
                    ClaimBatchItem::PrivateTransfer { contract_id, claim } => {
                        let proof_index = user_session_mgr
                            .add_external_proof(
                                claim.note_proof_fingerprint,
                                claim.note_proof,
                                claim.note_verifier_data.to_verifier_data::<C, D>(),
                            )
                            .await;
                        let proof_tree_root = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
                        user_session_mgr.require_lps_mut()?.set_proof_tree_root(proof_tree_root);
                        let leaf_proof = user_session_mgr.proof_tree_state.get_leaf_merkle_proof(proof_index).await;
                        if leaf_proof.root != proof_tree_root {
                            anyhow::bail!(
                                "private_transfer leaf_proof.root mismatch proof_tree_root: leaf={:?} tree={:?}",
                                leaf_proof.root,
                                proof_tree_root
                            );
                        }
                        let inputs = Self::build_private_claim_inputs(
                            claim.nullifier,
                            claim.owner,
                            claim.amount,
                            claim.user_tree_root,
                            claim.checkpoint_id,
                            claim.note_root_slot,
                            claim.random0,
                            claim.random1,
                            &leaf_proof,
                            proof_index,
                        );
                        tracing::info!(
                            item_index,
                            proof_index,
                            input_count = inputs.len(),
                            "prepared private_claim inside claim batch"
                        );
                        self.prove_claim_batch_call(&mut *user_session_mgr, item_index, total_items, contract_id, "private_claim", inputs)
                            .await?;
                    }
                    ClaimBatchItem::ShieldDeposit(claim) => {
                        let contract_id = claim.contract_id;
                        let proof_index = user_session_mgr
                            .add_external_proof(claim.proof_fingerprint, claim.proof, claim.verifier_data.to_verifier_data::<C, D>())
                            .await;
                        let proof_tree_root = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
                        user_session_mgr.require_lps_mut()?.set_proof_tree_root(proof_tree_root);
                        let leaf_proof = user_session_mgr.proof_tree_state.get_leaf_merkle_proof(proof_index).await;
                        if leaf_proof.root != proof_tree_root {
                            anyhow::bail!(
                                "leaf_proof.root mismatch proof_tree_root: leaf={:?} tree={:?}",
                                leaf_proof.root,
                                proof_tree_root
                            );
                        }
                        let inputs = Self::build_shield_deposit_claim_inputs(
                            claim.nullifier_hash,
                            claim.shield_address,
                            claim.token_address,
                            claim.amount,
                            claim.source_chain_index,
                            claim.deposit_root,
                            claim.note_commitment,
                            claim.deposit_index,
                            claim.r0,
                            claim.r1,
                            &leaf_proof,
                            proof_index,
                        );
                        self.prove_claim_batch_call(&mut *user_session_mgr, item_index, total_items, contract_id, "claim_deposit", inputs)
                            .await?;
                    }
                }
            }

            user_session_mgr.prove_burn_fee(self.wallet.random_circuit_manager().as_ref()).await?;

            let user_id = user_session_mgr.require_lps()?.get_current_user_id_64();
            let nonce = user_session_mgr.require_lps()?.get_nonce();
            self.check_user_state(user_id, nonce).await?;
        }

        self.sign_and_submit(public_key, DPNSoftwareDefinedCallData::default()).await
    }

    pub async fn sign_inner(
        &self,
        public_key: QHashOut<F>,
        software_defined_call: DPNSoftwareDefinedCallData,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let pk_info = self.wallet.get_public_key_info(&public_key).await?;
        let mut user_session_mgr = self
            .user_session_mgrs
            .get_mut(&public_key)
            .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;

        tracing::info!(
            "sign and submit for fingerprint {} (software defined call provided: {:?})",
            pk_info.fingerprint,
            software_defined_call
        );
        let mut sign_context = SignContext::new(pk_info.fingerprint);

        {
            if self.wallet.has_psy_software_defined_circuit(&pk_info.fingerprint) {
                sign_context = self
                    .build_psy_software_defined_context(&software_defined_call, pk_info.fingerprint, &mut user_session_mgr, sign_context)
                    .await?;
            } else if self.wallet.has_plonky2_software_defined_circuit(&pk_info.fingerprint) {
                sign_context = self
                    .build_plonky2_software_defined_context(&software_defined_call, pk_info.fingerprint, &mut user_session_mgr)
                    .await?;
            } else if self.wallet.has_sd_key_circuit(&pk_info.fingerprint) {
                sign_context = self
                    .build_sd_key_context(&software_defined_call, pk_info.fingerprint, &mut user_session_mgr)
                    .await?;
            };
        }

        let nonce = user_session_mgr.require_lps()?.get_nonce();
        let sighash = user_session_mgr.get_sighash(PSY_NETWORK_MAGIC, nonce);

        tracing::info!("zk sign for signhash: {}, nonce: {}", sighash.to_string(), nonce);
        let signature_result = self.wallet.sign_with_public_key(&public_key, &sign_context, sighash).await?;
        let SignatureResult {
            proof: signature_proof,
            circuit_info,
        } = signature_result;

        user_session_mgr
            .proof_tree_state
            .finalize_tree(self.wallet.random_circuit_manager().as_ref())
            .await?;

        let public_key_param = pk_info.public_key_param;

        let SignatureCircuitInfo {
            circuit_fingerprint,
            verifier_config: circuit_verifier_config,
        } = circuit_info;

        tracing::info!(
            "prove end cap with network magic {:x}, nonce {}, fingerprint {}, public key param {}, signature proof {:?}",
            PSY_NETWORK_MAGIC,
            nonce,
            circuit_fingerprint,
            public_key_param,
            signature_proof.public_inputs
        );
        let slots_modified = user_session_mgr.require_lps()?.get_total_slots_modified();
        let end_cap_proof = user_session_mgr
            .prove_end_cap(
                self.wallet.random_circuit_manager().as_ref(),
                PSY_NETWORK_MAGIC,
                nonce,
                slots_modified,
                circuit_fingerprint,
                public_key_param,
                signature_proof,
                circuit_verifier_config,
            )
            .await?;
        Ok(end_cap_proof)
    }

    pub async fn sign(
        &self,
        public_key: QHashOut<F>,
        software_defined_call: DPNSoftwareDefinedCallData,
    ) -> anyhow::Result<(SubmitUserEndCapNonProofInput<F>, ProofWithPublicInputs<F, C, D>)> {
        let end_cap_proof = self.sign_inner(public_key, software_defined_call).await?;

        let mut user_session_mgr = self
            .user_session_mgrs
            .get_mut(&public_key)
            .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;

        let user_ec_input = user_session_mgr.get_api_input().await?;
        tracing::info!("get user ec input: {}", serde_json::to_string_pretty(&user_ec_input)?);

        let end_user_leaf_hash = user_ec_input.core.state_transition.end_user_leaf_hash;
        let new_user_leaf = user_ec_input.core.new_user_leaf;
        if end_user_leaf_hash != new_user_leaf.qfhash::<PsyHasher>() {
            anyhow::bail!("end user leaf hash not match");
        }

        let user_id = user_session_mgr.require_lps()?.get_current_user_id_64();
        let nonce = user_session_mgr.require_lps()?.get_nonce();
        self.check_user_state(user_id, nonce).await?;

        Ok((user_ec_input, end_cap_proof))
    }

    pub async fn sign_imt(
        &self,
        public_key: QHashOut<F>,
        software_defined_call: DPNSoftwareDefinedCallData,
    ) -> anyhow::Result<(SubmitUserEndCapNonProofInput<F>, ProofWithPublicInputs<F, C, D>)> {
        self.sign(public_key, software_defined_call).await
    }

    pub async fn sign_and_submit(&self, public_key: QHashOut<F>, software_defined_call: DPNSoftwareDefinedCallData) -> anyhow::Result<QHashOut<F>> {
        let (user_ec_input, end_cap_proof) = self.sign(public_key, software_defined_call).await?;
        let user_id = user_ec_input.core.new_user_leaf.user_id.to_noncanonical_u64();
        let nonce = user_ec_input.core.new_user_leaf.nonce;
        self.check_submit_anchor(user_id, user_ec_input.core.state_transition.start_user_leaf_hash)
            .await?;
        self.check_user_state(user_id, nonce).await?;
        let req = QSubmitEndCapRPCRequest {
            user_ec_input,
            proof: bincode::serialize(&end_cap_proof)?,
        };

        let end_user_leaf_hash = req.user_ec_input.core.state_transition.end_user_leaf_hash;
        let contract_slot_updates = req
            .user_ec_input
            .get_slot_updates()?
            .into_iter()
            .flat_map(|contract| {
                contract.slot_updates.into_iter().map(move |update| EndCapContractSlotUpdate {
                    contract_id: contract.contract_id,
                    slot: update.slot,
                    old_value: update.old_value.to_canonical_u64(),
                    new_value: update.new_value.to_canonical_u64(),
                })
            })
            .collect();

        self.st_provider
            .with_user_id_owned(user_id)
            .submit_end_cap_proof::<F>(req)
            .await
            .map_err(|source| EndCapSubmissionError {
                end_user_leaf_hash,
                contract_slot_updates,
                source,
            })?;

        Ok(end_user_leaf_hash)
    }

    async fn ensure_trace_sign_circuit_registered(
        &self,
        fingerprint: QHashOut<F>,
        source: &crate::trace::TraceSignCircuitSource,
    ) -> anyhow::Result<()> {
        match source {
            crate::trace::TraceSignCircuitSource::ZkBuiltin
            | crate::trace::TraceSignCircuitSource::SecpBuiltin
            | crate::trace::TraceSignCircuitSource::EthPersonalSecpBuiltin => Ok(()),
            crate::trace::TraceSignCircuitSource::PsySoftwareDefined {
                circuit_def,
                force_four_align,
            } => {
                if !self.wallet.has_psy_software_defined_circuit(&fingerprint) {
                    let fn_def: DPNFunctionCircuitDefinition = bincode::deserialize(circuit_def)?;
                    let registered = self.wallet.register_psy_software_defined_circuit(fn_def, *force_four_align).await?;
                    anyhow::ensure!(
                        registered == fingerprint,
                        "PSY software-defined trace fingerprint mismatch: trace={} rebuilt={}",
                        fingerprint,
                        registered
                    );
                }
                Ok(())
            }
            crate::trace::TraceSignCircuitSource::Plonky2SoftwareDefined {
                contract_state_tree_height,
                input_len,
            } => {
                if !self.wallet.has_plonky2_software_defined_circuit(&fingerprint) {
                    let registered = self
                        .wallet
                        .register_plonky2_software_defined_circuit(*contract_state_tree_height, *input_len)
                        .await?;
                    anyhow::ensure!(
                        registered == fingerprint,
                        "Plonky2 software-defined trace fingerprint mismatch: trace={} rebuilt={}",
                        fingerprint,
                        registered
                    );
                }
                Ok(())
            }
            crate::trace::TraceSignCircuitSource::SdKey {
                allowed_contract_ids,
                allowed_method_ids,
                expected_tx_count,
            } => {
                let registered = self
                    .wallet
                    .register_allow_method_sd_key_circuit(allowed_contract_ids, allowed_method_ids, *expected_tx_count)
                    .await?;
                anyhow::ensure!(
                    registered == fingerprint,
                    "SD key trace fingerprint mismatch: trace={} rebuilt={}",
                    fingerprint,
                    registered
                );
                Ok(())
            }
        }
    }

    async fn build_psy_software_defined_context(
        &self,
        call_data: &DPNSoftwareDefinedCallData,
        fingerprint: QHashOut<F>,
        user_session_mgr: &mut UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
        sign_context: SignContext,
    ) -> anyhow::Result<SignContext> {
        let sdc = self
            .wallet
            .get_psy_software_defined_circuit(&fingerprint)
            .ok_or_else(|| anyhow::format_err!("PSY software defined circuit `{}` not found", fingerprint))?;

        let cfc_call_inputs = call_data.inputs.iter().map(|x| F::from_noncanonical_u64(*x)).collect::<Vec<_>>();

        if !sdc.fn_def.is_view_function() {
            anyhow::bail!("software-defined signing function must be view-only");
        }
        let cfc_proof_input = user_session_mgr
            .exec_deferred_contract_call_local(F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64), &sdc.fn_def, cfc_call_inputs)
            .await?;

        let signature_input = DPNSoftwareDefinedSignatureInput { cfc_input: cfc_proof_input };

        let current_header = user_session_mgr.get_current_ups_header();
        let current_checkpoint_id = current_header.session_start_context.checkpoint_id.to_canonical_u64();
        let user_id = current_header.session_start_context.start_session_user_leaf.user_id.to_canonical_u64();
        let start_contract_state_tree_root = current_header.current_state.user_leaf.user_state_tree_root;
        let checkpoint_tree_root = current_header.session_start_context.checkpoint_tree_root;

        Ok(sign_context.with_psy_signature_input(
            signature_input,
            current_checkpoint_id,
            user_id,
            start_contract_state_tree_root,
            checkpoint_tree_root,
        ))
    }

    async fn build_plonky2_software_defined_context(
        &self,
        call_data: &DPNSoftwareDefinedCallData,
        fingerprint: QHashOut<F>,
        user_session_mgr: &mut UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
    ) -> anyhow::Result<SignContext> {
        let current_header = user_session_mgr.get_current_ups_header();
        let user_id = current_header.session_start_context.start_session_user_leaf.user_id.to_canonical_u64();
        let checkpoint_id = current_header.session_start_context.checkpoint_id.to_canonical_u64();
        let user_leaf = current_header.session_start_context.start_session_user_leaf.clone();
        let checkpoint_tree_root = current_header.session_start_context.checkpoint_tree_root;

        let transaction_record = user_session_mgr.require_lps()?.last_transaction_record();

        let circuit_inputs = call_data.inputs.iter().map(|x| F::from_noncanonical_u64(*x)).collect::<Vec<_>>();

        let user_contract_state = UserContractState::new(
            checkpoint_tree_root,
            user_leaf,
            transaction_record.user_contract_tree_update_proof.new_value,
            F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64),
            F::from_canonical_u64(checkpoint_id),
        );

        let state_reader: StateReader<F, 2, RpcProvider> = StateReader::new(
            user_contract_state,
            user_session_mgr.require_lps()?.get_cmd_store().clone(),
            user_session_mgr.require_lps()?.get_state_tree_store().clone(),
        )
        .await;

        let plonky2_input = Plonky2SoftwareDefinedSignatureInput {
            state_reader_results: state_reader.to_results(),
            circuit_inputs,
        };

        Ok(SignContext::new(fingerprint)
            .with_contract_id(Some(DEFAULT_CALLER_CONTRACT_ID_U64))
            .with_sign_inputs(call_data.inputs.clone())
            .with_plonky2_signature_input(
                plonky2_input,
                checkpoint_id,
                user_id,
                transaction_record.user_contract_tree_update_proof.old_value,
                checkpoint_tree_root,
            ))
    }

    async fn build_sd_key_context(
        &self,
        call_data: &DPNSoftwareDefinedCallData,
        fingerprint: QHashOut<F>,
        user_session_mgr: &mut UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
    ) -> anyhow::Result<SignContext> {
        let sd_key = self
            .wallet
            .get_sd_key_circuit(&fingerprint)
            .ok_or_else(|| anyhow::format_err!("SD key circuit `{}` not found", fingerprint))?;
        let config = sd_key.config.clone();
        drop(sd_key);

        let transaction_infos = user_session_mgr.sd_key_transaction_infos();
        let expected_slots = config.num_introspectable_transactions as usize;
        if transaction_infos.len() != expected_slots {
            anyhow::bail!(
                "SD key circuit expects {} introspectable txs, but session has {} txs",
                expected_slots,
                transaction_infos.len()
            );
        }

        let current_header = user_session_mgr.get_current_ups_header();
        let checkpoint_id = current_header.session_start_context.checkpoint_id.to_canonical_u64();
        let user_id = current_header.session_start_context.start_session_user_leaf.user_id.to_canonical_u64();
        let circuit_inputs = call_data.inputs.iter().map(|x| F::from_noncanonical_u64(*x)).collect::<Vec<_>>();
        let tx_stack_hash = user_session_mgr.current_tx_hash_stack();
        let tx_count = user_session_mgr.current_tx_count();
        let start_contract_state_tree_root = current_header.current_state.user_leaf.user_state_tree_root;
        let checkpoint_tree_root = current_header.session_start_context.checkpoint_tree_root;

        let signature_input = SDKeyCircuitWitnessInput {
            circuit_inputs,
            transaction_infos,
            tx_stack_hash,
            tx_count,
            state_reader_results: None,
            secp256k1_slots: vec![],
            checkpoint_id: F::from_canonical_u64(checkpoint_id),
            user_id: F::from_canonical_u64(user_id),
        };

        Ok(SignContext::new(fingerprint)
            .with_sign_inputs(call_data.inputs.clone())
            .with_sd_key_signature_input(
                signature_input,
                checkpoint_id,
                user_id,
                start_contract_state_tree_root,
                checkpoint_tree_root,
            ))
    }

    async fn build_sd_key_context_step(
        &self,
        call_data: &DPNSoftwareDefinedCallData,
        fingerprint: QHashOut<F>,
        user_session_mgr: &UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
        trace_steps: &[crate::trace::TraceStep],
        current_header: &UserProvingSessionHeader<F>,
    ) -> anyhow::Result<SignContext> {
        let _ = user_session_mgr;
        self.build_sd_key_context_from_trace(call_data, fingerprint, trace_steps, current_header)
            .await
    }

    async fn build_sd_key_context_from_trace(
        &self,
        call_data: &DPNSoftwareDefinedCallData,
        fingerprint: QHashOut<F>,
        trace_steps: &[crate::trace::TraceStep],
        current_header: &UserProvingSessionHeader<F>,
    ) -> anyhow::Result<SignContext> {
        let sd_key = self
            .wallet
            .get_sd_key_circuit(&fingerprint)
            .ok_or_else(|| anyhow::format_err!("SD key circuit `{}` not found", fingerprint))?;
        let config = sd_key.config.clone();
        drop(sd_key);

        let transaction_infos = trace_steps
            .iter()
            .filter_map(crate::trace::TraceStep::as_cfc)
            .map(|cfc| {
                psy_client_data::dpn::sd_key::SDKeyTransactionInfo::from(cfc.cfc_witness.tx_input_ctx.transaction_call_start_ctx.call_data.clone())
            })
            .collect::<Vec<_>>();
        let expected_slots = config.num_introspectable_transactions as usize;
        if transaction_infos.len() != expected_slots {
            anyhow::bail!(
                "SD key circuit expects {} introspectable txs, but trace has {} txs",
                expected_slots,
                transaction_infos.len()
            );
        }

        let checkpoint_id = current_header.session_start_context.checkpoint_id.to_canonical_u64();
        let user_id = current_header.session_start_context.start_session_user_leaf.user_id.to_canonical_u64();
        let circuit_inputs = call_data.inputs.iter().map(|x| F::from_noncanonical_u64(*x)).collect::<Vec<_>>();
        let checkpoint_tree_root = current_header.session_start_context.checkpoint_tree_root;
        let signature_input = SDKeyCircuitWitnessInput {
            circuit_inputs,
            transaction_infos,
            tx_stack_hash: current_header.current_state.tx_hash_stack,
            tx_count: current_header.current_state.tx_count,
            state_reader_results: None,
            secp256k1_slots: vec![],
            checkpoint_id: F::from_canonical_u64(checkpoint_id),
            user_id: F::from_canonical_u64(user_id),
        };

        Ok(SignContext::new(fingerprint)
            .with_sign_inputs(call_data.inputs.clone())
            .with_sd_key_signature_input(
                signature_input,
                checkpoint_id,
                user_id,
                current_header.current_state.user_leaf.user_state_tree_root,
                checkpoint_tree_root,
            ))
    }

    pub fn get_deploy_contract_cmd(
        &self,
        deployer: QHashOut<F>,
        circuit_defs: Vec<DPNFunctionCircuitDefinition>,
    ) -> anyhow::Result<QBCDeployContract<F>> {
        let contract_state_tree_height = derive_state_tree_height(&circuit_defs);

        let (_result_circuits, deploy_cmd) =
            gen_contract_deploy_and_circuits_for_functions::<C, D>(deployer, contract_state_tree_height as u8, &circuit_defs)?;
        Ok(deploy_cmd)
    }

    pub async fn deploy_contract(&self, deployer: QHashOut<F>, circuit_defs: Vec<DPNFunctionCircuitDefinition>) -> anyhow::Result<String> {
        let deploy_cmd = self.get_deploy_contract_cmd(deployer, circuit_defs)?;

        let contract_uuid = self
            .st_provider
            .deploy_contract::<F>(QDeployContractRPCRequest { deploy_contract: deploy_cmd })
            .await?;
        Ok(contract_uuid)
    }

    // pub async fn get_claim_rewards_call_args(&self, mut job_infos: Vec<JobInfo>)
    // -> anyhow::Result<Vec<ContractCallArgs>> {     job_infos.
    // retain(|job_info| job_info.job_id.circuit_type.is_guta_job());

    //     if job_infos.is_empty() {
    //         tracing::info!("No valid GUTA jobs found after filtering");
    //         return Ok(Vec::new());
    //     }

    //     let mut checkpoint_jobs: HashMap<u64,
    // Vec<VariableHeightRewardMerkleProof>> = HashMap::new();

    //     match self.st_provider.get_job_proofs(job_infos).await {
    //         Ok(results) => {
    //             for (root_job_id, job_proof) in results {
    //                 let actual_checkpoint_id = root_job_id.goal_id;
    //                 checkpoint_jobs
    //                     .entry(actual_checkpoint_id)
    //                     .or_insert_with(Vec::new)
    //
    // .push(job_proof.pad_to_height(GUTA_REWARDS_TREE_MAX_HEIGHT));
    // }         }
    //         Err(e) => {
    //             tracing::warn!("Failed to get job proofs: {}", e);
    //         }
    //     }

    //     if checkpoint_jobs.is_empty() {
    //         tracing::info!("No valid checkpoints with rewards to claim");
    //         return Ok(Vec::new());
    //     }

    //     let mut sorted_checkpoints: Vec<_> =
    // checkpoint_jobs.keys().copied().collect();     sorted_checkpoints.sort();

    //     let mut all_proofs_with_checkpoints = Vec::new();

    //     for &checkpoint_id in &sorted_checkpoints {
    //         let proofs = checkpoint_jobs.get(&checkpoint_id).unwrap();

    //         let checkpoint_leaf =
    // self.st_provider.get_checkpoint_leaf_data(checkpoint_id).await?;
    //         let fees_collected =
    // checkpoint_leaf.stats.guta_fees_collected.to_canonical_u64();         let
    // gutas_completed =
    // checkpoint_leaf.stats.pm_jobs_completed.gutas_completed.to_canonical_u64();

    //         let proposed_reward = if gutas_completed > 0 { fees_collected /
    // gutas_completed } else { 0u64 };

    //         if proposed_reward == 0 {
    //             tracing::warn!(
    //                 "Skipping checkpoint {} due to zero reward
    // (fees_collected={}, gutas_completed={})",                 checkpoint_id,
    //                 fees_collected,
    //                 gutas_completed
    //             );
    //             continue;
    //         }

    //         tracing::info!("Checkpoint {} - Reward: {}, Jobs: {}", checkpoint_id,
    // proposed_reward, proofs.len());         for proof in proofs {
    //             all_proofs_with_checkpoints.push(ProofWithCheckpoint {
    //                 checkpoint_id,
    //                 proof: proof.clone(),
    //                 proposed_reward,
    //             });
    //         }
    //     }

    //     if all_proofs_with_checkpoints.is_empty() {
    //         tracing::info!("No checkpoints with valid rewards to claim");
    //         return Ok(Vec::new());
    //     }

    //     let mut all_contract_calls =
    // build_claim_calls_for_multi_checkpoints(&all_proofs_with_checkpoints).await;

    //     if all_contract_calls.is_empty() {
    //         tracing::info!("No checkpoints with valid rewards to claim");
    //         return Ok(Vec::new());
    //     }

    //     let last_checkpoint =
    // all_proofs_with_checkpoints.last().unwrap().checkpoint_id;

    //     all_contract_calls.push(ContractCallArgs {
    //         contract_id: MINING_REWARDS_CONTRACT_ID as u64,
    //         method_name: "end_session".to_string(),
    //         inputs: vec![last_checkpoint],
    //     });

    //     all_contract_calls.push(ContractCallArgs {
    //         contract_id: TOKEN_CONTRACT_ID as u64,
    //         method_name: "simple_claim_pow_rewards".to_string(),
    //         inputs: vec![last_checkpoint],
    //     });

    //     if all_contract_calls.is_empty() {
    //         tracing::info!("No rewards to claim");
    //         return Ok(Vec::new());
    //     }

    //     tracing::info!("Executing {} contract calls in single transaction",
    // all_contract_calls.len());     Ok(all_contract_calls)
    // }

    // pub async fn claim_rewards(&self, user_pk_hash: QHashOut<F>, job_infos:
    // Vec<JobInfo>) -> anyhow::Result<()> {     let contract_call_args =
    // self.get_claim_rewards_call_args(job_infos).await?;
    //     self.exec_contract_call(user_pk_hash,
    // ContractCallData::new(contract_call_args)).await?;     Ok(())
    // }

    pub async fn get_zk_public_key(&self, private_key: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        self.wallet.get_zk_pk_info(private_key).await
    }

    pub async fn get_secp_public_key(&self, private_key: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        self.wallet.get_secp_pk_info(private_key).await
    }

    pub async fn get_random_keypair(&self) -> anyhow::Result<WalletKeyPair> {
        let private_key = QHashOut::<F>::rand();
        let pk_info = self.get_zk_public_key(private_key).await?;
        Ok(WalletKeyPair {
            private_key,
            public_key: pk_info,
        })
    }

    pub async fn call_view(&self, public_key: QHashOut<F>, call_data: ViewCallData) -> anyhow::Result<crate::trace::ViewCallResult> {
        anyhow::ensure!(!call_data.contract_calls.is_empty(), "No contract calls to execute");

        let user_id = self
            .resolve_registered_user_id(public_key)
            .await
            .map_err(|e| anyhow::format_err!("User {} not registered. Please register first: {}", public_key, e))?;
        let mut view_session = self.create_clean_user_session(user_id).await?;
        let checkpoint_id = view_session.require_lps()?.get_current_start_checkpoint_id_u64();
        let circuit_mgr = self.wallet.random_circuit_manager();

        let mut contract_calls = Vec::with_capacity(call_data.contract_calls.len());
        let mut storage_reads = Vec::new();
        for contract_call in call_data.contract_calls {
            let contract_code = view_session
                .require_lps_mut()?
                .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition {
                    contract_id: contract_call.contract_id,
                })
                .await?;
            let (_, definition) = circuit_mgr
                .resolve_contract_function_by_method_name(
                    contract_call.contract_id,
                    &contract_code,
                    contract_call.method_name.clone(),
                )
                .await?;
            ensure_view_definition(contract_call.contract_id, &contract_call.method_name, &definition)?;

            let inputs = contract_call
                .inputs
                .iter()
                .map(|input| F::from_noncanonical_u64(*input))
                .collect::<Vec<_>>();
            let witness = view_session
                .exec_contract_call(F::from_canonical_u64(contract_call.contract_id), &definition, inputs)
                .await?;
            let user_contract_update = &view_session.require_lps()?.last_transaction_record().user_contract_tree_update_proof;
            ensure_view_execution_effects(
                contract_call.contract_id,
                &contract_call.method_name,
                &witness,
                user_contract_update,
            )?;

            let storage = crate::trace::TxStorageData::from_call_witnesses(
                user_id,
                contract_call.contract_id,
                &witness.cmd_witnesses,
            );
            storage_reads.extend(storage.reads);
            contract_calls.push(crate::trace::ContractCallResultArgs {
                contract_id: contract_call.contract_id,
                method_name: contract_call.method_name,
                inputs: contract_call.inputs,
                outputs: witness.outputs.iter().map(|output| output.to_canonical_u64()).collect(),
            });
        }

        Ok(crate::trace::ViewCallResult {
            checkpoint_id,
            contract_calls,
            storage_reads,
        })
    }
    pub async fn generate_tx_trace(&self, public_key: QHashOut<F>, call_data: ContractCallData) -> anyhow::Result<crate::trace::TxTrace> {
        self.generate_tx_trace_with_opts(public_key, call_data).await
    }

    pub async fn generate_tx_trace_with_opts(&self, public_key: QHashOut<F>, call_data: ContractCallData) -> anyhow::Result<crate::trace::TxTrace> {
        let builder = self.begin_trace_build(public_key).await?;
        builder.generate_tx_trace_with_opts(call_data).await
    }

    pub async fn simulate_contract_call(
        &self,
        public_key: QHashOut<F>,
        call_data: ContractCallData,
    ) -> anyhow::Result<crate::trace::SimulatedTxJson> {
        self.simulate_contract_call_with_opts(public_key, call_data).await
    }

    pub async fn simulate_contract_call_with_opts(
        &self,
        public_key: QHashOut<F>,
        call_data: ContractCallData,
    ) -> anyhow::Result<crate::trace::SimulatedTxJson> {
        let builder = self.begin_trace_build(public_key).await?;
        builder.simulate_contract_call_with_opts(call_data).await
    }

    async fn push_external_proof_step(
        user_session_mgr: &mut UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
        trace_arena: &mut TraceArenaBuilder,
        fingerprint: QHashOut<F>,
        proof: ProofWithPublicInputs<F, C, D>,
        verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<(u64, MerkleProofCore<QHashOut<F>>)> {
        use crate::trace::{ExternalProofStep, TraceStep};

        let proof_tree_start_root = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
        let proof_bytes = bincode::serialize(&proof)?;
        let verifier_data_alt = AltVerifierOnlyCircuitData::from(&verifier_data);
        let leaf_index = user_session_mgr.add_external_proof(fingerprint, proof, verifier_data).await;
        let proof_tree_end_root = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
        user_session_mgr.require_lps_mut()?.set_proof_tree_root(proof_tree_end_root);
        let leaf_proof = user_session_mgr.proof_tree_state.get_leaf_merkle_proof(leaf_index).await;
        let siblings = leaf_proof
            .siblings
            .iter()
            .map(|sibling| {
                [
                    sibling.0.elements[0].to_canonical_u64().to_string(),
                    sibling.0.elements[1].to_canonical_u64().to_string(),
                    sibling.0.elements[2].to_canonical_u64().to_string(),
                    sibling.0.elements[3].to_canonical_u64().to_string(),
                ]
            })
            .collect();
        trace_arena.push_step(TraceStep::ExternalProof(ExternalProofStep {
            fingerprint,
            proof_tree_start_root,
            proof_tree_end_root,
            proof: proof_bytes,
            verifier_data_alt,
            siblings,
        }));
        Ok((leaf_index, leaf_proof))
    }

    fn validate_trace_cfc_parent_before_children(trace_steps: &[crate::trace::TraceStep]) -> anyhow::Result<()> {
        fn visit(
            trace_steps: &[crate::trace::TraceStep],
            id: crate::trace::TraceStepId,
            visited: &mut [bool],
            expected: &mut Vec<crate::trace::TraceStepId>,
        ) -> anyhow::Result<()> {
            if id.0 >= trace_steps.len() {
                anyhow::bail!("trace CFC child id {} is out of bounds", id.0);
            }
            if visited[id.0] {
                anyhow::bail!("trace CFC id {} is linked more than once", id.0);
            }
            let cfc = trace_steps[id.0]
                .as_cfc()
                .ok_or_else(|| anyhow::anyhow!("trace CFC id {} points to non-CFC step", id.0))?;
            if cfc.id != id {
                anyhow::bail!("trace CFC id mismatch at index {}: step id is {}", id.0, cfc.id.0);
            }
            visited[id.0] = true;
            expected.push(id);
            for child_id in cfc.deferred.iter().chain(cfc.inlined.iter()) {
                let child = trace_steps
                    .get(child_id.0)
                    .and_then(crate::trace::TraceStep::as_cfc)
                    .ok_or_else(|| anyhow::anyhow!("trace CFC id {} links non-CFC child {}", id.0, child_id.0))?;
                anyhow::ensure!(
                    child.parent == Some(id),
                    "trace CFC child {} parent mismatch: expected {} got {:?}",
                    child_id.0,
                    id.0,
                    child.parent
                );
                visit(trace_steps, *child_id, visited, expected)?;
            }
            Ok(())
        }

        let actual = trace_steps
            .iter()
            .filter_map(crate::trace::TraceStep::as_cfc)
            .map(|cfc| cfc.id)
            .collect::<Vec<_>>();
        let mut expected = Vec::with_capacity(actual.len());
        let mut visited = vec![false; trace_steps.len()];
        for step in trace_steps {
            if let Some(cfc) = step.as_cfc() {
                if cfc.parent.is_none() && !visited[cfc.id.0] {
                    visit(trace_steps, cfc.id, &mut visited, &mut expected)?;
                }
            }
        }
        anyhow::ensure!(
            actual == expected,
            "trace CFC arena order is not parent-before-children: actual={:?} expected={:?}",
            actual,
            expected
        );
        Ok(())
    }

    /// Prove one arena CFC step. Parent/inlined/deferred links are validated
    /// against `trace_steps`; step proving still follows arena order.
    async fn prove_trace_cfc_step(
        user_session_mgr: &mut UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
        cm: &(dyn psy_vm::ups::circuit_manager::UPSCircuitManager<C, D> + Send + Sync),
        checkpoint_state: PsyCheckpointLeafCompactWithStateRoots<F>,
        prev_header: &mut UserProvingSessionHeader<F>,
        second_to_last_header: &mut UserProvingSessionHeader<F>,
        trace_steps: &[crate::trace::TraceStep],
        step: &crate::trace::TraceStep,
        step_index: usize,
        precomputed: Option<psy_ups_circuit::session::CfcStepProofs<C>>,
    ) -> anyhow::Result<psy_ups_circuit::session::CfcStepProofs<C>> {
        let (kind, cfc) = match step {
            crate::trace::TraceStep::Standard(cfc) => (TraceCfcStepKind::Standard, cfc),
            crate::trace::TraceStep::BurnFee(cfc) => (TraceCfcStepKind::BurnFee, cfc),
            crate::trace::TraceStep::Inlined(cfc) => (TraceCfcStepKind::Inlined, cfc),
            crate::trace::TraceStep::Deferred(cfc) => (TraceCfcStepKind::Deferred, cfc),
            _ => anyhow::bail!("trace step {} is not a CFC step", step_index),
        };
        anyhow::ensure!(
            cfc.id.0 == step_index,
            "trace arena id mismatch at step {}: cfc.id={}",
            step_index,
            cfc.id.0
        );
        match (kind, cfc.parent) {
            (TraceCfcStepKind::Standard | TraceCfcStepKind::BurnFee, None) => {}
            (TraceCfcStepKind::Deferred | TraceCfcStepKind::Inlined, Some(parent_id)) => {
                anyhow::ensure!(
                    parent_id.0 < step_index,
                    "trace step {} parent {} must appear before child",
                    step_index,
                    parent_id.0
                );
                let parent = trace_steps
                    .get(parent_id.0)
                    .and_then(crate::trace::TraceStep::as_cfc)
                    .ok_or_else(|| anyhow::anyhow!("trace step {} parent {} is not a CFC step", step_index, parent_id.0))?;
                let linked = match kind {
                    TraceCfcStepKind::Deferred => parent.deferred.contains(&cfc.id),
                    TraceCfcStepKind::Inlined => parent.inlined.contains(&cfc.id),
                    _ => unreachable!(),
                };
                anyhow::ensure!(
                    linked,
                    "trace step {} parent {} does not link child as {:?}",
                    step_index,
                    parent_id.0,
                    kind
                );
            }
            (TraceCfcStepKind::Standard | TraceCfcStepKind::BurnFee, Some(parent_id)) => {
                anyhow::bail!("top-level trace step {} unexpectedly has parent {}", step_index, parent_id.0);
            }
            (TraceCfcStepKind::Deferred | TraceCfcStepKind::Inlined, None) => {
                anyhow::bail!("trace {:?} step {} is missing parent", kind, step_index);
            }
        }
        for child_id in cfc.deferred.iter().chain(cfc.inlined.iter()) {
            anyhow::ensure!(
                child_id.0 < trace_steps.len(),
                "trace step {} links out-of-bounds child {}",
                step_index,
                child_id.0
            );
            let child = trace_steps
                .get(child_id.0)
                .and_then(crate::trace::TraceStep::as_cfc)
                .ok_or_else(|| anyhow::anyhow!("trace step {} child {} is not a CFC step", step_index, child_id.0))?;
            anyhow::ensure!(
                child.parent == Some(cfc.id),
                "trace child {} parent mismatch: expected {} got {:?}",
                child_id.0,
                cfc.id.0,
                child.parent
            );
        }
        if kind == TraceCfcStepKind::Inlined {
            anyhow::bail!("inlined CFC step proving is not implemented; VM execution does not support synchronous external calls");
        }

        let before = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
        if before != cfc.proof_tree_start_root {
            anyhow::bail!(
                "trace step root mismatch before step {}: runtime={} trace_start={}",
                step_index,
                before,
                cfc.proof_tree_start_root
            );
        }

        let proofs = if kind == TraceCfcStepKind::Deferred {
            let deferred_step = psy_ups_circuit::session::TraceDeferredStepInput {
                contract_id: cfc.contract_id,
                fn_id: cfc.fn_id,
                cfc_witness: cfc.cfc_witness.clone(),
                state_delta: cfc.state_delta.clone().into(),
                cfc_inclusion_proof: cfc.cfc_inclusion_proof.clone(),
                debt_removal_proof: cfc
                    .debt_removal_proof
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("deferred CFC step {} missing debt_removal_proof", step_index))?,
                end_header: cfc.end_header.clone(),
            };
            user_session_mgr
                .prove_step_deferred(cm, checkpoint_state, prev_header, &deferred_step, precomputed)
                .await?
        } else {
            let standard_step = psy_ups_circuit::session::TraceStandardStepInput {
                contract_id: cfc.contract_id,
                fn_id: cfc.fn_id,
                cfc_witness: cfc.cfc_witness.clone(),
                state_delta: cfc.state_delta.clone().into(),
                cfc_inclusion_proof: cfc.cfc_inclusion_proof.clone(),
                end_header: cfc.end_header.clone(),
            };
            user_session_mgr
                .prove_step_standard(cm, checkpoint_state, prev_header, &standard_step, precomputed)
                .await?
        };

        let after = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
        if after != cfc.proof_tree_end_root {
            anyhow::bail!(
                "trace step root mismatch after step {}: runtime={} trace_end={}",
                step_index,
                after,
                cfc.proof_tree_end_root
            );
        }
        *second_to_last_header = prev_header.clone();
        *prev_header = cfc.end_header.clone();
        Ok(proofs)
    }

    /// One-shot trace proving for CLI/native callers. Stale-anchor handling is
    /// explicit: fail fast once before proving starts, then rely on the final
    /// submit-time check inside `finalize_trace` for the authoritative TOCTOU
    /// guard.
    pub async fn prove_tx_trace(&self, public_key: QHashOut<F>, trace: &crate::trace::TxTrace) -> Result<QHashOut<F>, ProveError> {
        let user_id = trace.finalization.submit_end_cap_input.core.new_user_leaf.user_id.to_noncanonical_u64();
        self.check_submit_anchor(
            user_id,
            trace.finalization.submit_end_cap_input.core.state_transition.start_user_leaf_hash,
        )
        .await
        .map_err(ProveError::from_anyhow)?;

        let mut trace = trace.clone();
        let result = async {
            let state = self.prove_trace_steps(public_key, &mut trace).await?;
            self.finalize_trace(public_key, &trace, state).await
        }
        .await
        .map_err(ProveError::from_anyhow);
        self.clear_trace_proving_state(public_key);
        result
    }

    async fn register_trace_contract_circuits(&self, trace: &crate::trace::TxTrace) -> anyhow::Result<()> {
        for code in &trace.contract_codes {
            self.wallet
                .ensure_trace_contract_circuits_registered(code.contract_id, &code.code)
                .await?;
        }
        Ok(())
    }

    fn validate_proving_state(state: &ProvingState, proof_blobs: &[Vec<u8>]) -> anyhow::Result<()> {
        anyhow::ensure!(!proof_blobs.is_empty(), "proving state is missing ups_start proof bytes");
        anyhow::ensure!(
            state.proof_tree_meta.leaf_records.len() == proof_blobs.len(),
            "leaf_records ({}) != proof_blobs ({})",
            state.proof_tree_meta.leaf_records.len(),
            proof_blobs.len()
        );
        Ok(())
    }

    fn trace_step_leaf_proof_count(step: &crate::trace::TraceStep) -> anyhow::Result<usize> {
        match step {
            crate::trace::TraceStep::Standard(_) | crate::trace::TraceStep::BurnFee(_) | crate::trace::TraceStep::Deferred(_) => Ok(2),
            crate::trace::TraceStep::ExternalProof(_) => Ok(1),
            crate::trace::TraceStep::ZkSign(_) => Ok(0),
            crate::trace::TraceStep::Inlined(_) => {
                anyhow::bail!("inlined CFC step proving is not implemented")
            }
        }
    }

    fn next_step_index_from_leaf_proof_count(trace: &crate::trace::TxTrace, leaf_proof_count: usize) -> anyhow::Result<usize> {
        anyhow::ensure!(leaf_proof_count >= 1, "trace proving state is missing ups_start proof bytes");

        let mut consumed = 1usize;
        for (step_index, step) in trace.steps.iter().enumerate() {
            if consumed == leaf_proof_count {
                return Ok(step_index);
            }
            consumed += Self::trace_step_leaf_proof_count(step)?;
            anyhow::ensure!(
                consumed <= leaf_proof_count,
                "leaf proof count {} splits trace step {}",
                leaf_proof_count,
                step_index
            );
        }

        anyhow::ensure!(
            consumed == leaf_proof_count,
            "leaf proof count {} does not match trace structure (expected {})",
            leaf_proof_count,
            consumed
        );
        Ok(trace.steps.len())
    }

    fn snapshot_trace_proving_state_from_mgr(mgr: &UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>) -> anyhow::Result<ProvingState> {
        Ok(ProvingState {
            proof_tree_meta: ProofTreeMeta::from_portable_manager(&mgr.proof_tree_state),
            last_step_info: mgr.get_last_ups_step_proof_info(),
            current_header: mgr.get_current_ups_header().clone(),
            previous_header: mgr.get_previous_ups_header().clone(),
        })
    }

    async fn restore_leaf_proofs_from_proving_state(
        &self,
        mgr: &mut UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
        trace: &crate::trace::TxTrace,
        state: &ProvingState,
        proof_blobs: &[Vec<u8>],
    ) -> anyhow::Result<()> {
        use psy_crypto::common::witnesses::qrecursion::proof_data::LeafProofRecord;

        Self::validate_proving_state(state, proof_blobs)?;

        let cm = self.wallet.random_circuit_manager();
        let mut records = Vec::with_capacity(proof_blobs.len());
        for (leaf_record, proof_bytes) in state.proof_tree_meta.leaf_records.iter().zip(proof_blobs.iter()) {
            let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(proof_bytes)?;
            let verifier_data = if leaf_record.leaf_circuit_type_id == 4 {
                trace.steps.iter().find_map(|step| match step {
                    crate::trace::TraceStep::ExternalProof(external) if external.fingerprint == leaf_record.fingerprint => {
                        Some(external.verifier_data_alt.to_verifier_data::<C, D>())
                    }
                    _ => None,
                })
            } else {
                None
            };
            let verifier_data = if let Some(verifier_data) = verifier_data {
                verifier_data
            } else {
                Self::lookup_verifier_data(cm.as_ref(), trace, leaf_record.leaf_circuit_type_id, leaf_record.fingerprint).await?
            };
            records.push(LeafProofRecord {
                leaf_circuit_type: leaf_record.leaf_circuit_type_id,
                fingerprint: leaf_record.fingerprint,
                insertion_proof: leaf_record.insertion_proof.clone(),
                proof,
                verifier_data,
            });
        }
        mgr.proof_tree_state.restore_leaf_proofs_from_records(records);
        Ok(())
    }

    async fn restore_trace_proving_state(
        &self,
        mgr: &mut UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
        trace: &crate::trace::TxTrace,
        state: &ProvingState,
        proof_blobs: &[Vec<u8>],
    ) -> anyhow::Result<()> {
        mgr.proof_tree_state.restore_snapshot(
            state.proof_tree_meta.to_merkle_tree(),
            state.proof_tree_meta.root_history.clone(),
            state.proof_tree_meta.next_leaf_index,
        );
        mgr.set_last_ups_step_proof_info(state.last_step_info.clone());
        mgr.set_current_ups_header(state.current_header.clone());
        mgr.set_previous_ups_header(state.previous_header.clone());
        self.restore_leaf_proofs_from_proving_state(mgr, trace, state, proof_blobs).await?;
        let stored_root = state.proof_tree_meta.get_root();
        let restored_root = mgr.proof_tree_state.get_proof_tree_root().await;
        anyhow::ensure!(
            restored_root == stored_root,
            "trace resume restored root mismatch: restored={} stored={}",
            restored_root,
            stored_root
        );
        Ok(())
    }

    fn clear_trace_proving_state(&self, public_key: QHashOut<F>) {
        self.user_session_mgrs.remove(&public_key);
    }

    fn ups_start_state_roots_for_trace(trace: &crate::trace::TxTrace) -> PsyCheckpointGlobalStateRoots<F> {
        if trace.ups_start_witness.state_roots == PsyCheckpointGlobalStateRoots::default() {
            trace.anchor.global_state_roots
        } else {
            trace.ups_start_witness.state_roots
        }
    }

    fn manager_matches_proving_state(
        mgr: &UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
        state: &ProvingState,
        proof_count: usize,
    ) -> bool {
        mgr.proof_tree_state.leaf_proofs.len() == proof_count
            && ProofTreeMeta::from_portable_manager(&mgr.proof_tree_state).next_leaf_index == state.proof_tree_meta.next_leaf_index
    }

    pub async fn prove_trace_step(
        &self,
        public_key: QHashOut<F>,
        trace: &crate::trace::TxTrace,
        state: Option<&ProvingState>,
        proof_blobs: Option<&[Vec<u8>]>,
    ) -> TraceProvingStepResult {
        let attempt = async {
            self.register_trace_contract_circuits(trace).await?;
            Self::validate_trace_cfc_parent_before_children(&trace.steps)?;

            match state {
                None => {
                    self.clear_trace_proving_state(public_key);
                    self.init_step_proving_session(public_key, trace).await?;
                    let mut mgr = self
                        .user_session_mgrs
                        .get_mut(&public_key)
                        .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;
                    let start_input = psy_client_data::ups::start_step::UPSStartStepInput {
                        ups_header: trace.ups_start_witness.ups_header.clone(),
                        checkpoint_leaf: trace.anchor.checkpoint_leaf.clone(),
                        state_roots: Self::ups_start_state_roots_for_trace(trace),
                        checkpoint_tree_proof: trace.ups_start_witness.checkpoint_tree_proof.clone(),
                        user_tree_proof: trace.ups_start_witness.user_tree_proof.clone(),
                    };
                    let start_reg_proof = trace.ups_start_witness.user_registration_tree_proof.clone();
                    let start_precomputed = match &trace.ups_start_witness.proof {
                        Some(rec) => Some(decode_proof_bytes(&rec.proof)?),
                        None => None,
                    };
                    mgr.prove_ups_start_step(
                        self.wallet.random_circuit_manager().as_ref(),
                        start_input,
                        start_reg_proof,
                        start_precomputed,
                    )
                    .await?;
                    let state = Self::snapshot_trace_proving_state_from_mgr(&mgr)?;
                    let proof = mgr
                        .proof_tree_state
                        .leaf_proofs
                        .back()
                        .ok_or_else(|| anyhow::anyhow!("ups_start step did not record a proof"))?;
                    return Ok(TraceProvingStepResult::Progress {
                        state,
                        proofs: vec![bincode::serialize(&proof.proof)?],
                    });
                }
                Some(state) => {
                    let proof_blobs = proof_blobs.ok_or_else(|| anyhow::anyhow!("proving state requires proof blobs for crash recovery"))?;
                    Self::validate_proving_state(state, proof_blobs)?;
                    let needs_restore = match self.user_session_mgrs.get(&public_key) {
                        None => true,
                        Some(mgr) => !Self::manager_matches_proving_state(&mgr, state, proof_blobs.len()),
                    };
                    if needs_restore {
                        self.clear_trace_proving_state(public_key);
                        self.init_step_proving_session(public_key, trace).await?;
                        let mut mgr = self
                            .user_session_mgrs
                            .get_mut(&public_key)
                            .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;
                        self.restore_trace_proving_state(&mut mgr, trace, state, proof_blobs).await?;
                    }
                }
            }

            let checkpoint_state = UserProvingSessionManager::<F, PoseidonHash, RpcProvider, C, D>::checkpoint_state_from_parts(
                &trace.anchor.checkpoint_leaf,
                &trace.anchor.global_state_roots,
            );
            let cm = self.wallet.random_circuit_manager();
            let mut mgr = self
                .user_session_mgrs
                .get_mut(&public_key)
                .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;
            let next_step_index = Self::next_step_index_from_leaf_proof_count(trace, mgr.proof_tree_state.leaf_proofs.len())?;
            let step = trace
                .steps
                .get(next_step_index)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("trace is not ready for another prove step"))?;

            match &step {
                crate::trace::TraceStep::ZkSign(zs) => {
                    let state = TraceStepsState {
                        prev_header: mgr.get_current_ups_header().clone(),
                        second_to_last_header: mgr.get_previous_ups_header().clone(),
                        zksign_step: Some(zs.clone()),
                    };
                    drop(mgr);
                    let tx_hash = self.finalize_trace(public_key, trace, state).await?;
                    self.clear_trace_proving_state(public_key);
                    Ok(TraceProvingStepResult::Submitted(tx_hash))
                }
                crate::trace::TraceStep::ExternalProof(external) => {
                    let before = mgr.proof_tree_state.get_proof_tree_root().await;
                    if before != external.proof_tree_start_root {
                        anyhow::bail!(
                            "trace step external-proof root mismatch before step {}: runtime={} trace_start={}",
                            next_step_index,
                            before,
                            external.proof_tree_start_root
                        );
                    }
                    let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&external.proof)?;
                    mgr.add_external_proof(external.fingerprint, proof, external.verifier_data_alt.to_verifier_data::<C, D>())
                        .await;
                    let after = mgr.proof_tree_state.get_proof_tree_root().await;
                    if after != external.proof_tree_end_root {
                        anyhow::bail!(
                            "trace step external-proof root mismatch after step {}: runtime={} trace_end={}",
                            next_step_index,
                            after,
                            external.proof_tree_end_root
                        );
                    }
                    let state = Self::snapshot_trace_proving_state_from_mgr(&mgr)?;
                    Ok(TraceProvingStepResult::Progress {
                        state,
                        proofs: vec![external.proof.clone()],
                    })
                }
                crate::trace::TraceStep::Standard(_)
                | crate::trace::TraceStep::BurnFee(_)
                | crate::trace::TraceStep::Deferred(_)
                | crate::trace::TraceStep::Inlined(_) => {
                    let mut prev_header = mgr.get_current_ups_header().clone();
                    let mut second_to_last_header = mgr.get_previous_ups_header().clone();
                    let step_proofs = Self::prove_trace_cfc_step(
                        &mut mgr,
                        cm.as_ref(),
                        checkpoint_state,
                        &mut prev_header,
                        &mut second_to_last_header,
                        &trace.steps,
                        &step,
                        next_step_index,
                        None,
                    )
                    .await?;
                    mgr.set_current_ups_header(prev_header.clone());
                    mgr.set_previous_ups_header(second_to_last_header.clone());
                    let state = Self::snapshot_trace_proving_state_from_mgr(&mgr)?;
                    Ok(TraceProvingStepResult::Progress {
                        state,
                        proofs: vec![bincode::serialize(&step_proofs.cfc_proof)?, bincode::serialize(&step_proofs.ups_proof)?],
                    })
                }
            }
        }
        .await;

        match attempt {
            Ok(result) => result,
            Err(error) => {
                self.clear_trace_proving_state(public_key);
                TraceProvingStepResult::Failed {
                    error: ProveError::from_anyhow(error).to_string(),
                }
            }
        }
    }

    /// Build the step proving session and prove/inject every unit, recording
    /// proofs into the trace. Returns the header chain + terminal zksign
    /// step needed to finalize.
    async fn prove_trace_steps(&self, public_key: QHashOut<F>, trace: &mut crate::trace::TxTrace) -> anyhow::Result<TraceStepsState> {
        let cm = self.wallet.random_circuit_manager();
        self.register_trace_contract_circuits(trace).await?;

        Self::validate_trace_cfc_parent_before_children(&trace.steps)?;

        // Build a clean step proving session seeded entirely from the trace (no RPC),
        // then rebuild the proof tree below by injecting/proving each unit in order.
        self.init_step_proving_session(public_key, trace).await?;
        let mut user_session_mgr = self
            .user_session_mgrs
            .get_mut(&public_key)
            .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;

        let start_input = psy_client_data::ups::start_step::UPSStartStepInput {
            ups_header: trace.ups_start_witness.ups_header.clone(),
            checkpoint_leaf: trace.anchor.checkpoint_leaf.clone(),
            state_roots: Self::ups_start_state_roots_for_trace(trace),
            checkpoint_tree_proof: trace.ups_start_witness.checkpoint_tree_proof.clone(),
            user_tree_proof: trace.ups_start_witness.user_tree_proof.clone(),
        };
        let start_reg_proof = trace.ups_start_witness.user_registration_tree_proof.clone();

        // ups_start: re-inject if already proven, else prove and record into the trace.
        let start_precomputed = match &trace.ups_start_witness.proof {
            Some(rec) => Some(decode_proof_bytes(&rec.proof)?),
            None => None,
        };
        if let Some(precomputed) = start_precomputed {
            user_session_mgr
                .prove_ups_start_step(cm.as_ref(), start_input, start_reg_proof, Some(precomputed))
                .await?;
        } else {
            let proof = user_session_mgr
                .prove_ups_start_step(cm.as_ref(), start_input, start_reg_proof, None)
                .await?;
            trace.ups_start_witness.proof = Some(crate::trace::UpsStartProofRecord {
                proof: bincode::serialize(&proof)?,
                ..Default::default()
            });
        }

        let checkpoint_state = UserProvingSessionManager::<F, PoseidonHash, RpcProvider, C, D>::checkpoint_state_from_parts(
            &trace.anchor.checkpoint_leaf,
            &trace.anchor.global_state_roots,
        );
        let mut prev_header = trace.ups_start_witness.ups_header.clone();
        let mut second_to_last_header = trace.ups_start_witness.ups_header.clone();

        let mut zksign_step: Option<crate::trace::ZkSignStep> = None;
        for step_index in 0..trace.steps.len() {
            // Work on a clone so the trace can be mutated (proof slot fill) after
            // the immutable borrows taken by `prove_trace_cfc_step` are released.
            let step = trace.steps[step_index].clone();
            match &step {
                crate::trace::TraceStep::Standard(_)
                | crate::trace::TraceStep::BurnFee(_)
                | crate::trace::TraceStep::Inlined(_)
                | crate::trace::TraceStep::Deferred(_) => {
                    // Re-inject if already proven, else prove and record.
                    let precomputed = match step.as_cfc().and_then(|c| c.proof.as_ref()) {
                        Some(rec) => Some(cfc_record_to_proofs(rec)?),
                        None => None,
                    };
                    let need_record = precomputed.is_none();
                    let proofs = Self::prove_trace_cfc_step(
                        &mut user_session_mgr,
                        cm.as_ref(),
                        checkpoint_state,
                        &mut prev_header,
                        &mut second_to_last_header,
                        &trace.steps,
                        &step,
                        step_index,
                        precomputed,
                    )
                    .await?;
                    if need_record {
                        let rec = cfc_proofs_to_record(&proofs)?;
                        if let Some(c) = trace.steps[step_index].as_cfc_mut() {
                            c.proof = Some(rec);
                        }
                    }
                }
                crate::trace::TraceStep::ExternalProof(external) => {
                    let before = user_session_mgr.proof_tree_state.get_proof_tree_root().await;

                    if before != external.proof_tree_start_root {
                        anyhow::bail!(
                            "trace step external-proof root mismatch before step {}: runtime={} trace_start={}",
                            step_index,
                            before,
                            external.proof_tree_start_root
                        );
                    }
                    let proof_bytes = &external.proof;
                    let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(proof_bytes)?;
                    user_session_mgr
                        .add_external_proof(external.fingerprint, proof, external.verifier_data_alt.to_verifier_data::<C, D>())
                        .await;
                    let after = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
                    if after != external.proof_tree_end_root {
                        anyhow::bail!(
                            "trace step external-proof root mismatch after step {}: runtime={} trace_end={}",
                            step_index,
                            after,
                            external.proof_tree_end_root
                        );
                    }
                }
                crate::trace::TraceStep::ZkSign(zs) => {
                    if step_index + 1 != trace.steps.len() {
                        anyhow::bail!("ZkSign trace step must be terminal");
                    }
                    let before = user_session_mgr.proof_tree_state.get_proof_tree_root().await;
                    if before != zs.proof_tree_start_root {
                        anyhow::bail!(
                            "trace step zksign root mismatch before step {}: runtime={} trace_start={}",
                            step_index,
                            before,
                            zs.proof_tree_start_root
                        );
                    }
                    zksign_step = Some(zs.clone());
                }
            }
        }

        Ok(TraceStepsState {
            prev_header,
            second_to_last_header,
            zksign_step,
        })
    }

    // ================================
    // Stateless step proving (no DashMap)
    // ================================

    /// Build a stateless UserProvingSessionManager from a trace.
    /// Ensures the trace's contract circuits are available and seeds from
    /// `trace.anchor`. Does NOT store in `user_session_mgrs` — the returned
    /// manager is ephemeral.
    async fn build_step_manager(
        &self,
        trace: &crate::trace::TxTrace,
    ) -> anyhow::Result<UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>> {
        for code in &trace.contract_codes {
            self.wallet
                .ensure_trace_contract_circuits_registered(code.contract_id, &code.code)
                .await?;
        }

        UserProvingSessionManager::<F, PoseidonHash, RpcProvider, C, D>::new_from_trace_anchor(
            self.circuit_info.clone(),
            trace.ups_start_witness.ups_header.clone(),
            trace.anchor.checkpoint_leaf.clone(),
            trace.anchor.global_state_roots,
        )
        .await
    }

    /// Restore state onto a manager from externalized parameters.
    fn restore_manager_state(
        mgr: &mut UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
        meta: &ProofTreeMeta,
        baton: LastStepProofInfo,
        current_header: UserProvingSessionHeader<F>,
        previous_header: UserProvingSessionHeader<F>,
    ) {
        mgr.proof_tree_state
            .restore_snapshot(meta.to_merkle_tree(), meta.root_history.clone(), meta.next_leaf_index);
        mgr.set_last_ups_step_proof_info(baton);
        mgr.set_current_ups_header(current_header);
        mgr.set_previous_ups_header(previous_header);
    }

    /// Stateless ups_start prove.
    /// Returns all state needed for subsequent steps. `leaf_records` with
    /// `insertion_proof` are included in the returned `ProofTreeMeta`.
    /// Proof blobs are NOT returned here — JS stores them separately and
    /// Stateless ups_start prove. Manager is ephemeral — built, used,
    /// discarded. JS receives meta/baton/headers as the persistent backup
    /// for crash recovery.
    pub async fn prove_ups_start(
        &self,
        _public_key: QHashOut<F>,
        trace: &crate::trace::TxTrace,
    ) -> anyhow::Result<(
        ProofTreeMeta,
        LastStepProofInfo,
        UserProvingSessionHeader<F>,
        UserProvingSessionHeader<F>,
        ProofWithPublicInputs<F, C, D>,
    )> {
        let mut mgr = self.build_step_manager(trace).await?;

        let start_input = psy_client_data::ups::start_step::UPSStartStepInput {
            ups_header: trace.ups_start_witness.ups_header.clone(),
            checkpoint_leaf: trace.anchor.checkpoint_leaf.clone(),
            state_roots: Self::ups_start_state_roots_for_trace(trace),
            checkpoint_tree_proof: trace.ups_start_witness.checkpoint_tree_proof.clone(),
            user_tree_proof: trace.ups_start_witness.user_tree_proof.clone(),
        };
        let start_reg_proof = trace.ups_start_witness.user_registration_tree_proof.clone();
        let start_precomputed = match &trace.ups_start_witness.proof {
            Some(rec) => Some(decode_proof_bytes(&rec.proof)?),
            None => None,
        };

        let ups_proof = mgr
            .prove_ups_start_step(
                self.wallet.random_circuit_manager().as_ref(),
                start_input,
                start_reg_proof,
                start_precomputed,
            )
            .await?;

        let meta = ProofTreeMeta::from_portable_manager(&mgr.proof_tree_state);
        let baton = mgr.get_last_ups_step_proof_info();
        let current_header = mgr.get_current_ups_header().clone();
        let previous_header = mgr.get_previous_ups_header().clone();

        Ok((meta, baton, current_header, previous_header, ups_proof))
    }

    /// Stateless CFC step prove.
    /// CFC step prove. Uses the manager stored by `prove_ups_start` in
    /// Stateless CFC step prove. Rebuilds manager from JS-provided state,
    /// proves one step, returns updated state. No WASM state between calls.
    pub async fn prove_trace_step_with_state(
        &self,
        _public_key: QHashOut<F>,
        trace: &crate::trace::TxTrace,
        step_index: usize,
        meta: &ProofTreeMeta,
        baton: LastStepProofInfo,
        current_header: &UserProvingSessionHeader<F>,
        previous_header: &UserProvingSessionHeader<F>,
    ) -> anyhow::Result<(
        psy_ups_circuit::session::CfcStepProofs<C>,
        ProofTreeMeta,
        LastStepProofInfo,
        UserProvingSessionHeader<F>,
        UserProvingSessionHeader<F>,
    )> {
        let mut mgr = self.build_step_manager(trace).await?;
        Self::restore_manager_state(&mut mgr, meta, baton, current_header.clone(), previous_header.clone());

        let step = trace
            .steps
            .get(step_index)
            .ok_or_else(|| anyhow::anyhow!("step index {} out of bounds (len {})", step_index, trace.steps.len()))?
            .clone();

        let cfc = step
            .as_cfc()
            .ok_or_else(|| anyhow::anyhow!("trace step {} is not a CFC step", step_index))?;
        anyhow::ensure!(cfc.id.0 == step_index, "trace arena id mismatch at step {}", step_index);

        let prev_header = current_header;

        let checkpoint_state = UserProvingSessionManager::<F, PoseidonHash, RpcProvider, C, D>::checkpoint_state_from_parts(
            &trace.anchor.checkpoint_leaf,
            &trace.anchor.global_state_roots,
        );

        let precomputed = match cfc.proof.as_ref() {
            Some(rec) => Some(cfc_record_to_proofs(rec)?),
            None => None,
        };

        let proofs = match &step {
            crate::trace::TraceStep::Standard(_) | crate::trace::TraceStep::BurnFee(_) => {
                let standard_step = psy_ups_circuit::session::TraceStandardStepInput {
                    contract_id: cfc.contract_id,
                    fn_id: cfc.fn_id,
                    cfc_witness: cfc.cfc_witness.clone(),
                    state_delta: cfc.state_delta.clone().into(),
                    cfc_inclusion_proof: cfc.cfc_inclusion_proof.clone(),
                    end_header: cfc.end_header.clone(),
                };
                mgr.prove_step_standard(
                    self.wallet.random_circuit_manager().as_ref(),
                    checkpoint_state,
                    prev_header,
                    &standard_step,
                    precomputed,
                )
                .await?
            }
            crate::trace::TraceStep::Deferred(_) => {
                let deferred_step = psy_ups_circuit::session::TraceDeferredStepInput {
                    contract_id: cfc.contract_id,
                    fn_id: cfc.fn_id,
                    cfc_witness: cfc.cfc_witness.clone(),
                    state_delta: cfc.state_delta.clone().into(),
                    cfc_inclusion_proof: cfc.cfc_inclusion_proof.clone(),
                    debt_removal_proof: cfc
                        .debt_removal_proof
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("deferred CFC step {} missing debt_removal_proof", step_index))?,
                    end_header: cfc.end_header.clone(),
                };
                mgr.prove_step_deferred(
                    self.wallet.random_circuit_manager().as_ref(),
                    checkpoint_state,
                    prev_header,
                    &deferred_step,
                    precomputed,
                )
                .await?
            }
            crate::trace::TraceStep::Inlined(_) => {
                anyhow::bail!("inlined CFC step proving is not implemented");
            }
            _ => {
                anyhow::bail!("trace step {} is not a CFC step", step_index);
            }
        };

        // Merge leaf_records: JS meta has all prior leaves, this step adds new ones.
        let next_meta = ProofTreeMeta::from_portable_manager(&mgr.proof_tree_state);
        let mut all_meta = meta.clone();
        all_meta.leaf_records.extend(next_meta.leaf_records);
        all_meta.next_leaf_index = next_meta.next_leaf_index;
        all_meta.root_history = next_meta.root_history;
        all_meta.proof_tree = next_meta.proof_tree;

        let new_baton = mgr.get_last_ups_step_proof_info();
        let new_current_header = cfc.end_header.clone();
        let new_previous_header = prev_header.clone();

        Ok((proofs, all_meta, new_baton, new_current_header, new_previous_header))
    }

    pub async fn prove_one_cfc_job(
        &self,
        public_key: QHashOut<F>,
        trace: &crate::trace::TxTrace,
        step_index: usize,
        seed: &StepSeed,
    ) -> anyhow::Result<TraceCfcJobOutput> {
        let (proofs, meta, baton, _current_header, _previous_header) = self
            .prove_trace_step_with_state(
                public_key,
                trace,
                step_index,
                &seed.proof_tree_meta,
                seed.prev_baton,
                &seed.prev_header,
                &seed.second_to_last_header,
            )
            .await?;

        Ok((
            (bincode::serialize(&proofs.cfc_proof)?, bincode::serialize(&proofs.ups_proof)?),
            meta,
            baton,
        ))
    }

    pub async fn prepare_trace_proof_schedule(&self, trace: &crate::trace::TxTrace) -> anyhow::Result<TraceProofSchedule> {
        self.build_trace_proof_schedule_from_trace(trace).await
    }

    pub async fn prove_ups_start_job(&self, public_key: QHashOut<F>, trace: &crate::trace::TxTrace) -> anyhow::Result<TraceProofJobOutput> {
        let (meta, baton, current_header, previous_header, proof) = self.prove_ups_start(public_key, trace).await?;
        Ok(TraceProofJobOutput::UpsStart {
            proof: bincode::serialize(&proof)?,
            meta,
            baton,
            current_header,
            previous_header,
        })
    }

    pub async fn prove_cfc_job_with_seed(
        &self,
        public_key: QHashOut<F>,
        trace: &crate::trace::TxTrace,
        seed: &StepSeed,
    ) -> anyhow::Result<TraceProofJobOutput> {
        let step_index = seed.step_index;
        let (proof_bytes, meta, baton) = self.prove_one_cfc_job(public_key, trace, step_index, seed).await?;
        Ok(TraceProofJobOutput::CfcStep {
            step_index,
            proof_bytes,
            meta,
            baton,
        })
    }

    pub async fn prove_external_proof_job(&self, trace: &crate::trace::TxTrace, step_index: usize) -> anyhow::Result<TraceProofJobOutput> {
        let proof = trace
            .steps
            .get(step_index)
            .and_then(|step| match step {
                crate::trace::TraceStep::ExternalProof(external) => Some(external.proof.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("trace step {} is not an external proof", step_index))?;
        let _: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&proof)?;
        Ok(TraceProofJobOutput::ExternalProof { step_index, proof })
    }

    pub async fn prove_zksign_job(&self, public_key: QHashOut<F>, trace: &crate::trace::TxTrace) -> anyhow::Result<TraceProofJobOutput> {
        let current_header = trace
            .steps
            .iter()
            .filter_map(crate::trace::TraceStep::as_cfc)
            .last()
            .map(|cfc| cfc.end_header.clone())
            .unwrap_or_else(|| trace.ups_start_witness.ups_header.clone());
        let signature_result = self.sign_trace_finalization(public_key, trace, &current_header).await?;
        Ok(TraceProofJobOutput::ZkSign {
            proof: bincode::serialize(&signature_result.proof)?,
        })
    }

    pub async fn prove_endcap_job_from_outputs(
        &self,
        public_key: QHashOut<F>,
        trace: &crate::trace::TxTrace,
        schedule: &TraceProofSchedule,
        outputs: Vec<TraceProofJobOutput>,
    ) -> anyhow::Result<TraceProofJobOutput> {
        let seeds_by_step = schedule.seeds.iter().map(|seed| (seed.step_index, seed)).collect::<BTreeMap<_, _>>();
        let mut ups_start = None;
        let mut zksign = None;
        let mut cfc_steps = BTreeMap::new();
        let mut external_proofs = BTreeMap::new();

        for output in outputs {
            match output {
                TraceProofJobOutput::UpsStart { .. } => {
                    anyhow::ensure!(ups_start.replace(output).is_none(), "duplicate UPS-start output");
                }
                TraceProofJobOutput::CfcStep { step_index, .. } => {
                    anyhow::ensure!(
                        cfc_steps.insert(step_index, output).is_none(),
                        "duplicate CFC output for step {}",
                        step_index
                    );
                }
                TraceProofJobOutput::ExternalProof { step_index, .. } => {
                    anyhow::ensure!(
                        external_proofs.insert(step_index, output).is_none(),
                        "duplicate external-proof output for step {}",
                        step_index
                    );
                }
                TraceProofJobOutput::ZkSign { .. } => {
                    anyhow::ensure!(zksign.replace(output).is_none(), "duplicate ZkSign output");
                }
                TraceProofJobOutput::EndCap { .. } | TraceProofJobOutput::Submit { .. } => {
                    anyhow::bail!("end-cap input list must only contain first-wave job outputs");
                }
            }
        }

        let TraceProofJobOutput::UpsStart {
            proof: ups_proof,
            mut meta,
            mut baton,
            mut current_header,
            mut previous_header,
        } = ups_start.ok_or_else(|| anyhow::anyhow!("missing UPS-start output"))?
        else {
            unreachable!("ups_start is filtered by variant above");
        };

        let mut all_proof_blobs = vec![ups_proof];
        for (step_index, step) in trace.steps.iter().enumerate() {
            match step {
                crate::trace::TraceStep::Standard(_) | crate::trace::TraceStep::BurnFee(_) | crate::trace::TraceStep::Deferred(_) => {
                    let seed = seeds_by_step
                        .get(&step_index)
                        .ok_or_else(|| anyhow::anyhow!("missing proof seed for CFC step {}", step_index))?;
                    let TraceProofJobOutput::CfcStep {
                        proof_bytes,
                        meta: step_meta,
                        baton: step_baton,
                        ..
                    } = cfc_steps
                        .remove(&step_index)
                        .ok_or_else(|| anyhow::anyhow!("missing CFC output for step {}", step_index))?
                    else {
                        unreachable!("cfc_steps is keyed only from CfcStep variants");
                    };

                    all_proof_blobs.push(proof_bytes.0.clone());
                    all_proof_blobs.push(proof_bytes.1.clone());

                    let mut new_leaf_records = step_meta.leaf_records.clone();
                    let seed_leaf_count = seed.proof_tree_meta.leaf_records.len();
                    anyhow::ensure!(
                        new_leaf_records.len() >= seed_leaf_count,
                        "CFC step {} returned fewer leaf records than its seed",
                        step_index,
                    );
                    let new_leaf_records = new_leaf_records.split_off(seed_leaf_count);
                    meta.proof_tree = step_meta.proof_tree.clone();
                    meta.root_history = step_meta.root_history.clone();
                    meta.next_leaf_index = step_meta.next_leaf_index;
                    meta.leaf_records.extend(new_leaf_records);

                    baton = step_baton;
                    previous_header = current_header;
                    current_header = step
                        .as_cfc()
                        .ok_or_else(|| anyhow::anyhow!("trace step {} is not a CFC step", step_index))?
                        .end_header
                        .clone();
                }
                crate::trace::TraceStep::Inlined(_) => {
                    tracing::debug!(step_index, "skipping inlined trace step in end-cap job merge");
                }
                crate::trace::TraceStep::ExternalProof(external) => {
                    let TraceProofJobOutput::ExternalProof { proof, .. } = external_proofs
                        .remove(&step_index)
                        .ok_or_else(|| anyhow::anyhow!("missing external-proof output for step {}", step_index))?
                    else {
                        unreachable!("external_proofs is keyed only from ExternalProof variants");
                    };
                    let proof_deser: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&proof)?;
                    all_proof_blobs.push(proof);
                    meta = self
                        .insert_external_proof(
                            public_key,
                            trace,
                            &meta,
                            baton,
                            &current_header,
                            &previous_header,
                            external.fingerprint,
                            proof_deser,
                        )
                        .await?;
                }
                crate::trace::TraceStep::ZkSign(_) => break,
            }
        }

        anyhow::ensure!(cfc_steps.is_empty(), "unused CFC outputs: {:?}", cfc_steps.keys().collect::<Vec<_>>());
        anyhow::ensure!(
            external_proofs.is_empty(),
            "unused external-proof outputs: {:?}",
            external_proofs.keys().collect::<Vec<_>>()
        );

        let TraceProofJobOutput::ZkSign { proof: signature_proof } = zksign.ok_or_else(|| anyhow::anyhow!("missing ZkSign output"))? else {
            unreachable!("zksign is filtered by variant above");
        };
        let signature_proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&signature_proof)?;

        let mut proof_blobs_deser = Vec::with_capacity(all_proof_blobs.len());
        for bytes in &all_proof_blobs {
            proof_blobs_deser.push(bincode::deserialize(bytes)?);
        }

        let (end_cap_proof, tx_hash) = self
            .prove_end_cap_proof(public_key, trace, &meta, proof_blobs_deser, baton, signature_proof)
            .await?;
        Ok(TraceProofJobOutput::EndCap {
            proof: bincode::serialize(&end_cap_proof)?,
            tx_hash,
        })
    }

    pub async fn submit_endcap_job(&self, trace: &crate::trace::TxTrace, endcap: TraceProofJobOutput) -> anyhow::Result<TraceProofJobOutput> {
        let TraceProofJobOutput::EndCap { proof, .. } = endcap else {
            anyhow::bail!("submit_endcap_job expects an EndCap output");
        };
        let end_cap_proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&proof)?;
        let tx_hash = self.submit_end_cap(trace, end_cap_proof).await?;
        Ok(TraceProofJobOutput::Submit { tx_hash })
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn prove_trace_jobs_by_graph(
        self: Arc<Self>,
        public_key: QHashOut<F>,
        trace: Arc<crate::trace::TxTrace>,
        plan: &TraceProofPlan,
    ) -> anyhow::Result<QHashOut<F>> {
        let manager = &self.local_proving_job_manager;
        let graph_id = plan.graph_id.clone();
        manager.clear_graph(graph_id.clone())?;
        manager.add_graph(graph_id.clone(), plan.job_graph.to_job_graph())?;

        let seeds_by_step = Arc::new(plan.seeds_by_step());
        let runnable_jobs = plan.job_graph.jobs();
        let manager_for_jobs = manager.clone();
        let wallet_session = self.clone();
        let trace_for_jobs = trace.clone();
        let runtime = tokio::runtime::Handle::current();
        let graph_id_for_jobs = graph_id.clone();

        let outputs = manager
            .run_graph(graph_id, [], runnable_jobs, move |job| {
                let manager = manager_for_jobs.clone();
                let wallet_session = wallet_session.clone();
                let trace = trace_for_jobs.clone();
                let seeds_by_step = seeds_by_step.clone();
                let runtime = runtime.clone();
                let graph_id = graph_id_for_jobs.clone();

                async move {
                    match job {
                        TraceProofJobId::UpsStart => tokio::task::spawn_blocking(move || {
                            runtime.block_on(async move {
                                let (meta, baton, current_header, previous_header, proof) =
                                    wallet_session.prove_ups_start(public_key, trace.as_ref()).await?;
                                Ok::<_, anyhow::Error>(TraceProofJobOutput::UpsStart {
                                    proof: bincode::serialize(&proof)?,
                                    meta,
                                    baton,
                                    current_header,
                                    previous_header,
                                })
                            })
                        })
                        .await
                        .map_err(|e| anyhow::anyhow!("UPS start job failed to join: {}", e))?,
                        TraceProofJobId::CfcStep(step_index) => {
                            let seed = seeds_by_step
                                .get(&step_index)
                                .ok_or_else(|| anyhow::anyhow!("missing proof seed for CFC step {}", step_index))?
                                .clone();
                            tokio::task::spawn_blocking(move || {
                                runtime.block_on(async move {
                                    let (proof_bytes, meta, baton) =
                                        wallet_session.prove_one_cfc_job(public_key, trace.as_ref(), step_index, &seed).await?;
                                    Ok::<_, anyhow::Error>(TraceProofJobOutput::CfcStep {
                                        step_index,
                                        proof_bytes,
                                        meta,
                                        baton,
                                    })
                                })
                            })
                            .await
                            .map_err(|e| anyhow::anyhow!("CFC job {} failed to join: {}", step_index, e))?
                        }
                        TraceProofJobId::ExternalProof(step_index) => {
                            let proof = trace
                                .steps
                                .get(step_index)
                                .and_then(|step| match step {
                                    crate::trace::TraceStep::ExternalProof(external) => Some(external.proof.clone()),
                                    _ => None,
                                })
                                .ok_or_else(|| anyhow::anyhow!("trace step {} is not an external proof", step_index))?;
                            let _: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&proof)?;
                            Ok(TraceProofJobOutput::ExternalProof { step_index, proof })
                        }
                        TraceProofJobId::ZkSign => {
                            let current_header = trace
                                .steps
                                .iter()
                                .filter_map(crate::trace::TraceStep::as_cfc)
                                .last()
                                .map(|cfc| cfc.end_header.clone())
                                .unwrap_or_else(|| trace.ups_start_witness.ups_header.clone());
                            let signature_result = wallet_session
                                .sign_trace_finalization(public_key, trace.as_ref(), &current_header)
                                .await?;
                            Ok(TraceProofJobOutput::ZkSign {
                                proof: bincode::serialize(&signature_result.proof)?,
                            })
                        }
                        TraceProofJobId::EndCap => {
                            let TraceProofJobOutput::UpsStart {
                                proof: ups_proof,
                                mut meta,
                                mut baton,
                                mut current_header,
                                mut previous_header,
                            } = manager
                                .result(graph_id.clone(), &TraceProofJobId::UpsStart)
                                .ok_or_else(|| anyhow::anyhow!("missing UpsStart job result"))?
                            else {
                                anyhow::bail!("UpsStart job returned unexpected output");
                            };

                            let mut all_proof_blobs = vec![ups_proof];
                            for (step_index, step) in trace.steps.iter().enumerate() {
                                match step {
                                    crate::trace::TraceStep::Standard(_)
                                    | crate::trace::TraceStep::BurnFee(_)
                                    | crate::trace::TraceStep::Deferred(_) => {
                                        let seed = seeds_by_step
                                            .get(&step_index)
                                            .ok_or_else(|| anyhow::anyhow!("missing proof seed for CFC step {}", step_index))?;
                                        let TraceProofJobOutput::CfcStep {
                                            proof_bytes,
                                            meta: step_meta,
                                            baton: step_baton,
                                            ..
                                        } = manager
                                            .result(graph_id.clone(), &TraceProofJobId::CfcStep(step_index))
                                            .ok_or_else(|| anyhow::anyhow!("missing CFC job result for step {}", step_index))?
                                        else {
                                            anyhow::bail!("CFC job {} returned unexpected output", step_index);
                                        };
                                        all_proof_blobs.push(proof_bytes.0.clone());
                                        all_proof_blobs.push(proof_bytes.1.clone());

                                        let mut new_leaf_records = step_meta.leaf_records.clone();
                                        let seed_leaf_count = seed.proof_tree_meta.leaf_records.len();
                                        anyhow::ensure!(
                                            new_leaf_records.len() >= seed_leaf_count,
                                            "CFC step {} returned fewer leaf records than its seed",
                                            step_index,
                                        );
                                        let new_leaf_records = new_leaf_records.split_off(seed_leaf_count);
                                        meta.proof_tree = step_meta.proof_tree.clone();
                                        meta.root_history = step_meta.root_history.clone();
                                        meta.next_leaf_index = step_meta.next_leaf_index;
                                        meta.leaf_records.extend(new_leaf_records);

                                        baton = step_baton;
                                        previous_header = current_header;
                                        current_header = step
                                            .as_cfc()
                                            .ok_or_else(|| anyhow::anyhow!("trace step {} is not a CFC step", step_index))?
                                            .end_header
                                            .clone();
                                    }
                                    crate::trace::TraceStep::Inlined(_) => {
                                        tracing::debug!(step_index, "skipping inlined trace step in job graph path");
                                    }
                                    crate::trace::TraceStep::ExternalProof(external) => {
                                        let TraceProofJobOutput::ExternalProof { proof, .. } = manager
                                            .result(graph_id.clone(), &TraceProofJobId::ExternalProof(step_index))
                                            .ok_or_else(|| anyhow::anyhow!("missing external proof job result for step {}", step_index))?
                                        else {
                                            anyhow::bail!("external proof job {} returned unexpected output", step_index);
                                        };
                                        let proof_deser: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&proof)?;
                                        all_proof_blobs.push(proof);
                                        meta = wallet_session
                                            .insert_external_proof(
                                                public_key,
                                                trace.as_ref(),
                                                &meta,
                                                baton,
                                                &current_header,
                                                &previous_header,
                                                external.fingerprint,
                                                proof_deser,
                                            )
                                            .await?;
                                    }
                                    crate::trace::TraceStep::ZkSign(_) => break,
                                }
                            }

                            let TraceProofJobOutput::ZkSign { proof: signature_proof } =
                                manager
                                    .result(graph_id.clone(), &TraceProofJobId::ZkSign)
                                    .ok_or_else(|| anyhow::anyhow!("missing ZkSign job result"))?
                            else {
                                anyhow::bail!("ZkSign job returned unexpected output");
                            };
                            let signature_proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&signature_proof)?;

                            let mut proof_blobs_deser = Vec::with_capacity(all_proof_blobs.len());
                            for bytes in &all_proof_blobs {
                                proof_blobs_deser.push(bincode::deserialize(bytes)?);
                            }

                            let (end_cap_proof, tx_hash) = wallet_session
                                .prove_end_cap_proof(public_key, trace.as_ref(), &meta, proof_blobs_deser, baton, signature_proof)
                                .await?;
                            Ok(TraceProofJobOutput::EndCap {
                                proof: bincode::serialize(&end_cap_proof)?,
                                tx_hash,
                            })
                        }
                        TraceProofJobId::Submit => {
                            let TraceProofJobOutput::EndCap { proof, .. } = manager
                                .result(graph_id.clone(), &TraceProofJobId::EndCap)
                                .ok_or_else(|| anyhow::anyhow!("missing EndCap job result"))?
                            else {
                                anyhow::bail!("EndCap job returned unexpected output");
                            };
                            let end_cap_proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&proof)?;
                            let tx_hash = wallet_session.submit_end_cap(trace.as_ref(), end_cap_proof).await?;
                            Ok(TraceProofJobOutput::Submit { tx_hash })
                        }
                    }
                }
            })
            .await?;

        let TraceProofJobOutput::Submit { tx_hash } = outputs
            .get(&TraceProofJobId::Submit)
            .ok_or_else(|| anyhow::anyhow!("missing Submit job output"))?
        else {
            anyhow::bail!("Submit job returned unexpected output");
        };
        Ok(*tx_hash)
    }

    pub async fn build_trace_proof_schedule_from_trace(&self, trace: &crate::trace::TxTrace) -> anyhow::Result<TraceProofSchedule> {
        let cm = self.wallet.random_circuit_manager();
        let is_new_user = trace.ups_start_witness.user_registration_tree_proof.is_some();
        let ups_start_fingerprint = if is_new_user {
            cm.ups_start_register_user_circuit_fingerprint().await?
        } else {
            cm.ups_start_circuit_fingerprint().await?
        };
        let (initial_meta, initial_baton) = TraceProofSchedule::initial_state_from_trace(trace, ups_start_fingerprint, is_new_user)?;
        TraceProofSchedule::build(initial_meta, initial_baton, trace)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn build_trace_proof_plan_from_trace(&self, trace: &crate::trace::TxTrace) -> anyhow::Result<TraceProofPlan> {
        let schedule = self.build_trace_proof_schedule_from_trace(trace).await?;
        Ok(TraceProofPlan::from_trace_and_schedule(trace, schedule))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_proving_graph_id_for_trace(trace: &crate::trace::TxTrace) -> GraphId {
        graph_id_from_trace(trace)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_proving_job_status_for_graph(&self, graph_id: GraphId, job: TraceProofJobId) -> Option<JobStatus> {
        self.local_proving_job_manager.status(graph_id, &job)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_proving_job_status_for_trace(&self, trace: &crate::trace::TxTrace, job: TraceProofJobId) -> Option<JobStatus> {
        self.local_proving_job_status_for_graph(graph_id_from_trace(trace), job)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_proving_job_statuses_for_graph(&self, graph_id: GraphId) -> BTreeMap<TraceProofJobId, JobStatus> {
        self.local_proving_job_manager.statuses(graph_id)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_proving_job_statuses_for_trace(&self, trace: &crate::trace::TxTrace) -> BTreeMap<TraceProofJobId, JobStatus> {
        self.local_proving_job_statuses_for_graph(graph_id_from_trace(trace))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_proving_graph_status_for_graph(&self, graph_id: GraphId) -> Option<JobStatus> {
        self.local_proving_job_manager.graph_status(graph_id)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_proving_graph_status_for_trace(&self, trace: &crate::trace::TxTrace) -> Option<JobStatus> {
        self.local_proving_graph_status_for_graph(graph_id_from_trace(trace))
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_proving_job_result_for_graph(&self, graph_id: GraphId, job: TraceProofJobId) -> Option<TraceProofJobOutput> {
        self.local_proving_job_manager.result(graph_id, &job)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_proving_job_result_for_trace(&self, trace: &crate::trace::TxTrace, job: TraceProofJobId) -> Option<TraceProofJobOutput> {
        self.local_proving_job_result_for_graph(graph_id_from_trace(trace), job)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_proving_job_results_for_graph(&self, graph_id: GraphId) -> BTreeMap<TraceProofJobId, TraceProofJobOutput> {
        self.local_proving_job_manager.results(graph_id)
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn local_proving_job_results_for_trace(&self, trace: &crate::trace::TxTrace) -> BTreeMap<TraceProofJobId, TraceProofJobOutput> {
        self.local_proving_job_results_for_graph(graph_id_from_trace(trace))
    }

    pub async fn sign_trace_finalization(
        &self,
        public_key: QHashOut<F>,
        trace: &crate::trace::TxTrace,
        current_header: &UserProvingSessionHeader<F>,
    ) -> anyhow::Result<SignatureResult> {
        let zs = trace
            .steps
            .last()
            .and_then(|step| match step {
                crate::trace::TraceStep::ZkSign(zs) => Some(zs),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("trace is missing terminal ZkSign step"))?;

        let pk_info = self.wallet.get_public_key_info(&public_key).await?;
        anyhow::ensure!(
            zs.fingerprint == pk_info.fingerprint,
            "trace signing fingerprint {} does not match wallet key fingerprint {}",
            zs.fingerprint,
            pk_info.fingerprint
        );
        self.ensure_trace_sign_circuit_registered(pk_info.fingerprint, &zs.sign_circuit_source)
            .await?;

        let sign_context = match &zs.sign_circuit_source {
            crate::trace::TraceSignCircuitSource::ZkBuiltin
            | crate::trace::TraceSignCircuitSource::SecpBuiltin
            | crate::trace::TraceSignCircuitSource::EthPersonalSecpBuiltin => SignContext::new(pk_info.fingerprint),
            crate::trace::TraceSignCircuitSource::PsySoftwareDefined { .. } => {
                anyhow::ensure!(
                    !zs.sign_witness.is_empty(),
                    "stateless graph signing requires trace sign_witness for PSY software-defined signing"
                );
                let signature_input: DPNSoftwareDefinedSignatureInput = bincode::deserialize(&zs.sign_witness)?;
                SignContext::new(pk_info.fingerprint).with_psy_signature_input(
                    signature_input,
                    trace.finalization.submit_end_cap_input.core.checkpoint_id.to_canonical_u64(),
                    trace.meta.user_id,
                    current_header.current_state.user_leaf.user_state_tree_root,
                    trace.finalization.submit_end_cap_input.core.state_transition.checkpoint_tree_root_hash,
                )
            }
            crate::trace::TraceSignCircuitSource::Plonky2SoftwareDefined { .. } => {
                anyhow::ensure!(
                    !zs.sign_witness.is_empty(),
                    "stateless graph signing requires trace sign_witness for Plonky2 software-defined signing"
                );
                let signature_input: Plonky2SoftwareDefinedSignatureInput = bincode::deserialize(&zs.sign_witness)?;
                SignContext::new(pk_info.fingerprint)
                    .with_contract_id(Some(DEFAULT_CALLER_CONTRACT_ID_U64))
                    .with_sign_inputs(trace.finalization.software_defined_call.inputs.clone())
                    .with_plonky2_signature_input(
                        signature_input,
                        trace.finalization.submit_end_cap_input.core.checkpoint_id.to_canonical_u64(),
                        trace.meta.user_id,
                        current_header.current_state.user_leaf.user_state_tree_root,
                        trace.finalization.submit_end_cap_input.core.state_transition.checkpoint_tree_root_hash,
                    )
            }
            crate::trace::TraceSignCircuitSource::SdKey { .. } => {
                if !zs.sign_witness.is_empty() {
                    let signature_input: SDKeyCircuitWitnessInput = bincode::deserialize(&zs.sign_witness)?;
                    SignContext::new(pk_info.fingerprint)
                        .with_sign_inputs(trace.finalization.software_defined_call.inputs.clone())
                        .with_sd_key_signature_input(
                            signature_input,
                            current_header.session_start_context.checkpoint_id.to_canonical_u64(),
                            current_header.session_start_context.start_session_user_leaf.user_id.to_canonical_u64(),
                            current_header.current_state.user_leaf.user_state_tree_root,
                            current_header.session_start_context.checkpoint_tree_root,
                        )
                } else {
                    self.build_sd_key_context_from_trace(
                        &trace.finalization.software_defined_call,
                        pk_info.fingerprint,
                        &trace.steps,
                        current_header,
                    )
                    .await?
                }
            }
        };

        let sighash = UserProvingSessionManager::<F, PoseidonHash, RpcProvider, C, D>::compute_sighash_from_header(
            PSY_NETWORK_MAGIC,
            F::from_canonical_u64(trace.meta.user_id),
            current_header,
            trace.finalization.nonce,
        );
        self.wallet.sign_with_public_key(&public_key, &sign_context, sighash).await
    }

    /// Stateless external proof insertion: rebuilds manager from JS state,
    /// inserts external proof, returns updated meta.
    pub async fn insert_external_proof(
        &self,
        _public_key: QHashOut<F>,
        trace: &crate::trace::TxTrace,
        meta: &ProofTreeMeta,
        baton: LastStepProofInfo,
        current_header: &UserProvingSessionHeader<F>,
        previous_header: &UserProvingSessionHeader<F>,
        fingerprint: QHashOut<F>,
        proof: ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<ProofTreeMeta> {
        let mut mgr = self.build_step_manager(trace).await?;
        Self::restore_manager_state(&mut mgr, meta, baton, current_header.clone(), previous_header.clone());
        let proof_tree_start_root = mgr.proof_tree_state.get_proof_tree_root().await;
        let verifier_data = trace.steps.iter().find_map(|step| match step {
            crate::trace::TraceStep::ExternalProof(external)
                if external.fingerprint == fingerprint && external.proof_tree_start_root == proof_tree_start_root =>
            {
                Some(external.verifier_data_alt.to_verifier_data::<C, D>())
            }
            _ => None,
        });
        let verifier_data = if let Some(verifier_data) = verifier_data {
            verifier_data
        } else {
            let cm = self.wallet.random_circuit_manager();
            const EXT_LEAF: u64 = 4;
            Self::lookup_verifier_data(cm.as_ref(), trace, EXT_LEAF, fingerprint).await?
        };

        mgr.add_external_proof(fingerprint, proof, verifier_data).await;

        let next_meta = ProofTreeMeta::from_portable_manager(&mgr.proof_tree_state);
        let mut all_meta = meta.clone();
        all_meta.leaf_records.extend(next_meta.leaf_records);
        all_meta.next_leaf_index = next_meta.next_leaf_index;
        all_meta.root_history = next_meta.root_history;
        all_meta.proof_tree = next_meta.proof_tree;
        Ok(all_meta)
    }

    /// Stateless end-cap prove: reconstructs leaf_proofs from leaf metadata
    /// (insertion_proof from ProofTreeMeta.leaf_records) + proof blobs (from
    /// trace) + verifier_data (looked up from circuit manager), adds ZkSign
    /// leaf, runs finalize_tree, and produces the end-cap proof.
    /// Does NOT sign (signature_proof comes from JS) and does NOT submit.
    pub async fn prove_end_cap_proof(
        &self,
        _public_key: QHashOut<F>,
        trace: &crate::trace::TxTrace,
        meta: &ProofTreeMeta,
        all_proof_blobs: Vec<ProofWithPublicInputs<F, C, D>>,
        baton: LastStepProofInfo,
        signature_proof: ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, QHashOut<F>)> {
        use psy_crypto::common::witnesses::qrecursion::proof_data::LeafProofRecord;

        let mut mgr = self.build_step_manager(trace).await?;
        let cm = self.wallet.random_circuit_manager();

        // Restore proof tree from meta (hash tree only, no leaf_proofs)
        mgr.proof_tree_state
            .restore_snapshot(meta.to_merkle_tree(), meta.root_history.clone(), meta.next_leaf_index);
        // Set baton (needed by get_verify_previous_ups_step_proof_for)
        mgr.set_last_ups_step_proof_info(baton);

        // Reconstruct LeafProofRecords from: leaf metadata (from meta) + proof
        // blobs (from JS/trace) + verifier_data (looked up from circuit manager).
        anyhow::ensure!(
            meta.leaf_records.len() == all_proof_blobs.len(),
            "leaf_records ({}) != proof_blobs ({})",
            meta.leaf_records.len(),
            all_proof_blobs.len(),
        );

        let mut records = Vec::with_capacity(all_proof_blobs.len());
        for (lr, proof) in meta.leaf_records.iter().zip(all_proof_blobs.into_iter()) {
            let verifier_data = if lr.leaf_circuit_type_id == 4 {
                trace.steps.iter().find_map(|step| match step {
                    crate::trace::TraceStep::ExternalProof(external) if external.fingerprint == lr.fingerprint => {
                        Some(external.verifier_data_alt.to_verifier_data::<C, D>())
                    }
                    _ => None,
                })
            } else {
                None
            };
            let verifier_data = if let Some(verifier_data) = verifier_data {
                verifier_data
            } else {
                Self::lookup_verifier_data(cm.as_ref(), trace, lr.leaf_circuit_type_id, lr.fingerprint).await?
            };
            records.push(LeafProofRecord {
                leaf_circuit_type: lr.leaf_circuit_type_id,
                fingerprint: lr.fingerprint,
                insertion_proof: lr.insertion_proof.clone(),
                proof,
                verifier_data,
            });
        }
        mgr.proof_tree_state.restore_leaf_proofs_from_records(records);

        // Derive headers + ZkSign step from trace
        let mut cfc_headers: Vec<_> = trace
            .steps
            .iter()
            .filter_map(crate::trace::TraceStep::as_cfc)
            .map(|cfc| cfc.end_header.clone())
            .collect();
        anyhow::ensure!(!cfc_headers.is_empty(), "trace has no CFC steps to finalize");
        let prev_header = cfc_headers.pop().unwrap();
        let second_to_last_header = cfc_headers.pop().unwrap_or_else(|| trace.ups_start_witness.ups_header.clone());

        let zs = trace
            .steps
            .last()
            .and_then(|step| match step {
                crate::trace::TraceStep::ZkSign(zs) => Some(zs.clone()),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("trace is missing terminal ZkSign step"))?;

        self.ensure_trace_sign_circuit_registered(zs.fingerprint, &zs.sign_circuit_source).await?;

        let end_cap_proof = mgr
            .prove_end_cap_step(
                cm.as_ref(),
                PSY_NETWORK_MAGIC,
                F::from_canonical_u64(trace.meta.user_id),
                &prev_header,
                second_to_last_header.current_state.tx_hash_stack,
                trace.finalization.nonce,
                trace.finalization.submit_end_cap_input.core.stats.slots_modified,
                zs.fingerprint,
                zs.public_key_param,
                signature_proof,
                zs.sign_verifier_data_alt.to_verifier_data::<C, D>(),
                Some(zs.proof_tree_end_root),
            )
            .await?;

        Ok((end_cap_proof, trace.finalization.tx_hash))
    }

    /// Submit a pre-proven end-cap proof (RPC only). Stateless — no manager
    /// needed.
    pub async fn submit_end_cap(&self, trace: &crate::trace::TxTrace, end_cap_proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<QHashOut<F>> {
        let user_id = trace.finalization.submit_end_cap_input.core.new_user_leaf.user_id.to_noncanonical_u64();
        self.check_submit_anchor(
            user_id,
            trace.finalization.submit_end_cap_input.core.state_transition.start_user_leaf_hash,
        )
        .await?;
        self.check_user_state(user_id, trace.finalization.nonce).await?;
        let req = QSubmitEndCapRPCRequest {
            user_ec_input: trace.finalization.submit_end_cap_input.clone(),
            proof: bincode::serialize(&end_cap_proof)?,
        };
        let tx_hash = trace.finalization.tx_hash;
        let _ = self.st_provider.with_user_id_owned(user_id).submit_end_cap_proof::<F>(req).await?;
        Ok(tx_hash)
    }

    /// Look up verifier_data for a leaf by its circuit type and fingerprint.
    /// CFC leaves need contract-method-specific verifier_data, which requires
    /// the circuit manager to have the contract registered.
    async fn lookup_verifier_data(
        cm: &dyn psy_vm::ups::circuit_manager::UPSCircuitManager<C, D>,
        trace: &crate::trace::TxTrace,
        leaf_circuit_type: u64,
        fingerprint: QHashOut<F>,
    ) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        const UPS_STEP_LEAF: u64 = 1;
        const CFC_LEAF: u64 = 2;
        const ZK_SIG_LEAF: u64 = 3;
        const EXT_LEAF: u64 = 4;

        match leaf_circuit_type {
            UPS_STEP_LEAF => {
                let std_fp = cm.ups_cfc_standard_tx_circuit_fingerprint().await?;
                let def_fp = cm.ups_cfc_deferred_tx_circuit_fingerprint().await?;
                let start_fp = cm.ups_start_circuit_fingerprint().await?;
                let start_reg_fp = cm.ups_start_register_user_circuit_fingerprint().await?;
                if fingerprint == std_fp {
                    cm.ups_cfc_standard_tx_circuit_verifier_config().await
                } else if fingerprint == def_fp {
                    cm.ups_cfc_deferred_tx_circuit_verifier_config().await
                } else if fingerprint == start_fp {
                    cm.ups_start_circuit_verifier_config().await
                } else if fingerprint == start_reg_fp {
                    cm.ups_start_register_user_circuit_verifier_config().await
                } else {
                    anyhow::bail!("unknown UPS step fingerprint: {}", fingerprint)
                }
            }
            CFC_LEAF => {
                for cfc in trace.steps.iter().filter_map(crate::trace::TraceStep::as_cfc) {
                    let (fp, verifier) = cm.get_contract_method_common_data(cfc.contract_id, cfc.fn_id).await?;
                    if fp == fingerprint {
                        return Ok(verifier);
                    }
                }
                anyhow::bail!("unknown CFC fingerprint in trace: {}", fingerprint)
            }
            ZK_SIG_LEAF => cm.zk_signature_minifier_verifier_config().await,
            EXT_LEAF => {
                let note_fp = cm.private_note_inclusion_minifier_fingerprint().await?;
                let shield_fp = cm.shield_deposit_claim_minifier_fingerprint().await?;
                if fingerprint == note_fp {
                    cm.private_note_inclusion_minifier_verifier_config().await
                } else if fingerprint == shield_fp {
                    cm.shield_deposit_claim_minifier_verifier_config().await
                } else {
                    anyhow::bail!("unknown external proof fingerprint: {}", fingerprint)
                }
            }
            _ => anyhow::bail!("unknown leaf_circuit_type: {}", leaf_circuit_type),
        }
    }

    async fn finalize_trace(&self, public_key: QHashOut<F>, trace: &crate::trace::TxTrace, state: TraceStepsState) -> anyhow::Result<QHashOut<F>> {
        let user_id = trace.finalization.submit_end_cap_input.core.new_user_leaf.user_id.to_noncanonical_u64();
        self.check_submit_anchor(
            user_id,
            trace.finalization.submit_end_cap_input.core.state_transition.start_user_leaf_hash,
        )
        .await?;

        let TraceStepsState {
            prev_header,
            second_to_last_header,
            zksign_step,
        } = state;
        let zs = zksign_step.ok_or_else(|| anyhow::anyhow!("trace is missing terminal ZkSign step"))?;

        let mut user_session_mgr = self
            .user_session_mgrs
            .get_mut(&public_key)
            .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;

        let pk_info = self.wallet.get_public_key_info(&public_key).await?;
        anyhow::ensure!(
            zs.fingerprint == pk_info.fingerprint,
            "trace signing fingerprint {} does not match wallet key fingerprint {}",
            zs.fingerprint,
            pk_info.fingerprint
        );
        self.ensure_trace_sign_circuit_registered(pk_info.fingerprint, &zs.sign_circuit_source)
            .await?;
        let mut sign_context = SignContext::new(pk_info.fingerprint);
        match &zs.sign_circuit_source {
            crate::trace::TraceSignCircuitSource::ZkBuiltin
            | crate::trace::TraceSignCircuitSource::SecpBuiltin
            | crate::trace::TraceSignCircuitSource::EthPersonalSecpBuiltin => {}
            crate::trace::TraceSignCircuitSource::PsySoftwareDefined { .. } => {
                if !zs.sign_witness.is_empty() {
                    let signature_input: DPNSoftwareDefinedSignatureInput = bincode::deserialize(&zs.sign_witness)?;
                    sign_context = sign_context.with_psy_signature_input(
                        signature_input,
                        trace.finalization.submit_end_cap_input.core.checkpoint_id.to_canonical_u64(),
                        trace.meta.user_id,
                        prev_header.current_state.user_leaf.user_state_tree_root,
                        trace.finalization.submit_end_cap_input.core.state_transition.checkpoint_tree_root_hash,
                    );
                } else {
                    sign_context = self
                        .build_psy_software_defined_context(
                            &trace.finalization.software_defined_call,
                            pk_info.fingerprint,
                            &mut user_session_mgr,
                            sign_context,
                        )
                        .await?;
                }
            }
            crate::trace::TraceSignCircuitSource::Plonky2SoftwareDefined { .. } => {
                if !zs.sign_witness.is_empty() {
                    let signature_input: Plonky2SoftwareDefinedSignatureInput = bincode::deserialize(&zs.sign_witness)?;
                    sign_context = SignContext::new(pk_info.fingerprint)
                        .with_contract_id(Some(DEFAULT_CALLER_CONTRACT_ID_U64))
                        .with_sign_inputs(trace.finalization.software_defined_call.inputs.clone())
                        .with_plonky2_signature_input(
                            signature_input,
                            trace.finalization.submit_end_cap_input.core.checkpoint_id.to_canonical_u64(),
                            trace.meta.user_id,
                            prev_header.current_state.user_leaf.user_state_tree_root,
                            trace.finalization.submit_end_cap_input.core.state_transition.checkpoint_tree_root_hash,
                        );
                } else {
                    sign_context = self
                        .build_plonky2_software_defined_context(&trace.finalization.software_defined_call, pk_info.fingerprint, &mut user_session_mgr)
                        .await?;
                }
            }
            crate::trace::TraceSignCircuitSource::SdKey { .. } => {
                if !zs.sign_witness.is_empty() {
                    let signature_input: SDKeyCircuitWitnessInput = bincode::deserialize(&zs.sign_witness)?;
                    sign_context = SignContext::new(pk_info.fingerprint)
                        .with_sign_inputs(trace.finalization.software_defined_call.inputs.clone())
                        .with_sd_key_signature_input(
                            signature_input,
                            prev_header.session_start_context.checkpoint_id.to_canonical_u64(),
                            prev_header.session_start_context.start_session_user_leaf.user_id.to_canonical_u64(),
                            prev_header.current_state.user_leaf.user_state_tree_root,
                            prev_header.session_start_context.checkpoint_tree_root,
                        );
                } else {
                    sign_context = self
                        .build_sd_key_context_step(
                            &trace.finalization.software_defined_call,
                            pk_info.fingerprint,
                            &user_session_mgr,
                            &trace.steps,
                            &prev_header,
                        )
                        .await?;
                }
            }
        }
        let sighash = UserProvingSessionManager::<F, PoseidonHash, RpcProvider, C, D>::compute_sighash_from_header(
            PSY_NETWORK_MAGIC,
            F::from_canonical_u64(trace.meta.user_id),
            &prev_header,
            trace.finalization.nonce,
        );
        let signature_result = self.wallet.sign_with_public_key(&public_key, &sign_context, sighash).await?;
        let signature_proof = signature_result.proof;
        let zk_sig_fingerprint = signature_result.circuit_info.circuit_fingerprint;
        let zk_sig_verifier_config = signature_result.circuit_info.verifier_config;

        let end_cap_proof = user_session_mgr
            .prove_end_cap_step(
                self.wallet.random_circuit_manager().as_ref(),
                PSY_NETWORK_MAGIC,
                F::from_canonical_u64(trace.meta.user_id),
                &prev_header,
                second_to_last_header.current_state.tx_hash_stack,
                trace.finalization.nonce,
                trace.finalization.submit_end_cap_input.core.stats.slots_modified,
                zk_sig_fingerprint,
                pk_info.public_key_param,
                signature_proof,
                zk_sig_verifier_config,
                Some(zs.proof_tree_end_root),
            )
            .await?;

        drop(user_session_mgr);

        let req = QSubmitEndCapRPCRequest {
            user_ec_input: trace.finalization.submit_end_cap_input.clone(),
            proof: bincode::serialize(&end_cap_proof)?,
        };
        let tx_hash = trace.finalization.tx_hash;
        self.check_user_state(user_id, trace.finalization.nonce).await?;
        let _ = self.st_provider.with_user_id_owned(user_id).submit_end_cap_proof::<F>(req).await?;
        Ok(tx_hash)
    }
}

/// Header chain + terminal zksign produced by
/// [`WalletSession::prove_trace_steps`], consumed by
/// [`WalletSession::finalize_trace`].
struct TraceStepsState {
    prev_header: UserProvingSessionHeader<F>,
    second_to_last_header: UserProvingSessionHeader<F>,
    zksign_step: Option<crate::trace::ZkSignStep>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvingState {
    pub proof_tree_meta: ProofTreeMeta,
    pub last_step_info: LastStepProofInfo,
    pub current_header: UserProvingSessionHeader<F>,
    pub previous_header: UserProvingSessionHeader<F>,
}

#[derive(Clone, Debug)]
pub enum TraceProvingStepResult {
    Progress { state: ProvingState, proofs: Vec<Vec<u8>> },
    Submitted(QHashOut<F>),
    Failed { error: String },
}

pub type TraceCfcProofBytes = (Vec<u8>, Vec<u8>);
pub type TraceCfcJobOutput = (TraceCfcProofBytes, ProofTreeMeta, LastStepProofInfo);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum TraceProofJobOutput {
    UpsStart {
        proof: Vec<u8>,
        meta: ProofTreeMeta,
        baton: LastStepProofInfo,
        current_header: UserProvingSessionHeader<F>,
        previous_header: UserProvingSessionHeader<F>,
    },
    CfcStep {
        step_index: usize,
        proof_bytes: TraceCfcProofBytes,
        meta: ProofTreeMeta,
        baton: LastStepProofInfo,
    },
    ExternalProof {
        step_index: usize,
        proof: Vec<u8>,
    },
    ZkSign {
        proof: Vec<u8>,
    },
    EndCap {
        proof: Vec<u8>,
        tx_hash: QHashOut<F>,
    },
    Submit {
        tx_hash: QHashOut<F>,
    },
}

#[derive(Default)]
pub struct TraceCfcJobArtifacts {
    pub proof_blobs: BTreeMap<usize, TraceCfcProofBytes>,
    pub step_meta: BTreeMap<usize, ProofTreeMeta>,
    pub step_baton: BTreeMap<usize, LastStepProofInfo>,
}

impl TraceCfcJobArtifacts {
    fn insert(&mut self, step_index: usize, proof_bytes: TraceCfcProofBytes, meta: ProofTreeMeta, baton: LastStepProofInfo) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.proof_blobs.insert(step_index, proof_bytes).is_none(),
            "duplicate CFC proof output for step {}",
            step_index
        );
        self.step_meta.insert(step_index, meta);
        self.step_baton.insert(step_index, baton);
        Ok(())
    }
}

fn decode_proof_bytes(bytes: &[u8]) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    Ok(bincode::deserialize(bytes)?)
}

fn cfc_proofs_to_record(p: &psy_ups_circuit::session::CfcStepProofs<C>) -> anyhow::Result<crate::trace::CfcProofRecord> {
    Ok(crate::trace::CfcProofRecord {
        cfc_proof: bincode::serialize(&p.cfc_proof)?,
        ups_proof: bincode::serialize(&p.ups_proof)?,
        ..Default::default()
    })
}

fn cfc_record_to_proofs(r: &crate::trace::CfcProofRecord) -> anyhow::Result<psy_ups_circuit::session::CfcStepProofs<C>> {
    Ok(psy_ups_circuit::session::CfcStepProofs {
        cfc_proof: decode_proof_bytes(&r.cfc_proof)?,
        ups_proof: decode_proof_bytes(&r.ups_proof)?,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletKeyPair {
    pub private_key: QHashOut<F>,
    pub public_key: ZKPublicKeyInfo<F>,
}

#[cfg(all(not(target_arch = "wasm32"), feature = "is_sync"))]
mod tests {
    use std::{path::Path, thread, time::Duration};

    use super::*;

    #[test]
    fn test_scenario0() -> anyhow::Result<()> {
        psy_client_common::setup_logging()?;
        tracing::info!("test_scenario0");
        let project_path =
            std::env::var("CARGO_MANIFEST_DIR").map_err(|e| anyhow::format_err!("Error `{}`, cannot get CARGO_MANIFEST_DIR env", e))?;

        let private_key0 = QHashOut::<GoldilocksField>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;
        let private_key1 = QHashOut::<GoldilocksField>::from_str("f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d")?;

        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&Path::new(&project_path).join("../../../config.json").to_string_lossy())?;
        let rpc_config = psy_config.get_current_network()?;

        let circuit_defs = serde_json::from_str::<Vec<DPNFunctionCircuitDefinition>>(&std::fs::read_to_string(
            Path::new(&project_path).join("../examples/target/examples.json"),
        )?)?;

        let mut wallet_session = super::WalletSession::new(&rpc_config)?;

        let deployer_pk_info = wallet_session.get_zk_public_key(private_key0)?;
        wallet_session.deploy_contract(deployer_pk_info.qfhash::<PsyHasher>(), circuit_defs)?;

        let user0 = wallet_session.register_user(private_key0)?;
        let user1 = wallet_session.register_user(private_key0)?;

        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));

        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));
        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));

        // add user0
        wallet_session.add_user(private_key0)?;

        // add user1
        wallet_session.add_user(private_key1)?;

        // user0 mint 1000
        wallet_session.exec_contract_call(
            user0,
            vec![ContractCallArgs {
                contract_id: 0,
                method_name: "simple_mint".to_string(),
                inputs: vec![1_000_000_000_000],
            }],
        )?;

        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));
        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));

        // user0 transfer 500 to user1
        wallet_session.exec_contract_call(
            user0,
            vec![ContractCallArgs {
                contract_id: 0,
                method_name: "simple_transfer".to_string(),
                inputs: vec![1, 500],
            }],
        )?;

        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));
        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));

        // user1 claim
        wallet_session.exec_contract_call(
            user1,
            vec![ContractCallArgs {
                contract_id: 0,
                method_name: "simple_claim".to_string(),
                inputs: vec![0],
            }],
        )?;

        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));
        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));

        // user1 transfer 500 to user0
        wallet_session.exec_contract_call(
            user1,
            vec![ContractCallArgs {
                contract_id: 0,
                method_name: "simple_transfer".to_string(),
                inputs: vec![0, 500],
            }],
        )?;

        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));
        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));

        Ok(())
    }

    #[test]
    fn test_two_contracts() -> anyhow::Result<()> {
        psy_client_common::setup_logging()?;
        tracing::info!("test_two_contracts");
        let project_path =
            std::env::var("CARGO_MANIFEST_DIR").map_err(|e| anyhow::format_err!("Error `{}`, cannot get CARGO_MANIFEST_DIR env", e))?;

        let private_key0 = QHashOut::<GoldilocksField>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;
        let private_key1 = QHashOut::<GoldilocksField>::from_str("f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d")?;

        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&Path::new(&project_path).join("../../../config.json").to_string_lossy())?;
        let rpc_config = psy_config.get_current_network()?;

        let circuit_defs = serde_json::from_str::<Vec<DPNFunctionCircuitDefinition>>(&std::fs::read_to_string(
            Path::new(&project_path).join("../examples/target/examples.json"),
        )?)?;

        let mut wallet_session = super::WalletSession::new(&rpc_config)?;

        let deployer_pk_info = wallet_session.get_zk_public_key(private_key0)?;
        wallet_session.deploy_contract(deployer_pk_info.qfhash::<PsyHasher>(), circuit_defs.clone())?;
        wallet_session.deploy_contract(deployer_pk_info.qfhash::<PsyHasher>(), circuit_defs)?;

        let user0 = wallet_session.register_user(private_key0)?;
        let user1 = wallet_session.register_user(private_key0)?;

        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));

        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));
        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));

        // add user0
        wallet_session.add_user(private_key0)?;

        // add user1
        wallet_session.add_user(private_key1)?;

        // user0 mint 1000 contract 0
        wallet_session.exec_contract_call(
            user0,
            vec![ContractCallArgs {
                contract_id: 0,
                method_name: "simple_mint".to_string(),
                inputs: vec![1_000_000_000_000],
            }],
        )?;

        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));
        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));

        // user0 mint 1000 contract 1
        wallet_session.exec_contract_call(
            user0,
            vec![ContractCallArgs {
                contract_id: 1,
                method_name: "simple_mint".to_string(),
                inputs: vec![1_000_000_000_000],
            }],
        )?;

        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));
        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));

        Ok(())
    }

    #[test]
    fn test_generate_prove_simple_mint() -> anyhow::Result<()> {
        psy_client_common::setup_logging()?;
        tracing::info!("test_generate_prove_simple_mint");
        let project_path =
            std::env::var("CARGO_MANIFEST_DIR").map_err(|e| anyhow::format_err!("Error `{}`, cannot get CARGO_MANIFEST_DIR env", e))?;

        let private_key0 = QHashOut::<GoldilocksField>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;

        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&Path::new(&project_path).join("../../../config.json").to_string_lossy())?;
        let rpc_config = psy_config.get_current_network()?;

        let circuit_defs = serde_json::from_str::<Vec<DPNFunctionCircuitDefinition>>(&std::fs::read_to_string(
            Path::new(&project_path).join("../examples/target/examples.json"),
        )?)?;

        let mut wallet_session = super::WalletSession::new(&rpc_config)?;

        let deployer_pk_info = wallet_session.get_zk_public_key(private_key0)?;
        wallet_session.deploy_contract(deployer_pk_info.qfhash::<PsyHasher>(), circuit_defs)?;

        let user0 = wallet_session.register_user(private_key0)?;
        thread::sleep(Duration::from_secs(20));
        thread::sleep(Duration::from_secs(20));
        thread::sleep(Duration::from_secs(20));

        wallet_session.add_user(private_key0)?;

        // Generate trace: simple mint
        tracing::info!("=== generate_tx_trace: simple_mint ===");
        let call_data = ContractCallData::new(vec![ContractCallArgs {
            contract_id: 0,
            method_name: "simple_mint".to_string(),
            inputs: vec![1_000_000_000_000],
        }]);
        let trace = wallet_session.generate_tx_trace(user0, call_data)?;
        tracing::info!("trace generated: {} steps, tx_hash={}", trace.steps.len(), trace.finalization.tx_hash);
        assert!(!trace.steps.is_empty(), "trace must have at least one step");
        assert_eq!(trace.meta.user_id, 0, "user_id should be 0");

        // Prove + submit from trace
        tracing::info!("=== prove_tx_trace ===");
        let tx_hash = wallet_session.prove_tx_trace(user0, &trace)?;
        tracing::info!("tx submitted: {}", tx_hash);

        Ok(())
    }

    #[test]
    fn test_generate_prove_multicall() -> anyhow::Result<()> {
        psy_client_common::setup_logging()?;
        tracing::info!("test_generate_prove_multicall");
        let project_path =
            std::env::var("CARGO_MANIFEST_DIR").map_err(|e| anyhow::format_err!("Error `{}`, cannot get CARGO_MANIFEST_DIR env", e))?;

        let private_key0 = QHashOut::<GoldilocksField>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;

        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&Path::new(&project_path).join("../../../config.json").to_string_lossy())?;
        let rpc_config = psy_config.get_current_network()?;

        let circuit_defs = serde_json::from_str::<Vec<DPNFunctionCircuitDefinition>>(&std::fs::read_to_string(
            Path::new(&project_path).join("../examples/target/examples.json"),
        )?)?;

        let mut wallet_session = super::WalletSession::new(&rpc_config)?;

        let deployer_pk_info = wallet_session.get_zk_public_key(private_key0)?;
        wallet_session.deploy_contract(deployer_pk_info.qfhash::<PsyHasher>(), circuit_defs.clone())?;
        wallet_session.deploy_contract(deployer_pk_info.qfhash::<PsyHasher>(), circuit_defs)?;

        let user0 = wallet_session.register_user(private_key0)?;
        thread::sleep(Duration::from_secs(20));
        thread::sleep(Duration::from_secs(20));
        thread::sleep(Duration::from_secs(20));

        wallet_session.add_user(private_key0)?;

        // Generate trace: multicall (mint on contract 0 + mint on contract 1)
        tracing::info!("=== generate_tx_trace: multicall ===");
        let call_data = ContractCallData::new(vec![
            ContractCallArgs {
                contract_id: 0,
                method_name: "simple_mint".to_string(),
                inputs: vec![1_000_000_000_000],
            },
            ContractCallArgs {
                contract_id: 1,
                method_name: "simple_mint".to_string(),
                inputs: vec![2_000_000_000_000],
            },
        ]);
        let trace = wallet_session.generate_tx_trace(user0, call_data)?;
        tracing::info!("trace generated: {} steps", trace.steps.len());

        // Should have 2 standard steps + 1 burn fee
        let standard_count = trace.steps.iter().filter(|s| matches!(s, crate::trace::TraceStep::Standard(_))).count();
        assert_eq!(standard_count, 2, "should have 2 standard steps for multicall");

        // Prove + submit
        tracing::info!("=== prove_tx_trace ===");
        let tx_hash = wallet_session.prove_tx_trace(user0, &trace)?;
        tracing::info!("tx submitted: {}", tx_hash);

        Ok(())
    }

    #[test]
    fn test_generate_prove_deferred() -> anyhow::Result<()> {
        psy_client_common::setup_logging()?;
        tracing::info!("test_generate_prove_deferred");
        let project_path =
            std::env::var("CARGO_MANIFEST_DIR").map_err(|e| anyhow::format_err!("Error `{}`, cannot get CARGO_MANIFEST_DIR env", e))?;

        let private_key0 = QHashOut::<GoldilocksField>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;
        let private_key1 = QHashOut::<GoldilocksField>::from_str("f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d")?;

        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&Path::new(&project_path).join("../../../config.json").to_string_lossy())?;
        let rpc_config = psy_config.get_current_network()?;

        let circuit_defs = serde_json::from_str::<Vec<DPNFunctionCircuitDefinition>>(&std::fs::read_to_string(
            Path::new(&project_path).join("../examples/target/examples.json"),
        )?)?;

        let mut wallet_session = super::WalletSession::new(&rpc_config)?;

        let deployer_pk_info = wallet_session.get_zk_public_key(private_key0)?;
        wallet_session.deploy_contract(deployer_pk_info.qfhash::<PsyHasher>(), circuit_defs)?;

        let user0 = wallet_session.register_user(private_key0)?;
        let user1 = wallet_session.register_user(private_key0)?;
        thread::sleep(Duration::from_secs(20));
        thread::sleep(Duration::from_secs(20));
        thread::sleep(Duration::from_secs(20));

        wallet_session.add_user(private_key0)?;
        wallet_session.add_user(private_key1)?;

        // First: user0 mints via generate+prove
        tracing::info!("=== generate+prove: user0 mint ===");
        let trace = wallet_session.generate_tx_trace(
            user0,
            ContractCallData::new(vec![ContractCallArgs {
                contract_id: 0,
                method_name: "simple_mint".to_string(),
                inputs: vec![1_000_000_000_000],
            }]),
        )?;
        wallet_session.prove_tx_trace(user0, &trace)?;
        thread::sleep(Duration::from_secs(20));
        thread::sleep(Duration::from_secs(20));

        // Then: user0 transfers to user1 (this creates a deferred call for user1's
        // claim)
        tracing::info!("=== generate+prove: user0 transfer to user1 ===");
        let trace = wallet_session.generate_tx_trace(
            user0,
            ContractCallData::new(vec![ContractCallArgs {
                contract_id: 0,
                method_name: "simple_transfer".to_string(),
                inputs: vec![1, 500],
            }]),
        )?;
        tracing::info!("trace steps: {}", trace.steps.len());
        wallet_session.prove_tx_trace(user0, &trace)?;
        thread::sleep(Duration::from_secs(20));
        thread::sleep(Duration::from_secs(20));

        // user1 claims
        tracing::info!("=== generate+prove: user1 claim ===");
        let trace = wallet_session.generate_tx_trace(
            user1,
            ContractCallData::new(vec![ContractCallArgs {
                contract_id: 0,
                method_name: "simple_claim".to_string(),
                inputs: vec![0],
            }]),
        )?;
        tracing::info!("trace steps: {}", trace.steps.len());
        wallet_session.prove_tx_trace(user1, &trace)?;

        Ok(())
    }
    #[test]
    fn private_transfer_claim_rejects_contract_relabel() {
        let error = ensure_private_transfer_contract_matches(5, 4).unwrap_err();
        assert!(error.to_string().contains("proof token_contract_id=4"));
    }

}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod async_split_tests {
    use std::{fs, path::Path, process::Command, str::FromStr, thread, time::Duration};

    use psy_client_data::{dpn::proving_session::DPNProvingSessionSimpleMethodCall, privacy::deposit_inclusion::DepositInclusionInput};
    use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
    use psy_crypto::shield_address::{
        derive_deposit_commitment, derive_note_commitment, derive_nullifier_hash, derive_shield_address, qhashout_to_bytes32_be, qhashout_to_u32x8_be,
    };
    use psy_dpn_circuit::circuits::privacy::{deposit_inclusion::DepositInclusionCircuit, private_note_inclusion::PrivateNoteInclusionCircuit};
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Deserialize)]
    struct LegacyNoteProofOutput {
        nullifier: [u64; 4],
        owner: [u64; 4],
        amount: u64,
        user_tree_root: [u64; 4],
        checkpoint_id: u64,
        note_root_slot: u64,
        token_contract_id: String,
        note_proof_fingerprint: [u64; 4],
        note_proof: Vec<u8>,
    }

    #[derive(Debug, Deserialize)]
    struct ApiResponse<T> {
        success: bool,
        data: Option<T>,
        error: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    struct DepositClaimProofDeposit {
        shield_address: String,
        token_address: String,
        l2_token_contract_id: String,
        amount: String,
        note_commitment: String,
        source_chain_id: u32,
    }

    #[derive(Debug, Deserialize)]
    struct DepositClaimProofResponse {
        found: bool,
        checkpoint_id: Option<u64>,
        deposit_index: Option<u64>,
        leaf_hash: Option<String>,
        siblings: Option<Vec<String>>,
        deposit_root: Option<String>,
        deposit: Option<DepositClaimProofDeposit>,
    }

    fn u64_to_u32x8_be(v: u64) -> [u32; 8] {
        [0, 0, 0, 0, 0, 0, (v >> 32) as u32, (v & 0xffff_ffff) as u32]
    }

    fn u32x8_be_to_u64(v: [u32; 8]) -> anyhow::Result<u64> {
        anyhow::ensure!(v[..6] == [0, 0, 0, 0, 0, 0], "u32x8 value does not fit into u64");
        Ok(((v[6] as u64) << 32) | v[7] as u64)
    }

    fn parse_evm_addr_or_bytes32_to_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
        let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))?;
        let bytes = match bytes.len() {
            20 => {
                let mut out = [0u8; 32];
                out[12..32].copy_from_slice(&bytes);
                out
            }
            32 => {
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                out
            }
            n => anyhow::bail!("expected 20-byte address or 32-byte bytes32 hex, got {} bytes", n),
        };
        let mut out = [0u32; 8];
        for i in 0..8 {
            out[i] = u32::from_be_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        Ok(out)
    }

    fn parse_qhash_internal_bytes_hex(hex_str: &str) -> anyhow::Result<QHashOut<F>> {
        let raw = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
        anyhow::ensure!(raw.len() == 64, "expected 32-byte hex for qhash, got {} hex chars", raw.len());
        let bytes = hex::decode(raw)?;
        let mut words = [0u32; 8];
        for i in 0..8 {
            words[i] = u32::from_be_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        Ok(QHashOut::from_values(
            (words[0] as u64) | ((words[1] as u64) << 32),
            (words[2] as u64) | ((words[3] as u64) << 32),
            (words[4] as u64) | ((words[5] as u64) << 32),
            (words[6] as u64) | ((words[7] as u64) << 32),
        ))
    }

    fn parse_qhash_bytes32_be(hex_str: &str) -> anyhow::Result<QHashOut<F>> {
        let raw = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
        anyhow::ensure!(raw.len() == 64, "expected 32-byte hex for qhash bytes32, got {} hex chars", raw.len());
        let bytes = hex::decode(raw)?;
        Ok(QHashOut::from_values(
            u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
            u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
            u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
        ))
    }

    fn parse_qhash_display_hex(hex_str: &str) -> anyhow::Result<QHashOut<F>> {
        QHashOut::<F>::from_str(hex_str.trim().trim_start_matches("0x").trim_start_matches("0X"))
            .map_err(|e| anyhow::anyhow!("Invalid qhash '{}': {}", hex_str, e))
    }

    fn parse_qhash_cli_input(input: &str) -> anyhow::Result<QHashOut<F>> {
        let raw = input.trim().trim_start_matches("0x").trim_start_matches("0X");
        if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
            return parse_qhash_bytes32_be(input);
        }
        QHashOut::<F>::from_str(raw).map_err(|e| anyhow::anyhow!("Invalid qhash '{}': {}", input, e))
    }

    fn qhash_to_u64x4(hash: QHashOut<F>) -> [u64; 4] {
        [
            hash.0.elements[0].to_canonical_u64(),
            hash.0.elements[1].to_canonical_u64(),
            hash.0.elements[2].to_canonical_u64(),
            hash.0.elements[3].to_canonical_u64(),
        ]
    }

    async fn setup_wallet_and_users_with_keys() -> anyhow::Result<(
        WalletSession,
        WalletKeyPair,
        QHashOut<GoldilocksField>,
        u64,
        WalletKeyPair,
        QHashOut<GoldilocksField>,
        u64,
    )> {
        psy_client_common::setup_logging()?;
        let project_path =
            std::env::var("CARGO_MANIFEST_DIR").map_err(|e| anyhow::format_err!("Error `{}`, cannot get CARGO_MANIFEST_DIR env", e))?;
        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&Path::new(&project_path).join("../config.json").to_string_lossy())?;
        let mut rpc_config = psy_config.get_current_network()?.clone();
        rpc_config.prove_proxy_url.clear();

        let mut wallet_session = WalletSession::new(&rpc_config).await?;
        let user0_keys = wallet_session.get_random_keypair().await?;
        let user1_keys = wallet_session.get_random_keypair().await?;
        let user0_pk = user0_keys.public_key.clone();
        let user1_pk = user1_keys.public_key.clone();

        for _ in 0..60 {
            let realm_ok = wallet_session.st_provider.get_latest_block_state().await.is_ok();
            let tree_ok = wallet_session.st_provider.get_checkpoint_tree_root(0).await.is_ok();
            if realm_ok && tree_ok {
                break;
            }
            thread::sleep(Duration::from_secs(5));
        }

        let user0 = {
            let mut last_err = None;
            let mut value = None;
            for _ in 0..30 {
                match wallet_session.register_user(user0_keys.private_key, user0_pk.fingerprint).await {
                    Ok(v) => {
                        value = Some(v);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        thread::sleep(Duration::from_secs(5));
                    }
                }
            }
            value.ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("register_user(user0) failed")))?
        };
        let user1 = {
            let mut last_err = None;
            let mut value = None;
            for _ in 0..30 {
                match wallet_session.register_user(user1_keys.private_key, user1_pk.fingerprint).await {
                    Ok(v) => {
                        value = Some(v);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        thread::sleep(Duration::from_secs(5));
                    }
                }
            }
            value.ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("register_user(user1) failed")))?
        };
        let user0_id = loop {
            match wallet_session.resolve_registered_user_id(user0).await {
                Ok(v) => break v,
                Err(_) => thread::sleep(Duration::from_secs(5)),
            }
        };
        let user1_id = loop {
            match wallet_session.resolve_registered_user_id(user1).await {
                Ok(v) => break v,
                Err(_) => thread::sleep(Duration::from_secs(5)),
            }
        };
        for _ in 0..60 {
            let u0_ok = wallet_session
                .add_user_with_user_id(user0_keys.private_key, user0_pk.fingerprint, user0_id)
                .await
                .is_ok();
            let u1_ok = wallet_session
                .add_user_with_user_id(user1_keys.private_key, user1_pk.fingerprint, user1_id)
                .await
                .is_ok();
            if u0_ok && u1_ok {
                if let Some(mut mgr) = wallet_session.user_session_mgrs.get_mut(&user0) {
                    mgr.require_lps_mut().unwrap().set_is_new_user(false);
                }
                if let Some(mut mgr) = wallet_session.user_session_mgrs.get_mut(&user1) {
                    mgr.require_lps_mut().unwrap().set_is_new_user(false);
                }
                wait_for_user_registered_on_realm(&wallet_session, user0_id).await?;
                wait_for_user_registered_on_realm(&wallet_session, user1_id).await?;
                return Ok((wallet_session, user0_keys, user0, user0_id, user1_keys, user1, user1_id));
            }
            thread::sleep(Duration::from_secs(5));
        }
        anyhow::bail!("timed out waiting for add_user_with_user_id to succeed against provider")
    }

    async fn wait_for_user_nonce_gt(wallet_session: &WalletSession, user_id: u64, baseline_nonce: u64) -> anyhow::Result<u64> {
        for _ in 0..60 {
            let checkpoint_id = wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id;
            let user_leaf = wallet_session.st_provider.get_user_leaf_data(checkpoint_id, user_id).await?;
            let nonce = user_leaf.nonce.to_canonical_u64();
            if nonce > baseline_nonce {
                return Ok(checkpoint_id);
            }
            thread::sleep(Duration::from_secs(5));
        }
        anyhow::bail!("timed out waiting for user {} nonce to exceed {}", user_id, baseline_nonce)
    }

    async fn wait_for_user_registered_on_realm(wallet_session: &WalletSession, user_id: u64) -> anyhow::Result<u64> {
        let registration_id = get_registration_id_from_user_id(user_id);
        let provider = wallet_session.st_provider.with_user_id_owned(user_id);
        for _ in 0..120 {
            let checkpoint_id = wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id;
            let leaf_hash = provider.get_user_registration_tree_leaf_hash(checkpoint_id, registration_id).await?;
            if leaf_hash != QHashOut::ZERO {
                return Ok(checkpoint_id);
            }
            thread::sleep(Duration::from_secs(5));
        }
        anyhow::bail!(
            "timed out waiting for user {} registration leaf to appear on realm latest checkpoint",
            user_id
        )
    }

    async fn load_private_transfer_claim_from_file(
        wallet_session: &mut WalletSession,
        note_path: &Path,
        random0: u64,
        random1: u64,
    ) -> anyhow::Result<PrivateTransferClaim> {
        let note_data: LegacyNoteProofOutput = serde_json::from_str(&fs::read_to_string(note_path)?)?;
        let token_contract_id = note_data
            .token_contract_id
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("invalid token_contract_id in note proof: {}", e))?;
        let proof: ProofWithPublicInputs<F, C, D> =
            bincode::deserialize(&note_data.note_proof).map_err(|e| anyhow::anyhow!("invalid bincode proof: {}", e))?;
        let fingerprint = QHashOut::<F>::from_values(
            note_data.note_proof_fingerprint[0],
            note_data.note_proof_fingerprint[1],
            note_data.note_proof_fingerprint[2],
            note_data.note_proof_fingerprint[3],
        );
        let verifier_data = if let Ok(info) = wallet_session.circuit_info.get_circuit_info_by_fingerprint(fingerprint) {
            info.verifier_data.to_verifier_data::<C, D>()
        } else {
            let local = PrivateNoteInclusionCircuit::<C, D>::new(
                psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT as usize,
                psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize,
                psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT as usize,
                20,
            );
            let local_fingerprint = local.get_fingerprint();
            anyhow::ensure!(
                local_fingerprint == fingerprint,
                "local PrivateNoteInclusion fingerprint mismatch: payload={}, local={}",
                fingerprint,
                local_fingerprint
            );
            local.get_verifier_config_ref().clone()
        };
        Ok(PrivateTransferClaim {
            nullifier: note_data.nullifier,
            owner: note_data.owner,
            amount: note_data.amount,
            user_tree_root: note_data.user_tree_root,
            checkpoint_id: note_data.checkpoint_id,
            note_root_slot: note_data.note_root_slot,
            token_contract_id,
            random0,
            random1,
            note_proof_fingerprint: fingerprint,
            note_proof: proof,
            note_verifier_data: AltVerifierOnlyCircuitData::from(&verifier_data),
        })
    }

    async fn get_contract_slot_value(
        wallet_session: &WalletSession,
        user_id: u64,
        contract_id: u64,
        slot_index: u64,
    ) -> anyhow::Result<QHashOut<GoldilocksField>> {
        let checkpoint_id = wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id;
        let contract_leaf = wallet_session.st_provider.get_contract_leaf_data(contract_id).await?;
        let slot = wallet_session
            .st_provider
            .get_user_contract_state_tree_merkle_proof(
                checkpoint_id,
                user_id,
                contract_id as u32,
                contract_leaf.state_tree_height.to_canonical_u64() as u8,
                slot_index,
            )
            .await?;
        Ok(slot.value)
    }

    async fn wait_for_indexed_deposit(indexer_url: &str, tx_hash: &str) -> anyhow::Result<(u64, DepositClaimProofDeposit)> {
        let client = reqwest::Client::new();
        let tx_hash = tx_hash.to_lowercase();
        for _ in 0..240 {
            let query = format!(
                "{{ Deposit(where: {{ tx_hash: {{_eq: \\\"{}\\\"}}, chain_index: {{_eq: 0}} }}, order_by: {{deposit_index: desc}}, limit: 1) {{ tx_hash shield_address token_address: token l2_token_contract_id amount note_commitment source_chain_id: chain_index deposit_index }} }}",
                tx_hash
            );
            let body = serde_json::json!({ "query": query });
            let resp = client.post(indexer_url).json(&body).send().await?;
            let status = resp.status();
            let text = resp.text().await?;
            anyhow::ensure!(status.is_success(), "indexer query failed: status={} body={}", status, text);
            let json: serde_json::Value = serde_json::from_str(&text)?;
            if let Some(item) = json
                .get("data")
                .and_then(|d| d.get("Deposit"))
                .and_then(|d| d.as_array())
                .and_then(|arr| arr.first())
            {
                let deposit_index = item
                    .get("deposit_index")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow::anyhow!("missing deposit_index in indexer response"))?;
                let deposit: DepositClaimProofDeposit = serde_json::from_value(item.clone())?;
                return Ok((deposit_index, deposit));
            }
            thread::sleep(Duration::from_secs(5));
        }
        anyhow::bail!("timed out waiting for indexed deposit tx_hash={}", tx_hash)
    }

    async fn fetch_deposit_claim_proof(
        services_url: &str,
        deposit_index: u64,
    ) -> anyhow::Result<(QHashOut<F>, MerkleProofCore<QHashOut<F>>, DepositClaimProofDeposit, Option<u64>)> {
        let url = format!(
            "{}/api/v1/bridge/deposit-claim-proof?deposit_index={}",
            services_url.trim_end_matches('/'),
            deposit_index
        );
        let response = reqwest::Client::new().get(&url).send().await?;
        let status = response.status();
        let body = response.text().await?;
        anyhow::ensure!(status.is_success(), "deposit claim proof request failed: status={} body={}", status, body);
        let envelope: ApiResponse<DepositClaimProofResponse> = serde_json::from_str(&body)?;
        anyhow::ensure!(
            envelope.success,
            "deposit claim proof request unsuccessful: {}",
            envelope.error.unwrap_or_else(|| "unknown error".to_string())
        );
        let parsed = envelope
            .data
            .ok_or_else(|| anyhow::anyhow!("deposit claim proof response missing data"))?;
        anyhow::ensure!(parsed.found, "deposit claim proof not found for deposit_index={}", deposit_index);
        let deposit_root = parse_qhash_internal_bytes_hex(
            parsed
                .deposit_root
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("deposit proof missing deposit_root"))?,
        )?;
        let siblings = parsed.siblings.ok_or_else(|| anyhow::anyhow!("deposit proof missing siblings"))?;
        let leaf_hash = parse_qhash_bytes32_be(
            parsed
                .leaf_hash
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("deposit proof missing leaf_hash"))?,
        )?;
        let deposit = parsed.deposit.ok_or_else(|| anyhow::anyhow!("deposit proof missing deposit payload"))?;
        let sibling_qhashes = siblings
            .iter()
            .map(|hex| parse_qhash_internal_bytes_hex(hex))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((
            deposit_root,
            MerkleProofCore {
                root: deposit_root,
                index: parsed.deposit_index.unwrap_or(deposit_index),
                value: leaf_hash,
                siblings: sibling_qhashes,
            },
            deposit,
            parsed.checkpoint_id,
        ))
    }

    async fn submit_local_usdt_deposit(shield_address: &str, note_commitment: &str) -> anyhow::Result<String> {
        let output = Command::new("npx")
            .arg("hardhat")
            .arg("psy:deposit")
            .arg("--network")
            .arg("localhost")
            .arg("--token")
            .arg("USDTToken")
            .arg("--amount-raw")
            .arg("1000000")
            .arg("--l2-recipient")
            .arg(if shield_address.starts_with("0x") {
                shield_address.to_string()
            } else {
                format!("0x{}", shield_address)
            })
            .arg("--note-commitment")
            .arg(note_commitment)
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../psy-contracts"))
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "hardhat psy:deposit failed: stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout
            .lines()
            .find(|line| line.contains("[psy:deposit] deposit tx = "))
            .ok_or_else(|| anyhow::anyhow!("deposit tx hash missing from hardhat output"))?;
        Ok(line.split(" = ").nth(1).unwrap().trim().to_string())
    }

    async fn build_shield_deposit_claim(
        services_url: &str,
        deposit_index: u64,
        user_id: u64,
        random0: u64,
        random1: u64,
        token_l1_address: &str,
        amount_u64: u64,
        note_secret_input: &str,
        nullifier_secret_input: &str,
    ) -> anyhow::Result<(ShieldDepositClaim, Option<u64>)> {
        let token_address = parse_evm_addr_or_bytes32_to_u32x8(token_l1_address)?;
        let amount = u64_to_u32x8_be(amount_u64);
        let note_secret_q = parse_qhash_cli_input(note_secret_input)?;
        let nullifier_secret_q = parse_qhash_cli_input(nullifier_secret_input)?;
        let note_secret = qhash_to_u64x4(note_secret_q);
        let nullifier_secret = qhash_to_u64x4(nullifier_secret_q);
        let note_commitment_q = derive_note_commitment(nullifier_secret, note_secret);
        let shield_address = derive_shield_address(user_id, random0, random1);
        let nullifier_hash = derive_nullifier_hash(nullifier_secret);
        let (deposit_root, deposit_proof, proof_deposit, services_checkpoint_id) = fetch_deposit_claim_proof(services_url, deposit_index).await?;

        let proof_token_address = parse_evm_addr_or_bytes32_to_u32x8(&proof_deposit.token_address)?;
        let proof_l2_token_contract_id = parse_evm_addr_or_bytes32_to_u32x8(&proof_deposit.l2_token_contract_id)?;
        let proof_amount_u64 = proof_deposit.amount.parse::<u64>()?;
        let proof_amount = u64_to_u32x8_be(proof_amount_u64);
        let proof_note_commitment = parse_qhash_bytes32_be(&proof_deposit.note_commitment)?;
        let proof_shield_address = parse_qhash_display_hex(&proof_deposit.shield_address)?;
        anyhow::ensure!(proof_shield_address == shield_address, "shield address mismatch vs services proof");
        anyhow::ensure!(proof_token_address == token_address, "token address mismatch vs services proof");
        anyhow::ensure!(proof_amount == amount, "amount mismatch vs services proof");
        anyhow::ensure!(proof_deposit.source_chain_id == 0, "source_chain_index mismatch vs services proof");
        anyhow::ensure!(proof_note_commitment == note_commitment_q, "note_commitment mismatch vs services proof");

        let l2_token_contract_id = proof_l2_token_contract_id;
        let proof_index = deposit_proof.index;
        let deposit_commitment = derive_deposit_commitment(
            shield_address,
            token_address,
            l2_token_contract_id,
            amount,
            0,
            qhash_to_u64x4(note_commitment_q),
        );
        anyhow::ensure!(
            deposit_proof.value == deposit_commitment,
            "services leaf_hash mismatch vs derived shield deposit leaf"
        );

        let input = DepositInclusionInput::<GoldilocksField> {
            nullifier_secret: std::array::from_fn(|i| GoldilocksField::from_canonical_u64(nullifier_secret[i])),
            note_secret: std::array::from_fn(|i| GoldilocksField::from_canonical_u64(note_secret[i])),
            shield_address,
            deposit_index: proof_index,
            token_address,
            l2_token_contract_id,
            amount,
            source_chain_index: 0,
            deposit_root,
            deposit_proof,
        };
        let circuit = DepositInclusionCircuit::<PoseidonGoldilocksConfig, 2>::new();
        let fingerprint = circuit.get_fingerprint();
        let proof = circuit.prove(&input)?;
        Ok((
            ShieldDepositClaim {
                contract_id: u32x8_be_to_u64(proof_l2_token_contract_id)?,
                l2_token_contract_id: proof_l2_token_contract_id,
                nullifier_hash,
                shield_address,
                token_address,
                amount,
                source_chain_index: 0,
                deposit_root,
                note_commitment: note_commitment_q,
                deposit_index: proof_index,
                r0: random0,
                r1: random1,
                proof_fingerprint: fingerprint,
                proof,
                verifier_data: circuit.get_verifier_config_ref().into(),
            },
            services_checkpoint_id,
        ))
    }
    async fn setup_wallet_and_users(
        two_contracts: bool,
    ) -> anyhow::Result<(WalletSession, QHashOut<GoldilocksField>, QHashOut<GoldilocksField>, Vec<u64>)> {
        psy_client_common::setup_logging()?;
        let project_path =
            std::env::var("CARGO_MANIFEST_DIR").map_err(|e| anyhow::format_err!("Error `{}`, cannot get CARGO_MANIFEST_DIR env", e))?;

        let deployer_private_key = QHashOut::<GoldilocksField>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;

        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&Path::new(&project_path).join("../config.json").to_string_lossy())?;
        let mut rpc_config = psy_config.get_current_network()?.clone();
        rpc_config.prove_proxy_url.clear();

        let mut wallet_session = WalletSession::new(&rpc_config).await?;
        let user0_keys = wallet_session.get_random_keypair().await?;
        let user1_keys = wallet_session.get_random_keypair().await?;
        let user0_pk = user0_keys.public_key.clone();
        let user1_pk = user1_keys.public_key.clone();

        // Wait until realm RPC + coordinator checkpoint RPC are actually responsive.
        // Do NOT use get_user_ids_for_public_key(random_pk) here: a fresh random key
        // correctly returns "no user ids found", which is not a readiness failure.
        for _ in 0..60 {
            let realm_ok = wallet_session.st_provider.get_latest_block_state().await.is_ok();
            let tree_ok = wallet_session.st_provider.get_checkpoint_tree_root(0).await.is_ok();
            if realm_ok && tree_ok {
                break;
            }
            thread::sleep(Duration::from_secs(5));
        }

        // Built-in token contract 0 uses the standard simple_mint method id.
        let built_in_simple_mint_method_id = 1450059340_u32;

        let source = format!(
            r#"
            use std::prelude::*;

            #[contract]
            #[derive(Storage)]
            pub struct DeferredWrapper {{
                pub marker: Felt,
            }}

            impl DeferredWrapperRef {{
                #[contract_method]
                pub fn simple_deferred_mint() -> Felt {{
                    invoke_deferred(0, {built_in_simple_mint_method_id}, [500000000000]);
                    return 1;
                }}

                #[contract_method]
                pub fn pure_view() -> Felt {{
                    return 42;
                }}
            }}
        "#
        );
        let deployer_private_key = QHashOut::<GoldilocksField>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;
        let deployer_pk_info = wallet_session.get_zk_public_key(deployer_private_key).await?;
        let compiled = crate::session::compile_bridge::compile_contract(&source, deployer_pk_info.qfhash::<PsyHasher>())?;
        let helper_simple_deferred_method_id = compiled
            .contract_output
            .abi
            .contract
            .methods
            .iter()
            .find(|m| m.name == "simple_deferred_mint")
            .ok_or_else(|| anyhow::anyhow!("simple_deferred_mint missing from helper ABI"))?
            .method_id;
        wallet_session
            .st_provider
            .deploy_contract::<F>(QDeployContractRPCRequest {
                deploy_contract: compiled.deploy_cmd.clone(),
            })
            .await?;
        let helper_contract_id = {
            let mut found = None;
            for _ in 0..20 {
                let next_contract_id = wallet_session.st_provider.get_latest_block_state().await?.next_contract_id as u64;
                let start = next_contract_id.saturating_sub(16);
                for contract_id in start..next_contract_id {
                    if let Ok(def) = wallet_session.st_provider.get_contract_code_definition(contract_id).await {
                        if def
                            .functions
                            .iter()
                            .any(|f| f.method_id == helper_simple_deferred_method_id && f.num_inputs == 0)
                        {
                            found = Some(contract_id);
                        }
                    }
                }
                if found.is_some() {
                    break;
                }
                thread::sleep(Duration::from_secs(2));
            }
            found.ok_or_else(|| anyhow::anyhow!("could not resolve helper contract_id for simple_deferred_mint"))?
        };
        let contract_ids = vec![0_u64, helper_contract_id];

        let user0 = {
            let mut last_err = None;
            let mut value = None;
            for _ in 0..30 {
                match wallet_session.register_user(user0_keys.private_key, user0_pk.fingerprint).await {
                    Ok(v) => {
                        value = Some(v);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        thread::sleep(Duration::from_secs(5));
                    }
                }
            }
            value.ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("register_user(user0) failed")))?
        };
        let user1 = {
            let mut last_err = None;
            let mut value = None;
            for _ in 0..30 {
                match wallet_session.register_user(user1_keys.private_key, user1_pk.fingerprint).await {
                    Ok(v) => {
                        value = Some(v);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        thread::sleep(Duration::from_secs(5));
                    }
                }
            }
            value.ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("register_user(user1) failed")))?
        };
        for _ in 0..60 {
            let u0_ok = wallet_session.add_user(user0_keys.private_key, user0_pk.fingerprint).await.is_ok();
            let u1_ok = wallet_session.add_user(user1_keys.private_key, user1_pk.fingerprint).await.is_ok();
            if u0_ok && u1_ok {
                return Ok((wallet_session, user0, user1, contract_ids));
            }
            thread::sleep(Duration::from_secs(5));
        }

        anyhow::bail!("timed out waiting for add_user to succeed against provider")
    }

    async fn setup_single_user_ready() -> anyhow::Result<(WalletSession, WalletKeyPair, QHashOut<GoldilocksField>, u64, u64)> {
        let project_path =
            std::env::var("CARGO_MANIFEST_DIR").map_err(|e| anyhow::format_err!("Error `{}`, cannot get CARGO_MANIFEST_DIR env", e))?;
        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&Path::new(&project_path).join("../config.json").to_string_lossy())?;
        let mut rpc_config = psy_config.get_current_network()?.clone();
        rpc_config.prove_proxy_url.clear();

        let mut wallet_session = WalletSession::new(&rpc_config).await?;
        let user_keys = wallet_session.get_random_keypair().await?;
        let user_pk = user_keys.public_key.clone();
        let contract_id = 0_u64;

        for _ in 0..60 {
            let realm_ok = wallet_session.st_provider.get_latest_block_state().await.is_ok();
            let tree_ok = wallet_session.st_provider.get_checkpoint_tree_root(0).await.is_ok();
            if realm_ok && tree_ok {
                break;
            }
            thread::sleep(Duration::from_secs(5));
        }

        let user = {
            let mut last_err = None;
            let mut value = None;
            for _ in 0..30 {
                match wallet_session.register_user(user_keys.private_key, user_pk.fingerprint).await {
                    Ok(v) => {
                        value = Some(v);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        thread::sleep(Duration::from_secs(5));
                    }
                }
            }
            value.ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("register_user(single user) failed")))?
        };

        let user_id = loop {
            match wallet_session.resolve_registered_user_id(user).await {
                Ok(v) => break v,
                Err(_) => thread::sleep(Duration::from_secs(5)),
            }
        };

        for _ in 0..30 {
            if wallet_session
                .add_user_with_user_id(user_keys.private_key, user_pk.fingerprint, user_id)
                .await
                .is_ok()
            {
                if let Some(mut mgr) = wallet_session.user_session_mgrs.get_mut(&user) {
                    mgr.require_lps_mut().unwrap().set_is_new_user(false);
                }
                return Ok((wallet_session, user_keys, user, user_id, contract_id));
            }
            thread::sleep(Duration::from_secs(5));
        }

        anyhow::bail!("add_user_with_user_id(single user) failed")
    }

    async fn wait_for_contract_slot_min(
        wallet_session: &WalletSession,
        user_id: u64,
        contract_id: u64,
        slot_index: u64,
        min_value: u64,
    ) -> anyhow::Result<()> {
        for _ in 0..60 {
            let checkpoint_id = wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id;
            let contract_leaf = wallet_session.st_provider.get_contract_leaf_data(contract_id).await?;
            let slot = wallet_session
                .st_provider
                .get_user_contract_state_tree_merkle_proof(
                    checkpoint_id,
                    user_id,
                    contract_id as u32,
                    contract_leaf.state_tree_height.to_canonical_u64() as u8,
                    slot_index,
                )
                .await?;
            if slot.value.0.elements[0].to_canonical_u64() >= min_value {
                return Ok(());
            }
            thread::sleep(Duration::from_secs(5));
        }
        anyhow::bail!(
            "timed out waiting for contract {} slot {} to reach at least {}",
            contract_id,
            slot_index,
            min_value
        )
    }

    #[tokio::test]
    async fn async_generate_prove_simple_mint() -> anyhow::Result<()> {
        let (wallet_session, user0, _, contract_ids) = setup_wallet_and_users(false).await?;
        let contract_id = contract_ids[0];

        let call_data = ContractCallData::new(vec![ContractCallArgs {
            contract_id,
            method_name: "simple_mint".to_string(),
            inputs: vec![1_000_000_000_000],
        }]);
        wallet_session.start_session(user0).await?;
        let (before_count, before_hash) = {
            let mgr = wallet_session.user_session_mgrs.get(&user0).unwrap();
            (mgr.current_tx_count(), mgr.current_tx_hash_stack())
        };

        let simulated = wallet_session.simulate_contract_call(user0, call_data.clone()).await?;
        let generated = &simulated.generated;
        assert_eq!(simulated.metadata.tx_hash.to_string(), generated.tx_hash);
        assert!(!generated.trace.payload.is_empty());
        assert_eq!(simulated.metadata.contract_call_data.contract_calls.len(), 1);
        assert_eq!(simulated.metadata.contract_call_data.contract_calls[0].contract_id, contract_id);
        assert_eq!(simulated.metadata.contract_call_data.contract_calls[0].method_name, "simple_mint");
        assert_eq!(simulated.metadata.contract_call_data.contract_calls[0].inputs, vec![1_000_000_000_000]);
        assert!(!simulated.metadata.storage_data.writes.is_empty());
        let (after_count, after_hash) = {
            let mgr = wallet_session.user_session_mgrs.get(&user0).unwrap();
            (mgr.current_tx_count(), mgr.current_tx_hash_stack())
        };
        assert_eq!(before_count, after_count, "simulation must not advance shared session tx_count");
        assert_eq!(before_hash, after_hash, "simulation must not advance shared session hash stack");

        let trace = wallet_session.generate_tx_trace(user0, call_data).await?;
        assert!(!trace.steps.is_empty());
        let _tx_hash = wallet_session.prove_tx_trace(user0, &trace).await?;
        Ok(())
    }


    #[tokio::test]
    async fn async_call_view_is_read_only_and_rejects_mutation() -> anyhow::Result<()> {
        let (wallet_session, user0, _, contract_ids) = setup_wallet_and_users(false).await?;
        let helper_contract_id = contract_ids[1];
        wallet_session.start_session(user0).await?;
        let (before_count, before_hash) = {
            let mgr = wallet_session.user_session_mgrs.get(&user0).unwrap();
            (mgr.current_tx_count(), mgr.current_tx_hash_stack())
        };

        let view_call = ContractCallArgs {
            contract_id: helper_contract_id,
            method_name: "pure_view".to_string(),
            inputs: Vec::new(),
        };
        let request = ViewCallData::new(vec![view_call.clone(), view_call]);
        let first = wallet_session.call_view(user0, request.clone()).await?;
        let second = wallet_session.call_view(user0, request).await?;
        assert_eq!(first.contract_calls.iter().map(|call| call.outputs.as_slice()).collect::<Vec<_>>(), vec![&[42], &[42]]);
        assert_eq!(second.contract_calls.iter().map(|call| call.outputs.as_slice()).collect::<Vec<_>>(), vec![&[42], &[42]]);
        assert_eq!(first.checkpoint_id, second.checkpoint_id);
        let (after_count, after_hash) = {
            let mgr = wallet_session.user_session_mgrs.get(&user0).unwrap();
            (mgr.current_tx_count(), mgr.current_tx_hash_stack())
        };
        assert_eq!(before_count, after_count, "call_view must not advance shared session tx_count");
        assert_eq!(before_hash, after_hash, "call_view must not advance shared session hash stack");

        let mutation = wallet_session
            .call_view(
                user0,
                ViewCallData::new(vec![ContractCallArgs {
                    contract_id: 0,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![1],
                }]),
            )
            .await
            .unwrap_err();
        assert!(mutation.to_string().contains("not read-only"));

        let empty = wallet_session.call_view(user0, ViewCallData::new(Vec::new())).await.unwrap_err();
        assert!(empty.to_string().contains("No contract calls"));
        Ok(())
    }

    /// Mode-A MetaMask `personal_sign` end-to-end: authenticate the selected
    /// address with the network-bound registration challenge, generate the
    /// trace without a held key, sign the exact session sighash, then inject
    /// the 65-byte signature for proving.
    #[tokio::test]
    async fn async_external_eth_personal_user_simple_mint() -> anyhow::Result<()> {
        use psy_client_common::data::base_types::hash256::Hash256;

        let (mut wallet_session, _user0, _user1, contract_ids) = setup_wallet_and_users(false).await?;
        let contract_id = contract_ids[0];
        let private_key = QHashOut::<GoldilocksField>::rand();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&Hash256::from(private_key).0)?;
        let selected_address = psy_crypto::signature::secp256k1::wallet::ethereum_address_for_verifying_key(signing_key.verifying_key());

        let challenge = WalletSession::eth_personal_registration_challenge(selected_address)?;
        let challenge_digest = psy_crypto::signature::secp256k1::wallet::eth_personal_sign_digest(&challenge.0);
        let (challenge_signature, challenge_recovery_id) = signing_key.sign_prehash_recoverable(&challenge_digest)?;
        let mut challenge_signature_bytes = [0u8; 65];
        challenge_signature_bytes[..64].copy_from_slice(&challenge_signature.to_bytes());
        challenge_signature_bytes[64] = challenge_recovery_id.to_byte() + 27;
        let public_key = wallet_session
            .register_external_eth_personal_user(selected_address, challenge, challenge_signature_bytes)
            .await?;
        let user_id = loop {
            match wallet_session.resolve_registered_user_id(public_key).await {
                Ok(value) => break value,
                Err(_) => thread::sleep(Duration::from_secs(5)),
            }
        };
        wait_for_user_registered_on_realm(&wallet_session, user_id).await?;

        let call_data = ContractCallData::new(vec![ContractCallArgs {
            contract_id,
            method_name: "simple_mint".to_string(),
            inputs: vec![1_000_000_000_000],
        }]);
        let trace = wallet_session.generate_tx_trace(public_key, call_data).await?;
        assert!(!trace.steps.is_empty());

        let message = Hash256::from(trace.finalization.sig_hash);
        let digest = psy_crypto::signature::secp256k1::wallet::eth_personal_sign_digest(&message.0);
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest)?;
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&signature.to_bytes());
        signature_bytes[64] = recovery_id.to_byte() + 27;
        wallet_session
            .inject_eth_personal_signature(public_key, selected_address, message, signature_bytes)
            .await?;

        let _tx_hash = wallet_session.prove_tx_trace(public_key, &trace).await?;
        Ok(())
    }
    #[tokio::test]
    async fn async_trace_first_step_root_matches_ups_start_root() -> anyhow::Result<()> {
        let (wallet_session, user0, _, contract_ids) = setup_wallet_and_users(false).await?;
        let contract_id = contract_ids[0];

        let trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![1_000_000_000_000],
                }]),
            )
            .await?;

        let (meta, _, _, _, proof) = wallet_session.prove_ups_start(user0, &trace).await?;
        let start_root_from_proof = meta
            .leaf_records
            .last()
            .map(|record| record.insertion_proof.new_root)
            .ok_or_else(|| anyhow::anyhow!("ups_start meta missing leaf record"))?;
        let start_root_from_trace = trace
            .steps
            .first()
            .and_then(crate::trace::TraceStep::as_cfc)
            .map(|step| step.proof_tree_start_root)
            .ok_or_else(|| anyhow::anyhow!("trace missing first CFC step"))?;

        assert_eq!(
            start_root_from_trace,
            start_root_from_proof,
            "trace first-step start root should match prove_ups_start leaf root; proof public inputs {:?}",
            &proof.public_inputs[0..4]
        );

        Ok(())
    }

    #[tokio::test]
    async fn async_prove_trace_step_resume_after_manager_drop() -> anyhow::Result<()> {
        let (wallet_session, user0, _, contract_ids) = setup_wallet_and_users(false).await?;
        let contract_id = contract_ids[0];

        let trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![1_000_000_000_000],
                }]),
            )
            .await?;

        let mut proving_state: Option<ProvingState> = None;
        let mut proof_blobs: Vec<Vec<u8>> = Vec::new();
        let mut progress_count = 0usize;

        loop {
            match wallet_session
                .prove_trace_step(
                    user0,
                    &trace,
                    proving_state.as_ref(),
                    if proof_blobs.is_empty() { None } else { Some(proof_blobs.as_slice()) },
                )
                .await
            {
                TraceProvingStepResult::Progress { state, proofs } => {
                    progress_count += 1;
                    proof_blobs.extend(proofs);
                    proving_state = Some(state);

                    if progress_count == 1 {
                        wallet_session.user_session_mgrs.remove(&user0);
                    }
                }
                TraceProvingStepResult::Submitted(_tx_hash) => {
                    assert!(progress_count >= 2);
                    break;
                }
                TraceProvingStepResult::Failed { error } => {
                    anyhow::bail!("prove_trace_step failed unexpectedly: error={}", error);
                }
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn async_trace_resume_snapshot_restores_ups_start_root() -> anyhow::Result<()> {
        let (wallet_session, user0, _, contract_ids) = setup_wallet_and_users(false).await?;
        let contract_id = contract_ids[0];

        let trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![1_000_000_000_000],
                }]),
            )
            .await?;

        let expected_root = trace
            .steps
            .first()
            .and_then(crate::trace::TraceStep::as_cfc)
            .map(|step| step.proof_tree_start_root)
            .ok_or_else(|| anyhow::anyhow!("trace missing first CFC step"))?;

        let (proving_state, proof_blobs) = match wallet_session.prove_trace_step(user0, &trace, None, None).await {
            TraceProvingStepResult::Progress { state, proofs } => (state, proofs),
            TraceProvingStepResult::Submitted(tx_hash) => {
                anyhow::bail!("expected progress, got submitted tx {}", tx_hash)
            }
            TraceProvingStepResult::Failed { error } => {
                anyhow::bail!("initial prove_trace_step failed unexpectedly: error={}", error);
            }
        };

        assert_eq!(proving_state.proof_tree_meta.get_root(), expected_root);

        wallet_session.user_session_mgrs.remove(&user0);
        wallet_session.init_step_proving_session(user0, &trace).await?;
        let mut mgr = wallet_session
            .user_session_mgrs
            .get_mut(&user0)
            .ok_or_else(|| anyhow::anyhow!("missing restored user session manager"))?;
        wallet_session
            .restore_trace_proving_state(&mut mgr, &trace, &proving_state, &proof_blobs)
            .await?;
        let restored_root = mgr.proof_tree_state.get_proof_tree_root().await;
        drop(mgr);

        assert_eq!(restored_root, expected_root);

        Ok(())
    }

    #[tokio::test]
    async fn async_prove_trace_step_resume_simple_claim() -> anyhow::Result<()> {
        let (wallet_session, user0, user1, contract_ids) = setup_wallet_and_users(false).await?;
        let contract_id = contract_ids[0];
        let user0_id = wallet_session.resolve_registered_user_id(user0).await?;
        let user1_id = wallet_session.resolve_registered_user_id(user1).await?;

        tracing::info!("step-claim test: start mint");
        let mint_before = wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id;
        let mint_trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![1_000_000_000_000],
                }]),
            )
            .await?;
        let mint_tx_hash = wallet_session.prove_tx_trace(user0, &mint_trace).await?;
        tracing::info!("step-claim test: mint submitted tx_hash={}", mint_tx_hash);
        wallet_session
            .st_provider
            .wait_for_endcap_inclusion(user0_id, mint_tx_hash, mint_before, Some(240), 1)
            .await?;
        tracing::info!("step-claim test: mint included");

        tracing::info!("step-claim test: start transfer");
        let transfer_before = wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id;
        let transfer_trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_transfer".to_string(),
                    inputs: vec![user1_id, 250_000_000_000],
                }]),
            )
            .await?;
        let transfer_tx_hash = wallet_session.prove_tx_trace(user0, &transfer_trace).await?;
        tracing::info!("step-claim test: transfer submitted tx_hash={}", transfer_tx_hash);
        wallet_session
            .st_provider
            .wait_for_endcap_inclusion(user0_id, transfer_tx_hash, transfer_before, Some(240), 1)
            .await?;
        tracing::info!("step-claim test: transfer included");

        tracing::info!("step-claim test: build claim trace");
        let claim_trace = wallet_session
            .generate_tx_trace(
                user1,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_claim".to_string(),
                    inputs: vec![user0_id],
                }]),
            )
            .await?;

        let mut proving_state: Option<ProvingState> = None;
        let mut proof_blobs: Vec<Vec<u8>> = Vec::new();
        let mut progress_count = 0usize;
        let mut dropped_manager = false;

        loop {
            match wallet_session
                .prove_trace_step(
                    user1,
                    &claim_trace,
                    proving_state.as_ref(),
                    if proof_blobs.is_empty() { None } else { Some(proof_blobs.as_slice()) },
                )
                .await
            {
                TraceProvingStepResult::Progress { state, proofs } => {
                    progress_count += 1;
                    proof_blobs.extend(proofs);
                    tracing::info!("step-claim test: claim progress iteration={}", progress_count);
                    proving_state = Some(state);

                    if !dropped_manager {
                        tracing::info!("step-claim test: dropping live manager after first progress");
                        wallet_session.user_session_mgrs.remove(&user1);
                        dropped_manager = true;
                    }
                }
                TraceProvingStepResult::Submitted(_tx_hash) => {
                    tracing::info!("step-claim test: claim submitted");
                    assert!(progress_count >= 2);
                    break;
                }
                TraceProvingStepResult::Failed { error } => {
                    anyhow::bail!("prove_trace_step simple_claim failed unexpectedly: error={}", error);
                }
            }
        }

        Ok(())
    }

    #[tokio::test]
    async fn async_generate_prove_multicall() -> anyhow::Result<()> {
        let (wallet_session, user0, _, contract_ids) = setup_wallet_and_users(false).await?;
        let contract_id = contract_ids[0];

        let trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![
                    ContractCallArgs {
                        contract_id,
                        method_name: "simple_mint".to_string(),
                        inputs: vec![2_000_000_000_000],
                    },
                    ContractCallArgs {
                        contract_id,
                        method_name: "simple_burn".to_string(),
                        inputs: vec![1_000_000_000_000],
                    },
                ]),
            )
            .await?;

        let standard_count = trace.steps.iter().filter(|s| matches!(s, crate::trace::TraceStep::Standard(_))).count();
        assert_eq!(standard_count, 2);
        let _tx_hash = wallet_session.prove_tx_trace(user0, &trace).await?;
        Ok(())
    }

    #[tokio::test]
    async fn async_generate_prove_deferred() -> anyhow::Result<()> {
        let (wallet_session, user0, _user1, contract_ids) = setup_wallet_and_users(false).await?;
        let contract_id = contract_ids[1];
        let cm = wallet_session.wallet.random_circuit_manager();

        // Generate side: capture one standard parent + one real deferred child on the
        // built-in token contract.
        wallet_session.start_session(user0).await?;
        let (
            parent_witness,
            parent_delta,
            parent_end_header,
            parent_inclusion,
            parent_fn_id,
            deferred_contract_id,
            deferred_witness,
            deferred_delta,
            deferred_end_header,
            deferred_inclusion,
            deferred_fn_id,
            debt_removal_proof,
        ) = {
            let mut mgr = wallet_session
                .user_session_mgrs
                .get_mut(&user0)
                .ok_or_else(|| anyhow::format_err!("user {} not found", user0.to_string()))?;

            println!(
                "DEBUG deferred-test generate root after start = {}",
                mgr.proof_tree_state.get_proof_tree_root().await
            );
            let contract_code = mgr
                .require_lps_mut()?
                .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition { contract_id })
                .await?;
            let (parent_fn_id, parent_fn_circuit_def) = cm
                .resolve_contract_function_by_method_name(contract_id, &contract_code, "simple_deferred_mint".to_string())
                .await?;

            let parent_step = mgr
                .trace_standard_call(
                    cm.as_ref(),
                    F::from_canonical_u64(contract_id),
                    parent_fn_id as u32,
                    &parent_fn_circuit_def,
                    vec![],
                )
                .await?;
            println!(
                "DEBUG deferred-test parent witness session_root = {}",
                parent_step.cfc_witness.session_proof_tree_root
            );

            let parent_witness = parent_step.cfc_witness.clone();
            let parent_delta = parent_step.state_delta.clone();
            let parent_end_header = parent_step.end_header.clone();
            let parent_inclusion = parent_step.cfc_inclusion_proof.clone();

            let debt_item = mgr
                .require_lps()?
                .last_transaction_record()
                .added_deferred_tx_items
                .last()
                .cloned()
                .ok_or_else(|| anyhow::format_err!("expected a deferred debt item"))?;
            let deferred_contract_id = debt_item.call_data.contract_id.to_canonical_u64();
            let deferred_method_id = debt_item.call_data.method_id.to_canonical_u64() as u32;
            let deferred_contract_code = mgr
                .require_lps_mut()?
                .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition {
                    contract_id: deferred_contract_id,
                })
                .await?;
            let (deferred_fn_id, _) = cm
                .resolve_contract_function_by_method_id(deferred_contract_id, &deferred_contract_code, deferred_method_id)
                .await?;
            let deferred_step = mgr.trace_deferred_call(cm.as_ref(), &debt_item).await?;
            let deferred_witness = deferred_step.cfc_witness.clone();
            let deferred_delta = deferred_step.state_delta.clone();
            let deferred_end_header = deferred_step.end_header.clone();
            let debt_removal_proof = deferred_step
                .debt_removal_proof
                .clone()
                .ok_or_else(|| anyhow::format_err!("expected deferred debt_removal_proof"))?;
            let deferred_inclusion = deferred_step.cfc_inclusion_proof.clone();

            (
                parent_witness,
                parent_delta,
                parent_end_header,
                parent_inclusion,
                parent_fn_id as u32,
                deferred_contract_id,
                deferred_witness,
                deferred_delta,
                deferred_end_header,
                deferred_inclusion,
                deferred_fn_id as u32,
                debt_removal_proof,
            )
        };

        // Prove side: fresh manager created through the same start_session path used by
        // the legacy flow.
        wallet_session.user_session_mgrs.remove(&user0);
        wallet_session.start_session(user0).await?;
        {
            let mut mgr = wallet_session
                .user_session_mgrs
                .get_mut(&user0)
                .ok_or_else(|| anyhow::format_err!("user {} not found", user0.to_string()))?;
            let checkpoint_state = mgr.get_checkpoint_state();
            let prev_header: UserProvingSessionHeader<F> = mgr.get_current_ups_header().clone();
            let parent_step = psy_ups_circuit::session::TraceStandardStepInput {
                contract_id,
                fn_id: parent_fn_id,
                cfc_witness: parent_witness.clone(),
                state_delta: parent_delta.clone(),
                cfc_inclusion_proof: parent_inclusion.clone(),
                end_header: parent_end_header.clone(),
            };
            mgr.prove_step_standard(cm.as_ref(), checkpoint_state, &prev_header, &parent_step, None)
                .await?;

            let checkpoint_state = mgr.get_checkpoint_state();
            let prev_header: UserProvingSessionHeader<F> = mgr.get_current_ups_header().clone();
            let deferred_step = psy_ups_circuit::session::TraceDeferredStepInput {
                contract_id: deferred_contract_id,
                fn_id: deferred_fn_id,
                cfc_witness: deferred_witness.clone(),
                state_delta: deferred_delta.clone(),
                cfc_inclusion_proof: deferred_inclusion.clone(),
                debt_removal_proof: debt_removal_proof.clone(),
                end_header: deferred_end_header.clone(),
            };
            mgr.prove_step_deferred(cm.as_ref(), checkpoint_state, &prev_header, &deferred_step, None)
                .await?;
        }

        Ok(())
    }

    #[tokio::test]
    async fn async_legacy_claim_batch_public_and_private_transfer() -> anyhow::Result<()> {
        let (mut wallet_session, user0_keys, user0, user0_id, _user1_keys, user1, user1_id) = setup_wallet_and_users_with_keys().await?;
        let contract_id = 0_u64;
        let sender_mint = 20_000_000_000_000_u64;
        let receiver_fee_mint = 2_000_000_000_000_u64;
        let public_amount = 5_000_000_000_000_u64;
        let private_amount = 7_000_000_000_000_u64;

        // Fund sender for both transfers and receiver for batch-claim fee.
        let baseline_sender_nonce = wallet_session
            .st_provider
            .get_user_leaf_data(wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id, user0_id)
            .await?
            .nonce
            .to_canonical_u64();
        let trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![sender_mint],
                }]),
            )
            .await?;
        wallet_session.prove_tx_trace(user0, &trace).await?;
        wait_for_user_nonce_gt(&wallet_session, user0_id, baseline_sender_nonce).await?;

        let baseline_receiver_nonce = wallet_session
            .st_provider
            .get_user_leaf_data(wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id, user1_id)
            .await?
            .nonce
            .to_canonical_u64();
        let trace = wallet_session
            .generate_tx_trace(
                user1,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![receiver_fee_mint],
                }]),
            )
            .await?;
        wallet_session.prove_tx_trace(user1, &trace).await?;
        wait_for_user_nonce_gt(&wallet_session, user1_id, baseline_receiver_nonce).await?;

        // Prepare a public pending claim for receiver.
        let baseline_sender_nonce = wallet_session
            .st_provider
            .get_user_leaf_data(wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id, user0_id)
            .await?
            .nonce
            .to_canonical_u64();
        let trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_transfer".to_string(),
                    inputs: vec![user1_id, public_amount],
                }]),
            )
            .await?;
        wallet_session.prove_tx_trace(user0, &trace).await?;
        wait_for_user_nonce_gt(&wallet_session, user0_id, baseline_sender_nonce).await?;

        let owner = derive_shield_address(user1_id, 111, 222).to_string();
        let project_path =
            std::env::var("CARGO_MANIFEST_DIR").map_err(|e| anyhow::format_err!("Error `{}`, cannot get CARGO_MANIFEST_DIR env", e))?;
        let cli_bin = Path::new(&project_path).join("../../target/release/psy_user_cli");
        anyhow::ensure!(cli_bin.exists(), "psy_user_cli binary missing at {}", cli_bin.display());
        let note_path = std::env::temp_dir().join(format!("claim-batch-{}-{}.json", user0_id, user1_id));
        let output = Command::new(&cli_bin)
            .arg("private-transfer")
            .arg("--rpc-config")
            .arg(Path::new(&project_path).join("../config.json"))
            .arg("-p")
            .arg(user0_keys.private_key.to_string())
            .arg("--contract-id")
            .arg(contract_id.to_string())
            .arg("--amount")
            .arg(private_amount.to_string())
            .arg("--receiver")
            .arg(owner)
            .arg("--output")
            .arg(&note_path)
            .output()?;
        anyhow::ensure!(
            output.status.success(),
            "private-transfer CLI failed: stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let private_claim = load_private_transfer_claim_from_file(&mut wallet_session, &note_path, 111, 222).await?;

        let checkpoint_before = wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id;
        let baseline_balance = get_contract_slot_value(&wallet_session, user1_id, contract_id, 0).await?.0.elements[0].to_canonical_u64();

        let end_user_leaf_hash = wallet_session
            .claim_batch(
                user1,
                vec![
                    ClaimBatchItem::Public(ContractCallArgs {
                        contract_id,
                        method_name: "simple_claim".to_string(),
                        inputs: vec![user0_id],
                    }),
                    ClaimBatchItem::PrivateTransfer {
                        contract_id,
                        claim: private_claim,
                    },
                ],
            )
            .await?;

        let confirmed_checkpoint = wallet_session
            .wait_for_endcap_inclusion(user1_id, end_user_leaf_hash, checkpoint_before, Some(180), 1)
            .await?;
        tracing::info!("legacy claim_batch mixed batch confirmed at checkpoint {}", confirmed_checkpoint);

        let expected_min = baseline_balance + public_amount + private_amount - 5_000_000_000_u64;
        wait_for_contract_slot_min(&wallet_session, user1_id, contract_id, 0, expected_min).await?;
        Ok(())
    }

    #[tokio::test]
    async fn async_legacy_claim_batch_public_and_shield_deposit() -> anyhow::Result<()> {
        let (mut wallet_session, _user0_keys, user0, user0_id, _user1_keys, user1, user1_id) = setup_wallet_and_users_with_keys().await?;
        let public_contract_id = 0_u64;
        let sender_mint = 20_000_000_000_000_u64;
        let receiver_fee_mint = 2_000_000_000_000_u64;
        let public_amount = 5_000_000_000_000_u64;
        let deposit_amount = 1_000_000_u64;
        let random0 = 333_u64;
        let random1 = 444_u64;
        let note_secret = "0x0000000000000000000000000000000000000000000000000000000000001234";
        let nullifier_secret = "0x0000000000000000000000000000000000000000000000000000000000005678";

        let baseline_sender_nonce = wallet_session
            .st_provider
            .get_user_leaf_data(wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id, user0_id)
            .await?
            .nonce
            .to_canonical_u64();
        let trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id: public_contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![sender_mint],
                }]),
            )
            .await?;
        wallet_session.prove_tx_trace(user0, &trace).await?;
        wait_for_user_nonce_gt(&wallet_session, user0_id, baseline_sender_nonce).await?;

        let baseline_receiver_nonce = wallet_session
            .st_provider
            .get_user_leaf_data(wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id, user1_id)
            .await?
            .nonce
            .to_canonical_u64();
        let trace = wallet_session
            .generate_tx_trace(
                user1,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id: public_contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![receiver_fee_mint],
                }]),
            )
            .await?;
        wallet_session.prove_tx_trace(user1, &trace).await?;
        wait_for_user_nonce_gt(&wallet_session, user1_id, baseline_receiver_nonce).await?;

        let baseline_sender_nonce = wallet_session
            .st_provider
            .get_user_leaf_data(wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id, user0_id)
            .await?
            .nonce
            .to_canonical_u64();
        let trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id: public_contract_id,
                    method_name: "simple_transfer".to_string(),
                    inputs: vec![user1_id, public_amount],
                }]),
            )
            .await?;
        wallet_session.prove_tx_trace(user0, &trace).await?;
        wait_for_user_nonce_gt(&wallet_session, user0_id, baseline_sender_nonce).await?;

        let shield_address = derive_shield_address(user1_id, random0, random1).to_string();
        let note_secret_q = parse_qhash_cli_input(note_secret)?;
        let nullifier_secret_q = parse_qhash_cli_input(nullifier_secret)?;
        let note_commitment = format!(
            "0x{}",
            hex::encode(qhashout_to_bytes32_be(derive_note_commitment(
                qhash_to_u64x4(nullifier_secret_q),
                qhash_to_u64x4(note_secret_q),
            )))
        );
        let tx_hash = submit_local_usdt_deposit(&shield_address, &note_commitment).await?;
        let (deposit_index, indexed_deposit) = wait_for_indexed_deposit("http://127.0.0.1:8080/v1/graphql", &tx_hash).await?;
        anyhow::ensure!(indexed_deposit.shield_address.to_lowercase() == format!("0x{}", shield_address).to_lowercase());

        let (shield_claim, _services_checkpoint_id) = loop {
            match build_shield_deposit_claim(
                "http://127.0.0.1:3000",
                deposit_index,
                user1_id,
                random0,
                random1,
                &indexed_deposit.token_address,
                deposit_amount,
                note_secret,
                nullifier_secret,
            )
            .await
            {
                Ok(v) => break v,
                Err(_) => thread::sleep(Duration::from_secs(5)),
            }
        };

        let checkpoint_before = wallet_session.st_provider.get_latest_block_state().await?.checkpoint_id;
        let baseline_public_balance = get_contract_slot_value(&wallet_session, user1_id, public_contract_id, 0)
            .await?
            .0
            .elements[0]
            .to_canonical_u64();
        let baseline_deposit_balance = get_contract_slot_value(&wallet_session, user1_id, shield_claim.contract_id, 0)
            .await?
            .0
            .elements[0]
            .to_canonical_u64();

        let end_user_leaf_hash = wallet_session
            .claim_batch(
                user1,
                vec![
                    ClaimBatchItem::Public(ContractCallArgs {
                        contract_id: public_contract_id,
                        method_name: "simple_claim".to_string(),
                        inputs: vec![user0_id],
                    }),
                    ClaimBatchItem::ShieldDeposit(shield_claim.clone()),
                ],
            )
            .await?;

        let confirmed_checkpoint = wallet_session
            .wait_for_endcap_inclusion(user1_id, end_user_leaf_hash, checkpoint_before, Some(240), 1)
            .await?;
        tracing::info!("legacy claim_batch public+shield confirmed at checkpoint {}", confirmed_checkpoint);

        let expected_public_min = baseline_public_balance + public_amount - 5_000_000_000_u64;
        wait_for_contract_slot_min(&wallet_session, user1_id, public_contract_id, 0, expected_public_min).await?;
        wait_for_contract_slot_min(
            &wallet_session,
            user1_id,
            shield_claim.contract_id,
            0,
            baseline_deposit_balance + deposit_amount,
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "legacy business flow probe"]
    async fn async_legacy_transfer_claim_probe_old_fixture() -> anyhow::Result<()> {
        let (wallet_session, user0, user1, contract_ids) = setup_wallet_and_users(false).await?;
        let contract_id = contract_ids[0];
        let user0_id = wallet_session.resolve_registered_user_id(user0).await?;
        let user1_id = wallet_session.resolve_registered_user_id(user1).await?;

        wallet_session
            .exec_contract_call(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![1_000_000_000_000],
                }]),
            )
            .await?;
        thread::sleep(Duration::from_secs(5));
        thread::sleep(Duration::from_secs(5));

        wallet_session
            .exec_contract_call(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_transfer".to_string(),
                    inputs: vec![user1_id, 250_000_000_000],
                }]),
            )
            .await?;
        thread::sleep(Duration::from_secs(5));
        thread::sleep(Duration::from_secs(5));

        wallet_session
            .exec_contract_call(
                user1,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_claim".to_string(),
                    inputs: vec![user0_id],
                }]),
            )
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn async_legacy_exec_simple_mint_smoke() -> anyhow::Result<()> {
        let (wallet_session, user0, _, contract_ids) = setup_wallet_and_users(false).await?;
        let contract_id = contract_ids[0];
        let tx_hash = wallet_session
            .exec_contract_call(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![1_000_000_000_000],
                }]),
            )
            .await?;
        tracing::info!("legacy exec tx_hash={}", tx_hash);
        Ok(())
    }

    #[tokio::test]
    async fn async_generate_prove_deferred_simple_mint() -> anyhow::Result<()> {
        let (wallet_session, user0, _user1, contract_ids) = setup_wallet_and_users(false).await?;
        let token_contract_id = contract_ids[0];
        let deferred_contract_id = contract_ids[1];

        let mint_trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id: token_contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![1_000_000_000_000],
                }]),
            )
            .await?;
        wallet_session.prove_tx_trace(user0, &mint_trace).await?;
        thread::sleep(Duration::from_secs(20));

        let deferred_trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id: deferred_contract_id,
                    method_name: "simple_deferred_mint".to_string(),
                    inputs: vec![],
                }]),
            )
            .await?;
        for (idx, step) in deferred_trace.steps.iter().enumerate() {
            match step {
                crate::trace::TraceStep::Standard(cfc)
                | crate::trace::TraceStep::BurnFee(cfc)
                | crate::trace::TraceStep::Inlined(cfc)
                | crate::trace::TraceStep::Deferred(cfc) => {
                    tracing::info!(
                        "DEFERRED_TRACE step[{idx}] {:?} id={} parent={:?} contract={} method={} fn={} inlined_children={} deferred_children={}",
                        match step {
                            crate::trace::TraceStep::Standard(_) => TraceCfcStepKind::Standard,
                            crate::trace::TraceStep::BurnFee(_) => TraceCfcStepKind::BurnFee,
                            crate::trace::TraceStep::Inlined(_) => TraceCfcStepKind::Inlined,
                            crate::trace::TraceStep::Deferred(_) => TraceCfcStepKind::Deferred,
                            _ => unreachable!(),
                        },
                        cfc.id.0,
                        cfc.parent,
                        cfc.contract_id,
                        cfc.method_id,
                        cfc.fn_id,
                        cfc.inlined.len(),
                        cfc.deferred.len()
                    );
                }
                crate::trace::TraceStep::ExternalProof(step) => {
                    tracing::info!("DEFERRED_TRACE step[{idx}] ExternalProof fingerprint={}", step.fingerprint);
                }
                crate::trace::TraceStep::ZkSign(step) => {
                    tracing::info!("DEFERRED_TRACE step[{idx}] ZkSign fingerprint={}", step.fingerprint);
                }
            }
        }
        assert!(
            deferred_trace.steps.iter().any(|s| match s {
                crate::trace::TraceStep::Standard(c)
                | crate::trace::TraceStep::BurnFee(c)
                | crate::trace::TraceStep::Inlined(c)
                | crate::trace::TraceStep::Deferred(c) => !c.deferred.is_empty(),
                _ => false,
            }),
            "simple_deferred_mint should generate deferred children"
        );
        wallet_session.prove_tx_trace(user0, &deferred_trace).await?;

        Ok(())
    }

    #[tokio::test]
    async fn async_generate_prove_deferred_business_flow() -> anyhow::Result<()> {
        let (wallet_session, user0, _user1, contract_ids) = {
            let mut last_err = None;
            let mut value = None;
            for _ in 0..5 {
                match setup_wallet_and_users(false).await {
                    Ok(v) => {
                        value = Some(v);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        thread::sleep(Duration::from_secs(10));
                    }
                }
            }
            value.ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("setup_wallet_and_users failed for deferred business flow")))?
        };
        let token_contract_id = contract_ids[0];
        let deferred_contract_id = contract_ids[1];
        let mint_trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id: token_contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![1_000_000_000_000],
                }]),
            )
            .await?;
        wallet_session.prove_tx_trace(user0, &mint_trace).await?;
        thread::sleep(Duration::from_secs(5));
        thread::sleep(Duration::from_secs(5));

        let deferred_trace = {
            let mut last_err = None;
            let mut value = None;
            for _ in 0..5 {
                match wallet_session
                    .generate_tx_trace(
                        user0,
                        ContractCallData::new(vec![ContractCallArgs {
                            contract_id: deferred_contract_id,
                            method_name: "simple_deferred_mint".to_string(),
                            inputs: vec![],
                        }]),
                    )
                    .await
                {
                    Ok(v) => {
                        value = Some(v);
                        break;
                    }
                    Err(e) if format!("{e:#}").contains("stale nonce") => {
                        last_err = Some(e);
                        thread::sleep(Duration::from_secs(5));
                    }
                    Err(e) => return Err(e),
                }
            }
            value.ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("generate deferred trace failed")))?
        };
        assert!(
            deferred_trace.steps.iter().any(|s| match s {
                crate::trace::TraceStep::Standard(c)
                | crate::trace::TraceStep::BurnFee(c)
                | crate::trace::TraceStep::Inlined(c)
                | crate::trace::TraceStep::Deferred(c) => !c.deferred.is_empty(),
                _ => false,
            }),
            "simple_deferred_mint should generate deferred children"
        );
        wallet_session.prove_tx_trace(user0, &deferred_trace).await?;

        Ok(())
    }

    #[tokio::test]
    async fn async_generate_prove_transfer_deferred_only() -> anyhow::Result<()> {
        let (wallet_session, user0, user1, contract_ids) = {
            let mut last_err = None;
            let mut value = None;
            for _ in 0..5 {
                match setup_wallet_and_users(false).await {
                    Ok(v) => {
                        value = Some(v);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        thread::sleep(Duration::from_secs(10));
                    }
                }
            }
            value.ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("setup_wallet_and_users failed for deferred transfer flow")))?
        };
        let contract_id = contract_ids[0];
        let user1_id = wallet_session.resolve_registered_user_id(user1).await?;

        let mint_trace = wallet_session
            .generate_tx_trace(
                user0,
                ContractCallData::new(vec![ContractCallArgs {
                    contract_id,
                    method_name: "simple_mint".to_string(),
                    inputs: vec![1_000_000_000_000],
                }]),
            )
            .await?;
        wallet_session.prove_tx_trace(user0, &mint_trace).await?;
        thread::sleep(Duration::from_secs(5));
        thread::sleep(Duration::from_secs(5));

        let transfer_trace = {
            let mut last_err = None;
            let mut value = None;
            for _ in 0..5 {
                match wallet_session
                    .generate_tx_trace(
                        user0,
                        ContractCallData::new(vec![ContractCallArgs {
                            contract_id,
                            method_name: "simple_transfer".to_string(),
                            inputs: vec![user1_id, 250_000_000_000],
                        }]),
                    )
                    .await
                {
                    Ok(v) => {
                        value = Some(v);
                        break;
                    }
                    Err(e) if format!("{e:#}").contains("stale nonce") => {
                        last_err = Some(e);
                        thread::sleep(Duration::from_secs(5));
                    }
                    Err(e) => return Err(e),
                }
            }
            value.ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("generate transfer trace failed")))?
        };
        assert!(
            transfer_trace.steps.iter().any(|s| match s {
                crate::trace::TraceStep::Standard(c)
                | crate::trace::TraceStep::BurnFee(c)
                | crate::trace::TraceStep::Inlined(c)
                | crate::trace::TraceStep::Deferred(c) => !c.deferred.is_empty(),
                _ => false,
            }),
            "transfer should generate deferred children"
        );
        wallet_session.prove_tx_trace(user0, &transfer_trace).await?;

        Ok(())
    }
    #[tokio::test]
    #[ignore = "debug baseline only"]
    async fn async_local_prove_minimal_add_balance_baseline() -> anyhow::Result<()> {

        let project_path =
            std::env::var("CARGO_MANIFEST_DIR").map_err(|e| anyhow::format_err!("Error `{}`, cannot get CARGO_MANIFEST_DIR env", e))?;
        let deployer_private_key = QHashOut::<GoldilocksField>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;

        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&Path::new(&project_path).join("../config.json").to_string_lossy())?;
        let mut rpc_config = psy_config.get_current_network()?.clone();
        rpc_config.prove_proxy_url.clear();
        let source = r#"
            use std::prelude::*;

            #[derive(Storage)]
            pub struct TokenState {
                pub balance: Felt,
            }

            #[contract]
            #[derive(Storage)]
            pub struct TokenContract {
                pub token_state: TokenState,
            }

            impl TokenContractRef {
                #[contract_method]
                pub fn add_balance(amount: Felt) {
                    let c = TokenContractRef::new(ContractMetadata::current());
                    c.token_state.balance += amount;
                }
            }
        "#;

        let mut wallet_session = WalletSession::new(&rpc_config).await?;
        let deployer_pk_info = wallet_session.get_zk_public_key(deployer_private_key).await?;
        let compiled = crate::session::compile_bridge::compile_contract(source, deployer_pk_info.qfhash::<PsyHasher>())?;
        wallet_session
            .st_provider
            .deploy_contract::<F>(QDeployContractRPCRequest {
                deploy_contract: compiled.deploy_cmd,
            })
            .await?;

        let user_keys = wallet_session.get_random_keypair().await?;
        let user_pk = user_keys.public_key.clone();
        let user = wallet_session.register_user(user_keys.private_key, user_pk.fingerprint).await?;
        for _ in 0..18 {
            if wallet_session.resolve_registered_user_id(user).await.is_ok() {
                break;
            }
            thread::sleep(Duration::from_secs(10));
        }
        wallet_session.add_user(user_keys.private_key, user_pk.fingerprint).await?;

        let cm = wallet_session.wallet.random_circuit_manager();
        wallet_session.start_session(user).await?;

        {
            let mut mgr = wallet_session
                .user_session_mgrs
                .get_mut(&user)
                .ok_or_else(|| anyhow::format_err!("user {} not found", user.to_string()))?;

            let contract_code = mgr
                .require_lps_mut()?
                .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition { contract_id: 0 })
                .await?;
            let (fn_id, fn_circuit_def) = cm
                .resolve_contract_function_by_method_name(0, &contract_code, "add_balance".to_string())
                .await?;

            let step = mgr
                .trace_standard_call(
                    cm.as_ref(),
                    F::from_canonical_u64(0),
                    fn_id as u32,
                    &fn_circuit_def,
                    vec![F::from_canonical_u64(123)],
                )
                .await?;
            let witness = step.cfc_witness.clone();

            let proof_result = cm.prove_contract_call(0, fn_id as u32, &witness).await;
            println!(
                "DEBUG minimal add_balance prove result: {:?}",
                proof_result.as_ref().map(|p| p.public_inputs.len())
            );
            if let Err(e) = &proof_result {
                println!("DEBUG minimal add_balance prove error: {:#}", e);
            }
        }

        Ok(())
    }
}
