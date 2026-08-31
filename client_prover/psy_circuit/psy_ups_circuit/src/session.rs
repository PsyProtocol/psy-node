use plonky2::{
    field::{
        extension::Extendable,
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::hash_types::{HashOut, RichField},
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{data::qhashout::QHashOut, ups::circuits::LocalCircuitType, utils::debug_timer::DebugTimer};
use psy_client_data::{
    config::store_config::PsyHasher,
    dpn::proving_session::{DPNProvingSessionSimpleMethodCall, DPNTransactionDebtItem, PsyLocalTransactionRecord},
    guta::{api::SubmitUserEndCapNonProofCoreInput, end_cap_input::SubmitUserEndCapNonProofInput, stats::GUTAStats},
    qdata::{
        checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf, PsyCheckpointLeafCompact, PsyCheckpointLeafCompactWithStateRoots},
        contract_inclusion::PsyContractFunctionInclusionProof,
        ups_end_cap_result::UPSEndCapResultCompact,
        ups_signature::PsyUserProvingSessionSignatureDataCompact,
        user::PsyUserLeaf,
        user_contract_state::SignContext,
    },
    qstore::{
        controllers::{
            proving_session::{PsyEventsStore, PsyLocalProvingSessionStore, PsyReadLocalProvingSessionStore},
            session_info::SessionCircuitInfoStore,
            state_tracker::PsyUserSessionUpdateHistory,
        },
        imm::{
            cache::PsyCmdStoreWithCache,
            cmd::{
                QSRCmdGetCheckpointLeafData, QSRCmdGetContractCodeDefinition, QSRMerkleCmd, QSRMerkleCmdGetCheckpointTreeMerkleProof,
                QSRMerkleCmdGetUserRegistrationTreeMerkleProof, QSRMerkleCmdGetUserTreeMerkleProof,
            },
            cmd_processor::{PsyReadCommandProcessorSync, PsyReadCommandProcessorSyncMut},
        },
    },
    traits::qdatastore::qtreedata::PsyComboDataStoreReaderSync,
    ups::{
        start_step::UPSStartStepInput,
        start_step_register_user::UPSStartStepRegisterUserInput,
        ups_cfc_standard_step::{UPSCFCDeferredTransactionCircuitInput, UPSCFCStandardTransactionCircuitInput},
        ups_context_input::{UserProvingSessionCurrentState, UserProvingSessionHeader},
        ups_end_cap::UPSEndCapFromProofTreeGadgetInput,
        ups_standard_cfc_input::{UPSCFCStandardStateDeltaInput, UPSVerifyCFCStandardStepInput, UPSVerifyPopDeferredTxStepInput},
        verify_previous_ups_step::VerifyPreviousUPSStepProofInProofTreeInput,
    },
};
use psy_common_circuit::treeprover::qrecursion::standard::manager::portable::core::PortableQTreeRecursionManager;
use psy_config::{
    network_constants::{
        DEFAULT_CALLER_CONTRACT_ID_U64, DEFERRED_TRANSACTION_TREE_HEIGHT, GUTA_FEE, INLINE_TRANSACTION_TREE_HEIGHT, TOKEN_CONTRACT_ID,
        TOKEN_SIMPLE_BURN_METHOD_ID, UPS_SESSION_PROOF_TREE_HEIGHT,
    },
    DA_FEE,
};
use psy_crypto::{
    common::{
        user_id::get_registration_id_from_user_id,
        witnesses::qrecursion::{
            header::{AttestProofInTreeInput, AttestTreeAwareProofInTreeInput},
            proof_data::{InputLeafProof, TreeAwareTreeProofRecord},
        },
    },
    hash::{
        merkle::core::{DeltaMerkleProofCore, MerkleProofCore},
        traits::{
            hasher::{FieldQHasher, MerkleZeroHasherWithMarkedLeaf},
            qhashable::QFieldHashable,
        },
    },
};
use psy_vm::{
    dpn::{contract::cfc_code_definition_to_dapen_fc, vm::def::DPNFunctionCircuitDefinition},
    ups::circuit_manager::UPSCircuitManager,
    vm::{cfc_input::DapenContractFunctionCircuitInput, exec::PsyEvalSessionResult},
};
use serde::Serialize;

const UPS_STEP_LEAF_TYPE: u64 = 1;
const CFC_LEAF_TYPE: u64 = 2;
const ZK_SIG_LEAF_TYPE: u64 = 3;
const EXTERNAL_PROOF_LEAF_TYPE: u64 = 4;

#[derive(Clone)]
pub struct TracedCfcStep<F: RichField> {
    pub contract_id: u64,
    pub fn_id: u32,
    pub method_id: u32,
    pub method_name: String,
    pub cfc_fingerprint: QHashOut<F>,
    pub ups_fingerprint: QHashOut<F>,
    pub proof_tree_start_root: QHashOut<F>,
    pub proof_tree_end_root: QHashOut<F>,
    pub cfc_witness: DapenContractFunctionCircuitInput<F>,
    pub state_delta: UPSCFCStandardStateDeltaInput<F>,
    pub cfc_inclusion_proof: PsyContractFunctionInclusionProof<F>,
    pub end_header: UserProvingSessionHeader<F>,
    pub debt_removal_proof: Option<DeltaMerkleProofCore<QHashOut<F>>>,
    pub deferred: Vec<TracedCfcStep<F>>,
}

#[derive(Clone)]
pub struct TraceStandardStepInput<F: RichField> {
    pub contract_id: u64,
    pub fn_id: u32,
    pub cfc_witness: DapenContractFunctionCircuitInput<F>,
    pub state_delta: UPSCFCStandardStateDeltaInput<F>,
    pub cfc_inclusion_proof: PsyContractFunctionInclusionProof<F>,
    pub end_header: UserProvingSessionHeader<F>,
}

#[derive(Clone)]
pub struct TraceDeferredStepInput<F: RichField> {
    pub contract_id: u64,
    pub fn_id: u32,
    pub cfc_witness: DapenContractFunctionCircuitInput<F>,
    pub state_delta: UPSCFCStandardStateDeltaInput<F>,
    pub cfc_inclusion_proof: PsyContractFunctionInclusionProof<F>,
    pub debt_removal_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub end_header: UserProvingSessionHeader<F>,
}

pub struct UserProvingSessionManager<
    F: RichField + Extendable<D>,
    H: MerkleZeroHasherWithMarkedLeaf<HashOut<F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + AlgebraicHasher<F> + Send,
    R: PsyReadCommandProcessorSync<F> + PsyComboDataStoreReaderSync<F> + psy_client_data::qstore::imm::cmd_processor::QUserIdManager + Send + Sync,
    C: GenericConfig<D, F = F, Hasher = H>,
    const D: usize,
> {
    pub lps: Option<PsyLocalProvingSessionStore<F, R, H>>,
    circuit_info: SessionCircuitInfoStore<F>,
    pub proof_tree_state: PortableQTreeRecursionManager<C, D>,
    current_ups_header: UserProvingSessionHeader<F>,
    previous_ups_header: UserProvingSessionHeader<F>,
    current_checkpoint_leaf: PsyCheckpointLeaf<F>,
    current_global_state_roots: PsyCheckpointGlobalStateRoots<F>,
    last_ups_step_proof_info: TreeAwareTreeProofRecord<F>,

    tx_log: Vec<DPNProvingSessionSimpleMethodCall<F>>,
}

type F = GoldilocksField;
const D: usize = 2;

/// The leaf proof(s) ingested by a single CFC trace step (standard or
/// deferred). A CFC step always produces two proof-tree leaves: the
/// contract-function-call (CFC) proof and the UPS step proof. Returned by
/// `prove_step_*` so callers can persist them into the trace and later
/// re-inject without re-proving.
#[derive(Clone)]
pub struct CfcStepProofs<C: GenericConfig<D, F = F>> {
    pub cfc_proof: ProofWithPublicInputs<F, C, D>,
    pub ups_proof: ProofWithPublicInputs<F, C, D>,
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<
        H: MerkleZeroHasherWithMarkedLeaf<HashOut<F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + AlgebraicHasher<F> + FieldQHasher<F> + Send,
        R: PsyReadCommandProcessorSync<F> + PsyComboDataStoreReaderSync<F> + psy_client_data::qstore::imm::cmd_processor::QUserIdManager + Send + Sync,
        C: GenericConfig<D, F = F, Hasher = H> + Serialize,
    > UserProvingSessionManager<F, H, R, C, D>
{
    pub fn require_lps(&self) -> anyhow::Result<&PsyLocalProvingSessionStore<F, R, H>> {
        self.lps
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("LPS is unavailable in stateless step proving"))
    }

    pub fn require_lps_mut(&mut self) -> anyhow::Result<&mut PsyLocalProvingSessionStore<F, R, H>> {
        self.lps
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("LPS is unavailable in stateless step proving"))
    }

    pub fn into_cmd_store(self) -> anyhow::Result<PsyCmdStoreWithCache<F, R>> {
        self.lps
            .ok_or_else(|| anyhow::anyhow!("LPS is unavailable in stateless step proving"))
            .map(PsyLocalProvingSessionStore::into_cmd_store)
    }

    pub async fn into_clean_for_user(self, user_id: F) -> anyhow::Result<Self> {
        let ups_step_circuit_whitelist_root = self.current_ups_header.ups_step_circuit_whitelist_root;
        let circuit_info = self.circuit_info;
        let lps = self
            .lps
            .ok_or_else(|| anyhow::anyhow!("LPS is unavailable in stateless step proving"))?
            .into_clean_for_user(user_id)
            .await?;

        Self::new(lps, circuit_info, ups_step_circuit_whitelist_root).await
    }

    pub fn checkpoint_state_from_parts(
        checkpoint_leaf: &PsyCheckpointLeaf<F>,
        global_state_roots: &PsyCheckpointGlobalStateRoots<F>,
    ) -> PsyCheckpointLeafCompactWithStateRoots<F> {
        PsyCheckpointLeafCompactWithStateRoots {
            checkpoint_leaf: PsyCheckpointLeafCompact {
                global_chain_root: checkpoint_leaf.global_chain_root,
                stats_hash: checkpoint_leaf.stats.qfhash::<H>(),
            },
            global_state_roots: *global_state_roots,
        }
    }

    pub fn get_checkpoint_state(&self) -> PsyCheckpointLeafCompactWithStateRoots<F> {
        Self::checkpoint_state_from_parts(&self.current_checkpoint_leaf, &self.current_global_state_roots)
    }
    pub fn get_current_ups_header(&self) -> &UserProvingSessionHeader<F> {
        &self.current_ups_header
    }

    pub fn set_current_ups_header_nonce(&mut self, nonce: F) {
        self.current_ups_header.current_state.user_leaf.nonce = nonce;
    }

    pub fn get_previous_ups_header(&self) -> &UserProvingSessionHeader<F> {
        &self.previous_ups_header
    }

    pub fn get_current_checkpoint_leaf(&self) -> &PsyCheckpointLeaf<F> {
        &self.current_checkpoint_leaf
    }

    pub fn get_current_global_state_roots(&self) -> &PsyCheckpointGlobalStateRoots<F> {
        &self.current_global_state_roots
    }

    /// Read-only access to the baton produced by the last UPS step proof
    /// (used for step-by-step proving snapshot/handoff across the WASM
    /// boundary).
    pub fn get_last_ups_step_proof_info(&self) -> TreeAwareTreeProofRecord<F> {
        self.last_ups_step_proof_info
    }

    pub fn set_current_ups_header(&mut self, header: UserProvingSessionHeader<F>) {
        self.current_ups_header = header;
    }

    pub fn set_previous_ups_header(&mut self, header: UserProvingSessionHeader<F>) {
        self.previous_ups_header = header;
    }

    pub fn set_last_ups_step_proof_info(&mut self, info: TreeAwareTreeProofRecord<F>) {
        self.last_ups_step_proof_info = info;
    }

    pub async fn new(
        mut lps: PsyLocalProvingSessionStore<F, R, H>,
        circuit_info: SessionCircuitInfoStore<F>,
        ups_step_circuit_whitelist_root: QHashOut<F>,
    ) -> anyhow::Result<Self> {
        let proof_tree_state = PortableQTreeRecursionManager::<C, D>::new(UPS_SESSION_PROOF_TREE_HEIGHT as usize).await;
        let session_start_context = lps.get_ups_start_ctx().await?;

        let mut new_user = session_start_context.start_session_user_leaf.clone();

        let latest_checkpoint_id_u64 = lps.get_current_start_checkpoint_id_u64();
        let latest_checkpoint_id_f = lps.get_current_start_checkpoint_id();

        if latest_checkpoint_id_u64 != 0 && latest_checkpoint_id_u64 <= new_user.last_checkpoint_id.to_canonical_u64() {
            anyhow::bail!(
                "Invalid checkpoint: new checkpoint {} must be > last user_leaf checkpoint {}",
                latest_checkpoint_id_u64,
                new_user.last_checkpoint_id.to_canonical_u64()
            );
        }

        new_user.last_checkpoint_id = latest_checkpoint_id_f;
        tracing::debug!("ups_start_checkpoint_id: {}", latest_checkpoint_id_u64);

        let current_checkpoint_leaf = lps
            .resolve_get_checkpoint_leaf_mut(&QSRCmdGetCheckpointLeafData {
                checkpoint_id: latest_checkpoint_id_u64,
            })
            .await?;

        let current_global_state_roots = lps.get_global_state_tree_roots(latest_checkpoint_id_u64).await?;

        tracing::debug!(
            "ups_start_global_state_roots: {}",
            serde_json::to_string_pretty(&current_global_state_roots).unwrap()
        );

        let current_state = UserProvingSessionCurrentState {
            user_leaf: new_user,
            deferred_tx_debt_tree_root: H::get_zero_hash(DEFERRED_TRANSACTION_TREE_HEIGHT as usize),
            inline_tx_debt_tree_root: H::get_zero_hash(INLINE_TRANSACTION_TREE_HEIGHT as usize),
            tx_hash_stack: QHashOut::ZERO,
            tx_count: F::ZERO,
        };

        let current_ups_header = UserProvingSessionHeader {
            ups_step_circuit_whitelist_root,
            session_start_context,
            current_state,
        };

        Ok(Self {
            lps: Some(lps),
            proof_tree_state,
            current_ups_header: current_ups_header.clone(),
            previous_ups_header: current_ups_header,
            current_checkpoint_leaf,
            current_global_state_roots,
            last_ups_step_proof_info: TreeAwareTreeProofRecord::default(),
            circuit_info,
            tx_log: vec![],
        })
    }

    /// Build a manager for **stateless step proving** with an empty proof tree
    /// and all checkpoint/header state seeded directly from the trace — no
    /// RPC and no `PsyLocalProvingSessionStore`. Stateless prove/finalize
    /// methods operate only on explicit trace/header/proof-tree inputs.
    pub async fn new_from_trace_anchor(
        circuit_info: SessionCircuitInfoStore<F>,
        ups_header: UserProvingSessionHeader<F>,
        checkpoint_leaf: PsyCheckpointLeaf<F>,
        global_state_roots: PsyCheckpointGlobalStateRoots<F>,
    ) -> anyhow::Result<Self> {
        let proof_tree_state = PortableQTreeRecursionManager::<C, D>::new(UPS_SESSION_PROOF_TREE_HEIGHT as usize).await;
        Ok(Self {
            lps: None,
            proof_tree_state,
            current_ups_header: ups_header.clone(),
            previous_ups_header: ups_header,
            current_checkpoint_leaf: checkpoint_leaf,
            current_global_state_roots: global_state_roots,
            last_ups_step_proof_info: TreeAwareTreeProofRecord::default(),
            circuit_info,
            tx_log: vec![],
        })
    }

    pub async fn get_ups_start_witness(&mut self) -> anyhow::Result<UPSStartStepInput<F>> {
        let lps = self.require_lps_mut()?;
        let start_checkpoint_id = lps.get_current_start_checkpoint_id_u64();
        let current_write_checkpoint_id = lps.get_current_write_checkpoint_id_u64();
        let current_user_id = lps.get_current_user_id_64();
        tracing::info!(
            "resolve checkpoint tree proof at checkpoint {}, leaf checkpoint {}",
            current_write_checkpoint_id,
            start_checkpoint_id
        );
        let checkpoint_tree_proof = lps
            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetCheckpointTreeMerkleProof(QSRMerkleCmdGetCheckpointTreeMerkleProof {
                checkpoint_id: start_checkpoint_id,
                leaf_checkpoint_id: start_checkpoint_id,
            }))
            .await?;

        tracing::info!(
            "resolve user tree proof at checkpoint {}, start checkpoint {}, user {}",
            current_write_checkpoint_id,
            start_checkpoint_id,
            current_user_id,
        );
        let user_tree_proof = lps
            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserTreeMerkleProof(QSRMerkleCmdGetUserTreeMerkleProof {
                checkpoint_id: start_checkpoint_id,
                user_id: current_user_id,
            }))
            .await?;

        let mut state_roots = self.current_global_state_roots.clone();
        state_roots.user_tree_root = user_tree_proof.root;

        // Debug logging for checkpoint consistency
        let header_checkpoint_id = self.current_ups_header.session_start_context.checkpoint_id.to_canonical_u64();
        tracing::info!(
            "get_ups_start_witness: start_checkpoint_id={}, header.checkpoint_id={}, checkpoint_tree_proof.index={}",
            start_checkpoint_id,
            header_checkpoint_id,
            checkpoint_tree_proof.index
        );

        let input = UPSStartStepInput {
            ups_header: self.current_ups_header.clone(),
            checkpoint_leaf: self.current_checkpoint_leaf.clone(),
            state_roots,
            checkpoint_tree_proof,
            user_tree_proof,
        };
        Ok(input)
    }

    async fn build_register_user_input_from_start(&mut self, base_input: &UPSStartStepInput<F>) -> anyhow::Result<UPSStartStepRegisterUserInput<F>> {
        let lps = self.require_lps_mut()?;
        let start_checkpoint_id = lps.get_current_start_checkpoint_id_u64();
        let user_registration_tree_proof: MerkleProofCore<QHashOut<F>> = lps
            .resolve_get_merkle_proof_mut(&QSRMerkleCmd::GetUserRegistrationTreeMerkleProof(
                QSRMerkleCmdGetUserRegistrationTreeMerkleProof {
                    checkpoint_id: start_checkpoint_id,
                    leaf_index: get_registration_id_from_user_id(lps.get_current_user_id_64()),
                },
            ))
            .await?;

        Ok(UPSStartStepRegisterUserInput {
            ups_header: base_input.ups_header.clone(),
            checkpoint_leaf: base_input.checkpoint_leaf.clone(),
            state_roots: base_input.state_roots.clone(),
            checkpoint_tree_proof: base_input.checkpoint_tree_proof.clone(),
            user_tree_proof: base_input.user_tree_proof.clone(),
            user_registration_tree_proof,
        })
    }

    pub fn append_to_tx_log(&mut self, item: DPNProvingSessionSimpleMethodCall<F>) -> QHashOut<F> {
        let prev_hash_tip = self.current_ups_header.current_state.tx_hash_stack;
        let new_hash_tip = H::q_two_to_one(prev_hash_tip, item.qfhash::<H>());
        self.current_ups_header.current_state.tx_hash_stack = new_hash_tip;
        self.current_ups_header.current_state.tx_count += F::ONE;
        self.tx_log.push(item);
        new_hash_tip
    }

    pub fn current_tx_hash_stack(&self) -> QHashOut<F> {
        self.current_ups_header.current_state.tx_hash_stack
    }

    pub fn current_tx_count(&self) -> F {
        self.current_ups_header.current_state.tx_count
    }

    pub fn sd_key_transaction_infos(&self) -> Vec<psy_client_data::dpn::sd_key::SDKeyTransactionInfo<F>> {
        self.tx_log
            .iter()
            .map(|tx| psy_client_data::dpn::sd_key::SDKeyTransactionInfo::from(tx.to_compact::<H>()))
            .collect()
    }

    pub async fn prove_ups_start<CM: UPSCircuitManager<C, D> + ?Sized>(&mut self, circuit_mgr: &CM) -> anyhow::Result<()> {
        let mut timer = DebugTimer::new("prove_ups_start");
        timer.lap("start");
        tracing::info!("get_ups_start_witness");
        let input = self.get_ups_start_witness().await?;

        timer.lap("gen_witness");
        if !input.checkpoint_tree_proof.verify::<PsyHasher>() {
            tracing::error!(
                "input.checkpoint_tree_proof {}",
                serde_json::to_string_pretty(&input.checkpoint_tree_proof)?
            );
            anyhow::bail!("invalid checkpoint tree proof");
        }

        if !input.user_tree_proof.verify::<PsyHasher>() {
            tracing::error!("input.user_tree_proof {}", serde_json::to_string_pretty(&input.user_tree_proof)?);
            anyhow::bail!("invalid user tree proof");
        }

        let inner_public_inputs_hash = input.ups_header.qfhash::<H>();
        let is_new_user = self.require_lps()?.is_new_user();
        let proof = if is_new_user {
            if input.user_tree_proof.value != QHashOut::ZERO {
                tracing::error!(
                    "Expected user tree proof value to be ZERO for new user, got: {}",
                    input.user_tree_proof.value
                );
                anyhow::bail!("invalid user tree proof value for new user");
            }
            tracing::info!("new user detected, proving register-user start");
            let register_input = self.build_register_user_input_from_start(&input).await?;
            circuit_mgr.prove_ups_start_register_user(&register_input).await?
        } else {
            if input.ups_header.session_start_context.start_session_user_leaf.qfhash::<PsyHasher>() != input.user_tree_proof.value {
                tracing::error!(
                    "input.ups_header.session_start_context.start_session_user_leaf.qfhash::<PsyHasher>()!= input.user_tree_proof.value\n{:?}!= {:?}",
                    input
                        .ups_header
                        .session_start_context
                        .start_session_user_leaf
                        .qfhash::<PsyHasher>()
                        .to_string(),
                    input.user_tree_proof.value.to_string()
                );
                anyhow::bail!("value doesn't match user leaf");
            }
            // Debug: check checkpoint_id consistency
            let header_checkpoint_id = input.ups_header.session_start_context.checkpoint_id.to_canonical_u64();
            let proof_checkpoint_index = input.checkpoint_tree_proof.index;
            tracing::info!(
                "DEBUG: header checkpoint_id={}, checkpoint_tree_proof.index={}, match={}",
                header_checkpoint_id,
                proof_checkpoint_index,
                header_checkpoint_id == proof_checkpoint_index
            );
            if header_checkpoint_id != proof_checkpoint_index {
                tracing::error!(
                    "MISMATCH: session_start_context.checkpoint_id ({}) != checkpoint_tree_proof.index ({})",
                    header_checkpoint_id,
                    proof_checkpoint_index
                );
                anyhow::bail!(
                    "checkpoint_id mismatch: header={} vs proof={}",
                    header_checkpoint_id,
                    proof_checkpoint_index
                );
            }
            tracing::info!("circuit_mgr.ups_start.prove_base start");
            let proof = circuit_mgr.prove_ups_start(&input).await?;
            timer.lap("circuit_mgr.ups_start.prove_base");
            proof
        };

        timer.lap("prove_ups_start");
        let known_proof_tree_root = self.proof_tree_state.get_proof_tree_root().await;
        let last_ups_step_proof_index = self
            .proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: UPS_STEP_LEAF_TYPE,
                fingerprint: if is_new_user {
                    circuit_mgr.ups_start_register_user_circuit_fingerprint().await?
                } else {
                    circuit_mgr.ups_start_circuit_fingerprint().await?
                },
                verifier_data: if is_new_user {
                    circuit_mgr.ups_start_register_user_circuit_verifier_config().await?
                } else {
                    circuit_mgr.ups_start_circuit_verifier_config().await?
                },
                proof,
            })
            .await;
        self.last_ups_step_proof_info = TreeAwareTreeProofRecord {
            circuit_id: if self.require_lps()?.is_new_user() {
                LocalCircuitType::UPSStartRegisterUser.into()
            } else {
                LocalCircuitType::UPSStart.into()
            },
            inner_public_inputs_hash,
            known_proof_tree_root,
            proof_tree_index: last_ups_step_proof_index,
        };
        self.previous_ups_header = self.current_ups_header.clone();
        self.current_ups_header = input.ups_header;
        timer.lap("injest_single_leaf_proof");

        Ok(())
    }

    /// Stateless UPS start prove using a caller-provided witness, instead of
    /// re-reading latest checkpoint state from lps/provider.
    pub async fn prove_ups_start_step<CM: UPSCircuitManager<C, D> + ?Sized>(
        &mut self,
        circuit_mgr: &CM,
        input: UPSStartStepInput<F>,
        user_registration_tree_proof: Option<MerkleProofCore<QHashOut<F>>>,
        precomputed: Option<ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        // is_new_user comes from the trace, not LPS. The presence of a user
        // registration tree proof indicates a new user.
        let is_new_user = user_registration_tree_proof.is_some();

        // All checkpoint / state-root data comes from the trace input itself.

        if !input.checkpoint_tree_proof.verify::<PsyHasher>() {
            anyhow::bail!("invalid checkpoint tree proof");
        }
        if !input.user_tree_proof.verify::<PsyHasher>() {
            anyhow::bail!("invalid user tree proof");
        }

        let inner_public_inputs_hash = input.ups_header.qfhash::<H>();
        // When a previously-produced proof is supplied, re-inject it instead of
        // re-proving (staged / multi-session step proving). Otherwise prove now.
        let proof = if let Some(precomputed) = precomputed {
            precomputed
        } else if is_new_user {
            if input.user_tree_proof.value != QHashOut::ZERO {
                anyhow::bail!("invalid user tree proof value for new user");
            }
            let register_input = if let Some(user_registration_tree_proof) = user_registration_tree_proof {
                UPSStartStepRegisterUserInput {
                    ups_header: input.ups_header.clone(),
                    checkpoint_leaf: input.checkpoint_leaf,
                    state_roots: input.state_roots,
                    checkpoint_tree_proof: input.checkpoint_tree_proof.clone(),
                    user_tree_proof: input.user_tree_proof.clone(),
                    user_registration_tree_proof,
                }
            } else {
                self.build_register_user_input_from_start(&input).await?
            };
            circuit_mgr.prove_ups_start_register_user(&register_input).await?
        } else {
            if input.ups_header.session_start_context.start_session_user_leaf.qfhash::<PsyHasher>() != input.user_tree_proof.value {
                anyhow::bail!("value doesn't match user leaf");
            }
            circuit_mgr.prove_ups_start(&input).await?
        };

        let known_proof_tree_root = self.proof_tree_state.get_proof_tree_root().await;
        let last_ups_step_proof_index = self
            .proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: UPS_STEP_LEAF_TYPE,
                fingerprint: if is_new_user {
                    circuit_mgr.ups_start_register_user_circuit_fingerprint().await?
                } else {
                    circuit_mgr.ups_start_circuit_fingerprint().await?
                },
                verifier_data: if is_new_user {
                    circuit_mgr.ups_start_register_user_circuit_verifier_config().await?
                } else {
                    circuit_mgr.ups_start_circuit_verifier_config().await?
                },
                proof: proof.clone(),
            })
            .await;
        self.last_ups_step_proof_info = TreeAwareTreeProofRecord {
            circuit_id: if is_new_user {
                LocalCircuitType::UPSStartRegisterUser.into()
            } else {
                LocalCircuitType::UPSStart.into()
            },
            inner_public_inputs_hash,
            known_proof_tree_root,
            proof_tree_index: last_ups_step_proof_index,
        };
        Ok(proof)
    }

    pub async fn get_verify_previous_ups_step_proof_for(
        &mut self,
        previous_step_header: &UserProvingSessionHeader<F>,
    ) -> anyhow::Result<VerifyPreviousUPSStepProofInProofTreeInput<F>> {
        let ups_circuit_whitelist_merkle_proof = self
            .circuit_info
            .get_whitelist_merkle_proof(self.last_ups_step_proof_info.circuit_id)?
            .to_owned();
        let historical_root_proof = match self
            .proof_tree_state
            .find_zero_hash_proof_for_historical_root(self.last_ups_step_proof_info.known_proof_tree_root)
            .await
        {
            Some(p) => p,
            None => anyhow::bail!(
                "could not find historical root proof for root {:?}",
                self.last_ups_step_proof_info.known_proof_tree_root
            ),
        };
        let inclusion_proof = self
            .proof_tree_state
            .get_leaf_merkle_proof(self.last_ups_step_proof_info.proof_tree_index)
            .await;

        let proof_attestation_witness = AttestTreeAwareProofInTreeInput {
            fingerprint: ups_circuit_whitelist_merkle_proof.value,
            inner_public_inputs_hash: self.last_ups_step_proof_info.inner_public_inputs_hash,
            historical_root_proof,
            inclusion_proof,
        };

        if !proof_attestation_witness.verify::<H>() {
            anyhow::bail!("AttestTreeAwareProofInTreeInput verification failed for previous UPS step");
        }

        Ok(VerifyPreviousUPSStepProofInProofTreeInput {
            proof_attestation_witness,
            previous_step_header: previous_step_header.clone(),
            ups_circuit_whitelist_merkle_proof,
        })
    }

    pub async fn get_verify_previous_ups_step_proof(&mut self) -> anyhow::Result<VerifyPreviousUPSStepProofInProofTreeInput<F>> {
        let previous_step_header = self.current_ups_header.clone();
        self.get_verify_previous_ups_step_proof_for(&previous_step_header).await
    }

    async fn resolve_contract_function(&mut self, contract_id: u64, method_id: u32) -> anyhow::Result<(usize, DPNFunctionCircuitDefinition)> {
        let contract_def = self
            .require_lps_mut()?
            .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition { contract_id })
            .await?;

        let (fn_id, fn_code_def) = contract_def
            .functions
            .iter()
            .enumerate()
            .find_map(|(fn_id, f)| if f.method_id == method_id { Some((fn_id, f)) } else { None })
            .ok_or_else(|| anyhow::anyhow!("method ({}) not found in contract {}", method_id, contract_id))?;

        let fn_circuit_def = cfc_code_definition_to_dapen_fc(fn_code_def)?;
        Ok((fn_id, fn_circuit_def))
    }

    pub async fn prove_contract_call<CM: UPSCircuitManager<C, D> + ?Sized>(
        &mut self,
        circuit_mgr: &CM,
        contract_id: F,
        fn_id: u32,
        fn_circuit_def: &DPNFunctionCircuitDefinition,
        inputs: Vec<F>,
    ) -> anyhow::Result<()> {
        self.prove_standard_call(circuit_mgr, contract_id, fn_id, fn_circuit_def, inputs).await?;
        self.prove_burn_fee(circuit_mgr).await?;
        Ok(())
    }

    /// Compute the next `UserProvingSessionCurrentState` after executing one
    /// standard (CFC) UPS step, using the execution-produced state delta.
    fn build_next_current_state(
        &self,
        state_delta_input: &UPSCFCStandardStateDeltaInput<F>,
        tx_log_item_hash: QHashOut<F>,
    ) -> UserProvingSessionCurrentState<F> {
        let cu = &self.current_ups_header.current_state;
        let new_step_user_leaf = PsyUserLeaf {
            public_key: cu.user_leaf.public_key,
            user_state_tree_root: state_delta_input.user_contract_tree_update_proof.new_root,
            balance: state_delta_input
                .cfc_transaction_input_context
                .transaction_call_start_ctx
                .start_user_balance,
            event_index: state_delta_input
                .cfc_transaction_input_context
                .transaction_call_start_ctx
                .start_user_event_index
                + state_delta_input.cfc_transaction_input_context.transaction_end_ctx.total_events_emitted,
            nonce: cu.user_leaf.nonce,
            last_checkpoint_id: cu.user_leaf.last_checkpoint_id,
            user_id: cu.user_leaf.user_id,
        };
        let new_step_tx_hash_stack = H::q_two_to_one(cu.tx_hash_stack, tx_log_item_hash);
        let new_step_tx_count = cu.tx_count + F::ONE;
        UserProvingSessionCurrentState {
            user_leaf: new_step_user_leaf,
            deferred_tx_debt_tree_root: state_delta_input
                .cfc_transaction_input_context
                .transaction_end_ctx
                .end_deferred_tx_debt_tree_root,
            inline_tx_debt_tree_root: state_delta_input.inline_tx_debt_pivot_proof.root,
            tx_hash_stack: new_step_tx_hash_stack,
            tx_count: new_step_tx_count,
        }
    }

    /// Execute a standard CFC call without generating any proofs.
    /// Mirrors CFC leaf + UPS step leaf values into the proof tree so that
    /// `session_proof_tree_root` stays in sync with the real prove path.
    pub async fn trace_standard_call<CM: UPSCircuitManager<C, D> + ?Sized>(
        &mut self,
        circuit_mgr: &CM,
        contract_id: F,
        fn_id: u32,
        fn_circuit_def: &DPNFunctionCircuitDefinition,
        inputs: Vec<F>,
    ) -> anyhow::Result<TracedCfcStep<F>> {
        let deferred_tx_pivot_index = self.require_lps()?.get_deferred_tx_debt_latest_index();
        let inline_tx_pivot_index = self.require_lps()?.get_inline_tx_debt_latest_index();
        let tx_log_item = DPNProvingSessionSimpleMethodCall {
            caller_contract_id: F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64),
            contract_id,
            method_id: F::from_canonical_u32(fn_circuit_def.method_id),
            inputs: inputs.clone(),
        };
        let proof_tree_start_root = self.proof_tree_state.get_proof_tree_root().await;

        let cfc_witness = self.exec_contract_call(contract_id, fn_circuit_def, inputs).await?;

        let (fn_circuit_fingerprint, _) = circuit_mgr.get_contract_method_common_data(contract_id.to_canonical_u64(), fn_id).await?;
        self.proof_tree_state
            .injest_single_leaf_value(
                fn_circuit_fingerprint,
                cfc_witness.session_proof_tree_root,
                cfc_witness.tx_input_ctx.qfhash::<H>(),
            )
            .await;

        let last_tx_rec: &PsyLocalTransactionRecord<F> = self.require_lps()?.last_transaction_record();
        let state_delta = UPSCFCStandardStateDeltaInput {
            cfc_transaction_input_context: cfc_witness.tx_input_ctx.clone(),
            user_contract_tree_update_proof: last_tx_rec.user_contract_tree_update_proof.clone(),
            deferred_tx_debt_pivot_proof: self.require_lps()?.get_deferred_tx_tree_leaf(deferred_tx_pivot_index)?,
            inline_tx_debt_pivot_proof: self.require_lps()?.get_inline_tx_tree_leaf(inline_tx_pivot_index)?,
        };

        let tx_log_item_hash = tx_log_item.qfhash::<H>();
        let new_step_current_state = self.build_next_current_state(&state_delta, tx_log_item_hash);
        let new_ups_header = UserProvingSessionHeader {
            ups_step_circuit_whitelist_root: self.current_ups_header.ups_step_circuit_whitelist_root,
            session_start_context: self.current_ups_header.session_start_context.clone(),
            current_state: new_step_current_state,
        };

        let ups_step_fingerprint = circuit_mgr.ups_cfc_standard_tx_circuit_fingerprint().await?;
        self.proof_tree_state
            .injest_single_leaf_value(
                ups_step_fingerprint,
                self.proof_tree_state.get_proof_tree_root().await,
                new_ups_header.qfhash::<H>(),
            )
            .await;

        self.previous_ups_header = std::mem::replace(&mut self.current_ups_header, new_ups_header);
        self.tx_log.push(tx_log_item);
        let proof_tree_root = self.proof_tree_state.get_proof_tree_root().await;
        self.require_lps_mut()?.set_proof_tree_root(proof_tree_root);
        let proof_tree_end_root = self.proof_tree_state.get_proof_tree_root().await;
        let end_header = self.current_ups_header.clone();

        let deferred_items = self.require_lps()?.last_transaction_record().added_deferred_tx_items.clone();
        let mut deferred = Vec::with_capacity(deferred_items.len());
        for debt_item in &deferred_items {
            deferred.push(Box::pin(self.trace_deferred_call(circuit_mgr, debt_item)).await?);
        }

        Ok(TracedCfcStep {
            contract_id: contract_id.to_canonical_u64(),
            fn_id,
            method_id: fn_circuit_def.method_id,
            method_name: fn_circuit_def.name.clone(),
            cfc_fingerprint: fn_circuit_fingerprint,
            ups_fingerprint: ups_step_fingerprint,
            proof_tree_start_root,
            proof_tree_end_root,
            cfc_witness,
            state_delta,
            cfc_inclusion_proof: self
                .require_lps_mut()?
                .get_contract_function_inclusion_proof(contract_id.to_canonical_u64() as u32, fn_id)
                .await?,
            end_header,
            debt_removal_proof: None,
            deferred,
        })
    }
    pub async fn prove_standard_call<CM: UPSCircuitManager<C, D> + ?Sized>(
        &mut self,
        circuit_mgr: &CM,
        contract_id: F,
        fn_id: u32,
        fn_circuit_def: &DPNFunctionCircuitDefinition,
        inputs: Vec<F>,
    ) -> anyhow::Result<()> {
        // if self.last_ups_step_proof_info.circuit_id.circuit_type ==
        // LocalCircuitType::Unknown {     tracing::warn!(
        //         "last_ups_step_proof_info is Unknown before prove_standard_call;
        // proving UPS start as recovery"     );
        //     self.prove_ups_start(circuit_mgr).await?;
        // }

        let deferred_tx_pivot_index = self.require_lps()?.get_deferred_tx_debt_latest_index();
        let inline_tx_pivot_index = self.require_lps()?.get_inline_tx_debt_latest_index();
        let tx_log_item = DPNProvingSessionSimpleMethodCall {
            caller_contract_id: F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64),
            contract_id,
            method_id: F::from_canonical_u32(fn_circuit_def.method_id),
            inputs: inputs.clone(),
        };
        // Ensure the underlying contract circuit is registered before we request
        // common data or prove the call. Some paths, such as the implicit fee burn,
        // only resolve the method id locally and would otherwise miss the cache.
        let contract_code = self
            .require_lps_mut()?
            .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition {
                contract_id: contract_id.to_canonical_u64(),
            })
            .await?;
        let (resolved_fn_id, _) = circuit_mgr
            .resolve_contract_function_by_method_id(contract_id.to_canonical_u64(), &contract_code, fn_circuit_def.method_id)
            .await?;
        if resolved_fn_id as u32 != fn_id {
            anyhow::bail!(
                "resolved fn_id mismatch for contract {} method {}: expected {}, got {}",
                contract_id,
                fn_circuit_def.method_id,
                fn_id,
                resolved_fn_id
            );
        }
        let (fn_circuit_fingerprint, fn_circuit_verifier_data) =
            circuit_mgr.get_contract_method_common_data(contract_id.to_canonical_u64(), fn_id).await?;
        let cfc_proof_input = self.exec_contract_call(contract_id, fn_circuit_def, inputs).await?;
        let cfc_proof = circuit_mgr
            .prove_contract_call(contract_id.to_canonical_u64(), fn_id, &cfc_proof_input)
            .await?;
        let cfc_proof_index = self
            .proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: CFC_LEAF_TYPE,
                fingerprint: fn_circuit_fingerprint,
                verifier_data: fn_circuit_verifier_data,
                proof: cfc_proof,
            })
            .await;
        let cfc_inclusion_proof = self
            .require_lps_mut()?
            .get_contract_function_inclusion_proof(contract_id.to_canonical_u64() as u32, fn_id)
            .await?;
        let historical_root_proof = match self
            .proof_tree_state
            .find_zero_hash_proof_for_historical_root(cfc_proof_input.session_proof_tree_root)
            .await
        {
            Some(mp) => mp,
            None => anyhow::bail!("error finding historical root proof in proof_tree_state"),
        };
        let checkpoint_state = self.get_checkpoint_state();
        let last_tx_rec: &PsyLocalTransactionRecord<GoldilocksField> = self.require_lps()?.last_transaction_record();
        let user_contract_tree_update_proof = last_tx_rec.user_contract_tree_update_proof.clone();
        let deferred_tx_debt_pivot_proof = self.require_lps()?.get_deferred_tx_tree_leaf(deferred_tx_pivot_index)?;
        let inline_tx_debt_pivot_proof = self.require_lps()?.get_inline_tx_tree_leaf(inline_tx_pivot_index)?;
        let new_step_deferred_tx_debt_tree_root = deferred_tx_debt_pivot_proof.root;
        let new_step_inline_tx_debt_tree_root = inline_tx_debt_pivot_proof.root;
        let proof_tree_inclusion_proof = self.proof_tree_state.get_leaf_merkle_proof(cfc_proof_index).await;
        let new_step_known_proof_tree_root = proof_tree_inclusion_proof.root;
        let verify_cfc_proof_input = AttestTreeAwareProofInTreeInput {
            fingerprint: fn_circuit_fingerprint,
            inner_public_inputs_hash: cfc_proof_input.tx_input_ctx.qfhash::<H>(),
            historical_root_proof,
            inclusion_proof: proof_tree_inclusion_proof,
        };

        if !verify_cfc_proof_input.verify::<H>() {
            anyhow::bail!("AttestTreeAwareProofInTreeInput verification failed for CFC standard step");
        }

        let process_cfc_state_delta_input = UPSCFCStandardStateDeltaInput {
            cfc_transaction_input_context: cfc_proof_input.tx_input_ctx,
            user_contract_tree_update_proof,
            deferred_tx_debt_pivot_proof,
            inline_tx_debt_pivot_proof,
        };
        let new_step_user_leaf = PsyUserLeaf {
            public_key: self.current_ups_header.current_state.user_leaf.public_key,
            user_state_tree_root: process_cfc_state_delta_input.user_contract_tree_update_proof.new_root,
            balance: process_cfc_state_delta_input
                .cfc_transaction_input_context
                .transaction_call_start_ctx
                .start_user_balance,
            event_index: process_cfc_state_delta_input
                .cfc_transaction_input_context
                .transaction_call_start_ctx
                .start_user_event_index
                + process_cfc_state_delta_input
                    .cfc_transaction_input_context
                    .transaction_end_ctx
                    .total_events_emitted,
            nonce: self.current_ups_header.current_state.user_leaf.nonce,
            last_checkpoint_id: self.current_ups_header.current_state.user_leaf.last_checkpoint_id,
            user_id: self.current_ups_header.current_state.user_leaf.user_id,
        };
        let tx_log_item_hash = tx_log_item.qfhash::<H>();
        let new_step_tx_hash_stack = H::q_two_to_one(self.current_ups_header.current_state.tx_hash_stack, tx_log_item_hash);
        let new_step_tx_count = self.current_ups_header.current_state.tx_count + F::ONE;
        let new_step_current_state = UserProvingSessionCurrentState {
            user_leaf: new_step_user_leaf,
            deferred_tx_debt_tree_root: process_cfc_state_delta_input
                .cfc_transaction_input_context
                .transaction_end_ctx
                .end_deferred_tx_debt_tree_root,
            inline_tx_debt_tree_root: process_cfc_state_delta_input.inline_tx_debt_pivot_proof.root,
            tx_hash_stack: new_step_tx_hash_stack,
            tx_count: new_step_tx_count,
        };
        let ups_cfc_standard_input = UPSVerifyCFCStandardStepInput {
            checkpoint_state,
            verify_cfc_proof_input,
            cfc_inclusion_proof,
            process_cfc_state_delta_input,
        };
        let verify_previous_ups_step = self.get_verify_previous_ups_step_proof().await?;
        let circuit_input = UPSCFCStandardTransactionCircuitInput {
            verify_previous_ups_step,
            standard_cfc_step: ups_cfc_standard_input,
        };
        tracing::info!(
            "UPS standard tx input: {}",
            serde_json::to_string_pretty(&circuit_input.standard_cfc_step)?
        );
        let ups_proof = circuit_mgr.prove_ups_cfc_standard_tx(&circuit_input).await?;

        self.last_ups_step_proof_info.circuit_id = LocalCircuitType::UPSCFCStandard.into();
        let new_ups_header = UserProvingSessionHeader {
            ups_step_circuit_whitelist_root: self.current_ups_header.ups_step_circuit_whitelist_root,
            session_start_context: self.current_ups_header.session_start_context.clone(),
            current_state: new_step_current_state,
        };
        let ups_step_proof_tree_index = self
            .proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: UPS_STEP_LEAF_TYPE,
                fingerprint: circuit_mgr.ups_cfc_standard_tx_circuit_fingerprint().await?,
                verifier_data: circuit_mgr.ups_cfc_standard_tx_circuit_verifier_config().await?,
                proof: ups_proof,
            })
            .await;
        self.last_ups_step_proof_info = TreeAwareTreeProofRecord {
            inner_public_inputs_hash: new_ups_header.qfhash::<H>(),
            circuit_id: LocalCircuitType::UPSCFCStandard.into(),
            known_proof_tree_root: new_step_known_proof_tree_root,
            proof_tree_index: ups_step_proof_tree_index,
        };
        self.previous_ups_header = self.current_ups_header.clone();
        self.current_ups_header = new_ups_header;
        self.tx_log.push(tx_log_item);

        let deferred_debt_items = self.require_lps()?.last_transaction_record().added_deferred_tx_items.clone();

        for debt_item in &deferred_debt_items {
            self.repay_deferred_debt(circuit_mgr, debt_item).await?;
        }

        let proof_tree_root = self.proof_tree_state.get_proof_tree_root().await;
        self.require_lps_mut()?.set_proof_tree_root(proof_tree_root);

        Ok(())
    }

    /// Prove a standard CFC + UPS step from trace witness (no re-execution, no
    /// lps queries). This is the lps-free step proving path.
    pub async fn prove_step_standard<CM: UPSCircuitManager<C, D> + ?Sized>(
        &mut self,
        circuit_mgr: &CM,
        checkpoint_state: PsyCheckpointLeafCompactWithStateRoots<F>,
        previous_step_header: &UserProvingSessionHeader<F>,
        step: &TraceStandardStepInput<F>,
        precomputed: Option<CfcStepProofs<C>>,
    ) -> anyhow::Result<CfcStepProofs<C>> {
        let (fn_circuit_fingerprint, fn_circuit_verifier_data) = circuit_mgr.get_contract_method_common_data(step.contract_id, step.fn_id).await?;

        let cfc_witness = &step.cfc_witness;
        let state_delta = &step.state_delta;
        let cfc_inclusion_proof_from_step = &step.cfc_inclusion_proof;
        let end_header = &step.end_header;

        // Re-inject a previously-produced proof instead of re-proving (staged /
        // multi-session step proving), or prove now when none is supplied.
        let cfc_proof = match &precomputed {
            Some(p) => p.cfc_proof.clone(),
            None => circuit_mgr.prove_contract_call(step.contract_id, step.fn_id, cfc_witness).await?,
        };

        let cfc_proof_index = self
            .proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: CFC_LEAF_TYPE,
                fingerprint: fn_circuit_fingerprint,
                verifier_data: fn_circuit_verifier_data,
                proof: cfc_proof.clone(),
            })
            .await;

        let current_root = self.proof_tree_state.get_proof_tree_root().await;
        tracing::info!(
            "TRACE STEP standard current_root={} witness_session_root={}",
            current_root,
            cfc_witness.session_proof_tree_root
        );
        let start_ctx = &state_delta.cfc_transaction_input_context.transaction_call_start_ctx;
        let prev = &previous_step_header.current_state;
        if start_ctx.start_user_contract_tree_root != prev.user_leaf.user_state_tree_root {
            anyhow::bail!(
                "trace step standard start_user_contract_tree_root mismatch: witness={} prev_header={}",
                start_ctx.start_user_contract_tree_root,
                prev.user_leaf.user_state_tree_root
            );
        }
        if start_ctx.start_user_balance != prev.user_leaf.balance {
            anyhow::bail!(
                "trace step standard start_user_balance mismatch: witness={} prev_header={}",
                start_ctx.start_user_balance,
                prev.user_leaf.balance
            );
        }
        if start_ctx.start_user_event_index != prev.user_leaf.event_index {
            anyhow::bail!(
                "trace step standard start_user_event_index mismatch: witness={} prev_header={}",
                start_ctx.start_user_event_index,
                prev.user_leaf.event_index
            );
        }
        if start_ctx.start_deferred_tx_debt_tree_root != prev.deferred_tx_debt_tree_root {
            anyhow::bail!(
                "trace step standard start_deferred_tx_debt_tree_root mismatch: witness={} prev_header={}",
                start_ctx.start_deferred_tx_debt_tree_root,
                prev.deferred_tx_debt_tree_root
            );
        }
        let proof_tree_inclusion_proof = self.proof_tree_state.get_leaf_merkle_proof(cfc_proof_index).await;
        let new_step_known_proof_tree_root = proof_tree_inclusion_proof.root;

        let ups_proof = match &precomputed {
            Some(p) => p.ups_proof.clone(),
            None => {
                let historical_root_proof = match self
                    .proof_tree_state
                    .find_zero_hash_proof_for_historical_root(cfc_witness.session_proof_tree_root)
                    .await
                {
                    Some(mp) => mp,
                    None => anyhow::bail!("historical root proof not found during lps-free step proving"),
                };
                let verify_cfc_proof_input = AttestTreeAwareProofInTreeInput {
                    fingerprint: fn_circuit_fingerprint,
                    inner_public_inputs_hash: cfc_witness.tx_input_ctx.qfhash::<H>(),
                    historical_root_proof,
                    inclusion_proof: proof_tree_inclusion_proof,
                };
                if !verify_cfc_proof_input.verify::<H>() {
                    anyhow::bail!("AttestTreeAwareProofInTreeInput verification failed during lps-free step proving");
                }

                let ups_cfc_standard_input = UPSVerifyCFCStandardStepInput {
                    checkpoint_state,
                    verify_cfc_proof_input,
                    cfc_inclusion_proof: cfc_inclusion_proof_from_step.clone(),
                    process_cfc_state_delta_input: state_delta.clone(),
                };
                let verify_previous_ups_step = self.get_verify_previous_ups_step_proof_for(previous_step_header).await?;
                let circuit_input = UPSCFCStandardTransactionCircuitInput {
                    verify_previous_ups_step,
                    standard_cfc_step: ups_cfc_standard_input,
                };
                circuit_mgr.prove_ups_cfc_standard_tx(&circuit_input).await?
            }
        };

        let ups_step_proof_tree_index = self
            .proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: UPS_STEP_LEAF_TYPE,
                fingerprint: circuit_mgr.ups_cfc_standard_tx_circuit_fingerprint().await?,
                verifier_data: circuit_mgr.ups_cfc_standard_tx_circuit_verifier_config().await?,
                proof: ups_proof.clone(),
            })
            .await;
        self.last_ups_step_proof_info = TreeAwareTreeProofRecord {
            inner_public_inputs_hash: end_header.qfhash::<H>(),
            circuit_id: LocalCircuitType::UPSCFCStandard.into(),
            known_proof_tree_root: new_step_known_proof_tree_root,
            proof_tree_index: ups_step_proof_tree_index,
        };

        Ok(CfcStepProofs { cfc_proof, ups_proof })
    }

    /// Prove a deferred CFC + UPS step from trace witness (no re-execution, no
    pub async fn prove_step_deferred<CM: UPSCircuitManager<C, D> + ?Sized>(
        &mut self,
        circuit_mgr: &CM,
        checkpoint_state: PsyCheckpointLeafCompactWithStateRoots<F>,
        previous_step_header: &UserProvingSessionHeader<F>,
        step: &TraceDeferredStepInput<F>,
        precomputed: Option<CfcStepProofs<C>>,
    ) -> anyhow::Result<CfcStepProofs<C>> {
        let (fn_circuit_fingerprint, fn_circuit_verifier_data) = circuit_mgr.get_contract_method_common_data(step.contract_id, step.fn_id).await?;

        let cfc_witness = &step.cfc_witness;
        let state_delta = &step.state_delta;
        let cfc_inclusion_proof_from_step = &step.cfc_inclusion_proof;
        let debt_removal_proof = &step.debt_removal_proof;
        let end_header = &step.end_header;

        // Re-inject a previously-produced proof instead of re-proving (staged /
        // multi-session step proving), or prove now when none is supplied.
        let cfc_proof = match &precomputed {
            Some(p) => p.cfc_proof.clone(),
            None => circuit_mgr.prove_contract_call(step.contract_id, step.fn_id, cfc_witness).await?,
        };
        let cfc_proof_index = self
            .proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: CFC_LEAF_TYPE,
                fingerprint: fn_circuit_fingerprint,
                verifier_data: fn_circuit_verifier_data,
                proof: cfc_proof.clone(),
            })
            .await;

        let proof_tree_inclusion_proof = self.proof_tree_state.get_leaf_merkle_proof(cfc_proof_index).await;
        let new_step_known_proof_tree_root = proof_tree_inclusion_proof.root;

        let start_ctx = &state_delta.cfc_transaction_input_context.transaction_call_start_ctx;
        let prev = &previous_step_header.current_state;
        if start_ctx.start_user_contract_tree_root != prev.user_leaf.user_state_tree_root {
            anyhow::bail!(
                "trace step deferred start_user_contract_tree_root mismatch: witness={} prev_header={}",
                start_ctx.start_user_contract_tree_root,
                prev.user_leaf.user_state_tree_root
            );
        }
        if start_ctx.start_user_balance != prev.user_leaf.balance {
            anyhow::bail!(
                "trace step deferred start_user_balance mismatch: witness={} prev_header={}",
                start_ctx.start_user_balance,
                prev.user_leaf.balance
            );
        }
        if start_ctx.start_user_event_index != prev.user_leaf.event_index {
            anyhow::bail!(
                "trace step deferred start_user_event_index mismatch: witness={} prev_header={}",
                start_ctx.start_user_event_index,
                prev.user_leaf.event_index
            );
        }
        if start_ctx.start_deferred_tx_debt_tree_root != debt_removal_proof.new_root {
            anyhow::bail!(
                "trace step deferred start_deferred_tx_debt_tree_root mismatch: witness={} debt_new_root={}",
                start_ctx.start_deferred_tx_debt_tree_root,
                debt_removal_proof.new_root
            );
        }
        let expected_debt_leaf_hash = start_ctx.call_data.qfhash::<H>();
        if debt_removal_proof.old_value != expected_debt_leaf_hash {
            anyhow::bail!(
                "trace step deferred debt leaf hash mismatch: debt_old_value={} call_data_hash={}",
                debt_removal_proof.old_value,
                expected_debt_leaf_hash
            );
        }

        let ups_proof = match &precomputed {
            Some(p) => p.ups_proof.clone(),
            None => {
                let historical_root_proof = match self
                    .proof_tree_state
                    .find_zero_hash_proof_for_historical_root(cfc_witness.session_proof_tree_root)
                    .await
                {
                    Some(mp) => mp,
                    None => anyhow::bail!("historical root proof not found during lps-free deferred step proving"),
                };
                let verify_cfc_proof_input = AttestTreeAwareProofInTreeInput {
                    fingerprint: fn_circuit_fingerprint,
                    inner_public_inputs_hash: cfc_witness.tx_input_ctx.qfhash::<H>(),
                    historical_root_proof,
                    inclusion_proof: proof_tree_inclusion_proof,
                };
                if !verify_cfc_proof_input.verify::<H>() {
                    anyhow::bail!("AttestTreeAwareProofInTreeInput verification failed during lps-free deferred step proving");
                }
                let ups_cfc_standard_input = UPSVerifyCFCStandardStepInput {
                    checkpoint_state,
                    verify_cfc_proof_input,
                    cfc_inclusion_proof: cfc_inclusion_proof_from_step.clone(),
                    process_cfc_state_delta_input: state_delta.clone(),
                };
                let verify_previous_ups_step = self.get_verify_previous_ups_step_proof_for(previous_step_header).await?;
                let deferred_input = UPSCFCDeferredTransactionCircuitInput {
                    verify_previous_ups_step,
                    deferred_tx_cfc_step: UPSVerifyPopDeferredTxStepInput {
                        standard_cfc_verify_input: ups_cfc_standard_input,
                        ups_pop_deferred_tx_proof: debt_removal_proof.clone(),
                    },
                };
                circuit_mgr.prove_ups_cfc_deferred_tx(&deferred_input).await?
            }
        };

        let ups_step_proof_tree_index = self
            .proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: UPS_STEP_LEAF_TYPE,
                fingerprint: circuit_mgr.ups_cfc_deferred_tx_circuit_fingerprint().await?,
                verifier_data: circuit_mgr.ups_cfc_deferred_tx_circuit_verifier_config().await?,
                proof: ups_proof.clone(),
            })
            .await;
        self.last_ups_step_proof_info = TreeAwareTreeProofRecord {
            inner_public_inputs_hash: end_header.qfhash::<H>(),
            circuit_id: LocalCircuitType::UPSCFCDeferred.into(),
            known_proof_tree_root: new_step_known_proof_tree_root,
            proof_tree_index: ups_step_proof_tree_index,
        };

        Ok(CfcStepProofs { cfc_proof, ups_proof })
    }

    pub fn compute_sighash_from_header(network_magic: u64, user_id: F, current_header: &UserProvingSessionHeader<F>, nonce: F) -> QHashOut<F> {
        let mut end_user_leaf = current_header.current_state.user_leaf.clone();
        end_user_leaf.nonce = nonce;

        let sig_data = PsyUserProvingSessionSignatureDataCompact {
            start_user_leaf_hash: current_header.session_start_context.start_session_user_leaf.qfhash::<H>(),
            end_user_leaf_hash: end_user_leaf.qfhash::<H>(),
            checkpoint_leaf_hash: current_header.session_start_context.checkpoint_leaf_hash,
            tx_stack_hash: current_header.current_state.tx_hash_stack,
            tx_count: current_header.current_state.tx_count,
        };

        let sign_context = SignContext {
            checkpoint_tree_root: current_header.session_start_context.checkpoint_tree_root,
            user_leaf: current_header.current_state.user_leaf,
        };

        sig_data
            .get_sig_action_for_user::<H>(network_magic, user_id, nonce, sign_context)
            .get_qhash::<H>()
    }

    pub fn get_sighash(&self, network_magic: u64, nonce: F) -> QHashOut<F> {
        Self::compute_sighash_from_header(
            network_magic,
            self.current_ups_header.current_state.user_leaf.user_id,
            &self.current_ups_header,
            nonce,
        )
    }

    pub async fn prove_burn_fee<CM: UPSCircuitManager<C, D> + ?Sized>(&mut self, circuit_mgr: &CM) -> anyhow::Result<()> {
        tracing::info!("Adding burn transaction for GUTA fee: {}", GUTA_FEE);

        // Fee estimation must be side-effect free. Calling get_all_state_updates()
        // here mutates and re-proves the in-session trees, which can desync the next
        // burn transaction witness from tracked slot versions.
        let mut total_slots_modified = self.require_lps()?.get_total_modified_slots_for_fee();
        let has_contract_0_slot_0 = self.require_lps()?.has_positional_slot_update(TOKEN_CONTRACT_ID as u64, 0);

        if !has_contract_0_slot_0 {
            total_slots_modified += 1;
        }

        let total_da_fee = DA_FEE * total_slots_modified as u64;

        tracing::info!("Adding burn transaction for DA fee: {}", total_da_fee);

        let (burn_fn_id, burn_fn_circuit_def) = self
            .resolve_contract_function(TOKEN_CONTRACT_ID as u64, TOKEN_SIMPLE_BURN_METHOD_ID)
            .await?;

        let burn_contract_id = F::from_canonical_u64(TOKEN_CONTRACT_ID as u64);
        let burn_amount = F::from_canonical_u64(GUTA_FEE + total_da_fee);
        let burn_inputs = vec![burn_amount];

        tracing::info!("Executing burn transaction: contract_id={}, amount={}", burn_contract_id, burn_amount);

        self.prove_standard_call(circuit_mgr, burn_contract_id, burn_fn_id as u32, &burn_fn_circuit_def, burn_inputs)
            .await?;

        Ok(())
    }

    /// Add a standalone ZK signature proof leaf into the session proof tree.
    /// Returns the inserted leaf index. End-cap proving consumes the same leaf
    /// later; this method only advances the proof tree.
    pub async fn add_zk_signature_proof(
        &mut self,
        fingerprint: QHashOut<F>,
        proof: ProofWithPublicInputs<F, C, D>,
        verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> u64 {
        self.proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: ZK_SIG_LEAF_TYPE,
                fingerprint,
                verifier_data,
                proof,
            })
            .await
    }

    /// Add an external proof (e.g. private note inclusion proof) to session
    /// proof tree. Returns the inserted leaf index.
    pub async fn add_external_proof(
        &mut self,
        fingerprint: QHashOut<F>,
        proof: ProofWithPublicInputs<F, C, D>,
        verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> u64 {
        self.proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: EXTERNAL_PROOF_LEAF_TYPE,
                fingerprint,
                verifier_data,
                proof,
            })
            .await
    }

    pub async fn prove_end_cap<CM: UPSCircuitManager<C, D> + psy_vm::ups::circuit_manager::PortableQTreeRecursion<C, D> + ?Sized>(
        &mut self,
        circuit_mgr: &CM,
        network_magic: u64,
        nonce: F,
        slots_modified: F,
        zk_sig_fingerprint: QHashOut<F>,
        public_key_param: QHashOut<F>,
        signature_proof: ProofWithPublicInputs<F, C, D>,
        verifier_data: VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        if signature_proof.public_inputs.len() != 4 {
            anyhow::bail!("signature proof must have 4 public inputs");
        }

        // ensure the signature is correct
        let expected_sighash = self.get_sighash(network_magic, nonce);
        let expected_public_inputs_hash = H::q_two_to_one(expected_sighash, public_key_param);
        tracing::info!(
            "Expected public inputs hash: H::q_two_to_one({}, {}) = {}",
            expected_sighash,
            public_key_param,
            expected_public_inputs_hash
        );

        let proof_public_inputs_hash = QHashOut(HashOut {
            elements: [
                signature_proof.public_inputs[0],
                signature_proof.public_inputs[1],
                signature_proof.public_inputs[2],
                signature_proof.public_inputs[3],
            ],
        });
        tracing::info!(
            "Actual proof public inputs: [{}, {}, {}, {}] = {}",
            signature_proof.public_inputs[0],
            signature_proof.public_inputs[1],
            signature_proof.public_inputs[2],
            signature_proof.public_inputs[3],
            proof_public_inputs_hash
        );
        if !proof_public_inputs_hash.eq(&expected_public_inputs_hash) {
            anyhow::bail!(
                "invalid signature for ups session, likely incorrect sighash\n{:?}!= {:?}",
                proof_public_inputs_hash.to_string(),
                expected_public_inputs_hash.to_string()
            );
        }

        // injest signature into the proof tree
        tracing::info!(
            "injesting zk signature proof into proof tree, fingerprint: {:?}",
            zk_sig_fingerprint.to_string()
        );
        let zk_sig_proof_index = self
            .proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: ZK_SIG_LEAF_TYPE,
                fingerprint: zk_sig_fingerprint,
                proof: signature_proof,
                verifier_data,
            })
            .await;
        tracing::info!(
            zk_sig_proof_index,
            last_ups_step_proof_index = self.last_ups_step_proof_info.proof_tree_index,
            "zk signature proof inserted into proof tree"
        );

        // compress all proofs into a sign tree proof
        tracing::info!("compress all proofs into a sign tree proof");
        self.proof_tree_state.finalize_tree(circuit_mgr).await?;

        let zk_sig_leaf_proof = self.proof_tree_state.get_leaf_merkle_proof(zk_sig_proof_index).await;
        let verify_previous_ups_step_input = self.get_verify_previous_ups_step_proof().await?;
        let end_cap_from_proof_tree_input = UPSEndCapFromProofTreeGadgetInput {
            verify_previous_ups_step_input,
            verify_zk_signature_proof_input: AttestProofInTreeInput {
                fingerprint: zk_sig_fingerprint,
                public_inputs_hash: proof_public_inputs_hash,
                inclusion_proof: zk_sig_leaf_proof,
            },
            user_public_key_param: public_key_param,
            nonce,
            slots_modified,
            second_to_last_tx_hash_stack: self.previous_ups_header.current_state.tx_hash_stack,
        };
        let nonce_u64 = end_cap_from_proof_tree_input.nonce.to_canonical_u64();
        let slots_modified_u64 = end_cap_from_proof_tree_input.slots_modified.to_canonical_u64();
        tracing::info!(
            nonce = nonce_u64,
            slots_modified = slots_modified_u64,
            second_to_last_tx_hash_stack = %end_cap_from_proof_tree_input.second_to_last_tx_hash_stack,
            previous_user_leaf_hash = %end_cap_from_proof_tree_input.verify_previous_ups_step_input.previous_step_header.current_state.user_leaf.qfhash::<PsyHasher>(),
            current_tx_hash_stack = %self.current_ups_header.current_state.tx_hash_stack,
            "assembled end-cap witness input"
        );

        let finalized_proof_tree_record = self.proof_tree_state.get_finalized_proot_tree_record().await?;
        tracing::info!(
            finalized_fingerprint = %finalized_proof_tree_record.fingerprint,
            finalized_circuit_type = ?finalized_proof_tree_record.circuit_type,
            finalized_state_transition_start = %finalized_proof_tree_record.agg_header.state_transition_start,
            finalized_state_transition_end = %finalized_proof_tree_record.agg_header.state_transition_end,
            finalized_agg_circuit_whitelist_root = %finalized_proof_tree_record.agg_header.agg_circuit_whitelist_root,
            "finalized proof-tree record before prove_ups_end_cap"
        );

        let proof = circuit_mgr
            .prove_ups_end_cap(&self.circuit_info, &end_cap_from_proof_tree_input, &finalized_proof_tree_record)
            .await?;

        // update the user's nonce
        self.current_ups_header.current_state.user_leaf.nonce = nonce;
        let proof_tree_root = self.proof_tree_state.get_proof_tree_root().await;
        self.require_lps_mut()?.set_proof_tree_root(proof_tree_root);

        Ok(proof)
    }

    pub async fn prove_end_cap_step<CM: UPSCircuitManager<C, D> + psy_vm::ups::circuit_manager::PortableQTreeRecursion<C, D> + ?Sized>(
        &mut self,
        circuit_mgr: &CM,
        network_magic: u64,
        user_id: F,
        current_header: &UserProvingSessionHeader<F>,
        second_to_last_tx_hash_stack: QHashOut<F>,
        nonce: F,
        slots_modified: F,
        zk_sig_fingerprint: QHashOut<F>,
        public_key_param: QHashOut<F>,
        signature_proof: ProofWithPublicInputs<F, C, D>,
        verifier_data: VerifierOnlyCircuitData<C, D>,
        expected_zksign_proof_tree_root: Option<QHashOut<F>>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        if signature_proof.public_inputs.len() != 4 {
            anyhow::bail!("signature proof must have 4 public inputs");
        }

        let expected_sighash = Self::compute_sighash_from_header(network_magic, user_id, current_header, nonce);
        let expected_public_inputs_hash = H::q_two_to_one(expected_sighash, public_key_param);
        let proof_public_inputs_hash = QHashOut(HashOut {
            elements: [
                signature_proof.public_inputs[0],
                signature_proof.public_inputs[1],
                signature_proof.public_inputs[2],
                signature_proof.public_inputs[3],
            ],
        });
        if !proof_public_inputs_hash.eq(&expected_public_inputs_hash) {
            anyhow::bail!(
                "invalid signature for ups session, likely incorrect sighash\n{:?}!= {:?}",
                proof_public_inputs_hash.to_string(),
                expected_public_inputs_hash.to_string()
            );
        }

        let zk_sig_proof_index = self
            .proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: ZK_SIG_LEAF_TYPE,
                fingerprint: zk_sig_fingerprint,
                proof: signature_proof,
                verifier_data,
            })
            .await;
        if let Some(expected) = expected_zksign_proof_tree_root {
            let actual = self.proof_tree_state.get_proof_tree_root().await;
            if actual != expected {
                anyhow::bail!(
                    "trace step zksign root mismatch after signature proof insertion: runtime={} trace_end={}",
                    actual,
                    expected
                );
            }
        }
        self.proof_tree_state.finalize_tree(circuit_mgr).await?;

        let zk_sig_leaf_proof = self.proof_tree_state.get_leaf_merkle_proof(zk_sig_proof_index).await;
        let verify_previous_ups_step_input = self.get_verify_previous_ups_step_proof_for(current_header).await?;
        let end_cap_from_proof_tree_input = UPSEndCapFromProofTreeGadgetInput {
            verify_previous_ups_step_input,
            verify_zk_signature_proof_input: AttestProofInTreeInput {
                fingerprint: zk_sig_fingerprint,
                public_inputs_hash: proof_public_inputs_hash,
                inclusion_proof: zk_sig_leaf_proof,
            },
            user_public_key_param: public_key_param,
            nonce,
            slots_modified,
            second_to_last_tx_hash_stack,
        };

        let finalized_proof_tree_record = self.proof_tree_state.get_finalized_proot_tree_record().await?;
        let proof = circuit_mgr
            .prove_ups_end_cap(&self.circuit_info, &end_cap_from_proof_tree_input, &finalized_proof_tree_record)
            .await?;

        Ok(proof)
    }

    pub async fn exec_deferred_contract_call(
        &mut self,
        contract_id: F,
        caller_contract_id: F,
        fn_circuit_def: &DPNFunctionCircuitDefinition,
        inputs: Vec<F>,
    ) -> anyhow::Result<DapenContractFunctionCircuitInput<F>> {
        let proof_tree_root = self.proof_tree_state.get_proof_tree_root().await;
        let lps = self.require_lps_mut()?;
        lps.set_proof_tree_root(proof_tree_root);
        PsyEvalSessionResult::new()
            .exec_deferred_contract_call(lps, contract_id, caller_contract_id, fn_circuit_def, inputs)
            .await
    }

    pub async fn exec_deferred_contract_call_local(
        &mut self,
        caller_contract_id: F,
        fn_circuit_def: &DPNFunctionCircuitDefinition,
        inputs: Vec<F>,
    ) -> anyhow::Result<DapenContractFunctionCircuitInput<F>> {
        let proof_tree_root = self.proof_tree_state.get_proof_tree_root().await;
        let lps = self.require_lps_mut()?;
        lps.set_proof_tree_root(proof_tree_root);
        PsyEvalSessionResult::new()
            .exec_deferred_contract_call_local(lps, caller_contract_id, fn_circuit_def, inputs)
            .await
    }

    pub async fn exec_contract_call(
        &mut self,
        contract_id: F,
        fn_circuit_def: &DPNFunctionCircuitDefinition,
        inputs: Vec<F>,
    ) -> anyhow::Result<DapenContractFunctionCircuitInput<F>> {
        self.exec_deferred_contract_call(contract_id, F::from_canonical_u64(DEFAULT_CALLER_CONTRACT_ID_U64), fn_circuit_def, inputs)
            .await
    }

    async fn repay_deferred_debt<CM: UPSCircuitManager<C, D> + ?Sized>(
        &mut self,
        circuit_mgr: &CM,
        initial_debt_item: &DPNTransactionDebtItem<DPNProvingSessionSimpleMethodCall<F>, F>,
    ) -> anyhow::Result<()> {
        let mut debt_queue = vec![initial_debt_item.clone()];

        while let Some(debt_item) = debt_queue.pop() {
            self.prove_deferred_call(circuit_mgr, &debt_item).await?;

            let new_debt_items = self.require_lps()?.last_transaction_record().added_deferred_tx_items.clone();

            debt_queue.extend(new_debt_items);
        }

        Ok(())
    }

    async fn prove_deferred_call<CM: UPSCircuitManager<C, D> + ?Sized>(
        &mut self,
        circuit_mgr: &CM,
        debt_item: &DPNTransactionDebtItem<DPNProvingSessionSimpleMethodCall<F>, F>,
    ) -> anyhow::Result<()> {
        let (_, debt_removal_proof) = self.require_lps_mut()?.repay_deferred_tx_debt(debt_item.tree_index)?;
        let deferred_tx = &debt_item.call_data;
        let method_id = deferred_tx.method_id.to_canonical_u64() as u32;
        let contract_id = deferred_tx.contract_id.to_canonical_u64();

        let contract_def = self
            .require_lps_mut()?
            .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition { contract_id })
            .await?;
        let (fn_id, fn_circuit_def) = circuit_mgr
            .resolve_contract_function_by_method_id(contract_id, &contract_def, method_id)
            .await?;
        let cfc_proof_input = self
            .exec_deferred_contract_call(
                deferred_tx.contract_id,
                deferred_tx.caller_contract_id,
                &fn_circuit_def,
                deferred_tx.inputs.clone(),
            )
            .await?;

        let (fn_circuit_fingerprint, fn_circuit_verifier_data) = circuit_mgr
            .get_contract_method_common_data(deferred_tx.contract_id.to_canonical_u64(), fn_id as u32)
            .await?;
        let cfc_proof = circuit_mgr
            .prove_contract_call(deferred_tx.contract_id.to_canonical_u64(), fn_id as u32, &cfc_proof_input)
            .await?;
        let cfc_proof_index = self
            .proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: CFC_LEAF_TYPE,
                fingerprint: fn_circuit_fingerprint,
                verifier_data: fn_circuit_verifier_data,
                proof: cfc_proof,
            })
            .await;
        let historical_root_proof = match self
            .proof_tree_state
            .find_zero_hash_proof_for_historical_root(cfc_proof_input.session_proof_tree_root)
            .await
        {
            Some(mp) => mp,
            None => anyhow::bail!("error finding historical root proof in proof_tree_state"),
        };
        let checkpoint_state = self.get_checkpoint_state();
        let last_tx_rec = self.require_lps()?.last_transaction_record();
        let user_contract_tree_update_proof = last_tx_rec.user_contract_tree_update_proof.clone();
        let deferred_tx_pivot_index = debt_item.tree_index;
        let inline_tx_pivot_index = self.require_lps()?.get_inline_tx_debt_latest_index();
        let deferred_tx_debt_pivot_proof = self.require_lps()?.get_deferred_tx_tree_leaf(deferred_tx_pivot_index)?;
        let inline_tx_debt_pivot_proof = self.require_lps()?.get_inline_tx_tree_leaf(inline_tx_pivot_index)?;
        let proof_tree_inclusion_proof = self.proof_tree_state.get_leaf_merkle_proof(cfc_proof_index).await;
        let new_step_known_proof_tree_root = proof_tree_inclusion_proof.root;
        let verify_cfc_proof_input = AttestTreeAwareProofInTreeInput {
            fingerprint: fn_circuit_fingerprint,
            inner_public_inputs_hash: cfc_proof_input.tx_input_ctx.qfhash::<H>(),
            historical_root_proof,
            inclusion_proof: proof_tree_inclusion_proof,
        };

        if !verify_cfc_proof_input.verify::<H>() {
            anyhow::bail!("AttestTreeAwareProofInTreeInput verification failed for CFC deferred transaction step");
        }

        let process_cfc_state_delta_input = UPSCFCStandardStateDeltaInput {
            cfc_transaction_input_context: cfc_proof_input.tx_input_ctx,
            user_contract_tree_update_proof,
            deferred_tx_debt_pivot_proof: deferred_tx_debt_pivot_proof.clone(),
            inline_tx_debt_pivot_proof: inline_tx_debt_pivot_proof.clone(),
        };
        let cfc_inclusion_proof = self
            .require_lps_mut()?
            .get_contract_function_inclusion_proof(deferred_tx.contract_id.to_canonical_u64() as u32, fn_id.try_into().unwrap())
            .await?;
        let ups_cfc_standard_input = UPSVerifyCFCStandardStepInput {
            checkpoint_state,
            verify_cfc_proof_input,
            cfc_inclusion_proof,
            process_cfc_state_delta_input: process_cfc_state_delta_input.clone(),
        };
        let verify_previous_ups_step = self.get_verify_previous_ups_step_proof().await?;
        let deferred_input = UPSCFCDeferredTransactionCircuitInput {
            verify_previous_ups_step,
            deferred_tx_cfc_step: UPSVerifyPopDeferredTxStepInput {
                standard_cfc_verify_input: ups_cfc_standard_input,
                ups_pop_deferred_tx_proof: debt_removal_proof,
            },
        };
        let ups_proof = circuit_mgr.prove_ups_cfc_deferred_tx(&deferred_input).await?;
        self.last_ups_step_proof_info.circuit_id = LocalCircuitType::UPSCFCDeferred.into();
        let new_step_user_leaf = PsyUserLeaf {
            public_key: self.current_ups_header.current_state.user_leaf.public_key,
            user_state_tree_root: process_cfc_state_delta_input.user_contract_tree_update_proof.new_root,
            balance: process_cfc_state_delta_input
                .cfc_transaction_input_context
                .transaction_call_start_ctx
                .start_user_balance,
            event_index: process_cfc_state_delta_input
                .cfc_transaction_input_context
                .transaction_call_start_ctx
                .start_user_event_index
                + process_cfc_state_delta_input
                    .cfc_transaction_input_context
                    .transaction_end_ctx
                    .total_events_emitted,
            nonce: self.current_ups_header.current_state.user_leaf.nonce,
            last_checkpoint_id: self.current_ups_header.current_state.user_leaf.last_checkpoint_id,
            user_id: self.current_ups_header.current_state.user_leaf.user_id,
        };
        let tx_log_item = DPNProvingSessionSimpleMethodCall {
            caller_contract_id: deferred_tx.caller_contract_id,
            contract_id: deferred_tx.contract_id,
            method_id: deferred_tx.method_id,
            inputs: deferred_tx.inputs.clone(),
        };
        let tx_log_item_hash = tx_log_item.qfhash::<H>();
        let new_step_tx_hash_stack = H::q_two_to_one(self.current_ups_header.current_state.tx_hash_stack, tx_log_item_hash);
        let new_step_tx_count = self.current_ups_header.current_state.tx_count + F::ONE;
        let new_step_current_state = UserProvingSessionCurrentState {
            user_leaf: new_step_user_leaf,
            deferred_tx_debt_tree_root: process_cfc_state_delta_input
                .cfc_transaction_input_context
                .transaction_end_ctx
                .end_deferred_tx_debt_tree_root,
            inline_tx_debt_tree_root: process_cfc_state_delta_input.inline_tx_debt_pivot_proof.root,
            tx_hash_stack: new_step_tx_hash_stack,
            tx_count: new_step_tx_count,
        };
        let new_ups_header = UserProvingSessionHeader {
            ups_step_circuit_whitelist_root: self.current_ups_header.ups_step_circuit_whitelist_root,
            session_start_context: self.current_ups_header.session_start_context.clone(),
            current_state: new_step_current_state,
        };
        let ups_step_proof_tree_index = self
            .proof_tree_state
            .injest_single_leaf_proof(InputLeafProof {
                leaf_circuit_type: UPS_STEP_LEAF_TYPE,
                fingerprint: circuit_mgr.ups_cfc_deferred_tx_circuit_fingerprint().await?,
                verifier_data: circuit_mgr.ups_cfc_deferred_tx_circuit_verifier_config().await?,
                proof: ups_proof,
            })
            .await;
        self.last_ups_step_proof_info = TreeAwareTreeProofRecord {
            inner_public_inputs_hash: new_ups_header.qfhash::<H>(),
            circuit_id: LocalCircuitType::UPSCFCDeferred.into(),
            known_proof_tree_root: new_step_known_proof_tree_root,
            proof_tree_index: ups_step_proof_tree_index,
        };
        self.previous_ups_header = self.current_ups_header.clone();
        self.current_ups_header = new_ups_header;
        self.tx_log.push(tx_log_item);
        Ok(())
    }

    /// Execute a deferred call without generating proofs.
    /// Mirrors CFC leaf + UPS deferred step leaf. Returns witness + state delta
    /// + end header.
    pub async fn trace_deferred_call<CM: UPSCircuitManager<C, D> + ?Sized>(
        &mut self,
        circuit_mgr: &CM,
        debt_item: &DPNTransactionDebtItem<DPNProvingSessionSimpleMethodCall<F>, F>,
    ) -> anyhow::Result<TracedCfcStep<F>> {
        let proof_tree_start_root = self.proof_tree_state.get_proof_tree_root().await;
        let (_, debt_removal_proof) = self.require_lps_mut()?.repay_deferred_tx_debt(debt_item.tree_index)?;
        let deferred_tx = &debt_item.call_data;
        let method_id = deferred_tx.method_id.to_canonical_u64() as u32;
        let contract_id = deferred_tx.contract_id.to_canonical_u64();

        let contract_def = self
            .require_lps_mut()?
            .resolve_get_contract_code_mut(&QSRCmdGetContractCodeDefinition { contract_id })
            .await?;
        let (fn_id, fn_circuit_def) = circuit_mgr
            .resolve_contract_function_by_method_id(contract_id, &contract_def, method_id)
            .await?;

        let deferred_tx_pivot_index = self.require_lps()?.get_deferred_tx_debt_latest_index();
        let inline_tx_pivot_index = self.require_lps()?.get_inline_tx_debt_latest_index();
        let tx_log_item = DPNProvingSessionSimpleMethodCall {
            caller_contract_id: deferred_tx.caller_contract_id,
            contract_id: deferred_tx.contract_id,
            method_id: deferred_tx.method_id,
            inputs: deferred_tx.inputs.clone(),
        };

        let cfc_witness = self
            .exec_deferred_contract_call(
                deferred_tx.contract_id,
                deferred_tx.caller_contract_id,
                &fn_circuit_def,
                deferred_tx.inputs.clone(),
            )
            .await?;

        let (fn_circuit_fingerprint, _) = circuit_mgr.get_contract_method_common_data(contract_id, fn_id as u32).await?;
        self.proof_tree_state
            .injest_single_leaf_value(
                fn_circuit_fingerprint,
                cfc_witness.session_proof_tree_root,
                cfc_witness.tx_input_ctx.qfhash::<H>(),
            )
            .await;

        let last_tx_rec: &PsyLocalTransactionRecord<F> = self.require_lps()?.last_transaction_record();
        let state_delta = UPSCFCStandardStateDeltaInput {
            cfc_transaction_input_context: cfc_witness.tx_input_ctx.clone(),
            user_contract_tree_update_proof: last_tx_rec.user_contract_tree_update_proof.clone(),
            deferred_tx_debt_pivot_proof: self.require_lps()?.get_deferred_tx_tree_leaf(deferred_tx_pivot_index)?,
            inline_tx_debt_pivot_proof: self.require_lps()?.get_inline_tx_tree_leaf(inline_tx_pivot_index)?,
        };

        let tx_log_item_hash = tx_log_item.qfhash::<H>();
        let new_step_current_state = self.build_next_current_state(&state_delta, tx_log_item_hash);
        let new_ups_header = UserProvingSessionHeader {
            ups_step_circuit_whitelist_root: self.current_ups_header.ups_step_circuit_whitelist_root,
            session_start_context: self.current_ups_header.session_start_context.clone(),
            current_state: new_step_current_state,
        };

        let ups_step_fingerprint = circuit_mgr.ups_cfc_deferred_tx_circuit_fingerprint().await?;
        self.proof_tree_state
            .injest_single_leaf_value(
                ups_step_fingerprint,
                self.proof_tree_state.get_proof_tree_root().await,
                new_ups_header.qfhash::<H>(),
            )
            .await;

        self.previous_ups_header = std::mem::replace(&mut self.current_ups_header, new_ups_header);
        self.tx_log.push(tx_log_item);
        let proof_tree_root = self.proof_tree_state.get_proof_tree_root().await;
        self.require_lps_mut()?.set_proof_tree_root(proof_tree_root);
        let proof_tree_end_root = self.proof_tree_state.get_proof_tree_root().await;
        let end_header = self.current_ups_header.clone();

        let new_items = self.require_lps()?.last_transaction_record().added_deferred_tx_items.clone();
        let mut deferred = Vec::with_capacity(new_items.len());
        for child_item in &new_items {
            deferred.push(Box::pin(self.trace_deferred_call(circuit_mgr, child_item)).await?);
        }

        Ok(TracedCfcStep {
            contract_id,
            fn_id: fn_id as u32,
            method_id,
            method_name: fn_circuit_def.name.clone(),
            cfc_fingerprint: fn_circuit_fingerprint,
            ups_fingerprint: ups_step_fingerprint,
            proof_tree_start_root,
            proof_tree_end_root,
            cfc_witness,
            state_delta,
            cfc_inclusion_proof: self
                .require_lps_mut()?
                .get_contract_function_inclusion_proof(contract_id as u32, fn_id as u32)
                .await?,
            end_header,
            debt_removal_proof: Some(debt_removal_proof),
            deferred,
        })
    }

    /// Execute burn fee without generating proofs.
    pub async fn trace_burn_fee<CM: UPSCircuitManager<C, D> + ?Sized>(&mut self, circuit_mgr: &CM) -> anyhow::Result<TracedCfcStep<F>> {
        let mut total_slots_modified = self.require_lps()?.get_total_modified_slots_for_fee();
        let has_contract_0_slot_0 = self.require_lps()?.has_positional_slot_update(TOKEN_CONTRACT_ID as u64, 0);
        if !has_contract_0_slot_0 {
            total_slots_modified += 1;
        }
        let total_da_fee = DA_FEE * total_slots_modified as u64;

        let (burn_fn_id, burn_fn_circuit_def) = self
            .resolve_contract_function(TOKEN_CONTRACT_ID as u64, TOKEN_SIMPLE_BURN_METHOD_ID)
            .await?;

        let burn_contract_id = F::from_canonical_u64(TOKEN_CONTRACT_ID as u64);
        let burn_amount = F::from_canonical_u64(GUTA_FEE + total_da_fee);
        let burn_inputs = vec![burn_amount];

        self.trace_standard_call(circuit_mgr, burn_contract_id, burn_fn_id as u32, &burn_fn_circuit_def, burn_inputs)
            .await
    }

    pub async fn get_api_input(&mut self) -> anyhow::Result<SubmitUserEndCapNonProofInput<F>> {
        let checkpoint_id = self.current_ups_header.current_state.user_leaf.last_checkpoint_id;

        let updates = self.get_user_session_update_history().await?;

        let start_user_leaf_hash = if self.require_lps()?.is_new_user() {
            QHashOut::<F>::ZERO
        } else {
            self.current_ups_header.session_start_context.start_session_user_leaf.qfhash::<H>()
        };
        let core = SubmitUserEndCapNonProofCoreInput {
            checkpoint_id,
            stats: GUTAStats {
                guta_fees_collected: F::from_canonical_u64(GUTA_FEE),
                da_fees_collected: F::from_canonical_u64(DA_FEE * updates.total_slots_modified as u64),
                user_ops_processed: F::from_noncanonical_u64(1),
                total_transactions: self.current_ups_header.current_state.tx_count,
                slots_modified: F::from_canonical_u32(updates.total_slots_modified),
            },
            state_transition: UPSEndCapResultCompact {
                start_user_leaf_hash,
                end_user_leaf_hash: self.current_ups_header.current_state.user_leaf.qfhash::<H>(),
                checkpoint_tree_root_hash: self.current_ups_header.session_start_context.checkpoint_tree_root,
                user_id: self.current_ups_header.session_start_context.start_session_user_leaf.user_id,
            },
            new_user_leaf: self.current_ups_header.current_state.user_leaf,
        };
        let contract_state_updates = updates.contract_updates;

        Ok(SubmitUserEndCapNonProofInput {
            core,
            contract_state_updates,
            events: self.require_lps()?.read_events(),
        })
    }

    pub async fn get_user_session_update_history(&mut self) -> anyhow::Result<PsyUserSessionUpdateHistory<F>> {
        let (contract_updates, total_slots_modified) = self.require_lps_mut()?.get_all_state_updates().await?;

        Ok(PsyUserSessionUpdateHistory {
            start_user_leaf: self.current_ups_header.session_start_context.start_session_user_leaf,
            end_user_leaf: self.current_ups_header.current_state.user_leaf,
            total_slots_modified,
            contract_updates,
        })
    }
}
