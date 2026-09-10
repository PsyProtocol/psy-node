use std::sync::{Arc, OnceLock};

use jsonrpsee::{core::async_trait, proc_macros::rpc, types::ErrorObjectOwned};
use parth_core::{
    crypto::hash::merkle_proof::DeltaMerkleProofCore as ParthDeltaMerkleProofCore, pgoldilocks::QHashOut as ParthQHashOut,
    protocol::core_types::QNetworkTreeConstants,
};
use plonky2::{
    field::types::{Field, PrimeField64},
    plonk::{circuit_data::CommonCircuitData, proof::ProofWithPublicInputs},
};
use psy_config::network_constants::{DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT, WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT};
use psy_core::{constants::chain_id::PsyChainNetworkType, job::job_id::ProvingJobCircuitType, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::v1::qdata::checkpoint::PQEDCheckpointGlobalStateRoots;
use psy_plonky2_basic_helpers::verifier::circuit_library::CircuitInfoLibraryCore;
use psy_plonky2_circuits::{
    bridge::{
        circuits::{
            bridge_agg_final::BridgeAggFinalCircuit,
            bridge_wrap::{BridgeWrapCircuit, DepositBatchWrapCircuit, SharedGroth16Wrapper, WithdrawalClaimWrapCircuit},
        },
        gadgets::tree_root_in_contract_state::TreeRootInContractStateWitnessInput,
    },
    circuit_library::get_plonky2_circuit_library_and_prover_for_network,
    coordinator::coordinator_helper::QEDCoordinatorCircuitManager,
};
use psy_plonky2_common_circuits::bridge::{
    deposit_batch_append_circuit::{
        compute_batch_append_preimage, BatchAppendInputs as DepositBatchAppendInputs, DepositBatchAppendCircuit,
        DepositLeafData as DepositBatchLeafData, MAX_DEPOSIT_BATCH_SIZE,
    },
    withdrawal_batch_claim_circuit::{
        WithdrawalBatchClaimCircuit, WithdrawalBatchClaimInputs, WithdrawalBatchClaimSlotInputs, MAX_WITHDRAWAL_CLAIM_BATCH_SIZE,
        WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS, WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS,
    },
};

use super::{
    types::*,
    C, D, F,
};

#[rpc(server, client, namespace = "psy")]
pub trait ProveProxySystemRpc {
    #[method(name = "prove_withdrawal_batch_claim_groth16")]
    async fn prove_withdrawal_batch_claim_groth16(
        &self,
        input: BridgeWithdrawalBatchWitnessInput,
    ) -> Result<BridgeWithdrawalBatchGroth16Proof, ErrorObjectOwned>;

    #[method(name = "prove_deposit_batch_append_groth16")]
    async fn prove_deposit_batch_append_groth16(
        &self,
        input: BridgeDepositBatchWitnessInput,
    ) -> Result<BridgeDepositBatchGroth16Proof, ErrorObjectOwned>;

    /// Bridge aggregation: checkpoints → BridgeAggCircuit → BridgeWrapCircuit →
    /// Groth16
    #[method(name = "prove_bridge_agg_groth16")]
    async fn prove_bridge_agg_groth16(&self, deps_network: String, input: BridgeAggWitnessInput) -> Result<BridgeAggGroth16Output, ErrorObjectOwned>;
}

pub struct SystemProveProvider {
    pub deposit_batch_wrap_circuit: Arc<DepositBatchWrapCircuit>,
    pub withdrawal_claim_wrap_circuit: Arc<WithdrawalClaimWrapCircuit>,
    pub bridge_wrap_circuit: Arc<BridgeWrapCircuit>,
    pub deposit_batch_groth16_wrapper: Arc<SharedGroth16Wrapper>,
    pub withdrawal_claim_groth16_wrapper: Arc<SharedGroth16Wrapper>,
    pub bridge_groth16_wrapper: Arc<SharedGroth16Wrapper>,
}

impl SystemProveProvider {
    /// Builds the bridge wrap circuits and preloads the three Groth16 keystores.
    /// Does not touch the coordinator RPC or the UPS circuit manager.
    pub fn new() -> anyhow::Result<Self> {
        use psy_plonky2_circuits::qstandard::QStandardCircuit;

        // ── Pre-build Groth16 wrapping circuits (shared across all threads) ──
        // These depend only on the inner circuit structure, not on runtime data.
        // Building once at startup saves ~200ms per request (CircuitBuilder::new +
        // builder.build).

        tracing::info!("Pre-building DepositBatchWrapCircuit...");
        let deposit_template = DepositBatchAppendCircuit::<C, D>::build(MAX_DEPOSIT_BATCH_SIZE, 32);
        let deposit_minifier = psy_plonky2_circuits::proof_minifier::pm_chain::QEDProofMinifierChain::<D, F, C>::new(
            &deposit_template.circuit_data.verifier_only,
            &deposit_template.circuit_data.common,
            2,
        );
        let deposit_fp = ParthQHashOut(deposit_minifier.get_fingerprint());
        let deposit_batch_wrap_circuit = Arc::new(DepositBatchWrapCircuit::new(
            deposit_minifier.get_common_data(),
            deposit_fp,
            deposit_minifier.get_verifier_data().constants_sigmas_cap.height(),
        ));
        let deposit_batch_groth16_wrapper = Arc::new(
            DepositBatchWrapCircuit::new(
                deposit_minifier.get_common_data(),
                deposit_fp,
                deposit_minifier.get_verifier_data().constants_sigmas_cap.height(),
            )
            .into_shared_groth16_wrapper(format!("{}/.psy/keystore/deposit_append/", dirs::home_dir().unwrap().display())),
        );

        tracing::info!("Pre-building WithdrawalClaimWrapCircuit...");
        let withdrawal_template = WithdrawalBatchClaimCircuit::<C, D>::build(32);
        let withdrawal_fp = ParthQHashOut(psy_plonky2_circuits::proof_minifier::pm_core::get_circuit_fingerprint_generic(
            &withdrawal_template.circuit_data.verifier_only,
        ));
        let withdrawal_claim_wrap_circuit = Arc::new(WithdrawalClaimWrapCircuit::new(
            &withdrawal_template.circuit_data.common,
            withdrawal_fp,
            withdrawal_template.circuit_data.verifier_only.constants_sigmas_cap.height(),
        ));
        let withdrawal_claim_groth16_wrapper = Arc::new(
            WithdrawalClaimWrapCircuit::new(
                &withdrawal_template.circuit_data.common,
                withdrawal_fp,
                withdrawal_template.circuit_data.verifier_only.constants_sigmas_cap.height(),
            )
            .into_shared_groth16_wrapper(format!("{}/.psy/keystore/withdrawal_claim/", dirs::home_dir().unwrap().display())),
        );

        tracing::info!("Pre-building BridgeWrapCircuit...");
        let coordinator_circuits = cached_bridge_coordinator_circuits()?;
        let checkpoint_common_data: &CommonCircuitData<F, D> = coordinator_circuits.checkpoint_root_transition.get_common_circuit_data_ref();
        let checkpoint_verifier_data = coordinator_circuits.checkpoint_root_transition.get_verifier_config_ref();
        let checkpoint_cap_height = checkpoint_verifier_data.constants_sigmas_cap.height();
        let coordinator_checkpoint_fp = coordinator_circuits.checkpoint_root_transition.get_fingerprint();
        // step_commit must use the cached library fingerprint (same as RCP circuit
        // genesis proving), NOT base_fingerprint or minifier get_fingerprint().
        let cached_lib = psy_plonky2_circuits::generated::cached_circuit_library::get_cached_circuit_library::<F>();
        let coordinator_checkpoint_step_commit_fp = cached_lib
            .get_fingerprint(ProvingJobCircuitType::GenerateRollupStateTransitionProof)
            .expect("GenerateRollupStateTransitionProof not found in cached circuit library");

        tracing::info!(
            "[PROXY] checkpoint minifier_fp={:?} step_commit_fp(cached)={:?}",
            coordinator_checkpoint_fp.0.elements,
            coordinator_checkpoint_step_commit_fp.0.elements,
        );

        let bridge_agg_template = BridgeAggFinalCircuit::<C, D>::prebuild_final_circuit(
            checkpoint_common_data,
            checkpoint_cap_height,
            coordinator_checkpoint_fp,
            coordinator_checkpoint_step_commit_fp,
            32,
            PsyNetworkLocalDevnetConstants::GLOBAL_USER_TREE_HEIGHT_USIZE,
            PsyNetworkLocalDevnetConstants::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE,
            DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize,
            WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT as usize,
        );
        let bridge_agg_fingerprint = bridge_agg_template.get_fingerprint();
        let bridge_agg_common = bridge_agg_template.get_common_circuit_data_ref();
        let bridge_agg_verifier = bridge_agg_template.get_verifier_config_ref();
        let bridge_wrap_circuit = Arc::new(BridgeWrapCircuit::new(
            bridge_agg_common,
            bridge_agg_fingerprint,
            bridge_agg_verifier.constants_sigmas_cap.height(),
        ));
        let bridge_groth16_wrapper = Arc::new(
            BridgeWrapCircuit::new(
                bridge_agg_common,
                bridge_agg_fingerprint,
                bridge_agg_verifier.constants_sigmas_cap.height(),
            )
            .into_shared_groth16_wrapper(format!("{}/.psy/keystore/", dirs::home_dir().unwrap().display())),
        );

        tracing::info!("Groth16 wrapping circuits pre-built successfully.");

        // Preload Groth16 keystores into the gnark Go runtime so the first proof
        // request doesn't pay the ~15s cold-start penalty (ReadCircuit +
        // ReadProvingKey). Each keystore is ~500MB–800MB on disk; loading
        // lazily on first request causes relayer claim-proof-fetch timeouts.
        tracing::info!("Preloading Groth16 keystores...");
        for (label, keystore_path) in [
            ("bridge", &bridge_groth16_wrapper.keystore_path),
            ("deposit_append", &deposit_batch_groth16_wrapper.keystore_path),
            ("withdrawal_claim", &withdrawal_claim_groth16_wrapper.keystore_path),
        ] {
            let keystore_dir = std::path::Path::new(keystore_path);
            if keystore_dir.join("circuit_groth16.bin").exists()
                && keystore_dir.join("pk_groth16.bin").exists()
                && keystore_dir.join("vk_groth16.bin").exists()
            {
                tracing::info!(keystore = label, path = keystore_path, "preloading Groth16 setup");
                gnark_plonky2_verifier_ffi::initialize(keystore_path);
                tracing::info!(keystore = label, "Groth16 setup preloaded");
            } else {
                tracing::warn!(keystore = label, path = keystore_path, "skipping preload — keystore files missing");
            }
        }
        tracing::info!("All Groth16 keystores preloaded.");

        Ok(Self {
            deposit_batch_wrap_circuit,
            withdrawal_claim_wrap_circuit,
            bridge_wrap_circuit,
            deposit_batch_groth16_wrapper,
            withdrawal_claim_groth16_wrapper,
            bridge_groth16_wrapper,
        })
    }
}

fn cached_bridge_coordinator_circuits() -> anyhow::Result<&'static QEDCoordinatorCircuitManager<C, D>> {
    static CACHE: OnceLock<anyhow::Result<QEDCoordinatorCircuitManager<C, D>>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            tracing::info!("Building QEDCoordinatorCircuitManager for bridge agg...");
            get_plonky2_circuit_library_and_prover_for_network::<C, D>(PsyChainNetworkType::LocalDevnet).map(|(_, circuits)| circuits)
        })
        .as_ref()
        .map_err(|e| anyhow::anyhow!("failed to build/retrieve cached bridge circuits: {}", e))
}

#[async_trait]
impl ProveProxySystemRpcServer for SystemProveProvider {
    async fn prove_withdrawal_batch_claim_groth16(
        &self,
        input: BridgeWithdrawalBatchWitnessInput,
    ) -> Result<BridgeWithdrawalBatchGroth16Proof, ErrorObjectOwned> {
        tracing::debug!("prove_withdrawal_batch_claim_groth16 count={}", input.withdrawals.len());

        let wrap_circuit = self.withdrawal_claim_wrap_circuit.clone();
        let groth16_wrapper = self.withdrawal_claim_groth16_wrapper.clone();
        tokio::task::spawn_blocking(move || {
            anyhow::ensure!(
                input.withdrawals.len() <= MAX_WITHDRAWAL_CLAIM_BATCH_SIZE,
                "withdrawal batch too large: got {}, max {}",
                input.withdrawals.len(),
                MAX_WITHDRAWAL_CLAIM_BATCH_SIZE
            );
            anyhow::ensure!(!input.withdrawals.is_empty(), "withdrawal batch must include at least one withdrawal");

            let mut slot_data = vec![0u64; MAX_WITHDRAWAL_CLAIM_BATCH_SIZE * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS];
            let mut root: Option<ParthQHashOut<F>> = None;
            let mut withdrawals = Vec::with_capacity(input.withdrawals.len());
            for (i, withdrawal) in input.withdrawals.iter().enumerate() {
                anyhow::ensure!(
                    withdrawal.siblings.len() == 32,
                    "withdrawal[{}] expected 32 siblings, got {}",
                    i,
                    withdrawal.siblings.len()
                );
                let parsed_root = parse_hex_qhashout(&withdrawal.withdrawal_root)?;
                if let Some(existing) = root {
                    anyhow::ensure!(existing == parsed_root, "withdrawal[{}] root mismatch within batch", i);
                } else {
                    root = Some(parsed_root);
                }
                let siblings = withdrawal
                    .siblings
                    .iter()
                    .map(|hex| parse_hex_qhashout(hex))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                let slot_offset = i * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS;
                slot_data[slot_offset] = withdrawal.sender_user_id as u64;
                for (j, word) in withdrawal.recipient.iter().enumerate() {
                    slot_data[slot_offset + 1 + j] = *word as u64;
                }
                for (j, word) in withdrawal.token.iter().enumerate() {
                    slot_data[slot_offset + 9 + j] = *word as u64;
                }
                for (j, word) in withdrawal.amount.iter().enumerate() {
                    slot_data[slot_offset + 17 + j] = *word as u64;
                }
                for (j, word) in withdrawal.nonce.iter().enumerate() {
                    slot_data[slot_offset + 25 + j] = *word as u64;
                }
                slot_data[slot_offset + 33] = withdrawal.destination_chain_index as u64;
                withdrawals.push(WithdrawalBatchClaimSlotInputs::<F> {
                    sender_user_id: withdrawal.sender_user_id,
                    recipient: withdrawal.recipient,
                    token: withdrawal.token,
                    amount: withdrawal.amount,
                    nonce: withdrawal.nonce,
                    destination_chain_index: withdrawal.destination_chain_index,
                    leaf_index: withdrawal.leaf_index,
                    siblings,
                });
            }

            let circuit = WithdrawalBatchClaimCircuit::<C, D>::build(32);
            let proof = circuit.generate_proof(&WithdrawalBatchClaimInputs::<F> {
                withdrawal_root: root.expect("non-empty batch ensured above"),
                bridge_user_id: input.bridge_user_id,
                withdrawals,
            })?;
            let groth16 = wrap_circuit.prove_groth16_with_shared_wrapper(&groth16_wrapper, &circuit.circuit_data.verifier_only, &proof)?;
            tracing::warn!(
                withdrawal_claim_gnark_public_inputs = ?groth16.public_inputs,
                "withdrawal claim gnark returned public inputs"
            );

            Ok::<_, anyhow::Error>(BridgeWithdrawalBatchGroth16Proof {
                solidity_proof: g16_proof_to_solidity_words(&groth16),
                public_inputs: {
                    let pis = proof.public_inputs.iter().map(|x| x.to_noncanonical_u64()).collect::<Vec<_>>();
                    anyhow::ensure!(
                        pis.len() == WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS,
                        "expected {} withdrawal batch public inputs, got {}",
                        WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS,
                        pis.len()
                    );
                    pis
                },
                slot_data,
            })
        })
        .await
        .map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_withdrawal_batch_claim_groth16: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?
        .map_err(|err| ErrorObjectOwned::owned(1, "prove_withdrawal_batch_claim_groth16 proving error", Some(err.to_string())))
    }

    async fn prove_deposit_batch_append_groth16(
        &self,
        input: BridgeDepositBatchWitnessInput,
    ) -> Result<BridgeDepositBatchGroth16Proof, ErrorObjectOwned> {
        tracing::debug!(
            "prove_deposit_batch_append_groth16 from_index={} count={}",
            input.from_index,
            input.deposits.len()
        );

        let wrap_circuit = self.deposit_batch_wrap_circuit.clone();
        let groth16_wrapper = self.deposit_batch_groth16_wrapper.clone();
        tokio::task::spawn_blocking(move || {
            anyhow::ensure!(
                input.old_frontier.len() == 32,
                "expected 32 frontier nodes, got {}",
                input.old_frontier.len()
            );
            anyhow::ensure!(!input.deposits.is_empty(), "deposit batch must include at least one deposit");

            let old_frontier_vec = input
                .old_frontier
                .iter()
                .map(|hex| parse_hex_qhashout(hex))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let old_frontier: [ParthQHashOut<F>; 32] = old_frontier_vec
                .try_into()
                .map_err(|v: Vec<ParthQHashOut<F>>| anyhow::anyhow!("invalid frontier length: {}", v.len()))?;
            let deposits = input
                .deposits
                .into_iter()
                .map(|leaf| DepositBatchLeafData {
                    shield_address: leaf.shield_address,
                    token: leaf.token,
                    l2_token_contract_id: leaf.l2_token_contract_id,
                    amount: leaf.amount,
                    chain_index: leaf.chain_index,
                    note_commitment: leaf.note_commitment,
                })
                .collect::<Vec<_>>();
            let batch_inputs = DepositBatchAppendInputs {
                frontier: old_frontier,
                from_index: input.from_index,
                deposits,
                bridge_user_id: input.bridge_user_id,
            };

            let circuit = DepositBatchAppendCircuit::<C, D>::build(
                psy_plonky2_common_circuits::bridge::deposit_batch_append_circuit::MAX_DEPOSIT_BATCH_SIZE,
                32,
            );
            let proof = circuit.generate_proof(&batch_inputs)?;
            let preimage = compute_batch_append_preimage(&batch_inputs);
            let minifier = psy_plonky2_circuits::proof_minifier::pm_chain::QEDProofMinifierChain::<D, F, C>::new(
                &circuit.circuit_data.verifier_only,
                &circuit.circuit_data.common,
                2,
            );
            let minified_proof = minifier.prove(&proof)?;
            let groth16 = wrap_circuit.prove_groth16_with_shared_wrapper(&groth16_wrapper, minifier.get_verifier_data(), &minified_proof)?;

            Ok::<_, anyhow::Error>(BridgeDepositBatchGroth16Proof {
                solidity_proof: g16_proof_to_solidity_words(&groth16),
                public_inputs: preimage.to_u32_words().into_iter().map(|x| x as u64).collect(),
            })
        })
        .await
        .map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_deposit_batch_append_groth16: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?
        .map_err(|err| ErrorObjectOwned::owned(1, "prove_deposit_batch_append_groth16 proving error", Some(err.to_string())))
    }

    async fn prove_bridge_agg_groth16(
        &self,
        _deps_network: String,
        input: BridgeAggWitnessInput,
    ) -> Result<BridgeAggGroth16Output, ErrorObjectOwned> {
        tracing::debug!("prove_bridge_agg_groth16 from={} to={}", input.from_checkpoint, input.to_checkpoint);

        let from_checkpoint = input.from_checkpoint.max(1);
        let to_checkpoint = input.to_checkpoint;
        if from_checkpoint > to_checkpoint {
            return Err(ErrorObjectOwned::owned(
                1,
                "prove_bridge_agg_groth16: from_checkpoint must be <= to_checkpoint",
                None::<()>,
            ));
        }
        let num_checkpoints_aggregated = to_checkpoint - from_checkpoint + 1;

        let wrap_circuit = self.bridge_wrap_circuit.clone();
        let groth16_wrapper = self.bridge_groth16_wrapper.clone();
        tokio::task::spawn_blocking(move || -> Result<BridgeAggGroth16Output, ErrorObjectOwned> {
            use psy_plonky2_circuits::qstandard::QStandardCircuit;
            let coordinator_circuits = cached_bridge_coordinator_circuits()
                .map_err(|e| ErrorObjectOwned::owned(1, "failed to load bridge circuits", Some(e.to_string())))?;

            let checkpoint_common_data: &CommonCircuitData<F, D> =
                coordinator_circuits.checkpoint_root_transition.get_common_circuit_data_ref();
            let checkpoint_verifier_data =
                coordinator_circuits.checkpoint_root_transition.get_verifier_config_ref();
            let cap_height = checkpoint_verifier_data.constants_sigmas_cap.height();
            let coordinator_checkpoint_fp =
                coordinator_circuits.checkpoint_root_transition.get_fingerprint();
            let checkpoint_state_transition_fingerprint = parse_hex_qhashout_to_qhash(&input.checkpoint_fp)
                .map_err(|e| ErrorObjectOwned::owned(1, "parse checkpoint_fp", Some(e.to_string())))?;
            if checkpoint_state_transition_fingerprint != coordinator_checkpoint_fp {
                return Err(ErrorObjectOwned::owned(
                    1,
                    "checkpoint_fp mismatch",
                    Some(format!(
                        "bridge agg witness checkpoint_fp differs from proxy coordinator fingerprint: input={:?} coordinator={:?}",
                        checkpoint_state_transition_fingerprint,
                        coordinator_checkpoint_fp
                    )),
                ));
            }
            // step_commit must use the cached library fingerprint (same as RCP circuit genesis proving).
            let cached_lib = psy_plonky2_circuits::generated::cached_circuit_library::get_cached_circuit_library::<F>();
            let checkpoint_step_commit_fingerprint = cached_lib
                .get_fingerprint(ProvingJobCircuitType::GenerateRollupStateTransitionProof)
                .expect("GenerateRollupStateTransitionProof not found in cached circuit library");

            // Deserialize the final (to_checkpoint) checkpoint proof from bincode hex
            let final_checkpoint_proof_bytes = hex::decode(
                input.final_checkpoint_proof_hex.trim_start_matches("0x"),
            )
            .map_err(|e| ErrorObjectOwned::owned(1, "hex decode final checkpoint proof", Some(e.to_string())))?;
            let final_checkpoint_proof: ProofWithPublicInputs<F, C, D> =
                bincode::deserialize(&final_checkpoint_proof_bytes)
                    .map_err(|e| ErrorObjectOwned::owned(1, "bincode deserialize final checkpoint proof", Some(e.to_string())))?;

            // Parse delta merkle proofs
            use plonky2::hash::poseidon::PoseidonHash;
            let parse_delta = |dp: &BridgeAggDeltaProof| -> anyhow::Result<ParthDeltaMerkleProofCore<parth_core::pgoldilocks::QHashOut<F>>> {
                let new_value = parse_hex_qhashout_to_qhash(&dp.new_value)?;
                let siblings = dp.siblings.iter().map(|s| parse_hex_qhashout_to_qhash(s)).collect::<Result<Vec<_>, _>>()?;
                Ok(ParthDeltaMerkleProofCore::from_params::<PoseidonHash>(
                    dp.index,
                    parth_core::pgoldilocks::QHashOut::default(),
                    new_value,
                    siblings,
                ))
            };

            let delta_merkle_proofs: Vec<ParthDeltaMerkleProofCore<parth_core::pgoldilocks::QHashOut<F>>> = input.delta_merkle_proofs
                .iter()
                .map(parse_delta)
                .collect::<anyhow::Result<Vec<_>>>()
                .map_err(|e| ErrorObjectOwned::owned(1, "parse delta proofs", Some(e.to_string())))?;

            let pre_delta_merkle_proofs: Vec<ParthDeltaMerkleProofCore<parth_core::pgoldilocks::QHashOut<F>>> = input.pre_delta_merkle_proofs
                .iter()
                .map(parse_delta)
                .collect::<anyhow::Result<Vec<_>>>()
                .map_err(|e| ErrorObjectOwned::owned(1, "parse pre-delta proofs", Some(e.to_string())))?;

            // `chain_start` is the chain hash immediately before the aggregated range
            // (chain hash of checkpoint `from_checkpoint - 1`; for `from_checkpoint <= 1`
            // this is the genesis checkpoint state transition hash).
            let start_chain_hash = parse_hex_qhashout_to_qhash(&input.chain_start)
                .map_err(|e| ErrorObjectOwned::owned(1, "parse chain_start", Some(e.to_string())))?;

            let final_leaf = psy_data::v1::qdata::checkpoint::PQEDCheckpointLeafCompact {
                global_chain_root: parse_hex_qhashout_to_qhash(&input.final_checkpoint_leaf.global_chain_root)
                    .map_err(|e| ErrorObjectOwned::owned(1, "parse final leaf chain root", Some(e.to_string())))?,
                stats_hash: parse_hex_qhashout_to_qhash(&input.final_checkpoint_leaf.stats_hash)
                    .map_err(|e| ErrorObjectOwned::owned(1, "parse final leaf stats hash", Some(e.to_string())))?,
            };

            // Parse global state roots (anchors the user_tree_root to the verified checkpoint)
            let parse_qhash = |hex: &str| -> anyhow::Result<parth_core::pgoldilocks::QHashOut<F>> {
                parse_hex_qhashout_to_qhash(hex)
            };
            let global_state_roots = PQEDCheckpointGlobalStateRoots {
                contract_tree_root: parse_qhash(&input.final_checkpoint_global_state_roots.contract_tree_root)
                    .map_err(|e| ErrorObjectOwned::owned(1, "parse contract_tree_root", Some(e.to_string())))?,
                deposit_tree_root: parse_qhash(&input.final_checkpoint_global_state_roots.deposit_tree_root)
                    .map_err(|e| ErrorObjectOwned::owned(1, "parse deposit_tree_root", Some(e.to_string())))?,
                user_tree_root: parse_qhash(&input.final_checkpoint_global_state_roots.user_tree_root)
                    .map_err(|e| ErrorObjectOwned::owned(1, "parse user_tree_root", Some(e.to_string())))?,
                withdrawal_tree_root: parse_qhash(&input.final_checkpoint_global_state_roots.withdrawal_tree_root)
                    .map_err(|e| ErrorObjectOwned::owned(1, "parse withdrawal_tree_root", Some(e.to_string())))?,
                user_registration_tree_root: parse_qhash(&input.final_checkpoint_global_state_roots.user_registration_tree_root)
                    .map_err(|e| ErrorObjectOwned::owned(1, "parse user_registration_tree_root", Some(e.to_string())))?,
            };

            // Parse witnesses (slot witnesses are the full TreeRootInContractStateWitnessInput)
            let parse_slot_witness = |w: &BridgeAggSlotWitness| -> anyhow::Result<TreeRootInContractStateWitnessInput<F>> {
                let user_leaf = psy_data::v1::qdata::user::PQEDUserLeaf::<F, parth_core::pgoldilocks::QHashOut<F>> {
                    public_key: parse_hex_qhashout_to_qhash(&w.user_leaf_public_key)?,
                    user_state_tree_root: parse_hex_qhashout_to_qhash(&w.user_leaf_user_state_tree_root)?,
                    balance: F::from_canonical_u64(w.user_leaf_balance),
                    nonce: F::from_canonical_u64(w.user_leaf_nonce),
                    last_checkpoint_id: F::from_canonical_u64(w.user_leaf_last_checkpoint_id),
                    event_index: F::from_canonical_u64(w.user_leaf_event_index),
                    user_id: F::from_canonical_u64(w.user_leaf_user_id),
                };

                let mk_proof = |root: &str, value: &str, index: u64, sibs: &[String]| -> anyhow::Result<parth_core::crypto::hash::merkle_proof::MerkleProofCore<parth_core::pgoldilocks::QHashOut<F>>> {
                    Ok(parth_core::crypto::hash::merkle_proof::MerkleProofCore {
                        root: parse_hex_qhashout_to_qhash(root)?,
                        value: parse_hex_qhashout_to_qhash(value)?,
                        index,
                        siblings: sibs.iter().map(|s| parse_hex_qhashout_to_qhash(s)).collect::<Result<Vec<_>, _>>()?,
                    })
                };

                Ok(TreeRootInContractStateWitnessInput {
                    owner_user_id: w.owner_user_id,
                    contract_id: w.contract_id,
                    user_leaf,
                    slot0_proof: mk_proof(&w.slot0_root, &w.slot0_value, w.slot0_index, &w.slot0_siblings)?,
                    slot1_proof: mk_proof(&w.slot1_root, &w.slot1_value, w.slot1_index, &w.slot1_siblings)?,
                    contract_proof: mk_proof(&w.contract_root, &w.contract_value, w.contract_index, &w.contract_siblings)?,
                    user_tree_proof: mk_proof(&w.user_tree_root, &w.user_tree_value, w.user_tree_index, &w.user_tree_siblings)?,
                })
            };

            let deposit_witness = parse_slot_witness(&input.deposit_witness)
                .map_err(|e| ErrorObjectOwned::owned(1, "parse deposit witness", Some(e.to_string())))?;
            let withdrawal_witness = parse_slot_witness(&input.withdrawal_witness)
                .map_err(|e| ErrorObjectOwned::owned(1, "parse withdrawal witness", Some(e.to_string())))?;

            tracing::info!(
                "Proving bridge aggregation for checkpoints {} to {}...",
                from_checkpoint,
                to_checkpoint
            );

            let result = BridgeAggFinalCircuit::<C, D>::prove_range(
                from_checkpoint,
                to_checkpoint,
                start_chain_hash,
                checkpoint_common_data,
                cap_height,
                checkpoint_state_transition_fingerprint,
                checkpoint_step_commit_fingerprint,
                &final_checkpoint_proof,
                &checkpoint_verifier_data,
                &delta_merkle_proofs,
                &pre_delta_merkle_proofs,
                &final_leaf,
                &global_state_roots,
                &deposit_witness,
                &withdrawal_witness,
                32, // CHECKPOINT_TREE_HEIGHT
                PsyNetworkLocalDevnetConstants::GLOBAL_USER_TREE_HEIGHT_USIZE,
                PsyNetworkLocalDevnetConstants::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE,
                DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize,
                WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT as usize,
            )
            .map_err(|e| ErrorObjectOwned::owned(1, "bridge_agg prove_range failed", Some(e.to_string())))?;

            let bridge_agg_proof = result.proof;
            let bridge_agg_verifier_data = result.verifier_data;

            tracing::info!("Proving BridgeWrapCircuit (Groth16 wrap)...");
            let groth16_proof = wrap_circuit
                .prove_groth16_with_shared_wrapper(&groth16_wrapper, &bridge_agg_verifier_data, &bridge_agg_proof)
                .map_err(|e| ErrorObjectOwned::owned(1, "bridge_wrap Groth16 failed", Some(e.to_string())))?;

            // Format outputs
            let groth16_pi = &bridge_agg_proof.public_inputs;
            let checkpoint_roots = vec![
                felt4_to_bytes32_hex(&groth16_pi[0..4]),
                felt4_to_bytes32_hex(&groth16_pi[20..24]),
            ];
            let deposit_tree_root = u32x8_to_bytes32_hex(&groth16_pi[4..12]);
            let withdrawal_tree_root = u32x8_to_bytes32_hex(&groth16_pi[12..20]);
            let end_checkpoint_index = groth16_pi[24].to_canonical_u64();
            if end_checkpoint_index != to_checkpoint {
                return Err(ErrorObjectOwned::owned(
                    1,
                    "prove_bridge_agg_groth16: end_checkpoint_index mismatch",
                    Some(format!("pi={} expected={}", end_checkpoint_index, to_checkpoint)),
                ));
            }

            let solidity_words = g16_proof_to_solidity_words(&groth16_proof);
            let pub_inputs_0 = groth16_proof.public_inputs[0].clone();
            let pub_inputs_1 = groth16_proof.public_inputs[1].clone();
            let public_inputs_str: Vec<String> = groth16_pi.iter().map(|x| x.to_canonical_u64().to_string()).collect();
            let num_pis = groth16_pi.len();

            Ok(BridgeAggGroth16Output {
                from_checkpoint,
                to_checkpoint,
                num_checkpoints_aggregated,
                bridge_agg_public_inputs_count: num_pis,
                bridge_agg_public_inputs: public_inputs_str,
                groth16_proof,
                solidity_proof: [
                    solidity_words[0].clone(),
                    solidity_words[1].clone(),
                    solidity_words[2].clone(),
                    solidity_words[3].clone(),
                    solidity_words[4].clone(),
                    solidity_words[5].clone(),
                    solidity_words[6].clone(),
                    solidity_words[7].clone(),
                ],
                solidity_public_inputs: [
                    pub_inputs_0,
                    pub_inputs_1,
                ],
                checkpoint_roots,
                deposit_tree_root,
                withdrawal_tree_root,
                end_checkpoint_index,
            })
        })
        .await
        .map_err(|join_err| {
            ErrorObjectOwned::owned(
                1,
                "prove_bridge_agg_groth16: task schedule failed",
                Some(format!("Thread pool task execution failed: {}", join_err)),
            )
        })?
    }
}
