use std::sync::Arc;

use anyhow::Context;
use jsonrpsee::{core::async_trait, proc_macros::rpc, types::ErrorObjectOwned};
use parth_core::pgoldilocks::QHashOut as ParthQHashOut;
use plonky2::field::types::Field;
use plonky2::field::types::PrimeField64;
use psy_plonky2_circuits::{
    bridge::circuits::bridge_wrap::{DepositBatchWrapCircuit, SharedGroth16Wrapper, WithdrawalClaimWrapCircuit},
    proof_minifier::pm_chain::QEDProofMinifierChain,
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

}

pub struct SystemProveProvider {
    pub deposit_batch_wrap_circuit: Arc<DepositBatchWrapCircuit>,
    pub withdrawal_claim_wrap_circuit: Arc<WithdrawalClaimWrapCircuit>,
    pub deposit_batch_groth16_wrapper: Arc<SharedGroth16Wrapper>,
    pub withdrawal_claim_groth16_wrapper: Arc<SharedGroth16Wrapper>,
    pub deposit_append_circuit: Arc<DepositBatchAppendCircuit<C, D>>,
    pub deposit_batch_minifier: Arc<QEDProofMinifierChain<D, F, C>>,
    pub withdrawal_claim_circuit: Arc<WithdrawalBatchClaimCircuit<C, D>>,
}

impl SystemProveProvider {
    /// Builds the deposit and withdrawal circuits and preloads their Groth16 keystores.
    /// Does not touch the coordinator RPC or the UPS circuit manager.
    pub fn new() -> anyhow::Result<Self> {
        let home = dirs::home_dir().context("cannot locate system prove-proxy keystore HOME")?;
        Self::new_with_keystore_root(&home.join(".psy/keystore"))
    }

    fn new_with_keystore_root(root: &std::path::Path) -> anyhow::Result<Self> {

        // Check every required file before expensive circuit construction. The
        // synchronous FFI initialization below also decodes each group before
        // this provider can be registered as system-capable.
        for (label, directory) in [("deposit_append", "deposit_append"), ("withdrawal_claim", "withdrawal_claim")] {
            for name in ["circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin"] {
                let path = root.join(directory).join(name);
                let file = std::fs::File::open(&path)
                    .with_context(|| format!("required {label} setup file is unavailable: {}", path.display()))?;
                let metadata = file.metadata()?;
                anyhow::ensure!(metadata.is_file() && metadata.len() > 0,
                    "required {label} setup file is not a nonempty regular file: {}", path.display());
            }
        }

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
            .into_shared_groth16_wrapper(format!("{}/deposit_append/", root.display())),
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
            .into_shared_groth16_wrapper(format!("{}/withdrawal_claim/", root.display())),
        );


        tracing::info!("Groth16 wrapping circuits pre-built successfully.");

        // Preload Groth16 keystores into the gnark Go runtime so the first proof
        // request doesn't pay the ~15s cold-start penalty (ReadCircuit +
        // ReadProvingKey). Each keystore is ~500MB–800MB on disk; loading
        // lazily on first request causes relayer claim-proof-fetch timeouts.
        tracing::info!("Preloading Groth16 keystores...");
        for (label, keystore_path) in [
            ("deposit_append", &deposit_batch_groth16_wrapper.keystore_path),
            ("withdrawal_claim", &withdrawal_claim_groth16_wrapper.keystore_path),
        ] {
            tracing::info!(keystore = label, path = keystore_path, "preloading Groth16 setup");
            gnark_plonky2_verifier_ffi::initialize(keystore_path);
            tracing::info!(keystore = label, "Groth16 setup preloaded");
        }
        tracing::info!("All Groth16 keystores preloaded.");

        Ok(Self {
            deposit_batch_wrap_circuit,
            withdrawal_claim_wrap_circuit,
            deposit_batch_groth16_wrapper,
            withdrawal_claim_groth16_wrapper,
            deposit_append_circuit: Arc::new(deposit_template),
            deposit_batch_minifier: Arc::new(deposit_minifier),
            withdrawal_claim_circuit: Arc::new(withdrawal_template),
        })
    }
}

#[cfg(test)]
mod setup_tests {
    use super::*;

    #[test]
    fn system_startup_rejects_missing_empty_or_non_file_setup_before_building_circuits() {
        for directory in ["deposit_append", "withdrawal_claim"] {
            for name in ["circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin"] {
                for failure in ["missing", "empty", "directory"] {
                    let root = tempfile::tempdir().unwrap();
                    for group in ["deposit_append", "withdrawal_claim"] {
                        std::fs::create_dir_all(root.path().join(group)).unwrap();
                        for file in ["circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin"] {
                            std::fs::write(root.path().join(group).join(file), b"placeholder").unwrap();
                        }
                    }
                    let path = root.path().join(directory).join(name);
                    std::fs::remove_file(&path).unwrap();
                    match failure {
                        "empty" => std::fs::write(&path, b"").unwrap(),
                        "directory" => std::fs::create_dir(&path).unwrap(),
                        _ => (),
                    }
                    let error = SystemProveProvider::new_with_keystore_root(root.path())
                        .err().expect("invalid setup must prevent system startup");
                    assert!(error.to_string().contains(path.to_str().unwrap()), "{error}");
                }
            }
        }
    }
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
        let circuit = self.withdrawal_claim_circuit.clone();
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
                    let pis = proof.public_inputs.iter().map(|x| x.to_canonical_u64()).collect::<Vec<_>>();
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
        let circuit = self.deposit_append_circuit.clone();
        let minifier = self.deposit_batch_minifier.clone();
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

            let proof = circuit.generate_proof(&batch_inputs)?;
            let preimage = compute_batch_append_preimage(&batch_inputs);
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

}
