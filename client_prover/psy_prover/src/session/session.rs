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
    args::{ContractCallArgs, ContractCallData, DPNSoftwareDefinedCallData},
    data::{alt::AltVerifierOnlyCircuitData, qhashout::QHashOut},
    ups::circuits::LocalCircuitType,
};
use psy_client_data::{
    config::store_config::PsyHasher,
    guta::end_cap_input::SubmitUserEndCapNonProofInput,
    qblock::cmds::deploy_contract::{get_code_root_by_code_hashes, QBCDeployContract},
    qdata::{contract::ContractCodeDefinition, user_contract_state::UserContractState},
    qstore::{
        controllers::{
            proving_session::{PsyLocalProvingSessionStore, PsyReadLocalProvingSessionStore},
            session_info::SessionCircuitInfoStore,
        },
        imm::{
            cmd::{QSRCmdGetContractCodeDefinition, QSRCmdGetUserLeafData},
            cmd_processor::{PsyReadCommandProcessorSync, PsyReadCommandProcessorSyncMut},
        },
    },
    traits::qdatastore::{
        qmetadata::QMetaDataStoreReaderSync,
        qtreedata::{PsyComboDataStoreReaderSync, QTreeDataStoreReaderSync},
    },
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
    hash::traits::{
        hasher::{MerkleZeroHasher, MerkleZeroHasherWithMarkedLeaf},
        qhashable::QFieldHashable,
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
        vm::def::DPNFunctionCircuitDefinition,
    },
    ups::{
        circuit_manager::UPSCircuitManager, sdk_key::SDKKeyCircuitWitnessInput, signature::Plonky2SoftwareDefinedSignatureInput,
        state_reader::StateReader,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    signature::{
        context::SignContext,
        traits::{SignatureCircuitInfo, SignatureResult},
    },
    wallet::memory_wallet::PsyMemoryWallet,
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

    pub user_session_mgrs: DashMap<QHashOut<F>, UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateTransferClaim {
    pub nullifier: [u64; 4],
    pub owner: [u64; 4],
    pub amount: u64,
    pub user_tree_root: [u64; 4],
    pub checkpoint_id: u64,
    pub note_root_slot: u64,
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

        let proxy_urls: Vec<_> = rpc_config
            .prove_proxy_url
            .iter()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

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

        let mut circuit_info = SessionCircuitInfoStore::new();

        tracing::info!("register ZKSignature circuit info");
        circuit_info.register_circuit(
            LocalCircuitType::SimpleZKSignature.into(),
            main_circuits[0].zk_circuit_fingerprint().await?,
            main_circuits[0].zk_circuit_verifier_config().await?.into(),
        );

        circuit_info.register_circuit(
            LocalCircuitType::SimpleSecp256K1.into(),
            main_circuits[0].secp_circuit_fingerprint().await?,
            main_circuits[0].secp_circuit_verifier_config().await?.into(),
        );

        for main_circuit in main_circuits.iter() {
            main_circuit.as_ref().register_info(&mut circuit_info).await;
        }

        let wallet = PsyMemoryWallet::new(main_circuits);

        Ok(WalletSession {
            wallet,
            circuit_info,
            st_provider,
            user_session_mgrs: DashMap::new(),
        })
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

    pub async fn register_sdk_key_circuit(
        &mut self,
        allowed_contract_ids: &[u64],
        allowed_method_ids: &[u64],
        expected_tx_count: u64,
    ) -> anyhow::Result<QHashOut<F>> {
        self.wallet
            .register_allow_method_sdk_key_circuit(allowed_contract_ids, allowed_method_ids, expected_tx_count)
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
            let cleaned_mgr = existing_mgr.into_clean_for_user(F::from_canonical_u64(user_id)).await?;
            self.user_session_mgrs.insert(public_key, cleaned_mgr);
        } else {
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
            let mgr =
                UserProvingSessionManager::<F, _, _, C, D>::new(lps, self.circuit_info.clone(), circuit_mgr.ups_circuit_whitelist_root().await?)
                    .await?;

            self.user_session_mgrs.insert(public_key, mgr);
        }
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
        user_session_mgr
            .lps
            .set_proof_tree_root(proof_tree_root);
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
        user_session_mgr
            .lps
            .set_proof_tree_root(proof_tree_root);

        let leaf_proof = user_session_mgr.proof_tree_state.get_leaf_merkle_proof(leaf_index).await;
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
        // Always refresh the session manager to get latest checkpoint state
        // This ensures we don't reuse stale session state from previous transactions
        self.update_circuit_mgr(public_key).await?;

        let mut user_session_mgr = self
            .user_session_mgrs
            .get_mut(&public_key)
            .ok_or_else(|| anyhow::format_err!("user {} not found", public_key.to_string()))?;

        let latest_block_state = user_session_mgr.lps.get_read_store().get_latest_block_state().await?;
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
            return Err(anyhow::format_err!(
                "realm latest checkpoint {} is ahead of coordinator checkpoint {}",
                latest_block_state.checkpoint_id,
                global_latest_block_state.checkpoint_id
            ));
        };

        tracing::info!("local proving ups start");
        tracing::info!("user session manager nonce: {}", user_session_mgr.lps.get_nonce());

        user_session_mgr.prove_ups_start(self.wallet.random_circuit_manager().as_ref()).await?;

        let user_id = user_session_mgr.lps.get_current_user_id_64();
        let registration_id = get_registration_id_from_user_id(user_id);
        let checkpoint = user_session_mgr.lps.get_current_start_checkpoint_id_u64();

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

        if registration_leaf_hash == QHashOut::ZERO {
            anyhow::bail!(
                "user {}: {} of registration id {} is not registered at checkpoint {}, please check it first",
                user_id,
                public_key.to_string(),
                registration_id,
                checkpoint
            );
        }

        let nonce = user_session_mgr.lps.get_nonce();
        self.check_user_state(user_id, nonce).await?;

        Ok(())
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
                .lps
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

        let user_id = user_session_mgr.lps.get_current_user_id_64();
        let nonce = user_session_mgr.lps.get_nonce();
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
        user_session_mgr
            .lps
            .set_proof_tree_root(proof_tree_root);
        let contract_code = user_session_mgr
            .lps
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
                        user_session_mgr
                            .lps
                            .set_proof_tree_root(proof_tree_root);
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
                        user_session_mgr
                            .lps
                            .set_proof_tree_root(proof_tree_root);
                        let leaf_proof = user_session_mgr.proof_tree_state.get_leaf_merkle_proof(proof_index).await;
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
                        user_session_mgr
                            .lps
                            .set_proof_tree_root(proof_tree_root);
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

            let user_id = user_session_mgr.lps.get_current_user_id_64();
            let nonce = user_session_mgr.lps.get_nonce();
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
            } else if self.wallet.has_sdk_key_circuit(&pk_info.fingerprint) {
                sign_context = self
                    .build_sdk_key_context(&software_defined_call, pk_info.fingerprint, &mut user_session_mgr)
                    .await?;
            };
        }

        let nonce = user_session_mgr.lps.get_nonce();
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
        let end_cap_proof = user_session_mgr
            .prove_end_cap(
                self.wallet.random_circuit_manager().as_ref(),
                PSY_NETWORK_MAGIC,
                nonce,
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

        let user_id = user_session_mgr.lps.get_current_user_id_64();
        let nonce = user_session_mgr.lps.get_nonce();
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

    pub async fn sign_and_submit(
        &self,
        public_key: QHashOut<F>,
        software_defined_call: DPNSoftwareDefinedCallData,
    ) -> anyhow::Result<QHashOut<F>> {
        let (user_ec_input, end_cap_proof) = self.sign(public_key, software_defined_call).await?;
        let user_id = user_ec_input.core.new_user_leaf.user_id.to_noncanonical_u64();
        let req = QSubmitEndCapRPCRequest {
            user_ec_input,
            proof: bincode::serialize(&end_cap_proof)?,
        };

        // let tx_hash = req.user_ec_input.get_tx_hash()?;
        let tx_hash = req.user_ec_input.core.state_transition.end_user_leaf_hash;

        let _ = self.st_provider.with_user_id_owned(user_id).submit_end_cap_proof::<F>(req).await?;

        Ok(tx_hash)
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

        let cfc_proof_input = user_session_mgr.exec_contract_call_local(&sdc.fn_def, cfc_call_inputs).await?;

        let signature_input = DPNSoftwareDefinedSignatureInput { cfc_input: cfc_proof_input };

        let current_checkpoint_id = user_session_mgr.lps.get_current_start_checkpoint_id_u64();
        let user_id = user_session_mgr.lps.get_current_user_id_64();
        let start_contract_state_tree_root = user_session_mgr.lps.last_transaction_record().user_contract_tree_update_proof.old_value;
        let checkpoint_tree_root = self.st_provider.get_checkpoint_tree_root(current_checkpoint_id).await?;

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
        let user_id = user_session_mgr.lps.get_current_user_id_64();
        let checkpoint_id = user_session_mgr.lps.get_current_start_checkpoint_id_u64();
        let user_leaf = user_session_mgr
            .lps
            .resolve_get_user_leaf_mut(&QSRCmdGetUserLeafData { checkpoint_id, user_id })
            .await?;

        let checkpoint_tree_root = self.st_provider.get_checkpoint_tree_root(checkpoint_id).await?;

        let transaction_record = user_session_mgr.lps.last_transaction_record();

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
            user_session_mgr.lps.get_cmd_store().clone(),
            user_session_mgr.lps.get_state_tree_store().clone(),
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

    async fn build_sdk_key_context(
        &self,
        call_data: &DPNSoftwareDefinedCallData,
        fingerprint: QHashOut<F>,
        user_session_mgr: &mut UserProvingSessionManager<F, PoseidonHash, RpcProvider, C, D>,
    ) -> anyhow::Result<SignContext> {
        let sdk_key = self
            .wallet
            .get_sdk_key_circuit(&fingerprint)
            .ok_or_else(|| anyhow::format_err!("SDK key circuit `{}` not found", fingerprint))?;
        let config = sdk_key.config.clone();
        drop(sdk_key);

        let transaction_infos = user_session_mgr.sdk_key_transaction_infos();
        let expected_slots = config.num_introspectable_transactions as usize;
        if transaction_infos.len() != expected_slots {
            anyhow::bail!(
                "SDK key circuit expects {} introspectable txs, but session has {} txs",
                expected_slots,
                transaction_infos.len()
            );
        }

        let checkpoint_id = user_session_mgr.lps.get_current_start_checkpoint_id_u64();
        let user_id = user_session_mgr.lps.get_current_user_id_64();
        let circuit_inputs = call_data.inputs.iter().map(|x| F::from_noncanonical_u64(*x)).collect::<Vec<_>>();
        let tx_stack_hash = user_session_mgr.current_tx_hash_stack();
        let tx_count = user_session_mgr.current_tx_count();
        let start_contract_state_tree_root = user_session_mgr.lps.last_transaction_record().user_contract_tree_update_proof.old_value;
        let checkpoint_tree_root = self.st_provider.get_checkpoint_tree_root(checkpoint_id).await?;

        let signature_input = SDKKeyCircuitWitnessInput {
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
            .with_sdk_key_signature_input(
                signature_input,
                checkpoint_id,
                user_id,
                start_contract_state_tree_root,
                checkpoint_tree_root,
            ))
    }

    pub fn get_deploy_contract_cmd(
        &self,
        deployer: QHashOut<F>,
        circuit_defs: Vec<DPNFunctionCircuitDefinition>,
    ) -> anyhow::Result<QBCDeployContract<F>> {
        let contract_state_tree_height = MAX_CONTRACT_STATE_TREE_HEIGHT as usize;

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

        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&Path::new(&project_path).join("../../../psy-genesis/config.json").to_string_lossy())?;
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
                inputs: vec![1000],
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

        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&Path::new(&project_path).join("../../../psy-genesis/config.json").to_string_lossy())?;
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
                inputs: vec![1000],
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
                inputs: vec![1000],
            }],
        )?;

        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));
        // wallet_session.st_provider.produce_block::<F>()?;
        thread::sleep(Duration::from_secs(20));

        Ok(())
    }
}
