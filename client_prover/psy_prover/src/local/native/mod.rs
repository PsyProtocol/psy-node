pub mod faucet;
#[cfg(feature = "gnark-wrap")]
pub mod prove_proxy;

use std::{sync::Arc, time::Duration};

use jsonrpsee::{
    core::async_trait,
    proc_macros::rpc,
    types::{ErrorObject, ErrorObjectOwned},
};
use parking_lot::RwLock;
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::{
    args::{ContractCallArgs, ContractCallData, DPNSoftwareDefinedCallData, ViewCallData},
    data::{base_types::hash256::Hash256, qhashout::QHashOut},
};
use psy_crypto::signature::zk::data::ZKPublicKeyInfo;
use psy_provider::provider::RpcProvider;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;
use tokio::time::timeout;

use crate::session::{WalletKeyPair, WalletSession};
type F = GoldilocksField;

fn parse_eip191_signature(signature: Vec<u8>) -> Result<[u8; 65], ErrorObjectOwned> {
    signature
        .try_into()
        .map_err(|signature: Vec<u8>| ErrorObject::owned(1, format!("EIP-191 signature must be 65 bytes, got {}", signature.len()), None::<()>))
}

fn decode_trace_payload(payload: &crate::trace::TracePayload) -> anyhow::Result<crate::trace::TxTrace> {
    use base64::Engine;

    match payload.encoding.as_str() {
        "json" => Ok(serde_json::from_str(&payload.payload)?),
        "bincode-base64" => {
            let bytes = base64::engine::general_purpose::STANDARD.decode(&payload.payload)?;
            Ok(bincode::deserialize(&bytes)?)
        }
        other => anyhow::bail!("Unsupported trace payload encoding: {}", other),
    }
}

#[rpc(server, client, namespace = "psy")]
pub trait Rpc {
    /// local proving operation
    #[method(name = "exec_contract_call")]
    async fn exec_contract_call(&self, public_key: QHashOut<F>, contract_call_args: Vec<ContractCallArgs>) -> Result<String, ErrorObjectOwned>;
    #[method(name = "generate_tx_trace")]
    async fn generate_tx_trace(&self, public_key: QHashOut<F>, call_data: ContractCallData) -> Result<String, ErrorObjectOwned>;
    #[method(name = "simulate_contract_call")]
    async fn simulate_contract_call(&self, public_key: QHashOut<F>, call_data: ContractCallData) -> Result<String, ErrorObjectOwned>;
    #[method(name = "call_view")]
    async fn call_view(&self, public_key: QHashOut<F>, call_data: ViewCallData) -> Result<String, ErrorObjectOwned>;
    #[method(name = "prove_tx_trace")]
    async fn prove_tx_trace(&self, public_key: QHashOut<F>, envelope_json: String) -> Result<String, ErrorObjectOwned>;
    #[method(name = "start_session")]
    async fn start_session(&self, public_key: QHashOut<F>) -> Result<String, ErrorObjectOwned>;
    #[method(name = "prove_contract_calls")]
    async fn prove_contract_call(&self, public_key: QHashOut<F>, contract_call_args: Vec<ContractCallArgs>) -> Result<String, ErrorObjectOwned>;
    #[method(name = "sign_and_submit")]
    async fn sign_and_submit(&self, public_key: QHashOut<F>) -> Result<String, ErrorObjectOwned>;
    #[method(name = "register_user")]
    async fn register_user(&self, private_key: QHashOut<F>, fingerprint: QHashOut<F>) -> Result<QHashOut<F>, ErrorObjectOwned>;
    #[method(name = "add_user")]
    async fn add_user(&self, private_key: QHashOut<F>, fingerprint: QHashOut<F>) -> Result<QHashOut<F>, ErrorObjectOwned>;
    #[method(name = "eth_personal_registration_challenge")]
    async fn eth_personal_registration_challenge(&self, selected_evm_address: [u8; 20]) -> Result<Hash256, ErrorObjectOwned>;
    #[method(name = "register_external_eth_personal_user")]
    async fn register_external_eth_personal_user(
        &self,
        selected_evm_address: [u8; 20],
        recovery_message: Hash256,
        signature: Vec<u8>,
    ) -> Result<QHashOut<F>, ErrorObjectOwned>;
    #[method(name = "inject_eth_personal_signature")]
    async fn inject_eth_personal_signature(
        &self,
        expected_public_key: QHashOut<F>,
        selected_evm_address: [u8; 20],
        message: Hash256,
        signature: Vec<u8>,
    ) -> Result<QHashOut<F>, ErrorObjectOwned>;
    #[method(name = "register_sd_key_circuit")]
    async fn register_sd_key_circuit(
        &self,
        allowed_contract_ids: Vec<u64>,
        allowed_method_ids: Vec<u32>,
        expected_tx_count: u64,
    ) -> Result<QHashOut<F>, ErrorObjectOwned>;
    #[method(name = "get_zk_public_key")]
    async fn get_zk_public_key(&self, private_key: QHashOut<F>) -> Result<ZKPublicKeyInfo<F>, ErrorObjectOwned>;
    #[method(name = "get_random_keypair")]
    async fn get_random_keypair(&self) -> Result<WalletKeyPair, ErrorObjectOwned>;
    #[method(name = "deploy_contract")]
    async fn deploy_contract(
        &self,
        deployer: QHashOut<F>,
        circuit_defs: Vec<DPNFunctionCircuitDefinition>,
        abi: psy_compiler::abi::Abi,
    ) -> Result<String, ErrorObjectOwned>;
    #[method(name = "get_deploy_contract_cmd")]
    async fn get_deploy_contract_cmd(
        &self,
        deployer: QHashOut<F>,
        circuit_defs: Vec<DPNFunctionCircuitDefinition>,
        abi: psy_compiler::abi::Abi,
    ) -> Result<psy_client_data::qblock::cmds::deploy_contract::QBCDeployContractV2<F>, ErrorObjectOwned>;
}

// RpcServer trait is generated by the #[rpc] macro above

#[derive(Clone)]
pub struct RpcServerImpl {
    wallet_session: Arc<RwLock<WalletSession>>,
}

impl RpcServerImpl {
    pub fn new(wallet_session: Arc<RwLock<WalletSession>>) -> Self {
        Self { wallet_session }
    }

    pub fn rpc_provider(&self) -> RpcProvider {
        self.wallet_session.read().st_provider.clone()
    }
}

#[async_trait]
impl RpcServer for RpcServerImpl {
    async fn exec_contract_call(&self, public_key: QHashOut<F>, contract_call_args: Vec<ContractCallArgs>) -> Result<String, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move {
                wallet_session
                    .read()
                    .exec_contract_call(public_key, ContractCallData::new(contract_call_args))
                    .await
            })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?;
        Ok("exec contract call".to_string())
    }

    async fn generate_tx_trace(&self, public_key: QHashOut<F>, call_data: ContractCallData) -> Result<String, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        let envelope = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move {
                let call_data_value = serde_json::to_value(&call_data)?;
                let trace = wallet_session.read().generate_tx_trace_with_opts(public_key, call_data).await?;
                crate::trace::GeneratedTxTraceJson::from_trace(&trace, call_data_value)
            })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?;
        serde_json::to_string(&envelope).map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn simulate_contract_call(&self, public_key: QHashOut<F>, call_data: ContractCallData) -> Result<String, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        let simulated = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current()
                .block_on(async move { wallet_session.read().simulate_contract_call_with_opts(public_key, call_data).await })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?;
        serde_json::to_string(&simulated).map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn call_view(&self, public_key: QHashOut<F>, call_data: ViewCallData) -> Result<String, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        let result = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move { wallet_session.read().call_view(public_key, call_data).await })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?;
        serde_json::to_string(&result).map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn prove_tx_trace(&self, public_key: QHashOut<F>, envelope_json: String) -> Result<String, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        let result = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move {
                let envelope: crate::trace::GeneratedTxTraceJson = serde_json::from_str(&envelope_json)?;
                let trace = decode_trace_payload(&envelope.trace)?;
                let tx_hash = wallet_session.read().prove_tx_trace(public_key, &trace).await?;
                Ok::<_, anyhow::Error>(crate::trace::ProvedTxResultJson::new(
                    envelope.sig_hash.clone(),
                    tx_hash.to_string(),
                    None,
                    "submitted".to_string(),
                ))
            })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?;
        serde_json::to_string(&result).map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn start_session(&self, public_key: QHashOut<F>) -> Result<String, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move { wallet_session.read().start_session(public_key).await })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?;
        Ok("start session".to_string())
    }

    async fn prove_contract_call(&self, public_key: QHashOut<F>, contract_call_args: Vec<ContractCallArgs>) -> Result<String, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        match timeout(
            Duration::from_secs(60),
            tokio::task::spawn_blocking(move || {
                tokio::runtime::Handle::current()
                    .block_on(async move { wallet_session.read().prove_contract_call(public_key, contract_call_args).await })
            }),
        )
        .await
        {
            Ok(join_result) => match join_result {
                Ok(result) => {
                    result.map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?;
                    Ok("prove contract calls".to_string())
                }
                Err(join_err) => Err(ErrorObject::owned(1, join_err.to_string(), None::<()>)),
            },
            Err(_) => Err(ErrorObject::owned(
                1,
                "Timeout: prove_contract_calls took longer than 60 seconds".to_string(),
                None::<()>,
            )),
        }
    }

    async fn sign_and_submit(&self, public_key: QHashOut<F>) -> Result<String, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        let hash = tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move {
                wallet_session
                    .read()
                    .sign_and_submit(public_key, DPNSoftwareDefinedCallData::default())
                    .await
            })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?;
        Ok(hash.to_string())
    }

    async fn register_user(&self, private_key: QHashOut<F>, fingerprint: QHashOut<F>) -> Result<QHashOut<F>, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move { wallet_session.write().register_user(private_key, fingerprint).await })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn add_user(&self, private_key: QHashOut<F>, fingerprint: QHashOut<F>) -> Result<QHashOut<F>, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move { wallet_session.write().add_user(private_key, fingerprint).await })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn eth_personal_registration_challenge(&self, selected_evm_address: [u8; 20]) -> Result<Hash256, ErrorObjectOwned> {
        WalletSession::eth_personal_registration_challenge(selected_evm_address)
            .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn register_external_eth_personal_user(
        &self,
        selected_evm_address: [u8; 20],
        recovery_message: Hash256,
        signature: Vec<u8>,
    ) -> Result<QHashOut<F>, ErrorObjectOwned> {
        let signature = parse_eip191_signature(signature)?;
        let wallet_session = self.wallet_session.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move {
                wallet_session
                    .write()
                    .register_external_eth_personal_user(selected_evm_address, recovery_message, signature)
                    .await
            })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn inject_eth_personal_signature(
        &self,
        expected_public_key: QHashOut<F>,
        selected_evm_address: [u8; 20],
        message: Hash256,
        signature: Vec<u8>,
    ) -> Result<QHashOut<F>, ErrorObjectOwned> {
        let signature = parse_eip191_signature(signature)?;
        let wallet_session = self.wallet_session.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move {
                wallet_session
                    .write()
                    .inject_eth_personal_signature(expected_public_key, selected_evm_address, message, signature)
                    .await
            })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn register_sd_key_circuit(
        &self,
        allowed_contract_ids: Vec<u64>,
        allowed_method_ids: Vec<u32>,
        expected_tx_count: u64,
    ) -> Result<QHashOut<F>, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move {
                wallet_session
                    .write()
                    .register_sd_key_circuit(&allowed_contract_ids, &allowed_method_ids, expected_tx_count)
                    .await
            })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn get_zk_public_key(&self, private_key: QHashOut<F>) -> Result<ZKPublicKeyInfo<F>, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move { wallet_session.read().get_zk_public_key(private_key).await })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn get_random_keypair(&self) -> Result<WalletKeyPair, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current().block_on(async move { wallet_session.read().get_random_keypair().await })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn deploy_contract(
        &self,
        deployer: QHashOut<F>,
        circuit_defs: Vec<DPNFunctionCircuitDefinition>,
        abi: psy_compiler::abi::Abi,
    ) -> Result<String, ErrorObjectOwned> {
        let wallet_session = self.wallet_session.clone();
        tokio::task::spawn_blocking(move || {
            tokio::runtime::Handle::current()
                .block_on(async move { wallet_session.read().deploy_contract_with_abi(deployer, circuit_defs, abi).await })
        })
        .await
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))?
        .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }

    async fn get_deploy_contract_cmd(
        &self,
        deployer: QHashOut<F>,
        circuit_defs: Vec<DPNFunctionCircuitDefinition>,
        abi: psy_compiler::abi::Abi,
    ) -> Result<psy_client_data::qblock::cmds::deploy_contract::QBCDeployContractV2<F>, ErrorObjectOwned> {
        self.wallet_session
            .read()
            .get_layout_aware_deploy_contract_cmd(deployer, circuit_defs, abi)
            .map_err(|e| ErrorObject::owned(1, e.to_string(), None::<()>))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use base64::Engine;
    use k256::ecdsa::{SigningKey, VerifyingKey};
    use plonky2::hash::poseidon::PoseidonPermutation;
    use psy_client_common::data::secp256k1::CompressedPublicKey;
    use psy_client_data::config::store_config::PsyHasher;
    use psy_crypto::{
        hash::traits::qhashable::QFieldHashable,
        signature::secp256k1::wallet::{
            eth_personal_sign_digest, ethereum_address_for_verifying_key, hash_no_pad_compressed_public_key, recover_eth_personal_signature,
        },
    };

    use super::*;

    fn minimal_trace() -> crate::trace::TxTrace {
        crate::trace::TxTrace {
            meta: crate::trace::TraceMeta {
                network_magic: 1,
                user_id: 2,
                public_key: QHashOut::ZERO,
            },
            anchor: crate::trace::SessionAnchor {
                start_checkpoint_id: 3,
                checkpoint_leaf: Default::default(),
                global_state_roots: Default::default(),
                ups_step_circuit_whitelist_root: QHashOut::ZERO,
            },
            ups_start_witness: crate::trace::UpsStartWitness {
                ups_header: Default::default(),
                state_roots: Default::default(),
                checkpoint_tree_proof: Default::default(),
                user_tree_proof: Default::default(),
                user_registration_tree_proof: None,
                proof: Some(crate::trace::UpsStartProofRecord { proof: vec![1] }),
            },
            contract_codes: Vec::new(),
            steps: Vec::new(),
            finalization: crate::trace::TxFinalization {
                submit_end_cap_input: Default::default(),
                nonce: Default::default(),
                software_defined_call: Default::default(),
                tx_hash: QHashOut::ZERO,
                sig_hash: QHashOut::ZERO,
            },
        }
    }

    #[test]
    fn eip191_signature_parser_requires_exactly_65_bytes() {
        let signature = (0..65).map(|value| value as u8).collect::<Vec<_>>();
        let parsed = parse_eip191_signature(signature.clone()).unwrap();
        assert_eq!(parsed.as_slice(), signature);

        for invalid_length in [0, 64, 66] {
            let error = parse_eip191_signature(vec![0; invalid_length]).unwrap_err();
            assert_eq!(error.code(), 1);
            assert!(error.message().contains(&format!("got {invalid_length}")));
        }
    }

    #[test]
    fn trace_payload_decoder_supports_json_and_bincode_and_rejects_unknown_encoding() {
        let trace = minimal_trace();
        let json_payload = crate::trace::TracePayload {
            encoding: "json".to_string(),
            payload: serde_json::to_string(&trace).unwrap(),
        };
        let decoded_json = decode_trace_payload(&json_payload).unwrap();
        assert_eq!(decoded_json.meta.network_magic, 1);
        assert_eq!(decoded_json.meta.user_id, 2);

        let bincode_payload = crate::trace::TracePayload {
            encoding: "bincode-base64".to_string(),
            payload: base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&trace).unwrap()),
        };
        let decoded_bincode = decode_trace_payload(&bincode_payload).unwrap();
        assert_eq!(decoded_bincode.anchor.start_checkpoint_id, 3);
        assert_eq!(decoded_bincode.ups_start_witness.proof.unwrap().proof, vec![1]);

        let unsupported = crate::trace::TracePayload {
            encoding: "cbor".to_string(),
            payload: String::new(),
        };
        assert!(decode_trace_payload(&unsupported)
            .err()
            .unwrap()
            .to_string()
            .contains("Unsupported trace payload encoding: cbor"));
    }

    #[test]
    fn trace_payload_decoder_reports_malformed_payloads() {
        for payload in [
            crate::trace::TracePayload {
                encoding: "json".to_string(),
                payload: "not-json".to_string(),
            },
            crate::trace::TracePayload {
                encoding: "bincode-base64".to_string(),
                payload: "not-base64!".to_string(),
            },
            crate::trace::TracePayload {
                encoding: "bincode-base64".to_string(),
                payload: "AA==".to_string(),
            },
        ] {
            assert!(decode_trace_payload(&payload).is_err());
        }
    }

    #[tokio::test]
    async fn offline_session_backs_rpc_server_error_paths() {
        let start = std::time::Instant::now();
        let session = crate::test_support::shared_offline_wallet_session().await;
        eprintln!("offline wallet session initialized in {:?}", start.elapsed());

        let rpc_server = RpcServerImpl::new(session);
        assert!(!rpc_server.rpc_provider().realm_configs.is_empty());
        assert!(!rpc_server.rpc_provider().coordinator_configs.is_empty());

        // Pure handler: deterministic network-bound EIP-191 challenge.
        let challenge = rpc_server.eth_personal_registration_challenge([7; 20]).await.unwrap();
        assert_eq!(challenge, rpc_server.eth_personal_registration_challenge([7; 20]).await.unwrap());
        let zero_address = rpc_server.eth_personal_registration_challenge([0; 20]).await.unwrap_err();
        assert!(zero_address.message().contains("zero address"));

        // Dead-RPC handlers surface mapped errors instead of panicking.
        let call = ContractCallArgs {
            contract_id: 1,
            method_name: "main".to_string(),
            inputs: vec![1],
        };
        let error = rpc_server.call_view(QHashOut::ZERO, ViewCallData::new(vec![call])).await.unwrap_err();
        assert_eq!(error.code(), 1);

        let error = rpc_server
            .simulate_contract_call(QHashOut::ZERO, ContractCallData::new(Vec::new()))
            .await
            .unwrap_err();
        assert_eq!(error.code(), 1);
    }

    #[tokio::test]
    async fn rpc_handlers_validate_and_dispatch_against_the_offline_session() {
        let session_arc = crate::test_support::shared_offline_wallet_session().await;
        let rpc_server = RpcServerImpl::new(session_arc.clone());
        let unregistered = QHashOut::ZERO;
        let call = ContractCallArgs {
            contract_id: 1,
            method_name: "main".to_string(),
            inputs: vec![1],
        };

        // exec_contract_call bails on empty call lists before touching users.
        let error = rpc_server.exec_contract_call(unregistered, Vec::new()).await.unwrap_err();
        assert_eq!(error.code(), 1);
        let error = rpc_server.exec_contract_call(unregistered, vec![call.clone()]).await.unwrap_err();
        assert_eq!(error.code(), 1);

        // trace generation and proving fail fast on the unknown user.
        let error = rpc_server
            .generate_tx_trace(unregistered, ContractCallData::new(vec![call.clone()]))
            .await
            .unwrap_err();
        assert_eq!(error.code(), 1);
        let error = rpc_server.start_session(unregistered).await.unwrap_err();
        assert_eq!(error.code(), 1);
        let error = rpc_server.prove_contract_call(unregistered, vec![call.clone()]).await.unwrap_err();
        assert_eq!(error.code(), 1);
        let error = rpc_server.sign_and_submit(unregistered).await.unwrap_err();
        assert_eq!(error.code(), 1);

        // prove_tx_trace: malformed envelope, unsupported encoding, undecodable
        // payload, then the decoded-trace path failing on the unknown user.
        let error = rpc_server.prove_tx_trace(unregistered, "not json".to_string()).await.unwrap_err();
        assert_eq!(error.code(), 1);

        let envelope = serde_json::json!({
            "user_id": "0", "pk_hash": "0", "sig_hash": "0", "tx_hash": "0",
            "call_data": serde_json::Value::Null,
            "tx_count": 0,
            "trace": { "encoding": "cbor", "payload": String::new() },
        });
        let error = rpc_server
            .prove_tx_trace(unregistered, serde_json::to_string(&envelope).unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.code(), 1);

        let envelope = serde_json::json!({
            "user_id": "0", "pk_hash": "0", "sig_hash": "0", "tx_hash": "0",
            "call_data": serde_json::Value::Null,
            "tx_count": 0,
            "trace": {
                "encoding": "json".to_string(),
                "payload": serde_json::to_string(&minimal_trace()).unwrap(),
            },
        });
        let error = rpc_server
            .prove_tx_trace(unregistered, serde_json::to_string(&envelope).unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.code(), 1);

        // register_user creates the wallet user locally, then the dead-RPC
        // chain registration surfaces as a mapped error; add_user reports the
        // missing on-chain registration.
        let zk_fingerprint = session_arc.read().wallet.zk_circuit_fingerprint().await.unwrap();
        let private_key = QHashOut::from_values(101, 102, 103, 104);
        let error = rpc_server.register_user(private_key, zk_fingerprint).await.unwrap_err();
        assert_eq!(error.code(), 1);
        let error = rpc_server.add_user(private_key, zk_fingerprint).await.unwrap_err();
        assert_eq!(error.code(), 1);

        // SD-key circuit registration is fully offline.
        let sd_key_fingerprint = rpc_server.register_sd_key_circuit(vec![9], vec![8], 1).await.unwrap();
        assert_ne!(sd_key_fingerprint, QHashOut::ZERO);

        // keypair helpers stay offline and consistent.
        let keypair = rpc_server.get_random_keypair().await.unwrap();
        let pk_info = rpc_server.get_zk_public_key(keypair.private_key).await.unwrap();
        assert_eq!(pk_info.fingerprint, keypair.public_key.fingerprint);
        assert_eq!(pk_info.public_key_param, keypair.public_key.public_key_param);

        // EIP-191 registration validates before touching the chain.
        let error = rpc_server
            .register_external_eth_personal_user([0; 20], Hash256([1; 32]), vec![0; 65])
            .await
            .unwrap_err();
        assert_eq!(error.code(), 1);
        let error = rpc_server
            .inject_eth_personal_signature(unregistered, [7; 20], Hash256([7; 32]), vec![1; 64])
            .await
            .unwrap_err();
        assert!(error.message().contains("65 bytes"));

        // A canonical personal_sign registration signature installs the PK-only
        // wallet user before the dead-RPC submission fails, so the follow-up
        // injection succeeds and returns the expected public key.
        let signing = SigningKey::from_slice(&[3_u8; 32]).unwrap();
        let address = ethereum_address_for_verifying_key(&VerifyingKey::from(&signing));
        let challenge = WalletSession::eth_personal_registration_challenge(address).unwrap();
        let signature65 = sign_eth_personal_65(&signing, challenge);
        let error = rpc_server
            .register_external_eth_personal_user(address, challenge, signature65.to_vec())
            .await
            .unwrap_err();
        assert_eq!(error.code(), 1);

        let recovered = recover_eth_personal_signature(address, challenge, signature65).unwrap();
        let session = session_arc.read();
        let manager = session.wallet.random_circuit_manager();
        let eth_personal_fingerprint = manager.as_ref().eth_personal_secp_circuit_fingerprint().await.unwrap();
        let expected_public_key = ZKPublicKeyInfo {
            fingerprint: eth_personal_fingerprint,
            public_key_param: hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(CompressedPublicKey(recovered.public_key)),
        }
        .qfhash::<PsyHasher>();
        drop(session);

        let message = Hash256([9; 32]);
        let injected = rpc_server
            .inject_eth_personal_signature(expected_public_key, address, message, sign_eth_personal_65(&signing, message).to_vec())
            .await
            .unwrap();
        assert_eq!(injected, expected_public_key);
    }

    fn sign_eth_personal_65(signing: &SigningKey, message: Hash256) -> [u8; 65] {
        let digest = eth_personal_sign_digest(&message.0);
        let (signature, recovery_id) = signing.sign_prehash_recoverable(&digest).unwrap();
        let mut signature65 = [0_u8; 65];
        signature65[..64].copy_from_slice(&signature.to_bytes());
        signature65[64] = recovery_id.to_byte();
        signature65
    }

    #[tokio::test]
    async fn rpc_handlers_build_and_submit_contract_deploy_commands() {
        let session_arc = crate::test_support::shared_offline_wallet_session().await;
        let rpc_server = RpcServerImpl::new(session_arc.clone());

        let source = r#"
            #[contract]
            pub struct TestContract {
                pub value: Felt,
            }

            #[contract_implementation]
            impl TestContract {
                #[contract_method]
                pub fn set_value(&mut self, ctx: &ChainContext, new_value: Felt) {
                    self.value = new_value;
                }
            }
        "#;
        let output = psy_compiler::compile(source).expect("compilation should succeed");
        let deployer = QHashOut::ZERO;

        // the layout-aware deploy command is built entirely offline
        let deploy_cmd = rpc_server
            .get_deploy_contract_cmd(deployer, output.circuit_definitions.clone(), output.abi.clone())
            .await
            .unwrap();
        assert_eq!(deploy_cmd.deploy_contract.deployer, deployer);

        // deploy_contract performs the same local build, then the dead-RPC
        // submission fails
        let error = rpc_server
            .deploy_contract(deployer, output.circuit_definitions, output.abi)
            .await
            .unwrap_err();
        assert_eq!(error.code(), 1);
    }

    /// The happy-path handlers against the offline chain: trace generation,
    /// view simulation, view calls, session start, and contract-call proving
    /// all serialize their results without touching a live network.
    #[tokio::test]
    async fn rpc_handlers_serve_offline_success_paths() {
        use crate::session::session::offline_trace_pipeline_tests as offline;

        let (port, _rpc_seen, responses) = offline::spawn_offline_rpc().await;
        let mut wallet_session = WalletSession::new(&offline::loopback_network_config(port)).await.unwrap();
        let pk_info = wallet_session
            .wallet
            .add_zk_private_key(QHashOut::from_values(881, 882, 883, 884))
            .await
            .unwrap();
        let public_key = pk_info.qfhash::<PsyHasher>();

        let chain = offline::build_offline_chain(
            public_key,
            vec![offline::seeded_helper_contract(), offline::seeded_token_contract()],
        );
        offline::set_offline_responses(&responses, &chain).unwrap();
        offline::set_offline_chain_rpc_rules(&responses, &chain, public_key).unwrap();

        let session_arc = Arc::new(parking_lot::RwLock::new(wallet_session));
        let rpc_server = RpcServerImpl::new(session_arc);

        let set_value = ContractCallArgs {
            contract_id: offline::OFFLINE_HELPER_CONTRACT_ID,
            method_name: "set_value".to_string(),
            inputs: vec![5],
        };
        let get_value = ContractCallArgs {
            contract_id: offline::OFFLINE_HELPER_CONTRACT_ID,
            method_name: "get_value".to_string(),
            inputs: vec![],
        };

        // generate_tx_trace serializes the full envelope
        let envelope = rpc_server
            .generate_tx_trace(public_key, ContractCallData::new(vec![set_value.clone()]))
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        assert_eq!(parsed["tx_count"], 3);
        assert_eq!(parsed["trace"]["encoding"], "json");

        // view simulation stays read-only through the getter
        let simulated = rpc_server
            .simulate_contract_call(public_key, ContractCallData::new(vec![get_value.clone()]))
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&simulated).unwrap();
        assert!(parsed["metadata"].get("tx_hash").is_none());

        // call_view returns the checkpoint-bound read result
        let view = rpc_server.call_view(public_key, ViewCallData::new(vec![get_value])).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&view).unwrap();
        assert_eq!(parsed["checkpoint_id"], offline::OFFLINE_CHECKPOINT_ID);

        // start_session acknowledges, and prove_contract_call proves without
        // submitting
        assert_eq!(rpc_server.start_session(public_key).await.unwrap(), "start session");
        assert_eq!(
            rpc_server.prove_contract_call(public_key, vec![set_value]).await.unwrap(),
            "prove contract calls"
        );
    }

    /// `prove_tx_trace` round-trips against the offline chain: the envelope
    /// from `generate_tx_trace` feeds straight back in and, with the submit
    /// shadowed, the full prove pipeline reports a submitted result. The
    /// remaining mapped inner errors (signature injection for an unknown
    /// public key, sd-key allowed-pairs shape) surface as RPC errors.
    #[tokio::test]
    async fn rpc_handlers_prove_tx_trace_and_map_inner_errors() {
        use crate::session::session::offline_trace_pipeline_tests as offline;

        let (port, _rpc_seen, responses) = offline::spawn_offline_rpc().await;
        let mut wallet_session = WalletSession::new(&offline::loopback_network_config(port)).await.unwrap();
        let pk_info = wallet_session
            .wallet
            .add_zk_private_key(QHashOut::from_values(891, 892, 893, 894))
            .await
            .unwrap();
        let public_key = pk_info.qfhash::<PsyHasher>();

        let chain = offline::build_offline_chain(public_key, vec![offline::seeded_helper_contract(), offline::seeded_token_contract()]);
        offline::set_offline_responses(&responses, &chain).unwrap();
        offline::set_offline_chain_rpc_rules(&responses, &chain, public_key).unwrap();
        responses.lock().insert(
            0,
            offline::OfflineRpcRule {
                method: "psy_submit_user_end_cap".to_string(),
                params: None,
                response: serde_json::json!({ "result": serde_json::to_value(&QHashOut::<F>::ZERO).unwrap() }),
            },
        );

        let session_arc = Arc::new(parking_lot::RwLock::new(wallet_session));
        let rpc_server = RpcServerImpl::new(session_arc);

        let set_value = ContractCallArgs {
            contract_id: offline::OFFLINE_HELPER_CONTRACT_ID,
            method_name: "set_value".to_string(),
            inputs: vec![6],
        };
        let envelope = rpc_server
            .generate_tx_trace(public_key, ContractCallData::new(vec![set_value]))
            .await
            .unwrap();

        let proved = rpc_server.prove_tx_trace(public_key, envelope).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&proved).unwrap();
        assert_eq!(parsed["status"], "submitted");
        assert!(parsed["tx_hash"].as_str().is_some_and(|hash| !hash.is_empty()));

        // mapped inner errors: a well-formed 65-byte signature for an unknown
        // public key, and an empty sd-key allowed-contract list
        let error = rpc_server
            .inject_eth_personal_signature(QHashOut::ZERO, [7; 20], Hash256([7; 32]), vec![1; 65])
            .await
            .unwrap_err();
        assert_eq!(error.code(), 1);

        let error = rpc_server.register_sd_key_circuit(vec![], vec![2, 3], 1).await.unwrap_err();
        assert_eq!(error.code(), 1);
    }
}
