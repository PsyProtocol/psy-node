use std::result::Result::Ok;

use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{
    config::store_config::PsyHasher,
    dpn::event::PsyUserEventRecord,
    qdata::{
        checkpoint::PsyCheckpointLeaf,
        contract::{ContractCodeDefinition, PsyContractLeaf, SimpleContractCodeDefinition},
        user::{self, PsyUserLeaf},
    },
    traits::qdatastore::{
        qmetadata::QMetaDataStoreReaderSync,
        qtreedata::{PsyComboDataStoreReaderSync, QTreeDataStoreReaderSync},
    },
};
use psy_config::network_constants::{COORDINATOR_USER_TREE_HEIGHT, GLOBAL_DEPOSIT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, REALM_USER_TREE_HEIGHT};
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::hasher::MerkleZeroHasher};
use tracing::{debug, error, info, instrument};

use super::{provider::RpcProvider, request::*};

type F = GoldilocksField;

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl QTreeDataStoreReaderSync<F> for RpcProvider {
    #[instrument(skip(self), fields(checkpoint_id, user_id, contract_id))]
    async fn get_user_contract_state_tree_root(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
    ) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        debug!(
            checkpoint_id = checkpoint_id,
            user_id = user_id,
            contract_id = contract_id,
            "Fetching user contract state tree root"
        );
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserContractStateTreeRootRPCRequest {
            checkpoint_id,
            user_id,
            contract_id,
        };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetUserContractStateTreeRoot(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    contract_id = contract_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_contract_state_tree_root rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, user_id, contract_id, leaf_id))]
    async fn get_user_contract_state_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        _height: u8,
        leaf_id: u64,
    ) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        debug!(
            checkpoint_id = checkpoint_id,
            user_id = user_id,
            contract_id = contract_id,
            leaf_id = leaf_id,
            "Fetching user contract state tree leaf hash"
        );
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserContractStateTreeLeafHashRPCRequest {
            checkpoint_id,
            user_id,
            contract_id,
            leaf_id,
        };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetUserContractStateTreeLeafHash(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    contract_id = contract_id,
                    leaf_id = leaf_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_contract_state_tree_leaf_hash rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, user_id, contract_id, leaf_id))]
    async fn get_user_contract_state_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        expected_height: u8,
        leaf_id: u64,
    ) -> anyhow::Result<psy_crypto::hash::merkle::core::MerkleProofCore<psy_client_common::data::qhashout::QHashOut<F>>> {
        debug!(
            checkpoint_id = checkpoint_id,
            user_id = user_id,
            contract_id = contract_id,
            leaf_id = leaf_id,
            "Fetching user contract state tree merkle proof"
        );
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserContractStateTreeMerkleProofRPCRequest {
            checkpoint_id,
            user_id,
            contract_id,
            leaf_id,
        };
        let response = psy_rpc_call_back!(
            self,
            rpc_url,
            RequestParams::<F>::GetUserContractStateTreeMerkleProof(input),
            MerkleProofCore<QHashOut<F>>
        );
        match response.result {
            ResponseResult::Success(merkle_proof) => {
                // `expected_height == 0` is the "unknown / let the Realm
                // decide" sentinel used by callers (e.g. the CLI) that do not
                // know the deployed contract's state-tree height; skip the
                // check in that case. Real state-tree heights are never 0.
                if expected_height != 0 && merkle_proof.siblings.len() != expected_height as usize {
                    anyhow::bail!(
                        "user contract state proof height mismatch: checkpoint_id={} user_id={} contract_id={} leaf_id={} expected_height={} rpc_siblings_len={}",
                        checkpoint_id,
                        user_id,
                        contract_id,
                        leaf_id,
                        expected_height,
                        merkle_proof.siblings.len()
                    );
                }
                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    contract_id = contract_id,
                    leaf_id = leaf_id,
                    merkle_proof = %serde_json::to_string_pretty(&merkle_proof).unwrap(),
                    "Successfully fetched merkle proof"
                );
                Ok(merkle_proof)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_contract_state_tree_merkle_proof rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, user_id))]
    async fn get_user_contract_tree_root(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        debug!(checkpoint_id = checkpoint_id, user_id = user_id, "Fetching user contract tree root");
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserContractTreeRootRPCRequest { checkpoint_id, user_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetUserContractTreeRoot(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_contract_tree_root rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, user_id, contract_id))]
    async fn get_user_contract_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
    ) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        debug!(
            checkpoint_id = checkpoint_id,
            user_id = user_id,
            contract_id = contract_id,
            "Fetching user contract tree leaf hash"
        );
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserContractTreeLeafHashRPCRequest {
            checkpoint_id,
            user_id,
            contract_id,
        };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetUserContractTreeLeafHash(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    contract_id = contract_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_contract_tree_root_f rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, user_id, contract_id))]
    async fn get_user_contract_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
    ) -> anyhow::Result<psy_crypto::hash::merkle::core::MerkleProofCore<psy_client_common::data::qhashout::QHashOut<F>>> {
        debug!(
            checkpoint_id = checkpoint_id,
            user_id = user_id,
            contract_id = contract_id,
            "Fetching user contract tree merkle proof"
        );
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserContractTreeMerkleProofRPCRequest {
            checkpoint_id,
            user_id,
            contract_id,
        };
        let response = psy_rpc_call_back!(
            self,
            rpc_url,
            RequestParams::<F>::GetUserContractTreeMerkleProof(input),
            MerkleProofCore<QHashOut<F>>
        );
        match response.result {
            ResponseResult::Success(merkle_proof) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    contract_id = contract_id,
                    merkle_proof = %serde_json::to_string_pretty(&merkle_proof).unwrap(),
                    "Successfully fetched merkle proof"
                );
                debug!("Merkle proof verification result: {}", merkle_proof.verify::<PsyHasher>());
                Ok(merkle_proof)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_contract_tree_merkle_proof rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id))]
    async fn get_user_registration_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        debug!(checkpoint_id = checkpoint_id, "Fetching user registration tree root");
        let rpc_url = self.get_coordinator_url()?;
        let input = QUserRegistrationTreeRootRPCRequest { checkpoint_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetUserRegistrationTreeRoot(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_registration_tree_root rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, leaf_index))]
    async fn get_user_registration_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        leaf_index: u64,
    ) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        debug!(
            checkpoint_id = checkpoint_id,
            leaf_index = leaf_index,
            "Fetching user registration tree leaf hash"
        );
        let rpc_url = self.get_coordinator_url()?;
        let input = QUserRegistrationTreeLeafHashRPCRequest { checkpoint_id, leaf_index };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetUserRegistrationTreeLeafHash(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    leaf_index = leaf_index,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_registration_tree_leaf_hash rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, leaf_index))]
    async fn get_user_registration_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        leaf_index: u64,
    ) -> anyhow::Result<psy_crypto::hash::merkle::core::MerkleProofCore<psy_client_common::data::qhashout::QHashOut<F>>> {
        debug!(
            checkpoint_id = checkpoint_id,
            leaf_index = leaf_index,
            "Fetching user registration tree merkle proof"
        );
        let rpc_url = self.get_coordinator_url()?;
        let input = QUserRegistrationTreeMerkleProofRPCRequest { checkpoint_id, leaf_index };
        let response = psy_rpc_call_back!(
            self,
            rpc_url,
            RequestParams::<F>::GetUserRegistrationTreeMerkleProof(input),
            MerkleProofCore<QHashOut<F>>
        );
        match response.result {
            ResponseResult::Success(merkle_proof) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    leaf_index = leaf_index,
                    merkle_proof = %serde_json::to_string_pretty(&merkle_proof).unwrap(),
                    "Successfully fetched merkle proof"
                );
                Ok(merkle_proof)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_registration_tree_merkle_proof rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id))]
    async fn get_user_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        debug!(checkpoint_id = checkpoint_id, "Fetching user tree root");
        let rpc_url = self.get_coordinator_url()?;
        let input = QUserTreeRootRPCRequest { checkpoint_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetUserTreeRoot(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_tree_root rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, user_id))]
    async fn get_user_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        info!("Fetching user tree leaf hash checkpoint_id: {}, user_id: {}", checkpoint_id, user_id);
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserTreeLeafHashRPCRequest { checkpoint_id, user_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetUserTreeLeafHash(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_tree_leaf_hash rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, user_id))]
    async fn get_user_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
    ) -> anyhow::Result<psy_crypto::hash::merkle::core::MerkleProofCore<psy_client_common::data::qhashout::QHashOut<F>>> {
        info!("Fetching user tree merkle proof checkpoint_id: {}, user_id: {}", checkpoint_id, user_id);
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserTreeMerkleProofRPCRequest { checkpoint_id, user_id };
        let response = psy_rpc_call_back!(
            self,
            rpc_url,
            RequestParams::<F>::GetUserTreeMerkleProof(input),
            MerkleProofCore<QHashOut<F>>
        );
        match response.result {
            ResponseResult::Success(mut merkle_proof) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    merkle_proof = %serde_json::to_string_pretty(&merkle_proof).unwrap(),
                    "Successfully fetched merkle proof"
                );
                debug!("Retrieved bottom merkle proof: {}", serde_json::to_string_pretty(&merkle_proof).unwrap());
                info!("Merkle proof root: {:?}", merkle_proof.root.to_string());
                info!("Merkle proof value: {:?}", merkle_proof.value.to_string());
                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    verify_result = %merkle_proof.verify::<PsyHasher>(),
                    "Before verify"
                );

                // Newer realm edges can already return a full global-user-tree proof.
                // Prefer the proof as-is when it verifies locally, and only fall back
                // to the older coordinator+realm stitching path when necessary.
                // if merkle_proof.verify::<PsyHasher>() {
                //     return Ok(merkle_proof);
                // }

                let top_proof = self
                    .get_user_sub_tree_merkle_proof(checkpoint_id, 0, COORDINATOR_USER_TREE_HEIGHT, self.get_realm_id(user_id))
                    .await?;
                debug!("Retrieved top proof: {}", serde_json::to_string_pretty(&top_proof).unwrap());
                let mut new_siblings = vec![];
                new_siblings.extend_from_slice(&merkle_proof.siblings[0..(REALM_USER_TREE_HEIGHT as usize)]);
                new_siblings.extend_from_slice(&top_proof.siblings);
                merkle_proof.root = top_proof.root;
                merkle_proof.siblings = new_siblings;
                debug!(
                    "Modified merkle proof with top proof: {}",
                    serde_json::to_string_pretty(&merkle_proof).unwrap()
                );

                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    verify_result = %merkle_proof.verify::<PsyHasher>(),
                    "After verify"
                );
                match merkle_proof.verify::<PsyHasher>() {
                    true => Ok(merkle_proof),
                    false => Err(anyhow::format_err!("user tree merkle proof verify failed")),
                }
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_tree_merkle_proof rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, root_level, leaf_level, leaf_index))]
    async fn get_user_sub_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> anyhow::Result<psy_crypto::hash::merkle::core::MerkleProofCore<psy_client_common::data::qhashout::QHashOut<F>>> {
        info!(
            "Fetching user sub tree merkle proof checkpoint_id: {}, root_level: {}, leaf_level: {}, leaf_index: {}",
            checkpoint_id, root_level, leaf_level, leaf_index
        );

        if root_level > leaf_level {
            anyhow::bail!("root level {} must be less than leaf level {}", root_level, leaf_level);
        }
        if root_level > GLOBAL_USER_TREE_HEIGHT || leaf_level > GLOBAL_USER_TREE_HEIGHT {
            anyhow::bail!(
                "root level {} and leaf level {} must be less than global user tree height {}",
                root_level,
                leaf_level,
                GLOBAL_USER_TREE_HEIGHT
            );
        }

        let real_user_id = leaf_index << (GLOBAL_USER_TREE_HEIGHT - leaf_level);
        let realm_rpc_url = self.get_realm_url(real_user_id)?;

        let coordinator_rpc_url = self.get_coordinator_url()?;

        if root_level >= COORDINATOR_USER_TREE_HEIGHT {
            self.get_user_sub_tree_merkle_proof_inner(realm_rpc_url, checkpoint_id, root_level, leaf_level, leaf_index)
                .await
        } else if leaf_level <= COORDINATOR_USER_TREE_HEIGHT {
            self.get_user_sub_tree_merkle_proof_inner(&coordinator_rpc_url, checkpoint_id, root_level, leaf_level, leaf_index)
                .await
        } else {
            tracing::info!("you need to get both sub tree of coordinator and realm");
            let top_tree_leaf_index = leaf_index >> (leaf_level - COORDINATOR_USER_TREE_HEIGHT);
            let top_tree_proof = self
                .get_user_sub_tree_merkle_proof_inner(
                    &coordinator_rpc_url,
                    checkpoint_id,
                    root_level,
                    COORDINATOR_USER_TREE_HEIGHT,
                    top_tree_leaf_index,
                )
                .await?;
            debug!("top tree proof:{}", serde_json::to_string_pretty(&top_tree_proof)?);
            let bottom_tree_proof = self
                .get_user_sub_tree_merkle_proof_inner(&realm_rpc_url, checkpoint_id, COORDINATOR_USER_TREE_HEIGHT, leaf_level, leaf_index)
                .await?;
            debug!("bottom tree proof:{}", serde_json::to_string_pretty(&bottom_tree_proof)?);

            if top_tree_proof.value != bottom_tree_proof.root {
                tracing::error!(
                    "coordinator sub tree proof's value {} should be equal to realm sub tree proof's root {}",
                    top_tree_proof.value,
                    bottom_tree_proof.root
                );
                anyhow::bail!(
                    "coordinator sub tree proof's value {} should be equal to realm sub tree proof's root {}",
                    top_tree_proof.value,
                    bottom_tree_proof.root
                );
            }

            let mut new_siblings = bottom_tree_proof.siblings;
            new_siblings.extend_from_slice(&top_tree_proof.siblings);

            let combine_tree_proof = MerkleProofCore {
                root: top_tree_proof.root,
                value: bottom_tree_proof.value,
                index: leaf_index,
                siblings: new_siblings,
            };

            debug!("combine_tree_proof: {}", serde_json::to_string_pretty(&combine_tree_proof)?);

            debug!(
                checkpoint_id = checkpoint_id,
                root_level = root_level,
                leaf_level = leaf_level,
                leaf_index = leaf_index,
                verify_result = %combine_tree_proof.verify::<PsyHasher>(),
                "After verify"
            );
            match combine_tree_proof.verify::<PsyHasher>() {
                true => Ok(combine_tree_proof),
                false => Err(anyhow::format_err!("user sub tree merkle proof verify failed")),
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, contract_id))]
    async fn get_contract_function_tree_root(
        &self,
        checkpoint_id: u64,
        contract_id: u32,
    ) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        debug!(
            checkpoint_id = checkpoint_id,
            contract_id = contract_id,
            "Fetching contract function tree root"
        );
        let rpc_url = self.get_coordinator_url()?;
        let input = QContractFunctionTreeRootRPCRequest { checkpoint_id, contract_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetContractFunctionTreeRoot(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    contract_id = contract_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_contract_function_tree_root rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, contract_id, function_id))]
    async fn get_contract_function_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        contract_id: u32,
        function_id: u32,
    ) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        debug!(
            checkpoint_id = checkpoint_id,
            contract_id = contract_id,
            function_id = function_id,
            "Fetching contract function tree leaf hash"
        );
        let rpc_url = self.get_coordinator_url()?;
        let input = QContractFunctionTreeLeafHashRPCRequest {
            checkpoint_id,
            contract_id,
            function_id,
        };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetContractFunctionTreeLeafHash(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    contract_id = contract_id,
                    function_id = function_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_contract_function_tree_leaf_hash rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, contract_id, function_id))]
    async fn get_contract_function_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        contract_id: u32,
        function_id: u32,
    ) -> anyhow::Result<psy_crypto::hash::merkle::core::MerkleProofCore<psy_client_common::data::qhashout::QHashOut<F>>> {
        debug!(
            checkpoint_id = checkpoint_id,
            contract_id = contract_id,
            function_id = function_id,
            "Fetching contract function tree merkle proof"
        );
        let rpc_url = self.get_coordinator_url()?;
        let input = QContractFunctionTreeMerkleProofRPCRequest {
            checkpoint_id,
            contract_id,
            function_id,
        };
        let response = psy_rpc_call_back!(
            self,
            rpc_url,
            RequestParams::<F>::GetContractFunctionTreeMerkleProof(input),
            MerkleProofCore<QHashOut<F>>
        );
        match response.result {
            ResponseResult::Success(merkle_proof) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    contract_id = contract_id,
                    function_id = function_id,
                    merkle_proof = %serde_json::to_string_pretty(&merkle_proof).unwrap(),
                    "Successfully fetched merkle proof"
                );
                Ok(merkle_proof)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_contract_function_tree_merkle_proof rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id))]
    async fn get_contract_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        debug!(checkpoint_id = checkpoint_id, "Fetching contract tree root");
        let rpc_url = self.get_coordinator_url()?;
        let input = QContractTreeRootRPCRequest { checkpoint_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetContractTreeRoot(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_contract_tree_root rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, contract_id))]
    async fn get_contract_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        contract_id: u32,
    ) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        info!(
            "Fetching contract tree leaf hash checkpoint_id: {}, contract_id: {}",
            checkpoint_id, contract_id
        );
        let rpc_url = self.get_coordinator_url()?;
        let input = QContractTreeLeafHashRPCRequest { checkpoint_id, contract_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetContractTreeLeafHash(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    contract_id = contract_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_contract_tree_leaf_hash rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, contract_id))]
    async fn get_contract_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        contract_id: u32,
    ) -> anyhow::Result<psy_crypto::hash::merkle::core::MerkleProofCore<psy_client_common::data::qhashout::QHashOut<F>>> {
        info!(
            "Fetching contract tree merkle proof checkpoint_id: {}, contract_id: {}",
            checkpoint_id, contract_id
        );
        let rpc_url = self.get_coordinator_url()?;
        let input = QContractTreeMerkleProofRPCRequest { checkpoint_id, contract_id };
        let response = psy_rpc_call_back!(
            self,
            rpc_url,
            RequestParams::<F>::GetContractTreeMerkleProof(input),
            MerkleProofCore<QHashOut<F>>
        );
        match response.result {
            ResponseResult::Success(merkle_proof) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    contract_id = contract_id,
                    merkle_proof = %serde_json::to_string_pretty(&merkle_proof).unwrap(),
                    "Successfully fetched merkle proof"
                );
                Ok(merkle_proof)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_contract_tree_merkle_proof rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, deposit_id))]
    #[instrument(skip(self), fields(checkpoint_id))]
    async fn get_withdrawal_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        info!("Fetching withdrawal tree root");
        let roots = self.get_checkpoint_global_state_roots(checkpoint_id).await?;
        let hash = roots.withdrawal_tree_root;
        debug!(
            checkpoint_id = checkpoint_id,
            hash = %hash,
            "Successfully fetched withdrawal tree root from checkpoint global state roots"
        );
        Ok(hash)
    }

    #[instrument(skip(self))]
    async fn get_latest_checkpoint_tree_root(&self) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        info!("Fetching latest checkpoint tree root");
        let rpc_url = self.get_coordinator_url()?;
        let input = QLatestCheckpointTreeRootRPCRequest {};
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetLatestCheckpointTreeRoot(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_latest_checkpoint_tree_root rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id))]
    async fn get_checkpoint_tree_root(&self, checkpoint_id: u64) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        info!("Fetching checkpoint tree root");
        let rpc_url = self.get_checkpoint_scope_rpc_url()?;
        let input = QCheckpointTreeRootRPCRequest { checkpoint_id };
        let response = psy_rpc_call_back!(self, &rpc_url, RequestParams::<F>::GetCheckpointTreeRoot(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_checkpoint_tree_root rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, leaf_checkpoint_id))]
    async fn get_checkpoint_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        leaf_checkpoint_id: u64,
    ) -> anyhow::Result<psy_client_common::data::qhashout::QHashOut<F>> {
        info!("Fetching checkpoint tree leaf hash");
        let rpc_url = self.get_checkpoint_scope_rpc_url()?;
        let input = QCheckpointTreeLeafHashRPCRequest {
            checkpoint_id,
            leaf_checkpoint_id,
        };
        let response = psy_rpc_call_back!(self, &rpc_url, RequestParams::<F>::GetCheckpointTreeLeafHash(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    leaf_checkpoint_id = leaf_checkpoint_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_checkpoint_tree_leaf_hash rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, leaf_checkpoint_id))]
    async fn get_checkpoint_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        leaf_checkpoint_id: u64,
    ) -> anyhow::Result<psy_crypto::hash::merkle::core::MerkleProofCore<psy_client_common::data::qhashout::QHashOut<F>>> {
        info!("Fetching checkpoint tree merkle proof");
        let rpc_url = self.get_checkpoint_scope_rpc_url()?;
        let input = QCheckpointTreeMerkleProofRPCRequest {
            checkpoint_id,
            leaf_checkpoint_id,
        };
        let response = psy_rpc_call_back!(
            self,
            &rpc_url,
            RequestParams::<F>::GetCheckpointTreeMerkleProof(input),
            MerkleProofCore<QHashOut<F>>
        );
        match response.result {
            ResponseResult::Success(merkle_proof) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    leaf_checkpoint_id = leaf_checkpoint_id,
                    merkle_proof = %serde_json::to_string_pretty(&merkle_proof).unwrap(),
                    "Successfully fetched merkle proof"
                );
                Ok(merkle_proof)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_checkpoint_tree_merkle_proof rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, user_id))]
    async fn get_user_event_tree_root(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<QHashOut<F>> {
        info!("Fetching user event tree root");
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserEventTreeRootRPCRequest { checkpoint_id, user_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetUserEventTreeRoot(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_event_tree_root rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, user_id, event_index))]
    async fn get_user_event_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64, event_index: u64) -> anyhow::Result<QHashOut<F>> {
        info!("Fetching user event tree leaf hash");
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserEventTreeLeafHashRPCRequest {
            checkpoint_id,
            user_id,
            event_index,
        };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetUserEventTreeLeafHash(input), QHashOut<F>);
        match response.result {
            ResponseResult::Success(hash) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    event_index = event_index,
                    hash = %hash,
                    "Successfully fetched hash"
                );
                Ok(hash)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_event_tree_leaf_hash rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, user_id, event_index))]
    async fn get_user_event_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        event_index: u64,
    ) -> anyhow::Result<MerkleProofCore<QHashOut<F>>> {
        info!("Fetching user event tree merkle proof");
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserEventTreeMerkleProofRPCRequest {
            checkpoint_id,
            user_id,
            event_index,
        };
        let response = psy_rpc_call_back!(
            self,
            rpc_url,
            RequestParams::<F>::GetUserEventTreeMerkleProof(input),
            MerkleProofCore<QHashOut<F>>
        );
        match response.result {
            ResponseResult::Success(merkle_proof) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    user_id = user_id,
                    event_index = event_index,
                    merkle_proof = %serde_json::to_string_pretty(&merkle_proof).unwrap(),
                    "Successfully fetched merkle proof"
                );
                Ok(merkle_proof)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_event_tree_merkle_proof rpc call failed `{:?}`", e))
            }
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl QMetaDataStoreReaderSync<F> for RpcProvider {
    #[instrument(skip(self), fields(checkpoint_id, user_id))]
    async fn get_user_leaf_data(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<user::PsyUserLeaf<F>> {
        info!("Fetching user leaf data checkpoint_id: {}, user_id: {}", checkpoint_id, user_id);
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserLeafDataRPCRequest { checkpoint_id, user_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetUserLeafData(input), PsyUserLeaf<F>);
        use psy_crypto::hash::traits::qhashable::QFieldHashable;
        match response.result {
            ResponseResult::Success(leaf) => {
                info!(
                    "Successfully fetched user leaf data checkpoint_id: {}, user_id: {}, leaf: {}, hash: {}",
                    checkpoint_id,
                    user_id,
                    serde_json::to_string_pretty(&leaf).unwrap(),
                    leaf.qfhash::<PsyHasher>().to_string()
                );
                Ok(leaf)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_leaf_data rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id, user_id))]
    async fn get_user_event_data(&self, user_id: u64, checkpoint_id: u64, event_index: u64) -> anyhow::Result<PsyUserEventRecord<F>> {
        info!("Fetching user event checkpoint_id: {}, user_id: {}", checkpoint_id, user_id);
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QUserEventDataRPCRequest {
            checkpoint_id,
            user_id,
            event_index,
        };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetUserEventData(input), PsyUserEventRecord<F>);
        use psy_crypto::hash::traits::qhashable::QFieldHashable;
        match response.result {
            ResponseResult::Success(event) => {
                info!(
                    "Successfully fetched user event checkpoint_id: {}, user_id: {}, event_index: {}, event: {}",
                    checkpoint_id,
                    user_id,
                    serde_json::to_string_pretty(&event).unwrap(),
                    event.qfhash::<PsyHasher>().to_string()
                );
                Ok(event)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_user_event rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(contract_id))]
    async fn get_contract_leaf_data(&self, contract_id: u64) -> anyhow::Result<psy_client_data::qdata::contract::PsyContractLeaf<F>> {
        info!("Fetching contract leaf data contract_id: {}", contract_id);
        let rpc_url = self.get_coordinator_url()?;
        let input = QContractLeafDataRPCRequest { contract_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetContractLeafData(input), PsyContractLeaf<F>);
        match response.result {
            ResponseResult::Success(leaf) => {
                debug!(
                    contract_id = contract_id,
                    leaf = %serde_json::to_string_pretty(&leaf).unwrap(),
                    "Successfully fetched contract leaf"
                );
                Ok(leaf)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_contract_leaf_data rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(checkpoint_id))]
    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> anyhow::Result<psy_client_data::qdata::checkpoint::PsyCheckpointLeaf<F>> {
        info!("Fetching checkpoint leaf data checkpoint_id: {}", checkpoint_id);
        let rpc_url = self.get_checkpoint_scope_rpc_url()?;
        let input = QCheckpointLeafDataRPCRequest { checkpoint_id };
        let response = psy_rpc_call_back!(self, &rpc_url, RequestParams::<F>::GetCheckpointLeafData(input), PsyCheckpointLeaf<F>);
        match response.result {
            ResponseResult::Success(leaf) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    leaf = %serde_json::to_string_pretty(&leaf).unwrap(),
                    "Successfully fetched checkpoint leaf"
                );
                Ok(leaf)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_checkpoint_leaf_data rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self), fields(contract_id))]
    async fn get_contract_code_definition(&self, contract_id: u64) -> anyhow::Result<psy_client_data::qdata::contract::ContractCodeDefinition> {
        info!("Fetching contract code definition contract_id: {}", contract_id);
        let rpc_url = self.get_coordinator_url()?;
        let input = QContractCodeDefinitionRPCRequest { contract_id };
        let response = psy_rpc_call_back!(
            self,
            rpc_url,
            RequestParams::<F>::GetContractCodeDefinition(input),
            ContractCodeDefinition
        );
        match response.result {
            ResponseResult::Success(contract_code) => {
                debug!(
                    "Successfully fetched contract {} code definition: {}",
                    contract_id,
                    serde_json::to_string_pretty(&SimpleContractCodeDefinition::from(&contract_code))?
                );
                Ok(contract_code)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_contract_code_definition rpc call failed `{:?}`", e))
            }
        }
    }

    #[instrument(skip(self))]
    async fn get_latest_block_state(&self) -> anyhow::Result<psy_client_data::qdata::checkpoint::PsyBlockState> {
        self.get_realm_latest_block_state().await
    }

    #[instrument(skip(self), fields(checkpoint_id))]
    async fn get_block_state(&self, checkpoint_id: u64) -> anyhow::Result<psy_client_data::qdata::checkpoint::PsyBlockState> {
        self.get_realm_block_state(checkpoint_id).await
    }

    #[instrument(skip(self), fields(checkpoint_id))]
    async fn get_checkpoint_global_state_roots(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots<F>> {
        RpcProvider::get_checkpoint_global_state_roots(self, checkpoint_id).await
    }

    async fn contract_state_imt_get_leaf_preimage(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        leaf_index: u64,
    ) -> anyhow::Result<psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf<F>> {
        info!(
            "Fetching IMT leaf preimage checkpoint_id: {}, user_id: {}, contract_id: {}, leaf_index: {}",
            checkpoint_id, user_id, contract_id, leaf_index
        );
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QIMTLeafPreimageRPCRequest {
            checkpoint_id,
            user_id,
            contract_id,
            leaf_index,
        };
        let response = psy_rpc_call_back!(
            self,
            rpc_url,
            RequestParams::<F>::GetIMTLeafPreimage(input),
            psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf<F>
        );
        match response.result {
            ResponseResult::Success(leaf) => {
                info!("Successfully fetched IMT leaf preimage");
                Ok(leaf)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("contract_state_imt_get_leaf_preimage rpc call failed `{:?}`", e))
            }
        }
    }

    async fn contract_state_imt_get_leaf_index_for_key(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        key: &QHashOut<F>,
    ) -> anyhow::Result<u64> {
        info!(
            "Fetching IMT leaf index for key checkpoint_id: {}, user_id: {}, contract_id: {}, key: {}",
            checkpoint_id, user_id, contract_id, key
        );
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QIMTLeafIndexForKeyRPCRequest::<F> {
            checkpoint_id,
            user_id,
            contract_id,
            key: key.clone(),
        };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetIMTLeafIndexForKey(input), u64);
        match response.result {
            ResponseResult::Success(index) => {
                info!("Successfully fetched IMT leaf index: {}", index);
                Ok(index)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("contract_state_imt_get_leaf_index_for_key rpc call failed `{:?}`", e))
            }
        }
    }

    async fn contract_state_imt_find_predecessor(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        key: &QHashOut<F>,
    ) -> anyhow::Result<(u64, psy_client_data::qdata::imt_contract_state::IMTContractStateLeaf<F>)> {
        info!(
            "Finding IMT predecessor checkpoint_id: {}, user_id: {}, contract_id: {}",
            checkpoint_id, user_id, contract_id
        );
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QFindIMTPredecessorRPCRequest {
            checkpoint_id,
            user_id,
            contract_id,
            key: key.clone(),
        };
        let response = psy_rpc_call_back!(
            self,
            rpc_url,
            RequestParams::<F>::FindIMTPredecessor(input),
            QFindIMTPredecessorResponse<F>
        );
        match response.result {
            ResponseResult::Success(resp) => {
                info!("Successfully found IMT predecessor at index: {}", resp.leaf_index);
                Ok((resp.leaf_index, resp.leaf))
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("contract_state_imt_find_predecessor rpc call failed `{:?}`", e))
            }
        }
    }

    async fn contract_state_imt_get_next_append_index(&self, user_id: u64, contract_id: u64) -> anyhow::Result<u64> {
        info!("Fetching IMT next append index user_id: {}, contract_id: {}", user_id, contract_id);
        let rpc_url = self.get_realm_url(user_id)?;
        let input = QIMTNextAppendIndexRPCRequest { user_id, contract_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetIMTNextAppendIndex(input), u64);
        match response.result {
            ResponseResult::Success(index) => {
                info!("Successfully fetched IMT next append index: {}", index);
                Ok(index)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("contract_state_imt_get_next_append_index rpc call failed `{:?}`", e))
            }
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl PsyComboDataStoreReaderSync<F> for RpcProvider {}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl RpcProvider {
    fn get_checkpoint_scope_rpc_url(&self) -> anyhow::Result<String> {
        if self.current_user_id != 0 {
            Ok(self.get_realm_url(self.current_user_id)?.to_string())
        } else {
            Ok(self.get_coordinator_url()?.to_string())
        }
    }

    pub async fn get_checkpoint_global_state_roots(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots<F>> {
        info!("Fetching checkpoint global state roots for checkpoint {}", checkpoint_id);
        let rpc_url = self.get_coordinator_url()?;
        let input = QCheckpointGlobalStateRootsRPCRequest { checkpoint_id };
        let request = RpcRequest {
            jsonrpc: Version::V2,
            request: RequestParams::<F>::GetCheckpointGlobalStateRoots(input),
            id: Id::Number(1),
        };
        let response_http = self.client.post(rpc_url.clone()).json(&request).send().await?;
        let status = response_http.status();
        let body = response_http.text().await?;
        let response: RpcResponse<psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots<F>> = match serde_json::from_str(&body) {
            Ok(parsed) => parsed,
            Err(err) => {
                error!(
                    url = %rpc_url,
                    checkpoint_id,
                    status = %status,
                    body_len = body.len(),
                    body = %body,
                    error = %err,
                    "[ROOTS_RPC_DECODE_FAIL] failed to decode checkpoint roots response"
                );
                return Err(anyhow::format_err!("Failed to parse JSON response: {}", err));
            }
        };
        match response.result {
            ResponseResult::Success(roots) => {
                debug!(checkpoint_id = checkpoint_id, "Successfully fetched checkpoint global state roots");
                Ok(roots)
            }
            ResponseResult::Error(e) => {
                error!(
                    url = %rpc_url,
                    checkpoint_id,
                    status = %status,
                    body_len = body.len(),
                    body = %body,
                    "RPC call failed for checkpoint roots: {:?}",
                    e
                );
                Err(anyhow::format_err!("get_checkpoint_global_state_roots rpc call failed `{:?}`", e))
            }
        }
    }

    pub async fn get_checkpoint_state_transition_proof(&self, checkpoint_id: u64) -> anyhow::Result<Vec<u8>> {
        info!("Fetching checkpoint state transition proof for checkpoint {}", checkpoint_id);
        let rpc_url = self.get_coordinator_url()?;
        let input = QCheckpointStateTransitionProofRPCRequest { checkpoint_id };
        let response = psy_rpc_call_back!(self, rpc_url, RequestParams::<F>::GetCheckpointStateTransitionProof(input), Vec<u8>);
        match response.result {
            ResponseResult::Success(proof_bytes) => {
                debug!(
                    checkpoint_id = checkpoint_id,
                    proof_len = proof_bytes.len(),
                    "Successfully fetched checkpoint state transition proof"
                );
                Ok(proof_bytes)
            }
            ResponseResult::Error(e) => {
                error!("RPC call failed: {:?}", e);
                Err(anyhow::format_err!("get_checkpoint_state_transition_proof rpc call failed `{:?}`", e))
            }
        }
    }
}
