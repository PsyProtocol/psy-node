use anyhow::Result;
use criterion::Criterion;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::{
        db::row::{
            QDatabaseDoubleIdTableRow, QDatabaseDoubleIdTableRowNoCheckpointId, QDatabaseKeyIdValueTableRow, QDatabaseSingleIdTableRow, QDoubleIdKey,
        },
        hash::hash256::Hash256,
        serializable::{QPDPair, QPDPairWithCheckpointId},
    },
    protocol::core_types::QHashBase,
};
use parth_node_v1::store::scylla::{
    core::ScyllaCoreStore,
    tables::object::{
        ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements,
        ScyllaGenericObjectSingleIdTablePreparedStatements,
    },
};
use parth_crypto::hash::sha256::CoreSha256Hasher;

use rand::{seq::SliceRandom, thread_rng, RngCore};
use serde::{Deserialize, Serialize};

const GOLDILOCKS_PRIME: u64 = 18446744069414584321;
const MAX_CHECKPOINT_ID: u64 = (i64::MAX - 1) as u64;

const NEVER_EXIST_CONTRACT_IDS_COUNT: u64 = 0xfffffff;
const START_NEVER_EXIST_CONTRACT_IDS: u64 = GOLDILOCKS_PRIME - NEVER_EXIST_CONTRACT_IDS_COUNT - 2;

fn rand_non_existent_contract_id() -> u64 {
    1 + START_NEVER_EXIST_CONTRACT_IDS + (rand::random::<u64>() % NEVER_EXIST_CONTRACT_IDS_COUNT)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct ExDepositInfo {
    pub from_chain: u32,
    pub amount: u64,
    pub recipient_user_id: u64,
    pub deposit_counter: u64,
    pub event_hash: Hash256,
    pub event_stack_hash: Hash256,
}

impl ExDepositInfo {
    pub fn new(from_chain: u32, amount: u64, recipient_user_id: u64, deposit_counter: u64, event_hash: Hash256, event_stack_hash: Hash256) -> Self {
        Self {
            from_chain,
            amount,
            recipient_user_id,
            deposit_counter,
            event_hash,
            event_stack_hash,
        }
    }
    pub fn new_random() -> Self {
        Self {
            from_chain: rand::random::<u32>() % 10,
            amount: rand::random::<u64>() % 1_000_000_000,
            recipient_user_id: rand::random::<u64>() % (GOLDILOCKS_PRIME - 0xffffff),
            deposit_counter: rand::random::<u64>() % 1_000_000,
            event_hash: Hash256::rand(),
            event_stack_hash: Hash256::rand(),
        }
    }
    pub fn to_db_row(&self, deposit_id: u64) -> QPDPair<u64, Self> {
        QPDPair {
            key: deposit_id,
            value: self.clone(),
        }
    }
    pub fn to_db_row_with_random_id(&self) -> QPDPair<u64, Self> {
        let deposit_id = rand::random::<u64>() % (GOLDILOCKS_PRIME - 0xffffff);
        QPDPair {
            key: deposit_id,
            value: self.clone(),
        }
    }
    pub fn new_random_row() -> QPDPair<u64, Self> {
        let deposit_id = rand::random::<u64>() % (GOLDILOCKS_PRIME - 0xffffff);
        let value = Self::new_random();
        QPDPair { key: deposit_id, value }
    }
    pub fn new_random_row_with_deposit_id(deposit_id: u64) -> QPDPair<u64, Self> {
        let value = Self::new_random();
        QPDPair { key: deposit_id, value }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct ExContractInfo {
    pub deployed_checkpoint_id: u64,
    pub contract_function_tree_root: Hash256,
    pub number_of_functions: u32,
    pub deployed_by_user_id: u64,
    pub upgrade_key: Hash256,
    pub function_leaves: Vec<Hash256>,
}

impl ExContractInfo {
    pub fn new(
        deployed_checkpoint_id: u64,
        contract_function_tree_root: Hash256,
        number_of_functions: u32,
        deployed_by_user_id: u64,
        upgrade_key: Hash256,
        function_leaves: Vec<Hash256>,
    ) -> Self {
        Self {
            deployed_checkpoint_id,
            contract_function_tree_root,
            number_of_functions,
            deployed_by_user_id,
            upgrade_key,
            function_leaves,
        }
    }
    pub fn new_random_with_deployed_checkpoint_id(deployed_checkpoint_id: u64) -> Self {
        let number_of_functions = (rand::random::<u32>() % 50);
        Self {
            deployed_checkpoint_id,
            contract_function_tree_root: Hash256::rand(),
            number_of_functions,
            deployed_by_user_id: rand::random::<u64>(),
            upgrade_key: Hash256::rand(),
            function_leaves: (0..number_of_functions).map(|_| Hash256::rand()).collect(),
        }
    }
    pub fn new_random() -> Self {
        Self::new_random_with_deployed_checkpoint_id(rand::random::<u64>() % MAX_CHECKPOINT_ID)
    }
    pub fn new_random_row() -> QPDPair<u64, Self> {
        // we don't do golidlocks all on because we reserve some ids that should be
        // empty for testing
        let key = rand::random::<u64>() % (GOLDILOCKS_PRIME - 0xffffff);
        let value = Self::new_random();
        QPDPair { key, value }
    }
    pub fn to_db_row(&self, contract_id: u64) -> QPDPair<u64, Self> {
        QPDPair {
            key: contract_id,
            value: self.clone(),
        }
    }
}

const RANDOM_TYPES: [&str; 6] = ["Felt", "Hash", "u32", "u256", "u16", "u8"];
const RANDOM_ARG_NAMES: [&str; 17] = [
    "user",
    "token",
    "user_id",
    "token_id",
    "amount",
    "sender",
    "receiver",
    "data",
    "metadata",
    "value",
    "contract",
    "contract_id",
    "to",
    "from",
    "counter",
    "vote",
    "nonce",
];
const RANDOM_FUNCTION_NAMES: [&str; 30] = [
    "bridge",
    "transfer",
    "approve",
    "mint",
    "burn",
    "set_approval_for_all",
    "safe_transfer_from",
    "get_balance",
    "get_owner",
    "deploy_contract",
    "upgrade_contract",
    "call_function",
    "get_nonce",
    "set_metadata",
    "vote",
    "stake",
    "unstake",
    "claim_rewards",
    "register_user",
    "deregister_user",
    "update_profile",
    "commit",
    "save",
    "unlock",
    "vest",
    "withdraw",
    "swap",
    "add_liquidity",
    "remove_liquidity",
    "flash_loan",
];
const RANDOM_FUNCTION_SUFFIXES: [&str; 20] = [
    "",
    "_with_authorization",
    "_internal",
    "_ext",
    "_raw",
    "_checked",
    "_unchecked",
    "_safe",
    "_unsafe",
    "_fast",
    "_slow",
    "_optimized",
    "_debug",
    "_test",
    "_prod",
    "_main",
    "_core",
    "_base",
    "_combo",
    "_batch",
];

fn generate_random_arg() -> String {
    let arg_type = *RANDOM_TYPES.choose(&mut rand::thread_rng()).unwrap();
    let arg_name = *RANDOM_ARG_NAMES.choose(&mut rand::thread_rng()).unwrap();
    format!("{}: {}", arg_name, arg_type)
}
fn generate_random_args(count: usize) -> Vec<String> {
    let mut args = Vec::new();
    for _ in 0..count {
        args.push(generate_random_arg());
    }
    args
}
fn generate_random_function_name() -> String {
    let base_name = *RANDOM_FUNCTION_NAMES.choose(&mut rand::thread_rng()).unwrap();
    let suffix = *RANDOM_FUNCTION_SUFFIXES.choose(&mut rand::thread_rng()).unwrap();
    let random_version = rand::random::<u32>() % 1000;
    format!("{}{}_v{}", base_name, suffix, random_version)
}

fn generate_random_code() -> Vec<u8> {
    let code_length = 300 + (rand::random::<usize>() % 2000);
    let mut random_bytes: Vec<u8> = vec![0; code_length];
    let mut rng = thread_rng();
    rng.fill_bytes(&mut random_bytes);
    random_bytes
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct ExContractFunctionInfo {
    pub verifier_data_hash: Hash256,
    pub name: String,
    pub args: Vec<String>,
    pub code: Vec<u8>,
}

impl ExContractFunctionInfo {
    pub fn new(verifier_data_hash: Hash256, name: String, args: Vec<String>, code: Vec<u8>) -> Self {
        Self {
            verifier_data_hash,
            name,
            args,
            code,
        }
    }
    pub fn new_random() -> Self {
        let arg_count = rand::random::<usize>() % 6;
        Self {
            verifier_data_hash: Hash256::rand(),
            name: generate_random_function_name(),
            args: generate_random_args(arg_count),
            code: generate_random_code(),
        }
    }
    pub fn new_random_row_with_contract_id(contract_id: u64) -> QDatabaseDoubleIdTableRowNoCheckpointId<Self> {
        // we don't do golidlocks all on because we reserve some ids that should be
        // empty for testing
        let function_id = rand::random::<u64>() % START_NEVER_EXIST_CONTRACT_IDS;
        let value = Self::new_random();
        QDatabaseDoubleIdTableRowNoCheckpointId {
            obj_id: contract_id,
            secondary_id: function_id,
            value,
        }
    }
    pub fn new_random_row_with_contract_id_qpd(contract_id: u64) -> QPDPair<QDoubleIdKey, Self> {
        // we don't do golidlocks all on because we reserve some ids that should be
        // empty for testing
        let function_id = rand::random::<u64>() % START_NEVER_EXIST_CONTRACT_IDS;
        let value = Self::new_random();
        QPDPair {
            key: QDoubleIdKey {
                obj_id: contract_id,
                secondary_id: function_id,
            },
            value,
        }
    }

    pub fn new_random_row() -> QDatabaseDoubleIdTableRowNoCheckpointId<Self> {
        let contract_id = rand::random::<u64>() % START_NEVER_EXIST_CONTRACT_IDS;
        Self::new_random_row_with_contract_id(contract_id)
    }
    pub fn new_random_row_qpd() -> QPDPair<QDoubleIdKey, Self> {
        let contract_id = rand::random::<u64>() % START_NEVER_EXIST_CONTRACT_IDS;
        Self::new_random_row_with_contract_id_qpd(contract_id)
    }
    pub fn new_with_random_verifier_data_hash(&self) -> Self {
        let mut new_cfi = self.clone();
        new_cfi.verifier_data_hash = Hash256::rand();
        new_cfi
    }
    pub fn to_db_row(&self, contract_id: u64, function_id: u64) -> QDatabaseDoubleIdTableRowNoCheckpointId<Self> {
        QDatabaseDoubleIdTableRowNoCheckpointId {
            obj_id: contract_id,
            secondary_id: function_id,
            value: self.clone(),
        }
    }
    pub fn to_db_row_qpd(&self, contract_id: u64, function_id: u64) -> QPDPair<QDoubleIdKey, Self> {
        QPDPair {
            key: QDoubleIdKey {
                obj_id: contract_id,
                secondary_id: function_id,
            },
            value: self.clone(),
        }
    }
}

struct ExDatabaseTables {
    pub contract_function_info_table: ScyllaGenericObjectDoubleIdTablePreparedStatements,
    pub contract_info_table: ScyllaGenericObjectSingleIdTablePreparedStatements,
    pub deposit_info_table: ScyllaGenericKeyIdValueTablePreparedStatements,
}
impl ExDatabaseTables {
    pub const CONTRACT_FUNCTION_INFO_TABLE_NAME: &'static str = "ex_contract_function_info";
    pub const CONTRACT_INFO_TABLE_NAME: &'static str = "ex_contract_info";
    pub const DEPOSIT_INFO_TABLE_NAME: &'static str = "ex_deposit_info";

    pub fn new(
        contract_function_info_table: ScyllaGenericObjectDoubleIdTablePreparedStatements,
        contract_info_table: ScyllaGenericObjectSingleIdTablePreparedStatements,
        deposit_info_table: ScyllaGenericKeyIdValueTablePreparedStatements,
    ) -> Self {
        Self {
            contract_function_info_table,
            contract_info_table,
            deposit_info_table,
        }
    }
}

struct ExDatabaseManager<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>> {
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub keyspace: String,
    pub scylla_helper: ScyllaCoreStore<Hash, Hasher>,
    pub tables: ExDatabaseTables,
}

impl<Hash: QHashBase, Hasher: MerkleZeroHasher<Hash>> ExDatabaseManager<Hash, Hasher> {
    pub async fn new(realm_id: u64, realm_sub_id: u64, keyspace: String, scylla_nodes: &[String]) -> Result<Self> {
        let scylla_helper = ScyllaCoreStore::<Hash, Hasher>::new(realm_id, realm_sub_id, keyspace.clone(), scylla_nodes).await?;

        let contract_function_info_table = scylla_helper
            .init_double_id_checkpointed(ExDatabaseTables::CONTRACT_FUNCTION_INFO_TABLE_NAME)
            .await?;

        let contract_info_table = scylla_helper
            .init_single_id_checkpointed(ExDatabaseTables::CONTRACT_INFO_TABLE_NAME)
            .await?;

        let deposit_info_table = scylla_helper.init_key_id_value(ExDatabaseTables::DEPOSIT_INFO_TABLE_NAME).await?;

        Ok(Self {
            realm_id,
            realm_sub_id,
            keyspace,
            scylla_helper,
            tables: ExDatabaseTables::new(contract_function_info_table, contract_info_table, deposit_info_table),
        })
    }
    pub async fn set_deposit_info(&self, deposit_id: u64, info: &ExDepositInfo) -> anyhow::Result<()> {
        self.scylla_helper
            .insert_one_kiv(&self.tables.deposit_info_table, deposit_id, info)
            .await?;
        Ok(())
    }
    pub async fn get_deposit_info(&self, deposit_id: u64) -> anyhow::Result<Option<ExDepositInfo>> {
        let res = self
            .scylla_helper
            .select_one_kiv_value::<ExDepositInfo>(&self.tables.deposit_info_table, deposit_id)
            .await?;
        Ok(res)
    }
    pub async fn get_deposit_info_with_id(&self, deposit_id: u64) -> anyhow::Result<Option<QDatabaseKeyIdValueTableRow<ExDepositInfo>>> {
        let res = self
            .scylla_helper
            .select_one_kiv_value_and_ids::<ExDepositInfo>(&self.tables.deposit_info_table, deposit_id)
            .await?;
        Ok(res)
    }
    pub async fn get_deposit_infos(&self, deposit_ids: &[u64]) -> anyhow::Result<Vec<Option<ExDepositInfo>>> {
        let res = self
            .scylla_helper
            .select_many_kiv_values::<ExDepositInfo>(&self.tables.deposit_info_table, deposit_ids)
            .await?;
        Ok(res)
    }
    pub async fn get_deposit_infos_with_ids(&self, deposit_ids: &[u64]) -> anyhow::Result<Vec<QDatabaseKeyIdValueTableRow<ExDepositInfo>>> {
        let res = self
            .scylla_helper
            .select_many_kiv_keys_and_values::<ExDepositInfo, _>(&self.tables.deposit_info_table, deposit_ids)
            .await?;
        Ok(res)
    }
    pub async fn set_many_deposit_infos(&self, infos: &[QPDPair<u64, ExDepositInfo>]) -> anyhow::Result<()> {
        self.scylla_helper.insert_many_kivs_t(&self.tables.deposit_info_table, infos).await?;
        Ok(())
    }
    pub async fn set_contract_function_info(
        &self,
        contract_id: u64,
        function_id: u64,
        checkpoint_id: u64,
        leaf: &ExContractFunctionInfo,
    ) -> anyhow::Result<()> {
        self.scylla_helper
            .insert_one_double_checkpointed_object(&self.tables.contract_function_info_table, contract_id, function_id, checkpoint_id, leaf)
            .await?;
        Ok(())
    }
    pub async fn set_many_contract_function_infos(
        &self,
        checkpoint_id: u64,
        leaves: &[QPDPair<QDoubleIdKey, ExContractFunctionInfo>],
    ) -> anyhow::Result<()> {
        self.scylla_helper
            .insert_many_double_checkpointed_objects_at_checkpoint_t(&self.tables.contract_function_info_table, checkpoint_id, leaves)
            .await?;
        Ok(())
    }
    pub async fn get_contract_function_info(
        &self,
        contract_id: u64,
        function_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<ExContractFunctionInfo>> {
        let res = self
            .scylla_helper
            .select_one_double_checkpointed_object_value::<ExContractFunctionInfo>(
                &self.tables.contract_function_info_table,
                contract_id,
                function_id,
                max_checkpoint_id,
            )
            .await?;
        Ok(res)
    }
    pub async fn get_contract_function_info_with_ids(
        &self,
        contract_id: u64,
        function_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseDoubleIdTableRow<ExContractFunctionInfo>>> {
        let res = self
            .scylla_helper
            .select_one_double_checkpointed_object_value_and_ids::<ExContractFunctionInfo>(
                &self.tables.contract_function_info_table,
                contract_id,
                function_id,
                max_checkpoint_id,
            )
            .await?;
        Ok(res)
    }
    pub async fn get_contract_function_info_latest(&self, contract_id: u64, function_id: u64) -> anyhow::Result<Option<ExContractFunctionInfo>> {
        let res = self
            .scylla_helper
            .select_one_double_checkpointed_object_value::<ExContractFunctionInfo>(
                &self.tables.contract_function_info_table,
                contract_id,
                function_id,
                MAX_CHECKPOINT_ID,
            )
            .await?;
        Ok(res)
    }
    pub async fn get_contract_function_infos(
        &self,
        contract_function_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<Option<ExContractFunctionInfo>>> {
        let res = self
            .scylla_helper
            .select_many_double_checkpointed_object_values::<ExContractFunctionInfo>(
                &self.tables.contract_function_info_table,
                contract_function_ids,
                max_checkpoint_id,
            )
            .await?;
        Ok(res)
    }
    pub async fn get_contract_function_infos_with_ids(
        &self,
        contract_function_ids: &[QDoubleIdKey],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<QDatabaseDoubleIdTableRow<ExContractFunctionInfo>>> {
        let res = self
            .scylla_helper
            .select_many_double_checkpointed_object_keys_and_values::<ExContractFunctionInfo, _>(
                &self.tables.contract_function_info_table,
                contract_function_ids,
                max_checkpoint_id,
            )
            .await?;
        Ok(res)
    }
    pub async fn set_contract_info(&self, contract_id: u64, checkpoint_id: u64, leaf: &ExContractInfo) -> anyhow::Result<()> {
        self.scylla_helper
            .insert_one_single_checkpointed_object(&self.tables.contract_info_table, contract_id, checkpoint_id, leaf)
            .await?;
        Ok(())
    }
    pub async fn set_many_contract_infos(&self, checkpoint_id: u64, leaves: &[QPDPair<u64, ExContractInfo>]) -> anyhow::Result<()> {
        self.scylla_helper
            .insert_many_single_checkpointed_objects_at_checkpoint_t(&self.tables.contract_info_table, checkpoint_id, leaves)
            .await?;
        Ok(())
    }
    pub async fn get_contract_info(&self, contract_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<ExContractInfo>> {
        let res = self
            .scylla_helper
            .select_one_single_checkpointed_object_value::<ExContractInfo>(&self.tables.contract_info_table, contract_id, max_checkpoint_id)
            .await?;
        Ok(res)
    }
    pub async fn get_contract_info_with_ids(
        &self,
        contract_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<ExContractInfo>>> {
        let res = self
            .scylla_helper
            .select_one_single_checkpointed_object_value_and_ids::<ExContractInfo>(&self.tables.contract_info_table, contract_id, max_checkpoint_id)
            .await?;
        Ok(res)
    }
    pub async fn get_contract_info_with_ids_t(
        &self,
        contract_id: u64,
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<ExContractInfo>>> {
        let res = self
            .scylla_helper
            .select_one_single_checkpointed_object_value_and_ids_t::<ExContractInfo, _>(
                &self.tables.contract_info_table,
                contract_id,
                max_checkpoint_id,
            )
            .await?;
        Ok(res)
    }
    pub async fn get_contract_info_latest(&self, contract_id: u64) -> anyhow::Result<Option<ExContractInfo>> {
        let res = self
            .scylla_helper
            .select_one_single_checkpointed_object_value::<ExContractInfo>(&self.tables.contract_info_table, contract_id, MAX_CHECKPOINT_ID)
            .await?;
        Ok(res)
    }
    pub async fn get_contract_infos(&self, contract_ids: &[u64], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<ExContractInfo>>> {
        let res = self
            .scylla_helper
            .select_many_single_checkpointed_object_values::<ExContractInfo>(&self.tables.contract_info_table, contract_ids, max_checkpoint_id)
            .await?;
        Ok(res)
    }
    pub async fn get_contract_infos_with_ids(
        &self,
        contract_ids: &[u64],
        max_checkpoint_id: u64,
    ) -> anyhow::Result<Vec<QPDPairWithCheckpointId<u64, ExContractInfo>>> {
        let res = self
            .scylla_helper
            .select_many_single_checkpointed_object_keys_and_values::<ExContractInfo, _>(
                &self.tables.contract_info_table,
                contract_ids,
                max_checkpoint_id,
            )
            .await?;
        Ok(res)
    }
    pub async fn check_insert_contract_function_simple(
        &self,
        contract_id: u64,
        function_id: u64,
        checkpoint_id: u64,
        contract_function_info: &ExContractFunctionInfo,
    ) -> anyhow::Result<()> {
        let last_contract_function_info = self
            .get_contract_function_info_with_ids(contract_id, function_id, MAX_CHECKPOINT_ID)
            .await?;

        let expected_post_write_latest_cfi = if let Some(last_cfi) = last_contract_function_info.clone() {
            if last_cfi.obj_id != contract_id || last_cfi.secondary_id != function_id {
                anyhow::bail!("Mismatched contract ID in last contract function info");
            }
            if checkpoint_id > last_cfi.checkpoint_id {
                contract_function_info.clone()
            } else {
                last_cfi.value.clone()
            }
        } else {
            contract_function_info.clone()
        };

        self.set_contract_function_info(contract_id, function_id, checkpoint_id, contract_function_info)
            .await?;
        let after_contract_function_info_latest = self.get_contract_function_info_latest(contract_id, function_id).await?.unwrap();
        assert_eq!(
            after_contract_function_info_latest, expected_post_write_latest_cfi,
            "Latest contract function info after write does not match expected"
        );

        let just_set_contract_function_info = self.get_contract_function_info(contract_id, function_id, checkpoint_id).await?.unwrap();
        assert_eq!(
            just_set_contract_function_info,
            contract_function_info.clone(),
            "Just set contract function info does not match expected"
        );

        if let Some(last_cfi) = last_contract_function_info {
            let at_last_checkpoint_contract_function_info = self
                .get_contract_function_info(contract_id, function_id, last_cfi.checkpoint_id)
                .await?
                .unwrap();
            assert_eq!(
                at_last_checkpoint_contract_function_info, last_cfi.value,
                "Contract function info at last checkpoint does not match expected"
            );
        }

        let contract_function_info_with_ids = self
            .get_contract_function_info_with_ids(contract_id, function_id, checkpoint_id)
            .await?
            .unwrap();
        assert_eq!(
            contract_function_info_with_ids.obj_id, contract_id,
            "Contract ID mismatch in fetched with IDs"
        );
        assert_eq!(
            contract_function_info_with_ids.secondary_id, function_id,
            "Function ID mismatch in fetched with IDs"
        );
        assert_eq!(
            contract_function_info_with_ids.checkpoint_id, checkpoint_id,
            "Checkpoint ID mismatch in fetched with IDs"
        );
        assert_eq!(
            contract_function_info_with_ids.value,
            contract_function_info.clone(),
            "Contract function info value mismatch in fetched with IDs"
        );

        Ok(())
    }

    pub async fn check_insert_contract_info_simple(&self, contract_id: u64, checkpoint_id: u64, info: &ExContractInfo) -> anyhow::Result<()> {
        let last_contract_info = self.get_contract_info_with_ids(contract_id, MAX_CHECKPOINT_ID).await?;

        let expected_post_write_latest_contract = if let Some(last_info) = last_contract_info.clone() {
            if last_info.obj_id != contract_id {
                anyhow::bail!("Mismatched contract ID in last info");
            }
            if checkpoint_id > last_info.checkpoint_id {
                info.clone()
            } else {
                last_info.value.clone()
            }
        } else {
            info.clone()
        };

        self.set_contract_info(contract_id, checkpoint_id, info).await?;
        let after_contract_latest = self.get_contract_info_latest(contract_id).await?.unwrap();
        assert_eq!(
            after_contract_latest, expected_post_write_latest_contract,
            "Latest contract info after write does not match expected"
        );

        let just_set_contract = self.get_contract_info(contract_id, checkpoint_id).await?.unwrap();
        assert_eq!(just_set_contract, *info, "Just set contract info does not match expected");

        if let Some(last_info) = last_contract_info {
            let at_last_checkpoint_contract = self.get_contract_info(contract_id, last_info.checkpoint_id).await?.unwrap();
            assert_eq!(
                at_last_checkpoint_contract, last_info.value,
                "User info at last checkpoint does not match expected"
            );
        }

        let contract_info_with_ids = self.get_contract_info_with_ids(contract_id, checkpoint_id).await?.unwrap();
        assert_eq!(contract_info_with_ids.obj_id, contract_id, "Contract ID mismatch in fetched with IDs");
        assert_eq!(
            contract_info_with_ids.checkpoint_id, checkpoint_id,
            "Checkpoint ID mismatch in fetched with IDs"
        );
        assert_eq!(contract_info_with_ids.value, *info, "Contract info value mismatch in fetched with IDs");

        Ok(())
    }
    pub async fn check_insert_deposit_simple(&self, deposit_id: u64, info: &ExDepositInfo) -> anyhow::Result<()> {
        self.set_deposit_info(deposit_id, info).await?;
        let fetched_deposit = self.get_deposit_info(deposit_id).await?.unwrap();
        assert_eq!(fetched_deposit, *info, "Fetched deposit info does not match set info");
        let fetched_deposit_with_id = self.get_deposit_info_with_id(deposit_id).await?.unwrap();
        assert_eq!(fetched_deposit_with_id.obj_id, deposit_id, "Fetched deposit ID does not match set ID");
        assert_eq!(
            fetched_deposit_with_id.value, *info,
            "Fetched deposit info with ID does not match set info"
        );
        let multi_fetched = self
            .get_deposit_infos(&[rand::random::<u64>(), deposit_id, rand::random::<u64>()])
            .await?;
        assert_eq!(
            multi_fetched[1].as_ref().unwrap(),
            info,
            "Multi fetched deposit info does not match set info"
        );
        let multi_fetched_with_ids = self
            .get_deposit_infos_with_ids(&[rand::random::<u64>(), deposit_id, rand::random::<u64>()])
            .await?;
        assert_eq!(
            multi_fetched_with_ids.iter().find(|x| x.obj_id == deposit_id).unwrap().value,
            *info,
            "Multi fetched with IDs deposit info does not match set info"
        );
        Ok(())
    }
}

fn bench_object_ops(c: &mut Criterion) {
    let realm_id = 1;
    let realm_sub_id = 1;
    let keyspace_prefix = format!("bench_object_ops_v1_{}_{}", realm_id, realm_sub_id);

    let rt = tokio::runtime::Runtime::new().unwrap();

    let store = rt
        .block_on(ExDatabaseManager::<Hash256, CoreSha256Hasher>::new(
            realm_id,
            realm_sub_id,
            keyspace_prefix,
            &["127.0.0.1:9042".to_string()],
        ))
        .unwrap();
    let deposit_infos: Vec<_> = (0..10000).map(|i| ExDepositInfo::new_random_row_with_deposit_id(i)).collect();
    let deposit_info_keys: Vec<_> = deposit_infos.iter().map(|info| info.key).collect();

    let contract_infos: Vec<_> = (0..10000).map(|i| ExContractInfo::new_random().to_db_row(i)).collect();
    let contract_info_keys: Vec<_> = contract_infos.iter().map(|info| info.key).collect();
    let contract_function_infos: Vec<_> = (0..10000)
        .map(|i| ExContractFunctionInfo::new_random().to_db_row_qpd(i / 32, i % 32))
        .collect();
    let contract_function_info_keys: Vec<_> = contract_function_infos.iter().map(|info| info.key).collect();

    let mut group = c.benchmark_group("object_ops_large");
    group.bench_function("set_10000_kiv_keys", |b| {
        b.iter(|| {
            rt.block_on(store.set_many_deposit_infos(&deposit_infos)).unwrap();
        });
    });

    group.bench_function("get_10000_kiv_keys", |b| {
        b.iter(|| {
            let _all = rt.block_on(store.get_deposit_infos(&deposit_info_keys)).unwrap();
        });
    });
    group.bench_function("set_10000_single_id_objects", |b| {
        b.iter(|| {
            rt.block_on(store.set_many_contract_infos(1337, &contract_infos)).unwrap();
        });
    });

    group.bench_function("get_10000_single_id_objects", |b| {
        b.iter(|| {
            let _all = rt.block_on(store.get_contract_infos(&contract_info_keys, 2000)).unwrap();
        });
    });
    group.bench_function("set_10000_double_id_objects", |b| {
        b.iter(|| {
            rt.block_on(store.set_many_contract_function_infos(6969, &contract_function_infos))
                .unwrap();
        });
    });

    group.bench_function("get_10000_double_id_objects", |b| {
        b.iter(|| {
            let _all = rt
                .block_on(store.get_contract_function_infos(&contract_function_info_keys, 8000))
                .unwrap();
        });
    });
}

criterion::criterion_group!(benches, bench_object_ops);
criterion::criterion_main!(benches);
