use anyhow::Result;
use parth_core::{crypto::hash::{sha256::CoreSha256Hasher, traits::MerkleZeroHasher}, data::{db::{self, row::QDatabaseSingleIdTableRow}, hash::{hash256::Hash256, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}, serializable::{QPDPair, QPDPairWithCheckpointId}}, protocol::core_types::QHashBase};
use parth_node_v1::store::scylla::{core::ScyllaCoreStore, tables::object::ScyllaGenericObjectSingleIdTablePreparedStatements};
use serde::{Deserialize, Serialize};
use rand::seq::SliceRandom;

const GOLDILOCKS_PRIME: u64 = 18446744069414584321;
const MAX_CHECKPOINT_ID: u64 = (i64::MAX - 1) as u64;

const NEVER_EXIST_CONTRACT_IDS_COUNT: u64 = 0xfffffff;
const START_NEVER_EXIST_CONTRACT_IDS: u64 = GOLDILOCKS_PRIME - NEVER_EXIST_CONTRACT_IDS_COUNT - 2;

fn rand_non_existent_contract_id() -> u64 {
    1 + START_NEVER_EXIST_CONTRACT_IDS + (rand::random::<u64>() % NEVER_EXIST_CONTRACT_IDS_COUNT)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Copy)]
struct ExUserLeaf {
    pub last_submitted_checkpoint_id: u64,
    pub public_key_hash: Hash256,
    pub user_state_tree_root: Hash256,
}
impl ExUserLeaf {
    pub fn new(last_submitted_checkpoint_id: u64, public_key_hash: Hash256, user_state_tree_root: Hash256) -> Self {
        Self { last_submitted_checkpoint_id, public_key_hash, user_state_tree_root }
    }
    pub fn new_random_with_last_submitted_checkpoint_id(last_submitted_checkpoint_id: u64) -> Self {
        Self {
            last_submitted_checkpoint_id,
            public_key_hash: Hash256::rand(),
            user_state_tree_root: Hash256::rand(),
        }
    }
    pub fn new_random() -> Self {
        Self::new_random_with_last_submitted_checkpoint_id(rand::random::<u64>()%MAX_CHECKPOINT_ID)
    }
    pub fn updated_with_new_rand_root(&self, new_checkpoint_id: u64) -> Self {
        Self {
            last_submitted_checkpoint_id: new_checkpoint_id,
            public_key_hash: self.public_key_hash,
            user_state_tree_root: Hash256::rand(),
        }
    }
    pub fn new_random_row() -> QPDPair<u64, ExUserLeaf> {
        let user_id = rand::random::<u64>() % GOLDILOCKS_PRIME;
        let leaf = ExUserLeaf::new_random();
        QPDPair {
            key: user_id,
            value: leaf,
        }
    }
    pub fn to_db_row(&self, user_id: u64) -> QPDPair<u64, ExUserLeaf> {
        QPDPair {
            key: user_id,
            value: self.clone()
        }
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
    pub fn new(deployed_checkpoint_id: u64, contract_function_tree_root: Hash256, number_of_functions: u32, deployed_by_user_id: u64, upgrade_key: Hash256, function_leaves: Vec<Hash256>) -> Self {
        Self { deployed_checkpoint_id, contract_function_tree_root, number_of_functions, deployed_by_user_id, upgrade_key, function_leaves }
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
        Self::new_random_with_deployed_checkpoint_id(rand::random::<u64>()%MAX_CHECKPOINT_ID)
    }
    pub fn new_random_row() -> QPDPair<u64, Self> {
        // we don't do golidlocks all on because we reserve some ids that should be empty for testing
        let key = rand::random::<u64>() % (GOLDILOCKS_PRIME - 0xffffff);
        let value = Self::new_random();
        QPDPair {
            key,
            value,
        }
    }
    pub fn to_db_row(&self, contract_id: u64) -> QPDPair<u64, Self> {
        QPDPair {
            key: contract_id,
            value: self.clone()
        }
    }
}


struct ExDatabaseTables {
    pub user_leaf_table: ScyllaGenericObjectSingleIdTablePreparedStatements,
    pub contract_info_table: ScyllaGenericObjectSingleIdTablePreparedStatements,
}
impl ExDatabaseTables {
    pub const USER_LEAF_TABLE_NAME: &'static str = "ex_user_leaf";
    pub const CONTRACT_INFO_TABLE_NAME: &'static str = "ex_contract_info";
    pub fn new(user_leaf_table: ScyllaGenericObjectSingleIdTablePreparedStatements, contract_info_table: ScyllaGenericObjectSingleIdTablePreparedStatements) -> Self {
        Self { user_leaf_table, contract_info_table }
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
                
        let user_leaf_table = scylla_helper.init_single_id_checkpointed(ExDatabaseTables::USER_LEAF_TABLE_NAME).await?;
        let contract_info_table = scylla_helper.init_single_id_checkpointed(ExDatabaseTables::CONTRACT_INFO_TABLE_NAME).await?;

        Ok(Self {
            realm_id,
            realm_sub_id,
            keyspace,
            scylla_helper,
            tables: ExDatabaseTables::new(user_leaf_table, contract_info_table),
        })
    }
    pub async fn set_user_leaf(&self, user_id: u64, checkpoint_id: u64, leaf: &ExUserLeaf) -> anyhow::Result<()> {
        self.scylla_helper.insert_one_single_checkpointed_object(
            &self.tables.user_leaf_table,
            user_id,
            checkpoint_id,
            leaf
        ).await?;
        Ok(())
    }
    pub async fn set_many_user_leaves(&self, checkpoint_id: u64, leaves: &[QPDPair<u64, ExUserLeaf>]) -> anyhow::Result<()> {
        self.scylla_helper.insert_many_single_checkpointed_objects_at_checkpoint_t(
            &self.tables.user_leaf_table,
            checkpoint_id,
            leaves
        ).await?;
        Ok(())
    }
    pub async fn get_user_leaf(&self, user_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<ExUserLeaf>> {
        let res = self.scylla_helper.select_one_single_checkpointed_object_value::<ExUserLeaf>(
            &self.tables.user_leaf_table,
            user_id,
            max_checkpoint_id
        ).await?;
        Ok(res)
    }
    pub async fn get_user_leaf_with_ids(&self, user_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<ExUserLeaf>>> {
        let res = self.scylla_helper.select_one_single_checkpointed_object_value_and_ids::<ExUserLeaf>(
            &self.tables.user_leaf_table,
            user_id,
            max_checkpoint_id
        ).await?;
        Ok(res)
    }
    pub async fn get_user_leaf_latest(&self, user_id: u64) -> anyhow::Result<Option<ExUserLeaf>> {
        let res = self.scylla_helper.select_one_single_checkpointed_object_value::<ExUserLeaf>(
            &self.tables.user_leaf_table,
            user_id,
            MAX_CHECKPOINT_ID,
        ).await?;
        Ok(res)
    }
    pub async fn get_user_leaves(&self, user_ids: &[u64], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<ExUserLeaf>>> {
        let res = self.scylla_helper.select_many_single_checkpointed_object_values::<ExUserLeaf>(
            &self.tables.user_leaf_table,
            user_ids,
            max_checkpoint_id
        ).await?;
        Ok(res)
    }
    pub async fn get_user_leaves_with_ids(&self, user_ids: &[u64], max_checkpoint_id: u64) -> anyhow::Result<Vec<QDatabaseSingleIdTableRow<ExUserLeaf>>> {
        let res = self.scylla_helper.select_many_single_checkpointed_object_keys_and_values::<ExUserLeaf, _>(
            &self.tables.user_leaf_table,
            user_ids,
            max_checkpoint_id
        ).await?;
        Ok(res)
    }

    pub async fn set_contract_info(&self, contract_id: u64, checkpoint_id: u64, leaf: &ExContractInfo) -> anyhow::Result<()> {
        self.scylla_helper.insert_one_single_checkpointed_object(
            &self.tables.contract_info_table,
            contract_id,
            checkpoint_id,
            leaf
        ).await?;
        Ok(())
    }
    pub async fn set_many_contract_leaves(&self, checkpoint_id: u64, leaves: &[QPDPair<u64, ExContractInfo>]) -> anyhow::Result<()> {
        self.scylla_helper.insert_many_single_checkpointed_objects_at_checkpoint_t(
            &self.tables.contract_info_table,
            checkpoint_id,
            leaves
        ).await?;
        Ok(())
    }
    pub async fn get_contract_info(&self, contract_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<ExContractInfo>> {
        let res = self.scylla_helper.select_one_single_checkpointed_object_value::<ExContractInfo>(
            &self.tables.contract_info_table,
            contract_id,
            max_checkpoint_id
        ).await?;
        Ok(res)
    }
    pub async fn get_contract_info_with_ids(&self, contract_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<ExContractInfo>>> {
        let res = self.scylla_helper.select_one_single_checkpointed_object_value_and_ids::<ExContractInfo>(
            &self.tables.contract_info_table,
            contract_id,
            max_checkpoint_id
        ).await?;
        Ok(res)
    }
    pub async fn get_contract_info_with_ids_t(&self, contract_id: u64, max_checkpoint_id: u64) -> anyhow::Result<Option<QDatabaseSingleIdTableRow<ExContractInfo>>> {
        let res = self.scylla_helper.select_one_single_checkpointed_object_value_and_ids_t::<ExContractInfo, _>(
            &self.tables.contract_info_table,
            contract_id,
            max_checkpoint_id
        ).await?;
        Ok(res)
    }
    pub async fn get_contract_info_latest(&self, contract_id: u64) -> anyhow::Result<Option<ExContractInfo>> {
        let res = self.scylla_helper.select_one_single_checkpointed_object_value::<ExContractInfo>(
            &self.tables.contract_info_table,
            contract_id,
            MAX_CHECKPOINT_ID,
        ).await?;
        Ok(res)
    }
    pub async fn get_contract_infos(&self, contract_ids: &[u64], max_checkpoint_id: u64) -> anyhow::Result<Vec<Option<ExContractInfo>>> {
        let res = self.scylla_helper.select_many_single_checkpointed_object_values::<ExContractInfo>(
            &self.tables.contract_info_table,
            contract_ids,
            max_checkpoint_id
        ).await?;
        Ok(res)
    }
    pub async fn get_contract_infos_with_ids(&self, contract_ids: &[u64], max_checkpoint_id: u64) -> anyhow::Result<Vec<QPDPairWithCheckpointId<u64, ExContractInfo>>> {
        let res = self.scylla_helper.select_many_single_checkpointed_object_keys_and_values::<ExContractInfo, _>(
            &self.tables.contract_info_table,
            contract_ids,
            max_checkpoint_id
        ).await?;
        Ok(res)
    }
    pub async fn check_insert_user_leaf_simple(&self, user_id: u64, checkpoint_id: u64, leaf: &ExUserLeaf) -> anyhow::Result<()> {
        let last_user_leaf = self.get_user_leaf_with_ids(user_id, MAX_CHECKPOINT_ID).await?;

        let expected_post_write_latest_user = if let Some(last_leaf) = last_user_leaf.clone() {
            if last_leaf.obj_id != user_id {
                anyhow::bail!("Mismatched user ID in last leaf");
            }
            if checkpoint_id > last_leaf.checkpoint_id {
                *leaf
            } else {
                last_leaf.value.clone()
            }
        } else {
            *leaf
        };

        self.set_user_leaf(user_id, checkpoint_id, leaf).await?;
        let after_user_latest = self.get_user_leaf_latest(user_id).await?.unwrap();
        assert_eq!(after_user_latest, expected_post_write_latest_user, "Latest user leaf after write does not match expected");

        let just_set_user = self.get_user_leaf(user_id, checkpoint_id).await?.unwrap();
        assert_eq!(just_set_user, *leaf, "Just set user leaf does not match expected");

        if let Some(last_leaf) = last_user_leaf {
            let at_last_checkpoint_user = self.get_user_leaf(user_id, last_leaf.checkpoint_id).await?.unwrap();
            assert_eq!(at_last_checkpoint_user, last_leaf.value, "User leaf at last checkpoint does not match expected");
        }

        let user_leaf_with_ids = self.get_user_leaf_with_ids(user_id, checkpoint_id).await?.unwrap();
        assert_eq!(user_leaf_with_ids.obj_id, user_id, "User ID mismatch in fetched with IDs");
        assert_eq!(user_leaf_with_ids.checkpoint_id, checkpoint_id, "Checkpoint ID mismatch in fetched with IDs");
        assert_eq!(user_leaf_with_ids.value, *leaf, "User leaf value mismatch in fetched with IDs");

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
        assert_eq!(after_contract_latest, expected_post_write_latest_contract, "Latest contract info after write does not match expected");

        let just_set_contract = self.get_contract_info(contract_id, checkpoint_id).await?.unwrap();
        assert_eq!(just_set_contract, *info, "Just set contract info does not match expected");

        if let Some(last_info) = last_contract_info {
            let at_last_checkpoint_contract = self.get_contract_info(contract_id, last_info.checkpoint_id).await?.unwrap();
            assert_eq!(at_last_checkpoint_contract, last_info.value, "User info at last checkpoint does not match expected");
        }

        let contract_info_with_ids = self.get_contract_info_with_ids(contract_id, checkpoint_id).await?.unwrap();
        assert_eq!(contract_info_with_ids.obj_id, contract_id, "Contract ID mismatch in fetched with IDs");
        assert_eq!(contract_info_with_ids.checkpoint_id, checkpoint_id, "Checkpoint ID mismatch in fetched with IDs");
        assert_eq!(contract_info_with_ids.value, *info, "Contract info value mismatch in fetched with IDs");

        Ok(())
    }
}
#[tokio::test]
async fn test_set_get_correctness() -> Result<()> {
    let realm_id = 1;
    let realm_sub_id = 1;
    let rand_keyspace_part = rand::random::<u64>();
    let keyspace_prefix = format!("test_single_store_ex1_{}_{}_{}", realm_id, realm_sub_id, rand_keyspace_part);

    let db_manager = ExDatabaseManager::<Hash256, CoreSha256Hasher>::new(realm_id, realm_sub_id, keyspace_prefix, &["127.0.0.1:9042".to_string()]).await?;


    let first_user_id = 1337u64;
    let ex_1 = ExUserLeaf::new_random_with_last_submitted_checkpoint_id(10);
    let ex_2 = ex_1.updated_with_new_rand_root(11);
    let ex_3 = ex_2.updated_with_new_rand_root(20);
    let ex_4 = ex_2.updated_with_new_rand_root(30);
    let ex_5 = ex_2.updated_with_new_rand_root(31);


    db_manager.check_insert_user_leaf_simple(first_user_id, ex_1.last_submitted_checkpoint_id, &ex_1).await?;
    db_manager.check_insert_user_leaf_simple(first_user_id, ex_2.last_submitted_checkpoint_id, &ex_2).await?;
    
    db_manager.check_insert_user_leaf_simple(first_user_id, ex_3.last_submitted_checkpoint_id, &ex_3).await?;
    assert_eq!(ex_3, db_manager.get_user_leaf(first_user_id, 25).await?.unwrap());
    assert_eq!(ex_3, db_manager.get_user_leaf(first_user_id, 30).await?.unwrap());
    assert_eq!(ex_3, db_manager.get_user_leaf(first_user_id, 29).await?.unwrap());
    assert_eq!(ex_2, db_manager.get_user_leaf(first_user_id, 11).await?.unwrap());
    assert_eq!(ex_1, db_manager.get_user_leaf(first_user_id, 10).await?.unwrap());
    assert!(db_manager.get_user_leaf(first_user_id, 9).await?.is_none());
    assert!(db_manager.get_user_leaf(first_user_id, 0).await?.is_none());
    assert_eq!(ex_3, db_manager.get_user_leaf_latest(first_user_id).await?.unwrap());
    
    db_manager.check_insert_user_leaf_simple(first_user_id, ex_4.last_submitted_checkpoint_id, &ex_4).await?;
    assert_eq!(ex_4, db_manager.get_user_leaf(first_user_id, 30).await?.unwrap());
    assert_eq!(ex_4, db_manager.get_user_leaf_latest(first_user_id).await?.unwrap());
    assert_eq!(ex_3, db_manager.get_user_leaf(first_user_id, 29).await?.unwrap());
    assert_eq!(ex_2, db_manager.get_user_leaf(first_user_id, 11).await?.unwrap());
    assert_eq!(ex_1, db_manager.get_user_leaf(first_user_id, 10).await?.unwrap());
    
    db_manager.check_insert_user_leaf_simple(first_user_id, ex_5.last_submitted_checkpoint_id, &ex_5).await?;

    let alt_user_id = 2024u64;
    let alt_ex_1 = ExUserLeaf::new_random_with_last_submitted_checkpoint_id(15);
    let alt_ex_2 = alt_ex_1.updated_with_new_rand_root(11);
    let alt_ex_3 = alt_ex_2.updated_with_new_rand_root(30);
    let alt_ex_4 = alt_ex_3.updated_with_new_rand_root(335);


    let post_set_latest_1 = ex_1.clone().updated_with_new_rand_root(400);
    let post_set_latest_2 = alt_ex_4.clone().updated_with_new_rand_root(400);
    let user_set_batch_1 = vec![
        post_set_latest_1.to_db_row(first_user_id),
        ExUserLeaf::new_random_row(),
        ExUserLeaf::new_random_row(),
        ExUserLeaf::new_random_row(),
        ExUserLeaf::new_random_row(),
        post_set_latest_2.to_db_row(alt_user_id),
        ExUserLeaf::new_random_row(),
        ExUserLeaf::new_random_row(),
        ExUserLeaf::new_random_row(),
    ];
    db_manager.set_many_user_leaves(400, &user_set_batch_1).await?;
    assert_eq!(post_set_latest_1, db_manager.get_user_leaf(first_user_id, 400).await?.unwrap());
    assert_eq!(ex_4, db_manager.get_user_leaf(first_user_id, 30).await?.unwrap());
    assert_eq!(ex_3, db_manager.get_user_leaf(first_user_id, 29).await?.unwrap());
    assert_eq!(ex_2, db_manager.get_user_leaf(first_user_id, 11).await?.unwrap());
    assert_eq!(ex_1, db_manager.get_user_leaf(first_user_id, 10).await?.unwrap());
    assert!(db_manager.get_user_leaf(first_user_id, 9).await?.is_none());
    assert!(db_manager.get_user_leaf(first_user_id, 0).await?.is_none());
    for row in user_set_batch_1.iter() {
        let fetched = db_manager.get_user_leaf(row.key, 400).await?.unwrap();
        assert_eq!(fetched, row.value, "Fetched user leaf does not match set value");
        let fetched = db_manager.get_user_leaf(row.key, 500).await?.unwrap();
        assert_eq!(fetched, row.value, "Fetched user leaf does not match set value");
        let n_value = row.value.updated_with_new_rand_root(600);
        db_manager.check_insert_user_leaf_simple(row.key, 700, &n_value).await?;
    }
    


    let first_batch_contracts_one_by_one = (0..100).map(|_| ExContractInfo::new_random_row()).collect::<Vec<_>>();
    for entry in first_batch_contracts_one_by_one.iter() {
        db_manager.check_insert_contract_info_simple(entry.key, entry.value.deployed_checkpoint_id, &entry.value).await?;
    }
    let fetched_contracts = db_manager.get_contract_infos(&first_batch_contracts_one_by_one.iter().map(|e| e.key).collect::<Vec<_>>(), MAX_CHECKPOINT_ID).await?;
    for (i, entry) in first_batch_contracts_one_by_one.iter().enumerate() {
        assert_eq!(Some(entry.value.clone()), fetched_contracts[i], "Fetched contract info does not match set value");
        let fetched_after = db_manager.get_contract_info(entry.key, MAX_CHECKPOINT_ID).await?.unwrap();
        assert_eq!(fetched_after, entry.value, "Fetched contract info does not match set value");
        let fetched_after_with_keys = db_manager.get_contract_info_with_ids_t(entry.key, MAX_CHECKPOINT_ID).await?.unwrap();
        assert_eq!(fetched_after_with_keys, QDatabaseSingleIdTableRow{
            checkpoint_id: entry.value.deployed_checkpoint_id,
            obj_id: entry.key,
            value: entry.value.clone()
        }, "Fetched contract info with keys does not match set value");
    }

    let first_batch_contract_ids: Vec<u64> = first_batch_contracts_one_by_one.iter().map(|x|x.key).collect();







    let not_in_ids = (0..100).map(|_| rand_non_existent_contract_id()).collect::<Vec<_>>();
    let should_be_in_ids = first_batch_contract_ids[first_batch_contract_ids.len()/4..3*first_batch_contract_ids.len()/4].to_vec();
    let mut mixed_ids = [not_in_ids.as_slice(), should_be_in_ids.as_slice()].concat();
    let mut rng = rand::thread_rng();
    mixed_ids.shuffle(&mut rng);


    let batch_contract_infos = db_manager.get_contract_infos_with_ids(&mixed_ids, MAX_CHECKPOINT_ID).await?;

    assert_eq!(batch_contract_infos.len(), should_be_in_ids.len(), "Batch fetched contract infos length mismatch");
    let mut sorted_batch_contract_infos = batch_contract_infos.clone();
    sorted_batch_contract_infos.sort_by_key(|e| e.pair.key);
    let sorted_batch_contract_info_ids = sorted_batch_contract_infos.iter().map(|e| e.pair.key).collect::<Vec<u64>>();
    let mut sorted_should_be_in_ids = should_be_in_ids.clone();
    sorted_should_be_in_ids.sort();
    assert_eq!(sorted_batch_contract_info_ids, sorted_should_be_in_ids, "Sorted fetched contract info IDs do not match expected");


    for (sorted_id, result) in sorted_batch_contract_info_ids.iter().zip(sorted_batch_contract_infos.iter()) {
        assert_eq!(*sorted_id, result.pair.key, "Sorted ID does not match fetched contract info ID");
        let original = first_batch_contracts_one_by_one.iter().find(|e| e.key == *sorted_id).unwrap();
        assert_eq!(original.value, result.pair.value, "Fetched contract info value does not match original");
    }
    for should_be_in_id in should_be_in_ids.iter() {
        let fetched = db_manager.get_contract_info_with_ids(*should_be_in_id, MAX_CHECKPOINT_ID).await?;
        assert!(fetched.is_some(), "Should be in ID {} not found individually", should_be_in_id);
        let fetched = db_manager.get_contract_info(*should_be_in_id, MAX_CHECKPOINT_ID).await?;
        assert!(fetched.is_some(), "Should be in ID {} not found individually (no keys)", should_be_in_id);
        let fetched = db_manager.get_contract_info_with_ids_t(*should_be_in_id, MAX_CHECKPOINT_ID).await?;
        assert!(fetched.is_some(), "Should be in ID {} not found individually (no keys)", should_be_in_id);
        assert_eq!(fetched.unwrap().value, sorted_batch_contract_infos.iter().find(|x| x.pair.key == *should_be_in_id).unwrap().pair.value, "Individually fetched contract info does not match batch fetched");
    }
    Ok(())
}
