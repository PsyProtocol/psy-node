use crate::psy_core_db::{
    traits::full::{
        PsyNodeCheckpointObjectDatabaseReader, PsyNodeCheckpointObjectDatabaseWriter, PsyNodeCheckpointRealmSpecificDatabaseReader,
        PsyNodeCheckpointTreeDatabaseReader, PsyNodeCheckpointTreeDatabaseWriter, PsyNodeCoreDatabaseBasicContractInfoStoreReader,
        PsyNodeCoreDatabaseBasicContractInfoStoreWriter, PsyNodeCoreDatabaseContractObjectStoreReader,
        PsyNodeCoreDatabaseContractObjectStoreWriter, PsyNodeCoreDatabaseUserStoreReader, PsyNodeCoreDatabaseUserStoreWriter,
        PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyNodeGlobalContractTreeDatabaseReader,
        PsyNodeGlobalContractTreeDatabaseWriter, PsyNodeGlobalUserTreeDatabaseReader, PsyNodeGlobalUserTreeDatabaseWriter,
        PsyNodeUserContractTreeDatabaseReader, PsyNodeUserContractTreeDatabaseWriter, PsyNodeUserRegistrationTreeDatabaseReader,
        PsyNodeUserRegistrationTreeDatabaseWriter, PsyNodeContractStateTreeTreeDatabaseReader, PsyNodeContractStateTreeTreeDatabaseWriter, PsyNodeContractFunctionTreeDatabaseReader, PsyNodeContractFunctionTreeDatabaseWriter,
    },
    v3_implementation::full::PsyUnifiedCoreDatabaseStore,
};
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::db::row::QDatabaseSingleIdTableRowNoCheckpointId};
use anyhow::Ok;
use parth_core::{
    crypto::hash::{
        merkle_proof::{MerkleProofCore},
        tag_tree::TagTreeMerkleProof,
    },
    data::db::row::QDatabaseSingleIdTableRow,
    data::hash::{
        merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
        merkle_store_key::{QMerkleStoreDoubleIdNode, QMerkleStoreSingleIdNode},
    },
    felt::ToU64Value,
    protocol::core_types::QNetworkDatabaseTypes,
    utils::QPGenRandom,
    QCoreProcCheckpointUniqueId,
};
use psy_data::v1::qdata::{
    checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
    contract::{ContractCodeDefinition, ContractCodeDefinitionWithContractId, PQEDContractLeaf},
    public_key::PZKPublicKeyInfo,
    user::PQEDUserLeaf,
};
use psy_serialize::{FastFixedSerializable, PsySerializeCanonicalAsyncSafe};
use crate::store::traits::core_db::CoreDatabaseStore;

pub struct ExPsyUnifiedStoreTestHelper<
    N: QNetworkDatabaseTypes,
    BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
    BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
    U64TableIdentifier: Clone + Send + Sync,
    SingleIdTableIdentifier: Clone + Send + Sync,
    DoubleIdTableIdentifier: Clone + Send + Sync,
    KivTableIdentifier: Clone + Send + Sync,
    SingleIdMerkleTableIdentifier: Clone + Send + Sync,
    DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
    ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
    TagTreeTableIdentifier: Clone + Send + Sync,
    HashToManyIdsTableIdentifier: Clone + Send + Sync,
    S: CoreDatabaseStore<
            N::QHash,
            N::HasherBase,
            BiDirectionalMappingTableIdentifier,
            BiDirectionalU64U128MappingTableIdentifier,
            U64TableIdentifier,
            SingleIdTableIdentifier,
            DoubleIdTableIdentifier,
            KivTableIdentifier,
            SingleIdMerkleTableIdentifier,
            DoubleIdMerkleTableIdentifier,
            ZeroIdMerkleTableIdentifier,
            TagTreeTableIdentifier,
            HashToManyIdsTableIdentifier,
        > + Send
        + Sync,
> {
    pub db: PsyUnifiedCoreDatabaseStore<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        S,
    >,
    pub realm_id: u64,
    pub realm_sub_id: u64,
}


impl<
    N: QNetworkDatabaseTypes,
    BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
    BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
    U64TableIdentifier: Clone + Send + Sync,
    SingleIdTableIdentifier: Clone + Send + Sync,
    DoubleIdTableIdentifier: Clone + Send + Sync,
    KivTableIdentifier: Clone + Send + Sync,
    SingleIdMerkleTableIdentifier: Clone + Send + Sync,
    DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
    ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
    TagTreeTableIdentifier: Clone + Send + Sync,
    HashToManyIdsTableIdentifier: Clone + Send + Sync,
    S: CoreDatabaseStore<
            N::QHash,
            N::HasherBase,
            BiDirectionalMappingTableIdentifier,
            BiDirectionalU64U128MappingTableIdentifier,
            U64TableIdentifier,
            SingleIdTableIdentifier,
            DoubleIdTableIdentifier,
            KivTableIdentifier,
            SingleIdMerkleTableIdentifier,
            DoubleIdMerkleTableIdentifier,
            ZeroIdMerkleTableIdentifier,
            TagTreeTableIdentifier,
            HashToManyIdsTableIdentifier,
        > + Send
        + Sync,
> ExPsyUnifiedStoreTestHelper<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        S,
> {
    pub fn new(
        db: PsyUnifiedCoreDatabaseStore<
            N,
            BiDirectionalMappingTableIdentifier,
            BiDirectionalU64U128MappingTableIdentifier,
            U64TableIdentifier,
            SingleIdTableIdentifier,
            DoubleIdTableIdentifier,
            KivTableIdentifier,
            SingleIdMerkleTableIdentifier,
            DoubleIdMerkleTableIdentifier,
            ZeroIdMerkleTableIdentifier,
            TagTreeTableIdentifier,
            HashToManyIdsTableIdentifier,
            S,
        >,
        realm_id: u64,
        realm_sub_id: u64,
    ) -> Self {
        Self {
            db,
            realm_id,
            realm_sub_id,
        }
    }
}


impl<
    N: QNetworkDatabaseTypes,
    BiDirectionalMappingTableIdentifier: Clone + Send + Sync,
    BiDirectionalU64U128MappingTableIdentifier: Clone + Send + Sync,
    U64TableIdentifier: Clone + Send + Sync,
    SingleIdTableIdentifier: Clone + Send + Sync,
    DoubleIdTableIdentifier: Clone + Send + Sync,
    KivTableIdentifier: Clone + Send + Sync,
    SingleIdMerkleTableIdentifier: Clone + Send + Sync,
    DoubleIdMerkleTableIdentifier: Clone + Send + Sync,
    ZeroIdMerkleTableIdentifier: Clone + Send + Sync,
    TagTreeTableIdentifier: Clone + Send + Sync,
    HashToManyIdsTableIdentifier: Clone + Send + Sync,
    S: CoreDatabaseStore<
            N::QHash,
            N::HasherBase,
            BiDirectionalMappingTableIdentifier,
            BiDirectionalU64U128MappingTableIdentifier,
            U64TableIdentifier,
            SingleIdTableIdentifier,
            DoubleIdTableIdentifier,
            KivTableIdentifier,
            SingleIdMerkleTableIdentifier,
            DoubleIdMerkleTableIdentifier,
            ZeroIdMerkleTableIdentifier,
            TagTreeTableIdentifier,
            HashToManyIdsTableIdentifier,
        > + Send
        + Sync,
> ExPsyUnifiedStoreTestHelper<
        N,
        BiDirectionalMappingTableIdentifier,
        BiDirectionalU64U128MappingTableIdentifier,
        U64TableIdentifier,
        SingleIdTableIdentifier,
        DoubleIdTableIdentifier,
        KivTableIdentifier,
        SingleIdMerkleTableIdentifier,
        DoubleIdMerkleTableIdentifier,
        ZeroIdMerkleTableIdentifier,
        TagTreeTableIdentifier,
        HashToManyIdsTableIdentifier,
        S,
> where N::QHash: QPGenRandom + std::fmt::Debug + PartialEq, N::F: QPGenRandom + PsySerializeCanonicalAsyncSafe + std::fmt::Debug + PartialEq, {
    pub async fn run_all_tests(&self) -> anyhow::Result<()> {
        self.test_set_l2_block_data().await?;
        self.test_checkpoint_ids_and_hashes().await?;
        self.test_checkpoint_leaf_and_roots().await?;
        self.test_pending_ids().await?;
        self.test_realm_specific_proofs().await?;
        self.test_user_objects().await?;
        self.test_contract_objects().await?;
        self.test_contract_tree_heights().await?;
        self.test_checkpoint_tree().await?;
        self.test_user_registration_tree().await?;
        self.test_global_user_tree().await?;
        self.test_user_contract_tree().await?;
        self.test_contract_state_tree().await?;
        self.test_global_contract_tree().await?;
        self.test_contract_function_tree().await?;
        self.test_rewards_tag_tree().await?;
        println!("All tests passed!");
        Ok(())
    }
    pub async fn test_set_l2_block_data(&self) -> anyhow::Result<()> {
        // test basic fetch and set l2 block state
        let base = QEDL2BlockState::qp_rand_gen();
        assert!(self.db.get_latest_l2_block_state().await.is_err());
        assert!(self.db.get_l2_block_state(0).await.is_err());
        self.db.set_l2_block_state(0, &base).await?;
        assert!(self.db.get_latest_l2_block_state().await.is_err());
        assert!(self.db.get_l2_block_state(0).await.is_ok());
        let got_block_state = self.db.get_l2_block_state(0).await;
        assert!(got_block_state.is_ok());
        let got_block_state = got_block_state.unwrap();
        assert_eq!(base, got_block_state);
        self.db.set_l2_latest_block_state(&base).await?;
        assert!(self.db.get_latest_l2_block_state().await.is_ok());

        let got_block_state = self.db.get_latest_l2_block_state().await;
        assert!(got_block_state.is_ok());
        let got_block_state = got_block_state.unwrap();
        assert_eq!(base, got_block_state);


        let block_state_100 = QEDL2BlockState::qp_rand_gen();
        self.db.set_l2_block_state(100, &block_state_100).await?;
        self.db.set_l2_latest_block_state(&block_state_100).await?;
        let got_block_state_100 = self.db.get_latest_l2_block_state().await?;
        assert_eq!(block_state_100, got_block_state_100);
        // block state is not checkpointed in the same way that other objects are.
        assert!(self.db.get_l2_block_state(10).await.is_err());
        let got_block_state_100 = self.db.get_l2_block_state(100).await?;
        assert_eq!(block_state_100, got_block_state_100);

        // test out of order setting
        let block_state_50 = QEDL2BlockState::qp_rand_gen();
        self.db.set_l2_block_state(50, &block_state_50).await?;
        let got_block_state_50 = self.db.get_l2_block_state(50).await?;
        assert_eq!(block_state_50, got_block_state_50);

        // test sequential insertions
        for i in 1..50 {
            let block_state_i = QEDL2BlockState::qp_rand_gen();
            self.db.set_l2_block_state(i, &block_state_i).await?;
            let got_block_state_i = self.db.get_l2_block_state(i).await?;
            let latest = self.db.get_latest_l2_block_state().await?;
            assert_eq!(block_state_i, got_block_state_i);
            assert_ne!(block_state_i, latest);
        }
        Ok(())

    }

    async fn test_checkpoint_ids_and_hashes(&self) -> anyhow::Result<()> {
        let db = &self.db;

        // Test latest checkpoint ID
        assert_eq!(db.get_latest_checkpoint_id().await?, 0, "Initial checkpoint ID should be 0");
        db.set_latest_checkpoint_id(42).await?;
        assert_eq!(db.get_latest_checkpoint_id().await?, 42);
        db.set_latest_checkpoint_id(24).await?;
        assert_eq!(db.get_latest_checkpoint_id().await?, 24);

        // Test root hash to ID mapping
        let root_hash_1 = N::QHash::qp_rand_gen();
        let root_hash_2 = N::QHash::qp_rand_gen();
        
        assert_eq!(db.get_checkpoint_id_for_checkpoint_root_hash(root_hash_1).await?, None);
        
        db.set_checkpoint_root_hash_to_id_mapping(root_hash_1, 101).await?;
        assert_eq!(db.get_checkpoint_id_for_checkpoint_root_hash(root_hash_1).await?, Some(101));
        assert_eq!(db.get_checkpoint_id_for_checkpoint_root_hash(root_hash_2).await?, None);

        db.set_checkpoint_root_hash_to_id_mapping(root_hash_2, 202).await?;
        assert_eq!(db.get_checkpoint_id_for_checkpoint_root_hash(root_hash_1).await?, Some(101));
        assert_eq!(db.get_checkpoint_id_for_checkpoint_root_hash(root_hash_2).await?, Some(202));
        
        Ok(())
    }

    async fn test_checkpoint_leaf_and_roots(&self) -> anyhow::Result<()> {
        let db = &self.db;
        
        // Test Checkpoint Leaf Data
        let leaf_data_1 = PQEDCheckpointLeaf::<N::F, N::QHash>::qp_rand_gen();
        let leaf_data_2 = PQEDCheckpointLeaf::<N::F, N::QHash>::qp_rand_gen();

        assert!(db.get_checkpoint_leaf_data(1).await.is_err(), "Should fail for non-existent leaf");
        
        db.set_checkpoint_leaf_data(1, &leaf_data_1).await?;
        let retrieved_leaf_1 = db.get_checkpoint_leaf_data(1).await?;
        assert_eq!(leaf_data_1, retrieved_leaf_1, "Retrieved leaf data does not match");
        
        db.set_checkpoint_leaf_data(2, &leaf_data_2).await?;
        let retrieved_leaf_2 = db.get_checkpoint_leaf_data(2).await?;
        assert_eq!(leaf_data_2, retrieved_leaf_2, "Retrieved leaf data 2 does not match");
        assert_eq!(leaf_data_1, db.get_checkpoint_leaf_data(1).await?, "Leaf 1 data changed unexpectedly");

        // Test Checkpoint Global State Roots
        let roots_data_1 = PQEDCheckpointGlobalStateRoots::<N::QHash>::qp_rand_gen();
        assert!(db.get_checkpoint_global_state_roots(1).await.is_err(), "Should fail for non-existent roots");
        
        db.set_checkpoint_global_state_roots(1, &roots_data_1).await?;
        let retrieved_roots_1 = db.get_checkpoint_global_state_roots(1).await?;
        assert_eq!(roots_data_1, retrieved_roots_1, "Retrieved roots data does not match");
        
        Ok(())
    }

    async fn test_pending_ids(&self) -> anyhow::Result<()> {
        let db = &self.db;

        // Test pending ID counter
        assert_eq!(db.get_latest_pending_id().await?, 0, "Initial pending ID should be 0");
        let (pending_id_1, unique_id_1) = db.inc_unique_pending_id(1).await?;
        assert_eq!(pending_id_1, 1);
        assert_eq!(db.get_latest_pending_id().await?, 1);
        
        let (current_pid, current_uid) = db.get_current_unique_pending_id().await?;
        assert_eq!(current_pid, 1);
        assert_eq!(current_uid, unique_id_1);

        let (pending_id_6, unique_id_6) = db.inc_unique_pending_id(5).await?;
        assert_eq!(pending_id_6, 6);
        assert_eq!(db.get_latest_pending_id().await?, 6);
        assert_ne!(unique_id_1, unique_id_6);

        // Test mappings
        let checkpoint_id = 100;
        let unique_pending_id = 1;
        let unique_id_struct = unique_id_1;

        assert_eq!(db.get_checkpoint_id_for_unique_pending_id(unique_pending_id).await?, None);
        db.set_unique_pending_id_checkpoint_id_mapping(unique_pending_id, checkpoint_id).await?;
        assert_eq!(db.get_checkpoint_id_for_unique_pending_id(unique_pending_id).await?, Some(checkpoint_id));

        assert_eq!(db.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await?, None);
        db.set_checkpoint_id_to_unique_pending_id_mapping(checkpoint_id, unique_pending_id, &unique_id_struct).await?;
        let retrieved_mapping = db.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await?;
        assert_eq!(retrieved_mapping, Some((unique_pending_id, unique_id_struct)));

        Ok(())
    }

    async fn test_realm_specific_proofs(&self) -> anyhow::Result<()> {
        let db = &self.db;
        let checkpoint_id = 42;
        let unique_pending_id = 7;
        
        // Test Rewards Tag Tree Proof
        let tag_proof = TagTreeMerkleProof::<N::QHash>::qp_rand_gen();
        
        assert!(db.get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id(checkpoint_id).await.is_err());
        db.set_realm_rewards_tag_tree_top_proof_at_checkpoint_id(checkpoint_id, &tag_proof).await?;
        let retrieved_tag_proof = db.get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id(checkpoint_id).await?;
        assert_eq!(tag_proof, retrieved_tag_proof);
        
        assert!(db.get_top_global_user_rewards_tree_proof_to_realm_at_unique_pending_id(unique_pending_id).await.is_err());
        db.set_realm_rewards_tag_tree_top_proof_at_unique_pending_id(unique_pending_id, &tag_proof).await?;
        let retrieved_tag_proof_pending = db.get_top_global_user_rewards_tree_proof_to_realm_at_unique_pending_id(unique_pending_id).await?;
        assert_eq!(tag_proof, retrieved_tag_proof_pending);

        // Test Global User Tree Proof
        let user_tree_proof = MerkleProofCore::<N::QHash>::qp_rand_gen();
        
        assert!(db.get_top_global_user_tree_proof_to_realm_root_at_checkpoint_id(checkpoint_id).await.is_err());
        // The writer for this is on the PsyNodeGlobalUserTreeDatabaseWriter trait
        db.global_user_tree_set_top_tree_merkle_proof(checkpoint_id, &user_tree_proof).await?;
        let retrieved_user_proof = db.get_top_global_user_tree_proof_to_realm_root_at_checkpoint_id(checkpoint_id).await?;
        assert_eq!(user_tree_proof, retrieved_user_proof);

        Ok(())
    }

    async fn test_user_objects(&self) -> anyhow::Result<()> {
        let db = &self.db;
        let user_id = 1;
        let checkpoint_10 = 10;
        let checkpoint_12 = 12;

        // Test User Leaf
        let user_leaf_10 = PQEDUserLeaf::<N::F, N::QHash>::random_with_user_id(user_id);
        assert!(db.get_user_leaf(checkpoint_10, user_id).await.is_err());

        db.set_user_leaf_(checkpoint_10, &user_leaf_10).await?;
        assert_eq!(db.get_user_leaf(checkpoint_10, user_id).await?, user_leaf_10);
        assert!(db.get_user_leaf(checkpoint_10 - 1, user_id).await.is_err());
        assert_eq!(db.get_user_leaf(checkpoint_10 + 1, user_id).await?, user_leaf_10);

        let user_leaf_12 = PQEDUserLeaf::<N::F, N::QHash>::random_with_user_id(user_id);
        db.set_user_leaf_(checkpoint_12, &user_leaf_12).await?;
        assert_eq!(db.get_user_leaf(checkpoint_10 + 1, user_id).await?, user_leaf_10);
        assert_eq!(db.get_user_leaf(checkpoint_12, user_id).await?, user_leaf_12);

        // Test ZK Public Key
        let pk_info_10 = PZKPublicKeyInfo::<N::QHash>::qp_rand_gen();
        db.set_zk_public_key(checkpoint_10, user_id, &pk_info_10).await?;
        assert_eq!(db.get_zk_public_key(checkpoint_10, user_id).await?, pk_info_10);

        // Test FFS methods
        let mut leaves = Vec::new();
        for i in 2..12 {
            let mut leaf = PQEDUserLeaf::<N::F, N::QHash>::qp_rand_gen();
            leaf.user_id = N::F::from_owned_u64(i as u64);
            leaves.push(leaf.clone());
        }
        let data = PQEDUserLeaf::ffs_serialize_vec_of_self_ref(&leaves);
        db.set_user_leaves_ffs(checkpoint_10, &data).await?;

        for leaf in leaves {
            let retrieved = db.get_user_leaf(checkpoint_10, leaf.user_id.to_u64_value()).await?;
            assert_eq!(retrieved, leaf);
        }

        // Test public key to user ID mapping
        let pk_hash = N::QHash::qp_rand_gen();
        let user_ids_for_pk = vec![10, 20, 30, 40, 50];

        assert_eq!(db.get_user_ids_for_public_key(pk_hash, 0, 100).await?, Vec::<u64>::new());
        for &user_id in &user_ids_for_pk {
            db.store.db_insert_one_hash_to_u64(&db.public_key_hash_to_user_ids_table, pk_hash, user_id).await?;
        }

        assert_eq!(db.get_user_ids_for_public_key(pk_hash, 0, 3).await?, vec![10, 20, 30]);
        assert_eq!(db.get_user_ids_for_public_key(pk_hash, 25, 3).await?, vec![30, 40, 50]);
        assert_eq!(db.get_user_ids_for_public_key(pk_hash, 45, 10).await?, vec![50]);
        assert_eq!(db.get_user_ids_for_public_key(pk_hash, 51, 10).await?, Vec::<u64>::new());
        
        Ok(())
    }

    async fn test_contract_objects(&self) -> anyhow::Result<()> {
        let db = &self.db;
        let contract_id = 1;
        let checkpoint_id = 20;

        // Test Contract Leaf
        let contract_leaf = PQEDContractLeaf::<N::F, N::QHash>::qp_rand_gen();
        assert!(db.get_contract_leaf(checkpoint_id, contract_id).await.is_err());
        db.set_contract_leaf(checkpoint_id, contract_id, &contract_leaf).await?;
        assert_eq!(db.get_contract_leaf(checkpoint_id, contract_id).await?, contract_leaf);
        assert_eq!(db.get_contract_leaf(checkpoint_id + 5, contract_id).await?, contract_leaf);

        // Test Contract Code Definition
        let code_def = ContractCodeDefinition::qp_rand_gen();
        assert!(db.get_contract_code_definition(checkpoint_id, contract_id).await.is_err());
        db.set_contract_code_definition(checkpoint_id, contract_id, &code_def).await?;
        assert_eq!(db.get_contract_code_definition(checkpoint_id, contract_id).await?, code_def);

        // Test batch insert for code definitions
        let mut inserts = Vec::new();
        for i in 2..12 {
            inserts.push(ContractCodeDefinitionWithContractId::new(i, ContractCodeDefinition::qp_rand_gen()));
        }
        db.set_many_contract_code_definitions(checkpoint_id, &inserts).await?;
        for row in inserts {
            assert_eq!(db.get_contract_code_definition(checkpoint_id, row.contract_id).await?, row.code_definition);
        }

        Ok(())
    }
    
    async fn test_contract_tree_heights(&self) -> anyhow::Result<()> {
        let db = &self.db;
        let c_ids = vec![1, 2, 3];
        let checkpoint_10 = 10;
        let checkpoint_11 = 11;

        assert_eq!(db.get_contract_tree_heights(checkpoint_10, &c_ids).await?, vec![0, 0, 0]);

        let heights_10 = vec![(1, 8), (3, 16)];
        db.set_contract_tree_heights(checkpoint_10, &heights_10).await?;

        assert_eq!(db.get_contract_tree_heights(checkpoint_10 - 1, &c_ids).await?, vec![0, 0, 0]);
        assert_eq!(db.get_contract_tree_heights(checkpoint_10, &c_ids).await?, vec![8, 0, 16]);
        assert_eq!(db.get_contract_tree_heights(checkpoint_10 + 1, &c_ids).await?, vec![8, 0, 16]);

        let heights_11 = vec![(2, 24)];
        db.set_contract_tree_heights(checkpoint_11, &heights_11).await?;
        assert_eq!(db.get_contract_tree_heights(checkpoint_10, &c_ids).await?, vec![8, 0, 16]);
        assert_eq!(db.get_contract_tree_heights(checkpoint_11, &c_ids).await?, vec![8, 24, 16]);
        
        Ok(())
    }

    async fn test_checkpoint_tree(&self) -> anyhow::Result<()> {
        let db = &self.db;
        let tree_height = N::CHECKPOINT_TREE_HEIGHT;
        let leaf_index = 0;

        let initial_root = db.checkpoint_tree_get_root_hash(0).await?;
        assert_eq!(initial_root, N::HasherBase::get_zero_hash(tree_height as usize));

        let proof_of_nothing = db.checkpoint_tree_get_merkle_proof(0, leaf_index).await?;
        assert_eq!(proof_of_nothing.root, initial_root);
        assert!(proof_of_nothing.verify::<N::HasherBase>());

        let leaf_val_1 = N::QHash::qp_rand_gen();
        // The writer function hardcodes leaf_index to 0
        let delta_proof_1 = db.checkpoint_tree_set_leaf_hash(1, leaf_val_1).await?;
        
        assert!(delta_proof_1.verify::<N::HasherBase>());
        assert_eq!(delta_proof_1.old_root, initial_root);

        let new_root_1 = db.checkpoint_tree_get_root_hash(1).await?;
        assert_eq!(new_root_1, delta_proof_1.new_root);

        assert_eq!(db.checkpoint_tree_get_root_hash(0).await?, initial_root);
        assert_eq!(db.checkpoint_tree_get_leaf_hash(1, leaf_index).await?, leaf_val_1);

        let proof_1 = db.checkpoint_tree_get_merkle_proof(1, leaf_index).await?;
        assert_eq!(proof_1.root, new_root_1);
        assert!(proof_1.verify::<N::HasherBase>());
        assert_eq!(proof_1.value, leaf_val_1);
        
        Ok(())
    }

    async fn test_user_registration_tree(&self) -> anyhow::Result<()> {
        let db = &self.db;
        let tree_height = N::GLOBAL_USER_TREE_HEIGHT;
        let leaf_index = 0;

        let initial_root = db.user_registration_tree_get_root_hash(0).await?;
        assert_eq!(initial_root, N::HasherBase::get_zero_hash(tree_height as usize));
        
        let leaf_val = N::QHash::qp_rand_gen();
        let delta_proof = db.user_registration_tree_set_leaf_hash(1, leaf_val).await?;
        assert!(delta_proof.verify::<N::HasherBase>());
        
        let new_root = db.user_registration_tree_get_root_hash(1).await?;
        assert_eq!(new_root, delta_proof.new_root);
        assert_eq!(db.user_registration_tree_get_leaf_hash(1, leaf_index).await?, leaf_val);
        
        let proof = db.user_registration_tree_get_merkle_proof(1, leaf_index).await?;
        assert!(proof.verify::<N::HasherBase>());
        assert_eq!(proof.root, new_root);
        
        Ok(())
    }

    async fn test_global_user_tree(&self) -> anyhow::Result<()> {
        let db = &self.db;
        let tree_height = N::GLOBAL_USER_TREE_HEIGHT;
        let leaf_index = 0;
        let root_level = 5;

        assert_eq!(db.global_user_tree_get_root_hash(0).await?, N::HasherBase::get_zero_hash(tree_height as usize));
        let leaf_val = N::QHash::qp_rand_gen();
        let delta = db.global_user_tree_set_leaf_hash(1, leaf_val).await?;
        
        let proof = db.global_user_tree_get_merkle_proof(1, leaf_index).await?;
        assert!(proof.verify::<N::HasherBase>());
        assert_eq!(proof.root, delta.new_root);

        let sub_proof = db.global_user_tree_get_merkle_proof_sub_tree(1, root_level, tree_height, leaf_index).await?;
        assert_eq!(sub_proof.siblings.len(), (tree_height - root_level) as usize);
        assert!(sub_proof.verify::<N::HasherBase>(), "proof is invalid");
        
        Ok(())
    }

    async fn test_user_contract_tree(&self) -> anyhow::Result<()> {
        let db = &self.db;
        let user_id = self.realm_id;
        let contract_id = 123;
        let checkpoint_id = 5;
        let tree_height = N::GLOBAL_CONTRACT_TREE_HEIGHT;

        assert_eq!(db.user_contract_tree_get_root_hash(checkpoint_id, user_id).await?, N::HasherBase::get_zero_hash(tree_height as usize));
        
        let leaf_val = N::QHash::qp_rand_gen();
        let delta = db.user_contract_tree_set_leaf_hash(checkpoint_id, user_id, contract_id, leaf_val).await?;
        
        let new_root = db.user_contract_tree_get_root_hash(checkpoint_id, user_id).await?;
        assert_eq!(new_root, delta.new_root);
        assert_eq!(db.user_contract_tree_get_leaf_hash(checkpoint_id, user_id, contract_id).await?, leaf_val);
        
        let proof = db.user_contract_tree_get_merkle_proof(checkpoint_id, user_id, contract_id).await?;
        assert!(proof.verify::<N::HasherBase>());
        assert_eq!(proof.root, new_root);

        Ok(())
    }

    async fn test_contract_state_tree(&self) -> anyhow::Result<()> {
        let db = &self.db;
        let user_id = self.realm_id;
        let contract_id = self.realm_sub_id;
        let state_slot_id = 0; // The writer hardcodes this
        let checkpoint_id = 15;
        let tree_height = N::MAX_CONTRACT_STATE_TREE_HEIGHT;

        assert_eq!(db.contract_state_tree_get_root_hash(checkpoint_id, user_id, contract_id).await?, N::HasherBase::get_zero_hash(tree_height as usize));
        
        let leaf_val = N::QHash::qp_rand_gen();
        let delta = db.contract_state_tree_set_leaf_hash(checkpoint_id, user_id, contract_id, leaf_val).await?;
        
        let new_root = db.contract_state_tree_get_root_hash(checkpoint_id, user_id, contract_id).await?;
        assert_eq!(new_root, delta.new_root);
        assert_eq!(db.contract_state_tree_get_leaf_hash(checkpoint_id, user_id, contract_id, state_slot_id).await?, leaf_val);
        
        let proof = db.contract_state_tree_get_merkle_proof(checkpoint_id, user_id, contract_id, state_slot_id).await?;
        assert!(proof.verify::<N::HasherBase>());
        assert_eq!(proof.root, new_root);
        
        Ok(())
    }

    async fn test_global_contract_tree(&self) -> anyhow::Result<()> {
        let db = &self.db;
        let tree_height = N::GLOBAL_CONTRACT_TREE_HEIGHT;
        let leaf_index = 0;

        assert_eq!(db.global_contract_tree_get_root_hash(0).await?, N::HasherBase::get_zero_hash(tree_height as usize));
        
        let leaf_val = N::QHash::qp_rand_gen();
        let delta = db.global_contract_tree_set_leaf_hash(1, leaf_val).await?;
        
        let new_root = db.global_contract_tree_get_root_hash(1).await?;
        assert_eq!(new_root, delta.new_root);
        let proof = db.global_contract_tree_get_merkle_proof(1, leaf_index).await?;
        assert!(proof.verify::<N::HasherBase>());

        Ok(())
    }

    async fn test_contract_function_tree(&self) -> anyhow::Result<()> {
        let db = &self.db;
        let contract_id = 42;
        let function_id = 7;
        let checkpoint_id = 8;
        let tree_height = N::CONTRACT_FUNCTION_TREE_HEIGHT;

        assert_eq!(db.contract_function_tree_get_root_hash(checkpoint_id, contract_id).await?, N::HasherBase::get_zero_hash(tree_height as usize));
        
        let leaf_val = N::QHash::qp_rand_gen();
        let delta = db.contract_function_tree_set_leaf_hash(checkpoint_id, contract_id, function_id, leaf_val).await?;
        
        let new_root = db.contract_function_tree_get_root_hash(checkpoint_id, contract_id).await?;
        assert_eq!(new_root, delta.new_root);
        
        let proof = db.contract_function_tree_get_merkle_proof(checkpoint_id, contract_id, function_id).await?;
        assert!(proof.verify::<N::HasherBase>());

        Ok(())
    }

    async fn test_rewards_tag_tree(&self) -> anyhow::Result<()> {
        let db = &self.db;
        let unique_pending_id = 1;
        
        let root_key = SimpleMerkleNodeKey::new_root();
        assert!(db.rewards_tag_tree_get_root_at_unique_pending_id(unique_pending_id).await.is_err());
        assert_eq!(db.rewards_tag_tree_get_node_at_unique_pending_id(unique_pending_id, root_key).await.unwrap_or_default(), N::QHash::default());

        let key = SimpleMerkleNodeKey::new(1, 0);
        let tag = N::QHash::qp_rand_gen();
        let value = N::QHash::qp_rand_gen();

        db.rewards_tag_tree_set_node_tag(unique_pending_id, key, tag, value).await?;

        let retrieved_tag = db.rewards_tag_tree_get_node_tags_at_unique_pending_id(unique_pending_id, &[key]).await?;
        assert_eq!(retrieved_tag, vec![Some(tag)]);
        let retrieved_value = db.rewards_tag_tree_get_node_values_at_unique_pending_id(unique_pending_id, &[key]).await?;
        assert_eq!(retrieved_value, vec![Some(value)]);



        let unique_pending_id = 2;
        let key_child_0 = SimpleMerkleNodeKey::new(1, 0);
        let key_child_1 = SimpleMerkleNodeKey::new(1, 1);
        let tag_child_0 = N::QHash::qp_rand_gen();
        let tag_child_1 = N::QHash::qp_rand_gen();
        db.rewards_tag_tree_set_node_tag_only(unique_pending_id, key_child_0, tag_child_0).await?;
        db.rewards_tag_tree_set_node_tag_only(unique_pending_id, key_child_1, tag_child_1).await?;

        let parent_key = SimpleMerkleNodeKey::new(0, 0);
        let parent_tag = N::QHash::qp_rand_gen();
        db.rewards_tag_tree_set_node_tag_only(unique_pending_id, parent_key, parent_tag).await?;


        
        let proofs = db.rewards_tag_tree_get_tag_tree_merkle_proof_at_unique_pending_id(unique_pending_id, &[key_child_0, key_child_1, parent_key]).await?;
        assert_eq!(proofs.len(), 3);
        for p in proofs.iter() {
            assert!(p.verify::<N::HasherBase>());
        }

        assert!(proofs[0].root == proofs[1].root);
        assert!(proofs[0].root == proofs[2].root);
        assert!(proofs[0].leaf.left == N::QHash::default(),"for leaf child, left should be default");
        assert!(proofs[0].leaf.right == N::QHash::default(),"for leaf child, right should be default");
        assert!(proofs[1].leaf.left == N::QHash::default(),"for leaf child, left should be default");
        assert!(proofs[1].leaf.right == N::QHash::default(),"for leaf child, right should be default");
        assert!(proofs[0].leaf.tag == tag_child_0, "tag mismatch for child 0");
        assert!(proofs[1].leaf.tag == tag_child_1, "tag mismatch for child 1");

        assert!(proofs[2].leaf.tag == parent_tag, "tag mismatch for parent");


        Ok(())
    }
}