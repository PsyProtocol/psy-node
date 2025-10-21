
use crate::psy_core_db::{traits::full::{PsyNodeCheckpointObjectDatabaseReader, PsyNodeCheckpointObjectDatabaseWriter}, v3_implementation::full::PsyUnifiedCoreDatabaseStore};

use parth_core::{
    crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, tag_tree::TagTreeMerkleProof}, data::{db::row::QDatabaseSingleIdTableRow, hash::{merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, merkle_store_key::{QMerkleStoreDoubleIdNode, QMerkleStoreSingleIdNode}}}, protocol::core_types::QNetworkDatabaseTypes, utils::QPGenRandom, QCoreProcCheckpointUniqueId
};
use psy_data::v1::qdata::{
    checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState}, checkpoint_sync::PQEDCheckpointSyncInfo, contract::{ContractCodeDefinition, PQEDContractLeaf}, ffs_sizes::{PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY, PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF}, public_key::PZKPublicKeyInfo, user::PQEDUserLeaf
};
use crate::{psy_core_db::{core_implementation::constants::CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_REWARDS_TAG_TREE_ROOT_PROOF}, store::traits::{core_db::{
    CoreDatabaseBidirectionalMappingReader, CoreDatabaseBidirectionalU64U128MappingReader,
    CoreDatabaseKivReader, CoreDatabaseSingleIdCheckpointedReader, CoreDatabaseSingleIdMerkleReader, CoreDatabaseStore,
    CoreDatabaseU64Reader, CoreDatabaseZeroIdMerkleReader,
}, helpers::*}};

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
    pub async fn run_all_tests(&self) -> anyhow::Result<()> {

        Ok(())
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
> {
    pub async fn test_set_l2_block_data(&self) -> anyhow::Result<()> {
        // test basic fetch and set l2 block state
        let base = QEDL2BlockState::qp_rand_gen();
        assert!(self.db.get_latest_l2_block_state().await.is_err());
        self.db.set_l2_block_state(0, &base).await?;
        let got_block_state = self.db.get_latest_l2_block_state().await;
        assert!(got_block_state.is_ok());
        let got_block_state = got_block_state.unwrap();
        assert_eq!(base, got_block_state);


        let block_state_100 = QEDL2BlockState::qp_rand_gen();
        self.db.set_l2_block_state(100, &block_state_100).await?;
        let got_block_state_100 = self.db.get_latest_l2_block_state().await?;
        assert_eq!(block_state_100, got_block_state_100);
        // block state is not checkpointed in the same way that other objects are.
        assert!(self.db.get_l2_block_state(10).await.is_err());
        Ok(())

    }
}