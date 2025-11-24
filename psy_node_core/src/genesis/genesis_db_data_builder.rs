use parth_common::{
    memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore,
    merkle_leaf_serializer::{
        double_id::DoubleIdMerkleNodeBatchSerializer, single_id::SingleIdMerkleNodeBatchSerializer,
        zero_id::zero_id_merkle_tree_nodes_hash_map_from_leaves,
    },
};
use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore, compute_root_merkle_proof_generic},
        traits::{FieldQHasher, QFieldHashable},
    },
    data::{
        db::hash_id_u64::{PSY_OBJECT_FFS_SIZE_HASH_256_AND_U64, QHash256AndU64},
        hash::{fast_node_serializer::QMerkleStoreFastZeroNodeSerializer, merkle_node_nest::MerkleLeafNode},
    },
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase, QNetworkConstants},
};
use psy_core::user_id::get_user_id_from_registration_id;
use psy_data::{
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    prepared_block::{common::PsyCoordinatorPendingCheckpointBase, coordinator::PsyPreparedCoordinatorBlockStateUpdates},
    v1::qdata::{
        checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafStats, QEDL2BlockState},
        contract::{ContractCodeDefinitionWithContractId, PQEDContractLeaf},
        ffs_sizes::{PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF, PSY_OBJECT_FFS_SIZE_USER_LEAF, PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY},
        user::PQEDUserLeaf,
    },
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate;
pub const GENESIS_INJEST_ALL_USERS_REALM_ID: u64 = 0xFFFFFFFFFFFFFFFF;

#[derive(Debug, Clone)]
pub struct GenesisDatabaseDataBuilder<F, Hash> {
    pub deposit_tree_root: Hash,
    pub withdrawal_tree_root: Hash,

    pub checkpoint_stats: PQEDCheckpointLeafStats<F, Hash>,

    pub global_contract_tree_root: Hash,
    pub global_user_tree_root: Hash,
    pub user_registration_tree_root: Hash,

    pub global_user_tree_nodes_ffs: Vec<u8>,
    pub user_contract_tree_nodes_ffs: Vec<u8>,
    pub contract_state_tree_nodes_ffs: Vec<u8>,
    pub user_registration_tree_nodes_ffs: Vec<u8>,

    pub global_contract_tree_nodes_ffs: Vec<u8>,
    pub contract_function_tree_nodes_ffs: Vec<u8>,

    pub user_leaves_ffs: Vec<u8>,
    pub public_keys_ffs: Vec<u8>,
    pub contract_leaves_ffs: Vec<u8>,
    pub public_key_hash_to_user_id_rows_ffs: Vec<u8>,
    pub total_users_registered: usize,

    pub contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,
}

impl<F: QFelt64, Hash: QFHashBase<F> + Q256BitHash + Default + Copy> GenesisDatabaseDataBuilder<F, Hash> {
    pub fn new(deposit_tree_root: Hash, withdrawal_tree_root: Hash, checkpoint_stats: PQEDCheckpointLeafStats<F, Hash>) -> Self {
        Self {
            deposit_tree_root,
            withdrawal_tree_root,
            checkpoint_stats,
            global_contract_tree_root: Hash::default(),
            global_user_tree_root: Hash::default(),
            user_registration_tree_root: Hash::default(),

            global_user_tree_nodes_ffs: Vec::new(),
            user_contract_tree_nodes_ffs: Vec::new(),
            user_registration_tree_nodes_ffs: Vec::new(),
            contract_state_tree_nodes_ffs: Vec::new(),
            global_contract_tree_nodes_ffs: Vec::new(),
            contract_function_tree_nodes_ffs: Vec::new(),

            user_leaves_ffs: Vec::new(),
            public_keys_ffs: Vec::new(),
            contract_leaves_ffs: Vec::new(),
            public_key_hash_to_user_id_rows_ffs: Vec::new(),

            contract_code_definitions: Vec::new(),
            total_users_registered: 0,
        }
    }

    pub fn setup_contracts<Hasher: FieldQHasher<F, Hash>, N: QNetworkConstants>(
        &mut self,
        genesis_block: &PsyGenesisBlockSetupData<F, Hash>,
        collect_contracts: bool,
    ) -> anyhow::Result<()> {
        let mut contract_function_tree_nodes_serializer = SingleIdMerkleNodeBatchSerializer::<Hash>::new();
        let mut global_contract_tree_merkle_leaves = Vec::<MerkleLeafNode<Hash>>::with_capacity(genesis_block.contracts.len());
        if collect_contracts {
            self.contract_leaves_ffs = Vec::with_capacity(genesis_block.contracts.len() * PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF);
            self.contract_code_definitions = Vec::with_capacity(genesis_block.contracts.len());
        }
        for (contract_id, contract) in genesis_block.contracts.iter().enumerate() {
            let contract_id = contract_id as u64;

            let function_tree_leaves = contract
                .function_whitelist
                .iter()
                .enumerate()
                .map(|(i, f)| MerkleLeafNode { index: i as u64, value: *f })
                .collect::<Vec<MerkleLeafNode<Hash>>>();

            let function_tree_root = contract_function_tree_nodes_serializer.add_merkle_leaves_save_optional::<Hasher>(
                contract_id,
                N::CONTRACT_FUNCTION_TREE_HEIGHT,
                &function_tree_leaves,
                collect_contracts,
            );

            let contract_leaf = PQEDContractLeaf::<F, Hash> {
                deployer: contract.deployer,
                function_tree_root,
                state_tree_height: F::from_u16_value(contract.code_definition.state_tree_height),
            };

            let contract_leaf_hash = contract_leaf.qfhash::<Hasher>();
            global_contract_tree_merkle_leaves.push(MerkleLeafNode {
                index: contract_id,
                value: contract_leaf_hash,
            });

            if collect_contracts {
                self.contract_leaves_ffs
                    .extend_from_slice(&contract_leaf.fx_tpl_psy_ser_into_bytes_vec()?);

                self.contract_code_definitions.push(ContractCodeDefinitionWithContractId {
                    contract_id,
                    code_definition: contract.code_definition.clone(),
                });
            }
        }
        let (global_contract_tree_root, global_contract_tree_nodes_hash_map) =
            zero_id_merkle_tree_nodes_hash_map_from_leaves::<Hasher, Hash>(N::GLOBAL_CONTRACT_TREE_HEIGHT, &global_contract_tree_merkle_leaves);
        self.global_contract_tree_root = global_contract_tree_root;

        if collect_contracts {
            self.contract_function_tree_nodes_ffs = contract_function_tree_nodes_serializer.serialize_into_bytes();
            self.global_contract_tree_nodes_ffs =
                QMerkleStoreFastZeroNodeSerializer::serialize_zero_id_hash_map_to_vec(&global_contract_tree_nodes_hash_map);
        }

        Ok(())
    }

    pub fn setup_users<Hasher: FieldQHasher<F, Hash>, N: QNetworkConstants>(
        &mut self,
        genesis_block: &PsyGenesisBlockSetupData<F, Hash>,
        realm_id: Option<u64>,
        collect_public_keys: bool,
        collect_user_leaves_and_contract_tree_nodes: bool,
    ) -> anyhow::Result<Option<MerkleProofCore<Hash>>> {
        let realm_start_user_id = if realm_id.is_some() {
            realm_id.unwrap() << N::REALM_GLOBAL_USER_TREE_HEIGHT
        } else {
            0
        };

        let next_realm_start_user_id = if realm_id.is_some() {
            (1u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT) + realm_start_user_id
        } else {
            u64::MAX
        };
        let mut user_contract_tree_nodes_serializer = SingleIdMerkleNodeBatchSerializer::<Hash>::new();
        let mut contract_state_tree_nodes_serializer = DoubleIdMerkleNodeBatchSerializer::<Hash>::new();
        let mut user_registration_tree_leaves = Vec::<MerkleLeafNode<Hash>>::with_capacity(genesis_block.users.len());

        self.total_users_registered = genesis_block.users.len();
        let user_ids = (0..(genesis_block.users.len() as u64))
            .map(|registration_id| {
                get_user_id_from_registration_id(
                    registration_id,
                    N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
                    N::REALM_GLOBAL_USER_TREE_HEIGHT,
                    N::GROUP_REALM_HEIGHT,
                )
            })
            .collect::<Vec<u64>>();

        let total_user_ids_in_realm = if realm_id.is_some() {
            user_ids
                .iter()
                .filter(|&&user_id| user_id >= realm_start_user_id && user_id < next_realm_start_user_id)
                .count()
        } else {
            user_ids.len()
        };
        if collect_user_leaves_and_contract_tree_nodes {
            self.user_leaves_ffs = Vec::with_capacity(total_user_ids_in_realm * PSY_OBJECT_FFS_SIZE_USER_LEAF);
        }
        if collect_public_keys {
            self.public_keys_ffs = Vec::with_capacity(user_ids.len() * PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY);
        }
        if collect_public_keys {
            self.public_key_hash_to_user_id_rows_ffs = Vec::with_capacity(user_ids.len() * PSY_OBJECT_FFS_SIZE_HASH_256_AND_U64);
        }

        let mut global_user_tree_leaves = Vec::<MerkleLeafNode<Hash>>::with_capacity(genesis_block.users.len());

        for ((registration_id, user), user_id) in genesis_block.users.iter().enumerate().zip(user_ids.into_iter()) {
            let registration_id = registration_id as u64;
            let public_key_hash = user.public_key_info.to_hash::<Hasher>();
            user_registration_tree_leaves.push(MerkleLeafNode {
                index: registration_id,
                value: public_key_hash,
            });

            let is_in_realm = if realm_id.is_some() {
                user_id >= realm_start_user_id && user_id < next_realm_start_user_id
            } else {
                true
            };
            let should_save_tree_nodes = is_in_realm && collect_user_leaves_and_contract_tree_nodes;

            if collect_public_keys {
                let u64_hash_mapping_row = QHash256AndU64 {
                    hash: public_key_hash,
                    value_u64: user_id,
                };
                self.public_key_hash_to_user_id_rows_ffs
                    .extend_from_slice(&u64_hash_mapping_row.fx_tpl_psy_ser_into_bytes_vec()?);
                self.public_keys_ffs
                    .extend_from_slice(&user.public_key_info.fx_tpl_psy_ser_into_bytes_vec()?);
            }

            let mut user_contract_tree_leaves = Vec::<MerkleLeafNode<Hash>>::with_capacity(user.constract_state_tree_records.len());

            for constract_state_tree_record in user.constract_state_tree_records.iter() {
                let contract_id = constract_state_tree_record.parent_index;
                let contract_state_tree_height = genesis_block.get_contract_state_tree_height(contract_id)?;
                let root = contract_state_tree_nodes_serializer.add_merkle_leaves_save_optional::<Hasher>(
                    user_id,
                    contract_id,
                    contract_state_tree_height,
                    &constract_state_tree_record.children,
                    should_save_tree_nodes,
                );
                user_contract_tree_leaves.push(MerkleLeafNode {
                    index: contract_id,
                    value: root,
                });
            }

            let user_contract_tree_root = user_contract_tree_nodes_serializer.add_merkle_leaves_save_optional::<Hasher>(
                user_id,
                N::GLOBAL_CONTRACT_TREE_HEIGHT,
                &user_contract_tree_leaves,
                should_save_tree_nodes,
            );

            let user_leaf = PQEDUserLeaf::<F, Hash> {
                public_key: public_key_hash,
                user_state_tree_root: user_contract_tree_root,
                balance: F::from_u64_value(user.balance),
                nonce: F::from_u64_value(user.nonce),
                last_checkpoint_id: F::from_u64_value(user.last_checkpoint_id),
                event_index: F::from_u64_value(user.event_index),
                user_id: F::from_u64_value(user_id),
            };
            let user_leaf_hash = user_leaf.qfhash::<Hasher>();
            if should_save_tree_nodes {
                self.user_leaves_ffs.extend_from_slice(&user_leaf.fx_tpl_psy_ser_into_bytes_vec()?);
            }
            global_user_tree_leaves.push(MerkleLeafNode {
                index: user_id,
                value: user_leaf_hash,
            });
        }

        self.user_contract_tree_nodes_ffs = user_contract_tree_nodes_serializer.serialize_into_bytes();
        self.contract_state_tree_nodes_ffs = contract_state_tree_nodes_serializer.serialize_into_bytes();

        let (user_registration_tree_root, user_registration_tree_nodes_hash_map) =
            zero_id_merkle_tree_nodes_hash_map_from_leaves::<Hasher, Hash>(N::GLOBAL_CONTRACT_TREE_HEIGHT, &user_registration_tree_leaves);
        self.user_registration_tree_root = user_registration_tree_root;
        self.user_registration_tree_nodes_ffs =
            QMerkleStoreFastZeroNodeSerializer::serialize_zero_id_hash_map_to_vec(&user_registration_tree_nodes_hash_map);

        let mut global_user_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(N::GLOBAL_USER_TREE_HEIGHT);
        for leaf in global_user_tree_leaves.iter() {
            global_user_tree.set_leaf_no_proof(leaf.index, leaf.value);
        }
        let global_user_tree_root = global_user_tree.get_root();

        let merkle_proof_to_realm_root = if let Some(realm_id) = realm_id {
            Some(global_user_tree.get_leaf_in_subtree(0, N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, realm_id))
        } else {
            None
        };

        self.global_user_tree_root = global_user_tree_root;
        self.global_user_tree_nodes_ffs = QMerkleStoreFastZeroNodeSerializer::serialize_zero_id_hash_map_to_vec(global_user_tree.get_changes());

        Ok(merkle_proof_to_realm_root)
    }
    pub fn get_checkpoint_state_roots(&self) -> PQEDCheckpointGlobalStateRoots<Hash> {
        PQEDCheckpointGlobalStateRoots {
            deposit_tree_root: self.deposit_tree_root,
            withdrawal_tree_root: self.withdrawal_tree_root,
            contract_tree_root: self.global_contract_tree_root,
            user_tree_root: self.global_user_tree_root,
            user_registration_tree_root: self.user_registration_tree_root,
        }
    }

    pub fn get_core_block_state(&self) -> QEDL2BlockState {
        QEDL2BlockState {
            checkpoint_id: 0,
            next_add_withdrawal_id: 0,
            next_process_withdrawal_id: 0,
            next_deposit_id: 0,
            total_deposits_claimed_epoch: 0,
            next_user_id: self.total_users_registered as u64,
            end_balance: 0,
            next_contract_id: self.contract_code_definitions.len() as u32,
        }
    }
    pub fn get_checkpoint_leaf<Hasher: FieldQHasher<F, Hash>>(&self) -> PQEDCheckpointLeaf<F, Hash> {
        PQEDCheckpointLeaf {
            global_chain_root: self.get_checkpoint_state_roots().qfhash::<Hasher>(),
            stats: self.checkpoint_stats.clone(),
        }
    }
    pub fn get_coordinator_pending_checkpoint_base<Hasher: FieldQHasher<F, Hash>, N: QNetworkConstants>(
        &self,
    ) -> PsyCoordinatorPendingCheckpointBase<F, Hash> {
        
        let siblings = (0..N::CHECKPOINT_TREE_HEIGHT_USIZE).map(|i| Hasher::get_zero_hash(i)).collect::<Vec<Hash>>();
        let checkpoint_leaf = self.get_checkpoint_leaf::<Hasher>();
        let checkpoint_leaf_hash = checkpoint_leaf.qfhash::<Hasher>();
        let checkpoint_tree_root = compute_root_merkle_proof_generic::<Hash, Hasher>(checkpoint_leaf_hash, 0, &siblings);
        

        PsyCoordinatorPendingCheckpointBase {
            block_state: self.get_core_block_state(),
            state_roots: self.get_checkpoint_state_roots(),
            checkpoint_leaf,
            checkpoint_leaf_hash,
            checkpoint_tree_root,
        }
    }

    pub fn setup_for_coordinator<Hasher: FieldQHasher<F, Hash>, N: QNetworkConstants>(
        genesis_block: &PsyGenesisBlockSetupData<F, Hash>,
    ) -> anyhow::Result<PsyPreparedCoordinatorBlockStateUpdates<F, Hash>> {
        let mut builder = GenesisDatabaseDataBuilder::new(
            genesis_block.deposit_tree_root,
            genesis_block.withdrawal_tree_root,
            genesis_block.checkpoint_stats.clone(),
        );
        builder.setup_contracts::<Hasher, N>(genesis_block, true)?;
        builder.setup_users::<Hasher, N>(genesis_block, None, true, false)?;
    
        let pending_checkpoint_base = builder.get_coordinator_pending_checkpoint_base::<Hasher, N>();

        let siblings = (0..N::CHECKPOINT_TREE_HEIGHT_USIZE).map(|i| Hasher::get_zero_hash(i)).collect::<Vec<Hash>>();
    
        let checkpoint_leaf_hash = pending_checkpoint_base.checkpoint_leaf_hash;
        let checkpoint_tree_update_proof = DeltaMerkleProofCore {
            old_root: pending_checkpoint_base.checkpoint_tree_root,
            new_root: pending_checkpoint_base.checkpoint_tree_root,
            old_value: checkpoint_leaf_hash,
            new_value: checkpoint_leaf_hash,
            siblings,
            index: 0,
        };
        Ok(PsyPreparedCoordinatorBlockStateUpdates {
            coordinator_id: 0,
            unique_pending_id: 0,
            proc_checkpoint_unique_id: 0,
            old_base: pending_checkpoint_base.clone(),
            new_base: pending_checkpoint_base,
            update_global_contract_tree_nodes_ffs: builder.global_contract_tree_nodes_ffs,
            update_contract_function_tree_nodes_ffs: builder.contract_function_tree_nodes_ffs,
            new_contract_leaves_ffs: builder.contract_leaves_ffs,
            new_contract_code_definitions: builder.contract_code_definitions,
            update_user_registration_tree_nodes_ffs: builder.user_registration_tree_nodes_ffs,
            new_user_public_keys_ffs: builder.public_keys_ffs,
            new_public_key_hash_to_user_id_rows_ffs: builder.public_key_hash_to_user_id_rows_ffs,
            update_global_user_tree_nodes_ffs: builder.global_user_tree_nodes_ffs,
            checkpoint_tree_update_proof: checkpoint_tree_update_proof,
        })
    }
}
