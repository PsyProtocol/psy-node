use hashbrown::HashMap;
use parth_common::memory_stores::{
    mem_tree_recorder::SimpleMemoryMerkleRecorderStore,
    traits::{PsyMemoryMerkleStoreAppendOnlyReaderBase, PsyMemoryMerkleStoreAppendOnlyReaderBaseAsync},
};
use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::FieldQHasher},
    data::hash::{
        merkle_node_key::SimpleMerkleNodeKey,
        merkle_planner::{NCAMerklePlannerVisitorWithTreeStores, run_merkle_planner_visitor_with_offset_root_and_trees},
    },
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    guta::{
        header::GlobalUserTreeAggregatorHeader, header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
        header_job_prep::GUTAHeaderWithJobMetadata,
    },
    proof_input::guta::generic::GlobalUserTreeAggregatorHeaderWi,
    worker::{metadata::PsyProvingJobMetadata, metadata_with_job_id::PsyProvingJobMetadataWithJobId},
};

pub struct CoordinatorGUTAPlannerHelper<Hash> {
    pub last_checkpoint_root: Hash,
    pub last_checkpoint_id: u64,
    pub last_checkpoint_merkle_proof: MerkleProofCore<Hash>,
    pub global_user_tree_height: u8,
    pub guta_realm_level: u8,
    pub reward_tags: Vec<(SimpleMerkleNodeKey, QProvingJobDataID, Hash)>,
    pub leaf_tag_values: HashMap<u64, Hash>,
    pub job_witnesses: Vec<(QProvingJobDataID, Vec<u8>)>,
    pub output_jobs: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>>,
}

impl<
        F: QFelt64,
        Hash: QFHashBase<F> + Q256BitHash,
        Hasher: FieldQHasher<F, Hash>,
        CheckpointTreeFetcher: PsyMemoryMerkleStoreAppendOnlyReaderBase<Hash>,
    > NCAMerklePlannerVisitorWithTreeStores<GUTAHeaderWithJobMetadata<F, Hash>, CheckpointTreeFetcher, SimpleMemoryMerkleRecorderStore<Hasher, Hash>>
    for CoordinatorGUTAPlannerHelper<Hash>
{
    fn visit(
        &mut self,
        read_tree: &CheckpointTreeFetcher,
        rw_tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
        left_child: &GUTAHeaderWithJobMetadata<F, Hash>,
        left_child_merkle_tree_key: SimpleMerkleNodeKey,
        right_child: &GUTAHeaderWithJobMetadata<F, Hash>,
        right_child_merkle_tree_key: SimpleMerkleNodeKey,
        nca_merkle_tree_key: SimpleMerkleNodeKey,
        nca_reward_tree_key: SimpleMerkleNodeKey,
        is_reward_root: bool,
    ) -> anyhow::Result<GUTAHeaderWithJobMetadata<F, Hash>> {
        let left_guta_key = left_child.get_global_user_tree_key();
        let right_guta_key = right_child.get_global_user_tree_key();
        let nca_merkle_tree_key = if is_reward_root {
            SimpleMerkleNodeKey::new_root()
        } else {
            nca_merkle_tree_key
        };
        let needs_upgrade = left_guta_key.level == self.guta_realm_level || right_guta_key.level == self.guta_realm_level;
        if needs_upgrade {
            // Handle upgrade case
            
        }else{

        }

        
        todo!()
    }
    fn init_with_reward_tree_height(&mut self, total_jobs: usize, jobs_per_level: Vec<usize>, reward_tree_height: u8) {
        self.output_jobs = vec![vec![]; reward_tree_height as usize + 1];
        self.job_witnesses = Vec::with_capacity(total_jobs);
        self.output_jobs = jobs_per_level.iter().map(|&n| Vec::with_capacity(n)).collect();
    }
}
pub fn plan_guta_jobs_for_coordinator_nca_offset_root<
    F: QFelt64,
    Hash: QFHashBase<F> + Q256BitHash,
    Hasher: FieldQHasher<F, Hash>,
    CheckpointTreeFetcher: PsyMemoryMerkleStoreAppendOnlyReaderBase<Hash>,
>(
    checkpoint_tree_store: &CheckpointTreeFetcher,
    global_user_tree_store: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    global_user_tree_height: u8,
    last_checkpoint_id: u64,
    last_checkpoint_root: Hash,
    unique_checkpoint_id: u64,
    start_global_tree_root: Hash,
    allowed_circuit_hashes_root: Hash,
    leaves: &[GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>],
    reward_tree_root_index: u64,
    reward_tree_root_level: u8,
) -> anyhow::Result<(
    Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>>,
    Vec<(QProvingJobDataID, Vec<u8>)>,
)> {
    if leaves.len() == 0 {
        anyhow::bail!("No leaves provided for GUTA planning, not yet implemented");
    } else if leaves.len() == 1 {
        anyhow::bail!("Only one leaf provided for GUTA planning, not yet implemented");
    }
    let guta_realm_level: u8 = leaves[0].header.header_with_stats.base_header.state_transition.node_level.to_u64_value() as u8;

    let mut leaf_tag_values = HashMap::<u64, Hash>::with_capacity(leaves.len());
    let mut new_leaves: Vec<(SimpleMerkleNodeKey, GUTAHeaderWithJobMetadata<F, Hash>)> = Vec::with_capacity(leaves.len());
    for leaf in leaves.iter() {
        let node_key = SimpleMerkleNodeKey::new(
            leaf.header.header_with_stats.base_header.state_transition.node_level.to_u64_value() as u8,
            leaf.header.header_with_stats.base_header.state_transition.node_index.to_u64_value(),
        );
        let input = GUTAHeaderWithJobMetadata {
            header: leaf.header.header_with_stats.clone(),
            metadata: PsyProvingJobMetadataWithJobId {
                job_id: leaf.job_id,
                metadata: PsyProvingJobMetadata {
                    expected_public_inputs_hash: Hash::get_zero_value(),
                    reward_tree_node_index: 0,
                    reward_tree_node_level: 0,
                    reward_tree_hash_mode: 0,
                    reward_tree_node_children: 0,
                    dependencies: Vec::new(),
                },
            },
        };
        leaf_tag_values.insert(node_key.index, leaf.header.new_tag_tree_node_value);
        new_leaves.push((node_key, input));
    }

    

    let mut helper = CoordinatorGUTAPlannerHelper {
        last_checkpoint_id,
        last_checkpoint_root,
        last_checkpoint_merkle_proof: checkpoint_tree_store.get_merkle_proof_for_leaf(last_checkpoint_id),
        global_user_tree_height,
        guta_realm_level,
        reward_tags: Vec::with_capacity(leaves.len()),
        leaf_tag_values,
        job_witnesses: Vec::new(),
        output_jobs: Vec::new(),
    };
    let root_res = run_merkle_planner_visitor_with_offset_root_and_trees::<
        GUTAHeaderWithJobMetadata<F, Hash>,
        CoordinatorGUTAPlannerHelper<Hash>,
        CheckpointTreeFetcher,
        SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    >(
        checkpoint_tree_store,
        global_user_tree_store,
        new_leaves,
        global_user_tree_height,
        reward_tree_root_level,
        reward_tree_root_index,
        &mut helper,
    )?;

    todo!()
}
