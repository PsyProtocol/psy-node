use parth_common::memory_stores::traits::PsyMemoryMerkleStoreAppendOnlyReaderBaseAsync;
use parth_core::{crypto::hash::traits::FieldQHasher, data::hash::merkle_node_key::SimpleMerkleNodeKey, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase, QNetworkTypesConfig}};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID, worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId};



pub trait NCATreePlannerHelper<JobId, Hash, LeafWitness, AggWitness, DummyWitness> {
    fn get_dummy_job_id(unique_checkpoint_id: u64) -> JobId;
    fn get_agg_job_id(unique_checkpoint_id: u64, node_key: SimpleMerkleNodeKey) -> JobId;
    fn get_leaf_job_id(unique_checkpoint_id: u64, node_key: SimpleMerkleNodeKey) -> JobId;
    fn create_dummy_witness(allowed_circuit_hashes_root: Hash, tree_root: Hash) -> DummyWitness;
    fn create_agg_two_leaf_witness(left: &LeafWitness, right: &LeafWitness) -> AggWitness;
    fn create_agg_left_leaf_right_agg_witness(left: &LeafWitness, right: &AggWitness) -> AggWitness;
    fn create_agg_left_agg_right_leaf_witness(left: &AggWitness, right: &LeafWitness) -> AggWitness;
    fn create_agg_to_agg_witness(left: &AggWitness, right: &AggWitness) -> AggWitness;
}


pub struct NCATreePlannerWitnessHelper<N: QNetworkTypesConfig<JobId = QProvingJobDataID>>{
    phantom: std::marker::PhantomData<N>,
}

impl<N: QNetworkTypesConfig<JobId = QProvingJobDataID>> NCATreePlannerWitnessHelper<N> {
}

/*


        let group_levels = generate_nca_tree_groups_v1(&leaves, guta_height);
        println!("n_group_levels: {:#?}", group_levels);
        let tree_height = group_levels.len()-1;
        assert_eq!(e_group_levels, group_levels);
        assert_eq!(group_levels.len(), 3);
        let mut simple_tree = SimpleMemoryTagTreeStore::<Hasher, Hash>::new(tree_height as u8);
        let mut hash_map_dat = HashMap::<SimpleMerkleNodeKey, SimpleMerkleNodeKey>::new();
        for (level, gl) in group_levels.iter().enumerate() {    
            for (index, g) in gl.iter().enumerate() {
                let hash = Hash::rand();
                let key = SimpleMerkleNodeKey::new((tree_height-level) as u8, index as u64);
                hash_map_dat.insert(g.nca, key);
                simple_tree.set_tag(key, hash);
            }
        }
        */

pub fn plan_guta_jobs_for_coordinator_nca_offset_root<
    F: QFelt64,
    Hash: QFHashBase<F> + Q256BitHash,
    Hasher: FieldQHasher<F, Hash>,
    CheckpointTreeFetcher: PsyMemoryMerkleStoreAppendOnlyReaderBaseAsync<Hash>,
>(
    unique_checkpoint_id: u64,
    start_global_tree_root: Hash,
    allowed_circuit_hashes_root: Hash,
    leaves: &[GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<F, Hash>],
    reward_tree_root_index: u64,
    reward_tree_root_level: u8,
    checkpoint_tree_reader: &CheckpointTreeFetcher,
) -> anyhow::Result<(Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>>, Vec<(QProvingJobDataID, Vec<u8>)>)> {









    todo!()

}