use parth_core::pgoldilocks::QHashOut;
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::worker::{
    metadata::{PsyProvingJobMetadata, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN},
    metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

fn main() -> anyhow::Result<()> {
    type H = QHashOut<parth_core::PF>;

    let meta = PsyProvingJobMetadataWithJobId::<H, QProvingJobDataID> {
        job_id: QProvingJobDataID::new_proof_job_id(1, 0, ProvingJobCircuitType::GUTANoChange, 0, 0)
            .get_output_id(),
        metadata: PsyProvingJobMetadata {
            expected_public_inputs_hash: H::from_values(
                9552129461118044126u64,
                7102188177517956164u64,
                10591706526469384156u64,
                11311337996656673209u64,
            ),
            reward_tree_node_index: 0,
            reward_tree_node_level: 0,
            reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
            reward_tree_node_children: 0,
            dependencies: vec![],
        },
    };

    let bytes = meta.psy_ser_to_bytes_vec()?;
    let decoded =
        PsyProvingJobMetadataWithJobId::<H, QProvingJobDataID>::psy_ser_from_slice(&bytes)?;

    println!("orig={:?}", meta.metadata.expected_public_inputs_hash);
    println!("decoded={:?}", decoded.metadata.expected_public_inputs_hash);
    println!(
        "same={}",
        meta.metadata.expected_public_inputs_hash == decoded.metadata.expected_public_inputs_hash
    );
    println!("len={}", bytes.len());

    Ok(())
}
