use anyhow::Result;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}};
use parth_node_v1::{data::hash::QPMerkleTreeStore, scylla::{merkle_store::ScyllaMerkleTreeStore, utils::KeccakHasher}};

#[tokio::test]
async fn test_set_get_correctness() -> Result<()> {
    let store = ScyllaMerkleTreeStore::<[u8; 32], KeccakHasher>::new(vec!["127.0.0.1:9042".to_string()]).await?;

    // Set nodes at block 1
    let nodes = vec![
        SimpleMerkleNode { key: SimpleMerkleNodeKey { level: 0, index: 0 }, value: [1u8; 32] },
        SimpleMerkleNode { key: SimpleMerkleNodeKey { level: 1, index: 0 }, value: [2u8; 32] },
    ];
    store.set_tree_nodes(1, 1, nodes.clone()).await?;

    // Get latest
    let keys = vec![SimpleMerkleNodeKey { level: 0, index: 0 }, SimpleMerkleNodeKey { level: 1, index: 0 }, SimpleMerkleNodeKey { level: 2, index: 0 }];
    let values = store.get_tree_nodes(u64::MAX, 1, &keys).await?;
    assert_eq!(values[0], [1u8; 32]);
    assert_eq!(values[1], [2u8; 32]);
    assert_eq!(values[2], KeccakHasher::get_zero_hash(2)); // Zero for missing

    // Historical: max_block_height=0 -> all zero
    let values_hist = store.get_tree_nodes(0, 1, &keys).await?;
    assert_eq!(values_hist[0], KeccakHasher::get_zero_hash(0));
    assert_eq!(values_hist[1], KeccakHasher::get_zero_hash(1));

    // Set at higher block
    let new_nodes = vec![SimpleMerkleNode { key: SimpleMerkleNodeKey { level: 0, index: 0 }, value: [3u8; 32] }];
    store.set_tree_nodes(2, 1, new_nodes).await?;
    let values = store.get_tree_nodes(1, 1, &keys).await?; // Should get block 1 version
    assert_eq!(values[0], [1u8; 32]);

    Ok(())
}
