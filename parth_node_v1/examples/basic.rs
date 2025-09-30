use parth_core::data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey};
use parth_node_v1::{data::hash::QPMerkleTreeStore, scylla::{merkle_store::ScyllaMerkleTreeStore, utils::KeccakHasher}};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let store = ScyllaMerkleTreeStore::<[u8; 32], KeccakHasher>::new(vec!["127.0.0.1:9042".to_string()]).await?;

    // Example set
    let nodes = vec![
        SimpleMerkleNode { key: SimpleMerkleNodeKey { level: 0, index: 0 }, value: [1u8; 32] },
        SimpleMerkleNode { key: SimpleMerkleNodeKey { level: 1, index: 0 }, value: [2u8; 32] },
    ];
    store.set_tree_nodes(1, 999, nodes).await?;

    // Example get
    let keys = vec![SimpleMerkleNodeKey { level: 0, index: 0 }, SimpleMerkleNodeKey { level: 2, index: 0 }]; // Second is missing -> zero
    let values = store.get_tree_nodes(u64::MAX, 999, &keys).await?;
    println!("Values: {:?}", values);

    Ok(())
}