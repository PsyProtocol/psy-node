use std::collections::HashMap;

use cf_utils::timer::DebugTimer;
use dashmap::DashMap;
use parth_core::{data::hash::{hash256::Hash256, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}, protocol::core_types::QDBHashBase, utils::QPGenRandom, PHash};


type Hash = PHash;


fn gen_random_semi_realistic_merkle_nodes_for_bench<H: QDBHashBase + QPGenRandom>(leaf_count: usize, tree_height: u8) -> Vec<SimpleMerkleNode<H>> {

    let max_index = 1u64 << tree_height;
    let count = if leaf_count as u64 > max_index { max_index } else { leaf_count as u64 } ;
    let mut nodes = HashMap::<SimpleMerkleNodeKey, H>::with_capacity((count as usize)*2);
    for _ in 0..count {
        let key = SimpleMerkleNodeKey {
            level: tree_height,
            index: u64::qp_rand_gen() % max_index,
        };
        for parent in key.get_above_path_without_root() {
            nodes.insert(parent, H::from_owned_32bytes(Hash256::rand().0));
        }
        nodes.insert(key, H::from_owned_32bytes(Hash256::rand().0));
    }
    nodes.into_iter().map(|(k,v)| SimpleMerkleNode { key: k,  value: v }).collect()
}


async fn test_hashmap() -> anyhow::Result<()> {
    let random_merkle_nodes = gen_random_semi_realistic_merkle_nodes_for_bench::<Hash>(1_000_000, 24);


    let mut node_map = std::collections::HashMap::<SimpleMerkleNodeKey, Hash>::new();


    let mut debug_timer = DebugTimer::new("std::HashMap insert");
    debug_timer.event(format!("start insert {} nodes into hashmap ", random_merkle_nodes.len()));

    for node in &random_merkle_nodes {
        node_map.insert(node.key.clone(), node.value.clone());
    }
    debug_timer.event_batch_item_ref(format!("inserted {} nodes into std::HashMap", random_merkle_nodes.len()), "node", random_merkle_nodes.len());


    let random_merkle_keys = random_merkle_nodes.iter().map(|n| n.key.clone()).collect::<Vec<_>>();
    let mut debug_timer = DebugTimer::new("std::HashMap get");
    debug_timer.event(format!("start get {} nodes from hashmap ", random_merkle_keys.len()));
    for key in &random_merkle_keys {
        let _v = node_map.get(key);
        if node_map.contains_key(&SimpleMerkleNodeKey { level: 255, index: key.index}) {
            panic!("should not find this key");
        }
    }
    debug_timer.event_batch_item_ref(format!("got {} nodes from std::HashMap", random_merkle_keys.len()), "node", random_merkle_keys.len());
    let dash_map = DashMap::<SimpleMerkleNodeKey, Hash>::new();
    let mut debug_timer = DebugTimer::new("DashMap insert");
    debug_timer.event(format!("start insert {} nodes into DashMap ", random_merkle_nodes.len()));
    for node in &random_merkle_nodes {
        dash_map.insert(node.key.clone(), node.value.clone());
    }
    debug_timer.event_batch_item_ref(format!("inserted {} nodes into DashMap", random_merkle_nodes.len()), "node", random_merkle_nodes.len());

    let mut debug_timer = DebugTimer::new("DashMap get");
    debug_timer.event(format!("start get {} nodes from DashMap ", random_merkle_keys.len()));
    for key in &random_merkle_keys {
        let _v = dash_map.get(key);
        if dash_map.contains_key(&SimpleMerkleNodeKey { level: 255, index: key.index}) {
            panic!("should not find this key");
        }
    }
    debug_timer.event_batch_item_ref(format!("got {} nodes from DashMap", random_merkle_keys.len()), "node", random_merkle_keys.len());

    

    Ok(())
}



async fn test_hashmap_u64() -> anyhow::Result<()> {
    let random_merkle_nodes = gen_random_semi_realistic_merkle_nodes_for_bench::<Hash>(1_000_000, 24);


    let mut node_map = std::collections::HashMap::<u64, Hash>::new();


    let mut debug_timer = DebugTimer::new("std::HashMap insert u64 keys");
    debug_timer.event(format!("start insert {} nodes into hashmap ", random_merkle_nodes.len()));

    for node in &random_merkle_nodes {
        node_map.insert(node.key.to_reward_path_info(), node.value.clone());
    }
    debug_timer.event_batch_item_ref(format!("inserted {} nodes into std::HashMap", random_merkle_nodes.len()), "node", random_merkle_nodes.len());


    let random_merkle_keys = random_merkle_nodes.iter().map(|n| n.key.to_reward_path_info()).collect::<Vec<_>>();
    let mut debug_timer = DebugTimer::new("std::HashMap get u64 keys");
    debug_timer.event(format!("start get {} nodes from hashmap ", random_merkle_keys.len()));
    for key in &random_merkle_keys {
        let _v = node_map.get(key);
        if node_map.contains_key(&(0xff00_0000_0000_0000u64| *key)) {
            panic!("should not find this key");
        }
    }
    debug_timer.event_batch_item_ref(format!("got {} nodes from std::HashMap", random_merkle_keys.len()), "node", random_merkle_keys.len());
    let dash_map = DashMap::<u64, Hash>::new();
    let mut debug_timer = DebugTimer::new("DashMap insert");
    debug_timer.event(format!("start insert {} nodes into DashMap ", random_merkle_nodes.len()));
    for node in &random_merkle_nodes {
        dash_map.insert(node.key.to_reward_path_info(), node.value.clone());
    }
    debug_timer.event_batch_item_ref(format!("inserted {} nodes into DashMap", random_merkle_nodes.len()), "node", random_merkle_nodes.len());

    let mut debug_timer = DebugTimer::new("DashMap get u64 keys");
    debug_timer.event(format!("start get {} nodes from DashMap ", random_merkle_keys.len()));
    for key in &random_merkle_keys {
                    let _v = dash_map.get(key);
                    if dash_map.contains_key(&(0xff00_0000_0000_0000u64| *key)) {
                        panic!("should not find this key");
        }
    }
    debug_timer.event_batch_item_ref(format!("got {} nodes from DashMap", random_merkle_keys.len()), "node", random_merkle_keys.len());

    

    Ok(())
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {

    test_hashmap().await?;
    test_hashmap_u64().await?;

    Ok(())
}