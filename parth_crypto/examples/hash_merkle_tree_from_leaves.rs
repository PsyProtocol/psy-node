

use cf_utils::timer::DebugTimer;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::hash256::Hash256, pgoldilocks::PoseidonHasher, protocol::core_types::Q256BitHash, utils::QPGenRandom, PHash};
use rayon::{iter::ParallelIterator, slice::ParallelSlice};

/// Computes the Merkle root from a slice of leaves in an efficient, in-place manner.
///
/// This version avoids allocations within the loop by reusing a single vector,
/// making it significantly faster for trees with many leaves.
fn hash_merkle_from_leaves_2<Hash: PartialEq + Copy, Hasher: MerkleZeroHasher<Hash>>(
    leaves: Vec<Hash>
) -> anyhow::Result<Hash> {
    if leaves.is_empty() {
        // The loop condition `nodes.len() > 1` handles the `len == 1` case automatically.
        anyhow::bail!("Cannot compute Merkle root of zero leaves");
    }

    // Clone the leaves into a mutable vector. This is the *only* allocation.
    let mut nodes = leaves.to_vec();
    let mut level = 0;

    // Continue collapsing the tree until only the root hash remains.
    while nodes.len() > 1 {
        let num_nodes = nodes.len();
        let mut write_idx = 0;

        // Process nodes in pairs. The result of hash(nodes[2*i], nodes[2*i+1])
        // is written to nodes[i], effectively halving the vector size in place.
        for i in 0..(num_nodes / 2) {
            nodes[write_idx] = Hasher::two_to_one(&nodes[2 * i], &nodes[2 * i + 1]);
            write_idx += 1;
        }

        // If there's an odd number of nodes, hash the last one with a zero hash.
        if num_nodes % 2 == 1 {
            let last_node = nodes[num_nodes - 1]; // Important: read before potential overwrite
            let zero_hash = Hasher::get_zero_hash(level);
            nodes[write_idx] = Hasher::two_to_one(&last_node, &zero_hash);
            write_idx += 1;
        }

        // The vector now logically contains `write_idx` elements. Truncate it.
        nodes.truncate(write_idx);
        level += 1;
    }

    // The single remaining element is the Merkle root.
    Ok(nodes[0])
}



fn hash_tree_of_height(height: u8) -> anyhow::Result<()> {
    type Hash = PHash;
    let mut timer = DebugTimer::new("hash_leaves");
    let num_leaves = 1 << height;
    timer.event(format!("start with_capacity {} leaves", num_leaves));
    timer.event(format!("got with_capacity {} leaves", num_leaves));
    /* 
    for _ in 0..num_leaves {
        leaves.push(Hash::rand());
    }
    */

    let ot_leaves = Hash256::qp_rand_gen_vec(num_leaves).into_iter().map(|x| Hash::from_owned_32bytes(x.0)).collect::<Vec<_>>();
    timer.event(format!("generated {} leaves", num_leaves));
    
    let root = hash_merkle_from_leaves_2::<Hash, PoseidonHasher>(ot_leaves)?;
    let duration = timer.event(format!("hashed all {} leaves to root", num_leaves));
    let per_leaf = duration as f64 * 1000f64 as f64 / num_leaves as f64;
    println!("Time per leaf: {:.3} µs", per_leaf);
    println!("Merkle root for tree of height {}: {:?}", height, root);
    Ok(())
}


fn hash_tree_of_height_parallel(height: u8) -> anyhow::Result<()> {
    type Hash = PHash;
    let mut timer = DebugTimer::new("hash_leaves");
    //type Hasher = CoreSha256Hasher;
    let num_leaves = 1 << height;
    timer.event(format!("start with_capacity {} leaves", num_leaves));
    timer.event(format!("got with_capacity {} leaves", num_leaves));
    /* 
    for _ in 0..num_leaves {
        leaves.push(Hash::rand());
    }
    */

    let ot_leaves = Hash256::qp_rand_gen_vec(num_leaves).into_iter().map(|x| Hash::from_owned_32bytes(x.0)).collect::<Vec<_>>();
    ot_leaves.par_chunks(1024).for_each(|chunk| {
        let _ = hash_merkle_from_leaves_2::<Hash, PoseidonHasher>(chunk.to_vec());
    });
    timer.event(format!("generated {} leaves", num_leaves));
    
    let root = hash_merkle_from_leaves_2::<Hash, PoseidonHasher>(ot_leaves)?;
    let duration = timer.event(format!("hashed all {} leaves to root", num_leaves));
    let per_leaf = duration as f64 * 1000f64 as f64 / num_leaves as f64;
    println!("Time per leaf: {:.3} µs", per_leaf);
    println!("Merkle root for tree of height {}: {:?}", height, root);
    Ok(())
}

fn main(){
    hash_tree_of_height(24).unwrap();
    hash_tree_of_height_parallel(24).unwrap();


}