use parth_core::{crypto::hash::{merkle_proof::generate_zero_hashes_code, sha256::CoreSha256Hasher, traits::{CodeSerializableHash, MerkleHasher, ZeroableHash}}, data::hash::hash256::Hash256};


fn run_zhg<Hash: PartialEq + CodeSerializableHash + ZeroableHash, Hasher: MerkleHasher<Hash>>() -> anyhow::Result<()> {
    

    let code = generate_zero_hashes_code::<Hash, Hasher>();
    println!("{}", code);
    Ok(())
}

fn main() {
    run_zhg::<Hash256, CoreSha256Hasher>().unwrap();
}