use parth_common::secp256k1::get_public_key_for_secp256k1_private_key;
use parth_core::data::hash::hash256::Hash256;

pub fn get_public_key_for_private_key(private_key: &str) -> anyhow::Result<()> {
    let private_key_bytes = hex::decode(private_key)?;
    if private_key_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "Invalid private key length: expected 32 bytes, got {} bytes",
            private_key_bytes.len()
        ));
    }
    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&private_key_bytes);
    let hash256 = Hash256(pk_array);
    let public_key = get_public_key_for_secp256k1_private_key(hash256)?;
    println!("Public Key:\n{}", hex::encode(public_key.0));
    Ok(())
}



pub fn generate_keypair() -> anyhow::Result<()> {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut private_key_bytes = [0u8; 32];
    rng.fill_bytes(&mut private_key_bytes);
    let hash256 = Hash256(private_key_bytes);
    let public_key = get_public_key_for_secp256k1_private_key(hash256)?;
    println!("Private Key:\n{}", hex::encode(private_key_bytes));
    println!("Public Key:\n{}", hex::encode(public_key.0));
    Ok(())
}