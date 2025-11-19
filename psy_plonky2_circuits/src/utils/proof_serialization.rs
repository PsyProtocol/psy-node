use plonky2::plonk::{config::GenericConfig, proof::ProofWithPublicInputs};

pub fn serialize_plonky2_proof<C: GenericConfig<D>, const D: usize>(
    proof: &ProofWithPublicInputs<C::F, C, D>,
) -> anyhow::Result<Vec<u8>> {
    bincode::serialize(proof).map_err(|e| anyhow::anyhow!("Failed to serialize Plonky2 proof: {}", e))
}

pub fn deserialize_plonky2_proof<C: GenericConfig<D>, const D: usize>(
    data: &[u8],
) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
    bincode::deserialize(data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize Plonky2 proof: {}", e))
}
pub fn deserialize_plonky2_proofs<C: GenericConfig<D>, const D: usize>(
    data: &[Vec<u8>],
) -> anyhow::Result<Vec<ProofWithPublicInputs<C::F, C, D>>> {
    let mut proofs = Vec::with_capacity(data.len());
    for proof_data in data {
        let proof: ProofWithPublicInputs<C::F, C, D> = bincode::deserialize(proof_data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize Plonky2 proof: {}", e))?;
        proofs.push(proof);
    }
    Ok(proofs)
}

