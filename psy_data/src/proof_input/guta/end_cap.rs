
#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyEndCapSimpleStandardInput<F, Hash> {
    pub guta_stats: GUTAStats<F>,
    pub checkpoint_root: Hash,
    pub checkpoint_historical_merkle_proof: MerkleProofCore<Hash>,
}


