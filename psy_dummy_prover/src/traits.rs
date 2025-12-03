use async_trait::async_trait;
use psy_data::proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput;

pub trait DummyUPSProver<F, Hash> {
    fn prove_end_cap_dummy_ups(&self, global_user_tree_height: u8, input: &SubmitUserEndCapNonProofInput<F, Hash>) -> anyhow::Result<Vec<u8>>;
}
#[async_trait]
pub trait DummyUPSEndCapProverHelper<F, Hash> {
    async fn generate_proof_for_updates_and_submit(&self, user_id: u64, updates: &[(u32, u64, Hash)]) -> anyhow::Result<()>;
}
