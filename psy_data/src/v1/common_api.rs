#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Copy)]
pub struct APILatestCheckpointResponse {
    pub checkpoint_id: u64,
}
