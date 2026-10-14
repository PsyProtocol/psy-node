pub mod bridge_agg;
pub mod bridge_agg_chain;
pub mod bridge_agg_final;
#[cfg(all(feature = "gnark-wrap", not(target_arch = "wasm32")))]
pub mod bridge_wrap;
pub mod historical_merkle_proof;
pub mod reward_claim_wrap;
pub mod user_reward_tree;
pub mod user_reward_checkpoint_aggregate;
pub use user_reward_checkpoint_aggregate::{
    UserRewardCheckpointAggregateCircuit, UserRewardCheckpointAggregateProof,
    UserRewardCheckpointAggregateTargets, UserRewardCheckpointAggregateWitness,
    REWARD_CLAIM_MAX_CHECKPOINTS,
    USER_REWARD_CHECKPOINT_AGGREGATE_PUBLIC_INPUT_COUNT,
    USER_REWARD_CHECKPOINT_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT,
    USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT,
};

pub use bridge_agg::BridgeAggProveResult;
pub use bridge_agg_chain::{BridgeAggChainBoundary, BridgeAggChainCircuit, BridgeAggChainSlotWitness, BRIDGE_AGG_CHAIN_MAX_SLOTS, BRIDGE_AGG_CHAIN_PI_LEN};
pub use bridge_agg_final::{BridgeAggFinalCircuit, BRIDGE_AGG_FINAL_PI_LEN};
