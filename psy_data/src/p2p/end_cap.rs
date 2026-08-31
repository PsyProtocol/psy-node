//! EndCap input protocol limits and helpers.
//!
//! The recursive `SubmitUserEndCapNonProofInput` wire grammar is owned by
//! `psy_data` (conversion from domain types) but uses these frozen bounds and
//! `ProtocolEncode`/`ProtocolReader` primitives from this module so P2P hashing
//! never depends on serde/bincode/speedy/feature-gated memory layouts.

/// Maximum contract-state-update histories in one EndCap input.
pub const MAX_END_CAP_CONTRACT_HISTORIES: u32 = 4_096;

/// Maximum slot/IMT updates inside one contract history.
pub const MAX_END_CAP_UPDATES_PER_HISTORY: u32 = 65_536;

/// Maximum Merkle siblings in any proof carried by an EndCap input.
pub const MAX_END_CAP_MERKLE_SIBLINGS: u32 = 256;

/// Maximum user events in one EndCap input.
pub const MAX_END_CAP_EVENTS: u32 = 65_536;

/// Maximum felt words in one event `data` vector.
pub const MAX_END_CAP_EVENT_DATA_FELTS: u32 = 65_536;

/// Fixed core size without variable sections:
/// checkpoint_id(8) + GUTAStats(40) + PUPSEndCapResultCompact(136) + PQEDUserLeaf(104).
pub const END_CAP_CORE_FIXED_BYTES: usize = 8 + 40 + 136 + 104;
