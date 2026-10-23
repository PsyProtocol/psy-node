//! The Reader's in-memory model of the Envio deposit, claim and batch tables.
//!
//! Concurrency scheme (design section 14): each chain index's committed part
//! (`ChainData`) sits in an `Arc` behind a `parking_lot::RwLock` and only
//! grows. The writer appends under the write lock before it publishes a `View`
//! that covers the new rows; a view ignores every committed entry at or past
//! its own `committed_len`, so old views stay valid without a copy. The
//! window above the committed boundary is an immutable `Arc` rebuilt per
//! tick. Views are published whole through one `ArcSwap<View>`: a read loads
//! one `Arc<View>` and computes everything from it, so a response never mixes
//! two revisions.

mod apply;
mod chain;
mod claims;
mod query;
pub mod tick;

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use psy_bridge_reader_api::{DepositRow, EnvioChainStatus, FinalizedBatchRow, Revision, WithdrawalClaimRow};

use self::chain::{ChainData, RowIndex};
use self::claims::ClaimData;

pub use chain::ChainView;
pub use claims::ClaimChainView;
pub use tick::{ChainProgress, Cursors, DepositCursor, DepositWithLeaf, Identity, TickData, TreeMetaRow};

/// One immutable published state of every chain.
pub struct View {
    pub(crate) revision: Revision,
    /// `Err(reason)` until the first verified, untruncated tick, and after a
    /// full reset.
    pub(crate) ready: Result<(), String>,
    /// Keyed by chain_index.
    pub(crate) chains: BTreeMap<u64, ChainView>,
    /// Keyed by chain_id.
    pub(crate) claim_chains: BTreeMap<u64, ClaimChainView>,
    /// Keyed by chain_id.
    pub(crate) envio_chains: BTreeMap<u64, EnvioChainStatus>,
}

impl View {
    fn empty(revision: Revision, reason: &str) -> View {
        View {
            revision,
            ready: Err(reason.to_owned()),
            chains: BTreeMap::new(),
            claim_chains: BTreeMap::new(),
            envio_chains: BTreeMap::new(),
        }
    }

    pub fn revision(&self) -> &Revision {
        &self.revision
    }
}

/// What one `Model::apply` did.
#[derive(Debug, Clone, PartialEq)]
pub enum ApplyOutcome {
    /// A new view is published; `reorged` lists the chain indexes whose window
    /// changed other than by extension.
    Published { reorged: Vec<u64> },
    /// Nothing changed; the view stays.
    Unchanged,
    /// The read was truncated: safe rows were committed, the view stays.
    CatchingUp,
    /// The model cannot follow this state; the caller resets and reloads.
    Reload(ReloadReason),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ReloadReason {
    IdentityChanged,
    ProgressBelowCommitted { chain_id: u64 },
    InvariantViolated { chain_index: u64, what: String },
    TreeMismatch { chain_index: u64 },
    /// A chain index with committed deposits has no `DepositTreeMeta` row.
    MetaMissing { chain_index: u64 },
    WindowOverLimit,
}

impl fmt::Display for ReloadReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReloadReason::IdentityChanged => write!(f, "the Envio schema identity changed"),
            ReloadReason::ProgressBelowCommitted { chain_id } => {
                write!(f, "Envio progress of chain_id {chain_id} is below the committed safe block")
            }
            ReloadReason::InvariantViolated { chain_index, what } => {
                write!(f, "chain_index {chain_index} violates an invariant: {what}")
            }
            ReloadReason::TreeMismatch { chain_index } => {
                write!(f, "chain_index {chain_index} tree does not match Envio's DepositTreeMeta")
            }
            ReloadReason::MetaMissing { chain_index } => {
                write!(f, "chain_index {chain_index} has committed deposits but no DepositTreeMeta row")
            }
            ReloadReason::WindowOverLimit => write!(f, "the unsafe window is above the follow row limit"),
        }
    }
}

/// A read that returns no data. Not-found is data, never a `ReadError`.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ReadError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("not ready: {0}")]
    NotReady(String),
    #[error("count {count} is above the {indexed} indexed deposits")]
    CountNotIndexed { count: u64, indexed: u64 },
    #[error("internal: {0}")]
    Internal(String),
}

/// One chain index as the writer holds it.
struct ChainState {
    data: Arc<ChainData>,
    /// Set by the first row seen (C8).
    chain_id: Option<u64>,
    /// Set when the chain fails, with the not-ready reason its views carry;
    /// cleared only by a reset.
    fault: Option<(ReloadReason, String)>,
}

impl ChainState {
    fn new(chain_id: Option<u64>) -> Self {
        ChainState { data: Arc::new(ChainData::default()), chain_id, fault: None }
    }

    fn cursor(&self) -> DepositCursor {
        let committed = self.data.committed.read();
        DepositCursor {
            local_count: committed.len(),
            next_deposit_index: committed.deposits.last().map_or(0, |d| d.deposit_index + 1),
        }
    }
}

/// The writer side: the committed parts, the cursors, and the published view.
/// One task owns it and calls `apply` once per tick.
pub struct Model {
    identity: Option<Identity>,
    epoch: u64,
    seq: u64,
    /// Keyed by chain_index.
    chains: BTreeMap<u64, ChainState>,
    /// Keyed by chain_id.
    claim_chains: BTreeMap<u64, Arc<ClaimData>>,
    /// Keyed by chain_id. Rows at or below it are committed.
    committed_safe_blocks: BTreeMap<u64, i64>,
    view: Arc<ArcSwap<View>>,
}

const STARTING: &str = "no verified tick yet";
const RELOADING: &str = "reloading";

impl Model {
    pub fn new() -> Model {
        let revision = Revision { epoch: 0, seq: 0, as_of_unix_ms: 0 };
        Model {
            identity: None,
            epoch: 0,
            seq: 0,
            chains: BTreeMap::new(),
            claim_chains: BTreeMap::new(),
            committed_safe_blocks: BTreeMap::new(),
            view: Arc::new(ArcSwap::from_pointee(View::empty(revision, STARTING))),
        }
    }

    /// An estimate of the model's own structures, in bytes: the capacity of
    /// every row string, 32 bytes per leaf hash and per stored upper node, and
    /// 16 bytes per index entry, over the committed parts and the current
    /// window. Process RSS is exported separately. Nothing is cached; call it
    /// once per tick.
    pub fn resident_bytes_estimate(&self) -> u64 {
        const HASH: u64 = 32;
        const INDEX_ENTRY: u64 = 16;
        fn deposits(rows: &[DepositRow]) -> u64 {
            rows.iter()
                .map(|r| {
                    [&r.id, &r.shield_address, &r.token, &r.l2_token_contract_id, &r.amount, &r.note_commitment, &r.leaf_hash, &r.tx_hash]
                        .iter()
                        .map(|s| s.capacity() as u64)
                        .sum::<u64>()
                })
                .sum()
        }
        fn claims(rows: &[WithdrawalClaimRow]) -> u64 {
            rows.iter()
                .map(|r| [&r.id, &r.nullifier, &r.recipient, &r.token, &r.amount, &r.tx_hash].iter().map(|s| s.capacity() as u64).sum::<u64>())
                .sum()
        }
        fn batches(rows: &[FinalizedBatchRow]) -> u64 {
            rows.iter()
                .map(|r| {
                    [&r.id, &r.finalized_checkpoint_id, &r.deposit_tree_root, &r.withdrawal_tree_root, &r.tx_hash]
                        .iter()
                        .map(|s| s.capacity() as u64)
                        .sum::<u64>()
                })
                .sum()
        }
        fn entries(index: &RowIndex) -> u64 {
            index.values().map(|v| v.len() as u64).sum::<u64>() * INDEX_ENTRY
        }
        let mut total = 0u64;
        for state in self.chains.values() {
            let c = state.data.committed.read();
            total += deposits(&c.deposits) + c.leaves.len() as u64 * HASH + c.upper.node_count() as u64 * HASH;
            total += entries(&c.by_address) + entries(&c.by_tx);
        }
        for data in self.claim_chains.values() {
            let c = data.committed.read();
            total += claims(&c.claims) + batches(&c.batches) + entries(&c.by_nullifier);
        }
        let view = self.view.load();
        for chain in view.chains.values() {
            let w = &chain.window;
            total += deposits(&w.deposits) + w.leaves.len() as u64 * HASH + w.nodes.len() as u64 * HASH;
            total += entries(&w.by_address) + entries(&w.by_tx);
        }
        for chain in view.claim_chains.values() {
            let w = &chain.window;
            total += claims(&w.claims) + batches(&w.batches) + entries(&w.by_nullifier);
        }
        total
    }

    /// The committed boundaries the next read starts from.
    pub fn cursors(&self) -> Cursors {
        let deposits = self.chains.iter().map(|(ci, s)| (*ci, s.cursor())).collect();
        let mut claims = BTreeMap::new();
        let mut batches = BTreeMap::new();
        for (chain_id, data) in &self.claim_chains {
            let committed = data.committed.read();
            if let Some(c) = committed.claims.last() {
                claims.insert(*chain_id, (c.block_number, c.id.clone()));
            }
            if let Some(b) = committed.batches.last() {
                batches.insert(*chain_id, (b.block_number, b.id.clone()));
            }
        }
        Cursors { deposits, claims, batches }
    }

    pub fn view(&self) -> Arc<View> {
        self.view.load_full()
    }

    /// The handle the server reads views from.
    pub fn view_handle(&self) -> Arc<ArcSwap<View>> {
        self.view.clone()
    }

    /// Drops one chain index's rows; it is not ready until a later tick loads
    /// and verifies it again. Views already taken keep the old rows.
    pub fn reset_chain(&mut self, chain_index: u64) {
        let chain_id = self.chains.get(&chain_index).and_then(|s| s.chain_id);
        let state = ChainState::new(chain_id);
        let placeholder = ChainView::not_ready(state.data.clone(), chain_id, RELOADING.to_owned());
        self.chains.insert(chain_index, state);
        let old = self.view.load_full();
        let mut chains = old.chains.clone();
        chains.insert(chain_index, placeholder);
        self.epoch += 1;
        let revision = self.next_revision(old.revision.as_of_unix_ms);
        self.publish(View {
            revision,
            ready: old.ready.clone(),
            chains,
            claim_chains: old.claim_chains.clone(),
            envio_chains: old.envio_chains.clone(),
        });
    }

    /// Drops everything, including the identity; nothing is ready until a
    /// later tick loads and verifies it again.
    pub fn reset_all(&mut self) {
        self.identity = None;
        self.chains.clear();
        self.claim_chains.clear();
        self.committed_safe_blocks.clear();
        self.epoch += 1;
        let as_of = self.view.load().revision.as_of_unix_ms;
        let revision = self.next_revision(as_of);
        self.publish(View::empty(revision, RELOADING));
    }

    /// Advances `seq` and returns the revision of the next publish.
    fn next_revision(&mut self, as_of_unix_ms: u64) -> Revision {
        self.seq += 1;
        Revision { epoch: self.epoch, seq: self.seq, as_of_unix_ms }
    }

    fn publish(&self, view: View) {
        self.view.store(Arc::new(view));
    }
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}
