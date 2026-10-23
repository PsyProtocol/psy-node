//! The read functions behind every API endpoint. Each one reads one `View`
//! only, so a response never mixes two revisions, and a root or proof uses
//! exactly that view's leaves.
//!
//! Not found is data. A chain index or chain_id the view does not know, once
//! the view is ready, has no rows, count 0 and root `zero(32)`. A known chain
//! that is not ready answers `NotReady`.

use psy_bridge_reader_api::{
    ChainStatus, ClaimProofQuery, ClaimProofResponse, DepositByIndexQuery, DepositByIndexResponse, DepositProof, DepositRow,
    DepositsByAddressQuery, DepositsByAddressResponse, DepositsByTxQuery, DepositsByTxResponse, EnvioChainStatus, ExplorerQuery,
    ExplorerResponse,
    FinalizedBatchRow, PrefixQuery, PrefixResponse, StatusResponse, TreeRootQuery, TreeRootResponse, WithdrawalClaimsRequest,
    WithdrawalClaimsResponse, FEED_LEN, MAX_BY_TX, MAX_NULLIFIERS, MAX_PAGE,
};

use super::chain::{ChainRead, ChainView};
use super::claims::ClaimChainView;
use super::{ReadError, View};
use crate::tree::hash::{to_display_hex, zero, Hash};
use crate::tree::snapshot::{proof_at, root_at, TreeError};

fn internal(e: TreeError) -> ReadError {
    ReadError::Internal(e.to_string())
}

fn not_indexed(count: u64, indexed: u64) -> Result<(), ReadError> {
    if count > indexed {
        return Err(ReadError::CountNotIndexed { count, indexed });
    }
    Ok(())
}

/// The explorer order: `(block_number desc, id desc)`.
fn newest_first(a: (u64, &str), b: (u64, &str)) -> std::cmp::Ordering {
    b.0.cmp(&a.0).then_with(|| b.1.cmp(a.1))
}

/// The newest `FEED_LEN` of a sequence ordered by block, from its tail: rows
/// are taken until `FEED_LEN` are held and the block falls below the block of
/// the last one held, so a block that straddles the cut is taken whole.
fn feed_candidates<'a, T: 'a>(len: usize, at: impl Fn(usize) -> &'a T, block: impl Fn(&T) -> u64) -> Vec<&'a T> {
    let mut out: Vec<&T> = Vec::new();
    for i in (0..len).rev() {
        let row = at(i);
        if out.len() >= FEED_LEN && block(row) < block(out[FEED_LEN - 1]) {
            break;
        }
        out.push(row);
    }
    out
}

impl View {
    fn require_ready(&self) -> Result<(), ReadError> {
        self.ready.clone().map_err(ReadError::NotReady)
    }

    /// The chain index, `None` if the view does not know it.
    fn chain(&self, chain_index: u64) -> Result<Option<&ChainView>, ReadError> {
        self.require_ready()?;
        let Some(chain) = self.chains.get(&chain_index) else { return Ok(None) };
        chain.ready.clone().map_err(ReadError::NotReady)?;
        Ok(Some(chain))
    }

    /// Every chain index of `chain_id`. A not-ready chain whose chain_id is not
    /// known yet may belong to it, so it makes the answer not ready too.
    fn chains_of(&self, chain_id: u64) -> Result<Vec<(u64, &ChainView)>, ReadError> {
        self.require_ready()?;
        let mut out = Vec::new();
        for (&chain_index, chain) in &self.chains {
            match (chain.chain_id, &chain.ready) {
                (Some(id), _) if id != chain_id => {}
                (None, Ok(())) => {}
                (_, Err(reason)) => return Err(ReadError::NotReady(reason.clone())),
                (Some(_), Ok(())) => out.push((chain_index, chain)),
            }
        }
        Ok(out)
    }

    fn claim_chain(&self, chain_id: u64) -> Result<Option<&ClaimChainView>, ReadError> {
        self.require_ready()?;
        let Some(chain) = self.claim_chains.get(&chain_id) else { return Ok(None) };
        chain.ready.clone().map_err(ReadError::NotReady)?;
        Ok(Some(chain))
    }

    /// Ordered by `(deposit_index, chain_index)` asc; `total` is exact.
    pub fn deposits_by_address(&self, q: &DepositsByAddressQuery) -> Result<DepositsByAddressResponse, ReadError> {
        if !(1..=MAX_PAGE).contains(&q.limit) {
            return Err(ReadError::BadRequest(format!("limit {} is outside 1..={MAX_PAGE}", q.limit)));
        }
        let chains = match q.chain_index {
            Some(chain_index) => {
                self.chain(chain_index)?.filter(|c| c.chain_id == Some(q.chain_id)).map(|c| vec![(chain_index, c)]).unwrap_or_default()
            }
            None => self.chains_of(q.chain_id)?,
        };
        let reads = chains.iter().map(|(ci, c)| (*ci, c.read())).collect::<Vec<_>>();
        let lists = reads.iter().map(|(_, r)| r.address(&q.shield_address)).collect::<Vec<_>>();
        let key = |l: usize, k: usize| (reads[l].1.row(lists[l].get(k)).deposit_index, reads[l].0);
        let total = lists.iter().map(|p| p.len() as u64).sum::<u64>();
        let mut rows = Vec::new();
        if q.offset < total {
            let end = total.min(q.offset + u64::from(q.limit));
            let mut next = vec![0usize; lists.len()];
            for merged in 0..end {
                let l = (0..lists.len()).filter(|l| next[*l] < lists[*l].len()).min_by_key(|l| key(*l, next[*l])).expect("rows remain");
                if merged >= q.offset {
                    rows.push(reads[l].1.row(lists[l].get(next[l])).clone());
                }
                next[l] += 1;
            }
        }
        let last = (0..lists.len()).filter_map(|l| lists[l].len().checked_sub(1).map(|k| key(l, k))).max();
        let epoch = self.revision.epoch;
        let list_tag = match last {
            Some((deposit_index, _)) => format!("{epoch}-{total}-{deposit_index}"),
            None => format!("{epoch}-0-none"),
        };
        Ok(DepositsByAddressResponse { revision: self.revision.clone(), total, list_tag, rows })
    }

    pub fn deposit_by_index(&self, q: &DepositByIndexQuery) -> Result<DepositByIndexResponse, ReadError> {
        let deposit = self.chain(q.chain_index)?.filter(|c| c.chain_id == Some(q.chain_id)).and_then(|c| {
            let r = c.read();
            r.find_deposit_index(q.deposit_index).map(|i| r.row(i).clone())
        });
        Ok(DepositByIndexResponse { revision: self.revision.clone(), deposit })
    }

    /// Ordered by `deposit_index` desc, at most `MAX_BY_TX` rows.
    pub fn deposits_by_tx(&self, q: &DepositsByTxQuery) -> Result<DepositsByTxResponse, ReadError> {
        let rows = match self.chain(q.chain_index)? {
            None => Vec::new(),
            Some(c) => {
                let r = c.read();
                let positions = r.tx(&q.tx_hash);
                (0..positions.len()).rev().take(MAX_BY_TX).map(|k| r.row(positions.get(k)).clone()).collect()
            }
        };
        Ok(DepositsByTxResponse { revision: self.revision.clone(), rows })
    }

    pub fn prefix(&self, q: &PrefixQuery) -> Result<PrefixResponse, ReadError> {
        let (chain_local_count, has_foreign_deposits) = self.resolve_prefix(q.chain_index, q.chain_id, q.target_deposit_count)?;
        Ok(PrefixResponse { revision: self.revision.clone(), chain_local_count, has_foreign_deposits })
    }

    /// This chain's deposits with `deposit_index < target`, and whether another
    /// chain index of `chain_id` has a first deposit below `target`.
    fn resolve_prefix(&self, chain_index: u64, chain_id: u64, target: u64) -> Result<(u64, bool), ReadError> {
        let count = match self.chain(chain_index)? {
            Some(c) if c.chain_id == Some(chain_id) => c.read().count_below(target),
            _ => 0,
        };
        let foreign = self.chains_of(chain_id)?.iter().filter(|(other, _)| *other != chain_index).any(|(_, c)| {
            let r = c.read();
            r.len() > 0 && r.row(0).deposit_index < target
        });
        Ok((count, foreign))
    }

    /// The chain-local count of a tree query: `count`, or `target` resolved
    /// through the prefix probe in this view.
    fn resolve_count(
        &self,
        chain_index: u64,
        count: Option<u64>,
        target: Option<u64>,
        chain_id: Option<u64>,
    ) -> Result<(u64, bool), ReadError> {
        match (count, target) {
            (Some(n), None) => Ok((n, false)),
            (None, Some(target)) => {
                let chain_id = chain_id.ok_or_else(|| ReadError::BadRequest("target_deposit_count needs chain_id".to_owned()))?;
                self.resolve_prefix(chain_index, chain_id, target)
            }
            _ => Err(ReadError::BadRequest("give exactly one of count or target_deposit_count".to_owned())),
        }
    }

    pub fn withdrawal_claims(&self, q: &WithdrawalClaimsRequest) -> Result<WithdrawalClaimsResponse, ReadError> {
        if q.nullifiers.len() > MAX_NULLIFIERS {
            return Err(ReadError::BadRequest(format!("{} nullifiers, at most {MAX_NULLIFIERS}", q.nullifiers.len())));
        }
        let mut claims = Vec::new();
        if let Some(c) = self.claim_chain(q.chain_id)? {
            let r = c.read();
            let mut seen = std::collections::HashSet::new();
            for nullifier in q.nullifiers.iter().filter(|n| seen.insert(n.as_str())) {
                claims.extend(r.by_nullifier(nullifier).cloned());
            }
        }
        Ok(WithdrawalClaimsResponse { revision: self.revision.clone(), claims })
    }

    /// Root at a chain-local count; a count above the indexed deposits is
    /// `CountNotIndexed`, never a root over fewer leaves.
    pub fn tree_root(&self, q: &TreeRootQuery) -> Result<TreeRootResponse, ReadError> {
        let (count, has_foreign_deposits) = self.resolve_count(q.chain_index, q.count, q.target_deposit_count, q.chain_id)?;
        let root = match self.chain(q.chain_index)? {
            None => {
                not_indexed(count, 0)?;
                zero(32)
            }
            Some(c) => {
                let r = c.read();
                not_indexed(count, r.len())?;
                root_at(&r.tree(), count).map_err(internal)?
            }
        };
        Ok(TreeRootResponse {
            revision: self.revision.clone(),
            chain_local_count: count,
            has_foreign_deposits,
            root: to_display_hex(&root),
        })
    }

    /// The deposit and its proof at a count. `proof` is `None` when the deposit
    /// is absent or its leaf is not below the count.
    pub fn claim_proof(&self, q: &ClaimProofQuery) -> Result<ClaimProofResponse, ReadError> {
        match (q.leaf, q.deposit_index, q.chain_id) {
            (Some(_), None, _) | (None, Some(_), Some(_)) => {}
            (None, Some(_), None) => return Err(ReadError::BadRequest("deposit_index needs chain_id".to_owned())),
            _ => return Err(ReadError::BadRequest("give exactly one of leaf or deposit_index".to_owned())),
        }
        let (count, has_foreign_deposits) = self.resolve_count(q.chain_index, q.count, q.target_deposit_count, q.chain_id)?;
        let (deposit, proof) = match self.chain(q.chain_index)? {
            None => {
                not_indexed(count, 0)?;
                (None, None)
            }
            Some(c) => {
                let r = c.read();
                not_indexed(count, r.len())?;
                let leaf = match (q.leaf, q.deposit_index) {
                    (Some(leaf), _) => (leaf < r.len()).then_some(leaf),
                    (None, Some(deposit_index)) if c.chain_id == q.chain_id => r.find_deposit_index(deposit_index),
                    _ => None,
                };
                let proof = match leaf.filter(|leaf| *leaf < count) {
                    Some(leaf) => Some(deposit_proof(&r, leaf, count)?),
                    None => None,
                };
                (leaf.map(|leaf| r.row(leaf).clone()), proof)
            }
        };
        Ok(ClaimProofResponse { revision: self.revision.clone(), chain_local_count: count, has_foreign_deposits, deposit, proof })
    }

    /// The newest `FEED_LEN` deposits of every chain index of the chain_id and
    /// the newest `FEED_LEN` batches, each `(block_number desc, id desc)`.
    pub fn explorer(&self, q: &ExplorerQuery) -> Result<ExplorerResponse, ReadError> {
        let chains = self.chains_of(q.chain_id)?;
        let claim_chain = self.claim_chain(q.chain_id)?;
        let reads = chains.iter().map(|(_, c)| c.read()).collect::<Vec<ChainRead<'_>>>();
        let mut deposits: Vec<&DepositRow> = Vec::new();
        for r in &reads {
            deposits.extend(feed_candidates(r.len() as usize, |i| r.row(i as u64), |d: &DepositRow| d.block_number));
        }
        deposits.sort_by(|a, b| newest_first((a.block_number, &a.id), (b.block_number, &b.id)));
        let deposits = deposits.into_iter().take(FEED_LEN).cloned().collect();
        let batches = match claim_chain {
            None => Vec::new(),
            Some(c) => {
                let r = c.read();
                let mut batches = feed_candidates(c.batches_len(), |i| r.batch(i), |b: &FinalizedBatchRow| b.block_number);
                batches.sort_by(|a, b| newest_first((a.block_number, &a.id), (b.block_number, &b.id)));
                batches.into_iter().take(FEED_LEN).cloned().collect()
            }
        };
        Ok(ExplorerResponse { revision: self.revision.clone(), deposits, batches })
    }

    /// Never fails: it reports readiness instead.
    pub fn status(&self) -> StatusResponse {
        let view_reason = self.ready.as_ref().err();
        let chains = self
            .chains
            .iter()
            .map(|(&chain_index, c)| {
                let reason = view_reason.or(c.ready.as_ref().err()).cloned();
                ChainStatus {
                    chain_index,
                    chain_id: c.chain_id.unwrap_or(0),
                    ready: reason.is_none(),
                    not_ready_reason: reason,
                    deposit_count: c.total(),
                    committed_count: c.committed_len,
                    envio_tree_count: c.meta.map_or(0, |m| m.last_count),
                    envio_tree_root: to_display_hex(&c.meta.map_or_else(|| zero(32), |m| m.root)),
                    tree_root: to_display_hex(&c.tree_root),
                    last_verified_unix_ms: c.last_verified_unix_ms,
                }
            })
            .collect::<Vec<_>>();
        // Recomputed here: a chain can go not ready after the tick that wrote
        // these statuses.
        let envio_chains = self
            .envio_chains
            .values()
            .map(|e| {
                let deposits_ready = self.chains.values().filter(|c| c.chain_id == Some(e.chain_id)).all(|c| c.ready.is_ok());
                let claims_ready = self.claim_chains.get(&e.chain_id).is_some_and(|c| c.ready.is_ok());
                EnvioChainStatus { ready: view_reason.is_none() && deposits_ready && claims_ready, ..e.clone() }
            })
            .collect::<Vec<_>>();
        let ready = view_reason.is_none() && chains.iter().all(|c| c.ready) && envio_chains.iter().all(|c| c.ready);
        StatusResponse { revision: self.revision.clone(), ready, chains, envio_chains }
    }
}

fn deposit_proof(r: &ChainRead<'_>, leaf: u64, count: u64) -> Result<DepositProof, ReadError> {
    let proof = proof_at(&r.tree(), leaf, count).map_err(internal)?;
    let hex = |h: &Hash| to_display_hex(h);
    Ok(DepositProof {
        leaf_index: leaf,
        leaf_hash: hex(&proof.leaf),
        siblings: proof.siblings.iter().map(hex).collect(),
        root: hex(&proof.root),
    })
}

#[cfg(test)]
mod tests {
    use psy_bridge_reader_api::{
        ClaimProofQuery, DepositByIndexQuery, DepositRow, DepositsByAddressQuery, ExplorerQuery, FinalizedBatchRow, PrefixQuery,
        TreeRootQuery, WithdrawalClaimsRequest,
    };

    use crate::model::{ApplyOutcome, Model, ReadError, View};
    use crate::test_support::{naive_root, naive_siblings, TickBuilder};
    use crate::tree::hash::{to_display_hex, zero};

    fn ready_model(b: &TickBuilder) -> Model {
        let mut m = Model::new();
        assert!(matches!(b.apply_to(&mut m), ApplyOutcome::Published { .. }));
        m
    }

    fn address(shield_address: &str, chain_index: Option<u64>, limit: u32, offset: u64) -> DepositsByAddressQuery {
        DepositsByAddressQuery { shield_address: shield_address.to_owned(), chain_id: 1, chain_index, limit, offset }
    }

    fn tree_root(chain_index: u64, count: Option<u64>, target: Option<u64>, chain_id: Option<u64>) -> TreeRootQuery {
        TreeRootQuery { chain_index, count, target_deposit_count: target, chain_id }
    }

    fn prefix(v: &View, chain_index: u64, target: u64) -> (u64, bool) {
        let r = v.prefix(&PrefixQuery { chain_index, chain_id: 1, target_deposit_count: target }).unwrap();
        (r.chain_local_count, r.has_foreign_deposits)
    }

    #[test]
    fn root_above_indexed_count_is_an_error() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for block in [10, 11, 95, 96, 97] {
            b.deposit(0, 1, block, "A");
        }
        let v = ready_model(&b).view();
        assert_eq!(v.tree_root(&tree_root(0, Some(6), None, None)), Err(ReadError::CountNotIndexed { count: 6, indexed: 5 }));
        let r = v.tree_root(&tree_root(0, Some(5), None, None)).unwrap();
        assert_eq!(r.root, to_display_hex(&naive_root(&b.leaves(0), 5)));
        assert_eq!(r.chain_local_count, 5);
    }

    #[test]
    fn address_list_without_chain_index_merges_by_deposit_index_then_chain_index() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for (chain_index, deposit_index, shield) in [(0, 1, "A"), (1, 2, "A"), (1, 3, "A"), (0, 4, "A"), (0, 5, "A"), (1, 5, "A"), (0, 6, "B")] {
            b.deposit_at(chain_index, 1, deposit_index, 90 + deposit_index, shield);
        }
        let v = ready_model(&b).view();
        let r = v.deposits_by_address(&address("A", None, 1000, 0)).unwrap();
        let order = r.rows.iter().map(|d| (d.deposit_index, d.chain_index)).collect::<Vec<_>>();
        assert_eq!(order, vec![(1, 0), (2, 1), (3, 1), (4, 0), (5, 0), (5, 1)]);
        assert_eq!(r.total, 6);
        let page = v.deposits_by_address(&address("A", None, 3, 2)).unwrap();
        assert_eq!(page.rows, r.rows[2..5].to_vec());
        assert_eq!(page.total, 6);
        let one = v.deposits_by_address(&address("A", Some(1), 1000, 0)).unwrap();
        assert_eq!(one.rows.iter().map(|d| d.deposit_index).collect::<Vec<_>>(), vec![2, 3, 5]);
    }

    #[test]
    fn offset_beyond_total_returns_no_rows_and_the_real_total() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for block in [10, 95, 96] {
            b.deposit(0, 1, block, "A");
        }
        let v = ready_model(&b).view();
        for q in [address("A", Some(0), 10, 3), address("A", Some(0), 10, 1_000_000), address("A", None, 10, 3)] {
            let r = v.deposits_by_address(&q).unwrap();
            assert!(r.rows.is_empty());
            assert_eq!(r.total, 3);
        }
        for limit in [0, 1001] {
            assert!(matches!(v.deposits_by_address(&address("A", Some(0), limit, 0)), Err(ReadError::BadRequest(_))));
        }
    }

    #[test]
    fn list_tag_changes_only_when_the_address_result_changes() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        b.deposit(0, 1, 95, "A");
        b.deposit(0, 1, 96, "A");
        let mut m = ready_model(&b);
        let tag = |m: &Model, shield: &str| m.view().deposits_by_address(&address(shield, None, 10, 0)).unwrap().list_tag;
        let epoch = m.view().revision.epoch;
        assert_eq!(tag(&m, "A"), format!("{epoch}-2-1"));
        assert_eq!(tag(&m, "C"), format!("{epoch}-0-none"));
        let seq = m.view().revision.seq;
        b.deposit(0, 1, 97, "B");
        b.apply_to(&mut m);
        assert_eq!(m.view().revision.seq, seq + 1);
        assert_eq!(tag(&m, "A"), format!("{epoch}-2-1"));
        b.deposit(0, 1, 98, "A");
        b.apply_to(&mut m);
        assert_eq!(tag(&m, "A"), format!("{epoch}-3-3"));
    }

    #[test]
    fn prefix_probe_counts_and_detects_foreign_chain_indexes() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8).progress(2, 100, 8);
        for (chain_index, chain_id, deposit_index) in [(0, 1, 0), (0, 1, 1), (0, 1, 2), (1, 1, 3), (1, 1, 4), (2, 2, 0)] {
            b.deposit_at(chain_index, chain_id, deposit_index, 50 + deposit_index, "A");
        }
        let v = ready_model(&b).view();
        assert_eq!(prefix(&v, 0, 2), (2, false));
        assert_eq!(prefix(&v, 0, 3), (3, false));
        assert_eq!(prefix(&v, 0, 4), (3, true));
        assert_eq!(prefix(&v, 1, 4), (1, true));
        assert_eq!(prefix(&v, 1, 0), (0, false));
        // Chain index 2 is on chain_id 2: no deposits of chain_id 1, and never foreign to it.
        assert_eq!(prefix(&v, 2, 10), (0, true));
        // A chain index the view does not know is empty data.
        assert_eq!(prefix(&v, 9, 10), (0, true));
    }

    #[test]
    fn claim_proof_by_global_index_matches_the_reference() {
        // Chain index 0 holds even deposit indexes, chain index 1 odd ones.
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for local in 0..1100u64 {
            b.deposit_at(0, 1, 2 * local, if local < 1000 { 10 } else { 95 }, "A");
        }
        for local in 0..5u64 {
            b.deposit_at(1, 1, 2 * local + 1, 10, "B");
        }
        let v = ready_model(&b).view();
        let leaves = b.leaves(0);
        let q = ClaimProofQuery {
            chain_index: 0,
            leaf: None,
            deposit_index: Some(1400),
            chain_id: Some(1),
            count: None,
            target_deposit_count: Some(2101),
        };
        let r = v.claim_proof(&q).unwrap();
        assert_eq!(r.chain_local_count, 1051);
        assert!(r.has_foreign_deposits);
        assert_eq!(r.deposit, Some(b.rows(0)[700].clone()));
        let proof = r.proof.unwrap();
        assert_eq!(proof.leaf_index, 700);
        assert_eq!(proof.leaf_hash, to_display_hex(&leaves[700]));
        assert_eq!(proof.siblings, naive_siblings(&leaves, 700, 1051).iter().map(to_display_hex).collect::<Vec<_>>());
        assert_eq!(proof.root, to_display_hex(&naive_root(&leaves, 1051)));
        // A leaf at or above the count: the deposit, no proof.
        let r = v.claim_proof(&ClaimProofQuery { deposit_index: Some(2120), ..q.clone() }).unwrap();
        assert_eq!(r.deposit, Some(b.rows(0)[1060].clone()));
        assert_eq!(r.proof, None);
        // Absent deposit: neither.
        let r = v.claim_proof(&ClaimProofQuery { deposit_index: Some(1401), ..q.clone() }).unwrap();
        assert_eq!((r.deposit, r.proof), (None, None));
        // A window leaf by chain-local index at the full count.
        let q = ClaimProofQuery { leaf: Some(1099), deposit_index: None, count: Some(1100), target_deposit_count: None, ..q };
        let proof = v.claim_proof(&q).unwrap().proof.unwrap();
        assert_eq!(proof.siblings, naive_siblings(&leaves, 1099, 1100).iter().map(to_display_hex).collect::<Vec<_>>());
    }

    #[test]
    fn explorer_orders_by_block_desc_then_id_desc_and_caps_at_100() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        // Three deposits per block on chain index 0; the block of deposit
        // indexes 99, 100 and 101 straddles the cut, and "1-99" sorts above
        // "1-101" and "1-100".
        for deposit_index in 50..200u64 {
            b.deposit_at(0, 1, deposit_index, 10 + (deposit_index - 48) / 3, "A");
        }
        for k in 0..40u64 {
            b.deposit_at(1, 1, 1000 + k, 40 + k, "B");
        }
        for checkpoint in 0..130u64 {
            b.batch(1, 10 + checkpoint / 4, checkpoint);
        }
        let v = ready_model(&b).view();
        let r = v.explorer(&ExplorerQuery { chain_id: 1 }).unwrap();
        let mut deposits = b.rows(0).into_iter().chain(b.rows(1)).collect::<Vec<DepositRow>>();
        deposits.sort_by(|x, y| (y.block_number, &y.id).cmp(&(x.block_number, &x.id)));
        deposits.truncate(100);
        assert_eq!(r.deposits, deposits);
        let mut batches = b.batches[&1].clone();
        batches.sort_by(|x, y| (y.block_number, &y.id).cmp(&(x.block_number, &x.id)));
        batches.truncate(100);
        assert_eq!(r.batches, batches);
        assert_eq!((r.deposits.len(), r.batches.len()), (100, 100));
        // Chain index 0 alone: the straddling block contributes 99 and 101, not 100.
        let mut only = TickBuilder::new();
        only.progress(1, 100, 8);
        for deposit_index in 50..200u64 {
            only.deposit_at(0, 1, deposit_index, 10 + (deposit_index - 48) / 3, "A");
        }
        let r = ready_model(&only).view().explorer(&ExplorerQuery { chain_id: 1 }).unwrap();
        let tail = r.deposits[98..].iter().map(|d| d.deposit_index).collect::<Vec<_>>();
        assert_eq!(tail, vec![99, 101]);
        let _: Vec<FinalizedBatchRow> = r.batches;
    }

    #[test]
    fn a_view_answers_not_ready_until_its_first_verified_tick() {
        let v = Model::new().view();
        assert!(matches!(v.deposits_by_address(&address("A", None, 10, 0)), Err(ReadError::NotReady(_))));
        assert!(matches!(v.tree_root(&tree_root(0, Some(0), None, None)), Err(ReadError::NotReady(_))));
        assert!(!v.status().ready);
    }

    #[test]
    fn an_unknown_chain_in_a_ready_view_is_empty_data() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        b.deposit(0, 1, 95, "A");
        let v = ready_model(&b).view();
        let r = v.tree_root(&tree_root(7, Some(0), None, None)).unwrap();
        assert_eq!((r.chain_local_count, r.root), (0, to_display_hex(&zero(32))));
        assert_eq!(v.tree_root(&tree_root(7, Some(1), None, None)), Err(ReadError::CountNotIndexed { count: 1, indexed: 0 }));
        assert_eq!(v.tree_root(&tree_root(7, None, Some(10), Some(1))).unwrap().chain_local_count, 0);
        assert_eq!(v.deposits_by_address(&address("A", Some(7), 10, 0)).unwrap().total, 0);
        assert_eq!(v.deposit_by_index(&DepositByIndexQuery { chain_index: 7, chain_id: 1, deposit_index: 0 }).unwrap().deposit, None);
        let claims = v.withdrawal_claims(&WithdrawalClaimsRequest { chain_id: 9, nullifiers: vec!["n".to_owned()] }).unwrap();
        assert!(claims.claims.is_empty());
        let explorer = v.explorer(&ExplorerQuery { chain_id: 9 }).unwrap();
        assert!(explorer.deposits.is_empty() && explorer.batches.is_empty());
    }

    #[test]
    fn malformed_queries_are_bad_requests() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        b.deposit(0, 1, 95, "A");
        let v = ready_model(&b).view();
        let bad = |r: Result<_, ReadError>| matches!(r, Err(ReadError::BadRequest(_)));
        assert!(bad(v.tree_root(&tree_root(0, Some(1), Some(1), Some(1))).map(|_| ())));
        assert!(bad(v.tree_root(&tree_root(0, None, None, Some(1))).map(|_| ())));
        assert!(bad(v.tree_root(&tree_root(0, None, Some(1), None)).map(|_| ())));
        let proof = ClaimProofQuery { chain_index: 0, leaf: Some(0), deposit_index: None, chain_id: None, count: Some(1), target_deposit_count: None };
        assert!(v.claim_proof(&proof).unwrap().proof.is_some());
        assert!(bad(v.claim_proof(&ClaimProofQuery { deposit_index: Some(0), chain_id: Some(1), ..proof.clone() }).map(|_| ())));
        assert!(bad(v.claim_proof(&ClaimProofQuery { leaf: None, ..proof.clone() }).map(|_| ())));
        assert!(bad(v.claim_proof(&ClaimProofQuery { leaf: None, deposit_index: Some(0), ..proof.clone() }).map(|_| ())));
        assert!(bad(v.claim_proof(&ClaimProofQuery { count: None, ..proof.clone() }).map(|_| ())));
        let nullifiers = (0..1001).map(|i| i.to_string()).collect();
        assert!(bad(v.withdrawal_claims(&WithdrawalClaimsRequest { chain_id: 1, nullifiers }).map(|_| ())));
    }

    #[test]
    fn claims_are_found_by_nullifier_and_follow_reorgs() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        let committed = b.claim(1, 10, "n1");
        b.claim(1, 95, "n2");
        let mut m = ready_model(&b);
        let get = |m: &Model, n: &[&str]| {
            let q = WithdrawalClaimsRequest { chain_id: 1, nullifiers: n.iter().map(|s| s.to_string()).collect() };
            m.view().withdrawal_claims(&q).unwrap().claims
        };
        assert_eq!(get(&m, &["n1", "n2", "n1", "n3"]), b.claims[&1]);
        assert_eq!(m.cursors().claims[&1], (10, committed.id.clone()));
        let epoch = m.view().revision.epoch;
        b.claims.get_mut(&1).unwrap().pop();
        assert_eq!(b.apply_to(&mut m), ApplyOutcome::Published { reorged: vec![] });
        assert_eq!(m.view().revision.epoch, epoch + 1);
        assert_eq!(get(&m, &["n1", "n2"]), vec![committed]);
    }
}
