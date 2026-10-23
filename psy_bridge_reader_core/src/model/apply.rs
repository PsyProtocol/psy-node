//! `Model::apply`: one tick's rows into the committed part and a new window,
//! window re-read reorg following (design C12), and tree verification against
//! Envio's `DepositTreeMeta`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use psy_bridge_reader_api::{EnvioChainStatus, Revision};

use super::chain::{ChainView, WindowChain};
use super::claims::{ClaimChainView, ClaimWindow};
use super::tick::{ChainProgress, DepositWithLeaf, TickData, TreeMetaRow};
use super::{ApplyOutcome, ChainState, Model, ReloadReason, View, RELOADING};
use crate::tree::hash::{to_display_hex, zero};
use crate::tree::snapshot::root_at;

/// Envio's own safe block: `progress_block - max_reorg_depth` (plan P1). It is
/// negative while nothing is safe.
fn envio_safe_block(p: &ChainProgress) -> i64 {
    p.progress_block.saturating_sub(i64::try_from(p.max_reorg_depth).unwrap_or(i64::MAX))
}

fn is_safe(block_number: u64, safe_block: i64) -> bool {
    u64::try_from(safe_block).is_ok_and(|safe| block_number <= safe)
}

/// Whether the rows an old view served at positions `old_from..old_from +
/// old_len` are not all still there: the new sequence is shorter, or
/// `same(i)` is false for some position `i` the two share.
fn sequence_differs(old_from: usize, old_len: usize, new_len: usize, same: impl Fn(usize) -> bool) -> bool {
    new_len < old_from + old_len || (old_from..old_from + old_len).any(|i| !same(i))
}

/// The next view of one chain index, and whether it is a reorg or a change.
struct NextChain {
    view: ChainView,
    reorg: bool,
    changed: bool,
}

impl Model {
    /// Applies one tick. Rules, in order (plan Task 6): identity; progress
    /// against the committed safe block; deposit invariants; promotion of
    /// safe rows; truncation; window comparison; tree verification; publish.
    pub fn apply(&mut self, tick: TickData) -> ApplyOutcome {
        // Rule 1.
        if self.identity.is_some_and(|identity| identity != tick.identity) {
            return ApplyOutcome::Reload(ReloadReason::IdentityChanged);
        }
        // Rule 2.
        let mut safe_blocks = self.committed_safe_blocks.clone();
        for p in &tick.progress {
            let committed = self.committed_safe_blocks.get(&p.chain_id).copied().unwrap_or(-1);
            if p.progress_block < committed {
                return ApplyOutcome::Reload(ReloadReason::ProgressBelowCommitted { chain_id: p.chain_id });
            }
            safe_blocks.insert(p.chain_id, committed.max(envio_safe_block(p)));
        }
        // Rule 3. A skipped chain index, and one whose rows break an invariant,
        // is held: its rows are neither promoted nor shown, and the rest of the
        // tick applies.
        let mut held = tick.skipped.clone();
        let mut violation = None;
        for (&chain_index, rows) in &tick.deposits {
            if let Err(what) = self.check_deposits(chain_index, rows) {
                let reason = ReloadReason::InvariantViolated { chain_index, what };
                self.set_fault(chain_index, rows.first().map(|r| r.row.chain_id), reason.clone());
                violation.get_or_insert(reason);
                held.insert(chain_index);
            }
        }
        self.identity = Some(tick.identity);
        self.committed_safe_blocks = safe_blocks;

        // Rule 4: deposits, then claims and batches.
        let mut promoted_any = false;
        let mut deposit_split = BTreeMap::new();
        for (&chain_index, rows) in tick.deposits.iter().filter(|(chain_index, _)| !held.contains(*chain_index)) {
            let state = self.chains.entry(chain_index).or_insert_with(|| ChainState::new(None));
            if state.chain_id.is_none() {
                state.chain_id = rows.first().map(|r| r.row.chain_id);
            }
            let safe = state.chain_id.and_then(|id| self.committed_safe_blocks.get(&id)).copied().unwrap_or(-1);
            let n = rows.iter().take_while(|r| is_safe(r.row.block_number, safe)).count();
            if n > 0 {
                state.data.committed.write().append(&rows[..n]);
                promoted_any = true;
            }
            deposit_split.insert(chain_index, n);
        }
        let mut claim_split = BTreeMap::new();
        for &chain_id in tick.claims.keys().chain(tick.batches.keys()) {
            if claim_split.contains_key(&chain_id) {
                continue;
            }
            let claims = tick.claims.get(&chain_id).map_or(&[][..], Vec::as_slice);
            let batches = tick.batches.get(&chain_id).map_or(&[][..], Vec::as_slice);
            let safe = self.committed_safe_blocks.get(&chain_id).copied().unwrap_or(-1);
            let nc = claims.iter().take_while(|c| is_safe(c.block_number, safe)).count();
            let nb = batches.iter().take_while(|b| is_safe(b.block_number, safe)).count();
            let data = self.claim_chains.entry(chain_id).or_default();
            if nc + nb > 0 {
                data.committed.write().append(&claims[..nc], &batches[..nb]);
                promoted_any = true;
            }
            claim_split.insert(chain_id, (nc, nb));
        }

        // Rule 5.
        if tick.truncated {
            return if let Some(reason) = violation {
                ApplyOutcome::Reload(reason)
            } else if promoted_any {
                ApplyOutcome::CatchingUp
            } else {
                ApplyOutcome::Reload(ReloadReason::WindowOverLimit)
            };
        }
        self.publish_tick(&tick, &held, &deposit_split, &claim_split)
    }

    /// Rule 3 over the rows read from this chain's cursor.
    fn check_deposits(&self, chain_index: u64, rows: &[DepositWithLeaf]) -> Result<(), String> {
        let (cursor, mut chain_id) = self.chains.get(&chain_index).map_or_else(Default::default, |s| (s.cursor(), s.chain_id));
        let mut last = (cursor.local_count > 0).then(|| cursor.next_deposit_index - 1);
        for (k, r) in rows.iter().enumerate() {
            let d = &r.row;
            let expected = cursor.local_count + k as u64;
            if d.chain_local_deposit_index != expected {
                return Err(format!("chain_local_deposit_index {} where {expected} was expected", d.chain_local_deposit_index));
            }
            if d.chain_index != chain_index {
                return Err(format!("deposit {} has chain_index {}", d.id, d.chain_index));
            }
            if let Some(last) = last.filter(|last| d.deposit_index <= *last) {
                return Err(format!("deposit_index {} does not increase after {last}", d.deposit_index));
            }
            last = Some(d.deposit_index);
            match chain_id {
                Some(id) if id != d.chain_id => {
                    return Err(format!("deposit {} has chain_id {} on a chain_index of chain_id {id}", d.id, d.chain_id));
                }
                _ => chain_id = Some(d.chain_id),
            }
            if r.leaf_deposit_index != d.deposit_index || r.leaf_chain_id != d.chain_id {
                return Err(format!(
                    "leaf {expected} has deposit_index {} and chain_id {}, its deposit {} and {}",
                    r.leaf_deposit_index, r.leaf_chain_id, d.deposit_index, d.chain_id
                ));
            }
        }
        Ok(())
    }

    /// Marks one chain not ready until a reset and publishes that at once.
    /// The rest of the view is unchanged, so it keeps its `as_of_unix_ms`. A
    /// fault the published view already shows publishes nothing.
    fn set_fault(&mut self, chain_index: u64, chain_id: Option<u64>, reason: ReloadReason) {
        let message = reason.to_string();
        let state = self.chains.entry(chain_index).or_insert_with(|| ChainState::new(chain_id));
        let old = self.view.load_full();
        let shown = old.chains.get(&chain_index).is_some_and(|v| v.ready.as_ref().err() == Some(&message));
        if shown && state.fault.as_ref().is_some_and(|(r, m)| *r == reason && *m == message) {
            return;
        }
        state.fault = Some((reason, message.clone()));
        let view = match old.chains.get(&chain_index) {
            Some(v) => ChainView { ready: Err(message), ..v.clone() },
            None => ChainView::not_ready(state.data.clone(), state.chain_id, message),
        };
        let mut chains = old.chains.clone();
        chains.insert(chain_index, view);
        let revision = self.next_revision(old.revision.as_of_unix_ms);
        self.publish(View {
            revision,
            ready: old.ready.clone(),
            chains,
            claim_chains: old.claim_chains.clone(),
            envio_chains: old.envio_chains.clone(),
        });
    }

    /// Rules 6 to 8 on an untruncated tick.
    fn publish_tick(
        &mut self,
        tick: &TickData,
        held: &BTreeSet<u64>,
        deposit_split: &BTreeMap<u64, usize>,
        claim_split: &BTreeMap<u64, (usize, usize)>,
    ) -> ApplyOutcome {
        let old = self.view.load_full();
        let as_of = tick.started_unix_ms;
        let mut changed = old.ready.is_err();
        let mut reorged = Vec::new();
        let metas = tick.metas.iter().map(|m| (m.chain_index, *m)).collect::<BTreeMap<_, _>>();
        for &chain_index in metas.keys() {
            self.chains.entry(chain_index).or_insert_with(|| ChainState::new(None));
        }
        // A chain index with no meta row and nothing committed is unknown again
        // (Envio rolled back its first deposits); one with committed rows is
        // a deep change that `next_chain_view` reports as `MetaMissing`.
        let unknown = self
            .chains
            .iter()
            .filter(|(chain_index, state)| !metas.contains_key(chain_index) && state.data.committed.read().len() == 0)
            .map(|(&chain_index, _)| chain_index)
            .collect::<Vec<_>>();
        for chain_index in unknown {
            self.chains.remove(&chain_index);
            if let Some(o) = old.chains.get(&chain_index) {
                changed = true;
                if o.total() > 0 {
                    reorged.push(chain_index);
                }
            }
        }
        let mut chains = BTreeMap::new();
        for (&chain_index, state) in self.chains.iter_mut() {
            if held.contains(&chain_index) {
                let view = old.chains.get(&chain_index).cloned();
                changed |= view.is_none();
                let view = view.unwrap_or_else(|| ChainView::not_ready(state.data.clone(), state.chain_id, RELOADING.to_owned()));
                chains.insert(chain_index, view);
                continue;
            }
            let rows = tick.deposits.get(&chain_index).map_or(&[][..], Vec::as_slice);
            let window_rows = &rows[deposit_split.get(&chain_index).copied().unwrap_or(0)..];
            let meta = metas.get(&chain_index).copied();
            let next = next_chain_view(chain_index, state, old.chains.get(&chain_index), window_rows, meta, as_of);
            if next.reorg {
                reorged.push(chain_index);
            }
            changed |= next.changed;
            chains.insert(chain_index, next.view);
        }

        let mut claims_reorged = false;
        for p in &tick.progress {
            self.claim_chains.entry(p.chain_id).or_default();
        }
        let mut claim_chains = BTreeMap::new();
        for (&chain_id, data) in &self.claim_chains {
            let claims = tick.claims.get(&chain_id).map_or(&[][..], Vec::as_slice);
            let batches = tick.batches.get(&chain_id).map_or(&[][..], Vec::as_slice);
            let (nc, nb) = claim_split.get(&chain_id).copied().unwrap_or((0, 0));
            let (claims, batches) = (&claims[nc..], &batches[nb..]);
            let committed = data.committed.read();
            let (ccl, cbl) = (committed.claims.len(), committed.batches.len());
            let old_view = old.claim_chains.get(&chain_id).filter(|o| Arc::ptr_eq(&o.data, data));
            if let Some(o) = old_view {
                let claim_at = |i: usize| if i < ccl { &committed.claims[i] } else { &claims[i - ccl] };
                let batch_at = |i: usize| if i < cbl { &committed.batches[i] } else { &batches[i - cbl] };
                claims_reorged |= sequence_differs(o.committed_claims, o.window.claims.len(), ccl + claims.len(), |i| {
                    *claim_at(i) == o.window.claims[i - o.committed_claims]
                }) || sequence_differs(o.committed_batches, o.window.batches.len(), cbl + batches.len(), |i| {
                    *batch_at(i) == o.window.batches[i - o.committed_batches]
                });
            }
            drop(committed);
            let reuse = old_view.filter(|o| o.committed_claims == ccl && o.committed_batches == cbl && o.window.holds(claims, batches));
            let view = match reuse {
                Some(o) if o.ready.is_ok() => o.clone(),
                _ => {
                    changed = true;
                    let window = reuse.map_or_else(|| Arc::new(ClaimWindow::build(claims, batches)), |o| o.window.clone());
                    ClaimChainView { data: data.clone(), committed_claims: ccl, committed_batches: cbl, window, ready: Ok(()) }
                }
            };
            claim_chains.insert(chain_id, view);
        }

        let envio_chains = tick
            .progress
            .iter()
            .map(|p| {
                let deposits_ready = chains.values().filter(|c| c.chain_id == Some(p.chain_id)).all(|c| c.ready.is_ok());
                let status = EnvioChainStatus {
                    chain_id: p.chain_id,
                    progress_block: u64::try_from(p.progress_block).unwrap_or(0),
                    max_reorg_depth: p.max_reorg_depth,
                    safe_block: u64::try_from(envio_safe_block(p)).unwrap_or(0),
                    committed_safe_block: u64::try_from(self.committed_safe_blocks.get(&p.chain_id).copied().unwrap_or(-1)).unwrap_or(0),
                    ready: deposits_ready && claim_chains.get(&p.chain_id).is_some_and(|c| c.ready.is_ok()),
                };
                (p.chain_id, status)
            })
            .collect::<BTreeMap<_, _>>();
        changed |= envio_chains != old.envio_chains;

        let fault = self.chains.values().find_map(|s| s.fault.as_ref().map(|(reason, _)| reason.clone()));
        if !changed {
            // The data is unchanged but verified as of this tick: refresh
            // `as_of_unix_ms` and keep epoch and seq, so an idle Envio does not
            // make valid data look stale.
            if old.revision.as_of_unix_ms != as_of {
                self.publish(View {
                    revision: Revision { as_of_unix_ms: as_of, ..old.revision.clone() },
                    ready: old.ready.clone(),
                    chains: old.chains.clone(),
                    claim_chains: old.claim_chains.clone(),
                    envio_chains: old.envio_chains.clone(),
                });
            }
            return fault.map_or(ApplyOutcome::Unchanged, ApplyOutcome::Reload);
        }
        if !reorged.is_empty() || claims_reorged {
            self.epoch += 1;
        }
        let revision = self.next_revision(as_of);
        self.publish(View { revision, ready: Ok(()), chains, claim_chains, envio_chains });
        fault.map_or(ApplyOutcome::Published { reorged }, ApplyOutcome::Reload)
    }
}

/// Rules 6 and 7 for one chain index: its new window, whether that is a reorg
/// of `old`, and its verification against Envio's tree meta.
fn next_chain_view(
    chain_index: u64,
    state: &mut ChainState,
    old: Option<&ChainView>,
    window_rows: &[DepositWithLeaf],
    meta: Option<TreeMetaRow>,
    as_of: u64,
) -> NextChain {
    let committed = state.data.committed.read();
    let committed_len = committed.len();
    let old_same = old.filter(|o| Arc::ptr_eq(&o.data, &state.data));
    let reorg = match (old, old_same) {
        (_, Some(o)) => {
            let ocl = o.committed_len as usize;
            let ncl = committed_len as usize;
            sequence_differs(ocl, o.window.deposits.len(), ncl + window_rows.len(), |i| {
                let (row, leaf) = if i < ncl {
                    (&committed.deposits[i], committed.leaves[i])
                } else {
                    (&window_rows[i - ncl].row, window_rows[i - ncl].leaf)
                };
                *row == o.window.deposits[i - ocl] && leaf == o.window.leaves[i - ocl]
            })
        }
        (Some(o), None) => o.total() > 0,
        (None, None) => false,
    };
    let reuse = old_same.filter(|o| o.committed_len == committed_len && o.window.holds(window_rows));
    if let Some(o) = reuse.filter(|o| o.ready.is_ok() && state.fault.is_none() && o.meta == meta && o.chain_id == state.chain_id) {
        return NextChain { view: o.clone(), reorg: false, changed: false };
    }
    let window = reuse.map_or_else(|| Arc::new(WindowChain::build(&committed, window_rows)), |o| o.window.clone());
    drop(committed);

    let mut view = ChainView {
        data: state.data.clone(),
        committed_len,
        window,
        ready: Ok(()),
        meta,
        chain_id: state.chain_id,
        tree_root: zero(32),
        last_verified_unix_ms: old.map_or(0, |o| o.last_verified_unix_ms),
    };
    let total = view.total();
    let root = root_at(&view.read().tree(), total);
    let verified = match (&root, meta) {
        (Err(e), _) => Err(format!("tree at {total}: {e}")),
        (Ok(_), None) => Err("no DepositTreeMeta row".to_owned()),
        (Ok(_), Some(m)) if m.last_count != total => {
            Err(format!("{total} deposits read, DepositTreeMeta.last_count {}", m.last_count))
        }
        (Ok(root), Some(m)) if *root != m.root => Err(format!(
            "root {} at {total}, DepositTreeMeta root {}",
            to_display_hex(root),
            to_display_hex(&m.root)
        )),
        (Ok(_), Some(_)) => Ok(()),
    };
    if let Ok(root) = root {
        view.tree_root = root;
    }
    match verified {
        Ok(()) if state.fault.is_none() => view.last_verified_unix_ms = as_of,
        Ok(()) => {}
        Err(detail) => {
            if state.fault.is_none() {
                let reason = match meta {
                    None => ReloadReason::MetaMissing { chain_index },
                    Some(_) => ReloadReason::TreeMismatch { chain_index },
                };
                state.fault = Some((reason.clone(), format!("{reason}: {detail}")));
            }
        }
    }
    if let Some((_, message)) = &state.fault {
        view.ready = Err(message.clone());
    }
    let changed = reorg
        || old.map_or(true, |o| {
            o.committed_len != view.committed_len
                || o.total() != view.total()
                || !Arc::ptr_eq(&o.window, &view.window)
                || o.ready != view.ready
                || o.meta != view.meta
                || o.chain_id != view.chain_id
        });
    NextChain { view, reorg, changed }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use psy_bridge_reader_api::{ClaimProofQuery, DepositRow, DepositsByAddressQuery, DepositsByTxQuery, PrefixQuery, TreeRootQuery};

    use crate::model::{ApplyOutcome, DepositCursor, Model, ReadError, ReloadReason, View};
    use crate::test_support::{naive_root, naive_siblings, TickBuilder};
    use crate::tree::hash::{to_display_hex, zero, Hash};

    fn published(reorged: &[u64]) -> ApplyOutcome {
        ApplyOutcome::Published { reorged: reorged.to_vec() }
    }

    fn by_address(v: &View, chain_index: u64, shield_address: &str) -> Result<Vec<DepositRow>, ReadError> {
        let q = DepositsByAddressQuery {
            shield_address: shield_address.to_owned(),
            chain_id: 1,
            chain_index: Some(chain_index),
            limit: 1000,
            offset: 0,
        };
        v.deposits_by_address(&q).map(|r| r.rows)
    }

    fn by_tx(v: &View, tx_hash: &str) -> Vec<DepositRow> {
        v.deposits_by_tx(&DepositsByTxQuery { tx_hash: tx_hash.to_owned(), chain_index: 0 }).unwrap().rows
    }

    fn root(v: &View, chain_index: u64, count: u64) -> Result<String, ReadError> {
        let q = TreeRootQuery { chain_index, count: Some(count), target_deposit_count: None, chain_id: None };
        v.tree_root(&q).map(|r| r.root)
    }

    fn naive_hex(leaves: &[Hash], n: u64) -> String {
        to_display_hex(&naive_root(leaves, n))
    }

    #[test]
    fn appends_within_the_window_publish_without_a_reorg() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for block in 95..98 {
            b.deposit(0, 1, block, "A");
        }
        let mut m = Model::new();
        assert_eq!(b.apply_to(&mut m), published(&[]));
        let v1 = m.view();
        for block in 98..100 {
            b.deposit(0, 1, block, "A");
        }
        assert_eq!(b.apply_to(&mut m), published(&[]));
        let v2 = m.view();
        assert_eq!(v2.revision.epoch, v1.revision.epoch);
        assert_eq!(v2.revision.seq, v1.revision.seq + 1);
        assert_eq!(by_address(&v2, 0, "A").unwrap(), b.rows(0));
        assert_eq!(v2.chains[&0].committed_len, 0);
    }

    #[test]
    fn rows_at_or_below_the_safe_block_are_committed() {
        let mut b = TickBuilder::new();
        b.progress(1, 20, 8);
        for block in [10, 11, 12, 13, 15] {
            b.deposit(0, 1, block, "A");
        }
        let mut m = Model::new();
        assert_eq!(b.apply_to(&mut m), published(&[]));
        assert_eq!(m.cursors().deposits[&0], DepositCursor { local_count: 3, next_deposit_index: 3 });
        assert_eq!(m.view().chains[&0].committed_len, 3);
        assert_eq!(m.view().status().chains[0].committed_count, 3);
        b.progress(1, 23, 8);
        assert_eq!(b.apply_to(&mut m), published(&[]));
        assert_eq!(m.cursors().deposits[&0], DepositCursor { local_count: 5, next_deposit_index: 5 });
        assert_eq!(m.view().chains[&0].committed_len, 5);
        assert_eq!(by_address(&m.view(), 0, "A").unwrap(), b.rows(0));
    }

    #[test]
    fn equal_count_replacement_is_a_reorg() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for block in 95..98 {
            b.deposit(0, 1, block, "A");
        }
        let mut m = Model::new();
        b.apply_to(&mut m);
        let v1 = m.view();
        let old_tx = b.deposits[&0][1].row.tx_hash.clone();
        b.deposits.get_mut(&0).unwrap()[1].row.tx_hash = "0xreplaced".to_owned();
        assert_eq!(b.apply_to(&mut m), published(&[0]));
        let v2 = m.view();
        assert_eq!(v2.revision.epoch, v1.revision.epoch + 1);
        assert_eq!(by_tx(&v2, "0xreplaced"), vec![b.rows(0)[1].clone()]);
        assert!(by_tx(&v2, &old_tx).is_empty());
        let rows = by_address(&v2, 0, "A").unwrap();
        assert_eq!(rows, b.rows(0));
        assert!(rows.iter().all(|r| r.tx_hash != old_tx));
    }

    #[test]
    fn removal_in_the_window_is_a_reorg_and_rolls_the_tree_back() {
        // 1020 committed rows and 10 in the window, so block 0 (1024 leaves)
        // completes inside the window; the reorg drops it again.
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for _ in 0..1020 {
            b.deposit(0, 1, 10, "A");
        }
        for block in 95..105 {
            b.deposit(0, 1, block.min(100), "A");
        }
        let mut m = Model::new();
        assert_eq!(b.apply_to(&mut m), published(&[]));
        assert_eq!(m.view().chains[&0].committed_len, 1020);
        assert_eq!(root(&m.view(), 0, 1030).unwrap(), naive_hex(&b.leaves(0), 1030));
        b.deposits.get_mut(&0).unwrap().truncate(1022);
        assert_eq!(b.apply_to(&mut m), published(&[0]));
        let v = m.view();
        assert_eq!(root(&v, 0, 1022).unwrap(), naive_hex(&b.leaves(0), 1022));
        assert_eq!(root(&v, 0, 1024), Err(ReadError::CountNotIndexed { count: 1024, indexed: 1022 }));
        assert_eq!(v.status().chains[0].deposit_count, 1022);
        assert_eq!(v.status().chains[0].tree_root, naive_hex(&b.leaves(0), 1022));
    }

    #[test]
    fn old_views_are_unaffected_by_later_applies() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for block in 95..98 {
            b.deposit(0, 1, block, "A");
        }
        let mut m = Model::new();
        b.apply_to(&mut m);
        let v1 = m.view();
        let (old_revision, old_rows, old_leaves) = (v1.revision.clone(), b.rows(0), b.leaves(0));
        // Replace the last row, add two, and promote all five.
        let last = &mut b.deposits.get_mut(&0).unwrap()[2];
        last.leaf = Hash::from_values(9, 9, 9, 9);
        last.row.tx_hash = "0xother".to_owned();
        b.deposit(0, 1, 150, "A");
        b.deposit(0, 1, 151, "A");
        b.progress(1, 200, 8);
        assert_eq!(b.apply_to(&mut m), published(&[0]));
        assert_eq!(m.view().chains[&0].committed_len, 5);
        assert_eq!(v1.revision, old_revision);
        assert_eq!(by_address(&v1, 0, "A").unwrap(), old_rows);
        assert_eq!(root(&v1, 0, 3).unwrap(), naive_hex(&old_leaves, 3));
        assert_eq!(root(&v1, 0, 4), Err(ReadError::CountNotIndexed { count: 4, indexed: 3 }));
        assert_eq!(root(&m.view(), 0, 5).unwrap(), naive_hex(&b.leaves(0), 5));
    }

    #[test]
    fn an_old_view_keeps_its_own_upper_nodes_after_promotion_and_reorg() {
        // Old view: 1000 committed + 30 window rows; block 0 (level 10, index 0)
        // completes in its window. A reorg inside block 0, then promotion of
        // everything, appends the new branch's block 0 to the committed store.
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for _ in 0..1000 {
            b.deposit(0, 1, 10, "A");
        }
        for _ in 0..30 {
            b.deposit(0, 1, 95, "A");
        }
        let mut m = Model::new();
        b.apply_to(&mut m);
        let v1 = m.view();
        assert_eq!(v1.chains[&0].committed_len, 1000);
        let old_leaves = b.leaves(0);
        b.deposits.get_mut(&0).unwrap()[1010].leaf = Hash::from_values(5, 6, 7, 8);
        b.progress(1, 300, 8);
        assert_eq!(b.apply_to(&mut m), published(&[0]));
        assert_eq!(m.view().chains[&0].committed_len, 1030);
        let new_leaves = b.leaves(0);
        assert_ne!(naive_root(&old_leaves, 1030), naive_root(&new_leaves, 1030));
        for n in [1024, 1030] {
            assert_eq!(root(&v1, 0, n).unwrap(), naive_hex(&old_leaves, n), "old view at {n}");
            assert_eq!(root(&m.view(), 0, n).unwrap(), naive_hex(&new_leaves, n), "new view at {n}");
        }
        let q = ClaimProofQuery { chain_index: 0, leaf: Some(5), deposit_index: None, chain_id: None, count: Some(1030), target_deposit_count: None };
        let proof = v1.claim_proof(&q).unwrap().proof.unwrap();
        let expected = naive_siblings(&old_leaves, 5, 1030).iter().map(to_display_hex).collect::<Vec<_>>();
        assert_eq!(proof.siblings, expected);
        assert_eq!(proof.root, naive_hex(&old_leaves, 1030));
    }

    #[test]
    fn progress_below_committed_safe_block_reloads() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        b.deposit(0, 1, 50, "A");
        let mut m = Model::new();
        b.apply_to(&mut m);
        b.progress(1, 91, 8);
        assert_eq!(b.apply_to(&mut m), ApplyOutcome::Reload(ReloadReason::ProgressBelowCommitted { chain_id: 1 }));
        b.progress(1, 92, 8);
        assert_eq!(b.apply_to(&mut m), published(&[]));
    }

    #[test]
    fn identity_change_reloads() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        b.deposit(0, 1, 50, "A");
        let mut m = Model::new();
        b.apply_to(&mut m);
        b.identity.deposit_oid += 1;
        assert_eq!(b.apply_to(&mut m), ApplyOutcome::Reload(ReloadReason::IdentityChanged));
    }

    #[test]
    fn a_gap_in_chain_local_indexes_is_an_invariant_violation() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for block in [10, 95, 96] {
            b.deposit(0, 1, block, "A");
        }
        let mut m = Model::new();
        assert_eq!(b.apply_to(&mut m), published(&[]));
        b.deposit(0, 1, 97, "A");
        b.deposits.get_mut(&0).unwrap()[3].row.chain_local_deposit_index = 4;
        let ApplyOutcome::Reload(ReloadReason::InvariantViolated { chain_index: 0, what }) = b.apply_to(&mut m) else {
            panic!("expected an invariant violation");
        };
        assert!(what.contains("chain_local_deposit_index 4 where 3 was expected"), "{what}");
        assert!(matches!(by_address(&m.view(), 0, "A"), Err(ReadError::NotReady(_))));
        assert!(matches!(root(&m.view(), 0, 1), Err(ReadError::NotReady(_))));
    }

    #[test]
    fn a_leaf_that_does_not_match_its_deposit_is_an_invariant_violation() {
        for wrong_field in ["deposit_index", "chain_id"] {
            let mut b = TickBuilder::new();
            b.progress(1, 100, 8);
            b.deposit(0, 1, 95, "A");
            let mut m = Model::new();
            assert_eq!(b.apply_to(&mut m), published(&[]));
            b.deposit(0, 1, 96, "A");
            let leaf = &mut b.deposits.get_mut(&0).unwrap()[1];
            match wrong_field {
                "deposit_index" => leaf.leaf_deposit_index += 1,
                _ => leaf.leaf_chain_id = 2,
            }
            let ApplyOutcome::Reload(ReloadReason::InvariantViolated { chain_index: 0, what }) = b.apply_to(&mut m) else {
                panic!("expected an invariant violation for {wrong_field}");
            };
            assert!(what.starts_with("leaf 1 has"), "{what}");
            assert!(matches!(by_address(&m.view(), 0, "A"), Err(ReadError::NotReady(_))));
            // The fault holds until a reset, even if Envio's rows are right again.
            b.deposits.get_mut(&0).unwrap().pop();
            assert!(matches!(b.apply_to(&mut m), ApplyOutcome::Reload(ReloadReason::InvariantViolated { .. })));
            m.reset_chain(0);
            assert_eq!(b.apply_to(&mut m), published(&[]));
            assert_eq!(by_address(&m.view(), 0, "A").unwrap(), b.rows(0));
        }
    }

    #[test]
    fn tree_mismatch_with_envio_meta_makes_the_chain_not_ready() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8).progress(2, 100, 8);
        for block in [10, 95] {
            b.deposit(0, 1, block, "A");
            b.deposit(1, 2, block, "A");
        }
        b.meta_root.insert(0, zero(5));
        let mut m = Model::new();
        assert_eq!(b.apply_to(&mut m), ApplyOutcome::Reload(ReloadReason::TreeMismatch { chain_index: 0 }));
        let v = m.view();
        assert!(matches!(root(&v, 0, 1), Err(ReadError::NotReady(_))));
        assert!(matches!(by_address(&v, 0, "A"), Err(ReadError::NotReady(_))));
        assert_eq!(root(&v, 1, 2).unwrap(), naive_hex(&b.leaves(1), 2));
        let q = DepositsByAddressQuery { shield_address: "A".to_owned(), chain_id: 2, chain_index: Some(1), limit: 10, offset: 0 };
        assert_eq!(v.deposits_by_address(&q).unwrap().rows, b.rows(1));
        let status = v.status();
        assert!(!status.ready);
        assert!(!status.chains[0].ready && status.chains[1].ready);
    }

    #[test]
    fn truncated_read_promotes_only_safe_rows() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for block in [10, 11, 95, 96, 97] {
            b.deposit(0, 1, block, "A");
        }
        let mut m = Model::new();
        assert_eq!(b.apply_to(&mut m), published(&[]));
        let v1 = m.view();
        // Safe block 102: of the 7 rows above the cursor, a 4-row read gets
        // 95, 96, 97, 98, all safe.
        b.progress(1, 110, 8);
        for block in [98, 99, 105, 106] {
            b.deposit(0, 1, block, "A");
        }
        assert_eq!(m.apply(b.tick_limited(&m.cursors(), 4)), ApplyOutcome::CatchingUp);
        assert!(Arc::ptr_eq(&m.view(), &v1));
        assert_eq!(m.cursors().deposits[&0].local_count, 6);
        assert_eq!(by_address(&m.view(), 0, "A").unwrap(), b.rows(0)[..5].to_vec());
        assert_eq!(b.apply_to(&mut m), published(&[]));
        let v2 = m.view();
        assert_eq!(v2.revision.epoch, v1.revision.epoch);
        assert_eq!(v2.chains[&0].committed_len, 7);
        assert_eq!(by_address(&v2, 0, "A").unwrap(), b.rows(0));
    }

    #[test]
    fn a_truncated_read_with_nothing_safe_is_window_over_limit() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for block in [95, 96, 97] {
            b.deposit(0, 1, block, "A");
        }
        let mut m = Model::new();
        assert_eq!(m.apply(b.tick_limited(&m.cursors(), 2)), ApplyOutcome::Reload(ReloadReason::WindowOverLimit));
        assert!(matches!(by_address(&m.view(), 0, "A"), Err(ReadError::NotReady(_))));
    }

    #[test]
    fn an_unchanged_tick_refreshes_as_of_without_bumping_seq() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        b.deposit(0, 1, 10, "A");
        b.deposit(0, 1, 95, "A");
        let mut m = Model::new();
        assert_eq!(b.apply_to(&mut m), published(&[]));
        let v1 = m.view();
        assert_eq!(v1.revision.as_of_unix_ms, 1_000);
        b.started_unix_ms = 2_000;
        assert_eq!(b.apply_to(&mut m), ApplyOutcome::Unchanged);
        let v2 = m.view();
        assert_eq!((v2.revision.epoch, v2.revision.seq), (v1.revision.epoch, v1.revision.seq));
        assert_eq!(v2.revision.as_of_unix_ms, 2_000);
        assert!(Arc::ptr_eq(&v2.chains[&0].window, &v1.chains[&0].window));
        assert!(Arc::ptr_eq(&v2.chains[&0].data, &v1.chains[&0].data));
        assert_eq!(by_address(&v2, 0, "A").unwrap(), b.rows(0));
    }

    #[test]
    fn a_persisting_fault_does_not_bump_seq_every_tick() {
        // An invariant violation found again on the next tick.
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        b.deposit(0, 1, 95, "A");
        let mut m = Model::new();
        assert_eq!(b.apply_to(&mut m), published(&[]));
        b.deposit(0, 1, 96, "A");
        b.deposits.get_mut(&0).unwrap()[1].leaf_chain_id = 2;
        assert!(matches!(b.apply_to(&mut m), ApplyOutcome::Reload(ReloadReason::InvariantViolated { .. })));
        let seq = m.view().revision.seq;
        for _ in 0..3 {
            assert!(matches!(b.apply_to(&mut m), ApplyOutcome::Reload(ReloadReason::InvariantViolated { .. })));
            assert_eq!(m.view().revision.seq, seq);
        }
        // A tree mismatch that Envio keeps reporting.
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        b.deposit(0, 1, 95, "A");
        b.meta_root.insert(0, zero(3));
        let mut m = Model::new();
        assert_eq!(b.apply_to(&mut m), ApplyOutcome::Reload(ReloadReason::TreeMismatch { chain_index: 0 }));
        let seq = m.view().revision.seq;
        for _ in 0..3 {
            assert_eq!(b.apply_to(&mut m), ApplyOutcome::Reload(ReloadReason::TreeMismatch { chain_index: 0 }));
            assert_eq!(m.view().revision.seq, seq);
        }
    }

    #[test]
    fn a_rolled_back_first_deposit_removes_the_chain_and_keeps_its_sibling_ready() {
        // Chain indexes 0 and 1 share chain_id 1. A reorg removes chain index
        // 1's only deposit, and Envio's rollback deletes its DepositTreeMeta row.
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        b.deposit_at(0, 1, 0, 10, "A");
        b.deposit_at(0, 1, 1, 11, "A");
        b.deposit_at(1, 1, 2, 95, "B");
        let mut m = Model::new();
        assert_eq!(b.apply_to(&mut m), published(&[]));
        let v1 = m.view();
        b.deposits.remove(&1);
        assert_eq!(b.apply_to(&mut m), published(&[1]));
        let v2 = m.view();
        assert_eq!(v2.revision.epoch, v1.revision.epoch + 1);
        let status = v2.status();
        assert!(status.ready);
        assert_eq!(status.chains.iter().map(|c| c.chain_index).collect::<Vec<_>>(), [0]);
        let prefix = v2.prefix(&PrefixQuery { chain_index: 0, chain_id: 1, target_deposit_count: 2 }).unwrap();
        assert_eq!((prefix.chain_local_count, prefix.has_foreign_deposits), (2, false));
        let q = TreeRootQuery { chain_index: 0, count: None, target_deposit_count: Some(2), chain_id: Some(1) };
        let r = v2.tree_root(&q).unwrap();
        assert_eq!((r.chain_local_count, r.root), (2, naive_hex(&b.leaves(0), 2)));
        // Chain index 1 is unknown again: count 0, root zero(32), no rows.
        assert_eq!(root(&v2, 1, 0).unwrap(), to_display_hex(&zero(32)));
        assert_eq!(by_address(&v2, 1, "B").unwrap(), vec![]);
        assert!(m.cursors().deposits.get(&1).is_none());
        // A further tick with nothing new neither reloads nor bumps the epoch.
        b.started_unix_ms = 2_000;
        assert_eq!(b.apply_to(&mut m), ApplyOutcome::Unchanged);
        let v3 = m.view();
        assert_eq!((v3.revision.epoch, v3.revision.seq), (v2.revision.epoch, v2.revision.seq));
        assert_eq!(v3.revision.as_of_unix_ms, 2_000);
    }

    #[test]
    fn an_invariant_violation_on_one_chain_lets_the_others_progress_and_refresh_as_of() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8).progress(2, 100, 8);
        b.deposit(0, 1, 10, "A");
        b.deposit(1, 2, 10, "A");
        let mut m = Model::new();
        assert_eq!(b.apply_to(&mut m), published(&[]));
        let v1 = m.view();
        // Chain index 0 gets a row with a chain-local gap; chain index 1 a new deposit.
        b.deposit(0, 1, 95, "A");
        b.deposits.get_mut(&0).unwrap()[1].row.chain_local_deposit_index = 5;
        b.deposit(1, 2, 95, "B");
        b.started_unix_ms = 2_000;
        assert!(matches!(b.apply_to(&mut m), ApplyOutcome::Reload(ReloadReason::InvariantViolated { chain_index: 0, .. })));
        let v2 = m.view();
        assert_eq!(v2.revision.as_of_unix_ms, 2_000);
        assert!(v2.revision.seq > v1.revision.seq);
        assert!(matches!(by_address(&v2, 0, "A"), Err(ReadError::NotReady(_))));
        let q = DepositsByAddressQuery { shield_address: "B".to_owned(), chain_id: 2, chain_index: Some(1), limit: 10, offset: 0 };
        assert_eq!(v2.deposits_by_address(&q).unwrap().rows, b.rows(1)[1..].to_vec());
        assert_eq!(v2.status().chains[1].deposit_count, 2);
        assert!(v2.status().chains[1].ready);
        // The fault holds; a tick with nothing new still refreshes as_of.
        b.started_unix_ms = 3_000;
        assert!(matches!(b.apply_to(&mut m), ApplyOutcome::Reload(ReloadReason::InvariantViolated { chain_index: 0, .. })));
        let v3 = m.view();
        assert_eq!((v3.revision.epoch, v3.revision.seq), (v2.revision.epoch, v2.revision.seq));
        assert_eq!(v3.revision.as_of_unix_ms, 3_000);
    }

    #[test]
    fn a_missing_meta_row_under_committed_deposits_is_meta_missing() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        b.deposit(0, 1, 10, "A");
        b.deposit(1, 1, 11, "B");
        let mut m = Model::new();
        assert_eq!(b.apply_to(&mut m), published(&[]));
        assert_eq!(m.view().chains[&1].committed_len, 1);
        b.deposits.remove(&1);
        assert_eq!(b.apply_to(&mut m), ApplyOutcome::Reload(ReloadReason::MetaMissing { chain_index: 1 }));
        assert!(matches!(root(&m.view(), 1, 1), Err(ReadError::NotReady(_))));
    }

    #[test]
    fn resident_estimate_grows_with_rows() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        let mut m = Model::new();
        let empty = m.resident_bytes_estimate();
        for block in [10, 11, 12] {
            b.deposit(0, 1, block, "A");
        }
        b.claim(1, 10, "n1");
        assert!(matches!(b.apply_to(&mut m), ApplyOutcome::Published { .. }));
        let one = m.resident_bytes_estimate();
        for block in [13, 14, 15] {
            b.deposit(0, 1, block, "A");
        }
        assert!(matches!(b.apply_to(&mut m), ApplyOutcome::Published { .. }));
        let two = m.resident_bytes_estimate();
        assert!(empty < one && one < two, "{empty} {one} {two}");
    }
}
