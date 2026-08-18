//! Deletes the discarded suffix behind a timestamp fence (design-r1 §5, I7).
//!
//! A tombstone only hides cells whose write timestamp is below its own, so the
//! fence has to sit above every write the discarded range made -- otherwise a
//! row survives repair or compaction and, once the height is reused, becomes a
//! live row of the new branch carrying the old branch's content.  The fence is
//! therefore computed from what the archive actually observed, not from a clock:
//! the archive holds each column's real WRITETIME, so the maximum over it is
//! evidence rather than an assumption.
//!
//! The consequence runs the other way too, and is why every commit is stamped by
//! the allocator (§2.1).  A fence placed above the discarded writes is also above
//! the wall clock, so any later write taking a server timestamp would land
//! *under* the tombstone and be invisible -- succeeding, reporting nothing, and
//! unreadable.  After a rollback the allocator's high water must therefore be
//! lifted past the fence before the chain writes again.
//!
//! Deletion walks checkpoints from the head downwards.  Ascending would leave, at
//! every intermediate moment, a height whose successor still exists; descending
//! means the visible head only ever moves backwards, so a crash mid-delete leaves
//! a shorter chain rather than a chain with a hole.

use std::sync::Arc;

use psy_node_core::store::timestamp::{CommitWriteTimestampUs, DeleteFenceTimestampUs};
use scylla::client::session::Session;
use scylla::statement::prepared::PreparedStatement;
use std::collections::HashMap;
use strum::IntoEnumIterator;

use super::row_image::{cql_key_values, key_column_names, table_shape};
use super::{
    ArchivedRow, ResolvedScyllaKey, ScyllaPhysicalTableId, decode_locator_canonical,
    physical_descriptor,
};

/// Deletes recorded rows at a fixed fence timestamp.
pub struct ScyllaDeleteExecutor {
    session: Arc<Session>,
    deletes: HashMap<ScyllaPhysicalTableId, PreparedStatement>,
}

impl ScyllaDeleteExecutor {
    pub async fn prepare(session: Arc<Session>, keyspace: &str) -> anyhow::Result<Self> {
        let mut deletes = HashMap::new();
        for table in ScyllaPhysicalTableId::iter() {
            if table_shape(table).is_none() {
                continue;
            }
            let name = physical_descriptor(table).physical_name;
            let predicate = key_column_names(table)
                .iter()
                .map(|column| format!("{column} = ?"))
                .collect::<Vec<_>>()
                .join(" AND ");
            // The fence is bound, not formatted: a timestamp spliced into CQL
            // text would be one more place for a wrong value to look right.
            let cql =
                format!("DELETE FROM {keyspace}.{name} USING TIMESTAMP ? WHERE {predicate}");
            deletes.insert(table, session.prepare(cql).await?);
        }
        Ok(Self { session, deletes })
    }

    /// Delete one recorded row at the fence.
    pub async fn delete_row(
        &self,
        fence: DeleteFenceTimestampUs,
        locator: &[u8],
    ) -> anyhow::Result<()> {
        let resolved: ResolvedScyllaKey = decode_locator_canonical(locator)
            .map_err(|error| anyhow::anyhow!("delete cannot decode locator: {error}"))?;
        let table = resolved.physical_table();
        let prepared = self.deletes.get(&table).ok_or_else(|| {
            anyhow::anyhow!(
                "physical table {table:?} is not on the recorded commit path, so a rollback \
                 must not delete from it"
            )
        })?;
        // The fence binds first because it precedes the WHERE clause in the CQL.
        let mut values = vec![scylla::value::CqlValue::BigInt(fence.as_i64())];
        values.extend(cql_key_values(resolved.typed_key())?);
        self.session.execute_unpaged(prepared, values).await?;
        Ok(())
    }
}

/// The fence for one rollback, derived from what the archive observed.
///
/// Returns `None` when the archive holds no timestamp at all -- every row was
/// absent, or every archived table is key-only.  A caller must not invent one
/// then: a fence below a real write silently fails to delete it.
pub fn fence_from_archive(
    archived: &[ArchivedRow],
    fence_gap_us: i64,
) -> anyhow::Result<Option<DeleteFenceTimestampUs>> {
    let mut max_seen: Option<i64> = None;
    for row in archived {
        for observed in decode_write_times(&row.write_times) {
            max_seen = Some(match max_seen {
                Some(current) => current.max(observed),
                None => observed,
            });
        }
    }
    let Some(max_seen) = max_seen else {
        return Ok(None);
    };
    let orphan_max = CommitWriteTimestampUs::try_from_i128(max_seen as i128)?;
    let fence = DeleteFenceTimestampUs::try_after(orphan_max, max_seen as i128 + fence_gap_us as i128)?;
    Ok(Some(fence))
}

/// Read back the per-column timestamps the archive stored.
fn decode_write_times(encoded: &[u8]) -> Vec<i64> {
    let mut out = Vec::new();
    if encoded.is_empty() {
        return out;
    }
    let count = encoded[0] as usize;
    let mut offset = 1usize;
    for _ in 0..count {
        if offset >= encoded.len() {
            break;
        }
        let present = encoded[offset];
        offset += 1;
        if present == 1 {
            if offset + 8 > encoded.len() {
                break;
            }
            out.push(i64::from_be_bytes(
                encoded[offset..offset + 8].try_into().expect("checked"),
            ));
            offset += 8;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archived(times: Vec<Option<i64>>) -> ArchivedRow {
        let mut encoded = vec![times.len() as u8];
        for time in times {
            match time {
                Some(value) => {
                    encoded.push(1);
                    encoded.extend_from_slice(&value.to_be_bytes());
                }
                None => encoded.push(0),
            }
        }
        ArchivedRow {
            source_kind: 1,
            locator: vec![1],
            checkpoint_id: 1,
            image: Some(vec![2]),
            write_times: encoded,
        }
    }

    #[test]
    fn the_fence_clears_the_highest_observed_write() {
        let rows = vec![
            archived(vec![Some(100), Some(400)]),
            archived(vec![Some(250)]),
        ];
        let fence = fence_from_archive(&rows, 1_000).unwrap().unwrap();
        assert!(fence.as_i64() > 400, "a fence at or below a real write deletes nothing");
        assert_eq!(fence.as_i64(), 1_400);
    }

    #[test]
    fn an_archive_with_no_timestamps_yields_no_fence() {
        // Every row absent, or every table key-only.  Inventing a fence here
        // would produce one that silently fails to cover a write nobody saw.
        let rows = vec![archived(vec![None, None])];
        assert!(fence_from_archive(&rows, 1_000).unwrap().is_none());
    }

    #[test]
    fn an_empty_archive_yields_no_fence() {
        assert!(fence_from_archive(&[], 1_000).unwrap().is_none());
    }

    #[test]
    fn a_zero_gap_still_clears_the_maximum() {
        // try_after enforces strict ordering, so even the tightest fence is
        // above every discarded write rather than equal to the highest.
        let rows = vec![archived(vec![Some(999)])];
        let fence = fence_from_archive(&rows, 1).unwrap().unwrap();
        assert!(fence.as_i64() > 999);
    }
}
