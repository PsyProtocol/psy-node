//! Copies the discarded suffix out before anything is deleted (design-r1 §2.3).
//!
//! Archiving is a precondition, not a backup (§0.2 D2): a participant that has
//! not finished copying and reading back may not enter the global barrier, and no
//! participant may delete before it. So the failure this module must never have
//! is a silent one -- an archive that reports success while holding less than the
//! hot tables did.
//!
//! Three things follow from that.
//!
//! **Rows are written with `IF NOT EXISTS`.** The slot is
//! `(plan_id, source_kind, physical source PK)`, so a retry of the same plan
//! writes the same slot and converges. Two different contents for one source PK
//! collide on the conditional instead of producing a second winner, which turns
//! "the same key archived twice with different bytes" from a silent overwrite
//! into a visible conflict.
//!
//! **Every row is read back by its full source PK.** Not counted, not sampled:
//! read back and compared byte for byte. A count proves only that something was
//! written.
//!
//! **A slot holds one row, because the hot table holds one row.** Tables with no
//! version axis are touched by every checkpoint in the range under the *same*
//! physical key, so they all address one slot -- and that is correct, since the
//! hot table only ever held the newest value.  The slot therefore keeps the first
//! `checkpoint_id` that reached it, which is `c(K)`: the lowest height above the
//! target that wrote the key, and so the boundary the restore cares about.  What
//! a re-visit must match is the *content*; a differing checkpoint id is expected
//! and is not a conflict.
//!
//! **An absent row is archived as absent.** A planned key that no longer exists
//! is evidence, not an error to skip: the manifest deliberately over-records, so
//! "planned but not present" is a normal and expected state, and recording it is
//! what lets the restore afterwards tell it apart from a key it failed to copy.

use std::sync::Arc;

use scylla::client::session::Session;
use scylla::statement::prepared::PreparedStatement;
use scylla::value::CqlValue;

use super::{ResolvedScyllaKey, RowImage, ScyllaRowImageReader, decode_locator_canonical};

pub const ROLLBACK_ARCHIVE_TABLE: &str = "rollback_archive";

/// What one archived row holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchivedRow {
    pub source_kind: i16,
    pub locator: Vec<u8>,
    pub checkpoint_id: u64,
    /// `None` when the planned key held no row.  Distinct from an empty image.
    pub image: Option<Vec<u8>>,
    /// Per-column write timestamps, in schema order, encoded for storage.
    pub write_times: Vec<u8>,
}

/// How one row's archiving turned out.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveOutcome {
    /// Copied and read back identically.
    Archived,
    /// The slot already held exactly this content -- a retry of the same plan.
    AlreadyIdentical,
    /// The slot already held *different* content for this source key.  Never
    /// overwritten: the two disagree about history and only a human can say
    /// which is right.
    Conflict,
    /// The slot was **already there** and holds different content -- an earlier
    /// attempt of this same plan archived it, and the live row has moved since
    /// because that attempt went on to delete and restore it.
    ///
    /// Kept apart from `Conflict` because it is not a disagreement about
    /// history: the stored copy is the one taken before anything was destroyed,
    /// and it is the copy that must survive.  The Coordinator never sees this,
    /// because it skips archiving once the barrier is behind it; a Realm
    /// re-running its own recovery has no phase to skip on and reaches it every
    /// retry.
    AlreadyArchivedByAnEarlierAttempt,
}

/// What a read-back that disagrees with the live row means.
///
/// Pulled out of the I/O so the rule can be stated once and pinned: which of
/// the two it is turns entirely on whether this call created the slot, and
/// getting that backwards either hides a second writer or stops a Realm
/// forever. The whole difference is one boolean that used to be discarded.
pub(crate) const fn classify_readback(applied: bool, content_matches: bool) -> ArchiveOutcome {
    match (content_matches, applied) {
        (true, _) => ArchiveOutcome::AlreadyIdentical,
        // Written a moment ago and already different: something else is writing
        // the archive.
        (false, true) => ArchiveOutcome::Conflict,
        // The slot was already there, so it is an earlier attempt of this same
        // plan -- taken before that attempt deleted and restored the live row.
        (false, false) => ArchiveOutcome::AlreadyArchivedByAnEarlierAttempt,
    }
}


/// Copies planned rows into the archive and proves each copy.
pub struct ScyllaRollbackArchive {
    session: Arc<Session>,
    keyspace: String,
    reader: ScyllaRowImageReader,
    insert: PreparedStatement,
    read_back: PreparedStatement,
}

impl ScyllaRollbackArchive {
    pub async fn create_table(session: &Session, no_tablet_keyspace: &str) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {no_tablet_keyspace}.{ROLLBACK_ARCHIVE_TABLE} (
                        plan_id BLOB,
                        source_kind SMALLINT,
                        locator BLOB,
                        checkpoint_id BIGINT,
                        row_present BOOLEAN,
                        row_image BLOB,
                        write_times BLOB,
                        PRIMARY KEY ((plan_id, source_kind), locator)
                    )"
                ),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }

    /// The archive lives in the no-tablet keyspace because its writes are
    /// conditional, and LWT is only linearizable there.  The rows it copies come
    /// from the state keyspace, so the reader is prepared against that one.
    pub async fn prepare(
        session: Arc<Session>,
        state_keyspace: &str,
        no_tablet_keyspace: &str,
    ) -> anyhow::Result<Self> {
        let reader = ScyllaRowImageReader::prepare(session.clone(), state_keyspace).await?;
        let insert = session
            .prepare(format!(
                "INSERT INTO {no_tablet_keyspace}.{ROLLBACK_ARCHIVE_TABLE} \
                 (plan_id, source_kind, locator, checkpoint_id, row_present, row_image, \
                  write_times) VALUES (?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS"
            ))
            .await?;
        let read_back = session
            .prepare(format!(
                "SELECT checkpoint_id, row_present, row_image, write_times FROM \
                 {no_tablet_keyspace}.{ROLLBACK_ARCHIVE_TABLE} \
                 WHERE plan_id = ? AND source_kind = ? AND locator = ?"
            ))
            .await?;
        Ok(Self {
            session,
            keyspace: no_tablet_keyspace.to_string(),
            reader,
            insert,
            read_back,
        })
    }

    /// Copy one planned row and prove the copy.
    ///
    /// Reads the hot row, writes the archive slot conditionally, then reads the
    /// slot back and compares. The read-back is the point: without it this
    /// reports success for a write that a coordinator accepted and a replica
    /// never took.
    pub async fn archive_row(
        &self,
        plan_id: &[u8],
        checkpoint_id: u64,
        physical_table: u16,
        locator: &[u8],
    ) -> anyhow::Result<ArchiveOutcome> {
        let resolved: ResolvedScyllaKey = decode_locator_canonical(locator)
            .map_err(|error| anyhow::anyhow!("archive cannot decode locator: {error}"))?;
        let live = self.reader.read(&resolved).await?;
        let image = live.as_ref().map(|row| row.canonical_bytes());
        let write_times = live
            .as_ref()
            .map(encode_write_times)
            .unwrap_or_default();

        let applied = self
            .session
            .execute_unpaged(
                &self.insert,
                (
                    plan_id.to_vec(),
                    physical_table as i16,
                    locator.to_vec(),
                    checkpoint_id as i64,
                    image.is_some(),
                    image.clone().unwrap_or_default(),
                    write_times.clone(),
                ),
            )
            .await?;
        // Whether the conditional applied is what separates "the slot was empty
        // and this run filled it" from "the slot was already there".  It was
        // discarded before, and without it a retry cannot tell its own earlier
        // observation from someone else's contradictory one.
        let rows = applied.into_rows_result()?;
        let applied = match rows.column_specs().get_by_name("[applied]") {
            Some(column) => matches!(
                rows.single_row::<scylla::value::Row>()?.columns.get(column.0),
                Some(Some(scylla::value::CqlValue::Boolean(true)))
            ),
            None => true,
        };

        // Read back by the full source key, whether or not the conditional
        // applied: an existing slot has to be proven identical, not assumed so.
        let stored = self
            .session
            .execute_unpaged(
                &self.read_back,
                (plan_id.to_vec(), physical_table as i16, locator.to_vec()),
            )
            .await?
            .into_rows_result()?
            .maybe_first_row::<(i64, bool, Option<Vec<u8>>, Option<Vec<u8>>)>()?;
        let Some((stored_checkpoint, stored_present, stored_image, stored_times)) = stored else {
            anyhow::bail!(
                "archive slot for table {physical_table} is empty immediately after writing it"
            );
        };

        // Content only.  A slot reached by several checkpoints keeps the first
        // one, so comparing the height would report every axis-less table as a
        // conflict on its second visit.  Differing *content* for one source key
        // is the real conflict: two observations disagree about what was stored.
        let content_matches = stored_present == image.is_some()
            && stored_image.unwrap_or_default() == image.clone().unwrap_or_default()
            && stored_times.unwrap_or_default() == write_times;
        if !content_matches {
            return Ok(classify_readback(applied, content_matches));
        }
        if stored_checkpoint as u64 == checkpoint_id {
            Ok(ArchiveOutcome::Archived)
        } else {
            // The slot was already filled by a lower checkpoint in this same
            // plan, which is how an overwrite-in-place table looks from here.
            Ok(ArchiveOutcome::AlreadyIdentical)
        }
    }

    /// Everything archived for one plan and table.
    pub async fn rows_for(
        &self,
        plan_id: &[u8],
        physical_table: u16,
    ) -> anyhow::Result<Vec<ArchivedRow>> {
        let rows = self
            .session
            .query_unpaged(
                format!(
                    "SELECT locator, checkpoint_id, row_present, row_image, write_times FROM \
                     {}.{ROLLBACK_ARCHIVE_TABLE} WHERE plan_id = ? AND source_kind = ?",
                    self.keyspace
                ),
                (plan_id.to_vec(), physical_table as i16),
            )
            .await?
            .into_rows_result()?;
        let mut out = Vec::new();
        for row in rows.rows::<(Vec<u8>, i64, bool, Option<Vec<u8>>, Option<Vec<u8>>)>()? {
            let (locator, checkpoint_id, present, image, times) = row?;
            out.push(ArchivedRow {
                source_kind: physical_table as i16,
                locator,
                checkpoint_id: checkpoint_id as u64,
                image: image.filter(|_| present),
                write_times: times.unwrap_or_default(),
            });
        }
        Ok(out)
    }

    /// Every `(table, locator)` the archive holds in a range, whatever plan put
    /// it there.
    ///
    /// Without the checkpoint, because the archive keeps **one row per key**:
    /// a slot several checkpoints reached keeps the first one, which is the
    /// value a restore needs. Including the height here reported every
    /// singleton as missing on its second visit -- twenty rows of LatestInfo
    /// and U64Singleton out of 2904, one per checkpoint past the first.
    ///
    /// Deliberately not filtered by plan id.  The question a resume needs
    /// answered is whether these rows were archived, not who archived them --
    /// and the plan id is caller-supplied, so keying on it is what let one run
    /// archive under `acceptance-6971-6961` and its own resume look under
    /// `acceptance-6972-6961` and find nothing.
    ///
    /// This scans, because the archive is partitioned by plan id and nothing
    /// indexes the checkpoint. That is affordable only because it runs on the
    /// resume path after a digest mismatch, which is rare, and never during a
    /// commit.
    pub async fn rows_in_range(
        &self,
        target: u64,
        head: u64,
    ) -> anyhow::Result<std::collections::HashSet<(i16, Vec<u8>)>> {
        let rows = self
            .session
            .query_unpaged(
                format!(
                    "SELECT source_kind, locator FROM \
                     {}.{ROLLBACK_ARCHIVE_TABLE} WHERE checkpoint_id > ? AND checkpoint_id <= ? \
                     ALLOW FILTERING",
                    self.keyspace
                ),
                (target as i64, head as i64),
            )
            .await?
            .into_rows_result()?;
        let mut out = std::collections::HashSet::new();
        for row in rows.rows::<(i16, Vec<u8>)>()? {
            let (source_kind, locator) = row?;
            out.insert((source_kind, locator));
        }
        Ok(out)
    }

    /// How many rows one plan holds, across every table it touched.
    pub async fn row_count(&self, plan_id: &[u8]) -> anyhow::Result<i64> {
        let count = self
            .session
            .query_unpaged(
                format!(
                    "SELECT count(*) FROM {}.{ROLLBACK_ARCHIVE_TABLE} WHERE plan_id = ? \
                     ALLOW FILTERING",
                    self.keyspace
                ),
                (plan_id.to_vec(),),
            )
            .await?
            .into_rows_result()?
            .first_row::<(i64,)>()?
            .0;
        Ok(count)
    }
}

/// Per-column write timestamps, in schema order.
///
/// Stored beside the value because §2.3 asks for them and because a restore has
/// to know what the delete fence had to beat. Absent timestamps -- a row that is
/// entirely primary key has no cell to ask about -- encode as a marker rather
/// than as zero, which would read as a real timestamp at the epoch.
fn encode_write_times(row: &RowImage) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + row.columns().len() * 9);
    out.push(row.columns().len() as u8);
    for column in row.columns() {
        match column.write_time_us {
            Some(value) => {
                out.push(1);
                out.extend_from_slice(&value.to_be_bytes());
            }
            None => out.push(0),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_write_time_is_not_the_epoch() {
        // A key-only row has no cell to read a timestamp from.  Encoding that as
        // zero would claim it was written in 1970, and a fence comparison would
        // then always think it dominated.
        let present = encode_write_times(&RowImage::for_test(vec![Some(1_700_000_000_000_000)]));
        let absent = encode_write_times(&RowImage::for_test(vec![None]));
        assert_ne!(present, absent);
        assert_eq!(absent, vec![1, 0]);
    }
}

#[cfg(test)]
mod readback_rules {
    use super::{classify_readback, ArchiveOutcome};

    #[test]
    fn a_slot_this_call_created_that_already_differs_is_someone_else_writing() {
        assert_eq!(
            classify_readback(true, false),
            ArchiveOutcome::Conflict,
            "nothing legitimate can change a slot between writing it and reading it back"
        );
    }

    #[test]
    fn a_slot_that_was_already_there_is_this_plans_own_earlier_attempt() {
        // The Realm's recovery re-archives after its own delete and restore, so
        // the live row cannot match the copy any more. Calling that a conflict
        // stopped a chain for 816 retries.
        assert_eq!(
            classify_readback(false, false),
            ArchiveOutcome::AlreadyArchivedByAnEarlierAttempt
        );
    }

    #[test]
    fn matching_content_is_a_plain_retry_whoever_wrote_it() {
        assert_eq!(classify_readback(true, true), ArchiveOutcome::AlreadyIdentical);
        assert_eq!(classify_readback(false, true), ArchiveOutcome::AlreadyIdentical);
    }
}
