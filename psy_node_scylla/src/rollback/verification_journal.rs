//! Records what every recorded key looked like before and after each commit.
//!
//! design-r1 §2.2.1 keeps the manifest to keys alone, which rests on two
//! inferences: that deleting a version makes a read fall back to the previous
//! one, and that the handful of recomputable tables can be rebuilt from the
//! target's authoritative state.  If either is wrong a rollback produces a state
//! that is self-consistent and yet does not match history -- and a root check
//! will not catch it, because a wrongly recomputed tree is self-consistent too.
//!
//! The journal turns those inferences into an assertion made of observations.
//! With `c(K)` the first checkpoint in `(T, old_head]` that touches physical key
//! `K`, after a rollback to `T`:
//!
//! ```text
//! live(K) == journal[c(K)].before      (byte for byte, when before exists)
//! live(K) does not exist               (when K was born at c(K))
//! ```
//!
//! Nothing here derives what a value *should* be; it compares against what was
//! actually observed at the time.
//!
//! ## `before` is a production-shaped read, not a point read
//!
//! `live(K)` means what a production read returns, and on a version-axis table
//! that is `checkpoint_id <= ? LIMIT 1`.  These tables are sparse -- a node is
//! written only at the checkpoints that change it -- so a point read at `c` finds
//! nothing for a key whose latest version is older, and recording that as an
//! absent `before` would claim the key was born at `c`.  The assertion would then
//! demand it not exist after the rollback, and a correct rollback would fail it.
//!
//! ## Development and test only
//!
//! This is an added verification layer that takes part in no delete decision, so
//! it is off unless asked for.  Turning it off loses only verification and never
//! leaves the manifest incomplete, which is why it does not conflict with §0.2 D3.
//! What it must not become is optional to *run*: the spike's lesson is that any
//! check that can be skipped eventually is, so §11.3 makes a full rollback with
//! the journal on a required part of G-A rather than an extra.

use std::sync::Arc;

use scylla::client::session::Session;
use scylla::statement::batch::Batch;
use scylla::statement::prepared::PreparedStatement;

use super::{ScyllaRowImageReader, decode_locator_canonical};

/// Where the journal keeps its observations.
///
/// Its own table, in the state keyspace: it is dropped wholesale between runs and
/// never enters production capacity planning (§2.2.2).
pub const VERIFICATION_JOURNAL_TABLE: &str = "rollback_verification_journal";

/// Records before/after images for the keys one commit writes.
pub struct ScyllaVerificationJournal {
    session: Arc<Session>,
    keyspace: String,
    reader: ScyllaRowImageReader,
    write_before: PreparedStatement,
    write_after: PreparedStatement,
}

/// One observation, as stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalEntry {
    pub checkpoint_id: u64,
    pub physical_table: i16,
    pub locator: Vec<u8>,
    /// `None` means the key did not exist -- distinct from existing with an empty
    /// value, which is what a rollback assertion has to tell apart.
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
    pub before_version: Option<u64>,
}

#[async_trait::async_trait]
impl psy_node_core::store::verification_journal::CommitVerificationJournal
    for ScyllaVerificationJournal
{
    async fn rewritten_before_images(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<Vec<(u16, Vec<u8>, Vec<u8>)>> {
        Ok(self
            .entries_for(checkpoint_id)
            .await?
            .into_iter()
            .filter_map(|entry| {
                entry
                    .before
                    .map(|before| (entry.physical_table as u16, entry.locator, before))
            })
            .collect())
    }

    async fn record_before(
        &self,
        checkpoint_id: u64,
        planned: &[(u16, Vec<u8>)],
    ) -> anyhow::Result<()> {
        ScyllaVerificationJournal::record_before(self, checkpoint_id, planned).await
    }

    async fn record_after(
        &self,
        checkpoint_id: u64,
        planned: &[(u16, Vec<u8>)],
    ) -> anyhow::Result<()> {
        ScyllaVerificationJournal::record_after(self, checkpoint_id, planned).await
    }
}

impl ScyllaVerificationJournal {
    pub async fn create_table(session: &Session, keyspace: &str) -> anyhow::Result<()> {
        session
            .query_unpaged(
                format!(
                    "CREATE TABLE IF NOT EXISTS {keyspace}.{VERIFICATION_JOURNAL_TABLE} (
                        checkpoint_id BIGINT,
                        physical_table SMALLINT,
                        locator BLOB,
                        before_image BLOB,
                        before_present BOOLEAN,
                        before_version BIGINT,
                        after_image BLOB,
                        after_present BOOLEAN,
                        PRIMARY KEY ((checkpoint_id), physical_table, locator)
                    )"
                ),
                &[],
            )
            .await?;
        session.await_schema_agreement().await?;
        Ok(())
    }

    pub async fn prepare(session: Arc<Session>, keyspace: &str) -> anyhow::Result<Self> {
        let reader = ScyllaRowImageReader::prepare(session.clone(), keyspace).await?;
        let write_before = session
            .prepare(format!(
                "INSERT INTO {keyspace}.{VERIFICATION_JOURNAL_TABLE} \
                 (checkpoint_id, physical_table, locator, before_image, before_present, \
                  before_version) VALUES (?, ?, ?, ?, ?, ?)"
            ))
            .await?;
        let write_after = session
            .prepare(format!(
                "INSERT INTO {keyspace}.{VERIFICATION_JOURNAL_TABLE} \
                 (checkpoint_id, physical_table, locator, after_image, after_present) \
                 VALUES (?, ?, ?, ?, ?)"
            ))
            .await?;
        Ok(Self {
            session,
            keyspace: keyspace.to_string(),
            reader,
            write_before,
            write_after,
        })
    }

    /// Observe every key this commit is about to write, before it writes them.
    ///
    /// Must run before the state writes.  Version-axis tables would survive a
    /// later reading -- their old row is still there -- but the singletons and
    /// cursors are overwritten in place, and once overwritten their previous
    /// value exists nowhere.
    pub async fn record_before(
        &self,
        checkpoint_id: u64,
        planned: &[(u16, Vec<u8>)],
    ) -> anyhow::Result<()> {
        // The state as a production read saw it just before this commit.  For a
        // version-axis table that is the newest version at or below `c - 1`;
        // reading at `c` would find this commit's own row once it lands, and
        // reading a sparse table at `c` beforehand would find nothing at all.
        let previous = checkpoint_id.saturating_sub(1);
        self.record_pass(checkpoint_id, planned, previous, true)
            .await
    }

    /// Observe the same keys once the commit has written them.
    ///
    /// The after image is what makes the journal check the *manifest* rather than
    /// only the rollback: a key whose stored value differs from the newest
    /// recorded after image was written by something the manifest never named,
    /// which is the under-recording that leaves ghosts at reused heights.
    pub async fn record_after(
        &self,
        checkpoint_id: u64,
        planned: &[(u16, Vec<u8>)],
    ) -> anyhow::Result<()> {
        self.record_pass(checkpoint_id, planned, checkpoint_id, false)
            .await
    }

    async fn record_pass(
        &self,
        checkpoint_id: u64,
        planned: &[(u16, Vec<u8>)],
        as_of: u64,
        is_before: bool,
    ) -> anyhow::Result<()> {
        let statement = if is_before {
            &self.write_before
        } else {
            &self.write_after
        };
        // Batched in chunks: one round trip per key would multiply a commit's
        // latency by its row count, and this runs inside the commit.
        for chunk in planned.chunks(64) {
            let mut batch = Batch::default();
            let mut values: Vec<Vec<scylla::value::CqlValue>> = Vec::with_capacity(chunk.len());
            for (physical_table, locator) in chunk {
                let Ok(resolved) = decode_locator_canonical(locator) else {
                    // A locator that will not decode cannot be read, and guessing
                    // would put a fabricated observation in the evidence.
                    continue;
                };
                let image = self.reader.read_as_of(&resolved, as_of).await;
                let image = match image {
                    Ok(image) => image,
                    // Tables outside the recorded read shapes are skipped rather
                    // than recorded as absent, for the same reason.
                    Err(_) => continue,
                };
                let bytes = image.as_ref().map(|image| image.canonical_bytes());
                let version = image.as_ref().and_then(|image| image.resolved_checkpoint());
                batch.append_statement(statement.clone());
                let mut row = vec![
                    scylla::value::CqlValue::BigInt(checkpoint_id as i64),
                    scylla::value::CqlValue::SmallInt(*physical_table as i16),
                    scylla::value::CqlValue::Blob(locator.clone()),
                    match &bytes {
                        Some(bytes) => scylla::value::CqlValue::Blob(bytes.clone()),
                        None => scylla::value::CqlValue::Blob(Vec::new()),
                    },
                    scylla::value::CqlValue::Boolean(bytes.is_some()),
                ];
                if is_before {
                    row.push(match version {
                        Some(version) => scylla::value::CqlValue::BigInt(version as i64),
                        None => scylla::value::CqlValue::BigInt(-1),
                    });
                }
                values.push(row);
            }
            if values.is_empty() {
                continue;
            }
            self.session.batch(&batch, values).await?;
        }
        Ok(())
    }

    /// Every observation recorded for one checkpoint.
    pub async fn entries_for(&self, checkpoint_id: u64) -> anyhow::Result<Vec<JournalEntry>> {
        let table = format!("{}.{VERIFICATION_JOURNAL_TABLE}", self.keyspace);
        let rows = self
            .session
            .query_unpaged(
                format!(
                    "SELECT physical_table, locator, before_image, before_present, \
                     before_version, after_image, after_present FROM {table} \
                     WHERE checkpoint_id = ?"
                ),
                (checkpoint_id as i64,),
            )
            .await?
            .into_rows_result()?;
        let mut out = Vec::new();
        for row in rows.rows::<(
            i16,
            Vec<u8>,
            Option<Vec<u8>>,
            Option<bool>,
            Option<i64>,
            Option<Vec<u8>>,
            Option<bool>,
        )>()? {
            let (physical_table, locator, before, before_present, before_version, after, after_present) =
                row?;
            out.push(JournalEntry {
                checkpoint_id,
                physical_table,
                locator,
                before: before.filter(|_| before_present.unwrap_or(false)),
                after: after.filter(|_| after_present.unwrap_or(false)),
                before_version: before_version.filter(|version| *version >= 0).map(|v| v as u64),
            });
        }
        Ok(out)
    }
}
