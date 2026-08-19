//! Puts back what a rollback deleted but should not have.
//!
//! A rollback plans every locator the manifest names and deletes it.  On a
//! version-axis table that is exactly right: the locator names one version among
//! many, so deleting the discarded one leaves the earlier one standing.  On a
//! table without one -- a row per key, overwritten in place -- it is right only
//! when the discarded commit *created* the row.  When it *rewrote* an existing
//! row, deleting destroys the only copy and the value from before the range is
//! gone.
//!
//! The manifest cannot tell those apart: it records the key and the operation,
//! not whether the row existed beforehand.  The verification journal can, and
//! does, because it observes every recorded key immediately before the commit
//! that writes it (design-r1 §2.2.2).  That makes the rule per row rather than
//! per table, and self-selecting:
//!
//! - a version-axis row is created at its own locator, so its before image is
//!   absent and nothing is restored;
//! - an axis-less row that was rewritten has a before image, and it is put back;
//! - an axis-less row that was created has none, and stays deleted.
//!
//! No table list is involved, which matters because a list is the thing that
//! goes stale.  Excluding whole tables was tried and cannot work: the same table
//! holds rows the range created, which must go, and rows it rewrote, which must
//! not.
//!
//! ## Which before image
//!
//! The one recorded at `c(K)`: the first checkpoint above the target that
//! touched this key *position*.  Not the last, and not the target's own -- the
//! state to restore is what a reader would have seen just before the discarded
//! range began, and only the first touch above the target observed that.
//!
//! ## Why the write sits above the fence
//!
//! The delete fence is a tombstone timestamp above every write the discarded
//! range made.  A restored row written under it would be shadowed: the insert
//! succeeds, reports nothing, and the row cannot be read.  Restoring therefore
//! writes at `fence + 1`, the same rule the singleton restore already follows.

use std::collections::HashMap;
use std::sync::Arc;

use psy_node_core::store::timestamp::DeleteFenceTimestampUs;
use scylla::client::session::Session;
use scylla::statement::prepared::PreparedStatement;
use scylla::value::CqlValue;
use strum::IntoEnumIterator;

use super::row_image::{cql_key_values, decode_canonical_row, key_column_names, table_shape};
use super::{
    ColumnKind, ResolvedScyllaKey, ScyllaPhysicalTableId, decode_locator_canonical,
    physical_descriptor,
};

/// Writes recorded rows back at a fixed timestamp above the fence.
pub struct ScyllaRestoreExecutor {
    session: Arc<Session>,
    inserts: HashMap<ScyllaPhysicalTableId, PreparedStatement>,
}

impl ScyllaRestoreExecutor {
    pub async fn prepare(session: Arc<Session>, keyspace: &str) -> anyhow::Result<Self> {
        let mut inserts = HashMap::new();
        for table in ScyllaPhysicalTableId::iter() {
            let Some(shape) = table_shape(table) else {
                continue;
            };
            let name = physical_descriptor(table).physical_name;
            let mut columns = key_column_names(table);
            columns.extend(shape.value_columns.iter().map(|(name, _)| *name));
            let placeholders = vec!["?"; columns.len()].join(", ");
            // The timestamp is bound rather than formatted, for the reason the
            // delete's fence is: a value spliced into CQL text is one more place
            // for a wrong one to look right.
            let cql = format!(
                "INSERT INTO {keyspace}.{name} ({}) VALUES ({placeholders}) USING TIMESTAMP ?",
                columns.join(", ")
            );
            inserts.insert(table, session.prepare(cql).await?);
        }
        Ok(Self { session, inserts })
    }

    /// Put one row back, as the journal observed it before the discarded range.
    pub async fn restore_row(
        &self,
        fence: DeleteFenceTimestampUs,
        locator: &[u8],
        before_image: &[u8],
    ) -> anyhow::Result<()> {
        let resolved: ResolvedScyllaKey = decode_locator_canonical(locator)
            .map_err(|error| anyhow::anyhow!("restore cannot decode locator: {error}"))?;
        let table = resolved.physical_table();
        let prepared = self.inserts.get(&table).ok_or_else(|| {
            anyhow::anyhow!(
                "physical table {table:?} is not on the recorded commit path, so a rollback \
                 must not write to it"
            )
        })?;
        let shape = table_shape(table).ok_or_else(|| {
            anyhow::anyhow!("physical table {table:?} has no recorded shape to restore into")
        })?;

        let values = decode_canonical_row(before_image)?;
        if values.len() != shape.value_columns.len() {
            // The stored image describes a different number of columns than this
            // build expects.  Writing it anyway would put back a row whose
            // columns are shifted by one, which reads as valid data.
            anyhow::bail!(
                "a stored row image for {table:?} has {} columns but the table has {}",
                values.len(),
                shape.value_columns.len()
            );
        }

        // Bound as options so a null column stays null.  `CqlValue::Empty` is a
        // zero-length value, which for a bigint is a different thing entirely --
        // writing it where NULL belongs would restore a row that reads as valid
        // and is not what was there.
        let mut bound: Vec<Option<CqlValue>> = cql_key_values(resolved.typed_key())?
            .into_iter()
            .map(Some)
            .collect();
        for ((_, kind), value) in shape.value_columns.iter().zip(values) {
            bound.push(cql_value_of(*kind, value)?);
        }
        // Above the fence, or the tombstone just written would hide it.
        bound.push(Some(CqlValue::BigInt(fence.as_i64() + 1)));
        self.session.execute_unpaged(prepared, bound).await?;
        Ok(())
    }
}

/// Rebuild one column's CQL value from the bytes the journal stored.
///
/// The kind comes from the table's shape rather than from the image, because the
/// image carries only bytes.  A uuid handed back as a blob would be rejected by
/// the driver rather than written wrong, which is the safe direction, but the
/// conversion is done here so it never gets that far.
fn cql_value_of(kind: ColumnKind, value: Option<Vec<u8>>) -> anyhow::Result<Option<CqlValue>> {
    let Some(bytes) = value else {
        return Ok(None);
    };
    Ok(Some(match kind {
        ColumnKind::Blob => CqlValue::Blob(bytes),
        ColumnKind::BigInt => {
            let raw: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("a stored bigint column is {} bytes, not 8", bytes.len())
            })?;
            CqlValue::BigInt(i64::from_be_bytes(raw))
        }
        ColumnKind::Uuid => {
            let raw: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("a stored uuid column is {} bytes, not 16", bytes.len())
            })?;
            CqlValue::Uuid(uuid::Uuid::from_bytes(raw))
        }
    }))
}
