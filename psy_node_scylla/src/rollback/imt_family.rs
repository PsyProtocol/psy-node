//! D-02T6 coordinated timestamp/fence plans for the three IMT tables.
//!
//! A leaf FFS entry is the semantic source. The plan validates its typed leaf
//! locator, derives any key-index birth, and computes the cursor transition
//! from an explicit before-image. This keeps the three physical tables in one
//! retry identity without claiming cross-table CQL atomicity.
//!
//! ```compile_fail
//! use psy_node_scylla::rollback::ImtFamilyAdapter;
//! ```

use std::{collections::{BTreeMap, BTreeSet}, error::Error, fmt};

use psy_node_core::store::{
    timestamp::{DeleteFenceTimestampUs, NewBranchWriteTimestampUs},
    typed::{
        CheckpointId, ImtCursorTransition, ImtCursorTransitionError,
        ImtEncodedKey, LeafIndex, LogicalMutation, MutationOperation,
        MutationValue, StructuredValueSchema, TreeId, TreeSubId,
        TypedTableKey,
    },
};
use scylla::{
    client::session::Session,
    statement::{prepared::PreparedStatement, Consistency},
};
use sha2::{Digest, Sha256};

use crate::utils::{convert_checkpoint_id_to_i64, u64_to_i64_exact};

use super::{
    physical_descriptor, resolve_key_for_rollback, CqlKeyspaceName, PrototypeBindValue,
    RegistryReadinessError, ScyllaPhysicalTableId, SealedTimestampedPut,
};

const IMT_LEAF_ROW_V1_BYTES: usize = 161;
const HASH_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ImtQueryKind {
    LeafPut = 1,
    LeafPointDelete = 2,
    LeafBoundedRangeDelete = 3,
    IndexPut = 4,
    IndexPointDelete = 5,
    CursorPut = 6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImtQuery {
    kind: ImtQueryKind,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl ImtQuery {
    pub const fn kind(&self) -> ImtQueryKind { self.kind }
    pub fn cql(&self) -> &str { &self.cql }
    pub const fn bind_shape(&self) -> &'static [&'static str] { self.bind_shape }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImtQueries {
    leaf_put: ImtQuery,
    leaf_point_delete: ImtQuery,
    leaf_range_delete: ImtQuery,
    index_put: ImtQuery,
    index_point_delete: ImtQuery,
    cursor_put: ImtQuery,
}

impl ImtQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        let leaf = format!(
            "{}.{}",
            keyspace.as_str(),
            physical_descriptor(ScyllaPhysicalTableId::ImtLeaf).physical_name
        );
        let index = format!(
            "{}.{}",
            keyspace.as_str(),
            physical_descriptor(ScyllaPhysicalTableId::ImtKeyIndex).physical_name
        );
        let cursor = format!(
            "{}.{}",
            keyspace.as_str(),
            physical_descriptor(ScyllaPhysicalTableId::ImtNextAppendIndex).physical_name
        );
        Self {
            leaf_put: query(
                ImtQueryKind::LeafPut,
                format!("INSERT INTO {leaf} (tree_id, tree_sub_id, leaf_index, checkpoint_id, leaf_hash, leaf_key, leaf_value, next_key, next_index) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) USING TIMESTAMP ?"),
                &["tree_id:BIGINT", "tree_sub_id:BIGINT", "leaf_index:BIGINT", "checkpoint_id:BIGINT", "leaf_hash:BLOB", "leaf_key:BLOB", "leaf_value:BLOB", "next_key:BLOB", "next_index:BIGINT", "write_timestamp_us:BIGINT"],
            ),
            leaf_point_delete: query(
                ImtQueryKind::LeafPointDelete,
                format!("DELETE FROM {leaf} USING TIMESTAMP ? WHERE tree_id = ? AND tree_sub_id = ? AND leaf_index = ? AND checkpoint_id = ?"),
                &["delete_fence_us:BIGINT", "tree_id:BIGINT", "tree_sub_id:BIGINT", "leaf_index:BIGINT", "checkpoint_id:BIGINT"],
            ),
            leaf_range_delete: query(
                ImtQueryKind::LeafBoundedRangeDelete,
                format!("DELETE FROM {leaf} USING TIMESTAMP ? WHERE tree_id = ? AND tree_sub_id = ? AND leaf_index = ? AND checkpoint_id > ? AND checkpoint_id <= ?"),
                &["delete_fence_us:BIGINT", "tree_id:BIGINT", "tree_sub_id:BIGINT", "leaf_index:BIGINT", "target_exclusive:BIGINT", "old_head_inclusive:BIGINT"],
            ),
            index_put: query(
                ImtQueryKind::IndexPut,
                format!("INSERT INTO {index} (tree_id, tree_sub_id, key_bucket, encoded_key, leaf_key, birth_checkpoint, leaf_index) VALUES (?, ?, ?, ?, ?, ?, ?) USING TIMESTAMP ?"),
                &["tree_id:BIGINT", "tree_sub_id:BIGINT", "key_bucket:SMALLINT", "encoded_key:BLOB", "leaf_key:BLOB", "birth_checkpoint:BIGINT", "leaf_index:BIGINT", "write_timestamp_us:BIGINT"],
            ),
            index_point_delete: query(
                ImtQueryKind::IndexPointDelete,
                format!("DELETE FROM {index} USING TIMESTAMP ? WHERE tree_id = ? AND tree_sub_id = ? AND key_bucket = ? AND encoded_key = ?"),
                &["delete_fence_us:BIGINT", "tree_id:BIGINT", "tree_sub_id:BIGINT", "key_bucket:SMALLINT", "encoded_key:BLOB"],
            ),
            cursor_put: query(
                ImtQueryKind::CursorPut,
                format!("INSERT INTO {cursor} (tree_id, tree_sub_id, next_append_index) VALUES (?, ?, ?) USING TIMESTAMP ?"),
                &["tree_id:BIGINT", "tree_sub_id:BIGINT", "next_append_index:BIGINT", "write_timestamp_us:BIGINT"],
            ),
        }
    }

    pub const fn leaf_put(&self) -> &ImtQuery { &self.leaf_put }
    pub const fn leaf_point_delete(&self) -> &ImtQuery { &self.leaf_point_delete }
    pub const fn leaf_range_delete(&self) -> &ImtQuery { &self.leaf_range_delete }
    pub const fn index_put(&self) -> &ImtQuery { &self.index_put }
    pub const fn index_point_delete(&self) -> &ImtQuery { &self.index_point_delete }
    pub const fn cursor_put(&self) -> &ImtQuery { &self.cursor_put }

    pub fn render_golden(&self) -> String {
        let mut output = String::new();
        for query in [
            self.leaf_put(),
            self.leaf_point_delete(),
            self.leaf_range_delete(),
            self.index_put(),
            self.index_point_delete(),
            self.cursor_put(),
        ] {
            output.push_str(&format!(
                "{:?}\n{}\n{}\n",
                query.kind(), query.cql(), query.bind_shape().join(",")
            ));
        }
        output
    }
}

fn query(kind: ImtQueryKind, cql: String, bind_shape: &'static [&'static str]) -> ImtQuery {
    ImtQuery { kind, cql, bind_shape }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ImtCursorSnapshot {
    tree: TreeId,
    tree_sub: TreeSubId,
    next_append_index: u64,
}

impl ImtCursorSnapshot {
    pub const fn new(tree: TreeId, tree_sub: TreeSubId, next_append_index: u64) -> Self {
        Self { tree, tree_sub, next_append_index }
    }
    pub const fn tree(&self) -> TreeId { self.tree }
    pub const fn tree_sub(&self) -> TreeSubId { self.tree_sub }
    pub const fn next_append_index(&self) -> u64 { self.next_append_index }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ImtCheckpointWriteDigest([u8; 32]);

impl ImtCheckpointWriteDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImtLeafPutBinding {
    tree: TreeId,
    tree_sub: TreeSubId,
    leaf: LeafIndex,
    checkpoint: CheckpointId,
    leaf_hash: [u8; HASH_BYTES],
    leaf_key: [u8; HASH_BYTES],
    leaf_value: [u8; HASH_BYTES],
    next_key: [u8; HASH_BYTES],
    next_index: u64,
    is_new_key: bool,
    write_timestamp_us: i64,
}

impl ImtLeafPutBinding {
    pub fn try_from_sealed(sealed: &SealedTimestampedPut) -> Result<Self, ImtPlanError> {
        let mutation = sealed.resolved().mutation();
        if mutation.physical_table() != ScyllaPhysicalTableId::ImtLeaf {
            return Err(ImtPlanError::WrongPhysicalTable(mutation.physical_table()));
        }
        let (tree, tree_sub, leaf, checkpoint) = match mutation.key() {
            TypedTableKey::ImtLeaf { tree, tree_sub, leaf, checkpoint } => {
                (*tree, *tree_sub, *leaf, *checkpoint)
            }
            _ => return Err(ImtPlanError::WrongTypedKey),
        };
        let bytes = match mutation.operation() {
            MutationOperation::Put(MutationValue::Structured {
                schema: StructuredValueSchema::ImtLeafRowV1,
                canonical_bytes,
            }) => canonical_bytes,
            _ => return Err(ImtPlanError::ExpectedLeafRowV1),
        };
        let parsed = ParsedLeafRow::try_parse(bytes)?;
        if parsed.tree_id != tree.get()
            || parsed.tree_sub_id != tree_sub.get()
            || parsed.leaf_index != leaf.get()
        {
            return Err(ImtPlanError::LeafKeyRowMismatch);
        }
        Ok(Self {
            tree,
            tree_sub,
            leaf,
            checkpoint,
            leaf_hash: parsed.leaf_hash,
            leaf_key: parsed.leaf_key,
            leaf_value: parsed.leaf_value,
            next_key: parsed.next_key,
            next_index: parsed.next_index,
            is_new_key: parsed.is_new_key,
            write_timestamp_us: sealed.timestamp().as_i64(),
        })
    }

    pub const fn tree(&self) -> TreeId { self.tree }
    pub const fn tree_sub(&self) -> TreeSubId { self.tree_sub }
    pub const fn leaf(&self) -> LeafIndex { self.leaf }
    pub const fn checkpoint(&self) -> CheckpointId { self.checkpoint }
    pub const fn leaf_key(&self) -> &[u8; HASH_BYTES] { &self.leaf_key }
    pub const fn next_index(&self) -> u64 { self.next_index }
    pub const fn is_new_key(&self) -> bool { self.is_new_key }
    pub const fn write_timestamp_us(&self) -> i64 { self.write_timestamp_us }

    fn creates_index(&self) -> bool {
        self.is_new_key
            || (self.leaf_key.iter().all(|byte| *byte == 0)
                && self.leaf_value.iter().all(|byte| *byte == 0))
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.tree.get())),
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.tree_sub.get())),
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.leaf.get())),
            PrototypeBindValue::BigInt(convert_checkpoint_id_to_i64(self.checkpoint.get())),
            PrototypeBindValue::Blob(self.leaf_hash.to_vec()),
            PrototypeBindValue::Blob(self.leaf_key.to_vec()),
            PrototypeBindValue::Blob(self.leaf_value.to_vec()),
            PrototypeBindValue::Blob(self.next_key.to_vec()),
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.next_index)),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    fn driver_values(&self) -> (i64, i64, i64, i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64) {
        (
            u64_to_i64_exact(self.tree.get()), u64_to_i64_exact(self.tree_sub.get()),
            u64_to_i64_exact(self.leaf.get()), convert_checkpoint_id_to_i64(self.checkpoint.get()),
            self.leaf_hash.to_vec(), self.leaf_key.to_vec(), self.leaf_value.to_vec(),
            self.next_key.to_vec(), u64_to_i64_exact(self.next_index), self.write_timestamp_us,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImtIndexPutBinding {
    tree: TreeId,
    tree_sub: TreeSubId,
    encoded_key: ImtEncodedKey,
    leaf_key: [u8; HASH_BYTES],
    birth_checkpoint: CheckpointId,
    leaf: LeafIndex,
    write_timestamp_us: i64,
}

impl ImtIndexPutBinding {
    pub const fn tree(&self) -> TreeId { self.tree }
    pub const fn tree_sub(&self) -> TreeSubId { self.tree_sub }
    pub const fn encoded_key(&self) -> &ImtEncodedKey { &self.encoded_key }
    pub const fn birth_checkpoint(&self) -> CheckpointId { self.birth_checkpoint }
    pub const fn leaf(&self) -> LeafIndex { self.leaf }
    pub const fn write_timestamp_us(&self) -> i64 { self.write_timestamp_us }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.tree.get())),
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.tree_sub.get())),
            PrototypeBindValue::SmallInt(self.encoded_key.cql_bucket()),
            PrototypeBindValue::Blob(self.encoded_key.as_bytes().to_vec()),
            PrototypeBindValue::Blob(self.leaf_key.to_vec()),
            PrototypeBindValue::BigInt(convert_checkpoint_id_to_i64(self.birth_checkpoint.get())),
            PrototypeBindValue::BigInt(u64_to_i64_exact(self.leaf.get())),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    fn driver_values(&self) -> (i64, i64, i16, Vec<u8>, Vec<u8>, i64, i64, i64) {
        (
            u64_to_i64_exact(self.tree.get()), u64_to_i64_exact(self.tree_sub.get()),
            self.encoded_key.cql_bucket(), self.encoded_key.as_bytes().to_vec(),
            self.leaf_key.to_vec(), convert_checkpoint_id_to_i64(self.birth_checkpoint.get()),
            u64_to_i64_exact(self.leaf.get()), self.write_timestamp_us,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImtCursorPutBinding {
    before: ImtCursorSnapshot,
    after: ImtCursorSnapshot,
    transition: ImtCursorTransition,
    write_timestamp_us: i64,
}

impl ImtCursorPutBinding {
    pub const fn before(&self) -> ImtCursorSnapshot { self.before }
    pub const fn after(&self) -> ImtCursorSnapshot { self.after }
    pub const fn checkpoint(&self) -> CheckpointId { self.transition.checkpoint() }
    pub const fn durable_transition(&self) -> ImtCursorTransition { self.transition }
    pub const fn write_timestamp_us(&self) -> i64 { self.write_timestamp_us }

    pub fn durable_supplement(&self) -> LogicalMutation {
        LogicalMutation::Put {
            key: TypedTableKey::ImtCursor {
                tree: self.after.tree,
                tree_sub: self.after.tree_sub,
            },
            value: MutationValue::imt_cursor_transition(self.transition),
        }
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        cursor_bind_values(self.after, self.write_timestamp_us)
    }

    fn driver_values(&self) -> (i64, i64, i64, i64) {
        cursor_driver_values(self.after, self.write_timestamp_us)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImtCheckpointWritePlan {
    checkpoint: CheckpointId,
    write_timestamp_us: i64,
    leaf_puts: Vec<ImtLeafPutBinding>,
    index_puts: Vec<ImtIndexPutBinding>,
    cursor_puts: Vec<ImtCursorPutBinding>,
    digest: ImtCheckpointWriteDigest,
}

impl ImtCheckpointWritePlan {
    pub fn try_from_sealed_leaves(
        sealed: &[SealedTimestampedPut],
        cursor_before: &[ImtCursorSnapshot],
    ) -> Result<Self, ImtPlanError> {
        let first_sealed = sealed.first().ok_or(ImtPlanError::EmptyLeafBatch)?;
        let first = ImtLeafPutBinding::try_from_sealed(first_sealed)?;
        let checkpoint = first.checkpoint;
        let write_timestamp_us = first.write_timestamp_us;
        let mut parsed = Vec::with_capacity(sealed.len());
        parsed.push(first);
        for member in &sealed[1..] {
            let binding = ImtLeafPutBinding::try_from_sealed(member)?;
            if binding.checkpoint != checkpoint {
                return Err(ImtPlanError::MixedCheckpoints { expected: checkpoint, actual: binding.checkpoint });
            }
            if binding.write_timestamp_us != write_timestamp_us {
                return Err(ImtPlanError::MixedWriteTimestamps { expected: write_timestamp_us, actual: binding.write_timestamp_us });
            }
            parsed.push(binding);
        }

        let mut snapshots = BTreeMap::new();
        for snapshot in cursor_before {
            if snapshots.insert((snapshot.tree, snapshot.tree_sub), *snapshot).is_some() {
                return Err(ImtPlanError::DuplicateCursorBeforeImage);
            }
        }
        let seen_pairs = parsed.iter().map(|row| (row.tree, row.tree_sub)).collect::<BTreeSet<_>>();
        if seen_pairs != snapshots.keys().copied().collect() {
            return Err(ImtPlanError::CursorBeforeImageCoverage);
        }

        let mut seen_leaf = BTreeSet::new();
        let mut leaf_puts = Vec::new();
        let mut index_by_key = BTreeMap::<(TreeId, TreeSubId, [u8; 32]), ImtIndexPutBinding>::new();
        let mut max_next = BTreeMap::<(TreeId, TreeSubId), u64>::new();
        for row in &parsed {
            if seen_leaf.insert((row.tree, row.tree_sub, row.leaf)) {
                leaf_puts.push(row.clone());
            }
            let candidate_next = row.leaf.get().checked_add(1).ok_or(ImtPlanError::LeafIndexOverflow)?;
            max_next.entry((row.tree, row.tree_sub)).and_modify(|value| *value = (*value).max(candidate_next)).or_insert(candidate_next);

            if row.creates_index() {
                let encoded_bytes = encode_raw_imt_key_for_sorting(row.leaf_key);
                let encoded_key = ImtEncodedKey::new(encoded_bytes);
                let resolved = resolve_key_for_rollback(&TypedTableKey::ImtKeyIndex {
                    tree: row.tree, tree_sub: row.tree_sub, encoded_key: encoded_key.clone(),
                })?;
                require_physical(resolved.physical_table(), ScyllaPhysicalTableId::ImtKeyIndex)?;
                let index = ImtIndexPutBinding {
                    tree: row.tree, tree_sub: row.tree_sub, encoded_key,
                    leaf_key: row.leaf_key, birth_checkpoint: checkpoint, leaf: row.leaf,
                    write_timestamp_us,
                };
                let key = (row.tree, row.tree_sub, encoded_bytes);
                if let Some(existing) = index_by_key.get(&key) {
                    if existing != &index { return Err(ImtPlanError::ConflictingIndexBirth); }
                } else {
                    index_by_key.insert(key, index);
                }
            }
        }

        let mut cursor_puts = Vec::new();
        for (pair, before) in snapshots {
            let requested = max_next[&pair];
            let after = ImtCursorSnapshot::new(pair.0, pair.1, before.next_append_index.max(requested));
            let resolved = resolve_key_for_rollback(&TypedTableKey::ImtCursor { tree: pair.0, tree_sub: pair.1 })?;
            require_physical(resolved.physical_table(), ScyllaPhysicalTableId::ImtNextAppendIndex)?;
            let transition = ImtCursorTransition::try_new(
                checkpoint,
                before.next_append_index,
                after.next_append_index,
            )
            .map_err(ImtPlanError::CursorTransition)?;
            cursor_puts.push(ImtCursorPutBinding { before, after, transition, write_timestamp_us });
        }

        let mut hasher = Sha256::new();
        hasher.update(b"psy/imt-checkpoint-write/v1");
        hasher.update(checkpoint.get().to_be_bytes());
        hasher.update(write_timestamp_us.to_be_bytes());
        for member in sealed { hasher.update((member.canonical_bytes().len() as u32).to_be_bytes()); hasher.update(member.canonical_bytes()); }
        for cursor in &cursor_puts {
            hasher.update(cursor.before.tree.get().to_be_bytes());
            hasher.update(cursor.before.tree_sub.get().to_be_bytes());
            hasher.update(cursor.before.next_append_index.to_be_bytes());
            hasher.update(cursor.after.next_append_index.to_be_bytes());
        }
        Ok(Self {
            checkpoint, write_timestamp_us, leaf_puts,
            index_puts: index_by_key.into_values().collect(), cursor_puts,
            digest: ImtCheckpointWriteDigest(hasher.finalize().into()),
        })
    }

    pub const fn checkpoint(&self) -> CheckpointId { self.checkpoint }
    pub const fn write_timestamp_us(&self) -> i64 { self.write_timestamp_us }
    pub fn leaf_puts(&self) -> &[ImtLeafPutBinding] { &self.leaf_puts }
    pub fn index_puts(&self) -> &[ImtIndexPutBinding] { &self.index_puts }
    pub fn cursor_puts(&self) -> &[ImtCursorPutBinding] { &self.cursor_puts }
    pub const fn digest(&self) -> ImtCheckpointWriteDigest { self.digest }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImtLeafPointDeletePlan {
    leaf: ImtLeafPutBinding,
    target: CheckpointId,
    fence: DeleteFenceTimestampUs,
}

impl ImtLeafPointDeletePlan {
    pub fn try_from_orphaned_version(leaf: &ImtLeafPutBinding, target: CheckpointId, fence: DeleteFenceTimestampUs) -> Result<Self, ImtPlanError> {
        require_orphan_and_fence(leaf.checkpoint, target, leaf.write_timestamp_us, fence)?;
        Ok(Self { leaf: leaf.clone(), target, fence })
    }
    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![PrototypeBindValue::BigInt(self.fence.as_i64()), PrototypeBindValue::BigInt(u64_to_i64_exact(self.leaf.tree.get())), PrototypeBindValue::BigInt(u64_to_i64_exact(self.leaf.tree_sub.get())), PrototypeBindValue::BigInt(u64_to_i64_exact(self.leaf.leaf.get())), PrototypeBindValue::BigInt(convert_checkpoint_id_to_i64(self.leaf.checkpoint.get()))]
    }
    pub const fn target(&self) -> CheckpointId { self.target }
    fn driver_values(&self) -> (i64, i64, i64, i64, i64) { (self.fence.as_i64(), u64_to_i64_exact(self.leaf.tree.get()), u64_to_i64_exact(self.leaf.tree_sub.get()), u64_to_i64_exact(self.leaf.leaf.get()), convert_checkpoint_id_to_i64(self.leaf.checkpoint.get())) }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImtLeafBoundedRangeDeletePlan {
    tree: TreeId, tree_sub: TreeSubId, leaf: LeafIndex,
    target: CheckpointId, old_head: CheckpointId, fence: DeleteFenceTimestampUs,
}

impl ImtLeafBoundedRangeDeletePlan {
    pub fn try_new(tree: TreeId, tree_sub: TreeSubId, leaf: LeafIndex, target: CheckpointId, old_head: CheckpointId, fence: DeleteFenceTimestampUs) -> Result<Self, ImtPlanError> {
        if target >= old_head { return Err(ImtPlanError::InvalidRange { target, old_head }); }
        let resolved = resolve_key_for_rollback(&TypedTableKey::ImtLeaf { tree, tree_sub, leaf, checkpoint: target })?;
        require_physical(resolved.physical_table(), ScyllaPhysicalTableId::ImtLeaf)?;
        Ok(Self { tree, tree_sub, leaf, target, old_head, fence })
    }
    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![PrototypeBindValue::BigInt(self.fence.as_i64()), PrototypeBindValue::BigInt(u64_to_i64_exact(self.tree.get())), PrototypeBindValue::BigInt(u64_to_i64_exact(self.tree_sub.get())), PrototypeBindValue::BigInt(u64_to_i64_exact(self.leaf.get())), PrototypeBindValue::BigInt(convert_checkpoint_id_to_i64(self.target.get())), PrototypeBindValue::BigInt(convert_checkpoint_id_to_i64(self.old_head.get()))]
    }
    fn driver_values(&self) -> (i64, i64, i64, i64, i64, i64) { (self.fence.as_i64(), u64_to_i64_exact(self.tree.get()), u64_to_i64_exact(self.tree_sub.get()), u64_to_i64_exact(self.leaf.get()), convert_checkpoint_id_to_i64(self.target.get()), convert_checkpoint_id_to_i64(self.old_head.get())) }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImtIndexPointDeletePlan { index: ImtIndexPutBinding, target: CheckpointId, fence: DeleteFenceTimestampUs }

impl ImtIndexPointDeletePlan {
    pub fn try_from_orphaned_birth(index: &ImtIndexPutBinding, target: CheckpointId, fence: DeleteFenceTimestampUs) -> Result<Self, ImtPlanError> {
        require_orphan_and_fence(index.birth_checkpoint, target, index.write_timestamp_us, fence)?;
        Ok(Self { index: index.clone(), target, fence })
    }
    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![PrototypeBindValue::BigInt(self.fence.as_i64()), PrototypeBindValue::BigInt(u64_to_i64_exact(self.index.tree.get())), PrototypeBindValue::BigInt(u64_to_i64_exact(self.index.tree_sub.get())), PrototypeBindValue::SmallInt(self.index.encoded_key.cql_bucket()), PrototypeBindValue::Blob(self.index.encoded_key.as_bytes().to_vec())]
    }
    pub const fn target(&self) -> CheckpointId { self.target }
    fn driver_values(&self) -> (i64, i64, i64, i16, Vec<u8>) { (self.fence.as_i64(), u64_to_i64_exact(self.index.tree.get()), u64_to_i64_exact(self.index.tree_sub.get()), self.index.encoded_key.cql_bucket(), self.index.encoded_key.as_bytes().to_vec()) }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImtCursorRestorePlan { target_checkpoint: CheckpointId, target: ImtCursorSnapshot, write_timestamp_us: i64 }

impl ImtCursorRestorePlan {
    pub fn try_new(target_checkpoint: CheckpointId, target: ImtCursorSnapshot, timestamp: NewBranchWriteTimestampUs) -> Result<Self, ImtPlanError> {
        let resolved = resolve_key_for_rollback(&TypedTableKey::ImtCursor { tree: target.tree, tree_sub: target.tree_sub })?;
        require_physical(resolved.physical_table(), ScyllaPhysicalTableId::ImtNextAppendIndex)?;
        Ok(Self { target_checkpoint, target, write_timestamp_us: timestamp.as_commit_timestamp().as_i64() })
    }
    pub const fn target_checkpoint(&self) -> CheckpointId { self.target_checkpoint }
    pub const fn target(&self) -> ImtCursorSnapshot { self.target }
    pub const fn write_timestamp_us(&self) -> i64 { self.write_timestamp_us }
    pub fn bind_values(&self) -> Vec<PrototypeBindValue> { cursor_bind_values(self.target, self.write_timestamp_us) }
    fn driver_values(&self) -> (i64, i64, i64, i64) { cursor_driver_values(self.target, self.write_timestamp_us) }
}

fn cursor_bind_values(snapshot: ImtCursorSnapshot, timestamp: i64) -> Vec<PrototypeBindValue> {
    vec![PrototypeBindValue::BigInt(u64_to_i64_exact(snapshot.tree.get())), PrototypeBindValue::BigInt(u64_to_i64_exact(snapshot.tree_sub.get())), PrototypeBindValue::BigInt(u64_to_i64_exact(snapshot.next_append_index)), PrototypeBindValue::BigInt(timestamp)]
}
fn cursor_driver_values(snapshot: ImtCursorSnapshot, timestamp: i64) -> (i64, i64, i64, i64) { (u64_to_i64_exact(snapshot.tree.get()), u64_to_i64_exact(snapshot.tree_sub.get()), u64_to_i64_exact(snapshot.next_append_index), timestamp) }

fn require_orphan_and_fence(birth: CheckpointId, target: CheckpointId, write: i64, fence: DeleteFenceTimestampUs) -> Result<(), ImtPlanError> {
    if birth <= target { return Err(ImtPlanError::VersionNotAfterTarget { version: birth, target }); }
    if fence.as_i64() <= write { return Err(ImtPlanError::FenceNotAfterWrite { fence: fence.as_i64(), write }); }
    Ok(())
}

fn require_physical(actual: ScyllaPhysicalTableId, expected: ScyllaPhysicalTableId) -> Result<(), ImtPlanError> {
    if actual == expected { Ok(()) } else { Err(ImtPlanError::WrongPhysicalTable(actual)) }
}

#[derive(Clone, Copy)]
struct ParsedLeafRow {
    tree_id: u64, tree_sub_id: u64, leaf_index: u64,
    leaf_hash: [u8; 32], leaf_key: [u8; 32], leaf_value: [u8; 32], next_key: [u8; 32],
    next_index: u64, is_new_key: bool,
}
impl ParsedLeafRow {
    fn try_parse(bytes: &[u8]) -> Result<Self, ImtPlanError> {
        if bytes.len() != IMT_LEAF_ROW_V1_BYTES { return Err(ImtPlanError::InvalidLeafRowLength { actual: bytes.len() }); }
        Ok(Self {
            tree_id: u64::from_le_bytes(bytes[0..8].try_into().expect("fixed")),
            tree_sub_id: u64::from_le_bytes(bytes[8..16].try_into().expect("fixed")),
            leaf_index: u64::from_le_bytes(bytes[16..24].try_into().expect("fixed")),
            leaf_hash: bytes[24..56].try_into().expect("fixed"),
            leaf_key: bytes[56..88].try_into().expect("fixed"),
            leaf_value: bytes[88..120].try_into().expect("fixed"),
            next_key: bytes[120..152].try_into().expect("fixed"),
            next_index: u64::from_le_bytes(bytes[152..160].try_into().expect("fixed")),
            is_new_key: bytes[160] != 0,
        })
    }
}

/// Converts four little-endian raw field limbs to the existing MSL-first,
/// limb-big-endian Scylla comparison encoding.
pub fn encode_raw_imt_key_for_sorting(raw: [u8; 32]) -> [u8; 32] {
    let mut encoded = [0_u8; 32];
    for destination_limb in 0..4 {
        let source_limb = 3 - destination_limb;
        let value = u64::from_le_bytes(raw[source_limb * 8..source_limb * 8 + 8].try_into().expect("fixed"));
        encoded[destination_limb * 8..destination_limb * 8 + 8].copy_from_slice(&value.to_be_bytes());
    }
    encoded
}

struct PreparedImtFamily { leaf_put: PreparedStatement, leaf_point_delete: PreparedStatement, leaf_range_delete: PreparedStatement, index_put: PreparedStatement, index_point_delete: PreparedStatement, cursor_put: PreparedStatement }

#[allow(dead_code)]
pub(crate) struct ImtFamilyAdapter { queries: ImtQueries, prepared: PreparedImtFamily }

#[allow(dead_code)]
impl ImtFamilyAdapter {
    pub(crate) async fn prepare_with_consistency(session: &Session, keyspace: CqlKeyspaceName, consistency: Consistency) -> anyhow::Result<Self> {
        let queries = ImtQueries::new(&keyspace);
        let prepared = PreparedImtFamily {
            leaf_put: prepare(session, queries.leaf_put().cql(), consistency).await?,
            leaf_point_delete: prepare(session, queries.leaf_point_delete().cql(), consistency).await?,
            leaf_range_delete: prepare(session, queries.leaf_range_delete().cql(), consistency).await?,
            index_put: prepare(session, queries.index_put().cql(), consistency).await?,
            index_point_delete: prepare(session, queries.index_point_delete().cql(), consistency).await?,
            cursor_put: prepare(session, queries.cursor_put().cql(), consistency).await?,
        };
        Ok(Self { queries, prepared })
    }
    pub(crate) const fn queries(&self) -> &ImtQueries { &self.queries }
    pub(crate) async fn put_leaf(&self, session: &Session, binding: &ImtLeafPutBinding) -> anyhow::Result<()> { session.execute_unpaged(&self.prepared.leaf_put, binding.driver_values()).await?; Ok(()) }
    pub(crate) async fn put_index(&self, session: &Session, binding: &ImtIndexPutBinding) -> anyhow::Result<()> { session.execute_unpaged(&self.prepared.index_put, binding.driver_values()).await?; Ok(()) }
    pub(crate) async fn put_cursor(&self, session: &Session, binding: &ImtCursorPutBinding) -> anyhow::Result<()> { session.execute_unpaged(&self.prepared.cursor_put, binding.driver_values()).await?; Ok(()) }
    pub(crate) async fn delete_leaf_point(&self, session: &Session, plan: &ImtLeafPointDeletePlan) -> anyhow::Result<()> { session.execute_unpaged(&self.prepared.leaf_point_delete, plan.driver_values()).await?; Ok(()) }
    pub(crate) async fn delete_leaf_range(&self, session: &Session, plan: &ImtLeafBoundedRangeDeletePlan) -> anyhow::Result<()> { session.execute_unpaged(&self.prepared.leaf_range_delete, plan.driver_values()).await?; Ok(()) }
    pub(crate) async fn delete_index(&self, session: &Session, plan: &ImtIndexPointDeletePlan) -> anyhow::Result<()> { session.execute_unpaged(&self.prepared.index_point_delete, plan.driver_values()).await?; Ok(()) }
    pub(crate) async fn restore_cursor(&self, session: &Session, plan: &ImtCursorRestorePlan) -> anyhow::Result<()> { session.execute_unpaged(&self.prepared.cursor_put, plan.driver_values()).await?; Ok(()) }
}

async fn prepare(session: &Session, cql: &str, consistency: Consistency) -> anyhow::Result<PreparedStatement> {
    let mut statement = session.prepare(cql).await?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImtPlanError {
    Registry(RegistryReadinessError), WrongPhysicalTable(ScyllaPhysicalTableId), WrongTypedKey,
    ExpectedLeafRowV1, InvalidLeafRowLength { actual: usize }, LeafKeyRowMismatch,
    EmptyLeafBatch, MixedCheckpoints { expected: CheckpointId, actual: CheckpointId },
    MixedWriteTimestamps { expected: i64, actual: i64 }, DuplicateCursorBeforeImage,
    CursorBeforeImageCoverage, LeafIndexOverflow, ConflictingIndexBirth,
    CursorTransition(ImtCursorTransitionError),
    VersionNotAfterTarget { version: CheckpointId, target: CheckpointId },
    FenceNotAfterWrite { fence: i64, write: i64 },
    InvalidRange { target: CheckpointId, old_head: CheckpointId },
}

impl fmt::Display for ImtPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "IMT plan rejected: {self:?}") }
}
impl Error for ImtPlanError {}
impl From<RegistryReadinessError> for ImtPlanError { fn from(value: RegistryReadinessError) -> Self { Self::Registry(value) } }
