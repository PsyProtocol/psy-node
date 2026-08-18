//! Reads production-written rows back through the typed-key reader.
//!
//! The reader binds primary keys from the typed key while taking column names
//! from the registry, so a wrong order or a wrong codec does not fail loudly --
//! it reads a key that does not exist and reports the row absent.  Unit tests can
//! check that the counts line up; only real rows, written by the production
//! adapters, can show that the values do.
//!
//! Point it at a chain that has actually run:
//!
//! ```text
//! PSY_ROLLBACK_LIVE_KEYSPACE=rollback_r1_verify \
//!   cargo test -p psy_node_scylla --test rollback_row_image_live -- --ignored
//! ```

use std::sync::Arc;

use psy_node_core::store::typed::{
    CheckpointId, ContractId, LatestInfoSlot, MerkleNode, NodeIndex, TypedTableKey,
    U64SingletonSlot, UserId,
};
use psy_node_scylla::rollback::{ScyllaRowImageReader, describe_existing_key};
use scylla::client::session_builder::SessionBuilder;

fn known_nodes() -> Vec<String> {
    vec![
        std::env::var("PSY_SCYLLA_URL").unwrap_or_else(|_| "127.0.0.1:9042".to_string()),
    ]
}

#[tokio::test]
#[ignore = "requires a keyspace holding a chain that has already run"]
async fn the_reader_finds_rows_the_production_writers_wrote() -> anyhow::Result<()> {
    let keyspace = std::env::var("PSY_ROLLBACK_LIVE_KEYSPACE")
        .expect("set PSY_ROLLBACK_LIVE_KEYSPACE to a keyspace with committed checkpoints");
    let session = Arc::new(
        SessionBuilder::new()
            .known_nodes(known_nodes().iter())
            .build()
            .await?,
    );
    let reader = ScyllaRowImageReader::prepare(session.clone(), &keyspace).await?;

    // The latest committed height, so the sampled keys are certain to exist.
    let latest = session
        .query_unpaged(
            format!("SELECT value FROM {keyspace}.u64_singleton_table WHERE obj_id = 1"),
            &[],
        )
        .await?
        .into_rows_result()?
        .first_row::<(i64,)>()?
        .0 as u64;
    assert!(latest > 2, "the chain must have committed something to read");
    let checkpoint = CheckpointId::try_new(latest - 1)?;

    // One key per family the Coordinator commit path writes, so a family whose
    // binding is wrong shows up as its own failure rather than hiding in a total.
    let mut probes: Vec<(&str, TypedTableKey)> = vec![
        ("kiv/checkpoint_leaf", TypedTableKey::CheckpointLeaf(checkpoint)),
        ("kiv/l2_block_state", TypedTableKey::L2BlockState(checkpoint)),
        ("kiv/checkpoint_state_roots", TypedTableKey::CheckpointStateRoots(checkpoint)),
        ("kiv/checkpoint_zk_proof", TypedTableKey::CheckpointZkProof(checkpoint)),
        (
            "kiv/latest_info",
            TypedTableKey::LatestInfo(LatestInfoSlot::LatestL2BlockState),
        ),
        (
            "u64/singleton",
            TypedTableKey::U64Singleton(U64SingletonSlot::LatestCheckpoint),
        ),
        ("u64/checkpoint_to_pending", TypedTableKey::CheckpointToPending(checkpoint)),
        // The height-keyed half of the root mapping: its CQL key is the
        // checkpoint serialized little-endian, which the locator stores the other
        // way round.  If that conversion were wrong this is the probe that fails.
        (
            "blob/root_by_checkpoint",
            TypedTableKey::CheckpointRootByCheckpoint(checkpoint),
        ),
        (
            "merkle_zero/global_checkpoint_root",
            TypedTableKey::GlobalCheckpointMerkle {
                node: MerkleNode::new(0, NodeIndex::new(0)),
                checkpoint,
            },
        ),
    ];

    // The user, registration and contract trees are sparse: a node is written
    // only at the checkpoints that change it, so a point read at an arbitrary
    // height finds nothing and that is correct.  Sample a triple each table
    // actually holds, otherwise the probe tests the workload rather than the
    // reader.
    for (label, table) in [
        ("merkle_zero/global_user", "global_user_tree_table"),
        ("merkle_zero/user_registration", "user_registration_tree_table"),
        ("merkle_zero/global_contract", "global_contract_tree_table"),
    ] {
        let node: Option<(i8, i64, i64)> = session
            .query_unpaged(
                format!("SELECT level, node_index, checkpoint_id FROM {keyspace}.{table} LIMIT 1"),
                &[],
            )
            .await?
            .into_rows_result()?
            .maybe_first_row::<(i8, i64, i64)>()?;
        let Some((level, index, at)) = node else {
            continue;
        };
        let merkle = MerkleNode::new(level as u8, NodeIndex::new(index as u64));
        let at = CheckpointId::try_new(at as u64)?;
        probes.push((
            label,
            match table {
                "global_user_tree_table" => {
                    TypedTableKey::GlobalUserMerkle { node: merkle, checkpoint: at }
                }
                "user_registration_tree_table" => {
                    TypedTableKey::UserRegistrationMerkle { node: merkle, checkpoint: at }
                }
                _ => TypedTableKey::GlobalContractMerkle { node: merkle, checkpoint: at },
            },
        ));
    }

    // The content-keyed half needs the root this chain actually produced, so read
    // it out rather than invent one.
    let root: Vec<u8> = session
        .query_unpaged(
            format!("SELECT obj_id FROM {keyspace}.checkpoint_root_to_checkpoint_id_table_k1 LIMIT 1"),
            &[],
        )
        .await?
        .into_rows_result()?
        .first_row::<(Vec<u8>,)>()?
        .0;
    probes.push((
        "blob/root_by_hash",
        TypedTableKey::CheckpointRootByHash(
            psy_node_core::store::typed::CheckpointRootKey::new(root),
        ),
    ));

    // Object-single and merkle-single rows only exist once a contract has been
    // deployed, so probe them only when the chain has one.
    let contract_rows: Option<(i64, i64)> = session
        .query_unpaged(
            format!("SELECT obj_id, checkpoint_id FROM {keyspace}.contract_leaf_table LIMIT 1"),
            &[],
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(i64, i64)>()?;
    if let Some((contract, contract_checkpoint)) = contract_rows {
        probes.push((
            "object_single/contract_leaf",
            TypedTableKey::ContractLeaf {
                contract: ContractId::new(contract as u64),
                checkpoint: CheckpointId::try_new(contract_checkpoint as u64)?,
            },
        ));
    }
    let user_rows: Option<(i64, i64)> = session
        .query_unpaged(
            format!("SELECT obj_id, checkpoint_id FROM {keyspace}.user_public_key_table LIMIT 1"),
            &[],
        )
        .await?
        .into_rows_result()?
        .maybe_first_row::<(i64, i64)>()?;
    if let Some((user, user_checkpoint)) = user_rows {
        probes.push((
            "object_single/user_public_key",
            TypedTableKey::UserPublicKey {
                user: UserId::new(user as u64),
                checkpoint: CheckpointId::try_new(user_checkpoint as u64)?,
            },
        ));
    }

    let mut missing = Vec::new();
    for (label, key) in probes {
        let resolved = describe_existing_key(&key);
        match reader.read(&resolved).await? {
            Some(image) => {
                assert!(
                    image.is_key_only() || !image.columns().is_empty(),
                    "{label} returned an image with no columns and no key-only marker"
                );
            }
            None => missing.push(label),
        }
    }
    assert!(
        missing.is_empty(),
        "the reader could not find rows the production writers wrote: {missing:?}"
    );
    Ok(())
}
