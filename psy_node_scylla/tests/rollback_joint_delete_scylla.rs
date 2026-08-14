//! Single-node Scylla behavior fixture for the first delete-only rollback flow.
//!
//! This is deliberately smaller than a production executor qualification. It
//! proves the storage semantics of one explicit request spanning one
//! Coordinator and every selected Realm: archive/read back all suffix rows,
//! cross the global barrier, delete with a fence, restore the target, and write
//! a new branch without allowing late old-branch writes to resurrect.

use std::{collections::BTreeSet, net::SocketAddr, time::Instant};

use anyhow::{ensure, Context};
use parth_core::PHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
};
use psy_node_core::store::{
    canonical_head::{CanonicalHeadTransition, StoredCanonicalHead},
    rollback_control::RollbackControlState,
    rollback_participant_plan::{RollbackParticipantPlan, RollbackRealmParticipant},
    rollback_topology::RollbackTopologySnapshot,
    timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
};
use scylla::{
    client::{
        execution_profile::ExecutionProfile, session::Session, session_builder::SessionBuilder,
    },
    statement::Consistency,
};

const KEYSPACE: &str = "psy_rollback_joint_single";
const REQUEST_ID: &str = "explicit-rollback-a3-to-a1";
const PARTICIPANTS: [&str; 3] = ["coordinator", "realm-10-0", "realm-20-0"];
const OLD_WRITE_TS: i64 = 100;
const ARCHIVE_WRITE_TS: i64 = 150;
const DELETE_FENCE_TS: i64 = 200;
const NEW_BRANCH_WRITE_TS: i64 = 300;

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredRow {
    checkpoint: i64,
    branch: String,
    value: String,
    writetime_us: i64,
}

fn hash(seed: u8) -> PHash {
    let seed = u64::from(seed);
    PHash::from_values(seed, seed + 1, seed + 2, seed + 3)
}

fn network() -> NetworkId {
    NetworkId::try_from_chain_id(1).expect("test network exists")
}

fn chain(epoch: u64, checkpoint: u64, seed: u8) -> CanonicalChainRef<PHash> {
    CanonicalChainRef::new(
        network(),
        ChainEpoch::new(epoch),
        CheckpointRef::new(
            CheckpointId::new(checkpoint),
            CheckpointHash::from_last_chain_hash(hash(seed)),
        ),
    )
}

fn idle_head(canonical: CanonicalChainRef<PHash>) -> StoredCanonicalHead<PHash> {
    StoredCanonicalHead::decode_persisted(
        canonical.network_id(),
        0,
        &canonical.to_canonical_bytes(),
        &RollbackControlState::<PHash>::Idle.to_canonical_bytes(),
    )
    .expect("fixture canonical head is valid")
}

async fn connect() -> anyhow::Result<Session> {
    let profile = ExecutionProfile::builder()
        .consistency(Consistency::One)
        .build()
        .into_handle();
    SessionBuilder::new()
        .known_node_addr("172.29.86.11:9042".parse::<SocketAddr>()?)
        .default_execution_profile_handle(profile)
        .build()
        .await
        .context("connect to the isolated single-node Scylla fixture")
}

async fn reconnect(session: Session, window: &str) -> anyhow::Result<Session> {
    drop(session);
    connect()
        .await
        .with_context(|| format!("reconnect after simulated {window} process exit"))
}

async fn create_schema(session: &Session) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "CREATE KEYSPACE IF NOT EXISTS {KEYSPACE} WITH replication = \
                 {{'class': 'NetworkTopologyStrategy', 'datacenter1': 1}} \
                 AND tablets = {{'enabled': false}}"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {KEYSPACE}.hot_checkpoint_state (\
                 participant text, checkpoint bigint, branch text, value text, \
                 PRIMARY KEY ((participant), checkpoint))"
            ),
            &[],
        )
        .await?;
    session
        .query_unpaged(
            format!(
                "CREATE TABLE IF NOT EXISTS {KEYSPACE}.rollback_suffix_archive (\
                 request_id text, participant text, checkpoint bigint, branch text, value text, \
                 source_writetime_us bigint, \
                 PRIMARY KEY ((request_id, participant), checkpoint))"
            ),
            &[],
        )
        .await?;
    session.await_schema_agreement().await?;
    Ok(())
}

async fn put_hot(
    session: &Session,
    participant: &str,
    checkpoint: i64,
    branch: &str,
    value: &str,
    writetime_us: i64,
) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "INSERT INTO {KEYSPACE}.hot_checkpoint_state \
                 (participant, checkpoint, branch, value) VALUES (?, ?, ?, ?) USING TIMESTAMP ?"
            ),
            (participant, checkpoint, branch, value, writetime_us),
        )
        .await?;
    Ok(())
}

async fn hot_rows(session: &Session, participant: &str) -> anyhow::Result<Vec<StoredRow>> {
    session
        .query_unpaged(
            format!(
                "SELECT checkpoint, branch, value, WRITETIME(value) \
                 FROM {KEYSPACE}.hot_checkpoint_state WHERE participant = ?"
            ),
            (participant,),
        )
        .await?
        .into_rows_result()?
        .rows::<(i64, String, String, i64)>()?
        .map(|row| {
            row.map(|(checkpoint, branch, value, writetime_us)| StoredRow {
                checkpoint,
                branch,
                value,
                writetime_us,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn archive_rows(session: &Session, participant: &str) -> anyhow::Result<Vec<StoredRow>> {
    session
        .query_unpaged(
            format!(
                "SELECT checkpoint, branch, value, source_writetime_us \
                 FROM {KEYSPACE}.rollback_suffix_archive \
                 WHERE request_id = ? AND participant = ?"
            ),
            (REQUEST_ID, participant),
        )
        .await?
        .into_rows_result()?
        .rows::<(i64, String, String, i64)>()?
        .map(|row| {
            row.map(|(checkpoint, branch, value, writetime_us)| StoredRow {
                checkpoint,
                branch,
                value,
                writetime_us,
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

async fn archive_suffix_and_read_back(
    session: &Session,
    participant: &str,
    target: i64,
) -> anyhow::Result<()> {
    let expected = hot_rows(session, participant)
        .await?
        .into_iter()
        .filter(|row| row.checkpoint > target)
        .collect::<Vec<_>>();
    ensure!(!expected.is_empty(), "fixture suffix is non-empty");
    for row in &expected {
        session
            .query_unpaged(
                format!(
                    "INSERT INTO {KEYSPACE}.rollback_suffix_archive \
                     (request_id, participant, checkpoint, branch, value, source_writetime_us) \
                     VALUES (?, ?, ?, ?, ?, ?) USING TIMESTAMP ?"
                ),
                (
                    REQUEST_ID,
                    participant,
                    row.checkpoint,
                    row.branch.as_str(),
                    row.value.as_str(),
                    row.writetime_us,
                    ARCHIVE_WRITE_TS,
                ),
            )
            .await?;
    }
    ensure!(
        archive_rows(session, participant).await? == expected,
        "archive exact read-back differs from the hot suffix for {participant}"
    );
    Ok(())
}

async fn delete_suffix(session: &Session, participant: &str, target: i64) -> anyhow::Result<()> {
    session
        .query_unpaged(
            format!(
                "DELETE FROM {KEYSPACE}.hot_checkpoint_state USING TIMESTAMP ? \
                 WHERE participant = ? AND checkpoint > ?"
            ),
            (DELETE_FENCE_TS, participant, target),
        )
        .await?;
    Ok(())
}

fn expected_rows(participant: &str, branch: &str, timestamps: [i64; 3]) -> Vec<StoredRow> {
    (1..=3)
        .zip(timestamps)
        .map(|(checkpoint, writetime_us)| StoredRow {
            checkpoint,
            branch: if checkpoint == 1 { "A" } else { branch }.to_owned(),
            value: format!(
                "{participant}:{}{}",
                if checkpoint == 1 { "A" } else { branch },
                checkpoint
            ),
            writetime_us,
        })
        .collect()
}

#[tokio::test]
#[ignore = "starts an isolated single-node Scylla fixture through the wrapper script"]
async fn explicit_joint_delete_archives_every_participant_then_continues_on_a_new_branch(
) -> anyhow::Result<()> {
    ensure!(
        std::env::var("PSY_ROLLBACK_JOINT_SINGLE").as_deref() == Ok("1"),
        "run through tests/rf3/run-rollback-joint-single.sh"
    );
    let session = connect().await?;
    create_schema(&session).await?;

    for participant in PARTICIPANTS {
        for checkpoint in 1..=3 {
            put_hot(
                &session,
                participant,
                checkpoint,
                "A",
                &format!("{participant}:A{checkpoint}"),
                OLD_WRITE_TS,
            )
            .await?;
        }
    }

    let realms = vec![
        RollbackRealmParticipant::new(10, 0),
        RollbackRealmParticipant::new(20, 0),
    ];
    let topology = RollbackTopologySnapshot::try_new(network(), 1, realms.clone())?;
    let old_head = idle_head(chain(0, 3, 0xA3));
    let target = chain(0, 1, 0xA1);
    let fence = TimestampFenceWindow::try_new(
        CommitWriteTimestampUs::try_from_i128(OLD_WRITE_TS as i128)?,
        DELETE_FENCE_TS as i128,
        NEW_BRANCH_WRITE_TS as i128,
    )?;
    let plan = RollbackParticipantPlan::try_new(
        old_head,
        target,
        fence,
        topology.revision(),
        *topology.digest(),
        realms,
    )?;
    ensure!(topology.validates_plan(&plan), "topology must select every participant");

    let requested =
        CanonicalHeadTransition::start_rollback(old_head, plan.rollback_request()?)?;
    let archiving =
        CanonicalHeadTransition::begin_rollback_archive(*requested.candidate())?;
    let archive_started = Instant::now();
    let mut archived = BTreeSet::new();
    for participant in PARTICIPANTS.into_iter().take(2) {
        archive_suffix_and_read_back(&session, participant, 1).await?;
        archived.insert(participant);
    }
    ensure!(archived.len() == 2, "only two participants are archived so far");
    ensure!(plan.participant_count() == 3, "plan covers Coordinator plus two Realms");
    ensure!(
        CanonicalHeadTransition::begin_rollback_delete(*archiving.candidate()).is_err(),
        "delete is unavailable before the global archive barrier"
    );
    for participant in PARTICIPANTS {
        ensure!(hot_rows(&session, participant).await?.len() == 3, "no early delete");
    }

    // Simulate losing the maintenance process after only a subset of the
    // participant archive rows are durable.  A fresh connection must recover
    // the exact rows and still observe an intact hot suffix for every
    // participant; it may then idempotently re-run the completed archive work.
    let session = reconnect(session, "partial archive").await?;
    for participant in PARTICIPANTS.into_iter().take(2) {
        ensure!(
            archive_rows(&session, participant).await?
                == expected_rows(participant, "A", [OLD_WRITE_TS; 3])
                    .into_iter()
                    .skip(1)
                    .collect::<Vec<_>>(),
            "completed participant archive must survive restart"
        );
        archive_suffix_and_read_back(&session, participant, 1).await?;
    }
    ensure!(
        archive_rows(&session, PARTICIPANTS[2]).await?.is_empty(),
        "missing participant must remain visibly missing after restart"
    );
    for participant in PARTICIPANTS {
        ensure!(hot_rows(&session, participant).await?.len() == 3, "restart cannot delete early");
    }

    archive_suffix_and_read_back(&session, PARTICIPANTS[2], 1).await?;
    archived.insert(PARTICIPANTS[2]);
    ensure!(archived.len() == plan.participant_count(), "all selected participants archived");
    let archive_elapsed = archive_started.elapsed();
    let archive_barrier =
        CanonicalHeadTransition::complete_rollback_archive_barrier(*archiving.candidate())?;
    let deleting =
        CanonicalHeadTransition::begin_rollback_delete(*archive_barrier.candidate())?;

    let session = reconnect(session, "archive barrier").await?;
    for participant in PARTICIPANTS {
        ensure!(
            archive_rows(&session, participant).await?.len() == 2,
            "every archive must remain selected after the barrier restart"
        );
    }

    let delete_started = Instant::now();
    delete_suffix(&session, PARTICIPANTS[0], 1).await?;
    ensure!(
        hot_rows(&session, PARTICIPANTS[0]).await?.len() == 1,
        "first participant delete is visible before the simulated crash"
    );
    for participant in PARTICIPANTS.into_iter().skip(1) {
        ensure!(
            hot_rows(&session, participant).await?.len() == 3,
            "later participants remain intact during a partial delete"
        );
    }

    // Restart in the destructive phase.  Deletion is deliberately retried
    // for all participants, including the already-completed Coordinator row.
    let session = reconnect(session, "partial delete").await?;
    for participant in PARTICIPANTS {
        delete_suffix(&session, participant, 1).await?;
    }
    let delete_elapsed = delete_started.elapsed();
    for participant in PARTICIPANTS {
        ensure!(
            hot_rows(&session, participant).await?
                == expected_rows(participant, "A", [OLD_WRITE_TS, OLD_WRITE_TS, OLD_WRITE_TS])
                    .into_iter()
                    .take(1)
                    .collect::<Vec<_>>(),
            "hot reads must expose only target A1 after delete"
        );
    }

    let session = reconnect(session, "completed delete before target publication").await?;
    for participant in PARTICIPANTS {
        ensure!(
            hot_rows(&session, participant).await?.len() == 1
                && archive_rows(&session, participant).await?.len() == 2,
            "target row and archived suffix must survive the restore-window restart"
        );
    }

    let restoring =
        CanonicalHeadTransition::begin_rollback_restore(*deleting.candidate())?;
    let verifying =
        CanonicalHeadTransition::begin_rollback_verify(*restoring.candidate())?;
    let realm_barrier =
        CanonicalHeadTransition::complete_rollback_realm_barrier(*verifying.candidate())?;
    let published = CanonicalHeadTransition::complete_rollback(*realm_barrier.candidate())?;
    ensure!(published.candidate().canonical_ref().checkpoint() == target.checkpoint());
    ensure!(published.candidate().canonical_ref().chain_epoch().get() == 1);

    let session = reconnect(session, "target publication").await?;
    for participant in PARTICIPANTS {
        for checkpoint in 2..=3 {
            put_hot(
                &session,
                participant,
                checkpoint,
                "A",
                &format!("{participant}:A{checkpoint}-late"),
                OLD_WRITE_TS,
            )
            .await?;
        }
        put_hot(
            &session,
            participant,
            2,
            "B",
            &format!("{participant}:B2"),
            NEW_BRANCH_WRITE_TS,
        )
        .await?;
        put_hot(
            &session,
            participant,
            3,
            "B",
            &format!("{participant}:B3"),
            NEW_BRANCH_WRITE_TS + 1,
        )
        .await?;
    }

    let b2 = CanonicalHeadTransition::normal_checkpoint_advance(
        *published.candidate(),
        chain(1, 2, 0xB2),
    )?;
    let b3 =
        CanonicalHeadTransition::normal_checkpoint_advance(*b2.candidate(), chain(1, 3, 0xB3))?;
    ensure!(b3.candidate().canonical_ref().checkpoint().checkpoint_id().get() == 3);

    for participant in PARTICIPANTS {
        ensure!(
            hot_rows(&session, participant).await?
                == expected_rows(
                    participant,
                    "B",
                    [OLD_WRITE_TS, NEW_BRANCH_WRITE_TS, NEW_BRANCH_WRITE_TS + 1],
                ),
            "new branch must be A1/B2/B3 and late A writes must remain hidden"
        );
        ensure!(
            archive_rows(&session, participant).await?
                == expected_rows(participant, "A", [OLD_WRITE_TS; 3])
                    .into_iter()
                    .skip(1)
                    .collect::<Vec<_>>(),
            "archive must retain the discarded A2/A3 suffix"
        );
    }

    eprintln!(
        "rollback_joint_single archive_ms={} delete_ms={} participants={} archived_rows=6 hot_rows=9",
        archive_elapsed.as_millis(),
        delete_elapsed.as_millis(),
        plan.participant_count(),
    );
    Ok(())
}
