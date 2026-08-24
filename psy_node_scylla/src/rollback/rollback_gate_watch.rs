//! Keep this process's answer to "is a rollback running" up to date.
//!
//! The Edge refuses to answer questions about the chain while one is, because a
//! rollback has intermediate states and an answer given during them describes a
//! branch that is about to stop existing.  See
//! `psy_node_core::store::rollback_gate` for what that cost.
//!
//! Polled rather than read per request: the answer changes a handful of times an
//! hour and is asked thousands of times.  The interval is the width of the
//! window this leaves -- a rollback that starts between two polls is answered
//! through for that long -- and closing it entirely needs the answers themselves
//! to carry the branch they came from, which is a larger change and is written
//! down beside this one.
//!
//! It fails towards refusing.  A control row that cannot be read leaves the flag
//! where it was rather than clearing it, because clearing it on a database blip
//! would answer straight through the phase the flag exists for.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use psy_node_core::store::rollback_control::{
    ROLLBACK_CONTROL_CODEC_VERSION, ROLLBACK_CONTROL_MAGIC, PHASE_ORDINAL_IDLE,
};

/// Watch the Coordinator's control row and install the flag the Edge reads.
///
/// The keyspace is the Coordinator's `_no_tablet` one, which is where the
/// control row lives.
pub fn watch_rollback_phase(scylla_url: String, no_tablet_keyspace: String, network_chain_id: i64) {
    let gate = Arc::new(AtomicBool::new(false));
    psy_node_core::store::rollback_gate::install_rollback_gate(gate.clone());

    tokio::spawn(async move {
        let interval = std::time::Duration::from_millis(
            std::env::var("PSY_ROLLBACK_GATE_POLL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1000),
        );
        loop {
            if let Some(rolling_back) =
                read_rolling_back(&scylla_url, &no_tablet_keyspace, network_chain_id).await
            {
                let was = gate.swap(rolling_back, Ordering::Relaxed);
                if was != rolling_back {
                    if rolling_back {
                        tracing::warn!(
                            "[EDGE] a rollback has started; refusing to answer questions about \
                             the chain until it finishes"
                        );
                    } else {
                        tracing::warn!("[EDGE] the rollback has finished; answering again");
                    }
                }
            }
            tokio::time::sleep(interval).await;
        }
    });
}

/// `Some(true)` while a rollback is published, `None` when the row cannot be
/// read -- which leaves the flag alone rather than clearing it.
async fn read_rolling_back(
    scylla_url: &str,
    no_tablet_keyspace: &str,
    network_chain_id: i64,
) -> Option<bool> {
    let session = super::open_reader_session(scylla_url).await.ok()?;
    let rows = session
        .query_unpaged(
            format!(
                "SELECT rollback_control FROM {no_tablet_keyspace}.{} WHERE network_chain_id = ?",
                super::COORDINATOR_CANONICAL_HEAD_TABLE
            ),
            (network_chain_id,),
        )
        .await
        .ok()?
        .into_rows_result()
        .ok()?;
    // No row is a chain that has not started; nothing is being rolled back.
    let (payload,) = rows.maybe_first_row::<(Option<Vec<u8>>,)>().ok()??;
    let payload = payload?;
    // The phase is one byte, after the magic and the codec version.  Read
    // directly rather than through the decoder because this has no Hash type to
    // decode with, and the layout is declared next to the constants used here.
    if payload.len() < 11 || payload[0..8] != ROLLBACK_CONTROL_MAGIC {
        return None;
    }
    if u16::from_le_bytes([payload[8], payload[9]]) != ROLLBACK_CONTROL_CODEC_VERSION {
        return None;
    }
    Some(payload[10] != PHASE_ORDINAL_IDLE)
}
