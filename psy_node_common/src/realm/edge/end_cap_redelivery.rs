use std::time::Duration;

use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    felt::ToU64Value,
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig},
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput;
use psy_node_core::{
    psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmEdgeAPIStoreReader},
    psy_temp_db::{EndCapRedeliveryRecord, StandardEdgeAPITempDBStoreBase},
    queue::{ephemeral::QStandardEphemeralQueuePublisher, worker_queue::QStandardWorkerQueueSubscriber},
    store::traits::proof_store::QParthProofStore,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::realm::edge::{error::EndCapSubmitError, handler::RealmEdgeHandler};

/// Exceeds the observed admission-to-inclusion maximum of about 7 checkpoints.
pub const END_CAP_REDELIVERY_DELAY_CHECKPOINTS: u64 = 10;
/// Measured from the EndCap's own checkpoint, so the bound survives forwarding to another validator.
pub const END_CAP_REDELIVERY_MAX_AGE_CHECKPOINTS: u64 = 300;
/// Pending ids a retired one waits before the cursor passes it, so an admission that read it as gathering can still list itself.
pub const END_CAP_REDELIVERY_RETIRED_MARGIN_PENDING_IDS: u64 = 2;
pub const END_CAP_REDELIVERY_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EndCapRedeliveryCounts {
    pub included: usize,
    pub superseded: usize,
    pub redelivered: usize,
    pub requeued: usize,
    pub expired: usize,
}

impl EndCapRedeliveryCounts {
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

enum EndCapOutcome {
    Included,
    Superseded,
    Abandoned,
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        UserUpdateQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore + Send + Sync + 'static,
    > RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
where
    N::HasherBase: MerkleZeroHasher<N::QHash>,
    N::ZKVerifier: 'static,
    N::ZKProof: 'static,
{
    pub async fn redeliver_abandoned_end_caps(&self) -> anyhow::Result<EndCapRedeliveryCounts> {
        let rid = self.realm_identifier;
        let (processing_unique_pending_id, _) = self.temp_db.get_unique_pending_ids(&rid).await?;
        let latest_checkpoint_id = self.get_latest_checkpoint_id().await?;
        let mut counts = EndCapRedeliveryCounts::default();
        let Some(mut cursor) = self.temp_db.get_end_cap_redelivery_cursor(&rid).await? else {
            return Ok(counts);
        };
        while cursor.saturating_add(END_CAP_REDELIVERY_RETIRED_MARGIN_PENDING_IDS) < processing_unique_pending_id {
            for user_id in self.temp_db.get_end_cap_redelivery_user_ids(&rid, cursor).await? {
                let Some(observed) = self.temp_db.get_end_cap_redelivery(&rid, user_id).await? else {
                    continue;
                };
                let record = match EndCapRedeliveryRecord::from_bytes(&observed) {
                    Ok(record) => record,
                    Err(error) => {
                        tracing::error!(user_id, error = %format!("{error:#}"), "Dropping undecodable EndCap redelivery record");
                        self.temp_db.remove_end_cap_redelivery(&rid, user_id, &observed).await?;
                        continue;
                    }
                };
                if record.admitted_unique_pending_id != cursor {
                    continue;
                }
                if latest_checkpoint_id < record.admitted_checkpoint_id.saturating_add(END_CAP_REDELIVERY_DELAY_CHECKPOINTS) {
                    return Ok(counts);
                }
                self.settle_end_cap(user_id, record, &observed, latest_checkpoint_id, &mut counts).await?;
            }
            self.temp_db.remove_end_cap_redelivery_user_ids(&rid, cursor).await?;
            if !self.temp_db.set_end_cap_redelivery_cursor(&rid, Some(cursor), cursor + 1).await? {
                return Ok(counts);
            }
            cursor += 1;
        }
        Ok(counts)
    }

    async fn settle_end_cap(
        &self,
        user_id: u64,
        record: EndCapRedeliveryRecord,
        observed: &[u8],
        latest_checkpoint_id: u64,
        counts: &mut EndCapRedeliveryCounts,
    ) -> anyhow::Result<()> {
        let rid = self.realm_identifier;
        let user_leaf_hash = self.db_reader.global_user_tree_get_merkle_proof(latest_checkpoint_id, user_id).await?.value.into_owned_32bytes();
        let outcome = if user_leaf_hash == record.new_user_leaf_hash {
            EndCapOutcome::Included
        } else if user_leaf_hash == record.old_user_leaf_hash {
            EndCapOutcome::Abandoned
        } else {
            EndCapOutcome::Superseded
        };
        match outcome {
            EndCapOutcome::Included => counts.included += 1,
            EndCapOutcome::Superseded => counts.superseded += 1,
            EndCapOutcome::Abandoned => {
                let input = SubmitUserEndCapNonProofInput::<N::F, N::QHash>::psy_ser_from_slice(&record.end_cap_input)?;
                let end_cap_checkpoint_id = input.core.checkpoint_id.to_u64_value();
                if latest_checkpoint_id > end_cap_checkpoint_id.saturating_add(END_CAP_REDELIVERY_MAX_AGE_CHECKPOINTS) {
                    tracing::error!(
                        user_id,
                        end_cap_checkpoint_id,
                        latest_checkpoint_id,
                        "EndCap was never included within the redelivery age limit; the user must prove it again"
                    );
                    counts.expired += 1;
                } else {
                    match self.handle_user_end_cap_proof_submission(input, record.proof.clone(), None).await {
                        Ok(()) => {
                            tracing::info!(user_id, from_unique_pending_id = record.admitted_unique_pending_id, "Redelivered abandoned EndCap");
                            counts.redelivered += 1;
                        }
                        Err(error) => match EndCapSubmitError::from_error_chain(&error) {
                            Some(EndCapSubmitError::Invalid(_)) => {
                                tracing::warn!(user_id, error = %format!("{error:#}"), "Abandoned EndCap is no longer admissible");
                                counts.superseded += 1;
                            }
                            Some(EndCapSubmitError::AlreadySubmitted { .. } | EndCapSubmitError::Busy(_)) | None => {
                                if self.requeue_end_cap(user_id, record, observed, latest_checkpoint_id, &error).await? {
                                    counts.requeued += 1;
                                } else {
                                    tracing::info!(user_id, "A newer admission replaced the EndCap redelivery record before its requeue");
                                    counts.superseded += 1;
                                }
                                return Ok(());
                            }
                        },
                    }
                }
            }
        }
        // A redelivery admitted locally already replaced this record, so only an unchanged one is removed.
        self.temp_db.remove_end_cap_redelivery(&rid, user_id, observed).await?;
        Ok(())
    }

    async fn requeue_end_cap(
        &self,
        user_id: u64,
        mut record: EndCapRedeliveryRecord,
        observed: &[u8],
        latest_checkpoint_id: u64,
        error: &anyhow::Error,
    ) -> anyhow::Result<bool> {
        let generation = self.temp_db.get_gathering_generation(&self.realm_identifier).await?;
        tracing::warn!(user_id, error = %format!("{error:#}"), "EndCap redelivery failed; retrying under pending id {}", generation.unique_pending_id);
        record.admitted_unique_pending_id = generation.unique_pending_id;
        record.admitted_checkpoint_id = latest_checkpoint_id;
        self.temp_db.replace_end_cap_redelivery(&self.realm_identifier, user_id, observed, &record).await
    }

    pub fn spawn_end_cap_redelivery(&self) -> tokio::task::JoinHandle<()> {
        let handler = self.clone();
        tokio::spawn(async move {
            loop {
                match handler.redeliver_abandoned_end_caps().await {
                    Ok(counts) if !counts.is_empty() => tracing::info!(?counts, "Settled admitted EndCaps"),
                    Ok(_) => {}
                    Err(error) => tracing::warn!(error = %format!("{error:#}"), "EndCap redelivery pass failed"),
                }
                tokio::time::sleep(END_CAP_REDELIVERY_INTERVAL).await;
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use parth_core::{crypto::hash::traits::ZeroableHash, protocol::core_types::Q256BitHash, PHash};
    use psy_node_core::{
        psy_core_db::traits::full::{PsyNodeCheckpointObjectDatabaseWriter, PsyNodeGlobalUserTreeDatabaseWriter},
        psy_temp_db::{
            tt_get_end_cap_redelivery_key, EndCapRedeliveryRecord, GatheringGeneration, QTempDBEndCapRedeliveryStore,
            QTempDBPendingIdWriter, QTempDBSubmitStatusWriter, TEMP_TABLE_ID_END_CAP_REDELIVERY_BYTES,
        },
        store::traits::temp_db::QTempDatabaseRawKVWriterBase,
    };

    use super::{EndCapRedeliveryCounts, END_CAP_REDELIVERY_DELAY_CHECKPOINTS, END_CAP_REDELIVERY_MAX_AGE_CHECKPOINTS};
    use crate::realm::{
        edge::handler::tests::{
            end_cap_env, seed_contract_heights, seed_three_validators, test_realm_identifier, valid_end_cap_submission, EndCapEnv,
            REALM_USER_ID,
        },
        network::{RealmNetworkCommand, RealmNetworkCommands},
    };
    use psy_data::p2p::EndCapForwardResponse;

    const RETIRED_PENDING_ID: u64 = 0;
    const PROCESSING_PENDING_ID: u64 = 3;
    const GATHERING_PENDING_ID: u64 = 4;

    async fn retired_admission() -> anyhow::Result<(EndCapEnv, EndCapRedeliveryRecord)> {
        let env = end_cap_env().await?;
        seed_contract_heights(&env).await?;
        let (input, proof) = valid_end_cap_submission(&env).await?;
        env.handler.handle_user_end_cap_proof_submission(input, proof, None).await?;
        let rid = test_realm_identifier();
        let record = stored_record(&env).await?.context("admission record")?;
        assert_eq!((record.admitted_unique_pending_id, record.admitted_checkpoint_id), (RETIRED_PENDING_ID, 0));
        assert_eq!(env.temp_db.get_end_cap_redelivery_user_ids(&rid, RETIRED_PENDING_ID).await?, vec![REALM_USER_ID]);
        env.temp_db.set_unique_pending_ids(&rid, PROCESSING_PENDING_ID, 3).await?;
        env.temp_db.set_gathering_generation(&rid, GatheringGeneration {
            checkpoint_id: 0, unique_pending_id: GATHERING_PENDING_ID, proc_checkpoint_unique_id: 4,
        }).await?;
        Ok((env, record))
    }

    async fn stored_record(env: &EndCapEnv) -> anyhow::Result<Option<EndCapRedeliveryRecord>> {
        env.temp_db.get_end_cap_redelivery(&test_realm_identifier(), REALM_USER_ID).await?
            .map(|bytes| EndCapRedeliveryRecord::from_bytes(&bytes)).transpose()
    }

    async fn settle_at(env: &EndCapEnv, latest_checkpoint_id: u64, user_leaf_hash: Option<PHash>) -> anyhow::Result<EndCapRedeliveryCounts> {
        env.db.set_latest_checkpoint_id(latest_checkpoint_id).await?;
        if let Some(user_leaf_hash) = user_leaf_hash {
            env.db.global_user_tree_set_leaf_hash(latest_checkpoint_id, REALM_USER_ID, user_leaf_hash).await?;
        }
        env.handler.redeliver_abandoned_end_caps().await
    }

    async fn assert_settled(env: &EndCapEnv) -> anyhow::Result<()> {
        let rid = test_realm_identifier();
        assert!(stored_record(env).await?.is_none());
        assert!(env.temp_db.get_end_cap_redelivery_user_ids(&rid, RETIRED_PENDING_ID).await?.is_empty());
        assert_eq!(env.temp_db.get_end_cap_redelivery_cursor(&rid).await?, Some(RETIRED_PENDING_ID + 1));
        assert_eq!(env.user_update_queue.published_count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn first_admission_starts_the_cursor_at_its_own_pending_id() -> anyhow::Result<()> {
        let env = end_cap_env().await?;
        let rid = test_realm_identifier();
        env.temp_db.set_unique_pending_ids(&rid, PROCESSING_PENDING_ID, 3).await?;
        assert_eq!(env.handler.redeliver_abandoned_end_caps().await?, EndCapRedeliveryCounts::default());
        assert_eq!(env.temp_db.get_end_cap_redelivery_cursor(&rid).await?, None, "a pass must not skip admissions it has not seen");
        seed_contract_heights(&env).await?;
        let (input, proof) = valid_end_cap_submission(&env).await?;
        env.handler.handle_user_end_cap_proof_submission(input.clone(), proof.clone(), None).await?;
        assert_eq!(env.temp_db.get_end_cap_redelivery_cursor(&rid).await?, Some(RETIRED_PENDING_ID));
        env.temp_db.set_gathering_generation(&rid, GatheringGeneration {
            checkpoint_id: 0, unique_pending_id: GATHERING_PENDING_ID, proc_checkpoint_unique_id: 4,
        }).await?;
        env.handler.handle_user_end_cap_proof_submission(input, proof, None).await?;
        assert_eq!(stored_record(&env).await?.context("second admission")?.admitted_unique_pending_id, GATHERING_PENDING_ID);
        assert_eq!(env.temp_db.get_end_cap_redelivery_cursor(&rid).await?, Some(RETIRED_PENDING_ID));
        Ok(())
    }

    #[tokio::test]
    async fn cursor_keeps_a_just_retired_pending_id_open_for_late_admissions() -> anyhow::Result<()> {
        let env = end_cap_env().await?;
        let rid = test_realm_identifier();
        env.temp_db.set_end_cap_redelivery_cursor(&rid, None, RETIRED_PENDING_ID).await?;
        env.temp_db.set_unique_pending_ids(&rid, RETIRED_PENDING_ID + 2, 2).await?;
        assert_eq!(env.handler.redeliver_abandoned_end_caps().await?, EndCapRedeliveryCounts::default());
        assert_eq!(env.temp_db.get_end_cap_redelivery_cursor(&rid).await?, Some(RETIRED_PENDING_ID));
        env.temp_db.set_unique_pending_ids(&rid, RETIRED_PENDING_ID + 3, 3).await?;
        env.handler.redeliver_abandoned_end_caps().await?;
        assert_eq!(env.temp_db.get_end_cap_redelivery_cursor(&rid).await?, Some(RETIRED_PENDING_ID + 1));
        Ok(())
    }

    #[tokio::test]
    async fn already_submitted_redelivery_keeps_the_record_for_a_later_pass() -> anyhow::Result<()> {
        let (env, record) = retired_admission().await?;
        let rid = test_realm_identifier();
        // A crashed earlier pass claimed the gathering pending id but never published or rewrote the record.
        env.temp_db.set_submitted_status_for_pending(&rid, GATHERING_PENDING_ID, REALM_USER_ID, 1).await?;
        let counts = settle_at(&env, END_CAP_REDELIVERY_DELAY_CHECKPOINTS, None).await?;
        assert_eq!(counts, EndCapRedeliveryCounts { requeued: 1, ..Default::default() });
        let requeued = stored_record(&env).await?.context("requeued record")?;
        assert_eq!(requeued.admitted_unique_pending_id, GATHERING_PENDING_ID);
        assert_eq!((requeued.end_cap_input, requeued.proof), (record.end_cap_input, record.proof));
        assert_eq!(env.temp_db.get_end_cap_redelivery_user_ids(&rid, GATHERING_PENDING_ID).await?, vec![REALM_USER_ID]);
        Ok(())
    }

    #[tokio::test]
    async fn replacing_a_record_never_overwrites_a_newer_admission() -> anyhow::Result<()> {
        let (env, record) = retired_admission().await?;
        let rid = test_realm_identifier();
        let observed = env.temp_db.get_end_cap_redelivery(&rid, REALM_USER_ID).await?.context("record bytes")?;
        let newer = EndCapRedeliveryRecord { admitted_unique_pending_id: GATHERING_PENDING_ID, proof: vec![42], ..record.clone() };
        assert!(env.temp_db.add_end_cap_redelivery(&rid, REALM_USER_ID, &newer).await?);
        let requeued = EndCapRedeliveryRecord { admitted_unique_pending_id: GATHERING_PENDING_ID + 1, ..record };
        assert!(!env.temp_db.replace_end_cap_redelivery(&rid, REALM_USER_ID, &observed, &requeued).await?);
        assert_eq!(stored_record(&env).await?, Some(newer));
        Ok(())
    }

    #[tokio::test]
    async fn admission_waits_for_the_redelivery_delay() -> anyhow::Result<()> {
        let (env, record) = retired_admission().await?;
        let rid = test_realm_identifier();
        env.temp_db.set_end_cap_redelivery_cursor(&rid, None, RETIRED_PENDING_ID).await?;
        assert_eq!(settle_at(&env, END_CAP_REDELIVERY_DELAY_CHECKPOINTS - 1, None).await?, EndCapRedeliveryCounts::default());
        assert_eq!(env.temp_db.get_end_cap_redelivery_cursor(&rid).await?, Some(RETIRED_PENDING_ID));
        assert_eq!(stored_record(&env).await?, Some(record));
        Ok(())
    }

    #[tokio::test]
    async fn included_end_cap_is_forgotten() -> anyhow::Result<()> {
        let (env, record) = retired_admission().await?;
        env.temp_db.set_end_cap_redelivery_cursor(&test_realm_identifier(), None, RETIRED_PENDING_ID).await?;
        let counts = settle_at(&env, END_CAP_REDELIVERY_DELAY_CHECKPOINTS, Some(PHash::from_owned_32bytes(record.new_user_leaf_hash))).await?;
        assert_eq!(counts, EndCapRedeliveryCounts { included: 1, ..Default::default() });
        assert_settled(&env).await
    }

    #[tokio::test]
    async fn superseded_end_cap_is_forgotten() -> anyhow::Result<()> {
        let (env, _) = retired_admission().await?;
        env.temp_db.set_end_cap_redelivery_cursor(&test_realm_identifier(), None, RETIRED_PENDING_ID).await?;
        let counts = settle_at(&env, END_CAP_REDELIVERY_DELAY_CHECKPOINTS, Some(PHash::from_values(5, 6, 7, 8))).await?;
        assert_eq!(counts, EndCapRedeliveryCounts { superseded: 1, ..Default::default() });
        assert_settled(&env).await
    }

    #[tokio::test]
    async fn abandoned_end_cap_is_submitted_again_into_the_gathering_pending_id() -> anyhow::Result<()> {
        let (env, record) = retired_admission().await?;
        let rid = test_realm_identifier();
        env.temp_db.set_end_cap_redelivery_cursor(&rid, None, RETIRED_PENDING_ID).await?;
        assert_eq!(PHash::from_owned_32bytes(record.old_user_leaf_hash), PHash::get_zero_value());
        let counts = settle_at(&env, END_CAP_REDELIVERY_DELAY_CHECKPOINTS, None).await?;
        assert_eq!(counts, EndCapRedeliveryCounts { redelivered: 1, ..Default::default() });
        assert_eq!(env.user_update_queue.published_count(), 2);
        let redelivered = stored_record(&env).await?.context("redelivered record")?;
        assert_eq!(redelivered.admitted_unique_pending_id, GATHERING_PENDING_ID);
        assert_eq!((redelivered.end_cap_input, redelivered.proof), (record.end_cap_input, record.proof));
        assert_eq!(env.temp_db.get_end_cap_redelivery_user_ids(&rid, GATHERING_PENDING_ID).await?, vec![REALM_USER_ID]);
        assert!(env.temp_db.get_end_cap_redelivery_user_ids(&rid, RETIRED_PENDING_ID).await?.is_empty());
        assert_eq!(env.temp_db.get_end_cap_redelivery_cursor(&rid).await?, Some(RETIRED_PENDING_ID + 1));
        Ok(())
    }

    #[tokio::test]
    async fn end_cap_past_the_age_limit_is_dropped_instead_of_redelivered() -> anyhow::Result<()> {
        let (env, _) = retired_admission().await?;
        env.temp_db.set_end_cap_redelivery_cursor(&test_realm_identifier(), None, RETIRED_PENDING_ID).await?;
        let counts = settle_at(&env, END_CAP_REDELIVERY_MAX_AGE_CHECKPOINTS + 1, None).await?;
        assert_eq!(counts, EndCapRedeliveryCounts { expired: 1, ..Default::default() });
        assert_settled(&env).await
    }

    #[tokio::test]
    async fn abandoned_end_cap_of_another_proposers_target_is_forwarded_and_forgotten() -> anyhow::Result<()> {
        let (mut env, record) = retired_admission().await?;
        let rid = test_realm_identifier();
        env.temp_db.set_end_cap_redelivery_cursor(&rid, None, RETIRED_PENDING_ID).await?;
        let (edges, proposer) = seed_three_validators(&env).await?;
        let local = (1..=3u16).find(|sub_id| *sub_id != proposer).context("non-proposer validator")?;
        let (commands, mut receiver) = tokio::sync::mpsc::channel(1);
        env.handler.set_realm_p2p(
            RealmNetworkCommands::from_channel(commands, edges[&local]),
            edges.clone(), edges.values().copied().collect(),
        );
        let remote = async {
            match receiver.recv().await.expect("forwarded EndCap") {
                RealmNetworkCommand::ForwardEndCap { destination, input, proof, response, .. } => {
                    assert_eq!(destination, edges[&proposer]);
                    assert_eq!((input, proof), (record.end_cap_input.clone(), record.proof.clone()));
                    response.send(Ok(EndCapForwardResponse::accepted())).expect("forward reply");
                }
                _ => panic!("expected an EndCap forwarding command"),
            }
        };
        let (counts, ()) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::join!(settle_at(&env, END_CAP_REDELIVERY_DELAY_CHECKPOINTS, None), remote)
        }).await.context("redelivery did not finish")?;
        assert_eq!(counts?, EndCapRedeliveryCounts { redelivered: 1, ..Default::default() });
        assert_settled(&env).await
    }

    #[tokio::test]
    async fn undecodable_record_is_dropped_and_the_pass_continues() -> anyhow::Result<()> {
        let (env, _) = retired_admission().await?;
        let rid = test_realm_identifier();
        env.temp_db.set_end_cap_redelivery_cursor(&rid, None, RETIRED_PENDING_ID).await?;
        let other_user = REALM_USER_ID + 1;
        let truncated = EndCapRedeliveryRecord {
            admitted_unique_pending_id: RETIRED_PENDING_ID, admitted_checkpoint_id: 0, old_user_leaf_hash: [0u8; 32],
            new_user_leaf_hash: [9u8; 32], end_cap_input: vec![], proof: vec![],
        };
        assert!(env.temp_db.add_end_cap_redelivery(&rid, other_user, &truncated).await?);
        let key = tt_get_end_cap_redelivery_key(rid.realm_id, rid.realm_sub_id, TEMP_TABLE_ID_END_CAP_REDELIVERY_BYTES, other_user);
        env.temp_db.qtdb_raw_kv_put_value(&key, &[1, 2, 3]).await?;
        let counts = settle_at(&env, END_CAP_REDELIVERY_DELAY_CHECKPOINTS, None).await?;
        assert_eq!(counts, EndCapRedeliveryCounts { redelivered: 1, ..Default::default() });
        assert!(env.temp_db.get_end_cap_redelivery(&rid, other_user).await?.is_none());
        assert_eq!(env.temp_db.get_end_cap_redelivery_cursor(&rid).await?, Some(RETIRED_PENDING_ID + 1));
        Ok(())
    }

    #[tokio::test]
    async fn stalled_older_admission_never_replaces_a_newer_one() -> anyhow::Result<()> {
        let (env, stalled) = retired_admission().await?;
        let rid = test_realm_identifier();
        let (input, proof) = valid_end_cap_submission(&env).await?;
        env.handler.handle_user_end_cap_proof_submission(input, proof, None).await?;
        let newer = stored_record(&env).await?.context("newer admission")?;
        assert_eq!(newer.admitted_unique_pending_id, GATHERING_PENDING_ID);
        assert!(!env.temp_db.add_end_cap_redelivery(&rid, REALM_USER_ID, &stalled).await?);
        assert_eq!(stored_record(&env).await?, Some(newer));
        Ok(())
    }
}
