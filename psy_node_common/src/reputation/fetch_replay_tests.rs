use std::sync::Arc;

use parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet;
use parth_core::{crypto::secp256k1::SimpleTimedRequest, data::queue::queue_key::PCoreQueueItemBase, node::realm_identifier::QRealmIdentifier, PHash};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use psy_core::job::job_id::{ProvingJobCircuitType, ProvingJobDataType, QJobTopic, QProvingJobDataID};
use psy_data::worker::{metadata::PsyProvingJobMetadata, metadata_with_job_id::PsyProvingJobMetadataWithJobId};
use psy_node_core::psy_temp_db::{QTempDBPendingIdWriter, QTempDBProofWitnessWriter, QTempDBWorkerReputationReader};

use crate::{coordinator::edge::handler::tests::EdgeTestEnv, realm::edge::handler::RealmEdgeHandler, test_common::{FakeEphemeralQueuePublisher, TestNetworkConfig, TestZKVerifier}};

#[tokio::test]
async fn captured_fetch_cannot_claim_twenty_jobs_or_consume_the_next_job() -> anyhow::Result<()> {
    let env = EdgeTestEnv::create().await?;
    let rid = QRealmIdentifier::new(1, 2);
    env.temp_db.set_unique_pending_ids(&rid, 7, 7).await?;
    let signer = MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&[1; 32])?;
    let key = signer.get_public_key();
    let (signature, request) = SimpleTimedRequest::create_signed_timed_request_for_request_proof_work::<_, CoreSha256Hasher>(
        &signer, &key, 30_000, [0; 32],
    );
    for task_index in 0..20 {
        let job = QProvingJobDataID {
            topic: QJobTopic::GenerateStandardProof, goal_id: 123,
            circuit_type: ProvingJobCircuitType::BatchUpdateContracts,
            group_id: 0, sub_group_id: 0, task_index,
            data_type: ProvingJobDataType::StandardProof, data_index: 0,
        };
        env.temp_db.set_tdb_proof_witnesses_tuple_owned_raw(&rid, 7, vec![(job.get_input_witness_id(), vec![0])]).await?;
        env.work_queue.add_items(vec![PsyProvingJobMetadataWithJobId::<PHash, _> {
            job_id: job, metadata: PsyProvingJobMetadata::new(PHash::default(), 0, 0, 1, 0, vec![]),
        }.encode_queue_item_vec()?]);
    }
    let response = env.handler.get_proving_work_with_child_proofs_internal(signature.clone(), request).await?;
    assert_eq!(response.base.job.job_id.task_index, 0);
    for _ in 1..20 {
        let error = env.handler.get_proving_work_with_child_proofs_internal(signature.clone(), request).await.unwrap_err();
        assert!(error.to_string().contains("already used"), "{error}");
    }
    let (fresh_sig, fresh_req) = SimpleTimedRequest::create_signed_timed_request_for_request_proof_work::<_, CoreSha256Hasher>(
        &signer, &key, 30_000, [1; 32],
    );
    let next = env.handler.get_proving_work_with_child_proofs_internal(fresh_sig, fresh_req).await?;
    assert_eq!(next.base.job.job_id.task_index, 1);
    assert_eq!(env.temp_db.get_worker_reputation(&rid, &key.0).await?, 5);
    Ok(())
}

#[tokio::test]
async fn coordinator_and_realm_reject_wrong_type_expired_and_duplicate_fetches() -> anyhow::Result<()> {
    let env = EdgeTestEnv::create().await?;
    let realm = RealmEdgeHandler::<TestNetworkConfig, _, _, _, _, _, _>::new(
        env.db.clone(), env.db.clone(), env.temp_db.clone(), env.temp_db.clone(),
        Arc::new(FakeEphemeralQueuePublisher::new()), env.work_queue.clone(),
        QRealmIdentifier::new(1, 3), 0, 0, Arc::new(TestZKVerifier {}),
    );
    let signer = MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&[2; 32])?;
    macro_rules! check {
        ($edge:expr, $tag:expr) => {{
            let (sig, req) = SimpleTimedRequest::create_signed_timed_request_for_submit_proof::<_, CoreSha256Hasher>(
                &signer, &signer.get_public_key(), 30_000, [$tag; 32],
            );
            assert!($edge.verify_miner_api_signature_and_check_reputation(&sig, &req).await.unwrap_err().to_string().contains("request type"));
            let (sig, req) = SimpleTimedRequest::create_signed_timed_request_for_request_proof_work::<_, CoreSha256Hasher>(
                &signer, &signer.get_public_key(), 30_000, [$tag; 32],
            );
            let mut bad = req;
            bad.tag[0] ^= 1;
            assert!($edge.verify_miner_api_signature_and_check_reputation(&sig, &bad).await.unwrap_err().to_string().contains("invalid signature"));
            let mut expired = req;
            expired.valid_until = 0;
            let expired_sig = parth_core::crypto::secp256k1::Secp256K1WalletProvider::sign(
                &signer, &signer.get_public_key(), expired.get_sig_hash::<CoreSha256Hasher>(),
            )?;
            assert!($edge.verify_miner_api_signature_and_check_reputation(&expired_sig, &expired).await.unwrap_err().to_string().contains("expired"));
            $edge.verify_miner_api_signature_and_check_reputation(&sig, &req).await?;
            assert!($edge.verify_miner_api_signature_and_check_reputation(&sig, &req).await.unwrap_err().to_string().contains("already used"));
        }};
    }
    check!(env.handler, 1);
    check!(realm, 2);
    let (sig, req) = SimpleTimedRequest::create_signed_timed_request_for_request_proof_work::<_, CoreSha256Hasher>(
        &signer, &signer.get_public_key(), 30_000, [3; 32],
    );
    env.handler.verify_miner_api_signature_and_check_reputation(&sig, &req).await?;
    assert!(realm.verify_miner_api_signature_and_check_reputation(&sig, &req).await.unwrap_err().to_string().contains("already used"));
    Ok(())
}

#[tokio::test]
async fn concurrent_fetch_authentication_has_one_winner() -> anyhow::Result<()> {
    let env = EdgeTestEnv::create().await?;
    let signer = MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&[3; 32])?;
    let (sig, req) = SimpleTimedRequest::create_signed_timed_request_for_request_proof_work::<_, CoreSha256Hasher>(
        &signer, &signer.get_public_key(), 30_000, [0; 32],
    );
    let results = futures::future::join_all((0..32).map(|_| {
        env.handler.verify_miner_api_signature_and_check_reputation(&sig, &req)
    })).await;
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results.iter().filter_map(|r| r.as_ref().err()).all(|e| e.to_string().contains("already used")));
    Ok(())
}
