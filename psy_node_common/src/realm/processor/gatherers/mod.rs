pub mod realm_end_cap_gatherer;
#[cfg(test)]
mod end_cap_handoff_tests {
    use std::{collections::HashMap, future::pending, io::Cursor, sync::{Arc, Mutex, RwLock}, time::Duration};

    use anyhow::Context;
    use async_trait::async_trait;
    use parth_common::memory_stores::{mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm};
    use parth_core::{
        crypto::hash::traits::QFieldHashable,
        data::queue::queue_key::{PCoreStandardQueueKeyForRealm, QPBaseQueueType},
        felt::{FromPrimitiveValuesFelt, ToU64Value},
        pgoldilocks::PoseidonHasher,
        protocol::core_types::{Q256BitHash, QNetworkTreeConstants},
        PHash, PF, QCoreProcCheckpointUniqueId,
    };
    use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
    use psy_data::{
        node::realm_processor::RealmProcessorCoreState,
        proof_input::guta::end_cap_input::PsyUserEventRecord,
        queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
        v1::qdata::{checkpoint::PQEDCheckpointLeaf, user::PQEDUserLeaf},
    };
    use psy_io::tokio::TokioLikeFileSystem;
    use psy_node_core::{
        file::memory_fs::SimpleMockMemoryFileSystem,
        psy_core_db::traits::full::{
            PsyNodeCheckpointObjectDatabaseWriter, PsyNodeCheckpointTreeDatabaseWriter,
            PsyNodeCoreDatabaseUserStoreWriter, PsyNodeGlobalUserTreeDatabaseWriter,
            PsyNodeValidatorTreeDatabaseWriter,
        },
        psy_temp_db::{QTempDBUserContractUpdatesReader, QTempDBUserContractUpdatesWriter},
        qblob::{
            blob_type::{QBlobDataType, QBlobMerkleNodeTreeType},
            data_views::{double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView, single_merkle_node_batch::QBlobSingleMerkleNodeBatchDataView},
            structs::common::{blob_metadata_header::QBlobWriterContextMetadataHeader, tree_node_batch_header::QBlobMerkleTreeNodeBatchHeaderV1},
        },
        queue::{ephemeral::QStandardEphemeralQueueSubscriber, infrastructure::QStandardQueueBase},
    };
    use psy_node_store_memory::temp_store::InMemoryTempStore;
    use psy_serialize::{PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
    use tokio::{io::AsyncReadExt, sync::{mpsc, Semaphore}, task::JoinHandle, time::timeout};

    use crate::{
        constants::queue::PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID,
        guta_planner::realm_guta_planner_tests::{
            create_rgp_test_db,
            test_env::{RGPContractUpdate, RGPTestChainState, RGPUser},
        },
        queue::gatherer::EphemeralQueueGathererWithTree,
        realm::{edge::utils::end_cap::validate_end_cap_and_generate_node_data_for_edge, queue_key::RealmUserUpdateQueueKey},
        test_common::{FakeEphemeralQueueSubscriber, TestNetworkConfig},
        utils::processor_status::ProcessorStatus,
    };

    use super::realm_end_cap_gatherer::{
        get_new_realm_end_cap_gatherer_backup_file_path, read_realm_end_cap_gatherer_backup_file,
        RealmGUTAEndCapGatherer, RealmGUTAEndCapGathererConfig, RealmGUTAEndCapGathererOutput,
    };

    type N = TestNetworkConfig;
    type Tree = SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>;
    type Item = PsyRealmUserUpdateQueueItem<PF, PHash>;
    type Output = RealmGUTAEndCapGathererOutput<PF, PHash, QProvingJobDataID>;
    type Config = RealmGUTAEndCapGathererConfig<N, InMemoryTempStore, SimpleMockMemoryFileSystem>;
    type Builder = RealmGUTAEndCapGatherer<N, InMemoryTempStore, SimpleMockMemoryFileSystem>;
    type Gatherer = EphemeralQueueGathererWithTree<PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID, Item, Output>;
    const FIRST_QUEUE: u128 = 11;
    const SECOND_QUEUE: u128 = 22;
    const THIRD_QUEUE: u128 = 33;
    const WAIT: Duration = Duration::from_secs(10);

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum QueueEvent {
        Consumer(u128),
        Intake(u128, usize),
        Idle(u128),
        TailReady(u128),
        Drain(u128, usize, usize),
        Deleted(u128),
    }

    struct HandoffSubscriber {
        queue: FakeEphemeralQueueSubscriber,
        drains: Mutex<HashMap<u128, usize>>,
        events: mpsc::UnboundedSender<QueueEvent>,
        history: Mutex<Vec<QueueEvent>>,
        release_tail: Semaphore,
    }

    impl HandoffSubscriber {
        fn record(&self, event: QueueEvent) {
            self.history.lock().unwrap().push(event.clone());
            self.events.send(event).expect("test still owns queue event receiver");
        }

        fn contains(&self, event: QueueEvent) -> bool {
            self.history.lock().unwrap().contains(&event)
        }
    }

    #[async_trait]
    impl QStandardQueueBase for HandoffSubscriber {
        async fn ensure_stream(&self) -> anyhow::Result<()> { Ok(()) }

        async fn ensure_consumer<QK: PCoreStandardQueueKeyForRealm>(
            &self, _: &QK, _: u64, _: u64, unique_id: QCoreProcCheckpointUniqueId, _: u32,
        ) -> anyhow::Result<()> {
            self.record(QueueEvent::Consumer(unique_id));
            Ok(())
        }
    }

    #[async_trait]
    impl QStandardEphemeralQueueSubscriber for HandoffSubscriber {
        async fn dump_entire_ephemeral_queue_bytes<QK: PCoreStandardQueueKeyForRealm>(
            &self, key: &QK, realm: u64, sub: u64, unique_id: QCoreProcCheckpointUniqueId,
            group: u32, max_items: usize,
        ) -> anyhow::Result<Vec<Vec<u8>>> {
            if max_items == usize::MAX {
                let pass = {
                    let mut drains = self.drains.lock().unwrap();
                    let count = drains.entry(unique_id).or_default();
                    *count += 1;
                    *count
                };
                assert!(pass <= 3, "unexpected extra drain of generation {unique_id}");
                if pass == 3 {
                    // Gate replacement bootstrap after finalized output to inject a late copy or authenticate its proof base.
                    self.record(QueueEvent::TailReady(unique_id));
                    self.release_tail.acquire().await?.forget();
                }
                let items = self.queue.dump_entire_ephemeral_queue_bytes(key, realm, sub, unique_id, group, max_items).await?;
                self.record(QueueEvent::Drain(unique_id, pass, items.len()));
                return Ok(items);
            }
            let items = self.queue.dump_entire_ephemeral_queue_bytes(key, realm, sub, unique_id, group, max_items).await?;
            if items.is_empty() {
                // The next normal read confirms the builder update completed; wait for finalize to advance the generation.
                self.record(QueueEvent::Idle(unique_id));
                pending::<()>().await;
            }
            self.record(QueueEvent::Intake(unique_id, items.len()));
            Ok(items)
        }

        async fn delete_ephemeral_queue_consumer<QK: PCoreStandardQueueKeyForRealm>(
            &self, _: &QK, _: u64, _: u64, unique_id: QCoreProcCheckpointUniqueId, _: u32,
        ) -> anyhow::Result<()> {
            self.record(QueueEvent::Deleted(unique_id));
            Ok(())
        }

        async fn wait_for_ephemeral_queue_item_bytes<QK: PCoreStandardQueueKeyForRealm>(
            &self, _: &QK, _: u64, _: u64, _: QCoreProcCheckpointUniqueId, _: u32, _: u64,
        ) -> anyhow::Result<Option<Vec<u8>>> { unreachable!("tree owner uses batch reads") }

        async fn wait_for_ephemeral_queue_item<QK: PCoreStandardQueueKeyForRealm>(
            &self, _: &QK, _: u64, _: u64, _: QCoreProcCheckpointUniqueId, _: u32, _: u64,
        ) -> anyhow::Result<Option<QK::QueueItem>> { unreachable!("tree owner uses byte batches") }

        async fn dump_entire_ephemeral_queue<QK: PCoreStandardQueueKeyForRealm>(
            &self, _: &QK, _: u64, _: u64, _: QCoreProcCheckpointUniqueId, _: u32, _: usize,
        ) -> anyhow::Result<Vec<QK::QueueItem>> { unreachable!("tree owner uses byte batches") }

        async fn consume_ephemeral_queue_item_or_none_bytes<QK: PCoreStandardQueueKeyForRealm>(
            &self, _: &QK, _: u64, _: u64, _: QCoreProcCheckpointUniqueId, _: u32,
        ) -> anyhow::Result<Option<Vec<u8>>> { unreachable!("tree owner uses batch reads") }

        async fn consume_ephemeral_queue_item_or_none<QK: PCoreStandardQueueKeyForRealm>(
            &self, _: &QK, _: u64, _: u64, _: QCoreProcCheckpointUniqueId, _: u32,
        ) -> anyhow::Result<Option<QK::QueueItem>> { unreachable!("tree owner uses byte batches") }
    }

    struct HandoffRunner {
        subscriber: Arc<HandoffSubscriber>,
        events: mpsc::UnboundedReceiver<QueueEvent>,
        gatherer: Gatherer,
        status: ProcessorStatus,
        task: Option<JoinHandle<anyhow::Result<()>>>,
    }

    impl Drop for HandoffRunner {
        fn drop(&mut self) {
            if let Some(task) = &self.task { task.abort(); }
        }
    }

    impl HandoffRunner {
        fn start(config: Config, tree: Arc<tokio::sync::RwLock<Tree>>, first: Option<Vec<u8>>) -> Self {
            let (tx, events) = mpsc::unbounded_channel();
            let subscriber = Arc::new(HandoffSubscriber {
                queue: FakeEphemeralQueueSubscriber::new(),
                drains: Mutex::new(HashMap::new()),
                events: tx,
                history: Mutex::new(Vec::new()),
                release_tail: Semaphore::new(0),
            });
            if let Some(first) = first { subscriber.queue.add_items(FIRST_QUEUE, vec![first]); }
            let key = RealmUserUpdateQueueKey::<PF, PHash> {
                realm_id: config.realm_id_u64,
                realm_sub_id: config.realm_sub_id_u64,
                unique_id: FIRST_QUEUE,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            };
            let status = ProcessorStatus::new();
            status.mark_running();
            let (gatherer, task) = Gatherer::new_with_status_shared::<_, _, PHash, PoseidonHasher, Builder>(
                subscriber.clone(), config, key, tree, status.clone(),
            );
            Self { subscriber, events, gatherer, status, task: Some(task) }
        }

        async fn wait_for(&mut self, expected: QueueEvent) -> anyhow::Result<()> {
            timeout(WAIT, async {
                loop {
                    let event = self.events.recv().await.context("queue owner stopped before expected event")?;
                    if event == expected { return Ok(()); }
                }
            }).await.with_context(|| format!("timed out waiting for {expected:?}"))?
        }

        async fn finalize(&mut self, old_queue: u128, next_queue: u128) -> anyhow::Result<Output> {
            let output = timeout(WAIT, self.gatherer.finalize_gathering_and_update_queue_key(next_queue))
                .await.context("timed out finalizing Realm generation")??;
            self.wait_for(QueueEvent::TailReady(old_queue)).await?;
            assert!(self.subscriber.contains(QueueEvent::Drain(old_queue, 1, 0)));
            assert!(self.subscriber.contains(QueueEvent::Drain(old_queue, 2, 0)));
            Ok(output)
        }

        async fn stop_at_tail(&mut self) -> anyhow::Result<()> {
            self.status.begin_shutdown();
            self.subscriber.release_tail.add_permits(1);
            timeout(WAIT, self.task.as_mut().expect("runner task"))
                .await.context("timed out stopping Realm queue owner")???;
            self.task.take();
            Ok(())
        }
    }

    struct HandoffFixture {
        chain: RGPTestChainState,
        config: Config,
        tree: Arc<tokio::sync::RwLock<Tree>>,
        initial_tree: Tree,
    }

    impl HandoffFixture {
        async fn new() -> anyhow::Result<Self> {
            let db = Arc::new(create_rgp_test_db().await?);
            let mut chain = RGPTestChainState::new(db, 0, 1);
            chain.unique_cord_proc_id = FIRST_QUEUE;
            chain.unique_pending_id = 1;
            chain.users.insert(0, RGPUser::new(0, PHash::from_values(41, 42, 43, 44)));
            chain.add_new_contract(12).await?;
            let mut initial_tree = chain.first_realm_global_user_tree.clone();
            initial_tree.commit_changes();
            let config = Config {
                realm_id_u64: chain.realm_id_u64,
                realm_sub_id_u64: chain.realm_sub_id_u64,
                status: Arc::new(RwLock::new(RealmProcessorCoreState::new_basic(
                    chain.chain_id, chain.realm_identifier, 0, 1, FIRST_QUEUE,
                    chain.checkpoint_tree_root, initial_tree.get_root(),
                ))),
                temp_db: chain.temp_db.clone(),
                file_system: Arc::new(SimpleMockMemoryFileSystem::new()),
                backup_file_directory: "handoff_backups".to_string(),
                coordinator_guta_updates_circuit_whitelist: chain.guta_circuit_whitelist,
                checkpoint_tree: Arc::new(chain.checkpoint_tree.clone()),
                future_pending_end_cap_jobs: Arc::new(RwLock::new(Vec::new())),
                current_validator_user_leaf: Arc::new(Mutex::new(chain.finalizer_user.user_leaf.clone())),
                tree_store: chain.db.clone(),
                _phantom_n: std::marker::PhantomData,
            };
            let mut fixture = Self {
                tree: Arc::new(tokio::sync::RwLock::new(initial_tree.clone())),
                chain, config, initial_tree,
            };
            fixture.save_checkpoint(0, None).await?;
            Ok(fixture)
        }

        async fn end_cap(&mut self, pending_id: u64, value: u64) -> anyhow::Result<Item> {
            let mut input = self.chain.users.get_mut(&0).unwrap().run_ups(
                &self.chain.contract_height_cache, 0, self.chain.checkpoint_tree_root,
                &[RGPContractUpdate { contract_id: 0, leaves: vec![(0, PHash::from_values(value, 2, 3, 4))] }],
            )?;
            input.events.push(PsyUserEventRecord {
                checkpoint_id: PF::from_u64_value(0), user_id: PF::from_u64_value(0),
                contract_id: PF::from_u64_value(0), method_id: PF::from_u64_value(7),
                event_index: PF::from_u64_value(0), data: vec![PF::from_u64_value(value)],
            });
            let nonce = 100 + pending_id;
            let context = QBlobWriterContextMetadataHeader::new_at_now(
                self.chain.chain_id, 0, 0, 1, pending_id, nonce, 0,
            );
            let updates = validate_end_cap_and_generate_node_data_for_edge::<PF, PHash, PoseidonHasher>(
                &context, 0, &input,
            )?;
            self.chain.temp_db.set_contract_updates_for_user(&self.chain.realm_identifier, pending_id, 0, updates).await?;
            Ok(Item {
                job_id: QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(0, N::GLOBAL_USER_TREE_HEIGHT, pending_id)?,
                submission_nonce: nonce,
                old_user_leaf_hash: input.core.state_transition.start_user_leaf_hash,
                new_user_leaf_hash: input.core.new_user_leaf.qfhash::<PoseidonHasher>(),
                new_user_leaf: input.core.new_user_leaf,
                stats: input.core.stats,
                events: input.events,
            })
        }

        async fn restage(&self, item: &Item) -> anyhow::Result<Item> {
            let updates = self.contract_updates(1).await?;
            self.chain.temp_db.set_contract_updates_for_user(&self.chain.realm_identifier, 2, 0, updates).await?;
            let mut restaged = item.clone();
            restaged.job_id = QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(0, N::GLOBAL_USER_TREE_HEIGHT, 2)?;
            Ok(restaged)
        }

        async fn contract_updates(&self, pending_id: u64) -> anyhow::Result<Vec<u8>> {
            self.chain.temp_db.get_contract_updates_for_user(&self.chain.realm_identifier, pending_id, 0)
                .await?.context("fixture contract updates")
        }

        async fn save_checkpoint(&mut self, checkpoint_id: u64, user: Option<&Item>) -> anyhow::Result<()> {
            let db = &self.chain.db;
            let validator = self.config.current_validator_user_leaf.lock().unwrap().clone();
            db.set_user_leaf(checkpoint_id, &validator).await?;
            db.global_user_tree_set_leaf_hash(checkpoint_id, validator.user_id.to_u64_value(), validator.qfhash::<PoseidonHasher>()).await?;
            if let Some(item) = user {
                db.set_user_leaf(checkpoint_id, &item.new_user_leaf).await?;
                db.global_user_tree_set_leaf_hash(checkpoint_id, 0, item.new_user_leaf_hash).await?;
            }
            let root = self.tree.read().await.get_root();
            self.chain.coordinator_global_user_tree.set_e_leaf(0, root);
            let top = self.chain.coordinator_global_user_tree.get_e_leaf(0);
            db.global_user_tree_set_top_tree_merkle_proof(checkpoint_id, &top).await?;
            db.validator_tree_set_leaf_hash(checkpoint_id, 1, PHash::from_owned_32bytes(self.chain.validator_preimage.leaf_hash()?)).await?;
            db.validator_tree_set_leaf_preimage(checkpoint_id, 1, &self.chain.validator_preimage).await?;
            let mut roots = self.chain.finalizer_state_roots;
            roots.user_tree_root = top.root;
            let leaf = PQEDCheckpointLeaf { global_chain_root: roots.qfhash::<PoseidonHasher>(), stats: self.chain.finalizer_checkpoint_leaf.stats };
            db.set_checkpoint_global_state_roots(checkpoint_id, &roots).await?;
            db.set_checkpoint_leaf_data(checkpoint_id, &leaf).await?;
            db.checkpoint_tree_set_leaf_hash(checkpoint_id, leaf.qfhash::<PoseidonHasher>()).await?;
            if checkpoint_id != 0 {
                self.config.checkpoint_tree.append_leaf(checkpoint_id, leaf.qfhash::<PoseidonHasher>())?;
            }
            Ok(())
        }

        fn replace_generation(&self, checkpoint_id: u64) {
            let mut status = self.config.status.write().unwrap();
            status.gathering_checkpoint_id = checkpoint_id;
            status.gathering_checkpoint_root = if checkpoint_id == 0 { self.chain.checkpoint_tree_root } else { self.config.checkpoint_tree.get_root() };
            status.gathering_unique_pending_id = 2;
            status.gathering_proc_checkpoint_unique_id = SECOND_QUEUE;
            status.processing_realm_end_root = status.gathering_realm_start_root;
        }

        async fn backup(&self, pending_id: u64) -> anyhow::Result<Vec<u8>> {
            let path = get_new_realm_end_cap_gatherer_backup_file_path("handoff_backups", 0, 1, pending_id);
            let mut file = self.config.file_system.file_like_fs_open(path.to_str().unwrap()).await?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).await?;
            Ok(bytes)
        }

        async fn assert_backup(&self, pending_id: u64, start: &Tree, output: &Output, item: Option<&Item>) -> anyhow::Result<()> {
            let bytes = self.backup(pending_id).await?;
            let count = u64::from_le_bytes(bytes[68..76].try_into()?);
            assert_eq!(count, u64::from(item.is_some()));
            if let Some(item) = item {
                let encoded = item.psy_ser_to_bytes_vec()?;
                assert_eq!(&bytes[76..76 + encoded.len()], encoded.as_slice());
                let mut cursor = Cursor::new(&bytes[76..]);
                let recorded = Item::pio_read_from_io(&mut cursor)?;
                assert_eq!(recorded.events, item.events);
                assert_eq!(recorded.events.len(), 1);
                let updates = self.contract_updates(pending_id).await?;
                let offset = 76 + cursor.position() as usize;
                assert_eq!(&bytes[offset..offset + updates.len()], updates.as_slice());
            }
            let path = get_new_realm_end_cap_gatherer_backup_file_path("handoff_backups", 0, 1, pending_id);
            let mut restored_tree = start.clone();
            let restored = read_realm_end_cap_gatherer_backup_file::<PoseidonHasher, PHash, PF, _>(
                self.config.file_system.as_ref(), path.to_str().unwrap(), &mut restored_tree,
                0, N::REALM_GLOBAL_USER_TREE_HEIGHT, N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, false,
            ).await?;
            assert_eq!(restored_tree.get_root(), output.db_output.new_realm_root);
            assert_eq!(restored.update_user_leaves_ffs, output.db_output.update_user_leaves_ffs);
            assert_eq!(restored.update_contract_state_tree_nodes_ffs, output.db_output.update_contract_state_tree_nodes_ffs);
            Ok(())
        }
    }

    fn assert_empty(output: &Output, root: PHash) {
        assert_eq!(output.db_output.old_realm_root, root);
        assert_eq!(output.db_output.new_realm_root, root);
        assert_eq!(output.db_output.total_users_updated, 0);
        assert_eq!(output.db_output.total_proofs_generated, 0);
        assert!(output.job_ids.is_empty());
        assert!(output.db_output.update_global_user_tree_nodes_ffs.is_empty());
        assert!(output.db_output.update_user_leaves_ffs.is_empty());
        assert!(output.db_output.update_user_contract_tree_nodes_ffs.is_empty());
        assert!(output.db_output.update_contract_state_tree_nodes_ffs.is_empty());
        assert!(output.db_output.update_contract_state_imt_leaves_ffs.is_empty());
    }

    async fn assert_one_end_cap(fixture: &HandoffFixture, output: &Output, item: &Item, pending_id: u64) -> anyhow::Result<()> {
        assert_eq!(output.db_output.total_users_updated, 1);
        assert_eq!(output.db_output.total_proofs_generated, 2);
        let jobs: Vec<_> = output.job_ids.iter().flatten().collect();
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].job_id.circuit_type, ProvingJobCircuitType::GUTASingleEndCap);
        assert_eq!(jobs[0].metadata.dependencies, vec![item.job_id]);
        assert_eq!(jobs[1].job_id.circuit_type, ProvingJobCircuitType::RealmFinalizeGUTA);
        assert_eq!(jobs[1].metadata.dependencies, vec![jobs[0].job_id]);
        assert_eq!(output.db_output.guta_header.job_id, jobs[1].job_id);
        let size = PQEDUserLeaf::<PF, PHash>::FIXED_SIZE;
        assert_eq!(output.db_output.update_user_leaves_ffs.len(), 2 * size);
        let leaves = output.db_output.update_user_leaves_ffs.chunks_exact(size)
            .map(PQEDUserLeaf::<PF, PHash>::psy_ser_from_slice).collect::<anyhow::Result<Vec<_>>>()?;
        assert_eq!(leaves.iter().filter(|leaf| leaf.user_id.to_u64_value() == 0).collect::<Vec<_>>(), vec![&item.new_user_leaf]);
        let validator = fixture.config.current_validator_user_leaf.lock().unwrap().clone();
        assert_eq!(leaves.iter().filter(|leaf| leaf.user_id == validator.user_id).collect::<Vec<_>>(), vec![&validator]);
        assert_eq!(fixture.tree.read().await.get_leaf_value(0), item.new_user_leaf_hash);

        let updates = fixture.contract_updates(pending_id).await?;
        let (_, single, rest) = QBlobSingleMerkleNodeBatchDataView::validate_single_tree_nodes_batch_header_for_realm_context_get_clipped_ref_no_exact_size_any_unique_pending_id(
            &updates, fixture.chain.chain_id, 0, 1, QBlobMerkleNodeTreeType::UserContractTree,
        )?;
        let (_, double, rest) = QBlobDoubleMerkleNodeBatchDataView::validate_cst_nodes_batch_header_for_realm_context_get_clipped_ref_any_unique_pending_id_with_remaining(
            rest, fixture.chain.chain_id, 0, 1,
        )?;
        let (_, imt) = QBlobMerkleTreeNodeBatchHeaderV1::clip_header_get_payload_for_blob_type_and_tree_ref(
            rest, QBlobDataType::GenericIMTLeafBatch, QBlobMerkleNodeTreeType::IMTContractStateLeaf, true,
        )?;
        assert!(!single.is_empty());
        assert!(!double.is_empty());
        assert_eq!(output.db_output.update_user_contract_tree_nodes_ffs.as_slice(), single);
        assert_eq!(output.db_output.update_contract_state_tree_nodes_ffs.as_slice(), double);
        assert_eq!(output.db_output.update_contract_state_imt_leaves_ffs.as_slice(), imt);
        Ok(())
    }

    async fn restage_through_queue_owner(first_consumed: bool) -> anyhow::Result<()> {
        let mut fixture = HandoffFixture::new().await?;
        let item = fixture.end_cap(1, 51).await?;
        let mut runner = HandoffRunner::start(fixture.config.clone(), fixture.tree.clone(),
            if first_consumed { Some(item.psy_ser_to_bytes_vec()?) } else { None });
        runner.wait_for(QueueEvent::Idle(FIRST_QUEUE)).await?;
        assert_eq!(runner.subscriber.contains(QueueEvent::Intake(FIRST_QUEUE, 1)), first_consumed);
        let first = runner.finalize(FIRST_QUEUE, SECOND_QUEUE).await?;
        let after_first = fixture.tree.read().await.clone();
        if first_consumed {
            assert_one_end_cap(&fixture, &first, &item, 1).await?;
        } else {
            assert_empty(&first, fixture.initial_tree.get_root());
            runner.subscriber.queue.add_items(FIRST_QUEUE, vec![item.psy_ser_to_bytes_vec()?]);
        }
        fixture.assert_backup(1, &fixture.initial_tree, &first, first_consumed.then_some(&item)).await?;
        fixture.save_checkpoint(1, first_consumed.then_some(&item)).await?;
        fixture.replace_generation(1);
        let restaged = fixture.restage(&item).await?;
        runner.subscriber.queue.add_items(SECOND_QUEUE, vec![restaged.psy_ser_to_bytes_vec()?]);
        runner.subscriber.release_tail.add_permits(1);
        runner.wait_for(QueueEvent::Idle(SECOND_QUEUE)).await?;
        assert!(runner.subscriber.contains(QueueEvent::Intake(SECOND_QUEUE, 1)));
        assert!(runner.subscriber.contains(QueueEvent::Drain(FIRST_QUEUE, 3, usize::from(!first_consumed))));
        assert_eq!(runner.subscriber.contains(QueueEvent::Deleted(FIRST_QUEUE)), first_consumed);
        let second = runner.finalize(SECOND_QUEUE, THIRD_QUEUE).await?;
        if first_consumed { assert_empty(&second, after_first.get_root()); }
        else { assert_one_end_cap(&fixture, &second, &restaged, 2).await?; }
        fixture.assert_backup(2, &after_first, &second, (!first_consumed).then_some(&restaged)).await?;
        assert_eq!(first.db_output.total_users_updated + second.db_output.total_users_updated, 1);
        assert_eq!(first.db_output.total_proofs_generated + second.db_output.total_proofs_generated, 2);
        assert_eq!(fixture.tree.read().await.get_leaf_value(0), item.new_user_leaf_hash);
        assert!(fixture.config.future_pending_end_cap_jobs.read().unwrap().is_empty());
        runner.stop_at_tail().await?;
        Ok(())
    }

    #[tokio::test]
    async fn consumed_end_cap_restaged_after_finalize_has_no_duplicate_effects() -> anyhow::Result<()> {
        restage_through_queue_owner(true).await
    }

    #[tokio::test]
    async fn retired_tail_end_cap_is_discarded_and_restaged_copy_is_consumed() -> anyhow::Result<()> {
        restage_through_queue_owner(false).await
    }

    #[tokio::test]
    async fn unauthenticated_replacement_proof_base_discards_accepted_end_cap() -> anyhow::Result<()> {
        let mut fixture = HandoffFixture::new().await?;
        let item = fixture.end_cap(1, 61).await?;
        let mut runner = HandoffRunner::start(fixture.config.clone(), fixture.tree.clone(), Some(item.psy_ser_to_bytes_vec()?));
        runner.wait_for(QueueEvent::Idle(FIRST_QUEUE)).await?;
        let first = runner.finalize(FIRST_QUEUE, SECOND_QUEUE).await?;
        assert_one_end_cap(&fixture, &first, &item, 1).await?;
        let retained_root = fixture.tree.read().await.get_root();
        let retained_validator = fixture.config.current_validator_user_leaf.lock().unwrap().clone();
        // Checkpoint 0 cannot authenticate the replacement's start root, so finalize must discard the accepted EndCap.
        fixture.replace_generation(0);
        let next = fixture.end_cap(2, 62).await?;
        assert_eq!(next.old_user_leaf_hash, item.new_user_leaf_hash);
        runner.subscriber.queue.add_items(SECOND_QUEUE, vec![next.psy_ser_to_bytes_vec()?]);
        runner.subscriber.release_tail.add_permits(1);
        runner.wait_for(QueueEvent::Idle(SECOND_QUEUE)).await?;
        let pending_backup = fixture.backup(2).await?;
        let encoded = next.psy_ser_to_bytes_vec()?;
        assert_eq!(&pending_backup[76..76 + encoded.len()], encoded.as_slice(), "new EndCap must reach the real builder before discard");
        let second = runner.finalize(SECOND_QUEUE, THIRD_QUEUE).await?;
        assert_empty(&second, retained_root);
        assert_eq!(fixture.tree.read().await.get_leaf_value(0), item.new_user_leaf_hash);
        assert_eq!(*fixture.config.current_validator_user_leaf.lock().unwrap(), retained_validator);
        assert!(fixture.config.future_pending_end_cap_jobs.read().unwrap().is_empty());
        runner.stop_at_tail().await?;
        Ok(())
    }

    struct OverlappedGeneration {
        fixture: HandoffFixture,
        item: Item,
        next: Item,
        first_end_tree: Tree,
        second: Output,
    }

    async fn finalize_generation_started_before_inclusion(proof_base_id: u64) -> anyhow::Result<OverlappedGeneration> {
        let mut fixture = HandoffFixture::new().await?;
        let item = fixture.end_cap(1, 71).await?;
        let mut runner = HandoffRunner::start(fixture.config.clone(), fixture.tree.clone(), Some(item.psy_ser_to_bytes_vec()?));
        runner.wait_for(QueueEvent::Idle(FIRST_QUEUE)).await?;
        let first = runner.finalize(FIRST_QUEUE, SECOND_QUEUE).await?;
        assert_one_end_cap(&fixture, &first, &item, 1).await?;
        let first_end_tree = fixture.tree.read().await.clone();
        for checkpoint_id in 1..=proof_base_id {
            fixture.save_checkpoint(checkpoint_id, Some(&item)).await?;
        }
        // Production order: the replacement bootstraps on the first end root while checkpoint 0 is still the gathering base.
        fixture.replace_generation(0);
        let next = fixture.end_cap(2, 72).await?;
        runner.subscriber.queue.add_items(SECOND_QUEUE, vec![next.psy_ser_to_bytes_vec()?]);
        runner.subscriber.release_tail.add_permits(1);
        runner.wait_for(QueueEvent::Idle(SECOND_QUEUE)).await?;
        let encoded = next.psy_ser_to_bytes_vec()?;
        assert_eq!(&fixture.backup(2).await?[76..76 + encoded.len()], encoded.as_slice());
        fixture.replace_generation(proof_base_id);
        let second = runner.finalize(SECOND_QUEUE, THIRD_QUEUE).await?;
        runner.stop_at_tail().await?;
        Ok(OverlappedGeneration { fixture, item, next, first_end_tree, second })
    }

    #[tokio::test]
    async fn end_cap_accepted_while_previous_generation_proves_commits_after_inclusion() -> anyhow::Result<()> {
        let overlapped = finalize_generation_started_before_inclusion(1).await?;
        let OverlappedGeneration { fixture, next, first_end_tree, second, .. } = &overlapped;
        assert_eq!(second.db_output.old_realm_root, first_end_tree.get_root());
        assert_one_end_cap(fixture, second, next, 2).await?;
        fixture.assert_backup(2, first_end_tree, second, Some(next)).await?;
        assert!(fixture.config.future_pending_end_cap_jobs.read().unwrap().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn generation_whose_including_checkpoint_schedules_next_epoch_is_discarded() -> anyhow::Result<()> {
        let proof_base_id = psy_config::CHECKPOINTS_PER_EPOCH - 1;
        let overlapped = finalize_generation_started_before_inclusion(proof_base_id).await?;
        let first_end_root = overlapped.first_end_tree.get_root();
        assert_empty(&overlapped.second, first_end_root);
        let validator = overlapped.fixture.config.current_validator_user_leaf.lock().unwrap().clone();
        assert_eq!(overlapped.first_end_tree.get_leaf_value(validator.user_id.to_u64_value()), validator.qfhash::<PoseidonHasher>());
        let tree = overlapped.fixture.tree.read().await;
        assert_eq!(tree.get_root(), first_end_root);
        assert_eq!(tree.get_leaf_value(0), overlapped.item.new_user_leaf_hash);
        Ok(())
    }
}
