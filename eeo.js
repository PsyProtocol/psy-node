processor_log:
```
                    ],
                },
            ),
            user_tree_root: QHashOut(
                HashOut {
                    elements: [
                        16463394126558395459,
                        12818610997234032270,
                        2968763245313636978,
                        15445927884703223427,
                    ],
                },
            ),
            withdrawal_tree_root: QHashOut(
                HashOut {
                    elements: [
                        16463394126558395459,
                        12818610997234032270,
                        2968763245313636978,
                        15445927884703223427,
                    ],
                },
            ),
            user_registration_tree_root: QHashOut(
                HashOut {
                    elements: [
                        16463394126558395459,
                        12818610997234032270,
                        2968763245313636978,
                        15445927884703223427,
                    ],
                },
            ),
        },
        stats: PQEDCheckpointLeafStats {
            fees_collected: 0,
            user_ops_processed: 0,
            total_transactions: 0,
            slots_modified: 0,
            pm_jobs_completed: PPMJobsCompletedStats {
                deploy_contracts_completed: 0,
                register_users_completed: 0,
                gutas_completed: 0,
            },
            block_time: 1764248609350,
            random_seed: QHashOut(
                HashOut {
                    elements: [
                        1,
                        2,
                        3,
                        4,
                    ],
                },
            ),
            pm_rewards_commitment: PPMRewardCommitment {
                register_users_root: QHashOut(
                    HashOut {
                        elements: [
                            0,
                            0,
                            0,
                            0,
                        ],
                    },
                ),
                gutas_root: QHashOut(
                    HashOut {
                        elements: [
                            0,
                            0,
                            0,
                            0,
                        ],
                    },
                ),
                deploy_contracts_root: QHashOut(
                    HashOut {
                        elements: [
                            0,
                            0,
                            0,
                            0,
                        ],
                    },
                ),
            },
            da_challenges_claimed: [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        },
    },
}
2025-11-29T12:39:46.502817Z  INFO psy_node_common/src/backup/checkpoint_tree/manager.rs:285: Syncing Checkpoint Manager. Target: 0. ReqStart: 0. Local: [0, 0)
2025-11-29T12:39:46.502841Z  WARN psy_node_common/src/backup/checkpoint_tree/manager.rs:245: Hard reset of Checkpoint Backup Manager at ID 0
2025-11-29T12:39:46.508513Z  INFO psy_node_common/src/coordinator/processor/db.rs:359: Applying genesis block setup data to coordinator processor database...
2025-11-29T12:39:46.514879Z  INFO psy_node_common/src/coordinator/processor/db.rs:362: Genesis block setup data applied to coordinator processor database.
2025-11-29T12:39:46.519133Z  INFO psy_node_common/src/coordinator/processor/db.rs:833: [COORDINATOR] Started with checkpoint ID: 0, unique pending ID: 0
2025-11-29T12:39:46.519179Z  INFO psy_node_common/src/coordinator/processor/db.rs:772: ======== Coordinator Processor State ========
[CORE_VITALS]
Last Committed Checkpoint ID: 0
Next Checkpoint ID: 1
Unique Pending ID: 0
Gatherer Unique Pending ID: 1
Checkpoint Root Hash: f74b0e463f982291c018afebd93a45f113cf3d1fbad7c5748fa0aa342b04aabc
[/CORE_VITALS]

[IDS]
CoordinatorProcessorIdState {
    realm_identifier: QRealmIdentifier {
        realm_id: 0,
        realm_sub_id: 0,
    },
    realm_id_u64: 0,
    realm_sub_id_u64: 0,
    checkpoint_id: 0,
    next_checkpoint_id: 1,
    unique_pending_id: 0,
    proc_checkpoint_unique_id: 0,
    gathering_unique_pending_id: 1,
    gathering_proc_checkpoint_unique_id: 110749009306944161857810156020120216205,
}
[/IDS]

[LAST_COMMITTED]
CoordinatorProcessorLastCommittedState {
    l2_state: QEDL2BlockState {
        checkpoint_id: 0,
        next_add_withdrawal_id: 0,
        next_process_withdrawal_id: 0,
        next_deposit_id: 0,
        total_deposits_claimed_epoch: 0,
        next_user_id: 0,
        end_balance: 0,
        next_contract_id: 0,
    },
    checkpoint_leaf_stats: PQEDCheckpointLeafStats {
        fees_collected: 0,
        user_ops_processed: 0,
        total_transactions: 0,
        slots_modified: 0,
        pm_jobs_completed: PPMJobsCompletedStats {
            deploy_contracts_completed: 0,
            register_users_completed: 0,
            gutas_completed: 0,
        },
        block_time: 1764248609350,
        random_seed: QHashOut(
            HashOut {
                elements: [
                    1,
                    2,
                    3,
                    4,
                ],
            },
        ),
        pm_rewards_commitment: PPMRewardCommitment {
            register_users_root: QHashOut(
                HashOut {
                    elements: [
                        0,
                        0,
                        0,
                        0,
                    ],
                },
            ),
            gutas_root: QHashOut(
                HashOut {
                    elements: [
                        0,
                        0,
                        0,
                        0,
                    ],
                },
            ),
            deploy_contracts_root: QHashOut(
                HashOut {
                    elements: [
                        0,
                        0,
                        0,
                        0,
                    ],
                },
            ),
        },
        da_challenges_claimed: [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    },
    checkpoint_leaf: PQEDCheckpointLeaf {
        global_chain_root: QHashOut(
            HashOut {
                elements: [
                    11618985594767661937,
                    2102957719162571832,
                    4877561579681668718,
                    8727826184444592850,
                ],
            },
        ),
        stats: PQEDCheckpointLeafStats {
            fees_collected: 0,
            user_ops_processed: 0,
            total_transactions: 0,
            slots_modified: 0,
            pm_jobs_completed: PPMJobsCompletedStats {
                deploy_contracts_completed: 0,
                register_users_completed: 0,
                gutas_completed: 0,
            },
            block_time: 1764248609350,
            random_seed: QHashOut(
                HashOut {
                    elements: [
                        1,
                        2,
                        3,
                        4,
                    ],
                },
            ),
            pm_rewards_commitment: PPMRewardCommitment {
                register_users_root: QHashOut(
                    HashOut {
                        elements: [
                            0,
                            0,
                            0,
                            0,
                        ],
                    },
                ),
                gutas_root: QHashOut(
                    HashOut {
                        elements: [
                            0,
                            0,
                            0,
                            0,
                        ],
                    },
                ),
                deploy_contracts_root: QHashOut(
                    HashOut {
                        elements: [
                            0,
                            0,
                            0,
                            0,
                        ],
                    },
                ),
            },
            da_challenges_claimed: [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        },
    },
    checkpoint_state_roots: PQEDCheckpointGlobalStateRoots {
        contract_tree_root: QHashOut(
            HashOut {
                elements: [
                    3896366420105793420,
                    17410332186442776169,
                    7329967984378645716,
                    6310665049578686403,
                ],
            },
        ),
        deposit_tree_root: QHashOut(
            HashOut {
                elements: [
                    16463394126558395459,
                    12818610997234032270,
                    2968763245313636978,
                    15445927884703223427,
                ],
            },
        ),
        user_tree_root: QHashOut(
            HashOut {
                elements: [
                    16463394126558395459,
                    12818610997234032270,
                    2968763245313636978,
                    15445927884703223427,
                ],
            },
        ),
        withdrawal_tree_root: QHashOut(
            HashOut {
                elements: [
                    16463394126558395459,
                    12818610997234032270,
                    2968763245313636978,
                    15445927884703223427,
                ],
            },
        ),
        user_registration_tree_root: QHashOut(
            HashOut {
                elements: [
                    16463394126558395459,
                    12818610997234032270,
                    2968763245313636978,
                    15445927884703223427,
                ],
            },
        ),
    },
    checkpoint_state_transition: CheckpointStateHashTransition {
        old_checkpoint_tree_root: QHashOut(
            HashOut {
                elements: [
                    10458088682233416695,
                    17385366644170102976,
                    8414368673199673107,
                    13594683008784965775,
                ],
            },
        ),
        new_checkpoint_tree_root: QHashOut(
            HashOut {
                elements: [
                    10458088682233416695,
                    17385366644170102976,
                    8414368673199673107,
                    13594683008784965775,
                ],
            },
        ),
        old_checkpoint_leaf_hash: QHashOut(
            HashOut {
                elements: [
                    8426879675417334206,
                    2436166045420849577,
                    16809635919563306144,
                    5309346835249992620,
                ],
            },
        ),
        new_checkpoint_leaf_hash: QHashOut(
            HashOut {
                elements: [
                    8426879675417334206,
                    2436166045420849577,
                    16809635919563306144,
                    5309346835249992620,
                ],
            },
        ),
    },
    checkpoint_root: QHashOut(
        HashOut {
            elements: [
                10458088682233416695,
                17385366644170102976,
                8414368673199673107,
                13594683008784965775,
            ],
        },
    ),
    checkpoint_leaf_hash: QHashOut(
        HashOut {
            elements: [
                8426879675417334206,
                2436166045420849577,
                16809635919563306144,
                5309346835249992620,
            ],
        },
    ),
}
[/LAST_COMMITTED]
=============================================
2025-11-29T12:39:46.519256Z  INFO psy_node_common/src/coordinator/processor/core/startup.rs:100: intialized coordinator processor database, building gatherers...
2025-11-29T12:39:46.519267Z  INFO psy_node_common/src/coordinator/processor/create.rs:225: Starting coordinator processor...
2025-11-29T12:39:46.519356Z  INFO psy_node_common/src/coordinator/processor/core/process_block.rs:361: Starting to process new coordinator block with checkpoint_id = 1...
2025-11-29T12:39:46.519492Z  INFO psy_node_common/src/queue/gatherer.rs:304: GATHERER_3: Starting new gathering phase.
2025-11-29T12:39:46.519595Z  INFO psy_node_common/src/queue/gatherer.rs:304: GATHERER_1: Starting new gathering phase.
2025-11-29T12:39:46.519630Z  INFO psy_node_common/src/queue/gatherer.rs:304: GATHERER_2: Starting new gathering phase.
2025-11-29T12:39:46.521971Z  INFO psy_node_common/src/queue/gatherer.rs:312: GATHERER_2: Interrupted by Processor. Preparing to hand over
2025-11-29T12:39:46.521977Z  INFO psy_node_common/src/queue/gatherer.rs:315: GATHERER_2: Current unique ID: 89398461500291837005716241473376363394, is_active: true
2025-11-29T12:39:46.521977Z  INFO psy_node_common/src/queue/gatherer.rs:312: GATHERER_1: Interrupted by Processor. Preparing to hand over
2025-11-29T12:39:46.521981Z  INFO psy_node_common/src/queue/gatherer.rs:315: GATHERER_1: Current unique ID: 89398461500291837005716241473376363394, is_active: true
2025-11-29T12:39:46.522406Z  INFO psy_node_common/src/queue/gatherer.rs:318: GATHERER_1: Finalized output prepared, sending to processor.
2025-11-29T12:39:46.522410Z  INFO psy_node_common/src/queue/gatherer.rs:322: GATHERER_1: Successfully handed over data to processor.
2025-11-29T12:39:46.522411Z  INFO psy_node_common/src/queue/gatherer.rs:352: GATHERER_1: Handoff complete. Cycle restarting.
2025-11-29T12:39:46.522549Z  INFO psy_node_common/src/queue/gatherer.rs:304: GATHERER_1: Starting new gathering phase.
2025-11-29T12:39:46.522706Z  INFO psy_node_common/src/queue/gatherer.rs:318: GATHERER_2: Finalized output prepared, sending to processor.
2025-11-29T12:39:46.522708Z  INFO psy_node_common/src/queue/gatherer.rs:322: GATHERER_2: Successfully handed over data to processor.
2025-11-29T12:39:46.522709Z  INFO psy_node_common/src/queue/gatherer.rs:352: GATHERER_2: Handoff complete. Cycle restarting.
2025-11-29T12:39:46.522840Z  INFO psy_node_common/src/queue/gatherer.rs:304: GATHERER_2: Starting new gathering phase.
2025-11-29T12:39:46.533321Z  INFO psy_node_common/src/queue/gatherer.rs:312: GATHERER_3: Interrupted by Processor. Preparing to hand over
2025-11-29T12:39:46.533326Z  INFO psy_node_common/src/queue/gatherer.rs:315: GATHERER_3: Current unique ID: 89398461500291837005716241473376363394, is_active: true
2025-11-29T12:39:46.533339Z  INFO psy_node_common/src/coordinator/processor/gatherers/coordinator_guta_update_gatherer.rs:365: Committing GUTA updates gatherer changes for pending id 1, committing root QHashOut(HashOut { elements: [16463394126558395459, 12818610997234032270, 2968763245313636978, 15445927884703223427] })
2025-11-29T12:39:46.533344Z  INFO psy_node_common/src/coordinator/processor/gatherers/coordinator_guta_update_gatherer.rs:391: Finalizing GUTA updates gatherer for pending id 1, start root QHashOut(HashOut { elements: [16463394126558395459, 12818610997234032270, 2968763245313636978, 15445927884703223427] }), end root QHashOut(HashOut { elements: [16463394126558395459, 12818610997234032270, 2968763245313636978, 15445927884703223427] })
2025-11-29T12:39:46.533746Z  INFO psy_node_common/src/coordinator/processor/gatherers/coordinator_guta_update_gatherer.rs:425: Finalized GUTA updates gatherer for pending id 1, total jobs created: 1
2025-11-29T12:39:46.533757Z  INFO psy_node_common/src/coordinator/processor/gatherers/coordinator_guta_update_gatherer.rs:458: GUTA updates gatherer for pending id 1 finalized successfully.
2025-11-29T12:39:46.533778Z  INFO psy_node_common/src/queue/gatherer.rs:318: GATHERER_3: Finalized output prepared, sending to processor.
2025-11-29T12:39:46.533781Z  INFO psy_node_common/src/queue/gatherer.rs:322: GATHERER_3: Successfully handed over data to processor.
2025-11-29T12:39:46.533782Z  INFO psy_node_common/src/queue/gatherer.rs:352: GATHERER_3: Handoff complete. Cycle restarting.
2025-11-29T12:39:46.533801Z  INFO psy_node_common/src/coordinator/processor/core/process_block.rs:100: No changes detected in GUTA, Register User, and Deploy Contract jobs.
2025-11-29T12:39:46.533803Z  INFO psy_node_common/src/coordinator/processor/core/process_block.rs:372: No jobs to process in this block, but proceeding to create empty checkpoint state transition.
Publishing worker jobs...
guta_jobs: [[PsyProvingJobMetadataWithJobId { job_id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1, circuit_type: GUTANoChange, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }, metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [11063847677076141211, 14529389044803656749, 2534641829950085436, 11380629727529504877] }), reward_tree_node_index: 0, reward_tree_node_level: 2, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] } }]]
register_user_jobs: [[PsyProvingJobMetadataWithJobId { job_id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }, metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [17194422574323743050, 1802933447085919836, 18386616461608425737, 15867607693607706886] }), reward_tree_node_index: 0, reward_tree_node_level: 0, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] } }]]
deploy_contract_jobs: [[PsyProvingJobMetadataWithJobId { job_id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1, circuit_type: DummyBatchDeployContractsAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }, metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [14349279882637562689, 4472754708323214162, 2322540293576037537, 12982351782103103972] }), reward_tree_node_index: 0, reward_tree_node_level: 0, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] } }]]
get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: 110749009306944161857810156020120216205
Publishing 1 jobs at level 0
2025-11-29T12:39:46.533926Z  INFO psy_node_common/src/queue/gatherer.rs:304: GATHERER_3: Starting new gathering phase.
Publishing 1 items to subject: test123.pq.r0.rs0.u53517bbbbf4f08e6787730e5404ce28d.qt40.g0
Publishing 1 jobs at level 0
Publishing 1 items to subject: test123.pq.r0.rs0.u53517bbbbf4f08e6787730e5404ce28d.qt40.g0
Publishing 1 jobs at level 0
Publishing 1 items to subject: test123.pq.r0.rs0.u53517bbbbf4f08e6787730e5404ce28d.qt40.g0
get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: 110749009306944161857810156020120216205
Publishing to subject: test123.pq.r0.rs0.u53517bbbbf4f08e6787730e5404ce28d.qt40.g0
2025-11-29T12:39:46.537040Z  INFO psy_node_common/src/coordinator/processor/core/process_block.rs:392: Waiting for first level of jobs to complete...
get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: 110749009306944161857810156020120216205
waiting until all jobs complete for subject: test123.pq.r0.rs0.u53517bbbbf4f08e6787730e5404ce28d.qt40.g0, durable_name: test123_pq_r0_rs0_u53517bbbbf4f08e6787730e5404ce28d_qt40_g0
2025-11-29T12:39:58.203296Z  INFO psy_node_common/src/coordinator/processor/core/process_block.rs:395: First level of jobs completed!
Publishing worker jobs...
guta_jobs: [[PsyProvingJobMetadataWithJobId { job_id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1, circuit_type: GUTANoChange, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }, metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [11063847677076141211, 14529389044803656749, 2534641829950085436, 11380629727529504877] }), reward_tree_node_index: 0, reward_tree_node_level: 2, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] } }]]
register_user_jobs: [[PsyProvingJobMetadataWithJobId { job_id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }, metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [17194422574323743050, 1802933447085919836, 18386616461608425737, 15867607693607706886] }), reward_tree_node_index: 0, reward_tree_node_level: 0, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] } }]]
deploy_contract_jobs: [[PsyProvingJobMetadataWithJobId { job_id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1, circuit_type: DummyBatchDeployContractsAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }, metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [14349279882637562689, 4472754708323214162, 2322540293576037537, 12982351782103103972] }), reward_tree_node_index: 0, reward_tree_node_level: 0, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] } }]]
get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: 110749009306944161857810156020120216205
2025-11-29T12:39:58.203336Z  INFO psy_node_common/src/coordinator/processor/core/process_block.rs:408: Pre-agg jobs completed!
get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: 110749009306944161857810156020120216205
Publishing job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1, circuit_type: AggUserRegisterDeployContractsGUTA, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }
self.db.ids.proc_checkpoint_unique_id: 110749009306944161857810156020120216205
Publishing to subject: test123.pq.r0.rs0.u53517bbbbf4f08e6787730e5404ce28d.qt40.g0
waiting until all jobs complete for subject: test123.pq.r0.rs0.u53517bbbbf4f08e6787730e5404ce28d.qt40.g0, durable_name: test123_pq_r0_rs0_u53517bbbbf4f08e6787730e5404ce28d_qt40_g0
2025-11-29T12:39:58.708421Z  INFO psy_node_common/src/backup/output/coordinator_output_builder.rs:252: last committed checkpoint leaf: PQEDCheckpointLeaf { global_chain_root: QHashOut(HashOut { elements: [11618985594767661937, 2102957719162571832, 4877561579681668718, 8727826184444592850] }), stats: PQEDCheckpointLeafStats { fees_collected: 0, user_ops_processed: 0, total_transactions: 0, slots_modified: 0, pm_jobs_completed: PPMJobsCompletedStats { deploy_contracts_completed: 0, register_users_completed: 0, gutas_completed: 0 }, block_time: 1764248609350, random_seed: QHashOut(HashOut { elements: [1, 2, 3, 4] }), pm_rewards_commitment: PPMRewardCommitment { register_users_root: QHashOut(HashOut { elements: [0, 0, 0, 0] }), gutas_root: QHashOut(HashOut { elements: [0, 0, 0, 0] }), deploy_contracts_root: QHashOut(HashOut { elements: [0, 0, 0, 0] }) }, da_challenges_claimed: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] } }
2025-11-29T12:39:58.708436Z  INFO psy_node_common/src/backup/output/coordinator_output_builder.rs:253: last committed checkpoint leaf hash: QHashOut(HashOut { elements: [8426879675417334206, 2436166045420849577, 16809635919563306144, 5309346835249992620] }) (be9135d26a4af274a9892d671c00cf21a0b437bdced247e9ac936b08d196ae49)
2025-11-29T12:39:58.708451Z  INFO psy_node_common/src/backup/output/coordinator_output_builder.rs:254: last committed checkpoint leaf hash (computed) : QHashOut(HashOut { elements: [8426879675417334206, 2436166045420849577, 16809635919563306144, 5309346835249992620] }) (be9135d26a4af274a9892d671c00cf21a0b437bdced247e9ac936b08d196ae49)
2025-11-29T12:39:58.708462Z  INFO psy_node_common/src/backup/output/coordinator_output_builder.rs:255: last committed checkpoint leaf hash (computed) : QHashOut(HashOut { elements: [8426879675417334206, 2436166045420849577, 16809635919563306144, 5309346835249992620] }) (be9135d26a4af274a9892d671c00cf21a0b437bdced247e9ac936b08d196ae49)
2025-11-29T12:39:58.708463Z  INFO psy_node_common/src/backup/output/coordinator_output_builder.rs:256: last committed global_chain_root: QHashOut(HashOut { elements: [11618985594767661937, 2102957719162571832, 4877561579681668718, 8727826184444592850] }) (71db81a2d6ed3ea138cc5954e7342f1d6ede040f6a94b043d2422c39ac771f79)
2025-11-29T12:39:58.708474Z  INFO psy_node_common/src/backup/output/coordinator_output_builder.rs:289: New checkpoint leaf hash: QHashOut(HashOut { elements: [2395959416063658952, 1728826371054501077, 599803573734259331, 5238054016548000777] }) (c80bba0265284021d5fc07bd6c06fe1783ba70232cee520809d4a62a604eb148)
circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint: QHashOut(HashOut { elements: [8653412727247185755, 6404210200288153421, 15842295031778658844, 851668705768035544] })
get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: 110749009306944161857810156020120216205
Publishing job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1, circuit_type: GenerateRollupStateTransitionProof, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }
self.db.ids.proc_checkpoint_unique_id: 110749009306944161857810156020120216205
Publishing to subject: test123.pq.r0.rs0.u53517bbbbf4f08e6787730e5404ce28d.qt40.g0
waiting until all jobs complete for subject: test123.pq.r0.rs0.u53517bbbbf4f08e6787730e5404ce28d.qt40.g0, durable_name: test123_pq_r0_rs0_u53517bbbbf4f08e6787730e5404ce28d_qt40_g0
2025-11-29T12:39:59.727883Z  INFO psy_node_common/src/coordinator/processor/db.rs:772: ======== Coordinator Processor State ========
[CORE_VITALS]
Last Committed Checkpoint ID: 1
Next Checkpoint ID: 2
Unique Pending ID: 1
Gatherer Unique Pending ID: 2
Checkpoint Root Hash: ce5cb757203a4d7e9961a5442477b5ead93cbd0423c215d1022e8d42104dc068
[/CORE_VITALS]

[IDS]
CoordinatorProcessorIdState {
    realm_identifier: QRealmIdentifier {
        realm_id: 0,
        realm_sub_id: 0,
    },
    realm_id_u64: 0,
    realm_sub_id_u64: 0,
    checkpoint_id: 1,
    next_checkpoint_id: 2,
    unique_pending_id: 1,
    proc_checkpoint_unique_id: 110749009306944161857810156020120216205,
    gathering_unique_pending_id: 2,
    gathering_proc_checkpoint_unique_id: 89398461500291837005716241473376363394,
}
[/IDS]

[LAST_COMMITTED]
CoordinatorProcessorLastCommittedState {
    l2_state: QEDL2BlockState {
        checkpoint_id: 1,
        next_add_withdrawal_id: 0,
        next_process_withdrawal_id: 0,
        next_deposit_id: 0,
        total_deposits_claimed_epoch: 0,
        next_user_id: 0,
        end_balance: 0,
        next_contract_id: 0,
    },
    checkpoint_leaf_stats: PQEDCheckpointLeafStats {
        fees_collected: 0,
        user_ops_processed: 0,
        total_transactions: 0,
        slots_modified: 0,
        pm_jobs_completed: PPMJobsCompletedStats {
            deploy_contracts_completed: 1,
            register_users_completed: 1,
            gutas_completed: 1,
        },
        block_time: 1764419999718,
        random_seed: QHashOut(
            HashOut {
                elements: [
                    686191062320707623,
                    11979345616392276282,
                    6719388120155154949,
                    4500086781896954073,
                ],
            },
        ),
        pm_rewards_commitment: PPMRewardCommitment {
            register_users_root: QHashOut(
                HashOut {
                    elements: [
                        6986357916869724019,
                        6327731205419157574,
                        15719055104599833021,
                        4571754155461516237,
                    ],
                },
            ),
            gutas_root: QHashOut(
                HashOut {
                    elements: [
                        6986357916869724019,
                        6327731205419157574,
                        15719055104599833021,
                        4571754155461516237,
                    ],
                },
            ),
            deploy_contracts_root: QHashOut(
                HashOut {
                    elements: [
                        6986357916869724019,
                        6327731205419157574,
                        15719055104599833021,
                        4571754155461516237,
                    ],
                },
            ),
        },
        da_challenges_claimed: [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    },
    checkpoint_leaf: PQEDCheckpointLeaf {
        global_chain_root: QHashOut(
            HashOut {
                elements: [
                    11618985594767661937,
                    2102957719162571832,
                    4877561579681668718,
                    8727826184444592850,
                ],
            },
        ),
        stats: PQEDCheckpointLeafStats {
            fees_collected: 0,
            user_ops_processed: 0,
            total_transactions: 0,
            slots_modified: 0,
            pm_jobs_completed: PPMJobsCompletedStats {
                deploy_contracts_completed: 1,
                register_users_completed: 1,
                gutas_completed: 1,
            },
            block_time: 1764419999718,
            random_seed: QHashOut(
                HashOut {
                    elements: [
                        686191062320707623,
                        11979345616392276282,
                        6719388120155154949,
                        4500086781896954073,
                    ],
                },
            ),
            pm_rewards_commitment: PPMRewardCommitment {
                register_users_root: QHashOut(
                    HashOut {
                        elements: [
                            6986357916869724019,
                            6327731205419157574,
                            15719055104599833021,
                            4571754155461516237,
                        ],
                    },
                ),
                gutas_root: QHashOut(
                    HashOut {
                        elements: [
                            6986357916869724019,
                            6327731205419157574,
                            15719055104599833021,
                            4571754155461516237,
                        ],
                    },
                ),
                deploy_contracts_root: QHashOut(
                    HashOut {
                        elements: [
                            6986357916869724019,
                            6327731205419157574,
                            15719055104599833021,
                            4571754155461516237,
                        ],
                    },
                ),
            },
            da_challenges_claimed: [
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ],
        },
    },
    checkpoint_state_roots: PQEDCheckpointGlobalStateRoots {
        contract_tree_root: QHashOut(
            HashOut {
                elements: [
                    3896366420105793420,
                    17410332186442776169,
                    7329967984378645716,
                    6310665049578686403,
                ],
            },
        ),
        deposit_tree_root: QHashOut(
            HashOut {
                elements: [
                    16463394126558395459,
                    12818610997234032270,
                    2968763245313636978,
                    15445927884703223427,
                ],
            },
        ),
        user_tree_root: QHashOut(
            HashOut {
                elements: [
                    16463394126558395459,
                    12818610997234032270,
                    2968763245313636978,
                    15445927884703223427,
                ],
            },
        ),
        withdrawal_tree_root: QHashOut(
            HashOut {
                elements: [
                    16463394126558395459,
                    12818610997234032270,
                    2968763245313636978,
                    15445927884703223427,
                ],
            },
        ),
        user_registration_tree_root: QHashOut(
            HashOut {
                elements: [
                    16463394126558395459,
                    12818610997234032270,
                    2968763245313636978,
                    15445927884703223427,
                ],
            },
        ),
    },
    checkpoint_state_transition: CheckpointStateHashTransition {
        old_checkpoint_tree_root: QHashOut(
            HashOut {
                elements: [
                    10458088682233416695,
                    17385366644170102976,
                    8414368673199673107,
                    13594683008784965775,
                ],
            },
        ),
        new_checkpoint_tree_root: QHashOut(
            HashOut {
                elements: [
                    9100994332570639566,
                    16912554973313982873,
                    15066161584097017049,
                    7548117707704315394,
                ],
            },
        ),
        old_checkpoint_leaf_hash: QHashOut(
            HashOut {
                elements: [
                    8426879675417334206,
                    2436166045420849577,
                    16809635919563306144,
                    5309346835249992620,
                ],
            },
        ),
        new_checkpoint_leaf_hash: QHashOut(
            HashOut {
                elements: [
                    8953239826435340432,
                    720574180395379416,
                    8977861569436724405,
                    9890825682981539431,
                ],
            },
        ),
    },
    checkpoint_root: QHashOut(
        HashOut {
            elements: [
                9100994332570639566,
                16912554973313982873,
                15066161584097017049,
                7548117707704315394,
            ],
        },
    ),
    checkpoint_leaf_hash: QHashOut(
        HashOut {
            elements: [
                8953239826435340432,
                720574180395379416,
                8977861569436724405,
                9890825682981539431,
            ],
        },
    ),
}
[/LAST_COMMITTED]
=============================================
2025-11-29T12:39:59.728198Z  INFO psy_node_common/src/coordinator/processor/core/runner.rs:57: Generated block in 13208ms, sleeping for 0ms
2025-11-29T12:39:59.729374Z  INFO psy_node_common/src/coordinator/processor/core/process_block.rs:361: Starting to process new coordinator block with checkpoint_id = 2...
2025-11-29T12:39:59.734519Z  INFO psy_node_common/src/queue/gatherer.rs:312: GATHERER_3: Interrupted by Processor. Preparing to hand over
2025-11-29T12:39:59.734529Z  INFO psy_node_common/src/queue/gatherer.rs:312: GATHERER_2: Interrupted by Processor. Preparing to hand over
2025-11-29T12:39:59.734546Z  INFO psy_node_common/src/queue/gatherer.rs:315: GATHERER_2: Current unique ID: 47620563628555662981549520815503724240, is_active: true
2025-11-29T12:39:59.734538Z  INFO psy_node_common/src/queue/gatherer.rs:315: GATHERER_3: Current unique ID: 47620563628555662981549520815503724240, is_active: true
2025-11-29T12:39:59.734561Z  INFO psy_node_common/src/coordinator/processor/gatherers/coordinator_guta_update_gatherer.rs:365: Committing GUTA updates gatherer changes for pending id 2, committing root QHashOut(HashOut { elements: [16463394126558395459, 12818610997234032270, 2968763245313636978, 15445927884703223427] })
2025-11-29T12:39:59.734574Z  INFO psy_node_common/src/coordinator/processor/gatherers/coordinator_guta_update_gatherer.rs:391: Finalizing GUTA updates gatherer for pending id 2, start root QHashOut(HashOut { elements: [16463394126558395459, 12818610997234032270, 2968763245313636978, 15445927884703223427] }), end root QHashOut(HashOut { elements: [16463394126558395459, 12818610997234032270, 2968763245313636978, 15445927884703223427] })
2025-11-29T12:39:59.734538Z  INFO psy_node_common/src/queue/gatherer.rs:312: GATHERER_1: Interrupted by Processor. Preparing to hand over
2025-11-29T12:39:59.734698Z  INFO psy_node_common/src/queue/gatherer.rs:315: GATHERER_1: Current unique ID: 47620563628555662981549520815503724240, is_active: true
2025-11-29T12:39:59.735169Z  INFO psy_node_common/src/coordinator/processor/gatherers/coordinator_guta_update_gatherer.rs:425: Finalized GUTA updates gatherer for pending id 2, total jobs created: 1
2025-11-29T12:39:59.735177Z  INFO psy_node_common/src/coordinator/processor/gatherers/coordinator_guta_update_gatherer.rs:458: GUTA updates gatherer for pending id 2 finalized successfully.
2025-11-29T12:39:59.735203Z  INFO psy_node_common/src/queue/gatherer.rs:318: GATHERER_3: Finalized output prepared, sending to processor.
2025-11-29T12:39:59.735207Z  INFO psy_node_common/src/queue/gatherer.rs:322: GATHERER_3: Successfully handed over data to processor.
2025-11-29T12:39:59.735209Z  INFO psy_node_common/src/queue/gatherer.rs:352: GATHERER_3: Handoff complete. Cycle restarting.
2025-11-29T12:39:59.735465Z  INFO psy_node_common/src/queue/gatherer.rs:318: GATHERER_1: Finalized output prepared, sending to processor.
2025-11-29T12:39:59.735475Z  INFO psy_node_common/src/queue/gatherer.rs:322: GATHERER_1: Successfully handed over data to processor.
2025-11-29T12:39:59.735478Z  INFO psy_node_common/src/queue/gatherer.rs:352: GATHERER_1: Handoff complete. Cycle restarting.
2025-11-29T12:39:59.735608Z  INFO psy_node_common/src/queue/gatherer.rs:318: GATHERER_2: Finalized output prepared, sending to processor.
2025-11-29T12:39:59.735615Z  INFO psy_node_common/src/queue/gatherer.rs:304: GATHERER_3: Starting new gathering phase.
2025-11-29T12:39:59.735616Z  INFO psy_node_common/src/queue/gatherer.rs:322: GATHERER_2: Successfully handed over data to processor.
2025-11-29T12:39:59.735622Z  INFO psy_node_common/src/queue/gatherer.rs:352: GATHERER_2: Handoff complete. Cycle restarting.
2025-11-29T12:39:59.735656Z  INFO psy_node_common/src/coordinator/processor/core/process_block.rs:100: No changes detected in GUTA, Register User, and Deploy Contract jobs.
2025-11-29T12:39:59.735662Z  INFO psy_node_common/src/coordinator/processor/core/process_block.rs:372: No jobs to process in this block, but proceeding to create empty checkpoint state transition.
Publishing worker jobs...
guta_jobs: [[PsyProvingJobMetadataWithJobId { job_id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: GUTANoChange, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }, metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [1525476321784204972, 5647927274577760844, 9460619120989556234, 17956033172403446845] }), reward_tree_node_index: 0, reward_tree_node_level: 2, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] } }]]
register_user_jobs: [[PsyProvingJobMetadataWithJobId { job_id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }, metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [17194422574323743050, 1802933447085919836, 18386616461608425737, 15867607693607706886] }), reward_tree_node_index: 0, reward_tree_node_level: 0, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] } }]]
deploy_contract_jobs: [[PsyProvingJobMetadataWithJobId { job_id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: DummyBatchDeployContractsAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }, metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [14349279882637562689, 4472754708323214162, 2322540293576037537, 12982351782103103972] }), reward_tree_node_index: 0, reward_tree_node_level: 0, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] } }]]
get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: 89398461500291837005716241473376363394
Publishing 1 jobs at level 0
2025-11-29T12:39:59.736002Z  INFO psy_node_common/src/queue/gatherer.rs:304: GATHERER_1: Starting new gathering phase.
Publishing 1 items to subject: test123.pq.r0.rs0.u434184743b55a9c85d7d014acb142382.qt40.g0
Publishing 1 jobs at level 0
2025-11-29T12:39:59.736204Z  INFO psy_node_common/src/queue/gatherer.rs:304: GATHERER_2: Starting new gathering phase.
Publishing 1 items to subject: test123.pq.r0.rs0.u434184743b55a9c85d7d014acb142382.qt40.g0
Publishing 1 jobs at level 0
Publishing 1 items to subject: test123.pq.r0.rs0.u434184743b55a9c85d7d014acb142382.qt40.g0
2025-11-29T12:39:59.739348Z  INFO psy_node_common/src/coordinator/processor/core/process_block.rs:392: Waiting for first level of jobs to complete...
get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: 89398461500291837005716241473376363394
waiting until all jobs complete for subject: test123.pq.r0.rs0.u434184743b55a9c85d7d014acb142382.qt40.g0, durable_name: test123_pq_r0_rs0_u434184743b55a9c85d7d014acb142382_qt40_g0
2025-11-29T12:40:00.745429Z  INFO psy_node_common/src/coordinator/processor/core/process_block.rs:395: First level of jobs completed!
Publishing worker jobs...
guta_jobs: [[PsyProvingJobMetadataWithJobId { job_id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: GUTANoChange, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }, metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [1525476321784204972, 5647927274577760844, 9460619120989556234, 17956033172403446845] }), reward_tree_node_index: 0, reward_tree_node_level: 2, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] } }]]
register_user_jobs: [[PsyProvingJobMetadataWithJobId { job_id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }, metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [17194422574323743050, 1802933447085919836, 18386616461608425737, 15867607693607706886] }), reward_tree_node_index: 0, reward_tree_node_level: 0, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] } }]]
deploy_contract_jobs: [[PsyProvingJobMetadataWithJobId { job_id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: DummyBatchDeployContractsAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }, metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [14349279882637562689, 4472754708323214162, 2322540293576037537, 12982351782103103972] }), reward_tree_node_index: 0, reward_tree_node_level: 0, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] } }]]
get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: 89398461500291837005716241473376363394
2025-11-29T12:40:00.745481Z  INFO psy_node_common/src/coordinator/processor/core/process_block.rs:408: Pre-agg jobs completed!
get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: 89398461500291837005716241473376363394
Publishing job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: AggUserRegisterDeployContractsGUTA, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }
self.db.ids.proc_checkpoint_unique_id: 89398461500291837005716241473376363394
Publishing to subject: test123.pq.r0.rs0.u434184743b55a9c85d7d014acb142382.qt40.g0
waiting until all jobs complete for subject: test123.pq.r0.rs0.u434184743b55a9c85d7d014acb142382.qt40.g0, durable_name: test123_pq_r0_rs0_u434184743b55a9c85d7d014acb142382_qt40_g0
2025-11-29T12:40:01.756639Z  INFO psy_node_common/src/backup/output/coordinator_output_builder.rs:252: last committed checkpoint leaf: PQEDCheckpointLeaf { global_chain_root: QHashOut(HashOut { elements: [11618985594767661937, 2102957719162571832, 4877561579681668718, 8727826184444592850] }), stats: PQEDCheckpointLeafStats { fees_collected: 0, user_ops_processed: 0, total_transactions: 0, slots_modified: 0, pm_jobs_completed: PPMJobsCompletedStats { deploy_contracts_completed: 1, register_users_completed: 1, gutas_completed: 1 }, block_time: 1764419999718, random_seed: QHashOut(HashOut { elements: [686191062320707623, 11979345616392276282, 6719388120155154949, 4500086781896954073] }), pm_rewards_commitment: PPMRewardCommitment { register_users_root: QHashOut(HashOut { elements: [6986357916869724019, 6327731205419157574, 15719055104599833021, 4571754155461516237] }), gutas_root: QHashOut(HashOut { elements: [6986357916869724019, 6327731205419157574, 15719055104599833021, 4571754155461516237] }), deploy_contracts_root: QHashOut(HashOut { elements: [6986357916869724019, 6327731205419157574, 15719055104599833021, 4571754155461516237] }) }, da_challenges_claimed: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] } }
2025-11-29T12:40:01.756686Z  INFO psy_node_common/src/backup/output/coordinator_output_builder.rs:253: last committed checkpoint leaf hash: QHashOut(HashOut { elements: [8953239826435340432, 720574180395379416, 8977861569436724405, 9890825682981539431] }) (90f88e932f4c407cd8eac83866feff09b52ce8d887c5977c67ce6c098e454389)
2025-11-29T12:40:01.756765Z  INFO psy_node_common/src/backup/output/coordinator_output_builder.rs:254: last committed checkpoint leaf hash (computed) : QHashOut(HashOut { elements: [8953239826435340432, 720574180395379416, 8977861569436724405, 9890825682981539431] }) (90f88e932f4c407cd8eac83866feff09b52ce8d887c5977c67ce6c098e454389)
2025-11-29T12:40:01.756830Z  INFO psy_node_common/src/backup/output/coordinator_output_builder.rs:255: last committed checkpoint leaf hash (computed) : QHashOut(HashOut { elements: [8953239826435340432, 720574180395379416, 8977861569436724405, 9890825682981539431] }) (90f88e932f4c407cd8eac83866feff09b52ce8d887c5977c67ce6c098e454389)
2025-11-29T12:40:01.756838Z  INFO psy_node_common/src/backup/output/coordinator_output_builder.rs:256: last committed global_chain_root: QHashOut(HashOut { elements: [11618985594767661937, 2102957719162571832, 4877561579681668718, 8727826184444592850] }) (71db81a2d6ed3ea138cc5954e7342f1d6ede040f6a94b043d2422c39ac771f79)
2025-11-29T12:40:01.756893Z  INFO psy_node_common/src/backup/output/coordinator_output_builder.rs:289: New checkpoint leaf hash: QHashOut(HashOut { elements: [2004279990969456274, 17656812691955938781, 2200784788895839586, 8934214916406378754] }) (9256285c08a2d01bdd75a4f1979909f5623538f11ac28a1e0201668721b5fc7b)
circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint: QHashOut(HashOut { elements: [8653412727247185755, 6404210200288153421, 15842295031778658844, 851668705768035544] })
get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: 89398461500291837005716241473376363394
Publishing job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: GenerateRollupStateTransitionProof, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 }
self.db.ids.proc_checkpoint_unique_id: 89398461500291837005716241473376363394
Publishing to subject: test123.pq.r0.rs0.u434184743b55a9c85d7d014acb142382.qt40.g0
waiting until all jobs complete for subject: test123.pq.r0.rs0.u434184743b55a9c85d7d014acb142382.qt40.g0, durable_name: test123_pq_r0_rs0_u434184743b55a9c85d7d014acb142382_qt40_g0

```


worker_log:
```text

pub_test_hash: [8173636668400790300, 1563310953851325238, 3081518508325915930, 3522297658072428737] (1ceb227f3e976e71360bc99d07ffb1151acd8eb9c1c0c32ac1f098de0eb7e130)
96mcompress0m - 94mproved compress0m: 38;5;230m48;5;34m 174ms 0m
96mcompress0m - 94mproved compress0m: 38;5;230m48;5;34m 100ms 0m
🏛️ Checkpoint State Transition - got_public_inputs: [8173636668400790300, 1563310953851325238, 3081518508325915930, 3522297658072428737] (1ceb227f3e976e71360bc99d07ffb1151acd8eb9c1c0c32ac1f098de0eb7e130)
2m2025-11-29T12:39:59.419303Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m55:0m Proved job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1, circuit_type: GenerateRollupStateTransitionProof, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } in 639.881709ms, submitting proof to API
2m2025-11-29T12:39:59.431794Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m57:0m Submitted proof for job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1, circuit_type: GenerateRollupStateTransitionProof, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } to API URL hash: 687474703a2f2f3132372e302e302e313a313333370000000000000000000000
2m2025-11-29T12:39:59.746750Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m47:0m Fetched new job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: GUTANoChange, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } from API URL hash: [104, 116, 116, 112, 58, 47, 47, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 49, 51, 51, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
GUTANoChangeCircuit witness loaded: GUTANoChangeFullInput {
    checkpoint_tree_proof: MerkleProofCore {
        root: QHashOut(
            HashOut {
                elements: [
                    9100994332570639566,
                    16912554973313982873,
                    15066161584097017049,
                    7548117707704315394,
                ],
            },
        ),
        value: QHashOut(
            HashOut {
                elements: [
                    8953239826435340432,
                    720574180395379416,
                    8977861569436724405,
                    9890825682981539431,
                ],
            },
        ),
        index: 1,
        siblings: [
            QHashOut(
                HashOut {
                    elements: [
                        8426879675417334206,
                        2436166045420849577,
                        16809635919563306144,
                        5309346835249992620,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        4330397376401421145,
                        14124799381142128323,
                        8742572140681234676,
                        14345658006221440202,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        13121882728673923020,
                        10197653806804742863,
                        16037207047953124082,
                        2420399206709257475,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        7052649073129349210,
                        11107139769197583972,
                        5114845353783771231,
                        7453521209854829890,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        5860469655587923524,
                        10142584705005652295,
                        1620588827255328039,
                        17663938664361140288,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        16854358529591173550,
                        9704301947898025017,
                        13222045073939169687,
                        14989445859181028978,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        2675805695450374474,
                        6493392849121218307,
                        15972287940310989584,
                        5284431416427098307,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        16823738737355150819,
                        4366876208047374841,
                        1642083707956929713,
                        13216064879834397173,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        18334109492892739862,
                        10192437552951753306,
                        15211985613247588647,
                        3157981091968158131,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        4369129498500264270,
                        10758747855946482846,
                        3238306058428322199,
                        18226589090145367109,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        14769473886748754115,
                        10513963056908986963,
                        8105478726930894327,
                        14014796621245524545,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        10191288259157808067,
                        944536249556834531,
                        16268598854718968908,
                        2417244819673331317,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        17088215091100491041,
                        18086883194773274646,
                        10296247222913205474,
                        7017044080942280524,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        2985877902215057279,
                        14516746119572211305,
                        594952314256159992,
                        17038984393731825093,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        101510842507023404,
                        2267676083447667738,
                        18106248392660779137,
                        17680390044293740318,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        16662284396446084312,
                        7269926520507830029,
                        14791338760961128332,
                        7825163129638412009,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        12364052984629808614,
                        13066500727264825316,
                        6321076066274078148,
                        11393071566019822187,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        6163084833659416779,
                        2853393070793212496,
                        214169662941198197,
                        766838854721082896,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        15062514972738604859,
                        4072732498117267624,
                        11453597623878964866,
                        15196232748141971349,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        8105799423402967201,
                        10398709180756906993,
                        12579914275816041967,
                        3722472173064824114,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        4869072528223352863,
                        6275850450145071959,
                        8159689720148436485,
                        8979985763136073723,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        8512358054591706621,
                        12918418052549764713,
                        3564884046313350424,
                        18039231110525565261,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        10074982884687544941,
                        4177217016749721471,
                        4797356481048217516,
                        6983283665462696061,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        7025400382759865156,
                        2103688473762123306,
                        8681027323514330807,
                        13853995481224614401,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        3896366420105793420,
                        17410332186442776169,
                        7329967984378645716,
                        6310665049578686403,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        6574146240104132812,
                        2239043898123515337,
                        13809601679688051486,
                        16196448971140258304,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        7429917014148897946,
                        13764740161233226515,
                        14310941960777962392,
                        10321132974520710857,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        16852763145767657080,
                        5650551567722662817,
                        4688637260797538488,
                        504212361217900660,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        17594730245457333136,
                        13719209718183388763,
                        11444947689050098668,
                        628489339233491445,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        7731246070744876899,
                        3033565575746121792,
                        14735263366152051322,
                        16212144996433476818,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        9947841139978160787,
                        692236217135079542,
                        16309341595179079658,
                        9294006745033445642,
                    ],
                },
            ),
            QHashOut(
                HashOut {
                    elements: [
                        8603459983426387388,
                        1706773463182378335,
                        10020230853197995171,
                        2362856042482390481,
                    ],
                },
            ),
        ],
    },
    checkpoint_leaf: PQEDCheckpointLeafCompactWithStateRoots {
        checkpoint_leaf: PQEDCheckpointLeafCompact {
            global_chain_root: QHashOut(
                HashOut {
                    elements: [
                        11618985594767661937,
                        2102957719162571832,
                        4877561579681668718,
                        8727826184444592850,
                    ],
                },
            ),
            stats_hash: QHashOut(
                HashOut {
                    elements: [
                        6464387175481163130,
                        14328992239308545828,
                        7461225356271743475,
                        5114282262302336978,
                    ],
                },
            ),
        },
        global_state_roots: PQEDCheckpointGlobalStateRoots {
            contract_tree_root: QHashOut(
                HashOut {
                    elements: [
                        3896366420105793420,
                        17410332186442776169,
                        7329967984378645716,
                        6310665049578686403,
                    ],
                },
            ),
            deposit_tree_root: QHashOut(
                HashOut {
                    elements: [
                        16463394126558395459,
                        12818610997234032270,
                        2968763245313636978,
                        15445927884703223427,
                    ],
                },
            ),
            user_tree_root: QHashOut(
                HashOut {
                    elements: [
                        16463394126558395459,
                        12818610997234032270,
                        2968763245313636978,
                        15445927884703223427,
                    ],
                },
            ),
            withdrawal_tree_root: QHashOut(
                HashOut {
                    elements: [
                        16463394126558395459,
                        12818610997234032270,
                        2968763245313636978,
                        15445927884703223427,
                    ],
                },
            ),
            user_registration_tree_root: QHashOut(
                HashOut {
                    elements: [
                        16463394126558395459,
                        12818610997234032270,
                        2968763245313636978,
                        15445927884703223427,
                    ],
                },
            ),
        },
    },
}
GUTANoChangeCircuit expected public inputs hash: "ac8e37e1a1942b154c9272a6ee77614e0aced94df7de4a833de43c0009a530f9"
guta_header: GlobalUserTreeAggregatorHeader {
    guta_circuit_whitelist: QHashOut(
        HashOut {
            elements: [
                48102772944174883,
                10430171004933760049,
                1354239069199203707,
                12244588903111203751,
            ],
        },
    ),
    checkpoint_tree_root: QHashOut(
        HashOut {
            elements: [
                9100994332570639566,
                16912554973313982873,
                15066161584097017049,
                7548117707704315394,
            ],
        },
    ),
    state_transition: SubTreeNodeStateTransition {
        old_node_value: QHashOut(
            HashOut {
                elements: [
                    16463394126558395459,
                    12818610997234032270,
                    2968763245313636978,
                    15445927884703223427,
                ],
            },
        ),
        new_node_value: QHashOut(
            HashOut {
                elements: [
                    16463394126558395459,
                    12818610997234032270,
                    2968763245313636978,
                    15445927884703223427,
                ],
            },
        ),
        node_index: 0,
        node_level: 0,
    },
    stats: GUTAStats {
        fees_collected: 0,
        user_ops_processed: 0,
        total_transactions: 0,
        slots_modified: 0,
    },
    total_aggregation_proofs_generated: 1,
}
expected_guta_header_hash: QHashOut(HashOut { elements: [1525476321784204972, 5647927274577760844, 9460619120989556234, 17956033172403446845] }) (ac8e37e1a1942b154c9272a6ee77614e0aced94df7de4a833de43c0009a530f9)
worker_reward_tag: QHashOut(HashOut { elements: [10847503993215243924, 7552012521989090961, 379268792538156506, 14632161393572777710] }) (94d639c768138a96912e76606023ce68dacda015f56e4305ee0e175043e10fcb)
reward_tree_value: QHashOut(HashOut { elements: [5579485639902852131, 13302545554175739819, 15021781436162784682, 10066626686504329459] }) (2374cdcba0506e4dabc7189db3229cb8aa3d0a9ca01678d0f3e08ed7a2d7b38b)
expected_final_public_inputs_hash: QHashOut(HashOut { elements: [17792992841846349366, 11519235727159831180, 1048176325124567029, 968500124033969673] }) (36de51e5b768edf68caa59c1dc8bdc9ff52f0671d0de8b0e096ef741bbcd700d)
GUTANoChangeCircuit generated public inputs hash: 36de51e5b768edf68caa59c1dc8bdc9ff52f0671d0de8b0e096ef741bbcd700d
GUTANoChangeCircuit proof generated with public inputs [17792992841846349366, 11519235727159831180, 1048176325124567029, 968500124033969673]
2m2025-11-29T12:39:59.917821Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m55:0m Proved job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: GUTANoChange, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } in 171.040583ms, submitting proof to API
2m2025-11-29T12:39:59.931747Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m57:0m Submitted proof for job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: GUTANoChange, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } to API URL hash: 687474703a2f2f3132372e302e302e313a313333370000000000000000000000
2m2025-11-29T12:40:00.041101Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m47:0m Fetched new job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } from API URL hash: [104, 116, 116, 112, 58, 47, 47, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 49, 51, 51, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
DummyAggStateTransition expected public inputs hash: "4a39863c3bdc9eee5c0e3af36a4e05190919855f41622aff0621be8c201135dc"
Computed public inputs hash with worker reward tag: "7bf8c87f4b4dbeaee2a881dd2554e5482c9ee248018c0f8c73c96d221cb11b33"
Proof public inputs hash: "7bf8c87f4b4dbeaee2a881dd2554e5482c9ee248018c0f8c73c96d221cb11b33"
2m2025-11-29T12:40:00.209130Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m55:0m Proved job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } in 168.013708ms, submitting proof to API
2m2025-11-29T12:40:00.221747Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m57:0m Submitted proof for job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } to API URL hash: 687474703a2f2f3132372e302e302e313a313333370000000000000000000000
2m2025-11-29T12:40:00.339567Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m47:0m Fetched new job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: DummyBatchDeployContractsAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } from API URL hash: [104, 116, 116, 112, 58, 47, 47, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 49, 51, 51, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
DummyAggStateTransition expected public inputs hash: "4153450b07e222c752a30fa5b56a123ea194217717523b20e4396a9129942ab4"
Computed public inputs hash with worker reward tag: "c4a7338bab671a82e570dae0fa8038bf4eddaf209ae596e9f7f27d6542177425"
Proof public inputs hash: "c4a7338bab671a82e570dae0fa8038bf4eddaf209ae596e9f7f27d6542177425"
2m2025-11-29T12:40:00.508476Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m55:0m Proved job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: DummyBatchDeployContractsAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } in 168.890875ms, submitting proof to API
2m2025-11-29T12:40:00.521906Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m57:0m Submitted proof for job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: DummyBatchDeployContractsAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } to API URL hash: 687474703a2f2f3132372e302e302e313a313333370000000000000000000000
2m2025-11-29T12:40:00.870342Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m47:0m Fetched new job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: AggUserRegisterDeployContractsGUTA, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } from API URL hash: [104, 116, 116, 112, 58, 47, 47, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 49, 51, 51, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
guta_header: GlobalUserTreeAggregatorHeader {
    guta_circuit_whitelist: QHashOut(
        HashOut {
            elements: [
                48102772944174883,
                10430171004933760049,
                1354239069199203707,
                12244588903111203751,
            ],
        },
    ),
    checkpoint_tree_root: QHashOut(
        HashOut {
            elements: [
                9100994332570639566,
                16912554973313982873,
                15066161584097017049,
                7548117707704315394,
            ],
        },
    ),
    state_transition: SubTreeNodeStateTransition {
        old_node_value: QHashOut(
            HashOut {
                elements: [
                    16463394126558395459,
                    12818610997234032270,
                    2968763245313636978,
                    15445927884703223427,
                ],
            },
        ),
        new_node_value: QHashOut(
            HashOut {
                elements: [
                    16463394126558395459,
                    12818610997234032270,
                    2968763245313636978,
                    15445927884703223427,
                ],
            },
        ),
        node_index: 0,
        node_level: 0,
    },
    stats: GUTAStats {
        fees_collected: 0,
        user_ops_processed: 0,
        total_transactions: 0,
        slots_modified: 0,
    },
    total_aggregation_proofs_generated: 1,
}
guta_proof_header_hash: QHashOut(HashOut { elements: [1525476321784204972, 5647927274577760844, 9460619120989556234, 17956033172403446845] }) (ac8e37e1a1942b154c9272a6ee77614e0aced94df7de4a833de43c0009a530f9)
guta_proof_public_inputs: QHashOut(HashOut { elements: [17792992841846349366, 11519235727159831180, 1048176325124567029, 968500124033969673] })
guta_public_inputs_expected: QHashOut(HashOut { elements: [17792992841846349366, 11519235727159831180, 1048176325124567029, 968500124033969673] }) (36de51e5b768edf68caa59c1dc8bdc9ff52f0671d0de8b0e096ef741bbcd700d)
guta_rewards_tree_value: QHashOut(HashOut { elements: [5579485639902852131, 13302545554175739819, 15021781436162784682, 10066626686504329459] }) (2374cdcba0506e4dabc7189db3229cb8aa3d0a9ca01678d0f3e08ed7a2d7b38b)
expected_public_inputs_hash_no_rewards: QHashOut(HashOut { elements: [17196468909343551648, 15577720748487765019, 1435319234641106914, 2630248784321937976] }) (a0b078bc5c21a6ee1b6cd8877c2e2fd8e29711403d47eb133882696c55858024)
metadata_public_inputs_hash_no_rewards: QHashOut(HashOut { elements: [17196468909343551648, 15577720748487765019, 1435319234641106914, 2630248784321937976] }) (a0b078bc5c21a6ee1b6cd8877c2e2fd8e29711403d47eb133882696c55858024)
expected_rewards_value: QHashOut(HashOut { elements: [5947549229293269765, 9053432156226556536, 2312305553521184632, 16196625046874990721] }) (05732c3883f089527892fb359440a47d780fcb59a6f5162081a82dafaaf8c5e0)
expected_public_inputs_1: QHashOut(HashOut { elements: [10364978500547453518, 1875781598320177361, 2414737231482381513, 16381202464144829434] }) (4e22b1bd07cdd78fd1b016e46c1d081ac9e46adcb7de8221fa2b1b8dd9b855e3)
metadata_with_expected_rewards: QHashOut(HashOut { elements: [10364978500547453518, 1875781598320177361, 2414737231482381513, 16381202464144829434] }) (4e22b1bd07cdd78fd1b016e46c1d081ac9e46adcb7de8221fa2b1b8dd9b855e3)
2m2025-11-29T12:40:00.870578Z0m 32m INFO0m 2mpsy_plonky2_circuits/src/coordinator/gadgets/verify_agg_user_registration_deploy_guta.rs0m2m:0m2m265:0m 🏭 Agg User Registration Deploy Contracts GUTA set_witness - register_users public_inputs: [
  12591586594836248699,
  5252697062004336866,
  10092439227106237996,
  3682731854700333427
], deploy_contracts public_inputs: [
  9374919560797595588,
  13778904874942623973,
  16831893107479928142,
  2698807650639803127
], guta_proof public_inputs: [
  17792992841846349366,
  11519235727159831180,
  1048176325124567029,
  968500124033969673
]
2m2025-11-29T12:40:00.870590Z0m 32m INFO0m 2mpsy_plonky2_circuits/src/coordinator/gadgets/verify_agg_user_registration_deploy_guta.rs0m2m:0m2m270:0m 🏭 Agg User Registration Deploy Contracts GUTA set_witness - guta_proof_header: {
  "guta_circuit_whitelist": "a9ed84bb96a21ba712cb39422492fd7b90bf69447fa7e43100aae537960c7f23",
  "checkpoint_tree_root": "68c04d10428d2e02d115c22304bd3cd9eab5772444a561997e4d3a2057b75cce",
  "state_transition": {
    "old_node_value": "d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43",
    "new_node_value": "d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43",
    "node_index": 0,
    "node_level": 0
  },
  "stats": {
    "fees_collected": 0,
    "user_ops_processed": 0,
    "total_transactions": 0,
    "slots_modified": 0
  },
  "total_aggregation_proofs_generated": 1
}
2m2025-11-29T12:40:00.870596Z0m 32m INFO0m 2mpsy_plonky2_circuits/src/coordinator/gadgets/verify_agg_user_registration_deploy_guta.rs0m2m:0m2m275:0m register_users_state_transition={
  "state_transition_start": "d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43",
  "state_transition_end": "d65af5933a094e8329332a714327ba72b1e4dac93c0cde8ee479b9bb36c3fc43"
}
2m2025-11-29T12:40:00.871079Z0m 32m INFO0m 2mpsy_plonky2_circuits/src/coordinator/gadgets/verify_agg_user_registration_deploy_guta.rs0m2m:0m2m287:0m deploy_contracts_state_transition={
  "state_transition_start": "5793fc6d609c47c365b9470bc3e00cd4f19dece13278be693612ac9d812a8f8c",
  "state_transition_end": "5793fc6d609c47c365b9470bc3e00cd4f19dece13278be693612ac9d812a8f8c"
}
got_public_inputs: QHashOut(HashOut { elements: [10364978500547453518, 1875781598320177361, 2414737231482381513, 16381202464144829434] }) (4e22b1bd07cdd78fd1b016e46c1d081ac9e46adcb7de8221fa2b1b8dd9b855e3)
2m2025-11-29T12:40:01.254088Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m55:0m Proved job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: AggUserRegisterDeployContractsGUTA, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } in 383.724959ms, submitting proof to API
2m2025-11-29T12:40:01.265391Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m57:0m Submitted proof for job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: AggUserRegisterDeployContractsGUTA, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } to API URL hash: 687474703a2f2f3132372e302e302e313a313333370000000000000000000000
2m2025-11-29T12:40:01.825364Z0m 32m INFO0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m47:0m Fetched new job: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 2, circuit_type: GenerateRollupStateTransitionProof, group_id: 0, sub_group_id: 0, task_index: 0, data_type: StandardProof, data_index: 0 } from API URL hash: [104, 116, 116, 112, 58, 47, 47, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 49, 51, 51, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
genesis state transition hash: [7559311643411310228, 14299849723889717690, 641545705442395094, 1551506835590227835] (94660184e311e868ba11ea5d8f4573c6d64312886b3ae7087b27f2293f0f8815)
expected_public_inputs_no_tag: [17575745596799393260, 14921557193435308900, 6364895015942701540, 18182167773496177101] (ec1dddff7f97e9f364e362aa350514cfe441eb594ba65458cd71cbb9410954fc)
expected_public_inputs_metadata: [17575745596799393260, 14921557193435308900, 6364895015942701540, 18182167773496177101] (ec1dddff7f97e9f364e362aa350514cfe441eb594ba65458cd71cbb9410954fc)
part_1_proof_public_inputs: [10364978500547453518, 1875781598320177361, 2414737231482381513, 16381202464144829434] (4e22b1bd07cdd78fd1b016e46c1d081ac9e46adcb7de8221fa2b1b8dd9b855e3)
part_1_worker_reward_tree_value: [5947549229293269765, 9053432156226556536, 2312305553521184632, 16196625046874990721] (05732c3883f089527892fb359440a47d780fcb59a6f5162081a82dafaaf8c5e0)
last_checkpoint_hash_transition: CheckpointStateHashTransition {
    old_checkpoint_tree_root: QHashOut(
        HashOut {
            elements: [
                10458088682233416695,
                17385366644170102976,
                8414368673199673107,
                13594683008784965775,
            ],
        },
    ),
    new_checkpoint_tree_root: QHashOut(
        HashOut {
            elements: [
                9100994332570639566,
                16912554973313982873,
                15066161584097017049,
                7548117707704315394,
            ],
        },
    ),
    old_checkpoint_leaf_hash: QHashOut(
        HashOut {
            elements: [
                8426879675417334206,
                2436166045420849577,
                16809635919563306144,
                5309346835249992620,
            ],
        },
    ),
    new_checkpoint_leaf_hash: QHashOut(
        HashOut {
            elements: [
                8953239826435340432,
                720574180395379416,
                8977861569436724405,
                9890825682981539431,
            ],
        },
    ),
}
last_checkpoint_hash_transition_hash: [5910256071946210448, 762659513076293004, 10811297432778432814, 11855557238117893111] (900cf363957205528c1d7c51c982950a2ee1d901bc710996f70354a07e6687a4)
last_checkpoint_transition_publics_hash: [17513607767332389821, 352912007909802957, 4551557380883300468, 12112786358221628142] (bd835e2b79d50cf3cd036ff499cbe50474405b9e52612a3fee62ff39044319a8)
checkpoint_hash_transition: CheckpointStateHashTransition {
    old_checkpoint_tree_root: QHashOut(
        HashOut {
            elements: [
                9100994332570639566,
                16912554973313982873,
                15066161584097017049,
                7548117707704315394,
            ],
        },
    ),
    new_checkpoint_tree_root: QHashOut(
        HashOut {
            elements: [
                5452279168738418021,
                12101492494798353092,
                1155018305160592936,
                3011309780899170237,
            ],
        },
    ),
    old_checkpoint_leaf_hash: QHashOut(
        HashOut {
            elements: [
                8953239826435340432,
                720574180395379416,
                8977861569436724405,
                9890825682981539431,
            ],
        },
    ),
    new_checkpoint_leaf_hash: QHashOut(
        HashOut {
            elements: [
                2004279990969456274,
                17656812691955938781,
                2200784788895839586,
                8934214916406378754,
            ],
        },
    ),
}
checkpoint_hash_transition_hash: [14154779530267870238, 8972752118980330574, 15907692112505859839, 16158046058857363024] (1e4496cffce06fc44ec47435839e857cffee319ab179c3dc50f6971248e93ce0)
checkpoint_hash_transition_publics_hash: [17575745596799393260, 14921557193435308900, 6364895015942701540, 18182167773496177101] (ec1dddff7f97e9f364e362aa350514cfe441eb594ba65458cd71cbb9410954fc)
genesis_checkpoint_state_transition_hash: [7559311643411310228, 14299849723889717690, 641545705442395094, 1551506835590227835] (94660184e311e868ba11ea5d8f4573c6d64312886b3ae7087b27f2293f0f8815)
transition_circuit_fingerprint: [8653412727247185755, 6404210200288153421, 15842295031778658844, 851668705768035544] (5ba76916071917784dcf1b073f53e0581c4a1a346523dbdbd8d49ef12cbcd10b)
expected_previous_checkpoint_state_transition_proof_public_inputs: [17513607767332389821, 352912007909802957, 4551557380883300468, 12112786358221628142] (bd835e2b79d50cf3cd036ff499cbe50474405b9e52612a3fee62ff39044319a8)
previous_checkpoint_state_transition_proof_public_inputs: [8173636668400790300, 1563310953851325238, 3081518508325915930, 3522297658072428737] (1ceb227f3e976e71360bc99d07ffb1151acd8eb9c1c0c32ac1f098de0eb7e130)
[updadting reward root]...
dmp: DeltaMerkleProofCore { old_root: QHashOut(HashOut { elements: [9100994332570639566, 16912554973313982873, 15066161584097017049, 7548117707704315394] }), old_value: QHashOut(HashOut { elements: [0, 0, 0, 0] }), new_root: QHashOut(HashOut { elements: [6735838171382428762, 1029274819274908194, 13463458549730000158, 11263680876058595367] }), new_value: QHashOut(HashOut { elements: [5704194446082850686, 11572558740810209821, 16607504152210017791, 14808386694440610688] }), index: 2, siblings: [QHashOut(HashOut { elements: [0, 0, 0, 0] }), QHashOut(HashOut { elements: [11851044809676678374, 14177634557182508192, 6988920434166908972, 16978219948904718492] }), QHashOut(HashOut { elements: [13121882728673923020, 10197653806804742863, 16037207047953124082, 2420399206709257475] }), QHashOut(HashOut { elements: [7052649073129349210, 11107139769197583972, 5114845353783771231, 7453521209854829890] }), QHashOut(HashOut { elements: [5860469655587923524, 10142584705005652295, 1620588827255328039, 17663938664361140288] }), QHashOut(HashOut { elements: [16854358529591173550, 9704301947898025017, 13222045073939169687, 14989445859181028978] }), QHashOut(HashOut { elements: [2675805695450374474, 6493392849121218307, 15972287940310989584, 5284431416427098307] }), QHashOut(HashOut { elements: [16823738737355150819, 4366876208047374841, 1642083707956929713, 13216064879834397173] }), QHashOut(HashOut { elements: [18334109492892739862, 10192437552951753306, 15211985613247588647, 3157981091968158131] }), QHashOut(HashOut { elements: [4369129498500264270, 10758747855946482846, 3238306058428322199, 18226589090145367109] }), QHashOut(HashOut { elements: [14769473886748754115, 10513963056908986963, 8105478726930894327, 14014796621245524545] }), QHashOut(HashOut { elements: [10191288259157808067, 944536249556834531, 16268598854718968908, 2417244819673331317] }), QHashOut(HashOut { elements: [17088215091100491041, 18086883194773274646, 10296247222913205474, 7017044080942280524] }), QHashOut(HashOut { elements: [2985877902215057279, 14516746119572211305, 594952314256159992, 17038984393731825093] }), QHashOut(HashOut { elements: [101510842507023404, 2267676083447667738, 18106248392660779137, 17680390044293740318] }), QHashOut(HashOut { elements: [16662284396446084312, 7269926520507830029, 14791338760961128332, 7825163129638412009] }), QHashOut(HashOut { elements: [12364052984629808614, 13066500727264825316, 6321076066274078148, 11393071566019822187] }), QHashOut(HashOut { elements: [6163084833659416779, 2853393070793212496, 214169662941198197, 766838854721082896] }), QHashOut(HashOut { elements: [15062514972738604859, 4072732498117267624, 11453597623878964866, 15196232748141971349] }), QHashOut(HashOut { elements: [8105799423402967201, 10398709180756906993, 12579914275816041967, 3722472173064824114] }), QHashOut(HashOut { elements: [4869072528223352863, 6275850450145071959, 8159689720148436485, 8979985763136073723] }), QHashOut(HashOut { elements: [8512358054591706621, 12918418052549764713, 3564884046313350424, 18039231110525565261] }), QHashOut(HashOut { elements: [10074982884687544941, 4177217016749721471, 4797356481048217516, 6983283665462696061] }), QHashOut(HashOut { elements: [7025400382759865156, 2103688473762123306, 8681027323514330807, 13853995481224614401] }), QHashOut(HashOut { elements: [3896366420105793420, 17410332186442776169, 7329967984378645716, 6310665049578686403] }), QHashOut(HashOut { elements: [6574146240104132812, 2239043898123515337, 13809601679688051486, 16196448971140258304] }), QHashOut(HashOut { elements: [7429917014148897946, 13764740161233226515, 14310941960777962392, 10321132974520710857] }), QHashOut(HashOut { elements: [16852763145767657080, 5650551567722662817, 4688637260797538488, 504212361217900660] }), QHashOut(HashOut { elements: [17594730245457333136, 13719209718183388763, 11444947689050098668, 628489339233491445] }), QHashOut(HashOut { elements: [7731246070744876899, 3033565575746121792, 14735263366152051322, 16212144996433476818] }), QHashOut(HashOut { elements: [9947841139978160787, 692236217135079542, 16309341595179079658, 9294006745033445642] }), QHashOut(HashOut { elements: [8603459983426387388, 1706773463182378335, 10020230853197995171, 2362856042482390481] })] }
old_state_roots: PQEDCheckpointGlobalStateRoots {
    contract_tree_root: QHashOut(
        HashOut {
            elements: [
                3896366420105793420,
                17410332186442776169,
                7329967984378645716,
                6310665049578686403,
            ],
        },
    ),
    deposit_tree_root: QHashOut(
        HashOut {
            elements: [
                16463394126558395459,
                12818610997234032270,
                2968763245313636978,
                15445927884703223427,
            ],
        },
    ),
    user_tree_root: QHashOut(
        HashOut {
            elements: [
                16463394126558395459,
                12818610997234032270,
                2968763245313636978,
                15445927884703223427,
            ],
        },
    ),
    withdrawal_tree_root: QHashOut(
        HashOut {
            elements: [
                16463394126558395459,
                12818610997234032270,
                2968763245313636978,
                15445927884703223427,
            ],
        },
    ),
    user_registration_tree_root: QHashOut(
        HashOut {
            elements: [
                16463394126558395459,
                12818610997234032270,
                2968763245313636978,
                15445927884703223427,
            ],
        },
    ),
}
new_state_roots: PQEDCheckpointGlobalStateRoots {
    contract_tree_root: QHashOut(
        HashOut {
            elements: [
                3896366420105793420,
                17410332186442776169,
                7329967984378645716,
                6310665049578686403,
            ],
        },
    ),
    deposit_tree_root: QHashOut(
        HashOut {
            elements: [
                16463394126558395459,
                12818610997234032270,
                2968763245313636978,
                15445927884703223427,
            ],
        },
    ),
    user_tree_root: QHashOut(
        HashOut {
            elements: [
                16463394126558395459,
                12818610997234032270,
                2968763245313636978,
                15445927884703223427,
            ],
        },
    ),
    withdrawal_tree_root: QHashOut(
        HashOut {
            elements: [
                16463394126558395459,
                12818610997234032270,
                2968763245313636978,
                15445927884703223427,
            ],
        },
    ),
    user_registration_tree_root: QHashOut(
        HashOut {
            elements: [
                16463394126558395459,
                12818610997234032270,
                2968763245313636978,
                15445927884703223427,
            ],
        },
    ),
}
old_global_chain_root: [11618985594767661937, 2102957719162571832, 4877561579681668718, 8727826184444592850] (71db81a2d6ed3ea138cc5954e7342f1d6ede040f6a94b043d2422c39ac771f79)
new_global_chain_root: [11618985594767661937, 2102957719162571832, 4877561579681668718, 8727826184444592850] (71db81a2d6ed3ea138cc5954e7342f1d6ede040f6a94b043d2422c39ac771f79)
old_checkpoint_leaf: PQEDCheckpointLeaf {
    global_chain_root: QHashOut(
        HashOut {
            elements: [
                11618985594767661937,
                2102957719162571832,
                4877561579681668718,
                8727826184444592850,
            ],
        },
    ),
    stats: PQEDCheckpointLeafStats {
        fees_collected: 0,
        user_ops_processed: 0,
        total_transactions: 0,
        slots_modified: 0,
        pm_jobs_completed: PPMJobsCompletedStats {
            deploy_contracts_completed: 1,
            register_users_completed: 1,
            gutas_completed: 1,
        },
        block_time: 1764419999718,
        random_seed: QHashOut(
            HashOut {
                elements: [
                    686191062320707623,
                    11979345616392276282,
                    6719388120155154949,
                    4500086781896954073,
                ],
            },
        ),
        pm_rewards_commitment: PPMRewardCommitment {
            register_users_root: QHashOut(
                HashOut {
                    elements: [
                        6986357916869724019,
                        6327731205419157574,
                        15719055104599833021,
                        4571754155461516237,
                    ],
                },
            ),
            gutas_root: QHashOut(
                HashOut {
                    elements: [
                        6986357916869724019,
                        6327731205419157574,
                        15719055104599833021,
                        4571754155461516237,
                    ],
                },
            ),
            deploy_contracts_root: QHashOut(
                HashOut {
                    elements: [
                        6986357916869724019,
                        6327731205419157574,
                        15719055104599833021,
                        4571754155461516237,
                    ],
                },
            ),
        },
        da_challenges_claimed: [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ],
    },
}
old_checkpoint_leaf_hash: [8953239826435340432, 720574180395379416, 8977861569436724405, 9890825682981539431] (90f88e932f4c407cd8eac83866feff09b52ce8d887c5977c67ce6c098e454389)
last_merkle_proof_checkpoint_leaf_hash: [8953239826435340432, 720574180395379416, 8977861569436724405, 9890825682981539431] (90f88e932f4c407cd8eac83866feff09b52ce8d887c5977c67ce6c098e454389)
expected_new_pubs: [1028455614299049705, 3092759890118959331, 9678538883105871498, 13541349045283474869] (e90e8da5eece450ee3e01de2bbb0eb2a8ad654c8d5135186b54db2273689ecbb)
upd_expected_public_inputs_metadata: [17575745596799393260, 14921557193435308900, 6364895015942701540, 18182167773496177101] (ec1dddff7f97e9f364e362aa350514cfe441eb594ba65458cd71cbb9410954fc)
pub_test: CheckpointStateTransitionPublicInputs {
    checkpoint_transition: CheckpointStateHashTransition {
        old_checkpoint_tree_root: QHashOut(
            HashOut {
                elements: [
                    9100994332570639566,
                    16912554973313982873,
                    15066161584097017049,
                    7548117707704315394,
                ],
            },
        ),
        new_checkpoint_tree_root: QHashOut(
            HashOut {
                elements: [
                    6735838171382428762,
                    1029274819274908194,
                    13463458549730000158,
                    11263680876058595367,
                ],
            },
        ),
        old_checkpoint_leaf_hash: QHashOut(
            HashOut {
                elements: [
                    8953239826435340432,
                    720574180395379416,
                    8977861569436724405,
                    9890825682981539431,
                ],
            },
        ),
        new_checkpoint_leaf_hash: QHashOut(
            HashOut {
                elements: [
                    5704194446082850686,
                    11572558740810209821,
                    16607504152210017791,
                    14808386694440610688,
                ],
            },
        ),
    },
    genesis_checkpoint_state_transition_hash: QHashOut(
        HashOut {
            elements: [
                7559311643411310228,
                14299849723889717690,
                641545705442395094,
                1551506835590227835,
            ],
        },
    ),
    checkpoint_state_transition_circuit_fingerprint: QHashOut(
        HashOut {
            elements: [
                8653412727247185755,
                6404210200288153421,
                15842295031778658844,
                851668705768035544,
            ],
        },
    ),
}
pub_test_hash: [1028455614299049705, 3092759890118959331, 9678538883105871498, 13541349045283474869] (e90e8da5eece450ee3e01de2bbb0eb2a8ad654c8d5135186b54db2273689ecbb)
2m2025-11-29T12:40:01.852906Z0m 31mERROR0m 2mpsy_worker_core/src/worker/manager.rs0m2m:0m2m68:0m Error processing job: Partition containing Wire(Wire { row: 8347, column: 12 }) was set twice with different values: 8173636668400790300 != 17513607767332389821
```


what would you say is likely wrong with the code for. the processor/worker?
Where is the inconsistency that results in the public inputs of the checkpoint state transition proof not matching the expected public inputs?