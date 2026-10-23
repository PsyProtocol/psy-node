//! Authenticated bridge snapshot at checkpoint T.
//!
//! Proves each realm transition into T and selects fully verified mapped archives
//! across configured replicas. Conflicting logical transcripts or no usable source
//! fail closed. Queue/finalizer replay and session/T openings authenticate withdrawal
//! state, not proposer identity or event bodies. Writes nothing; L1 deposit anchors
//! remain pinned to the latest included event block.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use anyhow::{Context, ensure};
use guardian_common::protocol::{
    DepositAnchor, DepositTreeState, GuardianAccount, GuardianAccountState, GuardianConfig, Hash4,
    WithdrawalAppendRecord, WithdrawalBurnRecord, BRIDGE_USER_ID,
};
use guardian_common::verify_l1::{finalized_deposit_anchor, verify_deposit_anchor, verify_saved_deposit_anchor_headers};
use parth_core::crypto::hash::merkle_proof::MerkleProofCore;
use parth_core::crypto::hash::traits::{FieldQHasher, QFieldHashable};
use parth_core::felt::ToU64Value;
use parth_core::protocol::core_types::{Q256BitHash, QNetworkHashTypes, QNetworkTreeConstants, QNetworkTypesConfigHelper};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::PrimeField64;
use plonky2::field::types::Field;
use psy_client_data::config::store_config::PsyHasher;
use psy_core::network_config::PsyNetworkLocalDevnetConstants;
use psy_core::job::job_id::QProvingJobDataID;
use psy_crypto::hash::traits::hasher::MerkleZeroHasher;
use psy_data::guta::header_extended::GlobalUserTreeAggregatorHeaderWithJobId;
use psy_data::proof_input::guta::end_cap_input::PsyUserEventRecord;
use psy_data::v1::qdata::user::PQEDUserLeaf;
use psy_node_common::realm::processor::gatherers::realm_end_cap_gatherer::{
    get_new_realm_end_cap_gatherer_backup_file_path, REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32,
};
use psy_node_core::psy_core_db::traits::full::{
    PsyNodeCheckpointObjectDatabaseReader, PsyNodeCheckpointRealmSpecificDatabaseReader, PsyNodeCheckpointTreeDatabaseReader,
    PsyNodeContractStateIMTDatabaseReader, PsyNodeContractStateTreeTreeDatabaseReader, PsyNodeCoreDatabaseContractObjectStoreReader,
    PsyNodeCoreDatabaseUserStoreReader, PsyNodeGlobalUserTreeDatabaseReader, PsyNodeUserContractTreeDatabaseReader,
    PsyNodeValidatorTreeDatabaseReader, PsyNodeGlobalContractTreeDatabaseReader,
};
use psy_node_core::qblob::blob_type::{QBlobDataType, QBlobMerkleNodeTreeType};
use psy_node_core::qblob::structs::common::tree_node_batch_header::{QBlobMerkleTreeNodeBatchHeaderV1, QBLOB_TREE_NODE_BATCH_HEADER_SIZE};
use psy_node_core::qblob::traits::common::QBlobStructHeaderBase;
use psy_node_scylla::psy_setup::setup_psy_scylla_database_store_from_connection_string;
use psy_plonky2_circuits::protocol_types::ZKTypesPlonky2GoldilocksPoseidon;
use psy_serialize::{PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use super::rollback::ProcessorConfig;

type Network = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
type NodeHash = <Network as QNetworkHashTypes>::QHash;
type Felt = <Network as QNetworkHashTypes>::F;
type Store = psy_node_scylla::psy_setup::ScyllaUnifiedPsyStore<Network, NodeHash, <Network as QNetworkHashTypes>::HasherBase>;

const DEPOSIT_CONTRACT: u32 = 2;
const WITHDRAWAL_CONTRACT: u32 = 3;
const TOKEN_CONTRACT: u32 = 0;
const USDT_CONTRACT: u32 = 4;
const POLICY_CONTRACT: u32 = 1;
const CHAIN_COUNT_SLOT: u64 = 65_544;
const CHAIN_ROOT_SLOT: u64 = 65_804;
const FRONTIER_BASE_SLOT: u64 = 8;
const WITHDRAWAL_MAP_BASE: u64 = 8_589_934_680;
const WITHDRAWAL_MAP_CAPACITY: u64 = 1_048_576;
// Compiled token withdraw ABI, not the unrelated fee-burning method.
const WITHDRAW_METHOD: u64 = 3_055_054_724;
const APPEND_METHODS: [u64; 3] = [2_140_131_902, 4_283_677_324, 961_124_698];

pub(crate) struct BridgeJournalSnapshot {
    pub account: GuardianAccount,
    pub deposits: Vec<DepositTreeState>,
    pub withdrawals: Vec<(WithdrawalAppendRecord, u64)>,
}

struct UserStateOpening { leaf_hash: Hash4, public_key: Hash4, state_root: Hash4, nonce: u64 }
struct BridgeChainOpening { count: u32, root: Hash4, frontier: [Hash4; 32] }
struct IncludedWithdrawal { record: WithdrawalAppendRecord, session_nonce: u64 }
struct Candidate { kind: CandidateKind, checkpoint: u64, event_index: u64 }
enum CandidateKind {
    Burn { burn: WithdrawalBurnRecord, nonce: u64, leaf_hash: Hash4 },
    Append { chain: u8, index: u32, leaf: Hash4, chain_root: Hash4, global_root: [u32; 8], nonce: u64, leaf_hash: Hash4 },
}

#[derive(Default, PartialEq, Eq)]
struct ArchiveTranscript {
    sessions: BTreeMap<(u64, u64), (u64, u64, Hash4)>,
    events: BTreeMap<(u64, u64, u64), (u64, u64, u64, Vec<u64>)>,
}
struct AuthenticatedArchive { candidates: Vec<Candidate>, transcript: ArchiveTranscript }

fn accept_archive(selected: &mut Option<AuthenticatedArchive>, candidate: AuthenticatedArchive) -> anyhow::Result<()> {
    if let Some(previous) = selected {
        ensure!(previous.transcript == candidate.transcript, "authenticated replica archives disagree on logical session/event transcript");
    } else {
        *selected = Some(candidate);
    }
    Ok(())
}

fn require_archive(selected: Option<AuthenticatedArchive>, failures: &[String]) -> anyhow::Result<AuthenticatedArchive> {
    selected.with_context(|| format!("no complete authenticated archive source: {}", failures.join("; ")))
}

// The archive fold authenticates only append coordinates and derives the
// frontier and root; the same burn record may legitimately occupy distinct
// append positions, so burn identity is never deduped inside this fold.
fn fold_chain_appends(index: u8, rows: &[IncludedWithdrawal]) -> anyhow::Result<([Hash4; 32], Hash4)> {
    let mut folded = [Hash4::ZERO; 32];
    let mut folded_root = empty_root();
    for (position, row) in rows.iter().enumerate() {
        ensure!(row.record.append_index == position as u32, "chain {index} appends are not a contiguous prefix");
        folded_root = guardian_common::protocol::append_merkle_leaf(&mut folded, row.record.append_index, guardian_common::protocol::withdrawal_tree_leaf(&row.record.burn));
    }
    Ok((folded, folded_root))
}

pub(crate) async fn build_bridge_journal_snapshot(target: u64, processors: &[ProcessorConfig], config: &GuardianConfig) -> anyhow::Result<BridgeJournalSnapshot> {
    ensure!(!processors.is_empty(), "snapshot requires the complete processor inventory");
    let store = open_coordinator(processors).await?;
    ensure!(store.get_latest_checkpoint_id().await? >= target, "store marker is behind checkpoint {target}");
    let committed = committed_root(&store, target).await?;
    let (checkpoint_hash, _) = authenticate_checkpoint(&store, target, target, committed).await?;
    let (user, openings) = target_bridge_openings(&store, processors, target, committed, config).await?;

    let mut deposits = Vec::new();
    let mut chains = Vec::new();
    for (chain, (deposit, withdrawal)) in config.l1_chains.iter().zip(openings) {
        let index = chain.chain_index;
        if deposit.count > 0 {
            let proven = prove_deposits(chain, deposit.count, deposit.root).await?;
            ensure!(proven.count == deposit.count && proven.root == deposit.root, "L1 deposit fold does not match L2 on chain {index}");
            deposits.push(proven);
        } else {
            ensure!(deposit.root == Hash4::ZERO || deposit.root == empty_root(), "zero-count deposit root on chain {index} is neither zero nor empty");
        }
        if withdrawal.count > 0 { chains.push((index, withdrawal.count, withdrawal.frontier, withdrawal.root)); }
        else {
            ensure!(withdrawal.frontier == [Hash4::ZERO; 32] && (withdrawal.root == Hash4::ZERO || withdrawal.root == empty_root()), "zero-count withdrawal opening on chain {index} is not empty");
        }
    }
    ensure!(deposits.len() <= 3, "more than three deposit chains have a count");
    let chain_indexes = config.l1_chains.iter().map(|chain| chain.chain_index).collect::<Vec<_>>();
    let included = included_withdrawals(&store, processors, target, committed, user.nonce, &chain_indexes).await?;
    let mut by_chain: BTreeMap<u8, Vec<_>> = BTreeMap::new();
    for item in included { by_chain.entry(item.record.chain_index).or_default().push(item); }
    let mut withdrawals = Vec::new();
    for (index, count, frontier, root) in &chains {
        let rows = by_chain.remove(index).context("authenticated withdrawal chain has no archive appends")?;
        ensure!(rows.len() == *count as usize, "chain {index} count {count} does not match the archive appends");
        let (folded, folded_root) = fold_chain_appends(*index, &rows)?;
        ensure!(&folded == frontier && &folded_root == root, "chain {index} archive fold does not reproduce the authenticated frontier and root");
        withdrawals.extend(rows.into_iter().map(|row| (row.record, row.session_nonce)));
    }
    ensure!(by_chain.is_empty(), "archives contain an append on a chain whose authenticated count is zero");
    withdrawals.sort_by(|left, right| left.0.chain_index.cmp(&right.0.chain_index).then(left.0.append_index.cmp(&right.0.append_index)));
    let imported_nonce = if user.nonce == 0 && withdrawals.is_empty() { None } else { Some(user.nonce) };
    let account = GuardianAccount {
        network_magic: config.network_magic().context("network magic")?, user_id: BRIDGE_USER_ID, state: GuardianAccountState::Active,
        last_checkpoint_id: target, last_checkpoint_hash: checkpoint_hash, imported_nonce, account_public_key: user.public_key,
        imported_ending_leaf: imported_nonce.map(|_| user.leaf_hash), withdrawal_chains: chains, halt_reason: None,
    };
    account.validate().map_err(|error| anyhow::anyhow!("reconstructed account is invalid: {error:?}"))?;
    Ok(BridgeJournalSnapshot { account, deposits, withdrawals })
}

async fn target_bridge_openings(coordinator: &Store, processors: &[ProcessorConfig], target: u64, committed: Hash4, config: &GuardianConfig) -> anyhow::Result<(UserStateOpening, Vec<(BridgeChainOpening, BridgeChainOpening)>)> {
    let expected_policy = config.initial_account().context("configured initial policy")?.initial_policy;
    let mut failures = Vec::new();
    for processor in processors {
        let ProcessorConfig::Realm(source) = processor else { continue };
        if source.realm_id != BRIDGE_USER_ID >> Network::REALM_GLOBAL_USER_TREE_HEIGHT { continue; }
        let result = async {
            let store = setup_psy_scylla_database_store_from_connection_string::<Network>(&source.db_namespace, &source.scylla_db_url, false).await?;
            let user = authenticate_user(&store, target, target, BRIDGE_USER_ID, committed).await?;
            ensure!(user.leaf_hash != Hash4::ZERO, "bridge user absent at target");
            ensure!(authenticate_policy(&store, target, &user).await? == expected_policy, "bridge policy differs from configuration");
            let mut openings = Vec::with_capacity(config.l1_chains.len());
            for chain in &config.l1_chains {
                let deposit = read_opening(&store, coordinator, target, committed, target, &user, DEPOSIT_CONTRACT, chain.chain_index, false).await?;
                let withdrawal = read_opening(&store, coordinator, target, committed, target, &user, WITHDRAWAL_CONTRACT, chain.chain_index, true).await?;
                openings.push((deposit, withdrawal));
            }
            Ok::<_, anyhow::Error>((user, openings))
        }.await;
        match result {
            Ok(openings) => return Ok(openings),
            Err(error) => failures.push(format!("realm={} sub={}: {error:#}", source.realm_id, source.realm_sub_id)),
        }
    }
    anyhow::bail!("no authenticated target bridge proof source: {}", failures.join("; "))
}

async fn open_coordinator(processors: &[ProcessorConfig]) -> anyhow::Result<Store> {
    let mut found = None;
    for processor in processors {
        if let ProcessorConfig::Coordinator(config) = processor {
            ensure!(found.is_none(), "processor inventory has more than one coordinator");
            found = Some(setup_psy_scylla_database_store_from_connection_string::<Network>(&config.db_namespace, &config.scylla_db_url, false).await?);
        }
    }
    found.context("processor inventory has no coordinator store")
}

async fn authenticate_checkpoint(store: &Store, target: u64, checkpoint: u64, committed: Hash4) -> anyhow::Result<(Hash4, Hash4)> {
    ensure!(checkpoint <= target, "checkpoint is after snapshot target");
    let leaf = store.get_checkpoint_leaf_data(checkpoint).await.context("checkpoint leaf missing")?;
    let roots = store.get_checkpoint_global_state_roots(checkpoint).await.context("checkpoint roots missing")?;
    ensure!(roots.qfhash::<<Network as QNetworkHashTypes>::HasherBase>() == leaf.global_chain_root, "checkpoint roots do not hash to the leaf");
    let proof = store.checkpoint_tree_get_merkle_proof(target, checkpoint).await?;
    let leaf_hash = hash4(leaf.qfhash::<<Network as QNetworkHashTypes>::HasherBase>())?;
    verify_proof(&proof, committed, checkpoint, leaf_hash, usize::from(Network::CHECKPOINT_TREE_HEIGHT))?;
    Ok((leaf_hash, hash4(roots.user_tree_root)?))
}

async fn authenticate_user(store: &Store, target: u64, checkpoint: u64, user_id: u64, committed: Hash4) -> anyhow::Result<UserStateOpening> {
    let (_, root) = authenticate_checkpoint(store, target, checkpoint, committed).await?;
    let leaf = store.get_user_leaf(checkpoint, user_id).await.with_context(|| format!("user {user_id} leaf missing at {checkpoint}"))?;
    ensure!(leaf.user_id.to_u64_value() == user_id, "stored user leaf names another user");
    let user = UserStateOpening { leaf_hash: hash4(leaf.qfhash::<<Network as QNetworkHashTypes>::HasherBase>())?, public_key: hash4(leaf.public_key)?, state_root: hash4(leaf.user_state_tree_root)?, nonce: leaf.nonce.to_u64_value() };
    let proof = user_proof(store, checkpoint, user_id).await?;
    verify_proof(&proof, root, user_id, user.leaf_hash, usize::from(Network::GLOBAL_USER_TREE_HEIGHT))?;
    Ok(user)
}

async fn authenticate_policy(store: &Store, target: u64, user: &UserStateOpening) -> anyhow::Result<psy_vm::ups::multisig::MultisigPolicy> {
    let mut slots = [Hash4::ZERO; 4];
    for slot in 0..4u64 { slots[slot as usize] = proven_slot(store, target, BRIDGE_USER_ID, user, POLICY_CONTRACT, 4, slot).await?; }
    psy_vm::ups::multisig::StoredMultisigPolicy { header: slots[0], members: [slots[1], slots[2], slots[3]] }.policy().context("bridge policy slots are not a policy")
}

async fn read_opening(store: &Store, coordinator: &Store, target: u64, committed: Hash4, checkpoint: u64, user: &UserStateOpening, contract: u32, chain: u8, should_read_frontier: bool) -> anyhow::Result<BridgeChainOpening> {
    let height = contract_height(coordinator, target, committed, checkpoint, contract).await?;
    let target = checkpoint;
    let count_words = read_words(store, target, user, contract, height, CHAIN_COUNT_SLOT + u64::from(chain), 1).await?;
    let count = u32::try_from(count_words[0]).context("chain count does not fit u32")?;
    let root = words_to_hash(&read_words(store, target, user, contract, height, CHAIN_ROOT_SLOT + u64::from(chain) * 8, 8).await?)?;
    let mut nodes = [Hash4::ZERO; 32];
    if should_read_frontier {
        for level in 0..32u64 {
            nodes[level as usize] = words_to_hash(&read_words(store, target, user, contract, height, FRONTIER_BASE_SLOT + (u64::from(chain) * 32 + level) * 8, 8).await?)?;
        }
        ensure!(guardian_common::protocol::frontier_root(count, &nodes) == root || (count == 0 && root == Hash4::ZERO), "withdrawal frontier does not fold to its root");
    }
    Ok(BridgeChainOpening { count, root, frontier: nodes })
}

async fn read_words(store: &Store, target: u64, user: &UserStateOpening, contract: u32, height: u8, start: u64, count: usize) -> anyhow::Result<Vec<u64>> {
    let end = start.checked_add(count as u64).context("slot range overflow")?;
    let mut values = Vec::with_capacity(count);
    let mut slot = start / 4;
    while slot * 4 < end {
        let value = proven_slot(store, target, BRIDGE_USER_ID, user, contract, height, slot).await?;
        for (offset, limb) in value.0.elements.into_iter().enumerate() {
            let position = slot * 4 + offset as u64;
            if (start..end).contains(&position) { values.push(limb.to_canonical_u64()); }
        }
        slot += 1;
    }
    ensure!(values.len() == count, "slot read returned the wrong number of words");
    Ok(values)
}

async fn proven_slot(store: &Store, checkpoint: u64, user_id: u64, user: &UserStateOpening, contract: u32, height: u8, slot: u64) -> anyhow::Result<Hash4> {
    let contract_proof = store.user_contract_tree_get_merkle_proof(checkpoint, user_id, u64::from(contract)).await?;
    let contract_root = hash4(contract_proof.value)?;
    verify_proof(&contract_proof, user.state_root, u64::from(contract), contract_root, usize::from(Network::GLOBAL_CONTRACT_TREE_HEIGHT))?;
    let root = if contract_root == Hash4::ZERO { empty_root_at(height) } else { contract_root };
    let proof = store.contract_state_tree_get_merkle_proof(checkpoint, user_id, u64::from(contract), height, slot).await?;
    let value = hash4(proof.value)?;
    verify_proof(&proof, root, slot, value, usize::from(height))?;
    Ok(value)
}

// Contract definitions and their global-tree proofs live in the coordinator;
// per-user contract state and IMT openings remain in the owning realm store.
async fn contract_height(store: &Store, target: u64, committed: Hash4, checkpoint: u64, contract: u32) -> anyhow::Result<u8> {
    authenticate_checkpoint(store, target, checkpoint, committed).await?;
    let leaf = store.get_contract_leaf(checkpoint, u64::from(contract)).await?;
    let height = leaf.state_tree_height.to_u64_value();
    let roots = store.get_checkpoint_global_state_roots(checkpoint).await?;
    let checkpoint_leaf = store.get_checkpoint_leaf_data(checkpoint).await?;
    ensure!(roots.qfhash::<<Network as QNetworkHashTypes>::HasherBase>() == checkpoint_leaf.global_chain_root, "contract global roots disagree with checkpoint");
    let proof = store.global_contract_tree_get_merkle_proof(checkpoint, u64::from(contract)).await?;
    verify_proof(&proof, hash4(roots.contract_tree_root)?, u64::from(contract), hash4(leaf.qfhash::<<Network as QNetworkHashTypes>::HasherBase>())?, usize::from(Network::GLOBAL_CONTRACT_TREE_HEIGHT))?;
    let expected = match contract {
        DEPOSIT_CONTRACT => u64::from(psy_config::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT),
        WITHDRAWAL_CONTRACT => u64::from(psy_config::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT),
        TOKEN_CONTRACT => u64::from(psy_config::TOKEN_CONTRACT_STATE_TREE_HEIGHT),
        USDT_CONTRACT => u64::from(psy_config::USDT_TOKEN_CONTRACT_STATE_TREE_HEIGHT),
        POLICY_CONTRACT => 4,
        _ => anyhow::bail!("unsupported contract {contract}"),
    };
    ensure!(height == expected, "contract {contract} state height is not the compiled height");
    u8::try_from(height).context("contract height exceeds u8")
}

async fn prove_deposits(chain: &guardian_common::protocol::ChainEndpoint, count: u32, expected: Hash4) -> anyhow::Result<DepositTreeState> {
    let scan = finalized_deposit_anchor(chain, 0, count).await.map_err(|error| anyhow::anyhow!("deposit scan failed: {error:?}"))?;
    let (_old, root, mut state) = verify_deposit_anchor(None, chain, &scan).await.map_err(|error| anyhow::anyhow!("deposit fold failed: {error:?}"))?;
    ensure!(root == expected && state.root == expected && state.count == count && state.previous_count == 0 && state.event_block <= scan.block_number, "deposit fold does not match L2");
    ensure!(state.event_block >= chain.deployment_block, "latest included deposit block precedes deployment");
    let mut anchor = DepositAnchor { chain_index: chain.chain_index, block_number: state.event_block, block_hash: scan.block_hash, old_count: 0, new_count: count };
    anchor.block_hash = verify_saved_deposit_anchor_headers(chain, &anchor).await.map_err(|error| anyhow::anyhow!("included deposit header failed: {error:?}"))?;
    state.anchor = anchor;
    state.validate().map_err(|error| anyhow::anyhow!("pinned deposit snapshot is invalid: {error:?}"))?;
    Ok(state)
}

// A burn identity is proven by its full record. A verbatim repeat is the same
// burn authenticated again and keeps its first checkpoint, so append matching
// (burn checkpoint <= append checkpoint) stays monotone. Any field difference
// at the same identity is a second, conflicting burn event and fails closed.
type BurnIdentity = (u32, u32, [u32; 8]);

fn record_authenticated_burn(burns: &mut BTreeMap<BurnIdentity, (WithdrawalBurnRecord, u64, u64)>, burn: WithdrawalBurnRecord, checkpoint: u64, nonce: u64) -> anyhow::Result<()> {
    let key: BurnIdentity = (burn.sender_user_id, burn.token_contract_id, burn.nonce);
    if let Some((previous, _, _)) = burns.get(&key) {
        ensure!(*previous == burn, "conflicting burn events share identity sender={} token_contract={}", burn.sender_user_id, burn.token_contract_id);
        return Ok(());
    }
    burns.insert(key, (burn, checkpoint, nonce));
    Ok(())
}

async fn included_withdrawals(store: &Store, processors: &[ProcessorConfig], target: u64, committed: Hash4, bridge_nonce: u64, chain_indexes: &[u8]) -> anyhow::Result<Vec<IncludedWithdrawal>> {
    let mut replicas = BTreeMap::new();
    for processor in processors {
        if let ProcessorConfig::Realm(config) = processor { replicas.entry(config.realm_id).or_insert_with(Vec::new).push(config); }
    }
    let mut burns = BTreeMap::new();
    let mut appends = BTreeMap::new();
    let mut append_order = BTreeMap::new();
    for (realm_id, configs) in replicas {
        let mut sources = Vec::new();
        let mut unavailable = Vec::new();
        for config in configs {
            match setup_psy_scylla_database_store_from_connection_string::<Network>(&config.db_namespace, &config.scylla_db_url, false).await {
                Ok(source) => sources.push((config, source)),
                Err(error) => unavailable.push(format!("realm={realm_id} sub={} store open: {error:#}", config.realm_sub_id)),
            }
        }
        let mut before = authenticated_realm_root(store, target, 0, realm_id, committed).await?;
        for checkpoint in 1..=target {
            let after = authenticated_realm_root(store, target, checkpoint, realm_id, committed).await?;
            if before == after { continue; }
            let mut selected = None;
            let mut failures = unavailable.clone();
            for (config, source) in &sources {
                let result = authenticate_archive_source(store, source, config, target, committed, checkpoint, before, after, bridge_nonce, chain_indexes).await;
                match result {
                    Ok(candidate) => accept_archive(&mut selected, candidate)
                        .with_context(|| format!("realm={realm_id} checkpoint={checkpoint} replica conflict"))?,
                    Err(error) => failures.push(format!("realm={realm_id} sub={} checkpoint={checkpoint}: {error:#}", config.realm_sub_id)),
                }
            }
            let selected = require_archive(selected, &failures)
                .with_context(|| format!("changed realm={realm_id} checkpoint={checkpoint} lacks coverage"))?;
            // No rejected source can mutate these cross-checkpoint accumulators.
            for candidate in selected.candidates {
                match candidate.kind {
                    CandidateKind::Burn { burn, nonce, .. } => record_authenticated_burn(&mut burns, burn, candidate.checkpoint, nonce)?,
                    CandidateKind::Append { chain, index, leaf, chain_root, global_root, nonce, .. } => {
                        let order = (candidate.checkpoint, nonce, candidate.event_index);
                        ensure!(append_order.insert(order, (chain, index, leaf, chain_root, global_root)).is_none(), "duplicate append event identity");
                        ensure!(appends.insert((chain, index), (leaf, nonce, candidate.checkpoint)).is_none(), "duplicate append index");
                    }
                }
            }
            before = after;
        }
    }
    // Mandatory global acceptance barriers: a transcript with omitted/retyped
    // append bodies cannot pass the final contiguous T count/frontier fold.
    validate_append_roots(&append_order)?;
    let mut included = Vec::new();
    for ((chain, index), (leaf, nonce, append_checkpoint)) in appends {
        let matched = burns.values().filter(|(burn, checkpoint, _)| guardian_common::protocol::withdrawal_tree_leaf(burn) == leaf && burn.destination_chain_index == chain && *checkpoint <= append_checkpoint).collect::<Vec<_>>();
        ensure!(matched.len() == 1, "append on chain {chain} index {index} does not have exactly one authenticated burn");
        // Both historical and T membership were verified using the accepted
        // archive's own source before it entered the shared burn map.
        included.push(IncludedWithdrawal { record: WithdrawalAppendRecord { chain_index: chain, append_index: index, burn: matched[0].0.clone() }, session_nonce: nonce });
    }
    Ok(included)
}

async fn authenticate_archive_source(coordinator: &Store, realm: &Store, config: &psy_node_core::config::node_start_config::RealmProcessorStartConfig, target: u64, committed: Hash4, checkpoint: u64, previous_root: Hash4, committed_root: Hash4, bridge_nonce: u64, chain_indexes: &[u8]) -> anyhow::Result<AuthenticatedArchive> {
    ensure!(realm.get_latest_checkpoint_id().await? >= target, "realm store marker behind target");
    let (pending, proc_id) = realm.get_unique_pending_id_for_checkpoint_id(checkpoint).await?.context("checkpoint has no local pending mapping")?;
    let result = async {
        ensure!(realm.get_checkpoint_id_for_unique_pending_id(pending).await? == Some(checkpoint), "checkpoint/pending mappings disagree");
        ensure!(realm.get_proc_checkpoint_unique_id_for_pending_id(pending).await? == Some(proc_id), "pending processor identity disagrees");
        let bytes = std::fs::read(get_new_realm_end_cap_gatherer_backup_file_path(&config.get_guta_updates_backup_path(), config.realm_id, u64::from(config.realm_sub_id), pending)).context("mapped archive missing")?;
        let footer_size = GlobalUserTreeAggregatorHeaderWithJobId::<Felt, NodeHash>::FIXED_SIZE;
        ensure!(bytes.len() >= 76 + footer_size, "truncated archive header/footer");
        let end_root = hash4(NodeHash::from_owned_32bytes(bytes[36..68].try_into()?))?;
        ensure!(end_root == committed_root, "local archive end root is not committed transition");
        let start_root = hash4(NodeHash::from_owned_32bytes(bytes[4..36].try_into()?))?;
        ensure!(start_root == previous_root, "archive start root does not match preceding committed realm root");
        let footer = read_value::<GlobalUserTreeAggregatorHeaderWithJobId<Felt, NodeHash>>(&bytes[bytes.len() - footer_size..])?;
        let (_, user_root) = authenticate_checkpoint(coordinator, target, checkpoint, committed).await?;
        let top = realm.get_top_global_user_tree_proof_to_realm_root_at_checkpoint_id(checkpoint).await?;
        verify_proof(&top, user_root, config.realm_id, end_root, usize::from(Network::COORDINATOR_GLOBAL_USER_TREE_HEIGHT))?;
        let proof_checkpoint = coordinator.get_checkpoint_id_for_checkpoint_root_hash(footer.header.checkpoint_tree_root).await?.context("footer checkpoint root unmapped")?;
        ensure!(proof_checkpoint < checkpoint, "archive proof checkpoint is not before inclusion");
        bind_checkpoint(coordinator, target, proof_checkpoint, committed).await?;
        ensure!(coordinator.checkpoint_tree_get_root_hash(proof_checkpoint).await? == footer.header.checkpoint_tree_root, "footer checkpoint mapping disagrees");
        ensure!(authenticated_realm_root(coordinator, target, proof_checkpoint, config.realm_id, committed).await? == start_root, "proof-base realm root does not authenticate archive start");
        let context = ArchiveContext { chain: config.network.get_chain_id(), realm: config.realm_id, sub: u64::from(config.realm_sub_id), pending, checkpoint, proof_checkpoint };
        let archive = parse_archive(&bytes, &context, &footer, start_root, end_root, coordinator, realm, target, committed).await.context("queue/finalizer replay")?;
        validate_session_appends(realm, coordinator, target, committed, proof_checkpoint, checkpoint, &archive, chain_indexes).await.context("append session authentication")?;
        for candidate in &archive.candidates {
            match &candidate.kind {
                CandidateKind::Burn { burn, nonce, leaf_hash } => {
                    let sender = authenticate_user(realm, target, checkpoint, u64::from(burn.sender_user_id), committed).await?;
                    ensure!(sender.leaf_hash == *leaf_hash && sender.nonce == *nonce, "burn sender disagrees with archive");
                    authenticate_membership(realm, coordinator, target, burn, checkpoint, committed).await.context("burn historical/T membership")?;
                }
                CandidateKind::Append { nonce, leaf_hash, .. } => {
                    let bridge = authenticate_user(realm, target, checkpoint, BRIDGE_USER_ID, committed).await?;
                    ensure!(bridge.leaf_hash == *leaf_hash && bridge.nonce == *nonce && *nonce <= bridge_nonce, "append bridge identity disagrees");
                }
            }
        }
        Ok(archive)
    }.await;
    result.with_context(|| format!("mapped archive pending={pending}"))
}

async fn authenticate_membership(store: &Store, coordinator: &Store, target: u64, burn: &WithdrawalBurnRecord, checkpoint: u64, committed: Hash4) -> anyhow::Result<()> {
    ensure!(matches!(burn.token_contract_id, TOKEN_CONTRACT | USDT_CONTRACT), "burn token contract is not a token contract");
    burn.amount_u64().map_err(|error| anyhow::anyhow!("burn amount is not canonical: {error:?}"))?;
    let sender = authenticate_user(store, target, checkpoint, u64::from(burn.sender_user_id), committed).await?;
    let key = withdrawal_key(burn)?;
    let index = store.contract_state_imt_get_leaf_index_for_key(checkpoint, u64::from(burn.sender_user_id), u64::from(burn.token_contract_id), &node_hash(key)?).await?.context("withdrawal key is absent")?;
    let base = WITHDRAWAL_MAP_BASE / 4;
    ensure!((base + 1..=base + WITHDRAWAL_MAP_CAPACITY).contains(&index), "membership index is outside the token map");
    let hash = membership_hash(store, checkpoint, burn, index, &key).await?;
    let height = contract_height(coordinator, target, committed, checkpoint, burn.token_contract_id).await?;
    ensure!(proven_slot(store, checkpoint, u64::from(burn.sender_user_id), &sender, burn.token_contract_id, height, index).await? == hash, "membership preimage is not the proven slot");
    let sender_at_target = authenticate_user(store, target, target, u64::from(burn.sender_user_id), committed).await?;
    let target_hash = membership_hash(store, target, burn, index, &key).await?;
    let target_height = contract_height(coordinator, target, committed, target, burn.token_contract_id).await?;
    ensure!(proven_slot(store, target, u64::from(burn.sender_user_id), &sender_at_target, burn.token_contract_id, target_height, index).await? == target_hash, "membership at T is not the proven sender slot");
    Ok(())
}

async fn membership_hash(store: &Store, checkpoint: u64, burn: &WithdrawalBurnRecord, index: u64, key: &Hash4) -> anyhow::Result<Hash4> {
    let current = store.contract_state_imt_get_leaf_index_for_key(checkpoint, u64::from(burn.sender_user_id), u64::from(burn.token_contract_id), &node_hash(*key)?).await?.context("withdrawal key is absent")?;
    ensure!(current == index, "withdrawal key index changed");
    let preimage = store.contract_state_imt_get_leaf_preimage(checkpoint, u64::from(burn.sender_user_id), u64::from(burn.token_contract_id), index).await?.context("membership preimage missing")?;
    ensure!(hash4(preimage.key)? == *key && hash4(preimage.value)? == guardian_common::protocol::withdrawal_tree_leaf(burn), "membership key or value does not match the burn");
    let next = preimage.next_index.to_u64_value();
    let base = WITHDRAWAL_MAP_BASE / 4;
    ensure!(next == 0 || (base + 1..=base + WITHDRAWAL_MAP_CAPACITY).contains(&next), "membership successor is outside the token map");
    Ok(hash4(preimage.qfhash::<<Network as QNetworkHashTypes>::HasherBase>())?)
}

async fn bind_checkpoint(store: &Store, target: u64, checkpoint: u64, committed: Hash4) -> anyhow::Result<()> {
    authenticate_checkpoint(store, target, checkpoint, committed).await?;
    Ok(())
}

struct ArchiveContext { chain: u64, realm: u64, sub: u64, pending: u64, checkpoint: u64, proof_checkpoint: u64 }

async fn parse_archive(bytes: &[u8], context: &ArchiveContext, footer_header: &GlobalUserTreeAggregatorHeaderWithJobId<Felt, NodeHash>, start_root: Hash4, end_root: Hash4, coordinator: &Store, realm: &Store, target: u64, committed: Hash4) -> anyhow::Result<AuthenticatedArchive> {
    let footer = GlobalUserTreeAggregatorHeaderWithJobId::<Felt, NodeHash>::FIXED_SIZE;
    ensure!(bytes.len() >= 76 + footer && u32::from_le_bytes(bytes[..4].try_into().unwrap()) == REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32, "end-cap archive header is not RGE1");
    let expected = u64::from_le_bytes(bytes[68..76].try_into().unwrap());
    let mut cursor = Cursor::new(&bytes[76..bytes.len() - footer]);
    ensure!(expected <= cursor.get_ref().len() as u64 / 244, "archive queue count exceeds its size");
    if expected == 0 {
        ensure!(start_root == end_root && cursor.get_ref().is_empty(), "empty archive changes realm root");
        return Ok(AuthenticatedArchive { candidates: Vec::new(), transcript: ArchiveTranscript::default() });
    }
    let transition = &footer_header.header.state_transition;
    ensure!(hash4(transition.old_node_value)? == start_root && hash4(transition.new_node_value)? == end_root, "footer transition disagrees with archive roots");
    ensure!(transition.node_index.to_u64_value() == context.realm && transition.node_level.to_u64_value() == u64::from(Network::COORDINATOR_GLOBAL_USER_TREE_HEIGHT), "footer transition names another realm");
    ensure!(footer_header.job_id == QProvingJobDataID::realm_finalize_guta(context.proof_checkpoint, u32::try_from(context.realm)?), "footer job identity disagrees");
    let mut owners = BTreeSet::new();
    let mut candidates = Vec::new();
    let mut transcript = ArchiveTranscript::default();
    let validator = authenticated_archive_validator(coordinator, context).await?;
    let mut replay = parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore::<<Network as QNetworkHashTypes>::HasherBase, NodeHash>::new(Network::REALM_GLOBAL_USER_TREE_HEIGHT);
    let mut updates = Vec::new();
    for _ in 0..expected {
        let job = QProvingJobDataID::try_from_byte_vec(&read_fixed::<24>(&mut cursor)?)?;
        let submission_nonce = u64::from_le_bytes(read_fixed(&mut cursor)?);
        let old_hash = hash4(NodeHash::from_owned_32bytes(read_fixed(&mut cursor)?))?;
        let new_hash = hash4(NodeHash::from_owned_32bytes(read_fixed(&mut cursor)?))?;
        let user_leaf = PQEDUserLeaf::<Felt, NodeHash>::pio_read_from_io(&mut cursor).context("truncated user leaf")?;
        let owner = user_leaf.user_id.to_u64_value();
        let nonce = user_leaf.nonce.to_u64_value();
        let leaf_hash = hash4(user_leaf.qfhash::<<Network as QNetworkHashTypes>::HasherBase>())?;
        ensure!(owner >> Network::REALM_GLOBAL_USER_TREE_HEIGHT == context.realm && owners.insert(owner), "queue user outside realm or repeated");
        ensure!(job == QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(owner, Network::GLOBAL_USER_TREE_HEIGHT, context.pending)?, "queue job identity disagrees with mapped archive");
        ensure!(new_hash == leaf_hash, "queue new hash does not hash its user leaf");
        let (_, old_root) = authenticate_checkpoint(coordinator, target, context.proof_checkpoint, committed).await?;
        let old_proof = user_proof(realm, context.proof_checkpoint, owner).await?;
        verify_proof(&old_proof, old_root, owner, old_hash, usize::from(Network::GLOBAL_USER_TREE_HEIGHT))?;
        let old_event_index = if old_hash == Hash4::ZERO {
            ensure!(nonce == 1, "first user session nonce is not one");
            0
        } else {
            let old_leaf = realm.get_user_leaf(context.proof_checkpoint, owner).await?;
            ensure!(hash4(old_leaf.qfhash::<<Network as QNetworkHashTypes>::HasherBase>())? == old_hash && old_leaf.nonce.to_u64_value().checked_add(1) == Some(nonce), "queue old preimage or nonce disagrees");
            old_leaf.event_index.to_u64_value()
        };
        let mut local_proof = realm.global_user_tree_get_merkle_proof_sub_tree(context.proof_checkpoint, Network::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, Network::GLOBAL_USER_TREE_HEIGHT, owner).await?;
        local_proof.index = owner & ((1u64 << Network::REALM_GLOBAL_USER_TREE_HEIGHT) - 1);
        ensure!(hash4(local_proof.root)? == start_root && hash4(local_proof.value)? == old_hash && local_proof.verify::<<Network as QNetworkHashTypes>::HasherBase>(), "queue old path does not reach archive start");
        replay.injest_merkle_proof_into_nodes(&local_proof)?;
        let mut ending_leaf = user_leaf.clone();
        if owner == validator {
            apply_validator_fee(&mut ending_leaf, footer_header.header.stats.da_fees_collected.to_u64_value(), context.proof_checkpoint)?;
        }
        let ending_hash = hash4(ending_leaf.qfhash::<<Network as QNetworkHashTypes>::HasherBase>())?;
        let current = authenticate_user(realm, target, context.checkpoint, owner, committed).await?;
        ensure!(current.leaf_hash == ending_hash && current.nonce == nonce, "queue ending user including finalizer is not authenticated");
        updates.push((local_proof.index, ending_leaf.qfhash::<<Network as QNetworkHashTypes>::HasherBase>()));
        ensure!(user_leaf.last_checkpoint_id.to_u64_value() <= context.proof_checkpoint, "queue proving checkpoint exceeds archive proof base");
        skip(&mut cursor, 40)?;
        let event_count = read_u32(&mut cursor)?;
        ensure!(event_count <= (cursor.get_ref().len() - cursor.position() as usize) / 44, "event count exceeds remaining bytes");
        let first_event = user_leaf.event_index.to_u64_value().checked_sub(event_count as u64).context("event count exceeds user event index")?;
        ensure!(first_event == old_event_index, "archive omits part of authenticated user event range");
        transcript.sessions.insert((owner, nonce), (old_event_index, user_leaf.event_index.to_u64_value(), ending_hash));
        for offset in 0..event_count {
            let event = read_event(&mut cursor)?;
            ensure!(event.user_id.to_u64_value() == owner, "event user is not the end-cap user");
            ensure!(event.event_index.to_u64_value() == first_event + offset as u64 && event.checkpoint_id.to_u64_value() <= context.proof_checkpoint, "event metadata disagrees with authenticated queue user");
            ensure!(transcript.events.insert((owner, nonce, event.event_index.to_u64_value()), (event.checkpoint_id.to_u64_value(), event.contract_id.to_u64_value(), event.method_id.to_u64_value(), event.data.iter().map(ToU64Value::to_u64_value).collect())).is_none(), "duplicate transcript event");
            if let Some(kind) = decode_event(event.contract_id.to_u64_value(), event.method_id.to_u64_value(), owner, nonce, ending_hash, &event.data)? {
                candidates.push(Candidate { kind, checkpoint: context.checkpoint, event_index: event.event_index.to_u64_value() });
            }
        }
        for (blob, tree) in [(QBlobDataType::GenericSingleIdMerkleNodeBatch, QBlobMerkleNodeTreeType::UserContractTree), (QBlobDataType::GenericDoubleIdMerkleNodeBatch, QBlobMerkleNodeTreeType::UserContractStateTree), (QBlobDataType::GenericIMTLeafBatch, QBlobMerkleNodeTreeType::IMTContractStateLeaf)] {
            skip_qblob(&mut cursor, blob, tree, context, owner, submission_nonce)?;
        }
    }
    if !owners.contains(&validator) {
        let mut leaf = realm.get_user_leaf(context.proof_checkpoint, validator).await?;
        let old = authenticate_user(realm, target, context.proof_checkpoint, validator, committed).await?;
        let mut proof = realm.global_user_tree_get_merkle_proof_sub_tree(context.proof_checkpoint, Network::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, Network::GLOBAL_USER_TREE_HEIGHT, validator).await?;
        proof.index = validator & ((1u64 << Network::REALM_GLOBAL_USER_TREE_HEIGHT) - 1);
        ensure!(hash4(proof.root)? == start_root && hash4(proof.value)? == old.leaf_hash && proof.verify::<<Network as QNetworkHashTypes>::HasherBase>(), "finalizer old path mismatch");
        replay.injest_merkle_proof_into_nodes(&proof)?;
        apply_validator_fee(&mut leaf, footer_header.header.stats.da_fees_collected.to_u64_value(), context.proof_checkpoint)?;
        let current = authenticate_user(realm, target, context.checkpoint, validator, committed).await?;
        ensure!(current.leaf_hash == hash4(leaf.qfhash::<<Network as QNetworkHashTypes>::HasherBase>())?, "finalizer fee transition mismatch");
        updates.push((proof.index, leaf.qfhash::<<Network as QNetworkHashTypes>::HasherBase>()));
    }
    ensure!(hash4(replay.get_root())? == start_root, "queue paths disagree on archive start root");
    for (index, hash) in updates { replay.set_leaf(index, hash); }
    ensure!(hash4(replay.get_root())? == end_root, "archive queue and finalizer do not reproduce committed realm root");
    ensure!(cursor.position() == cursor.get_ref().len() as u64, "archive has trailing bytes before its footer");
    Ok(AuthenticatedArchive { candidates, transcript })
}

async fn authenticated_archive_validator(store: &Store, context: &ArchiveContext) -> anyhow::Result<u64> {
    ensure!(context.sub < 256, "validator sub-id exceeds tree slot");
    let index = (context.realm << 8) | context.sub;
    let preimage = store.validator_tree_get_leaf_preimage(context.proof_checkpoint, index).await?.context("archive validator preimage missing")?;
    ensure!(preimage.chain_id == context.chain && u64::from(preimage.realm_id) == context.realm && u64::from(preimage.realm_sub_id) == context.sub, "archive validator identity mismatch");
    let roots = store.get_checkpoint_global_state_roots(context.proof_checkpoint).await?;
    let proof = store.validator_tree_get_merkle_proof(context.proof_checkpoint, index).await?;
    let hash = hash4(NodeHash::from_owned_32bytes(preimage.leaf_hash()?))?;
    verify_proof(&proof, hash4(roots.validator_tree_root)?, index, hash, psy_data::guta::realm_finalize::VALIDATOR_TREE_HEIGHT as usize)?;
    ensure!(preimage.validator_user_id >> Network::REALM_GLOBAL_USER_TREE_HEIGHT == context.realm, "validator user is outside archive realm");
    Ok(preimage.validator_user_id)
}

fn apply_validator_fee(leaf: &mut PQEDUserLeaf<Felt, NodeHash>, fee: u64, checkpoint: u64) -> anyhow::Result<()> {
    use parth_core::felt::FromPrimitiveValuesFelt;
    let balance = leaf.balance.to_u64_value().checked_add(fee).filter(|balance| *balance < 1u64 << 60).context("validator fee balance overflow")?;
    leaf.balance = Felt::from_u64_value(balance);
    if fee != 0 { leaf.last_checkpoint_id = Felt::from_u64_value(checkpoint); }
    Ok(())
}

async fn validate_session_appends(store: &Store, coordinator: &Store, target: u64, committed: Hash4, before: u64, after: u64, archive: &AuthenticatedArchive, chain_indexes: &[u8]) -> anyhow::Result<()> {
    if !archive.transcript.sessions.keys().any(|(owner, _)| *owner == BRIDGE_USER_ID) { return Ok(()); }
    let mut chains = BTreeMap::<u8, Vec<(u32, Hash4, Hash4)>>::new();
    for candidate in &archive.candidates {
        if let CandidateKind::Append { chain, index, leaf, chain_root, .. } = &candidate.kind {
            chains.entry(*chain).or_default().push((*index, *leaf, *chain_root));
        }
    }
    ensure!(chains.keys().all(|chain| chain_indexes.contains(chain)), "archive appends name an unconfigured chain");
    for chain in chain_indexes { chains.entry(*chain).or_default(); }
    let (_, old_root) = authenticate_checkpoint(store, target, before, committed).await?;
    let old_path = user_proof(store, before, BRIDGE_USER_ID).await?;
    let old_hash = hash4(old_path.value)?;
    verify_proof(&old_path, old_root, BRIDGE_USER_ID, old_hash, usize::from(Network::GLOBAL_USER_TREE_HEIGHT))?;
    let old = if old_hash == Hash4::ZERO { None } else { Some(authenticate_user(store, target, before, BRIDGE_USER_ID, committed).await?) };
    let new = authenticate_user(store, target, after, BRIDGE_USER_ID, committed).await?;
    ensure!(old.as_ref().map_or(Some(1), |user| user.nonce.checked_add(1)) == Some(new.nonce), "archive does not identify exactly one bridge session");
    for (chain, appends) in chains {
        // Proven user nonmembership implies no contract state, hence the pristine
        // append frontier. This is a derived initial condition, not a stored leaf.
        let mut opening = match &old {
            Some(user) => read_opening(store, coordinator, target, committed, before, user, WITHDRAWAL_CONTRACT, chain, true).await?,
            None => BridgeChainOpening { count: 0, root: empty_root(), frontier: [Hash4::ZERO; 32] },
        };
        let ending = read_opening(store, coordinator, target, committed, after, &new, WITHDRAWAL_CONTRACT, chain, true).await?;
        for (index, leaf, claimed_root) in appends {
            ensure!(index == opening.count, "append index not in authenticated session prefix");
            opening.root = guardian_common::protocol::append_merkle_leaf(&mut opening.frontier, index, leaf);
            ensure!(opening.root == claimed_root, "session intermediate root mismatch");
            opening.count = opening.count.checked_add(1).context("session append count overflow")?;
        }
        let roots_equal = opening.root == ending.root || (opening.count == 0 && ending.count == 0 && [Hash4::ZERO, empty_root()].contains(&opening.root) && [Hash4::ZERO, empty_root()].contains(&ending.root));
        ensure!(opening.count == ending.count && roots_equal && opening.frontier == ending.frontier, "session appends do not reproduce authenticated ending state");
    }
    Ok(())
}

fn decode_event(contract: u64, method: u64, owner: u64, nonce: u64, leaf_hash: Hash4, data: &[Felt]) -> anyhow::Result<Option<CandidateKind>> {
    let words = data.iter().map(ToU64Value::to_u64_value).collect::<Vec<_>>();
    if (contract == u64::from(TOKEN_CONTRACT) || contract == u64::from(USDT_CONTRACT)) && method == WITHDRAW_METHOD {
        ensure!(words.len() == 34, "burn event does not have 34 words");
        let sender = u32::try_from(words[0]).context("burn sender does not fit u32")?;
        ensure!(u64::from(sender) == owner, "burn sender is not the end-cap user");
        return Ok(Some(CandidateKind::Burn { burn: WithdrawalBurnRecord { sender_user_id: sender, token_contract_id: contract as u32, destination_chain_index: u8::try_from(words[1])?, token: word8(&words[2..10])?, amount: word8(&words[10..18])?, recipient: word8(&words[18..26])?, nonce: word8(&words[26..34])? }, nonce, leaf_hash }));
    }
    if contract == u64::from(WITHDRAWAL_CONTRACT) && APPEND_METHODS.contains(&method) {
        ensure!(words.len() == 26 && owner == BRIDGE_USER_ID, "append event is not owned by the bridge user");
        return Ok(Some(CandidateKind::Append { chain: u8::try_from(words[0])?, index: u32::try_from(words[1])?, leaf: words_to_hash(&words[2..10])?, chain_root: words_to_hash(&words[10..18])?, global_root: word8(&words[18..26])?, nonce, leaf_hash }));
    }
    Ok(None)
}

fn skip_qblob(cursor: &mut Cursor<&[u8]>, blob: QBlobDataType, tree: QBlobMerkleNodeTreeType, context: &ArchiveContext, owner: u64, submission_nonce: u64) -> anyhow::Result<()> {
    let start = usize::try_from(cursor.position())?;
    let header_end = start.checked_add(QBLOB_TREE_NODE_BATCH_HEADER_SIZE).context("qblob header overflow")?;
    let header = QBlobMerkleTreeNodeBatchHeaderV1::try_read_header_from_slice(cursor.get_ref().get(start..header_end).context("truncated qblob header")?)?;
    let item_size = psy_node_core::qblob::blob_type::get_item_size_for_data_type(blob).context("unknown qblob item size")?;
    let size = usize::try_from(header.item_count)?.checked_mul(item_size).and_then(|size| size.checked_add(QBLOB_TREE_NODE_BATCH_HEADER_SIZE)).context("qblob count overflow")?;
    ensure!(usize::try_from(header.total_size)? == size, "qblob size/count mismatch");
    let end = start.checked_add(size).context("qblob offset overflow")?;
    let full = cursor.get_ref().get(start..end).context("truncated qblob payload")?;
    let (header, _) = QBlobMerkleTreeNodeBatchHeaderV1::clip_header_get_payload_for_blob_type_and_tree_ref(full, blob, tree, true)?;
    // The edge producer finalizes single/double blobs with the submission token,
    // but constructs the IMT header with new_imt_leaf_header (checkpoint_id = 0).
    let expected_checkpoint = match blob {
        QBlobDataType::GenericIMTLeafBatch => 0,
        _ => submission_nonce,
    };
    ensure!(header.is_valid_for_realm_context(context.chain, context.realm, context.sub, context.pending) && header.for_target_id == owner && header.checkpoint_id == expected_checkpoint,
        "qblob context disagrees with queue job: type={blob:?} chain_matches={} realm_matches={} sub_matches={} pending_matches={} owner_matches={} checkpoint_field_matches={}",
        header.chain_id == context.chain, header.realm_id == context.realm, header.realm_sub_id == context.sub,
        header.unique_pending_id == context.pending, header.for_target_id == owner, header.checkpoint_id == expected_checkpoint);
    cursor.set_position(end as u64);
    Ok(())
}

fn read_fixed<const N: usize>(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<[u8; N]> {
    let mut bytes = [0; N];
    std::io::Read::read_exact(cursor, &mut bytes)?;
    Ok(bytes)
}

// Intermediate roots are derived, not trusted event state. Keccak words are not
// Goldilocks field elements and must never pass through words_to_hash.
fn validate_append_roots(appends: &BTreeMap<(u64, u64, u64), (u8, u32, Hash4, Hash4, [u32; 8])>) -> anyhow::Result<()> {
    let mut frontiers = BTreeMap::<u8, (u32, [Hash4; 32])>::new();
    let mut aggregate = [[0u32; 8]; 512];
    for (chain, index, leaf, chain_root, global_root) in appends.values() {
        let (count, frontier) = frontiers.entry(*chain).or_insert((0, [Hash4::ZERO; 32]));
        ensure!(*index == *count, "intermediate append index is not contiguous");
        let derived = guardian_common::protocol::append_merkle_leaf(frontier, *index, *leaf);
        ensure!(derived == *chain_root, "intermediate chain root disagrees with fold");
        *count = count.checked_add(1).context("withdrawal count overflow")?;
        let mut node = 256 + usize::from(*chain);
        let limbs = derived.0.elements.map(|felt| felt.to_canonical_u64());
        aggregate[node] = std::array::from_fn(|i| (limbs[i / 2] >> (32 * (i % 2))) as u32);
        let mut zero = [0; 8];
        for _ in 0..8 {
            let left = node & !1;
            let a = if aggregate[left] == [0; 8] { zero } else { aggregate[left] };
            let b = if aggregate[left + 1] == [0; 8] { zero } else { aggregate[left + 1] };
            node >>= 1;
            aggregate[node] = keccak_words(a, b);
            zero = keccak_words(zero, zero);
        }
        ensure!(aggregate[1] == *global_root, "intermediate global root disagrees with fold");
    }
    Ok(())
}

fn keccak_words(left: [u32; 8], right: [u32; 8]) -> [u32; 8] {
    let mut bytes = [0; 64];
    for (word, chunk) in left.into_iter().chain(right).zip(bytes.chunks_exact_mut(4)) { chunk.copy_from_slice(&word.to_be_bytes()); }
    let digest = alloy_primitives::keccak256(bytes);
    std::array::from_fn(|i| u32::from_be_bytes(digest[i * 4..i * 4 + 4].try_into().unwrap()))
}

async fn committed_root(store: &Store, target: u64) -> anyhow::Result<Hash4> { hash4(store.checkpoint_tree_get_root_hash(target).await?) }
async fn user_proof(store: &Store, checkpoint: u64, user_id: u64) -> anyhow::Result<MerkleProofCore<NodeHash>> {
    let top = store.get_top_global_user_tree_proof_to_realm_root_at_checkpoint_id(checkpoint).await?;
    let bottom = store.global_user_tree_get_merkle_proof_sub_tree(checkpoint, Network::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, Network::GLOBAL_USER_TREE_HEIGHT, user_id).await?;
    ensure!(bottom.index == user_id && bottom.root == top.value && bottom.siblings.len() == usize::from(Network::REALM_GLOBAL_USER_TREE_HEIGHT) && bottom.verify::<<Network as QNetworkHashTypes>::HasherBase>(), "local user proof does not reach authenticated realm root");
    verify_proof(&top, hash4(top.root)?, user_id >> Network::REALM_GLOBAL_USER_TREE_HEIGHT, hash4(top.value)?, usize::from(Network::COORDINATOR_GLOBAL_USER_TREE_HEIGHT))?;
    let mut siblings = bottom.siblings;
    siblings.extend(top.siblings);
    Ok(MerkleProofCore { root: top.root, value: bottom.value, index: user_id, siblings })
}

async fn authenticated_realm_root(store: &Store, target: u64, checkpoint: u64, realm: u64, committed: Hash4) -> anyhow::Result<Hash4> {
    let (_, root) = authenticate_checkpoint(store, target, checkpoint, committed).await?;
    let proof = store.global_user_tree_get_merkle_proof_sub_tree(checkpoint, 0, Network::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, realm).await?;
    let value = hash4(proof.value)?;
    verify_proof(&proof, root, realm, value, usize::from(Network::COORDINATOR_GLOBAL_USER_TREE_HEIGHT))?;
    Ok(value)
}
fn withdrawal_key(record: &WithdrawalBurnRecord) -> anyhow::Result<Hash4> {
    let hashed: NodeHash = <Network as QNetworkHashTypes>::HasherBase::q_hash_many(&record.nonce.map(GoldilocksField::from_canonical_u32));
    let mut namespaced = [GoldilocksField::ZERO; 5];
    namespaced[0] = GoldilocksField::from_canonical_u64(6);
    namespaced[1..].copy_from_slice(&hashed.0.elements);
    hash4(<Network as QNetworkHashTypes>::HasherBase::q_hash_many(&namespaced))
}
fn hash4(hash: NodeHash) -> anyhow::Result<Hash4> {
    let bytes = hash.into_owned_32bytes();
    let limbs = std::array::from_fn(|index| u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap()));
    ensure!(limbs.iter().all(|limb| *limb < guardian_common::protocol::GOLDILOCKS_MODULUS), "node hash limb is not canonical");
    Ok(Hash4::try_from(&limbs)?)
}
fn node_hash(hash: Hash4) -> anyhow::Result<NodeHash> { Ok(NodeHash::from_owned_32bytes(hash.to_le_bytes())) }
fn words_to_hash(words: &[u64]) -> anyhow::Result<Hash4> {
    ensure!(words.len() == 8, "stored hash is not 8 words");
    let mut limbs = [0u64; 4];
    for index in 0..4 {
        limbs[index] = u64::from(u32::try_from(words[index * 2])?) | (u64::from(u32::try_from(words[index * 2 + 1])?) << 32);
        ensure!(limbs[index] < guardian_common::protocol::GOLDILOCKS_MODULUS, "stored hash limb is not canonical");
    }
    Ok(Hash4::try_from(&limbs)?)
}
// Verify in the node hash domain before canonically converting the proven hashes.
fn verify_proof(proof: &MerkleProofCore<NodeHash>, root: Hash4, index: u64, value: Hash4, height: usize) -> anyhow::Result<()> {
    ensure!(height <= 63 && index < (1u64 << height) && proof.siblings.len() == height && proof.index == index && proof.verify::<<Network as QNetworkHashTypes>::HasherBase>() && hash4(proof.root)? == root && hash4(proof.value)? == value, "merkle proof does not authenticate the claimed leaf");
    Ok(())
}
fn empty_root() -> Hash4 { <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(32) }
fn empty_root_at(height: u8) -> Hash4 { <PsyHasher as MerkleZeroHasher<Hash4>>::get_zero_hash(usize::from(height)) }
fn read_value<T: PsyIOReadWrite>(bytes: &[u8]) -> anyhow::Result<T> {
    let mut cursor = Cursor::new(bytes);
    let value = T::pio_read_from_io(&mut cursor)?;
    ensure!(cursor.position() == bytes.len() as u64, "serialized value did not consume its bytes");
    Ok(value)
}
fn read_u32(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<usize> {
    let mut bytes = [0u8; 4];
    std::io::Read::read_exact(cursor, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes) as usize)
}
fn skip(cursor: &mut Cursor<&[u8]>, count: usize) -> anyhow::Result<()> {
    let end = usize::try_from(cursor.position())?.checked_add(count).context("archive offset overflow")?;
    ensure!(end <= cursor.get_ref().len(), "truncated archive segment");
    cursor.set_position(end as u64);
    Ok(())
}
fn word8(words: &[u64]) -> anyhow::Result<[u32; 8]> { let mut out = [0u32; 8]; for (index, word) in words.iter().enumerate() { out[index] = u32::try_from(*word)?; } Ok(out) }
fn read_event(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<PsyUserEventRecord<Felt>> {
    let position = cursor.position() as usize;
    let remaining = cursor.get_ref().len().saturating_sub(position);
    ensure!(remaining >= 44, "truncated contract event");
    let data_len = u32::from_le_bytes(cursor.get_ref()[position + 40..position + 44].try_into().unwrap()) as usize;
    let size = data_len.checked_mul(8).and_then(|size| size.checked_add(44)).context("event size overflow")?;
    ensure!(remaining >= size, "contract event length is outside the archive");
    PsyUserEventRecord::<Felt>::pio_read_from_io(cursor).context("truncated contract event")
}

#[cfg(test)]
mod archive_selection_tests {
    use super::*;

    fn archive(payload: u64) -> AuthenticatedArchive {
        let mut transcript = ArchiveTranscript::default();
        transcript.sessions.insert((BRIDGE_USER_ID, 7), (3, 4, Hash4::ZERO));
        transcript.events.insert((BRIDGE_USER_ID, 7, 3), (11, 3, APPEND_METHODS[0], vec![payload]));
        AuthenticatedArchive { candidates: Vec::new(), transcript }
    }

    #[test]
    fn identical_replica_transcripts_contribute_once() {
        let mut selected = None;
        accept_archive(&mut selected, archive(1)).unwrap();
        accept_archive(&mut selected, archive(1)).unwrap();
        assert_eq!(require_archive(selected, &[]).unwrap().transcript.events.len(), 1);
    }

    #[test]
    fn conflicting_authenticated_payload_fails_without_replacing_selection() {
        let mut selected = None;
        accept_archive(&mut selected, archive(1)).unwrap();
        assert!(accept_archive(&mut selected, archive(2)).is_err());
        assert!(selected.unwrap().transcript == archive(1).transcript);
    }

    #[test]
    fn rejected_source_cannot_supply_coverage_or_pollute_selection() {
        let mut selected = None;
        let rejected: anyhow::Result<AuthenticatedArchive> = Err(anyhow::anyhow!("invalid replay"));
        if let Ok(candidate) = rejected { accept_archive(&mut selected, candidate).unwrap(); }
        assert!(selected.is_none());
        accept_archive(&mut selected, archive(9)).unwrap();
        assert!(require_archive(selected, &["rejected replica".into()]).unwrap().transcript == archive(9).transcript);
    }

    #[test]
    fn no_usable_source_fails_with_context() {
        let error = require_archive(None, &["sub=1 invalid replay".into(), "sub=2 missing file".into()]).err().unwrap();
        let message = error.to_string();
        assert!(message.contains("sub=1 invalid replay") && message.contains("sub=2 missing file"));
    }
    #[test]
    fn conflicting_session_transcripts_fail_even_when_events_match() {
        let transcript = |session_range: (u64, u64)| {
            let mut transcript = ArchiveTranscript::default();
            transcript.sessions.insert((BRIDGE_USER_ID, 7), (session_range.0, session_range.1, Hash4::ZERO));
            transcript.events.insert((BRIDGE_USER_ID, 7, 3), (11, 3, APPEND_METHODS[0], vec![1]));
            transcript
        };
        let mut selected = None;
        accept_archive(&mut selected, AuthenticatedArchive { candidates: Vec::new(), transcript: transcript((3, 4)) }).unwrap();
        assert!(accept_archive(&mut selected, AuthenticatedArchive { candidates: Vec::new(), transcript: transcript((2, 4)) }).is_err());
    }

}

#[cfg(test)]
mod qblob_context_tests {
    use super::*;

    #[test]
    fn imt_uses_constructor_zero_while_node_blobs_require_submission_token() {
        let context = ArchiveContext { chain: 11, realm: 2, sub: 3, pending: 7, checkpoint: 9, proof_checkpoint: 8 };
        let mut imt = QBlobMerkleTreeNodeBatchHeaderV1::new_imt_leaf_header(QBlobMerkleNodeTreeType::IMTContractStateLeaf, 11, 1, 2, 3, 7, 42);
        imt.modify_for_final_count_and_size(psy_node_core::qblob::blob_type::QBLOB_IMT_LEAF_ENTRY_SIZE as u32, 0);
        let bytes = imt.to_bytes_fixed_size_array();
        assert!(skip_qblob(&mut Cursor::new(bytes.as_slice()), QBlobDataType::GenericIMTLeafBatch, QBlobMerkleNodeTreeType::IMTContractStateLeaf, &context, 42, 123).is_ok());
        imt.checkpoint_id = 123;
        let bytes = imt.to_bytes_fixed_size_array();
        assert!(skip_qblob(&mut Cursor::new(bytes.as_slice()), QBlobDataType::GenericIMTLeafBatch, QBlobMerkleNodeTreeType::IMTContractStateLeaf, &context, 42, 123).is_err());
        let mut single = QBlobMerkleTreeNodeBatchHeaderV1::new_single_id_header(QBlobMerkleNodeTreeType::UserContractTree, 11, 1, 2, 3, 7, 42);
        single.modify_for_final_count_and_size(single.item_size, 0);
        let bytes = single.to_bytes_fixed_size_array();
        assert!(skip_qblob(&mut Cursor::new(bytes.as_slice()), QBlobDataType::GenericSingleIdMerkleNodeBatch, QBlobMerkleNodeTreeType::UserContractTree, &context, 42, 123).is_err());
        single.checkpoint_id = 123;
        let bytes = single.to_bytes_fixed_size_array();
        assert!(skip_qblob(&mut Cursor::new(bytes.as_slice()), QBlobDataType::GenericSingleIdMerkleNodeBatch, QBlobMerkleNodeTreeType::UserContractTree, &context, 42, 123).is_ok());
    }
    #[test]
    fn qblob_rejects_foreign_chain_and_realm_identity() {
        let context = ArchiveContext { chain: 11, realm: 2, sub: 3, pending: 7, checkpoint: 9, proof_checkpoint: 8 };
        let header = |chain: u64, realm: u64| {
            let mut header = QBlobMerkleTreeNodeBatchHeaderV1::new_imt_leaf_header(QBlobMerkleNodeTreeType::IMTContractStateLeaf, chain, 1, realm, 3, 7, 42);
            header.modify_for_final_count_and_size(psy_node_core::qblob::blob_type::QBLOB_IMT_LEAF_ENTRY_SIZE as u32, 0);
            header.to_bytes_fixed_size_array()
        };
        assert!(skip_qblob(&mut Cursor::new(header(11, 2).as_slice()), QBlobDataType::GenericIMTLeafBatch, QBlobMerkleNodeTreeType::IMTContractStateLeaf, &context, 42, 123).is_ok());
        let foreign_chain = skip_qblob(&mut Cursor::new(header(12, 2).as_slice()), QBlobDataType::GenericIMTLeafBatch, QBlobMerkleNodeTreeType::IMTContractStateLeaf, &context, 42, 123).err().unwrap();
        assert!(foreign_chain.to_string().contains("qblob context disagrees with queue job"));
        let foreign_realm = skip_qblob(&mut Cursor::new(header(11, 5).as_slice()), QBlobDataType::GenericIMTLeafBatch, QBlobMerkleNodeTreeType::IMTContractStateLeaf, &context, 42, 123).err().unwrap();
        assert!(foreign_realm.to_string().contains("qblob context disagrees with queue job"));
    }
}

#[cfg(test)]
mod archive_fold_tests {
    use super::*;

    fn burn_record() -> WithdrawalBurnRecord {
        WithdrawalBurnRecord {
            sender_user_id: 5, token_contract_id: TOKEN_CONTRACT, destination_chain_index: 1,
            token: [3; 8], amount: [1, 0, 0, 0, 0, 0, 0, 0], recipient: [4; 8], nonce: [9, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    fn row(append_index: u32, burn: &WithdrawalBurnRecord) -> IncludedWithdrawal {
        IncludedWithdrawal { record: WithdrawalAppendRecord { chain_index: 1, append_index, burn: burn.clone() }, session_nonce: 7 }
    }

    #[test]
    fn same_burn_at_append_indexes_zero_and_one_folds_both_positions() {
        let burn = burn_record();
        let (frontier, root) = fold_chain_appends(1, &[row(0, &burn), row(1, &burn)]).unwrap();
        let leaf = guardian_common::protocol::withdrawal_tree_leaf(&burn);
        let mut expected = [Hash4::ZERO; 32];
        let after_first = guardian_common::protocol::append_merkle_leaf(&mut expected, 0, leaf);
        let expected_root = guardian_common::protocol::append_merkle_leaf(&mut expected, 1, leaf);
        assert_eq!(frontier, expected);
        assert_eq!(root, expected_root);
        assert_ne!(root, after_first);
    }

    #[test]
    fn non_contiguous_append_positions_still_fail_closed() {
        let burn = burn_record();
        assert!(fold_chain_appends(1, &[row(0, &burn), row(2, &burn)]).is_err());
    }
}

#[cfg(test)]
mod burn_identity_tests {
    use super::*;

    fn burn(amount_low: u32) -> WithdrawalBurnRecord {
        WithdrawalBurnRecord {
            sender_user_id: 5, token_contract_id: TOKEN_CONTRACT, destination_chain_index: 1,
            token: [3; 8], amount: [amount_low, 0, 0, 0, 0, 0, 0, 0], recipient: [4; 8], nonce: [9, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    #[test]
    fn verbatim_burn_repeat_at_different_checkpoint_keeps_first_record() {
        let mut burns = BTreeMap::new();
        record_authenticated_burn(&mut burns, burn(1), 4, 7).unwrap();
        record_authenticated_burn(&mut burns, burn(1), 9, 7).unwrap();
        let stored = burns.values().next().unwrap();
        assert!(burns.len() == 1 && stored.0 == burn(1) && stored.1 == 4 && stored.2 == 7);
    }

    #[test]
    fn conflicting_burn_record_at_same_identity_fails_closed() {
        let mut burns = BTreeMap::new();
        record_authenticated_burn(&mut burns, burn(1), 4, 7).unwrap();
        assert!(record_authenticated_burn(&mut burns, burn(2), 6, 8).is_err());
        let stored = burns.values().next().unwrap();
        assert!(burns.len() == 1 && stored.0 == burn(1) && stored.1 == 4);
    }
}
// Ignored by default (deterministic, isolated suite); run explicitly with
// `cargo test -p psy_dev_cli bridge_state_snapshot -- --ignored`.
// Real `parse_archive` authentication negatives driven by an actual producer
// archive (the devnet end-cap gatherer backup under
// `local_checkpoints/realm_0_1/guta_updates_backup`). Every exercised check
// sits before the first store query, so the devnet store is only opened to
// satisfy the `&Store` parameters and is never awaited by these negatives.
#[cfg(test)]
mod parse_archive_auth_tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::LazyLock;

    // Prerequisite: devnet Scylla reachable at 127.0.0.1:9042 with the existing
    // `realm_0_1` and `realm_0_1_no_tablet` keyspaces. The open is read-only
    // (`create_tables=false`): keyspaces are validated and statements prepared.
    const DEVNET_SCYLLA: &str = "127.0.0.1:9042";
    const DEVNET_REALM_NAMESPACE: &str = "realm_0_1";

    // Canonical footer layout: whitelist[0..32], checkpoint_tree_root[32..64],
    // transition[64..144] with old root [64..96] and node_index [128..136],
    // stats, total_aggregation_proofs_generated, then the 24-byte job id.
    const TRANSITION_NODE_INDEX_OFFSET: usize = 128;

    struct ProducerArchive {
        bytes: Vec<u8>,
        footer: GlobalUserTreeAggregatorHeaderWithJobId<Felt, NodeHash>,
        start_root: Hash4,
        end_root: Hash4,
        context: ArchiveContext,
    }

    fn footer_size() -> usize {
        GlobalUserTreeAggregatorHeaderWithJobId::<Felt, NodeHash>::FIXED_SIZE
    }

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().join("local_checkpoints").join("realm_0_1").join("guta_updates_backup")
    }

    fn producer_archive() -> &'static ProducerArchive {
        static ARCHIVE: LazyLock<ProducerArchive> = LazyLock::new(|| {
            let mut entries: Vec<PathBuf> = fs::read_dir(fixtures_dir()).expect("realm_0_1 guta_updates_backup fixture directory").map(|entry| entry.expect("fixture entry").path()).filter(|path| path.extension().map_or(false, |extension| extension.to_string_lossy() == "backup")).collect();
            entries.sort();
            for path in entries {
                let Ok(bytes) = fs::read(&path) else { continue };
                if bytes.len() < 76 + footer_size() { continue; }
                if u64::from_le_bytes(bytes[68..76].try_into().unwrap()) == 0 { continue; }
                let (Ok(start_root), Ok(end_root)) = (hash4(NodeHash::from_owned_32bytes(bytes[4..36].try_into().unwrap())), hash4(NodeHash::from_owned_32bytes(bytes[36..68].try_into().unwrap()))) else { continue };
                let Ok(footer) = read_value::<GlobalUserTreeAggregatorHeaderWithJobId<Felt, NodeHash>>(&bytes[bytes.len() - footer_size()..]) else { continue };
                let transition = &footer.header.state_transition;
                if hash4(transition.old_node_value).map_or(true, |value| value != start_root) || hash4(transition.new_node_value).map_or(true, |value| value != end_root) { continue; }
                if transition.node_level.to_u64_value() != u64::from(Network::COORDINATOR_GLOBAL_USER_TREE_HEIGHT) { continue; }
                if footer.job_id != QProvingJobDataID::realm_finalize_guta(footer.job_id.goal_id, footer.job_id.group_id) { continue; }
                let file_name = path.file_name().expect("fixture file name").to_string_lossy().into_owned();
                let sub = file_name.split("sub_").nth(1).and_then(|rest| rest.split('_').next()).and_then(|value| value.parse().ok()).unwrap_or(0);
                let pending = file_name.split("pending_").nth(1).and_then(|rest| rest.trim_end_matches(".backup").parse().ok()).unwrap_or(0);
                // `realm` and `proof_checkpoint` are read back from the archive
                // itself. `chain`, `sub`, `pending` and `checkpoint` mirror the
                // producer identity but are only consulted by the store path.
                let context = ArchiveContext { chain: 0, realm: transition.node_index.to_u64_value(), sub, pending, checkpoint: footer.job_id.goal_id + 1, proof_checkpoint: footer.job_id.goal_id };
                return ProducerArchive { bytes, footer, start_root, end_root, context };
            }
            panic!("no finalized non-empty realm_0_1 producer archive under {} — prerequisite: devnet local_checkpoints holding at least one finalized realm_end_cap_gatherer backup", fixtures_dir().display());
        });
        &ARCHIVE
    }

    fn devnet_store() -> &'static Store {
        static STORE: LazyLock<Store> = LazyLock::new(|| {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime for store open");
            let store = runtime.block_on(setup_psy_scylla_database_store_from_connection_string::<Network>(DEVNET_REALM_NAMESPACE, DEVNET_SCYLLA, false));
            // The store is never awaited by the exercised negatives; keeping the
            // opening runtime alive via forget only preserves its connections.
            std::mem::forget(runtime);
            store.expect("prerequisite: devnet Scylla at 127.0.0.1:9042 with existing keyspaces realm_0_1 and realm_0_1_no_tablet")
        });
        &STORE
    }

    fn parse_inline(context: &ArchiveContext, footer: &GlobalUserTreeAggregatorHeaderWithJobId<Felt, NodeHash>, bytes: &[u8], start_root: Hash4, end_root: Hash4) -> anyhow::Result<AuthenticatedArchive> {
        // `target` and `committed` are only authenticated inside the store path.
        let store = devnet_store();
        tokio::runtime::Builder::new_current_thread().enable_all().build().expect("test tokio runtime").block_on(parse_archive(bytes, context, footer, start_root, end_root, store, store, 0, Hash4::ZERO))
    }

    fn assert_rejected(result: anyhow::Result<AuthenticatedArchive>, expected: &str) {
        let error = result.err().unwrap_or_else(|| panic!("archive was accepted, expected rejection containing {expected:?}"));
        assert!(error.to_string().contains(expected), "unexpected rejection: {error:#}");
    }

    fn bumped_root(hash: Hash4) -> Hash4 {
        let mut limbs = hash.0.elements.map(|felt| felt.to_canonical_u64());
        limbs[0] = (limbs[0] + 1) % guardian_common::protocol::GOLDILOCKS_MODULUS;
        Hash4::try_from(&limbs).expect("canonical bumped root")
    }

    fn root_other_than(hash: Hash4) -> Hash4 {
        let mut limbs = [1u64, 0, 0, 0];
        loop {
            let candidate = Hash4::try_from(&limbs).expect("canonical root limbs");
            if candidate != hash { return candidate; }
            limbs[0] += 1;
        }
    }

    #[ignore = "live E2E: needs devnet Scylla 127.0.0.1:9042 (realm_0_1) plus local_checkpoints backups; run with cargo test -p psy_dev_cli bridge_state_snapshot -- --ignored"]
    #[test]
    fn real_archive_rejects_corrupted_magic() {
        let archive = producer_archive();
        let mut bytes = archive.bytes.clone();
        bytes[0] ^= 1;
        assert_rejected(parse_inline(&archive.context, &archive.footer, &bytes, archive.start_root, archive.end_root), "end-cap archive header is not RGE1");
    }

    #[ignore = "live E2E: needs devnet Scylla 127.0.0.1:9042 (realm_0_1) plus local_checkpoints backups; run with cargo test -p psy_dev_cli bridge_state_snapshot -- --ignored"]
    #[test]
    fn real_archive_truncated_before_footer_is_rejected() {
        let archive = producer_archive();
        let bytes = archive.bytes[..76 + footer_size() - 1].to_vec();
        assert_rejected(parse_inline(&archive.context, &archive.footer, &bytes, archive.start_root, archive.end_root), "end-cap archive header is not RGE1");
    }

    #[ignore = "live E2E: needs devnet Scylla 127.0.0.1:9042 (realm_0_1) plus local_checkpoints backups; run with cargo test -p psy_dev_cli bridge_state_snapshot -- --ignored"]
    #[test]
    fn real_archive_with_missing_queue_body_rejects_count_above_size() {
        let archive = producer_archive();
        let mut bytes = archive.bytes[..76].to_vec();
        bytes.extend_from_slice(&archive.bytes[archive.bytes.len() - footer_size()..]);
        assert_rejected(parse_inline(&archive.context, &archive.footer, &bytes, archive.start_root, archive.end_root), "archive queue count exceeds its size");
    }

    #[ignore = "live E2E: needs devnet Scylla 127.0.0.1:9042 (realm_0_1) plus local_checkpoints backups; run with cargo test -p psy_dev_cli bridge_state_snapshot -- --ignored"]
    #[test]
    fn real_archive_with_altered_start_root_claim_is_rejected() {
        let archive = producer_archive();
        let altered = bumped_root(archive.start_root);
        assert_rejected(parse_inline(&archive.context, &archive.footer, &archive.bytes, altered, archive.end_root), "footer transition disagrees with archive roots");
    }

    #[ignore = "live E2E: needs devnet Scylla 127.0.0.1:9042 (realm_0_1) plus local_checkpoints backups; run with cargo test -p psy_dev_cli bridge_state_snapshot -- --ignored"]
    #[test]
    fn real_archive_with_tampered_realm_identity_is_rejected() {
        let archive = producer_archive();
        assert!(archive.context.realm < 128);
        let mut bytes = archive.bytes.clone();
        let offset = bytes.len() - footer_size() + TRANSITION_NODE_INDEX_OFFSET;
        bytes[offset] ^= 1;
        let footer = read_value::<GlobalUserTreeAggregatorHeaderWithJobId<Felt, NodeHash>>(&bytes[bytes.len() - footer_size()..]).expect("tampered footer still parses");
        assert_rejected(parse_inline(&archive.context, &footer, &bytes, archive.start_root, archive.end_root), "footer transition names another realm");
    }

    #[ignore = "live E2E: needs devnet Scylla 127.0.0.1:9042 (realm_0_1) plus local_checkpoints backups; run with cargo test -p psy_dev_cli bridge_state_snapshot -- --ignored"]
    #[test]
    fn real_archive_with_wrong_proof_checkpoint_is_rejected() {
        let archive = producer_archive();
        let context = ArchiveContext {
            chain: archive.context.chain, realm: archive.context.realm, sub: archive.context.sub, pending: archive.context.pending,
            checkpoint: archive.context.checkpoint, proof_checkpoint: archive.context.proof_checkpoint + 1,
        };
        assert_rejected(parse_inline(&context, &archive.footer, &archive.bytes, archive.start_root, archive.end_root), "footer job identity disagrees");
    }

    fn empty_archive_bytes(archive: &ProducerArchive) -> Vec<u8> {
        // The gatherer's own in-progress shape: real header with a zero count.
        let mut bytes = archive.bytes[..76].to_vec();
        bytes[68..76].copy_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&archive.bytes[archive.bytes.len() - footer_size()..]);
        bytes
    }

    #[ignore = "live E2E: needs devnet Scylla 127.0.0.1:9042 (realm_0_1) plus local_checkpoints backups; run with cargo test -p psy_dev_cli bridge_state_snapshot -- --ignored"]
    #[test]
    fn real_empty_archive_with_unchanged_roots_is_accepted() {
        let archive = producer_archive();
        let bytes = empty_archive_bytes(archive);
        let accepted = parse_inline(&archive.context, &archive.footer, &bytes, archive.start_root, archive.start_root).expect("empty archive with unchanged roots must authenticate");
        assert!(accepted.candidates.is_empty() && accepted.transcript == ArchiveTranscript::default());
    }

    #[ignore = "live E2E: needs devnet Scylla 127.0.0.1:9042 (realm_0_1) plus local_checkpoints backups; run with cargo test -p psy_dev_cli bridge_state_snapshot -- --ignored"]
    #[test]
    fn real_empty_archive_claiming_root_change_is_rejected() {
        let archive = producer_archive();
        let bytes = empty_archive_bytes(archive);
        let changed = root_other_than(archive.start_root);
        assert_rejected(parse_inline(&archive.context, &archive.footer, &bytes, archive.start_root, changed), "empty archive changes realm root");
    }

    #[ignore = "live E2E: needs devnet Scylla 127.0.0.1:9042 (realm_0_1) plus local_checkpoints backups; run with cargo test -p psy_dev_cli bridge_state_snapshot -- --ignored"]
    #[test]
    fn real_archive_event_segment_truncation_is_rejected() {
        let archive = producer_archive();
        let truncated = read_event(&mut Cursor::new(&archive.bytes[..20])).err().unwrap();
        assert!(truncated.to_string().contains("truncated contract event"), "unexpected: {truncated:#}");
        let mut segment = archive.bytes[..44].to_vec();
        segment[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        let outside = read_event(&mut Cursor::new(&segment[..])).err().unwrap();
        assert!(outside.to_string().contains("contract event length is outside the archive"), "unexpected: {outside:#}");
    }
}

// Append-fold authentication negatives: derived intermediate roots are the
// acceptance oracle, and every deviation from the fold must fail closed.
#[cfg(test)]
mod append_root_fold_tests {
    use super::*;
    use guardian_common::protocol::GOLDILOCKS_MODULUS;

    fn burn() -> WithdrawalBurnRecord {
        WithdrawalBurnRecord {
            sender_user_id: 5, token_contract_id: TOKEN_CONTRACT, destination_chain_index: 1,
            token: [3; 8], amount: [1, 0, 0, 0, 0, 0, 0, 0], recipient: [4; 8], nonce: [9, 0, 0, 0, 0, 0, 0, 0],
        }
    }

    // Same keccak aggregate the production fold derives global roots with.
    fn fold_global(chain: u8, derived: Hash4, aggregate: &mut [[u32; 8]; 512]) -> [u32; 8] {
        let mut node = 256 + usize::from(chain);
        let limbs = derived.0.elements.map(|felt| felt.to_canonical_u64());
        aggregate[node] = std::array::from_fn(|i| (limbs[i / 2] >> (32 * (i % 2))) as u32);
        let mut zero = [0; 8];
        for _ in 0..8 {
            let left = node & !1;
            let a = if aggregate[left] == [0; 8] { zero } else { aggregate[left] };
            let b = if aggregate[left + 1] == [0; 8] { zero } else { aggregate[left + 1] };
            node >>= 1;
            aggregate[node] = keccak_words(a, b);
            zero = keccak_words(zero, zero);
        }
        aggregate[1]
    }

    fn entry(order: (u64, u64, u64), index: u32, leaf: Hash4, chain_root: Hash4, global_root: [u32; 8]) -> ((u64, u64, u64), (u8, u32, Hash4, Hash4, [u32; 8])) {
        (order, (1, index, leaf, chain_root, global_root))
    }

    fn bumped(hash: Hash4) -> Hash4 {
        let mut limbs = hash.0.elements.map(|felt| felt.to_canonical_u64());
        limbs[0] = (limbs[0] + 1) % GOLDILOCKS_MODULUS;
        Hash4::try_from(&limbs).expect("canonical bumped hash")
    }

    #[test]
    fn contiguous_appends_with_derived_intermediate_roots_are_accepted() {
        let leaf = guardian_common::protocol::withdrawal_tree_leaf(&burn());
        let mut frontier = [Hash4::ZERO; 32];
        let first_chain_root = guardian_common::protocol::append_merkle_leaf(&mut frontier, 0, leaf);
        let second_chain_root = guardian_common::protocol::append_merkle_leaf(&mut frontier, 1, leaf);
        let mut aggregate = [[0; 8]; 512];
        let first_global = fold_global(1, first_chain_root, &mut aggregate);
        let second_global = fold_global(1, second_chain_root, &mut aggregate);
        let appends = BTreeMap::from([
            entry((10, 7, 1), 0, leaf, first_chain_root, first_global),
            entry((10, 7, 2), 1, leaf, second_chain_root, second_global),
        ]);
        validate_append_roots(&appends).unwrap();
    }

    #[test]
    fn missing_middle_append_fails_contiguous_prefix() {
        let leaf = guardian_common::protocol::withdrawal_tree_leaf(&burn());
        let mut frontier = [Hash4::ZERO; 32];
        let first_chain_root = guardian_common::protocol::append_merkle_leaf(&mut frontier, 0, leaf);
        let mut aggregate = [[0; 8]; 512];
        let first_global = fold_global(1, first_chain_root, &mut aggregate);
        // The index-1 append is absent; the next surviving append jumps to 2.
        let appends = BTreeMap::from([
            entry((10, 7, 1), 0, leaf, first_chain_root, first_global),
            entry((10, 7, 3), 2, leaf, first_chain_root, first_global),
        ]);
        let error = validate_append_roots(&appends).err().unwrap();
        assert!(error.to_string().contains("intermediate append index is not contiguous"), "unexpected: {error:#}");
    }

    #[test]
    fn altered_append_leaf_preimage_fails_chain_root_fold() {
        let leaf = guardian_common::protocol::withdrawal_tree_leaf(&burn());
        let altered_leaf = bumped(leaf);
        let mut frontier = [Hash4::ZERO; 32];
        let first_chain_root = guardian_common::protocol::append_merkle_leaf(&mut frontier, 0, leaf);
        let mut aggregate = [[0; 8]; 512];
        let first_global = fold_global(1, first_chain_root, &mut aggregate);
        let appends = BTreeMap::from([entry((10, 7, 1), 0, altered_leaf, first_chain_root, first_global)]);
        let error = validate_append_roots(&appends).err().unwrap();
        assert!(error.to_string().contains("intermediate chain root disagrees with fold"), "unexpected: {error:#}");
    }

    #[test]
    fn altered_chain_root_claim_fails_fold() {
        let leaf = guardian_common::protocol::withdrawal_tree_leaf(&burn());
        let mut frontier = [Hash4::ZERO; 32];
        let first_chain_root = guardian_common::protocol::append_merkle_leaf(&mut frontier, 0, leaf);
        let mut aggregate = [[0; 8]; 512];
        let first_global = fold_global(1, first_chain_root, &mut aggregate);
        let appends = BTreeMap::from([entry((10, 7, 1), 0, leaf, bumped(first_chain_root), first_global)]);
        let error = validate_append_roots(&appends).err().unwrap();
        assert!(error.to_string().contains("intermediate chain root disagrees with fold"), "unexpected: {error:#}");
    }

    #[test]
    fn altered_global_root_claim_fails_keccak_fold() {
        let leaf = guardian_common::protocol::withdrawal_tree_leaf(&burn());
        let mut frontier = [Hash4::ZERO; 32];
        let first_chain_root = guardian_common::protocol::append_merkle_leaf(&mut frontier, 0, leaf);
        let mut aggregate = [[0; 8]; 512];
        let mut first_global = fold_global(1, first_chain_root, &mut aggregate);
        first_global[0] ^= 1;
        let appends = BTreeMap::from([entry((10, 7, 1), 0, leaf, first_chain_root, first_global)]);
        let error = validate_append_roots(&appends).err().unwrap();
        assert!(error.to_string().contains("intermediate global root disagrees with fold"), "unexpected: {error:#}");
    }
}

// Event-level candidate identity: burn and append bodies must name their true
// authors, and unrelated events must stay unclassified.
#[cfg(test)]
mod event_candidate_identity_tests {
    use super::*;

    fn felt_words(words: &[u64]) -> Vec<Felt> {
        words.iter().map(|word| GoldilocksField::from_canonical_u64(*word)).collect()
    }

    fn burn_words(sender: u64) -> Vec<u64> {
        [sender, 1].into_iter().chain([3u64; 8]).chain([1, 0, 0, 0, 0, 0, 0, 0]).chain([4u64; 8]).chain([9, 0, 0, 0, 0, 0, 0, 0]).collect()
    }

    fn append_words() -> Vec<u64> {
        [1, 0].into_iter().chain([1u64, 2, 3, 4, 5, 6, 7, 8]).chain([9u64; 8]).chain([8u64; 8]).collect()
    }

    #[test]
    fn burn_event_claiming_another_sender_is_rejected() {
        let error = decode_event(u64::from(TOKEN_CONTRACT), WITHDRAW_METHOD, 7, 5, Hash4::ZERO, &felt_words(&burn_words(9))).err().unwrap();
        assert!(error.to_string().contains("burn sender is not the end-cap user"), "unexpected: {error:#}");
    }

    #[test]
    fn burn_event_with_short_body_is_rejected() {
        let error = decode_event(u64::from(TOKEN_CONTRACT), WITHDRAW_METHOD, 7, 5, Hash4::ZERO, &felt_words(&burn_words(7)[..33])).err().unwrap();
        assert!(error.to_string().contains("burn event does not have 34 words"), "unexpected: {error:#}");
    }

    #[test]
    fn append_event_outside_the_bridge_user_is_rejected() {
        let error = decode_event(u64::from(WITHDRAWAL_CONTRACT), APPEND_METHODS[0], 7, 5, Hash4::ZERO, &felt_words(&append_words())).err().unwrap();
        assert!(error.to_string().contains("append event is not owned by the bridge user"), "unexpected: {error:#}");
    }

    #[test]
    fn append_event_owned_by_the_bridge_user_decodes() {
        let candidate = decode_event(u64::from(WITHDRAWAL_CONTRACT), APPEND_METHODS[0], BRIDGE_USER_ID, 5, Hash4::ZERO, &felt_words(&append_words())).unwrap().expect("append candidate");
        match candidate.kind {
            CandidateKind::Append { chain, index, .. } => assert_eq!((chain, index), (1, 0)),
            CandidateKind::Burn { .. } => panic!("append event decoded as burn"),
        }
    }

    #[test]
    fn unrelated_events_stay_unclassified() {
        assert!(decode_event(9, 9, 7, 5, Hash4::ZERO, &felt_words(&[1, 2, 3])).unwrap().is_none());
    }
}

#[cfg(test)]
mod preimage_canonicality_tests {
    use super::*;

    #[test]
    fn non_canonical_stored_hash_words_are_rejected() {
        // Words (1, 0xffffffff) compose the Goldilocks modulus exactly.
        let error = words_to_hash(&[1, 0xFFFF_FFFF, 0, 0, 0, 0, 0, 0]).err().unwrap();
        assert!(error.to_string().contains("stored hash limb is not canonical"), "unexpected: {error:#}");
    }

    #[test]
    fn canonical_stored_hash_words_round_trip() {
        let hash = words_to_hash(&[1, 0, 2, 0, 3, 0, 4, 0]).unwrap();
        assert_eq!(hash.0.elements.map(|felt| felt.to_canonical_u64()), [1, 2, 3, 4]);
    }

    #[test]
    fn non_canonical_node_hash_limbs_are_rejected() {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&guardian_common::protocol::GOLDILOCKS_MODULUS.to_le_bytes());
        let error = hash4(NodeHash::from_owned_32bytes(bytes)).err().unwrap();
        assert!(error.to_string().contains("node hash limb is not canonical"), "unexpected: {error:#}");
    }

    #[test]
    fn canonical_node_hash_round_trips_through_both_domains() {
        let hash = words_to_hash(&[7, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(hash4(node_hash(hash)).unwrap(), hash);
    }
}
