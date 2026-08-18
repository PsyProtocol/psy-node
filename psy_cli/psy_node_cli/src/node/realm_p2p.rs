//! Optional Realm P2P wiring for processor and edge start paths.
//!
//! Empty start-config fields keep today's HTTP/NATS path. When P2P is
//! enabled this module builds the Swarm, starts the drive loop, and
//! consumes network events (non-proposer votes on processors, inbound
//! EndCap forwards on edges).

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;



use parth_common::realm_rotation::RealmRotationConfig;
use parth_core::{
    crypto::hash::traits::QFieldHashable,
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig, QZKProofVerifier},
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    genesis::genesis_block_setup::ValidatorGenesisEntry,
    guta::{
        header_extended::{
            GlobalUserTreeAggregatorHeaderWithTagValue,
            GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
        },
        realm_finalize::protocol_decode_finalize_output,
    },
    p2p::{BlsPublicKey, EndCapForwardHeader, EndCapForwardResponse, NodeId},
};
use psy_node_common::coordinator::validator_registry::ValidatorRegistry;
use psy_node_common::realm::network::{
    build_optional_realm_network, parse_proposer_node_ids, run_realm_network, OptionalRealmNetwork,
    RealmNetworkEvent,
};
use psy_node_common::realm::processor::consensus::{
    decode_proposal_state_updates, sign_vote, verify_proposal_submission,
};
use psy_node_common::realm::processor::core::IncludedProposalStateUpdates;


use psy_node_core::config::node_start_config::{RealmEdgeStartConfig, RealmProcessorStartConfig};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
struct RosterSubEntry {
    processor_node_id_hex38: String,
    bls_public_hex: String,
}

#[derive(Deserialize)]
struct RosterFile {
    realms: HashMap<String, HashMap<String, RosterSubEntry>>,
}

/// Build a validator registry from `init-realm-p2p-keys` roster.json.
pub fn validator_registry_from_roster_path(path: &str) -> anyhow::Result<ValidatorRegistry> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("failed to read P2P roster {path}: {error}"))?;
    let roster: RosterFile = serde_json::from_str(&text)
        .map_err(|error| anyhow::anyhow!("failed to parse P2P roster {path}: {error}"))?;
    let mut registry = ValidatorRegistry::new();
    for (realm_key, subs) in roster.realms {
        let realm_id: u32 = realm_key
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid roster realm id {realm_key}: {error}"))?;
        for (sub_key, entry) in subs {
            let realm_sub_id: u16 = sub_key
                .parse()
                .map_err(|error| anyhow::anyhow!("invalid roster sub id {sub_key}: {error}"))?;
            let bytes = hex::decode(&entry.bls_public_hex).map_err(|error| {
                anyhow::anyhow!("invalid roster BLS hex for realm {realm_id} sub {realm_sub_id}: {error}")
            })?;
            if bytes.len() != 48 {
                anyhow::bail!(
                    "roster BLS key for realm {realm_id} sub {realm_sub_id} must be 48 bytes, got {}",
                    bytes.len()
                );
            }
            let mut bls_public_key = [0u8; 48];
            bls_public_key.copy_from_slice(&bytes);
            let key = (realm_id, realm_sub_id);
            anyhow::ensure!(
                registry
                    .insert(
                        key,
                        ValidatorGenesisEntry {
                            realm_id,
                            realm_sub_id,
                            validator_user_id: (realm_id as u64) << 20 | realm_sub_id as u64,
                            node_id: [0u8; 38],
                            bls_public_key,
                        },
                    )
                    .is_none(),
                "duplicate roster validator for realm {realm_id} sub {realm_sub_id}"
            );
        }
    }
    Ok(registry)
}

pub fn bls_keys_from_roster_path(
    path: &str,
    realm_id: u32,
) -> anyhow::Result<HashMap<u16, BlsPublicKey>> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("failed to read P2P roster {path}: {error}"))?;
    let roster: RosterFile = serde_json::from_str(&text)
        .map_err(|error| anyhow::anyhow!("failed to parse P2P roster {path}: {error}"))?;
    let subs = roster
        .realms
        .get(&realm_id.to_string())
        .ok_or_else(|| anyhow::anyhow!("P2P roster missing realm {realm_id}"))?;
    let mut keys = HashMap::with_capacity(subs.len());
    for (sub, entry) in subs {
        let sub_id: u16 = sub
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid roster sub id {sub}: {error}"))?;
        let bytes = hex::decode(&entry.bls_public_hex).map_err(|error| {
            anyhow::anyhow!("invalid roster BLS hex for realm {realm_id} sub {sub_id}: {error}")
        })?;
        let key = BlsPublicKey::from_bytes(&bytes)
            .map_err(|error| anyhow::anyhow!("invalid roster BLS key for realm {realm_id} sub {sub_id}: {error}"))?;
        anyhow::ensure!(keys.insert(sub_id, key).is_none(), "duplicate roster sub_id {sub_id}");
    }
    Ok(keys)
}

pub fn proposer_node_ids_from_roster_path(
    path: &str,
    realm_id: u32,
) -> anyhow::Result<HashMap<u16, NodeId>> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("failed to read P2P roster {path}: {error}"))?;
    let roster: RosterFile = serde_json::from_str(&text)
        .map_err(|error| anyhow::anyhow!("failed to parse P2P roster {path}: {error}"))?;
    let subs = roster
        .realms
        .get(&realm_id.to_string())
        .ok_or_else(|| anyhow::anyhow!("P2P roster missing realm {realm_id}"))?;
    let values = subs
        .iter()
        .map(|(sub, entry)| format!("{}:{}", sub, entry.processor_node_id_hex38))
        .collect::<Vec<_>>();
    parse_proposer_node_ids(&values)
}

/// Construct a processor Realm network when P2P start-config fields are set.
pub fn maybe_build_processor_network(
    config: &RealmProcessorStartConfig,
    chain_id: u32,
) -> anyhow::Result<Option<OptionalRealmNetwork>> {
    if !config.realm_p2p_enabled() {
        return Ok(None);
    }
    let roster_path = config.p2p_roster_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!("--p2p-roster-path is required when Realm P2P is enabled")
    })?;
    proposer_node_ids_from_roster_path(roster_path, config.realm_id as u32)?;
    let identity = config
        .p2p_identity_key_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("p2p identity key required when P2P is enabled"))?;
    let listen = config
        .p2p_listen
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("p2p listen required when P2P is enabled"))?;
    let bls = config.p2p_bls_key_path.as_deref();
    let period = config.p2p_checkpoints_per_epoch.unwrap_or(10);
    Ok(Some(build_optional_realm_network(
        chain_id,
        config.realm_id as u32,
        false,
        identity,
        bls,
        listen,
        &config.p2p_bootnodes,
        config.p2p_coordinator.as_deref(),
        &config.p2p_validator_sub_ids,
        period,
    )?))
}

/// Construct an edge Realm network when P2P start-config fields are set.
pub fn maybe_build_edge_network(
    config: &RealmEdgeStartConfig,
    chain_id: u32,
) -> anyhow::Result<Option<(OptionalRealmNetwork, HashMap<u16, NodeId>, RealmRotationConfig)>> {
    if !config.realm_p2p_enabled() {
        return Ok(None);
    }
    let identity = config
        .p2p_identity_key_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("p2p identity key required when P2P is enabled"))?;
    let listen = config
        .p2p_listen
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("p2p listen required when P2P is enabled"))?;
    let period = config.p2p_checkpoints_per_epoch.unwrap_or(10);
    let built = build_optional_realm_network(
        chain_id,
        config.realm_id as u32,
        true,
        identity,
        None,
        listen,
        &config.p2p_bootnodes,
        config.p2p_coordinator.as_deref(),
        &config.p2p_validator_sub_ids,
        period,
    )?;
    let proposer_node_ids = parse_proposer_node_ids(&config.p2p_proposer_node_ids)?;
    if proposer_node_ids.is_empty() {
        anyhow::bail!("edge P2P requires at least one --p2p-proposer-node-id SUB:HEX38");
    }
    let rotation = built.rotation.clone();
    Ok(Some((built, proposer_node_ids, rotation)))
}

fn proposer_node_ids_from_config(
    config: &RealmProcessorStartConfig,
) -> anyhow::Result<HashMap<u16, NodeId>> {
    let roster_path = config.p2p_roster_path.as_deref().ok_or_else(|| {
        anyhow::anyhow!("--p2p-roster-path is required when Realm P2P is enabled")
    })?;
    let proposer_node_ids = proposer_node_ids_from_roster_path(roster_path, config.realm_id as u32)?;
    anyhow::ensure!(
        proposer_node_ids.len() == config.p2p_validator_sub_ids.len(),
        "processor P2P roster must contain one proposer NodeId for every validator"
    );
    Ok(proposer_node_ids)
}

/// Drive loop + processor event consumer. Non-proposers validate and vote.
pub fn spawn_processor_realm_network<N>(
    built: OptionalRealmNetwork,
    config: &RealmProcessorStartConfig,
    proof_verifier: N::ZKVerifier,
    included_proposal_updates: Arc<tokio::sync::RwLock<Option<IncludedProposalStateUpdates<N::QHash>>>>,
)
where
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    N::ZKVerifier: 'static,
{
    let OptionalRealmNetwork {
        network,
        handle,
        bls_secret,
        ..
    } = built;
    let local_sub_id = config.realm_sub_id;
    let realm_id = config.realm_id as u32;
    let chain_id = config.network.get_chain_id();
    let proposer_node_ids = proposer_node_ids_from_config(config)
        .expect("processor Realm P2P proposer NodeId config was validated at startup");
    let included_proposal_updates = included_proposal_updates.clone();

    let roster_path = config.p2p_roster_path.as_deref().expect(
        "processor Realm P2P roster path was validated at startup",
    );
    let validator_registry = validator_registry_from_roster_path(roster_path)
        .expect("processor Realm P2P roster was validated at startup");
    let proof_verifier = Arc::new(proof_verifier);
    let commands = handle.commands();
    let mut events = handle.into_parts().1;
    tokio::spawn(run_realm_network(network));
    tokio::spawn(async move {
        let Some(bls_secret) = bls_secret else {
            tracing::error!("processor P2P event loop missing BLS secret");
            return;
        };
        while let Some(event) = events.recv().await {
            match event {
                RealmNetworkEvent::ProposalReady { source, proposal, body } => {
                    if proposal.proposer_sub_id == local_sub_id {
                        continue;
                    }
                    let validation = async {
                        anyhow::ensure!(proposal.chain_id == chain_id, "Proposal chain_id mismatch");
                        anyhow::ensure!(proposal.realm_id == realm_id, "Proposal realm_id mismatch");
                        anyhow::ensure!(
                            proposal.compute_proposal_id() == proposal.proposal_id,
                            "Proposal proposal_id mismatch"
                        );
                        anyhow::ensure!(
                            proposer_node_ids.get(&proposal.proposer_sub_id) == Some(&source),
                            "Proposal source NodeId does not match configured proposer"
                        );
                        let decoded = psy_node_common::realm::processor::consensus::decode_proposal_body(
                            &proposal,
                            body.as_bytes(),
                        )
                        .map_err(|error| anyhow::anyhow!("invalid Proposal body: {error}"))?;
                        let output = protocol_decode_finalize_output::<N::F, N::QHash>(&decoded.output)
                            .map_err(|error| anyhow::anyhow!("invalid Realm finalize output: {error}"))?;
                        let mut submission = GlobalUserTreeAggregatorHeaderWithTagValueAndJobType {
                            header: GlobalUserTreeAggregatorHeaderWithTagValue {
                                header: output.final_guta_header,
                                new_tag_tree_node_value: output.root_guta_reward_tag,
                            },
                            job_type_u32: 0,
                        };
                        submission.job_type_u32 = infer_ordinary_guta_job_type::<N>(
                            proof_verifier.as_ref(),
                            &submission,
                            &decoded.proof,
                        )?;
                        let proposer = validator_registry
                            .get(&(proposal.realm_id, proposal.proposer_sub_id))
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "GUTA proposer sub_id {} has no genesis validator",
                                    proposal.proposer_sub_id
                                )
                            })?;
                        let decoded = verify_proposal_submission::<N>(
                            &proposal,
                            body.as_bytes(),
                            &submission,
                            proposer.validator_user_id,
                            proof_verifier.as_ref(),
                        )?;
                        let updates = decode_proposal_state_updates::<N::QHash>(&decoded.state_updates)?;
                        *included_proposal_updates.write().await = Some(IncludedProposalStateUpdates {
                            proposal_id: proposal.proposal_id,
                            end_root: updates.new_realm_root.into_owned_32bytes(),
                            updates,
                        });
                        Ok::<(), anyhow::Error>(())
                    }
                    .await;
                    if let Err(error) = validation {
                        tracing::warn!(
                            "realm P2P non-proposer rejected Proposal proposal={} error={:#}",
                            hex::encode(proposal.proposal_id),
                            error
                        );
                        continue;
                    }
                    let vote = sign_vote(&bls_secret, local_sub_id, &proposal);
                    if let Err(error) = commands.publish_vote(vote).await {
                        tracing::warn!(
                            "realm P2P non-proposer vote publish failed proposal={} error={}",
                            hex::encode(proposal.proposal_id),
                            error
                        );
                        continue;
                    }
                    tracing::info!(
                        "realm P2P non-proposer vote published proposal={} signer_sub_id={} realm={} source={:?}",
                        hex::encode(proposal.proposal_id),
                        local_sub_id,
                        realm_id,
                        source
                    );
                }
                RealmNetworkEvent::EndCapReceived { reply, .. } => {
                    let _ = reply.send(psy_data::p2p::EndCapForwardResponse::new(false));
                }
                RealmNetworkEvent::VoteReceived { .. }
                | RealmNetworkEvent::FinalizeResult { .. } => {}
            }
        }
    });
}

fn infer_ordinary_guta_job_type<N>(
    proof_verifier: &N::ZKVerifier,
    submission: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
    proof: &[u8],
) -> anyhow::Result<u32>
where
    N: QNetworkTypesConfig,
{
    let expected = submission.header.qfhash::<N::HasherBase>();
    for circuit_type in [
        ProvingJobCircuitType::GUTASingleEndCap,
        ProvingJobCircuitType::GUTATwoEndCap,
        ProvingJobCircuitType::GUTATwoGUTA,
        ProvingJobCircuitType::GUTALeftEndCapRightGUTA,
        ProvingJobCircuitType::GUTALeftGUTARightEndCap,
        ProvingJobCircuitType::GUTAVerifyToCap,
        ProvingJobCircuitType::GUTANoChange,
        ProvingJobCircuitType::GUTATwoGUTAWithCheckpointUpgrade,
        ProvingJobCircuitType::GUTAVerifyToCapWithCheckpointUpgrade,
        ProvingJobCircuitType::GUTATwoGUTALinear,
        ProvingJobCircuitType::GUTATwoGUTALinearUpgradeCheckpoint,
        ProvingJobCircuitType::GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint,
        ProvingJobCircuitType::GUTAVerifyLeftLeafRightLinearUpgradeCheckpoint,
    ] {
        if proof_verifier
            .verify_zk_proof_from_slice_check_public_inputs_hash(circuit_type as u32, proof, expected)
            .is_ok()
        {
            return Ok(circuit_type as u32);
        }
    }
    anyhow::bail!("Proposal proof is not a valid ordinary GUTA root proof")
}


/// Drive loop + edge event consumer. Inbound EndCaps are accepted locally.
pub fn spawn_edge_realm_network<H>(built: OptionalRealmNetwork, handler: H)
where
    H: EdgeEndCapReceiver + Clone + Send + Sync + 'static,
{
    let OptionalRealmNetwork {
        network,
        handle,
        ..
    } = built;
    let mut events = handle.into_parts().1;
    tokio::spawn(run_realm_network(network));
    tokio::spawn(async move {
        while let Some(event) = events.recv().await {
            match event {
                RealmNetworkEvent::EndCapReceived {
                    source,
                    header,
                    input,
                    proof,
                    reply,
                    ..
                } => {
                    let response = handler
                        .handle_p2p_end_cap_received(source, header, input, proof)
                        .await;
                    let _ = reply.send(response);
                }
                RealmNetworkEvent::ProposalReady { .. }
                | RealmNetworkEvent::VoteReceived { .. }
                | RealmNetworkEvent::FinalizeResult { .. } => {}
            }
        }
    });
}

pub trait EdgeEndCapReceiver {
    fn handle_p2p_end_cap_received(
        &self,
        source: NodeId,
        header: EndCapForwardHeader,
        input: Vec<u8>,
        proof: Vec<u8>,
    ) -> impl Future<Output = EndCapForwardResponse> + Send;
}

impl<
        N: parth_core::protocol::core_types::QNetworkTypesConfig<JobId = psy_core::job::job_id::QProvingJobDataID> + 'static,
        S: psy_node_core::psy_core_db::traits::full::PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        STagTreeRewards: psy_node_core::psy_core_db::traits::full::PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash>
            + psy_node_core::psy_core_db::traits::full::PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash>
            + Send
            + Sync
            + 'static,
        UserUpdateQueue: psy_node_core::queue::ephemeral::QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        GetProofWorkQueue: psy_node_core::queue::worker_queue::QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: psy_node_core::psy_temp_db::StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: psy_node_core::store::traits::proof_store::QParthProofStore + Send + Sync + 'static,
    > EdgeEndCapReceiver
    for psy_node_common::realm::edge::handler::RealmEdgeHandler<
        N,
        S,
        STagTreeRewards,
        UserUpdateQueue,
        GetProofWorkQueue,
        TempDatabase,
        ProofStore,
    >
where
    N::ZKVerifier: 'static,
    N::ZKProof: 'static,
{
    fn handle_p2p_end_cap_received(
        &self,
        source: NodeId,
        header: EndCapForwardHeader,
        input: Vec<u8>,
        proof: Vec<u8>,
    ) -> impl Future<Output = EndCapForwardResponse> + Send {
        psy_node_common::realm::edge::handler::RealmEdgeHandler::handle_p2p_end_cap_received(
            self, source, header, input, proof,
        )
    }
}
