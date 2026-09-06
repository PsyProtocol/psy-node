//! Realm P2P startup backed by the selected public network configuration.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;

use parth_common::realm_rotation::RealmRotationConfig;
use parth_core::{
    crypto::hash::traits::QFieldHashable,
    protocol::core_types::{QNetworkTypesConfig, QZKProofVerifier},
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_data::{
    genesis::genesis_block_setup::{GenesisValidator, PsyGenesisBlockSetupData},
    guta::{
        header_extended::{
            GlobalUserTreeAggregatorHeaderWithTagValue,
            GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
        },
        realm_finalize::protocol_decode_finalize_output,
    },
    p2p::{
        BlsPublicKey, EndCapForwardHeader, EndCapForwardResponse, NodeId,
        MAX_VALIDATORS_PER_REALM, MIN_VALIDATORS_PER_REALM,
    },
};
use psy_node_common::{
    coordinator::genesis_validators::{index_from_genesis, GenesisValidatorIndex},
    realm::{
        network::{
            build_optional_realm_network, load_bls_secret_key, load_ed25519_identity_key,
            parse_bootnode, run_realm_network, OptionalRealmNetwork, RealmNetworkEvent,
        },
        processor::consensus::{sign_vote, verify_proposal_submission},
    },
};
use psy_node_core::config::node_start_config::{RealmEdgeStartConfig, RealmProcessorStartConfig};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
struct PublicNode {
    node_id: String,
    addresses: Vec<String>,
}

#[derive(Clone, Deserialize)]
struct PublicValidator {
    validator_user_id: u64,
    processor_node_id: String,
    bls_public_key: String,
    processor_addresses: Vec<String>,
    edge_nodes: Vec<PublicNode>,
}

#[derive(Deserialize)]
struct PublicRealmConfig {
    id: u32,
    validators: Vec<PublicValidator>,
}

#[derive(Deserialize)]
struct PublicP2pConfig {
    checkpoints_per_epoch: u64,
}

#[derive(Deserialize)]
struct PublicNetworkConfig {
    realm_user_tree_height: u8,
    p2p: PublicP2pConfig,
    realm_configs: Vec<PublicRealmConfig>,
}

#[derive(Deserialize)]
struct PublicConfig {
    networks: HashMap<String, PublicNetworkConfig>,
}

struct RealmPublicData {
    validator_sub_ids: Vec<u16>,
    validator_user_ids: HashMap<u16, u64>,
    bls_public_keys: HashMap<u16, BlsPublicKey>,
    validator_processor_node_ids: HashMap<u16, NodeId>,
    proposer_edge_node_ids: HashMap<u16, NodeId>,
    realm_edge_node_ids: HashSet<NodeId>,
    bootnodes: Vec<String>,
    realm_user_tree_height: u8,
    checkpoints_per_epoch: u64,
}

fn public_network_key(network: PsyChainNetworkType) -> anyhow::Result<&'static str> {
    match network {
        PsyChainNetworkType::LocalDevnet => Ok("localhost"),
        PsyChainNetworkType::PsyPublicTestnet => Ok("sepolia"),
        PsyChainNetworkType::PsyMainnet => Ok("ethereum"),
        _ => anyhow::bail!("Realm P2P has no public config mapping for network {network:?}"),
    }
}

fn validate_realm_validator_count(realm_id: u32, count: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        (MIN_VALIDATORS_PER_REALM..=MAX_VALIDATORS_PER_REALM).contains(&count),
        "Realm {realm_id} validator count {count} is outside {MIN_VALIDATORS_PER_REALM}..={MAX_VALIDATORS_PER_REALM}"
    );
    Ok(())
}

fn validate_node_addresses(
    addresses: &[String],
    node_id: NodeId,
    description: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(!addresses.is_empty(), "{description} has no addresses");
    let expected_peer_id = node_id.to_peer_id();
    for address in addresses {
        let (peer_id, _) = parse_bootnode(address)?;
        anyhow::ensure!(
            peer_id == expected_peer_id,
            "{description} address PeerId {peer_id} does not match NodeId PeerId {expected_peer_id}"
        );
    }
    Ok(())
}

fn validate_public_network(network: &PublicNetworkConfig) -> anyhow::Result<()> {
    for realm in &network.realm_configs {
        if realm.validators.is_empty() {
            continue;
        }
        validate_realm_validator_count(realm.id, realm.validators.len())?;
        for (index, validator) in realm.validators.iter().enumerate() {
            let sub_id = index + 1;
            let description = format!("Realm {} validator sub {sub_id}", realm.id);
            let processor_node_id = parse_node_id(&validator.processor_node_id, &description)?;
            validate_node_addresses(
                &validator.processor_addresses,
                processor_node_id,
                &format!("{description} processor"),
            )?;
            anyhow::ensure!(
                !validator.edge_nodes.is_empty(),
                "{description} has no edge nodes"
            );
            for edge in &validator.edge_nodes {
                let edge_description = format!("{description} edge");
                let edge_node_id = parse_node_id(&edge.node_id, &edge_description)?;
                validate_node_addresses(&edge.addresses, edge_node_id, &edge_description)?;
            }
        }
    }
    Ok(())
}

fn load_selected_network(network: PsyChainNetworkType) -> anyhow::Result<PublicNetworkConfig> {
    let selected_name = public_network_key(network)?;
    let network_type = network;
    if let Ok(environment_name) = std::env::var("PSY_NETWORK") {
        anyhow::ensure!(
            environment_name == selected_name,
            "PSY_NETWORK {environment_name} does not match node network {network:?} ({selected_name})"
        );
    }
    let path = std::env::var("PSY_CONFIG_PATH")
        .unwrap_or_else(|_| "psy-genesis/config.json".to_string());
    let text = std::fs::read_to_string(&path)
        .map_err(|error| anyhow::anyhow!("failed to read network config {path}: {error}"))?;
    let config: PublicConfig = serde_json::from_str(&text)
        .map_err(|error| anyhow::anyhow!("failed to parse network config {path}: {error}"))?;
    let network = config
        .networks
        .into_iter()
        .find_map(|(name, public)| (name == selected_name).then_some(public))
        .ok_or_else(|| anyhow::anyhow!("network config has no network named {selected_name}"))?;
    validate_public_network(&network)?;
    psy_data::config::network_config::load_realm_rotation_config(network_type)?;
    Ok(network)
}

fn selected_realm(
    network: &PublicNetworkConfig,
    realm_id: u32,
) -> anyhow::Result<&PublicRealmConfig> {
    let mut matches = network
        .realm_configs
        .iter()
        .filter(|realm| realm.id == realm_id);
    let realm = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("network config has no Realm {realm_id}"))?;
    anyhow::ensure!(
        matches.next().is_none(),
        "network config contains duplicate Realm {realm_id}"
    );
    validate_realm_validator_count(realm_id, realm.validators.len())?;
    Ok(realm)
}

fn validator_sub_id(index: usize) -> anyhow::Result<u16> {
    let position = index + 1;
    anyhow::ensure!(
        position <= MAX_VALIDATORS_PER_REALM,
        "Realm has more than {MAX_VALIDATORS_PER_REALM} validators"
    );
    Ok(position as u16)
}

fn parse_node_id(value: &str, description: &str) -> anyhow::Result<NodeId> {
    let bytes = hex::decode(value)
        .map_err(|error| anyhow::anyhow!("invalid {description} NodeId hex: {error}"))?;
    anyhow::ensure!(
        bytes.len() == 38,
        "{description} NodeId must be 38 bytes, got {}",
        bytes.len()
    );
    let mut raw = [0u8; 38];
    raw.copy_from_slice(&bytes);
    NodeId::from_raw(raw).map_err(|error| anyhow::anyhow!("invalid {description} NodeId: {error}"))
}

fn parse_bls_key(value: &str, description: &str) -> anyhow::Result<BlsPublicKey> {
    let bytes = hex::decode(value)
        .map_err(|error| anyhow::anyhow!("invalid {description} BLS public key hex: {error}"))?;
    BlsPublicKey::from_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid {description} BLS public key: {error}"))
}

fn realm_public_data(
    network_type: PsyChainNetworkType,
    realm_id: u32,
) -> anyhow::Result<RealmPublicData> {
    let network = load_selected_network(network_type)?;
    anyhow::ensure!(
        network.p2p.checkpoints_per_epoch > 0,
        "p2p.checkpoints_per_epoch must be greater than zero"
    );
    let realm = selected_realm(&network, realm_id)?;

    let mut validator_sub_ids = Vec::with_capacity(realm.validators.len());
    let mut validator_user_ids = HashMap::with_capacity(realm.validators.len());
    let mut bls_public_keys = HashMap::with_capacity(realm.validators.len());
    let mut validator_processor_node_ids = HashMap::with_capacity(realm.validators.len());
    let mut proposer_edge_node_ids = HashMap::with_capacity(realm.validators.len());
    let mut realm_edge_node_ids = HashSet::new();
    let mut bootnodes = Vec::new();
    for (index, validator) in realm.validators.iter().enumerate() {
        let sub_id = validator_sub_id(index)?;
        let description = format!("Realm {realm_id} validator sub {sub_id}");
        let node_id = parse_node_id(&validator.processor_node_id, &description)?;
        let bls_public_key = parse_bls_key(&validator.bls_public_key, &description)?;
        validator_sub_ids.push(sub_id);
        anyhow::ensure!(
            validator_user_ids
                .insert(sub_id, validator.validator_user_id)
                .is_none(),
            "duplicate validator sub_id {sub_id}"
        );
        anyhow::ensure!(
            validator_processor_node_ids.insert(sub_id, node_id).is_none(),
            "duplicate validator sub_id {sub_id}"
        );
        anyhow::ensure!(
            bls_public_keys.insert(sub_id, bls_public_key).is_none(),
            "duplicate validator sub_id {sub_id}"
        );
        bootnodes.extend(validator.processor_addresses.iter().cloned());
        for (edge_index, edge) in validator.edge_nodes.iter().enumerate() {
            let edge_node_id = parse_node_id(&edge.node_id, &format!("{description} edge"))?;
            anyhow::ensure!(
                realm_edge_node_ids.insert(edge_node_id),
                "duplicate Realm edge NodeId"
            );
            if edge_index == 0 {
                proposer_edge_node_ids.insert(sub_id, edge_node_id);
            }
            bootnodes.extend(edge.addresses.iter().cloned());
        }
    }
    bootnodes.sort_unstable();
    bootnodes.dedup();

    Ok(RealmPublicData {
        validator_user_ids,
        validator_sub_ids,
        bls_public_keys,
        validator_processor_node_ids,
        proposer_edge_node_ids,
        realm_edge_node_ids,
        realm_user_tree_height: network.realm_user_tree_height,
        bootnodes,
        checkpoints_per_epoch: network.p2p.checkpoints_per_epoch,
    })
}
fn bootnodes_without_local_peer(
    bootnodes: &[String],
    local_node_id: NodeId,
) -> anyhow::Result<Vec<String>> {
    let local_peer_id = local_node_id.to_peer_id();
    bootnodes
        .iter()
        .filter_map(|address| match parse_bootnode(address) {
            Ok((peer_id, _)) if peer_id == local_peer_id => None,
            Ok(_) => Some(Ok(address.clone())),
            Err(error) => Some(Err(error.into())),
        })
        .collect()
}


/// Build the coordinator-facing genesis validator index from public network values.
pub fn genesis_validator_index_from_network_config(
    network_type: PsyChainNetworkType,
) -> anyhow::Result<(GenesisValidatorIndex, u64)> {
    let network = load_selected_network(network_type)?;
    anyhow::ensure!(
        network.p2p.checkpoints_per_epoch > 0,
        "p2p.checkpoints_per_epoch must be greater than zero"
    );
    let mut index = GenesisValidatorIndex::new();
    let mut user_ids = HashSet::new();
    let mut node_ids = HashSet::new();
    let mut bls_keys = HashSet::new();

    for realm in &network.realm_configs {
        if realm.validators.is_empty() {
            continue;
        }
        validate_realm_validator_count(realm.id, realm.validators.len())?;
        for (position, validator) in realm.validators.iter().enumerate() {
            let sub_id = validator_sub_id(position)?;
            let description = format!("Realm {} validator sub {sub_id}", realm.id);
            let node_id = parse_node_id(&validator.processor_node_id, &description)?;
            let bls_public_key = parse_bls_key(&validator.bls_public_key, &description)?;
            anyhow::ensure!(
                user_ids.insert(validator.validator_user_id),
                "duplicate validator_user_id {}",
                validator.validator_user_id
            );
            anyhow::ensure!(node_ids.insert(*node_id.as_raw()), "duplicate public NodeId");
            anyhow::ensure!(
                bls_keys.insert(bls_public_key.to_bytes()),
                "duplicate validator BLS public key"
            );
            for edge in &validator.edge_nodes {
                let edge_id = parse_node_id(&edge.node_id, &format!("{description} edge"))?;
                anyhow::ensure!(node_ids.insert(*edge_id.as_raw()), "duplicate public NodeId");
            }
            let genesis_validator = GenesisValidator {
                realm_id: realm.id,
                validator_user_id: validator.validator_user_id,
                node_id: *node_id.as_raw(),
                bls_public_key: bls_public_key.to_bytes(),
            };
            anyhow::ensure!(
                index.insert((realm.id, sub_id), genesis_validator).is_none(),
                "duplicate validator slot for Realm {} sub {sub_id}",
                realm.id
            );
        }
    }
    Ok((index, network.p2p.checkpoints_per_epoch))
}

/// Construct a processor Realm network from local keys/listen and public membership.
pub fn maybe_build_processor_network(
    config: &RealmProcessorStartConfig,
    chain_id: u32,
) -> anyhow::Result<OptionalRealmNetwork> {
    let identity = config
        .p2p_identity_key_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("p2p identity key is required"))?;
    let listen = config
        .p2p_listen
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("p2p listen is required"))?;
    let public = realm_public_data(config.network, config.realm_id as u32)?;
    let local_node_id = NodeId::from_keypair(&load_ed25519_identity_key(identity)?)?;
    let bootnodes = bootnodes_without_local_peer(&public.bootnodes, local_node_id)?;
    Ok(build_optional_realm_network(
        chain_id,
        config.realm_id as u32,
        false,
        identity,
        config.p2p_bls_key_path.as_deref(),
        listen,
        &bootnodes,
        &public.validator_sub_ids,
        public.checkpoints_per_epoch,
    )?)
}

/// Construct an edge Realm network from local identity/listen and public membership.
pub fn maybe_build_edge_network(
    config: &RealmEdgeStartConfig,
    chain_id: u32,
) -> anyhow::Result<(OptionalRealmNetwork, HashMap<u16, NodeId>, HashSet<NodeId>, RealmRotationConfig)> {
    let identity = config
        .p2p_identity_key_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("p2p identity key is required"))?;
    let listen = config
        .p2p_listen
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("p2p listen is required"))?;
    let public = realm_public_data(config.network, config.realm_id as u32)?;
    let local_node_id = NodeId::from_keypair(&load_ed25519_identity_key(identity)?)?;
    let bootnodes = bootnodes_without_local_peer(&public.bootnodes, local_node_id)?;
    let built = build_optional_realm_network(
        chain_id,
        config.realm_id as u32,
        true,
        identity,
        None,
        listen,
        &bootnodes,
        &public.validator_sub_ids,
        public.checkpoints_per_epoch,
    )?;
    let rotation = built.rotation.clone();
    Ok((built, public.proposer_edge_node_ids, public.realm_edge_node_ids, rotation))
}

/// Resolve the processor's one-based validator position from its local Ed25519 identity.
pub fn resolve_processor_sub_id(config: &RealmProcessorStartConfig) -> anyhow::Result<u16> {
    let identity_path = config
        .p2p_identity_key_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("p2p identity key is required"))?;
    let local_node_id = NodeId::from_keypair(&load_ed25519_identity_key(identity_path)?)?;
    let network = load_selected_network(config.network)?;
    let realm = selected_realm(&network, config.realm_id as u32)?;
    let mut matches = Vec::new();
    for (index, validator) in realm.validators.iter().enumerate() {
        let description = format!("Realm {} validator processor", config.realm_id);
        let node_id = parse_node_id(&validator.processor_node_id, &description)?;
        if node_id == local_node_id {
            matches.push(validator_sub_id(index)?);
        }
    }
    anyhow::ensure!(
        matches.len() == 1,
        "Realm {} public validators must contain exactly one processor for the local NodeId, found {}",
        config.realm_id,
        matches.len()
    );
    Ok(matches[0])
}

/// Resolve the edge's one-based validator position from its local Ed25519 identity.
pub fn resolve_edge_sub_id(config: &RealmEdgeStartConfig) -> anyhow::Result<u16> {
    let identity_path = config
        .p2p_identity_key_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("p2p identity key is required"))?;
    let local_node_id = NodeId::from_keypair(&load_ed25519_identity_key(identity_path)?)?;
    let network = load_selected_network(config.network)?;
    let realm = selected_realm(&network, config.realm_id as u32)?;
    let mut matches = Vec::new();
    for (index, validator) in realm.validators.iter().enumerate() {
        for edge in &validator.edge_nodes {
            let node_id = parse_node_id(&edge.node_id, "edge")?;
            if node_id == local_node_id {
                matches.push(validator_sub_id(index)?);
            }
        }
    }
    anyhow::ensure!(
        matches.len() == 1,
        "Realm {} public validators must contain exactly one edge for the local NodeId, found {}",
        config.realm_id,
        matches.len()
    );
    Ok(matches[0])
}

/// Validate the local processor identity and BLS key against public config and Genesis.
pub fn processor_validator_data<F, Hash>(
    config: &RealmProcessorStartConfig,
    genesis: &PsyGenesisBlockSetupData<F, Hash>,
) -> anyhow::Result<(u16, u64, HashMap<u16, BlsPublicKey>)> {
    let derived_sub_id = resolve_processor_sub_id(config)?;
    let identity_path = config
        .p2p_identity_key_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("p2p identity key is required"))?;
    let local_node_id = NodeId::from_keypair(&load_ed25519_identity_key(identity_path)?)?;
    let index = index_from_genesis(genesis)?;
    let genesis_matches = index
        .iter()
        .filter(|((realm_id, _), validator)| {
            *realm_id == config.realm_id as u32 && validator.node_id == *local_node_id.as_raw()
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        genesis_matches.len() == 1,
        "Realm {} Genesis validators must contain exactly one validator for the local NodeId, found {}",
        config.realm_id,
        genesis_matches.len()
    );
    let (&(_, genesis_sub_id), genesis_validator) = genesis_matches[0];
    anyhow::ensure!(
        genesis_sub_id == derived_sub_id,
        "public network validator position {derived_sub_id} does not match Genesis position {genesis_sub_id}"
    );
    anyhow::ensure!(
        genesis_validator.node_id == *local_node_id.as_raw(),
        "Genesis processor NodeId does not match local identity for sub {derived_sub_id}"
    );

    let public = realm_public_data(config.network, config.realm_id as u32)?;
    let users_per_realm = 1u64
        .checked_shl(u32::from(public.realm_user_tree_height))
        .ok_or_else(|| anyhow::anyhow!("realm_user_tree_height is too large"))?;
    let realm_start = config
        .realm_id
        .checked_mul(users_per_realm)
        .ok_or_else(|| anyhow::anyhow!("Realm user range overflow"))?;
    let realm_end = realm_start
        .checked_add(users_per_realm)
        .ok_or_else(|| anyhow::anyhow!("Realm user range overflow"))?;
    anyhow::ensure!(
        (realm_start..realm_end).contains(&genesis_validator.validator_user_id),
        "validator_user_id {} is outside Realm {} user range",
        genesis_validator.validator_user_id,
        config.realm_id
    );
    let configured_user_id = public
        .validator_user_ids
        .get(&derived_sub_id)
        .ok_or_else(|| anyhow::anyhow!("public network config is missing validator sub {derived_sub_id}"))?;
    anyhow::ensure!(
        *configured_user_id == genesis_validator.validator_user_id,
        "public network validator_user_id does not match Genesis for sub {derived_sub_id}"
    );
    let configured_node_id = public
        .validator_processor_node_ids
        .get(&derived_sub_id)
        .ok_or_else(|| anyhow::anyhow!("public network config is missing validator sub {derived_sub_id}"))?;
    anyhow::ensure!(
        configured_node_id == &local_node_id,
        "local processor NodeId does not match public network config for sub {derived_sub_id}"
    );
    let configured_bls = public
        .bls_public_keys
        .get(&derived_sub_id)
        .ok_or_else(|| anyhow::anyhow!("public network config is missing BLS key for sub {derived_sub_id}"))?;
    anyhow::ensure!(
        genesis_validator.bls_public_key == configured_bls.to_bytes(),
        "public network BLS key does not match Genesis for sub {derived_sub_id}"
    );
    let secret_path = config
        .p2p_bls_key_path
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("p2p BLS key is required"))?;
    let local_bls = load_bls_secret_key(secret_path)?.public_key();
    anyhow::ensure!(
        local_bls == *configured_bls,
        "local BLS secret public key does not match public config and Genesis for sub {derived_sub_id}"
    );

    Ok((
        derived_sub_id,
        genesis_validator.validator_user_id,
        public.bls_public_keys,
    ))
}

/// Drive loop plus processor event consumer. Non-proposers validate and vote.
pub fn spawn_processor_realm_network<N>(
    built: OptionalRealmNetwork,
    config: &RealmProcessorStartConfig,
    local_sub_id: u16,
    proof_verifier: N::ZKVerifier,
    verified_state_updates: tokio::sync::mpsc::Sender<Vec<u8>>,
) where
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    N::ZKVerifier: 'static,
{
    let OptionalRealmNetwork {
        network,
        handle,
        bls_secret,
        ..
    } = built;
    let realm_id = config.realm_id as u32;
    let chain_id = config.network.get_chain_id();
    let public = realm_public_data(config.network, realm_id)
        .expect("processor Realm P2P public config was validated at startup");
    let (validator_index, _) = genesis_validator_index_from_network_config(config.network)
        .expect("network validator config was validated at startup");
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
                            public.validator_processor_node_ids.get(&proposal.proposer_sub_id) == Some(&source),
                            "Proposal source NodeId does not match configured proposer"
                        );
                        let decoded = psy_node_common::realm::processor::consensus::decode_proposal_body(
                            &proposal,
                            body.as_bytes(),
                        ).map_err(|error| anyhow::anyhow!("invalid Proposal body: {error}"))?;
                        let output = protocol_decode_finalize_output::<N::F, N::QHash>(&decoded.output)
                            .map_err(|error| anyhow::anyhow!("invalid Realm finalize output: {error}"))?;
                        let mut submission = GlobalUserTreeAggregatorHeaderWithTagValueAndJobType {
                            header: GlobalUserTreeAggregatorHeaderWithTagValue {
                                header: output.final_guta_header,
                                new_tag_tree_node_value: output.root_guta_reward_tag,
                            },
                            job_type_u32: 0,
                        };
                        submission.job_type_u32 = infer_root_job_type::<N>(
                            proof_verifier.as_ref(),
                            &submission,
                            &decoded.proof,
                        )?;
                        let proposer = validator_index
                            .get(&(proposal.realm_id, proposal.proposer_sub_id))
                            .ok_or_else(|| anyhow::anyhow!(
                                "GUTA proposer sub_id {} has no genesis validator",
                                proposal.proposer_sub_id
                            ))?;
                        let decoded = verify_proposal_submission::<N>(
                            &proposal,
                            body.as_bytes(),
                            &submission,
                            proposer.validator_user_id,
                            proof_verifier.as_ref(),
                        )?;
                        verified_state_updates
                            .send(decoded.state_updates)
                            .await
                            .map_err(|_| anyhow::anyhow!("verified state_updates receiver dropped"))?;
                        Ok::<(), anyhow::Error>(())
                    }.await;
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
                    let _ = reply.send(EndCapForwardResponse::new(false));
                }
                RealmNetworkEvent::VoteReceived { .. } => {}
            }
        }
    });
}

fn infer_root_job_type<N>(
    proof_verifier: &N::ZKVerifier,
    submission: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
    proof: &[u8],
) -> anyhow::Result<u32>
where
    N: QNetworkTypesConfig,
{
    let expected = submission.header.qfhash::<N::HasherBase>();
    for circuit_type in [
        // The injected verifier resolves the finalizer and its recursive signature
        // child from the same registered circuit library used by the coordinator.
        ProvingJobCircuitType::RealmFinalizeGUTA,
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
            .verify_zk_proof_from_slice_check_public_inputs_hash(
                circuit_type as u32,
                proof,
                expected,
            )
            .is_ok()
        {
            return Ok(circuit_type as u32);
        }
    }
    anyhow::bail!("Proposal proof is not a valid registered GUTA root proof (ordinary or RealmFinalizeGUTA)")
}

/// Drive loop plus edge event consumer. Inbound EndCaps are accepted locally.
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
                | RealmNetworkEvent::VoteReceived { .. } => {}
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
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
        S: psy_node_core::psy_core_db::traits::full::PsyRealmEdgeAPIStoreReader<N::F, N::QHash>
            + Send
            + Sync
            + 'static,
        STagTreeRewards: psy_node_core::psy_core_db::traits::full::PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash>
            + psy_node_core::psy_core_db::traits::full::PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash>
            + Send
            + Sync
            + 'static,
        UserUpdateQueue: psy_node_core::queue::ephemeral::QStandardEphemeralQueuePublisher
            + Send
            + Sync
            + 'static,
        GetProofWorkQueue: psy_node_core::queue::worker_queue::QStandardWorkerQueueSubscriber
            + Send
            + Sync
            + 'static,
        TempDatabase: psy_node_core::psy_temp_db::StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>
            + Send
            + Sync
            + 'static,
        ProofStore: psy_node_core::store::traits::proof_store::QParthProofStore
            + Send
            + Sync
            + 'static,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_job_inference_verifies_registered_finalizer_and_fails_closed() {
        use parth_core::{pgoldilocks::{PoseidonHasher, QHashOut}, protocol::core_types::QNetworkTypesConfigHelper};
        use plonky2::{
            field::{goldilocks_field::GoldilocksField, types::Field},
            iop::witness::PartialWitness,
            plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
        };
        use psy_core::network_config::PsyNetworkLocalDevnetConstants;
        use psy_data::guta::{header::GlobalUserTreeAggregatorHeader, stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition};
        use psy_plonky2_circuits::{protocol_types::ZKTypesPlonky2GoldilocksPoseidon, zk_verifier::PsyPlonky2ZKVerifier};

        type F = GoldilocksField;
        type C = PoseidonGoldilocksConfig;
        type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
        let zero = QHashOut::from_values(0, 0, 0, 0);
        let mut submission = GlobalUserTreeAggregatorHeaderWithTagValueAndJobType {
            header: GlobalUserTreeAggregatorHeaderWithTagValue {
                header: GlobalUserTreeAggregatorHeader {
                    guta_circuit_whitelist: zero,
                    checkpoint_tree_root: zero,
                    state_transition: SubTreeNodeStateTransition {
                        old_node_value: zero, new_node_value: zero,
                        node_index: F::ZERO, node_level: F::ZERO,
                    },
                    stats: GUTAStats::get_zero_value(),
                    total_aggregation_proofs_generated: F::ZERO,
                },
                new_tag_tree_node_value: zero,
            },
            job_type_u32: ProvingJobCircuitType::RealmFinalizeGUTA as u32,
        };
        let expected = submission.header.qfhash::<PoseidonHasher>();
        // Small real Plonky2 circuits exercise typed registry dispatch without
        // substituting a permissive verifier or rebuilding the recursive prover.
        let build = |mismatch: bool| {
            let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
            for mut value in expected.0.elements {
                if mismatch { value += F::ONE; }
                let target = builder.constant(value);
                builder.register_public_input(target);
            }
            builder.build::<C>()
        };
        let matching = build(false);
        let mismatching = build(true);
        let proof = matching.prove(PartialWitness::new()).unwrap();
        let bytes = bincode::serialize(&proof).unwrap();
        let mut verifier = PsyPlonky2ZKVerifier::<C, 2>::from_cached();
        for (circuit_type, info) in &mut verifier.gcv.library.info_map {
            let data = if *circuit_type == ProvingJobCircuitType::RealmFinalizeGUTA {
                &matching
            } else {
                &mismatching
            };
            info.verifier_data = (&data.verifier_only).into();
            info.fingerprint = psy_plonky2_circuits::proof_minifier::pm_core::get_circuit_fingerprint_generic_q::<2, F, C>(&data.verifier_only);
            verifier.gcv.common.insert_common_data(*circuit_type, data.common.clone());
        }
        assert_eq!(infer_root_job_type::<N>(&verifier, &submission, &bytes).unwrap(), 63);
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
            assert!(verifier.verify_zk_proof_from_slice_check_public_inputs_hash(circuit_type as u32, &bytes, expected).is_err());
        }
        submission.header.new_tag_tree_node_value = QHashOut::from_values(1, 0, 0, 0);
        assert!(infer_root_job_type::<N>(&verifier, &submission, &bytes).is_err());
        submission.header.new_tag_tree_node_value = zero;
        let mut corrupted = proof;
        corrupted.public_inputs[0] += F::ONE;
        assert!(infer_root_job_type::<N>(&verifier, &submission, &bincode::serialize(&corrupted).unwrap()).is_err());
        assert!(verifier.verify_zk_proof_from_slice_check_public_inputs_hash(u32::MAX, &bytes, expected).is_err());
        let mut finalizer_info = verifier.gcv.library.info_map.remove(&ProvingJobCircuitType::RealmFinalizeGUTA).unwrap();
        finalizer_info.circuit_type = ProvingJobCircuitType::WrappedSignatureProof;
        verifier.gcv.library.info_map.insert(ProvingJobCircuitType::WrappedSignatureProof, finalizer_info);
        verifier.gcv.common.insert_common_data(ProvingJobCircuitType::WrappedSignatureProof, matching.common);
        assert!(verifier.verify_zk_proof_from_slice_check_public_inputs_hash(ProvingJobCircuitType::WrappedSignatureProof as u32, &bytes, expected).is_ok());
        let error = infer_root_job_type::<N>(&verifier, &submission, &bytes).unwrap_err();
        assert!(error.to_string().contains("not a valid registered GUTA root proof"));
    }

    fn node_id(seed: u8) -> NodeId {
        let mut raw = [0u8; 38];
        raw[..6].copy_from_slice(&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
        raw[6..].fill(seed);
        NodeId::from_raw(raw).unwrap()
    }

    fn address(port: u16, node_id: NodeId) -> String {
        format!("/ip4/127.0.0.1/tcp/{port}/p2p/{}", node_id.to_peer_id())
    }

    #[test]
    fn public_network_keys_are_explicit_and_fail_closed() {
        assert_eq!(public_network_key(PsyChainNetworkType::LocalDevnet).unwrap(), "localhost");
        assert_eq!(public_network_key(PsyChainNetworkType::PsyPublicTestnet).unwrap(), "sepolia");
        assert_eq!(public_network_key(PsyChainNetworkType::PsyMainnet).unwrap(), "ethereum");
        assert!(public_network_key(PsyChainNetworkType::InternalDevnet).is_err());
    }

    #[test]
    fn bootnodes_exclude_only_the_local_peer() {
        let local = node_id(1);
        let remote = node_id(2);
        let local_address = address(41001, local);
        let remote_processor = address(41002, remote);
        let remote_edge = address(41102, remote);
        let bootnodes = vec![
            local_address,
            remote_processor.clone(),
            remote_edge.clone(),
        ];

        assert_eq!(
            bootnodes_without_local_peer(&bootnodes, local).unwrap(),
            vec![remote_processor, remote_edge]
        );
    }

    #[test]
    fn bootnode_filter_rejects_invalid_addresses() {
        assert!(bootnodes_without_local_peer(&["/ip4/127.0.0.1/tcp/41001".into()], node_id(1)).is_err());
    }

    #[test]
    fn public_realm_validator_count_rejects_65() {
        assert!(validate_realm_validator_count(7, 65).is_err());
    }

    #[test]
    fn processor_address_peer_id_matches_declared_node_id() {
        let processor = node_id(3);
        validate_node_addresses(
            &[address(41003, processor)],
            processor,
            "processor",
        )
        .unwrap();
    }

    #[test]
    fn processor_address_peer_id_must_match_declared_node_id() {
        let error = validate_node_addresses(
            &[address(41003, node_id(4))],
            node_id(3),
            "processor",
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not match NodeId PeerId"));
    }

    #[test]
    fn edge_address_peer_id_matches_declared_node_id() {
        let edge = node_id(5);
        validate_node_addresses(&[address(41105, edge)], edge, "edge").unwrap();
    }

    #[test]
    fn edge_address_peer_id_must_match_declared_node_id() {
        let error = validate_node_addresses(
            &[address(41105, node_id(6))],
            node_id(5),
            "edge",
        )
        .unwrap_err();
        assert!(error.to_string().contains("does not match NodeId PeerId"));
    }

    #[test]
    fn public_network_accepts_active_and_inactive_realms() {
        let processor = node_id(7);
        let edge = node_id(8);
        let network = PublicNetworkConfig {
            realm_user_tree_height: 20,
            p2p: PublicP2pConfig { checkpoints_per_epoch: 10 },
            realm_configs: vec![
                PublicRealmConfig {
                    id: 0,
                    validators: vec![PublicValidator {
                        validator_user_id: 1,
                        processor_node_id: hex::encode(processor.as_raw()),
                        bls_public_key: String::new(),
                        processor_addresses: vec![address(41001, processor)],
                        edge_nodes: vec![PublicNode {
                            node_id: hex::encode(edge.as_raw()),
                            addresses: vec![address(41101, edge)],
                        }],
                    }],
                },
                PublicRealmConfig { id: 1, validators: Vec::new() },
            ],
        };

        validate_public_network(&network).unwrap();
        selected_realm(&network, 0).unwrap();
    }

    #[test]
    fn selected_inactive_realm_is_rejected() {
        let network = PublicNetworkConfig {
            realm_user_tree_height: 20,
            p2p: PublicP2pConfig { checkpoints_per_epoch: 10 },
            realm_configs: vec![PublicRealmConfig { id: 1, validators: Vec::new() }],
        };

        let error = selected_realm(&network, 1).err().expect("empty selected Realm must fail");
        assert!(error.to_string().contains("validator count 0"));
    }

    #[test]
    fn validator_without_edge_is_rejected() {
        let processor = node_id(7);
        let network = PublicNetworkConfig {
            realm_user_tree_height: 20,
            p2p: PublicP2pConfig { checkpoints_per_epoch: 10 },
            realm_configs: vec![PublicRealmConfig {
                id: 0,
                validators: vec![PublicValidator {
                    validator_user_id: 1,
                    processor_node_id: hex::encode(processor.as_raw()),
                    bls_public_key: String::new(),
                    processor_addresses: vec![address(41001, processor)],
                    edge_nodes: Vec::new(),
                }],
            }],
        };
        let error = validate_public_network(&network).unwrap_err();
        assert!(error.to_string().contains("has no edge nodes"));
    }
}
