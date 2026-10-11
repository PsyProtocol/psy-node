use anyhow::{Context as _, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use plonky2::{
    field::{goldilocks_field::GoldilocksField as F, types::{Field, PrimeField64}},
    hash::{hash_types::{HashOut, RichField}, poseidon::PoseidonHash},
    plonk::config::{AlgebraicHasher, Hasher, PoseidonGoldilocksConfig},
};
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::qhashable::QFieldHashable};
use psy_client_common::{data::qhashout::QHashOut, traits::to_qfelts::ToQFelts};
use psy_client_data::{
    api::reward::PsyProoffMinerRewardProofWithRewardPreimage,
    reward_claim::{circuit_set_hash, load_aggregate_setup_config, CircuitSetRegistration, NetworkConfig, RewardClaim, RewardLeaf, GOLDILOCKS_MODULUS},
    config::store_config::PsyHasher,
    qdata::{
        checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf},
        user::PsyUserLeaf,
    },
    traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync},
};
use psy_config::network_constants::{CHECKPOINT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT};
use psy_plonky2_circuits::bridge::{
    circuits::reward_chain::{
        AuthenticatedJobWitness, RewardMergeCircuit, RewardMergeWitness, RewardRootCircuit,
        RewardRootWitness, RewardSegmentCircuit, RewardSegmentSourceWitness, RewardSegmentWitness,
        RewardTagWitness, REWARD_LEAF_CAPACITY, REWARD_MERGE_STATEMENT_LEN,
        REWARD_ROOT_STATEMENT_LEN, REWARD_SEGMENT_STATEMENT_LEN,
    },
    gadgets::reward_nullifier::{
        RewardNullifierSourceWitness, INNER_EMPTY_ROOT, REWARD_NULLIFIER_EMPTY_LEAF,
        REWARD_NULLIFIER_EMPTY_ROOT, REWARD_NULLIFIER_INNER_HEIGHT,
        REWARD_NULLIFIER_OCCUPIED_LEAF, REWARD_NULLIFIER_OUTER_HEIGHT,
    },
};
use psy_provider::provider::RpcProvider;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    #[error("aggregation context changed; fresh witness and authorization required")]
    ContextChanged(AggregationContext),
    #[error("aggregation service rejected claim: {0}")]
    Rejected(String),
    #[error("invalid aggregation response: {0}")]
    InvalidResponse(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AggregationContext {
    pub version: u32,
    pub config_hash: String,
    pub end_checkpoint_id: String,
    pub end_checkpoint_root: [String; 4],
    pub context_id: String,
    pub max_proof_bytes: usize,
    pub max_records: usize,
}

#[derive(Deserialize)]
struct Envelope<T> { success: bool, data: Option<T>, error: Option<String> }
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ErrorData { error_code: String, current_context: Option<AggregationContext> }
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimStatus {
    pub claim_id: String,
    pub state: String,
    pub context_id: String,
    pub family: u8,
    pub opening_digest: Option<String>,
    pub error_code: Option<String>,
    pub current_context: Option<AggregationContext>,
}

pub fn word(value: u64) -> [u8; 32] { let mut out = [0; 32]; out[24..].copy_from_slice(&value.to_be_bytes()); out }
pub fn digest(parts: &[&[u8]]) -> String { use tiny_keccak::{Hasher, Keccak}; let mut hash = Keccak::v256(); for part in parts { hash.update(part); } let mut out = [0; 32]; hash.finalize(&mut out); format!("0x{}", hex::encode(out)) }
fn decimal(value: &str) -> Result<u64> { let number: u64 = value.parse()?; anyhow::ensure!(number.to_string() == value, "noncanonical decimal"); Ok(number) }
pub fn hex32(value: &str) -> Result<[u8; 32]> { anyhow::ensure!(value.len() == 66 && value.starts_with("0x") && value[2..].bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "noncanonical hex32"); Ok(hex::decode(&value[2..])?.try_into().map_err(|_| ClaimError::InvalidResponse("hex32 width"))?) }
pub fn address(value: &str) -> Result<[u8; 20]> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    let bytes = if bytes.len() == 32 { anyhow::ensure!(bytes[..12] == [0; 12], "address exceeds160 bits"); &bytes[12..] } else { &bytes[..] };
    Ok(bytes.try_into().map_err(|_| anyhow::anyhow!("address must be20 bytes or zero-padded32 bytes"))?)
}
pub fn hash_words(hash: QHashOut<F>) -> [u64; 4] { hash.0.elements.map(|v| v.to_canonical_u64()) }
pub fn verify_path(path: &MerkleProofCore<QHashOut<F>>, root: QHashOut<F>, index: u64, value: QHashOut<F>, height: usize) -> Result<()> {
    anyhow::ensure!(height < 64 && index < (1u64 << height) && path.root == root && path.index == index && path.value == value && path.siblings.len() == height && path.verify::<PsyHasher>(), "chosen-end membership mismatch"); Ok(())
}

pub fn reward_record(checkpoint: u64, user_id: u32, recipient: [u8; 20], proof: &PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<F>>) -> Result<(RewardLeaf, RewardTagWitness)> {
    let tag = &proof.inner.tag_tree_proof;
    let height = u8::try_from(tag.siblings.len())?;
    anyhow::ensure!((2..=21).contains(&height), "reward proof must reach full GUTA root");
    let path_index = u32::try_from(tag.index)?;
    let claim = RewardLeaf { claim_checkpoint_id: checkpoint, user_id, height, path_index, nullifier_index: ((1u32 << height) - 1).checked_add(path_index).context("reward nullifier overflow")?, recipient };
    claim.validate()?;
    let mut siblings = [parth_core::pgoldilocks::QHashOut(QHashOut::<F>::ZERO.0); 21];
    let mut parent_tags = siblings;
    for (i, node) in tag.siblings.iter().enumerate() { siblings[i] = parth_core::pgoldilocks::QHashOut(node.sibling.0); parent_tags[i] = parth_core::pgoldilocks::QHashOut(node.parent_tag.0); }
    Ok((claim, RewardTagWitness { tag_preimage: parth_core::pgoldilocks::QHashOut(proof.reward_tree_tag_preimage.0), leaf_left: parth_core::pgoldilocks::QHashOut(tag.leaf.left.0), leaf_right: parth_core::pgoldilocks::QHashOut(tag.leaf.right.0), leaf_tag: parth_core::pgoldilocks::QHashOut(tag.leaf.tag.0), siblings, parent_tags }))
}


pub struct ClaimClient {
    pub config: NetworkConfig,
    pub provider: RpcProvider,
    pub http: reqwest::Client,
    pub url: String,
}

impl ClaimClient {
    pub fn new(config: NetworkConfig, provider: RpcProvider, services_url: &str) -> Result<Self> {
        config.validate()?;
        Ok(Self { config, provider, http: reqwest::Client::new(), url: services_url.trim_end_matches('/').to_owned() })
    }
}
impl ClaimClient {
    pub fn load(rpc_config: &str, config_file: &str, services_url: &str) -> Result<(Self, ClaimCircuits)> {
        let approved = load_aggregate_setup_config(std::path::Path::new(config_file))?;
        let config = approved.config;
        let settings = psy_config::PsyConfigGoldilocks::from_file(rpc_config)?;
        let network = settings.get_current_network()?;
        let magic = u64::from_str_radix(network.magic.trim_start_matches("0x"), 16)?;
        anyhow::ensure!(magic == config.network_magic, "aggregate/provider network mismatch");
        let circuits = ClaimCircuits::build(&config, &approved.registrations)?;
        Ok((Self::new(config, RpcProvider::new_with_config(network)?, services_url)?, circuits))
}
}

impl ClaimClient {
    pub fn validate_context(&self, context: &AggregationContext) -> Result<(u64, [u64; 4])> {
        let id = decimal(&context.end_checkpoint_id)?;
        let end = u32::try_from(id).context("selected end exceeds u32")?;
        let mut root = [0; 4];
        for (out, text) in root.iter_mut().zip(&context.end_checkpoint_root) { *out = decimal(text)?; anyhow::ensure!(*out < GOLDILOCKS_MODULUS, "noncanonical context root"); }
        let config = self.config.config_hash()?;
        let expected = psy_client_data::reward_claim::claim_context_id(config, end, root).map_err(|error| anyhow::anyhow!("{error:?}"))?;
        anyhow::ensure!(context.version == 4 && context.max_proof_bytes == 16_777_216 && context.max_records == 32 && hex32(&context.config_hash)? == config && hex32(&context.context_id)? == expected, "context identity/configuration mismatch");
        Ok((id, root))
    }
    pub fn validate_status(&self, context: &AggregationContext, claim_id: &str, family: u8, status: &ClaimStatus) -> Result<()> {
        anyhow::ensure!(status.claim_id == claim_id && family == 3 && status.family == 3, "claim status identity/family mismatch");
        hex32(&status.context_id)?;
        if status.state == "queued" { anyhow::ensure!(status.context_id == context.context_id, "queued proof context mismatch"); }
        match status.state.as_str() {
            "refresh_required" => { let current = status.current_context.as_ref().context("refresh_required requires currentContext")?; self.validate_context(current)?; return Err(ClaimError::ContextChanged(current.clone()).into()); }
            "rejected" => { anyhow::ensure!(status.current_context.is_none(), "rejected status has currentContext"); return Err(ClaimError::Rejected(status.error_code.clone().context("rejected status requires errorCode")?).into()); }
            "queued" | "included" | "applied" => anyhow::ensure!(status.current_context.is_none() && status.error_code.is_none(), "invalid claim status fields"),
            _ => return Err(ClaimError::InvalidResponse("unknown claim state").into()),
        }
        if status.state != "queued" { hex32(status.opening_digest.as_deref().context("included/applied requires openingDigest")?)?; }
        else { anyhow::ensure!(status.opening_digest.is_none(), "queued claim has openingDigest"); }
        Ok(())
    }
    pub async fn response<T: serde::de::DeserializeOwned>(&self, mut response: reqwest::Response) -> Result<T> {
        let status = response.status();
        let body = response.bytes().await?;
        anyhow::ensure!(body.len() <= 24 * 1024 * 1024, "aggregation response exceeds24MiB");
        let envelope: Envelope<serde_json::Value> = serde_json::from_slice(&body)?;
        if !envelope.success {
            let error: ErrorData = serde_json::from_value(envelope.data.context("missing aggregation error data")?)?;
            if error.error_code == "ContextChanged" {
                let current = error.current_context.context("ContextChanged requires currentContext")?;
                self.validate_context(&current)?;
                return Err(ClaimError::ContextChanged(current).into());
            }
            anyhow::ensure!(error.current_context.is_none(), "unexpected currentContext on error");
            return Err(ClaimError::Rejected(error.error_code).into());
        }
        anyhow::ensure!(status.is_success() && envelope.error.is_none(), "inconsistent aggregation response");
        Ok(serde_json::from_value(envelope.data.context("missing aggregation response data")?)?)
    }
    pub async fn context(&self) -> Result<AggregationContext> {
        let context = self.response(self.http.get(format!("{}/api/v1/bridge/aggregation/context", self.url)).send().await?).await?;
        self.validate_context(&context)?;
        Ok(context)
    }
    pub async fn checkpoint(&self, context: &AggregationContext) -> Result<(psy_client_data::qdata::checkpoint::PsyCheckpointLeaf<F>, psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots<F>)> {
        let (id, root) = self.validate_context(context)?;
        anyhow::ensure!(hash_words(self.provider.get_checkpoint_tree_root(id).await?) == root, "published context differs from configured coordinator checkpoint");
        let leaf = self.provider.get_checkpoint_leaf_data(id).await?;
        let roots = self.provider.get_checkpoint_global_state_roots(id).await?;
        anyhow::ensure!(roots.qfhash::<PsyHasher>() == leaf.global_chain_root, "checkpoint global roots mismatch");
        let path = self.provider.get_checkpoint_tree_merkle_proof(id, id).await?;
        verify_path(&path, QHashOut::from_values(root[0], root[1], root[2], root[3]), id, leaf.qfhash::<PsyHasher>(), psy_config::network_constants::CHECKPOINT_TREE_HEIGHT as usize)?;
        Ok((leaf, roots))
    }
    async fn post_claim<T: Serialize>(&self, request: &T) -> Result<ClaimStatus> {
        self.response(self.http.post(format!("{}/api/v1/bridge/aggregation/claims", self.url)).json(request).send().await?).await
    }
    pub async fn submit_reward(&self, context: &AggregationContext, request: &RewardClaimRequest) -> Result<ClaimStatus> {
        self.validate_context(context)?;
        anyhow::ensure!(request.version == 2 && request.context_id == context.context_id && request.kind == "reward", "reward claim body mismatch");
        anyhow::ensure!(STANDARD.decode(&request.anchor)?.len() == 2696, "reward anchor is not 2696 bytes");
        anyhow::ensure!(STANDARD.decode(&request.proof)?.len() <= context.max_proof_bytes, "reward proof exceeds context bound");
        self.post_claim(request).await
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewardClaimRequest {
    pub version: u32,
    pub context_id: String,
    pub kind: String,
    pub proof: String,
    pub anchor: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewardConsumptionState {
    pub version: u32,
    pub config_hash: String,
    pub chain_id: String,
    pub payer: String,
    pub user_id: u32,
    pub confirmed: BTreeMap<u32, Vec<u32>>,
    pub pending: Option<RewardPendingClaim>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewardPendingSelection {
    pub realm_jobs: Vec<(u64, u64, psy_client_common::job::id::QProvingJobDataIDWithRewardPreimage)>,
    pub coordinator_jobs: Vec<(u64, psy_client_common::job::id::QProvingJobDataIDWithRewardPreimage)>,
}
impl RewardPendingSelection {
    pub fn jobs_len(&self) -> usize { self.realm_jobs.len() + self.coordinator_jobs.len() }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewardPendingClaim {
    pub jobs: RewardPendingSelection,
    pub coordinates: BTreeMap<u32, Vec<u32>>,
    pub request: RewardClaimRequest,
    pub record: Vec<u8>,
}
pub fn reward_root_bytes(root: HashOut<F>) -> Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    for (index, limb) in root.elements.into_iter().enumerate() {
        let value = limb.to_canonical_u64();
        anyhow::ensure!(value < GOLDILOCKS_MODULUS, "noncanonical reward nullifier root");
        bytes[index * 8..index * 8 + 8].copy_from_slice(&value.to_be_bytes());
    }
    Ok(bytes)
}
fn reward_coordinate(source: u32, height: u8, path_index: u32) -> Result<(u32, u32)> {
    anyhow::ensure!((2..=21).contains(&height), "reward nullifier height is outside 2..=21");
    let offset = (1u32 << height) - 1;
    let inner = offset.checked_add(path_index).context("reward nullifier overflow")?;
    anyhow::ensure!(inner < 1u32 << REWARD_NULLIFIER_INNER_HEIGHT, "reward inner coordinate exceeds its tree");
    Ok((source, inner))
}
pub fn rebuild_reward_tree(coordinates: &BTreeMap<u32, Vec<u32>>) -> Result<(BTreeMap<(usize, u64), HashOut<F>>, BTreeMap<u32, (BTreeMap<(usize, u64), HashOut<F>>, HashOut<F>)>, HashOut<F>)> {
    let mut outer = BTreeMap::new();
    let mut inners = BTreeMap::new();
    let mut root = *REWARD_NULLIFIER_EMPTY_ROOT;
    for (source, values) in coordinates {
        anyhow::ensure!(values.windows(2).all(|pair| pair[0] < pair[1]), "reward coordinates are not strictly ordered");
        let mut nodes = BTreeMap::new();
        let mut inner = *INNER_EMPTY_ROOT;
        for value in values {
            inner = insert_nullifier::<REWARD_NULLIFIER_INNER_HEIGHT>(&mut nodes, REWARD_NULLIFIER_EMPTY_LEAF, u64::from(*value), REWARD_NULLIFIER_OCCUPIED_LEAF)?.new_root;
        }
        root = insert_nullifier::<REWARD_NULLIFIER_OUTER_HEIGHT>(&mut outer, *INNER_EMPTY_ROOT, u64::from(*source), inner)?.new_root;
        inners.insert(*source, (nodes, inner));
    }
    Ok((outer, inners, root))
}

// Exact archive source registration, including serialized common/verifier digests.
fn circuit_set_registration(family: u16, variant: u8, data: &plonky2::plonk::circuit_data::CircuitData<F, PoseidonGoldilocksConfig, 2>) -> Result<CircuitSetRegistration> {
    let fingerprint = psy_plonky2_circuits::proof_minifier::pm_core::get_circuit_fingerprint_generic::<2, F, PoseidonGoldilocksConfig>(&data.verifier_only).elements.map(|limb| limb.to_canonical_u64());
    anyhow::ensure!(fingerprint != [0; 4], "missing source circuit pin");
    let hash = |bytes: &[u8]| {
        use tiny_keccak::{Hasher, Keccak};
        let mut hasher = Keccak::v256();
        hasher.update(bytes);
        let mut digest = [0; 32];
        hasher.finalize(&mut digest);
        digest
    };
    Ok(CircuitSetRegistration {
        family, level: 0, variant, pi_words: data.common.num_public_inputs.try_into()?, fingerprint,
        common_digest: hash(&data.common.to_bytes(&psy_common_circuit::serialization::PsyGateSerializer).map_err(|error| anyhow::anyhow!("common serialization: {error:?}"))?),
        verifier_digest: hash(&data.verifier_only.to_bytes().map_err(|error| anyhow::anyhow!("verifier serialization: {error:?}"))?),
        identity_fingerprint: [0; 4],
    })
}

pub struct ClaimCircuits {
    pub reward_segment: RewardSegmentCircuit,
    pub reward_merge: RewardMergeCircuit,
    pub reward_root: RewardRootCircuit,
}
impl ClaimCircuits {
    pub fn build(config: &NetworkConfig, registry: &[CircuitSetRegistration]) -> Result<Self> {
        config.validate()?;
        anyhow::ensure!(circuit_set_hash(registry)? == config.circuit_set_hash, "operator circuit registry differs from configuration");
        let reward_segment = RewardSegmentCircuit::new();
        let reward_merge = RewardMergeCircuit::new(&reward_segment);
        let reward_root = RewardRootCircuit::new(&reward_merge);
        anyhow::ensure!(reward_segment.circuit_data.common.num_public_inputs == REWARD_SEGMENT_STATEMENT_LEN, "reward segment width differs from 22");
        anyhow::ensure!(reward_merge.circuit_data.common.num_public_inputs == REWARD_MERGE_STATEMENT_LEN + 68, "reward merge width differs from 90");
        anyhow::ensure!(reward_root.circuit_data.common.num_public_inputs == REWARD_ROOT_STATEMENT_LEN, "reward root width differs from 30");
        for (family, variant, data) in [
            (14, 1, &reward_segment.circuit_data),
            (14, 0, &reward_merge.circuit_data),
            (15, 0, &reward_root.circuit_data),
        ] {
            let row = circuit_set_registration(family, variant, data)?;
            anyhow::ensure!(registry.iter().find(|pin| (pin.family, pin.level, pin.variant) == (family, 0, variant)) == Some(&row), "reward circuit differs from source registry");
        }
        Ok(Self { reward_segment, reward_merge, reward_root })
    }
}

impl ClaimClient {
    pub async fn prove_reward(&self, context: &AggregationContext, segment: &RewardSegmentCircuit, merge: &RewardMergeCircuit, root: &RewardRootCircuit, user_id: u32, recipient: [u32; 8], private_key: HashOut<F>, jobs: &BTreeMap<u32, Vec<AuthenticatedJobWitness>>, confirmed: &BTreeMap<u32, Vec<u32>>) -> Result<(RewardClaimRequest, Vec<u8>, BTreeMap<u32, Vec<u32>>)> {
        let (end_id, end_root) = self.validate_context(context)?;
        let anchor_id = u32::try_from(end_id)?;
        anyhow::ensure!(recipient[5..].iter().all(|limb| *limb == 0) && recipient != [0; 8], "reward recipient must be a nonzero 160-bit address");
        anyhow::ensure!(!jobs.is_empty() && jobs.values().all(|batch| !batch.is_empty()), "reward source has no jobs");
        let anchor_leaf = self.provider.get_checkpoint_leaf_data(end_id).await?;
        let anchor_path = self.provider.get_checkpoint_tree_merkle_proof(end_id, end_id).await?;
        let checkpoint_root = QHashOut::from_values(end_root[0], end_root[1], end_root[2], end_root[3]);
        verify_path(&anchor_path, checkpoint_root, end_id, anchor_leaf.qfhash::<PsyHasher>(), CHECKPOINT_TREE_HEIGHT as usize)?;
        const SEGMENT_OLD_NULLIFIER: usize = 5;
        const SEGMENT_NEW_NULLIFIER: usize = 9;
        let (mut outer_nodes, mut prior_inners, initial_root) = rebuild_reward_tree(confirmed)?;
        let mut old_root = initial_root;
        let mut segments = Vec::new();
        for (source_id, batch) in jobs {
            anyhow::ensure!(*source_id <= anchor_id, "reward source is newer than the admission anchor");
            let source_leaf = self.provider.get_checkpoint_leaf_data(u64::from(*source_id)).await?;
            let source_path = self.provider.get_checkpoint_tree_merkle_proof(end_id, u64::from(*source_id)).await?;
            verify_path(&source_path, checkpoint_root, u64::from(*source_id), source_leaf.qfhash::<PsyHasher>(), CHECKPOINT_TREE_HEIGHT as usize)?;
            let completed = u128::from(source_leaf.stats.pm_jobs_completed.gutas_completed.to_canonical_u64());
            let fees = u128::from(source_leaf.stats.guta_fees_collected.to_canonical_u64());
            let coordinate = |job: &AuthenticatedJobWitness| -> Result<u64> {
                let offset = 1u32.checked_shl(u32::from(job.height)).context("reward nullifier height exceeds u32")?.checked_sub(1).context("reward nullifier height is zero")?;
                let index = offset.checked_add(job.path_index).context("reward nullifier overflow")?;
                Ok((u64::from(*source_id) << REWARD_NULLIFIER_INNER_HEIGHT) + u64::from(index))
            };
            let mut ordered = batch.clone();
            ordered.sort_by_key(|job| coordinate(job).unwrap_or(u64::MAX));
            let keys = ordered.iter().map(coordinate).collect::<Result<Vec<_>>>()?;
            anyhow::ensure!(keys.windows(2).all(|pair| pair[0] < pair[1]), "reward jobs are not strictly ordered");
            let (mut inner_nodes, mut inner_root) = prior_inners.remove(source_id).unwrap_or_else(|| (BTreeMap::new(), *INNER_EMPTY_ROOT));
            for chunk in ordered.chunks(REWARD_LEAF_CAPACITY) {
                let chunk_keys = chunk.iter().map(|job| reward_coordinate(*source_id, job.height, job.path_index).map(|(_, inner)| inner)).collect::<Result<Vec<_>>>()?;
                let prior = confirmed.get(source_id).map(Vec::as_slice).unwrap_or(&[]);
                anyhow::ensure!(chunk_keys.iter().all(|key| prior.binary_search(key).is_err()), "reward coordinate was already consumed");
                let jobs_count = u128::try_from(chunk.len())?;
                anyhow::ensure!(completed > 0, "reward source has no completed jobs");
                let amount = (jobs_count * fees) / completed;
                let chunk_start = inner_root;
                let mut inner_siblings = Vec::with_capacity(chunk.len());
                for job in chunk {
                    let update = insert_nullifier::<REWARD_NULLIFIER_INNER_HEIGHT>(&mut inner_nodes, REWARD_NULLIFIER_EMPTY_LEAF, u64::from(coordinate(job)? & ((1u64 << REWARD_NULLIFIER_INNER_HEIGHT) - 1)), REWARD_NULLIFIER_OCCUPIED_LEAF)?;
                    inner_siblings.push(update.siblings);
                    inner_root = update.new_root;
                }
                let source_index = u64::from(*source_id);
                let before = outer_nodes.get(&(0, source_index)).copied().unwrap_or(*INNER_EMPTY_ROOT);
                let before_siblings: [HashOut<F>; REWARD_NULLIFIER_OUTER_HEIGHT] = std::array::from_fn(|level| outer_nodes.get(&(level, (source_index >> level) ^ 1)).copied().unwrap_or_else(|| empty_subtree(*INNER_EMPTY_ROOT, level)));
                let mut before_root = before;
                for level in 0..REWARD_NULLIFIER_OUTER_HEIGHT {
                    let sibling = before_siblings[level];
                    before_root = if (source_index >> level) & 1 == 1 { PoseidonHash::two_to_one(sibling, before_root) } else { PoseidonHash::two_to_one(before_root, sibling) };
                }
                anyhow::ensure!(before_root == old_root && before == chunk_start, "reward outer pre-update proof mismatch");
                let outer = insert_nullifier::<REWARD_NULLIFIER_OUTER_HEIGHT>(&mut outer_nodes, *INNER_EMPTY_ROOT, source_index, inner_root)?;
                segments.push((RewardSegmentWitness {
                    user_id, anchor_checkpoint_id: anchor_id, checkpoint_tree_root: checkpoint_root.0, old_nullifier_root: old_root,
                    source: RewardSegmentSourceWitness {
                        source_checkpoint_id: *source_id, checkpoint_leaf: source_leaf.clone(), checkpoint_siblings: fixed_siblings(&source_path, u64::from(*source_id), source_leaf.qfhash::<PsyHasher>(), checkpoint_root)?,
                        amount_limbs: [amount as u32, (amount >> 32) as u32], jobs: chunk.to_vec(),
                        nullifier: RewardNullifierSourceWitness { old_inner_root: chunk_start, outer_siblings: outer.siblings, inner_siblings },
                    },
                }, outer.new_root));
                old_root = outer.new_root;
            }
        }
        let mut proofs = Vec::with_capacity(segments.len());
        for (input, new_root) in &segments {
            let proof = segment.prove(input)?;
            anyhow::ensure!(proof.public_inputs.len() == REWARD_SEGMENT_STATEMENT_LEN, "reward segment statement width mismatch");
            let read = |offset: usize| QHashOut::<F>::from_values(proof.public_inputs[offset].to_canonical_u64(), proof.public_inputs[offset + 1].to_canonical_u64(), proof.public_inputs[offset + 2].to_canonical_u64(), proof.public_inputs[offset + 3].to_canonical_u64()).0;
            anyhow::ensure!(read(SEGMENT_OLD_NULLIFIER) == input.old_nullifier_root, "reward segment initial root mismatch");
            anyhow::ensure!(read(SEGMENT_NEW_NULLIFIER) == *new_root, "reward segment computed root mismatch");
            proofs.push(merge.prove(&RewardMergeWitness::Leaf { segment: proof })?);
        }
        while proofs.len() > 1 {
            let mut reduced = Vec::with_capacity(proofs.len().div_ceil(2));
            let mut round = proofs.into_iter();
            while let Some(left) = round.next() {
                reduced.push(match round.next() {
                    Some(right) => merge.prove(&RewardMergeWitness::Pair { left, right })?,
                    None => left,
                });
            }
            proofs = reduced;
        }
        let global_roots = self.provider.get_checkpoint_global_state_roots(end_id).await?;
        anyhow::ensure!(global_roots.qfhash::<PsyHasher>() == anchor_leaf.global_chain_root, "reward anchor global roots mismatch");
        let user = self.provider.get_user_leaf_data(end_id, u64::from(user_id)).await?;
        let user_path = self.provider.get_user_tree_merkle_proof(end_id, u64::from(user_id)).await?;
        verify_path(&user_path, global_roots.user_tree_root, u64::from(user_id), user.alghash::<PoseidonHash>(), GLOBAL_USER_TREE_HEIGHT as usize)?;
        let merge_proof = proofs.pop().context("reward merge has no proof")?;
        anyhow::ensure!(merge_proof.public_inputs.len() >= REWARD_MERGE_STATEMENT_LEN, "reward merge statement is short");
        let proved = root.prove(&RewardRootWitness {
            recipient, anchor_checkpoint_id: anchor_id, anchor_leaf, anchor_siblings: fixed_siblings(&anchor_path, end_id, anchor_leaf.qfhash::<PsyHasher>(), checkpoint_root)?,
            global_roots, user_leaf: user, user_siblings: fixed_siblings(&user_path, u64::from(user_id), user.alghash::<PoseidonHash>(), global_roots.user_tree_root)?, private_key, merge_proof,
        })?;
        root.circuit_data.verify(proved.clone())?;
        let claim = RewardClaim::from_public_inputs(self.config.ethereum_index, &proved.public_inputs.iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>().try_into().map_err(|_| ClaimError::InvalidResponse("reward root width"))?)?;
        anyhow::ensure!(claim.user_id == user_id && claim.old_nullifier_root == hash_words(QHashOut(initial_root)), "reward root statement mismatch");
        let mut added_coordinates = BTreeMap::new();
        for (source, batch) in jobs { let mut values = batch.iter().map(|job| reward_coordinate(*source, job.height, job.path_index).map(|(_, inner)| inner)).collect::<Result<Vec<_>>>()?; values.sort_unstable(); added_coordinates.insert(*source, values); }
        Ok((RewardClaimRequest { version: 2, context_id: context.context_id.clone(), kind: "reward".to_owned(), proof: STANDARD.encode(proved.to_bytes()), anchor: STANDARD.encode(encode_reward_anchor(anchor_id, &anchor_leaf, &anchor_path, &global_roots, &user, &user_path)?) }, claim.encode()?, added_coordinates))
    }
}

fn fixed_siblings<const N: usize>(path: &MerkleProofCore<QHashOut<F>>, index: u64, value: QHashOut<F>, root: QHashOut<F>) -> Result<[HashOut<F>; N]> {
    verify_path(path, root, index, value, N)?;
    Ok(std::array::from_fn(|index| path.siblings[index].0))
}

struct MerkleUpdate<const N: usize> { siblings: [HashOut<F>; N], new_root: HashOut<F> }
fn empty_subtree(leaf: HashOut<F>, height: usize) -> HashOut<F> {
    let mut root = leaf;
    for _ in 0..height { root = PoseidonHash::two_to_one(root, root); }
    root
}
fn insert_nullifier<const N: usize>(nodes: &mut BTreeMap<(usize, u64), HashOut<F>>, leaf: HashOut<F>, index: u64, new_value: HashOut<F>) -> Result<MerkleUpdate<N>> {
    anyhow::ensure!(index < 1u64 << N, "reward nullifier index exceeds its tree");
    let siblings = std::array::from_fn(|level| nodes.get(&(level, (index >> level) ^ 1)).copied().unwrap_or_else(|| empty_subtree(leaf, level)));
    let mut cursor = new_value;
    nodes.insert((0, index), new_value);
    for level in 0..N {
        let parent = index >> (level + 1);
        let right = (index >> level) & 1 == 1;
        cursor = if right { PoseidonHash::two_to_one(siblings[level], cursor) } else { PoseidonHash::two_to_one(cursor, siblings[level]) };
        nodes.insert((level + 1, parent), cursor);
    }
    Ok(MerkleUpdate { siblings, new_root: cursor })
}
fn encode_reward_anchor(anchor_id: u32, leaf: &PsyCheckpointLeaf<F>, path: &MerkleProofCore<QHashOut<F>>, roots: &PsyCheckpointGlobalStateRoots<F>, user: &PsyUserLeaf<F>, user_path: &MerkleProofCore<QHashOut<F>>) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(2696);
    let felt = |value: F| { anyhow::ensure!(value.to_canonical_u64() < GOLDILOCKS_MODULUS, "noncanonical reward anchor field"); Ok(value.to_canonical_u64().to_le_bytes()) };
    let hash = |bytes: &mut Vec<u8>, value: &QHashOut<F>| -> Result<()> { for limb in value.0.elements { bytes.extend_from_slice(&felt(limb)?); } Ok(()) };
    bytes.extend_from_slice(&(u64::from(anchor_id)).to_le_bytes());
    hash(&mut bytes, &leaf.global_chain_root)?;
    for value in leaf.stats.to_qfelts() { bytes.extend_from_slice(&felt(value)?); }
    for value in roots.to_qfelts() { bytes.extend_from_slice(&felt(value)?); }
    anyhow::ensure!(path.siblings.len() == 32, "reward anchor checkpoint path is not height 32");
    for sibling in &path.siblings { hash(&mut bytes, sibling)?; }
    for value in [user.public_key, user.user_state_tree_root] { hash(&mut bytes, &value)?; }
    for value in [user.balance, user.nonce, user.last_checkpoint_id, user.event_index, user.user_id] { bytes.extend_from_slice(&felt(value)?); }
    anyhow::ensure!(user_path.siblings.len() == 32, "reward anchor user path is not height 32");
    for sibling in &user_path.siblings { hash(&mut bytes, sibling)?; }
    anyhow::ensure!(bytes.len() == 2696, "reward anchor codec is not canonical");
    Ok(bytes)
}


#[cfg(test)]
mod status_tests {
    use super::*;

    #[test]
    fn status_accepts_only_reward_family_and_valid_state_fields() {
        use psy_client_data::reward_claim::{claim_context_id, ChainConfig, BRIDGE_USER_ID};
        let config = NetworkConfig {
            version: 1, network_magic: 1, bridge_user_id: BRIDGE_USER_ID, circuit_set_hash: [1; 32],
            chains: vec![ChainConfig { chain_index: 0, chain_id: [1; 32], bridge: [1; 20],
                state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: [0; 4] }],
            ethereum_index: 0, reward_payer: [3; 20], reward_token: [4; 20],
            reward_per_claim: word(1), reward_token_decimals: 18, max_withdrawals: 32, max_rewards: 32,
        };
        let config_hash = config.config_hash().unwrap();
        let http = reqwest::Client::new();
        let provider = RpcProvider { client: std::sync::Arc::new(http.clone()), realm_configs: Default::default(),
            coordinator_configs: Default::default(), users_per_realm: 1, current_user_id: 0 };
        let client = ClaimClient { config, provider, http, url: String::new() };
        let context = AggregationContext {
            version: 4, config_hash: format!("0x{}", hex::encode(config_hash)), end_checkpoint_id: "1".into(),
            end_checkpoint_root: std::array::from_fn(|_| "0".into()),
            context_id: format!("0x{}", hex::encode(claim_context_id(config_hash, 1, [0; 4]).unwrap())),
            max_proof_bytes: 16_777_216, max_records: 32,
        };
        let mut status = ClaimStatus { claim_id: "claim".into(), state: "queued".into(),
            context_id: context.context_id.clone(), family: 3, opening_digest: None,
            error_code: None, current_context: None };
        assert!(client.validate_status(&context, "claim", 3, &status).is_ok());
        for family in [0, 1, 2, 4] {
            status.family = family;
            assert!(client.validate_status(&context, "claim", family, &status).is_err());
        }
        status.family = 3;
        assert!(client.validate_status(&context, "other", 3, &status).is_err());
        status.opening_digest = Some(format!("0x{}", "00".repeat(32)));
        assert!(client.validate_status(&context, "claim", 3, &status).is_err());
        for state in ["included", "applied"] {
            status.state = state.into();
            assert!(client.validate_status(&context, "claim", 3, &status).is_ok());
        }
        status.opening_digest = None;
        assert!(client.validate_status(&context, "claim", 3, &status).is_err());
        status.state = "refresh_required".into();
        status.current_context = Some(context.clone());
        assert!(matches!(client.validate_status(&context, "claim", 3, &status).unwrap_err().downcast_ref::<ClaimError>(), Some(ClaimError::ContextChanged(_))));
        status.current_context = None;
        status.state = "rejected".into(); status.error_code = Some("InvalidProof".into());
        assert!(matches!(client.validate_status(&context, "claim", 3, &status).unwrap_err().downcast_ref::<ClaimError>(), Some(ClaimError::Rejected(_))));
    }
}
