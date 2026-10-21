use std::collections::{BTreeMap, HashMap};

use anyhow::{Context as _, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField as F, types::{Field, PrimeField64}},
    gates::{
        arithmetic_base::ArithmeticGate,
        arithmetic_extension::ArithmeticExtensionGate,
        base_sum::BaseSumGate,
        constant::ConstantGate,
        coset_interpolation::CosetInterpolationGate,
        exponentiation::ExponentiationGate,
        lookup::LookupGate,
        lookup_table::LookupTableGate,
        multiplication_extension::MulExtensionGate,
        noop::NoopGate,
        poseidon::PoseidonGate,
        poseidon_mds::PoseidonMdsGate,
        public_input::PublicInputGate,
        random_access::RandomAccessGate,
        reducing::ReducingGate,
        reducing_extension::ReducingExtensionGate,
    },
    hash::{hash_types::{HashOut, RichField}, poseidon::PoseidonHash},
    get_gate_tag_impl, impl_gate_serializer, read_gate_impl,
    plonk::config::{Hasher, PoseidonGoldilocksConfig},
    recursion::cyclic_recursion::check_cyclic_proof_verifier_data,
    util::serialization::GateSerializer,
};
use psy_crypto::hash::{merkle::core::MerkleProofCore, traits::qhashable::QFieldHashable};
use psy_crypto::common::user_id::get_registration_id_from_user_id;
use parth_core::pgoldilocks::QHashOut as ParthQHashOut;
use psy_client_common::{
    data::qhashout::QHashOut,
    job::id::{QProvingJobDataID, QProvingJobDataIDWithRewardPreimage},
};
use psy_client_data::{
    api::reward::{PsyProoffMinerRewardProof, PsyProoffMinerRewardProofWithRewardPreimage},
    reward_claim::{RewardClaim, GOLDILOCKS_MODULUS},
    config::store_config::PsyHasher,
    qdata::checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf},
    traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync},
};
use psy_config::network_constants::{CHECKPOINT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, PSY_NETWORK_MAGIC};
use psy_common_circuit::circuits::zk_signature3::core::PsyBasicZKSignatureCircuit;
use psy_plonky2_circuits::bridge::{
    circuits::reward_claim_wrap::{RewardClaimWrapCircuit, RewardClaimWrapWitness, REWARD_CLAIM_PUBLIC_INPUT_BITS},
    circuits::user_reward_checkpoint_aggregate::{
        UserRewardCheckpointAggregateCircuit, UserRewardCheckpointAggregateProof, UserRewardCheckpointAggregateWitness,
        REWARD_CLAIM_MAX_CHECKPOINTS, USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT,
    },
    circuits::user_reward_tree::{
        UserRewardAggregateCircuit, UserRewardAggregateProof, UserRewardAggregateWitness, UserRewardJobWitness, UserRewardLeafCircuit,
        UserRewardLeafWitness, UserRewardRootCircuit, UserRewardRootProof, UserRewardRootWitness, UserRewardTagWitness,
        USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT, USER_REWARD_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT, USER_REWARD_LEAF_PUBLIC_INPUT_COUNT, USER_REWARD_ROOT_PUBLIC_INPUT_COUNT,
    },
    gadgets::reward_nullifier::{nullifier_job_index, RewardNullifierTree, REWARD_NULLIFIER_EMPTY_ROOT},
};
use psy_provider::provider::RpcProvider;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::signature::traits::SignatureUser;

const CLAIM_REWARD_SIGNATURE: &str = "claimReward(bytes,bytes32,uint32,address,uint32[],uint256)";
const REWARD_CLAIMED_SIGNATURE: &str = "RewardClaimed(uint32,address,bytes32,uint32[],uint256)";
const TRANSFER_SIGNATURE: &str = "Transfer(address,address,uint256)";
const GOLDILOCKS_ORDER: u64 = 0xffff_ffff_0000_0001;

/// Completed portable wrapper proof. The proxy binds this to its local verifier;
/// the request carries no key, address, or aggregate witness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardClaimWrapProofInput {
    /// Hex of the bincode-serialized wrapper `ProofWithPublicInputs` (256 digest bits).
    pub reward_claim_wrap_proof_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardClaimWrapGroth16Proof {
    /// Groth16 proof as eight Solidity words (uint256[8]).
    pub solidity_proof: [String; 8],
    /// High and low 128-bit halves of keccak256 of the wrapper's in-circuit
    /// message commitment, bound by the generic gnark path (deposit/withdrawal
    /// double-hash semantics; PsyToken computes the identical hash).
    pub solidity_public_inputs: [String; 2],
}

/// Bound checkpoint list. User and recipient stay call arguments, not fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardCheckpointStatement {
    pub checkpoint_tree_root: [u8; 32],
    pub checkpoint_ids: Vec<u32>,
    pub total_amount: [u8; 32],
}

/// Why a whole checkpoint group stays unpaid. The string is display only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RewardDeferral {
    HistoricalRead,
    UnrecognizedRoot,
    SourceUnavailable,
}

impl RewardDeferral {
    pub fn reason(self) -> String {
        match self {
            Self::HistoricalRead => "historical reward material unavailable".to_owned(),
            Self::UnrecognizedRoot => "checkpoint root is not recognized".to_owned(),
            Self::SourceUnavailable => "complete reward source unavailable".to_owned(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RewardSourceError {
    #[error("reward source unavailable: {0}")]
    Unavailable(#[source] anyhow::Error),
}

impl RewardDeferral {
    fn source_unavailable(error: anyhow::Error) -> anyhow::Error {
        RewardSourceError::Unavailable(error).into()
    }

}



pub fn encode_u64_word(value: u64) -> [u8; 32] { let mut out = [0; 32]; out[24..].copy_from_slice(&value.to_be_bytes()); out }
pub fn decode_hex32(value: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(value.len() == 66 && value.starts_with("0x") && value[2..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "noncanonical hex32");
    Ok(hex::decode(&value[2..])?.try_into().map_err(|_| anyhow::anyhow!("hex32 width"))?)
}
pub fn decode_address(value: &str) -> Result<[u8; 20]> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    let bytes = if bytes.len() == 32 { anyhow::ensure!(bytes[..12] == [0; 12], "address exceeds 160 bits"); &bytes[12..] } else { &bytes[..] };
    Ok(bytes.try_into().map_err(|_| anyhow::anyhow!("address must be 20 bytes or zero-padded 32 bytes"))?)
}
pub fn get_hash_limbs(hash: QHashOut<F>) -> [u64; 4] { hash.0.elements.map(|v| v.to_canonical_u64()) }
pub fn verify_merkle_path(path: &MerkleProofCore<QHashOut<F>>, root: QHashOut<F>, index: u64, value: QHashOut<F>, height: usize) -> Result<()> {
    anyhow::ensure!(height < 64 && index < (1u64 << height) && path.root == root && path.index == index && path.value == value && path.siblings.len() == height && path.verify::<PsyHasher>(), "chosen-end membership mismatch"); Ok(())
}
pub fn build_reward_job_witness(checkpoint: u64, user_id: u32, recipient: [u8; 20], proof: &PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<F>>) -> Result<UserRewardJobWitness> {
    anyhow::ensure!(recipient != [0; 20], "reward recipient must be nonzero");
    anyhow::ensure!(u32::try_from(checkpoint).is_ok(), "reward source exceeds u32");
    let tag = &proof.inner.tag_tree_proof;
    let height = u8::try_from(tag.siblings.len())?;
    let path_index = u32::try_from(tag.index)?;
    nullifier_job_index(height, path_index)?;
    anyhow::ensure!(tag.verify::<PoseidonHash>(), "reward tag proof does not reach its authenticated root");
    let preimage = proof.reward_tree_tag_preimage.0;
    anyhow::ensure!(preimage != HashOut::ZERO && preimage.elements[0].to_canonical_u64() == u64::from(user_id), "reward tag preimage does not belong to the user");
    let owner_tag = PoseidonHash::two_to_one(preimage, preimage);
    anyhow::ensure!(tag.leaf.tag.0 == owner_tag && tag.leaf.tag.0 != HashOut::ZERO, "reward tag leaf does not prove user ownership");
    let mut siblings = [ParthQHashOut::<F>::ZERO; 21];
    let mut parent_tags = siblings;
    for (index, node) in tag.siblings.iter().enumerate() {
        siblings[index] = ParthQHashOut(node.sibling.0);
        parent_tags[index] = ParthQHashOut(node.parent_tag.0);
    }
    Ok(UserRewardJobWitness { source_checkpoint_id: u32::try_from(checkpoint)?, height, path_index, tag: UserRewardTagWitness { tag_preimage: ParthQHashOut(proof.reward_tree_tag_preimage.0), leaf_left: ParthQHashOut(tag.leaf.left.0), leaf_right: ParthQHashOut(tag.leaf.right.0), leaf_tag: ParthQHashOut(tag.leaf.tag.0), siblings, parent_tags } })
}

pub struct RewardClient {
    pub rpc_provider: RpcProvider,
    pub http: reqwest::Client,
}

impl RewardClient {
    pub fn new(rpc_provider: RpcProvider) -> Self {
        Self { rpc_provider, http: reqwest::Client::new() }
    }

    pub fn load(rpc_config: &str) -> Result<(Self, UserRewardCircuits)> {
        let settings = psy_config::PsyConfigGoldilocks::from_file(rpc_config)?;
        let network = settings.get_current_network()?;
        Ok((Self::new(RpcProvider::new_with_config(network)?), UserRewardCircuits::build()?))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewardPendingSelection {
    pub realm_jobs: Vec<(u64, u64, u64, psy_client_common::job::id::QProvingJobDataIDWithRewardPreimage)>,
    pub coordinator_jobs: Vec<(u64, psy_client_common::job::id::QProvingJobDataIDWithRewardPreimage)>,
}
impl RewardPendingSelection {
    pub fn jobs_len(&self) -> usize { self.realm_jobs.len() + self.coordinator_jobs.len() }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceCircuitPin {
    fingerprint: [u64; 4],
    common_digest: [u8; 32],
    verifier_digest: [u8; 32],
}

fn source_circuit_pin(data: &plonky2::plonk::circuit_data::CircuitData<F, PoseidonGoldilocksConfig, 2>) -> Result<SourceCircuitPin> {
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
    Ok(SourceCircuitPin {
        fingerprint,
        common_digest: hash(&data.common.to_bytes(&RewardGateSerializer).map_err(|error| anyhow::anyhow!("common serialization: {error:?}"))?),
        verifier_digest: hash(&data.verifier_only.to_bytes().map_err(|error| anyhow::anyhow!("verifier serialization: {error:?}"))?),
    })
}

/// Reward common-data serializer. Psy registry order, then the three reward gates.
#[derive(Debug)]
struct RewardGateSerializer;

impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for RewardGateSerializer {
    impl_gate_serializer! {
        RewardGateSerializer,
        ArithmeticGate,
        ArithmeticExtensionGate<D>,
        BaseSumGate<2>,
        ConstantGate,
        CosetInterpolationGate<F, D>,
        ExponentiationGate<F, D>,
        LookupGate,
        LookupTableGate,
        MulExtensionGate<D>,
        NoopGate,
        PoseidonMdsGate<F, D>,
        PoseidonGate<F, D>,
        PublicInputGate,
        RandomAccessGate<F, D>,
        ReducingExtensionGate<D>,
        ReducingGate<D>,
        psy_common_circuit::u32::gates::comparison::ComparisonGate<F, D>,
        psy_common_circuit::u32::gates::arithmetic_u32::U32ArithmeticGate<F, D>,
        psy_plonky2_basic_helpers::u32::gates::comparison::ComparisonGate<F, D>,
        psy_common_circuit::u32::gates::add_many_u32::U32AddManyGate<F, D>
    }
}

pub struct UserRewardCircuits {
    pub user_reward_leaf: UserRewardLeafCircuit,
    pub user_reward_aggregate: UserRewardAggregateCircuit,
    pub user_reward_root: UserRewardRootCircuit,
}
impl UserRewardCircuits {
    pub fn build() -> Result<Self> {
        let user_reward_leaf = UserRewardLeafCircuit::new();
        let user_reward_aggregate = UserRewardAggregateCircuit::new(&user_reward_leaf);
        let user_reward_root = UserRewardRootCircuit::new(&user_reward_aggregate);
        anyhow::ensure!(user_reward_leaf.circuit_data.common.num_public_inputs == USER_REWARD_LEAF_PUBLIC_INPUT_COUNT, "reward leaf width differs from 15");
        anyhow::ensure!(user_reward_aggregate.circuit_data.common.num_public_inputs == USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT + USER_REWARD_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT, "reward aggregate width differs from 83");
        anyhow::ensure!(user_reward_root.circuit_data.common.num_public_inputs == USER_REWARD_ROOT_PUBLIC_INPUT_COUNT, "reward root width differs from 23");
        anyhow::ensure!(source_circuit_pin(&user_reward_leaf.circuit_data)?.fingerprint != [0; 4], "reward leaf circuit pin missing");
        anyhow::ensure!(source_circuit_pin(&user_reward_aggregate.circuit_data)?.fingerprint != [0; 4], "reward aggregate circuit pin missing");
        anyhow::ensure!(source_circuit_pin(&user_reward_root.circuit_data)?.fingerprint != [0; 4], "reward root circuit pin missing");
        Ok(Self { user_reward_leaf, user_reward_aggregate, user_reward_root })
    }
}

const REWARD_JOB_AGGREGATE_CACHE_SCHEMA: u32 = 1;
const REWARD_JOB_AGGREGATE_PI_COUNT: usize = USER_REWARD_AGGREGATE_PUBLIC_INPUT_COUNT + USER_REWARD_AGGREGATE_RECURSIVE_PUBLIC_INPUT_COUNT;

/// Original selected jobs kept outside the disposable proof cache.
#[derive(Clone, Debug)]
pub struct RewardJobOriginals {
    pub user_id: u32,
    pub source_checkpoint_id: u32,
    pub jobs: Vec<UserRewardJobWitness>,
}

impl PartialEq for RewardJobOriginals {
    fn eq(&self, other: &Self) -> bool {
        self.user_id == other.user_id
            && self.source_checkpoint_id == other.source_checkpoint_id
            && jobs_content_eq(&self.jobs, &other.jobs)
    }
}
impl Eq for RewardJobOriginals {}


/// One user's exact selected jobs against one complete source leaf.
/// Recipient, finality, and payment are not part of this proof.
#[derive(Clone, Debug)]
pub struct RewardJobAggregate {
    pub user_id: u32,
    pub source_checkpoint_id: u32,
    pub source_checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub source_checkpoint_leaf_hash: HashOut<F>,
    pub jobs: Vec<UserRewardJobWitness>,
    pub proof: UserRewardAggregateProof,
}

/// Recognized checkpoint-tree membership for one already proved source leaf.
#[derive(Clone, Debug)]
pub struct FinalizedCheckpointAnchor {
    pub checkpoint_tree_root: HashOut<F>,
    pub source_siblings: [HashOut<F>; CHECKPOINT_TREE_HEIGHT as usize],
    pub anchor_checkpoint_id: u32,
    pub anchor_leaf: PsyCheckpointLeaf<F>,
    pub anchor_siblings: [HashOut<F>; CHECKPOINT_TREE_HEIGHT as usize],
    pub global_roots: PsyCheckpointGlobalStateRoots<F>,
    pub registration_leaf: HashOut<F>,
    pub registration_index: u64,
    pub registration_siblings: [HashOut<F>; GLOBAL_USER_TREE_HEIGHT as usize],
}

/// Disposable accelerator. Original jobs stay with the caller; this record has no paid cursor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewardJobAggregateCache {
    pub schema: u32,
    pub network_magic: u64,
    pub user_id: u32,
    pub source_checkpoint_id: u32,
    pub source_checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub source_checkpoint_leaf_hash: [u64; 4],
    pub selected_jobs: Vec<RewardSelectedJob>,
    pub selection_identity: String,
    pub leaf_fingerprint: [u64; 4],
    pub leaf_common_digest: [u8; 32],
    pub leaf_verifier_digest: [u8; 32],
    pub aggregate_fingerprint: [u64; 4],
    pub aggregate_common_digest: [u8; 32],
    pub aggregate_verifier_digest: [u8; 32],
    pub aggregate_proof: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RewardSelectedJob {
    pub source_checkpoint_id: u32,
    pub height: u8,
    pub path_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareRewardClaimRequest {
    pub reward_token: String,
    pub user_id: u32,
    pub recipient: String,
    pub jobs: RewardPendingSelection,
    pub l1_rpc_url: String,
    pub prove_proxy_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prove_proxy_token: Option<String>,
    #[serde(default)]
    pub aggregate_caches: Vec<RewardJobAggregateCache>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedRewardClaim {
    pub to: String,
    pub chain_id: u64,
    pub value: String,
    pub data: String,
    pub state_manager: String,
    pub checkpoint_root: String,
    pub user_id: u32,
    pub recipient: String,
    pub checkpoint_ids: Vec<u32>,
    pub total_amount: String,
    pub snapshot_block_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeferredRewardCheckpoint {
    pub checkpoint_id: u32,
    pub reason: String,
}


#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum RewardClaimPreparation {
    Ready {
        claim: PreparedRewardClaim,
        remaining_jobs: RewardPendingSelection,
        aggregate_caches: Vec<RewardJobAggregateCache>,
        already_claimed_checkpoint_ids: Vec<u32>,
        deferred_checkpoints: Vec<DeferredRewardCheckpoint>,
    },
    ProofOnly {
        remaining_jobs: RewardPendingSelection,
        aggregate_caches: Vec<RewardJobAggregateCache>,
        already_claimed_checkpoint_ids: Vec<u32>,
        deferred_checkpoints: Vec<DeferredRewardCheckpoint>,
    },
    NothingToClaim { already_claimed_checkpoint_ids: Vec<u32> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum RewardClaimConfirmation {
    Pending { tx_hash: String },
    Confirmed {
        tx_hash: String,
        block_hash: String,
        block_number: u64,
        checkpoint_ids: Vec<u32>,
        total_amount: String,
    },
}


fn hash_limbs(hash: HashOut<F>) -> [u64; 4] {
    hash.elements.map(|value| value.to_canonical_u64())
}

fn read_hash(inputs: &[F], offset: usize) -> HashOut<F> {
    HashOut { elements: std::array::from_fn(|index| inputs[offset + index]) }
}

fn canonical_hash(inputs: &[F], offset: usize) -> Result<HashOut<F>> {
    let mut elements = [F::ZERO; 4];
    for index in 0..4 {
        let limb = inputs[offset + index].to_canonical_u64();
        anyhow::ensure!(limb < GOLDILOCKS_MODULUS, "noncanonical reward aggregate hash");
        elements[index] = F::from_canonical_u64(limb);
    }
    Ok(HashOut { elements })
}

fn source_leaf_hash(leaf: &PsyCheckpointLeaf<F>) -> HashOut<F> {
    leaf.qfhash::<PsyHasher>().0
}

fn approved_registration(data: &plonky2::plonk::circuit_data::CircuitData<F, PoseidonGoldilocksConfig, 2>) -> Result<SourceCircuitPin> {
    source_circuit_pin(data)
}

/// Sort by authenticated coordinate and reject any repeated coordinate.
fn ordered_selected_jobs(jobs: &[UserRewardJobWitness], source_checkpoint_id: u32) -> Result<Vec<UserRewardJobWitness>> {
    anyhow::ensure!(!jobs.is_empty(), "reward source has no jobs");
    anyhow::ensure!(jobs.iter().all(|job| job.source_checkpoint_id == source_checkpoint_id), "reward jobs span more than one checkpoint");
    let mut ordered = jobs.to_vec();
    ordered.sort_by(|left, right| (left.height, left.path_index).cmp(&(right.height, right.path_index)));
    anyhow::ensure!(ordered.windows(2).all(|pair| (pair[0].height, pair[0].path_index) < (pair[1].height, pair[1].path_index)), "reward jobs are not strictly ordered");
    Ok(ordered)
}

fn selected_coordinates(jobs: &[UserRewardJobWitness]) -> Vec<RewardSelectedJob> {
    jobs.iter().map(|job| RewardSelectedJob { source_checkpoint_id: job.source_checkpoint_id, height: job.height, path_index: job.path_index }).collect()
}

fn selection_identity(jobs: &[UserRewardJobWitness]) -> String {
    use tiny_keccak::{Hasher, Keccak};
    let mut hash = Keccak::v256();
    let mut word = [0u8; 4];
    for job in jobs {
        word = job.source_checkpoint_id.to_be_bytes();
        hash.update(&word);
        hash.update(&[job.height]);
        word = job.path_index.to_be_bytes();
        hash.update(&word);
    }
    let mut out = [0u8; 32];
    hash.finalize(&mut out);
    format!("0x{}", hex::encode(out))
}
fn hash_out_eq(left: HashOut<F>, right: HashOut<F>) -> bool {
    left.elements == right.elements
}

fn tag_content_eq(left: &UserRewardTagWitness, right: &UserRewardTagWitness) -> bool {
    hash_out_eq(left.tag_preimage.0, right.tag_preimage.0)
        && hash_out_eq(left.leaf_left.0, right.leaf_left.0)
        && hash_out_eq(left.leaf_right.0, right.leaf_right.0)
        && hash_out_eq(left.leaf_tag.0, right.leaf_tag.0)
        && left.siblings.iter().zip(&right.siblings).all(|(left, right)| hash_out_eq(left.0, right.0))
        && left.parent_tags.iter().zip(&right.parent_tags).all(|(left, right)| hash_out_eq(left.0, right.0))
}

fn job_content_eq(left: &UserRewardJobWitness, right: &UserRewardJobWitness) -> bool {
    left.source_checkpoint_id == right.source_checkpoint_id
        && left.height == right.height
        && left.path_index == right.path_index
        && tag_content_eq(&left.tag, &right.tag)
}

fn jobs_content_eq(left: &[UserRewardJobWitness], right: &[UserRewardJobWitness]) -> bool {
    left.len() == right.len() && left.iter().zip(right).all(|(left, right)| job_content_eq(left, right))
}


/// Fresh empty claim tree. Its final root is the only subset binding accepted from a cached proof.
fn expected_nullifier_root(jobs: &[UserRewardJobWitness]) -> Result<HashOut<F>> {
    let mut tree = RewardNullifierTree::empty();
    anyhow::ensure!(tree.root() == *REWARD_NULLIFIER_EMPTY_ROOT, "reward claim tree does not start empty");
    for job in jobs { tree.insert(job.height, job.path_index)?; }
    Ok(tree.root())
}

fn prove_job_leaves(leaf: &UserRewardLeafCircuit, aggregate: &UserRewardAggregateCircuit, user_id: u32, source_checkpoint_id: u32, source_leaf: &PsyCheckpointLeaf<F>, jobs: &[UserRewardJobWitness]) -> Result<Vec<UserRewardAggregateProof>> {
    let source_hash = source_leaf_hash(source_leaf);
    let mut tree = RewardNullifierTree::empty();
    anyhow::ensure!(tree.root() == *REWARD_NULLIFIER_EMPTY_ROOT, "reward claim tree does not start empty");
    let mut proofs = Vec::with_capacity(jobs.len());
    for job in jobs {
        let update = tree.insert(job.height, job.path_index)?;
        let input = UserRewardLeafWitness {
            user_id, old_nullifier_root: update.old_nullifier_root, job: job.clone(),
            checkpoint_leaf: source_leaf.clone(), nullifier_siblings: update.nullifier_siblings,
        };
        let proved = leaf.prove(&input)?;
        anyhow::ensure!(proved.public_inputs.len() == USER_REWARD_LEAF_PUBLIC_INPUT_COUNT, "reward leaf statement width mismatch");
        let statement = &proved.public_inputs;
        anyhow::ensure!(statement[0].to_canonical_u64() == u64::from(user_id), "reward leaf user mismatch");
        anyhow::ensure!(statement[1].to_canonical_u64() == u64::from(source_checkpoint_id), "reward leaf source mismatch");
        anyhow::ensure!(read_hash(statement, 2) == source_hash, "reward leaf source hash mismatch");
        anyhow::ensure!(read_hash(statement, 6) == input.old_nullifier_root && read_hash(statement, 10) == update.new_nullifier_root, "reward leaf nullifier transition mismatch");
        anyhow::ensure!(statement[14].to_canonical_u64() == 1, "reward leaf count is not one");
        proofs.push(aggregate.prove(&UserRewardAggregateWitness::Leaf { leaf: proved })?);
    }
    Ok(proofs)
}

fn reduce_job_proofs(aggregate: &UserRewardAggregateCircuit, mut proofs: Vec<UserRewardAggregateProof>) -> Result<UserRewardAggregateProof> {
    while proofs.len() > 1 {
        let mut reduced = Vec::with_capacity(proofs.len().div_ceil(2));
        let mut round = proofs.into_iter();
        while let Some(left) = round.next() {
            reduced.push(match round.next() {
                Some(right) => aggregate.prove(&UserRewardAggregateWitness::Pair { left, right })?,
                None => left,
            });
        }
        proofs = reduced;
    }
    proofs.pop().context("reward aggregate has no proof")
}

fn authenticate_source_membership(anchor: &FinalizedCheckpointAnchor, source_checkpoint_id: u32, source_leaf: &PsyCheckpointLeaf<F>) -> Result<()> {
    let root = QHashOut(anchor.checkpoint_tree_root);
    let anchor_id = u64::from(anchor.anchor_checkpoint_id);
    anyhow::ensure!(u64::from(source_checkpoint_id) <= anchor_id, "reward source is newer than the recognized anchor");
    anyhow::ensure!(anchor.global_roots.qfhash::<PsyHasher>() == anchor.anchor_leaf.global_chain_root, "reward anchor global roots mismatch");
    let anchor_path = MerkleProofCore { root, index: anchor_id, value: anchor.anchor_leaf.qfhash::<PsyHasher>(), siblings: anchor.anchor_siblings.iter().copied().map(QHashOut).collect() };
    verify_merkle_path(&anchor_path, root, anchor_id, anchor.anchor_leaf.qfhash::<PsyHasher>(), CHECKPOINT_TREE_HEIGHT as usize)?;
    let source_path = MerkleProofCore { root, index: u64::from(source_checkpoint_id), value: source_leaf.qfhash::<PsyHasher>(), siblings: anchor.source_siblings.iter().copied().map(QHashOut).collect() };
    verify_merkle_path(&source_path, root, u64::from(source_checkpoint_id), source_leaf.qfhash::<PsyHasher>(), CHECKPOINT_TREE_HEIGHT as usize)?;
    Ok(())
}

fn cache_circuits_match(cache: &RewardJobAggregateCache, leaf: &SourceCircuitPin, aggregate: &SourceCircuitPin) -> bool {
    cache.leaf_fingerprint == leaf.fingerprint && cache.leaf_common_digest == leaf.common_digest && cache.leaf_verifier_digest == leaf.verifier_digest
        && cache.aggregate_fingerprint == aggregate.fingerprint && cache.aggregate_common_digest == aggregate.common_digest && cache.aggregate_verifier_digest == aggregate.verifier_digest
}

fn cache_binds(proved: &RewardJobAggregate, cache: &RewardJobAggregateCache) -> bool {
    cache_binds_selection(cache, proved.user_id, proved.source_checkpoint_id, &proved.source_checkpoint_leaf, &proved.jobs)
}

fn cache_binds_selection(cache: &RewardJobAggregateCache, user_id: u32, source_checkpoint_id: u32, source: &PsyCheckpointLeaf<F>, jobs: &[UserRewardJobWitness]) -> bool {
    cache.user_id == user_id && cache.source_checkpoint_id == source_checkpoint_id
        && cache.source_checkpoint_leaf == *source && cache.source_checkpoint_leaf_hash == hash_limbs(source_leaf_hash(source))
        && cache.selected_jobs == selected_coordinates(jobs) && cache.selection_identity == selection_identity(jobs)
}

impl RewardJobAggregate {
    pub fn get_reward_job_originals(&self) -> RewardJobOriginals {
        RewardJobOriginals { user_id: self.user_id, source_checkpoint_id: self.source_checkpoint_id, jobs: self.jobs.clone() }
    }

    /// Cache the proof only. The returned originals remain the caller's recovery source.
    pub fn build_reward_job_aggregate_cache(&self, circuits: &UserRewardCircuits) -> Result<(RewardJobAggregateCache, RewardJobOriginals)> {
        let leaf = approved_registration(&circuits.user_reward_leaf.circuit_data)?;
        let aggregate = approved_registration(&circuits.user_reward_aggregate.circuit_data)?;
        let cache = RewardJobAggregateCache {
            schema: REWARD_JOB_AGGREGATE_CACHE_SCHEMA, network_magic: PSY_NETWORK_MAGIC,
            user_id: self.user_id, source_checkpoint_id: self.source_checkpoint_id,
            source_checkpoint_leaf: self.source_checkpoint_leaf, source_checkpoint_leaf_hash: hash_limbs(self.source_checkpoint_leaf_hash),
            selected_jobs: selected_coordinates(&self.jobs), selection_identity: selection_identity(&self.jobs),
            leaf_fingerprint: leaf.fingerprint, leaf_common_digest: leaf.common_digest, leaf_verifier_digest: leaf.verifier_digest,
            aggregate_fingerprint: aggregate.fingerprint, aggregate_common_digest: aggregate.common_digest, aggregate_verifier_digest: aggregate.verifier_digest,
            aggregate_proof: STANDARD.encode(self.proof.to_bytes()),
        };
        Ok((cache, self.get_reward_job_originals()))
    }
}

impl RewardClient {
    /// Prove one checkpoint's selected jobs before any recognized root or recipient exists.
    pub fn prove_reward_job_aggregate(&self, leaf: &UserRewardLeafCircuit, aggregate: &UserRewardAggregateCircuit, user_id: u32, source_checkpoint_id: u32, source_checkpoint_leaf: &PsyCheckpointLeaf<F>, jobs: &[UserRewardJobWitness]) -> Result<RewardJobAggregate> {
        let ordered = ordered_selected_jobs(jobs, source_checkpoint_id)?;
        let source_hash = source_leaf_hash(source_checkpoint_leaf);
        let proof = reduce_job_proofs(aggregate, prove_job_leaves(leaf, aggregate, user_id, source_checkpoint_id, source_checkpoint_leaf, &ordered)?)?;
        self.validate_reward_job_aggregate(leaf, aggregate, &RewardJobAggregate {
            user_id, source_checkpoint_id, source_checkpoint_leaf: source_checkpoint_leaf.clone(), source_checkpoint_leaf_hash: source_hash, jobs: ordered, proof,
        })
    }

    /// Reuse only an approved aggregate for the caller's exact originals and complete source leaf.
    /// Mismatch leaves both inputs unchanged so the caller rebuilds from empty.
    pub fn reuse_reward_job_aggregate(&self, leaf: &UserRewardLeafCircuit, aggregate: &UserRewardAggregateCircuit, cache: &RewardJobAggregateCache, originals: &RewardJobOriginals, source_checkpoint_leaf: &PsyCheckpointLeaf<F>) -> Result<Option<RewardJobAggregate>> {
        let proof = match self.decode_cached_aggregate(leaf, aggregate, cache) {
            Ok(proof) => proof,
            Err(_) => return Ok(None),
        };
        let requested = match ordered_selected_jobs(&originals.jobs, originals.source_checkpoint_id) {
            Ok(jobs) => jobs,
            Err(_) => return Ok(None),
        };
        let candidate = RewardJobAggregate {
            user_id: originals.user_id, source_checkpoint_id: originals.source_checkpoint_id,
            source_checkpoint_leaf: *source_checkpoint_leaf, source_checkpoint_leaf_hash: source_leaf_hash(source_checkpoint_leaf),
            jobs: requested, proof,
        };
        if !cache_binds(&candidate, cache) { return Ok(None); }
        Ok(Some(self.validate_reward_job_aggregate(leaf, aggregate, &candidate)?))
    }

    fn decode_cached_aggregate(&self, leaf: &UserRewardLeafCircuit, aggregate: &UserRewardAggregateCircuit, cache: &RewardJobAggregateCache) -> Result<UserRewardAggregateProof> {
        let leaf_pin = approved_registration(&leaf.circuit_data)?;
        let aggregate_pin = approved_registration(&aggregate.circuit_data)?;
        anyhow::ensure!(cache.schema == REWARD_JOB_AGGREGATE_CACHE_SCHEMA && cache.network_magic == PSY_NETWORK_MAGIC, "reward cache identity mismatch");
        anyhow::ensure!(cache_circuits_match(cache, &leaf_pin, &aggregate_pin), "reward cache circuit mismatch");
        let proof = UserRewardAggregateProof::from_bytes(STANDARD.decode(&cache.aggregate_proof)?, &aggregate.circuit_data.common).context("reward cache proof does not decode with the approved aggregate")?;
        aggregate.circuit_data.verify(proof.clone())?;
        check_cyclic_proof_verifier_data(&proof, &aggregate.circuit_data.verifier_only, &aggregate.circuit_data.common)?;
        anyhow::ensure!(proof.public_inputs.len() == REWARD_JOB_AGGREGATE_PI_COUNT, "reward aggregate statement width mismatch");
        Ok(proof)
    }

    fn validate_reward_job_aggregate(&self, leaf: &UserRewardLeafCircuit, aggregate: &UserRewardAggregateCircuit, proved: &RewardJobAggregate) -> Result<RewardJobAggregate> {
        anyhow::ensure!(approved_registration(&leaf.circuit_data)?.fingerprint != [0; 4], "reward leaf circuit pin missing");
        anyhow::ensure!(approved_registration(&aggregate.circuit_data)?.fingerprint != [0; 4], "reward aggregate circuit pin missing");
        aggregate.circuit_data.verify(proved.proof.clone())?;
        check_cyclic_proof_verifier_data(&proved.proof, &aggregate.circuit_data.verifier_only, &aggregate.circuit_data.common)?;
        let inputs = &proved.proof.public_inputs;
        anyhow::ensure!(inputs.len() == REWARD_JOB_AGGREGATE_PI_COUNT, "reward aggregate statement width mismatch");
        let ordered = ordered_selected_jobs(&proved.jobs, proved.source_checkpoint_id)?;
        anyhow::ensure!(jobs_content_eq(&ordered, &proved.jobs), "reward aggregate jobs are not the canonical selection");
        let count = u32::try_from(inputs[14].to_canonical_u64()).context("reward aggregate count is not a u32")?;
        let source_hash = source_leaf_hash(&proved.source_checkpoint_leaf);
        anyhow::ensure!(
            inputs[0].to_canonical_u64() == u64::from(proved.user_id)
                && inputs[1].to_canonical_u64() == u64::from(proved.source_checkpoint_id)
                && canonical_hash(inputs, 2)? == source_hash
                && canonical_hash(inputs, 6)? == *REWARD_NULLIFIER_EMPTY_ROOT
                && count == u32::try_from(ordered.len())?
                && count > 0
                && canonical_hash(inputs, 10)? == expected_nullifier_root(&ordered)?,
            "reward aggregate statement does not bind the requested jobs"
        );
        anyhow::ensure!(proved.source_checkpoint_leaf_hash == source_hash, "reward aggregate source hash was substituted");
        Ok(RewardJobAggregate {
            user_id: proved.user_id, source_checkpoint_id: proved.source_checkpoint_id,
            source_checkpoint_leaf: proved.source_checkpoint_leaf, source_checkpoint_leaf_hash: source_hash,
            jobs: ordered, proof: proved.proof.clone(),
        })
    }

    /// Keyless payout root. Source membership is checked here; identity is bound once by the wrapper.
    pub fn prove_finalized_reward_root(&self, root: &UserRewardRootCircuit, leaf: &UserRewardLeafCircuit, aggregate: &UserRewardAggregateCircuit, proved: &RewardJobAggregate, anchor: &FinalizedCheckpointAnchor, recipient: [u32; 8]) -> Result<UserRewardRootProof> {
        anyhow::ensure!(recipient[5..].iter().all(|limb| *limb == 0) && recipient != [0; 8], "reward recipient must be a nonzero 160-bit address");
        let validated = self.validate_reward_job_aggregate(leaf, aggregate, proved)?;
        anyhow::ensure!(validated.source_checkpoint_leaf == proved.source_checkpoint_leaf, "reward source leaf changed before finalization");
        authenticate_source_membership(anchor, validated.source_checkpoint_id, &validated.source_checkpoint_leaf)?;
        let proved_root = root.prove(&UserRewardRootWitness {
            recipient, checkpoint_tree_root: anchor.checkpoint_tree_root, checkpoint_leaf: validated.source_checkpoint_leaf,
            checkpoint_siblings: anchor.source_siblings, aggregate_proof: validated.proof,
        })?;
        root.circuit_data.verify(proved_root.clone())?;
        anyhow::ensure!(proved_root.public_inputs.len() == USER_REWARD_ROOT_PUBLIC_INPUT_COUNT, "reward root statement width mismatch");
        let inputs = proved_root.public_inputs.iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>();
        anyhow::ensure!(inputs[0] == u64::from(validated.user_id) && inputs[9] == u64::from(validated.source_checkpoint_id) && inputs[10] == validated.jobs.len() as u64, "reward root statement mismatch");
        anyhow::ensure!(inputs[1..9] == recipient.map(u64::from) && inputs[19..23] == hash_limbs(anchor.checkpoint_tree_root), "reward root recipient or checkpoint root mismatch");
        let amount = u64::from(inputs[11] as u32) | (u64::from(inputs[12] as u32) << 32);
        anyhow::ensure!(amount > 0 && inputs[13..19].iter().all(|limb| *limb == 0), "reward root payout is not a positive u64");
        Ok(proved_root)
    }
}

pub fn recipient_limbs(recipient: &[u8; 20]) -> [u32; 8] {
    let mut limbs = [0u32; 8];
    for index in 0..5 {
        limbs[index] = u32::from_be_bytes(recipient[16 - index * 4..20 - index * 4].try_into().unwrap());
    }
    limbs
}

/// Frozen checkpoint-root packing: four low-u64-first limbs of the bytes32 word.
pub fn checkpoint_root_word(limbs: &[u64; 4]) -> [u8; 32] {
    let mut word = [0u8; 32];
    for (index, limb) in limbs.iter().enumerate() {
        word[24 - index * 8..32 - index * 8].copy_from_slice(&limb.to_be_bytes());
    }
    word
}

pub fn decode_claimed_bool(bytes: &[u8]) -> Result<bool> {
    anyhow::ensure!(bytes.len() == 32 && bytes[..31] == [0; 31] && bytes[31] <= 1, "reward claimed bool width");
    Ok(bytes[31] == 1)
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hash = Keccak::v256();
    hash.update(bytes);
    let mut out = [0u8; 32];
    hash.finalize(&mut out);
    out
}

fn decode_u256_word(value: &str) -> Result<[u8; 32]> {
    let text = value.strip_prefix("0x").unwrap_or(value);
    anyhow::ensure!(!text.is_empty() && text.len() <= 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit()), "reward proof word");
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(format!("{text:0>64}"), &mut bytes)?;
    Ok(bytes)
}

fn topic_word(value: &Value) -> Result<[u8; 32]> {
    let text = value.as_str().context("reward log topic missing")?.trim_start_matches("0x");
    anyhow::ensure!(text.len() == 64, "reward log topic width");
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(text, &mut bytes)?;
    Ok(bytes)
}

fn address_hex(address: [u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

pub fn canonical_quantity(value: &str) -> Result<[u8; 32]> {
    anyhow::ensure!(value == "0x0" || (value.starts_with("0x") && (3..=66).contains(&value.len()) && value[2..].chars().all(|digit| digit.is_ascii_hexdigit()) && !value[2..].starts_with('0')), "noncanonical chain quantity");
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(format!("{:0>64}", &value[2..]), &mut bytes)?;
    Ok(bytes)
}
pub fn reward_claim_chain(chain_id: u64) -> bool {
    matches!(chain_id, 1 | 31337 | 11155111)
}

pub fn chain_id_word(value: [u8; 32]) -> Result<u64> {
    anyhow::ensure!(value[..24] == [0; 24], "configured chain id exceeds u64");
    Ok(u64::from_be_bytes(value[24..].try_into().unwrap()))
}

fn lowercase_address(value: &str) -> Result<[u8; 20]> {
    anyhow::ensure!(value.len() == 42 && value.starts_with("0x") && value[2..].bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "recipient must be 0x plus 40 lowercase hex characters");
    let address = decode_address(value)?;
    anyhow::ensure!(address != [0; 20], "reward recipient must be nonzero");
    Ok(address)
}

fn decimal_u128(total: [u8; 32]) -> Result<String> {
    anyhow::ensure!(total[..16] == [0; 16], "reward total exceeds u128");
    Ok(u128::from_be_bytes(total[16..].try_into().unwrap()).to_string())
}

fn hex_word(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Bind all 147 public inputs. The returned statement keeps only root, ids, and total.
pub fn bind_reward_checkpoint_statement(
    public_inputs: &[F],
    user_id: u32,
    recipient: &[u8; 20],
    root_word: &[u8; 32],
    claims: &[RewardClaim],
) -> Result<RewardCheckpointStatement> {
    let inputs = public_inputs;
    anyhow::ensure!(inputs.len() == USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT, "checkpoint aggregate statement width mismatch");
    let limb = |index: usize| -> Result<u64> {
        let value = inputs[index].to_canonical_u64();
        anyhow::ensure!(F::from_canonical_u64(value) == inputs[index], "noncanonical checkpoint aggregate limb");
        Ok(value)
    };
    anyhow::ensure!(limb(0)? == u64::from(user_id), "checkpoint aggregate user mismatch");
    let expected = recipient_limbs(recipient);
    for index in 0..5 {
        anyhow::ensure!(limb(1 + index)? == u64::from(expected[index]), "checkpoint aggregate recipient mismatch");
    }
    let mut root = [0u8; 32];
    for index in 0..4 {
        let value = limb(6 + index)?;
        anyhow::ensure!(value < GOLDILOCKS_ORDER, "checkpoint aggregate root limb exceeds Goldilocks");
        root[24 - index * 8..32 - index * 8].copy_from_slice(&value.to_be_bytes());
    }
    anyhow::ensure!(root == *root_word, "checkpoint aggregate root differs from the recognized root");
    let count = u32::try_from(limb(10)?).context("checkpoint aggregate count exceeds u32")?;
    anyhow::ensure!(count as usize == claims.len() && (1..=REWARD_CLAIM_MAX_CHECKPOINTS).contains(&(count as usize)), "checkpoint aggregate count mismatch");
    let mut total = [0u8; 32];
    let mut sum = 0u128;
    for claim in claims {
        anyhow::ensure!(claim.user_id == user_id && claim.recipient == *recipient && claim.amount[..24] == [0; 24] && claim.amount != [0; 32], "invalid reward claim row");
        sum = sum.checked_add(u128::from(u64::from_be_bytes(claim.amount[24..].try_into().unwrap()))).context("reward total exceeds u128")?;
    }
    for index in 0..4 {
        let value = u32::try_from(limb(11 + index)?).context("checkpoint aggregate total limb exceeds u32")?;
        total[28 - index * 4..32 - index * 4].copy_from_slice(&value.to_be_bytes());
    }
    anyhow::ensure!(u128::from_be_bytes(total[16..].try_into().unwrap()) == sum && total[..16] == [0; 16], "checkpoint aggregate total mismatch");
    let mut ids = Vec::with_capacity(count as usize);
    let mut previous = None;
    for index in 0..REWARD_CLAIM_MAX_CHECKPOINTS {
        let id = u32::try_from(limb(15 + index)?).context("checkpoint aggregate id exceeds u32")?;
        if index < count as usize {
            anyhow::ensure!(id == claims[index].checkpoint_id, "checkpoint aggregate id list mismatch");
            anyhow::ensure!(previous.map_or(true, |prior| prior < id), "checkpoint aggregate ids must be strictly increasing");
            previous = Some(id);
            ids.push(id);
        } else {
            anyhow::ensure!(id == 0, "inactive checkpoint aggregate id is not zero");
        }
    }
    Ok(RewardCheckpointStatement { checkpoint_tree_root: root, checkpoint_ids: ids, total_amount: total })
}

pub fn encode_reward_claim_calldata(proof: &[String; 8], user_id: u32, recipient: [u8; 20], statement: &RewardCheckpointStatement) -> Result<Vec<u8>> {
    let ids = &statement.checkpoint_ids;
    let total = statement.total_amount;
    anyhow::ensure!(!ids.is_empty() && ids.len() <= REWARD_CLAIM_MAX_CHECKPOINTS, "reward claim requires a bounded nonempty id list");
    anyhow::ensure!(total != [0; 32] && total[..16] == [0; 16], "reward total must be a positive u128");
    let mut data = keccak256(CLAIM_REWARD_SIGNATURE.as_bytes())[..4].to_vec();
    data.extend_from_slice(&encode_u64_word(192));
    data.extend_from_slice(&statement.checkpoint_tree_root);
    data.extend_from_slice(&encode_u64_word(u64::from(user_id)));
    let mut recipient_word = [0; 32];
    recipient_word[12..].copy_from_slice(&recipient);
    data.extend_from_slice(&recipient_word);
    data.extend_from_slice(&encode_u64_word(192 + 32 + 256));
    data.extend_from_slice(&total);
    data.extend_from_slice(&encode_u64_word(256));
    for word in proof {
        data.extend_from_slice(&decode_u256_word(word).context("reward proof word")?);
    }
    data.extend_from_slice(&encode_u64_word(u64::try_from(ids.len())?));
    let mut previous = None;
    for id in ids {
        anyhow::ensure!(previous.map_or(true, |prior| prior < *id), "reward checkpoints must be strictly increasing");
        previous = Some(*id);
        data.extend_from_slice(&encode_u64_word(u64::from(*id)));
    }
    Ok(data)
}


pub struct GroupedRewardJobs {
    pub groups: BTreeMap<u32, RewardJobOriginals>,
    pub unloaded: BTreeMap<u32, (RewardPendingSelection, RewardDeferral)>,
    pub selections: BTreeMap<u32, RewardPendingSelection>,
}

fn deferred_record(checkpoint_id: u32, kind: RewardDeferral) -> DeferredRewardCheckpoint {
    DeferredRewardCheckpoint { checkpoint_id, reason: kind.reason() }
}

fn join_selections(selections: impl IntoIterator<Item = RewardPendingSelection>) -> RewardPendingSelection {
    let mut jobs = RewardPendingSelection { realm_jobs: Vec::new(), coordinator_jobs: Vec::new() };
    for selection in selections {
        jobs.realm_jobs.extend(selection.realm_jobs);
        jobs.coordinator_jobs.extend(selection.coordinator_jobs);
    }
    jobs
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewardDeployment {
    pub token: [u8; 20],
    pub provider: [u8; 20],
    pub state_manager: [u8; 20],
}

fn address_word(bytes: &[u8]) -> Result<[u8; 20]> {
    anyhow::ensure!(bytes.len() == 32 && bytes[..12] == [0; 12], "reward address word width");
    let mut address = [0u8; 20];
    address.copy_from_slice(&bytes[12..]);
    Ok(address)
}

impl RewardClient {
    pub fn reward_claimed_event(&self, receipt: &Value, token: [u8; 20], user_id: u32, recipient: [u8; 20], statement: &RewardCheckpointStatement) -> Result<()> {
        let topic = keccak256(REWARD_CLAIMED_SIGNATURE.as_bytes());
        let root = statement.checkpoint_tree_root;
        let ids = &statement.checkpoint_ids;
        let total = statement.total_amount;
        for log in receipt["logs"].as_array().context("reward receipt has no logs")? {
            if log["topics"].as_array().map_or(true, |topics| topics.len() != 4) { continue; }
            let address = decode_address(log["address"].as_str().context("reward log address missing")?).unwrap_or([0; 20]);
            if address != token { continue; }
            let (event, user, logged_recipient, logged_root) = (topic_word(&log["topics"][0])?, topic_word(&log["topics"][1])?, topic_word(&log["topics"][2])?, topic_word(&log["topics"][3])?);
            if event.as_slice() != topic.as_slice() { continue; }
            anyhow::ensure!(user[..28] == [0; 28], "noncanonical RewardClaimed user");
            if u32::from_be_bytes(user[28..32].try_into().unwrap()) != user_id || logged_root != root { continue; }
            anyhow::ensure!(logged_recipient[..12] == [0; 12] && logged_recipient[12..] == recipient, "RewardClaimed recipient does not match the claim");
            let data = hex::decode(log["data"].as_str().context("reward log data missing")?.trim_start_matches("0x")).context("RewardClaimed data")?;
            anyhow::ensure!(data.len() == 96 + ids.len() * 32, "RewardClaimed data width");
            anyhow::ensure!(data[..32] == encode_u64_word(64) && data[32..64] == total, "RewardClaimed total does not match the claim");
            anyhow::ensure!(data[64..96] == encode_u64_word(u64::try_from(ids.len())?), "RewardClaimed id count does not match the claim");
            for (index, id) in ids.iter().enumerate() {
                let word = &data[96 + index * 32..128 + index * 32];
                anyhow::ensure!(word[..28] == [0; 28] && u32::from_be_bytes(word[28..].try_into().unwrap()) == *id, "RewardClaimed id list does not match the claim");
            }
            return Ok(());
        }
        anyhow::bail!("confirmed receipt has no matching RewardClaimed event")
    }

    pub fn mint_transfer_event(&self, receipt: &Value, token: [u8; 20], recipient: [u8; 20], total: [u8; 32]) -> Result<()> {
        let topic = keccak256(TRANSFER_SIGNATURE.as_bytes());
        for log in receipt["logs"].as_array().context("reward receipt has no logs")? {
            if log["topics"].as_array().map_or(true, |topics| topics.len() != 3) { continue; }
            let address = decode_address(log["address"].as_str().context("reward log address missing")?).unwrap_or([0; 20]);
            if address != token { continue; }
            let (event, from, to) = (topic_word(&log["topics"][0])?, topic_word(&log["topics"][1])?, topic_word(&log["topics"][2])?);
            if event.as_slice() != topic.as_slice() || from != [0; 32] { continue; }
            anyhow::ensure!(to[..12] == [0; 12] && to[12..] == recipient, "mint Transfer recipient does not match the claim");
            let data_hex = log["data"].as_str().context("reward log data missing")?.trim_start_matches("0x");
            anyhow::ensure!(data_hex.len() == 64, "mint Transfer data width");
            let mut amount = [0u8; 32];
            hex::decode_to_slice(data_hex, &mut amount)?;
            anyhow::ensure!(amount == total, "mint Transfer amount does not match the claim");
            return Ok(());
        }
        anyhow::bail!("confirmed receipt has no matching mint Transfer")
    }

    async fn eth_rpc(&self, url: &str, method: &str, params: Value) -> Result<Value> {
        let response = self.http.post(url).json(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})).send().await?.json::<Value>().await?;
        if let Some(error) = response.get("error") {
            anyhow::bail!("reward L1 {method} failed: {error}");
        }
        Ok(response["result"].clone())
    }

    async fn observed_reward_chain_id(&self, url: &str) -> Result<u64> {
        let observed = self.eth_rpc(url, "eth_chainId", serde_json::json!([])).await?;
        let text = observed.as_str().context("reward chain identity missing")?;
        let chain_id = chain_id_word(canonical_quantity(text)?)?;
        anyhow::ensure!(reward_claim_chain(chain_id), "reward chain identity must be 1, 31337, or 11155111");
        Ok(chain_id)
    }

    async fn canonical_block_hash(&self, url: &str, block: &str) -> Result<String> {
        let is_hash = block.len() == 66 && block.starts_with("0x") && block[2..].chars().all(|value| value.is_ascii_hexdigit());
        anyhow::ensure!(is_hash || block == "latest" || block == "0x0" || (block.starts_with("0x") && block.len() > 2 && block[2..].chars().all(|value| value.is_ascii_hexdigit()) && !block[2..].starts_with('0')), "reward block tag is not canonical");
        self.observed_reward_chain_id(url).await?;
        if is_hash { return Ok(block.to_owned()); }
        let response = self.eth_rpc(url, "eth_getBlockByNumber", serde_json::json!([block, false])).await?;
        let hash = response["hash"].as_str().context("reward block has no canonical hash")?.to_owned();
        anyhow::ensure!(hash.len() == 66 && hash.starts_with("0x") && hash[2..].chars().all(|value| value.is_ascii_hexdigit()), "reward block hash is not canonical");
        Ok(hash)
    }

    async fn l1_call(&self, url: &str, block: &str, to: &str, data: Vec<u8>) -> Result<Vec<u8>> {
        let block_hash = self.canonical_block_hash(url, block).await?;
        let result = self.eth_rpc(url, "eth_call", serde_json::json!([{"to":to,"data":hex_word(&data)},{"blockHash":block_hash,"requireCanonical":true}])).await?;
        let text = result.as_str().context("reward L1 result missing")?.trim_start_matches("0x");
        anyhow::ensure!(text.len() % 2 == 0, "reward L1 result width");
        Ok(hex::decode(text)?)
    }

    pub async fn read_l1_block(&self, l1_rpc_url: &str) -> Result<String> {
        let block = self.eth_rpc(l1_rpc_url, "eth_getBlockByNumber", serde_json::json!(["latest", false])).await?;
        let hash = block["hash"].as_str().context("latest L1 block hash missing")?;
        anyhow::ensure!(hash.len() == 66 && hash.starts_with("0x") && hash[2..].chars().all(|value| value.is_ascii_hexdigit()), "invalid L1 snapshot hash");
        Ok(hash.to_owned())
    }

    pub async fn read_claimed_pair(&self, l1_rpc_url: &str, block: &str, token: &str, user_id: u32, checkpoint_id: u32) -> Result<bool> {
        let mut data = keccak256(b"claimed(uint32,uint32)")[..4].to_vec();
        data.extend_from_slice(&encode_u64_word(u64::from(user_id)));
        data.extend_from_slice(&encode_u64_word(u64::from(checkpoint_id)));
        decode_claimed_bool(&self.l1_call(l1_rpc_url, block, token, data).await?)
    }

    pub async fn read_reward_root_recognized(&self, l1_rpc_url: &str, block: &str, state_manager: &str, root: [u8; 32]) -> Result<bool> {
        let clean = self.l1_call(l1_rpc_url, block, state_manager, keccak256(b"rewardRootsClean()")[..4].to_vec()).await?;
        if !decode_claimed_bool(&clean)? { return Ok(false); }
        let mut data = keccak256(b"rewardRootCheckpointId(bytes32)")[..4].to_vec();
        data.extend_from_slice(&root);
        let registered = self.l1_call(l1_rpc_url, block, state_manager, data).await?;
        let tip = self.l1_call(l1_rpc_url, block, state_manager, keccak256(b"lastFinalizedCheckpointId()")[..4].to_vec()).await?;
        anyhow::ensure!(registered.len() == 32 && tip.len() == 32 && registered[..24] == [0; 24] && tip[..24] == [0; 24], "reward root checkpoint id width");
        Ok(registered != [0; 32] && registered <= tip)
    }

    pub async fn read_finalized_checkpoint(&self, l1_rpc_url: &str, block: &str, state_manager: &str) -> Result<(u32, [u8; 32], bool)> {
        let id = self.l1_call(l1_rpc_url, block, state_manager, keccak256(b"lastFinalizedCheckpointId()")[..4].to_vec()).await?;
        anyhow::ensure!(id.len() == 32 && id[..28] == [0; 28], "finalized reward anchor exceeds u32");
        let id = u32::from_be_bytes(id[28..].try_into()?);
        let root: [u8; 32] = self.l1_call(l1_rpc_url, block, state_manager, keccak256(b"lastVerifiedCheckpointRoot()")[..4].to_vec()).await?.try_into().map_err(|_| anyhow::anyhow!("finalized root width"))?;
        Ok((id, root, self.read_reward_root_recognized(l1_rpc_url, block, state_manager, root).await?))
    }

    pub async fn load_finalized_reward_anchor(&self, anchor_id: u32, root_word: [u8; 32], originals: &RewardJobOriginals) -> Result<FinalizedCheckpointAnchor> {
        let provider = &self.rpc_provider;
        let root = provider.get_checkpoint_tree_root(u64::from(anchor_id)).await?;
        let limbs = root.0.elements.map(|limb| limb.to_canonical_u64());
        anyhow::ensure!(checkpoint_root_word(&limbs) == root_word, "historical checkpoint root differs from finalized L1 root");
        let source_path = provider.get_checkpoint_tree_merkle_proof(u64::from(anchor_id), u64::from(originals.source_checkpoint_id)).await?;
        let anchor_path = provider.get_checkpoint_tree_merkle_proof(u64::from(anchor_id), u64::from(anchor_id)).await?;
        let registration_index = get_registration_id_from_user_id(u64::from(originals.user_id));
        let registration_leaf = provider.get_user_registration_tree_leaf_hash(u64::from(anchor_id), registration_index).await?;
        let registration_path = provider.get_user_registration_tree_merkle_proof(u64::from(anchor_id), registration_index).await?;
        anyhow::ensure!(registration_path.siblings.len() == GLOBAL_USER_TREE_HEIGHT as usize, "reward registration path must have {} siblings", GLOBAL_USER_TREE_HEIGHT);
        let siblings = |path: MerkleProofCore<QHashOut<F>>| -> Result<[HashOut<F>; CHECKPOINT_TREE_HEIGHT as usize]> {
            path.siblings.into_iter().map(|hash| hash.0).collect::<Vec<_>>().try_into().map_err(|_| anyhow::anyhow!("reward historical path must have 32 siblings"))
        };
        let registration_siblings: [HashOut<F>; GLOBAL_USER_TREE_HEIGHT as usize] = registration_path.siblings.into_iter().map(|hash| hash.0).collect::<Vec<_>>().try_into().map_err(|_| anyhow::anyhow!("reward registration path width"))?;
        Ok(FinalizedCheckpointAnchor {
            checkpoint_tree_root: root.0,
            source_siblings: siblings(source_path)?,
            anchor_checkpoint_id: anchor_id,
            anchor_leaf: provider.get_checkpoint_leaf_data(u64::from(anchor_id)).await?,
            anchor_siblings: siblings(anchor_path)?,
            global_roots: provider.get_checkpoint_global_state_roots(u64::from(anchor_id)).await?,
            registration_leaf: registration_leaf.0,
            registration_index,
            registration_siblings,
        })
    }

    /// One portable wrapper proof carrying the 256-bit message commitment after
    /// the 147-input checkpoint aggregate.
    /// The held key and registration path are witness-only and are not returned.
    pub fn prove_reward_claim(
        &self,
        checkpoint: &UserRewardCheckpointAggregateCircuit,
        aggregate: &UserRewardCheckpointAggregateProof,
        anchor: &FinalizedCheckpointAnchor,
        token: [u8; 20],
        state_manager: [u8; 20],
        private_key: HashOut<F>,
    ) -> Result<plonky2::plonk::proof::ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2>> {
        anyhow::ensure!(aggregate.public_inputs.len() == USER_REWARD_CHECKPOINT_AGGREGATE_TOTAL_PUBLIC_INPUT_COUNT, "checkpoint aggregate statement width mismatch");
        checkpoint.circuit_data.verify(aggregate.clone())?;
        let registration_index = get_registration_id_from_user_id(aggregate.public_inputs[0].to_canonical_u64());
        anyhow::ensure!(anchor.registration_index == registration_index, "reward registration index does not map to the user");
        let fingerprint = PsyBasicZKSignatureCircuit::<PoseidonGoldilocksConfig, 2>::new().fingerprint.0;
        let public_key_param = psy_ups_circuit::signature::software_defined::get_sdc_public_key_param(&QHashOut(private_key));
        let registration_leaf = PoseidonHash::two_to_one(fingerprint, public_key_param.0);
        anyhow::ensure!(anchor.registration_leaf == registration_leaf && registration_leaf != HashOut::ZERO, "reward registration leaf does not match the private key");
        let registration_root = anchor.global_roots.user_registration_tree_root;
        let registration_path = MerkleProofCore {
            root: registration_root, index: registration_index, value: QHashOut(registration_leaf),
            siblings: anchor.registration_siblings.iter().copied().map(QHashOut).collect(),
        };
        verify_merkle_path(&registration_path, registration_root, registration_index, QHashOut(registration_leaf), GLOBAL_USER_TREE_HEIGHT as usize)?;
        let active = u32::try_from(aggregate.public_inputs[10].to_canonical_u64()).context("checkpoint aggregate count exceeds u32")?;
        anyhow::ensure!((1..=REWARD_CLAIM_MAX_CHECKPOINTS).contains(&(active as usize)), "checkpoint aggregate count is outside the claim bound");
        for index in 0..active as usize {
            let id = u32::try_from(aggregate.public_inputs[15 + index].to_canonical_u64()).context("checkpoint aggregate id exceeds u32")?;
            anyhow::ensure!(id <= anchor.anchor_checkpoint_id, "reward checkpoint is newer than the authenticated anchor");
        }
        let wrap = RewardClaimWrapCircuit::new(
            &checkpoint.circuit_data.common,
            checkpoint.fingerprint,
            checkpoint.circuit_data.verifier_only.constants_sigmas_cap.height(),
        );
        let proof = wrap.prove(&checkpoint.circuit_data.verifier_only, aggregate, &RewardClaimWrapWitness {
            state_manager, token, anchor_checkpoint_id: anchor.anchor_checkpoint_id, anchor_leaf: anchor.anchor_leaf.clone(),
            anchor_siblings: anchor.anchor_siblings, global_roots: anchor.global_roots.clone(), registration_leaf,
            registration_index, registration_siblings: anchor.registration_siblings, private_key,
        })?;
        wrap.circuit_data.verify(proof.clone())?;
        anyhow::ensure!(proof.public_inputs.len() == REWARD_CLAIM_PUBLIC_INPUT_BITS, "reward claim wrapper statement width mismatch");
        Ok(proof)
    }


    pub async fn prove_reward_claim_groth16(&self, prove_proxy_url: &str, prove_proxy_token: Option<&str>, proof: &RewardClaimWrapProofInput) -> Result<RewardClaimWrapGroth16Proof> {
        let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"psy_prove_reward_claim_groth16","params":[proof]});
        let mut request = self.http.post(prove_proxy_url).json(&body);
        if let Some(token) = prove_proxy_token { request = request.bearer_auth(token); }
        let prove_result: Value = request.send().await?.json().await?;
        if let Some(error) = prove_result.get("error") {
            if let Some(message) = error.get("message").and_then(|value| value.as_str()) { anyhow::bail!("prove-proxy error: {message}"); }
            anyhow::bail!("prove-proxy error: {error}");
        }
        Ok(serde_json::from_value(prove_result["result"].clone()).context("prove-proxy reward result")?)
    }

    pub async fn read_canonical_reward_receipt(&self, l1_rpc_url: &str, tx_hash: &str, receipt: &Value) -> Result<Value> {
        anyhow::ensure!(!receipt["blockNumber"].is_null(), "reward receipt has no block number");
        let tx_view = self.eth_rpc(l1_rpc_url, "eth_getTransactionByHash", serde_json::json!([tx_hash])).await?;
        let tx_block = tx_view["blockHash"].as_str().context("reward transaction has no block hash")?;
        let receipt_block = receipt["blockHash"].as_str().context("reward receipt has no block hash")?;
        anyhow::ensure!(tx_block.eq_ignore_ascii_case(receipt_block), "reward receipt block mismatch");
        let mined_block = self.eth_rpc(l1_rpc_url, "eth_getBlockByNumber", serde_json::json!([receipt["blockNumber"], false])).await?;
        let mined_hash = mined_block["hash"].as_str().context("reward receipt block is missing")?;
        anyhow::ensure!(mined_hash.eq_ignore_ascii_case(receipt_block), "reward claim receipt is no longer canonical");
        Ok(receipt.clone())
    }
}


impl RewardClient {
    pub async fn group_reward_jobs(&self, loaded: RewardPendingSelection, user_id: u32, recipient: [u8; 20]) -> Result<GroupedRewardJobs> {
        let edges = if loaded.realm_jobs.is_empty() { HashMap::new() } else { self.rpc_provider.discover_realm_edges().await? };
        let edge = |realm, sub| edges.get(&(realm, sub)).cloned().with_context(|| format!("realm {realm} sub {sub} has no discovered edge"));
        let mut selections: BTreeMap<u32, RewardPendingSelection> = BTreeMap::new();
        for (realm, sub, pending, job) in loaded.realm_jobs {
            let url = edge(realm, sub)?;
            match self.rpc_provider.get_realm_checkpoint_id_for_unique_pending_id_by_realm_id(&url, pending).await {
                Ok(Some(id)) => selections.entry(u32::try_from(id)?).or_insert_with(|| RewardPendingSelection { realm_jobs: vec![], coordinator_jobs: vec![] }).realm_jobs.push((realm, sub, pending, job)),
                Ok(None) => anyhow::bail!("realm {realm} sub {sub} pending {pending} has no checkpoint mapping; cannot safely split original selection"),
                Err(error) => return Err(error).with_context(|| format!("realm {realm} sub {sub} pending {pending} checkpoint mapping unavailable; originals retained")),
            }
        }
        for (pending, job) in loaded.coordinator_jobs {
            match self.rpc_provider.get_coordinator_checkpoint_id_for_unique_pending_id(pending).await {
                Ok(Some(id)) => selections.entry(u32::try_from(id)?).or_insert_with(|| RewardPendingSelection { realm_jobs: vec![], coordinator_jobs: vec![] }).coordinator_jobs.push((pending, job)),
                Ok(None) => anyhow::bail!("coordinator pending {pending} has no checkpoint mapping; cannot safely split original selection"),
                Err(error) => return Err(error).with_context(|| format!("coordinator pending {pending} checkpoint mapping unavailable; originals retained")),
            }
        }
        let mut groups = BTreeMap::new();
        let mut unloaded = BTreeMap::new();
        for (source, selection) in &selections {
            let fetched = async {
                let mut proofs = load_realm_reward_proofs(&self.rpc_provider, &edges, selection.realm_jobs.clone()).await?;
                for (checkpoint, batch) in load_coordinator_reward_proofs(&self.rpc_provider, selection.coordinator_jobs.clone(), 2).await? {
                    proofs.entry(checkpoint).or_default().extend(batch);
                }
                Ok::<_, anyhow::Error>(proofs)
            }.await;
            let mut proofs = match fetched {
                Ok(proofs) => proofs,
                Err(error) if error.downcast_ref::<RewardSourceError>().is_some() => { unloaded.insert(*source, (selection.clone(), RewardDeferral::SourceUnavailable)); tracing::warn!(checkpoint_id = *source, %error, "reward source unavailable; original selection retained"); continue; }
                Err(error) => return Err(error),
            };
            anyhow::ensure!(proofs.len() == 1 && proofs.contains_key(&u64::from(*source)), "reward source mapping changed");
            let batch = proofs.remove(&u64::from(*source)).context("reward source proof missing")?;
            let mut jobs = Vec::with_capacity(batch.len());
            for proof in batch { jobs.push(build_reward_job_witness(u64::from(*source), user_id, recipient, &proof)?); }
            anyhow::ensure!(!jobs.is_empty(), "reward source has no selected witnesses");
            groups.insert(*source, RewardJobOriginals { user_id, source_checkpoint_id: *source, jobs });
        }
        Ok(GroupedRewardJobs { groups, unloaded, selections })
    }

    fn reuse_or_record(&self, circuits: &UserRewardCircuits, caches: &[RewardJobAggregateCache], originals: &RewardJobOriginals, source: &PsyCheckpointLeaf<F>) -> Result<(RewardJobAggregate, RewardJobAggregateCache)> {
        for cache in caches {
            if let Some(aggregate) = self.reuse_reward_job_aggregate(&circuits.user_reward_leaf, &circuits.user_reward_aggregate, cache, originals, source)? {
                return Ok((aggregate, cache.clone()));
            }
        }
        let aggregate = self.prove_reward_job_aggregate(&circuits.user_reward_leaf, &circuits.user_reward_aggregate, originals.user_id, originals.source_checkpoint_id, source, &originals.jobs)?;
        let (cache, _) = aggregate.build_reward_job_aggregate_cache(circuits)?;
        Ok((aggregate, cache))
    }

    pub async fn discover_reward_deployment(&self, l1_rpc_url: &str, block: &str, reward_token: &str) -> Result<RewardDeployment> {
        let token = lowercase_address(reward_token)?;
        let token_hex = address_hex(token);
        let block_hash = self.canonical_block_hash(l1_rpc_url, block).await?;
        let code = self.eth_rpc(l1_rpc_url, "eth_getCode", serde_json::json!([token_hex, {"blockHash": block_hash, "requireCanonical": true}])).await?;
        let code_text = code.as_str().context("reward token code missing")?.trim_start_matches("0x");
        anyhow::ensure!(!code_text.is_empty() && code_text != "0", "reward token has no code");
        let provider = address_word(&self.l1_call(l1_rpc_url, block, &token_hex, keccak256(b"addressesProvider()")[..4].to_vec()).await?)?;
        anyhow::ensure!(provider != [0; 20], "reward token provider is zero");
        let provider_hex = address_hex(provider);
        let state_manager_id = self.l1_call(l1_rpc_url, block, &provider_hex, keccak256(b"STATE_MANAGER_ID()")[..4].to_vec()).await?;
        anyhow::ensure!(state_manager_id.len() == 32, "reward provider state manager id width");
        let mut state_manager_call = keccak256(b"getAddress(bytes32)")[..4].to_vec();
        state_manager_call.extend_from_slice(&state_manager_id);
        let state_manager = address_word(&self.l1_call(l1_rpc_url, block, &provider_hex, state_manager_call).await?)?;
        anyhow::ensure!(state_manager != [0; 20], "reward state manager is zero");
        let roundtrip = address_word(&self.l1_call(l1_rpc_url, block, &address_hex(state_manager), keccak256(b"addressesProvider()")[..4].to_vec()).await?)?;
        anyhow::ensure!(roundtrip == provider, "reward provider roundtrip differs");
        Ok(RewardDeployment { token, provider, state_manager })
    }

    pub async fn prepare_reward_claim(&self, circuits: &UserRewardCircuits, signer: &(dyn SignatureUser + Sync), request: PrepareRewardClaimRequest) -> Result<RewardClaimPreparation> {
        let recipient = lowercase_address(&request.recipient)?;
        let grouped = self.group_reward_jobs(request.jobs.clone(), request.user_id, recipient).await?;
        if grouped.groups.is_empty() && request.jobs.jobs_len() == 0 {
            return Ok(RewardClaimPreparation::NothingToClaim { already_claimed_checkpoint_ids: Vec::new() });
        }
        let block = self.read_l1_block(&request.l1_rpc_url).await?;
        let deployment = self.discover_reward_deployment(&request.l1_rpc_url, &block, &request.reward_token).await?;
        let token = address_hex(deployment.token);
        let state_manager = address_hex(deployment.state_manager);
        let (anchor_id, root_word, recognized) = self.read_finalized_checkpoint(&request.l1_rpc_url, &block, &state_manager).await?;
        let mut claimed_ids = Vec::new();
        let mut eligible = Vec::new();
        let mut later = Vec::new();
        let mut deferred = Vec::new();
        for (checkpoint, originals) in &grouped.groups {
            if self.read_claimed_pair(&request.l1_rpc_url, &block, &token, request.user_id, *checkpoint).await? {
                claimed_ids.push(*checkpoint);
                continue;
            }
            if recognized && *checkpoint <= anchor_id { eligible.push(originals.clone()); }
            else {
                if !recognized { deferred.push(deferred_record(*checkpoint, RewardDeferral::UnrecognizedRoot)); }
                later.push((*checkpoint, originals.clone()));
            }
        }
        eligible.sort_by_key(|originals| originals.source_checkpoint_id);
        let selected_count = eligible.len().min(REWARD_CLAIM_MAX_CHECKPOINTS);
        let (selected, overflow) = eligible.split_at(selected_count);
        let mut payable = Vec::new();
        let mut caches = Vec::new();
        let mut kept = Vec::new();
        let checkpoint_circuit = UserRewardCheckpointAggregateCircuit::new(&circuits.user_reward_root);
        let mut proofs = Vec::new();
        let mut claims = Vec::new();
        for originals in selected {
            let historical = async {
                let source = self.rpc_provider.get_checkpoint_leaf_data(u64::from(originals.source_checkpoint_id)).await?;
                let anchor = self.load_finalized_reward_anchor(anchor_id, root_word, originals).await?;
                Ok::<_, anyhow::Error>((source, anchor))
            }.await;
            let (source, anchor) = match historical {
                Ok(material) => material,
                Err(error) => {
                    tracing::warn!(checkpoint_id = originals.source_checkpoint_id, %error, "reward historical material unavailable; whole selection remains pending");
                    deferred.push(deferred_record(originals.source_checkpoint_id, RewardDeferral::HistoricalRead));
                    kept.push(originals.clone());
                    continue;
                }
            };
            let (aggregate, cache) = self.reuse_or_record(circuits, &request.aggregate_caches, originals, &source)?;
            let root = self.prove_finalized_reward_root(&circuits.user_reward_root, &circuits.user_reward_leaf, &circuits.user_reward_aggregate, &aggregate, &anchor, recipient_limbs(&recipient))?;
            caches.push(cache);
            let pi: [u64; 23] = root.public_inputs.iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>().try_into().map_err(|_| anyhow::anyhow!("reward root statement width mismatch"))?;
            claims.push(RewardClaim::from_public_inputs(&pi)?);
            proofs.push(checkpoint_circuit.prove(&UserRewardCheckpointAggregateWitness::Root { root })?);
            payable.push(aggregate.get_reward_job_originals());
        }
        if payable.is_empty() {
            for originals in overflow.iter().cloned().chain(later.into_iter().map(|(_, originals)| originals)).chain(kept) {
                if let Ok(source) = self.rpc_provider.get_checkpoint_leaf_data(u64::from(originals.source_checkpoint_id)).await {
                    if let Ok((_, cache)) = self.reuse_or_record(circuits, &request.aggregate_caches, &originals, &source) { caches.push(cache); }
                } else {
                    deferred.push(deferred_record(originals.source_checkpoint_id, RewardDeferral::SourceUnavailable));
                }
            }
        }
        for (checkpoint, (_, kind)) in &grouped.unloaded { deferred.push(deferred_record(*checkpoint, *kind)); }
        let remaining_ids: Vec<u32> = grouped.selections.keys().copied().filter(|id| !claimed_ids.contains(id) && !payable.iter().any(|item| item.source_checkpoint_id == *id)).collect();
        let remaining_jobs = join_selections(remaining_ids.iter().filter_map(|id| grouped.selections.get(id).cloned()));
        if payable.is_empty() {
            if caches.is_empty() {
                if remaining_jobs.jobs_len() == 0 { return Ok(RewardClaimPreparation::NothingToClaim { already_claimed_checkpoint_ids: claimed_ids }); }
                anyhow::bail!("deferred reward work produced no validated job aggregate");
            }
            return Ok(RewardClaimPreparation::ProofOnly { remaining_jobs, aggregate_caches: caches, already_claimed_checkpoint_ids: claimed_ids, deferred_checkpoints: deferred });
        }
        while proofs.len() > 1 {
            let mut round = proofs.into_iter();
            let mut reduced = Vec::new();
            while let Some(left) = round.next() {
                reduced.push(match round.next() {
                    Some(right) => checkpoint_circuit.prove(&UserRewardCheckpointAggregateWitness::Pair { left, right })?,
                    None => left,
                });
            }
            proofs = reduced;
        }
        let proof = proofs.pop().context("no eligible checkpoint proof")?;
        let statement = bind_reward_checkpoint_statement(&proof.public_inputs, request.user_id, &recipient, &root_word, &claims)?;
        let anchor = self.load_finalized_reward_anchor(anchor_id, root_word, payable.first().context("reward claim has no payable group")?).await?;
        let wrapped = signer.prove_reward_claim(self, &checkpoint_circuit, &proof, &anchor, deployment.token, deployment.state_manager).await?;
        let request_proof = RewardClaimWrapProofInput { reward_claim_wrap_proof_hex: hex::encode(bincode::serialize(&wrapped)?) };
        let wrap = self.prove_reward_claim_groth16(&request.prove_proxy_url, request.prove_proxy_token.as_deref(), &request_proof).await?;
        let data = encode_reward_claim_calldata(&wrap.solidity_proof, request.user_id, recipient, &statement)?;
        let fresh = self.read_l1_block(&request.l1_rpc_url).await?;
        if !self.read_reward_root_recognized(&request.l1_rpc_url, &fresh, &state_manager, statement.checkpoint_tree_root).await? {
            anyhow::bail!("reward checkpoint root is no longer recognized");
        }
        for id in &statement.checkpoint_ids {
            anyhow::ensure!(!self.read_claimed_pair(&request.l1_rpc_url, &fresh, &token, request.user_id, *id).await?, "reward checkpoint {id} is already claimed; rebuild the selected unclaimed batch");
        }
        let chain_id = self.observed_reward_chain_id(&request.l1_rpc_url).await?;
        let claim = PreparedRewardClaim {
            to: token,
            chain_id,
            value: "0x0".to_owned(),
            data: hex_word(&data),
            state_manager,
            checkpoint_root: hex_word(&statement.checkpoint_tree_root),
            user_id: request.user_id,
            recipient: address_hex(recipient),
            checkpoint_ids: statement.checkpoint_ids,
            total_amount: decimal_u128(statement.total_amount)?,
            snapshot_block_hash: fresh,
        };
        Ok(RewardClaimPreparation::Ready { claim, remaining_jobs, aggregate_caches: caches, already_claimed_checkpoint_ids: claimed_ids, deferred_checkpoints: deferred })
    }

    pub async fn confirm_reward_claim(&self, l1_rpc_url: &str, prepared: &PreparedRewardClaim, tx_hash: &str) -> Result<RewardClaimConfirmation> {
        let chain_id = self.observed_reward_chain_id(l1_rpc_url).await.context(format!("submitted_tx={tx_hash}"))?;
        let token = lowercase_address(&prepared.to)?;
        let prepared_state_manager = lowercase_address(&prepared.state_manager)?;
        anyhow::ensure!(reward_claim_chain(prepared.chain_id) && prepared.chain_id == chain_id && prepared.value == "0x0", "prepared reward claim chain differs from the provider");
        let recipient = lowercase_address(&prepared.recipient)?;
        let root = decode_hex32(&prepared.checkpoint_root)?;
        let total = decimal_u128_word(&prepared.total_amount)?;
        let statement = RewardCheckpointStatement { checkpoint_tree_root: root, checkpoint_ids: prepared.checkpoint_ids.clone(), total_amount: total };
        let data = hex::decode(prepared.data.trim_start_matches("0x")).context("prepared reward calldata")?;
        decode_prepared_calldata(&data, prepared.user_id, recipient, &statement)?;
        let receipt = self.eth_rpc(l1_rpc_url, "eth_getTransactionReceipt", serde_json::json!([tx_hash])).await.context(format!("submitted_tx={tx_hash}"))?;
        if receipt.is_null() { return Ok(RewardClaimConfirmation::Pending { tx_hash: tx_hash.to_owned() }); }
        let receipt = self.read_canonical_reward_receipt(l1_rpc_url, tx_hash, &receipt).await.context(format!("submitted_tx={tx_hash}"))?;
        let observed_hash = receipt["transactionHash"].as_str().context("reward receipt has no transaction hash")?;
        anyhow::ensure!(observed_hash.eq_ignore_ascii_case(tx_hash), "reward receipt transaction hash mismatch");
        let tx_view = self.eth_rpc(l1_rpc_url, "eth_getTransactionByHash", serde_json::json!([tx_hash])).await.context(format!("submitted_tx={tx_hash}"))?;
        anyhow::ensure!(tx_view["hash"].as_str().context("reward transaction hash missing")?.eq_ignore_ascii_case(tx_hash), "reward transaction hash mismatch");
        let tx_block = tx_view["blockNumber"].as_str().context("reward transaction has no block number")?;
        let receipt_block_number = receipt["blockNumber"].as_str().context("reward receipt has no block number")?;
        anyhow::ensure!(canonical_quantity(tx_block)? == canonical_quantity(receipt_block_number)?, "reward receipt block number mismatch");
        let tx_chain = tx_view["chainId"].as_str().context("reward transaction has no chain id")?;
        anyhow::ensure!(chain_id_word(canonical_quantity(tx_chain)?)? == chain_id, "prepared reward claim chain differs from the signed transaction");
        self.observed_reward_chain_id(l1_rpc_url).await.context(format!("submitted_tx={tx_hash}"))?;
        let status = receipt["status"].as_str().context("reward receipt has no status")?;
        anyhow::ensure!(status == "0x1", "reward claim transaction reverted: tx_hash={tx_hash}");
        let tx_to = lowercase_address(tx_view["to"].as_str().context("reward transaction has no destination")?)?;
        let tx_input = tx_view["input"].as_str().context("reward transaction has no input")?;
        anyhow::ensure!(tx_to == token && tx_input.eq_ignore_ascii_case(&prepared.data), "reward transaction does not match the prepared claim");
        let block_hash = receipt["blockHash"].as_str().context("reward receipt has no block hash")?.to_owned();
        let discovered = self.discover_reward_deployment(l1_rpc_url, &block_hash, &prepared.to).await.context(format!("submitted_tx={tx_hash}"))?;
        anyhow::ensure!(discovered.state_manager == prepared_state_manager, "prepared reward claim state manager differs from the receipt deployment");
        self.reward_claimed_event(&receipt, token, prepared.user_id, recipient, &statement).context(format!("submitted_tx={tx_hash}"))?;
        self.mint_transfer_event(&receipt, token, recipient, total).context(format!("submitted_tx={tx_hash}"))?;
        for id in &statement.checkpoint_ids {
            anyhow::ensure!(self.read_claimed_pair(l1_rpc_url, &block_hash, &address_hex(token), prepared.user_id, *id).await.context(format!("submitted_tx={tx_hash}"))?, "reward token claimed pair differs for checkpoint {id}");
        }
        let block_number = u64::from_be_bytes(canonical_quantity(receipt_block_number)?[24..].try_into().unwrap());
        Ok(RewardClaimConfirmation::Confirmed { tx_hash: tx_hash.to_owned(), block_hash, block_number, checkpoint_ids: statement.checkpoint_ids, total_amount: prepared.total_amount.clone() })
    }
}

fn decimal_u128_word(value: &str) -> Result<[u8; 32]> {
    let number: u128 = value.parse().context("reward total is not a decimal u128")?;
    anyhow::ensure!(number.to_string() == value && number > 0, "noncanonical reward total");
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&number.to_be_bytes());
    Ok(word)
}

fn decode_prepared_calldata(data: &[u8], user_id: u32, recipient: [u8; 20], statement: &RewardCheckpointStatement) -> Result<()> {
    anyhow::ensure!(data.len() >= 4 + 512, "prepared calldata is shorter than the claim head");
    anyhow::ensure!(data[..4] == keccak256(CLAIM_REWARD_SIGNATURE.as_bytes())[..4], "prepared calldata selector mismatch");
    let word = |index: usize| -> [u8; 32] { data[4 + index * 32..4 + (index + 1) * 32].try_into().unwrap() };
    anyhow::ensure!(word(0) == encode_u64_word(192) && word(1) == statement.checkpoint_tree_root && word(2) == encode_u64_word(u64::from(user_id)), "prepared calldata head mismatch");
    let mut recipient_word = [0u8; 32];
    recipient_word[12..].copy_from_slice(&recipient);
    let ids = &statement.checkpoint_ids;
    anyhow::ensure!(word(3) == recipient_word && word(4) == encode_u64_word(480) && word(5) == statement.total_amount && word(6) == encode_u64_word(256), "prepared calldata statement mismatch");
    anyhow::ensure!(data.len() == 4 + 512 + ids.len() * 32, "prepared calldata width mismatch");
    anyhow::ensure!(word(15) == encode_u64_word(u64::try_from(ids.len())?), "prepared calldata id count mismatch");
    for index in 0..8 {
        anyhow::ensure!(word(7 + index).iter().any(|byte| *byte != 0), "prepared calldata proof word is zero");
    }
    for (index, id) in ids.iter().enumerate() {
        anyhow::ensure!(data[4 + 512 + index * 32..4 + 544 + index * 32] == encode_u64_word(u64::from(*id)), "prepared calldata id mismatch");
    }
    Ok(())
}


fn index_reward_preimages(jobs: &[QProvingJobDataIDWithRewardPreimage]) -> Result<HashMap<QProvingJobDataID, QHashOut<F>>> {
    let mut index = HashMap::new();
    for job in jobs {
        if let Some(existing) = index.insert(job.inner.job_data_id, job.reward_tree_tag_preimage) {
            anyhow::ensure!(existing == job.reward_tree_tag_preimage, "conflicting reward preimages for duplicate job_id {:?}", job.inner.job_data_id);
        }
    }
    Ok(index)
}

fn attach_reward_preimages(
    proofs: Vec<PsyProoffMinerRewardProof<QHashOut<F>>>,
    preimages: &HashMap<QProvingJobDataID, QHashOut<F>>,
    source: &str,
) -> Result<Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<F>>>> {
    let mut matched = HashMap::new();
    let mut attached = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let reward_tree_tag_preimage = preimages.get(&proof.job_id).copied().with_context(|| format!("missing reward preimage for {source} proof job {:?}", proof.job_id))?;
        anyhow::ensure!(matched.insert(proof.job_id, ()).is_none(), "duplicate {source} proof for job {:?}", proof.job_id);
        attached.push(PsyProoffMinerRewardProofWithRewardPreimage { inner: proof, reward_tree_tag_preimage });
    }
    if matched.len() != preimages.len() {
        let missing = preimages.keys().filter(|job_id| !matched.contains_key(*job_id)).copied().collect::<Vec<_>>();
        anyhow::bail!("{source} proofs are missing requested job_ids {missing:?}");
    }
    Ok(attached)
}

fn require_checkpoint_id(checkpoint_id: Option<u64>, source: &str) -> Result<u64> {
    checkpoint_id.with_context(|| format!("{source} has no checkpoint id"))
}

pub async fn load_realm_reward_proofs(
    provider: &RpcProvider,
    edges: &HashMap<(u64, u64), String>,
    job_ids: Vec<(u64, u64, u64, QProvingJobDataIDWithRewardPreimage)>,
) -> Result<HashMap<u64, Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<F>>>>> {
    let grouped: HashMap<(u64, u64, u64), Vec<QProvingJobDataIDWithRewardPreimage>> = job_ids.into_iter().fold(HashMap::new(), |mut map, (realm_id, realm_sub_id, unique_pending_id, job)| {
        map.entry((realm_id, realm_sub_id, unique_pending_id)).or_default().push(job);
        map
    });
    let mut proofs_by_checkpoint = HashMap::new();
    for ((realm_id, realm_sub_id, unique_pending_id), jobs) in grouped {
        let url = edges.get(&(realm_id, realm_sub_id)).with_context(|| format!("realm {realm_id} sub {realm_sub_id} has no discovered edge"))?;
        let ids = jobs.iter().map(|job| job.inner).collect::<Vec<_>>();
        let preimages = index_reward_preimages(&jobs)?;
        let checkpoint_id = require_checkpoint_id(provider.get_realm_checkpoint_id_for_unique_pending_id_by_realm_id(url, unique_pending_id).await.map_err(RewardDeferral::source_unavailable)?, &format!("realm {realm_id} sub {realm_sub_id} unique_pending_id {unique_pending_id}"))?;
        let proofs = provider.generate_realm_batch_proof_miner_reward_proofs_by_realm_id(url, unique_pending_id, ids).await.map_err(RewardDeferral::source_unavailable)?;
        proofs_by_checkpoint.entry(checkpoint_id).or_insert_with(Vec::new).extend(attach_reward_preimages(proofs, &preimages, "realm")?);
    }
    Ok(proofs_by_checkpoint)
}

pub async fn load_coordinator_reward_proofs(
    provider: &RpcProvider,
    job_ids: Vec<(u64, QProvingJobDataIDWithRewardPreimage)>,
    node_type: u8,
) -> Result<HashMap<u64, Vec<PsyProoffMinerRewardProofWithRewardPreimage<QHashOut<F>>>>> {
    let grouped: HashMap<u64, Vec<QProvingJobDataIDWithRewardPreimage>> = job_ids.into_iter().fold(HashMap::new(), |mut map, (unique_pending_id, job)| {
        map.entry(unique_pending_id).or_default().push(job);
        map
    });
    let mut proofs_by_checkpoint = HashMap::new();
    for (unique_pending_id, jobs) in grouped {
        let ids = jobs.iter().map(|job| job.inner).collect::<Vec<_>>();
        let preimages = index_reward_preimages(&jobs)?;
        let (checkpoint_id, proofs) = if node_type == 1 {
            let checkpoint_id = require_checkpoint_id(provider.get_realm_checkpoint_id_for_unique_pending_id(unique_pending_id).await.map_err(RewardDeferral::source_unavailable)?, &format!("realm unique_pending_id {unique_pending_id}"))?;
            (checkpoint_id, provider.generate_realm_batch_proof_miner_reward_proofs(unique_pending_id, ids).await.map_err(RewardDeferral::source_unavailable)?)
        } else {
            let checkpoint_id = require_checkpoint_id(provider.get_coordinator_checkpoint_id_for_unique_pending_id(unique_pending_id).await.map_err(RewardDeferral::source_unavailable)?, &format!("coordinator unique_pending_id {unique_pending_id}"))?;
            (checkpoint_id, provider.generate_coordinator_batch_proof_miner_reward_proofs(unique_pending_id, ids).await.map_err(RewardDeferral::source_unavailable)?)
        };
        proofs_by_checkpoint.entry(checkpoint_id).or_insert_with(Vec::new).extend(attach_reward_preimages(proofs, &preimages, "coordinator")?);
    }
    Ok(proofs_by_checkpoint)
}



#[cfg(test)]
mod status_tests {
    use super::*;


    fn cache_fixture() -> (RewardJobAggregateCache, RewardJobOriginals, PsyCheckpointLeaf<F>, UserRewardJobWitness) {
        let job = UserRewardJobWitness { source_checkpoint_id: 10, height: 2, path_index: 0, tag: UserRewardTagWitness { tag_preimage: ParthQHashOut::ZERO, leaf_left: ParthQHashOut::ZERO, leaf_right: ParthQHashOut::ZERO, leaf_tag: ParthQHashOut::ZERO, siblings: [ParthQHashOut::ZERO; 21], parent_tags: [ParthQHashOut::ZERO; 21] } };
        let originals = RewardJobOriginals { user_id: 7, source_checkpoint_id: 10, jobs: vec![job.clone()] };
        let leaf = PsyCheckpointLeaf::default();
        let cache = RewardJobAggregateCache {
            schema: REWARD_JOB_AGGREGATE_CACHE_SCHEMA, network_magic: PSY_NETWORK_MAGIC,
            user_id: 7, source_checkpoint_id: 10, source_checkpoint_leaf: leaf, source_checkpoint_leaf_hash: hash_limbs(source_leaf_hash(&leaf)),
            selected_jobs: selected_coordinates(&originals.jobs), selection_identity: selection_identity(&originals.jobs),
            leaf_fingerprint: [2; 4], leaf_common_digest: [3; 32], leaf_verifier_digest: [4; 32],
            aggregate_fingerprint: [5; 4], aggregate_common_digest: [6; 32], aggregate_verifier_digest: [7; 32], aggregate_proof: "proof".into(),
        };
        (cache, originals, leaf, job)
    }

    #[test]
    fn cache_rejects_tamper_subset_equal_count_and_source_change_without_mutation() {
        let (cache, originals, leaf, job) = cache_fixture();
        let saved = cache.clone();
        let mut tampered = cache.clone();
        tampered.aggregate_fingerprint[0] ^= 1;
        assert_ne!(tampered.aggregate_fingerprint, saved.aggregate_fingerprint);
        assert_eq!(tampered.aggregate_proof, saved.aggregate_proof);
        let other = UserRewardJobWitness { path_index: 1, ..job };
        assert!(cache_binds_selection(&cache, 7, 10, &leaf, &originals.jobs));
        assert!(!cache_binds_selection(&cache, 7, 10, &leaf, &[other.clone()]));
        assert_eq!(1, cache.selected_jobs.len());
        assert_ne!(expected_nullifier_root(&[other]).unwrap(), expected_nullifier_root(&originals.jobs).unwrap());
        let duplicate = ordered_selected_jobs(&[originals.jobs[0].clone(), originals.jobs[0].clone()], 10);
        assert!(duplicate.unwrap_err().to_string().contains("not strictly ordered"));
        let mut changed = leaf;
        changed.stats.guta_fees_collected += F::ONE;
        assert!(!cache_binds_selection(&cache, 7, 10, &changed, &originals.jobs));
        assert_eq!(cache, saved);
        assert_eq!(originals.jobs.len(), saved.selected_jobs.len());
    }

    #[test]
    fn production_witness_uses_claim_local_index_not_old_wire_formula() {
        use psy_client_data::api::reward::{PsyProoffMinerRewardProof, PsyProoffMinerRewardProofWithRewardPreimage};
        use psy_crypto::hash::merkle::tag_tree::{TagTreeMerkleProof, TagTreeNodePreimage, TagTreeProofNode};
        let hash = |value: u64| QHashOut(HashOut { elements: [F::from_canonical_u64(value), F::ZERO, F::ZERO, F::ZERO] });
        let preimage = HashOut { elements: [F::from_canonical_u64(7), F::ZERO, F::ONE, F::TWO] };
        let owner = PoseidonHash::two_to_one(preimage, preimage);
        let leaf = TagTreeNodePreimage { left: hash(1), right: hash(2), tag: QHashOut(owner) };
        let proof = TagTreeMerkleProof::new_from_params::<PoseidonHash>(1, leaf, vec![
            TagTreeProofNode { sibling: hash(3), parent_tag: hash(4) },
            TagTreeProofNode { sibling: hash(5), parent_tag: hash(6) },
            TagTreeProofNode { sibling: hash(7), parent_tag: hash(8) },
        ]);
        let job_id = QProvingJobDataID::new(psy_client_common::job::id::QJobTopic::GenerateStandardProof, 11, 0, 0, 0, 1, psy_client_common::job::id::ProvingJobCircuitType::AppendUserRegistrationTree, psy_client_common::job::id::ProvingJobDataType::InputWitness, 0);
        let wrapped = PsyProoffMinerRewardProofWithRewardPreimage {
            inner: PsyProoffMinerRewardProof { job_id, tag_tree_proof: proof },
            reward_tree_tag_preimage: QHashOut(preimage),
        };
        let witness = build_reward_job_witness(10, 7, [1; 20], &wrapped).unwrap();
        let shared = nullifier_job_index(witness.height, witness.path_index).unwrap();
        let old = (1u32 << witness.height) - 1 + witness.path_index;
        assert_eq!((witness.height, witness.path_index, shared, old), (3, 1, 2, 8));

        assert!(build_reward_job_witness(10, 8, [1; 20], &wrapped).is_err());
    }

    #[test]
    fn proofs_match_preimages_by_job_id_and_reject_incomplete_sets() {
        use psy_client_common::job::id::{ProvingJobCircuitType, ProvingJobDataType, QJobTopic};
        let job = |task_index: u32, marker: u64| QProvingJobDataIDWithRewardPreimage::new(
            QProvingJobDataID::new(QJobTopic::GenerateStandardProof, 11, 0, 0, 0, task_index, ProvingJobCircuitType::AppendUserRegistrationTree, ProvingJobDataType::InputWitness, 0),
            marker, QHashOut::from_values(7, 0, marker, marker + 1),
        );
        let first = job(1, 10);
        let second = job(2, 20);
        let preimages = index_reward_preimages(&[first.clone(), second.clone()]).unwrap();
        let attached = attach_reward_preimages(vec![
            PsyProoffMinerRewardProof { job_id: second.inner.job_data_id, tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty() },
            PsyProoffMinerRewardProof { job_id: first.inner.job_data_id, tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty() },
        ], &preimages, "test").unwrap();
        assert_eq!(attached[0].reward_tree_tag_preimage, second.reward_tree_tag_preimage);
        assert!(attach_reward_preimages(vec![PsyProoffMinerRewardProof { job_id: first.inner.job_data_id, tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty() }], &preimages, "test").unwrap_err().to_string().contains("missing requested job_ids"));
        assert!(require_checkpoint_id(None, "coordinator unique_pending_id 11").unwrap_err().to_string().contains("has no checkpoint id"));
    }

    #[test]
    fn malformed_proof_group_is_not_source_unavailable() {
        use psy_client_common::job::id::{ProvingJobCircuitType, ProvingJobDataType, QJobTopic};
        let job = |task_index: u32, marker: u64| QProvingJobDataIDWithRewardPreimage::new(
            QProvingJobDataID::new(QJobTopic::GenerateStandardProof, 11, 0, 0, 0, task_index, ProvingJobCircuitType::AppendUserRegistrationTree, ProvingJobDataType::InputWitness, 0),
            marker, QHashOut::from_values(7, 0, marker, marker + 1),
        );
        let available = job(1, 10);
        let malformed = job(2, 20);
        let available_ok = attach_reward_preimages(vec![PsyProoffMinerRewardProof { job_id: available.inner.job_data_id, tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty() }], &index_reward_preimages(&[available.clone()]).unwrap(), "available").is_ok();
        let malformed_error = attach_reward_preimages(vec![PsyProoffMinerRewardProof { job_id: available.inner.job_data_id, tag_tree_proof: psy_crypto::hash::merkle::tag_tree::TagTreeMerkleProof::new_empty() }], &index_reward_preimages(&[malformed]).unwrap(), "malformed").unwrap_err();
        assert!(available_ok);
        assert!(malformed_error.downcast_ref::<RewardSourceError>().is_none(), "malformed proof set became source unavailable: {malformed_error}");
        let unavailable = RewardDeferral::source_unavailable(anyhow::anyhow!("rpc transport"));
        assert!(unavailable.downcast_ref::<RewardSourceError>().is_some());
    }


    #[test]
    fn response_variants_use_camel_case_fields_and_snake_case_status() {
        let empty = RewardPendingSelection { realm_jobs: Vec::new(), coordinator_jobs: Vec::new() };
        let deferred = vec![DeferredRewardCheckpoint { checkpoint_id: 9, reason: RewardDeferral::SourceUnavailable.reason() }];
        let ready = RewardClaimPreparation::Ready {
            claim: PreparedRewardClaim { to: "0x11".into(), chain_id: 1, value: "0x0".into(), data: "0x".into(), state_manager: "0x33".into(), checkpoint_root: "0x44".into(), user_id: 7, recipient: "0x55".into(), checkpoint_ids: vec![1], total_amount: "12".into(), snapshot_block_hash: "0x66".into() },
            remaining_jobs: empty.clone(), aggregate_caches: Vec::new(), already_claimed_checkpoint_ids: vec![2], deferred_checkpoints: deferred.clone(),
        };
        let ready_json = serde_json::to_value(&ready).unwrap();
        assert_eq!(ready_json["status"], "ready");
        assert!(ready_json.get("remainingJobs").is_some() && ready_json.get("aggregateCaches").is_some() && ready_json.get("alreadyClaimedCheckpointIds").is_some() && ready_json.get("deferredCheckpoints").is_some());
        assert!(ready_json.get("remaining_jobs").is_none());
        assert_eq!(ready_json["claim"]["chainId"], 1);
        assert_eq!(ready_json["claim"]["snapshotBlockHash"], "0x66");
        let proof_only = RewardClaimPreparation::ProofOnly { remaining_jobs: empty.clone(), aggregate_caches: Vec::new(), already_claimed_checkpoint_ids: Vec::new(), deferred_checkpoints: deferred };
        assert_eq!(serde_json::to_value(&proof_only).unwrap()["status"], "proof_only");
        let nothing = RewardClaimPreparation::NothingToClaim { already_claimed_checkpoint_ids: vec![3] };
        let nothing_json = serde_json::to_value(&nothing).unwrap();
        assert_eq!(nothing_json["status"], "nothing_to_claim");
        assert_eq!(nothing_json["alreadyClaimedCheckpointIds"][0], 3);
        let pending = RewardClaimConfirmation::Pending { tx_hash: "0xab".into() };
        assert_eq!(serde_json::to_value(&pending).unwrap()["txHash"], "0xab");
        let confirmed = RewardClaimConfirmation::Confirmed { tx_hash: "0xab".into(), block_hash: "0xcd".into(), block_number: 9, checkpoint_ids: vec![1], total_amount: "12".into() };
        let confirmed_json = serde_json::to_value(&confirmed).unwrap();
        assert_eq!(confirmed_json["status"], "confirmed");
        assert_eq!(confirmed_json["blockHash"], "0xcd");
        assert_eq!(confirmed_json["blockNumber"], 9);
        assert!(confirmed_json.get("chainId").is_none());
        assert!(confirmed_json.get("block_number").is_none());
    }
    #[test]
    fn old_config_cache_and_prepared_claim_fail_closed() {
        let (cache, _, _, _) = cache_fixture();
        let mut old_cache = serde_json::to_value(&cache).unwrap();
        old_cache["configHash"] = "0x11".into();
        old_cache["circuitSetHash"] = "0x22".into();
        assert!(serde_json::from_value::<RewardJobAggregateCache>(old_cache).is_err());
        let mut old_request = serde_json::json!({"rewardToken":"0x1111111111111111111111111111111111111111","userId":7,"recipient":"0x2222222222222222222222222222222222222222","jobs":{"realmJobs":[],"coordinatorJobs":[]},"l1RpcUrl":"http://127.0.0.1:1","proveProxyUrl":"http://127.0.0.1:2"});
        old_request["aggregateSetup"] = serde_json::json!({});
        assert!(serde_json::from_value::<PrepareRewardClaimRequest>(old_request).is_err());
        let mut old_claim = serde_json::to_value(PreparedRewardClaim { to: "0x11".into(), chain_id: 1, value: "0x0".into(), data: "0x".into(), state_manager: "0x33".into(), checkpoint_root: format!("0x{}", "44".repeat(32)), user_id: 7, recipient: "0x55".into(), checkpoint_ids: vec![1], total_amount: "12".into(), snapshot_block_hash: format!("0x{}", "66".repeat(32)) }).unwrap();
        old_claim["configHash"] = format!("0x{}", "22".repeat(32)).into();
        assert!(serde_json::from_value::<PreparedRewardClaim>(old_claim).is_err());
    }

    #[test]
    fn cache_pin_mismatch_rejects_without_deleting_fields() {
        let (cache, _, _, _) = cache_fixture();
        let leaf = SourceCircuitPin { fingerprint: cache.leaf_fingerprint, common_digest: cache.leaf_common_digest, verifier_digest: cache.leaf_verifier_digest };
        let aggregate = SourceCircuitPin { fingerprint: cache.aggregate_fingerprint, common_digest: cache.aggregate_common_digest, verifier_digest: cache.aggregate_verifier_digest };
        assert!(cache_circuits_match(&cache, &leaf, &aggregate));
        let mut wrong_chain = cache.clone();
        wrong_chain.network_magic ^= 1;
        assert_ne!(wrong_chain.network_magic, PSY_NETWORK_MAGIC);
        let mut wrong_provider = cache.clone();
        wrong_provider.leaf_common_digest[0] ^= 1;
        assert!(!cache_circuits_match(&wrong_provider, &leaf, &aggregate));
        let mut wrong_verifier = cache;
        wrong_verifier.aggregate_verifier_digest[0] ^= 1;
        assert!(!cache_circuits_match(&wrong_verifier, &leaf, &aggregate));
    }

    #[test]
    fn discovery_address_word_rejects_short_and_nonzero_prefix() {
        assert!(address_word(&[0; 31]).is_err());
        let mut prefixed = [0u8; 32];
        prefixed[11] = 1;
        prefixed[31] = 2;
        assert!(address_word(&prefixed).unwrap_err().to_string().contains("address word"));
        let mut word = [0u8; 32];
        word[12..].copy_from_slice(&[3; 20]);
        assert_eq!(address_word(&word).unwrap(), [3; 20]);
        assert!(lowercase_address("0x111111111111111111111111111111111111111").is_err());
        assert!(lowercase_address("0xGG11111111111111111111111111111111111111").is_err());
    }

    #[test]
    fn reward_claim_chain_accepts_only_the_token_set() {
        for chain_id in [1u64, 31337, 11155111] {
            assert!(reward_claim_chain(chain_id));
            assert_eq!(chain_id_word(encode_u64_word(chain_id)).unwrap(), chain_id);
        }
        for chain_id in [0u64, 5, 31338, 11155110, 11155112] {
            assert!(!reward_claim_chain(chain_id));
        }
        let mut wide = encode_u64_word(1);
        wide[23] = 1;
        assert!(chain_id_word(wide).is_err());
    }

    #[tokio::test]
    async fn standard_receipt_without_chain_id_confirms_and_wrong_tx_chain_fails() {
        use std::io::{BufRead, Read, Write};
        use std::sync::atomic::{AtomicBool, Ordering};
        let token = [5u8; 20];
        let recipient = [1u8; 20];
        let root = [2u8; 32];
        let total = encode_u64_word(20);
        let statement = RewardCheckpointStatement { checkpoint_tree_root: root, checkpoint_ids: vec![10], total_amount: total };
        let data = encode_reward_claim_calldata(&["1".into(), "1".into(), "1".into(), "1".into(), "1".into(), "1".into(), "1".into(), "1".into()], 7, recipient, &statement).unwrap();
        let tx_hash = format!("0x{}", "cd".repeat(32));
        let block_hash = format!("0x{}", "ab".repeat(32));
        let mut recipient_word = [0u8; 32];
        recipient_word[12..].copy_from_slice(&recipient);
        let mut claimed_data = encode_u64_word(64).to_vec();
        claimed_data.extend_from_slice(&total);
        claimed_data.extend_from_slice(&encode_u64_word(1));
        claimed_data.extend_from_slice(&encode_u64_word(10));
        let claimed_topic = keccak256(REWARD_CLAIMED_SIGNATURE.as_bytes());
        let transfer_topic = keccak256(TRANSFER_SIGNATURE.as_bytes());
        let logs = serde_json::json!([
            {"address":format!("0x{}", hex::encode(token)),"topics":[hex_word(&claimed_topic),hex_word(&encode_u64_word(7)),hex_word(&recipient_word),hex_word(&root)],"data":hex_word(&claimed_data)},
            {"address":format!("0x{}", hex::encode(token)),"topics":[hex_word(&transfer_topic),hex_word(&[0u8; 32]),hex_word(&recipient_word)],"data":hex_word(&total)}
        ]);
        let receipt = serde_json::json!({"transactionHash": tx_hash, "blockHash": block_hash, "blockNumber": "0x2a", "status": "0x1", "logs": logs});
        assert!(receipt.get("chainId").is_none());
        let prepared = PreparedRewardClaim {
            to: format!("0x{}", hex::encode(token)), chain_id: 31337, value: "0x0".into(), data: hex_word(&data),
            state_manager: format!("0x{}", "33".repeat(20)), checkpoint_root: hex_word(&root),
            user_id: 7, recipient: format!("0x{}", hex::encode(recipient)), checkpoint_ids: vec![10], total_amount: "20".into(), snapshot_block_hash: block_hash.clone(),
        };
        let tx_view = serde_json::json!({"hash": tx_hash, "blockHash": block_hash, "blockNumber": "0x2a", "to": format!("0x{}", hex::encode(token)), "input": hex_word(&data)});
        let block_view = serde_json::json!({"hash": block_hash});
        let tx_chain = std::sync::Arc::new(parking_lot::Mutex::new("0x7a69".to_owned()));
        let tx_chain_reply = tx_chain.clone();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let thread = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if stopped.load(Ordering::SeqCst) { break; }
                let mut stream = stream.unwrap();
                stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
                let mut reader = std::io::BufReader::new(&mut stream);
                let mut length = None;
                loop {
                    let mut line = String::new();
                    assert_ne!(reader.read_line(&mut line).unwrap(), 0);
                    if line == "\r\n" { break; }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("content-length") { length = Some(value.trim().parse::<usize>().unwrap()); }
                    }
                }
                let mut body = vec![0; length.unwrap()];
                reader.read_exact(&mut body).unwrap();
                drop(reader);
                let request: Value = serde_json::from_slice(&body).unwrap();
                let result = match request["method"].as_str().unwrap() {
                    "eth_chainId" => serde_json::json!("0x7a69"),
                    "eth_getTransactionReceipt" => receipt.clone(),
                    "eth_getTransactionByHash" => { let mut tx = tx_view.clone(); tx["chainId"] = tx_chain_reply.lock().clone().into(); tx },
                    "eth_getBlockByNumber" => block_view.clone(),
                    "eth_getCode" => serde_json::json!("0x60"),
                    "eth_call" => {
                        let call = hex::decode(request["params"][0]["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
                        let selector = &call[..4];
                        if selector == &keccak256(b"addressesProvider()")[..4] { serde_json::json!(format!("0x{}{}", "00".repeat(12), "11".repeat(20))) }
                        else if selector == &keccak256(b"STATE_MANAGER_ID()")[..4] { serde_json::json!(format!("0x{}", "22".repeat(32))) }
                        else if selector == &keccak256(b"getAddress(bytes32)")[..4] { serde_json::json!(format!("0x{}{}", "00".repeat(12), "33".repeat(20))) }
                        else if selector == &keccak256(b"claimed(uint32,uint32)")[..4] { serde_json::json!(hex_word(&encode_u64_word(1))) }
                        else { panic!("unexpected call") }
                    },
                    method => panic!("unexpected method {method}"),
                };
                let response = serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":result}).to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
            }
        });
        let client = RewardClient::new(RpcProvider { client: std::sync::Arc::new(reqwest::Client::new()), endpoint_clients: None, realm_configs: HashMap::new(), coordinator_configs: std::collections::HashMap::from([(0, vec![url.clone()])]), users_per_realm: 1, current_user_id: 0 });
        let confirmed = client.confirm_reward_claim(&url, &prepared, &tx_hash).await.unwrap();
        assert!(matches!(confirmed, RewardClaimConfirmation::Confirmed { block_number: 42, .. }));
        *tx_chain.lock() = "0x1".into();
        let wrong = client.confirm_reward_claim(&url, &prepared, &tx_hash).await.unwrap_err();
        assert!(wrong.to_string().contains("signed transaction"), "{wrong:#}");
        stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(url.trim_start_matches("http://"));
        thread.join().unwrap();
    }
    #[tokio::test]
    async fn reordered_edges_dispatch_pending_310_by_reported_sub() {
        use std::io::{BufRead, Read, Write};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use psy_client_common::job::id::{ProvingJobCircuitType, ProvingJobDataType, QJobTopic, QProvingJobDataID};
        fn serve(sub: u64, checkpoint: Option<u64>, proof_hits: std::sync::Arc<AtomicUsize>, identity_hits: std::sync::Arc<AtomicUsize>) -> String {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let mut stream = stream.unwrap();
                    stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
                    let mut reader = std::io::BufReader::new(&mut stream);
                    let mut length = None;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 { return; }
                        if line == "\r\n" { break; }
                        if let Some((name, value)) = line.split_once(':') {
                            if name.eq_ignore_ascii_case("content-length") { length = Some(value.trim().parse::<usize>().unwrap()); }
                        }
                    }
                    let mut body = vec![0; length.unwrap()];
                    reader.read_exact(&mut body).unwrap();
                    drop(reader);
                    let request: Value = serde_json::from_slice(&body).unwrap();
                    let result = match request["method"].as_str().unwrap() {
                        "psy_worker_get_realm_identifier_worker_api" => { identity_hits.fetch_add(1, Ordering::SeqCst); serde_json::json!({"realm_id": 0, "realm_sub_id": sub}) }
                        "psy_get_checkpoint_id_for_unique_pending_id" => { assert_eq!(request["params"]["unique_pending_id"], 310); serde_json::json!(checkpoint) }
                        "psy_generate_batch_proof_miner_reward_proofs" => {
                            proof_hits.fetch_add(1, Ordering::SeqCst);
                            assert_eq!(request["params"]["unique_pending_id"], 310);
                            let job = request["params"]["job_ids"][0].clone();
                            serde_json::json!([{"job_id": job["job_data_id"], "tag_tree_proof": {"root": "00", "leaf": {"left": "00", "right": "00", "tag": "00"}, "index": 0, "siblings": []}}])
                        }
                        method => panic!("unexpected method {method}"),
                    };
                    let response = serde_json::json!({"jsonrpc":"2.0","id":request["id"],"result":result}).to_string();
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
                }
            });
            url
        }
        let sub1_identity = std::sync::Arc::new(AtomicUsize::new(0));
        let sub2_identity = std::sync::Arc::new(AtomicUsize::new(0));
        let sub1_proofs = std::sync::Arc::new(AtomicUsize::new(0));
        let sub2_proofs = std::sync::Arc::new(AtomicUsize::new(0));
        let first = serve(2, None, sub2_proofs.clone(), sub2_identity.clone());
        let second = serve(1, Some(119), sub1_proofs.clone(), sub1_identity.clone());
        let provider = RpcProvider { client: std::sync::Arc::new(reqwest::Client::new()), endpoint_clients: None, realm_configs: HashMap::from([(0, vec![first, second])]), coordinator_configs: std::collections::HashMap::from([(0, vec!["http://127.0.0.1:1".into()])]), users_per_realm: 1, current_user_id: 0 };
        let edges = provider.discover_realm_edges().await.unwrap();
        assert_eq!(sub1_identity.load(Ordering::SeqCst), 1);
        assert_eq!(sub2_identity.load(Ordering::SeqCst), 1);
        let job = QProvingJobDataIDWithRewardPreimage::new(QProvingJobDataID::new(QJobTopic::GenerateStandardProof, 11, 0, 0, 0, 1, ProvingJobCircuitType::AppendUserRegistrationTree, ProvingJobDataType::InputWitness, 0), 1, QHashOut::from_values(7, 0, 0, 0));
        let sub1 = load_realm_reward_proofs(&provider, &edges, vec![(0, 1, 310, job.clone())]).await.unwrap();
        assert_eq!(sub1.keys().copied().collect::<Vec<_>>(), vec![119]);
        assert_eq!(sub1_proofs.load(Ordering::SeqCst), 1);
        assert_eq!(sub2_proofs.load(Ordering::SeqCst), 0);
        let missing = load_realm_reward_proofs(&provider, &edges, vec![(0, 2, 310, job)]).await.unwrap_err();
        assert!(missing.to_string().contains("no checkpoint id"), "{missing}");
        assert_eq!(sub2_proofs.load(Ordering::SeqCst), 0);
        assert!(load_realm_reward_proofs(&provider, &edges, vec![(0, 9, 310, QProvingJobDataIDWithRewardPreimage::new(QProvingJobDataID::new(QJobTopic::GenerateStandardProof, 11, 0, 0, 0, 2, ProvingJobCircuitType::AppendUserRegistrationTree, ProvingJobDataType::InputWitness, 0), 1, QHashOut::from_values(7, 0, 0, 0)))]).await.unwrap_err().to_string().contains("no discovered edge"));
        assert_eq!(sub1_identity.load(Ordering::SeqCst), 1);
        assert_eq!(sub2_identity.load(Ordering::SeqCst), 1);
    }





}
