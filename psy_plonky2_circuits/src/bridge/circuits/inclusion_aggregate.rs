use parth_core::crypto::hash::traits::MerkleZeroHasher;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::{Field, Field64, PrimeField64}},
    hash::{hash_types::{HashOut, HashOutTarget}, poseidon::PoseidonHash},
    iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
    plonk::{circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget}, config::{AlgebraicHasher, GenericConfig, Hasher}, proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget}},
    recursion::dummy_circuit::{dummy_circuit, dummy_proof},
};
use psy_client_data::bridge_aggregate::{Bytes32, Hash4, NetworkConfig, RewardLeaf, WithdrawalLeaf, BRIDGE_USER_ID};
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers};
use psy_plonky2_common_circuits::bridge::{aggregate_commitment::{self as hash, Bytes32Target, Domain, AggregateLeafTarget, RewardLeafTarget, WithdrawalLeafTarget}, aggregate_config::NetworkConfigTarget};
use super::deposit_aggregate::less_words;

type F = GoldilocksField;
pub const AGGREGATE_PI_LEN: usize = 12;
const WITHDRAWAL_ROOT_LEAF: u64 = 0x57524f4f544c;
const WITHDRAWAL_ROOT_EMPTY: u64 = 0x57524f4f5445;
const WITHDRAWAL_ROOT_NODE: u64 = 0x57524f4f544e;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AggregateFamily { Withdrawal = 2, Reward = 3 }

pub enum InclusionAggregateSource<'a, C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    Withdrawal { circuit: &'a CircuitData<F, C, D>, chain_count: usize },
    Reward { circuit: &'a CircuitData<F, C, D>, chain_count: usize },
}

#[derive(Clone, Debug)]
pub struct AggregateWindow {
    pub config_hash: Bytes32,
    pub window_id: Bytes32,
    pub end_id: u64,
    pub end_root: Hash4,
}

#[derive(Clone, Debug)]
pub struct WithdrawalRootPath {
    pub ordinal: u8,
    pub siblings: [Hash4; 8],
}

pub struct WithdrawalAggregateLeaf<'a, C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub leaf: &'a WithdrawalLeaf,
    pub proof: &'a ProofWithPublicInputs<F, C, D>,
    pub path: &'a WithdrawalRootPath,
}

pub struct RewardAggregateLeaf<'a, C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub leaf: &'a RewardLeaf,
    pub proof: &'a ProofWithPublicInputs<F, C, D>,
}

pub enum AggregateLeaves<'a, C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    Withdrawal { leaves: &'a [WithdrawalAggregateLeaf<'a, C, D>], withdrawal_roots: &'a [Hash4] },
    Reward(&'a [RewardAggregateLeaf<'a, C, D>]),
}

impl<C: GenericConfig<D, F = F>, const D: usize> AggregateLeaves<'_, C, D>
where F: Extendable<D> {
    fn family(&self) -> AggregateFamily {
        match self { Self::Withdrawal { .. } => AggregateFamily::Withdrawal, Self::Reward(_) => AggregateFamily::Reward }
    }
    fn len(&self) -> usize {
        match self { Self::Withdrawal { leaves, .. } => leaves.len(), Self::Reward(leaves) => leaves.len() }
    }
}

const AGGREGATE_SLOT_COUNT: usize = 1024;

fn root_node<const D: usize>(builder: &mut CircuitBuilder<F, D>, level: usize, left: HashOutTarget, right: HashOutTarget) -> HashOutTarget
where F: Extendable<D> {
    let mut inputs = vec![builder.constant(F::from_canonical_u64(WITHDRAWAL_ROOT_NODE)), builder.constant(F::from_canonical_usize(level))];
    inputs.extend(left.elements);
    inputs.extend(right.elements);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs)
}

fn withdrawal_root_tree<const D: usize>(builder: &mut CircuitBuilder<F, D>, chains: &[(Target, [Target; 4])]) -> HashOutTarget
where F: Extendable<D> {
    assert!((1..=256).contains(&chains.len()));
    let mut nodes = (0..256).map(|ordinal| {
        let ordinal_target = builder.constant(F::from_canonical_usize(ordinal));
        let inputs = if ordinal < chains.len() {
            let mut inputs = vec![builder.constant(F::from_canonical_u64(WITHDRAWAL_ROOT_LEAF)), ordinal_target, chains[ordinal].0];
            inputs.extend(chains[ordinal].1);
            inputs
        } else { vec![builder.constant(F::from_canonical_u64(WITHDRAWAL_ROOT_EMPTY)), ordinal_target] };
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs)
    }).collect::<Vec<_>>();
    for level in 1..=8 {
        nodes = nodes.chunks_exact(2).map(|pair| root_node(builder, level, pair[0], pair[1])).collect();
    }
    nodes[0]
}

struct WithdrawalRootTarget {
    ordinal: Target,
    siblings: [HashOutTarget; 8],
}

impl WithdrawalRootTarget {
    fn build<const D: usize>(builder: &mut CircuitBuilder<F, D>, active: BoolTarget, chain_count: usize,
        chain_index: Target, withdrawal_root: [Target; 4], tree_root: HashOutTarget) -> Self
    where F: Extendable<D> {
        let ordinal = builder.add_virtual_target();
        let bits = builder.split_le(ordinal, 8);
        let count = builder.constant(F::from_canonical_usize(chain_count));
        let in_range = builder.is_less_than(9, ordinal, count);
        let one = builder.one();
        builder.connect_if_true(active, in_range.target, one);
        let inactive = builder.not(active);
        let zero = builder.zero();
        builder.connect_if_true(inactive, ordinal, zero);
        let mut inputs = vec![builder.constant(F::from_canonical_u64(WITHDRAWAL_ROOT_LEAF)), ordinal, chain_index];
        inputs.extend(withdrawal_root);
        let mut root = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
        let siblings: [HashOutTarget; 8] = std::array::from_fn(|_| builder.add_virtual_hash());
        for (level, sibling) in siblings.iter().enumerate() {
            for target in sibling.elements { builder.connect_if_true(inactive, target, zero); }
            let left = HashOutTarget { elements: std::array::from_fn(|j| builder.select(bits[level], sibling.elements[j], root.elements[j])) };
            let right = HashOutTarget { elements: std::array::from_fn(|j| builder.select(bits[level], root.elements[j], sibling.elements[j])) };
            root = root_node(builder, level + 1, left, right);
        }
        for i in 0..4 { builder.connect_if_true(active, root.elements[i], tree_root.elements[i]); }
        Self { ordinal, siblings }
    }

    fn set_witness(&self, witness: &mut PartialWitness<F>, path: Option<&WithdrawalRootPath>) -> anyhow::Result<()> {
        let empty = WithdrawalRootPath { ordinal: 0, siblings: [[0; 4]; 8] };
        let path = path.unwrap_or(&empty);
        witness.set_target(self.ordinal, F::from_canonical_u8(path.ordinal))?;
        for (target, sibling) in self.siblings.iter().zip(path.siblings) { set_hash4(witness, target.elements, sibling)?; }
        Ok(())
    }
}

pub fn withdrawal_root_paths(config: &NetworkConfig, roots: &[Hash4]) -> anyhow::Result<Vec<WithdrawalRootPath>> {
    config.validate()?;
    anyhow::ensure!(roots.len() == config.chains.len(), "withdrawal root count mismatch");
    let mut nodes = (0..256).map(|ordinal| {
        let mut inputs = if ordinal < roots.len() {
            vec![F::from_canonical_u64(WITHDRAWAL_ROOT_LEAF), F::from_canonical_usize(ordinal), F::from_canonical_u8(config.chains[ordinal].chain_index)]
        } else { vec![F::from_canonical_u64(WITHDRAWAL_ROOT_EMPTY), F::from_canonical_usize(ordinal)] };
        if ordinal < roots.len() {
            for value in roots[ordinal] {
                anyhow::ensure!(value < F::ORDER, "noncanonical withdrawal root");
                inputs.push(F::from_canonical_u64(value));
            }
        }
        Ok(PoseidonHash::hash_no_pad(&inputs))
    }).collect::<anyhow::Result<Vec<_>>>()?;
    let mut paths = (0..roots.len()).map(|ordinal| WithdrawalRootPath { ordinal: ordinal as u8, siblings: [[0; 4]; 8] }).collect::<Vec<_>>();
    for level in 0..8 {
        for (ordinal, path) in paths.iter_mut().enumerate() {
            path.siblings[level] = nodes[(ordinal >> level) ^ 1].elements.map(|value| value.to_canonical_u64());
        }
        nodes = nodes.chunks_exact(2).map(|pair| {
            let mut inputs = vec![F::from_canonical_u64(WITHDRAWAL_ROOT_NODE), F::from_canonical_usize(level + 1)];
            inputs.extend(pair[0].elements);
            inputs.extend(pair[1].elements);
            PoseidonHash::hash_no_pad(&inputs)
        }).collect();
    }
    Ok(paths)
}

pub struct InclusionAggregateCircuit<C: GenericConfig<D, F = F>, const D: usize>
where F: Extendable<D> {
    pub family: AggregateFamily,
    pub circuit_data: CircuitData<F, C, D>,
    config: NetworkConfigTarget,
    config_hash: Bytes32Target,
    window_id: Bytes32Target,
    end_id: [Target; 2],
    end_root: [Target; 4],
    count: Target,
    leaf_words: Vec<Vec<Target>>,
    proofs: Vec<ProofWithPublicInputsTarget<D>>,
    paths: Vec<WithdrawalRootTarget>,
    withdrawal_roots: Vec<[Target; 4]>,
    dummy: CircuitData<F, C, D>,
}

fn leaf_target<const D: usize>(builder: &mut CircuitBuilder<F, D>, family: AggregateFamily) -> AggregateLeafTarget
where F: Extendable<D> {
    match family {
        AggregateFamily::Withdrawal => AggregateLeafTarget::Withdrawal(WithdrawalLeafTarget {
            chain_index: builder.add_virtual_target(), sender_user_id: builder.add_virtual_target(), recipient: builder.add_virtual_target_arr(), token: builder.add_virtual_target_arr(), amount: builder.add_virtual_target_arr(), nonce: builder.add_virtual_target_arr(),
        }),
        AggregateFamily::Reward => AggregateLeafTarget::Reward(RewardLeafTarget {
            claim_checkpoint_id: builder.add_virtual_target_arr(), user_id: builder.add_virtual_target(), height: builder.add_virtual_target(), path_index: builder.add_virtual_target(), nullifier_index: builder.add_virtual_target(), recipient: builder.add_virtual_target_arr(),
        }),
    }
}

fn leaf_key(leaf: AggregateLeafTarget) -> Vec<Target> {
    match leaf {
        AggregateLeafTarget::Withdrawal(leaf) => { let mut key = vec![leaf.chain_index]; key.extend(leaf.nonce); key },
        AggregateLeafTarget::Reward(leaf) => vec![leaf.claim_checkpoint_id[1], leaf.claim_checkpoint_id[0], leaf.nullifier_index],
        AggregateLeafTarget::Deposit(_) => unreachable!(),
    }
}
struct AggregateSlot<const D: usize> {
    leaf: AggregateLeafTarget,
    words: Vec<Target>,
    proof: ProofWithPublicInputsTarget<D>,
    path: Option<WithdrawalRootTarget>,
}

fn constrain_aggregate_slot<C: GenericConfig<D, F = F>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, family: AggregateFamily, index: usize, count: Target, zero: Target, one: Target,
    previous: Option<AggregateLeafTarget>, child: &CircuitData<F, C, D>, real_vk: &VerifierCircuitTarget,
    dummy_vk: &VerifierCircuitTarget, config_hash: Bytes32Target, end_id: [Target; 2], end_root: [Target; 4],
    chain_count: usize, tree_root: Option<HashOutTarget>,
) -> AggregateSlot<D>
where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> {
    let slot = builder.constant(F::from_canonical_usize(index));
    let active = builder.is_less_than(11, slot, count);
    let inactive = builder.not(active);
    let leaf = leaf_target(builder, family);
    let words = leaf.encode(builder);
    for &word in &words { builder.connect_if_true(inactive, word, zero); }
    if let Some(previous) = previous {
        let increasing = less_words(builder, &leaf_key(previous), &leaf_key(leaf));
        builder.connect_if_true(active, increasing.target, one);
    }
    let proof = builder.add_virtual_proof_with_pis(&child.common);
    builder.conditionally_verify_proof::<C>(active, &proof, real_vk, &proof, dummy_vk, &child.common);
    let pi = &proof.public_inputs;
    for &word in pi { builder.connect_if_true(inactive, word, zero); }
    for (target, value) in pi[..4].iter().zip([1, family as u8, 0, 0]) {
        let expected = builder.constant(F::from_canonical_u8(value));
        builder.connect_if_true(active, *target, expected);
    }
    for (left, right) in pi[4..18].iter().zip(config_hash.iter().chain(&end_id).chain(&end_root)) { builder.connect_if_true(active, *left, *right); }
    let commit = leaf.leaf_commit(builder);
    let commit_start = if family == AggregateFamily::Withdrawal { 24 } else { 18 };
    for j in 0..8 { builder.connect_if_true(active, pi[commit_start + j], commit[j]); }
    let path = match leaf {
        AggregateLeafTarget::Withdrawal(leaf) => {
            let bridge_user = builder.constant(F::from_canonical_u32(BRIDGE_USER_ID));
            builder.connect_if_true(active, pi[18], bridge_user);
            builder.connect_if_true(active, pi[19], leaf.chain_index);
            Some(WithdrawalRootTarget::build(builder, active, chain_count, leaf.chain_index, pi[20..24].try_into().unwrap(), tree_root.unwrap()))
        }
        AggregateLeafTarget::Reward(leaf) => {
            for j in 0..2 { builder.connect_if_true(active, pi[26 + j], leaf.claim_checkpoint_id[j]); }
            None
        }
        AggregateLeafTarget::Deposit(_) => unreachable!(),
    };
    AggregateSlot { leaf, words, proof, path }
}

impl<C: GenericConfig<D, F = F>, const D: usize> InclusionAggregateCircuit<C, D>
where F: Extendable<D>, C::Hasher: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>> {
    pub fn new(source: InclusionAggregateSource<'_, C, D>) -> Self {
        let (family, child, chain_count) = match &source {
            InclusionAggregateSource::Withdrawal { circuit, chain_count, .. } => (AggregateFamily::Withdrawal, *circuit, *chain_count),
            InclusionAggregateSource::Reward { circuit, chain_count } => (AggregateFamily::Reward, *circuit, *chain_count),
        };
        assert!((1..=256).contains(&chain_count));
        assert_eq!(child.common.num_public_inputs, if family == AggregateFamily::Withdrawal { 32 } else { 28 });
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let zero = builder.zero();
        let one = builder.one();
        let config = NetworkConfigTarget::new(&mut builder, chain_count);
        let config_hash = config.hash(&mut builder);
        let window_id = builder.add_virtual_target_arr();
        for word in window_id { builder.range_check(word, 32); }
        let end_id = builder.add_virtual_target_arr();
        builder.range_check(end_id[0], 32);
        builder.assert_zero(end_id[1]);
        let end_root = builder.add_virtual_target_arr();
        hash::encode_hash4(&mut builder, end_root);
        let withdrawal_roots = if family == AggregateFamily::Withdrawal {
            (0..chain_count).map(|_| builder.add_virtual_target_arr()).collect::<Vec<_>>()
        } else { Vec::new() };
        let tree_root = if family == AggregateFamily::Withdrawal {
            let chains = config.chains.iter().zip(&withdrawal_roots).map(|(chain, &root)| (chain.chain_index, root)).collect::<Vec<_>>();
            Some(withdrawal_root_tree(&mut builder, &chains))
        } else { None };
        let count = builder.add_virtual_target();
        builder.range_check(count, 11);
        let limit = builder.constant(F::from_canonical_u32(1024));
        builder.ensure_is_less_than_or_equal(11, count, limit);
        let dummy = dummy_circuit::<F, C, D>(&child.common);
        assert_eq!(dummy.common, child.common);
        let real_vk = builder.constant_verifier_data(&child.verifier_only);
        let dummy_vk = builder.constant_verifier_data(&dummy.verifier_only);
        let mut leaves = Vec::with_capacity(AGGREGATE_SLOT_COUNT);
        let mut leaf_words = Vec::with_capacity(AGGREGATE_SLOT_COUNT);
        let mut proofs = Vec::with_capacity(AGGREGATE_SLOT_COUNT);
        let mut paths = Vec::new();
        for index in 0..AGGREGATE_SLOT_COUNT {
            let slot = constrain_aggregate_slot::<C, D>(&mut builder, family, index, count, zero, one, leaves.last().copied(), child,
                &real_vk, &dummy_vk, config_hash, end_id, end_root, chain_count, tree_root);
            leaves.push(slot.leaf);
            leaf_words.push(slot.words);
            proofs.push(slot.proof);
            if let Some(path) = slot.path { paths.push(path); }
        }
        let maximum = if family == AggregateFamily::Withdrawal { config.max_withdrawals } else { config.max_rewards };
        builder.ensure_is_less_than_or_equal(32, count, maximum);
        let mut body = config_hash.to_vec();
        body.extend(window_id);
        body.extend(hash::word_u64(&mut builder, end_id));
        body.extend(hash::encode_hash4(&mut builder, end_root));
        if family == AggregateFamily::Withdrawal {
            let chains = builder.constant(F::from_canonical_usize(chain_count));
            body.extend(hash::word(&mut builder, chains, 32));
            for &root in &withdrawal_roots { body.extend(hash::encode_hash4(&mut builder, root)); }
        }
        body.extend(hash::word(&mut builder, count, 32));
        let domain = if family == AggregateFamily::Withdrawal { Domain::WithdrawalAggregate } else { Domain::RewardAggregate };
        let opening_digest = hash::prefix_commitment(&mut builder, domain, &body, &leaf_words, count, 0);
        let prefix = [1, 7, family as u32, 0].map(|value| builder.constant(F::from_canonical_u32(value)));
        builder.register_public_inputs(&prefix);
        builder.register_public_inputs(&opening_digest);
        let circuit_data = builder.build::<C>();
        Self { family, circuit_data, config, config_hash, window_id, end_id, end_root, count, leaf_words, proofs, paths, withdrawal_roots, dummy }
    }

    pub fn set_witness(&self, witness: &mut PartialWitness<F>, config: &NetworkConfig, window: &AggregateWindow, leaves: &AggregateLeaves<'_, C, D>) -> anyhow::Result<()> {
        anyhow::ensure!(leaves.family() == self.family && leaves.len() <= 1024, "aggregate leaf family/count mismatch");
        anyhow::ensure!(config.config_hash()? == window.config_hash, "aggregate configuration mismatch");
        anyhow::ensure!(window.end_id <= u32::MAX as u64, "checkpoint index exceeds tree height");
        self.config.set_witness(witness, config)?;
        set_bytes(witness, &self.config_hash, &window.config_hash)?;
        set_bytes(witness, &self.window_id, &window.window_id)?;
        witness.set_target(self.end_id[0], F::from_canonical_u32(window.end_id as u32))?;
        witness.set_target(self.end_id[1], F::ZERO)?;
        set_hash4(witness, self.end_root, window.end_root)?;
        witness.set_target(self.count, F::from_canonical_usize(leaves.len()))?;
        if let AggregateLeaves::Withdrawal { withdrawal_roots, .. } = leaves {
            anyhow::ensure!(withdrawal_roots.len() == self.withdrawal_roots.len(), "withdrawal root count mismatch");
            for (&target, &root) in self.withdrawal_roots.iter().zip(*withdrawal_roots) { set_hash4(witness, target, root)?; }
        }
        let dummy = dummy_proof(&self.dummy, Default::default())?;
        for i in 0..1024 {
            if i < leaves.len() {
                match leaves {
                    AggregateLeaves::Withdrawal { leaves, .. } => {
                        set_bytes(witness, &self.leaf_words[i], &leaves[i].leaf.encode()?)?;
                        witness.set_proof_with_pis_target(&self.proofs[i], leaves[i].proof)?;
                        self.paths[i].set_witness(witness, Some(leaves[i].path))?;
                    }
                    AggregateLeaves::Reward(leaves) => {
                        set_bytes(witness, &self.leaf_words[i], &leaves[i].leaf.encode()?)?;
                        witness.set_proof_with_pis_target(&self.proofs[i], leaves[i].proof)?;
                    }
                }
            } else {
                for &word in &self.leaf_words[i] { witness.set_target(word, F::ZERO)?; }
                witness.set_proof_with_pis_target(&self.proofs[i], &dummy)?;
                if self.family == AggregateFamily::Withdrawal { self.paths[i].set_witness(witness, None)?; }
            }
        }
        Ok(())
    }

    pub fn prove(&self, config: &NetworkConfig, window: &AggregateWindow, leaves: &AggregateLeaves<'_, C, D>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut witness = PartialWitness::new();
        self.set_witness(&mut witness, config, window, leaves)?;
        self.circuit_data.prove(witness)
    }
}

pub(crate) fn set_bytes(witness: &mut PartialWitness<F>, targets: &[Target], bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(bytes.len() == targets.len() * 4, "byte/target width mismatch");
    for (target, bytes) in targets.iter().zip(bytes.chunks_exact(4)) {
        witness.set_target(*target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into()?)))?;
    }
    Ok(())
}

fn set_hash4(witness: &mut PartialWitness<F>, targets: [Target; 4], value: Hash4) -> anyhow::Result<()> {
    for (target, value) in targets.into_iter().zip(value) {
        anyhow::ensure!(value < F::ORDER, "noncanonical Goldilocks root");
        witness.set_target(target, F::from_canonical_u64(value))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use psy_client_data::bridge_aggregate::ChainConfig;

    fn config(indices: &[u8]) -> NetworkConfig {
        NetworkConfig {
            version: 1, network_magic: 0, bridge_user_id: 524288, circuit_set_hash: [7; 32],
            chains: indices.iter().enumerate().map(|(ordinal, &chain_index)| ChainConfig { chain_index, chain_id: [(ordinal + 1) as u8; 32], bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: [1, 2, 3, 4] }).collect(),
            ethereum_index: indices[0], reward_payer: [3; 20], reward_token: [4; 20], reward_per_claim: [1; 32], reward_token_decimals: 0, reward_cutover: 0, reward_end_exclusive: 100, max_deposits: 1024, max_withdrawals: 1024, max_rewards: 1024,
        }
    }

    #[test]
    fn withdrawal_lookup_rejects_wrong_row_root_ordinal_and_sibling() {
        let config = config(&[0, 3, 4, 255]);
        let roots = [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12], [13, 14, 15, 16]];
        let paths = withdrawal_root_paths(&config, &roots).unwrap();
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let chains = config.chains.iter().zip(roots).map(|(chain, root)| {
            (builder.constant(F::from_canonical_u8(chain.chain_index)), root.map(|value| builder.constant(F::from_canonical_u64(value))))
        }).collect::<Vec<_>>();
        let tree = withdrawal_root_tree(&mut builder, &chains);
        let active = builder.add_virtual_bool_target_safe();
        let chain = builder.add_virtual_target();
        let root = builder.add_virtual_target_arr();
        let path = WithdrawalRootTarget::build(&mut builder, active, chains.len(), chain, root, tree);
        let data = builder.build::<PoseidonGoldilocksConfig>();
        for selected in 0..4 {
            for mutation in 0..6 {
                let mut witness = PartialWitness::new();
                witness.set_bool_target(active, true).unwrap();
                witness.set_target(chain, F::from_canonical_u8(if mutation == 1 { 2 } else { config.chains[selected].chain_index })).unwrap();
                let mut supplied_root = roots[selected];
                if mutation == 2 { supplied_root[0] += 1; }
                set_hash4(&mut witness, root, supplied_root).unwrap();
                let mut supplied_path = paths[selected].clone();
                if mutation == 3 { supplied_path.ordinal = ((selected + 1) % 4) as u8; }
                if mutation == 4 { supplied_path.siblings[0][0] += 1; }
                if mutation == 5 { supplied_path.ordinal = 4; }
                path.set_witness(&mut witness, Some(&supplied_path)).unwrap();
                let result = data.prove(witness);
                if mutation == 0 { data.verify(result.unwrap()).unwrap(); }
                else { assert!(result.is_err(), "accepted lookup mutation {mutation}"); }
            }
        }
        for nonzero_padding in [false, true] {
            let mut witness = PartialWitness::new();
            witness.set_bool_target(active, false).unwrap();
            witness.set_target(chain, F::ZERO).unwrap();
            set_hash4(&mut witness, root, [0; 4]).unwrap();
            let mut padding = WithdrawalRootPath { ordinal: 0, siblings: [[0; 4]; 8] };
            if nonzero_padding { padding.siblings[7][3] = 1; }
            path.set_witness(&mut witness, Some(&padding)).unwrap();
            let result = data.prove(witness);
            if nonzero_padding { assert!(result.is_err()); }
            else { data.verify(result.unwrap()).unwrap(); }
        }
    }

    fn reward_proof(child: &CircuitData<F, PoseidonGoldilocksConfig, 2>, targets: &[Target], config: &NetworkConfig,
        window: &AggregateWindow, leaf: &RewardLeaf) -> ProofWithPublicInputs<F, PoseidonGoldilocksConfig, 2> {
        let mut witness = PartialWitness::new();
        for (target, value) in targets[..4].iter().zip([1, 3, 0, 0]) { witness.set_target(*target, F::from_canonical_u32(value)).unwrap(); }
        set_bytes(&mut witness, &targets[4..12], &config.config_hash().unwrap()).unwrap();
        witness.set_target(targets[12], F::from_canonical_u32(window.end_id as u32)).unwrap();
        witness.set_target(targets[13], F::ZERO).unwrap();
        set_hash4(&mut witness, targets[14..18].try_into().unwrap(), window.end_root).unwrap();
        set_bytes(&mut witness, &targets[18..26], &leaf.leaf_commit().unwrap()).unwrap();
        witness.set_target(targets[26], F::from_canonical_u32(leaf.claim_checkpoint_id as u32)).unwrap();
        witness.set_target(targets[27], F::ZERO).unwrap();
        child.prove(witness).unwrap()
    }

    #[test]
    fn flat_reward_capacity_order_padding_and_child_binding() {
        let config = config(&[0]);
        let window = AggregateWindow { config_hash: config.config_hash().unwrap(), window_id: [5; 32], end_id: 7, end_root: [1, 2, 3, 4] };
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let targets = builder.add_virtual_targets(28);
        builder.register_public_inputs(&targets);
        let child = builder.build::<PoseidonGoldilocksConfig>();
        let aggregate = InclusionAggregateCircuit::new(InclusionAggregateSource::Reward { circuit: &child, chain_count: 1 });
        let leaves = (0..1024).map(|i| RewardLeaf { claim_checkpoint_id: 7, user_id: 1000, height: 12,
            path_index: i, nullifier_index: 4095 + i, recipient: [1; 20] }).collect::<Vec<_>>();
        let proofs = leaves.iter().map(|leaf| reward_proof(&child, &targets, &config, &window, leaf)).collect::<Vec<_>>();
        let aggregate_leaves = leaves.iter().zip(&proofs).map(|(leaf, proof)| RewardAggregateLeaf { leaf, proof }).collect::<Vec<_>>();
        for count in [0, 1, 6, 7, 8, 23, 24, 25, 31, 32, 33, 1023, 1024] {
            let proof = aggregate.prove(&config, &window, &AggregateLeaves::Reward(&aggregate_leaves[..count])).unwrap();
            let opening = psy_client_data::bridge_aggregate::RewardAggregateOpening { config_hash: window.config_hash, window_id: window.window_id,
                end_checkpoint_id: window.end_id, end_checkpoint_root: window.end_root, rewards: leaves[..count].to_vec() };
            let digest = opening.opening_digest(&config).unwrap();
            use tiny_keccak::{Hasher as _, Keccak};
            let mut domain = [0; 32];
            let mut keccak = Keccak::v256();
            keccak.update(b"PsyBridge/TwoArtifact/1/RewardBatch");
            keccak.finalize(&mut domain);
            let encoded = opening.encode().unwrap();
            assert_eq!(encoded.len(), 256 + 192 * count);
            let mut keccak = Keccak::v256();
            keccak.update(&domain);
            keccak.update(&encoded);
            let mut flat_digest = [0; 32];
            keccak.finalize(&mut flat_digest);
            assert_eq!(digest, flat_digest);
            let mut expected = vec![F::ONE, F::from_canonical_u32(7), F::from_canonical_u32(3), F::ZERO];
            expected.extend(digest.chunks_exact(4).map(|bytes| F::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap()))));
            assert_eq!(proof.public_inputs, expected);
            aggregate.circuit_data.verify(proof).unwrap();
        }
        for mutation in 0..9 {
            let mut witness = PartialWitness::new();
            aggregate.set_witness(&mut witness, &config, &window, &AggregateLeaves::Reward(&aggregate_leaves[..33])).unwrap();
            match mutation {
                0 => { witness.target_values.insert(aggregate.count, F::from_canonical_u32(1025)); }
                1 => { witness.target_values.insert(aggregate.leaf_words[33][7], F::ONE); }
                2 => { witness.target_values.insert(aggregate.proofs[33].public_inputs[0], F::ONE); }
                3 => { witness.target_values.insert(aggregate.proofs[0].public_inputs[18], F::ZERO); }
                4 => { witness.target_values.insert(aggregate.proofs[0].public_inputs[1], F::from_canonical_u32(2)); }
                6 => { witness.target_values.insert(aggregate.end_id[0], F::from_canonical_u32(8)); }
                7 => { witness.target_values.insert(aggregate.end_root[0], F::from_canonical_u32(9)); }
                8 => { witness.target_values.insert(aggregate.config_hash[0], F::ZERO); }
                _ => {
                    let dummy = dummy_proof(&aggregate.dummy, Default::default()).unwrap();
                    let mut changed = PartialWitness::new();
                    changed.set_proof_with_pis_target(&aggregate.proofs[0], &dummy).unwrap();
                    witness.target_values.extend(changed.target_values);
                }
            }
            assert!(aggregate.circuit_data.prove(witness).is_err(), "accepted flat mutation {mutation}");
        }
        for duplicate in [false, true] {
            let mut order = (0..33).collect::<Vec<_>>();
            if duplicate { order[32] = 31; } else { order.swap(31, 32); }
            let reordered = order.iter().map(|&i| RewardAggregateLeaf { leaf: &leaves[i], proof: &proofs[i] }).collect::<Vec<_>>();
            assert!(aggregate.prove(&config, &window, &AggregateLeaves::Reward(&reordered)).is_err());
        }
        let mut limited = config.clone();
        limited.max_rewards = 32;
        let limited_window = AggregateWindow { config_hash: limited.config_hash().unwrap(), ..window.clone() };
        let limited_proofs = leaves[..33].iter().map(|leaf| reward_proof(&child, &targets, &limited, &limited_window, leaf)).collect::<Vec<_>>();
        let limited_leaves = leaves[..33].iter().zip(&limited_proofs).map(|(leaf, proof)| RewardAggregateLeaf { leaf, proof }).collect::<Vec<_>>();
        assert!(aggregate.prove(&limited, &limited_window, &AggregateLeaves::Reward(&limited_leaves)).is_err());
        let changed_window = AggregateWindow { window_id: [9; 32], ..window.clone() };
        let original = aggregate.prove(&config, &window, &AggregateLeaves::Reward(&aggregate_leaves[..1])).unwrap();
        let changed = aggregate.prove(&config, &changed_window, &AggregateLeaves::Reward(&aggregate_leaves[..1])).unwrap();
        assert_ne!(original.public_inputs[4..], changed.public_inputs[4..]);
        aggregate.circuit_data.verify(changed).unwrap();
    }
}
