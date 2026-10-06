use std::collections::BTreeMap;
use k256::ecdsa::VerifyingKey;
use plonky2::{field::{goldilocks_field::GoldilocksField as F, types::Field, secp256k1_base::Secp256K1Base, secp256k1_scalar::Secp256K1Scalar}, gates::{gate::GateRef, noop::NoopGate}, hash::{hash_types::HashOutTarget, poseidon::PoseidonHash}, iop::{target::{Target, BoolTarget}, witness::{PartialWitness, WitnessWrite}}, plonk::{circuit_builder::CircuitBuilder, circuit_data::CircuitData, config::PoseidonGoldilocksConfig as C}};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{bridge_aggregate::{Hash4, RewardLeaf}, config::store_config::PsyProof, qdata::{checkpoint::{PsyCheckpointLeaf, PsyCheckpointGlobalStateRoots}, user::PsyUserLeaf}};
use psy_common_circuit::{builder::{hash::core::CircuitBuilderHashCore, comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers}, circuits::{traits::qstandard::QStandardCircuit, zk_signature3::core::PsyBasicZKSignatureCircuit, secp256k1_signature::{Secp256K1SignatureCircuit, EthPersonalSignSecp256K1SignatureCircuit}}, crypto::secp256k1::{gadget::Secp256K1Gadget, ecdsa::gadgets::biguint::{BigUintTarget, CircuitBuilderBiguint}}, traits::CreatableTarget, u32::arithmetic_u32::U32Target};
use psy_config::network_constants::{CHECKPOINT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT};
use psy_network_circuit::gadgets::qdata::{checkpoint::PsyCheckpointLeafGadget, checkpoint_state_roots::PsyCheckpointGlobalStateRootsGadget, user::PsyUserLeafGadget};
use psy_plonky2_common_circuits::{bridge::aggregate_commitment::{self as encoding, RewardLeafTarget, AggregateLeafTarget}, hash::keccak::keccak256_u32_words_be_abi};
use psy_vm::{reward_authorization::RewardAuthorizationWitness, ups::multisig::MultisigPolicy};
use super::{multisig::MultisigSignatureCircuit, software_defined::get_zk_public_key_param};

#[derive(Clone)]
pub struct RewardAuthorizationContext {
    pub config_hash: [u8; 32],
    pub end_checkpoint_id: u64,
    pub end_checkpoint_root: Hash4,
    pub reward: RewardLeaf,
    pub claim_checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub claim_checkpoint_path: Vec<QHashOut<F>>,
    pub end_checkpoint_leaf: PsyCheckpointLeaf<F>,
    pub end_checkpoint_path: Vec<QHashOut<F>>,
    pub end_global_state_roots: PsyCheckpointGlobalStateRoots<F>,
    pub authorization_user_leaf: PsyUserLeaf<F>,
    pub authorization_user_path: Vec<QHashOut<F>>,
}

impl RewardAuthorizationContext {
    pub fn message(&self) -> anyhow::Result<[u8; 32]> {
        use plonky2::field::types::PrimeField64;
        use psy_crypto::hash::traits::qhashable::QFieldHashable;
        let limbs = |hash: QHashOut<F>| hash.0.elements.map(|v| v.to_canonical_u64());
        psy_vm::reward_authorization::build_reward_authorization_message(self.config_hash, self.end_checkpoint_id, self.end_checkpoint_root, limbs(self.end_checkpoint_leaf.qfhash::<PoseidonHash>()), limbs(self.authorization_user_leaf.qfhash::<PoseidonHash>()), limbs(self.claim_checkpoint_leaf.qfhash::<PoseidonHash>()), &self.reward)
    }
}

#[derive(Clone)]
pub struct RewardAuthorizationInput {
    pub context: RewardAuthorizationContext,
    pub authorization: RewardAuthorizationWitness,
}

pub fn build_reward_authorization_message_target(builder: &mut CircuitBuilder<F, 2>, config_hash: [Target; 8], end_id: [Target; 2], end_root: [Target; 4], end_leaf_hash: [Target; 4], user_hash: [Target; 4], claim_hash: [Target; 4], reward: &RewardLeafTarget) -> [Target; 8] {
    let mut words = encoding::constant_bytes32(builder, psy_vm::reward_authorization::reward_authorization_domain()).to_vec();
    words.extend(config_hash);
    words.extend(encoding::word_u64(builder, end_id));
    for hash in [end_root, end_leaf_hash, user_hash, claim_hash] { words.extend(encoding::encode_hash4(builder, hash)); }
    words.extend(AggregateLeafTarget::Reward(*reward).encode(builder));
    for &word in &words { builder.range_check(word, 32); }
    keccak256_u32_words_be_abi(builder, &words).map(|v| v.0)
}


fn canonical_bits(builder: &mut CircuitBuilder<F, 2>, value: Target) -> Vec<BoolTarget> {
    let bits = builder.split_le(value, 64);
    let limbs = BigUintTarget { limbs: bits.chunks_exact(32).map(|bits| U32Target(builder.le_sum(bits.iter()))).collect() };
    let maximum = builder.constant_biguint(&(F::order() - 1u32));
    let valid = builder.cmp_biguint(&limbs, &maximum); builder.assert_one(valid.target); bits
}

fn less_bits(builder: &mut CircuitBuilder<F, 2>, a: &[BoolTarget], b: &[BoolTarget]) -> BoolTarget {
    let mut less = builder._false();
    for (&a, &b) in a.iter().zip(b) {
        let equal = builder.is_equal(a.target, b.target);
        let not_a = builder.not(a); let bit_less = builder.and(not_a, b);
        let lower = builder.and(equal, less); less = builder.or(bit_less, lower);
    }
    less
}

fn path(builder: &mut CircuitBuilder<F, 2>, leaf: HashOutTarget, index: Target, height: u8) -> (HashOutTarget, Vec<HashOutTarget>) {
    let bits = builder.split_le(index, height as usize);
    let siblings: Vec<_> = (0..height).map(|_| builder.add_virtual_hash()).collect();
    let mut root = leaf;
    for (&bit, &sibling) in bits.iter().zip(&siblings) {
        let left = HashOutTarget { elements: core::array::from_fn(|i| builder.select(bit, sibling.elements[i], root.elements[i])) };
        let right = HashOutTarget { elements: core::array::from_fn(|i| builder.select(bit, root.elements[i], sibling.elements[i])) };
        root = builder.hash_two_to_one::<PoseidonHash>(left, right);
    }
    (root, siblings)
}

pub fn constrain_signature(builder: &mut CircuitBuilder<F, 2>, signature: &Secp256K1Gadget) {
    let coordinate_maximum = builder.constant_biguint(&(Secp256K1Base::order() - 1u32));
    let scalar_maximum = builder.constant_biguint(&(Secp256K1Scalar::order() - 1u32));
    let low_s_maximum = builder.constant_biguint(&(Secp256K1Scalar::order() >> 1usize));
    let zero = builder.zero_biguint();
    for coordinate in [&signature.public_key_x_target, &signature.public_key_y_target] {
        for limb in &coordinate.limbs { builder.range_check(limb.0, 32); }
        let valid = builder.cmp_biguint(coordinate, &coordinate_maximum); builder.assert_one(valid.target);
    }
    for scalar in [&signature.signature_r_target, &signature.signature_s_target] {
        for limb in &scalar.limbs { builder.range_check(limb.0, 32); }
        let valid = builder.cmp_biguint(scalar, &scalar_maximum); builder.assert_one(valid.target);
        let zero = builder.is_equal_biguint(scalar, &zero); builder.assert_zero(zero.target);
    }
    let low_s = builder.cmp_biguint(&signature.signature_s_target, &low_s_maximum); builder.assert_one(low_s.target);
}

pub struct PolicyTarget { pub version: Target, pub members: [HashOutTarget; 3], pub commitment: HashOutTarget }
impl PolicyTarget {
    pub fn new(builder: &mut CircuitBuilder<F, 2>, slots: [HashOutTarget; 4]) -> Self {
        let version = slots[0].elements[0]; builder.range_check(version, 32); builder.assert_non_zero(version);
        let two = builder.constant(F::from_canonical_u8(2)); let three = builder.constant(F::from_canonical_u8(3));
        builder.connect(slots[0].elements[1], two); builder.connect(slots[0].elements[2], three); builder.assert_zero(slots[0].elements[3]);
        let members = [slots[1], slots[2], slots[3]];
        let mut previous: Option<Vec<BoolTarget>> = None;
        for member in members {
            let zero = builder.is_zero_hash(member); builder.assert_zero(zero.target);
            let bits: Vec<_> = member.elements.iter().rev().flat_map(|&v| canonical_bits(builder, v)).collect();
            if let Some(previous) = previous { let ordered = less_bits(builder, &previous, &bits); builder.assert_one(ordered.target); }
            previous = Some(bits);
        }
        let domain = builder.constant(F::from_canonical_u32(0x4d534750)); let capacity = builder.constant(F::from_canonical_u8(8));
        let mut fields = vec![domain, version, two, three, capacity];
        fields.extend(members.iter().flat_map(|member| member.elements));
        fields.extend([builder.zero(); 20]);
        let commitment = builder.hash_n_to_hash_no_pad::<PoseidonHash>(fields);
        let zero = builder.is_zero_hash(commitment); builder.assert_zero(zero.target);
        Self { version, members, commitment }
    }
}

struct AuthorizationTargets {
    config: [Target; 8], end_id: [Target; 2], end_root: HashOutTarget, reward: RewardLeafTarget,
    claim: PsyCheckpointLeafGadget, end: PsyCheckpointLeafGadget, roots: PsyCheckpointGlobalStateRootsGadget, user: PsyUserLeafGadget,
    claim_path: Vec<HashOutTarget>, end_path: Vec<HashOutTarget>, user_path: Vec<HashOutTarget>,
    private_key: Option<HashOutTarget>, signatures: Vec<Secp256K1Gadget>,
    initial_slots: Option<[HashOutTarget; 4]>, policy_slots: Option<[HashOutTarget; 4]>,
    contract_paths: Vec<Vec<HashOutTarget>>, slot_paths: Vec<Vec<HashOutTarget>>, indices: Option<[Target; 2]>,
}

fn build(variant: u8, identity: QHashOut<F>, gates: &[GateRef<F, 2>], degree: usize) -> (AuthorizationTargets, CircuitData<F, C, 2>) {
    let mut builder = CircuitBuilder::<F, 2>::new(plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config());
    let config = builder.add_virtual_target_arr(); let end_id: [Target; 2] = builder.add_virtual_target_arr(); let end_root = builder.add_virtual_hash();
    for &target in config.iter().chain(&end_id) { builder.range_check(target, 32); }
    builder.assert_zero(end_id[1]);
    let reward = RewardLeafTarget { claim_checkpoint_id: builder.add_virtual_target_arr(), user_id: builder.add_virtual_target(), height: builder.add_virtual_target(), path_index: builder.add_virtual_target(), nullifier_index: builder.add_virtual_target(), recipient: builder.add_virtual_target_arr() };
    builder.assert_zero(reward.claim_checkpoint_id[1]);
    let claim = PsyCheckpointLeafGadget::create_virtual(&mut builder); let end = PsyCheckpointLeafGadget::create_virtual(&mut builder);
    let roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(&mut builder); let user = PsyUserLeafGadget::create_virtual(&mut builder);
    let claim_hash = claim.to_hash::<PoseidonHash, F, 2>(&mut builder); let end_hash = end.to_hash::<PoseidonHash, F, 2>(&mut builder); let user_hash = user.to_hash::<PoseidonHash, F, 2>(&mut builder);
    let (claim_root, claim_path) = path(&mut builder, claim_hash, reward.claim_checkpoint_id[0], CHECKPOINT_TREE_HEIGHT);
    let (end_tree_root, end_path) = path(&mut builder, end_hash, end_id[0], CHECKPOINT_TREE_HEIGHT);
    builder.connect_hashes(claim_root, end_root); builder.connect_hashes(end_tree_root, end_root);
    let global_hash = roots.to_hash::<PoseidonHash, F, 2>(&mut builder); builder.connect_hashes(global_hash, end.global_chain_root);
    builder.connect(user.user_id, reward.user_id);
    let (user_root, user_path) = path(&mut builder, user_hash, reward.user_id, GLOBAL_USER_TREE_HEIGHT); builder.connect_hashes(user_root, roots.user_tree_root);
    builder.range_check(user.last_checkpoint_id, 32);
    let too_new = builder.is_less_than(32, end_id[0], user.last_checkpoint_id); builder.assert_zero(too_new.target);
    let claim_too_new = builder.is_less_than(32, end_id[0], reward.claim_checkpoint_id[0]); builder.assert_zero(claim_too_new.target);
    let message = build_reward_authorization_message_target(&mut builder, config, end_id, end_root.elements, end_hash.elements, user_hash.elements, claim_hash.elements, &reward);
    let mut message_bytes = Vec::with_capacity(32);
    for word in message { let bits = builder.split_le(word, 32); for byte in (0..4).rev() { message_bytes.push(builder.le_sum(bits[byte * 8..byte * 8 + 8].iter())); } }
    let mut private_key = None; let mut signatures = Vec::new(); let mut initial_slots = None; let mut policy_slots = None; let mut contract_paths = Vec::new(); let mut slot_paths = Vec::new(); let mut indices = None;
    let param = match variant {
        0 => {
            let key = builder.add_virtual_hash(); private_key = Some(key);
            let param = get_zk_public_key_param::<C, 2>(&mut builder, &key);
            param
        },
        1 | 2 | 3 => {
            for _ in 0..if variant == 3 { 2 } else { 1 } {
                let signature = if variant == 2 { Secp256K1Gadget::add_virtual_to_eth_personal_sign::<PoseidonHash, F, 2>(&mut builder) } else { Secp256K1Gadget::add_virtual_to::<PoseidonHash, F, 2>(&mut builder, b"") };
                constrain_signature(&mut builder, &signature);
                for (&target, &byte) in signature.msg_bytes_target.iter().zip(&message_bytes) { builder.range_check(target, 8); builder.connect(target, byte); }
                signatures.push(signature);
            }
            if variant != 3 { signatures[0].public_key_hash } else {
                let initial: [HashOutTarget; 4] = core::array::from_fn(|_| builder.add_virtual_hash());
                let stored: [HashOutTarget; 4] = core::array::from_fn(|_| builder.add_virtual_hash());
                let initial_policy = PolicyTarget::new(&mut builder, initial); let current = PolicyTarget::new(&mut builder, stored);
                let one = builder.one(); builder.connect(initial_policy.version, one);
                let contract_id = builder.constant(F::from_canonical_u32(6));
                let mut first_root = None;
                for i in 0..4 {
                    let slot = builder.constant(F::from_canonical_usize(i));
                    let (state_root, slot_path) = path(&mut builder, stored[i], slot, 4);
                    if let Some(root) = first_root { builder.connect_hashes(state_root, root); } else { first_root = Some(state_root); }
                    let (account_root, contract_path) = path(&mut builder, state_root, contract_id, GLOBAL_CONTRACT_TREE_HEIGHT);
                    builder.connect_hashes(account_root, user.user_state_tree_root); contract_paths.push(contract_path); slot_paths.push(slot_path);
                }
                let selected: [Target; 2] = builder.add_virtual_target_arr(); let three = builder.constant(F::from_canonical_u8(3));
                for i in 0..2 {
                    builder.range_check(selected[i], 2); let valid = builder.is_less_than(2, selected[i], three); builder.assert_one(valid.target);
                    for j in 0..3 { let index = builder.constant(F::from_canonical_usize(j)); let active = builder.is_equal(selected[i], index); builder.connect_hashes_if_true(active, signatures[i].public_key_hash, current.members[j]); }
                }
                let ordered = builder.is_less_than(2, selected[0], selected[1]); builder.assert_one(ordered.target);
                initial_slots = Some(initial); policy_slots = Some(stored); indices = Some(selected);
                let domain = builder.constant(F::from_canonical_u32(0x4d534741)); let zero = builder.zero(); let height = builder.constant(F::from_canonical_u8(4));
                builder.hash_n_to_hash_no_pad::<PoseidonHash>([vec![domain, contract_id, zero, height], initial_policy.commitment.elements.to_vec()].concat())
            }
        },
        _ => unreachable!("closed reward authorization variant"),
    };
    let identity = builder.constant_hash(identity.0); let public_key = builder.hash_two_to_one::<PoseidonHash>(identity, param); builder.connect_hashes(public_key, user.public_key);
    for value in [1, 4, variant as u32, 0] { let target = builder.constant(F::from_canonical_u32(value)); builder.register_public_input(target); }
    builder.register_public_inputs(&config); builder.register_public_inputs(&end_id); builder.register_public_inputs(&end_root.elements); builder.register_public_inputs(&message); builder.register_public_inputs(&user_hash.elements);
    for gate in gates { builder.add_gate_to_gate_set(gate.clone()); }
    if degree > 0 { while builder.num_gates() < (1usize << (degree - 1)) + 1 { builder.add_gate(NoopGate, vec![]); } }
    let targets = AuthorizationTargets { config, end_id, end_root, reward, claim, end, roots, user, claim_path, end_path, user_path, private_key, signatures, initial_slots, policy_slots, contract_paths, slot_paths, indices };
    (targets, builder.build::<C>())
}

fn set_hashes(pw: &mut PartialWitness<F>, targets: &[HashOutTarget], values: &[QHashOut<F>]) -> anyhow::Result<()> {
    anyhow::ensure!(targets.len() == values.len(), "reward membership path height mismatch");
    for (&target, value) in targets.iter().zip(values) { pw.set_hash_target(target, value.0)?; } Ok(())
}
fn set_words(pw: &mut PartialWitness<F>, targets: &[Target], bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(targets.len() * 4 == bytes.len(), "reward byte width mismatch");
    for (&target, bytes) in targets.iter().zip(bytes.chunks_exact(4)) { pw.set_target(target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into()?)))?; } Ok(())
}
fn policy_slots(policy: &MultisigPolicy) -> [QHashOut<F>; 4] {
    [QHashOut::from_values(policy.version as u64, policy.threshold as u64, policy.member_count as u64, 0), policy.member_hashes[0], policy.member_hashes[1], policy.member_hashes[2]]
}

impl AuthorizationTargets {
    fn witness(&self, variant: u8, input: &RewardAuthorizationInput) -> anyhow::Result<PartialWitness<F>> {
        let context = &input.context;
        context.reward.validate()?;
        anyhow::ensure!(context.end_checkpoint_id <= u32::MAX as u64 && context.reward.claim_checkpoint_id <= u32::MAX as u64, "checkpoint outside fixed tree");
        anyhow::ensure!(context.end_checkpoint_root.iter().all(|&x| x < psy_client_data::bridge_aggregate::GOLDILOCKS_MODULUS), "noncanonical checkpoint root");
        let mut pw = PartialWitness::new();
        set_words(&mut pw, &self.config, &context.config_hash)?;
        pw.set_target(self.end_id[0], F::from_canonical_u32(context.end_checkpoint_id as u32))?; pw.set_target(self.end_id[1], F::ZERO)?;
        pw.set_hash_target(self.end_root, plonky2::hash::hash_types::HashOut { elements: context.end_checkpoint_root.map(F::from_canonical_u64) })?;
        for (target, value) in [(self.reward.claim_checkpoint_id[0], context.reward.claim_checkpoint_id), (self.reward.claim_checkpoint_id[1], 0), (self.reward.user_id, context.reward.user_id as u64), (self.reward.height, context.reward.height as u64), (self.reward.path_index, context.reward.path_index as u64), (self.reward.nullifier_index, context.reward.nullifier_index as u64)] { pw.set_target(target, F::from_canonical_u64(value))?; }
        set_words(&mut pw, &self.reward.recipient, &context.reward.recipient)?;
        self.claim.set_witness(&mut pw, &context.claim_checkpoint_leaf)?; self.end.set_witness(&mut pw, &context.end_checkpoint_leaf)?; self.roots.set_witness(&mut pw, &context.end_global_state_roots)?; self.user.set_witness(&mut pw, &context.authorization_user_leaf)?;
        set_hashes(&mut pw, &self.claim_path, &context.claim_checkpoint_path)?; set_hashes(&mut pw, &self.end_path, &context.end_checkpoint_path)?; set_hashes(&mut pw, &self.user_path, &context.authorization_user_path)?;
        let signers: Vec<(&[u8; 33], &[u8; 64])> = match (&input.authorization, variant) {
            (RewardAuthorizationWitness::Zk { private_key }, 0) => { pw.set_hash_target(self.private_key.unwrap(), private_key.0)?; vec![] },
            (RewardAuthorizationWitness::Secp { compressed_public_key, signature_rs }, 1) | (RewardAuthorizationWitness::PersonalSign { compressed_public_key, signature_rs }, 2) => vec![(compressed_public_key, signature_rs)],
            (RewardAuthorizationWitness::Multisig { contract_id, initial_policy, policy_slots: slots, contract_state_paths, policy_slot_paths, member_indices, compressed_public_keys, signatures_rs }, 3) => {
                anyhow::ensure!(*contract_id == 6 && initial_policy.version == 1, "wrong multisig enrollment"); initial_policy.validate()?;
                set_hashes(&mut pw, &self.initial_slots.unwrap(), &policy_slots(initial_policy))?; set_hashes(&mut pw, &self.policy_slots.unwrap(), slots)?;
                for i in 0..4 { set_hashes(&mut pw, &self.contract_paths[i], &contract_state_paths[i])?; set_hashes(&mut pw, &self.slot_paths[i], &policy_slot_paths[i])?; }
                for i in 0..2 { pw.set_target(self.indices.unwrap()[i], F::from_canonical_u8(member_indices[i]))?; }
                (0..2).map(|i| (&compressed_public_keys[i], &signatures_rs[i])).collect()
            },
            _ => anyhow::bail!("reward authorization scheme mismatch"),
        };
        for (gadget, (key, signature)) in self.signatures.iter().zip(signers) {
            let point = VerifyingKey::from_sec1_bytes(key)?.to_encoded_point(false); let point = point.as_bytes();
            for (target, bytes) in [(&gadget.public_key_x_target, &point[1..33]), (&gadget.public_key_y_target, &point[33..65]), (&gadget.signature_r_target, &signature[..32]), (&gadget.signature_s_target, &signature[32..])] {
                for (limb, bytes) in target.limbs.iter().zip(bytes.rchunks_exact(4)) { pw.set_target(limb.0, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into()?)))?; }
            }
        }
        Ok(pw)
    }
}

macro_rules! authorization_circuit {
    ($name:ident, $variant:expr, $identity:expr) => {
        pub struct $name { pub circuit_data: CircuitData<F, C, 2>, pub identity_fingerprint: QHashOut<F>, targets: AuthorizationTargets }
        impl $name {
            pub fn new() -> anyhow::Result<Self> { let identity = $identity; Ok(Self::build(identity, &[], 0)) }
            fn build(identity_fingerprint: QHashOut<F>, gates: &[GateRef<F, 2>], degree: usize) -> Self { let (targets, circuit_data) = build($variant, identity_fingerprint, gates, degree); Self { circuit_data, identity_fingerprint, targets } }
            pub fn prove(&self, input: &RewardAuthorizationInput) -> anyhow::Result<PsyProof> { self.circuit_data.prove(self.targets.witness($variant, input)?) }
        }
    };
}
authorization_circuit!(ZkRewardAuthorizationCircuit, 0, PsyBasicZKSignatureCircuit::<C, 2>::new().get_fingerprint());
authorization_circuit!(SecpRewardAuthorizationCircuit, 1, Secp256K1SignatureCircuit::<C, 2>::new().get_fingerprint());
authorization_circuit!(PersonalSignRewardAuthorizationCircuit, 2, EthPersonalSignSecp256K1SignatureCircuit::<C, 2>::new().get_fingerprint());
authorization_circuit!(MultisigRewardAuthorizationCircuit, 3, MultisigSignatureCircuit::new()?.get_fingerprint());

pub struct RewardAuthorizationCircuits { pub zk: ZkRewardAuthorizationCircuit, pub secp: SecpRewardAuthorizationCircuit, pub personal_sign: PersonalSignRewardAuthorizationCircuit, pub multisig: MultisigRewardAuthorizationCircuit }
impl RewardAuthorizationCircuits {
    pub fn prove(&self, input: &RewardAuthorizationInput) -> anyhow::Result<PsyProof> {
        match &input.authorization {
            RewardAuthorizationWitness::Zk { .. } => self.zk.prove(input),
            RewardAuthorizationWitness::Secp { .. } => self.secp.prove(input),
            RewardAuthorizationWitness::PersonalSign { .. } => self.personal_sign.prove(input),
            RewardAuthorizationWitness::Multisig { .. } => self.multisig.prove(input),
        }
    }
    pub fn new() -> anyhow::Result<Self> {
        let mut family = Self { zk: ZkRewardAuthorizationCircuit::new()?, secp: SecpRewardAuthorizationCircuit::new()?, personal_sign: PersonalSignRewardAuthorizationCircuit::new()?, multisig: MultisigRewardAuthorizationCircuit::new()? };
        let mut gates = BTreeMap::new(); let mut degree = 0;
        for _ in 0..8 {
            for data in [&family.zk.circuit_data, &family.secp.circuit_data, &family.personal_sign.circuit_data, &family.multisig.circuit_data] {
                degree = degree.max(data.common.degree_bits());
                for gate in &data.common.gates { gates.insert(gate.0.id(), gate.clone()); }
            }
            let union: Vec<_> = gates.values().cloned().collect();
            family = Self { zk: ZkRewardAuthorizationCircuit::build(family.zk.identity_fingerprint, &union, degree), secp: SecpRewardAuthorizationCircuit::build(family.secp.identity_fingerprint, &union, degree), personal_sign: PersonalSignRewardAuthorizationCircuit::build(family.personal_sign.identity_fingerprint, &union, degree), multisig: MultisigRewardAuthorizationCircuit::build(family.multisig.identity_fingerprint, &union, degree) };
            let serializer = psy_common_circuit::serialization::PsyGateSerializer;
            let expected = family.zk.circuit_data.common.to_bytes(&serializer).map_err(|error| anyhow::anyhow!("reward common-data serialization: {error:?}"))?;
            let mut equal = true;
            for common in [&family.secp.circuit_data.common, &family.personal_sign.circuit_data.common, &family.multisig.circuit_data.common] {
                equal &= *common == family.zk.circuit_data.common && common.to_bytes(&serializer).map_err(|error| anyhow::anyhow!("reward common-data serialization: {error:?}"))? == expected;
            }
            if equal { return Ok(family); }
        }
        anyhow::bail!("reward authorization common-data harmonization did not converge in eight rebuilds")
    }
}

#[cfg(test)]
fn test_message(input: &RewardAuthorizationInput) -> [u8; 32] {
    input.context.message().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{field::types::PrimeField64, plonk::config::Hasher};
    use psy_crypto::{hash::traits::qhashable::QFieldHashable, signature::zk::wallet::SimplePsyPrivateKey};

    pub(super) fn root(mut leaf: QHashOut<F>, index: u64, siblings: &[QHashOut<F>]) -> QHashOut<F> {
        for (level, sibling) in siblings.iter().enumerate() {
            leaf = if (index >> level) & 1 == 0 { QHashOut(PoseidonHash::two_to_one(leaf.0, sibling.0)) } else { QHashOut(PoseidonHash::two_to_one(sibling.0, leaf.0)) };
        }
        leaf
    }

    pub(super) fn fixture(public_key: QHashOut<F>, authorization: RewardAuthorizationWitness) -> RewardAuthorizationInput {
        let user = PsyUserLeaf { public_key, user_id: F::ONE, ..Default::default() };
        let user_path = vec![QHashOut::ZERO; GLOBAL_USER_TREE_HEIGHT as usize];
        let roots = PsyCheckpointGlobalStateRoots { user_tree_root: root(user.qfhash::<PoseidonHash>(), 1, &user_path), ..Default::default() };
        let end = PsyCheckpointLeaf { global_chain_root: roots.qfhash::<PoseidonHash>(), ..Default::default() };
        let checkpoint_path = vec![QHashOut::ZERO; CHECKPOINT_TREE_HEIGHT as usize];
        let end_root = root(end.qfhash::<PoseidonHash>(), 1, &checkpoint_path);
        RewardAuthorizationInput { context: RewardAuthorizationContext { config_hash: [7; 32], end_checkpoint_id: 1, end_checkpoint_root: end_root.0.elements.map(|v| v.to_canonical_u64()), reward: RewardLeaf { claim_checkpoint_id: 1, user_id: 1, height: 2, path_index: 0, nullifier_index: 3, recipient: [8; 20] }, claim_checkpoint_leaf: end, claim_checkpoint_path: checkpoint_path.clone(), end_checkpoint_leaf: end, end_checkpoint_path: checkpoint_path, end_global_state_roots: roots, authorization_user_leaf: user, authorization_user_path: user_path }, authorization }
    }

    #[test]
    fn zk_authorization_rejects_changed_authenticated_membership() {
        let circuit = ZkRewardAuthorizationCircuit::new().unwrap();
        let private_key = QHashOut::from_values(11, 22, 33, 44);
        let param = SimplePsyPrivateKey::new(private_key).get_public_key_param::<PoseidonHash>();
        let public_key = QHashOut(PoseidonHash::two_to_one(circuit.identity_fingerprint.0, param.0));
        let input = fixture(public_key, RewardAuthorizationWitness::Zk { private_key });
        let proof = circuit.prove(&input).unwrap(); circuit.circuit_data.verify(proof).unwrap();
        for field in 0..8 {
            let mut changed = input.clone();
            match field {
                0 => changed.context.claim_checkpoint_path[0] = QHashOut::from_values(1, 0, 0, 0),
                1 => changed.context.end_checkpoint_path[0] = QHashOut::from_values(1, 0, 0, 0),
                2 => changed.context.authorization_user_path[0] = QHashOut::from_values(1, 0, 0, 0),
                3 => changed.context.authorization_user_leaf.nonce = F::ONE,
                4 => changed.context.authorization_user_leaf.last_checkpoint_id = F::from_canonical_u32(2),
                5 => changed.context.end_global_state_roots.user_tree_root = QHashOut::ZERO,
                6 => changed.context.reward.user_id = 2,
                _ => changed.authorization = RewardAuthorizationWitness::Zk { private_key: QHashOut::from_values(12, 22, 33, 44) },
            }
            assert!(circuit.prove(&changed).is_err(), "mutation {field} accepted");
        }
    }

    #[test]
    fn raw_and_personal_sign_are_distinct_and_recipient_bound() {
        use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
        use psy_client_common::data::secp256k1::CompressedPublicKey;
        use psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key;
        use plonky2::hash::poseidon::PoseidonPermutation;
        let raw = SecpRewardAuthorizationCircuit::new().unwrap();
        let personal = PersonalSignRewardAuthorizationCircuit::new().unwrap();
        assert_ne!(raw.identity_fingerprint, personal.identity_fingerprint);
        let key = SigningKey::from_bytes((&[19u8; 32]).into()).unwrap();
        let compressed: [u8; 33] = key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
        let param = hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(CompressedPublicKey(compressed));
        let public_key = QHashOut(PoseidonHash::two_to_one(raw.identity_fingerprint.0, param.0));
        let mut input = fixture(public_key, RewardAuthorizationWitness::Secp { compressed_public_key: compressed, signature_rs: [0; 64] });
        let message = test_message(&input);
        let signature: k256::ecdsa::Signature = key.sign_prehash(&message).unwrap();
        let signature = signature.normalize_s().unwrap_or(signature);
        let signature_rs: [u8; 64] = signature.to_bytes().into();
        input.authorization = RewardAuthorizationWitness::Secp { compressed_public_key: compressed, signature_rs };
        let proof = raw.prove(&input).unwrap(); raw.circuit_data.verify(proof).unwrap();
        let mut changed = input.clone(); changed.context.reward.recipient[0] ^= 1;
        assert!(raw.prove(&changed).is_err());
        changed = input.clone(); changed.context.config_hash[0] ^= 1;
        assert!(raw.prove(&changed).is_err());
        changed = input; changed.authorization = RewardAuthorizationWitness::PersonalSign { compressed_public_key: compressed, signature_rs };
        assert!(personal.prove(&changed).is_err());
    }

    #[test]
    fn policy_header_and_member_order_are_constrained() {
        let mut builder = CircuitBuilder::<F, 2>::new(plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config());
        let slots = core::array::from_fn(|_| builder.add_virtual_hash());
        PolicyTarget::new(&mut builder, slots);
        let circuit = builder.build::<C>();
        let valid = [QHashOut::from_values(2, 2, 3, 0), QHashOut::from_values(1, 0, 0, 0), QHashOut::from_values(2, 0, 0, 0), QHashOut::from_values(3, 0, 0, 0)];
        let prove = |values: &[QHashOut<F>; 4]| { let mut pw = PartialWitness::new(); set_hashes(&mut pw, &slots, values).unwrap(); circuit.prove(pw) };
        circuit.verify(prove(&valid).unwrap()).unwrap();
        for field in 0..5 {
            let mut changed = valid;
            match field { 0 => changed[0] = QHashOut::ZERO, 1 => changed[0] = QHashOut::from_values(2, 1, 3, 0), 2 => changed[1] = QHashOut::ZERO, 3 => changed.swap(1, 2), _ => changed[2] = changed[1] }
            assert!(prove(&changed).is_err());
        }
    }
}

#[cfg(test)]
mod multisig_tests {
    use super::*;
    use k256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
    use plonky2::{field::types::PrimeField64, hash::poseidon::PoseidonPermutation, plonk::config::Hasher};
    use psy_client_common::data::secp256k1::CompressedPublicKey;
    use psy_crypto::{hash::traits::qhashable::QFieldHashable, signature::secp256k1::wallet::hash_no_pad_compressed_public_key};
    use psy_vm::ups::multisig::MultisigAccount;

    fn tree(leaves: Vec<QHashOut<F>>, index: usize) -> (QHashOut<F>, Vec<QHashOut<F>>) {
        let mut nodes = leaves; let mut index = index; let mut siblings = Vec::new();
        while nodes.len() > 1 {
            siblings.push(nodes[index ^ 1]);
            nodes = nodes.chunks_exact(2).map(|pair| QHashOut(PoseidonHash::two_to_one(pair[0].0, pair[1].0))).collect(); index >>= 1;
        }
        (nodes[0], siblings)
    }

    #[test]
    fn rotated_policy_rejects_revoked_and_duplicate_signers() {
        let circuit = MultisigRewardAuthorizationCircuit::new().unwrap();
        let mut keys: Vec<_> = (21u8..25).map(|seed| {
            let key = SigningKey::from_bytes((&[seed; 32]).into()).unwrap();
            let bytes: [u8; 33] = key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
            let hash = hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(CompressedPublicKey(bytes));
            (hash, bytes, key)
        }).collect();
        keys.sort_by_key(|row| row.0.0.elements.map(|v| v.to_canonical_u64()));
        let mut initial_members = [QHashOut::ZERO; 8]; initial_members[..3].copy_from_slice(&[keys[0].0, keys[1].0, keys[2].0]);
        let initial = MultisigPolicy { version: 1, threshold: 2, member_count: 3, member_hashes: initial_members };
        let param = MultisigAccount { contract_id: 6, initial_policy: initial.clone() }.public_key_param().unwrap();
        let public_key = QHashOut(PoseidonHash::two_to_one(circuit.identity_fingerprint.0, param.0));
        let slots = [QHashOut::from_values(2, 2, 3, 0), keys[1].0, keys[2].0, keys[3].0];
        let mut leaves = vec![QHashOut::ZERO; 16]; leaves[..4].copy_from_slice(&slots);
        let state_root = tree(leaves.clone(), 0).0;
        let slot_paths: [[QHashOut<F>; 4]; 4] = core::array::from_fn(|i| tree(leaves.clone(), i).1.try_into().unwrap());
        let contract_path = vec![QHashOut::ZERO; GLOBAL_CONTRACT_TREE_HEIGHT as usize];
        let mut input = tests::fixture(public_key, RewardAuthorizationWitness::Multisig { contract_id: 6, initial_policy: initial, policy_slots: slots, contract_state_paths: core::array::from_fn(|_| contract_path.clone()), policy_slot_paths: slot_paths, member_indices: [0, 1], compressed_public_keys: [keys[1].1, keys[2].1], signatures_rs: [[0; 64]; 2] });
        input.context.authorization_user_leaf.user_state_tree_root = tests::root(state_root, 6, &contract_path);
        input.context.end_global_state_roots.user_tree_root = tests::root(input.context.authorization_user_leaf.qfhash::<PoseidonHash>(), 1, &input.context.authorization_user_path);
        input.context.end_checkpoint_leaf.global_chain_root = input.context.end_global_state_roots.qfhash::<PoseidonHash>();
        input.context.claim_checkpoint_leaf = input.context.end_checkpoint_leaf;
        input.context.end_checkpoint_root = tests::root(input.context.end_checkpoint_leaf.qfhash::<PoseidonHash>(), 1, &input.context.end_checkpoint_path).0.elements.map(|v| v.to_canonical_u64());
        let message = test_message(&input);
        let sign = |key: &SigningKey| { let signature: k256::ecdsa::Signature = key.sign_prehash(&message).unwrap(); signature.normalize_s().unwrap_or(signature).to_bytes().into() };
        if let RewardAuthorizationWitness::Multisig { signatures_rs, .. } = &mut input.authorization { *signatures_rs = [sign(&keys[1].2), sign(&keys[2].2)]; }
        let proof = circuit.prove(&input).unwrap(); circuit.circuit_data.verify(proof).unwrap();
        let mut revoked = input.clone();
        if let RewardAuthorizationWitness::Multisig { compressed_public_keys, signatures_rs, .. } = &mut revoked.authorization { compressed_public_keys[0] = keys[0].1; signatures_rs[0] = sign(&keys[0].2); }
        assert!(circuit.prove(&revoked).is_err());
        let mut duplicate = input;
        if let RewardAuthorizationWitness::Multisig { member_indices, compressed_public_keys, signatures_rs, .. } = &mut duplicate.authorization { member_indices[1] = member_indices[0]; compressed_public_keys[1] = compressed_public_keys[0]; signatures_rs[1] = signatures_rs[0]; }
        assert!(circuit.prove(&duplicate).is_err());
    }
}
