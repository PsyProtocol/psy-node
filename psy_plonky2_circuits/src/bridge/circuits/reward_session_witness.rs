use plonky2::{
    field::{goldilocks_field::GoldilocksField, secp256k1_base::Secp256K1Base, secp256k1_scalar::Secp256K1Scalar, types::{Field, PrimeField}},
    hash::poseidon::PoseidonHash,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::config::Hasher,
};
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut};
use psy_common_circuit::{
    crypto::secp256k1::{ecdsa::gadgets::biguint::WitnessBigUint, gadget::Secp256K1Gadget},
    hash::base_types::hash256bytes::WitnessHash256Bytes,
};
use psy_crypto::signature::secp256k1::{
    core::{PsyCompressedSecp256K1Signature, PsyPreparedSecp256K1Signature},
    curve::{curve_types::Curve, secp256k1::Secp256K1},
    wallet::EIP191_PREFIX_32,
};
use psy_vm::ups::multisig::{MultisigAccount, MultisigPolicy};
use tiny_keccak::{Hasher as KeccakHasher, Keccak};

use super::reward_session::MultisigPolicyTargets;

type F = GoldilocksField;
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

pub(super) struct AuthSignatureValues {
    pub public_key_x: Secp256K1Base,
    pub public_key_y: Secp256K1Base,
    pub signature_r: Secp256K1Scalar,
    pub signature_s: Secp256K1Scalar,
    pub message: [u8; 32],
}

pub(super) struct MultisigPolicyValues {
    pub initial_slots: [QHashOut<F>; 4],
    pub current_slots: [QHashOut<F>; 4],
    pub selected: [u8; 2],
    pub slot_paths: [[QHashOut<F>; 4]; 4],
    pub contract_paths: [Vec<QHashOut<F>>; 4],
    pub public_key_param: QHashOut<F>,
}

impl AuthSignatureValues {
    pub(super) fn from_bytes(
        compressed_public_key: &[u8; 33], signature_rs: &[u8; 64], message: [u8; 32],
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(compressed_public_key[0] == 2 || compressed_public_key[0] == 3, "auth public key prefix is not canonical");
        let signature_r = canonical_scalar(&signature_rs[..32], false)?;
        let signature_s = canonical_scalar(&signature_rs[32..], true)?;
        let prepared = PsyPreparedSecp256K1Signature::<F>::try_from(&PsyCompressedSecp256K1Signature {
            public_key: *compressed_public_key, signature: *signature_rs, message: Hash256(message),
        })?;
        Ok(Self {
            public_key_x: prepared.public_key.0.x, public_key_y: prepared.public_key.0.y,
            signature_r, signature_s, message,
        })
    }
}

pub(super) fn set_auth_signature(
    witness: &mut PartialWitness<F>, gadget: &Secp256K1Gadget, values: &AuthSignatureValues,
) -> anyhow::Result<()> {
    witness.set_hash256_bytes_target(&gadget.msg_bytes_target, &values.message)?;
    witness.set_biguint_target(&gadget.public_key_x_target, &values.public_key_x.to_canonical_biguint())?;
    witness.set_biguint_target(&gadget.public_key_y_target, &values.public_key_y.to_canonical_biguint())?;
    witness.set_biguint_target(&gadget.signature_r_target, &values.signature_r.to_canonical_biguint())?;
    witness.set_biguint_target(&gadget.signature_s_target, &values.signature_s.to_canonical_biguint())
}

pub(super) fn set_multisig_policy(
    witness: &mut PartialWitness<F>, targets: &MultisigPolicyTargets, values: &MultisigPolicyValues,
) -> anyhow::Result<()> {
    for (target, value) in targets.initial_slots.iter().zip(values.initial_slots) {
        witness.set_hash_target(*target, value.0)?;
    }
    for (target, value) in targets.current_slots.iter().zip(values.current_slots) {
        witness.set_hash_target(*target, value.0)?;
    }
    for (target, index) in targets.selected.iter().zip(values.selected) {
        witness.set_target(*target, F::from_canonical_u8(index))?;
    }
    anyhow::ensure!(targets.slot_paths.len() == values.slot_paths.len(), "multisig policy slot path count mismatch");
    for (path, siblings) in targets.slot_paths.iter().zip(&values.slot_paths) {
        anyhow::ensure!(path.siblings.len() == siblings.len(), "multisig policy slot path height mismatch");
        for (target, sibling) in path.siblings.iter().zip(siblings) {
            witness.set_hash_target(*target, sibling.0)?;
        }
    }
    anyhow::ensure!(targets.contract_paths.len() == values.contract_paths.len(), "multisig policy contract path count mismatch");
    for (path, siblings) in targets.contract_paths.iter().zip(&values.contract_paths) {
        anyhow::ensure!(path.siblings.len() == siblings.len(), "multisig policy contract path height mismatch");
        for (target, sibling) in path.siblings.iter().zip(siblings) {
            witness.set_hash_target(*target, sibling.0)?;
        }
    }
    Ok(())
}

pub(super) fn auth_signature_padding(is_personal_sign: bool) -> anyhow::Result<AuthSignatureValues> {
    let point = Secp256K1::GENERATOR_AFFINE;
    let message = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let digest = if is_personal_sign { personal_digest(&message) } else { message };
    let signature_r = scalar_from_base(point.x);
    let signature_s = low_s(signature_r + scalar_from_be(&digest))?;
    Ok(AuthSignatureValues { public_key_x: point.x, public_key_y: point.y, signature_r, signature_s, message })
}

pub(super) fn multisig_policy_padding() -> anyhow::Result<MultisigPolicyValues> {
    let members = [1u64, 2, 3].map(|value| QHashOut::from_values(value, 0, 0, 0));
    let initial = policy(1, members);
    let current = policy(2, members);
    let initial_slots = policy_slots(&initial);
    let current_slots = policy_slots(&current);
    let slot_paths = slot_paths(current_slots);
    let height = psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize;
    let contract_paths = core::array::from_fn(|_| vec![QHashOut::ZERO; height]);
    let public_key_param = MultisigAccount { contract_id: 6, initial_policy: initial }.public_key_param()?;
    Ok(MultisigPolicyValues { initial_slots, current_slots, selected: [0, 1], slot_paths, contract_paths, public_key_param })
}

fn canonical_scalar(bytes: &[u8], low: bool) -> anyhow::Result<Secp256K1Scalar> {
    let bytes: &[u8; 32] = bytes.try_into().map_err(|_| anyhow::anyhow!("auth scalar width mismatch"))?;
    let scalar = scalar_from_be(bytes);
    anyhow::ensure!(scalar_bytes(scalar) == *bytes, "auth signature scalar is not canonical");
    anyhow::ensure!(scalar != Secp256K1Scalar::ZERO, "auth signature scalar is zero");
    if low {
        anyhow::ensure!(*bytes <= HALF_ORDER, "auth signature scalar is not low-S");
    }
    Ok(scalar)
}

fn scalar_from_base(value: Secp256K1Base) -> Secp256K1Scalar {
    scalar_from_be(&canonical_bytes(value.to_canonical_biguint().to_bytes_be()))
}

fn scalar_from_be(bytes: &[u8; 32]) -> Secp256K1Scalar {
    let wide = core::array::from_fn(|index| u64::from_be_bytes(bytes[24 - index * 8..32 - index * 8].try_into().unwrap()));
    Secp256K1Scalar(wide) + Secp256K1Scalar::ZERO
}

fn scalar_bytes(value: Secp256K1Scalar) -> [u8; 32] {
    canonical_bytes(value.to_canonical_biguint().to_bytes_be())
}

fn canonical_bytes(digits: Vec<u8>) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[32 - digits.len()..].copy_from_slice(&digits);
    bytes
}

fn low_s(value: Secp256K1Scalar) -> anyhow::Result<Secp256K1Scalar> {
    anyhow::ensure!(value != Secp256K1Scalar::ZERO, "auth padding scalar is zero");
    let normalized = if scalar_bytes(value) > HALF_ORDER { -value } else { value };
    anyhow::ensure!(normalized != Secp256K1Scalar::ZERO, "auth padding scalar is zero");
    Ok(normalized)
}

fn personal_digest(message: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(EIP191_PREFIX_32);
    hasher.update(message);
    let mut digest = [0u8; 32];
    hasher.finalize(&mut digest);
    digest
}

fn policy(version: u32, members: [QHashOut<F>; 3]) -> MultisigPolicy {
    let mut member_hashes = [QHashOut::ZERO; 8];
    member_hashes[..3].copy_from_slice(&members);
    MultisigPolicy { version, threshold: 2, member_count: 3, member_hashes }
}

fn policy_slots(policy: &MultisigPolicy) -> [QHashOut<F>; 4] {
    [
        QHashOut::from_values(policy.version as u64, policy.threshold as u64, policy.member_count as u64, 0),
        policy.member_hashes[0], policy.member_hashes[1], policy.member_hashes[2],
    ]
}

fn poseidon_pair(left: QHashOut<F>, right: QHashOut<F>) -> QHashOut<F> {
    QHashOut(PoseidonHash::two_to_one(left.0, right.0))
}

fn slot_paths(slots: [QHashOut<F>; 4]) -> [[QHashOut<F>; 4]; 4] {
    let mut nodes = [QHashOut::ZERO; 8];
    nodes[..4].copy_from_slice(&slots);
    let mut paths = [[QHashOut::ZERO; 4]; 4];
    for height in 0..4 {
        let width = 8 >> height;
        for slot in 0..4 {
            paths[slot][height] = nodes[(slot >> height) ^ 1];
        }
        let mut parent = [QHashOut::ZERO; 8];
        for index in 0..width / 2 {
            parent[index] = poseidon_pair(nodes[index * 2], nodes[index * 2 + 1]);
        }
        nodes = parent;
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::PrimeField64;

    fn fold(mut value: QHashOut<F>, index: usize, siblings: &[QHashOut<F>]) -> QHashOut<F> {
        for (height, sibling) in siblings.iter().enumerate() {
            value = if (index >> height) & 1 == 0 { poseidon_pair(value, *sibling) } else { poseidon_pair(*sibling, value) };
        }
        value
    }

    #[test]
    fn signature_padding_is_public_low_s_and_distinct_by_prefix() {
        let raw = auth_signature_padding(false).unwrap();
        let personal = auth_signature_padding(true).unwrap();
        let generator = Secp256K1::GENERATOR_AFFINE;
        assert!(generator.is_valid());
        assert_eq!((raw.public_key_x, raw.public_key_y), (generator.x, generator.y));
        assert_eq!(raw.message[31], 1);
        assert_ne!(raw.signature_s, personal.signature_s);
        for values in [&raw, &personal] {
            assert_ne!(values.signature_r, Secp256K1Scalar::ZERO);
            assert_ne!(values.signature_s, Secp256K1Scalar::ZERO);
            assert!(scalar_bytes(values.signature_r) < HALF_ORDER || scalar_bytes(values.signature_r) == scalar_bytes(values.signature_r));
            assert!(scalar_bytes(values.signature_s) <= HALF_ORDER);
        }
    }

    #[test]
    fn policy_padding_orders_members_and_changes_root_with_values() {
        let values = multisig_policy_padding().unwrap();
        assert_eq!(values.initial_slots[0].0.elements[0], F::ONE);
        assert_eq!(values.current_slots[0].0.elements[0], F::TWO);
        let members = values.current_slots[1..].iter().map(|hash| hash.0.elements[0].to_canonical_u64()).collect::<Vec<_>>();
        assert_eq!(members, vec![1, 2, 3]);
        let roots = core::array::from_fn(|slot| fold(values.current_slots[slot], slot, &values.slot_paths[slot]));
        assert!(roots.iter().all(|root| *root == roots[0]));
        let mut changed = values.current_slots;
        changed[1] = QHashOut::from_values(4, 0, 0, 0);
        assert_ne!(fold(changed[0], 0, &slot_paths(changed)[0]), roots[0]);
        assert!(values.contract_paths.iter().all(|path| path.iter().all(|sibling| *sibling == QHashOut::ZERO)));
        assert_ne!(values.public_key_param, QHashOut::ZERO);
    }
}
