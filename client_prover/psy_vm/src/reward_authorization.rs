use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash, plonk::config::Hasher};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::bridge_aggregate::{Hash4, RewardLeaf, GOLDILOCKS_MODULUS};
use tiny_keccak::{Hasher as KeccakHasher, Keccak};
use crate::ups::multisig::MultisigPolicy;

pub const REWARD_AUTHORIZATION_DOMAIN: &[u8] = b"PsyBridge/TwoArtifact/1/RewardAuthorization";

#[derive(Clone)]
pub enum RewardAuthorizationWitness {
    Zk { private_key: QHashOut<GoldilocksField> },
    Secp { compressed_public_key: [u8; 33], signature_rs: [u8; 64] },
    PersonalSign { compressed_public_key: [u8; 33], signature_rs: [u8; 64] },
    Multisig {
        contract_id: u32,
        initial_policy: MultisigPolicy,
        policy_slots: [QHashOut<GoldilocksField>; 4],
        contract_state_paths: [Vec<QHashOut<GoldilocksField>>; 4],
        policy_slot_paths: [[QHashOut<GoldilocksField>; 4]; 4],
        member_indices: [u8; 2],
        compressed_public_keys: [[u8; 33]; 2],
        signatures_rs: [[u8; 64]; 2],
    },
}

pub fn reward_authorization_domain() -> [u8; 32] {
    let mut domain = [0; 32];
    let mut hash = Keccak::v256();
    hash.update(REWARD_AUTHORIZATION_DOMAIN);
    hash.finalize(&mut domain);
    domain
}

pub fn build_reward_authorization_message(
    config_hash: [u8; 32], end_checkpoint_id: u64,
    end_checkpoint_root: Hash4, end_checkpoint_leaf_hash: Hash4,
    authorization_user_leaf_hash: Hash4, claim_checkpoint_leaf_hash: Hash4,
    reward: &RewardLeaf,
) -> anyhow::Result<[u8; 32]> {
    reward.validate()?;
    let domain = reward_authorization_domain();
    let mut hash = Keccak::v256();
    hash.update(&domain);
    hash.update(&config_hash);
    let mut word = [0; 32];
    word[24..].copy_from_slice(&end_checkpoint_id.to_be_bytes());
    hash.update(&word);
    for value in [end_checkpoint_root, end_checkpoint_leaf_hash, authorization_user_leaf_hash, claim_checkpoint_leaf_hash] {
        for limb in value {
            anyhow::ensure!(limb < GOLDILOCKS_MODULUS, "noncanonical reward authorization hash limb");
            word[24..].copy_from_slice(&limb.to_be_bytes());
            hash.update(&word);
        }
    }
    hash.update(&reward.encode()?);
    let mut message = [0; 32];
    hash.finalize(&mut message);
    Ok(message)
}

pub fn reward_authorization_message_felt_hash(message: [u8; 32]) -> QHashOut<GoldilocksField> {
    use plonky2::field::types::Field;
    let mut fields = [GoldilocksField::ZERO; 9];
    fields[0] = GoldilocksField::from_canonical_u32(0x52574155);
    for (field, bytes) in fields[1..].iter_mut().zip(message.chunks_exact(4)) {
        *field = GoldilocksField::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap()));
    }
    QHashOut(PoseidonHash::hash_no_pad(&fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_binds_every_context_and_reward_field() {
        let reward = RewardLeaf { claim_checkpoint_id: 3, user_id: 7, height: 3, path_index: 0, nullifier_index: 7, recipient: [1; 20] };
        let build = |config, end, roots: [Hash4; 4], reward: &RewardLeaf| build_reward_authorization_message(config, end, roots[0], roots[1], roots[2], roots[3], reward).unwrap();
        let roots = [[1, 2, 3, 4]; 4];
        let expected = build([1; 32], 8, roots, &reward);
        assert_ne!(expected, build([2; 32], 8, roots, &reward));
        assert_ne!(expected, build([1; 32], 9, roots, &reward));
        for i in 0..4 {
            for j in 0..4 {
                let mut changed = roots;
                changed[i][j] += 1;
                assert_ne!(expected, build([1; 32], 8, changed, &reward));
            }
        }
        let mut changed = reward.clone();
        changed.claim_checkpoint_id += 1;
        assert_ne!(expected, build([1; 32], 8, roots, &changed));
        changed = reward.clone(); changed.user_id += 1;
        assert_ne!(expected, build([1; 32], 8, roots, &changed));
        changed = reward.clone(); changed.recipient[0] += 1;
        assert_ne!(expected, build([1; 32], 8, roots, &changed));
        changed = reward.clone(); changed.path_index = 1; changed.nullifier_index = 8;
        assert_ne!(expected, build([1; 32], 8, roots, &changed));
        changed = reward.clone(); changed.height = 4; changed.nullifier_index = 15;
        assert_ne!(expected, build([1; 32], 8, roots, &changed));
    }

    #[test]
    fn noncanonical_hash_and_position_are_rejected() {
        let mut reward = RewardLeaf { claim_checkpoint_id: 3, user_id: 7, height: 3, path_index: 0, nullifier_index: 7, recipient: [1; 20] };
        assert!(build_reward_authorization_message([0; 32], 8, [GOLDILOCKS_MODULUS; 4], [0; 4], [0; 4], [0; 4], &reward).is_err());
        reward.nullifier_index += 1;
        assert!(build_reward_authorization_message([0; 32], 8, [0; 4], [0; 4], [0; 4], [0; 4], &reward).is_err());
    }
}
