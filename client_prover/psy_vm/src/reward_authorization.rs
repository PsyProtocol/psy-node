use std::array;
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

pub const REWARD_SESSION_AUTHORIZATION_DOMAIN: &[u8] = b"PsyRewardAuthorization/CreditSession/1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewardSessionAuthorization {
    pub config_hash: [u8; 32],
    pub economic_domain: [u8; 32],
    pub window_id: [u8; 32],
    pub source_checkpoint_id: u32,
    pub end_checkpoint_id: u32,
    pub user_id: u32,
    pub checkpoint_tree_root: Hash4,
    pub source_checkpoint_leaf_hash: Hash4,
    pub end_checkpoint_leaf_hash: Hash4,
    pub user_leaf_hash: Hash4,
    pub identity_fingerprint: Hash4,
    pub public_key_param: Hash4,
    pub nonce: u64,
    pub jobs_commitment: Hash4,
    pub count: u32,
    pub amount: [u32; 8],
    pub recipient: [u32; 5],
}

pub fn reward_session_authorization_preimage(authorization: &RewardSessionAuthorization) -> anyhow::Result<Vec<u8>> {
    for hash in [
        authorization.checkpoint_tree_root, authorization.source_checkpoint_leaf_hash,
        authorization.end_checkpoint_leaf_hash, authorization.user_leaf_hash,
        authorization.identity_fingerprint, authorization.public_key_param, authorization.jobs_commitment,
    ] {
        anyhow::ensure!(hash.iter().all(|limb| *limb < GOLDILOCKS_MODULUS), "noncanonical reward session hash limb");
    }
    anyhow::ensure!(authorization.nonce < GOLDILOCKS_MODULUS, "noncanonical reward session nonce");
    let mut preimage = Vec::with_capacity(REWARD_SESSION_AUTHORIZATION_DOMAIN.len() + 400);
    preimage.extend_from_slice(REWARD_SESSION_AUTHORIZATION_DOMAIN);
    preimage.extend_from_slice(&authorization.config_hash);
    preimage.extend_from_slice(&authorization.economic_domain);
    preimage.extend_from_slice(&authorization.window_id);
    for value in [1, authorization.source_checkpoint_id, authorization.end_checkpoint_id, authorization.user_id] {
        preimage.extend_from_slice(&value.to_le_bytes());
    }
    for hash in [
        authorization.checkpoint_tree_root, authorization.source_checkpoint_leaf_hash,
        authorization.end_checkpoint_leaf_hash, authorization.user_leaf_hash,
        authorization.identity_fingerprint, authorization.public_key_param,
    ] {
        append_canonical_hash(&mut preimage, hash);
    }
    preimage.extend_from_slice(&authorization.nonce.to_le_bytes());
    append_canonical_hash(&mut preimage, authorization.jobs_commitment);
    preimage.extend_from_slice(&authorization.count.to_le_bytes());
    for word in authorization.amount {
        preimage.extend_from_slice(&word.to_le_bytes());
    }
    for word in authorization.recipient {
        preimage.extend_from_slice(&word.to_le_bytes());
    }
    Ok(preimage)
}

pub fn build_reward_session_authorization_message(authorization: &RewardSessionAuthorization) -> anyhow::Result<[u8; 32]> {
    let preimage = reward_session_authorization_preimage(authorization)?;
    let mut hash = Keccak::v256();
    hash.update(&preimage);
    let mut digest = [0u8; 32];
    hash.finalize(&mut digest);
    Ok(digest)
}

fn append_canonical_hash(preimage: &mut Vec<u8>, hash: Hash4) {
    for limb in hash {
        preimage.extend_from_slice(&limb.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_binds_every_reward_field() {
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

    fn sample_authorization() -> RewardSessionAuthorization {
        RewardSessionAuthorization {
            config_hash: [1; 32], economic_domain: [2; 32], window_id: [3; 32],
            source_checkpoint_id: 4, end_checkpoint_id: 8, user_id: 7,
            checkpoint_tree_root: [11, 12, 13, 14], source_checkpoint_leaf_hash: [21, 22, 23, 24],
            end_checkpoint_leaf_hash: [31, 32, 33, 34], user_leaf_hash: [41, 42, 43, 44],
            identity_fingerprint: [51, 52, 53, 54], public_key_param: [61, 62, 63, 64],
            nonce: 0x0102_0304_0506_0708, jobs_commitment: [71, 72, 73, 74], count: 9,
            amount: [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, 0x5555_5555, 0x6666_6666, 0x7777_7777, 0x8888_8888],
            recipient: [0x0102_0304, 0x0506_0708, 0x090a_0b0c, 0x0d0e_0f10, 0x1112_1314],
        }
    }

    #[test]
    fn reward_session_preimage_is_fixed_length_and_domain_separated() {
        let authorization = sample_authorization();
        let preimage = reward_session_authorization_preimage(&authorization).unwrap();
        let domain = REWARD_SESSION_AUTHORIZATION_DOMAIN;
        assert_eq!(preimage.len(), domain.len() + 400);
        assert_eq!(&preimage[..domain.len()], domain);
        assert_ne!(&preimage[..domain.len()], REWARD_AUTHORIZATION_DOMAIN);
        let mut cursor = domain.len();
        for bytes in [authorization.config_hash, authorization.economic_domain, authorization.window_id] {
            assert_eq!(&preimage[cursor..cursor + 32], &bytes);
            cursor += 32;
        }
        for value in [1u32, authorization.source_checkpoint_id, authorization.end_checkpoint_id, authorization.user_id] {
            assert_eq!(&preimage[cursor..cursor + 4], &value.to_le_bytes());
            cursor += 4;
        }
        let hashes = [
            authorization.checkpoint_tree_root, authorization.source_checkpoint_leaf_hash,
            authorization.end_checkpoint_leaf_hash, authorization.user_leaf_hash,
            authorization.identity_fingerprint, authorization.public_key_param,
        ];
        for (index, hash) in hashes.into_iter().enumerate() {
            for (limb_index, limb) in hash.into_iter().enumerate() {
                let offset = cursor + (index * 4 + limb_index) * 8;
                assert_eq!(&preimage[offset..offset + 8], &limb.to_le_bytes());
            }
        }
        cursor += hashes.len() * 32;
        assert_eq!(&preimage[cursor..cursor + 8], &authorization.nonce.to_le_bytes());
        cursor += 8;
        for (limb_index, limb) in authorization.jobs_commitment.into_iter().enumerate() {
            let offset = cursor + limb_index * 8;
            assert_eq!(&preimage[offset..offset + 8], &limb.to_le_bytes());
        }
        cursor += 32;
        assert_eq!(&preimage[cursor..cursor + 4], &authorization.count.to_le_bytes());
        cursor += 4;
        for word in authorization.amount {
            assert_eq!(&preimage[cursor..cursor + 4], &word.to_le_bytes());
            cursor += 4;
        }
        for word in authorization.recipient {
            assert_eq!(&preimage[cursor..cursor + 4], &word.to_le_bytes());
            cursor += 4;
        }
        assert_eq!(cursor, preimage.len());
        let message = build_reward_session_authorization_message(&authorization).unwrap();
        let mut hash = Keccak::v256();
        hash.update(&preimage);
        let mut digest = [0u8; 32];
        hash.finalize(&mut digest);
        assert_eq!(message, digest);
    }

    #[test]
    fn reward_session_message_changes_with_source_jobs_recipient_amount_and_count() {
        let authorization = sample_authorization();
        let expected = build_reward_session_authorization_message(&authorization).unwrap();
        let mut changed = authorization;
        changed.source_checkpoint_id += 1;
        assert_ne!(expected, build_reward_session_authorization_message(&changed).unwrap());
        changed = authorization;
        changed.jobs_commitment[2] += 1;
        assert_ne!(expected, build_reward_session_authorization_message(&changed).unwrap());
        changed = authorization;
        changed.recipient[4] += 1;
        assert_ne!(expected, build_reward_session_authorization_message(&changed).unwrap());
        changed = authorization;
        changed.amount[7] += 1;
        assert_ne!(expected, build_reward_session_authorization_message(&changed).unwrap());
        changed = authorization;
        changed.count += 1;
        assert_ne!(expected, build_reward_session_authorization_message(&changed).unwrap());
        changed = authorization;
        changed.amount = array::from_fn(|index| authorization.amount[7 - index]);
        assert_ne!(expected, build_reward_session_authorization_message(&changed).unwrap());
    }

    #[test]
    fn reward_session_rejects_noncanonical_roots_and_nonce() {
        let authorization = sample_authorization();
        let hashes = [
            authorization.checkpoint_tree_root, authorization.source_checkpoint_leaf_hash,
            authorization.end_checkpoint_leaf_hash, authorization.user_leaf_hash,
            authorization.identity_fingerprint, authorization.public_key_param, authorization.jobs_commitment,
        ];
        for (index, hash) in hashes.into_iter().enumerate() {
            for limb in 0..4 {
                let mut changed = authorization;
                let mut rejected = hash;
                rejected[limb] = GOLDILOCKS_MODULUS;
                match index {
                    0 => changed.checkpoint_tree_root = rejected,
                    1 => changed.source_checkpoint_leaf_hash = rejected,
                    2 => changed.end_checkpoint_leaf_hash = rejected,
                    3 => changed.user_leaf_hash = rejected,
                    4 => changed.identity_fingerprint = rejected,
                    5 => changed.public_key_param = rejected,
                    6 => changed.jobs_commitment = rejected,
                    _ => unreachable!(),
                }
                assert!(reward_session_authorization_preimage(&changed).is_err());
            }
        }
        let mut changed = authorization;
        changed.nonce = GOLDILOCKS_MODULUS;
        assert!(reward_session_authorization_preimage(&changed).is_err());
        changed.nonce = (u32::MAX as u64) << 32;
        assert!(reward_session_authorization_preimage(&changed).is_ok());
        changed.nonce = ((u32::MAX as u64) << 32) | 1;
        assert!(reward_session_authorization_preimage(&changed).is_err());
        changed.nonce = GOLDILOCKS_MODULUS - 1;
        assert!(reward_session_authorization_preimage(&changed).is_ok());
    }
}
