use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::poseidon::PoseidonHash,
    plonk::config::Hasher,
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::qdata::{
    ups_signature::PsyUserProvingSessionSignatureDataCompact,
    user::PsyUserLeaf,
    user_contract_state::SignContext,
};
use psy_crypto::signature::secp256k1::core::PsyCompressedSecp256K1Signature;
use serde::{Deserialize, Serialize};

use super::state_reader::StateReaderResults;

pub const MULTISIG_POLICY_CONTRACT_ID: u32 = 6;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultisigPolicy {
    pub version: u32,
    pub threshold: u8,
    pub member_count: u8,
    pub member_hashes: [QHashOut<GoldilocksField>; 8],
}

impl MultisigPolicy {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.version != 0, "multisig policy version must be nonzero");
        anyhow::ensure!(
            self.threshold == 2 && self.member_count == 3,
            "multisig policy must be exactly two of three"
        );
        let mut previous = [0u64; 4];
        for (index, member_hash) in self.member_hashes.iter().enumerate() {
            let limbs = member_hash.0.elements.map(|limb| limb.to_canonical_u64());
            if index < usize::from(self.member_count) {
                anyhow::ensure!(limbs != [0; 4], "multisig active member {index} must be nonzero");
                anyhow::ensure!(limbs > previous, "multisig members must be strictly increasing by canonical hash limbs");
                previous = limbs;
            } else {
                anyhow::ensure!(limbs == [0; 4], "multisig unused member {index} must be zero");
            }
        }
        Ok(())
    }

    pub fn commitment(&self) -> anyhow::Result<QHashOut<GoldilocksField>> {
        self.validate()?;
        let mut fields = [GoldilocksField::ZERO; 37];
        fields[0] = GoldilocksField::from_canonical_u32(0x4d534750);
        fields[1] = GoldilocksField::from_canonical_u32(self.version);
        fields[2] = GoldilocksField::from_canonical_u8(self.threshold);
        fields[3] = GoldilocksField::from_canonical_u8(self.member_count);
        fields[4] = GoldilocksField::from_canonical_u8(8);
        for (slot, member_hash) in fields[5..].chunks_exact_mut(4).zip(&self.member_hashes) {
            slot.copy_from_slice(&member_hash.0.elements);
        }
        let commitment = QHashOut(PoseidonHash::hash_no_pad(&fields));
        anyhow::ensure!(commitment != QHashOut::ZERO, "multisig policy commitment must be nonzero");
        Ok(commitment)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigAccount {
    pub contract_id: u32,
    pub initial_policy: MultisigPolicy,
}

impl MultisigAccount {
    pub fn public_key_param(&self) -> anyhow::Result<QHashOut<GoldilocksField>> {
        anyhow::ensure!(self.contract_id == MULTISIG_POLICY_CONTRACT_ID, "multisig requires the policy precompile");
        anyhow::ensure!(self.initial_policy.version == 1, "multisig initial policy version must be 1");
        let initial_commitment = self.initial_policy.commitment()?;
        let mut fields = [GoldilocksField::ZERO; 8];
        fields[0] = GoldilocksField::from_canonical_u32(0x4d534741);
        fields[1] = GoldilocksField::from_canonical_u32(self.contract_id);
        fields[3] = GoldilocksField::from_canonical_u8(4);
        fields[4..].copy_from_slice(&initial_commitment.0.elements);
        Ok(QHashOut(PoseidonHash::hash_no_pad(&fields)))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigSignatures {
    pub member_indices: Vec<u8>,
    pub signatures: Vec<PsyCompressedSecp256K1Signature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultisigSignatureWitness {
    pub account: MultisigAccount,
    pub start_state: StateReaderResults<GoldilocksField>,
    pub end_state: StateReaderResults<GoldilocksField>,
    pub sig_data: PsyUserProvingSessionSignatureDataCompact<GoldilocksField>,
    pub sign_context: SignContext<GoldilocksField>,
    pub start_session_user_leaf: PsyUserLeaf<GoldilocksField>,
    pub nonce: GoldilocksField,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigSignatureInput {
    pub witness: MultisigSignatureWitness,
    pub signatures: MultisigSignatures,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredMultisigPolicy {
    pub header: QHashOut<GoldilocksField>,
    pub members: [QHashOut<GoldilocksField>; 3],
}

impl StoredMultisigPolicy {
    pub fn policy(&self) -> anyhow::Result<MultisigPolicy> {
        let header = self.header.0.elements.map(|limb| limb.to_canonical_u64());
        anyhow::ensure!(header[0] > 0 && header[0] <= u32::MAX as u64 && header[1..] == [2, 3, 0], "invalid multisig policy header");
        let mut member_hashes = [QHashOut::ZERO; 8];
        member_hashes[..3].copy_from_slice(&self.members);
        let policy = MultisigPolicy { version: header[0] as u32, threshold: 2, member_count: 3, member_hashes };
        policy.validate()?;
        Ok(policy)
    }

    pub fn load(state: &StateReaderResults<GoldilocksField>) -> anyhow::Result<Self> {
        use psy_client_data::config::store_config::PsyHasher;
        use psy_crypto::hash::traits::hasher::MerkleZeroHasher;
        use crate::dpn::ops::state_cmd::data::{DPNStateCmd, DPNStateCmdGetSelfUserCurrentContractStateSlotHash};
        anyhow::ensure!(state.state.contract_id == GoldilocksField::from_canonical_u32(MULTISIG_POLICY_CONTRACT_ID), "multisig account location mismatch");
        anyhow::ensure!(state.merkel_proofs.len() == 8 && state.state_cmds.len() == 4 && state.aux_user_leaves.is_empty() && state.checkpoint.is_none(), "multisig requires four self-state reads and eight proofs");
        let mut slots = [QHashOut::ZERO; 4];
        for (index, pair) in state.merkel_proofs.chunks_exact(2).enumerate() {
            let expected = DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(DPNStateCmdGetSelfUserCurrentContractStateSlotHash { slot_index: GoldilocksField::from_canonical_usize(index) });
            anyhow::ensure!(state.state_cmds[index] == expected, "multisig state command mismatch");
            let contract = &pair[0];
            let slot = &pair[1];
            anyhow::ensure!(contract == &state.merkel_proofs[0], "multisig UCON proofs disagree");
            anyhow::ensure!(contract.index == MULTISIG_POLICY_CONTRACT_ID as u64 && contract.root == state.state.user_leaf.user_state_tree_root, "multisig UCON anchor mismatch");
            anyhow::ensure!(contract.siblings.len() == psy_config::network_constants::GLOBAL_CONTRACT_TREE_HEIGHT as usize, "multisig UCON height mismatch");
            anyhow::ensure!(slot.index == index as u64 && slot.siblings.len() == 4, "multisig CSTATE location mismatch");
            let root = if contract.value == QHashOut::ZERO { <PsyHasher as MerkleZeroHasher<QHashOut<GoldilocksField>>>::get_zero_hash(4) } else { contract.value };
            anyhow::ensure!(slot.root == root && state.state.start_contract_state_root == root, "multisig CSTATE anchor mismatch");
            anyhow::ensure!(contract.verify::<PsyHasher>() && slot.verify::<PsyHasher>(), "invalid multisig state proof");
            slots[index] = slot.value;
        }
        Ok(Self { header: slots[0], members: [slots[1], slots[2], slots[3]] })
    }
}

impl MultisigSignatureWitness {
    pub fn policies(&self) -> anyhow::Result<(MultisigPolicy, MultisigPolicy)> {
        self.account.public_key_param()?;
        for (state, leaf) in [(&self.start_state, &self.start_session_user_leaf), (&self.end_state, &self.sign_context.user_leaf)] {
            anyhow::ensure!(state.state.user_leaf == *leaf, "multisig state user leaf mismatch");
            anyhow::ensure!(state.state.checkpoint_tree_root == self.sign_context.checkpoint_tree_root, "multisig checkpoint root mismatch");
        }
        anyhow::ensure!(self.start_state.state.checkpoint_id == self.end_state.state.checkpoint_id, "multisig checkpoint id mismatch");
        let start = StoredMultisigPolicy::load(&self.start_state)?;
        let ending = StoredMultisigPolicy::load(&self.end_state)?.policy()?;
        let current = if start.header == QHashOut::ZERO && start.members == [QHashOut::ZERO; 3] {
            let root = psy_config::DEFAULT_USER_STATE_TREE_ROOT_U64;
            anyhow::ensure!(self.start_session_user_leaf.nonce == GoldilocksField::ZERO && self.start_session_user_leaf.user_state_tree_root == QHashOut::from_values(root[0], root[1], root[2], root[3]), "multisig bootstrap requires pristine registered account");
            anyhow::ensure!(ending == self.account.initial_policy, "multisig bootstrap must install initial policy");
            self.account.initial_policy.clone()
        } else {
            let current = start.policy()?;
            anyhow::ensure!(current == ending || (current.version.checked_add(1) == Some(ending.version) && current.member_hashes != ending.member_hashes), "multisig replacement requires changed members and next version");
            current
        };
        Ok((current, ending))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored() -> StoredMultisigPolicy {
        StoredMultisigPolicy { header: QHashOut::from_values(1, 2, 3, 0), members: [QHashOut::from_values(1, 9, 0, 0), QHashOut::from_values(2, 0, 0, 0), QHashOut::from_values(3, 0, 0, 0)] }
    }

    #[test]
    fn stored_policy_rejects_invalid_headers_and_members() {
        let valid = stored();
        assert!(valid.policy().is_ok());
        for header in [[0, 2, 3, 0], [1, 1, 3, 0], [1, 3, 3, 0], [1, 2, 2, 0], [1, 2, 4, 0], [1, 2, 3, 1], [u32::MAX as u64 + 1, 2, 3, 0]] {
            let invalid = StoredMultisigPolicy { header: QHashOut::from_values(header[0], header[1], header[2], header[3]), ..valid.clone() };
            assert!(invalid.policy().is_err());
        }
        let mut invalid = valid.clone();
        invalid.members[1] = invalid.members[0];
        assert!(invalid.policy().is_err());
        invalid = valid.clone();
        invalid.members.swap(0, 1);
        assert!(invalid.policy().is_err());
        invalid = valid;
        invalid.members[0] = QHashOut::ZERO;
        assert!(invalid.policy().is_err());
    }

    #[test]
    fn initial_identity_pins_precompile_and_version() {
        let account = MultisigAccount { contract_id: MULTISIG_POLICY_CONTRACT_ID, initial_policy: stored().policy().unwrap() };
        let identity = account.public_key_param().unwrap();
        let mut invalid = account.clone();
        invalid.contract_id = 42;
        assert!(invalid.public_key_param().is_err());
        invalid = account.clone();
        invalid.initial_policy.version = 2;
        assert!(invalid.public_key_param().is_err());
        let mut changed = account.clone();
        changed.initial_policy.member_hashes[2] = QHashOut::from_values(4, 0, 0, 0);
        assert_ne!(changed.public_key_param().unwrap(), identity);
        let bytes = bincode::serialize(&account).unwrap();
        let decoded: MultisigAccount = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.public_key_param().unwrap(), identity);
    }

    #[test]
    fn commitment_retains_eight_entry_encoding_without_extra_members() {
        let policy = stored().policy().unwrap();
        let mut fields = vec![0x4d534750, 1, 2, 3, 8];
        fields.extend([1, 9, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
        fields.extend([0; 20]);
        let fields: Vec<_> = fields.into_iter().map(GoldilocksField::from_canonical_u64).collect();
        assert_eq!(policy.commitment().unwrap(), QHashOut(PoseidonHash::hash_no_pad(&fields)));
        let mut padded = policy;
        padded.member_hashes[3] = QHashOut::from_values(4, 0, 0, 0);
        assert!(padded.validate().is_err());
    }
}
