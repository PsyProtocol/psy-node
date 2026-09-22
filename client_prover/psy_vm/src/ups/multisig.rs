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

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            self.threshold >= 1 && self.threshold <= self.member_count && self.member_count <= 8,
            "multisig policy must satisfy 1 <= threshold <= member_count <= 8"
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
pub struct MultisigSignatureWitness {
    pub account: MultisigAccount,
    pub current_policy: MultisigPolicy,
    pub ending_policy: MultisigPolicy,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> MultisigPolicy {
        let mut member_hashes = [QHashOut::ZERO; 8];
        member_hashes[0] = QHashOut::from_values(1, 9, 0, 0);
        member_hashes[1] = QHashOut::from_values(2, 0, 0, 0);
        MultisigPolicy {
            version: 1,
            threshold: 2,
            member_count: 2,
            member_hashes,
        }
    }

    #[test]
    fn rejects_duplicate_and_unordered_members() {
        let mut policy = policy();
        assert!(policy.validate().is_ok());
        policy.member_hashes.swap(0, 1);
        assert!(policy.validate().is_err());
        policy.member_hashes[1] = policy.member_hashes[0];
        assert!(policy.commitment().is_err());
    }

    #[test]
    fn orders_by_canonical_limbs_not_serialized_bytes() {
        let mut policy = policy();
        policy.member_hashes[0] = QHashOut::from_values(1, 256, 0, 0);
        policy.member_hashes[1] = QHashOut::from_values(1, 257, 0, 0);
        assert!(policy.validate().is_ok());
        policy.member_hashes[1] = QHashOut::from_values(1, 255, 0, 0);
        assert!(policy.validate().is_err());
        policy.member_hashes[0] = QHashOut::from_values(1, 0, 0, 0);
        policy.member_hashes[1] = QHashOut::from_values(2, 0, 0, 0);
        policy.member_hashes[0].0.elements[0] = GoldilocksField(0xffff_ffff_0000_0002);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn rejects_zero_active_members_and_nonzero_padding() {
        let mut policy = policy();
        policy.member_hashes[0] = QHashOut::ZERO;
        assert!(policy.validate().is_err());
        policy.member_hashes[0] = QHashOut::from_values(1, 9, 0, 0);
        policy.member_hashes[7] = QHashOut::from_values(0, 0, 0, 1);
        assert!(policy.commitment().is_err());
    }

    #[test]
    fn enforces_threshold_capacity_and_version_bounds() {
        let valid = policy();
        for (version, threshold, member_count) in [(0, 2, 2), (1, 0, 2), (1, 3, 2), (1, 1, 0), (1, 1, 9)] {
            let invalid = MultisigPolicy { version, threshold, member_count, ..valid.clone() };
            assert!(invalid.validate().is_err());
        }
        let full = MultisigPolicy {
            version: u32::MAX,
            threshold: 8,
            member_count: 8,
            member_hashes: std::array::from_fn(|i| QHashOut::from_values(i as u64 + 1, 0, 0, 0)),
        };
        assert!(full.commitment().is_ok());
    }

    #[test]
    fn commitment_and_identity_use_exact_domain_encodings() {
        let initial_policy = policy();
        let encoded_policy: [u64; 37] = [
            0x4d534750, 1, 2, 2, 8,
            1, 9, 0, 0, 2, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let commitment = QHashOut(PoseidonHash::hash_no_pad(&encoded_policy.map(GoldilocksField::from_canonical_u64)));
        assert_eq!(initial_policy.commitment().unwrap(), commitment);
        let account = MultisigAccount { contract_id: 42, initial_policy };
        let encoded_account = [
            GoldilocksField::from_canonical_u32(0x4d534741),
            GoldilocksField::from_canonical_u32(42),
            GoldilocksField::ZERO,
            GoldilocksField::from_canonical_u8(4),
            commitment.0.elements[0], commitment.0.elements[1],
            commitment.0.elements[2], commitment.0.elements[3],
        ];
        let identity = account.public_key_param().unwrap();
        assert_eq!(identity, QHashOut(PoseidonHash::hash_no_pad(&encoded_account)));
        let mut other_contract = account.clone();
        other_contract.contract_id = u32::MAX;
        assert_ne!(other_contract.public_key_param().unwrap(), identity);
        let mut other_threshold = account.clone();
        other_threshold.initial_policy.threshold = 1;
        assert_ne!(other_threshold.public_key_param().unwrap(), identity);
        let mut replacement = account.initial_policy.clone();
        replacement.version = 2;
        assert_ne!(replacement.commitment().unwrap(), commitment);
        assert!(MultisigAccount { contract_id: 42, initial_policy: replacement }.public_key_param().is_err());
    }

    #[test]
    fn account_serialization_preserves_identity_and_requires_fields() {
        let account = MultisigAccount { contract_id: 42, initial_policy: policy() };
        let bytes = bincode::serialize(&account).unwrap();
        let decoded: MultisigAccount = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.public_key_param().unwrap(), account.public_key_param().unwrap());
        let mut json = serde_json::to_value(&account).unwrap();
        json["initial_policy"].as_object_mut().unwrap().remove("version");
        assert!(serde_json::from_value::<MultisigAccount>(json).is_err());
    }
}
