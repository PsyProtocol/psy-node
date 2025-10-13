use parth_core::{crypto::hash::traits::MerkleHasher, felt::{QFelt64, QFeltSized, ToQFelts}, protocol::core_types::QFHashBase};

pub const PM_REWARD_COMMITMENT_SIZE: usize = 12;

#[pderive::serialize_copy_hash_ts]
#[derive(Default)]
#[ts(export, concrete(Hash = parth_core::PHash), rename = "PMRewardCommitmentHash")]
pub struct PPMRewardCommitment<Hash> {
    pub register_users_root: Hash,
    pub gutas_root: Hash,
    pub deploy_contracts_root: Hash,
}



impl<Hash: PartialEq> PPMRewardCommitment<Hash> {
    pub fn combine_with<H: MerkleHasher<Hash>>(&self, other: &Self) -> Self {
        let register_users_root = H::two_to_one(
            &self.register_users_root,
            &other.register_users_root
        );

        let gutas_root = H::two_to_one(
            &self.gutas_root,
            &other.gutas_root
        );
        let deploy_contracts_root = H::two_to_one(
            &self.deploy_contracts_root,
            &other.deploy_contracts_root
        );
        PPMRewardCommitment {
            register_users_root,
            gutas_root,
            deploy_contracts_root,
        }
    }
    

    pub fn get_commitment_hash<H: MerkleHasher<Hash>>(&self) -> Hash{
        let temp = H::two_to_one(
            &self.register_users_root,
            &self.gutas_root,
        );
        H::two_to_one(
            &temp,
            &self.deploy_contracts_root,
        )
    }
}

impl<Hash> QFeltSized for PPMRewardCommitment<Hash> {
    fn q_felt_size() -> usize {
        PM_REWARD_COMMITMENT_SIZE
    }
}
impl<F: QFelt64, Hash: QFHashBase<F>> ToQFelts<F> for PPMRewardCommitment<Hash> {
    fn to_qfelts(&self) -> Vec<F> {
        let mut result = Vec::with_capacity(PM_REWARD_COMMITMENT_SIZE);
        result.extend_from_slice(&self.register_users_root.to_4_felts());
        result.extend_from_slice(&self.gutas_root.to_4_felts());
        result.extend_from_slice(&self.deploy_contracts_root.to_4_felts());
        result
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != PM_REWARD_COMMITMENT_SIZE {
            panic!("Invalid number of elements for PPMRewardCommitment, expected {} got {}", PM_REWARD_COMMITMENT_SIZE, felts.len());
        }
        PPMRewardCommitment {
            register_users_root: Hash::from_4_felts_slice(&felts[0..4]),
            gutas_root: Hash::from_4_felts_slice(&felts[4..8]),
            deploy_contracts_root: Hash::from_4_felts_slice(&felts[8..12]),
        }
    }
}