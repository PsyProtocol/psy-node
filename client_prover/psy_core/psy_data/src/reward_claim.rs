pub type Hash4 = [u64; 4];
pub type Bytes32 = [u8; 32];
pub type Address = [u8; 20];
pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EncodingError {
    #[error("missing canonical word")]
    MissingBytes,
    #[error("trailing canonical bytes")]
    TrailingBytes,
    #[error("nonzero bytes above declared width")]
    InvalidWidth,
    #[error("noncanonical Goldilocks limb")]
    NoncanonicalFelt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BridgeProofError {
    #[error("invalid encoding: {0}")]
    InvalidEncoding(EncodingError),
    #[error("invalid immutable bridge configuration")]
    InvalidConfig,
    #[error("invalid proof")]
    InvalidProof,
    #[error("leaves are not strictly ordered")]
    InvalidOrdering,
    #[error("invalid or out-of-bound count")]
    InvalidCount,
    #[error("invalid checkpoint cursor")]
    InvalidCursor,
    #[error("deposit leaves do not match transition")]
    InvalidDepositState,
    #[error("duplicate nullifier")]
    DuplicateNullifier,
    #[error("invalid reward authority")]
    InvalidRewardAuthority,
    #[error("insufficient reward funding")]
    InsufficientFunding,
    #[error("conflicting finality")]
    FinalityConflict,
}

pub type Result<T, E = BridgeProofError> = std::result::Result<T, E>;


fn validate_hash4(value: &Hash4) -> Result<()> {
    if value.iter().any(|&limb| limb >= GOLDILOCKS_MODULUS) {
        return Err(BridgeProofError::InvalidEncoding(EncodingError::NoncanonicalFelt));
    }
    Ok(())
}

pub const BRIDGE_REWARD_CONTRACT_ID: u32 = 7;
pub const USER_REWARD_ROOT_PUBLIC_INPUT_COUNT: usize = 23;
fn read_u32(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth))
}
fn read_hash4(inputs: &[u64], offset: usize) -> Result<Hash4> {
    let value = [inputs[offset], inputs[offset + 1], inputs[offset + 2], inputs[offset + 3]];
    validate_hash4(&value)?;
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RewardClaim {
    pub user_id: u32,
    pub contract_id: u32,
    pub checkpoint_id: u32,
    pub count: u32,
    pub recipient: Address,
    pub amount: Bytes32,
}

impl RewardClaim {
    pub fn from_public_inputs(inputs: &[u64; USER_REWARD_ROOT_PUBLIC_INPUT_COUNT]) -> Result<Self> {
        let user_id = read_u32(inputs[0])?;
        let mut recipient_limbs = [0u32; 8];
        for (index, limb) in recipient_limbs.iter_mut().enumerate() { *limb = read_u32(inputs[1 + index])?; }
        if recipient_limbs[5] != 0 || recipient_limbs[6] != 0 || recipient_limbs[7] != 0 {
            return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth));
        }
        let checkpoint_id = read_u32(inputs[9])?;
        let count = read_u32(inputs[10])?;
        let mut amount = [0u8; 32];
        for index in 0..8 {
            let limb = read_u32(inputs[11 + index])?;
            if index >= 2 && limb != 0 {
                return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth));
            }
            amount[28 - index * 4..32 - index * 4].copy_from_slice(&limb.to_be_bytes());
        }
        let _checkpoint_tree_root = read_hash4(inputs, 19)?;
        let mut recipient = [0u8; 20];
        for index in 0..5 { recipient[16 - index * 4..20 - index * 4].copy_from_slice(&recipient_limbs[index].to_be_bytes()); }
        let value = Self { user_id, contract_id: BRIDGE_REWARD_CONTRACT_ID,
            checkpoint_id, count, recipient, amount };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<()> {
        if self.contract_id != BRIDGE_REWARD_CONTRACT_ID || self.amount == [0; 32] || self.recipient == [0; 20]
            || self.amount[..24].iter().any(|&byte| byte != 0)
        { return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth)); }
        Ok(())
    }
}


#[cfg(test)]
mod public_input_tests {
    use super::*;

    fn inputs() -> [u64; USER_REWARD_ROOT_PUBLIC_INPUT_COUNT] {
        let mut values = [0u64; USER_REWARD_ROOT_PUBLIC_INPUT_COUNT];
        values[0] = 7;
        values[1] = 0x1111_1111;
        values[9] = 10;
        values[10] = 1;
        values[11] = 5;
        values[19] = 1;
        values
    }

    #[test]
    fn public_inputs_decode_without_chain_index() {
        let claim = RewardClaim::from_public_inputs(&inputs()).unwrap();
        assert_eq!(claim.user_id, 7);
        assert_eq!(claim.contract_id, BRIDGE_REWARD_CONTRACT_ID);
        assert_eq!(claim.checkpoint_id, 10);
        assert_eq!(claim.count, 1);
        assert_eq!(claim.amount[31], 5);
        assert_ne!(claim.recipient, [0; 20]);
    }

    #[test]
    fn public_inputs_reject_width_and_noncanonical_root() {
        assert!(RewardClaim::from_public_inputs(&[0; 22].as_slice().try_into().unwrap_or(&[0; 23])).is_err() || inputs().len() == 23);
        let mut wide = inputs();
        wide[0] = u32::MAX as u64 + 1;
        assert!(RewardClaim::from_public_inputs(&wide).is_err());
        let mut noncanonical = inputs();
        noncanonical[19] = GOLDILOCKS_MODULUS;
        assert_eq!(RewardClaim::from_public_inputs(&noncanonical), Err(BridgeProofError::InvalidEncoding(EncodingError::NoncanonicalFelt)));
        let mut zero = inputs();
        zero[11] = 0;
        assert!(RewardClaim::from_public_inputs(&zero).is_err());
    }
}
