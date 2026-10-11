use tiny_keccak::{Hasher, Keccak};

pub type Hash4 = [u64; 4];
pub type Bytes32 = [u8; 32];
pub type Address = [u8; 20];
pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
pub const BRIDGE_USER_ID: u32 = 524288;
pub const MAX_CHAINS: usize = 256;
pub const MAX_LEAVES: usize = 1024;
/// Single fixed deposit record bound. Circuit unroll, native and Solidity opening
/// validation, and setup identity use this bound; local scheduling budgets may be smaller.
pub const DEPOSIT_RECORD_CAPACITY: usize = 32;

pub fn deposit_aggregate_pi_len(chain_count: usize) -> usize {
    27 + 17 * chain_count + 39 * DEPOSIT_RECORD_CAPACITY
}

pub const DEPOSIT_ACCUMULATOR_SEED_DOMAIN: u64 = 0x44465331;
pub const DEPOSIT_ACCUMULATOR_FOLD_DOMAIN: u64 = 0x44464631;

fn deposit_poseidon(words: &[u64]) -> Result<Hash4> {
    use plonky2::{field::goldilocks_field::GoldilocksField, field::types::{Field, PrimeField64}, hash::poseidon::PoseidonHash, plonk::config::Hasher};
    if words.iter().any(|word| *word >= GOLDILOCKS_MODULUS) {
        return Err(BridgeProofError::InvalidEncoding(EncodingError::NoncanonicalFelt));
    }
    Ok(PoseidonHash::hash_no_pad(&words.iter().copied().map(GoldilocksField::from_canonical_u64).collect::<Vec<_>>()).elements.map(|word| word.to_canonical_u64()))
}

pub fn deposit_accumulator_seed(config_hash: Bytes32, end_checkpoint_id: u64, end_checkpoint_root: Hash4, global_deposit_count: u32) -> Result<Hash4> {
    let mut words = [0; 16];
    words[0] = DEPOSIT_ACCUMULATOR_SEED_DOMAIN;
    for (word, bytes) in words[1..9].iter_mut().zip(config_hash.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
    }
    words[9] = end_checkpoint_id as u32 as u64;
    words[10] = end_checkpoint_id >> 32;
    words[11..15].copy_from_slice(&end_checkpoint_root);
    words[15] = global_deposit_count as u64;
    deposit_poseidon(&words)
}

pub fn deposit_accumulator_fold(accumulator: Hash4, ordinal: u32, chain_index: u8, absolute_index: u32, leaf_hash: Hash4) -> Result<Hash4> {
    let mut words = [0; 12];
    words[0] = DEPOSIT_ACCUMULATOR_FOLD_DOMAIN;
    words[1..5].copy_from_slice(&accumulator);
    words[5] = ordinal as u64;
    words[6] = chain_index as u64;
    words[7] = absolute_index as u64;
    words[8..12].copy_from_slice(&leaf_hash);
    deposit_poseidon(&words)
}

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
}

pub type Result<T, E = BridgeProofError> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    Config, DepositAggregate, Window,
}

pub fn domain_hash(domain: Domain) -> Bytes32 {
    let label: &[u8] = match domain {
    // b"A" is an immutable wire-compatibility label; do not rename this byte string.
        Domain::Config => b"Config",
        Domain::DepositAggregate => b"A",
        Domain::Window => b"Window",
    };
    hash_parts(&[b"PsyBridge/TwoArtifact/1/", label])
}

fn hash_parts(parts: &[&[u8]]) -> Bytes32 {
    let mut hasher = Keccak::v256();
    for part in parts { hasher.update(part); }
    let mut digest = [0; 32];
    hasher.finalize(&mut digest);
    digest
}

fn commit(domain: Domain, body: &[u8]) -> Bytes32 {
    hash_parts(&[&domain_hash(domain), body])
}

fn word(value: u64) -> Bytes32 {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn validate_hash4(value: &Hash4) -> Result<()> {
    if value.iter().any(|&limb| limb >= GOLDILOCKS_MODULUS) {
        return Err(BridgeProofError::InvalidEncoding(EncodingError::NoncanonicalFelt));
    }
    Ok(())
}

struct Writer(Vec<u8>);
impl Writer {
    fn new() -> Self { Self(Vec::new()) }
    fn u8(&mut self, value: u8) -> Result<()> { self.u64(value as u64) }
    fn u16(&mut self, value: u16) -> Result<()> { self.u64(value as u64) }
    fn u32(&mut self, value: u32) -> Result<()> { self.u64(value as u64) }
    fn u64(&mut self, value: u64) -> Result<()> { self.0.extend_from_slice(&word(value)); Ok(()) }
    fn bytes32(&mut self, value: Bytes32) -> Result<()> { self.0.extend_from_slice(&value); Ok(()) }
    fn address(&mut self, value: Address) -> Result<()> {
        self.0.extend_from_slice(&[0; 12]); self.0.extend_from_slice(&value); Ok(())
    }
    fn hash4(&mut self, value: Hash4) -> Result<()> {
        validate_hash4(&value)?;
        for limb in value { self.u64(limb)?; }
        Ok(())
    }
    fn count(&mut self, value: usize, bound: usize) -> Result<()> {
        if value > bound { return Err(BridgeProofError::InvalidCount); }
        self.u32(value as u32)
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn bytes32(&mut self) -> Result<Bytes32> {
        if self.0.len() < 32 { return Err(BridgeProofError::InvalidEncoding(EncodingError::MissingBytes)); }
        let (word, rest) = self.0.split_at(32);
        self.0 = rest;
        Ok(word.try_into().unwrap())
    }
    fn integer(&mut self, width: usize) -> Result<u64> {
        let bytes = self.bytes32()?;
        if bytes[..32-width].iter().any(|&byte| byte != 0) {
            return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth));
        }
        Ok(u64::from_be_bytes(bytes[24..].try_into().unwrap()))
    }
    fn u8(&mut self) -> Result<u8> { Ok(self.integer(1)? as u8) }
    fn u16(&mut self) -> Result<u16> { Ok(self.integer(2)? as u16) }
    fn u32(&mut self) -> Result<u32> { Ok(self.integer(4)? as u32) }
    fn u64(&mut self) -> Result<u64> { self.integer(8) }
    fn address(&mut self) -> Result<Address> {
        let bytes = self.bytes32()?;
        if bytes[..12].iter().any(|&byte| byte != 0) {
            return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth));
        }
        Ok(bytes[12..].try_into().unwrap())
    }
    fn hash4(&mut self) -> Result<Hash4> {
        let value = [self.u64()?, self.u64()?, self.u64()?, self.u64()?];
        validate_hash4(&value)?;
        Ok(value)
    }
    fn count(&mut self, bound: usize, leaf_words: usize) -> Result<usize> {
        let count = self.u32()? as usize;
        if count > bound { return Err(BridgeProofError::InvalidCount); }
        if count > self.0.len() / (32 * leaf_words) {
            return Err(BridgeProofError::InvalidEncoding(EncodingError::MissingBytes));
        }
        Ok(count)
    }
    fn finish(self) -> Result<()> {
        if self.0.is_empty() { Ok(()) }
        else { Err(BridgeProofError::InvalidEncoding(EncodingError::TrailingBytes)) }
    }
}

// Concrete fixed-word wire structs only; arrays and opening validation stay in their impls.
macro_rules! wire_struct {
    ($name:ident { $($field:ident: $ty:ty => $encoding:ident),+ $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name { $(pub $field: $ty),+ }
        impl $name {
            pub fn encode(&self) -> Result<Vec<u8>> {
                let mut writer = Writer::new(); self.write(&mut writer)?; Ok(writer.0)
            }
            pub fn decode(bytes: &[u8]) -> Result<Self> {
                let mut reader = Reader(bytes); let value = Self::read(&mut reader)?;
                reader.finish()?; Ok(value)
            }
            fn write(&self, writer: &mut Writer) -> Result<()> {
                $(writer.$encoding(self.$field)?;)+ Ok(())
            }
            fn read(reader: &mut Reader<'_>) -> Result<Self> {
                Ok(Self { $($field: reader.$encoding()?),+ })
            }
        }
    };
}

wire_struct!(ChainConfig {
    chain_index: u8 => u8, chain_id: Bytes32 => bytes32, bridge: Address => address,
    state_manager: Address => address, bootstrap_id: u64 => u64, bootstrap_root: Hash4 => hash4,
});
wire_struct!(ChainStart {
    chain_index: u8 => u8, start_checkpoint_id: u64 => u64, start_checkpoint_root: Hash4 => hash4,
});
wire_struct!(DepositTransition {
    chain_index: u8 => u8, old_root: Hash4 => hash4, new_root: Hash4 => hash4,
    old_count: u32 => u32, new_count: u32 => u32,
});
wire_struct!(DepositLeaf {
    chain_index: u8 => u8, absolute_index: u32 => u32, shield_address: Bytes32 => bytes32,
    token: Address => address, l2_token_contract_id: Bytes32 => bytes32,
    amount: Bytes32 => bytes32, note_commitment: Bytes32 => bytes32,
});
wire_struct!(DepositLeafRange {
    first_leaf: u32 => u32, leaf_count: u32 => u32,
});
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    pub version: u32,
    pub network_magic: u64,
    pub bridge_user_id: u32,
    pub circuit_set_hash: Bytes32,
    pub chains: Vec<ChainConfig>,
    pub ethereum_index: u8,
    pub reward_payer: Address,
    pub reward_token: Address,
    pub reward_per_claim: Bytes32,
    pub reward_token_decimals: u8,
    pub max_withdrawals: u32,
    pub max_rewards: u32,
}

impl NetworkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.bridge_user_id != BRIDGE_USER_ID
            || self.chains.is_empty() || self.chains.len() > MAX_CHAINS
            || self.reward_payer == [0; 20] || self.reward_token == [0; 20]
            || self.reward_per_claim == [0; 32]
            || [self.max_withdrawals, self.max_rewards].iter().any(|&count| count as usize > MAX_LEAVES)
            || !self.chains.iter().any(|chain| chain.chain_index == self.ethereum_index)
        { return Err(BridgeProofError::InvalidConfig); }
        for (i, chain) in self.chains.iter().enumerate() {
            validate_hash4(&chain.bootstrap_root)?;
            if chain.bridge == [0; 20] || chain.state_manager == [0; 20]
                || chain.chain_id == [0; 32]
                || (i > 0 && self.chains[i-1].chain_index >= chain.chain_index)
                || self.chains[..i].iter().any(|previous| previous.chain_id == chain.chain_id)
            { return Err(BridgeProofError::InvalidConfig); }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.u32(self.version)?; writer.u64(self.network_magic)?;
        writer.u32(self.bridge_user_id)?; writer.bytes32(self.circuit_set_hash)?;
        writer.count(self.chains.len(), MAX_CHAINS)?;
        for chain in &self.chains { chain.write(&mut writer)?; }
        writer.u8(self.ethereum_index)?; writer.address(self.reward_payer)?;
        writer.address(self.reward_token)?; writer.bytes32(self.reward_per_claim)?;
        writer.u8(self.reward_token_decimals)?; writer.u32(self.max_withdrawals)?; writer.u32(self.max_rewards)?;
        Ok(writer.0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader(bytes);
        let version = reader.u32()?; let network_magic = reader.u64()?;
        let bridge_user_id = reader.u32()?; let circuit_set_hash = reader.bytes32()?;
        let count = reader.count(MAX_CHAINS, 9)?;
        let mut chains = Vec::with_capacity(count);
        for _ in 0..count { chains.push(ChainConfig::read(&mut reader)?); }
        let value = Self {
            version, network_magic, bridge_user_id, circuit_set_hash, chains,
            ethereum_index: reader.u8()?, reward_payer: reader.address()?,
            reward_token: reader.address()?, reward_per_claim: reader.bytes32()?,
            reward_token_decimals: reader.u8()?, max_withdrawals: reader.u32()?, max_rewards: reader.u32()?,
        };
        reader.finish()?; value.validate()?; Ok(value)
    }

    pub fn config_hash(&self) -> Result<Bytes32> { Ok(commit(Domain::Config, &self.encode()?)) }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositAggregateOpening {
    pub config_hash: Bytes32,
    pub window_id: Bytes32,
    pub end_checkpoint_id: u64,
    pub end_checkpoint_root: Hash4,
    pub starts: Vec<ChainStart>,
    pub deposits: Vec<DepositTransition>,
    pub deposit_leaves: Vec<DepositLeaf>,
}

impl DepositAggregateOpening {
    fn write(&self, writer: &mut Writer) -> Result<()> {
        writer.bytes32(self.config_hash)?; writer.bytes32(self.window_id)?;
        writer.u64(self.end_checkpoint_id)?; writer.hash4(self.end_checkpoint_root)?;
        writer.count(self.starts.len(), MAX_CHAINS)?;
        for start in &self.starts { start.write(writer)?; }
        writer.count(self.deposits.len(), MAX_CHAINS)?;
        for transition in &self.deposits { transition.write(writer)?; }
        writer.count(self.deposit_leaves.len(), DEPOSIT_RECORD_CAPACITY)?;
        for leaf in &self.deposit_leaves { leaf.write(writer)?; }
        Ok(())
    }
    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        let config_hash = reader.bytes32()?; let window_id = reader.bytes32()?;
        let end_checkpoint_id = reader.u64()?; let end_checkpoint_root = reader.hash4()?;
        let count = reader.count(MAX_CHAINS, 6)?;
        let mut starts = Vec::with_capacity(count);
        for _ in 0..count { starts.push(ChainStart::read(reader)?); }
        let count = reader.count(MAX_CHAINS, 11)?;
        let mut deposits = Vec::with_capacity(count);
        for _ in 0..count { deposits.push(DepositTransition::read(reader)?); }
        let count = reader.count(DEPOSIT_RECORD_CAPACITY, 7)?;
        let mut deposit_leaves = Vec::with_capacity(count);
        for _ in 0..count { deposit_leaves.push(DepositLeaf::read(reader)?); }
        let value = Self { config_hash, window_id, end_checkpoint_id, end_checkpoint_root,
            starts, deposits, deposit_leaves };
        value.validate_structure()?;
        Ok(value)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        let mut writer = Writer::new(); self.write(&mut writer)?; Ok(writer.0)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader(bytes); let value = Self::read(&mut reader)?;
        reader.finish()?; Ok(value)
    }
    fn validate_structure(&self) -> Result<()> {
        validate_hash4(&self.end_checkpoint_root)?;
        if self.starts.is_empty() || self.starts.len() > MAX_CHAINS
            || self.deposits.len() != self.starts.len() || self.deposit_leaves.len() > DEPOSIT_RECORD_CAPACITY
        { return Err(BridgeProofError::InvalidCount); }
        let mut position = 0usize;
        for (ordinal, (start, transition)) in self.starts.iter().zip(&self.deposits).enumerate() {
            validate_hash4(&start.start_checkpoint_root)?;
            validate_hash4(&transition.old_root)?; validate_hash4(&transition.new_root)?;
            if start.chain_index != transition.chain_index
                || (ordinal > 0 && self.starts[ordinal-1].chain_index >= start.chain_index)
            { return Err(BridgeProofError::InvalidOrdering); }
            if start.start_checkpoint_id > self.end_checkpoint_id
                || (start.start_checkpoint_id == self.end_checkpoint_id
                    && start.start_checkpoint_root != self.end_checkpoint_root)
            { return Err(BridgeProofError::InvalidCursor); }
            let count = transition.new_count.checked_sub(transition.old_count)
                .ok_or(BridgeProofError::InvalidDepositState)? as usize;
            if count > self.deposit_leaves.len() - position {
                return Err(BridgeProofError::InvalidCount);
            }
            if count == 0 && transition.old_root != transition.new_root {
                return Err(BridgeProofError::InvalidDepositState);
            }
            for (offset, leaf) in self.deposit_leaves[position..position+count].iter().enumerate() {
                if leaf.chain_index != transition.chain_index
                    || leaf.absolute_index != transition.old_count + offset as u32
                { return Err(BridgeProofError::InvalidDepositState); }
            }
            position += count;
        }
        if position != self.deposit_leaves.len() { return Err(BridgeProofError::InvalidCount); }
        if self.window_id != self.window_id()? { return Err(BridgeProofError::InvalidDepositState); }
        Ok(())
    }
    pub fn validate(&self, config: &NetworkConfig) -> Result<()> {
        config.validate()?; self.validate_structure()?;
        if self.config_hash != config.config_hash()? { return Err(BridgeProofError::InvalidConfig); }
        if self.starts.len() != config.chains.len() || self.deposit_leaves.len() > DEPOSIT_RECORD_CAPACITY {
            return Err(BridgeProofError::InvalidCount);
        }
        for (start, chain) in self.starts.iter().zip(&config.chains) {
            if start.chain_index != chain.chain_index { return Err(BridgeProofError::InvalidOrdering); }
            if start.start_checkpoint_id < chain.bootstrap_id
                || (start.start_checkpoint_id == chain.bootstrap_id && start.start_checkpoint_root != chain.bootstrap_root)
            { return Err(BridgeProofError::InvalidCursor); }
        }
        Ok(())
    }
    pub fn window_id(&self) -> Result<Bytes32> {
        let mut writer = Writer::new();
        writer.bytes32(self.config_hash)?; writer.u64(self.end_checkpoint_id)?;
        writer.hash4(self.end_checkpoint_root)?;
        writer.count(self.starts.len(), MAX_CHAINS)?;
        for start in &self.starts { start.write(&mut writer)?; }
        writer.count(self.deposits.len(), MAX_CHAINS)?;
        for transition in &self.deposits { transition.write(&mut writer)?; }
        Ok(commit(Domain::Window, &writer.0))
    }
}

#[cfg(test)]
mod deposit_leaf_tests {
    use super::*;

    #[test]
    fn range_encodes_only_two_canonical_words() {
        let range = DepositLeafRange { first_leaf: 1023, leaf_count: 1 };
        let bytes = [word(1023), word(1)].concat();
        assert_eq!(range.encode().unwrap(), bytes);
        assert_eq!(DepositLeafRange::decode(&bytes).unwrap(), range);
        let mut obsolete = bytes.clone(); obsolete.extend_from_slice(&[0; 32]);
        assert_eq!(DepositLeafRange::decode(&obsolete),
            Err(BridgeProofError::InvalidEncoding(EncodingError::TrailingBytes)));
        assert_eq!(DepositLeafRange::decode(&bytes[..32]),
            Err(BridgeProofError::InvalidEncoding(EncodingError::MissingBytes)));
        let mut wide = bytes; wide[27] = 1;
        assert_eq!(DepositLeafRange::decode(&wide),
            Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth)));
    }

}

impl DepositLeaf {
    pub fn poseidon_hash(&self) -> Result<Hash4> {
        let mut token = [0u8; 32];
        token[12..].copy_from_slice(&self.token);
        let mut words = [0u64; 41];
        for (index, value) in [&self.shield_address, &token, &self.l2_token_contract_id, &self.amount].into_iter().enumerate() {
            for (offset, bytes) in value.chunks_exact(4).enumerate() {
                words[index * 8 + offset] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
            }
        }
        words[32] = self.chain_index as u64;
        for (offset, bytes) in self.note_commitment.chunks_exact(4).enumerate() {
            words[33 + offset] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
        }
        deposit_poseidon(&words)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(chains: usize) -> NetworkConfig {
        NetworkConfig {
            version: 1, network_magic: 0, bridge_user_id: BRIDGE_USER_ID,
            circuit_set_hash: [7; 32],
            chains: (0..chains).map(|index| ChainConfig {
                chain_index: index as u8, chain_id: word(index as u64 + 1),
                bridge: [1; 20], state_manager: [2; 20], bootstrap_id: 0,
                bootstrap_root: [1, 2, 3, 4],
            }).collect(),
            ethereum_index: 0, reward_payer: [3; 20], reward_token: [4; 20],
            reward_per_claim: [1; 32], reward_token_decimals: 18,
            max_withdrawals: 1024, max_rewards: 1024,
        }
    }

    fn opening(config: &NetworkConfig, leaves: usize) -> DepositAggregateOpening {
        let mut a = DepositAggregateOpening {
            config_hash: config.config_hash().unwrap(), window_id: [0; 32],
            end_checkpoint_id: 1, end_checkpoint_root: [5, 6, 7, 8],
            starts: config.chains.iter().map(|chain| ChainStart {
                chain_index: chain.chain_index, start_checkpoint_id: 0,
                start_checkpoint_root: chain.bootstrap_root,
            }).collect(),
            deposits: config.chains.iter().enumerate().map(|(ordinal, chain)| DepositTransition {
                chain_index: chain.chain_index, old_root: [1, 2, 3, 4],
                new_root: if ordinal == 0 && leaves > 0 { [4, 3, 2, 1] } else { [1, 2, 3, 4] },
                old_count: 0, new_count: if ordinal == 0 { leaves as u32 } else { 0 },
            }).collect(),
            deposit_leaves: (0..leaves).map(|index| DepositLeaf {
                chain_index: config.chains[0].chain_index, absolute_index: index as u32,
                shield_address: [9; 32], token: [0; 20], l2_token_contract_id: word(1),
                amount: word(1), note_commitment: [8; 32],
            }).collect(),
        };
        a.window_id = a.window_id().unwrap(); a
    }

    #[test]
    fn rejects_width_felt_truncation_and_trailing_bytes() {
        let start = ChainStart { chain_index: 255, start_checkpoint_id: u64::MAX,
            start_checkpoint_root: [GOLDILOCKS_MODULUS-1, 0, 1, 2] };
        let bytes = start.encode().unwrap();
        assert_eq!(ChainStart::decode(&bytes).unwrap(), start);
        for length in 0..bytes.len() {
            assert!(matches!(ChainStart::decode(&bytes[..length]), Err(BridgeProofError::InvalidEncoding(EncodingError::MissingBytes))));
        }
        let mut mutated = bytes.clone(); mutated[30] = 1;
        assert_eq!(ChainStart::decode(&mutated), Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth)));
        let mut mutated = bytes.clone(); mutated[64..96].copy_from_slice(&word(GOLDILOCKS_MODULUS));
        assert_eq!(ChainStart::decode(&mutated), Err(BridgeProofError::InvalidEncoding(EncodingError::NoncanonicalFelt)));
        let mut mutated = bytes; mutated.push(0);
        assert_eq!(ChainStart::decode(&mutated), Err(BridgeProofError::InvalidEncoding(EncodingError::TrailingBytes)));
    }

    #[test]
    fn configuration_enforces_account_bounds_and_required_economics() {
        let config = config(256);
        let encoded = config.encode().unwrap();
        assert_eq!(encoded.len(), 384 + 288 * 256);
        assert_eq!(NetworkConfig::decode(&encoded).unwrap(), config);
        let mut changed = config.clone(); changed.bridge_user_id += 1;
        assert_eq!(changed.validate(), Err(BridgeProofError::InvalidConfig));
        let mut changed = config.clone(); changed.reward_per_claim = [0; 32];
        assert_eq!(changed.validate(), Err(BridgeProofError::InvalidConfig));
        let mut changed = config.clone(); changed.max_rewards = 1025;
        assert_eq!(changed.validate(), Err(BridgeProofError::InvalidConfig));
        let mut changed = config.clone(); changed.max_withdrawals = 1025;
        assert_eq!(changed.validate(), Err(BridgeProofError::InvalidConfig));
        let mut changed = config.clone(); changed.chains[1].chain_id = changed.chains[0].chain_id;
        assert_eq!(changed.validate(), Err(BridgeProofError::InvalidConfig));
        let mut bytes = encoded; bytes[128..160].copy_from_slice(&word(257));
        assert_eq!(NetworkConfig::decode(&bytes), Err(BridgeProofError::InvalidCount));
    }

    #[test]
    fn zero_odd_and_full_aggregates_hash_actual_leaves() {
        let network = config(1);
        for count in [0, 1, 31, 32] {
            let a = opening(&network, count);
            assert_eq!(DepositAggregateOpening::decode(&a.encode().unwrap()).unwrap(), a);
            if count > 0 {
                let mut mutated = a.clone();
                mutated.deposit_leaves[count - 1].note_commitment[0] ^= 1;
                assert_ne!(commit(Domain::DepositAggregate, &mutated.encode().unwrap()),
                    commit(Domain::DepositAggregate, &a.encode().unwrap()));
            }
        }
        assert!(opening(&network, DEPOSIT_RECORD_CAPACITY + 1).encode().is_err());
        let accepted = opening(&network, DEPOSIT_RECORD_CAPACITY);
        assert_eq!(accepted.encode().unwrap().len(), 320 + 544 + 224 * DEPOSIT_RECORD_CAPACITY);
        assert!(accepted.validate(&network).is_ok());
        let mut over_capacity = accepted.clone();
        over_capacity.deposit_leaves.push(DepositLeaf {
            chain_index: network.chains[0].chain_index, absolute_index: DEPOSIT_RECORD_CAPACITY as u32,
            shield_address: [9; 32], token: [0; 20], l2_token_contract_id: word(1),
            amount: word(1), note_commitment: [8; 32],
        });
        over_capacity.deposits[0].new_count = DEPOSIT_RECORD_CAPACITY as u32 + 1;
        over_capacity.deposits[0].new_root = [4, 3, 2, 1];
        over_capacity.window_id = over_capacity.window_id().unwrap();
        assert_eq!(over_capacity.validate(&network), Err(BridgeProofError::InvalidCount));
        let encoded = network.encode().unwrap();
        assert_eq!(encoded.len(), 384 + 288);
        let mut restored = encoded.clone();
        restored.splice(encoded.len() - 64..encoded.len() - 64, word(DEPOSIT_RECORD_CAPACITY as u64));
        assert_eq!(NetworkConfig::decode(&restored), Err(BridgeProofError::InvalidEncoding(EncodingError::TrailingBytes)));
    }

    #[test]
    fn complete_openings_reject_missing_foreign_rows_and_leaves() {
        let network = config(2);
        let a = opening(&network, 32);
        let mut missing = a.clone();
        missing.deposit_leaves.pop();
        assert_eq!(missing.validate(&network), Err(BridgeProofError::InvalidCount));
        let mut missing = a.clone();
        missing.starts.pop();
        missing.deposits.pop();
        missing.window_id = missing.window_id().unwrap();
        assert_eq!(missing.validate(&network), Err(BridgeProofError::InvalidCount));
    }

    #[test]
    fn aggregate_chunk_crosses_chain_boundary_without_restart() {
        let network = config(2);
        let mut a = opening(&network, 32);
        a.deposits[0].new_count = 31;
        a.deposits[1].new_count = 1;
        a.deposits[1].new_root = [8, 7, 6, 5];
        for (index, leaf) in a.deposit_leaves[31..].iter_mut().enumerate() {
            leaf.chain_index = 1;
            leaf.absolute_index = index as u32;
        }
        a.window_id = a.window_id().unwrap();
        a.deposit_leaves[31].absolute_index = 1;
        assert_eq!(a.validate(&network), Err(BridgeProofError::InvalidDepositState));
    }

}
