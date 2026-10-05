use tiny_keccak::{Hasher, Keccak};

pub type Hash4 = [u64; 4];
pub type Bytes32 = [u8; 32];
pub type Address = [u8; 20];
pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
pub const BRIDGE_USER_ID: u32 = 524288;
pub const MAX_CHAINS: usize = 256;
pub const MAX_LEAVES: usize = 1024;
pub const AGGREGATE_SIZE: usize = 32;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    Config, CircuitSet, DepositAggregate, WithdrawalAggregate, RewardAggregate, Aggregate, LeafCommit, Leaf, Node, Empty, Window, Reward,
    WithdrawalNonce,
}

pub fn domain_hash(domain: Domain) -> Bytes32 {
    let label: &[u8] = match domain {
    // b"A" and b"Record" are immutable wire-compatibility labels; do not rename these bytes.
        Domain::Config => b"Config", Domain::CircuitSet => b"CircuitSet",
        Domain::DepositAggregate => b"A", Domain::WithdrawalAggregate => b"WithdrawalBatch",
        Domain::RewardAggregate => b"RewardBatch", Domain::Aggregate => b"Batch",
        Domain::LeafCommit => b"Record", Domain::Leaf => b"Leaf", Domain::Node => b"Node",
        Domain::Empty => b"Empty", Domain::Window => b"Window", Domain::Reward => b"Reward",
        Domain::WithdrawalNonce => b"WithdrawalNonce",
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

// Concrete fixed-word wire structs only; arrays and opening validation remain explicit below.
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
wire_struct!(WithdrawalLeaf {
    chain_index: u8 => u8, sender_user_id: u32 => u32, recipient: Address => address,
    token: Address => address, amount: Bytes32 => bytes32, nonce: Bytes32 => bytes32,
});
wire_struct!(RewardLeaf {
    claim_checkpoint_id: u64 => u64, user_id: u32 => u32, height: u8 => u8,
    path_index: u32 => u32, nullifier_index: u32 => u32, recipient: Address => address,
});
wire_struct!(DepositLeafRange {
    first_leaf: u32 => u32, leaf_count: u32 => u32,
});
wire_struct!(CircuitSetEntry {
    family: u16 => u16, level: u8 => u8, variant: u8 => u8, pi_words: u16 => u16,
    fingerprint: Hash4 => hash4, common_digest: Bytes32 => bytes32,
    verifier_digest: Bytes32 => bytes32, identity_fingerprint: Hash4 => hash4,
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
    pub reward_cutover: u64,
    pub reward_end_exclusive: u64,
    pub max_deposits: u32,
    pub max_withdrawals: u32,
    pub max_rewards: u32,
}

impl NetworkConfig {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.bridge_user_id != BRIDGE_USER_ID
            || self.chains.is_empty() || self.chains.len() > MAX_CHAINS
            || self.reward_payer == [0; 20] || self.reward_token == [0; 20]
            || self.reward_per_claim == [0; 32] || self.reward_cutover >= self.reward_end_exclusive
            || [self.max_deposits, self.max_withdrawals, self.max_rewards].iter()
                .any(|&count| count as usize > MAX_LEAVES)
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
        writer.u8(self.reward_token_decimals)?; writer.u64(self.reward_cutover)?;
        writer.u64(self.reward_end_exclusive)?; writer.u32(self.max_deposits)?;
        writer.u32(self.max_withdrawals)?; writer.u32(self.max_rewards)?;
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
            reward_token_decimals: reader.u8()?, reward_cutover: reader.u64()?,
            reward_end_exclusive: reader.u64()?, max_deposits: reader.u32()?,
            max_withdrawals: reader.u32()?, max_rewards: reader.u32()?,
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
        writer.count(self.deposit_leaves.len(), MAX_LEAVES)?;
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
        let count = reader.count(MAX_LEAVES, 7)?;
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
            || self.deposits.len() != self.starts.len() || self.deposit_leaves.len() > MAX_LEAVES
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
        if self.starts.len() != config.chains.len() || self.deposit_leaves.len() > config.max_deposits as usize {
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
    pub fn opening_digest(&self, config: &NetworkConfig) -> Result<Bytes32> {
        self.validate(config)?;
        let mut writer = Writer::new();
        writer.bytes32(self.config_hash)?; writer.bytes32(self.window_id)?;
        writer.u64(self.end_checkpoint_id)?; writer.hash4(self.end_checkpoint_root)?;
        writer.count(self.starts.len(), MAX_CHAINS)?;
        for start in &self.starts { start.write(&mut writer)?; }
        writer.count(self.deposits.len(), MAX_CHAINS)?;
        for transition in &self.deposits { transition.write(&mut writer)?; }
        let leaves = self.deposit_leaves.len();
        let chunks = (leaves + AGGREGATE_SIZE - 1) / AGGREGATE_SIZE;
        writer.u32(leaves as u32)?; writer.u32(chunks as u32)?;
        writer.bytes32(deposit_aggregate_root(self)?)?;
        Ok(commit(Domain::DepositAggregate, &writer.0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WithdrawalAggregateOpening {
    pub config_hash: Bytes32,
    pub window_id: Bytes32,
    pub end_checkpoint_id: u64,
    pub end_checkpoint_root: Hash4,
    pub withdrawal_roots: Vec<Hash4>,
    pub withdrawals: Vec<WithdrawalLeaf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RewardAggregateOpening {
    pub config_hash: Bytes32,
    pub window_id: Bytes32,
    pub end_checkpoint_id: u64,
    pub end_checkpoint_root: Hash4,
    pub rewards: Vec<RewardLeaf>,
}

impl WithdrawalAggregateOpening {
    fn validate_structure(&self) -> Result<()> {
        validate_aggregate_context(self.end_checkpoint_root, self.withdrawals.len())?;
        if !(1..=MAX_CHAINS).contains(&self.withdrawal_roots.len()) {
            return Err(BridgeProofError::InvalidCount);
        }
        for root in &self.withdrawal_roots { validate_hash4(root)?; }
        for (i, leaf) in self.withdrawals.iter().enumerate() {
            leaf.validate()?;
            if i > 0 {
                let previous = &self.withdrawals[i - 1];
                if (previous.chain_index, previous.nonce) == (leaf.chain_index, leaf.nonce) {
                    return Err(BridgeProofError::DuplicateNullifier);
                }
                if (previous.chain_index, previous.nonce) > (leaf.chain_index, leaf.nonce) {
                    return Err(BridgeProofError::InvalidOrdering);
                }
            }
        }
        Ok(())
    }

    pub fn validate(&self, config: &NetworkConfig) -> Result<()> {
        validate_aggregate_config(config, self.config_hash, self.withdrawals.len(), config.max_withdrawals)?;
        self.validate_structure()?;
        if self.withdrawal_roots.len() != config.chains.len() {
            return Err(BridgeProofError::InvalidCount);
        }
        if self.withdrawals.iter().any(|leaf| !config.chains.iter().any(|chain| chain.chain_index == leaf.chain_index)) {
            return Err(BridgeProofError::InvalidConfig);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        let mut writer = Writer::new();
        writer.bytes32(self.config_hash)?; writer.bytes32(self.window_id)?;
        writer.u64(self.end_checkpoint_id)?; writer.hash4(self.end_checkpoint_root)?;
        writer.count(self.withdrawal_roots.len(), MAX_CHAINS)?;
        for root in &self.withdrawal_roots { writer.hash4(*root)?; }
        writer.count(self.withdrawals.len(), MAX_LEAVES)?;
        for leaf in &self.withdrawals { leaf.write_leaf(&mut writer)?; }
        Ok(writer.0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader(bytes);
        let config_hash = reader.bytes32()?;
        let window_id = reader.bytes32()?;
        let end_checkpoint_id = reader.u64()?;
        let end_checkpoint_root = reader.hash4()?;
        let chain_count = reader.count(MAX_CHAINS, 4)?;
        if chain_count == 0 { return Err(BridgeProofError::InvalidCount); }
        let mut withdrawal_roots = Vec::with_capacity(chain_count);
        for _ in 0..chain_count { withdrawal_roots.push(reader.hash4()?); }
        let count = reader.count(MAX_LEAVES, WithdrawalLeaf::LEAF_WORDS)?;
        let mut withdrawals = Vec::with_capacity(count);
        for _ in 0..count { withdrawals.push(WithdrawalLeaf::read_leaf(&mut reader)?); }
        reader.finish()?;
        let value = Self { config_hash, window_id, end_checkpoint_id, end_checkpoint_root,
            withdrawal_roots, withdrawals };
        value.validate_structure()?;
        Ok(value)
    }
    pub fn opening_digest(&self, config: &NetworkConfig) -> Result<Bytes32> {
        self.validate(config)?;
        Ok(hash_parts(&[&domain_hash(Domain::WithdrawalAggregate), &self.encode()?]))
    }
}

impl RewardAggregateOpening {
    fn validate_structure(&self) -> Result<()> {
        validate_aggregate_context(self.end_checkpoint_root, self.rewards.len())?;
        for (i, leaf) in self.rewards.iter().enumerate() {
            leaf.validate()?;
            if leaf.claim_checkpoint_id > self.end_checkpoint_id {
                return Err(BridgeProofError::InvalidCursor);
            }
            if i > 0 {
                let previous = &self.rewards[i - 1];
                let previous_key = (previous.claim_checkpoint_id, previous.nullifier_index);
                let key = (leaf.claim_checkpoint_id, leaf.nullifier_index);
                if previous_key == key { return Err(BridgeProofError::DuplicateNullifier); }
                if previous_key > key { return Err(BridgeProofError::InvalidOrdering); }
            }
        }
        Ok(())
    }

    pub fn validate(&self, config: &NetworkConfig) -> Result<()> {
        validate_aggregate_config(config, self.config_hash, self.rewards.len(), config.max_rewards)?;
        self.validate_structure()?;
        if self.rewards.iter().any(|leaf| leaf.claim_checkpoint_id < config.reward_cutover
            || leaf.claim_checkpoint_id >= config.reward_end_exclusive
            || leaf.recipient == config.reward_payer)
        { return Err(BridgeProofError::InvalidRewardAuthority); }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        encode_aggregate_opening(self.config_hash, self.window_id, self.end_checkpoint_id,
            self.end_checkpoint_root, &self.rewards)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (config_hash, window_id, end_checkpoint_id, end_checkpoint_root, rewards) =
            decode_aggregate_opening(bytes)?;
        let value = Self { config_hash, window_id, end_checkpoint_id, end_checkpoint_root, rewards };
        value.validate_structure()?;
        Ok(value)
    }
    pub fn opening_digest(&self, config: &NetworkConfig) -> Result<Bytes32> {
        self.validate(config)?;
        Ok(hash_parts(&[&domain_hash(Domain::RewardAggregate), &self.encode()?]))
    }
}

fn validate_aggregate_context(end_root: Hash4, leaves: usize) -> Result<()> {
    validate_hash4(&end_root)?;
    if leaves > MAX_LEAVES { return Err(BridgeProofError::InvalidCount); }
    Ok(())
}

fn validate_aggregate_config(config: &NetworkConfig, config_hash: Bytes32, leaves: usize, maximum: u32) -> Result<()> {
    config.validate()?;
    if config_hash != config.config_hash()? { return Err(BridgeProofError::InvalidConfig); }
    if leaves > maximum as usize { return Err(BridgeProofError::InvalidCount); }
    Ok(())
}

fn encode_aggregate_opening<R: AggregateLeaf>(config_hash: Bytes32, window_id: Bytes32, end_id: u64,
    end_root: Hash4, leaves: &[R]) -> Result<Vec<u8>>
{
    let mut writer = Writer::new();
    writer.bytes32(config_hash)?; writer.bytes32(window_id)?;
    writer.u64(end_id)?; writer.hash4(end_root)?;
    writer.count(leaves.len(), MAX_LEAVES)?;
    for leaf in leaves { leaf.write_leaf(&mut writer)?; }
    Ok(writer.0)
}

fn decode_aggregate_opening<R: AggregateLeaf>(bytes: &[u8]) -> Result<(Bytes32, Bytes32, u64, Hash4, Vec<R>)> {
    let mut reader = Reader(bytes);
    let config_hash = reader.bytes32()?;
    let window_id = reader.bytes32()?;
    let end_checkpoint_id = reader.u64()?;
    let end_checkpoint_root = reader.hash4()?;
    let count = reader.count(MAX_LEAVES, R::LEAF_WORDS)?;
    let mut leaves = Vec::with_capacity(count);
    for _ in 0..count { leaves.push(R::read_leaf(&mut reader)?); }
    reader.finish()?;
    Ok((config_hash, window_id, end_checkpoint_id, end_checkpoint_root, leaves))
}

trait AggregateLeaf: Sized {
    const LEAF_WORDS: usize;
    fn write_leaf(&self, writer: &mut Writer) -> Result<()>;
    fn read_leaf(reader: &mut Reader<'_>) -> Result<Self>;
}

impl AggregateLeaf for WithdrawalLeaf {
    const LEAF_WORDS: usize = 6;
    fn write_leaf(&self, writer: &mut Writer) -> Result<()> { self.write(writer) }
    fn read_leaf(reader: &mut Reader<'_>) -> Result<Self> { Self::read(reader) }
}

impl AggregateLeaf for RewardLeaf {
    const LEAF_WORDS: usize = 6;
    fn write_leaf(&self, writer: &mut Writer) -> Result<()> { self.write(writer) }
    fn read_leaf(reader: &mut Reader<'_>) -> Result<Self> { Self::read(reader) }
}

fn deposit_chunk_root(config_hash: Bytes32, end_id: u64, end_root: Hash4, leaves: &[DepositLeaf]) -> Result<Bytes32> {
    validate_hash4(&end_root)?;
    let chunks = (leaves.len() + AGGREGATE_SIZE - 1) / AGGREGATE_SIZE;
    let width = chunks.max(1).next_power_of_two();
    let mut nodes = Vec::with_capacity(width);
    for chunk in 0..width {
        if chunk >= chunks {
            nodes.push(hash_parts(&[&domain_hash(Domain::Empty), &word(1), &word(chunk as u64)]));
            continue;
        }
        let first = chunk * AGGREGATE_SIZE;
        let count = (leaves.len() - first).min(AGGREGATE_SIZE);
        let mut writer = Writer::new();
        writer.bytes32(config_hash)?; writer.u64(end_id)?; writer.hash4(end_root)?;
        writer.u64(1)?; writer.u32(chunk as u32)?; writer.u32(first as u32)?; writer.u32(count as u32)?;
        for leaf in &leaves[first..first + count] { leaf.write(&mut writer)?; }
        nodes.push(hash_parts(&[&domain_hash(Domain::Leaf), &word(1), &word(chunk as u64),
            &commit(Domain::Aggregate, &writer.0)]));
    }
    let mut level = 1u64;
    while nodes.len() > 1 {
        let parents = nodes.len() / 2;
        for index in 0..parents {
            nodes[index] = hash_parts(&[&domain_hash(Domain::Node), &word(level),
                &nodes[index * 2], &nodes[index * 2 + 1]]);
        }
        nodes.truncate(parents);
        level += 1;
    }
    Ok(nodes[0])
}

pub fn deposit_aggregate_root(a: &DepositAggregateOpening) -> Result<Bytes32> {
    a.validate_structure()?;
    deposit_chunk_root(a.config_hash, a.end_checkpoint_id, a.end_checkpoint_root, &a.deposit_leaves)
}

pub fn deposit_leaf_tree(leaf_commits: &[Bytes32]) -> Result<Vec<Bytes32>> {
    if leaf_commits.len() > MAX_LEAVES { return Err(BridgeProofError::InvalidCount); }
    let mut tree = vec![[0; 32]; 2 * MAX_LEAVES - 1];
    let marker = word(12);
    let count = word(leaf_commits.len() as u64);
    let leaf_domain = domain_hash(Domain::Leaf);
    let empty_domain = domain_hash(Domain::Empty);
    let node_domain = domain_hash(Domain::Node);
    for (ordinal, node) in tree[MAX_LEAVES-1..].iter_mut().enumerate() {
        let position = word(ordinal as u64);
        *node = if let Some(leaf) = leaf_commits.get(ordinal) {
            hash_parts(&[&leaf_domain, &marker, &count, &position, leaf])
        } else {
            hash_parts(&[&empty_domain, &marker, &count, &position])
        };
    }
    for level in 1..=10 {
        let first = (MAX_LEAVES >> level) - 1;
        let end = (MAX_LEAVES >> (level-1)) - 1;
        let level_word = word(level as u64);
        for index in first..end {
            tree[index] = hash_parts(&[&node_domain, &marker, &level_word,
                &tree[index*2+1], &tree[index*2+2]]);
        }
    }
    Ok(tree)
}

pub fn deposit_leaf_path(tree: &[Bytes32], count: u32, ordinal: u32) -> Result<[Bytes32; 10]> {
    if tree.len() != 2 * MAX_LEAVES - 1 || count > MAX_LEAVES as u32 || ordinal >= count {
        return Err(BridgeProofError::InvalidCount);
    }
    let mut path = [[0; 32]; 10];
    let mut index = MAX_LEAVES - 1 + ordinal as usize;
    for sibling in &mut path {
        *sibling = tree[if index % 2 == 1 { index+1 } else { index-1 }];
        index = (index-1) / 2;
    }
    Ok(path)
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

    #[test]
    fn tree_binds_domains_count_positions_and_padding() {
        let leaves = [word(77), word(77), word(99)];
        let tree = deposit_leaf_tree(&leaves).unwrap();
        for ordinal in 0..MAX_LEAVES {
            let expected = if ordinal < leaves.len() {
                hash_parts(&[&domain_hash(Domain::Leaf), &word(12), &word(3),
                    &word(ordinal as u64), &leaves[ordinal]])
            } else {
                hash_parts(&[&domain_hash(Domain::Empty), &word(12), &word(3), &word(ordinal as u64)])
            };
            assert_eq!(tree[MAX_LEAVES-1+ordinal], expected);
        }
        assert_ne!(tree[1023], tree[1024]);
        assert_ne!(tree[1026], tree[1027]);
        assert_ne!(tree[1023], hash_parts(&[&domain_hash(Domain::Leaf), &word(1), &word(3), &word(0), &leaves[0]]));
        assert_ne!(tree[1026], hash_parts(&[&domain_hash(Domain::Leaf), &word(12), &word(3), &word(3), &[0; 32]]));
        assert_eq!(tree[0], hash_parts(&[&domain_hash(Domain::Node), &word(12), &word(10), &tree[1], &tree[2]]));
        assert_ne!(tree[0], hash_parts(&[&domain_hash(Domain::Node), &word(6), &word(10), &tree[1], &tree[2]]));
        let shorter = deposit_leaf_tree(&leaves[..2]).unwrap();
        assert_ne!(tree[0], shorter[0]);
        assert_ne!(tree[1023], shorter[1023]);
        assert_ne!(tree[1027], shorter[1027]);
        let mut reordered = leaves; reordered.swap(0, 2);
        assert_ne!(tree[0], deposit_leaf_tree(&reordered).unwrap()[0]);
    }

    #[test]
    fn zero_partial_and_full_trees_have_exact_height_ten_paths() {
        for count in [0, 1, 33, 1024] {
            let leaves: Vec<_> = (0..count).map(|ordinal| word(ordinal as u64 + 1)).collect();
            let tree = deposit_leaf_tree(&leaves).unwrap();
            assert_eq!(tree.len(), 2047);
            for level in 1..=10 {
                let first = (MAX_LEAVES >> level) - 1;
                let end = (MAX_LEAVES >> (level-1)) - 1;
                for index in first..end {
                    assert_eq!(tree[index], hash_parts(&[&domain_hash(Domain::Node), &word(12),
                        &word(level as u64), &tree[2*index+1], &tree[2*index+2]]));
                }
            }
            if count == 0 {
                for ordinal in 0..MAX_LEAVES {
                    assert_eq!(tree[1023+ordinal], hash_parts(&[&domain_hash(Domain::Empty),
                        &word(12), &word(0), &word(ordinal as u64)]));
                }
            }
            for (ordinal, leaf) in leaves.iter().enumerate() {
                let path = deposit_leaf_path(&tree, count as u32, ordinal as u32).unwrap();
                let mut root = hash_parts(&[&domain_hash(Domain::Leaf), &word(12),
                    &word(count as u64), &word(ordinal as u64), leaf]);
                for (height, sibling) in path.iter().enumerate() {
                    let (left, right) = if (ordinal >> height) & 1 == 0 {
                        (&root, sibling)
                    } else { (sibling, &root) };
                    root = hash_parts(&[&domain_hash(Domain::Node), &word(12),
                        &word(height as u64 + 1), left, right]);
                }
                assert_eq!(root, tree[0]);
            }
            assert_eq!(deposit_leaf_path(&tree, count as u32, count as u32), Err(BridgeProofError::InvalidCount));
        }
    }

    #[test]
    fn path_and_tree_reject_invalid_counts_and_buffers() {
        assert_eq!(deposit_leaf_tree(&vec![[0; 32]; 1025]), Err(BridgeProofError::InvalidCount));
        let tree = deposit_leaf_tree(&[[1; 32]]).unwrap();
        for (count, ordinal) in [(0, 0), (1, 1), (1025, 0), (u32::MAX, 0), (1, u32::MAX)] {
            assert_eq!(deposit_leaf_path(&tree, count, ordinal), Err(BridgeProofError::InvalidCount));
        }
        assert_eq!(deposit_leaf_path(&[], 1, 0), Err(BridgeProofError::InvalidCount));
        assert_eq!(deposit_leaf_path(&tree[..2046], 1, 0), Err(BridgeProofError::InvalidCount));
        let mut oversized = tree; oversized.push([0; 32]);
        assert_eq!(deposit_leaf_path(&oversized, 1, 0), Err(BridgeProofError::InvalidCount));
    }

    #[test]
    fn registry_is_closed_eleven_entry_family_set() {
        let mut entries: Vec<CircuitSetEntry> = CIRCUIT_SET_FAMILIES.iter()
            .map(|&(family, level, variant, pi_words)| CircuitSetEntry {
                family, level, variant, pi_words,
                fingerprint: [1; 4], common_digest: [2; 32], verifier_digest: [3; 32],
                identity_fingerprint: if family == 4 { [4; 4] } else { [0; 4] },
            }).collect();
        assert_eq!(entries.len(), 11);
        let digest = circuit_set_hash(&entries).unwrap();
        let encoded = encode_circuit_set(&entries).unwrap();
        assert_eq!(decode_circuit_set(&encoded).unwrap(), entries);
        assert_eq!(commit(Domain::CircuitSet, &encoded), digest);
        let mut reader = Reader(&encoded);
        assert_eq!(reader.u32().unwrap(), 1);
        assert_eq!(reader.count(CIRCUIT_SET_FAMILIES.len(), 14).unwrap(), 11);
        for entry in &entries { assert_eq!(CircuitSetEntry::read(&mut reader).unwrap(), *entry); }
        reader.finish().unwrap();
        let mut trailing = encoded.clone(); trailing.push(0);
        assert_eq!(decode_circuit_set(&trailing),
            Err(BridgeProofError::InvalidEncoding(EncodingError::TrailingBytes)));
        assert_eq!(decode_circuit_set(&encoded[..encoded.len() - 1]),
            Err(BridgeProofError::InvalidEncoding(EncodingError::MissingBytes)));
        let mut unsupported = encoded.clone(); unsupported[..32].copy_from_slice(&word(2));
        assert_eq!(decode_circuit_set(&unsupported), Err(BridgeProofError::InvalidConfig));
        let mut noncanonical = encoded.clone(); noncanonical[32] = 1;
        assert_eq!(decode_circuit_set(&noncanonical),
            Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth)));
        for (family, level, variant) in [(1u16, 0u8, 0u8), (4, 0, 3), (7, 0, 2), (9, 0, 1), (11, 0, 1)] {
            let mut obsolete = entries.clone();
            let index = obsolete.iter().position(|entry| (entry.family, entry.level, entry.variant)
                == (family, level, variant)).unwrap();
            obsolete[index].pi_words += 1;
            assert_eq!(circuit_set_hash(&obsolete), Err(BridgeProofError::InvalidConfig));
        }
        let mut changed = entries.clone(); changed[0].fingerprint[0] += 1;
        assert_ne!(circuit_set_hash(&changed).unwrap(), digest);
        let mut duplicate = entries.clone(); duplicate[1] = duplicate[0].clone();
        assert_eq!(circuit_set_hash(&duplicate), Err(BridgeProofError::InvalidOrdering));
        let mut unordered = entries.clone(); unordered.swap(0, 1);
        assert_eq!(circuit_set_hash(&unordered), Err(BridgeProofError::InvalidOrdering));
        let mut missing = entries.clone(); missing.remove(0);
        assert_eq!(circuit_set_hash(&missing), Err(BridgeProofError::InvalidCount));
        let mut extra = entries.clone(); extra.push(extra[0].clone());
        extra.sort_by_key(|entry| (entry.family, entry.level, entry.variant));
        assert_eq!(circuit_set_hash(&extra), Err(BridgeProofError::InvalidCount));
        for removed in [(5u16, 0u8, 0u8), (6, 0, 0), (8, 1, 1), (10, 1, 1),
            (7, 0, 1), (7, 0, 129), (9, 0, 2), (11, 0, 2)] {
            let mut replaced = entries.clone();
            replaced[1] = CircuitSetEntry {
                family: removed.0, level: removed.1, variant: removed.2, pi_words: 12,
                fingerprint: [1; 4], common_digest: [2; 32], verifier_digest: [3; 32],
                identity_fingerprint: [0; 4],
            };
            replaced.sort_by_key(|entry| (entry.family, entry.level, entry.variant));
            assert_eq!(circuit_set_hash(&replaced), Err(BridgeProofError::InvalidConfig));
        }
        let mut zero_fingerprint = entries.clone(); zero_fingerprint[0].fingerprint = [0; 4];
        assert_eq!(circuit_set_hash(&zero_fingerprint), Err(BridgeProofError::InvalidConfig));
        let mut stray_identity = entries.clone(); stray_identity[0].identity_fingerprint = [4; 4];
        assert_eq!(circuit_set_hash(&stray_identity), Err(BridgeProofError::InvalidConfig));
        let mut noncanonical_felt = entries.clone();
        noncanonical_felt[0].fingerprint[0] = GOLDILOCKS_MODULUS;
        assert_eq!(circuit_set_hash(&noncanonical_felt),
            Err(BridgeProofError::InvalidEncoding(EncodingError::NoncanonicalFelt)));
    }
}

pub fn digest_inputs(digest: Bytes32) -> [u128; 2] {
    [u128::from_be_bytes(digest[..16].try_into().unwrap()),
        u128::from_be_bytes(digest[16..].try_into().unwrap())]
}
pub const USER_REWARD_PROOF_FIELD_COUNT: usize = 34;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserRewardProofFields {
    pub checkpoint_tree_root: Hash4,
    pub user_id: u32,
    pub recipient: [u32; 8],
    pub total_amount: [u32; 8],
    pub count: u32,
    pub jobs_commitment: Hash4,
    pub old_nullifier_root: Hash4,
    pub new_nullifier_root: Hash4,
}

impl UserRewardProofFields {
    pub fn from_public_inputs(inputs: &[u64]) -> Result<Self> {
        if inputs.len() != USER_REWARD_PROOF_FIELD_COUNT {
            return Err(BridgeProofError::InvalidProof);
        }
        let checkpoint_tree_root = read_hash4(inputs, 0)?;
        let user_id = read_u32(inputs[4])?;
        let mut recipient = [0u32; 8];
        for (index, limb) in recipient.iter_mut().enumerate() {
            *limb = read_u32(inputs[5 + index])?;
        }
        if recipient[5] != 0 || recipient[6] != 0 || recipient[7] != 0 {
            return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth));
        }
        let mut total_amount = [0u32; 8];
        for (index, limb) in total_amount.iter_mut().enumerate() {
            *limb = read_u32(inputs[13 + index])?;
        }
        let count = read_u32(inputs[21])?;
        let jobs_commitment = read_hash4(inputs, 22)?;
        let old_nullifier_root = read_hash4(inputs, 26)?;
        let new_nullifier_root = read_hash4(inputs, 30)?;
        Ok(Self { checkpoint_tree_root, user_id, recipient, total_amount, count,
            jobs_commitment, old_nullifier_root, new_nullifier_root })
    }

    pub fn to_public_inputs(&self) -> Result<[u64; USER_REWARD_PROOF_FIELD_COUNT]> {
        if self.recipient[5] != 0 || self.recipient[6] != 0 || self.recipient[7] != 0 {
            return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth));
        }
        let mut inputs = [0u64; USER_REWARD_PROOF_FIELD_COUNT];
        write_hash4(&mut inputs, 0, self.checkpoint_tree_root)?;
        inputs[4] = self.user_id as u64;
        for (index, limb) in self.recipient.iter().enumerate() { inputs[5 + index] = *limb as u64; }
        for (index, limb) in self.total_amount.iter().enumerate() { inputs[13 + index] = *limb as u64; }
        inputs[21] = self.count as u64;
        write_hash4(&mut inputs, 22, self.jobs_commitment)?;
        write_hash4(&mut inputs, 26, self.old_nullifier_root)?;
        write_hash4(&mut inputs, 30, self.new_nullifier_root)?;
        Ok(inputs)
    }
}

fn read_u32(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth))
}

fn read_hash4(inputs: &[u64], offset: usize) -> Result<Hash4> {
    let value = [inputs[offset], inputs[offset + 1], inputs[offset + 2], inputs[offset + 3]];
    validate_hash4(&value)?;
    Ok(value)
}

fn write_hash4(inputs: &mut [u64], offset: usize, value: Hash4) -> Result<()> {
    validate_hash4(&value)?;
    inputs[offset..offset + 4].copy_from_slice(&value);
    Ok(())
}
pub const WITHDRAWAL_PUBLICATION_FAMILY: u8 = 2;
pub const REWARD_PUBLICATION_FAMILY: u8 = 3;
pub const INCLUSION_AGGREGATE_CAPACITIES: [u32; 4] = [1024, 2048, 4096, 8192];
pub const CLAIM_TREE_MAX_CAPACITY: usize = 131072;
pub const CLAIM_TREE_MAX_DEPTH: u32 = 17;
pub const CUMULATIVE_REWARD_LEAF_BYTES: usize = 160;
pub const CUMULATIVE_REWARD_OPENING_CONTEXT_BYTES: usize = 256;
pub const WITHDRAWAL_HEADER_CONTEXT_BYTES: usize = 193;
pub const REWARD_HEADER_BYTES: usize = 257;
const PUBLICATION_DIGEST_WORDS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash4Encoding {
    CanonicalU64x4,
    LittleEndianU32x8,
}

pub fn read_hash4_encoding(words: &[u64], encoding: Hash4Encoding) -> Result<Hash4> {
    match encoding {
        Hash4Encoding::CanonicalU64x4 => {
            let value = words.try_into().map_err(|_| BridgeProofError::InvalidProof)?;
            validate_hash4(&value)?;
            Ok(value)
        }
        Hash4Encoding::LittleEndianU32x8 => {
            if words.len() != 8 { return Err(BridgeProofError::InvalidProof); }
            let mut value = [0u64; 4];
            for (limb, pair) in value.iter_mut().zip(words.chunks_exact(2)) {
                let low = read_u32(pair[0])? as u64;
                let high = read_u32(pair[1])? as u64;
                *limb = low | (high << 32);
            }
            validate_hash4(&value)?;
            Ok(value)
        }
    }
}

fn publication_domain(label: &[u8]) -> Bytes32 {
    hash_parts(&[b"PsyBridge/CumulativeReward/1/", label])
}

fn aggregate_header_domain() -> Bytes32 {
    hash_parts(&[b"PsyBridge/TwoArtifact/1/AggregateHeader"])
}

fn write_raw_u32(writer: &mut Writer, value: u32) {
    writer.0.extend_from_slice(&value.to_be_bytes());
}

fn write_raw_u64(writer: &mut Writer, value: u64) {
    writer.0.extend_from_slice(&value.to_be_bytes());
}

fn read_exact<'a>(bytes: &mut &'a [u8], width: usize) -> Result<&'a [u8]> {
    if bytes.len() < width { return Err(BridgeProofError::InvalidEncoding(EncodingError::MissingBytes)); }
    let (head, rest) = bytes.split_at(width);
    *bytes = rest;
    Ok(head)
}

fn read_raw_u32(bytes: &mut &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(read_exact(bytes, 4)?.try_into().unwrap()))
}

fn read_raw_u64(bytes: &mut &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(read_exact(bytes, 8)?.try_into().unwrap()))
}

fn read_raw_bytes32(bytes: &mut &[u8]) -> Result<Bytes32> {
    Ok(read_exact(bytes, 32)?.try_into().unwrap())
}

fn read_raw_address(bytes: &mut &[u8]) -> Result<Address> {
    let word = read_raw_bytes32(bytes)?;
    if word[..12].iter().any(|&byte| byte != 0) {
        return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth));
    }
    Ok(word[12..].try_into().unwrap())
}

fn read_canonical_hash4(bytes: &mut &[u8]) -> Result<Hash4> {
    read_hash4_encoding(&[read_raw_u64(bytes)?, read_raw_u64(bytes)?, read_raw_u64(bytes)?, read_raw_u64(bytes)?],
        Hash4Encoding::CanonicalU64x4)
}

fn checked_u32_mul(left: u32, right: u32) -> Result<u32> {
    left.checked_mul(right).ok_or(BridgeProofError::InvalidCount)
}

fn claim_tree_depth(aggregate_capacity: u32) -> Result<u32> {
    if aggregate_capacity == 0 || !aggregate_capacity.is_power_of_two()
        || aggregate_capacity > CLAIM_TREE_MAX_CAPACITY as u32
    { return Err(BridgeProofError::InvalidCount); }
    Ok(aggregate_capacity.trailing_zeros())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CumulativeRewardLeaf {
    pub economic_domain: Bytes32,
    pub user_id: u32,
    pub total_amount: [u32; 8],
    pub recipient: Address,
    pub initialized: bool,
}

impl CumulativeRewardLeaf {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if !self.initialized && self.recipient != [0; 20] {
            return Err(BridgeProofError::InvalidRewardAuthority);
        }
        let mut writer = Writer::new();
        writer.bytes32(self.economic_domain)?;
        writer.u32(self.user_id)?;
        for limb in self.total_amount.iter().rev() { writer.0.extend_from_slice(&limb.to_be_bytes()); }
        writer.address(self.recipient)?;
        writer.u64(u64::from(self.initialized))?;
        Ok(writer.0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != CUMULATIVE_REWARD_LEAF_BYTES {
            return Err(if bytes.len() < CUMULATIVE_REWARD_LEAF_BYTES {
                BridgeProofError::InvalidEncoding(EncodingError::MissingBytes)
            } else { BridgeProofError::InvalidEncoding(EncodingError::TrailingBytes) });
        }
        let mut reader = Reader(bytes);
        let economic_domain = reader.bytes32()?;
        let user_id = reader.u32()?;
        let amount = reader.bytes32()?;
        let mut total_amount = [0u32; 8];
        for (index, chunk) in amount.chunks_exact(4).rev().enumerate() { total_amount[index] = u32::from_be_bytes(chunk.try_into().unwrap()); }
        let recipient = reader.address()?;
        let initialized = match reader.u64()? { 0 => false, 1 => true, _ => {
            return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth));
        }};
        reader.finish()?;
        if !initialized && recipient != [0; 20] { return Err(BridgeProofError::InvalidRewardAuthority); }
        Ok(Self { economic_domain, user_id, total_amount, recipient, initialized })
    }

    pub fn leaf_commit(&self) -> Result<Bytes32> {
        Ok(hash_parts(&[&publication_domain(b"Record"), &self.encode()?]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CumulativeRewardOpening {
    pub config_hash: Bytes32,
    pub window_id: Bytes32,
    pub end_checkpoint_id: u64,
    pub end_checkpoint_root: Hash4,
    pub rewards: Vec<CumulativeRewardLeaf>,
}

impl CumulativeRewardOpening {
    fn validate_structure(&self) -> Result<()> {
        validate_hash4(&self.end_checkpoint_root)?;
        if self.rewards.len() > CLAIM_TREE_MAX_CAPACITY { return Err(BridgeProofError::InvalidCount); }
        for (index, leaf) in self.rewards.iter().enumerate() {
            if !leaf.initialized || leaf.recipient == [0; 20]
                || leaf.total_amount == [0; 8]
            { return Err(BridgeProofError::InvalidRewardAuthority); }
            if index > 0 && self.rewards[index - 1].user_id >= leaf.user_id {
                return Err(BridgeProofError::InvalidOrdering);
            }
            let _ = leaf.encode()?;
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_structure()?;
        let mut writer = Writer::new();
        writer.bytes32(self.config_hash)?;
        writer.bytes32(self.window_id)?;
        writer.u64(self.end_checkpoint_id)?;
        writer.hash4(self.end_checkpoint_root)?;
        writer.u32(self.rewards.len() as u32)?;
        for leaf in &self.rewards { writer.0.extend_from_slice(&leaf.encode()?); }
        Ok(writer.0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader(bytes);
        let config_hash = reader.bytes32()?;
        let window_id = reader.bytes32()?;
        let end_checkpoint_id = reader.u64()?;
        let end_checkpoint_root = reader.hash4()?;
        let count = reader.u32()? as usize;
        if count > CLAIM_TREE_MAX_CAPACITY { return Err(BridgeProofError::InvalidCount); }
        if reader.0.len() != count * CUMULATIVE_REWARD_LEAF_BYTES {
            return Err(if reader.0.len() < count * CUMULATIVE_REWARD_LEAF_BYTES {
                BridgeProofError::InvalidEncoding(EncodingError::MissingBytes)
            } else { BridgeProofError::InvalidEncoding(EncodingError::TrailingBytes) });
        }
        let mut rewards = Vec::with_capacity(count);
        for _ in 0..count {
            let (leaf_bytes, rest) = reader.0.split_at(CUMULATIVE_REWARD_LEAF_BYTES);
            reader.0 = rest;
            rewards.push(CumulativeRewardLeaf::decode(leaf_bytes)?);
        }
        reader.finish()?;
        let value = Self { config_hash, window_id, end_checkpoint_id, end_checkpoint_root, rewards };
        value.validate_structure()?;
        Ok(value)
    }

    pub fn opening_digest(&self) -> Result<Bytes32> {
        Ok(hash_parts(&[&publication_domain(b"Opening"), &self.encode()?]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionAggregateHeader {
    pub family: u8,
    pub config_hash: Bytes32,
    pub window_id: Bytes32,
    pub end_checkpoint_id: u64,
    pub end_checkpoint_root: Hash4,
    pub aggregate_capacity: u32,
    pub total_count: u32,
    pub segment_count: u32,
    pub segment_index: u32,
    pub first_ordinal: u32,
    pub count: u32,
    pub withdrawal_roots: Vec<Hash4>,
    pub old_nullifier_root: Option<Hash4>,
    pub new_nullifier_root: Option<Hash4>,
    pub opening_digest: Bytes32,
    pub claim_tree_root: Bytes32,
}

impl InclusionAggregateHeader {
    pub fn validate(&self) -> Result<()> {
        validate_hash4(&self.end_checkpoint_root)?;
        if !INCLUSION_AGGREGATE_CAPACITIES.contains(&self.aggregate_capacity) {
            return Err(BridgeProofError::InvalidCount);
        }
        let expected_segments = if self.total_count == 0 { 0 }
            else { self.total_count.div_ceil(self.aggregate_capacity) };
        if self.segment_count != expected_segments { return Err(BridgeProofError::InvalidCount); }
        if self.total_count == 0 {
            if self.segment_index != 0 || self.first_ordinal != 0 || self.count != 0
                || self.opening_digest != [0; 32] || self.claim_tree_root != [0; 32]
            { return Err(BridgeProofError::InvalidCount); }
        } else {
            if self.segment_index >= self.segment_count { return Err(BridgeProofError::InvalidCount); }
            let first = checked_u32_mul(self.segment_index, self.aggregate_capacity)?;
            if self.first_ordinal != first { return Err(BridgeProofError::InvalidCount); }
            let remaining = self.total_count - first;
            let expected_count = remaining.min(self.aggregate_capacity);
            if self.count == 0 || self.count != expected_count { return Err(BridgeProofError::InvalidCount); }
        }
        match self.family {
            WITHDRAWAL_PUBLICATION_FAMILY => {
                if !(1..=MAX_CHAINS).contains(&self.withdrawal_roots.len())
                    || self.old_nullifier_root.is_some() || self.new_nullifier_root.is_some()
                { return Err(BridgeProofError::InvalidCount); }
                for root in &self.withdrawal_roots { validate_hash4(root)?; }
            }
            REWARD_PUBLICATION_FAMILY => {
                let (Some(old_root), Some(new_root)) = (self.old_nullifier_root, self.new_nullifier_root) else {
                    return Err(BridgeProofError::InvalidCount);
                };
                if !self.withdrawal_roots.is_empty() { return Err(BridgeProofError::InvalidCount); }
                validate_hash4(&old_root)?;
                validate_hash4(&new_root)?;
                if self.total_count == 0 && old_root != new_root { return Err(BridgeProofError::InvalidCursor); }
            }
            _ => return Err(BridgeProofError::InvalidConfig),
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.0.push(self.family);
        writer.0.extend_from_slice(&self.config_hash);
        writer.0.extend_from_slice(&self.window_id);
        write_raw_u64(&mut writer, self.end_checkpoint_id);
        for limb in self.end_checkpoint_root { write_raw_u64(&mut writer, limb); }
        for value in [self.aggregate_capacity, self.total_count, self.segment_count,
            self.segment_index, self.first_ordinal, self.count]
        { write_raw_u32(&mut writer, value); }
        match self.family {
            WITHDRAWAL_PUBLICATION_FAMILY => {
                for root in &self.withdrawal_roots {
                    for limb in root { write_raw_u64(&mut writer, *limb); }
                }
            }
            REWARD_PUBLICATION_FAMILY => {
                for root in [self.old_nullifier_root.unwrap(), self.new_nullifier_root.unwrap()] {
                    for limb in root { write_raw_u64(&mut writer, limb); }
                }
            }
            _ => return Err(BridgeProofError::InvalidConfig),
        }
        writer.0.extend_from_slice(&self.opening_digest);
        writer.0.extend_from_slice(&self.claim_tree_root);
        Ok(writer.0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut rest = bytes;
        let family = *read_exact(&mut rest, 1)?.first().unwrap();
        let config_hash = read_raw_bytes32(&mut rest)?;
        let window_id = read_raw_bytes32(&mut rest)?;
        let end_checkpoint_id = read_raw_u64(&mut rest)?;
        let end_checkpoint_root = read_canonical_hash4(&mut rest)?;
        let aggregate_capacity = read_raw_u32(&mut rest)?;
        let total_count = read_raw_u32(&mut rest)?;
        let segment_count = read_raw_u32(&mut rest)?;
        let segment_index = read_raw_u32(&mut rest)?;
        let first_ordinal = read_raw_u32(&mut rest)?;
        let count = read_raw_u32(&mut rest)?;
        let (withdrawal_roots, old_nullifier_root, new_nullifier_root) = match family {
            WITHDRAWAL_PUBLICATION_FAMILY => {
                if rest.len() < 64 { return Err(BridgeProofError::InvalidEncoding(EncodingError::MissingBytes)); }
                let root_bytes = rest.len() - 64;
                let chain_count = root_bytes / 32;
                if !(1..=MAX_CHAINS).contains(&chain_count) { return Err(BridgeProofError::InvalidCount); }
                let mut roots = Vec::with_capacity(chain_count);
                for _ in 0..chain_count { roots.push(read_canonical_hash4(&mut rest)?); }
                (roots, None, None)
            }
            REWARD_PUBLICATION_FAMILY => {
                let old_root = read_canonical_hash4(&mut rest)?;
                let new_root = read_canonical_hash4(&mut rest)?;
                (Vec::new(), Some(old_root), Some(new_root))
            }
            _ => return Err(BridgeProofError::InvalidConfig),
        };
        let opening_digest = read_raw_bytes32(&mut rest)?;
        let claim_tree_root = read_raw_bytes32(&mut rest)?;
        if !rest.is_empty() { return Err(BridgeProofError::InvalidEncoding(EncodingError::TrailingBytes)); }
        let value = Self { family, config_hash, window_id, end_checkpoint_id, end_checkpoint_root,
            aggregate_capacity, total_count, segment_count, segment_index, first_ordinal, count,
            withdrawal_roots, old_nullifier_root, new_nullifier_root, opening_digest, claim_tree_root };
        value.validate()?;
        Ok(value)
    }

    pub fn header_digest(&self) -> Result<Bytes32> {
        Ok(hash_parts(&[&aggregate_header_domain(), &self.encode()?]))
    }

    pub fn publication_words(&self) -> Result<[u32; 28]> {
        let mut words = [0u32; 28];
        words[0] = 1;
        words[1] = 7;
        words[2] = self.family as u32;
        let mut offset = 4;
        for digest in [self.opening_digest, self.claim_tree_root, self.header_digest()?] {
            for chunk in digest.chunks_exact(4) {
                words[offset] = u32::from_be_bytes(chunk.try_into().unwrap());
                offset += 1;
            }
        }
        Ok(words)
    }
}

pub fn build_inclusion_aggregate_tree(leaf_commits: &[Bytes32], aggregate_capacity: usize) -> Result<Vec<Bytes32>> {
    let depth = claim_tree_depth(aggregate_capacity as u32)?;
    if aggregate_capacity > CLAIM_TREE_MAX_CAPACITY || leaf_commits.len() > aggregate_capacity {
        return Err(BridgeProofError::InvalidCount);
    }
    let mut tree = vec![[0; 32]; 2 * aggregate_capacity - 1];
    let marker = word(12);
    let count = word(leaf_commits.len() as u64);
    let leaf_domain = domain_hash(Domain::Leaf);
    let empty_domain = domain_hash(Domain::Empty);
    let node_domain = domain_hash(Domain::Node);
    for (ordinal, node) in tree[aggregate_capacity - 1..].iter_mut().enumerate() {
        let position = word(ordinal as u64);
        *node = if let Some(leaf) = leaf_commits.get(ordinal) {
            hash_parts(&[&leaf_domain, &marker, &count, &position, leaf])
        } else {
            hash_parts(&[&empty_domain, &marker, &count, &position])
        };
    }
    for level in 1..=depth {
        let first = (aggregate_capacity >> level) - 1;
        let end = (aggregate_capacity >> (level - 1)) - 1;
        let level_word = word(level as u64);
        for index in first..end {
            tree[index] = hash_parts(&[&node_domain, &marker, &level_word, &tree[index * 2 + 1], &tree[index * 2 + 2]]);
        }
    }
    Ok(tree)
}

pub fn claim_tree_path(tree: &[Bytes32], aggregate_capacity: u32, count: u32, ordinal: u32) -> Result<Vec<Bytes32>> {
    let depth = claim_tree_depth(aggregate_capacity)? as usize;
    if tree.len() != 2 * aggregate_capacity as usize - 1 || count > aggregate_capacity || ordinal >= count {
        return Err(BridgeProofError::InvalidCount);
    }
    let mut path = Vec::with_capacity(depth);
    let mut index = aggregate_capacity as usize - 1 + ordinal as usize;
    for _ in 0..depth {
        path.push(tree[if index % 2 == 1 { index + 1 } else { index - 1 }]);
        index = (index - 1) / 2;
    }
    Ok(path)
}

fn fold_claim_path(header: &InclusionAggregateHeader, leaf_commit: Bytes32, ordinal: u32, siblings: &[Bytes32]) -> Result<Bytes32> {
    let depth = claim_tree_depth(header.aggregate_capacity)?;
    if siblings.len() != depth as usize || ordinal >= header.count || header.count > header.aggregate_capacity {
        return Err(BridgeProofError::InvalidCount);
    }
    let marker = word(12);
    let count_word = word(header.count as u64);
    let mut state = hash_parts(&[&domain_hash(Domain::Leaf), &marker, &count_word, &word(ordinal as u64), &leaf_commit]);
    for (level, sibling) in siblings.iter().enumerate() {
        let level_word = word((level + 1) as u64);
        let (left, right) = if ordinal & (1 << level) == 0 { (&state, sibling) } else { (sibling, &state) };
        state = hash_parts(&[&domain_hash(Domain::Node), &marker, &level_word, left, right]);
    }
    Ok(state)
}

pub fn verify_claim_path(header: &InclusionAggregateHeader, ordinal: u32, leaf_bytes: &[u8], siblings: &[Bytes32]) -> Result<Bytes32> {
    header.validate()?;
    if ordinal >= header.count || siblings.len() != claim_tree_depth(header.aggregate_capacity)? as usize {
        return Err(BridgeProofError::InvalidCount);
    }
    let leaf_commit = match header.family {
        WITHDRAWAL_PUBLICATION_FAMILY => WithdrawalLeaf::decode(leaf_bytes)?.leaf_commit()?,
        REWARD_PUBLICATION_FAMILY => {
            let leaf = CumulativeRewardLeaf::decode(leaf_bytes)?;
            if !leaf.initialized || leaf.recipient == [0; 20] || leaf.total_amount == [0; 8] {
                return Err(BridgeProofError::InvalidRewardAuthority);
            }
            leaf.leaf_commit()?
        }
        _ => return Err(BridgeProofError::InvalidConfig),
    };
    let root = fold_claim_path(header, leaf_commit, ordinal, siblings)?;
    if root != header.claim_tree_root { return Err(BridgeProofError::InvalidProof); }
    Ok(leaf_commit)
}

pub fn publication_digest_words(digest: Bytes32) -> [u32; PUBLICATION_DIGEST_WORDS] {
    let mut words = [0u32; PUBLICATION_DIGEST_WORDS];
    for (word, chunk) in words.iter_mut().zip(digest.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    words
}
pub fn bind_claim_tree(header: &mut InclusionAggregateHeader, leaf_commits: &[Bytes32]) -> Result<Vec<Bytes32>> {
    header.validate()?;
    if leaf_commits.len() != header.count as usize { return Err(BridgeProofError::InvalidCount); }
    let tree = build_inclusion_aggregate_tree(leaf_commits, header.aggregate_capacity as usize)?;
    header.claim_tree_root = tree[0];
    header.validate()?;
    Ok(tree)
}


pub fn withdrawal_nonce(network_magic: u64, bridge_user_id: u32, token_contract_id: u32,
    sender_user_id: u32, destination_chain_index: u8, caller_nonce: Bytes32) -> Result<Bytes32>
{
    if bridge_user_id != BRIDGE_USER_ID { return Err(BridgeProofError::InvalidConfig); }
    Ok(hash_parts(&[&domain_hash(Domain::WithdrawalNonce), &word(network_magic),
        &word(bridge_user_id as u64), &word(token_contract_id as u64), &word(sender_user_id as u64),
        &word(destination_chain_index as u64), &caller_nonce]))
}

pub fn reward_nullifier_domain(config: &NetworkConfig) -> Result<Bytes32> {
    config.validate()?;
    let ethereum = config.chains.iter().find(|chain| chain.chain_index == config.ethereum_index)
        .ok_or(BridgeProofError::InvalidConfig)?;
    let mut writer = Writer::new(); writer.u32(1)?; writer.u64(config.network_magic)?;
    writer.u32(config.bridge_user_id)?; writer.bytes32(ethereum.chain_id)?;
    writer.u8(config.ethereum_index)?; writer.address(config.reward_payer)?; writer.address(config.reward_token)?;
    Ok(commit(Domain::Reward, &writer.0))
}

pub fn reward_nullifier(config: &NetworkConfig, leaf: &RewardLeaf) -> Result<Bytes32> {
    leaf.validate()?;
    Ok(hash_parts(&[&reward_nullifier_domain(config)?, &word(leaf.claim_checkpoint_id), &word(leaf.nullifier_index as u64)]))
}

impl DepositLeaf {
    pub fn leaf_commit(&self) -> Result<Bytes32> {
        Ok(hash_parts(&[&domain_hash(Domain::LeafCommit), &word(1), &self.encode()?]))
    }
}

impl WithdrawalLeaf {
    pub fn validate(&self) -> Result<()> {
        if self.recipient == [0; 20] || self.amount == [0; 32] || self.amount >= word(GOLDILOCKS_MODULUS) {
            return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth));
        }
        Ok(())
    }
    pub fn leaf_commit(&self) -> Result<Bytes32> {
        self.validate()?;
        Ok(hash_parts(&[&domain_hash(Domain::LeafCommit), &word(2), &self.encode()?]))
    }
}

impl RewardLeaf {
    pub fn validate(&self) -> Result<()> {
        if !(2..=21).contains(&self.height) || self.recipient == [0; 20] {
            return Err(BridgeProofError::InvalidRewardAuthority);
        }
        if self.path_index >= (1u32 << (self.height - 2))
            || self.nullifier_index != (1u32 << self.height) - 1 + self.path_index
        { return Err(BridgeProofError::InvalidRewardAuthority); }
        Ok(())
    }
    pub fn leaf_commit(&self) -> Result<Bytes32> {
        self.validate()?;
        Ok(hash_parts(&[&domain_hash(Domain::LeafCommit), &word(3), &self.encode()?]))
    }
}

const CIRCUIT_SET_FAMILIES: [(u16, u8, u8, u16); 11] = [
    (1, 0, 0, 40), (2, 0, 0, 32), (3, 0, 0, 28),
    (4, 0, 0, 30), (4, 0, 1, 30), (4, 0, 2, 30), (4, 0, 3, 30),
    (7, 0, 2, 12), (7, 0, 3, 12), (9, 0, 1, 37), (11, 0, 1, 12),
];

fn validate_circuit_set(entries: &[CircuitSetEntry]) -> Result<()> {
    // Every key in the closed family/level/variant table occurs exactly once, in order.
    if entries.len() != CIRCUIT_SET_FAMILIES.len() { return Err(BridgeProofError::InvalidCount); }
    for pair in entries.windows(2) {
        let previous = (pair[0].family, pair[0].level, pair[0].variant);
        let key = (pair[1].family, pair[1].level, pair[1].variant);
        if previous >= key { return Err(BridgeProofError::InvalidOrdering); }
    }
    for (entry, &(family, level, variant, pi_words)) in entries.iter().zip(&CIRCUIT_SET_FAMILIES) {
        if (entry.family, entry.level, entry.variant, entry.pi_words) != (family, level, variant, pi_words) {
            return Err(BridgeProofError::InvalidConfig);
        }
        if entry.fingerprint == [0; 4] || (entry.family == 4) != (entry.identity_fingerprint != [0; 4]) {
            return Err(BridgeProofError::InvalidConfig);
        }
        validate_hash4(&entry.fingerprint)?;
        validate_hash4(&entry.identity_fingerprint)?;
    }
    Ok(())
}

pub fn encode_circuit_set(entries: &[CircuitSetEntry]) -> Result<Vec<u8>> {
    validate_circuit_set(entries)?;
    let mut writer = Writer::new();
    writer.u32(1)?;
    writer.count(entries.len(), CIRCUIT_SET_FAMILIES.len())?;
    for entry in entries { entry.write(&mut writer)?; }
    Ok(writer.0)
}

pub fn decode_circuit_set(bytes: &[u8]) -> Result<Vec<CircuitSetEntry>> {
    let mut reader = Reader(bytes);
    if reader.u32()? != 1 { return Err(BridgeProofError::InvalidConfig); }
    let count = reader.count(CIRCUIT_SET_FAMILIES.len(), 14)?;
    let entries = (0..count).map(|_| CircuitSetEntry::read(&mut reader)).collect::<Result<Vec<_>>>()?;
    reader.finish()?;
    validate_circuit_set(&entries)?;
    Ok(entries)
}

pub fn circuit_set_hash(entries: &[CircuitSetEntry]) -> Result<Bytes32> {
    Ok(commit(Domain::CircuitSet, &encode_circuit_set(entries)?))
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
            reward_per_claim: word(1), reward_token_decimals: 0,
            reward_cutover: 0, reward_end_exclusive: 100,
            max_deposits: 1024, max_withdrawals: 1024, max_rewards: 1024,
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

    fn withdrawal_opening(config: &NetworkConfig, count: usize) -> WithdrawalAggregateOpening {
        WithdrawalAggregateOpening {
            config_hash: config.config_hash().unwrap(), window_id: [9; 32],
            end_checkpoint_id: 1, end_checkpoint_root: [5, 6, 7, 8],
            withdrawal_roots: config.chains.iter().map(|chain| [chain.chain_index as u64, 3, 4, 5]).collect(),
            withdrawals: (0..count).map(|index| WithdrawalLeaf {
                chain_index: 0, sender_user_id: 1, recipient: [1; 20], token: [0; 20],
                amount: word(1), nonce: word(index as u64),
            }).collect(),
        }
    }

    fn reward_opening(config: &NetworkConfig, count: usize) -> RewardAggregateOpening {
        RewardAggregateOpening {
            config_hash: config.config_hash().unwrap(), window_id: [9; 32],
            end_checkpoint_id: 1, end_checkpoint_root: [5, 6, 7, 8],
            rewards: (0..count).map(|index| RewardLeaf {
                claim_checkpoint_id: 1, user_id: 1, height: 12, path_index: index as u32,
                nullifier_index: 4095 + index as u32, recipient: [2; 20],
            }).collect(),
        }
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
        assert_eq!(NetworkConfig::decode(&config.encode().unwrap()).unwrap(), config);
        let mut changed = config.clone(); changed.bridge_user_id += 1;
        assert_eq!(changed.validate(), Err(BridgeProofError::InvalidConfig));
        let mut changed = config.clone(); changed.reward_per_claim = [0; 32];
        assert_eq!(changed.validate(), Err(BridgeProofError::InvalidConfig));
        let mut changed = config.clone(); changed.max_rewards = 1025;
        assert_eq!(changed.validate(), Err(BridgeProofError::InvalidConfig));
        let mut changed = config.clone(); changed.chains[1].chain_id = changed.chains[0].chain_id;
        assert_eq!(changed.validate(), Err(BridgeProofError::InvalidConfig));
        let mut bytes = config.encode().unwrap(); bytes[128..160].copy_from_slice(&word(257));
        assert_eq!(NetworkConfig::decode(&bytes), Err(BridgeProofError::InvalidCount));
    }

    fn reference_deposit_root(a: &DepositAggregateOpening) -> Bytes32 {
        let mut leaves: Vec<Bytes32> = a.deposit_leaves.chunks(32).enumerate().map(|(j, chunk)| {
            let mut body = Vec::new(); body.extend_from_slice(&domain_hash(Domain::Aggregate));
            body.extend_from_slice(&a.config_hash); body.extend_from_slice(&word(a.end_checkpoint_id));
            for limb in a.end_checkpoint_root { body.extend_from_slice(&word(limb)); }
            for value in [1, j as u64, (32*j) as u64, chunk.len() as u64] { body.extend_from_slice(&word(value)); }
            for leaf in chunk { body.extend_from_slice(&leaf.encode().unwrap()); }
            hash_parts(&[&domain_hash(Domain::Leaf), &word(1), &word(j as u64), &hash_parts(&[&body])])
        }).collect();
        let width = leaves.len().max(1).next_power_of_two();
        while leaves.len() < width {
            leaves.push(hash_parts(&[&domain_hash(Domain::Empty), &word(1), &word(leaves.len() as u64)]));
        }
        let mut level = 1;
        while leaves.len() > 1 {
            leaves = leaves.chunks_exact(2).map(|pair| hash_parts(&[&domain_hash(Domain::Node), &word(level), &pair[0], &pair[1]])).collect();
            level += 1;
        }
        leaves[0]
    }

    #[test]
    fn zero_odd_and_full_aggregates_hash_actual_leaves() {
        let network = config(1);
        for count in [0, 1, 31, 32, 33, 1024] {
            let a = opening(&network, count);
            assert_eq!(DepositAggregateOpening::decode(&a.encode().unwrap()).unwrap(), a);
            assert_eq!(deposit_aggregate_root(&a).unwrap(), reference_deposit_root(&a));
            let withdrawal = withdrawal_opening(&network, count);
            let reward = reward_opening(&network, count);
            assert_eq!(withdrawal.encode().unwrap().len(), 288 + 128 * network.chains.len() + 192 * count);
            assert_eq!(reward.encode().unwrap().len(), 256 + 192 * count);
            assert_eq!(WithdrawalAggregateOpening::decode(&withdrawal.encode().unwrap()).unwrap(), withdrawal);
            assert_eq!(RewardAggregateOpening::decode(&reward.encode().unwrap()).unwrap(), reward);
            assert_eq!(withdrawal.opening_digest(&network).unwrap(),
                hash_parts(&[&domain_hash(Domain::WithdrawalAggregate), &withdrawal.encode().unwrap()]));
            assert_eq!(reward.opening_digest(&network).unwrap(),
                hash_parts(&[&domain_hash(Domain::RewardAggregate), &reward.encode().unwrap()]));
            if count > 0 {
                let mut mutated = a.clone();
                mutated.deposit_leaves[count - 1].note_commitment[0] ^= 1;
                assert_ne!(mutated.opening_digest(&network).unwrap(), a.opening_digest(&network).unwrap());
                let mut mutated_withdrawal = withdrawal.clone();
                mutated_withdrawal.withdrawals[count - 1].amount = word(2);
                assert_ne!(mutated_withdrawal.opening_digest(&network).unwrap(), withdrawal.opening_digest(&network).unwrap());
                let mut mutated_reward = reward.clone();
                mutated_reward.rewards[count - 1].recipient = [6; 20];
                assert_ne!(mutated_reward.opening_digest(&network).unwrap(), reward.opening_digest(&network).unwrap());
            }
        }
        assert!(opening(&network, 1025).encode().is_err());
        assert!(withdrawal_opening(&network, 1025).encode().is_err());
        assert!(reward_opening(&network, 1025).encode().is_err());
    }

    #[test]
    fn withdrawal_roots_bind_configured_ordinals_and_exact_length() {
        let network = config(2);
        let opening = withdrawal_opening(&network, 0);
        assert!(opening.withdrawals.is_empty());
        assert_eq!(opening.withdrawal_roots.len(), 2);
        assert_eq!(opening.encode().unwrap().len(), 288 + 128 * 2);
        let mut empty_roots = opening.clone();
        empty_roots.withdrawal_roots.clear();
        assert_eq!(empty_roots.encode(), Err(BridgeProofError::InvalidCount));
        let mut wrong_count = opening.clone();
        wrong_count.withdrawal_roots.pop();
        assert_eq!(wrong_count.validate(&network), Err(BridgeProofError::InvalidCount));
        let mut noncanonical = opening.clone();
        noncanonical.withdrawal_roots[1][0] = GOLDILOCKS_MODULUS;
        assert_eq!(noncanonical.encode(),
            Err(BridgeProofError::InvalidEncoding(EncodingError::NoncanonicalFelt)));
        let mut too_many = opening.encode().unwrap();
        too_many[224..256].copy_from_slice(&word(257));
        assert_eq!(WithdrawalAggregateOpening::decode(&too_many), Err(BridgeProofError::InvalidCount));
        let mut zero_chains = opening.encode().unwrap();
        zero_chains[224..256].copy_from_slice(&word(0));
        assert_eq!(WithdrawalAggregateOpening::decode(&zero_chains), Err(BridgeProofError::InvalidCount));
        let mut trailing = opening.encode().unwrap();
        trailing.push(0);
        assert_eq!(WithdrawalAggregateOpening::decode(&trailing),
            Err(BridgeProofError::InvalidEncoding(EncodingError::TrailingBytes)));
    }

    #[test]
    fn aggregate_openings_reject_noncanonical_trailing_order_family_and_context() {
        let network = config(1);
        let withdrawal = withdrawal_opening(&network, 33);
        let reward = reward_opening(&network, 33);
        let withdrawal_bytes = withdrawal.encode().unwrap();
        let reward_bytes = reward.encode().unwrap();
        let mut noncanonical = withdrawal_bytes.clone();
        noncanonical[160..192].copy_from_slice(&word(GOLDILOCKS_MODULUS));
        assert_eq!(WithdrawalAggregateOpening::decode(&noncanonical),
            Err(BridgeProofError::InvalidEncoding(EncodingError::NoncanonicalFelt)));
        let mut trailing = withdrawal_bytes.clone();
        trailing.push(0);
        assert_eq!(WithdrawalAggregateOpening::decode(&trailing),
            Err(BridgeProofError::InvalidEncoding(EncodingError::TrailingBytes)));
        assert_eq!(WithdrawalAggregateOpening::decode(&withdrawal_bytes[..withdrawal_bytes.len() - 1]),
            Err(BridgeProofError::InvalidEncoding(EncodingError::MissingBytes)));
        assert!(RewardAggregateOpening::decode(&withdrawal_bytes).is_err());
        assert!(WithdrawalAggregateOpening::decode(&reward_bytes).is_err());
        let mut unordered_withdrawal = withdrawal.clone();
        unordered_withdrawal.withdrawals.swap(0, 1);
        assert_eq!(unordered_withdrawal.validate(&network), Err(BridgeProofError::InvalidOrdering));
        let mut unordered_reward = reward.clone();
        unordered_reward.rewards.swap(0, 1);
        assert_eq!(unordered_reward.validate(&network), Err(BridgeProofError::InvalidOrdering));
        let mut other_window = withdrawal.clone();
        other_window.window_id[0] ^= 1;
        assert_ne!(other_window.opening_digest(&network).unwrap(), withdrawal.opening_digest(&network).unwrap());
        let mut other_end = reward.clone();
        other_end.end_checkpoint_id += 1;
        assert_ne!(other_end.opening_digest(&network).unwrap(), reward.opening_digest(&network).unwrap());
        let mut other_config = network.clone();
        other_config.circuit_set_hash[0] ^= 1;
        assert_eq!(withdrawal.validate(&other_config), Err(BridgeProofError::InvalidConfig));
        assert_ne!(withdrawal.opening_digest(&network).unwrap(), reward.opening_digest(&network).unwrap());
    }

    #[test]
    fn aggregate_openings_reject_foreign_chain_and_payer_recipient() {
        let network = config(1);
        let mut foreign = withdrawal_opening(&network, 1);
        foreign.withdrawals[0].chain_index = 1;
        assert_eq!(foreign.validate(&network), Err(BridgeProofError::InvalidConfig));
        let mut payer = reward_opening(&network, 1);
        payer.rewards[0].recipient = network.reward_payer;
        assert_eq!(payer.validate(&network), Err(BridgeProofError::InvalidRewardAuthority));
        assert_ne!(withdrawal_opening(&network, 1).opening_digest(&network).unwrap(),
            reward_opening(&network, 1).opening_digest(&network).unwrap());
    }

    #[test]
    fn complete_openings_reject_missing_foreign_rows_and_leaves() {
        let network = config(2);
        let a = opening(&network, 33);
        let mut missing = a.clone();
        missing.deposit_leaves.pop();
        assert_eq!(missing.validate(&network), Err(BridgeProofError::InvalidCount));
        let mut missing = a.clone();
        missing.starts.pop();
        missing.deposits.pop();
        missing.window_id = missing.window_id().unwrap();
        assert_eq!(missing.validate(&network), Err(BridgeProofError::InvalidCount));
        let mut limited = network.clone();
        limited.max_withdrawals = 0;
        let above_cap = withdrawal_opening(&limited, 1);
        assert_eq!(above_cap.validate(&limited), Err(BridgeProofError::InvalidCount));
    }

    #[test]
    fn aggregate_chunk_crosses_chain_boundary_without_restart() {
        let network = config(2);
        let mut a = opening(&network, 33);
        a.deposits[0].new_count = 31;
        a.deposits[1].new_count = 2;
        a.deposits[1].new_root = [8, 7, 6, 5];
        for (index, leaf) in a.deposit_leaves[31..].iter_mut().enumerate() {
            leaf.chain_index = 1;
            leaf.absolute_index = index as u32;
        }
        a.window_id = a.window_id().unwrap();
        assert_eq!(deposit_aggregate_root(&a).unwrap(), reference_deposit_root(&a));
        a.deposit_leaves[31].absolute_index = 1;
        assert_eq!(a.validate(&network), Err(BridgeProofError::InvalidDepositState));
    }

    #[test]
    fn claims_reject_duplicate_keys_and_noncanonical_positions() {
        let network = config(1);
        let reward = RewardLeaf { claim_checkpoint_id: 1, user_id: 0, height: 2,
            path_index: 0, nullifier_index: 3, recipient: [1; 20] };
        let mut rewards = reward_opening(&network, 0);
        rewards.rewards = vec![reward.clone(), reward.clone()];
        rewards.rewards[1].recipient = [2; 20];
        assert_eq!(rewards.validate(&network), Err(BridgeProofError::DuplicateNullifier));
        let mut changed = reward.clone();
        changed.path_index = 1;
        changed.nullifier_index = 4;
        assert_eq!(changed.validate(), Err(BridgeProofError::InvalidRewardAuthority));
        let highest = RewardLeaf { height: 21, path_index: (1 << 19) - 1,
            nullifier_index: (1 << 21) - 1 + (1 << 19) - 1, ..reward };
        assert!(highest.validate().is_ok());
        let withdrawal = WithdrawalLeaf { chain_index: 0, sender_user_id: 1,
            recipient: [1; 20], token: [0; 20], amount: word(1), nonce: [0; 32] };
        let mut withdrawals = withdrawal_opening(&network, 0);
        withdrawals.withdrawals = vec![withdrawal.clone(), withdrawal.clone()];
        withdrawals.withdrawals[1].sender_user_id = 2;
        assert_eq!(withdrawals.validate(&network), Err(BridgeProofError::DuplicateNullifier));
        let changed = WithdrawalLeaf { amount: word(GOLDILOCKS_MODULUS), ..withdrawal };
        assert!(changed.validate().is_err());
    }

    #[test]
    fn window_excludes_claims_aggregate_digest_binds_leaves() {
        let network = config(1);
        let a = opening(&network, 0);
        let mut reward = reward_opening(&network, 0);
        reward.window_id = a.window_id;
        let before = reward.opening_digest(&network).unwrap();
        reward.rewards.push(RewardLeaf { claim_checkpoint_id: 1, user_id: 1,
            height: 2, path_index: 0, nullifier_index: 3, recipient: [5; 20] });
        assert_eq!(a.window_id().unwrap(), a.window_id);
        assert_ne!(reward.opening_digest(&network).unwrap(), before);
        let mut other_config = network.clone();
        other_config.circuit_set_hash[0] ^= 1;
        assert_eq!(reward_nullifier_domain(&network).unwrap(), reward_nullifier_domain(&other_config).unwrap());
        assert_ne!(network.config_hash().unwrap(), other_config.config_hash().unwrap());
        let halves = digest_inputs([1; 32]);
        assert_eq!(halves, [u128::from_be_bytes([1; 16]); 2]);
    }

    #[test]
    fn withdrawal_nonce_separates_user_contract_and_destination() {
        let nonce = withdrawal_nonce(1, BRIDGE_USER_ID, 2, 3, 4, [5; 32]).unwrap();
        assert_ne!(withdrawal_nonce(1, BRIDGE_USER_ID, 9, 3, 4, [5; 32]).unwrap(), nonce);
        assert_ne!(withdrawal_nonce(1, BRIDGE_USER_ID, 2, 9, 4, [5; 32]).unwrap(), nonce);
        assert_ne!(withdrawal_nonce(1, BRIDGE_USER_ID, 2, 3, 9, [5; 32]).unwrap(), nonce);
        assert_eq!(withdrawal_nonce(1, 0, 2, 3, 4, [5; 32]), Err(BridgeProofError::InvalidConfig));
    }
    fn user_reward_proof() -> UserRewardProofFields {
        UserRewardProofFields {
            checkpoint_tree_root: [1, 2, 3, GOLDILOCKS_MODULUS - 1],
            user_id: u32::MAX,
            recipient: [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, 0x5555_5555, 0, 0, 0],
            total_amount: [7, 1, 0, 0, 0, 0, 0, 0],
            count: 3,
            jobs_commitment: [9, 8, 7, 6],
            old_nullifier_root: [4, 3, 2, 1],
            new_nullifier_root: [5, 4, 3, 2],
        }
    }

    #[test]
    fn user_reward_proof_fields_keep_exact_offsets_and_uint256_limbs() {
        let proof = user_reward_proof();
        let inputs = proof.to_public_inputs().unwrap();
        assert_eq!(inputs.len(), 34);
        assert_eq!(&inputs[0..4], &proof.checkpoint_tree_root);
        assert_eq!(inputs[4], proof.user_id as u64);
        assert_eq!(&inputs[5..13], &proof.recipient.map(|limb| limb as u64));
        assert_eq!(&inputs[13..21], &[7, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(inputs[21], 3);
        assert_eq!(&inputs[22..26], &proof.jobs_commitment);
        assert_eq!(&inputs[26..30], &proof.old_nullifier_root);
        assert_eq!(&inputs[30..34], &proof.new_nullifier_root);
        assert_eq!(UserRewardProofFields::from_public_inputs(&inputs).unwrap(), proof);
        let full = UserRewardProofFields { total_amount: [u32::MAX; 8], ..proof };
        let full_inputs = full.to_public_inputs().unwrap();
        assert_eq!(&full_inputs[13..21], &[u32::MAX as u64; 8]);
        assert_eq!(full_inputs[13], u32::MAX as u64);
        assert!(full_inputs[13] < GOLDILOCKS_MODULUS);
        assert_eq!(UserRewardProofFields::from_public_inputs(&full_inputs).unwrap().total_amount, [u32::MAX; 8]);
    }

    #[test]
    fn user_reward_proof_fields_reject_invalid_ranges_and_width() {
        let proof = user_reward_proof();
        let inputs = proof.to_public_inputs().unwrap();
        assert_eq!(UserRewardProofFields::from_public_inputs(&inputs[..33]), Err(BridgeProofError::InvalidProof));
        assert_eq!(UserRewardProofFields::from_public_inputs(&[inputs.as_slice(), &[0]].concat()), Err(BridgeProofError::InvalidProof));
        for index in [0, 22, 26, 30] {
            let mut noncanonical = inputs;
            noncanonical[index] = GOLDILOCKS_MODULUS;
            assert_eq!(UserRewardProofFields::from_public_inputs(&noncanonical),
                Err(BridgeProofError::InvalidEncoding(EncodingError::NoncanonicalFelt)));
        }
        for index in [4, 5, 13, 21] {
            let mut wide = inputs;
            wide[index] = u32::MAX as u64 + 1;
            assert_eq!(UserRewardProofFields::from_public_inputs(&wide),
                Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth)));
        }
        for index in [10, 11, 12] {
            let mut padded = inputs;
            padded[index] = 1;
            assert_eq!(UserRewardProofFields::from_public_inputs(&padded),
                Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth)));
            let mut encoded = proof;
            encoded.recipient[index - 5] = 1;
            assert_eq!(encoded.to_public_inputs(),
                Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth)));
        }
        let mut modulus_amount = inputs;
        modulus_amount[13] = GOLDILOCKS_MODULUS;
        assert_eq!(UserRewardProofFields::from_public_inputs(&modulus_amount),
            Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth)));
    }
    fn cumulative_leaf(user_id: u32) -> CumulativeRewardLeaf {
        CumulativeRewardLeaf { economic_domain: [9; 32], user_id, total_amount: [1500, 0, 0, 0, 0, 0, 0, 0],
            recipient: [0x11; 20], initialized: true }
    }

    fn reward_header(count: u32, capacity: u32) -> InclusionAggregateHeader {
        let total = if count == 0 { 0 } else { count + capacity };
        InclusionAggregateHeader {
            family: REWARD_PUBLICATION_FAMILY, config_hash: [4; 32], window_id: [5; 32],
            end_checkpoint_id: 1200, end_checkpoint_root: [5, 6, 7, 8], aggregate_capacity: capacity,
            total_count: total, segment_count: if total == 0 { 0 } else { total.div_ceil(capacity) },
            segment_index: if count == 0 { 0 } else { 1 }, first_ordinal: if count == 0 { 0 } else { capacity },
            count, withdrawal_roots: Vec::new(), old_nullifier_root: Some([1, 2, 3, 4]),
            new_nullifier_root: Some(if count == 0 { [1, 2, 3, 4] } else { [8, 7, 6, 5] }),
            opening_digest: if count == 0 { [0; 32] } else { [6; 32] }, claim_tree_root: [0; 32],
        }
    }

    #[test]
    fn cumulative_reward_record_is_five_canonical_words() {
        let leaf = cumulative_leaf(7);
        let bytes = leaf.encode().unwrap();
        assert_eq!(bytes.len(), CUMULATIVE_REWARD_LEAF_BYTES);
        assert_eq!(&bytes[..32], &[9; 32]);
        assert_eq!(&bytes[32..64], &word(7));
        assert_eq!(&bytes[64..96], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05, 0xdc]);
        assert!(bytes[96..108].iter().all(|&byte| byte == 0));
        assert_eq!(&bytes[108..128], &[0x11; 20]);
        assert_eq!(&bytes[128..160], &word(1));
        assert_eq!(CumulativeRewardLeaf::decode(&bytes).unwrap(), leaf);
        assert_eq!(leaf.leaf_commit().unwrap(), hash_parts(&[&hash_parts(&[b"PsyBridge/CumulativeReward/1/Record"]), &bytes]));
        assert_ne!(leaf.leaf_commit().unwrap(), hash_parts(&[&domain_hash(Domain::LeafCommit), &word(3), &bytes]));
        for mutation in [0usize, 63, 95, 127, 159] {
            let mut changed = bytes.clone();
            changed[mutation] ^= 1;
            assert!(CumulativeRewardLeaf::decode(&changed).is_err()
                || CumulativeRewardLeaf::decode(&changed).unwrap().leaf_commit().unwrap() != leaf.leaf_commit().unwrap());
        }
        let mut uninitialized = leaf;
        uninitialized.initialized = false;
        uninitialized.recipient = [0; 20];
        uninitialized.total_amount = [0; 8];
        assert_eq!(uninitialized.encode().unwrap()[159], 0);
        assert!(CumulativeRewardOpening { config_hash: [4; 32], window_id: [5; 32], end_checkpoint_id: 1,
            end_checkpoint_root: [1, 2, 3, 4], rewards: vec![uninitialized] }.encode().is_err());
    }
    #[test]
    fn cumulative_opening_roundtrips_ordered_one_hundred_sixty_byte_leaves() {
        let opening = CumulativeRewardOpening { config_hash: [4; 32], window_id: [5; 32], end_checkpoint_id: 1200,
            end_checkpoint_root: [5, 6, 7, 8], rewards: vec![cumulative_leaf(7), cumulative_leaf(8)] };
        let bytes = opening.encode().unwrap();
        assert_eq!(bytes.len(), CUMULATIVE_REWARD_OPENING_CONTEXT_BYTES + CUMULATIVE_REWARD_LEAF_BYTES * 2);
        assert_eq!(CumulativeRewardOpening::decode(&bytes).unwrap(), opening);
        assert_eq!(opening.opening_digest().unwrap(), hash_parts(&[&hash_parts(&[b"PsyBridge/CumulativeReward/1/Opening"]), &bytes]));
        assert_ne!(opening.opening_digest().unwrap(), hash_parts(&[&domain_hash(Domain::RewardAggregate), &bytes]));
        let mut reversed = opening.clone();
        reversed.rewards.reverse();
        assert!(reversed.encode().is_err());
    }
    #[test]
    fn packed_headers_reject_wrong_family_width_and_byte_order() {
        let reward = reward_header(1, 1024);
        let mut bound = reward.clone();
        let commits = [cumulative_leaf(7).leaf_commit().unwrap()];
        bind_claim_tree(&mut bound, &commits).unwrap();
        let bytes = bound.encode().unwrap();
        assert_eq!(bytes.len(), REWARD_HEADER_BYTES);
        assert_eq!(InclusionAggregateHeader::decode(&bytes).unwrap(), bound);
        assert_eq!(bound.header_digest().unwrap(), hash_parts(&[&hash_parts(&[b"PsyBridge/TwoArtifact/1/AggregateHeader"]), &bytes]));
        let words = bound.publication_words().unwrap();
        assert_eq!(&words[..4], &[1, 7, 3, 0]);
        assert_eq!(&words[4..12], publication_digest_words(bound.opening_digest).as_slice());
        assert_eq!(&words[12..20], publication_digest_words(bound.claim_tree_root).as_slice());
        assert_eq!(&words[20..28], publication_digest_words(bound.header_digest().unwrap()).as_slice());
        let mut digest = [0u8; 32];
        digest[0] = 1;
        digest[31] = 2;
        bound.opening_digest = digest;
        let bytes = bound.encode().unwrap();
        let words = bound.publication_words().unwrap();
        assert_eq!(words[4], 0x0100_0000);
        assert_eq!(words[11], 2);
        assert_ne!(words[4], u32::from_le_bytes(digest[..4].try_into().unwrap()));
        let mut short = bytes.clone(); short.pop();
        assert_eq!(InclusionAggregateHeader::decode(&short), Err(BridgeProofError::InvalidEncoding(EncodingError::MissingBytes)));
        let mut long = bytes.clone(); long.push(0);
        assert_eq!(InclusionAggregateHeader::decode(&long), Err(BridgeProofError::InvalidEncoding(EncodingError::TrailingBytes)));
        let mut family = bytes.clone(); family[0] = 4;
        assert_eq!(InclusionAggregateHeader::decode(&family), Err(BridgeProofError::InvalidConfig));
        let mut felt = bytes.clone();
        felt[73..81].copy_from_slice(&GOLDILOCKS_MODULUS.to_be_bytes());
        assert_eq!(InclusionAggregateHeader::decode(&felt), Err(BridgeProofError::InvalidEncoding(EncodingError::NoncanonicalFelt)));
        let mut paired = [0u64; 8];
        paired[0] = 1; paired[1] = 2;
        assert_eq!(read_hash4_encoding(&paired, Hash4Encoding::LittleEndianU32x8).unwrap(), [1 + (2 << 32), 0, 0, 0]);
        assert!(read_hash4_encoding(&paired[..4], Hash4Encoding::LittleEndianU32x8).is_err());
        assert!(read_hash4_encoding(&[GOLDILOCKS_MODULUS, 0, 0, 0], Hash4Encoding::CanonicalU64x4).is_err());
        let mut withdrawal = bound.clone();
        withdrawal.family = WITHDRAWAL_PUBLICATION_FAMILY;
        withdrawal.withdrawal_roots = vec![[1, 2, 3, 4]; 256];
        withdrawal.old_nullifier_root = None; withdrawal.new_nullifier_root = None;
        let withdrawal_bytes = withdrawal.encode().unwrap();
        assert_eq!(withdrawal_bytes.len(), WITHDRAWAL_HEADER_CONTEXT_BYTES + 32 * 256);
        assert_eq!(InclusionAggregateHeader::decode(&withdrawal_bytes).unwrap().withdrawal_roots.len(), 256);
        let mut one_chain = withdrawal.clone();
        one_chain.withdrawal_roots.truncate(1);
        assert_eq!(one_chain.encode().unwrap().len(), WITHDRAWAL_HEADER_CONTEXT_BYTES + 32);
        let mut zero_roots = one_chain.encode().unwrap();
        zero_roots.drain(WITHDRAWAL_HEADER_CONTEXT_BYTES..WITHDRAWAL_HEADER_CONTEXT_BYTES + 32);
        assert_eq!(InclusionAggregateHeader::decode(&zero_roots), Err(BridgeProofError::InvalidCount));
        let mut excess_roots = withdrawal.encode().unwrap();
        excess_roots.splice(WITHDRAWAL_HEADER_CONTEXT_BYTES..WITHDRAWAL_HEADER_CONTEXT_BYTES, [0; 32]);
        assert_eq!(InclusionAggregateHeader::decode(&excess_roots), Err(BridgeProofError::InvalidCount));
        assert!(reward_header(0, 1024).encode().unwrap().ends_with(&[0; 64]));
        assert!(reward_header(1023, 1024).encode().is_ok());
        assert!(reward_header(1024, 1024).encode().is_ok());
        assert!(reward_header(1025, 1024).encode().is_err());
        assert!(build_inclusion_aggregate_tree(&[], 1).is_ok());
        assert!(build_inclusion_aggregate_tree(&[], 131072).is_ok());
        assert_eq!(build_inclusion_aggregate_tree(&[], 1 << 18), Err(BridgeProofError::InvalidCount));
    }

    #[test]
    fn claim_path_rejects_wrong_leaf_index_count_root_and_padding() {
        let leaves = [cumulative_leaf(7), cumulative_leaf(8)];
        let commits = [leaves[0].leaf_commit().unwrap(), leaves[1].leaf_commit().unwrap()];
        let mut header = reward_header(2, 1024);
        let tree = bind_claim_tree(&mut header, &commits).unwrap();
        let path = claim_tree_path(&tree, 1024, 2, 0).unwrap();
        assert_eq!(path.len(), 10);
        assert_eq!(verify_claim_path(&header, 0, &leaves[0].encode().unwrap(), &path).unwrap(), commits[0]);
        let other = claim_tree_path(&tree, 1024, 2, 1).unwrap();
        assert_eq!(verify_claim_path(&header, 1, &leaves[1].encode().unwrap(), &other).unwrap(), commits[1]);
        assert_eq!(verify_claim_path(&header, 0, &leaves[1].encode().unwrap(), &path), Err(BridgeProofError::InvalidProof));
        assert_eq!(verify_claim_path(&header, 1, &leaves[1].encode().unwrap(), &path), Err(BridgeProofError::InvalidProof));
        assert_eq!(verify_claim_path(&header, 2, &leaves[0].encode().unwrap(), &path), Err(BridgeProofError::InvalidCount));
        assert_eq!(verify_claim_path(&header, 1024, &leaves[0].encode().unwrap(), &path), Err(BridgeProofError::InvalidCount));
        let mut count = header.clone(); count.count = 1;
        assert!(count.validate().is_err());
        let mut root = header.clone(); root.claim_tree_root[0] ^= 1;
        assert_eq!(verify_claim_path(&root, 0, &leaves[0].encode().unwrap(), &path), Err(BridgeProofError::InvalidProof));
        let mut family = header.clone(); family.family = 9;
        assert_eq!(family.validate(), Err(BridgeProofError::InvalidConfig));
        let empty = hash_parts(&[&domain_hash(Domain::Empty), &word(12), &word(2), &word(2)]);
        assert_eq!(tree[1025], empty);
        assert_eq!(tree[1023], hash_parts(&[&domain_hash(Domain::Leaf), &word(12), &word(2), &word(0), &commits[0]]));
        let mut short = path.clone(); short.pop();
        assert_eq!(verify_claim_path(&header, 0, &leaves[0].encode().unwrap(), &short), Err(BridgeProofError::InvalidCount));
        let mut amount = leaves[0].clone();
        amount.total_amount[0] = 1501;
        let changed = amount.encode().unwrap();
        assert_eq!(changed.len(), CUMULATIVE_REWARD_LEAF_BYTES);
        assert_eq!(CumulativeRewardLeaf::decode(&changed).unwrap(), amount);
        assert_eq!(verify_claim_path(&header, 0, &changed, &path), Err(BridgeProofError::InvalidProof));
    }

}
