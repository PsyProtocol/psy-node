use tiny_keccak::{Hasher, Keccak};

pub type Hash4 = [u64; 4];
pub type Bytes32 = [u8; 32];
pub type Address = [u8; 20];
pub const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
pub const BRIDGE_USER_ID: u32 = 524288;
pub const MAX_CHAINS: usize = 256;
pub const MAX_LEAVES: usize = 1024;


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
    Config, CircuitSet, LeafCommit, Reward,
}

pub fn domain_hash(domain: Domain) -> Bytes32 {
    let label: &[u8] = match domain {
    // b"A" and b"Record" are immutable wire-compatibility labels; do not rename these bytes.
        Domain::Config => b"Config",
        Domain::CircuitSet => b"CircuitSet",
        Domain::LeafCommit => b"Record",
        Domain::Reward => b"Reward",
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

wire_struct!(CircuitSetRegistration {
    family: u16 => u16, level: u8 => u8, variant: u8 => u8, pi_words: u16 => u16,
    fingerprint: Hash4 => hash4, common_digest: Bytes32 => bytes32,
    verifier_digest: Bytes32 => bytes32, identity_fingerprint: Hash4 => hash4,
});

const CIRCUIT_SET_KEYS: [(u16, u8, u8); 10] = [
    (11, 0, 1), (14, 0, 0), (14, 0, 1), (15, 0, 0), (16, 0, 0),
    (17, 0, 0), (18, 0, 0), (19, 0, 1), (19, 0, 2), (20, 0, 0),
];

fn validate_circuit_set(registrations: &[CircuitSetRegistration]) -> Result<()> {
    if registrations.len() != CIRCUIT_SET_KEYS.len() { return Err(BridgeProofError::InvalidCount); }
    let chain_count = (1..=8).find(|&count| registrations[0].pi_words as usize == 27 + 17 * count + 39 * 32)
        .ok_or(BridgeProofError::InvalidConfig)?;
    let widths = [27 + 17 * chain_count + 39 * 32, 90, 22, 30, 1029, 2574, 3846,
        18 + 5 * chain_count, 18 + 5 * chain_count, 8316 + 128 * chain_count];
    for pair in registrations.windows(2) {
        if (pair[0].family, pair[0].level, pair[0].variant) >= (pair[1].family, pair[1].level, pair[1].variant) {
            return Err(BridgeProofError::InvalidOrdering);
        }
    }
    for ((row, key), width) in registrations.iter().zip(CIRCUIT_SET_KEYS).zip(widths) {
        if (row.family, row.level, row.variant) != key || usize::from(row.pi_words) != width
            || row.fingerprint == [0; 4] || row.identity_fingerprint != [0; 4] {
            return Err(BridgeProofError::InvalidConfig);
        }
        validate_hash4(&row.fingerprint)?;
        validate_hash4(&row.identity_fingerprint)?;
    }
    Ok(())
}

pub fn encode_circuit_set(registrations: &[CircuitSetRegistration]) -> Result<Vec<u8>> {
    validate_circuit_set(registrations)?;
    let mut writer = Writer::new();
    writer.u32(2)?;
    writer.count(registrations.len(), CIRCUIT_SET_KEYS.len())?;
    for row in registrations { row.write(&mut writer)?; }
    Ok(writer.0)
}

pub fn decode_circuit_set(bytes: &[u8]) -> Result<Vec<CircuitSetRegistration>> {
    let mut reader = Reader(bytes);
    if reader.u32()? != 2 { return Err(BridgeProofError::InvalidConfig); }
    let count = reader.count(CIRCUIT_SET_KEYS.len(), 14)?;
    let rows = (0..count).map(|_| CircuitSetRegistration::read(&mut reader)).collect::<Result<Vec<_>>>()?;
    reader.finish()?;
    validate_circuit_set(&rows)?;
    Ok(rows)
}

pub fn circuit_set_hash(registrations: &[CircuitSetRegistration]) -> Result<Bytes32> {
    Ok(commit(Domain::CircuitSet, &encode_circuit_set(registrations)?))
}

#[derive(Clone, Debug)]
pub struct AggregateSetupConfig {
    pub config: NetworkConfig,
    pub registrations: Vec<CircuitSetRegistration>,
}

impl AggregateSetupConfig {
    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Sources {
            node_source: String, native_source: String, plonky2_source: String, wrapper_source: String,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Encoded {
            network_config: String,
            circuit_set: String,
            sources: Sources,
            #[serde(default)]
            withdrawal_policies: serde::de::IgnoredAny,
        }
        let encoded: Encoded = serde_json::from_slice(bytes)?;
        let _ = encoded.withdrawal_policies;
        for source in [&encoded.sources.node_source, &encoded.sources.native_source,
            &encoded.sources.plonky2_source, &encoded.sources.wrapper_source] {
            let (value, width) = source.strip_prefix("local:").map_or((source.as_str(), 40), |value| (value, 64));
            anyhow::ensure!(value.len() == width && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "invalid reviewed source identity");
        }
        let canonical_hex = |text: &str| -> anyhow::Result<Vec<u8>> {
            anyhow::ensure!(text.len() % 2 == 0 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "setup bytes must be lowercase canonical hex without 0x");
            Ok(hex::decode(text)?)
        };
        let config = NetworkConfig::decode(&canonical_hex(&encoded.network_config)?)?;
        let registrations = decode_circuit_set(&canonical_hex(&encoded.circuit_set)?)?;
        anyhow::ensure!(circuit_set_hash(&registrations)? == config.circuit_set_hash, "operator circuit registry differs from configuration");
        Ok(Self { config, registrations })
    }
}

pub fn load_aggregate_setup_config(path: &std::path::Path) -> anyhow::Result<AggregateSetupConfig> {
    AggregateSetupConfig::decode(&std::fs::read(path)?)
}

wire_struct!(ChainConfig {
    chain_index: u8 => u8, chain_id: Bytes32 => bytes32, bridge: Address => address,
    state_manager: Address => address, bootstrap_id: u64 => u64, bootstrap_root: Hash4 => hash4,
});

wire_struct!(RewardLeaf {
    claim_checkpoint_id: u64 => u64, user_id: u32 => u32, height: u8 => u8,
    path_index: u32 => u32, nullifier_index: u32 => u32, recipient: Address => address,
});

pub const BRIDGE_OPENING_VERSION: u32 = 4;
pub const BRIDGE_OPENING_CHAIN_CAPACITY: usize = 8;
pub const BRIDGE_RECORD_CAPACITY: usize = 32;
pub const BRIDGE_OPENING_MAX_BYTES: usize = 37_344;
pub const BRIDGE_REWARD_CONTRACT_ID: u32 = 7;
pub const REWARD_CLAIM_BYTES: usize = 480;
pub const REWARD_ROOT_STATEMENT_LEN: usize = 30;
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
    pub chain_index: u8,
    pub user_id: u32,
    pub contract_id: u32,
    pub old_nullifier_root: Hash4,
    pub new_nullifier_root: Hash4,
    pub count: u32,
    pub recipient: Address,
    pub amount: Bytes32,
}

impl RewardClaim {
    pub fn from_public_inputs(chain_index: u8, inputs: &[u64; REWARD_ROOT_STATEMENT_LEN]) -> Result<Self> {
        let user_id = read_u32(inputs[0])?;
        let mut recipient_limbs = [0u32; 8];
        for (index, limb) in recipient_limbs.iter_mut().enumerate() { *limb = read_u32(inputs[1 + index])?; }
        if recipient_limbs[5] != 0 || recipient_limbs[6] != 0 || recipient_limbs[7] != 0 {
            return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth));
        }
        let old_nullifier_root = read_hash4(inputs, 9)?;
        let new_nullifier_root = read_hash4(inputs, 13)?;
        let count = read_u32(inputs[17])?;
        let mut amount = [0u8; 32];
        for index in 0..8 {
            amount[28 - index * 4..32 - index * 4].copy_from_slice(&read_u32(inputs[18 + index])?.to_be_bytes());
        }
        let _anchor = read_hash4(inputs, 26)?;
        let mut recipient = [0u8; 20];
        for index in 0..5 { recipient[16 - index * 4..20 - index * 4].copy_from_slice(&recipient_limbs[index].to_be_bytes()); }
        let value = Self { chain_index, user_id, contract_id: BRIDGE_REWARD_CONTRACT_ID,
            old_nullifier_root, new_nullifier_root, count, recipient, amount };
        value.validate()?;
        Ok(value)
    }

    fn write(&self, writer: &mut Writer) -> Result<()> {
        self.validate()?;
        writer.u8(2)?; writer.u8(self.chain_index)?; writer.u32(self.user_id)?;
        writer.u32(self.contract_id)?;
        writer.hash4(self.old_nullifier_root)?; writer.hash4(self.new_nullifier_root)?;
        writer.u32(self.count)?; writer.address(self.recipient)?; writer.bytes32(self.amount)
    }

    fn read(reader: &mut Reader<'_>) -> Result<Self> {
        if reader.u8()? != 2 { return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth)); }
        let value = Self { chain_index: reader.u8()?, user_id: reader.u32()?, contract_id: reader.u32()?,
            old_nullifier_root: reader.hash4()?, new_nullifier_root: reader.hash4()?,
            count: reader.u32()?, recipient: reader.address()?, amount: reader.bytes32()? };
        value.validate()?; Ok(value)
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new(); self.write(&mut writer)?;
        if writer.0.len() != REWARD_CLAIM_BYTES { return Err(BridgeProofError::InvalidCount); }
        Ok(writer.0)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != REWARD_CLAIM_BYTES {
            return Err(BridgeProofError::InvalidEncoding(if bytes.len() < REWARD_CLAIM_BYTES { EncodingError::MissingBytes } else { EncodingError::TrailingBytes }));
        }
        let mut reader = Reader(bytes); let value = Self::read(&mut reader)?; reader.finish()?; Ok(value)
    }
    fn validate(&self) -> Result<()> {
        validate_hash4(&self.old_nullifier_root)?; validate_hash4(&self.new_nullifier_root)?;
        if self.contract_id != BRIDGE_REWARD_CONTRACT_ID || self.amount == [0; 32] || self.recipient == [0; 20]
        { return Err(BridgeProofError::InvalidEncoding(EncodingError::InvalidWidth)); }
        Ok(())
    }
}

pub fn packed_root(value: Hash4) -> Result<Bytes32> {
    validate_hash4(&value)?;
    let high = (u128::from(value[0]) << 64) | u128::from(value[1]);
    let low = (u128::from(value[2]) << 64) | u128::from(value[3]);
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&high.to_be_bytes());
    bytes[16..].copy_from_slice(&low.to_be_bytes());
    Ok(bytes)
}
pub fn claim_context_id(config_hash: Bytes32, end_checkpoint_id: u32, end_checkpoint_root: Hash4) -> Result<Bytes32> {
    validate_hash4(&end_checkpoint_root)?;
    let mut body = Vec::with_capacity(192);
    body.extend_from_slice(&hash_parts(&[b"PsyBridge/ClaimContext/4"]));
    body.extend_from_slice(&config_hash);
    body.extend_from_slice(&word(end_checkpoint_id as u64));
    for limb in end_checkpoint_root { body.extend_from_slice(&word(limb)); }
    Ok(hash_parts(&[&body]))
}


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


#[cfg(test)]
mod setup_tests {
    use super::*;

    fn rows() -> Vec<CircuitSetRegistration> {
        CIRCUIT_SET_KEYS.into_iter().zip([1292, 90, 22, 30, 1029, 2574, 3846, 23, 23, 8444])
            .map(|((family, level, variant), pi_words)| CircuitSetRegistration {
                family, level, variant, pi_words, fingerprint: [1; 4], common_digest: [2; 32],
                verifier_digest: [3; 32], identity_fingerprint: [0; 4],
            }).collect()
    }

    fn setup() -> serde_json::Value {
        let config = NetworkConfig {
            version: 1, network_magic: 1, bridge_user_id: BRIDGE_USER_ID,
            circuit_set_hash: circuit_set_hash(&rows()).unwrap(),
            chains: vec![ChainConfig { chain_index: 0, chain_id: [1; 32], bridge: [1; 20],
                state_manager: [2; 20], bootstrap_id: 0, bootstrap_root: [0; 4] }],
            ethereum_index: 0, reward_payer: [3; 20], reward_token: [4; 20],
            reward_per_claim: word(1), reward_token_decimals: 18, max_withdrawals: 32, max_rewards: 32,
        };
        serde_json::json!({
            "network_config": hex::encode(config.encode().unwrap()),
            "circuit_set": hex::encode(encode_circuit_set(&rows()).unwrap()),
            "sources": { "node_source": "1".repeat(40), "native_source": "2".repeat(40),
                "plonky2_source": "3".repeat(40), "wrapper_source": "4".repeat(40) },
            "withdrawal_policies": [{"opaque_archive_metadata": true}]
        })
    }

    #[test]
    fn registry_preserves_all_archive_words_and_domain() {
        let rows = rows();
        let encoded = encode_circuit_set(&rows).unwrap();
        assert_eq!(encoded.len(), 32 * (2 + 10 * 14));
        assert_eq!(&encoded[..32], &word(2));
        assert_eq!(&encoded[32..64], &word(10));
        assert_eq!(decode_circuit_set(&encoded).unwrap(), rows);
        assert_eq!(circuit_set_hash(&rows).unwrap(), hash_parts(&[
            &hash_parts(&[b"PsyBridge/TwoArtifact/1/CircuitSet"]), &encoded,
        ]));
        for offset in [3, 4, 8, 9, 10] {
            let mut altered = encoded.clone();
            altered[(2 + offset) * 32 + 31] ^= 1;
            assert_ne!(altered, encoded);
            if let Ok(decoded) = decode_circuit_set(&altered) {
                assert_ne!(circuit_set_hash(&decoded).unwrap(), circuit_set_hash(&rows).unwrap());
            }
        }
        let mut trailing = encoded.clone(); trailing.push(0);
        assert!(decode_circuit_set(&trailing).is_err());
        assert!(decode_circuit_set(&encoded[..encoded.len() - 1]).is_err());
        let mut reordered = rows.clone(); reordered.swap(1, 2);
        assert!(encode_circuit_set(&reordered).is_err());
        let mut noncanonical = rows; noncanonical[0].fingerprint[0] = GOLDILOCKS_MODULUS;
        assert!(encode_circuit_set(&noncanonical).is_err());
    }

    #[test]
    fn approved_setup_rejects_missing_mismatched_and_noncanonical_registry() {
        let decode = |value: &serde_json::Value| AggregateSetupConfig::decode(&serde_json::to_vec(value).unwrap());
        let approved = setup();
        assert_eq!(decode(&approved).unwrap().registrations, rows());
        let mut missing = approved.clone(); missing.as_object_mut().unwrap().remove("circuit_set");
        assert!(decode(&missing).is_err());
        let mut changed = rows(); changed[0].common_digest[0] ^= 1;
        let mut mismatch = approved.clone(); mismatch["circuit_set"] = hex::encode(encode_circuit_set(&changed).unwrap()).into();
        assert!(decode(&mismatch).is_err());
        let mut prefixed = approved.clone(); prefixed["network_config"] = format!("0x{}", approved["network_config"].as_str().unwrap()).into();
        assert!(decode(&prefixed).is_err());
        let mut unknown = approved; unknown["circuit_registry"] = "unused".into();
        assert!(decode(&unknown).is_err());
    }
}
