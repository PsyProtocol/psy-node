use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{target::{BoolTarget, Target}, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};
use psy_client_data::bridge_aggregate::{ChainConfig, NetworkConfig, BRIDGE_USER_ID, MAX_CHAINS, MAX_RECORDS};
use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;

use super::aggregate_commitment::{
    commitment, encode_hash4, word, word_address, word_u64, AddressTarget,
    Bytes32Target, Domain, Hash4Target, U64Target,
};

#[derive(Clone, Debug)]
pub struct ChainConfigTarget {
    pub chain_index: Target,
    pub chain_id: Bytes32Target,
    pub bridge: AddressTarget,
    pub state_manager: AddressTarget,
    pub bootstrap_id: U64Target,
    pub bootstrap_root: Hash4Target,
}

impl ChainConfigTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let value = Self {
            chain_index: builder.add_virtual_target(),
            chain_id: builder.add_virtual_target_arr(),
            bridge: builder.add_virtual_target_arr(),
            state_manager: builder.add_virtual_target_arr(),
            bootstrap_id: builder.add_virtual_target_arr(),
            bootstrap_root: builder.add_virtual_target_arr(),
        };
        builder.range_check(value.chain_index, 8);
        for target in value.chain_id.iter().chain(&value.bridge).chain(&value.state_manager).chain(&value.bootstrap_id) {
            builder.range_check(*target, 32);
        }
        assert_nonzero(builder, &value.chain_id);
        assert_nonzero(builder, &value.bridge);
        assert_nonzero(builder, &value.state_manager);
        value
    }

    pub fn encode<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> {
        let mut words = Vec::with_capacity(72);
        words.extend(word(builder, self.chain_index, 8));
        words.extend(self.chain_id);
        words.extend(word_address(builder, self.bridge));
        words.extend(word_address(builder, self.state_manager));
        words.extend(word_u64(builder, self.bootstrap_id));
        words.extend(encode_hash4(builder, self.bootstrap_root));
        words
    }

    pub fn set_witness<F: RichField, W: WitnessWrite<F>>(&self, witness: &mut W, config: &ChainConfig) -> anyhow::Result<()> {
        anyhow::ensure!(config.bootstrap_root.iter().all(|&limb| limb < F::ORDER), "noncanonical bootstrap root");
        witness.set_target(self.chain_index, F::from_canonical_u32(config.chain_index as u32))?;
        set_bytes(witness, &self.chain_id, &config.chain_id)?;
        set_bytes(witness, &self.bridge, &config.bridge)?;
        set_bytes(witness, &self.state_manager, &config.state_manager)?;
        set_u64(witness, self.bootstrap_id, config.bootstrap_id)?;
        for (target, limb) in self.bootstrap_root.iter().zip(config.bootstrap_root) {
            witness.set_target(*target, F::from_canonical_u64(limb))?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct NetworkConfigTarget {
    pub version: Target,
    pub network_magic: U64Target,
    pub bridge_user_id: Target,
    pub circuit_set_hash: Bytes32Target,
    pub chains: Vec<ChainConfigTarget>,
    pub ethereum_index: Target,
    pub reward_payer: AddressTarget,
    pub reward_token: AddressTarget,
    pub reward_per_claim: Bytes32Target,
    pub reward_token_decimals: Target,
    pub reward_cutover: U64Target,
    pub reward_end_exclusive: U64Target,
    pub max_deposits: Target,
    pub max_withdrawals: Target,
    pub max_rewards: Target,
}

impl NetworkConfigTarget {
    pub fn new<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, source_chain_count: usize) -> Self {
        assert_eq!(F::ORDER, 0xffff_ffff_0000_0001);
        assert!((1..=MAX_CHAINS).contains(&source_chain_count));
        let value = Self {
            version: builder.add_virtual_target(),
            network_magic: builder.add_virtual_target_arr(),
            bridge_user_id: builder.add_virtual_target(),
            circuit_set_hash: builder.add_virtual_target_arr(),
            chains: (0..source_chain_count).map(|_| ChainConfigTarget::new(builder)).collect(),
            ethereum_index: builder.add_virtual_target(),
            reward_payer: builder.add_virtual_target_arr(),
            reward_token: builder.add_virtual_target_arr(),
            reward_per_claim: builder.add_virtual_target_arr(),
            reward_token_decimals: builder.add_virtual_target(),
            reward_cutover: builder.add_virtual_target_arr(),
            reward_end_exclusive: builder.add_virtual_target_arr(),
            max_deposits: builder.add_virtual_target(),
            max_withdrawals: builder.add_virtual_target(),
            max_rewards: builder.add_virtual_target(),
        };
        value.constrain(builder);
        value
    }

    pub fn constrain<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) {
        let one = builder.one();
        builder.connect(self.version, one);
        let bridge_user_id = builder.constant(F::from_canonical_u32(BRIDGE_USER_ID));
        builder.connect(self.bridge_user_id, bridge_user_id);
        builder.range_check(self.ethereum_index, 8);
        builder.range_check(self.reward_token_decimals, 8);
        for target in self.network_magic.iter().chain(&self.circuit_set_hash)
            .chain(&self.reward_payer).chain(&self.reward_token).chain(&self.reward_per_claim)
            .chain(&self.reward_cutover).chain(&self.reward_end_exclusive) {
            builder.range_check(*target, 32);
        }
        assert_nonzero(builder, &self.reward_payer);
        assert_nonzero(builder, &self.reward_token);
        assert_nonzero(builder, &self.reward_per_claim);
        let interval = less_than_words(builder,
            &[self.reward_cutover[1], self.reward_cutover[0]],
            &[self.reward_end_exclusive[1], self.reward_end_exclusive[0]]);
        builder.assert_one(interval.target);
        let maximum = builder.constant(F::from_canonical_usize(MAX_RECORDS));
        for count in [self.max_deposits, self.max_withdrawals, self.max_rewards] {
            builder.range_check(count, 32);
            builder.ensure_is_less_than_or_equal(32, count, maximum);
        }
        let mut ethereum_matches = builder.zero();
        for (ordinal, chain) in self.chains.iter().enumerate() {
            let matches = builder.is_equal(chain.chain_index, self.ethereum_index);
            ethereum_matches = builder.add(ethereum_matches, matches.target);
            if ordinal > 0 {
                let increasing = builder.is_less_than(8, self.chains[ordinal - 1].chain_index, chain.chain_index);
                builder.assert_one(increasing.target);
            }
        }
        builder.assert_one(ethereum_matches);
        constrain_unique_chain_ids(builder, &self.chains);
    }

    pub fn encode<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target> {
        let mut words = Vec::with_capacity(120 + self.chains.len() * 72);
        words.extend(word(builder, self.version, 32));
        words.extend(word_u64(builder, self.network_magic));
        words.extend(word(builder, self.bridge_user_id, 32));
        words.extend(self.circuit_set_hash);
        let count = builder.constant(F::from_canonical_usize(self.chains.len()));
        words.extend(word(builder, count, 32));
        for chain in &self.chains { words.extend(chain.encode(builder)); }
        words.extend(word(builder, self.ethereum_index, 8));
        words.extend(word_address(builder, self.reward_payer));
        words.extend(word_address(builder, self.reward_token));
        words.extend(self.reward_per_claim);
        words.extend(word(builder, self.reward_token_decimals, 8));
        words.extend(word_u64(builder, self.reward_cutover));
        words.extend(word_u64(builder, self.reward_end_exclusive));
        words.extend(word(builder, self.max_deposits, 32));
        words.extend(word(builder, self.max_withdrawals, 32));
        words.extend(word(builder, self.max_rewards, 32));
        words
    }

    pub fn hash<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> Bytes32Target {
        let words = self.encode(builder);
        commitment(builder, Domain::Config, &words)
    }

    pub fn set_witness<F: RichField, W: WitnessWrite<F>>(&self, witness: &mut W, config: &NetworkConfig) -> anyhow::Result<()> {
        config.validate()?;
        anyhow::ensure!(config.chains.len() == self.chains.len(), "configuration chain count differs from source-fixed C");
        for (target, value) in [
            (self.version, config.version), (self.bridge_user_id, config.bridge_user_id),
            (self.ethereum_index, config.ethereum_index as u32),
            (self.reward_token_decimals, config.reward_token_decimals as u32),
            (self.max_deposits, config.max_deposits), (self.max_withdrawals, config.max_withdrawals),
            (self.max_rewards, config.max_rewards),
        ] { witness.set_target(target, F::from_canonical_u32(value))?; }
        set_u64(witness, self.network_magic, config.network_magic)?;
        set_bytes(witness, &self.circuit_set_hash, &config.circuit_set_hash)?;
        for (target, chain) in self.chains.iter().zip(&config.chains) { target.set_witness(witness, chain)?; }
        set_bytes(witness, &self.reward_payer, &config.reward_payer)?;
        set_bytes(witness, &self.reward_token, &config.reward_token)?;
        set_bytes(witness, &self.reward_per_claim, &config.reward_per_claim)?;
        set_u64(witness, self.reward_cutover, config.reward_cutover)?;
        set_u64(witness, self.reward_end_exclusive, config.reward_end_exclusive)?;
        Ok(())
    }
}

fn assert_nonzero<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, words: &[Target]) {
    let zero = builder.zero();
    let mut all_zero = builder._true();
    for &word in words {
        let is_zero = builder.is_equal(word, zero);
        all_zero = builder.and(all_zero, is_zero);
    }
    builder.assert_zero(all_zero.target);
}

fn less_than_words<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, left: &[Target], right: &[Target]) -> BoolTarget {
    let mut less = builder._false();
    for (&left, &right) in left.iter().zip(right).rev() {
        let equal = builder.is_equal(left, right);
        let lower = builder.is_less_than(32, left, right);
        let equal_and_less = builder.and(equal, less);
        less = builder.or(lower, equal_and_less);
    }
    less
}

fn constrain_unique_chain_ids<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, chains: &[ChainConfigTarget]) {
    let size = chains.len().next_power_of_two();
    let mut sorted: Vec<_> = chains.iter().map(|chain| chain.chain_id).collect();
    sorted.resize(size, [builder.zero(); 8]);
    let mut width = 2;
    while width <= size {
        let mut stride = width / 2;
        while stride > 0 {
            for index in 0..size {
                let other = index ^ stride;
                if other <= index { continue; }
                let left = sorted[index];
                let right = sorted[other];
                let less = less_than_words(builder, &left, &right);
                let ascending = index & width == 0;
                for limb in 0..8 {
                    let low = builder.select(less, left[limb], right[limb]);
                    let high = builder.select(less, right[limb], left[limb]);
                    sorted[index][limb] = if ascending { low } else { high };
                    sorted[other][limb] = if ascending { high } else { low };
                }
            }
            stride /= 2;
        }
        width *= 2;
    }
    for pair in sorted[size - chains.len()..].windows(2) {
        let increasing = less_than_words(builder, &pair[0], &pair[1]);
        builder.assert_one(increasing.target);
    }
}

fn set_u64<F: RichField, W: WitnessWrite<F>>(witness: &mut W, targets: U64Target, value: u64) -> anyhow::Result<()> {
    witness.set_target(targets[0], F::from_canonical_u32(value as u32))?;
    witness.set_target(targets[1], F::from_canonical_u32((value >> 32) as u32))?;
    Ok(())
}

fn set_bytes<F: RichField, W: WitnessWrite<F>>(witness: &mut W, targets: &[Target], bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(bytes.len() == targets.len() * 4, "configuration byte width mismatch");
    for (target, bytes) in targets.iter().zip(bytes.chunks_exact(4)) {
        witness.set_target(*target, F::from_canonical_u32(u32::from_be_bytes(bytes.try_into()?)))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
        iop::witness::PartialWitness,
        plonk::{circuit_data::{CircuitConfig, CircuitData}, config::PoseidonGoldilocksConfig},
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    fn config() -> NetworkConfig {
        let chains = [9u8, 2, 7].into_iter().enumerate().map(|(index, id)| {
            let mut chain_id = [0; 32];
            chain_id[31] = id;
            ChainConfig {
                chain_index: (index * 3 + 1) as u8, chain_id,
                bridge: [0x11 + index as u8; 20], state_manager: [0x22; 20],
                bootstrap_id: (1u64 << 40) + index as u64,
                bootstrap_root: [1, 2, 3, 0xffff_ffff_0000_0000],
            }
        }).collect();
        NetworkConfig {
            version: 1, network_magic: u64::MAX, bridge_user_id: BRIDGE_USER_ID,
            circuit_set_hash: [0x55; 32], chains, ethereum_index: 4,
            reward_payer: [0x33; 20], reward_token: [0x44; 20],
            reward_per_claim: [0xff; 32], reward_token_decimals: 18,
            reward_cutover: (1u64 << 40) - 1, reward_end_exclusive: 1u64 << 40,
            max_deposits: 1024, max_withdrawals: 0, max_rewards: 31,
        }
    }

    fn rejects(data: &CircuitData<F, C, 2>, witness: PartialWitness<F>) {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            data.prove(witness).and_then(|proof| data.verify(proof))
        }));
        assert!(result.is_err() || result.unwrap().is_err(), "invalid configuration proved");
    }

    #[test]
    fn canonical_config_encoding_and_digest_match_host() {
        let config = config();
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let target = NetworkConfigTarget::new(&mut builder, 3);
        let encoded = target.encode(&mut builder);
        builder.register_public_inputs(&encoded);
        let hash = target.hash(&mut builder);
        builder.register_public_inputs(&hash);
        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        target.set_witness(&mut witness, &config).unwrap();
        let proof = data.prove(witness).unwrap();
        let bytes: Vec<_> = proof.public_inputs.iter().flat_map(|value| {
            (value.to_canonical_u64() as u32).to_be_bytes()
        }).collect();
        let mut expected = config.encode().unwrap();
        expected.extend(config.config_hash().unwrap());
        assert_eq!(bytes, expected);
        data.verify(proof.clone()).unwrap();
        let mut wrong_digest = proof;
        *wrong_digest.public_inputs.last_mut().unwrap() += F::ONE;
        assert!(data.verify(wrong_digest).is_err());
    }

    #[test]
    fn source_count_and_invalid_config_fields_reject() {
        let config = config();
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let target = NetworkConfigTarget::new(&mut builder, 3);
        let data = builder.build::<C>();
        let mut short = config.clone();
        short.chains.pop();
        assert!(target.set_witness(&mut PartialWitness::<F>::new(), &short).is_err());
        for (field, value) in [
            (target.version, 2), (target.bridge_user_id, BRIDGE_USER_ID as u64 + 1),
            (target.ethereum_index, 2), (target.max_rewards, 1025),
            (target.reward_token_decimals, 256), (target.chains[1].chain_index, 1),
            (target.reward_cutover[1], 256),
            (target.circuit_set_hash[0], 1u64 << 32),
        ] {
            let mut witness = PartialWitness::new();
            target.set_witness(&mut witness, &config).unwrap();
            witness.target_values.insert(field, F::from_canonical_u64(value));
            rejects(&data, witness);
        }
        for fields in [
            target.reward_payer.to_vec(), target.reward_token.to_vec(),
            target.reward_per_claim.to_vec(), target.chains[0].chain_id.to_vec(),
            target.chains[0].bridge.to_vec(), target.chains[0].state_manager.to_vec(),
        ] {
            let mut witness = PartialWitness::new();
            target.set_witness(&mut witness, &config).unwrap();
            for field in fields { witness.target_values.insert(field, F::ZERO); }
            rejects(&data, witness);
        }
        let mut duplicate = PartialWitness::new();
        target.set_witness(&mut duplicate, &config).unwrap();
        for (index, field) in target.chains[2].chain_id.iter().enumerate() {
            duplicate.target_values.insert(*field, F::from_canonical_u32(if index == 7 { 9 } else { 0 }));
        }
        rejects(&data, duplicate);
    }
}
