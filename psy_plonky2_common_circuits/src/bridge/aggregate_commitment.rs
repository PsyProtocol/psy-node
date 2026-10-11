use plonky2::{
    field::extension::Extendable,
    hash::{hash_types::RichField, poseidon::PoseidonHash},
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder,
};
use psy_client_data::bridge_aggregate::{
    DEPOSIT_ACCUMULATOR_SEED_DOMAIN, DEPOSIT_ACCUMULATOR_FOLD_DOMAIN,
};

use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;

/// Eight big-endian u32 words, in byte order. Never Poseidon limb order.
pub type Bytes32Target = [Target; 8];
pub type AddressTarget = [Target; 5];
pub type Hash4Target = [Target; 4];
/// Integer limbs in recursive PI order: low u32, high u32.
pub type U64Target = [Target; 2];



pub fn word_address<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, address: AddressTarget,
) -> Bytes32Target {
    let mut result = [builder.zero(); 8];
    for (out, value) in result[3..].iter_mut().zip(address) {
        builder.range_check(value, 32);
        *out = value;
    }
    result
}

#[derive(Clone, Copy)]
pub struct DepositLeafTarget {
    pub chain_index: Target,
    pub absolute_index: Target,
    pub shield_address: Bytes32Target,
    pub token: AddressTarget,
    pub l2_token_contract_id: Bytes32Target,
    pub amount: Bytes32Target,
    pub note_commitment: Bytes32Target,
}

impl DepositLeafTarget {
    pub fn poseidon_hash<F: RichField + Extendable<D>, const D: usize>(
        &self, builder: &mut CircuitBuilder<F, D>,
    ) -> Hash4Target {
        let mut fields = Vec::with_capacity(41);
        fields.extend(self.shield_address);
        fields.extend(word_address(builder, self.token));
        fields.extend(self.l2_token_contract_id);
        fields.extend(self.amount);
        fields.push(self.chain_index);
        fields.extend(self.note_commitment);
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(fields).elements
    }
}

pub fn deposit_accumulator_seed<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, config_hash: Bytes32Target,
    end_checkpoint_id: U64Target, end_checkpoint_root: Hash4Target,
    global_deposit_count: Target,
) -> Hash4Target {
    let mut fields = Vec::with_capacity(16);
    fields.push(builder.constant(F::from_canonical_u64(DEPOSIT_ACCUMULATOR_SEED_DOMAIN)));
    fields.extend(config_hash);
    fields.extend(end_checkpoint_id);
    fields.extend(end_checkpoint_root);
    fields.push(global_deposit_count);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(fields).elements
}

pub fn deposit_accumulator_fold<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>, accumulator: Hash4Target, ordinal: Target,
    chain_index: Target, absolute_index: Target, leaf_hash: Hash4Target,
) -> Hash4Target {
    let mut fields = Vec::with_capacity(12);
    fields.push(builder.constant(F::from_canonical_u64(DEPOSIT_ACCUMULATOR_FOLD_DOMAIN)));
    fields.extend(accumulator);
    fields.extend([ordinal, chain_index, absolute_index]);
    fields.extend(leaf_hash);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(fields).elements
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::{goldilocks_field::GoldilocksField, types::{Field, Field64}},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{circuit_data::CircuitConfig, config::PoseidonGoldilocksConfig},
    };

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    fn constant_bytes32<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>, bytes: [u8; 32],
    ) -> Bytes32Target {
        std::array::from_fn(|i| builder.constant(F::from_canonical_u32(
            u32::from_be_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap()),
        )))
    }


    #[test]
    fn deposit_poseidon_helpers_match_native_encodings() {
        use psy_client_data::bridge_aggregate as native;
        let mut builder = CircuitBuilder::<F, 2>::new(CircuitConfig::standard_recursion_config());
        let config = std::array::from_fn(|i| i as u8);
        let checkpoint_id = 0x123456789abcdef0u64;
        let checkpoint_root = [0, 1, 1u64 << 32, native::GOLDILOCKS_MODULUS - 1];
        let config_target = constant_bytes32(&mut builder, config);
        let id_target = [checkpoint_id as u32, (checkpoint_id >> 32) as u32]
            .map(|value| builder.constant(F::from_canonical_u32(value)));
        let root_target = checkpoint_root.map(|value| builder.constant(F::from_canonical_u64(value)));
        let count = builder.constant(F::from_canonical_u32(1024));
        let seed = deposit_accumulator_seed(&mut builder, config_target, id_target, root_target, count);
        let native_seed = native::deposit_accumulator_seed(config, checkpoint_id, checkpoint_root, 1024).unwrap();
        let leaf = native::DepositLeaf {
            chain_index: 255, absolute_index: u32::MAX - 1, shield_address: [0x81; 32],
            token: [0x42; 20], l2_token_contract_id: [0x23; 32], amount: [0xff; 32],
            note_commitment: [0x54; 32],
        };
        let leaf_target = DepositLeafTarget {
            chain_index: builder.constant(F::from_canonical_u8(leaf.chain_index)),
            absolute_index: builder.constant(F::from_canonical_u32(leaf.absolute_index)),
            shield_address: constant_bytes32(&mut builder, leaf.shield_address),
            token: std::array::from_fn(|i| builder.constant(F::from_canonical_u32(
                u32::from_be_bytes(leaf.token[i * 4..i * 4 + 4].try_into().unwrap())))),
            l2_token_contract_id: constant_bytes32(&mut builder, leaf.l2_token_contract_id),
            amount: constant_bytes32(&mut builder, leaf.amount),
            note_commitment: constant_bytes32(&mut builder, leaf.note_commitment),
        };
        let leaf_hash = leaf_target.poseidon_hash(&mut builder);
        let ordinal = builder.constant(F::from_canonical_u32(1023));
        let folded = deposit_accumulator_fold(&mut builder, seed, ordinal,
            leaf_target.chain_index, leaf_target.absolute_index, leaf_hash);
        for output in [seed, leaf_hash, folded] {
            builder.register_public_inputs(&output);
        }
        let data = builder.build::<C>();
        let proof = data.prove(PartialWitness::new()).unwrap();
        let expected = [native_seed, leaf.poseidon_hash().unwrap(),
            native::deposit_accumulator_fold(native_seed, 1023, leaf.chain_index,
                leaf.absolute_index, leaf.poseidon_hash().unwrap()).unwrap()];
        assert_eq!(proof.public_inputs, expected.into_iter().flatten()
            .map(F::from_canonical_u64).collect::<Vec<_>>());
        data.verify(proof).unwrap();
    }
}
