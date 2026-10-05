use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::{hash_types::{HashOut, HashOutTarget}, poseidon::PoseidonHash},
    iop::{target::Target, witness::{PartialWitness, WitnessWrite}},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_data::bridge_aggregate::{WithdrawalLeaf, BRIDGE_USER_ID, GOLDILOCKS_MODULUS};
use psy_plonky2_basic_helpers::builder::comparison::CircuitBuilderComparison;

use super::aggregate_commitment::{Bytes32Target, AggregateLeafTarget, U64Target, WithdrawalLeafTarget};
use crate::hash::merkle::gadgets::merkle_proof::{MerkleProofGadget, OptionalMerkleProofGadget};

pub const WITHDRAWAL_INCLUSION_PUBLIC_INPUTS: usize = 32;
pub const WITHDRAWAL_TREE_HEIGHT: usize = 32;

#[derive(Clone, Debug)]
pub struct WithdrawalWitness {
    pub leaf_index: u32,
    pub siblings: [[u64; 4]; WITHDRAWAL_TREE_HEIGHT],
}

#[derive(Clone, Debug)]
pub struct WithdrawalInclusionInputs {
    pub config_hash: [u8; 32],
    pub end_checkpoint_id: u64,
    pub end_checkpoint_root: [u64; 4],
    pub withdrawal_root: [u64; 4],
    pub leaf: WithdrawalLeaf,
    pub witness: WithdrawalWitness,
}

pub struct WithdrawalInclusionCircuit<C: GenericConfig<D, F = GoldilocksField>, const D: usize>
where
    C::Hasher: AlgebraicHasher<GoldilocksField>,
    GoldilocksField: Extendable<D>,
{
    pub circuit_data: CircuitData<GoldilocksField, C, D>,
    pub config_hash: Bytes32Target,
    pub end_checkpoint_id: U64Target,
    pub end_checkpoint_root: HashOutTarget,
    pub withdrawal_root: HashOutTarget,
    pub leaf: WithdrawalLeafTarget,
    pub leaf_commit: Bytes32Target,
    pub merkle_proof: MerkleProofGadget,
}

impl<C: GenericConfig<D, F = GoldilocksField> + 'static, const D: usize>
    WithdrawalInclusionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<GoldilocksField>,
    GoldilocksField: Extendable<D>,
{
    pub fn build() -> Self {
        let mut builder = CircuitBuilder::<GoldilocksField, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let config_hash: Bytes32Target = builder.add_virtual_target_arr();
        let end_checkpoint_id: U64Target = builder.add_virtual_target_arr();
        let end_checkpoint_root = builder.add_virtual_hash();
        let withdrawal_root = builder.add_virtual_hash();
        let leaf = WithdrawalLeafTarget {
            chain_index: builder.add_virtual_target(),
            sender_user_id: builder.add_virtual_target(),
            recipient: builder.add_virtual_target_arr(),
            token: builder.add_virtual_target_arr(),
            amount: builder.add_virtual_target_arr(),
            nonce: builder.add_virtual_target_arr(),
        };
        for target in config_hash.iter().chain(end_checkpoint_id.iter()) {
            builder.range_check(*target, 32);
        }
        let zero = builder.zero();
        for target in &leaf.amount[..6] { builder.connect(*target, zero); }
        // p - 1 = 0xffffffff00000000: the maximal high limb requires a zero low limb.
        let max_u32 = builder.constant(GoldilocksField::from_canonical_u32(u32::MAX));
        let max_high = builder.is_equal(leaf.amount[6], max_u32);
        let excess = builder.mul(max_high.target, leaf.amount[7]);
        builder.assert_zero(excess);
        let amount_sum = builder.add(leaf.amount[6], leaf.amount[7]);
        builder.assert_non_zero(amount_sum);
        let recipient_sum = builder.add_many(leaf.recipient);
        builder.assert_non_zero(recipient_sum);

        let leaf_commit = AggregateLeafTarget::Withdrawal(leaf).leaf_commit(&mut builder);
        // Preserve the existing aggregate circuit's 34-field source order, not wire order.
        let source_words: Vec<Target> = std::iter::once(leaf.sender_user_id)
            .chain([zero; 3]).chain(leaf.recipient)
            .chain([zero; 3]).chain(leaf.token)
            .chain(leaf.amount).chain(leaf.nonce)
            .chain(std::iter::once(leaf.chain_index)).collect();
        let leaf_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(source_words);
        let merkle_proof = MerkleProofGadget::add_virtual_to_with_options::<
            PoseidonHash, GoldilocksField, D,
        >(&mut builder, WITHDRAWAL_TREE_HEIGHT, OptionalMerkleProofGadget {
            root: Some(withdrawal_root), value: Some(leaf_hash), index: None, siblings: None,
        });
        let one = builder.one();
        let family = builder.constant(GoldilocksField::from_canonical_u32(2));
        let bridge_user = builder.constant(GoldilocksField::from_canonical_u32(BRIDGE_USER_ID));
        builder.register_public_inputs(&[one, family, zero, zero]);
        builder.register_public_inputs(&config_hash);
        builder.register_public_inputs(&end_checkpoint_id);
        builder.register_public_inputs(&end_checkpoint_root.elements);
        builder.register_public_inputs(&[bridge_user, leaf.chain_index]);
        builder.register_public_inputs(&withdrawal_root.elements);
        builder.register_public_inputs(&leaf_commit);
        let circuit_data = builder.build::<C>();
        Self { circuit_data, config_hash, end_checkpoint_id, end_checkpoint_root,
            withdrawal_root, leaf, leaf_commit, merkle_proof }
    }

    pub fn set_witness(
        &self, pw: &mut PartialWitness<GoldilocksField>, inputs: &WithdrawalInclusionInputs,
    ) -> anyhow::Result<()> {
        set_bytes(pw, &self.config_hash, &inputs.config_hash)?;
        pw.set_target(self.end_checkpoint_id[0], GoldilocksField::from_canonical_u32(inputs.end_checkpoint_id as u32))?;
        pw.set_target(self.end_checkpoint_id[1], GoldilocksField::from_canonical_u32((inputs.end_checkpoint_id >> 32) as u32))?;
        set_hash(pw, self.end_checkpoint_root, inputs.end_checkpoint_root)?;
        set_hash(pw, self.withdrawal_root, inputs.withdrawal_root)?;
        pw.set_target(self.leaf.chain_index, GoldilocksField::from_canonical_u32(inputs.leaf.chain_index as u32))?;
        pw.set_target(self.leaf.sender_user_id, GoldilocksField::from_canonical_u32(inputs.leaf.sender_user_id))?;
        set_bytes(pw, &self.leaf.recipient, &inputs.leaf.recipient)?;
        set_bytes(pw, &self.leaf.token, &inputs.leaf.token)?;
        set_bytes(pw, &self.leaf.amount, &inputs.leaf.amount)?;
        set_bytes(pw, &self.leaf.nonce, &inputs.leaf.nonce)?;
        pw.set_target(self.merkle_proof.index, GoldilocksField::from_canonical_u32(inputs.witness.leaf_index))?;
        for (target, hash) in self.merkle_proof.siblings.iter().zip(inputs.witness.siblings) {
            set_hash(pw, *target, hash)?;
        }
        Ok(())
    }

    pub fn generate_proof(&self, inputs: &WithdrawalInclusionInputs)
        -> anyhow::Result<ProofWithPublicInputs<GoldilocksField, C, D>>
    {
        let mut pw = PartialWitness::new();
        self.set_witness(&mut pw, inputs)?;
        self.circuit_data.prove(pw)
    }

    pub fn verify_proof(&self, proof: ProofWithPublicInputs<GoldilocksField, C, D>) -> anyhow::Result<()> {
        self.circuit_data.verify(proof)
    }
}

fn set_bytes(pw: &mut PartialWitness<GoldilocksField>, targets: &[Target], bytes: &[u8]) -> anyhow::Result<()> {
    anyhow::ensure!(bytes.len() == targets.len() * 4, "invalid canonical word width");
    for (target, bytes) in targets.iter().zip(bytes.chunks_exact(4)) {
        pw.set_target(*target, GoldilocksField::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap())))?;
    }
    Ok(())
}

fn set_hash(pw: &mut PartialWitness<GoldilocksField>, target: HashOutTarget, hash: [u64; 4]) -> anyhow::Result<()> {
    anyhow::ensure!(hash.iter().all(|value| *value < GOLDILOCKS_MODULUS), "noncanonical Goldilocks hash");
    pw.set_hash_target(target, HashOut { elements: hash.map(GoldilocksField::from_canonical_u64) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{field::types::PrimeField64, plonk::config::{Hasher, PoseidonGoldilocksConfig}};
    use tiny_keccak::{Hasher as KeccakHasher, Keccak};

    type Circuit = WithdrawalInclusionCircuit<PoseidonGoldilocksConfig, 2>;

    fn source_words(leaf: &WithdrawalLeaf) -> Vec<GoldilocksField> {
        let mut words = vec![GoldilocksField::from_canonical_u32(leaf.sender_user_id)];
        for address in [&leaf.recipient, &leaf.token] {
            words.extend([GoldilocksField::ZERO; 3]);
            words.extend(address.chunks_exact(4).map(|bytes| {
                GoldilocksField::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap()))
            }));
        }
        for bytes in [&leaf.amount, &leaf.nonce] {
            words.extend(bytes.chunks_exact(4).map(|bytes| {
                GoldilocksField::from_canonical_u32(u32::from_be_bytes(bytes.try_into().unwrap()))
            }));
        }
        words.push(GoldilocksField::from_canonical_u32(leaf.chain_index as u32));
        assert_eq!(words.len(), 34);
        words
    }

    fn root(inputs: &WithdrawalInclusionInputs, words: Vec<GoldilocksField>) -> [u64; 4] {
        let mut hash = PoseidonHash::hash_no_pad(&words);
        for (level, sibling) in inputs.witness.siblings.iter().enumerate() {
            let sibling = HashOut { elements: sibling.map(GoldilocksField::from_canonical_u64) };
            let (left, right) = if (inputs.witness.leaf_index >> level) & 1 == 0 {
                (hash, sibling)
            } else { (sibling, hash) };
            hash = PoseidonHash::hash_no_pad(&[left.elements, right.elements].concat());
        }
        hash.elements.map(|value| value.to_canonical_u64())
    }

    fn fixture() -> WithdrawalInclusionInputs {
        let mut amount = [0; 32];
        amount[31] = 100;
        let mut inputs = WithdrawalInclusionInputs {
            config_hash: [0x23; 32], end_checkpoint_id: (1 << 32) + 501,
            end_checkpoint_root: [30, 31, 32, 33], withdrawal_root: [0; 4],
            leaf: WithdrawalLeaf {
                chain_index: 7, sender_user_id: 1000, recipient: [0x55; 20],
                token: [0x33; 20], amount, nonce: [0x77; 32],
            },
            witness: WithdrawalWitness {
                leaf_index: 0x8000_0005,
                siblings: std::array::from_fn(|level| [level as u64 + 1; 4]),
            },
        };
        inputs.withdrawal_root = root(&inputs, source_words(&inputs.leaf));
        inputs
    }

    fn keccak(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        hasher.update(bytes);
        let mut digest = [0; 32];
        hasher.finalize(&mut digest);
        digest
    }

    fn leaf_commit(leaf: &WithdrawalLeaf) -> [u8; 32] {
        let mut body = keccak(b"PsyBridge/TwoArtifact/1/Record").to_vec();
        for integer in [2, leaf.chain_index as u32, leaf.sender_user_id] {
            body.extend([0; 28]);
            body.extend(integer.to_be_bytes());
        }
        for address in [&leaf.recipient, &leaf.token] {
            body.extend([0; 12]);
            body.extend(address);
        }
        body.extend(leaf.amount);
        body.extend(leaf.nonce);
        keccak(&body)
    }

    fn rejects(circuit: &Circuit, pw: PartialWitness<GoldilocksField>) {
        // A conflicting generated witness may be rejected before the prover returns an error.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            circuit.circuit_data.prove(pw).and_then(|proof| circuit.verify_proof(proof))
        }));
        assert!(result.is_err() || result.unwrap().is_err(), "invalid withdrawal proved");
    }

    #[test]
    fn withdrawal_membership_and_canonical_record_are_bound() {
        let circuit = Circuit::build();
        let inputs = fixture();
        let proof = circuit.generate_proof(&inputs).unwrap();
        let mut expected = vec![1, 2, 0, 0];
        expected.extend(inputs.config_hash.chunks_exact(4).map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()) as u64));
        expected.extend([501, 1]);
        expected.extend(inputs.end_checkpoint_root);
        expected.extend([BRIDGE_USER_ID as u64, inputs.leaf.chain_index as u64]);
        expected.extend(inputs.withdrawal_root);
        expected.extend(leaf_commit(&inputs.leaf).chunks_exact(4).map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()) as u64));
        assert_eq!(proof.public_inputs.len(), WITHDRAWAL_INCLUSION_PUBLIC_INPUTS);
        assert_eq!(proof.public_inputs.iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>(), expected);
        assert_eq!(leaf_commit(&inputs.leaf), inputs.leaf.leaf_commit().unwrap());
        circuit.verify_proof(proof.clone()).unwrap();
        for offset in [0, 1, 2, 3, 4, 12, 14, 18, 19, 20, 24] {
            let mut changed = proof.clone();
            changed.public_inputs[offset] += GoldilocksField::ONE;
            assert!(circuit.verify_proof(changed).is_err(), "accepted changed PI {offset}");
        }

        let mutations: [fn(&mut WithdrawalInclusionInputs); 7] = [
            |input| input.leaf.nonce[31] ^= 1,
            |input| input.withdrawal_root[0] ^= 1,
            |input| input.leaf.amount[31] += 1,
            |input| input.leaf.recipient[19] ^= 1,
            |input| input.witness.leaf_index ^= 1,
            |input| input.witness.siblings[31][0] ^= 1,
            |input| input.leaf.chain_index += 1,
        ];
        for mutate in mutations {
            let mut changed = inputs.clone();
            mutate(&mut changed);
            let mut pw = PartialWitness::new();
            circuit.set_witness(&mut pw, &changed).unwrap();
            rejects(&circuit, pw);
        }
        let mut pw = PartialWitness::new();
        circuit.set_witness(&mut pw, &inputs).unwrap();
        let mut wrong_commit = leaf_commit(&inputs.leaf);
        wrong_commit[0] ^= 1;
        set_bytes(&mut pw, &circuit.leaf_commit, &wrong_commit).unwrap();
        rejects(&circuit, pw);
    }

    #[test]
    fn rejects_invalid_records_even_under_their_own_root() {
        let circuit = Circuit::build();
        let inputs = fixture();
        let mutations: [fn(&mut WithdrawalInclusionInputs); 4] = [
            |input| input.leaf.amount = [0; 32],
            |input| input.leaf.amount[24..].copy_from_slice(&GOLDILOCKS_MODULUS.to_be_bytes()),
            |input| input.leaf.amount[0] = 1,
            |input| input.leaf.recipient = [0; 20],
        ];
        for mutate in mutations {
            let mut changed = inputs.clone();
            mutate(&mut changed);
            changed.withdrawal_root = root(&changed, source_words(&changed.leaf));
            let mut pw = PartialWitness::new();
            circuit.set_witness(&mut pw, &changed).unwrap();
            rejects(&circuit, pw);
        }
        // Address high words cannot be supplied through the canonical address type.
        // A source-tree leaf with nonzero padding still must not authenticate it.
        for offset in [1, 9] {
            let mut changed = inputs.clone();
            let mut words = source_words(&changed.leaf);
            words[offset] = GoldilocksField::ONE;
            changed.withdrawal_root = root(&changed, words);
            let mut pw = PartialWitness::new();
            circuit.set_witness(&mut pw, &changed).unwrap();
            rejects(&circuit, pw);
        }
        for (target, value) in [
            (circuit.merkle_proof.index, 1u64 << 32),
            (circuit.leaf.sender_user_id, 1u64 << 32),
            (circuit.leaf.chain_index, 256),
            (circuit.leaf.recipient[0], 1u64 << 32),
        ] {
            let mut pw = PartialWitness::new();
            circuit.set_witness(&mut pw, &inputs).unwrap();
            pw.target_values.insert(target, GoldilocksField::from_canonical_u64(value));
            rejects(&circuit, pw);
        }
        let mut boundary = inputs;
        boundary.leaf.amount[24..].copy_from_slice(&(GOLDILOCKS_MODULUS - 1).to_be_bytes());
        boundary.withdrawal_root = root(&boundary, source_words(&boundary.leaf));
        let proof = circuit.generate_proof(&boundary).unwrap();
        circuit.verify_proof(proof).unwrap();
    }
}
