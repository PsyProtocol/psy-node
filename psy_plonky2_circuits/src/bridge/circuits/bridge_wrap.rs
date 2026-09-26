pub use std::fmt::Display;

use hex::FromHexError;
use parth_core::{crypto::hash::traits::HashTo4Felts, pgoldilocks::QHashOut};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::witness::{PartialWitness, WitnessWrite},
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{PoseidonGoldilocksConfig, AlgebraicHasher},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_plonky2_basic_helpers::builder::verify::CircuitBuilderVerifyProofHelpers;
use psy_plonky2_basic_helpers::builder::{comparison::CircuitBuilderComparison, connect::CircuitBuilderConnectHelpers, hash::core::CircuitBuilderHashCore};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::to_string as json;
use serde_with::serde_as;
use plonky2x::backend::wrapper::wrap::WrappedCircuit;
use plonky2x::frontend::builder::CircuitBuilder as WrapperBuilder;
use plonky2x::prelude::DefaultParameters;

use crate::{
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    simple_wrapper::dynamic::SimpleWrapperDynamic,
};

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone, Copy, Debug, Eq, Hash, PartialOrd, Ord)]
pub struct Serialized2DFeltBN254(#[serde_as(as = "serde_with::hex::Hex")] pub [u8; 32]);
impl Default for Serialized2DFeltBN254 {
    fn default() -> Self {
        Self([0u8; 32])
    }
}

impl Serialized2DFeltBN254 {
    pub fn from_hex_string(s: &str) -> Result<Self, FromHexError> {
        let bytes = hex::decode(s)?;
        assert_eq!(bytes.len(), 32);
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.0)
    }
    pub fn rand() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Serialized2DFeltBN254(bytes)
    }
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }
    pub fn from_slice(data: &[u8]) -> Self {
        let mut array = [0u8; 32];
        array.copy_from_slice(data);
        Self(array)
    }
}

impl Display for Serialized2DFeltBN254 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl TryFrom<&str> for Serialized2DFeltBN254 {
    type Error = FromHexError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Serialized2DFeltBN254::from_hex_string(value)
    }
}
impl TryFrom<String> for Serialized2DFeltBN254 {
    type Error = FromHexError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Serialized2DFeltBN254::from_hex_string(&value)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Hash, Ord, PartialOrd, Eq)]
pub struct UncompressedGroth16ProofData {
    pub pi_a: [String; 2],
    pub pi_b: [[String; 2]; 2],
    pub pi_c: [String; 2],
    pub public_inputs: [String; 2],
}

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;

#[derive(Debug)]
pub struct SharedGroth16Wrapper {
    pub wrapped_circuit: WrappedCircuit<DefaultParameters, gnark_plonky2_wrapper::parameters::Groth16WrapperParameters, D>,
    pub keystore_path: String,
}

impl SharedGroth16Wrapper {
    pub fn new(circuit_data: CircuitData<F, C, D>, keystore_path: String) -> Self {
        let wrapper_builder = WrapperBuilder::<DefaultParameters, D>::new();
        let mut circuit = wrapper_builder.build();
        circuit.data = circuit_data;
        let wrapped_circuit = WrappedCircuit::<
            DefaultParameters,
            gnark_plonky2_wrapper::parameters::Groth16WrapperParameters,
            D,
        >::build(circuit);
        Self {
            wrapped_circuit,
            keystore_path,
        }
    }

    pub fn prove_groth16(
        &self,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
        save_wrapped_data_path: Option<&str>,
    ) -> anyhow::Result<UncompressedGroth16ProofData> {
        let wrapped_output = self.wrapped_circuit.prove(inner_proof)?;
        if let Some(path) = save_wrapped_data_path {
            wrapped_output.save(path)?;
        }

        let (proof_string, vk_string) = gnark_plonky2_verifier_ffi::generate_groth16_proof(
            &json(&wrapped_output.common_data)?,
            &json(&wrapped_output.proof)?,
            &json(&wrapped_output.verifier_data)?,
            &self.keystore_path,
        );
        if proof_string.starts_with("error:") {
            anyhow::bail!("generate_groth16_proof failed: {}", proof_string);
        }
        if vk_string.starts_with("error:") {
            anyhow::bail!("generate_groth16_proof failed: {}", vk_string);
        }

        let proof_data = serde_json::from_str::<UncompressedGroth16ProofData>(&proof_string)?;
        Ok(proof_data)
    }
}

fn bridge_wrap_public_inputs_keccak_bytes(public_inputs: &[F]) -> Vec<u8> {
    public_inputs
        .iter()
        .enumerate()
        .flat_map(|(i, x)| {
            if (4..20).contains(&i) {
                let paired_index = if i % 2 == 0 { i + 1 } else { i - 1 };
                (public_inputs[paired_index].to_noncanonical_u64() as u32).to_be_bytes().to_vec()
            } else {
                x.to_noncanonical_u64().to_be_bytes().to_vec()
            }
        })
        .collect()
}

#[derive(Debug)]
pub struct BridgeWrapCircuit {
    pub wrapper: SimpleWrapperDynamic<C, D>,
}

impl BridgeWrapCircuit {
    pub fn new(common_data: &CommonCircuitData<F, D>, fingerprint: QHashOut<F>, inner_verifier_data_cap_height: usize) -> Self {
        Self {
            wrapper: SimpleWrapperDynamic::<C, D>::new(
                common_data,
                fingerprint,
                inner_verifier_data_cap_height,
                |i| if i >= 4 && i < 20 { 32 } else { 64 },
            ),
        }
    }

    pub fn into_shared_groth16_wrapper(self, keystore_path: String) -> SharedGroth16Wrapper {
        SharedGroth16Wrapper::new(self.wrapper.circuit_data, keystore_path)
    }

    pub fn prove_groth16_with_shared_wrapper(
        &self,
        shared_wrapper: &SharedGroth16Wrapper,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<UncompressedGroth16ProofData> {
        tracing::info!(
            "bridge_wrap pre-wrap PI count: {}",
            self.wrapper.circuit_data.common.num_public_inputs
        );
        let wrapper_proof = self.wrapper.prove_base(inner_proof, verifier_data)?;
        tracing::info!(
            "bridge_wrap wrapper proof PI count: {}",
            wrapper_proof.public_inputs.len()
        );
        let public_inputs_hash = QHashOut::from_4_felts_slice(&inner_proof.public_inputs[20..24]);

        let flat_bytes = bridge_wrap_public_inputs_keccak_bytes(&inner_proof.public_inputs);
        let mut keccak = tiny_keccak::Keccak::v256();
        let mut hash = [0u8; 32];
        tiny_keccak::Hasher::update(&mut keccak, &flat_bytes);
        tiny_keccak::Hasher::finalize(keccak, &mut hash);
        tracing::info!("prove_groth16_with_shared_wrapper public inouts: keccak256: 0x{}", hex::encode(hash));

        shared_wrapper.prove_groth16(
            &wrapper_proof,
            Some(&format!("/tmp/plonky2_proof/{}", public_inputs_hash)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::bridge_wrap_public_inputs_keccak_bytes;
    use plonky2::field::{goldilocks_field::GoldilocksField, types::Field};

    #[test]
    fn bridge_wrap_keccak_bytes_pair_swap_tree_root_limbs() {
        // Final PI width is 26: roots and checkpoint metadata (no l1_chain_index).
        let public_inputs = (0u64..26)
            .map(GoldilocksField::from_canonical_u64)
            .collect::<Vec<_>>();
        let bytes = bridge_wrap_public_inputs_keccak_bytes(&public_inputs);

        assert_eq!(&bytes[0..8], &0u64.to_be_bytes());
        assert_eq!(&bytes[8..16], &1u64.to_be_bytes());
        assert_eq!(&bytes[16..24], &2u64.to_be_bytes());
        assert_eq!(&bytes[24..32], &3u64.to_be_bytes());

        // Tree-root limbs [4..20) are serialized as adjacent swapped u32 pairs.
        assert_eq!(&bytes[32..36], &5u32.to_be_bytes());
        assert_eq!(&bytes[36..40], &4u32.to_be_bytes());
        assert_eq!(&bytes[40..44], &7u32.to_be_bytes());
        assert_eq!(&bytes[44..48], &6u32.to_be_bytes());
        assert_eq!(&bytes[80..84], &17u32.to_be_bytes());
        assert_eq!(&bytes[84..88], &16u32.to_be_bytes());
        assert_eq!(&bytes[88..92], &19u32.to_be_bytes());
        assert_eq!(&bytes[92..96], &18u32.to_be_bytes());

        // Checkpoint metadata [20..26) remains full u64 limbs (no pair-swap).
        assert_eq!(&bytes[96..104], &20u64.to_be_bytes());
        assert_eq!(&bytes[120..128], &23u64.to_be_bytes());
        assert_eq!(&bytes[128..136], &24u64.to_be_bytes());
        assert_eq!(&bytes[136..144], &25u64.to_be_bytes());
    }
}

#[derive(Debug)]
pub struct DepositBatchWrapCircuit {
    pub proof_target: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget,
    pub circuit_data: CircuitData<F, C, D>,
}

impl DepositBatchWrapCircuit {
    pub fn new(common_data: &CommonCircuitData<F, D>, fingerprint: QHashOut<F>, inner_verifier_data_cap_height: usize) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let proof_target = builder.add_virtual_proof_with_pis(common_data);
        let verifier_data_target = builder.add_virtual_verifier_data(inner_verifier_data_cap_height);
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, common_data);

        let expected_fingerprint = builder.constant_hash(fingerprint.into());
        let actual_fingerprint =
            builder.get_circuit_fingerprint::<<C as plonky2::plonk::config::GenericConfig<D>>::Hasher>(&verifier_data_target);
        builder.connect_hashes(expected_fingerprint, actual_fingerprint);

        // gnark worker groups every 64 consecutive LE bits into one u64 limb and
        // serialises with BigEndian.PutUint64, which places the HIGH 32-bit word
        // first.  To make the resulting keccak input match the natural word order
        // (word[0]_BE, word[1]_BE, …) we register each pair in SWAPPED order:
        // [word1_bits, word0_bits] so that gnark reconstructs limb = word1 + word0<<32
        // and BE serialisation yields [word0_BE, word1_BE].
        for pair in proof_target.public_inputs.chunks(2) {
            if pair.len() == 2 {
                let bits1 = builder.split_le(pair[1], 32);
                for bit in &bits1 {
                    builder.register_public_input(bit.target);
                }
                let bits0 = builder.split_le(pair[0], 32);
                for bit in &bits0 {
                    builder.register_public_input(bit.target);
                }
            } else {
                // Odd trailing element: register normally, then pad to 64 bits.
                let bits = builder.split_le(pair[0], 32);
                for bit in &bits {
                    builder.register_public_input(bit.target);
                }
                let zero = builder.zero();
                let pad_bits = builder.split_le(zero, 32);
                for bit in &pad_bits {
                    builder.register_public_input(bit.target);
                }
            }
        }

        let circuit_data = builder.build::<C>();
        Self {
            proof_target,
            verifier_data_target,
            circuit_data,
        }
    }

    pub fn into_shared_groth16_wrapper(self, keystore_path: String) -> SharedGroth16Wrapper {
        SharedGroth16Wrapper::new(self.circuit_data, keystore_path)
    }

    pub fn prove_groth16_with_shared_wrapper(
        &self,
        shared_wrapper: &SharedGroth16Wrapper,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<UncompressedGroth16ProofData> {
        tracing::info!(
            "deposit_batch pre-wrap PI count: {}, inner proof PI count: {}",
            self.circuit_data.common.num_public_inputs,
            inner_proof.public_inputs.len()
        );
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.proof_target, inner_proof)?;
        pw.set_verifier_data_target(&self.verifier_data_target, verifier_data)?;
        let wrapper_proof = self.circuit_data.prove(pw)?;
        tracing::info!(
            "deposit_batch wrapper proof PI count: {}",
            wrapper_proof.public_inputs.len()
        );
        let public_inputs_hash = QHashOut::from_4_felts_slice(&inner_proof.public_inputs[0..4]);

        let mut flat_bytes: Vec<u8> = inner_proof
            .public_inputs
            .iter()
            .flat_map(|x| (x.to_noncanonical_u64() as u32).to_be_bytes().to_vec())
            .collect();
        if inner_proof.public_inputs.len() % 2 == 1 {
            flat_bytes.extend_from_slice(&0u32.to_be_bytes());
        }
        let mut keccak = tiny_keccak::Keccak::v256();
        let mut hash = [0u8; 32];
        tiny_keccak::Hasher::update(&mut keccak, &flat_bytes);
        tiny_keccak::Hasher::finalize(keccak, &mut hash);
        tracing::info!("deposit_batch prove_groth16_with_shared_wrapper public inputs: keccak256: 0x{}", hex::encode(hash));

        shared_wrapper.prove_groth16(
            &wrapper_proof,
            Some(&format!("/tmp/plonky2_proof/{}", public_inputs_hash)),
        )
    }
}

#[derive(Debug)]
pub struct WithdrawalClaimWrapCircuit {
    pub proof_target: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget,
    pub circuit_data: CircuitData<F, C, D>,
}

impl WithdrawalClaimWrapCircuit {
    pub fn new(common_data: &CommonCircuitData<F, D>, fingerprint: QHashOut<F>, inner_verifier_data_cap_height: usize) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let proof_target = builder.add_virtual_proof_with_pis(common_data);
        let verifier_data_target = builder.add_virtual_verifier_data(inner_verifier_data_cap_height);
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, common_data);

        let expected_fingerprint = builder.constant_hash(fingerprint.into());
        let actual_fingerprint =
            builder.get_circuit_fingerprint::<<C as plonky2::plonk::config::GenericConfig<D>>::Hasher>(&verifier_data_target);
        builder.connect_hashes(expected_fingerprint, actual_fingerprint);

        // Swap pair order so gnark's 64-bit BE limb grouping produces natural word order.
        // See DepositBatchWrapCircuit::new for detailed explanation.
        for pair in proof_target.public_inputs.chunks(2) {
            if pair.len() == 2 {
                let bits1 = builder.split_le(pair[1], 32);
                for bit in &bits1 {
                    builder.register_public_input(bit.target);
                }
                let bits0 = builder.split_le(pair[0], 32);
                for bit in &bits0 {
                    builder.register_public_input(bit.target);
                }
            } else {
                let bits = builder.split_le(pair[0], 32);
                for bit in &bits {
                    builder.register_public_input(bit.target);
                }
                let zero = builder.zero();
                let pad_bits = builder.split_le(zero, 32);
                for bit in &pad_bits {
                    builder.register_public_input(bit.target);
                }
            }
        }

        let circuit_data = builder.build::<C>();
        Self {
            proof_target,
            verifier_data_target,
            circuit_data,
        }
    }

    pub fn into_shared_groth16_wrapper(self, keystore_path: String) -> SharedGroth16Wrapper {
        SharedGroth16Wrapper::new(self.circuit_data, keystore_path)
    }

    pub fn prove_groth16_with_shared_wrapper(
        &self,
        shared_wrapper: &SharedGroth16Wrapper,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        inner_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<UncompressedGroth16ProofData> {
        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&self.proof_target, inner_proof)?;
        pw.set_verifier_data_target(&self.verifier_data_target, verifier_data)?;
        let wrapper_proof = self.circuit_data.prove(pw)?;
        let public_inputs_hash = QHashOut::from_4_felts_slice(&inner_proof.public_inputs[0..4]);

        let flat_bytes: Vec<u8> = inner_proof
            .public_inputs
            .iter()
            .flat_map(|x| (x.to_noncanonical_u64() as u32).to_be_bytes().to_vec())
            .collect();
        let mut keccak = tiny_keccak::Keccak::v256();
        let mut hash = [0u8; 32];
        tiny_keccak::Hasher::update(&mut keccak, &flat_bytes);
        tiny_keccak::Hasher::finalize(keccak, &mut hash);
        tracing::info!(
            "withdrawal_claim prove_groth16_with_shared_wrapper inner public inputs keccak (Bridge calldata order, pre-gnark packing): 0x{}",
            hex::encode(hash)
        );

        shared_wrapper.prove_groth16(
            &wrapper_proof,
            Some(&format!("/tmp/plonky2_proof/{}", public_inputs_hash)),
        )
    }
}

/// User data submitted with a reward batch. Address limbs are little-endian
/// u32 words, matching the recipient encoding in UserRewardFinalCircuit.
#[derive(Clone, Debug)]
pub struct RewardBatchUserInput {
    pub user_id: u64,
    pub recipient: [u32; 5],
    pub amount: u64,
}

#[derive(Clone, Debug)]
pub struct RewardBatchL1Input {
    pub chain_id: u64,
    pub ledger_address: [u32; 5],
    pub batch_id: u64,
    pub users: Vec<RewardBatchUserInput>,
}

impl RewardBatchL1Input {
    pub fn digest(&self, final_public_inputs: &[F]) -> anyhow::Result<[u8; 32]> {
        anyhow::ensure!(final_public_inputs.len() == RewardBatchWrapCircuit::INNER_PUBLIC_INPUTS, "reward batch final public-input count mismatch");
        anyhow::ensure!(!self.users.is_empty() && self.users.len() <= RewardBatchWrapCircuit::MAX_USERS, "invalid reward batch user count");
        let mut words = final_public_inputs.iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>();
        words.push(self.chain_id);
        words.extend(self.ledger_address.map(u64::from));
        words.push(self.batch_id);
        words.push(self.users.len() as u64);
        for i in 0..RewardBatchWrapCircuit::MAX_USERS {
            if let Some(user) = self.users.get(i) {
                words.push(user.user_id);
                words.extend(user.recipient.map(u64::from));
                words.push(user.amount);
            } else {
                words.extend([0u64; 7]);
            }
        }
        let mut keccak = tiny_keccak::Keccak::v256();
        for word in words {
            tiny_keccak::Hasher::update(&mut keccak, &word.to_be_bytes());
        }
        let mut digest = [0u8; 32];
        tiny_keccak::Hasher::finalize(keccak, &mut digest);
        Ok(digest)
    }
}

#[derive(Debug)]
struct RewardBatchUserTarget {
    user_id: Target,
    recipient: [Target; 5],
    amount: Target,
}

/// Fixed Groth16 wrapper over RewardBatchFinalCircuit. In addition to
/// verifying its fingerprint, it opens the Poseidon rewards root against the
/// exact user list whose bytes the L1 verifier will hash. Padding slots are
/// constrained to zero, so the proving key is independent of user count.
#[derive(Debug)]
pub struct RewardBatchWrapCircuit {
    proof_target: ProofWithPublicInputsTarget<D>,
    verifier_data_target: VerifierCircuitTarget,
    chain_id: Target,
    ledger_address: [Target; 5],
    batch_id: Target,
    user_count: Target,
    users: Vec<RewardBatchUserTarget>,
    pub circuit_data: CircuitData<F, C, D>,
}

impl RewardBatchWrapCircuit {
    pub const INNER_PUBLIC_INPUTS: usize = 21;
    pub const MAX_USERS: usize = 32;
    const USER_COUNT_BITS: usize = 6;
    pub const GOLDILOCKS_MODULUS: u64 = 0xFFFF_FFFF_0000_0001;

    fn register_u64(builder: &mut CircuitBuilder<F, D>, value: Target) {
        for bit in builder.split_le(value, 64) {
            builder.register_public_input(bit.target);
        }
    }

    pub fn new(
        common_data: &CommonCircuitData<F, D>,
        fingerprint: QHashOut<F>,
        inner_verifier_data_cap_height: usize,
    ) -> Self {
        assert_eq!(common_data.num_public_inputs, Self::INNER_PUBLIC_INPUTS);
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let proof_target = builder.add_virtual_proof_with_pis(common_data);
        let verifier_data_target = builder.add_virtual_verifier_data(inner_verifier_data_cap_height);
        builder.verify_proof::<C>(&proof_target, &verifier_data_target, common_data);
        let actual_fingerprint = builder.get_circuit_fingerprint::<<C as plonky2::plonk::config::GenericConfig<D>>::Hasher>(&verifier_data_target);
        let expected_fingerprint = builder.constant_hash(fingerprint.into());
        builder.connect_hashes(actual_fingerprint, expected_fingerprint);

        for value in &proof_target.public_inputs {
            Self::register_u64(&mut builder, *value);
        }
        let chain_id = builder.add_virtual_target();
        let ledger_address = builder.add_virtual_target_arr::<5>();
        let batch_id = builder.add_virtual_target();
        let user_count = builder.add_virtual_target();
        builder.range_check(user_count, Self::USER_COUNT_BITS);
        builder.assert_non_zero(user_count);
        let max_users = builder.constant(F::from_canonical_u64(Self::MAX_USERS as u64));
        builder.ensure_is_less_than_or_equal(Self::USER_COUNT_BITS, user_count, max_users);
        Self::register_u64(&mut builder, chain_id);
        for word in ledger_address {
            builder.range_check(word, 32);
            Self::register_u64(&mut builder, word);
        }
        Self::register_u64(&mut builder, batch_id);
        Self::register_u64(&mut builder, user_count);

        let zero = builder.zero();
        let mut users = Vec::with_capacity(Self::MAX_USERS);
        let mut nodes = Vec::with_capacity(Self::MAX_USERS);
        let mut total = zero;
        for i in 0..Self::MAX_USERS {
            let user_id = builder.add_virtual_target();
            let recipient = builder.add_virtual_target_arr::<5>();
            let amount = builder.add_virtual_target();
            builder.range_check(amount, 62);
            let index = builder.constant(F::from_canonical_u64(i as u64));
            let active = builder.is_less_than(Self::USER_COUNT_BITS, index, user_count);
            let inactive = builder.not(active);
            builder.connect_zero_if_true(inactive, user_id);
            builder.connect_zero_if_true(inactive, amount);
            for word in recipient {
                builder.range_check(word, 32);
                builder.connect_zero_if_true(inactive, word);
            }
            let leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
                std::iter::once(user_id)
                    .chain(recipient)
                    .chain([zero; 3])
                    .chain(std::iter::once(amount))
                    .collect(),
            );
            nodes.push(leaf);
            total = builder.add(total, amount);
            builder.range_check(total, 62);
            Self::register_u64(&mut builder, user_id);
            for word in recipient {
                Self::register_u64(&mut builder, word);
            }
            Self::register_u64(&mut builder, amount);
            users.push(RewardBatchUserTarget { user_id, recipient, amount });
        }
        builder.connect(total, proof_target.public_inputs[20]);

        // Canonical QTree shape: pair adjacent nodes; promote an odd tail.
        let mut width = Self::MAX_USERS;
        let mut stride = 1usize;
        while width > 1 {
            let mut next = Vec::with_capacity(width / 2);
            for pair in 0..width / 2 {
                let left = nodes[pair * 2];
                let right = nodes[pair * 2 + 1];
                let merged = builder.hash_two_to_one::<PoseidonHash>(left, right);
                let right_index = builder.constant(F::from_canonical_u64(((pair * 2 + 1) * stride) as u64));
                let right_active = builder.is_less_than(Self::USER_COUNT_BITS, right_index, user_count);
                let elements = std::array::from_fn(|i| builder.select(right_active, merged.elements[i], left.elements[i]));
                next.push(HashOutTarget { elements });
            }
            nodes = next;
            width /= 2;
            stride *= 2;
        }
        let rewards_root = HashOutTarget { elements: proof_target.public_inputs[12..16].try_into().unwrap() };
        builder.connect_hashes(nodes[0], rewards_root);
        let circuit_data = builder.build::<C>();
        Self { proof_target, verifier_data_target, chain_id, ledger_address, batch_id, user_count, users, circuit_data }
    }

    pub fn into_shared_groth16_wrapper(self, keystore_path: String) -> SharedGroth16Wrapper {
        SharedGroth16Wrapper::new(self.circuit_data, keystore_path)
    }

    pub fn prove_wrapper(
        &self,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        final_proof: &ProofWithPublicInputs<F, C, D>,
        l1: &RewardBatchL1Input,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        anyhow::ensure!(final_proof.public_inputs.len() == Self::INNER_PUBLIC_INPUTS, "reward batch final public-input count mismatch");
        anyhow::ensure!(!l1.users.is_empty() && l1.users.len() <= Self::MAX_USERS, "invalid reward batch user count");
        anyhow::ensure!(l1.chain_id < Self::GOLDILOCKS_MODULUS && l1.batch_id < Self::GOLDILOCKS_MODULUS, "reward batch metadata exceeds Goldilocks field");
        for user in &l1.users {
            anyhow::ensure!(user.user_id < Self::GOLDILOCKS_MODULUS && user.amount > 0 && user.amount < (1u64 << 62), "invalid reward batch user input");
        }
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(&self.proof_target, final_proof)?;
        witness.set_verifier_data_target(&self.verifier_data_target, verifier_data)?;
        witness.set_target(self.chain_id, F::from_canonical_u64(l1.chain_id))?;
        for (target, word) in self.ledger_address.iter().zip(l1.ledger_address) {
            witness.set_target(*target, F::from_canonical_u32(word))?;
        }
        witness.set_target(self.batch_id, F::from_canonical_u64(l1.batch_id))?;
        witness.set_target(self.user_count, F::from_canonical_usize(l1.users.len()))?;
        for (i, slot) in self.users.iter().enumerate() {
            let input = l1.users.get(i);
            witness.set_target(slot.user_id, F::from_canonical_u64(input.map_or(0, |v| v.user_id)))?;
            witness.set_target(slot.amount, F::from_canonical_u64(input.map_or(0, |v| v.amount)))?;
            for (target, word) in slot.recipient.iter().zip(input.map_or([0; 5], |v| v.recipient)) {
                witness.set_target(*target, F::from_canonical_u32(word))?;
            }
        }
        Ok(self.circuit_data.prove(witness)?)
    }

    pub fn prove_groth16_with_shared_wrapper(
        &self,
        shared_wrapper: &SharedGroth16Wrapper,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
        final_proof: &ProofWithPublicInputs<F, C, D>,
        l1: &RewardBatchL1Input,
    ) -> anyhow::Result<UncompressedGroth16ProofData> {
        let wrapper_proof = self.prove_wrapper(verifier_data, final_proof, l1)?;
        let digest = l1.digest(&final_proof.public_inputs)?;
        tracing::info!("reward_batch L1 digest: 0x{}", hex::encode(digest));
        shared_wrapper.prove_groth16(&wrapper_proof, None)
    }
}
