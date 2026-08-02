use plonky2::{
    field::extension::Extendable,
    gates::gate::GateRef,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
    util::serialization::{Buffer, Read, Write},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::privacy::deposit_inclusion::DepositInclusionInput;
use psy_common_circuit::{
    builder::pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
    circuits::traits::qstandard::QStandardCircuit,
    hash::merkle::gadgets::merkle_proof::{MerkleProofGadget, OptionalMerkleProofGadget},
    proof_minifier::{pm_chain::PsyProofMinifierChain, pm_core::get_circuit_fingerprint_generic},
    serialization::{from_bytes_compact, to_bytes_compact, PsyGateSerializer, PsyGeneratorSerializer},
    u32::gates::comparison::ComparisonGate,
};

const DEPOSIT_TREE_HEIGHT: usize = 32;

#[derive(Debug)]
pub struct DepositInclusionGadget {
    pub nullifier_secret: [Target; 4],
    pub note_secret: [Target; 4],
    pub shield_address: HashOutTarget,
    pub deposit_index: Target,
    pub source_chain_index: Target,
    pub deposit_proof: MerkleProofGadget,
    pub deposit_root: HashOutTarget,
    pub nullifier_hash: HashOutTarget,
    pub deposit_commitment: HashOutTarget,
    pub token_address_words: [Target; 8],
    pub l2_token_contract_id_words: [Target; 8],
    pub amount_words: [Target; 8],
}
// Permanent dual-name seam: wire/protocol uses `shield_deposit_claim` (JSON-RPC
// method names, serde); circuit/data layer uses `DepositInclusion`. These
// aliases export the old name for the protocol layer.
pub type ShieldDepositClaimGadget = DepositInclusionGadget;
pub type ShieldDepositClaimInput<F> = DepositInclusionInput<F>;

impl DepositInclusionGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let nullifier_secret = std::array::from_fn(|_| builder.add_virtual_target());
        let note_secret = std::array::from_fn(|_| builder.add_virtual_target());
        let shield_address = builder.add_virtual_hash();
        let deposit_index = builder.add_virtual_target();
        let source_chain_index = builder.add_virtual_target();
        let token_address_words = std::array::from_fn(|_| builder.add_virtual_target());
        let l2_token_contract_id_words = std::array::from_fn(|_| builder.add_virtual_target());
        let amount_words = std::array::from_fn(|_| builder.add_virtual_target());
        let zero = builder.zero();

        let nullifier_hash = builder.hash_n_to_hash_no_pad::<H>(nullifier_secret.to_vec());
        let note_commitment = builder.hash_n_to_hash_no_pad::<H>(vec![
            nullifier_secret[0],
            nullifier_secret[1],
            nullifier_secret[2],
            nullifier_secret[3],
            note_secret[0],
            note_secret[1],
            note_secret[2],
            note_secret[3],
        ]);

        for word in amount_words.iter().take(6) {
            builder.connect(*word, zero);
        }

        // Keep the exact field/u32 layout used by the relayer deposit leaf.
        // This proof must commit to the same leaf the receiver later claims.
        let shield_address_words: [Target; 8] = std::array::from_fn(|i| {
            let elem_idx = i / 2;
            let (low, high) = builder.split_low_high(shield_address.elements[elem_idx], 32, 64);
            if i % 2 == 0 {
                high
            } else {
                low
            }
        });
        let note_commitment_words: [Target; 8] = std::array::from_fn(|i| {
            let elem_idx = i / 2;
            let (low, high) = builder.split_low_high(note_commitment.elements[elem_idx], 32, 64);
            if i % 2 == 0 {
                high
            } else {
                low
            }
        });

        let mut deposit_commitment_preimage = Vec::with_capacity(41);
        deposit_commitment_preimage.extend_from_slice(&shield_address_words);
        deposit_commitment_preimage.extend_from_slice(&token_address_words);
        deposit_commitment_preimage.extend_from_slice(&l2_token_contract_id_words);
        deposit_commitment_preimage.extend_from_slice(&amount_words);
        deposit_commitment_preimage.push(source_chain_index);
        deposit_commitment_preimage.extend_from_slice(&note_commitment_words);
        let deposit_commitment = builder.hash_n_to_hash_no_pad::<H>(deposit_commitment_preimage);

        let deposit_proof = MerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            DEPOSIT_TREE_HEIGHT,
            OptionalMerkleProofGadget {
                root: None,
                value: Some(deposit_commitment),
                index: Some(deposit_index),
                siblings: None,
            },
        );
        let deposit_root = deposit_proof.root;

        let public_inputs_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            shield_address.elements[0],
            shield_address.elements[1],
            shield_address.elements[2],
            shield_address.elements[3],
            amount_words[0],
            amount_words[1],
            amount_words[2],
            amount_words[3],
            amount_words[4],
            amount_words[5],
            amount_words[6],
            amount_words[7],
            token_address_words[0],
            token_address_words[1],
            token_address_words[2],
            token_address_words[3],
            token_address_words[4],
            token_address_words[5],
            token_address_words[6],
            token_address_words[7],
            l2_token_contract_id_words[0],
            l2_token_contract_id_words[1],
            l2_token_contract_id_words[2],
            l2_token_contract_id_words[3],
            l2_token_contract_id_words[4],
            l2_token_contract_id_words[5],
            l2_token_contract_id_words[6],
            l2_token_contract_id_words[7],
            source_chain_index,
            deposit_root.elements[0],
            deposit_root.elements[1],
            deposit_root.elements[2],
            deposit_root.elements[3],
            nullifier_hash.elements[0],
            nullifier_hash.elements[1],
            nullifier_hash.elements[2],
            nullifier_hash.elements[3],
            note_commitment.elements[0],
            note_commitment.elements[1],
            note_commitment.elements[2],
            note_commitment.elements[3],
            deposit_index,
        ]);
        builder.register_public_inputs(&public_inputs_hash.elements);

        Self {
            nullifier_secret,
            note_secret,
            shield_address,
            deposit_index,
            source_chain_index,
            deposit_proof,
            deposit_root,
            nullifier_hash,
            deposit_commitment,
            token_address_words,
            l2_token_contract_id_words,
            amount_words,
        }
    }

    pub fn set_witness<F: RichField>(&self, pw: &mut PartialWitness<F>, input: &DepositInclusionInput<F>) -> anyhow::Result<()> {
        anyhow::ensure!(
            input.deposit_proof.root == input.deposit_root,
            "deposit_root does not match deposit_proof.root"
        );
        for (target, value) in self.nullifier_secret.iter().zip(input.nullifier_secret) {
            pw.set_target(*target, value)?;
        }
        for (target, value) in self.note_secret.iter().zip(input.note_secret) {
            pw.set_target(*target, value)?;
        }
        pw.set_hash_target(self.shield_address, input.shield_address.0)?;
        pw.set_target(self.deposit_index, F::from_canonical_u64(input.deposit_index))?;
        pw.set_target(self.source_chain_index, F::from_canonical_u64(input.source_chain_index as u64))?;
        for (target, word) in self.token_address_words.iter().zip(input.token_address) {
            pw.set_target(*target, F::from_canonical_u64(word as u64))?;
        }
        for (target, word) in self.l2_token_contract_id_words.iter().zip(input.l2_token_contract_id) {
            pw.set_target(*target, F::from_canonical_u64(word as u64))?;
        }
        for (target, word) in self.amount_words.iter().zip(input.amount) {
            pw.set_target(*target, F::from_canonical_u64(word as u64))?;
        }
        // The value is already constrained in-circuit as `deposit_commitment`
        // (passed as `value: Some(deposit_commitment)`). Do not set the proof
        // value witness here, or it would overwrite wires assigned by Poseidon.
        self.deposit_proof.set_witness_core_proof_q(pw, &input.deposit_proof)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct DepositInclusionCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    gadget: DepositInclusionGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub minifier_chain: PsyProofMinifierChain<D, C::F, C>,
}

impl<C: GenericConfig<D>, const D: usize> DepositInclusionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let gadget = DepositInclusionGadget::add_virtual_to::<C::Hasher, C::F, D>(&mut builder);
        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 11);
        let circuit_data = builder.build::<C>();
        let added_gates_for_minifier = [GateRef::new(ComparisonGate::new(32, 16))];
        let minifier_chain =
            PsyProofMinifierChain::<D, C::F, C>::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&added_gates_for_minifier));
        Self {
            gadget,
            circuit_data,
            minifier_chain,
        }
    }

    /// Serialize base `circuit_data` (length-prefixed) followed by the minifier
    /// chain.
    pub fn serialize(&self) -> anyhow::Result<Vec<u8>> {
        let gate_serializer = PsyGateSerializer;
        let generator_serializer = PsyGeneratorSerializer::<C, D> {
            _phantom: std::marker::PhantomData,
        };
        let base = self
            .circuit_data
            .to_bytes(&gate_serializer, &generator_serializer)
            .map_err(|e| anyhow::anyhow!("deposit inclusion circuit_data serialize failed: {e:?}"))?;

        let mut buf = Vec::new();
        buf.write_usize(base.len()).map_err(|e| anyhow::anyhow!("write base len failed: {e:?}"))?;
        buf.write_all(&base).map_err(|e| anyhow::anyhow!("write base failed: {e:?}"))?;
        let chain = self.minifier_chain.to_bytes(&gate_serializer, &generator_serializer)?;
        buf.write_all(&chain).map_err(|e| anyhow::anyhow!("write minifier chain failed: {e:?}"))?;
        Ok(buf)
    }

    pub fn new_with_serialized(bytes: &[u8]) -> anyhow::Result<Self> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        // Re-create the gadget targets in the same order as `new()`; builder is
        // discarded.
        let gadget = DepositInclusionGadget::add_virtual_to::<C::Hasher, C::F, D>(&mut builder);

        let gate_serializer = PsyGateSerializer;
        let generator_serializer = PsyGeneratorSerializer::<C, D> {
            _phantom: std::marker::PhantomData,
        };

        let mut buffer = Buffer::new(bytes);
        let base_len = buffer.read_usize().map_err(|e| anyhow::anyhow!("read base len failed: {e:?}"))?;
        let mut base_bytes = vec![0u8; base_len];
        buffer
            .read_exact(&mut base_bytes)
            .map_err(|e| anyhow::anyhow!("read base failed: {e:?}"))?;
        let circuit_data = CircuitData::<C::F, C, D>::from_bytes(&base_bytes, &gate_serializer, &generator_serializer)
            .map_err(|e| anyhow::format_err!("deposit inclusion circuit_data deserialize failed: {e}"))?;

        let chain_bytes = buffer.unread_bytes();
        let minifier_chain = PsyProofMinifierChain::<D, C::F, C>::from_bytes(chain_bytes, &gate_serializer, &generator_serializer)?;

        Ok(Self {
            gadget,
            circuit_data,
            minifier_chain,
        })
    }

    pub fn prove(&self, input: &DepositInclusionInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        self.gadget.set_witness(&mut pw, input)?;
        let base_proof = self.circuit_data.prove(pw)?;
        let minified_proof = self.minifier_chain.prove(&base_proof)?;
        Ok(minified_proof)
    }

    /// Minify a *base* proof produced by `ShieldDepositClaimInnerCircuit`
    /// (server-side).
    pub fn prove_minifier(&self, base_proof: ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.minifier_chain.prove(&base_proof)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for DepositInclusionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}

/// Base-only shield deposit claim circuit (no minifier chain). Lives in the
/// wallet and produces *base* proofs; minification is done server-side by the
/// manager's [`ShieldDepositClaimCircuit`]. Mirrors
/// `PsyBasicZKSignatureInnerCircuit`.
pub type ShieldDepositClaimCircuit<C, const D: usize> = DepositInclusionCircuit<C, D>;
#[derive(Debug)]
pub struct ShieldDepositClaimInnerCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    gadget: ShieldDepositClaimGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
    fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> ShieldDepositClaimInnerCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let gadget = ShieldDepositClaimGadget::add_virtual_to::<C::Hasher, C::F, D>(&mut builder);
        builder.add_psy_type_b_common_gates();
        pad_circuit_degree::<C::F, D>(&mut builder, 11);
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Self {
            gadget,
            circuit_data,
            fingerprint,
        }
    }

    /// Produce a *base* proof (no minification).
    pub fn prove(&self, input: &ShieldDepositClaimInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut pw = PartialWitness::<C::F>::new();
        self.gadget.set_witness(&mut pw, input)?;
        self.circuit_data.prove(pw)
    }

    pub fn serialize_circuit_data(&self) -> anyhow::Result<Vec<u8>> {
        let gate_serializer = PsyGateSerializer;
        let generator_serializer = PsyGeneratorSerializer::<C, D> {
            _phantom: std::marker::PhantomData,
        };
        self.circuit_data
            .to_bytes(&gate_serializer, &generator_serializer)
            .map_err(|e| anyhow::anyhow!("shield deposit claim inner circuit_data serialize failed: {e:?}"))
    }

    pub fn new_with_serialized_circuit(bytes: &[u8]) -> anyhow::Result<Self> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        // Must mirror `new()`'s gadget creation so wire indices match the bytes.
        let gadget = ShieldDepositClaimGadget::add_virtual_to::<C::Hasher, C::F, D>(&mut builder);
        let gate_serializer = PsyGateSerializer;
        let generator_serializer = PsyGeneratorSerializer::<C, D> {
            _phantom: std::marker::PhantomData,
        };
        let circuit_data = CircuitData::<C::F, C, D>::from_bytes(bytes, &gate_serializer, &generator_serializer)
            .map_err(|e| anyhow::format_err!("shield deposit claim inner circuit_data deserialize failed: {e}"))?;
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Ok(Self {
            gadget,
            circuit_data,
            fingerprint,
        })
    }

    /// Compact serialization: omits the derivable Merkle tree (~3.5x smaller);
    /// rebuilt on load.
    pub fn serialize_circuit_data_compact(&mut self) -> anyhow::Result<Vec<u8>> {
        let gate_serializer = PsyGateSerializer;
        let generator_serializer = PsyGeneratorSerializer::<C, D> {
            _phantom: std::marker::PhantomData,
        };
        to_bytes_compact(&mut self.circuit_data, &gate_serializer, &generator_serializer)
    }

    pub fn new_with_serialized_circuit_compact(bytes: &[u8]) -> anyhow::Result<Self> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let gadget = ShieldDepositClaimGadget::add_virtual_to::<C::Hasher, C::F, D>(&mut builder);
        let gate_serializer = PsyGateSerializer;
        let generator_serializer = PsyGeneratorSerializer::<C, D> {
            _phantom: std::marker::PhantomData,
        };
        let circuit_data = from_bytes_compact::<C::F, C, D>(bytes, &gate_serializer, &generator_serializer)?;
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));
        Ok(Self {
            gadget,
            circuit_data,
            fingerprint,
        })
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for ShieldDepositClaimInnerCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}

#[cfg(test)]
mod tests {

    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;

    use super::*;

    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn deposit_inclusion_circuit_builds() {
        let circuit = DepositInclusionCircuit::<C, D>::new();
        assert_eq!(circuit.circuit_data.common.num_public_inputs, 4);
        assert_eq!(circuit.get_common_circuit_data_ref().num_public_inputs, 4);
        println!("deposit inclusion fingerprint: {:?}", circuit.get_fingerprint());
    }

    /// build -> serialize (incl. minifier chain) -> deserialize, asserting
    /// fidelity. `cargo test -p psy_dpn_circuit
    /// shield_deposit_claim_serialize_round_trip -- --nocapture`
    #[test]
    fn shield_deposit_claim_serialize_round_trip() -> anyhow::Result<()> {
        use std::time::Instant;

        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let t0 = Instant::now();
        let circuit = ShieldDepositClaimCircuit::<C, D>::new();
        let build_time = t0.elapsed();

        let bytes = circuit.serialize()?;

        let t1 = Instant::now();
        let restored = ShieldDepositClaimCircuit::<C, D>::new_with_serialized(&bytes)?;
        let deserialize_time = t1.elapsed();

        assert_eq!(restored.circuit_data, circuit.circuit_data, "base circuit_data mismatch");
        assert_eq!(restored.get_fingerprint(), circuit.get_fingerprint(), "minified fingerprint mismatch");
        assert_eq!(
            restored.get_common_circuit_data_ref(),
            circuit.get_common_circuit_data_ref(),
            "minified common mismatch"
        );
        assert_eq!(restored.serialize()?, bytes, "round-trip bytes differ");

        let speedup = build_time.as_secs_f64() / deserialize_time.as_secs_f64();
        println!("ShieldDepositClaim (incl. minifier)  size: {} KiB", bytes.len() / 1024);
        println!("  build()      : {:>10.3?}", build_time);
        println!("  from_bytes() : {:>10.3?}  ({:.2}x)", deserialize_time, speedup);
        Ok(())
    }
}
