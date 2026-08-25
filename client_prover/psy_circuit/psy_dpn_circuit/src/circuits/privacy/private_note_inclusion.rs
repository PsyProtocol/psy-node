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
use psy_client_data::privacy::private_note_inclusion::PrivateNoteInclusionInput;
use psy_common_circuit::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderPsyCommonGates},
    },
    circuits::traits::qstandard::QStandardCircuit,
    hash::merkle::gadgets::merkle_proof::{MerkleProofGadget, OptionalMerkleProofGadget},
    proof_minifier::{pm_chain::PsyProofMinifierChain, pm_core::get_circuit_fingerprint_generic},
    serialization::{from_bytes_compact, to_bytes_compact, PsyGateSerializer, PsyGeneratorSerializer},
    traits::CreatableTarget,
    u32::gates::comparison::ComparisonGate,
};

use super::slot_value_in_contract_state::{SlotValueInContractStateGadget, SlotValueInContractStateWitnessInput};

/// Gadget for the privacy note existence proof.
///
/// Proves that a note commitment exists under a note root that is bound to
/// the global user tree, without revealing sender identity or spending key.
///
/// Public inputs (4 field elements):
///   [0..4]   public_inputs_hash = hash_n_to_hash_no_pad([
///              receiver(owner)[0..4], amount, user_tree_root[0..4],
///              checkpoint_id, slot_index, token_contract_id,
///              nullifier_hash[0..4]
///            ])

#[derive(Debug)]
pub struct PrivateNoteInclusionGadget {
    // Private witness targets
    pub nullifier_secret: HashOutTarget,

    // Merkle proof gadgets
    pub note_membership_proof: MerkleProofGadget,
    pub slot_value_in_contract_state: SlotValueInContractStateGadget,

    // Public input targets
    pub nullifier: HashOutTarget,
    pub owner: HashOutTarget,
    pub amount: Target,
    pub note_secret: HashOutTarget,
    pub user_tree_root: HashOutTarget,
    pub checkpoint_id: Target,
}

impl PrivateNoteInclusionGadget {
    /// Build the gadget constraints inside the given circuit builder.
    ///
    /// Tree heights are passed as parameters so the circuit can be
    /// instantiated for different network configurations.
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        global_user_tree_height: usize,
        global_contract_tree_height: usize,
        contract_state_tree_height: usize,
        note_tree_height: usize,
    ) -> Self {
        // --- Private witness targets ---
        let nullifier_secret = builder.add_virtual_hash();
        let note_secret = builder.add_virtual_hash();
        // --- Public input targets ---
        let owner = builder.add_virtual_hash();
        let amount = builder.add_virtual_target();
        let checkpoint_id = builder.add_virtual_target();

        // ============================================================
        // Constraint 1-3: Reconstruct commitment from public inputs
        // ============================================================

        // value_hash = [amount, 0, 0, 0]
        let zero = builder.zero();
        let value_hash = HashOutTarget {
            elements: [amount, zero, zero, zero],
        };

        // inner_hash = Hash(owner, value_hash)
        let inner_hash = builder.hash_two_to_one::<H>(owner, value_hash);

        let note_commitment = builder.hash_n_to_hash_no_pad::<H>(vec![
            nullifier_secret.elements[0],
            nullifier_secret.elements[1],
            nullifier_secret.elements[2],
            nullifier_secret.elements[3],
            note_secret.elements[0],
            note_secret.elements[1],
            note_secret.elements[2],
            note_secret.elements[3],
        ]);

        // commitment = Hash(inner_hash, note_commitment)
        let commitment = builder.hash_two_to_one::<H>(inner_hash, note_commitment);

        // ============================================================
        // Constraint 4: note membership proof
        //   commitment at note_index -> note_root
        // ============================================================
        let note_membership_proof = MerkleProofGadget::add_virtual_to_with_options::<H, F, D>(
            builder,
            note_tree_height,
            OptionalMerkleProofGadget {
                root: None,
                value: Some(commitment),
                index: None,
                siblings: None,
            },
        );
        let note_root = note_membership_proof.root;

        let slot_value_in_contract_state = SlotValueInContractStateGadget::add_virtual_to::<H, F, D>(
            builder,
            global_user_tree_height,
            global_contract_tree_height,
            contract_state_tree_height,
            note_root,
        );
        let user_tree_root = slot_value_in_contract_state.user_tree_root;

        // ============================================================
        // Constraint 9: nullifier_hash = Hash(nullifier_secret)
        // ============================================================
        let nullifier = builder.hash_n_to_hash_no_pad::<H>(vec![
            nullifier_secret.elements[0],
            nullifier_secret.elements[1],
            nullifier_secret.elements[2],
            nullifier_secret.elements[3],
        ]);

        // ============================================================
        // Register public inputs (4 field elements)
        // Hash all 16 values into a single HashOut for proof tree
        // aggregation compatibility.
        // ============================================================
        let public_inputs_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            owner.elements[0],
            owner.elements[1],
            owner.elements[2],
            owner.elements[3],
            amount,
            user_tree_root.elements[0],
            user_tree_root.elements[1],
            user_tree_root.elements[2],
            user_tree_root.elements[3],
            checkpoint_id,
            slot_value_in_contract_state.slot_index,
            slot_value_in_contract_state.contract_id,
            nullifier.elements[0],
            nullifier.elements[1],
            nullifier.elements[2],
            nullifier.elements[3],
        ]);
        builder.register_public_inputs(&public_inputs_hash.elements);

        Self {
            nullifier_secret,
            note_membership_proof,
            slot_value_in_contract_state,
            nullifier,
            owner,
            amount,
            note_secret,
            user_tree_root,
            checkpoint_id,
        }
    }

    /// Set witness values from a `PrivateNoteInclusionInput`.
    pub fn set_witness<F: RichField>(&self, pw: &mut PartialWitness<F>, input: &PrivateNoteInclusionInput<F>) -> anyhow::Result<()> {
        tracing::info!(
            "PrivateNoteInclusion set_witness: checkpoint_id={} sender_user_id={} contract_id={} note_root_slot={} note_index={} membership_root={} slot_value={} slot_root={}",
            input.checkpoint_id,
            input.sender_user_id,
            input.contract_id,
            input.note_root_slot,
            input.note_membership_proof.index,
            input.note_membership_proof.root,
            input.note_root_slot_proof.value,
            input.note_root_slot_proof.root
        );
        if input.note_membership_proof.root != input.note_root_slot_proof.value {
            anyhow::bail!(
                "PrivateNoteInclusion root mismatch before witness set: membership_root={} != slot_value={}; refusing to set a witness that would later fail proof tree root mismatch",
                input.note_membership_proof.root,
                input.note_root_slot_proof.value
            );
        }

        // Private witnesses
        pw.set_hash_target(self.nullifier_secret, input.nullifier_secret.0)?;
        pw.set_hash_target(self.note_secret, input.note_secret.0)?;
        pw.set_target(self.checkpoint_id, input.checkpoint_id)?;

        // Public input witnesses
        pw.set_hash_target(self.owner, input.owner.0)?;
        pw.set_target(self.amount, input.amount)?;

        // Merkle proofs
        self.note_membership_proof.set_witness_core_proof_q(pw, &input.note_membership_proof)?;
        self.slot_value_in_contract_state.set_witness(
            pw,
            &SlotValueInContractStateWitnessInput {
                sender_user_id: input.sender_user_id,
                contract_id: input.contract_id,
                slot_index: input.note_root_slot,
                user_leaf: input.user_leaf.clone(),
                slot_proof: input.note_root_slot_proof.clone(),
                contract_proof: input.contract_proof.clone(),
                user_tree_proof: input.user_tree_proof.clone(),
            },
        )?;

        Ok(())
    }
}

/// The compiled privacy note existence circuit.
///
/// Instantiate with `new(...)`, then call `prove(...)` to generate proofs.
#[derive(Debug)]
pub struct PrivateNoteInclusionCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    gadget: PrivateNoteInclusionGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub minifier_chain: PsyProofMinifierChain<D, C::F, C>,
}

impl<C: GenericConfig<D>, const D: usize> PrivateNoteInclusionCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        global_user_tree_height: usize,
        global_contract_tree_height: usize,
        contract_state_tree_height: usize,
        note_tree_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let gadget = PrivateNoteInclusionGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            global_user_tree_height,
            global_contract_tree_height,
            contract_state_tree_height,
            note_tree_height,
        );

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
            .map_err(|e| anyhow::anyhow!("private note inclusion circuit_data serialize failed: {e:?}"))?;

        let mut buf = Vec::new();
        buf.write_usize(base.len()).map_err(|e| anyhow::anyhow!("write base len failed: {e:?}"))?;
        buf.write_all(&base).map_err(|e| anyhow::anyhow!("write base failed: {e:?}"))?;
        let chain = self.minifier_chain.to_bytes(&gate_serializer, &generator_serializer)?;
        buf.write_all(&chain).map_err(|e| anyhow::anyhow!("write minifier chain failed: {e:?}"))?;
        Ok(buf)
    }

    pub fn new_with_serialized(
        bytes: &[u8],
        global_user_tree_height: usize,
        global_contract_tree_height: usize,
        contract_state_tree_height: usize,
        note_tree_height: usize,
    ) -> anyhow::Result<Self> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        // Must mirror `new()`'s gadget creation exactly so wire indices line up with
        // the deserialized circuit data; the builder is then discarded.
        let gadget = PrivateNoteInclusionGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            global_user_tree_height,
            global_contract_tree_height,
            contract_state_tree_height,
            note_tree_height,
        );

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
            .map_err(|e| anyhow::format_err!("private note inclusion circuit_data deserialize failed: {e}"))?;

        let chain_bytes = buffer.unread_bytes();
        let minifier_chain = PsyProofMinifierChain::<D, C::F, C>::from_bytes(chain_bytes, &gate_serializer, &generator_serializer)?;

        Ok(Self {
            gadget,
            circuit_data,
            minifier_chain,
        })
    }

    pub fn prove(&self, input: &PrivateNoteInclusionInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        tracing::info!(
            "PrivateNoteInclusion prove start: checkpoint_id={} sender_user_id={} contract_id={} note_root_slot={}",
            input.checkpoint_id,
            input.sender_user_id,
            input.contract_id,
            input.note_root_slot
        );
        let mut pw = PartialWitness::<C::F>::new();
        self.gadget.set_witness(&mut pw, input)?;
        let base_proof = self.circuit_data.prove(pw)?;
        let minified_proof = self.minifier_chain.prove(&base_proof)?;
        Ok(minified_proof)
    }

    /// Minify a *base* proof produced by `PrivateNoteInclusionInnerCircuit`
    /// (server-side).
    pub fn prove_minifier(&self, base_proof: ProofWithPublicInputs<C::F, C, D>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.minifier_chain.prove(&base_proof)
    }
}

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for PrivateNoteInclusionCircuit<C, D>
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

/// Base-only private note inclusion circuit (no minifier chain). Lives in the
/// wallet and produces *base* proofs; minification is done server-side by the
/// manager's [`PrivateNoteInclusionCircuit`]. Mirrors
/// `PsyBasicZKSignatureInnerCircuit`.
#[derive(Debug)]
pub struct PrivateNoteInclusionInnerCircuit<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    gadget: PrivateNoteInclusionGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
    fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> PrivateNoteInclusionInnerCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        global_user_tree_height: usize,
        global_contract_tree_height: usize,
        contract_state_tree_height: usize,
        note_tree_height: usize,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let gadget = PrivateNoteInclusionGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            global_user_tree_height,
            global_contract_tree_height,
            contract_state_tree_height,
            note_tree_height,
        );
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
    pub fn prove(&self, input: &PrivateNoteInclusionInput<C::F>) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
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
            .map_err(|e| anyhow::anyhow!("private note inclusion inner circuit_data serialize failed: {e:?}"))
    }

    pub fn new_with_serialized_circuit(
        bytes: &[u8],
        global_user_tree_height: usize,
        global_contract_tree_height: usize,
        contract_state_tree_height: usize,
        note_tree_height: usize,
    ) -> anyhow::Result<Self> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        // Must mirror `new()`'s gadget creation so wire indices match the bytes.
        let gadget = PrivateNoteInclusionGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            global_user_tree_height,
            global_contract_tree_height,
            contract_state_tree_height,
            note_tree_height,
        );
        let gate_serializer = PsyGateSerializer;
        let generator_serializer = PsyGeneratorSerializer::<C, D> {
            _phantom: std::marker::PhantomData,
        };
        let circuit_data = CircuitData::<C::F, C, D>::from_bytes(bytes, &gate_serializer, &generator_serializer)
            .map_err(|e| anyhow::format_err!("private note inclusion inner circuit_data deserialize failed: {e}"))?;
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

    pub fn new_with_serialized_circuit_compact(
        bytes: &[u8],
        global_user_tree_height: usize,
        global_contract_tree_height: usize,
        contract_state_tree_height: usize,
        note_tree_height: usize,
    ) -> anyhow::Result<Self> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let gadget = PrivateNoteInclusionGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            global_user_tree_height,
            global_contract_tree_height,
            contract_state_tree_height,
            note_tree_height,
        );
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

impl<C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for PrivateNoteInclusionInnerCircuit<C, D>
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
    use psy_client_common::data::qhashout::QHashOut;
    use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;

    use super::*;

    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    /// End-to-end base→minify compatibility: the wallet's base-only
    /// `PrivateNoteInclusionInnerCircuit` must be byte-identical (verifier
    /// + common) to the base of the server's `PrivateNoteInclusionCircuit`,
    /// whose minifier chain is built from exactly that base. This is the
    /// precondition that lets the manager minify a base proof produced by the
    /// wallet. (A real proof flow needs a valid `PrivateNoteInclusionInput`
    /// with merkle proofs, which the repo has no fixture for; the
    /// `*_serialize_round_trip` test already exercises the full
    /// circuit's own base→minify→verify path.)
    /// Quantifies where the base circuit's serialized bytes go, to see how much
    /// is *derivable* (recomputable on load) vs irreducible.
    /// `cargo test -p psy_dpn_circuit
    /// private_note_inclusion_prover_only_breakdown -- --nocapture` Compact
    /// serialization (omit derivable Merkle/fft, rebuild from poly coeffs on
    /// load) vs full serialization, on the 33 MiB base circuit. Asserts the
    /// rebuilt circuit's common/verifier data is identical.
    /// `cargo test -p psy_dpn_circuit private_note_inclusion_compact_size --
    /// --nocapture`
    #[test]
    fn private_note_inclusion_compact_size_and_timing() {
        use std::time::Instant;

        use plonky2::field::goldilocks_field::GoldilocksField as F;
        use psy_common_circuit::serialization::{from_bytes_compact, to_bytes_compact, PsyGateSerializer, PsyGeneratorSerializer};

        let gate_ser = PsyGateSerializer;
        let gen_ser = PsyGeneratorSerializer::<C, D> {
            _phantom: std::marker::PhantomData,
        };

        // Direct build (the cost compact loading avoids).
        let t0 = Instant::now();
        let mut c = PrivateNoteInclusionInnerCircuit::<C, D>::new(32, 24, 20, 20);
        let build_time = t0.elapsed();

        let full = c.circuit_data.to_bytes(&gate_ser, &gen_ser).unwrap();
        let compact = to_bytes_compact(&mut c.circuit_data, &gate_ser, &gen_ser).unwrap();

        // Full deserialize (reads the stored Merkle tree as-is).
        let t1 = Instant::now();
        let _restored_full = plonky2::plonk::circuit_data::CircuitData::<F, C, D>::from_bytes(&full, &gate_ser, &gen_ser).unwrap();
        let full_load_time = t1.elapsed();

        // Compact deserialize (rebuilds the Merkle tree from poly coeffs via FFT+hash).
        let t2 = Instant::now();
        let restored = from_bytes_compact::<F, C, D>(&compact, &gate_ser, &gen_ser).unwrap();
        let compact_load_time = t2.elapsed();

        assert_eq!(restored.common, c.circuit_data.common, "common mismatch after rebuild");
        assert_eq!(restored.verifier_only, c.circuit_data.verifier_only, "verifier mismatch after rebuild");

        println!("PrivateNoteInclusion base (33MiB circuit):");
        println!(
            "  size      : full {} MiB -> compact {} MiB ({:.2}x smaller)",
            full.len() / 1024 / 1024,
            compact.len() / 1024 / 1024,
            full.len() as f64 / compact.len() as f64
        );
        println!("  build()              : {:>10.3?}", build_time);
        println!(
            "  full from_bytes()    : {:>10.3?}  ({:.1}x vs build)",
            full_load_time,
            build_time.as_secs_f64() / full_load_time.as_secs_f64()
        );
        println!(
            "  compact from_bytes()  : {:>10.3?}  ({:.1}x vs build, +rebuild Merkle)",
            compact_load_time,
            build_time.as_secs_f64() / compact_load_time.as_secs_f64()
        );
    }

    #[test]
    fn private_note_inclusion_prover_only_breakdown() {
        const FE: usize = 8; // GoldilocksField = u64
        const HASH: usize = 32; // HashOut = 4 field elements

        let c = PrivateNoteInclusionInnerCircuit::<C, D>::new(32, 24, 20, 20);
        let total = c.serialize_circuit_data().unwrap().len();
        let po = &c.circuit_data.prover_only;
        let csc = &po.constants_sigmas_commitment;

        let polys = csc.polynomials.iter().map(|p| p.coeffs.len()).sum::<usize>() * FE;
        let leaves = csc.merkle_tree.leaves.iter().map(|l| l.len()).sum::<usize>() * FE;
        let digests = csc.merkle_tree.digests.len() * HASH;
        let cap = csc.merkle_tree.cap.0.len() * HASH;
        let sigmas = po.sigmas.iter().map(|s| s.len()).sum::<usize>() * FE;
        let subgroup = po.subgroup.len() * FE;
        let fft = po.fft_root_table.as_ref().map(|t| t.iter().map(|r| r.len()).sum::<usize>()).unwrap_or(0) * FE;

        let mib = |b: usize| b as f64 / 1024.0 / 1024.0;
        println!("PrivateNoteInclusion base — total serialized {:.1} MiB", mib(total));
        println!("  constants_sigmas_commitment:");
        println!("    polynomials (coeffs, SOURCE)  : {:>6.1} MiB", mib(polys));
        println!("    merkle leaves (LDE, ∝polys)   : {:>6.1} MiB  <- derivable via FFT", mib(leaves));
        println!("    merkle digests (hashes)       : {:>6.1} MiB  <- derivable by re-hash", mib(digests));
        println!("    merkle cap                    : {:>6.1} MiB", mib(cap));
        println!("  sigmas (Vec<Vec<F>>)            : {:>6.1} MiB", mib(sigmas));
        println!("  subgroup                        : {:>6.1} MiB", mib(subgroup));
        println!("  fft_root_table                  : {:>6.1} MiB  <- derivable", mib(fft));
        let derivable = leaves + digests + fft;
        println!(
            "  => derivable (leaves+digests+fft): {:.1} MiB ({:.0}% of total); keep-only-source floor ~{:.1} MiB",
            mib(derivable),
            100.0 * derivable as f64 / total as f64,
            mib(total - derivable)
        );
    }

    #[test]
    fn private_note_inclusion_inner_base_matches_minifier_base() {
        let heights = (32usize, 24usize, 20usize, 20usize);
        let inner = PrivateNoteInclusionInnerCircuit::<C, D>::new(heights.0, heights.1, heights.2, heights.3);
        let full = PrivateNoteInclusionCircuit::<C, D>::new(heights.0, heights.1, heights.2, heights.3);

        assert_eq!(
            inner.circuit_data.verifier_only, full.circuit_data.verifier_only,
            "inner base verifier data differs from server base"
        );
        assert_eq!(
            inner.circuit_data.common, full.circuit_data.common,
            "inner base common data differs from server base"
        );
        assert_eq!(
            inner.get_fingerprint().0,
            get_circuit_fingerprint_generic(&full.circuit_data.verifier_only),
            "inner base fingerprint differs from server base"
        );
    }

    #[test]
    fn test_private_note_inclusion_circuit_builds() {
        use psy_config::network_constants::{
            GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, PRIVATE_NOTE_TREE_HEIGHT, TOKEN_CONTRACT_STATE_TREE_HEIGHT,
        };
        let circuit = PrivateNoteInclusionCircuit::<C, D>::new(
            GLOBAL_USER_TREE_HEIGHT as usize,
            GLOBAL_CONTRACT_TREE_HEIGHT as usize,
            TOKEN_CONTRACT_STATE_TREE_HEIGHT as usize,
            PRIVATE_NOTE_TREE_HEIGHT,
        );

        // Base circuit data
        let base_common = &circuit.circuit_data.common;
        println!("base degree_bits: {}", base_common.degree_bits());
        println!("base num_gates: {}", base_common.degree());
        println!("base num_public_inputs: {}", base_common.num_public_inputs);
        assert_eq!(base_common.num_public_inputs, 4);

        // Minified circuit data (what aggregation circuit sees)
        let minified_common = circuit.get_common_circuit_data_ref();
        println!("minified degree_bits: {}", minified_common.degree_bits());
        println!("minified num_gates: {}", minified_common.degree());
        println!("minified num_public_inputs: {}", minified_common.num_public_inputs);
        assert_eq!(minified_common.num_public_inputs, 4);

        let actual = circuit.get_fingerprint();
        println!("fingerprint: {:?}", actual);
        let expected = QHashOut::from_values(2482434993266711942, 6028864160300535936, 2827549014984201026, 3018365102481798071);
        assert_eq!(actual, expected);
    }

    /// build -> serialize (incl. minifier chain) -> deserialize, asserting the
    /// base circuit data, minified common data, and fingerprint all survive
    /// the round-trip. `cargo test -p psy_dpn_circuit
    /// private_note_inclusion_serialize_round_trip -- --nocapture`
    #[test]
    fn private_note_inclusion_serialize_round_trip() -> anyhow::Result<()> {
        use std::time::Instant;

        let t0 = Instant::now();
        let circuit = PrivateNoteInclusionCircuit::<C, D>::new(32, 24, 20, 20);
        let build_time = t0.elapsed();

        let bytes = circuit.serialize()?;

        let t1 = Instant::now();
        let restored = PrivateNoteInclusionCircuit::<C, D>::new_with_serialized(&bytes, 32, 24, 20, 20)?;
        let deserialize_time = t1.elapsed();

        assert_eq!(restored.circuit_data, circuit.circuit_data, "base circuit_data mismatch");
        assert_eq!(restored.get_fingerprint(), circuit.get_fingerprint(), "minified fingerprint mismatch");
        assert_eq!(
            restored.get_common_circuit_data_ref(),
            circuit.get_common_circuit_data_ref(),
            "minified common mismatch"
        );
        // re-serialization is byte-stable.
        assert_eq!(restored.serialize()?, bytes, "round-trip bytes differ");

        let speedup = build_time.as_secs_f64() / deserialize_time.as_secs_f64();
        println!("PrivateNoteInclusion (incl. minifier)  size: {} KiB", bytes.len() / 1024);
        println!("  build()      : {:>10.3?}", build_time);
        println!("  from_bytes() : {:>10.3?}  ({:.2}x)", deserialize_time, speedup);
        Ok(())
    }
}
