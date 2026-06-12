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
    proof_minifier::pm_chain::PsyProofMinifierChain,
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
///              checkpoint_id, slot_index, nullifier_hash[0..4]
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
    pub randomness: HashOutTarget,
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
        // --- Public input targets ---
        let owner = builder.add_virtual_hash();
        let amount = builder.add_virtual_target();
        let randomness = builder.add_virtual_hash();
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

        // commitment = Hash(inner_hash, randomness)
        let commitment = builder.hash_two_to_one::<H>(inner_hash, randomness);

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
        // Hash all 19 values into a single HashOut for proof tree
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
            randomness,
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
            tracing::error!(
                "PrivateNoteInclusion root mismatch before witness set: membership_root={} != slot_value={}",
                input.note_membership_proof.root,
                input.note_root_slot_proof.value
            );
        }

        // Private witnesses
        pw.set_hash_target(self.nullifier_secret, input.nullifier_secret.0)?;
        pw.set_target(self.checkpoint_id, input.checkpoint_id)?;

        // Public input witnesses
        pw.set_hash_target(self.owner, input.owner.0)?;
        pw.set_target(self.amount, input.amount)?;
        pw.set_hash_target(self.randomness, input.randomness.0)?;

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

#[cfg(test)]
mod tests {
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;

    use super::*;

    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_private_note_inclusion_circuit_builds() {
        // note_tree_height = 20 (2^20 notes)
        let circuit = PrivateNoteInclusionCircuit::<C, D>::new(32, 24, 20, 20);

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

        println!("fingerprint: {:?}", circuit.get_fingerprint());
    }
}
