use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::qdata::{checkpoint::PsyCheckpointLeafCompactWithStateRoots, contract_inclusion::PsyContractFunctionInclusionProof};
use psy_common_circuit::treeprover::qrecursion::standard::gadgets::attest_tree_aware_proof_in_tree::AttestTreeAwareProofInTreeGadget;
use psy_crypto::{common::witnesses::qrecursion::header::AttestTreeAwareProofInTreeInput, hash::traits::hasher::MerkleZeroHasher};

use crate::gadgets::qdata::{
    checkpoint_compact_with_state::PsyCheckpointLeafCompactWithStateRootsGadget, contract_inclusion::PsyContractFunctionInclusionProofGadget,
};

#[derive(Clone, Debug)]
pub struct UPSVerifyCFCProofExistsAndValidGadget {
    // start require witness
    pub checkpoint_state_gadget: PsyCheckpointLeafCompactWithStateRootsGadget,
    pub verify_cfc_proof_gadget: AttestTreeAwareProofInTreeGadget,
    pub cfc_inclusion_proof_gadget: PsyContractFunctionInclusionProofGadget,

    // start computed

    // start computed assumptions
    pub checkpoint_leaf_hash: HashOutTarget,
    pub attested_proof_tree_root: HashOutTarget,

    // key proven results
    pub cfc_fingerprint: HashOutTarget,
    pub cfc_inner_public_inputs_hash: HashOutTarget,
    pub cfc_contract_id: Target,
    pub cfc_method_id: Target,
    pub cfc_num_inputs: Target,
    pub cfc_num_outputs: Target,
}
impl UPSVerifyCFCProofExistsAndValidGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        ups_session_proof_tree_height: usize,
    ) -> Self {
        // -- start require witness

        // ensure the proof exists in our proof tree
        let verify_cfc_proof_gadget = AttestTreeAwareProofInTreeGadget::add_virtual_to::<H, F, D>(builder, ups_session_proof_tree_height);

        // get the current checkpoint and contract state tree root
        let checkpoint_state_gadget = PsyCheckpointLeafCompactWithStateRootsGadget::add_virtual_to::<H, F, D>(builder);

        // get a proof that the fingerprint for this function proof exists in its
        // contract function tree
        let cfc_inclusion_proof_gadget = PsyContractFunctionInclusionProofGadget::add_virtual_to::<H, F, D>(builder);

        // -- end require_witnesss

        // -- start list assumptions
        let checkpoint_leaf_hash = checkpoint_state_gadget.checkpoint_leaf_hash;
        let attested_proof_tree_root = verify_cfc_proof_gadget.attested_proof_tree_root;
        tracing::debug!(
            "🔍 UPSVerifyCFC Assumptions - checkpoint_leaf_hash={:?}, attested_proof_tree_root={:?}",
            checkpoint_leaf_hash,
            attested_proof_tree_root
        );
        // -- end list assumptions

        // -- start constrainting cfc_inclusion_proof_gadget

        // ensure the inclusion and checkpoint gadgets have the same global contract
        // tree root
        tracing::debug!(
            "🔍 UPSVerifyCFC Constraint 1 - contract tree root equality: inclusion_root={:?}, checkpoint_root={:?}",
            cfc_inclusion_proof_gadget.contract_inclusion_proof.contract_tree_merkle_proof.root,
            checkpoint_state_gadget.global_state_roots.contract_tree_root
        );
        builder.connect_hashes(
            cfc_inclusion_proof_gadget.contract_inclusion_proof.contract_tree_merkle_proof.root,
            checkpoint_state_gadget.global_state_roots.contract_tree_root,
        );

        let verifier_cfc_fingerprint = verify_cfc_proof_gadget.fingerprint;
        // ensure the inclusion gadget's fingerprint matches the verify gadget's
        // verifier data fingerprint
        tracing::debug!(
            "🔍 UPSVerifyCFC Constraint 2 - fingerprint equality: inclusion_fingerprint={:?}, verifier_fingerprint={:?}",
            cfc_inclusion_proof_gadget.function_verifier_fingerprint,
            verifier_cfc_fingerprint
        );
        builder.connect_hashes(cfc_inclusion_proof_gadget.function_verifier_fingerprint, verifier_cfc_fingerprint);

        // -- end constraining cfc_inclusion_proof_gadget

        // -- start list key proven results
        let cfc_fingerprint = verifier_cfc_fingerprint;
        let cfc_inner_public_inputs_hash = verify_cfc_proof_gadget.inner_public_inputs_hash;

        let cfc_contract_id = cfc_inclusion_proof_gadget.contract_inclusion_proof.contract_tree_merkle_proof.index;
        let cfc_method_id = cfc_inclusion_proof_gadget.method_id;
        let cfc_num_inputs = cfc_inclusion_proof_gadget.num_inputs;
        let cfc_num_outputs = cfc_inclusion_proof_gadget.num_outputs;

        tracing::debug!(
            "🔍 UPSVerifyCFC Results - contract_id={:?}, method_id={:?}, num_inputs={:?}, num_outputs={:?}",
            cfc_contract_id,
            cfc_method_id,
            cfc_num_inputs,
            cfc_num_outputs
        );
        tracing::debug!(
            "🔍 UPSVerifyCFC Results - fingerprint={:?}, inner_public_inputs_hash={:?}",
            cfc_fingerprint,
            cfc_inner_public_inputs_hash
        );

        // -- end list key proven results

        Self {
            checkpoint_state_gadget,
            verify_cfc_proof_gadget,
            cfc_inclusion_proof_gadget,
            checkpoint_leaf_hash,
            attested_proof_tree_root,
            cfc_fingerprint,
            cfc_inner_public_inputs_hash,
            cfc_contract_id,
            cfc_method_id,
            cfc_num_inputs,
            cfc_num_outputs,
        }
    }
    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        checkpoint_state: &PsyCheckpointLeafCompactWithStateRoots<F>,
        verify_cfc_proof_input: &AttestTreeAwareProofInTreeInput<F>,
        cfc_inclusion_proof: &PsyContractFunctionInclusionProof<F>,
    ) -> anyhow::Result<()> {
        //self.checkpoint_state_gadget.set_witness_params(witness, global_state_roots,
        // stats_hash);
        self.checkpoint_state_gadget.set_witness(witness, checkpoint_state)?;
        self.verify_cfc_proof_gadget.set_witness(witness, verify_cfc_proof_input)?;
        self.cfc_inclusion_proof_gadget.set_witness(witness, cfc_inclusion_proof)
    }
}

/*
impl<F: RichField> WitnessValueFor<UPSVerifyCFCProofExistsAndValidGadget, F, true> for UPSVerifyCFCProofExistsAndValidInput<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UPSVerifyCFCProofExistsAndValidGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<UPSVerifyCFCProofExistsAndValidGadget, F, false> for UPSVerifyCFCProofExistsAndValidInput<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UPSVerifyCFCProofExistsAndValidGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

*/
