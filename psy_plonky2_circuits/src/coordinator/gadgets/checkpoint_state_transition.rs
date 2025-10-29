use async_trait::async_trait;
use plonky2::{
    field::{extension::Extendable, types::Field}, gates::{constant::ConstantGate, gate::GateRef}, hash::hash_types::{HashOut, HashOutTarget, RichField}, iop::
        witness::{PartialWitness, Witness, WitnessWrite}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    }
};
use parth_core::{
    crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, spiderman::SpidermanUpdateProof, traits::MerkleZeroHasher},
    data::proof_input::CircuitInputWithDependencies,
    pgoldilocks::QHashOut,
};
use psy_core::
    job::job_id::QProvingJobDataID
;
use psy_data::{
    guta::header::GlobalUserTreeAggregatorHeader,
    proof_input::guta::{VerifyGUTAToCapCircuitInputSimple, 
        VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple}, v1::qdata::contract::PQEDContractLeaf
    ,
};
use psy_plonky2_basic_helpers::{
    builder::{
        hash::core::CircuitBuilderHashCore,
        pad_circuit::pad_circuit_degree,
    },
    verifier::circuit_library::CircuitInfoLibrary,
};
use psy_plonky2_common_circuits::{hash::merkle::gadgets::{delta_merkle_proof::DeltaMerkleProofGadget, historical_root_merkle_proof::HistoricalRootMerkleProofGadget, merkle_proof::MerkleProofGadget, spiderman_append_proof::SpidermanAppendProofGadget}, traits::ToTargets};

use crate::{
    gadgets::qdata::pm_jobs_completed_stats::PMJobsCompletedStatsGadget,
    guta::gadgets::
        verify_guta_proof_to_line::VerifyGUTAProofToLineGadget
    ,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::{proof_store::QProofStoreReaderAsync, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync},
};

use crate::gadgets::qdata::contract::QEDContractLeafGadget;



#[derive(Debug, Clone)]
pub struct CheckpointStateTransitionCoreGadget {
    pub append_checkpoint_tree_proof: DeltaMerkleProofGadget,
    pub previous_checkpoint_proof: MerkleProofGadget,

    // computed
    pub old_checkpoint_tree_root: HashOutTarget,
    pub new_checkpoint_tree_root: HashOutTarget,

    pub old_checkpoint_leaf_hash: HashOutTarget,
    pub new_checkpoint_leaf_hash: HashOutTarget,
}

impl CheckpointStateTransitionCoreGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F> + MerkleZeroHasher<HashOut<F>>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        checkpoint_tree_height: usize,
    ) -> Self {
        let append_checkpoint_tree_proof =
            DeltaMerkleProofGadget::add_virtual_to_append_only::<H, F, D>(builder, checkpoint_tree_height);
        let previous_checkpoint_proof = MerkleProofGadget::add_virtual_to_append_only::<H,F,D>(builder, checkpoint_tree_height);

        // ensure we are appending to an empty leaf
        let zero_hash = builder.constant_qhash(QHashOut::ZERO);
        builder.connect_hashes(append_checkpoint_tree_proof.old_value, zero_hash);

        // ensure that old root == previous checkpoint root
        builder.connect_hashes(
            append_checkpoint_tree_proof.old_root,
            previous_checkpoint_proof.root,
        );

        // sanity check: previous.index + 1 == current.index
        let one = builder.one();
        let previous_index_plus_one = builder.add(previous_checkpoint_proof.index, one);
        builder.connect(append_checkpoint_tree_proof.index, previous_index_plus_one);

        let old_checkpoint_tree_root = previous_checkpoint_proof.root;
        let new_checkpoint_tree_root = append_checkpoint_tree_proof.new_root;
        let old_checkpoint_leaf_hash = previous_checkpoint_proof.value;
        let new_checkpoint_leaf_hash = append_checkpoint_tree_proof.new_value;

        Self {
            append_checkpoint_tree_proof,
            previous_checkpoint_proof,
            old_checkpoint_tree_root,
            new_checkpoint_tree_root,
            old_checkpoint_leaf_hash,
            new_checkpoint_leaf_hash,
        }
    }

    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        append_checkpoint_tree_proof: &DeltaMerkleProofCore<QHashOut<F>>,
        previous_checkpoint_proof: &MerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.append_checkpoint_tree_proof.set_witness_core_proof_q(
            witness,
            append_checkpoint_tree_proof,
        )?;
        self.previous_checkpoint_proof.set_witness_core_proof_q_generic(
            witness,
            previous_checkpoint_proof,
        )?;
        Ok(())
    }
}
