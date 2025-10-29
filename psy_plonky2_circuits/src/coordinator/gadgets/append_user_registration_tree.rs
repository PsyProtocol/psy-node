use async_trait::async_trait;
use plonky2::{
    field::{extension::Extendable, types::Field}, gates::{constant::ConstantGate, gate::GateRef}, hash::hash_types::{HashOut, HashOutTarget, RichField}, iop::{target::Target, 
        witness::{PartialWitness, Witness, WitnessWrite}}, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    }
};
use parth_core::{
    crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, spiderman::SpidermanUpdateProof, traits::MerkleZeroHasher},
    data::proof_input::CircuitInputWithDependencies,
    pgoldilocks::QHashOut,
};
use psy_core::{constants::protocol::DA_CHALLENGE_WINDOW, 
    job::job_id::QProvingJobDataID}
;
use psy_data::{
    agg::AggStateTransition, guta::header::GlobalUserTreeAggregatorHeader, proof_input::guta::{VerifyGUTAToCapCircuitInputSimple, 
        VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple}, v1::qdata::{checkpoint::PQEDCheckpointLeafStats, contract::PQEDContractLeaf, pm_rewards_commitment::PPMRewardCommitment}
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
    coordinator::gadgets::verify_agg_user_registration_deploy_guta::VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget, gadgets::qdata::{checkpoint::QEDCheckpointLeafGadget, checkpoint_state_roots::QEDCheckpointGlobalStateRootsGadget, checkpoint_stats::QEDCheckpointLeafStatsGadget, pm_jobs_completed_stats::PMJobsCompletedStatsGadget, pm_reward_commitment::PMRewardCommitmentGadget}, guta::gadgets::
        verify_guta_proof_to_line::VerifyGUTAProofToLineGadget, proof_minifier::pm_core::get_circuit_fingerprint_generic, qstandard::{proof_store::QProofStoreReaderAsync, QStandardCircuit, QStandardCircuitProvableWithProofStoreAndRefLibraryAsync}
};

use crate::gadgets::qdata::contract::QEDContractLeafGadget;


// we keep this separate from DPNProvingSessionCompactMethodCallGadget incase it changes in the future
#[derive(Debug, Clone)]
pub struct BatchAppendUserRegistrationTreeGadget {
    pub spiderman_gadgets: Vec<SpidermanAppendProofGadget>,

    // computed
    pub old_root: HashOutTarget,
    pub new_root: HashOutTarget,
}

impl BatchAppendUserRegistrationTreeGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        user_registration_tree_height: usize,
        batch_sub_tree_height: usize,
        max_sub_trees: usize,
    ) -> Self {
        assert!(max_sub_trees > 0, "must have at least one sub tree");
        let top_line_height = user_registration_tree_height-batch_sub_tree_height;

        let first_spiderman_gadget = SpidermanAppendProofGadget::add_virtual_to::<H,F,D>(
            builder,
            top_line_height,
            batch_sub_tree_height,
        );
        let old_root = first_spiderman_gadget.old_root;
        let mut new_root = first_spiderman_gadget.new_root;
        let mut spiderman_gadgets = Vec::with_capacity(max_sub_trees);

        spiderman_gadgets.push(first_spiderman_gadget);
        for _ in 1..max_sub_trees {
            let gadget = SpidermanAppendProofGadget::add_virtual_to::<H,F,D>(
                builder,
                top_line_height,
                batch_sub_tree_height,
            );
            builder.connect_hashes(new_root, gadget.old_root);
            new_root = gadget.new_root;
            spiderman_gadgets.push(gadget);
        }


        Self {
            spiderman_gadgets,
            old_root,
            new_root,
        }
    }
    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        spiderman_append_proofs: &[SpidermanUpdateProof<QHashOut<F>>],
    ) -> anyhow::Result<()> {

        let ap_length = spiderman_append_proofs.len();
        if ap_length == 0 {
            anyhow::bail!("cannot provide 0 append proofs");
        } else if ap_length > self.spiderman_gadgets.len() {
            anyhow::bail!("cannot provide {} append proofs, max is {}",ap_length, self.spiderman_gadgets.len());
        } else if ap_length == self.spiderman_gadgets.len() {
            for (g, p) in self.spiderman_gadgets.iter().zip(spiderman_append_proofs.iter()) {
                g.set_witness(witness, p)?;
            }
        } else {
            for i in 0..ap_length {
                self.spiderman_gadgets[i].set_witness(witness, &spiderman_append_proofs[i])?;
            }

            let mut noop_update = spiderman_append_proofs[ap_length-1].clone();
            noop_update.top_line_proof.old_value = noop_update.top_line_proof.new_value;
            noop_update.top_line_proof.old_root = noop_update.top_line_proof.new_root;
            noop_update.web_proof_old_leaves = noop_update.web_proof_new_leaves.clone();

            for i in ap_length..self.spiderman_gadgets.len() {
                self.spiderman_gadgets[i].set_witness(witness, &noop_update)?;
            }
        }
        Ok(())
    }
}
