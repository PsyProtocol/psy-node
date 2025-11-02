use std::{hash::Hash, ops::Add};

use parth_core::{crypto::hash::{merkle_proof::{compute_historical_and_current_merkle_roots_core_gt, DeltaMerkleProofCore, MerkleProofCore}, nca::nca_proof::PartialUpdateNearestCommonAncestorProof, traits::{FieldQHasher, MerkleHasher, MerkleZeroHasher, QFieldHashable, ZeroableHash}}, felt::QFelt64, protocol::core_types::QFHashBase};
use psy_core::job::job_id::{self, QProvingJobDataID};

use crate::{guta::{header::GlobalUserTreeAggregatorHeader, header_extended::GlobalUserTreeAggregatorHeaderWithTagValue, stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition}, v1::qdata::{checkpoint::PQEDCheckpointLeafCompactWithStateRoots, user::PQEDUserLeaf, user_end_cap_result::PUPSEndCapResultCompact}};


#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyTwoGUTAProofGadgetStandardInputSimple<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub b_checkpoint_tree_root: Hash,
    pub stats_a: GUTAStats<F>,
    pub stats_b: GUTAStats<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,
}
impl<F: Add<Output = F> + Copy, Hash> VerifyTwoGUTAProofGadgetStandardInputSimple<F, Hash> {
    pub fn get_combined_stats(&self) -> GUTAStats<F> {
        self.stats_a.combine_with(&self.stats_b)
    }

    pub fn check_witness(&self) -> anyhow::Result<()> {
        // todo: check nca proof
        Ok(())
    }
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyTwoGUTAProofGadgetStandardInput<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub b_checkpoint_tree_root: Hash,
    pub stats_a: GUTAStats<F>,
    pub stats_b: GUTAStats<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,

    pub guta_inclusion_proof_a: MerkleProofCore<Hash>,
    pub guta_inclusion_proof_b: MerkleProofCore<Hash>,
}

impl<F: QFelt64, Hash: Copy> VerifyTwoGUTAProofGadgetStandardInput<F, Hash> {

    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_a.root,
            checkpoint_tree_root: self.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_a.old_value,
                new_node_value: self.nca_proof.child_a.new_value,
                node_index: F::from_u64_value(self.nca_proof.get_a_node_key().index),
                node_level: F::from_u8_value(self.nca_proof.get_level_a()),
            },
            stats: self.stats_a,
        }
    }
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_b.root,
            checkpoint_tree_root: self.b_checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_b.old_value,
                new_node_value: self.nca_proof.child_b.new_value,
                node_index: F::from_u64_value(self.nca_proof.get_b_node_key().index),
                node_level: F::from_u8_value(self.nca_proof.get_level_b()),
            },
            stats: self.stats_b,
        }
    }

}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F, Hash> {
    pub historical_checkpoint_proof_a: MerkleProofCore<Hash>,
    pub historical_checkpoint_proof_b: MerkleProofCore<Hash>,
    pub stats_a: GUTAStats<F>,
    pub stats_b: GUTAStats<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,
}
impl<F: Add<Output = F> + Copy, Hash> VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F, Hash> {
    pub fn get_combined_stats(&self) -> GUTAStats<F> {
        self.stats_a.combine_with(&self.stats_b)
    }
}

impl<F, Hash: PartialEq + Copy> VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F, Hash> {
    pub fn check_witness<Hasher: MerkleZeroHasher<Hash>>(&self) -> anyhow::Result<()> {
        let (_historical_root_a, current_root_a) = compute_historical_and_current_merkle_roots_core_gt::<Hash, Hasher>(&self.historical_checkpoint_proof_a);
        let (_historical_root_b, current_root_b) = compute_historical_and_current_merkle_roots_core_gt::<Hash, Hasher>(&self.historical_checkpoint_proof_b);
        if current_root_a != self.historical_checkpoint_proof_a.root {
            return Err(anyhow::anyhow!("two guta upgrade checkpoint historical_checkpoint_proof_a not match"));
        }
        if current_root_b != self.historical_checkpoint_proof_b.root {
            return Err(anyhow::anyhow!("two guta upgrade checkpoint historical_checkpoint_proof_b not match"));
        }
        if current_root_a != current_root_b {
            return Err(anyhow::anyhow!("two guta upgrade checkpoint current checkpoint root not match"));
        }
        Ok(())
    }
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyTwoGUTAProofUpgradeCheckpointStandardInput<F, Hash> {
    pub historical_checkpoint_proof_a: MerkleProofCore<Hash>,
    pub historical_checkpoint_proof_b: MerkleProofCore<Hash>,
    pub stats_a: GUTAStats<F>,
    pub stats_b: GUTAStats<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,

    pub guta_inclusion_proof_a: MerkleProofCore<Hash>,
    pub guta_inclusion_proof_b: MerkleProofCore<Hash>,
}



impl<F: QFelt64, Hash: Copy> VerifyTwoGUTAProofUpgradeCheckpointStandardInput<F, Hash> {
    pub fn get_guta_header_a<H: MerkleZeroHasher<Hash>>(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_a.root,
            checkpoint_tree_root: compute_historical_and_current_merkle_roots_core_gt::<Hash, H>(
                &self.historical_checkpoint_proof_a
            ).0,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_a.old_value,
                new_node_value: self.nca_proof.child_a.new_value,
                node_index: F::from_u64_value(self.nca_proof.get_a_node_key().index),
                node_level: F::from_u8_value(self.nca_proof.get_level_a()),
            },
            stats: self.stats_a,
        }
    }
    pub fn get_guta_header_b<H: MerkleZeroHasher<Hash>>(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_b.root,
            checkpoint_tree_root: compute_historical_and_current_merkle_roots_core_gt::<Hash, H>(
                &self.historical_checkpoint_proof_b
            ).0,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_b.old_value,
                new_node_value: self.nca_proof.child_b.new_value,
                node_index: F::from_u64_value(self.nca_proof.get_b_node_key().index),
                node_level: F::from_u8_value(self.nca_proof.get_level_b()),
            },
            stats: self.stats_b,
        }
    }
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyEndCapSimpleStandardInput<F, Hash> {
    pub guta_stats: GUTAStats<F>,
    pub checkpoint_root: Hash,
    pub checkpoint_historical_merkle_proof: MerkleProofCore<Hash>,
}

impl<F, Hash: Copy + PartialEq> VerifyEndCapSimpleStandardInput<F, Hash> {
    pub fn check_witness<Hasher: MerkleZeroHasher<Hash>>(&self) -> anyhow::Result<()> {
        let (historical_root, current_root) = compute_historical_and_current_merkle_roots_core_gt::<Hash, Hasher>(&self.checkpoint_historical_merkle_proof);
        if self.checkpoint_root != historical_root {
            return Err(anyhow::anyhow!("end result historical root not match"));
        }
        if current_root != self.checkpoint_historical_merkle_proof.root {
            return Err(anyhow::anyhow!("end result current root not match"));
        }
        Ok(())
    }
}


#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyTwoEndCapCircuitWithIdsInput<F, Hash> {
    pub input: VerifyTwoEndCapCircuitInput<F, Hash>,

    pub proof_a_id: QProvingJobDataID,
    pub proof_b_id: QProvingJobDataID,
}


#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyTwoEndCapCircuitInput<F, Hash> {
    pub guta_circuit_whitelist: Hash,
    
    pub a_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,

    pub b_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,

    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,
}

impl<F: QFelt64, Hash: Copy> VerifyTwoEndCapCircuitInput<F, Hash> {

    pub fn get_end_result_a(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.nca_proof.child_a.old_value,
            end_user_leaf_hash: self.nca_proof.child_a.new_value,
            checkpoint_tree_root_hash: self.a_end_cap.checkpoint_root,
            user_id: F::from_u64_value(self.nca_proof.child_a.index),
        }
    }
    pub fn get_end_result_b(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.nca_proof.child_b.old_value,
            end_user_leaf_hash: self.nca_proof.child_b.new_value,
            checkpoint_tree_root_hash: self.b_end_cap.checkpoint_root,
            user_id: F::from_u64_value(self.nca_proof.child_b.index),
        }
    }

    pub fn get_new_guta_header<Hasher: MerkleHasher<Hash>>(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_circuit_whitelist,
            checkpoint_tree_root: self.a_end_cap.checkpoint_historical_merkle_proof.root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.compute_old_nca_value::<Hasher>(),
                new_node_value: self.nca_proof.compute_new_nca_value::<Hasher>(),
                node_index: F::from_u64_value(self.nca_proof.get_nca_index()),
                node_level: F::from_u8_value(self.nca_proof.nearest_common_ancestor_level),
            },
            stats: self.a_end_cap.guta_stats.combine_with(&self.b_end_cap.guta_stats),
        }
    }

}
impl<F: QFelt64, Hash: Copy + PartialEq> VerifyTwoEndCapCircuitInput<F, Hash> {
    pub fn check_witness<Hasher: MerkleZeroHasher<Hash>>(&self) -> anyhow::Result<()> {
        self.a_end_cap.check_witness::<Hasher>()?;
        self.b_end_cap.check_witness::<Hasher>()?;

        if self.a_end_cap.checkpoint_historical_merkle_proof.root != self.b_end_cap.checkpoint_historical_merkle_proof.root {
            return Err(anyhow::anyhow!("two endcap current checkpoint root not match"));
        }
        // todo: check nca proof

        Ok(())
    }
}





#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifySingleEndCapInput<F, Hash> {
    pub guta_circuit_whitelist: Hash,

    pub a_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,

    pub start_user_leaf_hash: Hash,
    pub end_user_leaf_hash: Hash,
    pub user_id: F,
}

impl<F: QFelt64, Hash: Copy> VerifySingleEndCapInput<F, Hash> {

    pub fn get_guta_header_a(&self, global_user_tree_height: u8) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_circuit_whitelist,
            checkpoint_tree_root: self.a_end_cap.checkpoint_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.start_user_leaf_hash,
                new_node_value: self.end_user_leaf_hash,
                node_index: self.user_id,
                node_level: F::from_u8_value(global_user_tree_height),
            },
            stats: self.a_end_cap.guta_stats,
        }
    }
    pub fn get_new_guta_header(&self, global_user_tree_height: u8) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_circuit_whitelist,
            checkpoint_tree_root: self.a_end_cap.checkpoint_historical_merkle_proof.root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.start_user_leaf_hash,
                new_node_value: self.end_user_leaf_hash,
                node_index: self.user_id,
                node_level: F::from_u8_value(global_user_tree_height),
            },
            stats: self.a_end_cap.guta_stats,
        }
    }
}
impl<F: QFelt64, Hash: Copy + PartialEq> VerifySingleEndCapInput<F, Hash> {
    pub fn get_end_result_a(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.start_user_leaf_hash,
            end_user_leaf_hash: self.end_user_leaf_hash,
            checkpoint_tree_root_hash: self.a_end_cap.checkpoint_root,
            user_id: self.user_id,
        }
    }
    pub fn check_witness<Hasher: MerkleZeroHasher<Hash>>(&self, global_user_tree_height: u8) -> anyhow::Result<()> {
        self.a_end_cap.check_witness::<Hasher>()?;
        let end_result = self.get_end_result_a();
        let guta_new_header = self.get_new_guta_header(global_user_tree_height);
        if end_result.start_user_leaf_hash != guta_new_header.state_transition.old_node_value ||
            end_result.end_user_leaf_hash != guta_new_header.state_transition.new_node_value ||
            end_result.user_id != guta_new_header.state_transition.node_index {
            return Err(anyhow::anyhow!("end result not match"));
        }

        let (historical_root, current_root) = compute_historical_and_current_merkle_roots_core_gt::<Hash, Hasher>(&self.a_end_cap.checkpoint_historical_merkle_proof);
        if historical_root != end_result.checkpoint_tree_root_hash {
            return Err(anyhow::anyhow!("historical root not match"));
        }
        if current_root != guta_new_header.checkpoint_tree_root {
            return Err(anyhow::anyhow!("current root not match"));
        }

        Ok(())
    }
}





#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyLeftGUTARightEndCapInputSimple<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub stats_a: GUTAStats<F>,
    pub b_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,
}

impl<F, Hash: Copy + PartialEq> VerifyLeftGUTARightEndCapInputSimple<F, Hash> {
    pub fn check_witness<Hasher: MerkleZeroHasher<Hash>>(&self) -> anyhow::Result<()> {
        self.b_end_cap.check_witness::<Hasher>()?;
        let (_historical_root, current_root) = compute_historical_and_current_merkle_roots_core_gt::<Hash, Hasher>(&self.b_end_cap.checkpoint_historical_merkle_proof);
        if current_root != self.checkpoint_tree_root {
            return Err(anyhow::anyhow!("left guta right endcap checkpoint tree root not match"));
        }
        if current_root != self.b_end_cap.checkpoint_historical_merkle_proof.root {
            return Err(anyhow::anyhow!("right endcap historical merkel proof not match"));
        }
        Ok(())
    }
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyLeftGUTARightEndCapInput<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub stats_a: GUTAStats<F>,
    pub b_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,

    pub guta_inclusion_proof_a: MerkleProofCore<Hash>,
}



impl<F: QFelt64, Hash: Copy> VerifyLeftGUTARightEndCapInput<F, Hash> {

    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_a.root,
            checkpoint_tree_root: self.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_a.old_value,
                new_node_value: self.nca_proof.child_a.new_value,
                node_index: F::from_u64_value(self.nca_proof.get_a_node_key().index),
                node_level: F::from_u8_value(self.nca_proof.get_level_a()),
            },
            stats: self.stats_a,
        }
    }
    pub fn get_end_result_b(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.nca_proof.child_b.old_value,
            end_user_leaf_hash: self.nca_proof.child_b.new_value,
            checkpoint_tree_root_hash: self.b_end_cap.checkpoint_root,
            user_id: F::from_u64_value(self.nca_proof.child_b.index),
        }
    }

}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyLeftEndCapRightGUTAInputSimple<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub stats_b: GUTAStats<F>,
    pub a_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,

}

impl<F, Hash: Copy + PartialEq> VerifyLeftEndCapRightGUTAInputSimple<F, Hash> {
    pub fn check_witness<Hasher: MerkleZeroHasher<Hash>>(&self) -> anyhow::Result<()> {
        self.a_end_cap.check_witness::<Hasher>()?;
        let (_historical_root, current_root) = compute_historical_and_current_merkle_roots_core_gt::<Hash, Hasher>(&self.a_end_cap.checkpoint_historical_merkle_proof);
        if current_root != self.checkpoint_tree_root {
            return Err(anyhow::anyhow!("left endcap right guta checkpoint tree root not match"));
        }
        if current_root != self.a_end_cap.checkpoint_historical_merkle_proof.root {
            return Err(anyhow::anyhow!("left endcap historical merkel proof not match"));
        }
        Ok(())
    }
}





#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyLeftEndCapRightGUTAInput<F, Hash> {
    pub checkpoint_tree_root: Hash,
    pub stats_b: GUTAStats<F>,
    pub a_end_cap: VerifyEndCapSimpleStandardInput<F, Hash>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<Hash>,

    pub guta_inclusion_proof_b: MerkleProofCore<Hash>,
}


impl<F: QFelt64, Hash: PartialEq + Copy> VerifyLeftEndCapRightGUTAInput<F, Hash> {

    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_b.root,
            checkpoint_tree_root: self.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_b.old_value,
                new_node_value: self.nca_proof.child_b.new_value,
                node_index: F::from_u64_value(self.nca_proof.get_b_node_key().index),
                node_level: F::from_u8_value(self.nca_proof.get_level_b()),
            },
            stats: self.stats_b,
        }
    }
    pub fn get_end_result_a(&self) -> PUPSEndCapResultCompact<F, Hash> {
        PUPSEndCapResultCompact {
            start_user_leaf_hash: self.nca_proof.child_a.old_value,
            end_user_leaf_hash: self.nca_proof.child_a.new_value,
            checkpoint_tree_root_hash: self.a_end_cap.checkpoint_root,
            user_id: F::from_u64_value(self.nca_proof.child_a.index),
        }
    }

}


#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct GUTANoChangeFullInput<Hash> {
    pub checkpoint_tree_proof: MerkleProofCore<Hash>,
    pub checkpoint_leaf: PQEDCheckpointLeafCompactWithStateRoots<Hash>,
}




#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct GUTARegisterUserFullInput<Hash> {
    pub user_registration_tree_merkle_proof: MerkleProofCore<Hash>,
    pub global_user_tree_update_proof: DeltaMerkleProofCore<Hash>,
}


impl<Hash: Copy + ZeroableHash> GUTARegisterUserFullInput<Hash> {


    pub fn new_dummy(global_user_tree_height: usize, height: usize, dummy_user_leaf_hash: Hash, fake_public_key: Hash) -> Self {

        let siblings = (0..global_user_tree_height).map(|_| Hash::get_zero_value()).collect::<Vec<_>>();
        let user_registration_tree_merkle_proof = MerkleProofCore {
            siblings,
            root: Hash::get_zero_value(),
            value : fake_public_key,
            index: 0,
        };

        let dmp_siblings = (0..height).map(|_| Hash::get_zero_value()).collect();
        let global_user_tree_update_proof = DeltaMerkleProofCore{
            siblings: dmp_siblings,
            old_root: Hash::get_zero_value(),
            old_value: Hash::get_zero_value(),
            new_root: Hash::get_zero_value(),
            new_value: dummy_user_leaf_hash,
            index: 0,
        };

        Self {
            user_registration_tree_merkle_proof,
            global_user_tree_update_proof,
        }

    }
}



#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyGUTAToCapCircuitInputSimple<F, Hash> {
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub top_line_siblings: Vec<Hash>,
}
impl<F: QFelt64, Hash: PartialEq + Copy> VerifyGUTAToCapCircuitInputSimple<F, Hash> {
    pub fn get_new_state_transition<H: MerkleHasher<Hash>>(&self) -> SubTreeNodeStateTransition<F, Hash> {

        if self.top_line_siblings.len() == 0 {
            self.guta_proof_header.state_transition.clone()
        }else{


            let new_dmp = DeltaMerkleProofCore::from_params::<H>(
                self.guta_proof_header.state_transition.node_index.to_u64_value(),
                self.guta_proof_header.state_transition.old_node_value,
                self.guta_proof_header.state_transition.new_node_value,
                self.top_line_siblings.clone(),
            );

            SubTreeNodeStateTransition{
                old_node_value: new_dmp.old_root,
                new_node_value: new_dmp.new_root,
                node_index:F::from_u64_value (
                    self.guta_proof_header.state_transition.node_index.to_u64_value()>>(self.top_line_siblings.len() as u64)
                ),
                node_level: F::from_u64_value (
                    self.guta_proof_header.state_transition.node_level.to_u64_value()-(self.top_line_siblings.len() as u64)
                ),
            }
        }

    }
    pub fn get_new_guta_header<H: MerkleHasher<Hash>>(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {


        GlobalUserTreeAggregatorHeader{
            guta_circuit_whitelist: self.guta_proof_header.guta_circuit_whitelist,
            checkpoint_tree_root: self.guta_proof_header.checkpoint_tree_root,
            state_transition: self.get_new_state_transition::<H>(),
            stats: self.guta_proof_header.stats,
        }

    }
}



#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F, Hash> {
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub top_line_siblings: Vec<Hash>,
    pub historical_checkpoint_proof: MerkleProofCore<Hash>,
}

impl<F: QFelt64, Hash: PartialEq + Copy> VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F, Hash> {
    pub fn get_new_state_transition<H: MerkleHasher<Hash>>(&self) -> SubTreeNodeStateTransition<F, Hash> {

        if self.top_line_siblings.len() == 0 {
            self.guta_proof_header.state_transition.clone()
        }else{


            let new_dmp = DeltaMerkleProofCore::from_params::<H>(
                self.guta_proof_header.state_transition.node_index.to_u64_value(),
                self.guta_proof_header.state_transition.old_node_value,
                self.guta_proof_header.state_transition.new_node_value,
                self.top_line_siblings.clone(),
            );

            SubTreeNodeStateTransition{
                old_node_value: new_dmp.old_root,
                new_node_value: new_dmp.new_root,
                node_index:F::from_u64_value (
                    self.guta_proof_header.state_transition.node_index.to_u64_value()>>(self.top_line_siblings.len() as u64)
                ),
                node_level: F::from_u64_value (
                    self.guta_proof_header.state_transition.node_level.to_u64_value()-(self.top_line_siblings.len() as u64)
                ),
            }
        }

    }
    pub fn get_new_guta_header<H: MerkleHasher<Hash>>(&self) -> GlobalUserTreeAggregatorHeader<F, Hash> {


        GlobalUserTreeAggregatorHeader{
            guta_circuit_whitelist: self.guta_proof_header.guta_circuit_whitelist,
            // upgraded to the new root for the new header
            checkpoint_tree_root: self.historical_checkpoint_proof.root,
            state_transition: self.get_new_state_transition::<H>(),
            stats: self.guta_proof_header.stats,
        }

    }
}



#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct VerifyGUTARegisterUsersCircuitInputSimple<F, Hash> {
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F, Hash>,
    pub top_line_siblings: Vec<Hash>,
    pub guta_register_user_inputs: Vec<GUTARegisterUserFullInput<Hash>>
}






#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct GUTAOnlyRegisterUsersInput<Hash> {
    pub checkpoint_tree_root: Hash,
    pub guta_register_user_inputs: Vec<GUTARegisterUserFullInput<Hash>>,
}




#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct SubmitUserEndCapNonProofCoreInput<F, Hash> {
    pub checkpoint_id: F,
    pub stats: GUTAStats<F>,
    pub state_transition: PUPSEndCapResultCompact<F, Hash>,
    pub new_user_leaf: PQEDUserLeaf<F, Hash>,
}
impl<F : QFelt64, Hash: QFHashBase<F>> SubmitUserEndCapNonProofCoreInput<F, Hash> {

    pub fn get_proof_public_inputs_hash<Hasher: FieldQHasher<F, Hash>>(&self, global_user_tree_height: u8) -> Hash {
        Hasher::q_two_to_one(
            self.state_transition.qfhash_with_guta_height::<Hasher>(global_user_tree_height),
            self.stats.qfhash::<Hasher>()
        )
    }
}


#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
#[repr(C)]
pub struct SubmitGUTARealmResultAPINoProofInput<F, Hash> {
    pub guta_header: GlobalUserTreeAggregatorHeaderWithTagValue<F, Hash>,
    pub circuit_type: job_id::ProvingJobCircuitType,
}

#[pderive::serialize_clone_f_hash_proof]
//#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash, Proof = Vec<u8>))]
pub struct SubmitGUTARealmResultAPIWithProof<F, Hash, Proof> {
    pub input: SubmitGUTARealmResultAPINoProofInput<F, Hash>,
    pub proof: Proof,
}