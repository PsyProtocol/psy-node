use kvq::traits::KVQSerializable;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::hash_types::{HashOut, RichField},
    plonk::config::AlgebraicHasher,
};
use psy_client_common::{data::qhashout::QHashOut, job::id::QProvingJobDataID};
use psy_config::{network_constants::GLOBAL_USER_TREE_HEIGHT, DEFAULT_USER_STATE_TREE_ROOT_U64};
use psy_crypto::hash::{
    merkle::{
        core::{
            compute_historical_and_current_merkle_roots_core_gt, compute_historical_and_current_merkle_roots_core_gt_qho, DeltaMerkleProofCore,
            MerkleProofCore,
        },
        treeprover::subtree::SubTreeNodeStateTransition,
        utils::sub_tree_nca::PartialUpdateNearestCommonAncestorProof,
    },
    traits::{
        hasher::{FieldQHasher, MerkleHasher, MerkleZeroHasher, MerkleZeroHasherWithMarkedLeaf},
        qhashable::QFieldHashable,
    },
};
use serde::{Deserialize, Serialize};

use super::{header::GlobalUserTreeAggregatorHeader, stats::GUTAStats};
use crate::{
    config::store_config::PsyHasher,
    qdata::{checkpoint::PsyCheckpointLeafCompactWithStateRoots, ups_end_cap_result::UPSEndCapResultCompact, user::PsyUserLeaf},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyTwoGUTAProofGadgetStandardInputSimple<F: RichField> {
    pub checkpoint_tree_root: QHashOut<F>,
    pub b_checkpoint_tree_root: QHashOut<F>,
    pub stats_a: GUTAStats<F>,
    pub stats_b: GUTAStats<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,
}
impl<F: RichField> VerifyTwoGUTAProofGadgetStandardInputSimple<F> {
    pub fn get_combined_stats(&self) -> GUTAStats<F> {
        self.stats_a.combine_with(&self.stats_b)
    }

    pub fn check_witness(&self) -> anyhow::Result<()> {
        // todo: check nca proof
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyTwoGUTAProofGadgetStandardInput<F: RichField> {
    pub checkpoint_tree_root: QHashOut<F>,
    pub b_checkpoint_tree_root: QHashOut<F>,
    pub stats_a: GUTAStats<F>,
    pub stats_b: GUTAStats<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,

    pub guta_inclusion_proof_a: MerkleProofCore<QHashOut<F>>,
    pub guta_inclusion_proof_b: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> KVQSerializable for VerifyTwoGUTAProofGadgetStandardInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> VerifyTwoGUTAProofGadgetStandardInput<F> {
    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_a.root,
            checkpoint_tree_root: self.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_a.old_value,
                new_node_value: self.nca_proof.child_a.new_value,
                node_index: F::from_canonical_u64(self.nca_proof.get_a_node_key().index),
                node_level: F::from_canonical_u8(self.nca_proof.get_level_a()),
            },
            stats: self.stats_a,
        }
    }
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_b.root,
            checkpoint_tree_root: self.b_checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_b.old_value,
                new_node_value: self.nca_proof.child_b.new_value,
                node_index: F::from_canonical_u64(self.nca_proof.get_b_node_key().index),
                node_level: F::from_canonical_u8(self.nca_proof.get_level_b()),
            },
            stats: self.stats_b,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F: RichField> {
    pub historical_checkpoint_proof_a: MerkleProofCore<QHashOut<F>>,
    pub historical_checkpoint_proof_b: MerkleProofCore<QHashOut<F>>,
    pub stats_a: GUTAStats<F>,
    pub stats_b: GUTAStats<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,
}
impl<F: RichField> VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F> {
    pub fn get_combined_stats(&self) -> GUTAStats<F> {
        self.stats_a.combine_with(&self.stats_b)
    }
}

impl VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<GoldilocksField> {
    pub fn check_witness(&self) -> anyhow::Result<()> {
        let (_historical_root_a, current_root_a) =
            compute_historical_and_current_merkle_roots_core_gt::<QHashOut<GoldilocksField>, PsyHasher>(&self.historical_checkpoint_proof_a);
        let (_historical_root_b, current_root_b) =
            compute_historical_and_current_merkle_roots_core_gt::<QHashOut<GoldilocksField>, PsyHasher>(&self.historical_checkpoint_proof_b);
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyTwoGUTAProofUpgradeCheckpointStandardInput<F: RichField> {
    pub historical_checkpoint_proof_a: MerkleProofCore<QHashOut<F>>,
    pub historical_checkpoint_proof_b: MerkleProofCore<QHashOut<F>>,
    pub stats_a: GUTAStats<F>,
    pub stats_b: GUTAStats<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,

    pub guta_inclusion_proof_a: MerkleProofCore<QHashOut<F>>,
    pub guta_inclusion_proof_b: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> KVQSerializable for VerifyTwoGUTAProofUpgradeCheckpointStandardInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> VerifyTwoGUTAProofUpgradeCheckpointStandardInput<F> {
    pub fn get_guta_header_a<H: MerkleZeroHasher<QHashOut<F>>>(&self) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_a.root,
            checkpoint_tree_root: compute_historical_and_current_merkle_roots_core_gt::<QHashOut<F>, H>(&self.historical_checkpoint_proof_a).0,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_a.old_value,
                new_node_value: self.nca_proof.child_a.new_value,
                node_index: F::from_canonical_u64(self.nca_proof.get_a_node_key().index),
                node_level: F::from_canonical_u8(self.nca_proof.get_level_a()),
            },
            stats: self.stats_a,
        }
    }
    pub fn get_guta_header_b<H: MerkleZeroHasher<QHashOut<F>>>(&self) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_b.root,
            checkpoint_tree_root: compute_historical_and_current_merkle_roots_core_gt::<QHashOut<F>, H>(&self.historical_checkpoint_proof_b).0,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_b.old_value,
                new_node_value: self.nca_proof.child_b.new_value,
                node_index: F::from_canonical_u64(self.nca_proof.get_b_node_key().index),
                node_level: F::from_canonical_u8(self.nca_proof.get_level_b()),
            },
            stats: self.stats_b,
        }
    }
    pub fn get_guta_header_a_ho<H: MerkleZeroHasher<HashOut<F>>>(&self) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_a.root,
            checkpoint_tree_root: compute_historical_and_current_merkle_roots_core_gt_qho::<F, H>(&self.historical_checkpoint_proof_a).0,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_a.old_value,
                new_node_value: self.nca_proof.child_a.new_value,
                node_index: F::from_canonical_u64(self.nca_proof.get_a_node_key().index),
                node_level: F::from_canonical_u8(self.nca_proof.get_level_a()),
            },
            stats: self.stats_a,
        }
    }
    pub fn get_guta_header_b_ho<H: MerkleZeroHasher<HashOut<F>>>(&self) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_b.root,
            checkpoint_tree_root: compute_historical_and_current_merkle_roots_core_gt_qho::<F, H>(&self.historical_checkpoint_proof_b).0,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_b.old_value,
                new_node_value: self.nca_proof.child_b.new_value,
                node_index: F::from_canonical_u64(self.nca_proof.get_b_node_key().index),
                node_level: F::from_canonical_u8(self.nca_proof.get_level_b()),
            },
            stats: self.stats_b,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyEndCapSimpleStandardInput<F: RichField> {
    pub guta_stats: GUTAStats<F>,
    pub checkpoint_root: QHashOut<F>,
    pub checkpoint_historical_merkle_proof: MerkleProofCore<QHashOut<F>>,
}

impl VerifyEndCapSimpleStandardInput<GoldilocksField> {
    pub fn check_witness(&self) -> anyhow::Result<()> {
        let (historical_root, current_root) =
            compute_historical_and_current_merkle_roots_core_gt::<QHashOut<GoldilocksField>, PsyHasher>(&self.checkpoint_historical_merkle_proof);
        if self.checkpoint_root != historical_root {
            return Err(anyhow::anyhow!("end result historical root not match"));
        }
        if current_root != self.checkpoint_historical_merkle_proof.root {
            return Err(anyhow::anyhow!("end result current root not match"));
        }
        Ok(())
    }
}
impl<F: RichField> KVQSerializable for VerifyEndCapSimpleStandardInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyTwoEndCapCircuitWithIdsInput<F: RichField> {
    pub input: VerifyTwoEndCapCircuitInput<F>,

    pub proof_a_id: QProvingJobDataID,
    pub proof_b_id: QProvingJobDataID,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyTwoEndCapCircuitInput<F: RichField> {
    pub guta_circuit_whitelist: QHashOut<F>,

    pub a_end_cap: VerifyEndCapSimpleStandardInput<F>,

    pub b_end_cap: VerifyEndCapSimpleStandardInput<F>,

    pub nca_proof: PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,
}

impl<F: RichField> VerifyTwoEndCapCircuitInput<F> {
    pub fn get_end_result_a(&self) -> UPSEndCapResultCompact<F> {
        UPSEndCapResultCompact {
            start_user_leaf_hash: self.nca_proof.child_a.old_value,
            end_user_leaf_hash: self.nca_proof.child_a.new_value,
            checkpoint_tree_root_hash: self.a_end_cap.checkpoint_root,
            user_id: F::from_canonical_u64(self.nca_proof.child_a.index),
        }
    }
    pub fn get_end_result_b(&self) -> UPSEndCapResultCompact<F> {
        UPSEndCapResultCompact {
            start_user_leaf_hash: self.nca_proof.child_b.old_value,
            end_user_leaf_hash: self.nca_proof.child_b.new_value,
            checkpoint_tree_root_hash: self.b_end_cap.checkpoint_root,
            user_id: F::from_canonical_u64(self.nca_proof.child_b.index),
        }
    }

    pub fn get_new_guta_header<H: AlgebraicHasher<F> + MerkleZeroHasherWithMarkedLeaf<HashOut<F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<F>>>(
        &self,
    ) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_circuit_whitelist,
            checkpoint_tree_root: self.a_end_cap.checkpoint_historical_merkle_proof.root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.compute_old_nca_value::<H>(),
                new_node_value: self.nca_proof.compute_new_nca_value::<H>(),
                node_index: F::from_canonical_u64(self.nca_proof.get_nca_index()),
                node_level: F::from_canonical_u8(self.nca_proof.nearest_common_ancestor_level),
            },
            stats: self.a_end_cap.guta_stats.combine_with(&self.b_end_cap.guta_stats),
        }
    }
}
impl VerifyTwoEndCapCircuitInput<GoldilocksField> {
    pub fn check_witness(&self) -> anyhow::Result<()> {
        self.a_end_cap.check_witness()?;
        self.b_end_cap.check_witness()?;

        if self.a_end_cap.checkpoint_historical_merkle_proof.root != self.b_end_cap.checkpoint_historical_merkle_proof.root {
            return Err(anyhow::anyhow!("two endcap current checkpoint root not match"));
        }
        // todo: check nca proof

        Ok(())
    }
}
impl<F: RichField> KVQSerializable for VerifyTwoEndCapCircuitInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifySingleEndCapInput<F: RichField> {
    pub guta_circuit_whitelist: QHashOut<F>,

    pub a_end_cap: VerifyEndCapSimpleStandardInput<F>,

    pub start_user_leaf_hash: QHashOut<F>,
    pub end_user_leaf_hash: QHashOut<F>,
    pub user_id: F,
}

impl<F: RichField> VerifySingleEndCapInput<F> {
    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_circuit_whitelist,
            checkpoint_tree_root: self.a_end_cap.checkpoint_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.start_user_leaf_hash,
                new_node_value: self.end_user_leaf_hash,
                node_index: self.user_id,
                node_level: F::from_canonical_u8(GLOBAL_USER_TREE_HEIGHT),
            },
            stats: self.a_end_cap.guta_stats,
        }
    }
    pub fn get_new_guta_header(&self) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_circuit_whitelist,
            checkpoint_tree_root: self.a_end_cap.checkpoint_historical_merkle_proof.root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.start_user_leaf_hash,
                new_node_value: self.end_user_leaf_hash,
                node_index: self.user_id,
                node_level: F::from_canonical_u8(GLOBAL_USER_TREE_HEIGHT),
            },
            stats: self.a_end_cap.guta_stats,
        }
    }
    pub fn get_end_result_a(&self) -> UPSEndCapResultCompact<F> {
        UPSEndCapResultCompact {
            start_user_leaf_hash: self.start_user_leaf_hash,
            end_user_leaf_hash: self.end_user_leaf_hash,
            checkpoint_tree_root_hash: self.a_end_cap.checkpoint_root,
            user_id: self.user_id,
        }
    }
}
impl VerifySingleEndCapInput<GoldilocksField> {
    pub fn check_witness(&self) -> anyhow::Result<()> {
        self.a_end_cap.check_witness()?;
        let end_result = self.get_end_result_a();
        let guta_new_header = self.get_new_guta_header();
        if end_result.start_user_leaf_hash != guta_new_header.state_transition.old_node_value
            || end_result.end_user_leaf_hash != guta_new_header.state_transition.new_node_value
            || end_result.user_id != guta_new_header.state_transition.node_index
        {
            return Err(anyhow::anyhow!("end result not match"));
        }

        let (historical_root, current_root) = compute_historical_and_current_merkle_roots_core_gt::<QHashOut<GoldilocksField>, PsyHasher>(
            &self.a_end_cap.checkpoint_historical_merkle_proof,
        );
        if historical_root != end_result.checkpoint_tree_root_hash {
            return Err(anyhow::anyhow!("historical root not match"));
        }
        if current_root != guta_new_header.checkpoint_tree_root {
            return Err(anyhow::anyhow!("current root not match"));
        }

        Ok(())
    }
}
impl<F: RichField> KVQSerializable for VerifySingleEndCapInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyLeftGUTARightEndCapInputSimple<F: RichField> {
    pub checkpoint_tree_root: QHashOut<F>,
    pub stats_a: GUTAStats<F>,
    pub b_end_cap: VerifyEndCapSimpleStandardInput<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,
}

impl VerifyLeftGUTARightEndCapInputSimple<GoldilocksField> {
    pub fn check_witness(&self) -> anyhow::Result<()> {
        self.b_end_cap.check_witness()?;
        let (_historical_root, current_root) = compute_historical_and_current_merkle_roots_core_gt::<QHashOut<GoldilocksField>, PsyHasher>(
            &self.b_end_cap.checkpoint_historical_merkle_proof,
        );
        if current_root != self.checkpoint_tree_root {
            return Err(anyhow::anyhow!("left guta right endcap checkpoint tree root not match"));
        }
        if current_root != self.b_end_cap.checkpoint_historical_merkle_proof.root {
            return Err(anyhow::anyhow!("right endcap historical merkel proof not match"));
        }
        Ok(())
    }
}
impl<F: RichField> KVQSerializable for VerifyLeftGUTARightEndCapInputSimple<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyLeftGUTARightEndCapInput<F: RichField> {
    pub checkpoint_tree_root: QHashOut<F>,
    pub stats_a: GUTAStats<F>,
    pub b_end_cap: VerifyEndCapSimpleStandardInput<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,

    pub guta_inclusion_proof_a: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> KVQSerializable for VerifyLeftGUTARightEndCapInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> VerifyLeftGUTARightEndCapInput<F> {
    pub fn get_guta_header_a(&self) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_a.root,
            checkpoint_tree_root: self.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_a.old_value,
                new_node_value: self.nca_proof.child_a.new_value,
                node_index: F::from_canonical_u64(self.nca_proof.get_a_node_key().index),
                node_level: F::from_canonical_u8(self.nca_proof.get_level_a()),
            },
            stats: self.stats_a,
        }
    }
    pub fn get_end_result_b(&self) -> UPSEndCapResultCompact<F> {
        UPSEndCapResultCompact {
            start_user_leaf_hash: self.nca_proof.child_b.old_value,
            end_user_leaf_hash: self.nca_proof.child_b.new_value,
            checkpoint_tree_root_hash: self.b_end_cap.checkpoint_root,
            user_id: F::from_canonical_u64(self.nca_proof.child_b.index),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyLeftEndCapRightGUTAInputSimple<F: RichField> {
    pub checkpoint_tree_root: QHashOut<F>,
    pub stats_b: GUTAStats<F>,
    pub a_end_cap: VerifyEndCapSimpleStandardInput<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,
}

impl VerifyLeftEndCapRightGUTAInputSimple<GoldilocksField> {
    pub fn check_witness(&self) -> anyhow::Result<()> {
        self.a_end_cap.check_witness()?;
        let (_historical_root, current_root) = compute_historical_and_current_merkle_roots_core_gt::<QHashOut<GoldilocksField>, PsyHasher>(
            &self.a_end_cap.checkpoint_historical_merkle_proof,
        );
        if current_root != self.checkpoint_tree_root {
            return Err(anyhow::anyhow!("left endcap right guta checkpoint tree root not match"));
        }
        if current_root != self.a_end_cap.checkpoint_historical_merkle_proof.root {
            return Err(anyhow::anyhow!("left endcap historical merkel proof not match"));
        }
        Ok(())
    }
}

impl<F: RichField> KVQSerializable for VerifyLeftEndCapRightGUTAInputSimple<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyLeftEndCapRightGUTAInput<F: RichField> {
    pub checkpoint_tree_root: QHashOut<F>,
    pub stats_b: GUTAStats<F>,
    pub a_end_cap: VerifyEndCapSimpleStandardInput<F>,
    pub nca_proof: PartialUpdateNearestCommonAncestorProof<QHashOut<F>>,

    pub guta_inclusion_proof_b: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> KVQSerializable for VerifyLeftEndCapRightGUTAInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl<F: RichField> VerifyLeftEndCapRightGUTAInput<F> {
    pub fn get_guta_header_b(&self) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_inclusion_proof_b.root,
            checkpoint_tree_root: self.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransition {
                old_node_value: self.nca_proof.child_b.old_value,
                new_node_value: self.nca_proof.child_b.new_value,
                node_index: F::from_canonical_u64(self.nca_proof.get_b_node_key().index),
                node_level: F::from_canonical_u8(self.nca_proof.get_level_b()),
            },
            stats: self.stats_b,
        }
    }
    pub fn get_end_result_a(&self) -> UPSEndCapResultCompact<F> {
        UPSEndCapResultCompact {
            start_user_leaf_hash: self.nca_proof.child_a.old_value,
            end_user_leaf_hash: self.nca_proof.child_a.new_value,
            checkpoint_tree_root_hash: self.a_end_cap.checkpoint_root,
            user_id: F::from_canonical_u64(self.nca_proof.child_a.index),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct GUTANoChangeFullInput<F: RichField> {
    pub checkpoint_tree_proof: MerkleProofCore<QHashOut<F>>,
    pub checkpoint_leaf: PsyCheckpointLeafCompactWithStateRoots<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct GUTARegisterUserFullInput<F: RichField> {
    pub user_registration_tree_merkle_proof: MerkleProofCore<QHashOut<F>>,
    pub global_user_tree_update_proof: DeltaMerkleProofCore<QHashOut<F>>,
}
impl<F: RichField> GUTARegisterUserFullInput<F> {
    pub fn new_empty<H: FieldQHasher<F>>(height: usize) -> Self {
        let user_state_tree_root = QHashOut::from_values(
            DEFAULT_USER_STATE_TREE_ROOT_U64[0],
            DEFAULT_USER_STATE_TREE_ROOT_U64[1],
            DEFAULT_USER_STATE_TREE_ROOT_U64[2],
            DEFAULT_USER_STATE_TREE_ROOT_U64[3],
        );
        let fake_public_key = QHashOut::from_values(1, 1, 1, 1);
        let siblings = (0..GLOBAL_USER_TREE_HEIGHT).map(|_| QHashOut::ZERO).collect::<Vec<_>>();
        let user_registration_tree_merkle_proof = MerkleProofCore::new_from_params::<H>(0, fake_public_key, siblings);

        let user_leaf = PsyUserLeaf::new_user_default(F::ZERO, fake_public_key, user_state_tree_root);
        let leaf_hash = user_leaf.qfhash::<H>();

        let dmp_siblings = (0..height).map(|_| QHashOut::ZERO).collect();
        let global_user_tree_update_proof = DeltaMerkleProofCore::from_params::<H>(0, QHashOut::ZERO, leaf_hash, dmp_siblings);

        Self {
            user_registration_tree_merkle_proof,
            global_user_tree_update_proof,
        }
    }

    pub fn new_dummy(height: usize, dummy_user_leaf_hash: QHashOut<F>, fake_public_key: QHashOut<F>) -> Self {
        let siblings = (0..GLOBAL_USER_TREE_HEIGHT).map(|_| QHashOut::ZERO).collect::<Vec<_>>();
        let user_registration_tree_merkle_proof = MerkleProofCore {
            siblings,
            root: QHashOut::ZERO,
            value: fake_public_key,
            index: 0,
        };

        let dmp_siblings = (0..height).map(|_| QHashOut::ZERO).collect();
        let global_user_tree_update_proof = DeltaMerkleProofCore {
            siblings: dmp_siblings,
            old_root: QHashOut::ZERO,
            old_value: QHashOut::ZERO,
            new_root: QHashOut::ZERO,
            new_value: dummy_user_leaf_hash,
            index: 0,
        };

        Self {
            user_registration_tree_merkle_proof,
            global_user_tree_update_proof,
        }
    }
}

impl<F: RichField> KVQSerializable for GUTARegisterUserFullInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyGUTAToCapCircuitInputSimple<F: RichField> {
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F>,
    pub top_line_siblings: Vec<QHashOut<F>>,
}
impl<F: RichField> VerifyGUTAToCapCircuitInputSimple<F> {
    pub fn get_new_state_transition<H: FieldQHasher<F>>(&self) -> SubTreeNodeStateTransition<F> {
        if self.top_line_siblings.len() == 0 {
            self.guta_proof_header.state_transition.clone()
        } else {
            let new_dmp = DeltaMerkleProofCore::from_params::<H>(
                self.guta_proof_header.state_transition.node_index.to_canonical_u64(),
                self.guta_proof_header.state_transition.old_node_value,
                self.guta_proof_header.state_transition.new_node_value,
                self.top_line_siblings.clone(),
            );

            SubTreeNodeStateTransition {
                old_node_value: new_dmp.old_root,
                new_node_value: new_dmp.new_root,
                node_index: F::from_canonical_u64(
                    self.guta_proof_header.state_transition.node_index.to_canonical_u64() >> (self.top_line_siblings.len() as u64),
                ),
                node_level: F::from_canonical_u64(
                    self.guta_proof_header.state_transition.node_level.to_canonical_u64() - (self.top_line_siblings.len() as u64),
                ),
            }
        }
    }
    pub fn get_new_guta_header<H: FieldQHasher<F>>(&self) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_proof_header.guta_circuit_whitelist,
            checkpoint_tree_root: self.guta_proof_header.checkpoint_tree_root,
            state_transition: self.get_new_state_transition::<H>(),
            stats: self.guta_proof_header.stats,
        }
    }
}
impl<F: RichField> KVQSerializable for VerifyGUTAToCapCircuitInputSimple<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F: RichField> {
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F>,
    pub top_line_siblings: Vec<QHashOut<F>>,
    pub historical_checkpoint_proof: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F> {
    pub fn get_new_state_transition<H: FieldQHasher<F>>(&self) -> SubTreeNodeStateTransition<F> {
        if self.top_line_siblings.len() == 0 {
            self.guta_proof_header.state_transition.clone()
        } else {
            let new_dmp = DeltaMerkleProofCore::from_params::<H>(
                self.guta_proof_header.state_transition.node_index.to_canonical_u64(),
                self.guta_proof_header.state_transition.old_node_value,
                self.guta_proof_header.state_transition.new_node_value,
                self.top_line_siblings.clone(),
            );

            SubTreeNodeStateTransition {
                old_node_value: new_dmp.old_root,
                new_node_value: new_dmp.new_root,
                node_index: F::from_canonical_u64(
                    self.guta_proof_header.state_transition.node_index.to_canonical_u64() >> (self.top_line_siblings.len() as u64),
                ),
                node_level: F::from_canonical_u64(
                    self.guta_proof_header.state_transition.node_level.to_canonical_u64() - (self.top_line_siblings.len() as u64),
                ),
            }
        }
    }
    pub fn get_new_guta_header<H: FieldQHasher<F>>(&self) -> GlobalUserTreeAggregatorHeader<F> {
        GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: self.guta_proof_header.guta_circuit_whitelist,
            // upgraded to the new root for the new header
            checkpoint_tree_root: self.historical_checkpoint_proof.root,
            state_transition: self.get_new_state_transition::<H>(),
            stats: self.guta_proof_header.stats,
        }
    }
}
impl<F: RichField> KVQSerializable for VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct VerifyGUTARegisterUsersCircuitInputSimple<F: RichField> {
    pub guta_proof_header: GlobalUserTreeAggregatorHeader<F>,
    pub top_line_siblings: Vec<QHashOut<F>>,
    pub guta_register_user_inputs: Vec<GUTARegisterUserFullInput<F>>,
}

impl<F: RichField> KVQSerializable for VerifyGUTARegisterUsersCircuitInputSimple<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct GUTAOnlyRegisterUsersInput<F: RichField> {
    pub checkpoint_tree_root: QHashOut<F>,
    pub guta_register_user_inputs: Vec<GUTARegisterUserFullInput<F>>,
}

impl<F: RichField> KVQSerializable for GUTAOnlyRegisterUsersInput<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
