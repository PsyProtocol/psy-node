use psy_client_common::data::base_types::{hash160::Hash160, hash192::Hash192, hash256::Hash256};

use super::merkle::core::{DeltaMerkleProofCore, MerkleProofCore};

pub type MerkleProof160 = MerkleProofCore<Hash160>;
pub type DeltaMerkleProof160 = DeltaMerkleProofCore<Hash160>;
pub type MerkleProof192 = MerkleProofCore<Hash192>;
pub type DeltaMerkleProof192 = DeltaMerkleProofCore<Hash192>;
pub type MerkleProof256 = MerkleProofCore<Hash256>;
pub type DeltaMerkleProof256 = DeltaMerkleProofCore<Hash256>;
