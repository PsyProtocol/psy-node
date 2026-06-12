use kvq::traits::KVQSerializable;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::{
    merkle::core::MerkleProofCore,
    traits::{hasher::FieldQHasher, qhashable::QFieldHashable},
};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::contract::PsyContractLeaf;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct PsyContractInclusionProof<F: RichField> {
    pub contract_leaf: PsyContractLeaf<F>,
    pub contract_tree_merkle_proof: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> PsyContractInclusionProof<F> {
    pub fn verify<H: FieldQHasher<F>>(&self) -> bool {
        self.contract_tree_merkle_proof.value == self.contract_leaf.qfhash::<H>() && self.contract_tree_merkle_proof.verify::<H>()
    }
}

impl<F: RichField> KVQSerializable for PsyContractInclusionProof<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct PsyContractFunctionInclusionProof<F: RichField> {
    pub contract_inclusion_proof: PsyContractInclusionProof<F>,
    pub contract_function_merkle_proof: MerkleProofCore<QHashOut<F>>,
}

impl<F: RichField> PsyContractFunctionInclusionProof<F> {
    pub fn verify<H: FieldQHasher<F>>(&self) -> bool {
        // must have a valid contract inclusion proof and a valid merkle proof with an
        // index divisible by 4 (each function uses four leaves: fingerprint,
        // metadata, code hash, reserved)
        self.contract_inclusion_proof.verify::<H>()
            && self.contract_function_merkle_proof.verify::<H>()
            && (self.contract_function_merkle_proof.index & 3) == 0
    }

    // note that each function occupies four leaves:
    // 4*i = verifier fingerprint, 4*i+1 = [method_id, (num_outputs<<32)|num_inputs,
    // 0, 0], 4*i+2 = code hash, 4*i+3 = reserved zero

    pub fn get_function_verifier_fingerprint(&self) -> QHashOut<F> {
        self.contract_function_merkle_proof.value
    }
    pub fn get_method_id(&self) -> u32 {
        self.contract_function_merkle_proof.siblings[0].0.elements[0].to_canonical_u64() as u32
    }
    pub fn get_num_inputs(&self) -> usize {
        (self.contract_function_merkle_proof.siblings[0].0.elements[1].to_canonical_u64() & 0xFFFFFFFFu64) as usize
    }
    pub fn get_num_outputs(&self) -> usize {
        (self.contract_function_merkle_proof.siblings[0].0.elements[1].to_canonical_u64() >> 32u64) as usize
    }
}

impl<F: RichField> KVQSerializable for PsyContractFunctionInclusionProof<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}
