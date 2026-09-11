use parth_core::{
    crypto::hash::{
        spiderman::SpidermanUpdateProof,
        traits::{
            FieldQHasher, MerkleHasher, PCircuitWitness,
            QFieldHashable,
        },
    },
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
use serde::{Deserialize, Serialize};

use crate::{
    agg::{AggStateTrackableInput, AggStateTransition},
    protocol::circuit_inputs::append_user_registration_tree::compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf,
    v1::qdata::contract::PQEDContractLeafV2,
};

/// Versioned contract-update input. Keeping this separate from the legacy
/// input prevents layout-unaware leaves from being decoded as layout-aware V2
/// leaves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QCBatchUpdateContractsCircuitInput<F, Hash> {
    pub update_contract_circuit_whitelist: Hash,
    pub spiderman_update_proof: SpidermanUpdateProof<Hash>,
    pub updated_contract_ids: Vec<u64>,
    pub old_contract_leaves: Vec<PQEDContractLeafV2<F, Hash>>,
    pub new_contract_leaves: Vec<PQEDContractLeafV2<F, Hash>>,
    /// Canonical aggregate layout proofs corresponding one-to-one with
    /// changed contract leaves.
    pub layout_update_proofs: Vec<Vec<u8>>,
}

impl<F: QFelt64, Hash: Copy> QCBatchUpdateContractsCircuitInput<F, Hash> {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.updated_contract_ids.len()
                == self.old_contract_leaves.len()
                && self.old_contract_leaves.len()
                    == self.new_contract_leaves.len()
                && self.new_contract_leaves.len()
                    == self.layout_update_proofs.len(),
            "contract update vectors must have equal length"
        );
        anyhow::ensure!(
            self.updated_contract_ids.len()
                <= psy_core::constants::protocol::
                    STATE_LAYOUT_MAX_BATCH_ITEMS,
            "contract update batch exceeds capacity"
        );
        anyhow::ensure!(
            !self.updated_contract_ids.is_empty(),
            "contract update batch cannot be empty"
        );
        anyhow::ensure!(
            self.updated_contract_ids.iter().all(|id| *id != 0),
            "update contract id must be non-zero"
        );
        anyhow::ensure!(
            self.updated_contract_ids.windows(2).all(|ids| ids[0] < ids[1]),
            "updated contract ids must be strictly increasing"
        );
        anyhow::ensure!(
            self.layout_update_proofs
                .iter()
                .all(|proof| !proof.is_empty()),
            "contract update layout proof bytes cannot be empty"
        );
        anyhow::ensure!(
            self.layout_update_proofs.iter().all(|proof| {
                proof.len()
                    <= psy_core::constants::protocol::
                        STATE_LAYOUT_MAX_PROOF_BYTES
            }),
            "contract update layout proof exceeds maximum size"
        );
        Ok(())
    }

    pub fn validate<Hasher>(&self) -> anyhow::Result<()>
    where
        Hasher: FieldQHasher<F, Hash> + MerkleHasher<Hash>,
        Hash: QFHashBase<F> + Default + PartialEq,
        PQEDContractLeafV2<F, Hash>: QFieldHashable<F, Hash>,
    {
        self.validate_shape()?;
        anyhow::ensure!(
            self.spiderman_update_proof.verify::<Hasher>(),
            "invalid contract-tree Spiderman update proof"
        );
        let changed_count = self
            .spiderman_update_proof
            .web_proof_old_leaves
            .iter()
            .zip(&self.spiderman_update_proof.web_proof_new_leaves)
            .filter(|(old, new)| old != new)
            .count();
        anyhow::ensure!(
            self.updated_contract_ids.len() == changed_count
                && self.old_contract_leaves.len() == changed_count
                && self.new_contract_leaves.len() == changed_count
                && self.layout_update_proofs.len() == changed_count,
            "contract update vectors must match changed leaf count"
        );
        let window_size =
            self.spiderman_update_proof.web_proof_old_leaves.len();
        let window_start = self
            .spiderman_update_proof
            .top_line_proof
            .index
            .checked_mul(window_size as u64)
            .ok_or_else(|| anyhow::anyhow!(
                "contract update window index overflow"
            ))?;
        let mut changed_index = 0usize;
        for (window_index, (&old_hash, &new_hash)) in self
            .spiderman_update_proof
            .web_proof_old_leaves
            .iter()
            .zip(&self.spiderman_update_proof.web_proof_new_leaves)
            .enumerate()
        {
            if old_hash == new_hash {
                continue;
            }
            let expected_contract_id = window_start
                .checked_add(window_index as u64)
                .ok_or_else(|| anyhow::anyhow!("contract id overflow"))?;
            anyhow::ensure!(
                self.updated_contract_ids[changed_index]
                    == expected_contract_id,
                "updated contract id does not match proof position"
            );
            anyhow::ensure!(
                self.old_contract_leaves[changed_index]
                    .qfhash::<Hasher>()
                    == old_hash
                    && self.new_contract_leaves[changed_index]
                        .qfhash::<Hasher>()
                        == new_hash,
                "contract leaf preimage does not match contract-tree proof"
            );
            changed_index += 1;
        }
        Ok(())
    }
}

impl<F, Hash: Copy> AggStateTrackableInput<Hash>
    for QCBatchUpdateContractsCircuitInput<F, Hash>
{
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        AggStateTransition {
            state_transition_start:
                self.spiderman_update_proof.top_line_proof.old_root,
            state_transition_end:
                self.spiderman_update_proof.top_line_proof.new_root,
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> PCircuitWitness<F, Hash>
    for QCBatchUpdateContractsCircuitInput<F, Hash>
{
    fn get_expected_public_inputs_hash<Hasher: FieldQHasher<F, Hash>>(
        &self,
    ) -> Hash {
        let state_transition_hash =
            self.get_state_transition().get_combined_hash::<Hasher>();
        compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf::<
            Hasher,
            F,
            Hash,
        >(
            self.update_contract_circuit_whitelist,
            state_transition_hash,
        )
    }
}

impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata
    for QCBatchUpdateContractsCircuitInput<F, Hash>
{
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}

impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical
    for QCBatchUpdateContractsCircuitInput<F, Hash>
{
    fn fallback_pio_serialized_size(&self) -> usize {
        32 + self.spiderman_update_proof.pio_serialized_size()
            + 4
            + self.updated_contract_ids.len() * 8
            + 4
            + self
                .old_contract_leaves
                .iter()
                .map(|leaf| leaf.pio_serialized_size())
                .sum::<usize>()
            + 4
            + self
                .new_contract_leaves
                .iter()
                .map(|leaf| leaf.pio_serialized_size())
                .sum::<usize>()
            + 4
            + self
                .layout_update_proofs
                .iter()
                .map(|proof| 4 + proof.len())
                .sum::<usize>()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(
        &self,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        self.validate_shape()?;
        writer.psy_write_bytes_fixed(
            &self
                .update_contract_circuit_whitelist
                .into_owned_32bytes(),
        )?;
        self.spiderman_update_proof
            .fallback_pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.updated_contract_ids.len())?;
        for id in &self.updated_contract_ids {
            writer.psy_write_u64(*id)?;
        }
        writer.psy_write_vec_length(self.old_contract_leaves.len())?;
        for leaf in &self.old_contract_leaves {
            leaf.pio_write_to_io(writer)?;
        }
        writer.psy_write_vec_length(self.new_contract_leaves.len())?;
        for leaf in &self.new_contract_leaves {
            leaf.pio_write_to_io(writer)?;
        }
        writer.psy_write_vec_length(self.layout_update_proofs.len())?;
        for proof in &self.layout_update_proofs {
            writer.psy_write_bytes_vec(proof)?;
        }
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(
        reader: &mut R,
    ) -> anyhow::Result<Self> {
        let update_contract_circuit_whitelist =
            Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let spiderman_update_proof =
            SpidermanUpdateProof::fallback_pio_read_from_io(reader)?;
        let id_count = reader.psy_read_vec_length()?;
        anyhow::ensure!(
            id_count
                <= psy_core::constants::protocol::
                    STATE_LAYOUT_MAX_BATCH_ITEMS,
            "update contract id count exceeds batch capacity"
        );
        let mut updated_contract_ids = Vec::with_capacity(id_count);
        for _ in 0..id_count {
            updated_contract_ids.push(reader.psy_read_u64()?);
        }
        let old_count = reader.psy_read_vec_length()?;
        anyhow::ensure!(
            old_count
                <= psy_core::constants::protocol::
                    STATE_LAYOUT_MAX_BATCH_ITEMS,
            "old contract leaf count exceeds batch capacity"
        );
        let mut old_contract_leaves = Vec::with_capacity(old_count);
        for _ in 0..old_count {
            old_contract_leaves.push(PQEDContractLeafV2::pio_read_from_io(
                reader,
            )?);
        }
        let new_count = reader.psy_read_vec_length()?;
        anyhow::ensure!(
            new_count
                <= psy_core::constants::protocol::
                    STATE_LAYOUT_MAX_BATCH_ITEMS,
            "new contract leaf count exceeds batch capacity"
        );
        let mut new_contract_leaves = Vec::with_capacity(new_count);
        for _ in 0..new_count {
            new_contract_leaves.push(PQEDContractLeafV2::pio_read_from_io(
                reader,
            )?);
        }
        let proof_count = reader.psy_read_vec_length()?;
        anyhow::ensure!(
            proof_count
                <= psy_core::constants::protocol::
                    STATE_LAYOUT_MAX_BATCH_ITEMS,
            "layout update proof count exceeds batch capacity"
        );
        let mut layout_update_proofs =
            Vec::with_capacity(proof_count);
        for _ in 0..proof_count {
            layout_update_proofs.push(
                reader.psy_read_bytes_vec_with_max_length(
                    psy_core::constants::protocol::
                        STATE_LAYOUT_MAX_PROOF_BYTES,
                )?,
            );
        }
        let value = Self {
            update_contract_circuit_whitelist,
            spiderman_update_proof,
            updated_contract_ids,
            old_contract_leaves,
            new_contract_leaves,
            layout_update_proofs,
        };
        value.validate_shape()?;
        Ok(value)
    }
}

impl<F: QFelt64, Hash: Q256BitHash>
    psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for QCBatchUpdateContractsCircuitInput<F, Hash>
{
}

#[cfg(test)]
mod tests {
    use parth_core::{
        crypto::hash::{
            merkle_proof::DeltaMerkleProofCore, spiderman::SpidermanUpdateProof,
            traits::{FromU64x4, MerkleLeafHasher, QFieldHashable},
        },
        felt::FromPrimitiveValuesFelt,
        pgoldilocks::{PoseidonHasher, QHashOut},
        utils::QPGenRandom,
        PF,
    };
    use psy_core::constants::protocol::{
        STATE_LAYOUT_MAX_BATCH_ITEMS, STATE_LAYOUT_MAX_PROOF_BYTES,
    };
    use psy_serialize::FallbackPsySerializeCanonical;

    use super::*;

    type Hash = QHashOut<PF>;

    fn valid_input() -> QCBatchUpdateContractsCircuitInput<PF, Hash> {
        QCBatchUpdateContractsCircuitInput {
            update_contract_circuit_whitelist: Hash::default(),
            spiderman_update_proof: SpidermanUpdateProof::qp_rand_gen(),
            updated_contract_ids: vec![1],
            old_contract_leaves: vec![PQEDContractLeafV2::default()],
            new_contract_leaves: vec![PQEDContractLeafV2::default()],
            layout_update_proofs: vec![vec![1]],
        }
    }

    #[test]
    fn validates_update_batch_shape_and_rejects_each_invalid_form() {
        let valid = valid_input();
        assert!(valid.validate_shape().is_ok());

        let mut mismatched = valid.clone();
        mismatched.new_contract_leaves.clear();
        assert!(mismatched.validate_shape().unwrap_err().to_string().contains("equal length"));

        let mut empty = valid.clone();
        empty.updated_contract_ids.clear();
        empty.old_contract_leaves.clear();
        empty.new_contract_leaves.clear();
        empty.layout_update_proofs.clear();
        assert!(empty.validate_shape().unwrap_err().to_string().contains("cannot be empty"));

        let mut zero_id = valid.clone();
        zero_id.updated_contract_ids[0] = 0;
        assert!(zero_id.validate_shape().unwrap_err().to_string().contains("non-zero"));

        let mut unordered = valid.clone();
        unordered.updated_contract_ids = vec![2, 1];
        unordered.old_contract_leaves = vec![PQEDContractLeafV2::default(); 2];
        unordered.new_contract_leaves = vec![PQEDContractLeafV2::default(); 2];
        unordered.layout_update_proofs = vec![vec![1]; 2];
        assert!(unordered.validate_shape().unwrap_err().to_string().contains("strictly increasing"));

        let mut empty_proof = valid.clone();
        empty_proof.layout_update_proofs[0].clear();
        assert!(empty_proof.validate_shape().unwrap_err().to_string().contains("cannot be empty"));
    }

    #[test]
    fn update_batch_fallback_serialization_round_trips() {
        let value = valid_input();
        let bytes = value.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), value.fallback_pio_serialized_size());
        assert_eq!(
            QCBatchUpdateContractsCircuitInput::<PF, Hash>::fallback_psy_ser_from_slice(&bytes).unwrap(),
            value
        );
    }

    fn hash(seed: u64) -> Hash {
        Hash::from_u64x4([
            seed,
            seed.wrapping_mul(31),
            seed.wrapping_mul(7),
            seed.wrapping_mul(13),
        ])
    }

    fn contract_leaf(seed: u64) -> PQEDContractLeafV2<PF, Hash> {
        PQEDContractLeafV2 {
            deployer: hash(seed),
            function_tree_root: hash(seed + 1),
            code_root: hash(seed + 2),
            state_tree_height: PF::from_u64_value(seed % 32),
            state_layout_root: hash(seed + 3),
            state_layout_field_count: PF::from_u64_value(seed + 4),
            state_layout_slot_count: PF::from_u64_value(seed + 5),
        }
    }

    fn spiderman_proof(
        top_index: u64,
        old_leaves: Vec<Hash>,
        new_leaves: Vec<Hash>,
        siblings: Vec<Hash>,
    ) -> SpidermanUpdateProof<Hash> {
        let old_web_root = PoseidonHasher::compute_root_from_leaves(&old_leaves).unwrap();
        let new_web_root = PoseidonHasher::compute_root_from_leaves(&new_leaves).unwrap();
        SpidermanUpdateProof {
            top_line_proof: DeltaMerkleProofCore::from_params::<PoseidonHasher>(
                top_index,
                old_web_root,
                new_web_root,
                siblings,
            ),
            web_proof_old_leaves: old_leaves,
            web_proof_new_leaves: new_leaves,
        }
    }

    fn update_input(
        proof: SpidermanUpdateProof<Hash>,
        updated_contract_ids: Vec<u64>,
        old_contract_leaves: Vec<PQEDContractLeafV2<PF, Hash>>,
        new_contract_leaves: Vec<PQEDContractLeafV2<PF, Hash>>,
        layout_update_proofs: Vec<Vec<u8>>,
    ) -> QCBatchUpdateContractsCircuitInput<PF, Hash> {
        QCBatchUpdateContractsCircuitInput {
            update_contract_circuit_whitelist: hash(1),
            spiderman_update_proof: proof,
            updated_contract_ids,
            old_contract_leaves,
            new_contract_leaves,
            layout_update_proofs,
        }
    }

    fn valid_update_input() -> QCBatchUpdateContractsCircuitInput<PF, Hash> {
        let old_leaf = contract_leaf(20);
        let new_leaf = contract_leaf(21);
        let proof = spiderman_proof(
            4,
            vec![old_leaf.qfhash::<PoseidonHasher>(), Hash::default()],
            vec![new_leaf.qfhash::<PoseidonHasher>(), Hash::default()],
            vec![hash(91), hash(92)],
        );
        // window_start = top_index * web_window = 4 * 2; first position changed.
        update_input(proof, vec![8], vec![old_leaf], vec![new_leaf], vec![vec![0xCC]])
    }

    #[test]
    fn validate_accepts_well_formed_update_batch() {
        assert!(valid_update_input().validate::<PoseidonHasher>().is_ok());

        // Updates may also touch the second slot of the window.
        let old_leaf = contract_leaf(30);
        let new_leaf = contract_leaf(31);
        let proof = spiderman_proof(
            4,
            vec![Hash::default(), old_leaf.qfhash::<PoseidonHasher>()],
            vec![Hash::default(), new_leaf.qfhash::<PoseidonHasher>()],
            vec![hash(91), hash(92)],
        );
        let second_slot = update_input(proof, vec![9], vec![old_leaf], vec![new_leaf], vec![vec![0xDD]]);
        assert!(second_slot.validate::<PoseidonHasher>().is_ok());
    }

    #[test]
    fn validate_rejects_proof_and_vector_mismatches() {
        // Corrupted top-line root: the Spiderman proof no longer verifies.
        let mut corrupted = valid_update_input();
        corrupted.spiderman_update_proof.top_line_proof.new_root = hash(123);
        assert!(corrupted
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("invalid contract-tree Spiderman update proof"));

        // Vectors shorter than the number of changed proof leaves.
        let leaves_a = vec![contract_leaf(20), contract_leaf(30)];
        let leaves_b = vec![contract_leaf(21), contract_leaf(31)];
        let old_hashes = leaves_a
            .iter()
            .map(|leaf| leaf.qfhash::<PoseidonHasher>())
            .collect::<Vec<_>>();
        let new_hashes = leaves_b
            .iter()
            .map(|leaf| leaf.qfhash::<PoseidonHasher>())
            .collect::<Vec<_>>();
        let both_changed = spiderman_proof(4, old_hashes, new_hashes, vec![hash(91), hash(92)]);
        let short = update_input(
            both_changed,
            vec![8],
            vec![leaves_a[0]],
            vec![leaves_b[0]],
            vec![vec![0xCC]],
        );
        assert!(short
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("contract update vectors must match changed leaf count"));

        // Updated id does not line up with the proof window position.
        let mut wrong_id = valid_update_input();
        wrong_id.updated_contract_ids = vec![9];
        assert!(wrong_id
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("updated contract id does not match proof position"));

        // Old leaf preimage does not hash to the web-proof old leaf.
        let mut wrong_preimage = valid_update_input();
        wrong_preimage.old_contract_leaves[0] = contract_leaf(50);
        assert!(wrong_preimage
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("contract leaf preimage does not match contract-tree proof"));

        // New leaf preimage does not hash to the web-proof new leaf.
        let mut wrong_new_preimage = valid_update_input();
        wrong_new_preimage.new_contract_leaves[0] = contract_leaf(51);
        assert!(wrong_new_preimage
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("contract leaf preimage does not match contract-tree proof"));

        // window_start = index * window_size overflows u64.
        let overflow_proof = spiderman_proof(
            u64::MAX,
            vec![contract_leaf(20).qfhash::<PoseidonHasher>(), Hash::default()],
            vec![contract_leaf(21).qfhash::<PoseidonHasher>(), Hash::default()],
            vec![hash(91), hash(92)],
        );
        let overflow = update_input(overflow_proof, vec![1], vec![contract_leaf(20)], vec![contract_leaf(21)], vec![vec![0xCC]]);
        assert!(overflow
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("contract update window index overflow"));
    }

    #[test]
    fn validate_shape_rejects_oversized_layout_proof_bytes() {
        let mut oversized = valid_input();
        oversized.layout_update_proofs[0] = vec![0u8; STATE_LAYOUT_MAX_PROOF_BYTES + 1];
        assert!(oversized
            .validate_shape()
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum size"));
    }

    #[test]
    fn state_transition_and_expected_hash_follow_update_proof() {
        let input = valid_update_input();
        assert_eq!(
            input.get_state_transition().state_transition_start,
            input.spiderman_update_proof.top_line_proof.old_root
        );
        assert_eq!(
            input.get_state_transition().state_transition_end,
            input.spiderman_update_proof.top_line_proof.new_root
        );
        let expected = compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf::<PoseidonHasher, PF, Hash>(
            input.update_contract_circuit_whitelist,
            input.get_state_transition().get_combined_hash::<PoseidonHasher>(),
        );
        assert!(input.get_expected_public_inputs_hash::<PoseidonHasher>() == expected);
    }

    #[test]
    fn deserializer_rejects_forged_batch_counts() {
        let input = valid_input();
        let bytes = input.fallback_psy_ser_to_bytes_vec().unwrap();

        // Measure the exact subfield byte lengths so the count fields can be patched.
        let mut proof_bytes = Vec::new();
        input.spiderman_update_proof.fallback_pio_write_to_io(&mut proof_bytes).unwrap();
        let mut old_leaf_bytes = Vec::new();
        input.old_contract_leaves[0].pio_write_to_io(&mut old_leaf_bytes).unwrap();
        let mut new_leaf_bytes = Vec::new();
        input.new_contract_leaves[0].pio_write_to_io(&mut new_leaf_bytes).unwrap();

        let ids_len_offset = 32 + proof_bytes.len();
        let old_leaves_len_offset = ids_len_offset + 4 + input.updated_contract_ids.len() * 8;
        let new_leaves_len_offset = old_leaves_len_offset + 4 + old_leaf_bytes.len();
        let layout_proofs_len_offset = new_leaves_len_offset + 4 + new_leaf_bytes.len();

        let over_limit = u32::try_from(STATE_LAYOUT_MAX_BATCH_ITEMS + 1).unwrap();

        let mut forged = bytes.clone();
        forged[ids_len_offset..ids_len_offset + 4].copy_from_slice(&over_limit.to_le_bytes());
        assert!(QCBatchUpdateContractsCircuitInput::<PF, Hash>::fallback_psy_ser_from_slice(&forged)
            .unwrap_err()
            .to_string()
            .contains("update contract id count exceeds batch capacity"));

        let mut forged = bytes.clone();
        forged[old_leaves_len_offset..old_leaves_len_offset + 4].copy_from_slice(&over_limit.to_le_bytes());
        assert!(QCBatchUpdateContractsCircuitInput::<PF, Hash>::fallback_psy_ser_from_slice(&forged)
            .unwrap_err()
            .to_string()
            .contains("old contract leaf count exceeds batch capacity"));

        let mut forged = bytes.clone();
        forged[new_leaves_len_offset..new_leaves_len_offset + 4].copy_from_slice(&over_limit.to_le_bytes());
        assert!(QCBatchUpdateContractsCircuitInput::<PF, Hash>::fallback_psy_ser_from_slice(&forged)
            .unwrap_err()
            .to_string()
            .contains("new contract leaf count exceeds batch capacity"));

        let mut forged = bytes;
        forged[layout_proofs_len_offset..layout_proofs_len_offset + 4]
            .copy_from_slice(&over_limit.to_le_bytes());
        assert!(QCBatchUpdateContractsCircuitInput::<PF, Hash>::fallback_psy_ser_from_slice(&forged)
            .unwrap_err()
            .to_string()
            .contains("layout update proof count exceeds batch capacity"));
    }
}

