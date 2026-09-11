use parth_core::{crypto::hash::{spiderman::SpidermanUpdateProof, traits::{FieldQHasher, MerkleHasher, PCircuitWitness, QFieldHashable}}, felt::QFelt64, protocol::core_types::{Q256BitHash, QFHashBase}};
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{FallbackPsySerializeCanonical, PsyCanonicalSerializeMetadata, PsyIOReadWrite};

use crate::{agg::{AggStateTrackableInput, AggStateTransition}, protocol::circuit_inputs::append_user_registration_tree::compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf, v1::qdata::contract::PQEDContractLeafV2};


/// Layout-aware deploy input. Its distinct Rust type and proof payload prevent
/// legacy 104-byte contract leaves from being accepted by the V2 circuit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QCBatchDeployContractsCircuitInput<F, Hash> {
    pub deploy_contract_circuit_whitelist: Hash,
    pub spiderman_append_proof: SpidermanUpdateProof<Hash>,
    /// Contract ids and leaves for newly occupied positions, in window order.
    pub contract_ids: Vec<u64>,
    pub contract_leaves: Vec<PQEDContractLeafV2<F, Hash>>,
    /// Serialized final layout proofs corresponding one-to-one with leaves.
    pub initial_layout_proofs: Vec<Vec<u8>>,
}

impl<F, Hash: Copy> AggStateTrackableInput<Hash> for QCBatchDeployContractsCircuitInput<F, Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        AggStateTransition {
            state_transition_start: self.spiderman_append_proof.top_line_proof.old_root,
            state_transition_end: self.spiderman_append_proof.top_line_proof.new_root,
        }
    }
}

impl<F, Hash> QCBatchDeployContractsCircuitInput<F, Hash> {
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.contract_ids.len() == self.contract_leaves.len()
                && self.contract_leaves.len()
                    == self.initial_layout_proofs.len(),
            "deploy ids, leaves and layout proofs must have equal length"
        );
        anyhow::ensure!(
            self.contract_ids.len()
                <= psy_core::constants::protocol::
                    STATE_LAYOUT_MAX_BATCH_ITEMS,
            "deploy batch exceeds capacity"
        );
        anyhow::ensure!(
            self.initial_layout_proofs
                .iter()
                .all(|proof| !proof.is_empty()),
            "deploy layout proof bytes cannot be empty"
        );
        anyhow::ensure!(
            self.initial_layout_proofs.iter().all(|proof| {
                proof.len()
                    <= psy_core::constants::protocol::
                        STATE_LAYOUT_MAX_PROOF_BYTES
            }),
            "deploy layout proof exceeds maximum size"
        );
        anyhow::ensure!(
            self.contract_ids.windows(2).all(|ids| ids[0] < ids[1]),
            "deployed contract ids must be strictly increasing"
        );
        Ok(())
    }
}

impl<F: QFelt64, Hash: Copy>
    QCBatchDeployContractsCircuitInput<F, Hash>
{
    pub fn validate<Hasher>(&self) -> anyhow::Result<()>
    where
        Hasher: FieldQHasher<F, Hash> + MerkleHasher<Hash>,
        Hash: QFHashBase<F> + Default + PartialEq,
        PQEDContractLeafV2<F, Hash>: QFieldHashable<F, Hash>,
    {
        self.validate_shape()?;
        anyhow::ensure!(
            self.spiderman_append_proof.verify::<Hasher>(),
            "invalid contract-tree Spiderman deploy proof"
        );
        let window_size =
            self.spiderman_append_proof.web_proof_old_leaves.len();
        anyhow::ensure!(
            window_size
                == self
                    .spiderman_append_proof
                    .web_proof_new_leaves
                    .len(),
            "contract deploy proof window lengths differ"
        );
        let window_start = self
            .spiderman_append_proof
            .top_line_proof
            .index
            .checked_mul(window_size as u64)
            .ok_or_else(|| anyhow::anyhow!(
                "contract deploy window index overflow"
            ))?;
        let mut added_index = 0usize;
        for (window_index, (&old_hash, &new_hash)) in self
            .spiderman_append_proof
            .web_proof_old_leaves
            .iter()
            .zip(
                &self
                    .spiderman_append_proof
                    .web_proof_new_leaves,
            )
            .enumerate()
        {
            if old_hash == new_hash {
                continue;
            }
            anyhow::ensure!(
                old_hash == Hash::default()
                    && new_hash != Hash::default(),
                "contract deploy proof attempts to overwrite a leaf"
            );
            let expected_contract_id = window_start
                .checked_add(window_index as u64)
                .ok_or_else(|| anyhow::anyhow!(
                    "contract deploy id overflow"
                ))?;
            anyhow::ensure!(
                self.contract_ids.get(added_index)
                    == Some(&expected_contract_id),
                "deployed contract id does not match proof position"
            );
            anyhow::ensure!(
                self.contract_leaves[added_index].qfhash::<Hasher>()
                    == new_hash,
                "deployed contract leaf does not match proof"
            );
            added_index += 1;
        }
        anyhow::ensure!(
            added_index == self.contract_leaves.len(),
            "deploy vectors do not match added proof leaves"
        );
        Ok(())
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> PCircuitWitness<F, Hash>
    for QCBatchDeployContractsCircuitInput<F, Hash>
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
            self.deploy_contract_circuit_whitelist,
            state_transition_hash,
        )
    }
}



impl<F: QFelt64, Hash: Q256BitHash> PsyCanonicalSerializeMetadata for QCBatchDeployContractsCircuitInput<F, Hash> {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl<F: QFelt64, Hash: Q256BitHash> FallbackPsySerializeCanonical
    for QCBatchDeployContractsCircuitInput<F, Hash>
{
    fn fallback_pio_serialized_size(&self) -> usize {
        32 + self.spiderman_append_proof.pio_serialized_size()
            + 4
            + self.contract_ids.len() * 8
            + 4
            + self
                .contract_leaves
                .iter()
                .map(|leaf| leaf.pio_serialized_size())
                .sum::<usize>()
            + 4
            + self
                .initial_layout_proofs
                .iter()
                .map(|proof| 4 + proof.len())
                .sum::<usize>()
    }

    fn fallback_pio_write_to_io<W: psy_io::Write>(
        &self,
        writer: &mut W,
    ) -> anyhow::Result<()> {
        println!(
            "BatchDeployContracts witness serialize: ids_len={}, leaves_len={}, layout_proofs_len={}, ids={:?}, layout_proof_bytes={:?}, spiderman_old_leaves_len={}, spiderman_new_leaves_len={}, top_line_index={}, serialized_size={}",
            self.contract_ids.len(),
            self.contract_leaves.len(),
            self.initial_layout_proofs.len(),
            self.contract_ids,
            self.initial_layout_proofs
                .iter()
                .map(|proof| proof.len())
                .collect::<Vec<_>>(),
            self.spiderman_append_proof.web_proof_old_leaves.len(),
            self.spiderman_append_proof.web_proof_new_leaves.len(),
            self.spiderman_append_proof.top_line_proof.index,
            self.fallback_pio_serialized_size(),
        );
        self.validate_shape()?;
        writer.psy_write_bytes_fixed(
            &self
                .deploy_contract_circuit_whitelist
                .into_owned_32bytes(),
        )?;
        self.spiderman_append_proof
            .fallback_pio_write_to_io(writer)?;
        writer.psy_write_vec_length(self.contract_ids.len())?;
        for contract_id in &self.contract_ids {
            writer.psy_write_u64(*contract_id)?;
        }
        writer.psy_write_vec_length(self.contract_leaves.len())?;
        for leaf in &self.contract_leaves {
            leaf.pio_write_to_io(writer)?;
        }
        writer.psy_write_vec_length(self.initial_layout_proofs.len())?;
        for proof in &self.initial_layout_proofs {
            writer.psy_write_bytes_vec(proof)?;
        }
        Ok(())
    }

    fn fallback_pio_read_from_io<R: psy_io::Read>(
        reader: &mut R,
    ) -> anyhow::Result<Self> {
        let deploy_contract_circuit_whitelist =
            Hash::from_owned_32bytes(reader.psy_read_bytes_32()?);
        let spiderman_append_proof =
            SpidermanUpdateProof::fallback_pio_read_from_io(reader)?;
        let contract_ids_len = reader.psy_read_vec_length()?;
        println!(
            "BatchDeployContracts witness deserialize ids length: ids_len={}, capacity={}, spiderman_old_leaves_len={}, spiderman_new_leaves_len={}, top_line_index={}",
            contract_ids_len,
            psy_core::constants::protocol::STATE_LAYOUT_MAX_BATCH_ITEMS,
            spiderman_append_proof.web_proof_old_leaves.len(),
            spiderman_append_proof.web_proof_new_leaves.len(),
            spiderman_append_proof.top_line_proof.index,
        );
        anyhow::ensure!(
            contract_ids_len
                <= psy_core::constants::protocol::
                    STATE_LAYOUT_MAX_BATCH_ITEMS,
            "deploy contract id count exceeds batch capacity"
        );
        let mut contract_ids = Vec::with_capacity(contract_ids_len);
        for _ in 0..contract_ids_len {
            contract_ids.push(reader.psy_read_u64()?);
        }
        println!(
            "BatchDeployContracts witness deserialize ids: {:?}",
            contract_ids
        );
        let contract_leaves_len = reader.psy_read_vec_length()?;
        println!(
            "BatchDeployContracts witness deserialize leaves length: leaves_len={}",
            contract_leaves_len
        );
        anyhow::ensure!(
            contract_leaves_len
                <= psy_core::constants::protocol::
                    STATE_LAYOUT_MAX_BATCH_ITEMS,
            "deploy contract leaf count exceeds batch capacity"
        );
        let mut contract_leaves =
            Vec::with_capacity(contract_leaves_len);
        for _ in 0..contract_leaves_len {
            contract_leaves.push(PQEDContractLeafV2::pio_read_from_io(
                reader,
            )?);
        }
        let layout_proofs_len = reader.psy_read_vec_length()?;
        println!(
            "BatchDeployContracts witness deserialize layout proofs length: layout_proofs_len={}",
            layout_proofs_len
        );
        anyhow::ensure!(
            layout_proofs_len
                <= psy_core::constants::protocol::
                    STATE_LAYOUT_MAX_BATCH_ITEMS,
            "deploy layout proof count exceeds batch capacity"
        );
        let mut initial_layout_proofs =
            Vec::with_capacity(layout_proofs_len);
        for _ in 0..layout_proofs_len {
            initial_layout_proofs.push(
                reader.psy_read_bytes_vec_with_max_length(
                    psy_core::constants::protocol::
                        STATE_LAYOUT_MAX_PROOF_BYTES,
                )?,
            );
        }
        println!(
            "BatchDeployContracts witness deserialize completed: ids_len={}, leaves_len={}, layout_proofs_len={}, layout_proof_bytes={:?}",
            contract_ids.len(),
            contract_leaves.len(),
            initial_layout_proofs.len(),
            initial_layout_proofs
                .iter()
                .map(|proof| proof.len())
                .collect::<Vec<_>>(),
        );
        let value = Self {
            deploy_contract_circuit_whitelist,
            spiderman_append_proof,
            contract_ids,
            contract_leaves,
            initial_layout_proofs,
        };
        value.validate_shape()?;
        Ok(value)
    }
}

impl<F: QFelt64, Hash: Q256BitHash>
    psy_serialize::AutoImplementFallbackPsySerializeCanonical
    for QCBatchDeployContractsCircuitInput<F, Hash>
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

    fn valid_input() -> QCBatchDeployContractsCircuitInput<PF, Hash> {
        QCBatchDeployContractsCircuitInput {
            deploy_contract_circuit_whitelist: Hash::default(),
            spiderman_append_proof: SpidermanUpdateProof::qp_rand_gen(),
            contract_ids: vec![1],
            contract_leaves: vec![PQEDContractLeafV2::default()],
            initial_layout_proofs: vec![vec![1]],
        }
    }

    #[test]
    fn validates_deploy_batch_shape_and_rejects_each_invalid_form() {
        let valid = valid_input();
        assert!(valid.validate_shape().is_ok());

        let mut mismatched = valid.clone();
        mismatched.initial_layout_proofs.clear();
        assert!(mismatched.validate_shape().unwrap_err().to_string().contains("equal length"));

        let mut too_many = valid.clone();
        too_many.contract_ids = vec![1, 2, 3];
        too_many.contract_leaves = vec![PQEDContractLeafV2::default(); 3];
        too_many.initial_layout_proofs = vec![vec![1]; 3];
        assert!(too_many.validate_shape().unwrap_err().to_string().contains("capacity"));

        let mut empty_proof = valid.clone();
        empty_proof.initial_layout_proofs[0].clear();
        assert!(empty_proof.validate_shape().unwrap_err().to_string().contains("cannot be empty"));

        let mut unordered = valid.clone();
        unordered.contract_ids = vec![2, 1];
        unordered.contract_leaves = vec![PQEDContractLeafV2::default(); 2];
        unordered.initial_layout_proofs = vec![vec![1]; 2];
        assert!(unordered.validate_shape().unwrap_err().to_string().contains("strictly increasing"));
    }

    #[test]
    fn deploy_batch_fallback_serialization_round_trips() {
        let value = valid_input();
        let bytes = value.fallback_psy_ser_to_bytes_vec().unwrap();
        assert_eq!(bytes.len(), value.fallback_pio_serialized_size());
        assert_eq!(
            QCBatchDeployContractsCircuitInput::<PF, Hash>::fallback_psy_ser_from_slice(&bytes).unwrap(),
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

    fn deploy_input(
        proof: SpidermanUpdateProof<Hash>,
        contract_ids: Vec<u64>,
        contract_leaves: Vec<PQEDContractLeafV2<PF, Hash>>,
        initial_layout_proofs: Vec<Vec<u8>>,
    ) -> QCBatchDeployContractsCircuitInput<PF, Hash> {
        QCBatchDeployContractsCircuitInput {
            deploy_contract_circuit_whitelist: hash(1),
            spiderman_append_proof: proof,
            contract_ids,
            contract_leaves,
            initial_layout_proofs,
        }
    }

    fn valid_deploy_input() -> QCBatchDeployContractsCircuitInput<PF, Hash> {
        let leaves = vec![contract_leaf(20), contract_leaf(30)];
        let new_hashes = leaves
            .iter()
            .map(|leaf| leaf.qfhash::<PoseidonHasher>())
            .collect::<Vec<_>>();
        let proof = spiderman_proof(
            5,
            vec![Hash::default(), Hash::default()],
            new_hashes,
            vec![hash(91), hash(92)],
        );
        // window_start = top_index * web_window = 5 * 2
        deploy_input(proof, vec![10, 11], leaves, vec![vec![0xAA], vec![0xBB]])
    }

    #[test]
    fn validate_accepts_well_formed_append_batch() {
        assert!(valid_deploy_input().validate::<PoseidonHasher>().is_ok());

        // An empty batch over an unchanged (all-default) window is also valid.
        let unchanged = spiderman_proof(
            0,
            vec![Hash::default(), Hash::default()],
            vec![Hash::default(), Hash::default()],
            vec![hash(51)],
        );
        let empty = deploy_input(unchanged, vec![], vec![], vec![]);
        assert!(empty.validate::<PoseidonHasher>().is_ok());
        assert!(empty.validate_shape().is_ok());
        let bytes = empty.fallback_psy_ser_to_bytes_vec().unwrap();
        assert!(
            QCBatchDeployContractsCircuitInput::<PF, Hash>::fallback_psy_ser_from_slice(&bytes).unwrap() == empty
        );
    }

    #[test]
    fn validate_rejects_proof_and_vector_mismatches() {
        // Corrupted top-line root: the Spiderman proof no longer verifies.
        let mut corrupted = valid_deploy_input();
        corrupted.spiderman_append_proof.top_line_proof.new_root = hash(123);
        assert!(corrupted
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("invalid contract-tree Spiderman deploy proof"));

        // Overwriting an existing (non-default) leaf is rejected.
        let leaves = vec![contract_leaf(20), contract_leaf(30)];
        let occupied = spiderman_proof(
            5,
            vec![hash(55), Hash::default()],
            vec![leaves[0].qfhash::<PoseidonHasher>(), Hash::default()],
            vec![hash(91), hash(92)],
        );
        let overwrite = deploy_input(
            occupied,
            vec![10, 11],
            leaves,
            vec![vec![0xAA], vec![0xBB]],
        );
        assert!(overwrite
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("attempts to overwrite a leaf"));

        // Deployed id does not line up with the proof window position.
        let mut wrong_ids = valid_deploy_input();
        wrong_ids.contract_ids = vec![10, 999];
        assert!(wrong_ids
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("deployed contract id does not match proof position"));

        // Serialized leaf does not hash to the web-proof leaf.
        let mut wrong_leaf = valid_deploy_input();
        wrong_leaf.contract_leaves[0] = contract_leaf(21);
        assert!(wrong_leaf
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("deployed contract leaf does not match proof"));

        // Fewer id/leaf/proof vectors than appended proof leaves: the id check
        // fires first because the proof keeps appending past the short vector.
        let leaves = vec![contract_leaf(20), contract_leaf(30)];
        let new_hashes = leaves
            .iter()
            .map(|leaf| leaf.qfhash::<PoseidonHasher>())
            .collect::<Vec<_>>();
        let short_proof = spiderman_proof(
            5,
            vec![Hash::default(), Hash::default()],
            new_hashes.clone(),
            vec![hash(91), hash(92)],
        );
        let short = deploy_input(short_proof, vec![10], vec![leaves[0]], vec![vec![0xAA]]);
        assert!(short
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("deployed contract id does not match proof position"));

        // An unchanged window with a leftover leaf reaches the final tally check:
        // every position is old == new, so nothing is appended, yet a leaf remains.
        let unchanged_proof = spiderman_proof(
            5,
            vec![Hash::default(), Hash::default()],
            vec![Hash::default(), Hash::default()],
            vec![hash(91), hash(92)],
        );
        let unchanged = deploy_input(
            unchanged_proof,
            vec![10],
            vec![contract_leaf(20)],
            vec![vec![0xAA]],
        );
        assert!(unchanged
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("deploy vectors do not match added proof leaves"));

        // window_start = index * window_size overflows u64.
        let overflow_proof = spiderman_proof(
            u64::MAX,
            vec![Hash::default(), Hash::default()],
            new_hashes,
            vec![hash(91), hash(92)],
        );
        let overflow = deploy_input(overflow_proof, vec![0, 1], leaves, vec![vec![0xAA], vec![0xBB]]);
        assert!(overflow
            .validate::<PoseidonHasher>()
            .unwrap_err()
            .to_string()
            .contains("contract deploy window index overflow"));
    }

    #[test]
    fn validate_shape_rejects_oversized_layout_proof_bytes() {
        let mut oversized = valid_input();
        oversized.initial_layout_proofs[0] = vec![0u8; STATE_LAYOUT_MAX_PROOF_BYTES + 1];
        assert!(oversized
            .validate_shape()
            .unwrap_err()
            .to_string()
            .contains("exceeds maximum size"));
    }

    #[test]
    fn state_transition_and_expected_hash_follow_append_proof() {
        let input = valid_deploy_input();
        assert_eq!(
            input.get_state_transition().state_transition_start,
            input.spiderman_append_proof.top_line_proof.old_root
        );
        assert_eq!(
            input.get_state_transition().state_transition_end,
            input.spiderman_append_proof.top_line_proof.new_root
        );
        let expected = compute_agg_state_trackable_final_public_inputs_no_rewards_tag_leaf::<PoseidonHasher, PF, Hash>(
            input.deploy_contract_circuit_whitelist,
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
        input.spiderman_append_proof.fallback_pio_write_to_io(&mut proof_bytes).unwrap();
        let mut leaf_bytes = Vec::new();
        input.contract_leaves[0].pio_write_to_io(&mut leaf_bytes).unwrap();

        let ids_len_offset = 32 + proof_bytes.len();
        let leaves_len_offset = ids_len_offset + 4 + input.contract_ids.len() * 8;
        let layout_proofs_len_offset = leaves_len_offset + 4 + leaf_bytes.len();

        let over_limit = u32::try_from(STATE_LAYOUT_MAX_BATCH_ITEMS + 1).unwrap();

        let mut forged = bytes.clone();
        forged[ids_len_offset..ids_len_offset + 4].copy_from_slice(&over_limit.to_le_bytes());
        assert!(QCBatchDeployContractsCircuitInput::<PF, Hash>::fallback_psy_ser_from_slice(&forged)
            .unwrap_err()
            .to_string()
            .contains("deploy contract id count exceeds batch capacity"));

        let mut forged = bytes.clone();
        forged[leaves_len_offset..leaves_len_offset + 4].copy_from_slice(&over_limit.to_le_bytes());
        assert!(QCBatchDeployContractsCircuitInput::<PF, Hash>::fallback_psy_ser_from_slice(&forged)
            .unwrap_err()
            .to_string()
            .contains("deploy contract leaf count exceeds batch capacity"));

        let mut forged = bytes;
        forged[layout_proofs_len_offset..layout_proofs_len_offset + 4]
            .copy_from_slice(&over_limit.to_le_bytes());
        assert!(QCBatchDeployContractsCircuitInput::<PF, Hash>::fallback_psy_ser_from_slice(&forged)
            .unwrap_err()
            .to_string()
            .contains("deploy layout proof count exceeds batch capacity"));
    }
}
