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



