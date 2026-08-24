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
