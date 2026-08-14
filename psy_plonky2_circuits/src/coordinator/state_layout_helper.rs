use parth_common::memory_stores::simple_merkle_tree::SimpleMerkleTree;
use parth_core::{
    crypto::hash::traits::{
        FieldQHasher, MerkleHasher, MerkleZeroHasher,
    },
    felt::{QFelt64, ToU64Value},
    pgoldilocks::QHashOut,
    protocol::core_types::QFHashBase,
};
use plonky2::plonk::{
    config::{AlgebraicHasher, GenericConfig},
    proof::ProofWithPublicInputs,
};
use std::time::Instant;
use psy_core::{
    constants::protocol::{
        STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT,
        STATE_LAYOUT_TREE_HEIGHT,
    },
    job::job_id::ProvingJobCircuitType,
};
use psy_data::v1::qdata::contract::{
    CanonicalContractStateLayout, CanonicalLayoutManifest,
    CanonicalTypeLayoutDag, CanonicalTypeLayoutNode,
    STATE_LAYOUT_DEPLOY_CONTRACT_ID, STATE_LAYOUT_VERSION,
};
use psy_plonky2_basic_helpers::verifier::circuit_library::{
    CircuitInfoLibraryBuilder,
};

use super::circuits::{
    batch_deploy_contract_v2::BatchDeployContractsCircuit,
    batch_update_contract::BatchUpdateContractsCircuit,
    canonical_type_layout::CanonicalTypeLayoutCircuit,
    state_layout_append_aggregate::StateLayoutAppendAggregateCircuit,
    state_layout_append::StateLayoutAppendCircuit,
    state_layout_append_wrapper::CanonicalStateLayoutAppendWrapperCircuit,
    type_layout::{
        CanonicalTypeLayoutWrapperCircuit,
        FixedArrayTypeLayoutCircuit, PrimitiveTypeLayoutCircuit,
    },
};
use crate::{
    qstandard::QStandardCircuit,
    utils::proof_serialization::serialize_plonky2_proof,
};

#[derive(Debug, Clone)]
pub struct LocalInitialLayoutProof<F>
where
    F: plonky2::hash::hash_types::RichField,
{
    pub layout: CanonicalContractStateLayout<QHashOut<F>>,
    pub canonical_verifier_fingerprint: QHashOut<F>,
    pub canonical_proof: Vec<u8>,
}

/// Canonical layout-aware base circuit bundle.
///
#[derive(Debug)]
pub struct StateLayoutCircuitManager<
    C: GenericConfig<D>,
    const D: usize,
> {
    pub canonical_type_layout: CanonicalTypeLayoutCircuit<C, D>,
    pub primitive_type_layout: PrimitiveTypeLayoutCircuit<C, D>,
    pub fixed_array_primitive_type_layout:
        FixedArrayTypeLayoutCircuit<C, D>,
    pub canonical_type_layout_wrapper:
        CanonicalTypeLayoutWrapperCircuit<C, D>,
    pub layout_append: StateLayoutAppendCircuit<C, D>,
    pub layout_aggregation_levels:
        Vec<StateLayoutAppendAggregateCircuit<C, D>>,
    pub canonical_layout_append:
        CanonicalStateLayoutAppendWrapperCircuit<C, D>,
    pub batch_deploy_contracts: BatchDeployContractsCircuit<C, D>,
    pub batch_update_contracts: BatchUpdateContractsCircuit<C, D>,
}

impl<C: GenericConfig<D>, const D: usize>
    StateLayoutCircuitManager<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        layout_top_line_height: usize,
        layout_web_tree_height: usize,
        contract_tree_height: usize,
        contract_batch_sub_tree_height: usize,
        state_layout_tree_height: usize,
        max_contract_state_tree_height: usize,
        max_layout_aggregation_depth: usize,
    ) -> Self {
        let manager_started_at = Instant::now();
        println!(
            "StateLayoutCircuitManager start (aggregation_depth: {}, tree_height: {}, append_subtree_height: {})",
            max_layout_aggregation_depth,
            state_layout_tree_height,
            layout_web_tree_height,
        );
        let started_at = Instant::now();
        let canonical_type_layout =
            CanonicalTypeLayoutCircuit::<C, D>::new();
        println!("StateLayout canonical_type_layout completed in {:?}", started_at.elapsed());
        let primitive_type_layout =
            PrimitiveTypeLayoutCircuit::<C, D>::new();
        let fixed_array_primitive_type_layout =
            FixedArrayTypeLayoutCircuit::<C, D>::new(
                &primitive_type_layout.circuit_data.common,
                &primitive_type_layout.circuit_data.verifier_only,
            );
        let canonical_type_layout_wrapper =
            CanonicalTypeLayoutWrapperCircuit::<C, D>::new(&[
                (
                    canonical_type_layout
                        .get_common_circuit_data_ref(),
                    canonical_type_layout.get_verifier_config_ref(),
                ),
                (
                    &fixed_array_primitive_type_layout
                        .circuit_data
                        .common,
                    &fixed_array_primitive_type_layout
                        .circuit_data
                        .verifier_only,
                ),
            ]);
        let started_at = Instant::now();
        let layout_append = StateLayoutAppendCircuit::new(
            layout_top_line_height,
            layout_web_tree_height,
            &canonical_type_layout_wrapper.circuit_data.common,
            &canonical_type_layout_wrapper.circuit_data.verifier_only,
        );
        println!("StateLayout layout_append completed in {:?}", started_at.elapsed());
        let started_at = Instant::now();
        let mut layout_aggregation_levels: Vec<
            StateLayoutAppendAggregateCircuit<C, D>,
        > = Vec::with_capacity(max_layout_aggregation_depth);
        for _ in 0..max_layout_aggregation_depth {
            let level = match layout_aggregation_levels.last() {
                Some(previous) => {
                    StateLayoutAppendAggregateCircuit::new(
                        previous.get_common_circuit_data_ref(),
                        previous.get_verifier_config_ref(),
                    )
                }
                None => StateLayoutAppendAggregateCircuit::new(
                    layout_append.get_common_circuit_data_ref(),
                    layout_append.get_verifier_config_ref(),
                ),
            };
            layout_aggregation_levels.push(level);
            println!(
                "StateLayout aggregation level {} completed in {:?}",
                layout_aggregation_levels.len() - 1,
                started_at.elapsed()
            );
        }
        println!("StateLayout aggregation_levels completed in {:?}", started_at.elapsed());
        let mut allowed = Vec::with_capacity(
            layout_aggregation_levels.len() + 1,
        );
        allowed.push((
            layout_append.get_common_circuit_data_ref(),
            layout_append.get_verifier_config_ref(),
        ));
        allowed.extend(layout_aggregation_levels.iter().map(|level| {
            (
                level.get_common_circuit_data_ref(),
                level.get_verifier_config_ref(),
            )
        }));
        let started_at = Instant::now();
        let canonical_layout_append =
            CanonicalStateLayoutAppendWrapperCircuit::new(&allowed);
        println!("StateLayout canonical_layout_append completed in {:?}", started_at.elapsed());
        let started_at = Instant::now();
        let batch_deploy_contracts = BatchDeployContractsCircuit::new(
            contract_tree_height,
            contract_batch_sub_tree_height,
            state_layout_tree_height,
            max_contract_state_tree_height,
            canonical_layout_append.get_common_circuit_data_ref(),
            canonical_layout_append.get_verifier_config_ref(),
        );
        println!("StateLayout batch_deploy_contracts completed in {:?}", started_at.elapsed());
        let started_at = Instant::now();
        let batch_update_contracts = BatchUpdateContractsCircuit::new(
            contract_tree_height,
            contract_batch_sub_tree_height,
            canonical_layout_append.get_common_circuit_data_ref(),
            canonical_layout_append.get_verifier_config_ref(),
        );
        println!("StateLayout batch_update_contracts completed in {:?}", started_at.elapsed());
        println!("StateLayoutCircuitManager completed in {:?}", manager_started_at.elapsed());
        Self {
            canonical_type_layout,
            primitive_type_layout,
            fixed_array_primitive_type_layout,
            canonical_type_layout_wrapper,
            layout_append,
            layout_aggregation_levels,
            canonical_layout_append,
            batch_deploy_contracts,
            batch_update_contracts,
        }
    }

    fn prove_canonical_type_layout(
        &self,
        dag: &CanonicalTypeLayoutDag,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        if let Some(CanonicalTypeLayoutNode::FixedArray {
            element,
            length,
        }) = dag.nodes.get(usize::from(dag.root))
        {
            if let Some(CanonicalTypeLayoutNode::Primitive { type_tag }) =
                dag.nodes.get(usize::from(*element))
            {
                dag.validate_shape()?;
                let child_proof =
                    self.primitive_type_layout.prove(*type_tag)?;
                let array_proof = self
                    .fixed_array_primitive_type_layout
                    .prove(&child_proof, *length)?;
                return self
                    .canonical_type_layout_wrapper
                    .prove(1, &array_proof);
            }
        }

        let proof = self.canonical_type_layout.prove(dag)?;
        self.canonical_type_layout_wrapper.prove(0, &proof)
    }

    /// Registers only network-facing deploy/update circuits.
    ///
    /// Layout/type circuits run locally while generating the command and are
    /// intentionally absent from the network proving-job library.
    pub fn register_base_library<T: CircuitInfoLibraryBuilder<C::F>>(
        &self,
        library: &mut T,
    ) {
        library.register_circuit(
            ProvingJobCircuitType::BatchDeployContracts.into(),
            self.batch_deploy_contracts.get_fingerprint(),
            self.batch_deploy_contracts
                .get_verifier_config_ref()
                .into(),
        );
        library.register_circuit(
            ProvingJobCircuitType::BatchUpdateContracts.into(),
            self.batch_update_contracts.get_fingerprint(),
            self.batch_update_contracts
                .get_verifier_config_ref()
                .into(),
        );
    }

    /// Builds the first pairwise aggregation level over layout base proofs.
    ///
    /// Further levels must be built from the returned circuit's verifier;
    /// they are intentionally not all assigned the single aggregate job ID
    /// until verifier normalization is implemented.
    pub fn first_layout_aggregation_level(
        &self,
    ) -> StateLayoutAppendAggregateCircuit<C, D> {
        StateLayoutAppendAggregateCircuit::new(
            self.layout_append.get_common_circuit_data_ref(),
            self.layout_append.get_verifier_config_ref(),
        )
    }

    /// Builds verifier data for every level of a fixed-depth pairwise tree.
    ///
    /// `levels[0]` aggregates two base layout proofs; each following entry
    /// aggregates two proofs produced by the preceding entry. This is useful
    /// for a planner that assigns verifier data per depth while the canonical
    /// aggregate wrapper is still pending.
    pub fn layout_aggregation_levels(
        &self,
        depth: usize,
    ) -> Vec<StateLayoutAppendAggregateCircuit<C, D>> {
        let mut levels: Vec<
            StateLayoutAppendAggregateCircuit<C, D>,
        > = Vec::with_capacity(depth);
        for _ in 0..depth {
            let level = match levels.last() {
                Some(previous) => {
                    StateLayoutAppendAggregateCircuit::new(
                        previous.get_common_circuit_data_ref(),
                        previous.get_verifier_config_ref(),
                    )
                }
                None => self.first_layout_aggregation_level(),
            };
            levels.push(level);
        }
        levels
    }

    /// Creates one stable verifier for all configured aggregation depths.
    pub fn canonical_layout_aggregation_wrapper(
        &self,
        levels: &[StateLayoutAppendAggregateCircuit<C, D>],
    ) -> CanonicalStateLayoutAppendWrapperCircuit<C, D> {
        assert!(
            !levels.is_empty(),
            "layout aggregation levels are empty"
        );
        let allowed = levels
            .iter()
            .map(|level| {
                (
                    level.get_common_circuit_data_ref(),
                    level.get_verifier_config_ref(),
                )
            })
            .collect::<Vec<_>>();
        CanonicalStateLayoutAppendWrapperCircuit::new(&allowed)
    }
}

impl<C: GenericConfig<D>, const D: usize>
    StateLayoutCircuitManager<C, D>
where
    C::F: QFelt64,
    C::Hasher: AlgebraicHasher<C::F>
        + FieldQHasher<C::F, QHashOut<C::F>>
        + MerkleHasher<QHashOut<C::F>>
        + MerkleZeroHasher<QHashOut<C::F>>,
    QHashOut<C::F>: QFHashBase<C::F>,
{
    /// Proves an initial layout using fixed append windows and pairwise
    /// recursive aggregation.
    ///
    /// The proof uses the reserved deploy contract id because the actual
    /// contract id is assigned only after the command reaches coordinator.
    pub fn prove_initial_layout(
        &self,
        manifest: &CanonicalLayoutManifest<QHashOut<C::F>>,
    ) -> anyhow::Result<LocalInitialLayoutProof<C::F>> {
        let prove_started_at = Instant::now();
        println!(
            "StateLayout prove_initial_layout start (fields: {}, slots: {}, state_tree_height: {})",
            manifest.layout.contract_layout.fields.len(),
            manifest.layout.contract_layout.state_layout_slot_count,
            manifest.state_tree_height,
        );
        anyhow::ensure!(
            manifest.layout_version == STATE_LAYOUT_VERSION,
            "unsupported canonical layout manifest version {}",
            manifest.layout_version
        );
        let layout = &manifest.layout;
        anyhow::ensure!(
            !layout.contract_layout.fields.is_empty(),
            "empty contract layouts are not yet supported by the local layout prover"
        );
        anyhow::ensure!(
            manifest.field_type_dags.len()
                == layout.contract_layout.fields.len(),
            "canonical type DAG count does not match layout field count"
        );
        for (index, ((dag, type_witness), field)) in manifest
            .field_type_dags
            .iter()
            .zip(&layout.field_type_layouts)
            .zip(&layout.contract_layout.fields)
            .enumerate()
        {
            let dag_summary =
                dag.evaluate::<C::Hasher, C::F, QHashOut<C::F>>()?;
            let witness_summary =
                type_witness.summary::<C::Hasher, C::F>()?;
            anyhow::ensure!(
                dag_summary == witness_summary,
                "field {} canonical type DAG and type witness disagree",
                index + 1
            );
            anyhow::ensure!(
                dag_summary.type_layout_hash == field.type_layout_hash
                    && dag_summary
                        .total_slot_count
                        .checked_add(field.payload_offset)
                        == Some(field.slot_count),
                "field {} canonical type summary does not match its layout leaf",
                index + 1
            );
        }
        // Each state-tree leaf stores four felts (a Hash).
        let state_capacity = (1u128
            .checked_shl(u32::from(manifest.state_tree_height))
            .ok_or_else(|| anyhow::anyhow!(
                "contract state tree height exceeds supported capacity"
            ))?)
            .checked_mul(4)
            .ok_or_else(|| anyhow::anyhow!("contract state capacity overflow"))?;
        anyhow::ensure!(
            u128::from(layout.contract_layout.state_layout_slot_count)
                <= state_capacity,
            "canonical layout exceeds contract state capacity"
        );
        println!(
            "StateLayout prove_initial_layout manifest validation completed in {:?}",
            prove_started_at.elapsed()
        );
        let type_proofs_started_at = Instant::now();
        let type_proofs = manifest
            .field_type_dags
            .iter()
            .enumerate()
            .map(|(index, dag)| {
                let started_at = Instant::now();
                let proof = self.prove_canonical_type_layout(dag);
                println!(
                    "StateLayout prove_initial_layout type proof {}/{} completed in {:?}",
                    index + 1,
                    manifest.field_type_dags.len(),
                    started_at.elapsed()
                );
                proof
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        println!(
            "StateLayout prove_initial_layout all type proofs completed in {:?}",
            type_proofs_started_at.elapsed()
        );
        for (index, (proof, field)) in type_proofs
            .iter()
            .zip(&layout.contract_layout.fields)
            .enumerate()
        {
            anyhow::ensure!(
                proof.public_inputs.len() == 5,
                "field {} canonical type proof has an invalid public interface",
                index + 1
            );
            let proof_type_hash = QHashOut([
                proof.public_inputs[0],
                proof.public_inputs[1],
                proof.public_inputs[2],
                proof.public_inputs[3],
            ].into());
            anyhow::ensure!(
                proof_type_hash == field.type_layout_hash
                    && proof.public_inputs[4].to_u64_value()
                        .checked_add(field.payload_offset)
                        == Some(field.slot_count),
                "field {} canonical type proof endpoint does not match its layout leaf",
                index + 1
            );
        }

        let append_planning_started_at = Instant::now();
        let mut tree =
            SimpleMerkleTree::<C::Hasher, QHashOut<C::F>>::new(
                u8::try_from(STATE_LAYOUT_TREE_HEIGHT)?,
            );
        let field_hashes = layout
            .contract_layout
            .fields
            .iter()
            .map(|field| field.hash::<C::Hasher, C::F>())
            .collect::<anyhow::Result<Vec<_>>>()?;
        let append_proofs = tree.append_leaves_spider_man(
            u8::try_from(STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT)?,
            &field_hashes,
        )?;
        for (index, proof) in append_proofs.iter().enumerate() {
            anyhow::ensure!(
                proof.verify::<C::Hasher>(),
                "native state-layout append proof {} is invalid before circuit proving",
                index
            );
            for (leaf_index, leaf_hash) in proof.web_proof_new_leaves.iter().enumerate() {
                if *leaf_hash != QHashOut::ZERO {
                    let field_index = index * (1usize << STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT) + leaf_index;
                    if let Some(expected) = field_hashes.get(field_index) {
                        anyhow::ensure!(
                            leaf_hash == expected,
                            "native append proof leaf {} does not match field hash",
                            field_index
                        );
                    }
                }
            }
        }
        anyhow::ensure!(
            !append_proofs.is_empty(),
            "initial layout produced no append proofs"
        );
        anyhow::ensure!(
            tree.get_root()
                == layout.contract_layout.state_layout_root,
            "local layout tree root does not match consensus adapter root"
        );
        println!(
            "StateLayout prove_initial_layout append planning completed in {:?} (batches: {})",
            append_planning_started_at.elapsed(),
            append_proofs.len()
        );
        let mut field_cursor = 0usize;
        let mut old_slot_count = 0u64;
        let mut base_proofs =
            Vec::with_capacity(append_proofs.len());
        let base_proofs_started_at = Instant::now();
        for (batch_index, append_proof) in append_proofs.iter().enumerate() {
            let batch_started_at = Instant::now();
            let added_count = append_proof
                .web_proof_old_leaves
                .iter()
                .zip(&append_proof.web_proof_new_leaves)
                .filter(|(old, new)| {
                    **old == QHashOut::default()
                        && **new != QHashOut::default()
                })
                .count();
            anyhow::ensure!(
                added_count > 0,
                "layout append planner produced an empty real batch"
            );
            let new_field_cursor = field_cursor
                .checked_add(added_count)
                .ok_or_else(|| anyhow::anyhow!(
                    "layout field cursor overflow"
                ))?;
            let fields =
                &layout.contract_layout.fields[field_cursor..new_field_cursor];
            let field_type_layouts =
                &layout.field_type_layouts[field_cursor..new_field_cursor];
            let field_type_proofs =
                &type_proofs[field_cursor..new_field_cursor];
            let added_slots = fields.iter().try_fold(
                0u64,
                |total, field| {
                    total.checked_add(field.slot_count).ok_or_else(|| {
                        anyhow::anyhow!("layout slot count overflow")
                    })
                },
            )?;
            let new_slot_count = old_slot_count
                .checked_add(added_slots)
                .ok_or_else(|| anyhow::anyhow!(
                    "layout slot count overflow"
                ))?;
            base_proofs.push(self.layout_append.prove(
                STATE_LAYOUT_DEPLOY_CONTRACT_ID,
                append_proof,
                fields,
                field_type_layouts,
                field_type_proofs,
                &type_proofs[0],
                u64::try_from(field_cursor)?,
                u64::try_from(new_field_cursor)?,
                old_slot_count,
                new_slot_count,
            )?);
            println!(
                "StateLayout prove_initial_layout base proof {}/{} completed in {:?} (fields: {}..{}, slots: {}..{})",
                batch_index + 1,
                append_proofs.len(),
                batch_started_at.elapsed(),
                field_cursor,
                new_field_cursor,
                old_slot_count,
                new_slot_count,
            );
            field_cursor = new_field_cursor;
            old_slot_count = new_slot_count;
        }
        println!(
            "StateLayout prove_initial_layout all base proofs completed in {:?}",
            base_proofs_started_at.elapsed()
        );
        anyhow::ensure!(
            field_cursor == layout.contract_layout.fields.len()
                && old_slot_count
                    == layout.contract_layout.state_layout_slot_count,
            "layout append batches do not cover the complete layout"
        );

        let target_batch_count = base_proofs.len().next_power_of_two();
        if base_proofs.len() < target_batch_count {
            let padding_started_at = Instant::now();
            let original_batch_count = base_proofs.len();
            let mut identity_spiderman =
                append_proofs.last().unwrap().clone();
            identity_spiderman.top_line_proof.old_root =
                identity_spiderman.top_line_proof.new_root;
            identity_spiderman.top_line_proof.old_value =
                identity_spiderman.top_line_proof.new_value;
            identity_spiderman.web_proof_old_leaves =
                identity_spiderman.web_proof_new_leaves.clone();
            let identity = self.layout_append.prove(
                STATE_LAYOUT_DEPLOY_CONTRACT_ID,
                &identity_spiderman,
                &[],
                &[],
                &[],
                &type_proofs[0],
                u64::try_from(field_cursor)?,
                u64::try_from(field_cursor)?,
                old_slot_count,
                old_slot_count,
            )?;
            while base_proofs.len() < target_batch_count {
                base_proofs.push(identity.clone());
            }
            println!(
                "StateLayout prove_initial_layout padding proof completed in {:?} (batches: {} -> {})",
                padding_started_at.elapsed(),
                original_batch_count,
                target_batch_count,
            );
        } else {
            println!(
                "StateLayout prove_initial_layout padding skipped (batches: {})",
                base_proofs.len()
            );
        }

        let mut aggregation_depth = 0usize;
        let mut current = base_proofs;
        while current.len() > 1 {
            let aggregation_started_at = Instant::now();
            let input_count = current.len();
            let aggregate = self
                .layout_aggregation_levels
                .get(aggregation_depth)
                .ok_or_else(|| anyhow::anyhow!(
                    "layout aggregation depth exceeds configured maximum"
                ))?;
            current = current
                .chunks_exact(2)
                .map(|pair| aggregate.prove(&pair[0], &pair[1]))
                .collect::<anyhow::Result<Vec<_>>>()?;
            println!(
                "StateLayout prove_initial_layout aggregation level {} completed in {:?} (proofs: {} -> {})",
                aggregation_depth,
                aggregation_started_at.elapsed(),
                input_count,
                current.len(),
            );
            aggregation_depth += 1;
        }
        let final_proof = current.pop().ok_or_else(|| {
            anyhow::anyhow!("layout proof planner produced no final proof")
        })?;
        println!(
            "StateLayout prove_initial_layout aggregation completed (depth: {})",
            aggregation_depth
        );
        let canonical_started_at = Instant::now();
        let canonical = self
            .canonical_layout_append
            .prove(aggregation_depth, &final_proof)?;
        println!(
            "StateLayout prove_initial_layout canonical wrapper proof completed in {:?}",
            canonical_started_at.elapsed()
        );
        let serialization_started_at = Instant::now();
        let canonical_proof =
            serialize_plonky2_proof::<C, D>(&canonical)?;
        println!(
            "StateLayout prove_initial_layout proof serialization completed in {:?} (bytes: {})",
            serialization_started_at.elapsed(),
            canonical_proof.len()
        );
        println!(
            "StateLayout prove_initial_layout completed in {:?}",
            prove_started_at.elapsed()
        );
        Ok(LocalInitialLayoutProof {
            layout: layout.clone(),
            canonical_verifier_fingerprint:
                self.canonical_layout_append.get_fingerprint(),
            canonical_proof,
        })
    }

    /// Proves an update whose code changes while its canonical state layout
    /// remains unchanged. The update protocol still requires one layout proof,
    /// so this builds an identity transition from the current layout root back
    /// to the same root instead of omitting the proof.
    pub fn prove_layout_no_change(
        &self,
        contract_id: u64,
        manifest: &CanonicalLayoutManifest<QHashOut<C::F>>,
    ) -> anyhow::Result<LocalInitialLayoutProof<C::F>> {
        anyhow::ensure!(
            contract_id != STATE_LAYOUT_DEPLOY_CONTRACT_ID,
            "layout update requires a real non-zero contract id"
        );
        anyhow::ensure!(
            manifest.layout_version == STATE_LAYOUT_VERSION,
            "unsupported canonical layout manifest version"
        );
        anyhow::ensure!(
            manifest.state_tree_height < 64,
            "contract state tree height is unsupported"
        );
        let layout = &manifest.layout;
        anyhow::ensure!(
            !layout.contract_layout.fields.is_empty(),
            "layout no-change proof requires at least one state field"
        );
        anyhow::ensure!(
            manifest.field_type_dags.len()
                == layout.contract_layout.fields.len(),
            "canonical type DAG count does not match layout"
        );
        let state_capacity =
            (1u64 << manifest.state_tree_height) * 4;
        anyhow::ensure!(
            layout.contract_layout.state_layout_slot_count
                <= state_capacity,
            "layout slot count exceeds contract state capacity"
        );

        let padding_type_proof =
            self.prove_canonical_type_layout(&manifest.field_type_dags[0])?;
        let mut tree =
            SimpleMerkleTree::<C::Hasher, QHashOut<C::F>>::new(
                u8::try_from(STATE_LAYOUT_TREE_HEIGHT)?,
            );
        let field_hashes = layout
            .contract_layout
            .fields
            .iter()
            .map(|field| field.hash::<C::Hasher, C::F>())
            .collect::<anyhow::Result<Vec<_>>>()?;
        let append_proofs = tree.append_leaves_spider_man(
            u8::try_from(STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT)?,
            &field_hashes,
        )?;
        anyhow::ensure!(
            tree.get_root()
                == layout.contract_layout.state_layout_root,
            "manifest root does not match its field leaves"
        );
        let mut identity = append_proofs
            .last()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!(
                "layout no-change proof produced no authentication path"
            ))?;
        identity.top_line_proof.old_root =
            identity.top_line_proof.new_root;
        identity.top_line_proof.old_value =
            identity.top_line_proof.new_value;
        identity.web_proof_old_leaves =
            identity.web_proof_new_leaves.clone();
        anyhow::ensure!(
            identity.verify::<C::Hasher>(),
            "native state-layout identity proof is invalid"
        );

        let field_count = u64::try_from(
            layout.contract_layout.fields.len(),
        )?;
        let slot_count =
            layout.contract_layout.state_layout_slot_count;
        let identity_proof = self.layout_append.prove(
            contract_id,
            &identity,
            &[],
            &[],
            &[],
            &padding_type_proof,
            field_count,
            field_count,
            slot_count,
            slot_count,
        )?;
        let canonical =
            self.canonical_layout_append.prove(0, &identity_proof)?;
        Ok(LocalInitialLayoutProof {
            layout: layout.clone(),
            canonical_verifier_fingerprint:
                self.canonical_layout_append.get_fingerprint(),
            canonical_proof:
                serialize_plonky2_proof::<C, D>(&canonical)?,
        })
    }

    /// Proves an append-only transition between two canonical manifests.
    pub fn prove_layout_update(
        &self,
        contract_id: u64,
        old_manifest: &CanonicalLayoutManifest<QHashOut<C::F>>,
        new_manifest: &CanonicalLayoutManifest<QHashOut<C::F>>,
    ) -> anyhow::Result<LocalInitialLayoutProof<C::F>> {
        anyhow::ensure!(
            contract_id != STATE_LAYOUT_DEPLOY_CONTRACT_ID,
            "layout update requires a real non-zero contract id"
        );
        anyhow::ensure!(
            old_manifest.layout_version == STATE_LAYOUT_VERSION
                && new_manifest.layout_version == STATE_LAYOUT_VERSION,
            "unsupported canonical layout manifest version"
        );
        anyhow::ensure!(
            old_manifest.state_tree_height
                == new_manifest.state_tree_height,
            "contract state tree height cannot change"
        );
        anyhow::ensure!(
            new_manifest.state_tree_height < 64,
            "contract state tree height is unsupported"
        );
        let old = &old_manifest.layout;
        let new = &new_manifest.layout;
        // Each state-tree leaf stores four felts (a Hash).
        let state_capacity =
            (1u64 << new_manifest.state_tree_height) * 4;
        anyhow::ensure!(
            new.contract_layout.state_layout_slot_count
                <= state_capacity,
            "new layout slot count exceeds contract state capacity"
        );
        let old_count = old.contract_layout.fields.len();
        anyhow::ensure!(
            new.contract_layout.fields.len() > old_count,
            "layout update must append at least one field"
        );
        anyhow::ensure!(
            new.contract_layout.fields[..old_count]
                == old.contract_layout.fields,
            "existing layout fields were modified or reordered"
        );
        anyhow::ensure!(
            new_manifest.field_type_dags.len()
                == new.contract_layout.fields.len(),
            "canonical type DAG count does not match new layout"
        );

        let appended_dags = &new_manifest.field_type_dags[old_count..];
        let type_proofs = appended_dags
            .iter()
            .map(|dag| self.prove_canonical_type_layout(dag))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let mut tree =
            SimpleMerkleTree::<C::Hasher, QHashOut<C::F>>::new(
                u8::try_from(STATE_LAYOUT_TREE_HEIGHT)?,
            );
        for (index, field) in old.contract_layout.fields.iter().enumerate() {
            tree.set_leaf(
                u64::try_from(index)?,
                field.hash::<C::Hasher, C::F>()?,
            );
        }
        anyhow::ensure!(
            tree.get_root() == old.contract_layout.state_layout_root,
            "old manifest root does not match its field leaves"
        );
        let appended_hashes = new.contract_layout.fields[old_count..]
            .iter()
            .map(|field| field.hash::<C::Hasher, C::F>())
            .collect::<anyhow::Result<Vec<_>>>()?;
        let append_proofs = tree.append_leaves_spider_man(
            u8::try_from(STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT)?,
            &appended_hashes,
        )?;
        for (batch_index, proof) in append_proofs.iter().enumerate() {
            anyhow::ensure!(
                proof.verify::<C::Hasher>(),
                "native state-layout update append proof {} is invalid before circuit proving",
                batch_index
            );
        }
        anyhow::ensure!(
            !append_proofs.is_empty()
                && tree.get_root()
                    == new.contract_layout.state_layout_root,
            "update append proofs do not reach the new layout root"
        );

        let mut field_cursor = old_count;
        let mut old_slot_count =
            old.contract_layout.state_layout_slot_count;
        let mut base_proofs =
            Vec::with_capacity(append_proofs.len());
        for append_proof in &append_proofs {
            let added_count = append_proof
                .web_proof_old_leaves
                .iter()
                .zip(&append_proof.web_proof_new_leaves)
                .filter(|(old, new)| {
                    **old == QHashOut::default()
                        && **new != QHashOut::default()
                })
                .count();
            anyhow::ensure!(
                added_count > 0,
                "layout update produced an empty real batch"
            );
            let next = field_cursor
                .checked_add(added_count)
                .ok_or_else(|| anyhow::anyhow!(
                    "layout field cursor overflow"
                ))?;
            let fields = &new.contract_layout.fields[field_cursor..next];
            let layouts = &new.field_type_layouts[field_cursor..next];
            let proof_start = field_cursor - old_count;
            let proof_end = next - old_count;
            let proofs = &type_proofs[proof_start..proof_end];
            let added_slots = fields.iter().try_fold(
                0u64,
                |total, field| {
                    total.checked_add(field.slot_count).ok_or_else(|| {
                        anyhow::anyhow!("layout slot count overflow")
                    })
                },
            )?;
            let new_slot_count = old_slot_count
                .checked_add(added_slots)
                .ok_or_else(|| anyhow::anyhow!(
                    "layout slot count overflow"
                ))?;
            base_proofs.push(self.layout_append.prove(
                contract_id,
                append_proof,
                fields,
                layouts,
                proofs,
                &type_proofs[0],
                u64::try_from(field_cursor)?,
                u64::try_from(next)?,
                old_slot_count,
                new_slot_count,
            )?);
            field_cursor = next;
            old_slot_count = new_slot_count;
        }
        anyhow::ensure!(
            field_cursor == new.contract_layout.fields.len()
                && old_slot_count
                    == new.contract_layout.state_layout_slot_count,
            "layout update batches do not cover the appended suffix"
        );

        let target_count = base_proofs.len().next_power_of_two();
        if base_proofs.len() < target_count {
            let mut identity = append_proofs.last().unwrap().clone();
            identity.top_line_proof.old_root =
                identity.top_line_proof.new_root;
            identity.top_line_proof.old_value =
                identity.top_line_proof.new_value;
            identity.web_proof_old_leaves =
                identity.web_proof_new_leaves.clone();
            let identity_proof = self.layout_append.prove(
                contract_id,
                &identity,
                &[],
                &[],
                &[],
                &type_proofs[0],
                u64::try_from(field_cursor)?,
                u64::try_from(field_cursor)?,
                old_slot_count,
                old_slot_count,
            )?;
            while base_proofs.len() < target_count {
                base_proofs.push(identity_proof.clone());
            }
        }
        let mut depth = 0usize;
        let mut current = base_proofs;
        while current.len() > 1 {
            let aggregate = self.layout_aggregation_levels.get(depth)
                .ok_or_else(|| anyhow::anyhow!(
                    "layout aggregation depth exceeds configured maximum"
                ))?;
            current = current
                .chunks_exact(2)
                .map(|pair| aggregate.prove(&pair[0], &pair[1]))
                .collect::<anyhow::Result<Vec<_>>>()?;
            depth += 1;
        }
        let final_proof = current.pop().ok_or_else(|| {
            anyhow::anyhow!("layout update produced no final proof")
        })?;
        let canonical =
            self.canonical_layout_append.prove(depth, &final_proof)?;
        Ok(LocalInitialLayoutProof {
            layout: new.clone(),
            canonical_verifier_fingerprint:
                self.canonical_layout_append.get_fingerprint(),
            canonical_proof:
                serialize_plonky2_proof::<C, D>(&canonical)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    use super::*;
    use crate::qstandard::QPsyNetworkCircuitWithType;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn builds_all_base_circuits_from_one_layout_verifier() {
        let manager = StateLayoutCircuitManager::<C, D>::new(
            2,
            1,
            4,
            1,
            1,
            8,
            3,
        );

        assert_eq!(
            manager.batch_deploy_contracts.get_circuit_type(),
            ProvingJobCircuitType::BatchDeployContracts
        );
        assert_eq!(
            manager.batch_update_contracts.get_circuit_type(),
            ProvingJobCircuitType::BatchUpdateContracts
        );

        assert_eq!(manager.layout_aggregation_levels.len(), 3);
        assert!(manager.layout_aggregation_levels.iter().all(|level| {
            level.circuit_data.common.num_public_inputs == 19
        }));
        assert_eq!(
            manager
                .canonical_layout_append
                .circuit_data
                .common
                .num_public_inputs,
            19
        );
        assert_eq!(manager.canonical_layout_append.adapters.len(), 4);
    }
}
