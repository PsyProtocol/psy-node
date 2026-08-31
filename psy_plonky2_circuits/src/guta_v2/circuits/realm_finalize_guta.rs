use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{FieldQHasher, MerkleZeroHasher, QFieldHashable},
    },
    felt::{QFelt64, ToU64Value},
    pgoldilocks::{QGenericConfig, QHashOut, QRichField},
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use plonky2::{
    field::{
        extension::Extendable,
        types::{Field, PrimeField64},
    },
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        generator::{GeneratedValues, SimpleGenerator},
        target::Target,
        witness::{PartialWitness, PartitionWitness, Witness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
            VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
    util::serialization::{Buffer, IoResult, Read, Write},
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    guta::{
        header::GlobalUserTreeAggregatorHeader,
        realm_finalize::{
            RealmFinalizeGUTAAction, RealmFinalizeGUTAInput, RealmFinalizeGUTAPublicOutput,
            SIGNATURE_TYPE_ZK,
        },
    },
    worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
};
use psy_plonky2_basic_helpers::{
    builder::{
        comparison::CircuitBuilderComparison,
        hash::core::CircuitBuilderHashCore,
        pad_circuit::{pad_circuit_degree, CircuitBuilderQEDCommonGates},
        select::CircuitBuilderSelectHelpers,
        verify::CircuitBuilderVerifyProofHelpers,
    },
    u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target},
    verifier::circuit_library::CircuitInfoLibrary,
};
use psy_plonky2_common_circuits::{
    hash::merkle::gadgets::{
        delta_merkle_proof::DeltaMerkleProofGadget, merkle_proof::MerkleProofGadget,
    },
    traits::CreatableTarget,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    gadgets::qdata::{
        checkpoint::QEDCheckpointLeafGadget,
        checkpoint_compact_with_state::QEDCheckpointLeafCompactWithStateRootsGadget,
        user::QEDUserLeafGadget,
    },
    guta::gadgets::{
        guta_header::GlobalUserTreeAggregatorHeaderGadget,
        verify_guta_proof::VerifyGUTAProofGadget,
    },
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::{
        QPsyNetworkCircuitWithType, QStandardCircuit,
        QStandardCircuitProvableWithRawProofsAndRefLibrary,
    },
    treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget,
    utils::proof_serialization::deserialize_plonky2_proof,
};

const AMOUNT_BITS: usize = 60;
const SCHEDULE_DOMAIN: u64 = 0x3230_544f_5259_5350;
const PIVOT_DOMAIN: u64 = 0x3130_5654_4f56_4950;
const SOURCE_DOMAIN: u64 = 0x3130_4543_5255_4f53;
const ROTATION_ROUNDS: usize = 90;

#[derive(Debug)]
struct ConstantDivRemGenerator<F: RichField + Extendable<D>, const D: usize> {
    dividend: Target,
    divisor: u64,
    quotient: Target,
    remainder: Target,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for ConstantDivRemGenerator<F, D>
{
    fn dependencies(&self) -> Vec<Target> {
        vec![self.dividend]
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> anyhow::Result<()> {
        let dividend = witness.get_target(self.dividend).to_canonical_u64();
        out_buffer.set_target(
            self.quotient,
            F::from_canonical_u64(dividend / self.divisor),
        )?;
        out_buffer.set_target(
            self.remainder,
            F::from_canonical_u64(dividend % self.divisor),
        )
    }

    fn id(&self) -> String {
        "RealmFinalizeConstantDivRemGenerator".to_string()
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_target(self.dividend)?;
        dst.extend_from_slice(&self.divisor.to_le_bytes());
        dst.write_target(self.quotient)?;
        dst.write_target(self.remainder)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let dividend = src.read_target()?;
        let mut divisor_bytes = [0u8; 8];
        for byte in &mut divisor_bytes {
            *byte = src.read_u8()?;
        }
        let quotient = src.read_target()?;
        let remainder = src.read_target()?;
        Ok(Self {
            dividend,
            divisor: u64::from_le_bytes(divisor_bytes),
            quotient,
            remainder,
            _phantom: std::marker::PhantomData,
        })
    }
}

#[derive(Debug)]
struct CanonicalGoldilocksWordGenerator<F: RichField + Extendable<D>, const D: usize> {
    value: Target,
    lo: U32Target,
    hi: U32Target,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for CanonicalGoldilocksWordGenerator<F, D>
{
    fn dependencies(&self) -> Vec<Target> {
        vec![self.value]
    }

    fn run_once(
        &self,
        witness: &PartitionWitness<F>,
        out_buffer: &mut GeneratedValues<F>,
    ) -> anyhow::Result<()> {
        let value = witness.get_target(self.value).to_canonical_u64();
        out_buffer.set_target(self.lo.0, F::from_canonical_u32(value as u32))?;
        out_buffer.set_target(self.hi.0, F::from_canonical_u32((value >> 32) as u32))
    }

    fn id(&self) -> String {
        "RealmFinalizeCanonicalGoldilocksWordGenerator".to_string()
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_target(self.value)?;
        dst.write_target(self.lo.0)?;
        dst.write_target(self.hi.0)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        Ok(Self {
            value: src.read_target()?,
            lo: U32Target(src.read_target()?),
            hi: U32Target(src.read_target()?),
            _phantom: std::marker::PhantomData,
        })
    }
}

#[derive(Debug)]
pub struct RealmFinalizeGUTACircuit<C: GenericConfig<D> + 'static, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub root_guta: VerifyGUTAProofGadget<D>,
    pub checkpoint_id: Target,
    pub realm_sub_id: Target,
    pub anchor_checkpoint_leaf: QEDCheckpointLeafGadget,
    pub anchor_checkpoint_tree_proof: MerkleProofGadget,
    pub checkpoint_tree_proof: MerkleProofGadget,
    pub checkpoint_leaf: QEDCheckpointLeafCompactWithStateRootsGadget,
    pub old_realm_root_proof: MerkleProofGadget,
    pub validator_user_id: Target,
    pub validator_tree_proof: MerkleProofGadget,
    pub validator_user_leaf: QEDUserLeafGadget,
    pub validator_user_tree_proof: MerkleProofGadget,
    pub validator_public_key_param: HashOutTarget,
    pub signature_proof_type: Target,
    pub signature_proof: ProofWithPublicInputsTarget<D>,
    pub signature_verifier_data: VerifierCircuitTarget,
    pub validator_fee_delta_proof: DeltaMerkleProofGadget,
    pub action_hash: HashOutTarget,
    pub final_guta_header: GlobalUserTreeAggregatorHeaderGadget,
    pub public_output_hash: HashOutTarget,
    pub chain_domain: QHashOut<C::F>,
    pub circuit_data: CircuitData<C::F, C, D>,
    pub fingerprint: QHashOut<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> QPsyNetworkCircuitWithType
    for RealmFinalizeGUTACircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_circuit_type(&self) -> ProvingJobCircuitType {
        ProvingJobCircuitType::RealmFinalizeGUTA
    }
}

impl<C: QGenericConfig<D> + 'static, const D: usize> RealmFinalizeGUTACircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasher<QHashOut<C::F>>,
    C::F: QRichField,
{
    fn nonzero_bit_width(value: u64) -> usize {
        usize::max(1, (u64::BITS - value.leading_zeros()) as usize)
    }

    fn strict_div_rem_const(
        builder: &mut CircuitBuilder<C::F, D>,
        dividend: Target,
        dividend_bits: usize,
        divisor: u64,
    ) -> (Target, Target) {
        assert!(divisor > 0, "strict constant divisor must be nonzero");
        let quotient = builder.add_virtual_target();
        let remainder = builder.add_virtual_target();
        builder.add_simple_generator(ConstantDivRemGenerator::<C::F, D> {
            dividend,
            divisor,
            quotient,
            remainder,
            _phantom: std::marker::PhantomData,
        });
        builder.range_check(dividend, dividend_bits);
        builder.range_check(quotient, dividend_bits);
        let divisor_target = builder.constant(C::F::from_canonical_u64(divisor));
        let reconstructed = builder.mul_add(quotient, divisor_target, remainder);
        builder.connect(dividend, reconstructed);
        let remainder_bits = Self::nonzero_bit_width(divisor - 1);
        builder.range_check(remainder, remainder_bits);
        let comparison_bits = Self::nonzero_bit_width(divisor);
        let is_strict = builder.is_less_than(comparison_bits, remainder, divisor_target);
        builder.assert_one(is_strict.target);
        (quotient, remainder)
    }

    fn canonical_goldilocks_word(
        builder: &mut CircuitBuilder<C::F, D>,
        value: Target,
    ) -> Target {
        let lo = builder.add_virtual_u32_target();
        let hi = builder.add_virtual_u32_target();
        builder.add_simple_generator(CanonicalGoldilocksWordGenerator::<C::F, D> {
            value,
            lo,
            hi,
            _phantom: std::marker::PhantomData,
        });
        builder.range_check(lo.0, 32);
        builder.range_check(hi.0, 32);
        let two_pow_32 = C::F::from_canonical_u64(1u64 << 32);
        let reconstructed = builder.mul_const_add(two_pow_32, hi.0, lo.0);
        builder.connect(value, reconstructed);
        let max_u32 = builder.constant(C::F::from_canonical_u64(u32::MAX as u64));
        let hi_lt_max = builder.is_less_than(32, hi.0, max_u32);
        let hi_is_max = builder.is_equal(hi.0, max_u32);
        let zero = builder.zero();
        let lo_is_zero = builder.is_equal(lo.0, zero);
        let max_hi_canonical = builder.and(hi_is_max, lo_is_zero);
        let canonical = builder.or(hi_lt_max, max_hi_canonical);
        builder.assert_one(canonical.target);
        lo.0
    }

    fn enforce_rotation(
        builder: &mut CircuitBuilder<C::F, D>,
        checkpoint_id: Target,
        realm_id: Target,
        realm_sub_id: Target,
        rotation_period_checkpoints: u64,
        validator_sub_ids: &[u16],
        checkpoint_tree_height: usize,
        checkpoint_tree_root: HashOutTarget,
    ) -> (QEDCheckpointLeafGadget, MerkleProofGadget) {
        assert!(rotation_period_checkpoints > 0, "rotation period must be nonzero");
        assert!(!validator_sub_ids.is_empty(), "rotation validators must be nonempty");
        assert!(validator_sub_ids.len() <= 256, "rotation validators exceed 8-bit sub-ID space");
        assert!(validator_sub_ids.iter().all(|&id| id <= u8::MAX as u16));

        // `checkpoint_id` is the target checkpoint `T`. Epoch/anchor still use
        // the quotient; the remainder/slot is unused so one proposer is fixed
        // for the whole epoch.
        let (epoch, _slot) = Self::strict_div_rem_const(
            builder,
            checkpoint_id,
            checkpoint_tree_height,
            rotation_period_checkpoints,
        );
        assert!(checkpoint_tree_height <= 63, "checkpoint IDs must fit canonical field range");
        let epoch_bits = builder.split_le(epoch, checkpoint_tree_height);
        let epoch_lo_end = usize::min(32, epoch_bits.len());
        let epoch_lo = builder.le_sum(epoch_bits[..epoch_lo_end].iter());
        let epoch_hi = if epoch_bits.len() > 32 {
            builder.le_sum(epoch_bits[32..].iter())
        } else {
            builder.zero()
        };

        let epoch_start = builder.mul_const(
            C::F::from_canonical_u64(rotation_period_checkpoints),
            epoch,
        );
        let zero = builder.zero();
        let epoch_is_zero = builder.is_equal(epoch, zero);
        let one = builder.one();
        let epoch_start_minus_one = builder.sub(epoch_start, one);
        let anchor_checkpoint_id = builder.select(epoch_is_zero, zero, epoch_start_minus_one);
        builder.range_check(anchor_checkpoint_id, checkpoint_tree_height);

        let anchor_checkpoint_leaf = QEDCheckpointLeafGadget::create_virtual(builder);
        let anchor_checkpoint_leaf_hash =
            anchor_checkpoint_leaf.to_hash::<C::Hasher, C::F, D>(builder);
        let anchor_checkpoint_tree_proof =
            MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(
                builder,
                checkpoint_tree_height,
            );
        builder.connect(anchor_checkpoint_tree_proof.index, anchor_checkpoint_id);
        builder.connect_hashes(anchor_checkpoint_tree_proof.value, anchor_checkpoint_leaf_hash);
        builder.connect_hashes(anchor_checkpoint_tree_proof.root, checkpoint_tree_root);

        let anchor_seed = anchor_checkpoint_leaf.stats.random_seed;
        let schedule_domain = builder.constant(C::F::from_canonical_u64(SCHEDULE_DOMAIN));
        let seed = builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
            schedule_domain,
            realm_id,
            epoch_lo,
            epoch_hi,
            anchor_seed.elements[0],
            anchor_seed.elements[1],
            anchor_seed.elements[2],
            anchor_seed.elements[3],
        ]);

        let validator_count = validator_sub_ids.len() as u64;
        let index_bits = Self::nonzero_bit_width(validator_count - 1);
        let validator_count_target = builder.constant(C::F::from_canonical_u64(validator_count));
        let mut index = builder.zero();
        for round in 0..ROTATION_ROUNDS {
            let round_target = builder.constant(C::F::from_canonical_usize(round));
            let pivot_domain = builder.constant(C::F::from_canonical_u64(PIVOT_DOMAIN));
            let pivot_hash = builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                pivot_domain,
                seed.elements[0],
                seed.elements[1],
                seed.elements[2],
                seed.elements[3],
                round_target,
            ]);
            let pivot_word = Self::canonical_goldilocks_word(builder, pivot_hash.elements[0]);
            let (_, pivot) = Self::strict_div_rem_const(builder, pivot_word, 32, validator_count);

            let pivot_plus_n = builder.add(pivot, validator_count_target);
            let flip_sum = builder.sub(pivot_plus_n, index);
            let flip_ge_n =
                builder.is_greater_than_or_equal(index_bits + 1, flip_sum, validator_count_target);
            let flip_minus_n = builder.sub(flip_sum, validator_count_target);
            let flip = builder.select(flip_ge_n, flip_minus_n, flip_sum);
            builder.range_check(flip, index_bits);
            let flip_is_greater = builder.is_greater_than(index_bits, flip, index);
            let position = builder.select(flip_is_greater, flip, index);

            let source_domain = builder.constant(C::F::from_canonical_u64(SOURCE_DOMAIN));
            let source_hash = builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                source_domain,
                seed.elements[0],
                seed.elements[1],
                seed.elements[2],
                seed.elements[3],
                round_target,
                position,
            ]);
            let source_word = Self::canonical_goldilocks_word(builder, source_hash.elements[0]);
            let source_bit = builder.split_le(source_word, 32)[0];
            index = builder.select(source_bit, flip, index);
        }

        let validator_sub_id_targets = validator_sub_ids
            .iter()
            .map(|&id| builder.constant(C::F::from_canonical_u64(id as u64)))
            .collect::<Vec<_>>();
        let expected_sub_id = builder.select_in_array(&validator_sub_id_targets, index);
        builder.connect(realm_sub_id, expected_sub_id);
        (anchor_checkpoint_leaf, anchor_checkpoint_tree_proof)
    }

    /// Constrains `realm_sub_id` to the epoch-fixed scheduled proposer for
    /// target checkpoint `checkpoint_id` (`T`; production ownership uses
    /// `T = P + 1`). Exposed so integration tests can prove native/circuit
    /// agreement without constructing the full finalize circuit.
    pub fn constrain_epoch_fixed_proposer_for_tests(
        builder: &mut CircuitBuilder<C::F, D>,
        checkpoint_id: Target,
        realm_id: Target,
        realm_sub_id: Target,
        checkpoints_per_epoch: u64,
        validator_sub_ids: &[u16],
        checkpoint_tree_height: usize,
        checkpoint_tree_root: HashOutTarget,
    ) -> (QEDCheckpointLeafGadget, MerkleProofGadget) {
        Self::enforce_rotation(
            builder,
            checkpoint_id,
            realm_id,
            realm_sub_id,
            checkpoints_per_epoch,
            validator_sub_ids,
            checkpoint_tree_height,
            checkpoint_tree_root,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        root_guta_common_data: &CommonCircuitData<C::F, D>,
        root_guta_verifier_cap_height: usize,
        guta_whitelist_tree_height: u8,
        guta_circuit_whitelist_root: QHashOut<C::F>,
        signature_common_data: &CommonCircuitData<C::F, D>,
        signature_verifier_cap_height: usize,
        zk_signature_fingerprint: QHashOut<C::F>,
        checkpoint_tree_height: usize,
        coordinator_global_user_tree_height: usize,
        validator_tree_height: usize,
        realm_global_user_tree_height: usize,
        chain_domain: QHashOut<C::F>,
        rotation_period_checkpoints: u64,
        validator_sub_ids: Vec<u16>,
    ) -> Self {
        assert_eq!(
            validator_tree_height,
            coordinator_global_user_tree_height + 8,
            "validator tree height must equal realm bits plus 8 sub-ID bits",
        );
        assert!(
            rotation_period_checkpoints > 0 && !validator_sub_ids.is_empty(),
            "RealmFinalizeGUTA rotation must be configured",
        );

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);

        let root_guta = VerifyGUTAProofGadget::add_virtual_to::<C, C::F>(
            &mut builder,
            root_guta_common_data,
            root_guta_verifier_cap_height,
            guta_whitelist_tree_height,
        );
        // Pin the root GUTA whitelist proof root to the protocol's official
        // whitelist root. Without this, a malicious prover could supply an
        // attacker-defined whitelist tree and recursively verify a forged
        // GUTA header that was never produced by an approved circuit.
        let official_whitelist_root = builder.constant_hash(guta_circuit_whitelist_root.into());
        builder.connect_hashes(
            root_guta.guta_whitelist_merkle_proof.root,
            official_whitelist_root,
        );
        let root_header = root_guta.guta_proof_header_gadget;
        let realm_id = root_header.state_transition.node_index;
        let expected_realm_level = builder.constant(C::F::from_canonical_usize(
            coordinator_global_user_tree_height,
        ));
        builder.connect(root_header.state_transition.node_level, expected_realm_level);

        let checkpoint_id = builder.add_virtual_target();
        builder.range_check(checkpoint_id, checkpoint_tree_height);

        let realm_sub_id = builder.add_virtual_target();
        builder.range_check(realm_sub_id, 8);
        let (anchor_checkpoint_leaf, anchor_checkpoint_tree_proof) = Self::enforce_rotation(
            &mut builder,
            checkpoint_id,
            realm_id,
            realm_sub_id,
            rotation_period_checkpoints,
            &validator_sub_ids,
            checkpoint_tree_height,
            root_header.checkpoint_tree_root,
        );
        let checkpoint_leaf =
            QEDCheckpointLeafCompactWithStateRootsGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
            );
        let checkpoint_tree_proof = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            checkpoint_tree_height,
        );
        builder.connect(checkpoint_tree_proof.index, checkpoint_id);
        builder.connect_hashes(checkpoint_tree_proof.value, checkpoint_leaf.checkpoint_leaf_hash);
        builder.connect_hashes(checkpoint_tree_proof.root, root_header.checkpoint_tree_root);

        let checkpoint_user_tree_root = checkpoint_leaf.global_state_roots.user_tree_root;
        let checkpoint_validator_tree_root = checkpoint_leaf.global_state_roots.validator_tree_root;

        let old_realm_root_proof = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            coordinator_global_user_tree_height,
        );
        builder.connect(old_realm_root_proof.index, realm_id);
        builder.connect_hashes(
            old_realm_root_proof.value,
            root_header.state_transition.old_node_value,
        );
        builder.connect_hashes(old_realm_root_proof.root, checkpoint_user_tree_root);

        let validator_user_id = builder.add_virtual_target();
        let global_user_tree_height =
            coordinator_global_user_tree_height + realm_global_user_tree_height;
        let validator_user_id_bits = builder.split_le(validator_user_id, global_user_tree_height);
        let local_user_index =
            builder.le_sum(validator_user_id_bits[..realm_global_user_tree_height].iter());
        let validator_user_realm_id =
            builder.le_sum(validator_user_id_bits[realm_global_user_tree_height..].iter());
        builder.connect(validator_user_realm_id, realm_id);

        let validator_leaf_hash =
            builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![validator_user_id]);
        builder.ensure_hash_is_non_zero(validator_leaf_hash);
        let validator_tree_proof = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            validator_tree_height,
        );
        let validator_index_bits = builder.split_le(validator_tree_proof.index, validator_tree_height);
        let proof_sub_id = builder.le_sum(validator_index_bits[..8].iter());
        let proof_realm_id = builder.le_sum(validator_index_bits[8..].iter());
        builder.connect(proof_sub_id, realm_sub_id);
        builder.connect(proof_realm_id, realm_id);
        builder.connect_hashes(validator_tree_proof.value, validator_leaf_hash);
        builder.connect_hashes(validator_tree_proof.root, checkpoint_validator_tree_root);

        let validator_user_leaf = QEDUserLeafGadget::create_virtual(&mut builder);
        builder.connect(validator_user_leaf.user_id, validator_user_id);
        let validator_user_leaf_hash =
            validator_user_leaf.to_hash::<C::Hasher, C::F, D>(&mut builder);
        let validator_user_tree_proof = MerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(
            &mut builder,
            global_user_tree_height,
        );
        builder.connect(validator_user_tree_proof.index, validator_user_id);
        builder.connect_hashes(validator_user_tree_proof.value, validator_user_leaf_hash);
        builder.connect_hashes(validator_user_tree_proof.root, checkpoint_user_tree_root);

        let root_guta_header_hash = root_header.to_hash::<C::Hasher, C::F, D>(&mut builder);
        let checkpoint_roots_hash = builder.hash_two_to_one::<C::Hasher>(
            root_header.checkpoint_tree_root,
            checkpoint_validator_tree_root,
        );
        let roots_hash = builder.hash_two_to_one::<C::Hasher>(
            checkpoint_roots_hash,
            root_guta_header_hash,
        );
        let chain_domain_target = builder.constant_qhash(chain_domain);
        let combined_action_fields =
            builder.hash_two_to_one::<C::Hasher>(chain_domain_target, roots_hash);
        let action_hash = builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
            combined_action_fields.elements[0],
            combined_action_fields.elements[1],
            combined_action_fields.elements[2],
            combined_action_fields.elements[3],
            checkpoint_id,
            realm_id,
        ]);

        let validator_public_key_param = builder.add_virtual_hash();
        builder.ensure_hash_is_non_zero(validator_public_key_param);
        let signature_proof_type = builder.add_virtual_target();
        let expected_signature_type = builder.constant(C::F::from_canonical_u64(
            SIGNATURE_TYPE_ZK as u64,
        ));
        builder.connect(signature_proof_type, expected_signature_type);
        let one = builder.one();

        let signature_proof = builder.add_virtual_proof_with_pis(signature_common_data);
        let signature_verifier_data =
            builder.add_virtual_verifier_data(signature_verifier_cap_height);
        builder.verify_proof::<C>(
            &signature_proof,
            &signature_verifier_data,
            signature_common_data,
        );
        let actual_signature_fingerprint =
            builder.get_circuit_fingerprint::<C::Hasher>(&signature_verifier_data);
        let expected_signature_fingerprint = builder.constant_qhash(zk_signature_fingerprint);
        builder.connect_hashes(
            actual_signature_fingerprint,
            expected_signature_fingerprint,
        );

        assert_eq!(signature_proof.public_inputs.len(), 4);
        let signature_public_inputs = HashOutTarget {
            elements: signature_proof.public_inputs[..4].try_into().unwrap(),
        };
        let expected_signature_public_inputs = builder.hash_two_to_one::<C::Hasher>(
            action_hash,
            validator_public_key_param,
        );
        builder.connect_hashes(signature_public_inputs, expected_signature_public_inputs);

        let expected_validator_public_key = builder.hash_two_to_one::<C::Hasher>(
            expected_signature_fingerprint,
            validator_public_key_param,
        );
        builder.connect_hashes(validator_user_leaf.public_key, expected_validator_public_key);
        builder.ensure_hash_is_non_zero(validator_user_leaf.public_key);

        let fee = root_header.stats.da_fees_collected;
        builder.range_check(validator_user_leaf.balance, AMOUNT_BITS);
        builder.range_check(fee, AMOUNT_BITS);
        let new_balance = builder.add(validator_user_leaf.balance, fee);
        builder.range_check(new_balance, AMOUNT_BITS);
        let has_fee = builder.is_not_zero(fee);
        let new_last_checkpoint_id = builder.select(
            has_fee,
            checkpoint_id,
            validator_user_leaf.last_checkpoint_id,
        );
        let new_validator_user_leaf = QEDUserLeafGadget {
            public_key: validator_user_leaf.public_key,
            user_state_tree_root: validator_user_leaf.user_state_tree_root,
            balance: new_balance,
            nonce: validator_user_leaf.nonce,
            last_checkpoint_id: new_last_checkpoint_id,
            event_index: validator_user_leaf.event_index,
            user_id: validator_user_leaf.user_id,
        };
        let new_validator_user_leaf_hash =
            new_validator_user_leaf.to_hash::<C::Hasher, C::F, D>(&mut builder);

        let validator_fee_delta_proof =
            DeltaMerkleProofGadget::add_virtual_to::<C::Hasher, C::F, D>(
                &mut builder,
                realm_global_user_tree_height,
            );
        builder.connect(validator_fee_delta_proof.index, local_user_index);
        builder.connect_hashes(validator_fee_delta_proof.old_value, validator_user_leaf_hash);
        builder.connect_hashes(
            validator_fee_delta_proof.new_value,
            new_validator_user_leaf_hash,
        );
        builder.connect_hashes(
            validator_fee_delta_proof.old_root,
            root_header.state_transition.new_node_value,
        );

        let final_guta_header = GlobalUserTreeAggregatorHeaderGadget {
            guta_circuit_whitelist: root_header.guta_circuit_whitelist,
            checkpoint_tree_root: root_header.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransitionGadget {
                old_node_value: root_header.state_transition.old_node_value,
                new_node_value: validator_fee_delta_proof.new_root,
                node_index: realm_id,
                node_level: expected_realm_level,
            },
            stats: root_header.stats,
            total_aggregation_proofs_generated: builder.add(
                root_header.total_aggregation_proofs_generated,
                one,
            ),
        };
        let final_guta_header_hash =
            final_guta_header.to_hash::<C::Hasher, C::F, D>(&mut builder);

        // RealmFinalizeGUTA is verified independently at the coordinator edge.
        // Its four-felt public-output hash commits to the full authorization
        // sidecar; only after verification does the coordinator enqueue the
        // committed final header into standard GUTA aggregation.
        let domain_checkpoint_binding = builder.hash_two_to_one::<C::Hasher>(
            chain_domain_target,
            root_header.checkpoint_tree_root,
        );
        let checkpoint_binding = builder.hash_two_to_one::<C::Hasher>(
            domain_checkpoint_binding,
            checkpoint_validator_tree_root,
        );
        let root_guta_binding = builder.hash_two_to_one::<C::Hasher>(
            root_guta_header_hash,
            root_guta.rewards_tree_value,
        );
        let authorization_binding = builder.hash_two_to_one::<C::Hasher>(
            root_guta_binding,
            action_hash,
        );
        let authorization_fields = builder.hash_two_to_one::<C::Hasher>(
            checkpoint_binding,
            authorization_binding,
        );
        let committed_fields = builder.hash_two_to_one::<C::Hasher>(
            authorization_fields,
            final_guta_header_hash,
        );
        let public_output_hash = builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
            committed_fields.elements[0],
            committed_fields.elements[1],
            committed_fields.elements[2],
            committed_fields.elements[3],
            checkpoint_id,
            realm_id,
            validator_user_id,
            realm_sub_id,
        ]);
        builder.register_public_inputs(&public_output_hash.elements);

        builder.add_qed_type_c_common_gates();
        eprintln!("pre-pad gates: {}", builder.num_gates());
        pad_circuit_degree(&mut builder, 14);
        let circuit_data = builder.build::<C>();
        let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit_data.verifier_only));

        Self {
            root_guta,
            checkpoint_id,
            realm_sub_id,
            anchor_checkpoint_leaf,
            anchor_checkpoint_tree_proof,
            checkpoint_tree_proof,
            checkpoint_leaf,
            old_realm_root_proof,
            validator_user_id,
            validator_tree_proof,
            validator_user_leaf,
            validator_user_tree_proof,
            validator_public_key_param,
            signature_proof_type,
            signature_proof,
            signature_verifier_data,
            validator_fee_delta_proof,
            action_hash,
            final_guta_header,
            public_output_hash,
            chain_domain,
            circuit_data,
            fingerprint,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prove_base(
        &self,
        input: &RealmFinalizeGUTAInput<C::F, QHashOut<C::F>>,
        root_guta_whitelist_proof: &MerkleProofCore<QHashOut<C::F>>,
        root_guta_proof: &ProofWithPublicInputs<C::F, C, D>,
        root_guta_verifier_data: &VerifierOnlyCircuitData<C, D>,
        root_guta_reward_tag: QHashOut<C::F>,
        signature_proof: &ProofWithPublicInputs<C::F, C, D>,
        signature_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut witness = PartialWitness::<C::F>::new();
        self.root_guta.set_witness(
            &mut witness,
            root_guta_whitelist_proof,
            &input.root_guta_header,
            root_guta_proof,
            root_guta_verifier_data,
            root_guta_reward_tag,
        )?;
        witness.set_target(self.checkpoint_id, input.checkpoint_id)?;
        witness.set_target(
            self.realm_sub_id,
            C::F::from_canonical_u64(input.realm_sub_id as u64),
        )?;
        self.anchor_checkpoint_leaf
            .set_witness(&mut witness, &input.anchor_checkpoint_leaf)?;
        self.anchor_checkpoint_tree_proof.set_witness_core_proof_q_generic(
            &mut witness,
            &input.anchor_checkpoint_tree_proof,
        )?;
        self.checkpoint_tree_proof
            .set_witness_core_proof_q_generic(&mut witness, &input.checkpoint_tree_proof)?;
        self.checkpoint_leaf
            .set_witness(&mut witness, &input.checkpoint_leaf)?;
        self.old_realm_root_proof
            .set_witness_core_proof_q_generic(&mut witness, &input.old_realm_root_proof)?;
        witness.set_target(self.validator_user_id, input.validator_user_id)?;
        self.validator_tree_proof
            .set_witness_core_proof_q_generic(&mut witness, &input.validator_tree_proof)?;
        self.validator_user_leaf
            .set_witness(&mut witness, &input.validator_user_leaf)?;
        self.validator_user_tree_proof.set_witness_core_proof_q_generic(
            &mut witness,
            &input.validator_user_tree_proof,
        )?;
        witness.set_hash_target(
            self.validator_public_key_param,
            input.validator_public_key_param.0,
        )?;
        witness.set_target(self.signature_proof_type, input.signature_proof_type)?;
        witness.set_proof_with_pis_target(&self.signature_proof, signature_proof)?;
        witness.set_verifier_data_target(
            &self.signature_verifier_data,
            signature_verifier_data,
        )?;
        self.validator_fee_delta_proof
            .set_witness_core_proof_q(&mut witness, &input.validator_fee_delta_proof)?;
        self.circuit_data.prove(witness)
    }

    pub fn expected_public_output(
        &self,
        input: &RealmFinalizeGUTAInput<C::F, QHashOut<C::F>>,
        root_guta_reward_tag: QHashOut<C::F>,
    ) -> RealmFinalizeGUTAPublicOutput<C::F, QHashOut<C::F>>
    where
        C::Hasher: FieldQHasher<C::F, QHashOut<C::F>>,
        QHashOut<C::F>: QFHashBase<C::F>,
    {
        let root_guta_header_hash = input.root_guta_header.qfhash::<C::Hasher>();
        let action = RealmFinalizeGUTAAction {
            chain_domain: self.chain_domain,
            checkpoint_id: input.checkpoint_id,
            realm_id: input.root_guta_header.state_transition.node_index,
            checkpoint_tree_root: input.root_guta_header.checkpoint_tree_root,
            validator_tree_root: input.checkpoint_leaf.global_state_roots.validator_tree_root,
            root_guta_header_hash,
        };
        let mut final_guta_header: GlobalUserTreeAggregatorHeader<C::F, QHashOut<C::F>> =
            input.root_guta_header.clone();
        final_guta_header.state_transition.new_node_value =
            input.validator_fee_delta_proof.new_root;
        final_guta_header.total_aggregation_proofs_generated += C::F::ONE;

        RealmFinalizeGUTAPublicOutput {
            chain_domain: self.chain_domain,
            checkpoint_id: input.checkpoint_id,
            realm_id: input.root_guta_header.state_transition.node_index,
            realm_sub_id: input.realm_sub_id,
            checkpoint_tree_root: input.root_guta_header.checkpoint_tree_root,
            validator_tree_root: input.checkpoint_leaf.global_state_roots.validator_tree_root,
            validator_user_id: input.validator_user_id,
            root_guta_header_hash,
            root_guta_reward_tag,
            action_hash: action.action_hash::<C::Hasher>(),
            final_guta_header,
        }
    }

    pub fn expected_public_output_hash(
        &self,
        input: &RealmFinalizeGUTAInput<C::F, QHashOut<C::F>>,
        root_guta_reward_tag: QHashOut<C::F>,
    ) -> QHashOut<C::F>
    where
        C::Hasher: FieldQHasher<C::F, QHashOut<C::F>>,
        QHashOut<C::F>: QFHashBase<C::F>,
    {
        self.expected_public_output(input, root_guta_reward_tag)
            .public_output_hash::<C::Hasher>()
    }
}

impl<C: GenericConfig<D> + 'static, const D: usize> QStandardCircuit<C, D>
    for RealmFinalizeGUTACircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        self.fingerprint
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        &self.circuit_data.verifier_only
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        &self.circuit_data.common
    }
}

impl<L: CircuitInfoLibrary<C, D>, C: QGenericConfig<D> + 'static, const D: usize>
    QStandardCircuitProvableWithRawProofsAndRefLibrary<L, C, D>
    for RealmFinalizeGUTACircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>
        + MerkleZeroHasher<QHashOut<C::F>>
        + FieldQHasher<C::F, QHashOut<C::F>>,
    QHashOut<C::F>: Q256BitHash + QFHashBase<C::F>,
    C::F: QFelt64 + QRichField,
{
    fn prove_with_raw_proofs_and_ref_library(
        &self,
        library: &L,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<
            QHashOut<C::F>,
            QProvingJobDataID,
        >,
        _worker_reward_tag: QHashOut<C::F>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        input.ensure_expected_child_proof_count(2)?;
        if input.base.child_proof_tag_values.is_empty() {
            anyhow::bail!("RealmFinalizeGUTA requires the root GUTA child reward tag at index 0");
        }

        let witness = RealmFinalizeGUTAInput::<C::F, QHashOut<C::F>>::psy_ser_from_slice(
            &input.base.witness,
        )?;
        let root_guta_type = input.get_child_proof_circuit_type(0)?;
        let signature_type = input.get_child_proof_circuit_type(1)?;
        if witness.signature_proof_type.to_u64_value() != SIGNATURE_TYPE_ZK as u64 {
            anyhow::bail!("RealmFinalizeGUTA requires a wrapped ZK signature proof");
        }
        if signature_type != ProvingJobCircuitType::WrappedSignatureProof {
            anyhow::bail!(
                "RealmFinalizeGUTA requires WrappedSignatureProof, got {:?}",
                signature_type
            );
        }

        let root_guta_whitelist_proof = library.get_group_inclusion_proof(
            ProvingJobCircuitType::RealmFinalizeGUTA,
            root_guta_type,
        )?;
        let root_guta_proof = deserialize_plonky2_proof::<C, D>(&input.input_proofs[0])?;
        let signature_proof = deserialize_plonky2_proof::<C, D>(&input.input_proofs[1])?;
        let root_guta_verifier_data = library.get_verifier_data(root_guta_type)?;
        let signature_verifier_data = library.get_verifier_data(signature_type)?;

        self.prove_base(
            &witness,
            &root_guta_whitelist_proof,
            &root_guta_proof,
            &root_guta_verifier_data,
            input.base.child_proof_tag_values[0],
            &signature_proof,
            &signature_verifier_data,
        )
    }
}

#[cfg(test)]
mod tests {
    use parth_common::{
        memory_stores::simple_merkle_tree::SimpleMerkleTree,
        realm_rotation::RealmRotationConfig,
    };
    use parth_core::{
        crypto::hash::traits::{FieldQHasher, QFieldHashable, ToU64x4},
        felt::FromPrimitiveValuesFelt,
        pgoldilocks::QHashOut,
        utils::QPGenRandom,
    };
    use psy_data::v1::qdata::checkpoint::PQEDCheckpointLeaf;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use psy_data::guta::{
        header::GlobalUserTreeAggregatorHeader,
        realm_finalize::{
            realm_validator_leaf_hash, RealmFinalizeGUTAAction,
            RealmFinalizeGUTAPublicOutput,
        },
        stats::GUTAStats,
        sub_tree_transition::SubTreeNodeStateTransition,
    };
    use psy_plonky2_basic_helpers::builder::hash::core::CircuitBuilderHashCore;

    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;
    type Hash = QHashOut<F>;
    type Hasher = PoseidonHash;
    const D: usize = 2;

    fn hash(values: [u64; 4]) -> Hash {
        Hash::from_values(values[0], values[1], values[2], values[3])
    }

    fn prove_hash_target<Targets>(
        build_hash: impl FnOnce(&mut CircuitBuilder<F, D>) -> (HashOutTarget, Targets),
        set_witness: impl FnOnce(&mut PartialWitness<F>, Targets) -> anyhow::Result<()>,
    ) -> Hash {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let (output, targets) = build_hash(&mut builder);
        builder.register_public_inputs(&output.elements);
        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        set_witness(&mut witness, targets).unwrap();
        let proof = data.prove(witness).unwrap();
        data.verify(proof.clone()).unwrap();
        Hash::from_felt_slice(&proof.public_inputs)
    }

    #[test]
    fn realm_finalize_validator_leaf_hash_matches_native() {
        let validator_user_id = 0x0102_0304_0506_0708;
        let expected = realm_validator_leaf_hash::<F, Hash, Hasher>(validator_user_id);

        let actual = prove_hash_target(
            |builder| {
                let target = builder.add_virtual_target();
                (
                    builder.hash_n_to_hash_no_pad::<Hasher>(vec![target]),
                    target,
                )
            },
            |witness, target| {
                witness.set_target(target, F::from_u64_value(validator_user_id))
            },
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn realm_finalize_action_hash_matches_native() {
        let action = RealmFinalizeGUTAAction {
            chain_domain: hash([1, 2, 3, 4]),
            checkpoint_id: F::from_u64_value(17),
            realm_id: F::from_u64_value(5),
            checkpoint_tree_root: hash([11, 12, 13, 14]),
            validator_tree_root: hash([21, 22, 23, 24]),
            root_guta_header_hash: hash([31, 32, 33, 34]),
        };
        let expected = action.qfhash::<Hasher>();

        let actual = prove_hash_target(
            |builder| {
                let chain_domain = builder.add_virtual_hash();
                let checkpoint_id = builder.add_virtual_target();
                let realm_id = builder.add_virtual_target();
                let checkpoint_tree_root = builder.add_virtual_hash();
                let validator_tree_root = builder.add_virtual_hash();
                let root_guta_header_hash = builder.add_virtual_hash();

                let roots_pair = builder.hash_two_to_one::<Hasher>(
                    checkpoint_tree_root,
                    validator_tree_root,
                );
                let roots_hash =
                    builder.hash_two_to_one::<Hasher>(roots_pair, root_guta_header_hash);
                let combined = builder.hash_two_to_one::<Hasher>(chain_domain, roots_hash);
                let output = builder.hash_n_to_hash_no_pad::<Hasher>(vec![
                    combined.elements[0],
                    combined.elements[1],
                    combined.elements[2],
                    combined.elements[3],
                    checkpoint_id,
                    realm_id,
                ]);
                (
                    output,
                    (
                        chain_domain,
                        checkpoint_id,
                        realm_id,
                        checkpoint_tree_root,
                        validator_tree_root,
                        root_guta_header_hash,
                    ),
                )

            },
            |witness,
             (
                chain_domain,
                checkpoint_id,
                realm_id,
                checkpoint_tree_root,
                validator_tree_root,
                root_guta_header_hash,
            )| {
                witness.set_hash_target(chain_domain, action.chain_domain.0)?;
                witness.set_target(checkpoint_id, action.checkpoint_id)?;
                witness.set_target(realm_id, action.realm_id)?;
                witness.set_hash_target(checkpoint_tree_root, action.checkpoint_tree_root.0)?;
                witness.set_hash_target(validator_tree_root, action.validator_tree_root.0)?;
                witness.set_hash_target(root_guta_header_hash, action.root_guta_header_hash.0)

            },
        );

        assert_eq!(actual, expected);
    }
    fn prove_strict_div_rem(
        dividend: u64,
        divisor: u64,
        quotient: Option<u64>,
        remainder: Option<u64>,
    ) -> anyhow::Result<()> {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let dividend_target = builder.add_virtual_target();
        let (quotient_target, remainder_target) =
            super::RealmFinalizeGUTACircuit::<C, D>::strict_div_rem_const(
                &mut builder,
                dividend_target,
                32,
                divisor,
            );
        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        witness.set_target(dividend_target, F::from_u64_value(dividend))?;
        if let Some(quotient) = quotient {
            witness.set_target(quotient_target, F::from_u64_value(quotient))?;
        }
        if let Some(remainder) = remainder {
            witness.set_target(remainder_target, F::from_u64_value(remainder))?;
        }
        data.prove(witness).map(|_| ())
    }

    #[test]
    fn realm_finalize_strict_div_rem_rejects_remainder_equal_divisor() {
        prove_strict_div_rem(17, 10, None, None).unwrap();
        assert!(prove_strict_div_rem(17, 10, Some(0), Some(17)).is_err());
        assert!(prove_strict_div_rem(17, 10, Some(1), Some(10)).is_err());
    }


    fn prove_rotation(
        checkpoint_id: u64,
        realm_id: u32,
        anchor_checkpoint_leaf: &PQEDCheckpointLeaf<F, Hash>,
        realm_sub_id: u16,
        rotation_period_checkpoints: u64,
        validator_sub_ids: &[u16],
    ) -> anyhow::Result<()> {
        const CHECKPOINT_TREE_HEIGHT: usize = 8;
        let mut checkpoint_tree =
            SimpleMerkleTree::<Hasher, Hash>::new(CHECKPOINT_TREE_HEIGHT as u8);
        let epoch = parth_common::realm_rotation::epoch(checkpoint_id, rotation_period_checkpoints);
        let anchor_checkpoint_id = parth_common::realm_rotation::anchor_checkpoint_id(
            epoch,
            rotation_period_checkpoints,
        );
        checkpoint_tree.set_leaf(
            anchor_checkpoint_id,
            anchor_checkpoint_leaf.qfhash::<Hasher>(),
        );
        let anchor_proof = checkpoint_tree.get_leaf(anchor_checkpoint_id);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let checkpoint_id_target = builder.add_virtual_target();
        builder.range_check(checkpoint_id_target, CHECKPOINT_TREE_HEIGHT);
        let realm_id_target = builder.add_virtual_target();
        builder.range_check(realm_id_target, 12);
        let realm_sub_id_target = builder.add_virtual_target();
        builder.range_check(realm_sub_id_target, 8);
        let root_target = builder.constant_hash(anchor_proof.root.0);
        let (anchor_leaf_target, anchor_proof_target) =
            super::RealmFinalizeGUTACircuit::<C, D>::constrain_epoch_fixed_proposer_for_tests(
                &mut builder,
                checkpoint_id_target,
                realm_id_target,
                realm_sub_id_target,
                rotation_period_checkpoints,
                validator_sub_ids,
                CHECKPOINT_TREE_HEIGHT,
                root_target,
            );
        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        witness.set_target(checkpoint_id_target, F::from_u64_value(checkpoint_id))?;
        witness.set_target(realm_id_target, F::from_u64_value(realm_id as u64))?;
        witness.set_target(realm_sub_id_target, F::from_u64_value(realm_sub_id as u64))?;
        anchor_leaf_target.set_witness(&mut witness, anchor_checkpoint_leaf)?;
        anchor_proof_target.set_witness_core_proof_q_generic(&mut witness, &anchor_proof)?;
        let proof = data.prove(witness)?;
        data.verify(proof)
    }

    fn rotation_leaf(seed: [u64; 4]) -> PQEDCheckpointLeaf<F, Hash> {
        let mut leaf = PQEDCheckpointLeaf::qp_rand_gen();
        let reward_root = Hash::from_values(100, 101, 102, 103);
        leaf.stats.pm_rewards_commitment.register_users_root = reward_root;
        leaf.stats.pm_rewards_commitment.gutas_root = reward_root;
        leaf.stats.pm_rewards_commitment.deploy_contracts_root = reward_root;
        leaf.stats.random_seed = Hash::from_values(seed[0], seed[1], seed[2], seed[3]);
        leaf
    }

    #[test]
    fn realm_finalize_rotation_matches_native_poseidon_shuffle() -> anyhow::Result<()> {
        let validator_sub_ids = [1, 2];
        let leaf = rotation_leaf([1, 2, 3, 4]);
        let native = RealmRotationConfig {
            checkpoints_per_epoch: 10,
            validator_sub_ids: validator_sub_ids.to_vec(),
        };
        let seed = leaf.stats.random_seed.to_u64x4();
        for checkpoint_id in [0, 9, 10, 17, 20] {
            let expected = native
                .proposer_sub_id(42, checkpoint_id, seed)?
                .expect("rotation enabled");
            prove_rotation(checkpoint_id, 42, &leaf, expected, 10, &validator_sub_ids)?;
            let wrong = if expected == 1 { 2 } else { 1 };
            assert!(prove_rotation(checkpoint_id, 42, &leaf, wrong, 10, &validator_sub_ids).is_err());
        }
        Ok(())
    }

    #[test]
    fn realm_finalize_rotation_changes_with_anchor_seed() -> anyhow::Result<()> {
        let validator_sub_ids = [1, 2];
        let first = rotation_leaf([1, 2, 3, 4]);
        let second = rotation_leaf([5, 8, 13, 21]);
        let native = RealmRotationConfig {
            checkpoints_per_epoch: 10,
            validator_sub_ids: validator_sub_ids.to_vec(),
        };
        let first_expected = native
            .proposer_sub_id(42, 17, first.stats.random_seed.to_u64x4())?
            .unwrap();
        let second_expected = native
            .proposer_sub_id(42, 17, second.stats.random_seed.to_u64x4())?
            .unwrap();
        prove_rotation(17, 42, &first, first_expected, 10, &validator_sub_ids)?;
        prove_rotation(17, 42, &second, second_expected, 10, &validator_sub_ids)?;
        Ok(())
    }

    fn public_output(realm_sub_id: u16) -> RealmFinalizeGUTAPublicOutput<F, Hash> {
        RealmFinalizeGUTAPublicOutput {
            chain_domain: hash([1, 2, 3, 4]),
            checkpoint_id: F::from_u64_value(17),
            realm_id: F::from_u64_value(5),
            realm_sub_id,
            checkpoint_tree_root: hash([11, 12, 13, 14]),
            validator_tree_root: hash([21, 22, 23, 24]),
            validator_user_id: F::from_u64_value(42),
            root_guta_header_hash: hash([31, 32, 33, 34]),
            root_guta_reward_tag: hash([41, 42, 43, 44]),
            action_hash: hash([51, 52, 53, 54]),
            final_guta_header: GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: hash([61, 62, 63, 64]),
                checkpoint_tree_root: hash([71, 72, 73, 74]),
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: hash([81, 82, 83, 84]),
                    new_node_value: hash([91, 92, 93, 94]),
                    node_index: F::from_u64_value(5),
                    node_level: F::from_u64_value(12),
                },
                stats: GUTAStats::get_zero_value(),
                total_aggregation_proofs_generated: F::from_u64_value(7),
            },
        }
    }

    #[test]
    fn realm_finalize_public_output_hash_binds_realm_sub_id() {
        let first = public_output(11).public_output_hash::<Hasher>();
        let second = public_output(12).public_output_hash::<Hasher>();
        assert_ne!(first, second);
    }

}
