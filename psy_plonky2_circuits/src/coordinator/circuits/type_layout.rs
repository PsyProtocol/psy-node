use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::extension::Extendable,
    field::types::Field,
    gates::{gate::GateRef, noop::NoopGate},
    hash::hash_types::{HashOutTarget, RichField},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{
            CircuitConfig, CircuitData, CommonCircuitData,
            VerifierCircuitTarget, VerifierOnlyCircuitData,
        },
        config::{AlgebraicHasher, GenericConfig},
        proof::{
            ProofWithPublicInputs, ProofWithPublicInputsTarget,
        },
    },
};
use psy_data::v1::qdata::contract::{
    canonical_primitive_slot_width, StateMapKind, StatePrimitiveTypeTag,
    TypeLayoutProofPublicInputs, FIXED_ARRAY_TYPE_LAYOUT_DOMAIN,
    FIXED_MAP_TYPE_LAYOUT_DOMAIN, PRIMITIVE_TYPE_LAYOUT_DOMAIN,
    STATE_LAYOUT_ENCODING_VERSION, STRUCT_MEMBER_LAYOUT_DOMAIN,
    STRUCT_TYPE_LAYOUT_DOMAIN,
};
use psy_plonky2_basic_helpers::builder::{
    connect::CircuitBuilderConnectHelpers,
    core::CircuitBuilderHelpersCore, hash::core::CircuitBuilderHashCore,
    verify::CircuitBuilderVerifyProofHelpers,
};

use crate::gadgets::qdata::state_layout::StateFieldLayoutLeafGadget;
use crate::proof_minifier::pm_core::get_circuit_fingerprint_generic;

#[derive(Debug, Clone)]
pub struct TypeLayoutProofPublicInputsGadget {
    pub type_layout_hash: HashOutTarget,
    pub total_slot_count: Target,
}

#[derive(Debug, Clone)]
pub struct VerifiedTypeLayoutProofGadget<const D: usize> {
    pub proof: ProofWithPublicInputsTarget<D>,
    pub output: TypeLayoutProofPublicInputsGadget,
}

impl<const D: usize> VerifiedTypeLayoutProofGadget<D> {
    pub fn add_virtual_to<C>(
        builder: &mut CircuitBuilder<C::F, D>,
        common_data: &CommonCircuitData<C::F, D>,
        verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Self
    where
        C: GenericConfig<D>,
        C::Hasher: AlgebraicHasher<C::F>,
    {
        assert_eq!(
            common_data.num_public_inputs,
            TypeLayoutProofPublicInputsGadget::PUBLIC_INPUT_COUNT,
        );
        let verifier = builder.constant_verifier_data(verifier_data);
        let proof = builder.add_virtual_proof_with_pis(common_data);
        builder.verify_proof::<C>(&proof, &verifier, common_data);
        let output =
            TypeLayoutProofPublicInputsGadget::from_public_inputs(
                &proof.public_inputs,
            );
        Self { proof, output }
    }

    pub fn connect_field<
        F: RichField + Extendable<D>,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        field: &StateFieldLayoutLeafGadget,
        is_active: plonky2::iop::target::BoolTarget,
    ) {
        builder.connect_hashes_if_true(
            is_active,
            field.type_layout_hash,
            self.output.type_layout_hash,
        );
        let expected_owned_slots =
            builder.add(field.payload_offset, self.output.total_slot_count);
        builder.connect_if_true(
            is_active,
            field.slot_count,
            expected_owned_slots,
        );
    }

    pub fn set_witness<C>(
        &self,
        witness: &mut impl WitnessWrite<C::F>,
        proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<()>
    where
        C: GenericConfig<D>,
        C::Hasher: AlgebraicHasher<C::F>,
    {
        witness.set_proof_with_pis_target(&self.proof, proof)
    }
}

impl TypeLayoutProofPublicInputsGadget {
    pub const PUBLIC_INPUT_COUNT: usize = 5;

    pub fn from_public_inputs(public_inputs: &[Target]) -> Self {
        assert_eq!(
            public_inputs.len(),
            Self::PUBLIC_INPUT_COUNT,
            "type-layout proof public input length mismatch"
        );
        Self {
            type_layout_hash: HashOutTarget {
                elements: public_inputs[..4].try_into().unwrap(),
            },
            total_slot_count: public_inputs[4],
        }
    }

    pub fn register_public_inputs<
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        builder.register_public_inputs(&self.type_layout_hash.elements);
        builder.register_public_input(self.total_slot_count);
    }

    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl WitnessWrite<F>,
        value: TypeLayoutProofPublicInputs<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(
            self.type_layout_hash,
            value.type_layout_hash.0,
        )?;
        witness.set_target(
            self.total_slot_count,
            F::from_canonical_u64(value.total_slot_count),
        )?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct NormalizedTypeLayoutProofCircuit<
    C: GenericConfig<D>,
    const D: usize,
> {
    pub proof_target: ProofWithPublicInputsTarget<D>,
    pub circuit_data: CircuitData<C::F, C, D>,
}

impl<C: GenericConfig<D>, const D: usize>
    NormalizedTypeLayoutProofCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub(crate) fn build(
        inner_common: &CommonCircuitData<C::F, D>,
        inner_verifier: &VerifierOnlyCircuitData<C, D>,
        public_input_count: usize,
        common_gates: &[GateRef<C::F, D>],
        target_degree: Option<usize>,
    ) -> Self {
        assert_eq!(
            inner_common.num_public_inputs,
            public_input_count,
        );
        let mut builder = CircuitBuilder::<C::F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let verifier = builder.constant_verifier_data(inner_verifier);
        let proof_target =
            builder.add_virtual_proof_with_pis(inner_common);
        builder.verify_proof::<C>(
            &proof_target,
            &verifier,
            inner_common,
        );
        builder.register_public_inputs(&proof_target.public_inputs);
        for gate in common_gates {
            builder.add_gate_to_gate_set(gate.clone());
        }
        if let Some(degree) = target_degree {
            // build() adds the public-input hash, PublicInputGate and
            // ConstantGate after this point.
            let reserved_rows =
                inner_common.num_public_inputs.div_ceil(8) + 2;
            let target_rows = degree
                .checked_sub(reserved_rows)
                .expect("normalization degree is too small");
            assert!(
                builder.num_gates() <= target_rows,
                "normalization degree does not fit adapter"
            );
            while builder.num_gates() < target_rows {
                builder.add_gate(NoopGate, vec![]);
            }
        }
        Self {
            proof_target,
            circuit_data: builder.build::<C>(),
        }
    }

    pub fn prove(
        &self,
        inner_proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(
            &self.proof_target,
            inner_proof,
        )?;
        self.circuit_data.prove(witness)
    }
}

/// Canonical recursive endpoint for all protocol-approved type circuits.
///
/// Per-type adapters are padded to identical common data. The final circuit
/// can therefore verify one dynamic proof target and pins its verifier
/// fingerprint to the adapter whitelist.
#[derive(Debug)]
pub struct CanonicalTypeLayoutWrapperCircuit<
    C: GenericConfig<D>,
    const D: usize,
> {
    pub adapters: Vec<NormalizedTypeLayoutProofCircuit<C, D>>,
    pub proof_target: ProofWithPublicInputsTarget<D>,
    pub verifier_target: VerifierCircuitTarget,
    pub output: TypeLayoutProofPublicInputsGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
}

impl<C: GenericConfig<D>, const D: usize>
    CanonicalTypeLayoutWrapperCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        allowed: &[(
            &CommonCircuitData<C::F, D>,
            &VerifierOnlyCircuitData<C, D>,
        )],
    ) -> Self {
        assert!(!allowed.is_empty(), "type circuit whitelist is empty");

        let preliminary = allowed
            .iter()
            .map(|(common, verifier)| {
                NormalizedTypeLayoutProofCircuit::<C, D>::build(
                    common,
                    verifier,
                    TypeLayoutProofPublicInputsGadget::PUBLIC_INPUT_COUNT,
                    &[],
                    None,
                )
            })
            .collect::<Vec<_>>();
        let target_degree = preliminary
            .iter()
            .map(|adapter| adapter.circuit_data.common.degree())
            .max()
            .unwrap();
        let mut common_gates = Vec::<GateRef<C::F, D>>::new();
        for adapter in &preliminary {
            for gate in &adapter.circuit_data.common.gates {
                if !common_gates.iter().any(|known| known == gate) {
                    common_gates.push(gate.clone());
                }
            }
        }
        let adapters = allowed
            .iter()
            .map(|(common, verifier)| {
                NormalizedTypeLayoutProofCircuit::<C, D>::build(
                    common,
                    verifier,
                    TypeLayoutProofPublicInputsGadget::PUBLIC_INPUT_COUNT,
                    &common_gates,
                    Some(target_degree),
                )
            })
            .collect::<Vec<_>>();
        let shared_common = &adapters[0].circuit_data.common;
        assert!(
            adapters
                .iter()
                .all(|adapter| adapter.circuit_data.common == *shared_common),
            "type proof adapters failed to normalize to common data"
        );

        let mut builder = CircuitBuilder::<C::F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let proof_target =
            builder.add_virtual_proof_with_pis(shared_common);
        let cap_height = adapters[0]
            .circuit_data
            .verifier_only
            .constants_sigmas_cap
            .height();
        assert!(adapters.iter().all(|adapter| {
            adapter
                .circuit_data
                .verifier_only
                .constants_sigmas_cap
                .height()
                == cap_height
        }));
        let verifier_target =
            builder.add_virtual_verifier_data(cap_height);
        builder.verify_proof::<C>(
            &proof_target,
            &verifier_target,
            shared_common,
        );

        let actual_fingerprint =
            builder.get_circuit_fingerprint::<C::Hasher>(
                &verifier_target,
            );
        let zero = builder.zero();
        let one = builder.one();
        let mut allowed_fingerprint = zero;
        for adapter in &adapters {
            let expected = builder.constant_hash(
                get_circuit_fingerprint_generic::<D, C::F, C>(
                    &adapter.circuit_data.verifier_only,
                ),
            );
            let mut equal = one;
            for (actual, expected) in actual_fingerprint
                .elements
                .iter()
                .zip(expected.elements)
            {
                let limb_equal =
                    builder.is_equal(*actual, expected);
                equal = builder.mul(equal, limb_equal.target);
            }
            allowed_fingerprint =
                builder.add(allowed_fingerprint, equal);
        }
        builder.connect(allowed_fingerprint, one);

        let output =
            TypeLayoutProofPublicInputsGadget::from_public_inputs(
                &proof_target.public_inputs,
            );
        output.register_public_inputs(&mut builder);
        let circuit_data = builder.build::<C>();
        Self {
            adapters,
            proof_target,
            verifier_target,
            output,
            circuit_data,
        }
    }

    pub fn prove(
        &self,
        adapter_index: usize,
        inner_proof: &ProofWithPublicInputs<C::F, C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let adapter = self.adapters.get(adapter_index).ok_or_else(|| {
            anyhow::anyhow!("type circuit is not in the whitelist")
        })?;
        let normalized = adapter.prove(inner_proof)?;
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(
            &self.proof_target,
            &normalized,
        )?;
        witness.set_verifier_data_target(
            &self.verifier_target,
            &adapter.circuit_data.verifier_only,
        )?;
        self.circuit_data.prove(witness)
    }
}

/// Base case for recursive type-layout verification.
///
/// Primitive widths are selected from the protocol table inside the circuit;
/// a prover cannot reuse a primitive hash with an arbitrary slot width.
#[derive(Debug)]
pub struct PrimitiveTypeLayoutCircuit<
    C: GenericConfig<D>,
    const D: usize,
> {
    pub type_tag: Target,
    pub output: TypeLayoutProofPublicInputsGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
}

impl<C: GenericConfig<D>, const D: usize>
    PrimitiveTypeLayoutCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let mut builder = CircuitBuilder::<C::F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let type_tag = builder.add_virtual_target();
        let zero = builder.zero();
        let one = builder.one();
        let mut valid_tag = zero;
        let mut total_slot_count = zero;
        for tag in [
            StatePrimitiveTypeTag::Felt,
            StatePrimitiveTypeTag::Bool,
            StatePrimitiveTypeTag::U32,
            StatePrimitiveTypeTag::U64,
            StatePrimitiveTypeTag::U128,
            StatePrimitiveTypeTag::Hash,
            StatePrimitiveTypeTag::Bytes32,
        ] {
            let tag_constant =
                builder.constant_u64(tag as u16 as u64);
            let is_tag = builder.is_equal(type_tag, tag_constant);
            valid_tag = builder.add(valid_tag, is_tag.target);
            let width = builder.constant_u64(
                canonical_primitive_slot_width(tag),
            );
            let selected = builder.mul(is_tag.target, width);
            total_slot_count =
                builder.add(total_slot_count, selected);
        }
        builder.connect(valid_tag, one);
        let domain =
            builder.constant_u64(PRIMITIVE_TYPE_LAYOUT_DOMAIN);
        let encoding = builder
            .constant_u64(STATE_LAYOUT_ENCODING_VERSION as u64);
        let type_layout_hash =
            builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                domain, type_tag, encoding,
            ]);
        let output = TypeLayoutProofPublicInputsGadget {
            type_layout_hash,
            total_slot_count,
        };
        output.register_public_inputs(&mut builder);
        let circuit_data = builder.build::<C>();
        Self {
            type_tag,
            output,
            circuit_data,
        }
    }

    pub fn prove(
        &self,
        type_tag: StatePrimitiveTypeTag,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let mut witness = PartialWitness::new();
        witness.set_target(
            self.type_tag,
            C::F::from_canonical_u64(type_tag as u16 as u64),
        )?;
        self.circuit_data.prove(witness)
    }
}

#[derive(Debug)]
pub struct FixedArrayTypeLayoutCircuit<
    C: GenericConfig<D>,
    const D: usize,
> {
    pub child_proof: ProofWithPublicInputsTarget<D>,
    pub array_length: Target,
    pub output: TypeLayoutProofPublicInputsGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
}

impl<C: GenericConfig<D>, const D: usize>
    FixedArrayTypeLayoutCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new(
        child_common_data: &CommonCircuitData<C::F, D>,
        child_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        assert_eq!(
            child_common_data.num_public_inputs,
            TypeLayoutProofPublicInputsGadget::PUBLIC_INPUT_COUNT,
            "type-layout child proof must expose the canonical endpoint"
        );
        let mut builder = CircuitBuilder::<C::F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let verifier_data =
            builder.constant_verifier_data(child_verifier_data);
        let child_proof =
            builder.add_virtual_proof_with_pis(child_common_data);
        builder.verify_proof::<C>(
            &child_proof,
            &verifier_data,
            child_common_data,
        );
        let child = TypeLayoutProofPublicInputsGadget::from_public_inputs(
            &child_proof.public_inputs,
        );
        let array_length = builder.add_virtual_target();
        let zero = builder.zero();
        let length_is_zero = builder.is_equal(array_length, zero);
        builder.connect(length_is_zero.target, zero);
        let child_slots_is_zero =
            builder.is_equal(child.total_slot_count, zero);
        builder.connect(child_slots_is_zero.target, zero);
        let total_slot_count =
            builder.mul(array_length, child.total_slot_count);
        let domain =
            builder.constant_u64(FIXED_ARRAY_TYPE_LAYOUT_DOMAIN);
        let encoding = builder
            .constant_u64(STATE_LAYOUT_ENCODING_VERSION as u64);
        let type_layout_hash =
            builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                domain,
                child.type_layout_hash.elements[0],
                child.type_layout_hash.elements[1],
                child.type_layout_hash.elements[2],
                child.type_layout_hash.elements[3],
                array_length,
                child.total_slot_count,
                total_slot_count,
                encoding,
            ]);
        let output = TypeLayoutProofPublicInputsGadget {
            type_layout_hash,
            total_slot_count,
        };
        output.register_public_inputs(&mut builder);
        let circuit_data = builder.build::<C>();
        Self {
            child_proof,
            array_length,
            output,
            circuit_data,
        }
    }

    pub fn prove(
        &self,
        child_proof: &ProofWithPublicInputs<C::F, C, D>,
        array_length: u64,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        anyhow::ensure!(
            array_length > 0,
            "fixed array length must be non-zero"
        );
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(
            &self.child_proof,
            child_proof,
        )?;
        witness.set_target(
            self.array_length,
            C::F::from_canonical_u64(array_length),
        )?;
        self.circuit_data.prove(witness)
    }
}

#[derive(Debug)]
pub struct FixedMapTypeLayoutCircuit<
    C: GenericConfig<D>,
    const D: usize,
> {
    pub key_proof: ProofWithPublicInputsTarget<D>,
    pub value_proof: ProofWithPublicInputsTarget<D>,
    pub map_kind: Target,
    pub capacity: Target,
    pub alignment_slots: Target,
    pub output: TypeLayoutProofPublicInputsGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
}

impl<C: GenericConfig<D>, const D: usize>
    FixedMapTypeLayoutCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub const MAX_ALIGNMENT_LOG2: usize = 16;

    pub fn new(
        key_common_data: &CommonCircuitData<C::F, D>,
        key_verifier_data: &VerifierOnlyCircuitData<C, D>,
        value_common_data: &CommonCircuitData<C::F, D>,
        value_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> Self {
        assert_eq!(
            key_common_data.num_public_inputs,
            TypeLayoutProofPublicInputsGadget::PUBLIC_INPUT_COUNT,
        );
        assert_eq!(
            value_common_data.num_public_inputs,
            TypeLayoutProofPublicInputsGadget::PUBLIC_INPUT_COUNT,
        );
        let mut builder = CircuitBuilder::<C::F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let key_verifier =
            builder.constant_verifier_data(key_verifier_data);
        let value_verifier =
            builder.constant_verifier_data(value_verifier_data);
        let key_proof =
            builder.add_virtual_proof_with_pis(key_common_data);
        let value_proof =
            builder.add_virtual_proof_with_pis(value_common_data);
        builder.verify_proof::<C>(
            &key_proof,
            &key_verifier,
            key_common_data,
        );
        builder.verify_proof::<C>(
            &value_proof,
            &value_verifier,
            value_common_data,
        );
        let key = TypeLayoutProofPublicInputsGadget::from_public_inputs(
            &key_proof.public_inputs,
        );
        let value =
            TypeLayoutProofPublicInputsGadget::from_public_inputs(
                &value_proof.public_inputs,
            );
        let map_kind = builder.add_virtual_target();
        let capacity = builder.add_virtual_target();
        let alignment_slots = builder.add_virtual_target();
        let zero = builder.zero();
        let one = builder.one();

        let mut valid_map_kind = zero;
        for kind in [
            StateMapKind::ContractHashMap,
            StateMapKind::Map,
            StateMapKind::NamespacedMap,
        ] {
            let kind_target =
                builder.constant_u64(kind as u16 as u64);
            let is_kind = builder.is_equal(map_kind, kind_target);
            valid_map_kind =
                builder.add(valid_map_kind, is_kind.target);
        }
        builder.connect(valid_map_kind, one);

        let mut valid_alignment = zero;
        for log2 in 0..=Self::MAX_ALIGNMENT_LOG2 {
            let alignment = builder.constant_u64(1u64 << log2);
            let is_alignment =
                builder.is_equal(alignment_slots, alignment);
            valid_alignment =
                builder.add(valid_alignment, is_alignment.target);
        }
        builder.connect(valid_alignment, one);
        for required_non_zero in [
            capacity,
            key.total_slot_count,
            value.total_slot_count,
        ] {
            let is_zero = builder.is_equal(required_non_zero, zero);
            builder.connect(is_zero.target, zero);
        }

        // Map keys participate in the lookup encoding but physical inline
        // state storage reserves one value payload per fixed-capacity entry.
        let total_slot_count =
            builder.mul(capacity, value.total_slot_count);
        let domain =
            builder.constant_u64(FIXED_MAP_TYPE_LAYOUT_DOMAIN);
        let encoding = builder
            .constant_u64(STATE_LAYOUT_ENCODING_VERSION as u64);
        let type_layout_hash =
            builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                domain,
                map_kind,
                key.type_layout_hash.elements[0],
                key.type_layout_hash.elements[1],
                key.type_layout_hash.elements[2],
                key.type_layout_hash.elements[3],
                key.total_slot_count,
                value.type_layout_hash.elements[0],
                value.type_layout_hash.elements[1],
                value.type_layout_hash.elements[2],
                value.type_layout_hash.elements[3],
                value.total_slot_count,
                capacity,
                alignment_slots,
                total_slot_count,
                encoding,
            ]);
        let output = TypeLayoutProofPublicInputsGadget {
            type_layout_hash,
            total_slot_count,
        };
        output.register_public_inputs(&mut builder);
        let circuit_data = builder.build::<C>();
        Self {
            key_proof,
            value_proof,
            map_kind,
            capacity,
            alignment_slots,
            output,
            circuit_data,
        }
    }

    pub fn prove(
        &self,
        key_proof: &ProofWithPublicInputs<C::F, C, D>,
        value_proof: &ProofWithPublicInputs<C::F, C, D>,
        map_kind: StateMapKind,
        capacity: u64,
        alignment_slots: u64,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        anyhow::ensure!(capacity > 0, "map capacity must be non-zero");
        anyhow::ensure!(
            alignment_slots > 0
                && alignment_slots.is_power_of_two()
                && alignment_slots
                    <= (1u64 << Self::MAX_ALIGNMENT_LOG2),
            "unsupported map alignment"
        );
        let mut witness = PartialWitness::new();
        witness.set_proof_with_pis_target(&self.key_proof, key_proof)?;
        witness.set_proof_with_pis_target(
            &self.value_proof,
            value_proof,
        )?;
        witness.set_target(
            self.map_kind,
            C::F::from_canonical_u64(map_kind as u16 as u64),
        )?;
        witness.set_target(
            self.capacity,
            C::F::from_canonical_u64(capacity),
        )?;
        witness.set_target(
            self.alignment_slots,
            C::F::from_canonical_u64(alignment_slots),
        )?;
        self.circuit_data.prove(witness)
    }
}

#[derive(Debug)]
pub struct StructTypeLayoutCircuit<
    C: GenericConfig<D>,
    const D: usize,
> {
    pub member_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    pub output: TypeLayoutProofPublicInputsGadget,
    pub circuit_data: CircuitData<C::F, C, D>,
}

impl<C: GenericConfig<D>, const D: usize>
    StructTypeLayoutCircuit<C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    /// Creates a circuit specialized to a struct's ordered member proof
    /// circuits. Heterogeneous members are allowed.
    pub fn new(
        member_circuits: &[(
            &CommonCircuitData<C::F, D>,
            &VerifierOnlyCircuitData<C, D>,
        )],
        members_tree_height: usize,
    ) -> Self {
        assert!(
            !member_circuits.is_empty(),
            "empty structs are not supported"
        );
        let capacity = 1usize
            .checked_shl(members_tree_height as u32)
            .expect("struct members tree height overflow");
        assert!(
            member_circuits.len() <= capacity,
            "struct members exceed members-tree capacity"
        );
        let mut builder = CircuitBuilder::<C::F, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let mut member_proofs =
            Vec::with_capacity(member_circuits.len());
        let mut member_hashes = Vec::with_capacity(capacity);
        let mut next_offset = builder.zero();
        let encoding = builder
            .constant_u64(STATE_LAYOUT_ENCODING_VERSION as u64);
        let member_domain =
            builder.constant_u64(STRUCT_MEMBER_LAYOUT_DOMAIN);

        for (index, (common, verifier_only)) in
            member_circuits.iter().enumerate()
        {
            assert_eq!(
                common.num_public_inputs,
                TypeLayoutProofPublicInputsGadget::PUBLIC_INPUT_COUNT,
            );
            let verifier =
                builder.constant_verifier_data(verifier_only);
            let proof = builder.add_virtual_proof_with_pis(common);
            builder.verify_proof::<C>(&proof, &verifier, common);
            let child =
                TypeLayoutProofPublicInputsGadget::from_public_inputs(
                    &proof.public_inputs,
                );
            let zero = builder.zero();
            let child_is_zero =
                builder.is_equal(child.total_slot_count, zero);
            builder.connect(child_is_zero.target, zero);
            let member_id =
                builder.constant_u64(index as u64 + 1);
            let member_hash =
                builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                    member_domain,
                    member_id,
                    next_offset,
                    child.total_slot_count,
                    child.type_layout_hash.elements[0],
                    child.type_layout_hash.elements[1],
                    child.type_layout_hash.elements[2],
                    child.type_layout_hash.elements[3],
                    encoding,
                ]);
            next_offset =
                builder.add(next_offset, child.total_slot_count);
            member_hashes.push(member_hash);
            member_proofs.push(proof);
        }

        let zero = builder.zero();
        let zero_hash = HashOutTarget {
            elements: [zero; 4],
        };
        member_hashes.resize(capacity, zero_hash);
        let mut level = member_hashes;
        while level.len() > 1 {
            level = level
                .chunks_exact(2)
                .map(|pair| {
                    builder.hash_two_to_one::<C::Hasher>(
                        pair[0], pair[1],
                    )
                })
                .collect();
        }
        let members_root = level[0];
        let struct_domain =
            builder.constant_u64(STRUCT_TYPE_LAYOUT_DOMAIN);
        let member_count =
            builder.constant_u64(member_circuits.len() as u64);
        let type_layout_hash =
            builder.hash_n_to_hash_no_pad::<C::Hasher>(vec![
                struct_domain,
                member_count,
                next_offset,
                members_root.elements[0],
                members_root.elements[1],
                members_root.elements[2],
                members_root.elements[3],
                encoding,
            ]);
        let output = TypeLayoutProofPublicInputsGadget {
            type_layout_hash,
            total_slot_count: next_offset,
        };
        output.register_public_inputs(&mut builder);
        let circuit_data = builder.build::<C>();
        Self {
            member_proofs,
            output,
            circuit_data,
        }
    }

    pub fn prove(
        &self,
        member_proofs: &[ProofWithPublicInputs<C::F, C, D>],
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        anyhow::ensure!(
            member_proofs.len() == self.member_proofs.len(),
            "struct member proof count mismatch"
        );
        let mut witness = PartialWitness::new();
        for (target, proof) in
            self.member_proofs.iter().zip(member_proofs)
        {
            witness.set_proof_with_pis_target(target, proof)?;
        }
        self.circuit_data.prove(witness)
    }
}

#[cfg(test)]
mod tests {
    use parth_core::{
        pgoldilocks::{PoseidonHasher, QHashOut},
        PF,
    };
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use psy_data::v1::qdata::contract::{
        fixed_array_type_layout, fixed_map_type_layout,
        primitive_type_layout, struct_type_layout,
        StateFieldLayoutLeaf, StateTypeLayoutSummary,
    };

    use super::*;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn primitive_type_proof_matches_native_layout() -> anyhow::Result<()> {
        let circuit = PrimitiveTypeLayoutCircuit::<C, D>::new();
        let proof = circuit.prove(StatePrimitiveTypeTag::Hash)?;
        circuit.circuit_data.verify(proof.clone())?;
        let expected: StateTypeLayoutSummary<QHashOut<PF>> =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::Hash,
                4,
            )?;
        assert_eq!(
            proof.public_inputs[..4],
            expected.type_layout_hash.0.elements
        );
        assert_eq!(proof.public_inputs[4], PF::from_canonical_u64(4));
        Ok(())
    }

    #[test]
    fn canonical_wrapper_accepts_whitelisted_type_circuits(
    ) -> anyhow::Result<()> {
        let primitive = PrimitiveTypeLayoutCircuit::<C, D>::new();
        let primitive_proof =
            primitive.prove(StatePrimitiveTypeTag::Hash)?;
        let array = FixedArrayTypeLayoutCircuit::<C, D>::new(
            &primitive.circuit_data.common,
            &primitive.circuit_data.verifier_only,
        );
        let array_proof = array.prove(&primitive_proof, 3)?;
        let map = FixedMapTypeLayoutCircuit::<C, D>::new(
            &primitive.circuit_data.common,
            &primitive.circuit_data.verifier_only,
            &array.circuit_data.common,
            &array.circuit_data.verifier_only,
        );
        let map_proof = map.prove(
            &primitive_proof,
            &array_proof,
            StateMapKind::Map,
            8,
            4,
        )?;
        let structure = StructTypeLayoutCircuit::<C, D>::new(
            &[
                (
                    &primitive.circuit_data.common,
                    &primitive.circuit_data.verifier_only,
                ),
                (
                    &array.circuit_data.common,
                    &array.circuit_data.verifier_only,
                ),
            ],
            1,
        );
        let struct_proof = structure
            .prove(&[primitive_proof.clone(), array_proof.clone()])?;
        let wrapper = CanonicalTypeLayoutWrapperCircuit::<C, D>::new(&[
            (
                &primitive.circuit_data.common,
                &primitive.circuit_data.verifier_only,
            ),
            (
                &array.circuit_data.common,
                &array.circuit_data.verifier_only,
            ),
            (
                &map.circuit_data.common,
                &map.circuit_data.verifier_only,
            ),
            (
                &structure.circuit_data.common,
                &structure.circuit_data.verifier_only,
            ),
        ]);

        let wrapped_primitive = wrapper.prove(0, &primitive_proof)?;
        wrapper
            .circuit_data
            .verify(wrapped_primitive.clone())?;
        assert_eq!(
            wrapped_primitive.public_inputs,
            primitive_proof.public_inputs
        );

        let wrapped_array = wrapper.prove(1, &array_proof)?;
        wrapper.circuit_data.verify(wrapped_array.clone())?;
        assert_eq!(
            wrapped_array.public_inputs,
            array_proof.public_inputs
        );
        let wrapped_map = wrapper.prove(2, &map_proof)?;
        wrapper.circuit_data.verify(wrapped_map.clone())?;
        assert_eq!(wrapped_map.public_inputs, map_proof.public_inputs);

        let wrapped_struct = wrapper.prove(3, &struct_proof)?;
        wrapper.circuit_data.verify(wrapped_struct.clone())?;
        assert_eq!(
            wrapped_struct.public_inputs,
            struct_proof.public_inputs
        );
        assert!(wrapper.prove(4, &array_proof).is_err());

        let mut forged = wrapped_primitive;
        forged.public_inputs[0] += PF::ONE;
        assert!(wrapper.circuit_data.verify(forged).is_err());
        Ok(())
    }

    #[test]
    fn array_and_map_parent_proofs_match_native_layout(
    ) -> anyhow::Result<()> {
        let primitive = PrimitiveTypeLayoutCircuit::<C, D>::new();
        let felt_proof =
            primitive.prove(StatePrimitiveTypeTag::Felt)?;
        let hash_proof =
            primitive.prove(StatePrimitiveTypeTag::Hash)?;

        let array = FixedArrayTypeLayoutCircuit::<C, D>::new(
            &primitive.circuit_data.common,
            &primitive.circuit_data.verifier_only,
        );
        let array_proof = array.prove(&hash_proof, 3)?;
        array.circuit_data.verify(array_proof.clone())?;
        let hash_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::Hash,
                4,
            )?;
        let expected_array =
            fixed_array_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                hash_layout,
                3,
            )?;
        assert_eq!(
            array_proof.public_inputs[..4],
            expected_array.type_layout_hash.0.elements
        );
        assert_eq!(
            array_proof.public_inputs[4],
            PF::from_canonical_u64(12)
        );

        let map = FixedMapTypeLayoutCircuit::<C, D>::new(
            &primitive.circuit_data.common,
            &primitive.circuit_data.verifier_only,
            &array.circuit_data.common,
            &array.circuit_data.verifier_only,
        );
        let map_proof = map.prove(
            &felt_proof,
            &array_proof,
            StateMapKind::Map,
            8,
            4,
        )?;
        map.circuit_data.verify(map_proof.clone())?;
        let felt_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::Felt,
                1,
            )?;
        let expected_map =
            fixed_map_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StateMapKind::Map,
                felt_layout,
                expected_array,
                8,
                4,
            )?;
        assert_eq!(
            map_proof.public_inputs[..4],
            expected_map.type_layout_hash.0.elements
        );
        assert_eq!(
            map_proof.public_inputs[4],
            PF::from_canonical_u64(96)
        );
        Ok(())
    }

    #[test]
    fn struct_proof_builds_authenticated_member_tree(
    ) -> anyhow::Result<()> {
        let primitive = PrimitiveTypeLayoutCircuit::<C, D>::new();
        let felt_proof =
            primitive.prove(StatePrimitiveTypeTag::Felt)?;
        let hash_proof =
            primitive.prove(StatePrimitiveTypeTag::Hash)?;
        let array = FixedArrayTypeLayoutCircuit::<C, D>::new(
            &primitive.circuit_data.common,
            &primitive.circuit_data.verifier_only,
        );
        let array_proof = array.prove(&hash_proof, 2)?;
        let member_circuits = [
            (
                &primitive.circuit_data.common,
                &primitive.circuit_data.verifier_only,
            ),
            (
                &array.circuit_data.common,
                &array.circuit_data.verifier_only,
            ),
        ];
        let struct_circuit =
            StructTypeLayoutCircuit::<C, D>::new(&member_circuits, 2);
        let proof =
            struct_circuit.prove(&[felt_proof, array_proof])?;
        struct_circuit.circuit_data.verify(proof.clone())?;

        let felt_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::Felt,
                1,
            )?;
        let hash_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::Hash,
                4,
            )?;
        let array_layout =
            fixed_array_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                hash_layout,
                2,
            )?;
        let expected =
            struct_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                &[felt_layout, array_layout],
                2,
            )?;
        assert_eq!(
            proof.public_inputs[..4],
            expected.summary.type_layout_hash.0.elements
        );
        assert_eq!(
            proof.public_inputs[4],
            PF::from_canonical_u64(9)
        );
        Ok(())
    }

    #[test]
    fn verified_type_endpoint_binds_field_hash_and_slots(
    ) -> anyhow::Result<()> {
        let primitive = PrimitiveTypeLayoutCircuit::<C, D>::new();
        let type_proof =
            primitive.prove(StatePrimitiveTypeTag::Hash)?;
        let hash_layout =
            primitive_type_layout::<PoseidonHasher, PF, QHashOut<PF>>(
                StatePrimitiveTypeTag::Hash,
                4,
            )?;
        let field = StateFieldLayoutLeaf::new(0, 0, hash_layout)?;

        let mut builder = CircuitBuilder::<PF, D>::new(
            CircuitConfig::standard_recursion_config(),
        );
        let verified =
            VerifiedTypeLayoutProofGadget::add_virtual_to::<C>(
                &mut builder,
                &primitive.circuit_data.common,
                &primitive.circuit_data.verifier_only,
            );
        let field_target =
            StateFieldLayoutLeafGadget::add_virtual_to(&mut builder);
        let active = builder._true();
        verified.connect_field(&mut builder, &field_target, active);
        let data = builder.build::<C>();

        let mut witness = PartialWitness::new();
        verified.set_witness::<C>(&mut witness, &type_proof)?;
        field_target.set_witness(&mut witness, &field)?;
        data.prove(witness)?;

        let mut forged = field;
        forged.slot_count = 5;
        let mut forged_witness = PartialWitness::new();
        verified.set_witness::<C>(&mut forged_witness, &type_proof)?;
        field_target.set_witness(&mut forged_witness, &forged)?;
        assert!(data.prove(forged_witness).is_err());
        Ok(())
    }
}
