use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::dpn::proving_session::{DPNProvingSessionCompactMethodCall, DPNProvingSessionSimpleMethodCall};
use psy_common_circuit::{
    builder::{core::CircuitBuilderHelpersCore, hash::core::CircuitBuilderHashCore},
    traits::{AlgebraicHashableTarget, CreatableTarget, FromTargets, ToTargets, WitnessValueFor},
};
use psy_config::network_constants::DEFERRED_CALL_MAGIC;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DPNProvingSessionCompactMethodCallGadget {
    pub caller_contract_id: Target,
    pub contract_id: Target,
    pub method_id: Target,
    pub inputs_length: Target,
    pub inputs_hash: HashOutTarget,
}

impl DPNProvingSessionCompactMethodCallGadget {
    pub fn new_from_inputs<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        caller_contract_id: Target,
        contract_id: Target,
        method_id: Target,
        inputs: &[Target],
    ) -> Self {
        let inputs_length = builder.constant_u64(inputs.len() as u64);
        let inputs_hash = builder.safe_hash_fixed_length::<H>(inputs);
        Self {
            caller_contract_id,
            contract_id,
            method_id,
            inputs_length,
            inputs_hash,
        }
    }
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let caller_contract_id = builder.add_virtual_target();
        let contract_id = builder.add_virtual_target();
        let method_id = builder.add_virtual_target();
        let inputs_length = builder.add_virtual_target();
        let inputs_hash = builder.add_virtual_hash();

        Self {
            caller_contract_id,
            contract_id,
            method_id,
            inputs_length,
            inputs_hash,
        }
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &DPNProvingSessionCompactMethodCall<F>) -> anyhow::Result<()> {
        witness.set_target(self.caller_contract_id, target.caller_contract_id)?;
        witness.set_target(self.contract_id, target.contract_id)?;
        witness.set_target(self.method_id, target.method_id)?;
        witness.set_target(self.inputs_length, target.inputs_length)?;
        witness.set_hash_target(self.inputs_hash, target.inputs_hash.0)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        let magic_felt = builder.constant_u64(DEFERRED_CALL_MAGIC);

        let final_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            magic_felt,
            self.caller_contract_id,
            self.contract_id,
            self.method_id,
            self.inputs_length,
            self.inputs_hash.elements[0],
            self.inputs_hash.elements[1],
            self.inputs_hash.elements[2],
            self.inputs_hash.elements[3],
        ]);
        final_hash
    }
}
impl CreatableTarget for DPNProvingSessionCompactMethodCallGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to(builder)
    }
}
impl AlgebraicHashableTarget for DPNProvingSessionCompactMethodCallGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl ToTargets for DPNProvingSessionCompactMethodCallGadget {
    fn to_targets(&self) -> Vec<Target> {
        vec![
            self.caller_contract_id,
            self.contract_id,
            self.method_id,
            self.inputs_length,
            self.inputs_hash.elements[0],
            self.inputs_hash.elements[1],
            self.inputs_hash.elements[2],
            self.inputs_hash.elements[3],
        ]
    }
}
impl FromTargets for DPNProvingSessionCompactMethodCallGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != 8 {
            panic!(
                "Invalid number of elements for DPNProvingSessionCompactMethodCallGadget, expected 8, got {}",
                targets.len()
            );
        }
        Self {
            caller_contract_id: targets[0],
            contract_id: targets[1],
            method_id: targets[2],
            inputs_length: targets[3],
            inputs_hash: HashOutTarget {
                elements: [targets[4], targets[5], targets[6], targets[7]],
            },
        }
    }
}

impl<F: RichField> WitnessValueFor<DPNProvingSessionCompactMethodCallGadget, F, true> for DPNProvingSessionCompactMethodCall<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &DPNProvingSessionCompactMethodCallGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<DPNProvingSessionCompactMethodCallGadget, F, false> for DPNProvingSessionCompactMethodCall<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &DPNProvingSessionCompactMethodCallGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DPNProvingSessionSimpleMethodCallGadget {
    pub caller_contract_id: Target,
    pub contract_id: Target,
    pub method_id: Target,
    pub inputs: Vec<Target>,
}

impl DPNProvingSessionSimpleMethodCallGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, input_count: usize) -> Self {
        let caller_contract_id = builder.add_virtual_target();
        let contract_id = builder.add_virtual_target();
        let method_id = builder.add_virtual_target();
        let inputs = (0..input_count).map(|_| builder.add_virtual_target()).collect::<Vec<Target>>();

        Self {
            caller_contract_id,
            contract_id,
            method_id,
            inputs,
        }
    }
    fn to_compact<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> DPNProvingSessionCompactMethodCallGadget {
        DPNProvingSessionCompactMethodCallGadget::new_from_inputs::<H, F, D>(
            builder,
            self.caller_contract_id,
            self.contract_id,
            self.method_id,
            &self.inputs,
        )
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &DPNProvingSessionSimpleMethodCall<F>) -> anyhow::Result<()> {
        witness.set_target(self.caller_contract_id, target.caller_contract_id)?;
        witness.set_target(self.contract_id, target.contract_id)?;
        witness.set_target(self.method_id, target.method_id)?;
        witness.set_target_arr(&self.inputs, &target.inputs)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        self.to_compact::<H, F, D>(builder).to_hash::<H, F, D>(builder)

        /*
        let inputs_length = self.inputs.len();
        let inputs_length_target = builder.constant_u64(inputs_length as u64);

        let mut inputs_hash_preimage = Vec::with_capacity(inputs_length + 2);

        inputs_hash_preimage.push(inputs_length_target);
        inputs_hash_preimage.extend_from_slice(&self.inputs);
        inputs_hash_preimage.push(inputs_length_target);
        let inputs_hash = builder.hash_n_to_hash_no_pad::<H>(inputs_hash_preimage);

        let magic_felt = builder.constant_u64(DEFERRED_CALL_MAGIC);

        let final_hash = builder.hash_n_to_hash_no_pad::<H>(vec![
            magic_felt,
            self.contract_id,
            self.method_id,
            inputs_length_target,
            inputs_hash.elements[0],
            inputs_hash.elements[1],
            inputs_hash.elements[2],
            inputs_hash.elements[3],
        ]);
        final_hash
        */
    }
}
impl AlgebraicHashableTarget for DPNProvingSessionSimpleMethodCallGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl ToTargets for DPNProvingSessionSimpleMethodCallGadget {
    fn to_targets(&self) -> Vec<Target> {
        let mut targets = Vec::with_capacity(3 + self.inputs.len());
        targets.push(self.caller_contract_id);
        targets.push(self.contract_id);
        targets.push(self.method_id);
        targets.extend_from_slice(&self.inputs);
        targets
    }
}
impl FromTargets for DPNProvingSessionSimpleMethodCallGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() < 3 {
            panic!("Invalid number of elements for DPNProvingSessionSimpleMethodCall");
        }
        Self {
            caller_contract_id: targets[0],
            contract_id: targets[1],
            method_id: targets[2],
            inputs: targets[3..].to_vec(),
        }
    }
}

impl<F: RichField> WitnessValueFor<DPNProvingSessionSimpleMethodCallGadget, F, true> for DPNProvingSessionSimpleMethodCall<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &DPNProvingSessionSimpleMethodCallGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<DPNProvingSessionSimpleMethodCallGadget, F, false> for DPNProvingSessionSimpleMethodCall<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &DPNProvingSessionSimpleMethodCallGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
