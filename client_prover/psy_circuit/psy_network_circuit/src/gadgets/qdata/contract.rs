use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::qdata::contract::PsyContractLeaf;
use psy_common_circuit::{
    builder::core::CircuitBuilderHelpersCore,
    traits::{AlgebraicHashableTarget, CreatableTarget, FromTargets, ToTargets, WitnessValueFor},
};
use psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT;

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct PsyContractLeafGadget {
    pub deployer: HashOutTarget,
    pub function_tree_root: HashOutTarget,
    pub code_root: HashOutTarget,
    pub state_tree_height: Target,
    pub state_layout_root: HashOutTarget,
    pub state_layout_field_count: Target,
    pub state_layout_slot_count: Target,
}

impl PsyContractLeafGadget {
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PsyContractLeaf<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.deployer, target.deployer.0)?;
        witness.set_hash_target(self.function_tree_root, target.function_tree_root.0)?;
        witness.set_hash_target(self.code_root, target.code_root.0)?;
        witness.set_target(self.state_tree_height, target.state_tree_height)?;
        witness.set_hash_target(self.state_layout_root, target.state_layout_root.0)?;
        witness.set_target(self.state_layout_field_count, target.state_layout_field_count)?;
        witness.set_target(self.state_layout_slot_count, target.state_layout_slot_count)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        let mut inputs = vec![builder.constant_u64(0x434c_5632)];
        inputs.extend(self.to_targets());
        builder.hash_n_to_hash_no_pad::<H>(inputs)
    }
}
impl AlgebraicHashableTarget for PsyContractLeafGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl CreatableTarget for PsyContractLeafGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let deployer = builder.add_virtual_hash();
        let function_tree_root = builder.add_virtual_hash();
        let code_root = builder.add_virtual_hash();
        let state_tree_height = builder.add_virtual_target();
        let state_layout_root = builder.add_virtual_hash();
        let state_layout_field_count = builder.add_virtual_target();
        let state_layout_slot_count = builder.add_virtual_target();
        let mut base = state_tree_height;
        let zero = builder.zero();

        // state tree height must be in 1..=MAX_CONTRACT_STATE_TREE_HEIGHT
        // so we multiply
        // (state_tree_height-1)*(state_tree_height-2*...
        // (state_tree_height-MAX_CONTRACT_STATE_TREE_HEIGHT) and ensure the product is
        // 0
        for i in 1..=MAX_CONTRACT_STATE_TREE_HEIGHT {
            let acceptable_height = builder.constant_u64(i as u64);
            let value = builder.sub(state_tree_height, acceptable_height);
            base = builder.mul(base, value);
        }
        builder.connect(base, zero);

        Self {
            deployer,
            function_tree_root,
            code_root,
            state_tree_height,
            state_layout_root,
            state_layout_field_count,
            state_layout_slot_count,
        }
    }
}
impl ToTargets for PsyContractLeafGadget {
    fn to_targets(&self) -> Vec<Target> {
        let mut targets = vec![
            self.deployer.elements[0],
            self.deployer.elements[1],
            self.deployer.elements[2],
            self.deployer.elements[3],
            self.function_tree_root.elements[0],
            self.function_tree_root.elements[1],
            self.function_tree_root.elements[2],
            self.function_tree_root.elements[3],
            self.code_root.elements[0],
            self.code_root.elements[1],
            self.code_root.elements[2],
            self.code_root.elements[3],
            self.state_tree_height,
        ];
        targets.extend(self.state_layout_root.elements);
        targets.push(self.state_layout_field_count);
        targets.push(self.state_layout_slot_count);
        targets
    }
}
impl FromTargets for PsyContractLeafGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != 19 {
            panic!(
                "tried to create PsyContractLeafGadget from an array of {} targets, but expected an array of 19 targets",
                targets.len()
            );
        }
        let deployer = HashOutTarget {
            elements: [targets[0], targets[1], targets[2], targets[3]],
        };
        let function_tree_root = HashOutTarget {
            elements: [targets[4], targets[5], targets[6], targets[7]],
        };
        let code_root = HashOutTarget {
            elements: [targets[8], targets[9], targets[10], targets[11]],
        };
        let state_tree_height = targets[12];
        let state_layout_root = HashOutTarget {
            elements: [targets[13], targets[14], targets[15], targets[16]],
        };
        let state_layout_field_count = targets[17];
        let state_layout_slot_count = targets[18];
        Self {
            deployer,
            function_tree_root,
            code_root,
            state_tree_height,
            state_layout_root,
            state_layout_field_count,
            state_layout_slot_count,
        }
    }
}

impl<F: RichField> WitnessValueFor<PsyContractLeafGadget, F, true> for PsyContractLeaf<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyContractLeafGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<PsyContractLeafGadget, F, false> for PsyContractLeaf<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyContractLeafGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
