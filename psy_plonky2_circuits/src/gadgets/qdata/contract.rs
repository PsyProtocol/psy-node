use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_data::v1::qdata::contract::PQEDContractLeaf;
use psy_plonky2_basic_helpers::{builder::core::CircuitBuilderHelpersCore};
use psy_plonky2_common_circuits::traits::{AlgebraicHashableTarget, FromTargets, ToTargets, WitnessValueFor};

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct QEDContractLeafGadget {
    pub deployer: HashOutTarget,
    pub function_tree_root: HashOutTarget,
    pub state_tree_height: Target,
}

impl QEDContractLeafGadget {
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PQEDContractLeaf<F, QHashOut<F>>) -> anyhow::Result<()> {
        witness.set_hash_target(self.deployer, target.deployer.0)?;
        witness.set_hash_target(self.function_tree_root, target.function_tree_root.0)?;
        witness.set_target(self.state_tree_height, target.state_tree_height)
    }
    pub fn to_hash<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<H>(self.to_targets())
    }
}
impl AlgebraicHashableTarget for QEDContractLeafGadget {
    fn to_hash_target<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl QEDContractLeafGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        max_contract_state_tree_height: usize,
    ) -> Self {
        let deployer = builder.add_virtual_hash();
        let function_tree_root = builder.add_virtual_hash();
        let state_tree_height = builder.add_virtual_target();
        let mut base = state_tree_height;
        let zero = builder.zero();

        // state tree height must be in 1..=MAX_CONTRACT_STATE_TREE_HEIGHT
        // so we multiply (state_tree_height-1)*(state_tree_height-2*...(state_tree_height-MAX_CONTRACT_STATE_TREE_HEIGHT) and ensure the product is 0
        for i in 1..=max_contract_state_tree_height {
            let acceptable_height = builder.constant_u64(i as u64);
            let value = builder.sub(state_tree_height, acceptable_height);
            base = builder.mul(base, value);
        }
        builder.connect(base, zero);


        
        
        Self {
            deployer,
            function_tree_root,
            state_tree_height,
        }

    }
}
impl ToTargets for QEDContractLeafGadget {
    fn to_targets(&self) -> Vec<Target> {
        vec![
            self.deployer.elements[0],
            self.deployer.elements[1],
            self.deployer.elements[2],
            self.deployer.elements[3],
            self.function_tree_root.elements[0],
            self.function_tree_root.elements[1],
            self.function_tree_root.elements[2],
            self.function_tree_root.elements[3],
            self.state_tree_height,
        ]
    }
}
impl FromTargets for QEDContractLeafGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != 9 {
            panic!("tried to create QEDContractLeafGadget from an array of {} targets, but expected an array of 9 targets", targets.len());
        }
        let deployer = HashOutTarget {
            elements: [
                targets[0],
                targets[1],
                targets[2],
                targets[3],
            ]
        };
        let function_tree_root = HashOutTarget {
            elements: [
                targets[4],
                targets[5],
                targets[6],
                targets[7],
            ]
        };
        let state_tree_height = targets[8];
        Self {
            deployer,
            function_tree_root,
            state_tree_height,
        }
    }
}


impl<F: RichField> WitnessValueFor<QEDContractLeafGadget, F, true> for PQEDContractLeaf<F, QHashOut<F>> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &QEDContractLeafGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<QEDContractLeafGadget, F, false> for PQEDContractLeaf<F, QHashOut<F>> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &QEDContractLeafGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
