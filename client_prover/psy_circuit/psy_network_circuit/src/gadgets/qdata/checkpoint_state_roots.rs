use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::qdata::checkpoint::PsyCheckpointGlobalStateRoots;
use psy_common_circuit::{
    builder::hash::core::CircuitBuilderHashCore,
    traits::{AlgebraicHashableTarget, CreatableTarget, FromTargets, ToTargets, WitnessValueFor},
};

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct PsyCheckpointGlobalStateRootsGadget {
    pub contract_tree_root: HashOutTarget,
    pub deposit_tree_root: HashOutTarget,
    pub user_tree_root: HashOutTarget,
    pub withdrawal_tree_root: HashOutTarget,
    pub user_registration_tree_root: HashOutTarget,
    pub validator_tree_root: HashOutTarget,
}

impl PsyCheckpointGlobalStateRootsGadget {
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointGlobalStateRoots<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.contract_tree_root, target.contract_tree_root.0)?;
        witness.set_hash_target(self.deposit_tree_root, target.deposit_tree_root.0)?;
        witness.set_hash_target(self.user_tree_root, target.user_tree_root.0)?;
        witness.set_hash_target(self.withdrawal_tree_root, target.withdrawal_tree_root.0)?;
        witness.set_hash_target(self.user_registration_tree_root, target.user_registration_tree_root.0)?;
        witness.set_hash_target(self.validator_tree_root, target.validator_tree_root.0)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        let contract_and_deposit = builder.hash_two_to_one::<H>(self.contract_tree_root, self.deposit_tree_root);
        let user_and_withdrawal = builder.hash_two_to_one::<H>(self.user_tree_root, self.withdrawal_tree_root);
        let base_combo = builder.hash_two_to_one::<H>(contract_and_deposit, user_and_withdrawal);
        let reg_and_validator = builder.hash_two_to_one::<H>(self.user_registration_tree_root, self.validator_tree_root);
        builder.hash_two_to_one::<H>(base_combo, reg_and_validator)
    }
}
impl AlgebraicHashableTarget for PsyCheckpointGlobalStateRootsGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl CreatableTarget for PsyCheckpointGlobalStateRootsGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let contract_tree_root = builder.add_virtual_hash();
        let deposit_tree_root = builder.add_virtual_hash();
        let user_tree_root = builder.add_virtual_hash();
        let withdrawal_tree_root = builder.add_virtual_hash();
        let user_registration_tree_root = builder.add_virtual_hash();
        let validator_tree_root = builder.add_virtual_hash();

        Self {
            contract_tree_root,
            deposit_tree_root,
            user_tree_root,
            withdrawal_tree_root,
            user_registration_tree_root,
            validator_tree_root,
        }
    }
}
impl ToTargets for PsyCheckpointGlobalStateRootsGadget {
    fn to_targets(&self) -> Vec<Target> {
        vec![
            self.contract_tree_root.elements[0],
            self.contract_tree_root.elements[1],
            self.contract_tree_root.elements[2],
            self.contract_tree_root.elements[3],
            self.deposit_tree_root.elements[0],
            self.deposit_tree_root.elements[1],
            self.deposit_tree_root.elements[2],
            self.deposit_tree_root.elements[3],
            self.user_tree_root.elements[0],
            self.user_tree_root.elements[1],
            self.user_tree_root.elements[2],
            self.user_tree_root.elements[3],
            self.withdrawal_tree_root.elements[0],
            self.withdrawal_tree_root.elements[1],
            self.withdrawal_tree_root.elements[2],
            self.withdrawal_tree_root.elements[3],
            self.user_registration_tree_root.elements[0],
            self.user_registration_tree_root.elements[1],
            self.user_registration_tree_root.elements[2],
            self.user_registration_tree_root.elements[3],
            self.validator_tree_root.elements[0],
            self.validator_tree_root.elements[1],
            self.validator_tree_root.elements[2],
            self.validator_tree_root.elements[3],
        ]
    }
}
impl FromTargets for PsyCheckpointGlobalStateRootsGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != 24 {
            panic!(
                "tried to create PsyCheckpointGlobalStateRootsGadget from an array of {} targets, but expected an array of 24 targets",
                targets.len()
            );
        }
        let contract_tree_root = HashOutTarget {
            elements: [targets[0], targets[1], targets[2], targets[3]],
        };
        let deposit_tree_root = HashOutTarget {
            elements: [targets[4], targets[5], targets[6], targets[7]],
        };
        let user_tree_root = HashOutTarget {
            elements: [targets[8], targets[9], targets[10], targets[11]],
        };
        let withdrawal_tree_root = HashOutTarget {
            elements: [targets[12], targets[13], targets[14], targets[15]],
        };
        let user_registration_tree_root = HashOutTarget {
            elements: [targets[16], targets[17], targets[18], targets[19]],
        };
        let validator_tree_root = HashOutTarget {
            elements: [targets[20], targets[21], targets[22], targets[23]],
        };
        Self {
            contract_tree_root,
            deposit_tree_root,
            user_tree_root,
            withdrawal_tree_root,
            user_registration_tree_root,
            validator_tree_root,
        }
    }
}

impl<F: RichField> WitnessValueFor<PsyCheckpointGlobalStateRootsGadget, F, true> for PsyCheckpointGlobalStateRoots<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointGlobalStateRootsGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<PsyCheckpointGlobalStateRootsGadget, F, false> for PsyCheckpointGlobalStateRoots<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointGlobalStateRootsGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
