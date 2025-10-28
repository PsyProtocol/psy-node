use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_data::v1::qdata::user_end_cap_result::PUPSEndCapResultCompact;
use psy_plonky2_basic_helpers::{builder::{core::CircuitBuilderHelpersCore, hash::core::CircuitBuilderHashCore}};
use psy_plonky2_common_circuits::traits::WitnessValueFor;




#[derive(Clone, Debug)]
pub struct UPSEndCapResultCompactGadget {

    // start require witness
    pub start_user_leaf_hash: HashOutTarget,
    pub end_user_leaf_hash: HashOutTarget,
    pub checkpoint_tree_root_hash: HashOutTarget,
    pub user_id: Target,
    

    // start computed

    
}
impl UPSEndCapResultCompactGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {

        let start_user_leaf_hash = builder.add_virtual_hash();
        let end_user_leaf_hash = builder.add_virtual_hash();
        let checkpoint_tree_root_hash = builder.add_virtual_hash();
        let user_id = builder.add_virtual_target();

        Self {
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_tree_root_hash,
            user_id,
        }
    }
    pub fn new_from_known(
        start_user_leaf_hash: HashOutTarget,
        end_user_leaf_hash: HashOutTarget,
        checkpoint_tree_root_hash: HashOutTarget,
        user_id: Target,
    ) -> Self {

        
        Self {
            start_user_leaf_hash,
            end_user_leaf_hash,
            checkpoint_tree_root_hash,
            user_id,
        }
    }
    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        target: &PUPSEndCapResultCompact<F, QHashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(
            self.start_user_leaf_hash,
            target.start_user_leaf_hash.0,
        )?;
        witness.set_hash_target(
            self.end_user_leaf_hash,
            target.end_user_leaf_hash.0,
        )?;
        witness.set_hash_target(
            self.checkpoint_tree_root_hash,
            target.checkpoint_tree_root_hash.0,
        )?;
        witness.set_target(
            self.user_id,
            target.user_id,
        )
    }

    pub fn to_hash<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, global_user_tree_height: u8) -> HashOutTarget {
        let user_level = builder.constant_u8(global_user_tree_height);
        let user_leaf_change_combo_with_user_id = builder.hash_n_to_hash_no_pad::<H>(vec![
            self.user_id,

            self.start_user_leaf_hash.elements[0],
            self.start_user_leaf_hash.elements[1],
            self.start_user_leaf_hash.elements[2],
            self.start_user_leaf_hash.elements[3],

            self.end_user_leaf_hash.elements[0],
            self.end_user_leaf_hash.elements[1],
            self.end_user_leaf_hash.elements[2],
            self.end_user_leaf_hash.elements[3],

            user_level,
        ]);

        let end_cap_result_hash = builder.hash_two_to_one::<H>(
            self.checkpoint_tree_root_hash,
            user_leaf_change_combo_with_user_id,
        );

        end_cap_result_hash
    }
}
impl<F: RichField> WitnessValueFor<UPSEndCapResultCompactGadget, F, true> for PUPSEndCapResultCompact<F, QHashOut<F>> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UPSEndCapResultCompactGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<UPSEndCapResultCompactGadget, F, false> for PUPSEndCapResultCompact<F, QHashOut<F>> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &UPSEndCapResultCompactGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
