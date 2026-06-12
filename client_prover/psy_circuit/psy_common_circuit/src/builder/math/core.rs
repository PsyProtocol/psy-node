use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

pub trait CircuitBuilderCoreMathHelpers<F: RichField + Extendable<D>, const D: usize> {
    // returns (floor(x/4), x%4)
    fn div_rem4(&mut self, x: Target) -> (Target, Target);
    fn div_rem(&mut self, x: Target, n: usize) -> (Target, Target);
    fn xor_bit(&mut self, x: BoolTarget, y: BoolTarget) -> BoolTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderCoreMathHelpers<F, D> for CircuitBuilder<F, D> {
    // returns ( floor(x/4), (x % 4) )
    fn div_rem4(&mut self, x: Target) -> (Target, Target) {
        self.div_rem(x, 2)
    }

    fn div_rem(&mut self, x: Target, n: usize) -> (Target, Target) {
        // TODO/UNSURE: can we skip the 63 bit range check and just use
        // self.split_low_high(x, n, 64)?
        self.range_check(x, 63);

        // TODO/UNSURE: can we make this num_bits = 64?:
        let (rem, div) = self.split_low_high(x, n, 63);
        (div, rem)
    }

    fn xor_bit(&mut self, x: BoolTarget, y: BoolTarget) -> BoolTarget {
        let x_plus_y = self.add(x.target, y.target);
        let x_times_y = self.mul(x.target, y.target);
        let x_times_y_2 = self.add(x_times_y, x_times_y);
        BoolTarget::new_unsafe(self.sub(x_plus_y, x_times_y_2))
    }
}
