use std::marker::PhantomData;

use plonky2::{field::extension::Extendable, hash::hash_types::RichField, iop::target::BoolTarget, plonk::circuit_builder::CircuitBuilder};

#[derive(Clone, Debug)]
pub struct U64Target<F, const D: usize> {
    pub bits: Vec<BoolTarget>,
    _phantom: PhantomData<F>,
}

impl<F, const D: usize> U64Target<F, D>
where
    F: RichField + Extendable<D>,
{
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        let mut result = vec![];
        for _ in 0..64 {
            result.push(builder.add_virtual_bool_target_safe());
        }
        Self {
            bits: result,
            _phantom: PhantomData,
        }
    }

    pub fn from(bits: Vec<BoolTarget>) -> Self {
        assert_eq!(bits.len(), 64);
        Self { bits, _phantom: PhantomData }
    }

    pub fn connect(&self, other: &Self, builder: &mut CircuitBuilder<F, D>) {
        for i in 0..64 {
            builder.connect(self.bits[i].target, other.bits[i].target);
        }
    }

    pub fn xor(&self, other: &Self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let mut result = vec![];
        for i in 0..64 {
            let xor_target = xor_circuit(self.bits[i], other.bits[i], builder);
            result.push(xor_target);
        }
        Self {
            bits: result,
            _phantom: PhantomData,
        }
    }

    pub fn xor_const(&self, other: u64, builder: &mut CircuitBuilder<F, D>) -> Self {
        let other_bits = u64_to_bits(other);
        let mut result = vec![];
        for i in 0..64 {
            let xor_target = xor_const_circuit(self.bits[i], other_bits[i], builder);
            result.push(xor_target);
        }
        Self {
            bits: result,
            _phantom: PhantomData,
        }
    }

    pub fn rotl(&self, n: usize) -> Self {
        let rotate = rotate_u64(n);
        let mut output = vec![];
        for i in 0..64 {
            output.push(self.bits[rotate[i]]);
        }

        Self {
            bits: output,
            _phantom: PhantomData,
        }
    }

    pub fn and_not(&self, other: &Self, builder: &mut CircuitBuilder<F, D>) -> Self {
        let mut result = vec![];
        for i in 0..64 {
            result.push(BoolTarget::new_unsafe(builder.arithmetic(
                F::NEG_ONE,
                F::ONE,
                self.bits[i].target,
                other.bits[i].target,
                self.bits[i].target,
            )));
        }
        Self {
            bits: result,
            _phantom: PhantomData,
        }
    }
}

pub fn xor_circuit<F, const D: usize>(a: BoolTarget, b: BoolTarget, builder: &mut CircuitBuilder<F, D>) -> BoolTarget
where
    F: RichField + Extendable<D>,
{
    let b_minus_2ab = builder.arithmetic(-F::TWO, F::ONE, a.target, b.target, b.target);
    let a_plus_b_minus_2ab = builder.add(a.target, b_minus_2ab);
    BoolTarget::new_unsafe(a_plus_b_minus_2ab)
}

pub fn xor_const_circuit<F, const D: usize>(a: BoolTarget, b: bool, builder: &mut CircuitBuilder<F, D>) -> BoolTarget
where
    F: RichField + Extendable<D>,
{
    if b {
        builder.not(a)
    } else {
        a
    }
}

fn rotate_u64(y: usize) -> Vec<usize> {
    let mut res = Vec::new();
    for i in 64 - y..64 {
        res.push(i);
    }
    for i in 0..64 - y {
        res.push(i);
    }
    res
}

fn u64_to_bits(num: u64) -> Vec<bool> {
    let mut result = Vec::with_capacity(64);
    let mut n = num;
    for _ in 0..64 {
        result.push(n & 1 == 1);
        n >>= 1;
    }
    result
}
