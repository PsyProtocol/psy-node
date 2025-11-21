use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::
        target::{BoolTarget, Target}
    ,
    plonk::circuit_builder::CircuitBuilder,
};


pub struct BitsHelper {
    pub index_bits: Vec<BoolTarget>,
    pub low_bits_mask: Vec<BoolTarget>,
    pub high_bits_mask: Vec<BoolTarget>,
}


#[derive(Debug, Clone)]
pub struct QVariableHeightBitInfo {
    pub index_bits: Vec<bool>,
    pub is_bit_not_within_height: Vec<bool>,
    pub is_first_bit_outside_height: Vec<bool>,

}

impl QVariableHeightBitInfo {
    pub fn is_right_child(
        &self,
    ) -> bool {
        let mut base = 0u32;

        for (a,b) in  self.index_bits.iter().zip(self.is_first_bit_outside_height.iter()) {
            let combo = (a&b) as u32;
            base = combo + base;
        }
        base >= 1

    }
    pub fn get_root_parent_index(
        &self,
    ) -> u32 {
        let mut sub_root_bit = 0u32;
        let mut sub_root_index = 0u32;
        let one = 1u32;
        for i in 0..self.index_bits.len() {
            let is_change = self.is_first_bit_outside_height[i];
            sub_root_bit = if is_change { one } else { sub_root_bit };

            let add_indicator = (self.index_bits[i] as u32) * sub_root_bit;
            sub_root_index = add_indicator + sub_root_index;


            sub_root_bit = sub_root_bit + sub_root_bit;

        }

        sub_root_index
    }

    pub fn from_index_and_height(index: u64, height: usize, max_height: usize) -> Self {
        let index_bits = (0..max_height)
            .map(|i| (index >> i) & 1 == 1)
            .collect::<Vec<_>>();

        let is_bit_not_within_height = (0..max_height)
            .map(|i| i >= height)
            .collect::<Vec<_>>();

        let mut is_first_bit_outside_height = vec![false; max_height];
        if let Some(first_outside) = (0..max_height).find(|&i| i >= height) {
            is_first_bit_outside_height[first_outside] = true;
        }

        Self {
            index_bits,
            is_bit_not_within_height,
            is_first_bit_outside_height,
        }
    }

}

#[derive(Debug, Clone)]
pub struct VariableHeightBitInfo {
    pub index_bits: Vec<BoolTarget>,
    pub is_bit_not_within_height: Vec<BoolTarget>,
    pub is_first_bit_outside_height: Vec<BoolTarget>,

}

impl VariableHeightBitInfo {
    pub fn is_right_child<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> BoolTarget {
        let mut base = builder.zero();

        for (a,b) in  self.index_bits.iter().zip(self.is_first_bit_outside_height.iter()) {
            let combo = builder.and(*a, *b);
            base = builder.add(combo.target, base);
        }
        BoolTarget::new_unsafe(base)

    }
    pub fn get_root_parent_index<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {

        let mut sub_root_bit = builder.zero();
        let mut sub_root_index = builder.zero();
        let one = builder.one();
        for i in 0..self.index_bits.len() {
            let is_change = self.is_first_bit_outside_height[i];
            sub_root_bit = builder.select(is_change, one, sub_root_bit);

            let add_indicator = builder.mul(self.index_bits[i].target, sub_root_bit);
            sub_root_index = builder.add(add_indicator, sub_root_index);


            sub_root_bit = builder.add(sub_root_bit, sub_root_bit);

        }

        sub_root_index
    }

    pub fn from_q_bit_info<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        q_info: &QVariableHeightBitInfo,
    ) -> Self {
        let index_bits = q_info.index_bits.iter()
            .map(|&b| builder.constant_bool(b))
            .collect();
        
        let is_bit_not_within_height = q_info.is_bit_not_within_height.iter()
            .map(|&b| builder.constant_bool(b))
            .collect();
        
        let is_first_bit_outside_height = q_info.is_first_bit_outside_height.iter()
            .map(|&b| builder.constant_bool(b))
            .collect();
        
        Self {
            index_bits,
            is_bit_not_within_height,
            is_first_bit_outside_height,
        }
    }

}
