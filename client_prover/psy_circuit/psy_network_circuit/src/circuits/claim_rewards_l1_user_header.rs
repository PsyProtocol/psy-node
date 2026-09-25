use anyhow::{ensure, Result};
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_common_circuit::builder::hash::core::CircuitBuilderHashCore;

pub const USER_REWARD_HEADER_FIELDS: usize = 19;

#[derive(Clone)]
pub struct UserRewardHeader<F: RichField> { pub fields: [F; USER_REWARD_HEADER_FIELDS] }

impl<F: RichField> UserRewardHeader<F> {
    pub fn combine<H: psy_crypto::hash::traits::hasher::FieldQHasher<F>>(&self, right:&Self)->Result<Self>{
        ensure!(self.fields[..13]==right.fields[..13],"user reward contexts differ");
        let mut fields=self.fields;
        fields[13]=self.fields[13]+right.fields[13]; fields[14]=self.fields[14]+right.fields[14];
        let left=psy_client_common::data::qhashout::QHashOut(plonky2::hash::hash_types::HashOut{elements:self.fields[15..19].try_into().unwrap()});
        let right_hash=psy_client_common::data::qhashout::QHashOut(plonky2::hash::hash_types::HashOut{elements:right.fields[15..19].try_into().unwrap()});
        let counts=psy_client_common::data::qhashout::QHashOut(plonky2::hash::hash_types::HashOut{elements:[self.fields[14],right.fields[14],F::ZERO,F::ZERO]});
        let pair=H::q_two_to_one(left,right_hash); let combined=H::q_two_to_one(pair,counts);
        fields[15..19].copy_from_slice(&combined.0.elements); Ok(Self{fields})
    }
}

#[derive(Clone,Copy)]
pub struct UserRewardHeaderTarget { pub fields:[Target;USER_REWARD_HEADER_FIELDS] }
impl UserRewardHeaderTarget {
    pub fn add_virtual<F:RichField+Extendable<D>,const D:usize>(b:&mut CircuitBuilder<F,D>)->Self{Self{fields:b.add_virtual_target_arr()}}
    pub fn hash<H:AlgebraicHasher<F>,F:RichField+Extendable<D>,const D:usize>(&self,b:&mut CircuitBuilder<F,D>)->HashOutTarget{b.hash_n_to_hash_no_pad::<H>(self.fields.to_vec())}
    pub fn combine<H:AlgebraicHasher<F>,F:RichField+Extendable<D>,const D:usize>(b:&mut CircuitBuilder<F,D>,left:Self,right:Self)->Self{
        for i in 0..13 { b.connect(left.fields[i],right.fields[i]); }
        let mut fields=left.fields; fields[13]=b.add(left.fields[13],right.fields[13]); fields[14]=b.add(left.fields[14],right.fields[14]);
        let lh=HashOutTarget{elements:left.fields[15..19].try_into().unwrap()}; let rh=HashOutTarget{elements:right.fields[15..19].try_into().unwrap()};
        let pair=b.hash_two_to_one::<H>(lh,rh); let zero=b.zero(); let counts=HashOutTarget{elements:[left.fields[14],right.fields[14],zero,zero]}; let combined=b.hash_two_to_one::<H>(pair,counts);
        fields[15..19].copy_from_slice(&combined.elements); Self{fields}
    }
    pub fn set_witness<F:RichField>(&self,w:&mut impl Witness<F>,value:&UserRewardHeader<F>)->Result<()>{for (t,v) in self.fields.iter().zip(value.fields){w.set_target(*t,v)?;} Ok(())}
}
