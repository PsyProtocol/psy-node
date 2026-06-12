#![allow(incomplete_features)]
// #![feature(generic_const_exprs)]
// #![feature(specialization)]

pub mod curve;
pub mod field;
pub mod gadgets;

use plonky2::plonk::circuit_data::CircuitConfig;

pub fn pairing_config() -> CircuitConfig {
    CircuitConfig {
        num_wires: 400,
        ..CircuitConfig::wide_ecc_config()
    }
}
