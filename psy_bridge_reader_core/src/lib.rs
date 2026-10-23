//! Deposit tree core of the Bridge Reader: Poseidon hashing and the display
//! encoding Envio stores, bit-exact with the Envio `DepositRecorded` handler.

pub mod admission;
pub mod model;
pub mod source;
pub mod tree;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
