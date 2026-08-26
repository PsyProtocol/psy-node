#[cfg(not(target_arch = "wasm32"))]
pub mod dummy;
#[cfg(not(target_arch = "wasm32"))]
pub mod dummy_prover;
