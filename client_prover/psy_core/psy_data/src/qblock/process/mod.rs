pub mod witnesses;

#[cfg(not(target_arch = "wasm32"))]
pub mod simple;
