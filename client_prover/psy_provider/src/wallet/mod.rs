#[cfg(not(target_arch = "wasm32"))]
pub mod secp_sign;
#[cfg(not(target_arch = "wasm32"))]
pub mod secp_wallet;
