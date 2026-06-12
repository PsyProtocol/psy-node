#[cfg(not(target_arch = "wasm32"))]
fn main() -> shadow_rs::SdResult<()> {
    shadow_rs::new()
}

#[cfg(target_arch = "wasm32")]
fn main() {
    println!("cargo:warning=Shadow-rs disabled for WASM target");
}
