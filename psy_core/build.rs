use std::{env, fs, path::PathBuf};

fn main() {
    let config_path = env::var_os("PSY_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../psy-genesis/config.json"));
    println!("cargo:rerun-if-env-changed=PSY_CONFIG_PATH");
    println!("cargo:rerun-if-changed={}", config_path.display());
    let config: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&config_path).expect("Failed to read network config"),
    ).expect("Failed to parse network config");
    let mut constants = String::new();
    for (network, name) in [
        ("localhost", "PSY_CHAIN_ID_LOCAL_DEVNET"),
        ("sepolia", "PSY_CHAIN_ID_PSY_PUBLIC_TESTNET"),
        ("ethereum", "PSY_CHAIN_ID_PSY_MAINNET"),
    ] {
        let value = config["networks"][network]["magic"].as_str()
            .unwrap_or_else(|| panic!("Missing magic for network {network}"));
        let magic = if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16)
        } else {
            value.parse::<u64>()
        }.unwrap_or_else(|_| panic!("Invalid magic for network {network}"));
        constants.push_str(&format!("pub const {name}: u64 = {magic};\n"));
    }
    fs::write(PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR missing")).join("chain_id.rs"), constants)
        .expect("Failed to write chain identity constants");
}
