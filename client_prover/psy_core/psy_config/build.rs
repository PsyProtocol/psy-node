use std::{env, fs, path::Path};

fn main() {
    let config_path = env::var("PSY_CONFIG_PATH").map(|p| Path::new(&p).to_path_buf()).unwrap_or_else(|_| {
        let mut current_dir = env::current_dir().expect("Failed to get current directory");
        loop {
            let cargo_toml = current_dir.join("Cargo.toml");
            if cargo_toml.exists() {
                if let Ok(cargo_content) = fs::read_to_string(&cargo_toml) {
                    if cargo_content.contains("[workspace]") {
                        let root_config = current_dir.join("config.json");
                        if root_config.exists() {
                            return root_config;
                        }
                        let client_prover_config = current_dir.join("client_prover").join("config.json");
                        if client_prover_config.exists() {
                            return client_prover_config;
                        }
                        return root_config;
                    }
                }
            }
            if let Some(parent) = current_dir.parent() {
                current_dir = parent.to_path_buf();
            } else {
                let local_config = Path::new("config.json").to_path_buf();
                if local_config.exists() {
                    return local_config;
                }
                let local_client_prover_config = Path::new("client_prover").join("config.json");
                if local_client_prover_config.exists() {
                    return local_client_prover_config;
                }
                return local_config;
            }
        }
    });

    let network = env::var("PSY_NETWORK").unwrap_or_else(|_| "localhost".to_string());

    println!("cargo:rerun-if-changed={}", config_path.display());
    println!("cargo:rerun-if-env-changed=PSY_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PSY_NETWORK");

    let config_content = fs::read_to_string(&config_path).unwrap_or_else(|_| panic!("Failed to read config file: {}", config_path.display()));

    let config: serde_json::Value = serde_json::from_str(&config_content).expect("Failed to parse config.json");

    let networks = config["networks"].as_object().expect("Config must have 'networks' object");

    let network_config = networks
        .get(&network)
        .unwrap_or_else(|| panic!("Network '{}' not found in config", network))
        .clone();

    let magic_str = network_config["magic"].as_str().expect("magic must be a hex string");
    let magic = if magic_str.starts_with("0x") || magic_str.starts_with("0X") {
        u64::from_str_radix(&magic_str[2..], 16).expect("Invalid hex magic value")
    } else {
        magic_str.parse::<u64>().expect("Invalid magic value")
    };

    let global_user_tree_height = network_config["global_user_tree_height"]
        .as_u64()
        .expect("global_user_tree_height must be a number") as u8;
    let realm_user_tree_height = network_config["realm_user_tree_height"]
        .as_u64()
        .expect("realm_user_tree_height must be a number") as u8;
    let users_per_realm = network_config["users_per_realm"].as_u64().expect("users_per_realm must be a number");
    let group_realm_height = network_config["group_realm_height"]
        .as_u64()
        .expect("group_realm_height must be a number") as u8;

    if global_user_tree_height < realm_user_tree_height {
        panic!(
            "global_user_tree_height ({}) must be >= realm_user_tree_height ({})",
            global_user_tree_height, realm_user_tree_height
        );
    }

    let expected_users_per_realm = 1u64 << realm_user_tree_height;
    if users_per_realm != expected_users_per_realm {
        panic!(
            "users_per_realm ({}) must equal 2^realm_user_tree_height (2^{} = {})",
            users_per_realm, realm_user_tree_height, expected_users_per_realm
        );
    }

    let coordinator_user_tree_height = global_user_tree_height - realm_user_tree_height;

    let native_currency_decimal = network_config["native_currency_decimal"]
        .as_u64()
        .expect("native_currency_decimal must be a number") as u8;
    let native_currency = network_config["native_currency"]
        .as_str()
        .expect("native_currency must be a string")
        .to_string();
    let native_currency_name = network_config["native_currency_name"]
        .as_str()
        .expect("native_currency_name must be a string")
        .to_string();

    let fees = &network_config["fees"];
    let register_user_fee = fees["register_user_fee"].as_u64().expect("register_user_fee must be a number");
    let deploy_contract_fee = fees["deploy_contract_fee"].as_u64().expect("deploy_contract_fee must be a number");
    let guta_fee = fees["guta_fee"].as_u64().expect("guta_fee must be a number");
    let da_fee = fees["da_fee"].as_u64().expect("da_fee must be a number");

    let coordinator_rpc_url = network_config["coordinator_configs"][0]["rpc_url"]
        .as_array()
        .expect("coordinator rpc_url must be an array")
        .first()
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let realm_rpc_urls = network_config["realm_configs"]
        .as_array()
        .expect("realm_configs must be an array")
        .iter()
        .map(|realm| {
            realm["rpc_url"]
                .as_array()
                .unwrap()
                .first()
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        })
        .collect::<Vec<_>>();

    let genesis_constants = String::new();

    let genesis_contracts_path = config_path
        .parent()
        .expect("config path must have a parent directory")
        .join("genesis_contracts.json");
    println!("cargo:rerun-if-changed={}", genesis_contracts_path.display());

    let precompile_constants =
        generate_precompile_constants_from_genesis_contracts(&genesis_contracts_path).unwrap_or_default();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("generated_constants.rs");

    let content = format!(
        r#"pub const PSY_NETWORK_MAGIC: u64 = {};
pub const GLOBAL_USER_TREE_HEIGHT: u8 = {};
pub const COORDINATOR_USER_TREE_HEIGHT: u8 = {};
pub const REALM_USER_TREE_HEIGHT: u8 = {};
pub const GROUP_REALM_HEIGHT: u8 = {};
pub const USERS_PER_REALM: u64 = {};
pub const NATIVE_CURRENCY_DECIMAL: u8 = {};
pub const NATIVE_CURRENCY: &str = "{}";
pub const NATIVE_CURRENCY_NAME: &str = "{}";
pub const REGISTER_USER_FEE: u64 = {};
pub const DEPLOY_CONTRACT_FEE: u64 = {};
pub const GUTA_FEE: u64 = {};
pub const DA_FEE: u64 = {};
pub const CURRENT_NETWORK: &str = "{}";
pub const COORDINATOR_RPC_URL: &str = "{}";
pub const REALM_RPC_URLS: &[&str] = &{:?};
{}
{}
"#,
        magic,
        global_user_tree_height,
        coordinator_user_tree_height,
        realm_user_tree_height,
        group_realm_height,
        users_per_realm,
        native_currency_decimal,
        native_currency,
        native_currency_name,
        register_user_fee,
        deploy_contract_fee,
        guta_fee,
        da_fee,
        network,
        coordinator_rpc_url,
        realm_rpc_urls,
        genesis_constants,
        precompile_constants
    );

    fs::write(&dest_path, content).expect("Failed to write generated constants");

    let json_constants = serde_json::json!({
        "PSY_NETWORK_MAGIC": magic,
        "GLOBAL_USER_TREE_HEIGHT": global_user_tree_height,
        "COORDINATOR_USER_TREE_HEIGHT": coordinator_user_tree_height,
        "REALM_USER_TREE_HEIGHT": realm_user_tree_height,
        "GROUP_REALM_HEIGHT": group_realm_height,
        "USERS_PER_REALM": users_per_realm,
        "NATIVE_CURRENCY_DECIMAL": native_currency_decimal,
        "NATIVE_CURRENCY": native_currency,
        "NATIVE_CURRENCY_NAME": native_currency_name,
        "REGISTER_USER_FEE": register_user_fee,
        "DEPLOY_CONTRACT_FEE": deploy_contract_fee,
        "GUTA_FEE": guta_fee,
        "CURRENT_NETWORK": network,
        "COORDINATOR_RPC_URL": coordinator_rpc_url,
        "REALM_RPC_URLS": realm_rpc_urls
    });

    let json_path = Path::new(&out_dir).join("constants.json");
    fs::write(&json_path, serde_json::to_string_pretty(&json_constants).unwrap()).expect("Failed to write JSON constants");
}

fn generate_precompile_constants_from_genesis_contracts(
    contracts_path: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let contracts_bytes =
        fs::read(contracts_path).unwrap_or_else(|_| panic!("Failed to read genesis_contracts.json at {}", contracts_path.display()));
    let contracts: Vec<serde_json::Value> = match serde_json::from_slice(&contracts_bytes) {
        Ok(v) => v,
        Err(_) => {
            let decoded =
                zstd::stream::decode_all(contracts_bytes.as_slice()).map_err(|e| format!("failed to decode zstd genesis_contracts.json: {}", e))?;
            serde_json::from_slice(&decoded)?
        }
    };

    let mut constants = String::new();
    constants.push_str("\n");

    // Generate contract ID constants
    for (index, contract) in contracts.iter().enumerate() {
        let name = contract
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| format!("Contract at index {} is missing required 'name' field", index))?;
        let const_name = name.to_uppercase();
        constants.push_str(&format!("pub const {}_CONTRACT_ID: u32 = {};\n", const_name, index));
    }
    constants.push('\n');

    // Generate method ID constants from code_definition.functions
    for contract in contracts.iter() {
        let contract_name = contract
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or_else(|| "Contract is missing required 'name' field".to_string())?;

        let functions = contract
            .get("code_definition")
            .and_then(|c| c.get("functions"))
            .and_then(|f| f.as_array())
            .ok_or_else(|| format!("Contract '{}' missing code_definition.functions", contract_name))?;

        for func in functions {
            let method_name = func
                .get("name")
                .and_then(|n| n.as_str())
                .map(|n| n.split("::").last().unwrap_or(n))
                .map(|n| n.to_string())
                .or_else(|| {
                    func.get("code").and_then(|c| c.as_array()).and_then(|arr| {
                        let bytes: Vec<u8> = arr.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect();
                        extract_method_name_from_cbor(&bytes)
                    })
                });

            if let (Some(method_name), Some(method_id)) = (method_name, func.get("method_id").and_then(|id| id.as_u64())) {
                let method_name = method_name.to_uppercase();
                constants.push_str(&format!(
                    "pub const {}_{}_METHOD_ID: u32 = {};\n",
                    contract_name.to_uppercase(),
                    method_name,
                    method_id as u32
                ));
            }
        }
    }

    if !contracts.is_empty() {
        constants.push('\n');
    }

    Ok(constants)
}

/// Extract method name from the CBOR-encoded `code` field of a genesis contract
/// function. The CBOR map starts with `0xa9` and the "name" key is typically
/// the first entry.
fn extract_method_name_from_cbor(code: &[u8]) -> Option<String> {
    // CBOR text string "name" = 0x64 + "name"
    let name_key = [0x64, b'n', b'a', b'm', b'e'];
    let pos = code.windows(5).position(|w| w == name_key)? + 5;

    let len_byte = *code.get(pos)?;
    let (len, offset) = if (0x60..=0x77).contains(&len_byte) {
        ((len_byte - 0x60) as usize, pos + 1)
    } else if len_byte == 0x78 {
        (*code.get(pos + 1)? as usize, pos + 2)
    } else if len_byte == 0x79 {
        let hi = *code.get(pos + 1)? as usize;
        let lo = *code.get(pos + 2)? as usize;
        ((hi << 8) | lo, pos + 3)
    } else {
        return None;
    };

    let name_bytes = code.get(offset..offset.checked_add(len)?)?;
    String::from_utf8(name_bytes.to_vec()).ok()
}
