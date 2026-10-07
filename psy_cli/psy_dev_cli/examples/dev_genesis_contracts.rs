use anyhow::{Context, Result};
use psy_client_data::config::store_config::{C, D};
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;
use serde::Deserialize;

#[derive(Deserialize)]
struct Artifact {
    state_tree_height: u16,
    circuit_definitions: Vec<DPNFunctionCircuitDefinition>,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let output = args.next().context("missing output path")?;
    let deployer: u64 = args.next().context("missing deployer user id")?.parse()?;
    let mut contracts = Vec::new();
    for input in args {
        let (name, path) = input.split_once('=').context("expected name=artifact path")?;
        let artifact: Artifact = serde_json::from_slice(&std::fs::read(path)?)?;
        let (_, contract) = psy_prover::session::gen_contract_deploy_and_circuits_for_functions::<C, D>(
            deployer, artifact.state_tree_height.try_into()?, &artifact.circuit_definitions,
        )?;
        let mut value = serde_json::to_value(contract)?;
        value["name"] = serde_json::Value::String(name.to_owned());
        contracts.push(value);
    }
    anyhow::ensure!(contracts.len() == 7 && contracts[6]["name"] == "multisig_policy", "expected seven ordered Genesis contracts");
    let file = std::fs::OpenOptions::new().write(true).create_new(true).open(output)?;
    serde_json::to_writer(file, &contracts)?;
    println!("generated_contracts=7 deployer_user_id={deployer}");
    Ok(())
}
