// Standalone, offline verifier; compile with the generator's exact dependency rlibs.
// Usage: validate_token_artifacts --bundle genesis_contracts.json --genesis genesis.json
//        --measurements measurements.json
// Measurements are caller-supplied same-build results, not independently measured here:
// {"schema_version":1,"network":"testnet","node_source_commit":"<40 hex>",
//  "config_sha256":"<64 hex>","deposit_inclusion_fingerprint":[a,b,c,d],
//  "private_note_inclusion_fingerprint":[a,b,c,d]}
// Exit 0 means only the reported static checks passed, NOT proof/E2E/deployment approval.

use std::{collections::{BTreeMap, BTreeSet}, fs::File, io::Read, path::Path};
use anyhow::{bail, ensure, Context, Result};
use guardian_common::protocol::parse_duplicate_free_json;
use parth_core::{pgoldilocks::PoseidonHasher, PF, PHash};
use psy_client_data::qdata::contract::ContractCodeDefinition;
use psy_config::network_constants::VM_TYPE_STANRDARD_DAPEN_V1;
use psy_data::{genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    v1::qdata::contract::CanonicalLayoutManifest};
use psy_vm::dpn::{contract::{cfc_code_definition_to_dapen_fc, hash_dpn_function},
    ops::op_types::{DPNIndexedVarDef, DPNOpType}, vm::def::DPNFunctionCircuitDefinition};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const MAX_BYTES: u64 = 1024 * 1024 * 1024;
const GOLDILOCKS_MODULUS: u64 = 18446744069414584321;
type Method = (&'static str, u32, u32, u32);
const TOKEN: &[Method] = &[
    ("withdraw", 3055054724, 33, 0), ("claim_deposit", 1577908089, 105, 0),
    ("mint", 3374273625, 1, 0), ("transfer", 2789897329, 2, 0),
    ("claim", 3824212239, 1, 0), ("batch_transfer_2", 1656917177, 4, 0),
    ("batch_transfer_5", 1394667333, 10, 0), ("burn", 3998182541, 1, 0),
    ("private_transfer", 1325380837, 9, 0), ("private_claim", 635905178, 82, 0),
];
const POLICY: &[Method] = &[("get_policy",2734444163,0,16),("set_policy",930568152,28,0)];
const DEPOSIT: &[Method] = &[
    ("get_root",2916128730,0,8),("get_chain_root",1100689054,1,8),
    ("is_known_root_hash",219410164,9,1),("is_known_root",2420703934,9,1),
    ("set_chain_root",4192350829,10,0),("append_leaf",861400038,8,0),
    ("append_deposit",1676735501,9,0),("batch_append_deposits_2",1556057369,18,0),
    ("batch_append_deposits_5",845640512,42,0),
];
const WITHDRAWAL: &[Method] = &[
    ("set_chain_root",4192350829,10,0),("get_root",2916128730,0,8),
    ("get_chain_root",1011075378,1,8),("append_leaf",861400038,8,0),
    ("append_withdrawal",2140131902,35,0),("batch_append_withdrawals_2",4283677324,71,0),
    ("batch_append_withdrawals_5",961124698,176,0),
];
const FAUCET: &[Method] = &[("faucet",3375543263,2,0)];
const CONTRACTS: &[(&str, u16, &[Method])] = &[
    ("token",32,TOKEN),("multisig_policy",4,POLICY),("deposit_tree",21,DEPOSIT),
    ("withdrawal_tree",15,WITHDRAWAL),("usdt_token",32,TOKEN),("faucet",31,FAUCET),
];

fn sha(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }

fn bounded_read(reader: impl Read) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_BYTES, "public input exceeds size bound");
    Ok(bytes)
}

fn public_json(path: &str, compressed: bool) -> Result<(Value, String)> {
    // Explicit public inputs only; never enumerate adjacent identity directories.
    ensure!(!path.to_ascii_lowercase().contains("private_keys"), "private keys are not an input");
    ensure!(std::fs::symlink_metadata(Path::new(path))?.file_type().is_file(),
        "public input must be a regular, non-symlink file");
    let raw = bounded_read(File::open(path)?)?;
    let digest = sha(&raw);
    let bytes = if compressed && raw.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        bounded_read(zstd::stream::read::Decoder::new(raw.as_slice())?)?
    } else { raw };
    Ok((parse_duplicate_free_json(&bytes)?, digest))
}

fn args() -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    let mut args = std::env::args().skip(1);
    while let Some(key) = args.next() {
        ensure!(["--bundle", "--genesis", "--measurements"].contains(&key.as_str()),
            "expected --bundle FILE --genesis FILE --measurements FILE");
        let value = args.next().context("missing input path")?;
        ensure!(result.insert(key, value).is_none(), "duplicate argument");
    }
    ensure!(result.len() == 3, "all three public input paths are required");
    Ok(result)
}

fn hex_pin(value: &Value, length: usize) -> bool {
    value.as_str().map_or(false, |s| s.len() == length && s.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn fingerprint(value: &Value) -> Result<[u64; 4]> {
    let values = value.as_array().context("fingerprint must be four decimal u64 limbs")?;
    ensure!(values.len() == 4, "fingerprint must have exactly four limbs");
    let mut result = [0; 4];
    for (out, value) in result.iter_mut().zip(values) {
        *out = value.as_u64().context("fingerprint limb is not an unsigned integer")?;
        ensure!(*out < GOLDILOCKS_MODULUS, "fingerprint limb is not canonical Goldilocks");
    }
    ensure!(result != [0; 4], "zero fingerprint is not an approval");
    Ok(result)
}

type Definitions<'a> = BTreeMap<u64, &'a DPNIndexedVarDef>;

fn constant(defs: &Definitions<'_>, id: u64) -> Option<u64> {
    let def = defs.get(&id)?;
    if matches!(def.op_type, DPNOpType::Constant | DPNOpType::ConstantU32)
        && def.inputs.len() == 1 { Some(def.inputs[0]) } else { None }
}

fn is_true(defs: &Definitions<'_>, id: u64) -> bool {
    defs.get(&id).map_or(false, |d| d.op_type == DPNOpType::ConstantTrue)
        || constant(defs, id) == Some(1)
}

fn proof_root_operands(defs: &Definitions<'_>, expression: u64) -> Result<Vec<u64>> {
    let mut pending = vec![expression];
    let mut seen = BTreeSet::new();
    let mut equalities = Vec::new();
    while let Some(id) = pending.pop() {
        if is_true(defs, id) { continue; }
        ensure!(seen.insert(id), "repeated/cyclic proof-root Boolean expression");
        let d = defs.get(&id).context("missing proof-root Boolean expression")?;
        match d.op_type {
            DPNOpType::Eq => {
                ensure!(d.inputs.len() == 2, "invalid root equality");
                equalities.push((d.inputs[0], d.inputs[1]));
            }
            DPNOpType::BoolAnd => {
                ensure!(d.inputs.len() == 2, "invalid root conjunction");
                pending.extend(d.inputs.iter().copied());
            }
            DPNOpType::Select => {
                // The compiler lowers hash equality to Select(Not(Eq), false, rest).
                ensure!(d.inputs.len() == 3, "invalid Boolean Select");
                let rejected = defs.get(&d.inputs[1]).context("missing false branch")?;
                ensure!(rejected.op_type == DPNOpType::ConstantFalse
                    || constant(defs, d.inputs[1]) == Some(0), "non-rejecting root comparison");
                let not = defs.get(&d.inputs[0]).context("missing root condition")?;
                ensure!(not.op_type == DPNOpType::BoolNot && not.inputs.len() == 1,
                    "unsupported root comparison condition");
                let equality = defs.get(&not.inputs[0]).context("missing root equality")?;
                ensure!(equality.op_type == DPNOpType::Eq && equality.inputs.len() == 2,
                    "root condition must negate equality");
                equalities.push((equality.inputs[0], equality.inputs[1]));
                pending.push(d.inputs[2]);
            }
            _ => bail!("unsupported proof-root Boolean expression"),
        }
    }
    ensure!(equalities.len() == 4, "four required root equalities expected");
    let session_limb = |id| -> Option<(u64, u64)> {
        let part = defs.get(&id)?;
        if part.op_type != DPNOpType::TargetAt || part.inputs.len() != 2 { return None; }
        let parent = defs.get(&part.inputs[0])?;
        if parent.op_type != DPNOpType::GetSessionProofTreeRoot { return None; }
        Some((part.inputs[0], constant(defs, part.inputs[1])?))
    };
    let mut parent = None;
    let mut indices = BTreeSet::new();
    let mut operands = Vec::new();
    for (left, right) in equalities {
        let ((root, index), operand) = match (session_limb(left), session_limb(right)) {
            (Some(limb), None) => (limb, right),
            (None, Some(limb)) => (limb, left),
            _ => bail!("root equality must bind one session-root limb"),
        };
        ensure!(index < 4 && indices.insert(index), "duplicate/invalid session-root limb");
        ensure!(parent.map_or(true, |old| old == root), "mixed session roots");
        parent = Some(root);
        operands.push(operand);
    }
    Ok(operands)
}

fn proof_binding(def: &DPNFunctionCircuitDefinition, pi_len: usize) -> Result<Value> {
    let defs: Definitions<'_> = def.definitions.iter()
        .map(|d| (d.get_combined_data_type_index(), d)).collect();
    ensure!(defs.len() == def.definitions.len(), "duplicate DPN definitions");
    let assertions: Vec<_> = def.assertions.iter()
        .filter(|a| a.message == "proof tree root mismatch").collect();
    ensure!(assertions.len() == 1, "expected one proof-root assertion");
    let a = assertions[0];
    let expression = if is_true(&defs, a.right) { a.left }
        else if is_true(&defs, a.left) { a.right }
        else { bail!("proof-root assertion does not require true") };
    let mut seen = BTreeSet::new();
    let mut pending = proof_root_operands(&defs, expression)?;
    let mut leaves = Vec::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) { continue; }
        let d = defs.get(&id).context("proof-root dependency is missing")?;
        use DPNOpType::*;
        match d.op_type {
            Select => {
                ensure!(d.inputs.len() == 3, "invalid proof-path Select");
                // Only data arms: a fingerprint in a selector is not a proof leaf.
                pending.extend(d.inputs[1..].iter().copied());
            }
            TargetAt => {
                ensure!(d.inputs.len() == 2, "invalid proof-path TargetAt");
                pending.push(d.inputs[0]);
            }
            HashTwoToOne => {
                ensure!(d.inputs.len() == 8, "unexpected proof hash arity");
                let limbs: Option<Vec<u64>> = d.inputs[..4].iter()
                    .map(|id| constant(&defs, *id)).collect();
                if let Some(limbs) = limbs {
                    let mut pi_hash = None;
                    for (index, target) in d.inputs[4..].iter().enumerate() {
                        let part = defs.get(target).context("missing PI limb")?;
                        ensure!(part.op_type == TargetAt && part.inputs.len() == 2
                            && constant(&defs, part.inputs[1]) == Some(index as u64),
                            "fingerprint leaf must consume PI hash limbs in order");
                        let base = part.inputs[0];
                        ensure!(pi_hash.map_or(true, |old| old == base), "PI hash limbs have different parents");
                        pi_hash = Some(base);
                    }
                    let pi_id = pi_hash.context("missing PI hash")?;
                    let pi = defs.get(&pi_id).context("missing PI definition")?;
                    ensure!(pi.op_type == HashNoPad && pi.inputs.len() == pi_len,
                        "unexpected claim public-input hash opcode/arity");
                    leaves.push(json!({"actual":limbs,"leaf_definition":id,
                        "public_inputs_hash_definition":pi_id,"public_input_count":pi_len}));
                } else { pending.extend(d.inputs.iter().copied()); }
            }
            GetSessionProofTreeRoot => bail!("computed proof root depends on the session root"),
            InputTarget | U32InputTarget | BoolInputTarget | Constant | ConstantU32
                | ConstantTrue | ConstantFalse => (),
            _ => bail!("unsupported opcode on proof assertion data path: {:?}", d.op_type),
        }
    }
    ensure!(leaves.len() == 1, "expected exactly one constant-fingerprint proof leaf, got {}", leaves.len());
    Ok(leaves.remove(0))
}

fn verify(report: &mut Value) -> Result<()> {
    let args = args()?;
    ensure!(psy_config::CURRENT_NETWORK == "testnet"
        && psy_config::PSY_NETWORK_MAGIC == 0x1337CF514544CF69,
        "verifier rlibs were not built for the approved testnet network/magic");
    report["compiled_network"] = json!(psy_config::CURRENT_NETWORK);
    report["compiled_network_magic"] = json!(format!("0x{:016x}", psy_config::PSY_NETWORK_MAGIC));
    let (measurements, measurement_sha) = public_json(&args["--measurements"], false)?;
    let fields = ["schema_version", "network", "node_source_commit", "config_sha256",
        "deposit_inclusion_fingerprint", "private_note_inclusion_fingerprint"];
    let object = measurements.as_object().context("measurement object required")?;
    ensure!(object.len() == fields.len() && fields.iter().all(|k| object.contains_key(*k)),
        "measurement schema fields differ from the documented schema");
    ensure!(measurements["schema_version"] == 1 && measurements["network"] == "testnet",
        "measurement schema/network mismatch");
    ensure!(hex_pin(&measurements["node_source_commit"], 40)
        && hex_pin(&measurements["config_sha256"], 64), "invalid measurement provenance pins");
    let deposit_fp = fingerprint(&measurements["deposit_inclusion_fingerprint"])?;
    let private_fp = fingerprint(&measurements["private_note_inclusion_fingerprint"])?;
    report["measurements"] = measurements;
    report["measurements_sha256"] = json!(measurement_sha);
    let (bundle, bundle_sha) = public_json(&args["--bundle"], true)?;
    let (genesis, genesis_sha) = public_json(&args["--genesis"], false)?;
    report["bundle_sha256"] = json!(bundle_sha);
    report["genesis_sha256"] = json!(genesis_sha);
    let bundle = bundle.as_array().context("bundle must be an array")?;
    let contracts = genesis["contracts"].as_array().context("Genesis contracts required")?;
    ensure!(bundle.len() == 6 && contracts.len() == 6, "full six-contract bundle/Genesis required");
    let mut mismatches = Vec::new();
    for (slot, ((name, height, expected), entry)) in CONTRACTS.iter().zip(bundle).enumerate() {
        ensure!(entry["name"] == *name, "wrong contract name/order at slot {slot}");
        let mut deployment = entry.as_object().context("deployment object required")?.clone();
        deployment.remove("name");
        let mut final_deployment = contracts[slot].as_object()
            .context("final Genesis contract wrapper required")?.clone();
        // The native generator adds layout metadata; the compiler bundle remains flat.
        final_deployment.remove("state_layout");
        ensure!(deployment == final_deployment,
            "bundle and final Genesis deployment differ at slot {slot}");
        let code: ContractCodeDefinition = serde_json::from_value(entry["code_definition"].clone())?;
        ensure!(code.state_tree_height == *height && code.functions.len() == expected.len(),
            "incomplete or wrong contract shape at slot {slot}");
        let whitelist: Vec<PHash> = serde_json::from_value(entry["function_whitelist"].clone())?;
        ensure!(whitelist.len() == expected.len() * 2, "wrong whitelist count at slot {slot}");
        let _: PHash = serde_json::from_value(entry["code_root"].clone())?;
        let mut names = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut methods = Vec::new();
        for function in &code.functions {
            ensure!(function.vm_type == VM_TYPE_STANRDARD_DAPEN_V1, "wrong VM at slot {slot}");
            let decoded = cfc_code_definition_to_dapen_fc(function)
                .with_context(|| format!("production DPN decode slot {slot}, method {}", function.method_id))?;
            ensure!(decoded.method_id == function.method_id
                && decoded.circuit_inputs.len() == function.num_inputs as usize
                && decoded.circuit_outputs.len() == function.num_outputs as usize,
                "DPN/function envelope mismatch at slot {slot}");
            ensure!(names.insert(decoded.name.clone()) && ids.insert(decoded.method_id),
                "duplicate method at slot {slot}");
            ensure!(expected.iter().any(|(n,id,inputs,outputs)| *n == decoded.name
                && *id == function.method_id && *inputs == function.num_inputs && *outputs == function.num_outputs),
                "unexpected method signature at slot {slot}: {}", decoded.name);
            let mut method = json!({"name":decoded.name,"method_id":decoded.method_id,
                "num_inputs":function.num_inputs,"num_outputs":function.num_outputs,
                "cbor_sha256":sha(&function.code),"dpn_hash":hash_dpn_function::<PF>(&decoded)});
            if (slot == 0 || slot == 4) && matches!(decoded.name.as_str(), "claim_deposit" | "private_claim") {
                let (expected_fp, pi_len) = if decoded.name == "claim_deposit" { (deposit_fp,42) }
                    else { (private_fp,16) };
                let mut binding = proof_binding(&decoded, pi_len)
                    .with_context(|| format!("proof binding slot {slot} {}", decoded.name))?;
                binding["expected"] = json!(expected_fp);
                let actual = fingerprint(&binding["actual"])?;
                binding["match"] = json!(actual == expected_fp);
                if actual != expected_fp { mismatches.push(format!("slot {slot} {} fingerprint mismatch", decoded.name)); }
                method["fingerprint_binding"] = binding;
            }
            methods.push(method);
        }
        report["contracts"].as_array_mut().unwrap().push(json!({"slot":slot,"name":name,
            "state_tree_height":height,"code_root":entry["code_root"],
            "whitelist_count":whitelist.len(),"methods":methods}));
    }
    report["fingerprint_mismatches"] = json!(mismatches);
    ensure!(mismatches.is_empty(), "embedded fingerprints do not match supplied measurements");
    // Native final-Genesis parsing must not silently drop mandatory layout metadata.
    let native: PsyGenesisBlockSetupData<PF, PHash> = serde_json::from_value(genesis.clone())?;
    ensure!(native.contracts.len() == 6, "native Genesis contract count mismatch");
    for (slot, contract) in native.contracts.iter().enumerate() {
        let layout: &CanonicalLayoutManifest<PHash> = &contract.state_layout;
        ensure!(layout.state_tree_height == CONTRACTS[slot].1
            && layout.state_tree_height == contract.deploy_contract.code_definition.state_tree_height,
            "layout/code height mismatch at slot {slot}");
        let validated = layout.validate::<PoseidonHasher, PF>()
            .with_context(|| format!("canonical layout validation slot {slot}"))?;
        let metadata = &layout.layout.contract_layout;
        ensure!(validated.state_layout_root == metadata.state_layout_root
            && validated.state_layout_field_count == metadata.state_layout_field_count
            && validated.state_layout_slot_count == metadata.state_layout_slot_count,
            "reconstructed layout/native root metadata mismatch at slot {slot}");
        report["contracts"][slot]["layout"] = json!({"validated":true,
            "root":validated.state_layout_root,"field_count":validated.state_layout_field_count,
            "slot_count":validated.state_layout_slot_count});
    }
    report["native_genesis_decode"] = json!(true);
    Ok(())
}

fn main() {
    let mut report = json!({"ok":false,"scope":"offline_static_token_artifacts",
        "measurement_provenance":"caller_supplied_not_remeasured",
        "proof_or_e2e_verified":false,"checkpoint_constructed":false,
        "full_proof_path_semantics_verified":false,
        "code_root_and_function_whitelist_recomputed":false,"contracts":[]});
    match verify(&mut report) {
        Ok(()) => report["ok"] = json!(true),
        Err(error) => report["error"] = json!(format!("{error:#}")),
    }
    println!("{}", serde_json::to_string_pretty(&report).expect("public report serialization"));
    if report["ok"] != true { std::process::exit(1); }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> Vec<DPNFunctionCircuitDefinition> {
        let path = std::env::var("PSY_TOKEN_COMPILED_FIXTURE")
            .expect("explicit approved compiled token fixture required");
        let (compiled, _) = public_json(&path, false).unwrap();
        serde_json::from_value::<Vec<DPNFunctionCircuitDefinition>>(
            compiled["circuit_definitions"].clone()).unwrap().into_iter()
            .filter(|function| matches!(function.name.as_str(), "claim_deposit" | "private_claim"))
            .collect()
    }

    #[test]
    fn real_claims_follow_boolean_assertion_dependencies() {
        let claims = claims();
        assert_eq!(claims.len(), 2);
        for function in claims {
            let count = if function.name == "claim_deposit" { 42 } else { 16 };
            let binding = proof_binding(&function, count).expect("real compiled proof-root assertion");
            assert_eq!(binding["public_input_count"], count);
            assert_eq!(binding["actual"].as_array().unwrap().len(), 4);
        }
    }

    #[test]
    fn real_claims_reject_missing_session_root() {
        for mut function in claims() {
            let count = if function.name == "claim_deposit" { 42 } else { 16 };
            function.definitions.retain(|definition| definition.op_type != DPNOpType::GetSessionProofTreeRoot);
            assert!(proof_binding(&function, count).is_err());
        }
    }

    #[test]
    fn real_claims_reject_non_rejecting_root_comparison() {
        for mut function in claims() {
            let assertion = function.assertions.iter().find(|a| a.message == "proof tree root mismatch").unwrap();
            let id = assertion.left;
            let true_value = assertion.right;
            let root = function.definitions.iter_mut().find(|d| d.get_combined_data_type_index() == id).unwrap();
            assert_eq!(root.op_type, DPNOpType::Select);
            root.inputs[1] = true_value;
            let count = if function.name == "claim_deposit" { 42 } else { 16 };
            assert!(proof_binding(&function, count).is_err());
        }
    }
}
