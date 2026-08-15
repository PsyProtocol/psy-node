use std::{fs, path::Path};

use psy_client_data::abi::Abi;
use psy_vm::dpn::{
    eval::executor::{ExecutionContext, ExecutionResult, InMemoryStateBackend, VmExecutor},
    vm::def::DPNFunctionCircuitDefinition,
};

use super::args::SimulateArgs;

pub async fn run(args: SimulateArgs) -> anyhow::Result<()> {
    tracing::info!("simulating contract method: {}", args.method);

    // Load circuit definitions: either from source or pre-compiled
    let (circuit_defs, abi) = load_contract(&args)?;

    // Find the method to execute
    let method_info = abi.contract.methods.iter().find(|m| m.name == args.method).ok_or_else(|| {
        let available: Vec<&str> = abi.contract.methods.iter().map(|m| m.name.as_str()).collect();
        anyhow::anyhow!("Method '{}' not found. Available methods: {:?}", args.method, available)
    })?;

    let circuit_def = circuit_defs.iter().find(|d| d.method_id == method_info.method_id).ok_or_else(|| {
        anyhow::anyhow!(
            "Circuit definition not found for method '{}' (method_id={})",
            args.method,
            method_info.method_id
        )
    })?;

    // Build execution context
    let context = ExecutionContext {
        user_id: args.user_id,
        contract_id: args.contract_id.unwrap_or(1),
        caller_contract_id: 0,
        checkpoint_id: args.checkpoint_id.unwrap_or(100),
        nonce: args.nonce.unwrap_or(0),
        user_public_key_hash: [0; 4],
    };

    // Create state backend (InMemory for simulation)
    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);

    // Execute
    tracing::info!(
        "executing method '{}' (method_id={}) with {} inputs",
        args.method,
        method_info.method_id,
        args.inputs.len()
    );

    let result = executor.execute(circuit_def, &context, &args.inputs)?;

    // Format and display
    format_result(&result, &abi, &args)?;

    Ok(())
}

fn load_contract(args: &SimulateArgs) -> anyhow::Result<(Vec<DPNFunctionCircuitDefinition>, Abi)> {
    if let Some(source_path) = &args.source {
        // Compile from source
        let path = Path::new(source_path);
        if !path.exists() {
            anyhow::bail!("Source file not found: {}", source_path);
        }

        let output = if args.is_crate {
            psy_prover::session::compile_bridge::compile_crate_output(path)
                .map_err(|error| anyhow::anyhow!("failed to compile crate source {}: {:#}", path.display(), error))?
        } else {
            let source = fs::read_to_string(path).map_err(|error| anyhow::anyhow!("failed to read source file {}: {}", path.display(), error))?;
            psy_prover::session::compile_bridge::compile_contract_output(&source)
                .map_err(|error| anyhow::anyhow!("failed to compile source {}: {:#}", path.display(), error))?
        };

        Ok((output.circuit_definitions, output.abi))
    } else if let Some(defs_path) = &args.circuit_defs_path {
        // Load pre-compiled circuit definitions + ABI
        let defs_source =
            fs::read_to_string(defs_path).map_err(|error| anyhow::anyhow!("failed to read circuit definitions {}: {}", defs_path, error))?;
        let defs: Vec<DPNFunctionCircuitDefinition> =
            serde_json::from_str(&defs_source).map_err(|error| anyhow::anyhow!("failed to parse circuit definitions {}: {}", defs_path, error))?;

        let abi = if let Some(abi_path) = &args.abi_path {
            let abi_source = fs::read_to_string(abi_path).map_err(|error| anyhow::anyhow!("failed to read ABI {}: {}", abi_path, error))?;
            serde_json::from_str(&abi_source).map_err(|error| anyhow::anyhow!("failed to parse ABI {}: {}", abi_path, error))?
        } else {
            // If no ABI path, create a minimal ABI from the circuit definitions
            Abi {
                schema_version: "2.0.0".to_string(),
                contract: psy_client_data::abi::AbiContract {
                    name: "Unknown".to_string(),
                    state_tree_height: 0,
                    state: vec![],
                    methods: defs
                        .iter()
                        .map(|d| psy_client_data::abi::AbiMethod {
                            name: d.name.clone(),
                            method_id: d.method_id,
                            state_mutability: if d.is_view_function() {
                                psy_client_data::abi::StateMutability::View
                            } else {
                                psy_client_data::abi::StateMutability::External
                            },
                            inputs: vec![],
                            outputs: vec![],
                            input_felt_count: 0,
                            output_felt_count: 0,
                            vm_type: None,
                        })
                        .collect(),
                },
                types: vec![],
            }
        };

        Ok((defs, abi))
    } else {
        anyhow::bail!("Must specify either --source or --circuit-defs-path");
    }
}

fn format_result(result: &ExecutionResult, abi: &Abi, args: &SimulateArgs) -> anyhow::Result<()> {
    let format = args.format.as_deref().unwrap_or("table");

    match format {
        "json" => {
            println!("{}", serde_json::to_string_pretty(result)?);
        }
        "minimal" => {
            if result.success {
                println!("SUCCESS");
                if !result.outputs.is_empty() {
                    println!("outputs: {:?}", result.outputs);
                }
                println!("state_changes: {} reads, {} writes", result.state_reads.len(), result.state_writes.len());
            } else if let Some(failure) = &result.failure {
                println!("FAILED: {}", failure.message);
                println!(
                    "  assertion[{}]: {} != {}",
                    failure.assertion_index, failure.left_value, failure.right_value
                );
            }
        }
        _ => {
            // Default: table format
            println!("=== Simulation Result ===");
            println!();
            println!("Status: {}", if result.success { "SUCCESS" } else { "FAILED" });

            if let Some(failure) = &result.failure {
                println!();
                println!("Failure:");
                println!("  Assertion #{}: {}", failure.assertion_index, failure.message);
                println!("  Left:  {} (0x{:x})", failure.left_value, failure.left_value);
                println!("  Right: {} (0x{:x})", failure.right_value, failure.right_value);
            }

            if !result.outputs.is_empty() {
                println!();
                println!("Outputs: {:?}", result.outputs);
            }

            if !result.state_delta.is_empty() {
                println!();
                println!("State Delta:");
                for delta in &result.state_delta {
                    // Try to resolve field name from ABI
                    let field_name = resolve_field_name(abi, delta.slot_index);
                    println!(
                        "  [user={}, contract={}, slot={}{}]",
                        delta.user_id,
                        delta.contract_id,
                        delta.slot_index,
                        field_name.map(|n| format!(" ({})", n)).unwrap_or_default()
                    );
                    println!("    old: {:?}", delta.old_value);
                    println!("    new: {:?}", delta.new_value);
                }
            }

            if !result.state_reads.is_empty() {
                println!();
                println!("State Reads: {} total", result.state_reads.len());
                for read in &result.state_reads {
                    println!(
                        "  [{}] user={}, contract={}, slot={}: {:?}",
                        read.command_type, read.user_id, read.contract_id, read.slot_index, read.value
                    );
                }
            }

            if !result.state_writes.is_empty() {
                println!();
                println!("State Writes: {} total", result.state_writes.len());
                for write in &result.state_writes {
                    println!(
                        "  [{}] user={}, contract={}, slot={} (condition={})",
                        write.command_type, write.user_id, write.contract_id, write.slot_index, write.condition
                    );
                    println!("    old: {:?} -> new: {:?}", write.old_value, write.new_value);
                }
            }

            if !result.events.is_empty() {
                println!();
                println!("Events: {} emitted", result.events.len());
                for event in &result.events {
                    println!(
                        "  checkpoint={}, user={}, contract={}, data={:?}",
                        event.checkpoint_id, event.user_id, event.contract_id, event.data
                    );
                }
            }

            println!();
            println!("Operation Counts:");
            println!("  Total:      {}", result.op_counts.total_operations);
            println!("  Arithmetic: {}", result.op_counts.arithmetic_ops);
            println!("  Boolean:    {}", result.op_counts.boolean_ops);
            println!("  Comparison: {}", result.op_counts.comparison_ops);
            println!("  Hash:       {}", result.op_counts.hash_ops);
            println!("  State read: {}", result.op_counts.state_read_ops);
            println!("  State write:{}", result.op_counts.state_write_ops);
            println!("  Ext calls:  {}", result.op_counts.external_call_ops);
        }
    }

    Ok(())
}

/// Try to resolve a slot index to a human-readable field name from the ABI
fn resolve_field_name(abi: &Abi, slot_index: u64) -> Option<String> {
    use psy_client_data::abi::TypeRef;
    for field in &abi.contract.state {
        let offset = field.offset as u64;
        let size = field.felt_size as u64;

        if slot_index >= offset && slot_index < offset + size {
            let relative = slot_index - offset;
            if let TypeRef::Array { item_felt_size, length, .. } = &field.ty {
                let elem_size = *item_felt_size as u64;
                if elem_size > 0 {
                    let array_idx = relative / elem_size;
                    let field_offset = relative % elem_size;
                    return Some(format!("{}.{}[{}]+{}", abi.contract.name, field.name, array_idx, field_offset));
                }
                let _ = length;
            }
            if relative == 0 {
                return Some(format!("{}.{}", abi.contract.name, field.name));
            } else {
                return Some(format!("{}.{}+{}", abi.contract.name, field.name, relative));
            }
        }
    }
    None
}
