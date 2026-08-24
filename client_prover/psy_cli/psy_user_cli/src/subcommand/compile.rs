use std::{fs, path::Path};

use super::args::CompileArgs;

pub async fn run(args: CompileArgs) -> anyhow::Result<()> {
    tracing::info!("compiling contract from: {}", args.source);

    let source_path = Path::new(&args.source);
    if !source_path.exists() {
        anyhow::bail!("Source file not found: {}", args.source);
    }

    // Determine output directory
    let output_dir = args.output_dir.as_deref().unwrap_or("./build");
    fs::create_dir_all(output_dir).map_err(|error| anyhow::anyhow!("failed to create output directory {}: {}", output_dir, error))?;

    // Compile: crate mode vs. single file
    let output = if args.is_crate {
        tracing::info!("compiling as multi-file crate");
        psy_prover::session::compile_bridge::compile_crate_output(source_path)
            .map_err(|error| anyhow::anyhow!("failed to compile crate source {}: {:#}", source_path.display(), error))?
    } else {
        tracing::info!("compiling single file");
        let source = fs::read_to_string(source_path)
            .map_err(|error| anyhow::anyhow!("failed to read source file {}: {}", source_path.display(), error))?;
        psy_prover::session::compile_bridge::compile_contract_output(&source)
            .map_err(|error| anyhow::anyhow!("failed to compile source {}: {:#}", source_path.display(), error))?
    };

    tracing::info!(
        "compilation successful: {} methods, state_tree_height={}",
        output.method_count(),
        output.state_tree_height()
    );

    // --check: type-check only, no output
    if args.check {
        println!("Compilation check passed: {} methods", output.method_count());
        return Ok(());
    }

    // --abi-only: only generate ABI JSON
    if args.abi_only {
        let abi_json = output.abi_to_json()?;
        let abi_path = format!("{}/abi.json", output_dir);
        fs::write(&abi_path, &abi_json).map_err(|error| anyhow::anyhow!("failed to write ABI {}: {}", abi_path, error))?;
        println!("ABI written to {}", abi_path);
        return Ok(());
    }

    // Full output: contract_code.bin, abi.json, circuit_defs.json, compilation_artifact.json
    let code_bytes = output.to_bytes()?;
    let code_path = format!("{}/contract_code.bin", output_dir);
    fs::write(&code_path, &code_bytes).map_err(|error| anyhow::anyhow!("failed to write contract code {}: {}", code_path, error))?;
    tracing::info!("contract code written to {} ({} bytes)", code_path, code_bytes.len());

    let abi_json = output.abi_to_json()?;
    let abi_path = format!("{}/abi.json", output_dir);
    fs::write(&abi_path, &abi_json).map_err(|error| anyhow::anyhow!("failed to write ABI {}: {}", abi_path, error))?;
    tracing::info!("ABI written to {}", abi_path);

    let defs_json = serde_json::to_string(&output.circuit_definitions)?;
    let defs_path = format!("{}/circuit_defs.json", output_dir);
    fs::write(&defs_path, &defs_json).map_err(|error| anyhow::anyhow!("failed to write circuit definitions {}: {}", defs_path, error))?;
    tracing::info!("circuit definitions written to {}", defs_path);

    let artifact_json = output.to_compilation_artifact_json()?;
    let artifact_path = format!("{}/compilation_artifact.json", output_dir);
    fs::write(&artifact_path, &artifact_json).map_err(|error| anyhow::anyhow!("failed to write compilation artifact {}: {}", artifact_path, error))?;
    tracing::info!("compilation artifact written to {}", artifact_path);

    println!("Compilation successful:");
    println!("  Methods: {}", output.method_count());
    println!("  State tree height: {}", output.state_tree_height());
    println!("  Contract code: {}", code_path);
    println!("  ABI: {}", abi_path);
    println!("  Circuit definitions: {}", defs_path);
    println!("  Compilation artifact: {}", artifact_path);

    Ok(())
}
