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
    fs::create_dir_all(output_dir)?;

    // Compile: crate mode vs. single file
    let output = if args.is_crate {
        tracing::info!("compiling as multi-file crate");
        psy_compiler::compile_crate(source_path)?
    } else {
        tracing::info!("compiling single file");
        let source = fs::read_to_string(source_path)?;
        psy_compiler::compile(&source)?
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
        fs::write(&abi_path, &abi_json)?;
        println!("ABI written to {}", abi_path);
        return Ok(());
    }

    // Full output: contract_code.bin, abi.json, circuit_defs.json
    let code_bytes = output.to_bytes()?;
    let code_path = format!("{}/contract_code.bin", output_dir);
    fs::write(&code_path, &code_bytes)?;
    tracing::info!("contract code written to {} ({} bytes)", code_path, code_bytes.len());

    let abi_json = output.abi_to_json()?;
    let abi_path = format!("{}/abi.json", output_dir);
    fs::write(&abi_path, &abi_json)?;
    tracing::info!("ABI written to {}", abi_path);

    let defs_json = serde_json::to_string(&output.circuit_definitions)?;
    let defs_path = format!("{}/circuit_defs.json", output_dir);
    fs::write(&defs_path, &defs_json)?;
    tracing::info!("circuit definitions written to {}", defs_path);

    println!("Compilation successful:");
    println!("  Methods: {}", output.method_count());
    println!("  State tree height: {}", output.state_tree_height());
    println!("  Contract code: {}", code_path);
    println!("  ABI: {}", abi_path);
    println!("  Circuit definitions: {}", defs_path);

    Ok(())
}
