pub mod abi;
pub mod lower;
pub mod modules;
pub mod output;
pub mod parse;
pub mod sd_key;
pub mod types;

use std::path::Path;

use anyhow::Result;
use lower::context::CompilerContext;
use modules::resolver::ModuleResolver;
use output::serialize::ContractOutput;
use parse::{ast::ModulePath, parser::Parser};
use sd_key::context::{SDKeyCompileOutput, SDKeyCompilerContext};
use types::{checker::TypeChecker, resolver::Resolver};

/// Compile a PSY DSL source string into a ContractOutput
/// (ContractCodeDefinition + ABI).
///
/// This is the single-file compilation entry point (existing API, unchanged).
pub fn compile(source: &str) -> Result<ContractOutput> {
    // Phase 1: Parse
    let ast = Parser::new(source).parse_program()?;

    // Phase 2: Resolve names and types
    let resolved = Resolver::new().resolve(&ast)?;

    // Phase 3: Type check
    let checked = TypeChecker::new().check(&resolved)?;

    // Phase 4: Lower to DPN IR + serialize
    let mut compiler = CompilerContext::new(&checked);
    let output = compiler.compile_contract()?;

    Ok(output)
}

/// Compile a multi-file contract crate from a root file path.
///
/// The root file is typically `lib.psy.rs` and may contain `mod` declarations
/// that reference other `.psy.rs` files in the same directory or
/// subdirectories.
pub fn compile_crate(root_file: &Path) -> Result<ContractOutput> {
    // Phase 0: Resolve modules (load all files, merge AST)
    let resolved_crate = ModuleResolver::resolve_crate(root_file)?;

    // Phase 1-4: Compile the merged program using existing pipeline
    let resolved = Resolver::new().resolve(&resolved_crate.merged_program)?;
    let checked = TypeChecker::new().check(&resolved)?;
    let mut compiler = CompilerContext::new(&checked);
    let output = compiler.compile_contract()?;

    Ok(output)
}

/// Compile a multi-file contract crate from pre-loaded source strings.
///
/// Each entry is a (module_path, source_text) pair where module_path is
/// empty for the root module, or `["types"]`, `["helpers", "math"]`, etc.
pub fn compile_crate_from_sources(sources: &[(ModulePath, String)]) -> Result<ContractOutput> {
    // Phase 0: Resolve modules from sources
    let resolved_crate = ModuleResolver::resolve_from_sources(sources)?;

    // Phase 1-4: Compile the merged program
    let resolved = Resolver::new().resolve(&resolved_crate.merged_program)?;
    let checked = TypeChecker::new().check(&resolved)?;
    let mut compiler = CompilerContext::new(&checked);
    let output = compiler.compile_contract()?;

    Ok(output)
}

/// Compile a PSY DSL source string as a software-defined key (SD key).
///
/// SD keys are custom ZK circuits that define authorization logic.
/// The contract must have an `authorize` method that defines the key's logic.
///
/// SD key contracts can:
/// - Read contract state (read-only, no mutations)
/// - Introspect transaction info via `sd.tx[n].field` where n is a constant
/// - Verify secp256k1 signatures via `psystd::secp256k1_verify()`
/// - Access blockchain context (checkpoint_id, user_id, etc.)
///
/// SD key contracts CANNOT:
/// - Modify contract state (all state access is read-only)
/// - Emit events
/// - Make external contract calls
pub fn compile_sd_key(source: &str) -> Result<SDKeyCompileOutput> {
    let ast = Parser::new(source).parse_program()?;
    let resolved = Resolver::new().resolve(&ast)?;
    let checked = TypeChecker::new().check(&resolved)?;
    let mut compiler = SDKeyCompilerContext::new(&checked);
    compiler.compile_sd_key()
}

/// Compile an SD key bound to the contract whose state it may read.
pub fn compile_sd_key_for_contract(source: &str, contract_id: u64) -> Result<SDKeyCompileOutput> {
    let ast = Parser::new(source).parse_program()?;
    let resolved = Resolver::new().resolve(&ast)?;
    let checked = TypeChecker::new().check(&resolved)?;
    let mut compiler = SDKeyCompilerContext::new_for_contract(&checked, contract_id);
    compiler.compile_sd_key()
}

/// Compile a multi-file SD key from a root file path.
pub fn compile_sd_key_crate(root_file: &Path) -> Result<SDKeyCompileOutput> {
    let resolved_crate = ModuleResolver::resolve_crate(root_file)?;
    let resolved = Resolver::new().resolve(&resolved_crate.merged_program)?;
    let checked = TypeChecker::new().check(&resolved)?;
    let mut compiler = SDKeyCompilerContext::new(&checked);
    compiler.compile_sd_key()
}

pub fn compile_sd_key_crate_for_contract(root_file: &Path, contract_id: u64) -> Result<SDKeyCompileOutput> {
    let resolved_crate = ModuleResolver::resolve_crate(root_file)?;
    let resolved = Resolver::new().resolve(&resolved_crate.merged_program)?;
    let checked = TypeChecker::new().check(&resolved)?;
    let mut compiler = SDKeyCompilerContext::new_for_contract(&checked, contract_id);
    compiler.compile_sd_key()
}

/// Compile a multi-file SD key from pre-loaded source strings.
pub fn compile_sd_key_from_sources(sources: &[(ModulePath, String)]) -> Result<SDKeyCompileOutput> {
    let resolved_crate = ModuleResolver::resolve_from_sources(sources)?;
    let resolved = Resolver::new().resolve(&resolved_crate.merged_program)?;
    let checked = TypeChecker::new().check(&resolved)?;
    let mut compiler = SDKeyCompilerContext::new(&checked);
    compiler.compile_sd_key()
}

pub fn compile_sd_key_from_sources_for_contract(
    sources: &[(ModulePath, String)],
    contract_id: u64,
) -> Result<SDKeyCompileOutput> {
    let resolved_crate = ModuleResolver::resolve_from_sources(sources)?;
    let resolved = Resolver::new().resolve(&resolved_crate.merged_program)?;
    let checked = TypeChecker::new().check(&resolved)?;
    let mut compiler = SDKeyCompilerContext::new_for_contract(&checked, contract_id);
    compiler.compile_sd_key()
}
