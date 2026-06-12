pub mod abi;
pub mod lower;
pub mod modules;
pub mod output;
pub mod parse;
pub mod sdk_key;
pub mod types;

use std::path::Path;

use anyhow::Result;
use lower::context::CompilerContext;
use modules::resolver::ModuleResolver;
use output::serialize::ContractOutput;
use parse::{ast::ModulePath, parser::Parser};
use sdk_key::context::{SDKKeyCompileOutput, SDKKeyCompilerContext};
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

/// Compile a PSY DSL source string as a software-defined key (SDK key).
///
/// SDK keys are custom ZK circuits that define authorization logic.
/// The contract must have an `authorize` method that defines the key's logic.
///
/// SDK key contracts can:
/// - Read contract state (read-only, no mutations)
/// - Introspect transaction info via `sdk.tx[n].field` where n is a constant
/// - Verify secp256k1 signatures via `psystd::secp256k1_verify()`
/// - Access blockchain context (checkpoint_id, user_id, etc.)
///
/// SDK key contracts CANNOT:
/// - Modify contract state (all state access is read-only)
/// - Emit events
/// - Make external contract calls
pub fn compile_sdk_key(source: &str) -> Result<SDKKeyCompileOutput> {
    let ast = Parser::new(source).parse_program()?;
    let resolved = Resolver::new().resolve(&ast)?;
    let checked = TypeChecker::new().check(&resolved)?;
    let mut compiler = SDKKeyCompilerContext::new(&checked);
    compiler.compile_sdk_key()
}

/// Compile a multi-file SDK key from a root file path.
pub fn compile_sdk_key_crate(root_file: &Path) -> Result<SDKKeyCompileOutput> {
    let resolved_crate = ModuleResolver::resolve_crate(root_file)?;
    let resolved = Resolver::new().resolve(&resolved_crate.merged_program)?;
    let checked = TypeChecker::new().check(&resolved)?;
    let mut compiler = SDKKeyCompilerContext::new(&checked);
    compiler.compile_sdk_key()
}

/// Compile a multi-file SDK key from pre-loaded source strings.
pub fn compile_sdk_key_from_sources(sources: &[(ModulePath, String)]) -> Result<SDKKeyCompileOutput> {
    let resolved_crate = ModuleResolver::resolve_from_sources(sources)?;
    let resolved = Resolver::new().resolve(&resolved_crate.merged_program)?;
    let checked = TypeChecker::new().check(&resolved)?;
    let mut compiler = SDKKeyCompilerContext::new(&checked);
    compiler.compile_sdk_key()
}
