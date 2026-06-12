//! Module resolver for multi-file PSY contracts.
//!
//! Resolves `mod` declarations by loading files from disk, parsing them,
//! and merging all items into a single unified AST with qualified names.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

use anyhow::{bail, Result};

use crate::parse::{ast::*, parser::Parser};

/// A resolved module from a single file
#[derive(Debug, Clone)]
pub struct ResolvedModule {
    /// Module path segments, e.g., `["helpers", "math"]`
    pub path: ModulePath,
    /// Original source text
    pub source: String,
    /// Absolute file path
    pub file_path: PathBuf,
    /// Parsed AST
    pub ast: Program,
    /// Whether this module is declared `pub`
    pub is_public: bool,
}

/// Result of resolving an entire crate
#[derive(Debug, Clone)]
pub struct ResolvedCrate {
    /// All modules in the crate
    pub modules: Vec<ResolvedModule>,
    /// Merged program with all items (qualified names applied)
    pub merged_program: Program,
}

/// Resolves multi-file contracts into a merged AST
pub struct ModuleResolver {
    /// Root directory of the contract crate
    _root_dir: PathBuf,
    /// Track visited modules to detect circular dependencies
    visited: HashSet<PathBuf>,
}

impl ModuleResolver {
    /// Resolve all modules starting from the crate root file.
    ///
    /// The root file is expected to be `lib.psy.rs` or a single `.psy.rs` file.
    pub fn resolve_crate(root_file: &Path) -> Result<ResolvedCrate> {
        let root_dir = root_file.parent().unwrap_or_else(|| Path::new(".")).to_path_buf();

        let mut resolver = ModuleResolver {
            _root_dir: root_dir.clone(),
            visited: HashSet::new(),
        };

        let source = std::fs::read_to_string(root_file).map_err(|e| anyhow::anyhow!("Cannot read root file {}: {}", root_file.display(), e))?;

        let mut parser = Parser::new(&source);
        let ast = parser.parse_program()?;

        let root_module = ResolvedModule {
            path: vec![],
            source: source.clone(),
            file_path: root_file.to_path_buf(),
            ast: ast.clone(),
            is_public: true,
        };

        resolver.visited.insert(root_file.to_path_buf());

        let mut all_modules = vec![root_module];

        // Recursively resolve mod declarations
        resolver.resolve_mod_declarations(&root_dir, &ast, &[], &mut all_modules)?;

        // Merge all modules into a single program
        let merged_program = Self::merge_modules(&all_modules)?;

        Ok(ResolvedCrate {
            modules: all_modules,
            merged_program,
        })
    }

    /// Resolve from pre-loaded sources (for testing or embedded use).
    ///
    /// When all sources are provided up-front (as in the IDE), items from
    /// non-root modules are automatically made available by their unqualified
    /// names so that explicit `mod` / `use` declarations are optional.
    pub fn resolve_from_sources(sources: &[(ModulePath, String)]) -> Result<ResolvedCrate> {
        let mut all_modules = Vec::new();

        for (path, source) in sources {
            let mut parser = Parser::new(source);
            let ast = parser.parse_program()?;

            all_modules.push(ResolvedModule {
                path: path.clone(),
                source: source.clone(),
                file_path: PathBuf::from(path.join("/")),
                ast,
                is_public: true,
            });
        }

        let merged_program = Self::merge_modules_auto_import(&all_modules)?;

        Ok(ResolvedCrate {
            modules: all_modules,
            merged_program,
        })
    }

    /// Recursively resolve mod declarations in an AST
    fn resolve_mod_declarations(
        &mut self,
        parent_dir: &Path,
        ast: &Program,
        parent_path: &[String],
        modules: &mut Vec<ResolvedModule>,
    ) -> Result<()> {
        for item in &ast.items {
            if let Item::ModDecl(mod_decl) = item {
                // psystd is a built-in standard library, not a file module
                if mod_decl.name == "psystd" {
                    continue;
                }
                let file_path = self.resolve_mod_file(parent_dir, &mod_decl.name)?;

                // Check for circular dependencies
                let canonical = file_path.canonicalize().unwrap_or_else(|_| file_path.clone());
                if self.visited.contains(&canonical) {
                    bail!(
                        "Circular module dependency detected: {} (from module path {:?})",
                        file_path.display(),
                        parent_path
                    );
                }
                self.visited.insert(canonical);

                let source = std::fs::read_to_string(&file_path).map_err(|e| {
                    anyhow::anyhow!(
                        "Cannot read module file {}: {} (declared at offset {})",
                        file_path.display(),
                        e,
                        mod_decl.span.start
                    )
                })?;

                let mut parser = Parser::new(&source);
                let mod_ast = parser.parse_program()?;

                let mut mod_path = parent_path.to_vec();
                mod_path.push(mod_decl.name.clone());

                let resolved = ResolvedModule {
                    path: mod_path.clone(),
                    source: source.clone(),
                    file_path: file_path.clone(),
                    ast: mod_ast.clone(),
                    is_public: mod_decl.is_public,
                };
                modules.push(resolved);

                // Recursively resolve nested mod declarations
                let child_dir = if file_path.file_name().map(|f| f == "mod.psy.rs").unwrap_or(false) {
                    file_path.parent().unwrap().to_path_buf()
                } else {
                    file_path.parent().unwrap().to_path_buf()
                };

                self.resolve_mod_declarations(&child_dir, &mod_ast, &mod_path, modules)?;
            }
        }
        Ok(())
    }

    /// Resolve a module name to a file path.
    ///
    /// Tries: `parent_dir/name.psy.rs`, then `parent_dir/name/mod.psy.rs`
    fn resolve_mod_file(&self, parent_dir: &Path, mod_name: &str) -> Result<PathBuf> {
        // Try name.psy.rs first
        let file_path = parent_dir.join(format!("{}.psy.rs", mod_name));
        if file_path.exists() {
            return Ok(file_path);
        }

        // Try name/mod.psy.rs
        let dir_path = parent_dir.join(mod_name).join("mod.psy.rs");
        if dir_path.exists() {
            return Ok(dir_path);
        }

        bail!(
            "Module `{}` not found. Looked for:\n  - {}\n  - {}",
            mod_name,
            file_path.display(),
            dir_path.display()
        )
    }

    /// Merge all modules into a single Program.
    ///
    /// Items from child modules get their names qualified with the module path.
    /// `use` declarations are processed to create import mappings.
    fn merge_modules(modules: &[ResolvedModule]) -> Result<Program> {
        Self::merge_modules_inner(modules, false)
    }

    /// Like `merge_modules` but with auto-import enabled: all items from
    /// non-root modules are automatically available by their unqualified names.
    /// Used by `resolve_from_sources` where the IDE provides all files
    /// up-front.
    fn merge_modules_auto_import(modules: &[ResolvedModule]) -> Result<Program> {
        Self::merge_modules_inner(modules, true)
    }

    fn merge_modules_inner(modules: &[ResolvedModule], auto_import: bool) -> Result<Program> {
        let mut merged_items = Vec::new();
        let mut contract_count = 0;
        let mut impl_count = 0;

        // Track which modules already have explicit glob imports
        let mut glob_imported: HashSet<Vec<String>> = HashSet::new();
        if auto_import {
            for module in modules {
                for item in &module.ast.items {
                    if let Item::UseDecl(use_decl) = item {
                        if use_decl.is_glob {
                            glob_imported.insert(use_decl.path.clone());
                        }
                    }
                }
            }
        }

        for module in modules {
            let prefix = &module.path;

            for item in &module.ast.items {
                match item {
                    // Skip mod and use declarations in merged output
                    Item::ModDecl(_) | Item::UseDecl(_) => continue,

                    Item::ConstDecl(c) => {
                        let mut qualified = c.clone();
                        if !prefix.is_empty() {
                            qualified.name = Self::qualify_name(prefix, &c.name);
                        }
                        merged_items.push(Item::ConstDecl(qualified));
                    }

                    Item::StructDef(s) => {
                        let mut qualified = s.clone();
                        if !prefix.is_empty() {
                            qualified.name = Self::qualify_name(prefix, &s.name);
                        }
                        merged_items.push(Item::StructDef(qualified));
                    }

                    Item::ContractDef(c) => {
                        contract_count += 1;
                        if contract_count > 1 {
                            bail!(
                                "Multiple #[contract] definitions found. Only one contract per crate is allowed. \
                                 Second contract '{}' found in module {:?}",
                                c.name,
                                prefix
                            );
                        }
                        // Contract always uses its original name (no qualification)
                        merged_items.push(Item::ContractDef(c.clone()));
                    }

                    Item::ImplBlock(i) => {
                        impl_count += 1;
                        if impl_count > 1 {
                            bail!(
                                "Multiple #[contract_implementation] blocks found. Only one per crate is allowed. \
                                 Found in module {:?}",
                                prefix
                            );
                        }
                        // Impl block always refers to the contract by original name
                        merged_items.push(Item::ImplBlock(i.clone()));
                    }

                    Item::TraitDef(t) => {
                        merged_items.push(Item::TraitDef(t.clone()));
                    }

                    Item::TraitImplBlock(ti) => {
                        merged_items.push(Item::TraitImplBlock(ti.clone()));
                    }
                }
            }
        }

        // Process explicit use declarations
        for module in modules {
            for item in &module.ast.items {
                if let Item::UseDecl(use_decl) = item {
                    Self::process_use_decl(use_decl, modules, &mut merged_items)?;
                }
            }
        }

        // Auto-import: for non-root modules that don't already have an explicit
        // glob import, add unqualified aliases for all their public items.
        // This makes types from other files available without requiring
        // explicit `pub mod` / `use` declarations in the IDE.
        if auto_import {
            for module in modules {
                if module.path.is_empty() {
                    continue; // Root module items already have unqualified
                              // names
                }
                if glob_imported.contains(&module.path) {
                    continue; // Already handled by explicit use declaration
                }
                for item in &module.ast.items {
                    match item {
                        Item::ConstDecl(c) => {
                            let mut alias = c.clone();
                            alias.name = c.name.clone();
                            merged_items.push(Item::ConstDecl(alias));
                        }
                        Item::StructDef(s) => {
                            let mut alias = s.clone();
                            alias.name = s.name.clone();
                            merged_items.push(Item::StructDef(alias));
                        }
                        _ => {}
                    }
                }
            }
        }

        // Reorder merged items so that dependencies are satisfied:
        // ConstDecls first, then StructDefs, then TraitDefs, then ContractDefs, then
        // ImplBlocks, then TraitImplBlocks. This ensures struct layouts are
        // computed before contracts reference them.
        let mut const_items = Vec::new();
        let mut struct_items = Vec::new();
        let mut trait_items = Vec::new();
        let mut contract_items = Vec::new();
        let mut impl_items = Vec::new();
        let mut trait_impl_items = Vec::new();

        for item in merged_items {
            match &item {
                Item::ConstDecl(_) => const_items.push(item),
                Item::StructDef(_) => struct_items.push(item),
                Item::TraitDef(_) => trait_items.push(item),
                Item::ContractDef(_) => contract_items.push(item),
                Item::ImplBlock(_) => impl_items.push(item),
                Item::TraitImplBlock(_) => trait_impl_items.push(item),
                _ => {}
            }
        }

        let mut ordered_items = Vec::new();
        ordered_items.extend(const_items);
        ordered_items.extend(struct_items);
        ordered_items.extend(trait_items);
        ordered_items.extend(contract_items);
        ordered_items.extend(impl_items);
        ordered_items.extend(trait_impl_items);

        Ok(Program { items: ordered_items })
    }

    /// Process a `use` declaration by creating alias items in the merged
    /// program
    fn process_use_decl(use_decl: &UseDecl, modules: &[ResolvedModule], merged_items: &mut Vec<Item>) -> Result<()> {
        // psystd is a built-in standard library — its functions are handled
        // directly by the compiler. Skip all psystd use declarations.
        if use_decl.path.first().map(|s| s.as_str()) == Some("psystd") {
            return Ok(());
        }

        if use_decl.is_glob {
            // `use module::*` — find the target module and import all pub items
            let target_path = &use_decl.path;
            for module in modules {
                if module.path == *target_path {
                    for item in &module.ast.items {
                        match item {
                            Item::ConstDecl(c) => {
                                let qualified_name = Self::qualify_name(target_path, &c.name);
                                // Add an alias from unqualified name to qualified
                                let mut alias = c.clone();
                                alias.name = c.name.clone();
                                // Create a const that references the qualified version
                                // For simplicity, we duplicate the const with its original name
                                merged_items.push(Item::ConstDecl(alias));
                                let _ = qualified_name;
                            }
                            Item::StructDef(s) => {
                                // Add struct with its original (unqualified) name
                                let mut alias = s.clone();
                                alias.name = s.name.clone();
                                merged_items.push(Item::StructDef(alias));
                            }
                            _ => {}
                        }
                    }
                    break;
                }
            }
        }
        // Non-glob use declarations are handled during name resolution
        Ok(())
    }

    /// Create a qualified name by joining module path with item name
    fn qualify_name(prefix: &[String], name: &str) -> String {
        let mut parts = prefix.to_vec();
        parts.push(name.to_string());
        parts.join("::")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qualify_name() {
        assert_eq!(
            ModuleResolver::qualify_name(&["helpers".into(), "math".into()], "max"),
            "helpers::math::max"
        );
        assert_eq!(ModuleResolver::qualify_name(&[], "Foo"), "Foo");
    }

    #[test]
    fn test_resolve_from_sources_single() {
        let sources = vec![(
            vec![],
            r#"
const X: usize = 42;

#[derive(FeltSized)]
pub struct Foo {
    pub a: Felt,
}
"#
            .to_string(),
        )];

        let crate_result = ModuleResolver::resolve_from_sources(&sources).unwrap();
        assert_eq!(crate_result.modules.len(), 1);
        // Merged program should have 2 items (const + struct)
        let items: Vec<_> = crate_result
            .merged_program
            .items
            .iter()
            .filter(|i| !matches!(i, Item::ModDecl(_) | Item::UseDecl(_)))
            .collect();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn test_resolve_from_sources_multi() {
        let sources = vec![
            (
                vec![],
                r#"
const X: usize = 42;
"#
                .to_string(),
            ),
            (
                vec!["types".to_string()],
                r#"
#[derive(FeltSized)]
pub struct TokenState {
    pub balance: Felt,
}
"#
                .to_string(),
            ),
        ];

        let crate_result = ModuleResolver::resolve_from_sources(&sources).unwrap();
        assert_eq!(crate_result.modules.len(), 2);
        // Merged program: const X + qualified struct types::TokenState
        let merged = &crate_result.merged_program;
        let struct_items: Vec<_> = merged
            .items
            .iter()
            .filter_map(|i| match i {
                Item::StructDef(s) => Some(s.name.as_str()),
                _ => None,
            })
            .collect();
        assert!(struct_items.contains(&"types::TokenState"));
    }

    #[test]
    fn test_resolve_from_sources_auto_import() {
        // Simulates the IDE scenario: types.psy.rs defines a struct,
        // lib.psy.rs uses it WITHOUT explicit `mod`/`use` declarations.
        let sources = vec![
            (
                vec![],
                r#"
const PSY_TOTAL_USERS: usize = 16;

#[contract]
pub struct MyToken {
    pub token_state: TokenBalance,
}

#[contract_implementation]
impl MyToken {
    #[contract_method]
    pub fn get(&mut self, ctx: &ChainContext) -> Felt {
        return self.token_state.amount;
    }
}
"#
                .to_string(),
            ),
            (
                vec!["types".to_string()],
                r#"
#[derive(FeltSized)]
pub struct TokenBalance {
    pub amount: Felt,
}
"#
                .to_string(),
            ),
        ];

        let crate_result = ModuleResolver::resolve_from_sources(&sources).unwrap();
        let merged = &crate_result.merged_program;

        // Should have both qualified and unqualified struct names
        let struct_names: Vec<_> = merged
            .items
            .iter()
            .filter_map(|i| match i {
                Item::StructDef(s) => Some(s.name.as_str()),
                _ => None,
            })
            .collect();
        assert!(struct_names.contains(&"types::TokenBalance"), "should have qualified name");
        assert!(struct_names.contains(&"TokenBalance"), "should have auto-imported unqualified name");
    }

    #[test]
    fn test_multiple_contracts_error() {
        let sources = vec![
            (
                vec![],
                r#"
#[contract]
pub struct ContractA {
    pub x: Felt,
}
"#
                .to_string(),
            ),
            (
                vec!["other".to_string()],
                r#"
#[contract]
pub struct ContractB {
    pub y: Felt,
}
"#
                .to_string(),
            ),
        ];

        let result = ModuleResolver::resolve_from_sources(&sources);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Multiple #[contract]"));
    }
}
