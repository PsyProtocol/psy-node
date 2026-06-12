use std::collections::HashMap;

use anyhow::{bail, Result};

use super::{layout::*, resolver::*};
use crate::parse::ast::*;

/// A fully type-checked program, ready for lowering.
#[derive(Debug, Clone)]
pub struct CheckedProgram {
    pub constants: HashMap<String, u64>,
    pub struct_layouts: HashMap<String, StructLayout>,
    pub contract_layout: ContractStateLayout,
    pub contract_name: String,
    pub methods: Vec<CheckedMethod>,
}

#[derive(Debug, Clone)]
pub struct CheckedMethod {
    pub name: String,
    pub is_contract_method: bool,
    pub is_pub: bool,
    pub generics: Vec<ConstGenericParam>,
    pub params: Vec<ResolvedParam>,
    pub return_type: Option<ResolvedType>,
    pub body: Vec<Stmt>,
    pub span: Span,
}

pub struct TypeChecker;

impl TypeChecker {
    pub fn new() -> Self {
        TypeChecker
    }

    /// Validate that all trait implementations satisfy their trait definitions.
    fn check_trait_impls(&self, resolved: &ResolvedProgram) -> Result<()> {
        for trait_impl in &resolved.trait_impls {
            let trait_def = resolved
                .traits
                .get(&trait_impl.trait_name)
                .ok_or_else(|| anyhow::anyhow!("Unknown trait: {}", trait_impl.trait_name))?;

            // Check that all non-default trait methods are implemented
            for trait_method in &trait_def.methods {
                if trait_method.has_default {
                    continue; // Default methods don't need to be implemented
                }
                let found = trait_impl.methods.iter().any(|m| m.name == trait_method.name);
                if !found {
                    bail!(
                        "Trait method '{}' from trait '{}' is not implemented for '{}'",
                        trait_method.name,
                        trait_impl.trait_name,
                        trait_impl.target_name
                    );
                }
            }

            // Check that all implemented methods match the trait signatures
            for impl_method in &trait_impl.methods {
                if let Some(trait_method) = trait_def.methods.iter().find(|m| m.name == impl_method.name) {
                    // Check parameter count (excluding self) matches
                    let impl_non_self: Vec<_> = impl_method
                        .params
                        .iter()
                        .filter(|p| !matches!(p.ty, ResolvedParamType::SelfRef { .. }))
                        .collect();
                    let trait_non_self: Vec<_> = trait_method
                        .params
                        .iter()
                        .filter(|p| !matches!(p.ty, ResolvedParamType::SelfRef { .. }))
                        .collect();

                    if impl_non_self.len() != trait_non_self.len() {
                        bail!(
                            "Method '{}' in impl for '{}' has {} parameters but trait '{}' expects {}",
                            impl_method.name,
                            trait_impl.target_name,
                            impl_non_self.len(),
                            trait_impl.trait_name,
                            trait_non_self.len()
                        );
                    }
                }
            }
        }
        Ok(())
    }

    pub fn check(&self, resolved: &ResolvedProgram) -> Result<CheckedProgram> {
        let contract_layout = resolved
            .contract_layout
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No contract definition found"))?
            .clone();
        let contract_name = resolved
            .contract_name
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No contract name found"))?
            .clone();

        let impl_block = resolved.impl_block.as_ref().ok_or_else(|| anyhow::anyhow!("No impl block found"))?;

        if impl_block.contract_name != contract_name {
            bail!("Impl block for {} does not match contract {}", impl_block.contract_name, contract_name);
        }

        // Validate trait implementations
        self.check_trait_impls(resolved)?;

        // Check each method
        let mut methods = Vec::new();
        let mut method_ids: HashMap<u32, String> = HashMap::new();

        for method in &impl_block.methods {
            // Validate contract method requirements
            if method.is_contract_method {
                self.check_contract_method_signature(method)?;

                // Check for duplicate method IDs
                let method_id = compute_method_id(&contract_name, &method.name, &method.params);
                if let Some(existing) = method_ids.get(&method_id) {
                    bail!(
                        "Method ID collision: {}::{} and {}::{} both produce ID 0x{:08x}",
                        contract_name,
                        method.name,
                        contract_name,
                        existing,
                        method_id
                    );
                }
                method_ids.insert(method_id, method.name.clone());
            }

            // Type check the method body
            self.check_method_body(method, &resolved.constants, &contract_layout, &resolved.struct_layouts)?;

            methods.push(CheckedMethod {
                name: method.name.clone(),
                is_contract_method: method.is_contract_method,
                is_pub: method.is_pub,
                generics: method.generics.clone(),
                params: method.params.clone(),
                return_type: method.return_type.clone(),
                body: method.body.clone(),
                span: method.span,
            });
        }

        Ok(CheckedProgram {
            constants: resolved.constants.clone(),
            struct_layouts: resolved.struct_layouts.clone(),
            contract_layout,
            contract_name,
            methods,
        })
    }

    fn check_contract_method_signature(&self, method: &ResolvedMethod) -> Result<()> {
        // Must have &mut self as first parameter
        if method.params.is_empty() {
            bail!("Contract method {} must have &mut self as first parameter", method.name);
        }
        match &method.params[0].ty {
            ResolvedParamType::SelfRef { mutable } => {
                if !mutable {
                    bail!("Contract method {} must take &mut self, not &self", method.name);
                }
            }
            _ => bail!("Contract method {} must have &mut self as first parameter", method.name),
        }

        // Must have ctx: &mut ChainContext as second parameter
        if method.params.len() < 2 {
            bail!("Contract method {} must have ctx: &mut ChainContext as second parameter", method.name);
        }
        match &method.params[1].ty {
            ResolvedParamType::Typed { ty, .. } => {
                if *ty != ResolvedType::Struct("ChainContext".to_string()) {
                    bail!("Contract method {} second parameter must be &mut ChainContext", method.name);
                }
            }
            _ => bail!("Contract method {} must have ctx: &mut ChainContext as second parameter", method.name),
        }

        Ok(())
    }

    fn check_method_body(
        &self,
        method: &ResolvedMethod,
        constants: &HashMap<String, u64>,
        contract_layout: &ContractStateLayout,
        struct_layouts: &HashMap<String, StructLayout>,
    ) -> Result<()> {
        // Build local variable scope
        let mut locals: HashMap<String, ResolvedType> = HashMap::new();

        // Add parameters
        for param in &method.params {
            match &param.ty {
                ResolvedParamType::SelfRef { .. } => {} // self is special
                ResolvedParamType::Typed { ty, .. } => {
                    locals.insert(param.name.clone(), ty.clone());
                }
            }
        }

        // Add const generic parameters as placeholder constants so that
        // for-loop bounds and other const evaluations can reference them.
        // Actual values are determined at monomorphization time during lowering.
        let method_constants = if method.generics.is_empty() {
            constants.clone()
        } else {
            let mut mc = constants.clone();
            for g in &method.generics {
                mc.insert(g.name.clone(), 0);
            }
            mc
        };

        // Check each statement (basic validation)
        for stmt in &method.body {
            self.check_stmt(stmt, &mut locals, &method_constants, contract_layout, struct_layouts)?;
        }

        Ok(())
    }

    fn check_stmt(
        &self,
        stmt: &Stmt,
        locals: &mut HashMap<String, ResolvedType>,
        constants: &HashMap<String, u64>,
        contract_layout: &ContractStateLayout,
        struct_layouts: &HashMap<String, StructLayout>,
    ) -> Result<()> {
        match stmt {
            Stmt::Let { name, ty, value, .. } => {
                // Infer type from value if not specified
                let resolved_ty = if let Some(explicit_ty) = ty {
                    let struct_names: HashMap<String, bool> = struct_layouts.keys().map(|k| (k.clone(), true)).collect();
                    resolve_type(explicit_ty, constants, &struct_names)?
                } else {
                    // Type inference — infer from value expression
                    self.infer_expr_type(value, locals, constants, contract_layout, struct_layouts)?
                };
                locals.insert(name.clone(), resolved_ty);
            }
            Stmt::Assign { .. } => {
                // Assignment type checking is done during lowering
            }
            Stmt::CompoundAssign { .. } => {
                // Compound assignment checked during lowering
            }
            Stmt::Expr(_) => {
                // Expression statements are always valid
            }
            Stmt::If {
                then_block,
                else_if_blocks,
                else_block,
                ..
            } => {
                for s in then_block {
                    self.check_stmt(s, locals, constants, contract_layout, struct_layouts)?;
                }
                for (_, block) in else_if_blocks {
                    for s in block {
                        self.check_stmt(s, locals, constants, contract_layout, struct_layouts)?;
                    }
                }
                if let Some(block) = else_block {
                    for s in block {
                        self.check_stmt(s, locals, constants, contract_layout, struct_layouts)?;
                    }
                }
            }
            Stmt::For { var, start, end, body, .. } => {
                // Check that bounds are compile-time constants
                let start_val = self.try_eval_const(start, constants);
                let end_val = self.try_eval_const(end, constants);
                if start_val.is_none() || end_val.is_none() {
                    bail!("For loop bounds must be compile-time constants");
                }
                let mut inner_locals = locals.clone();
                inner_locals.insert(var.clone(), ResolvedType::U32);
                for s in body {
                    self.check_stmt(s, &mut inner_locals, constants, contract_layout, struct_layouts)?;
                }
            }
            Stmt::While { body, .. } => {
                // While loops are unrolled at compile time, similar to for loops.
                // The condition must be compile-time evaluable (finite iterations).
                for s in body {
                    self.check_stmt(s, locals, constants, contract_layout, struct_layouts)?;
                }
            }
            Stmt::Return { .. } => {}
        }
        Ok(())
    }

    fn infer_expr_type(
        &self,
        expr: &Expr,
        locals: &HashMap<String, ResolvedType>,
        constants: &HashMap<String, u64>,
        contract_layout: &ContractStateLayout,
        struct_layouts: &HashMap<String, StructLayout>,
    ) -> Result<ResolvedType> {
        match expr {
            Expr::IntLiteral(_, _) => Ok(ResolvedType::Felt),
            Expr::BoolLiteral(_, _) => Ok(ResolvedType::Bool),
            Expr::StringLiteral(_, _) => Ok(ResolvedType::Felt), // strings are only for error messages
            Expr::Ident(name, _) => {
                if let Some(ty) = locals.get(name) {
                    Ok(ty.clone())
                } else if constants.contains_key(name) {
                    Ok(ResolvedType::Felt)
                } else {
                    Ok(ResolvedType::Felt) // default
                }
            }
            Expr::FieldAccess(_, _, _) => Ok(ResolvedType::Felt), // simplified
            Expr::IndexAccess(_, _, _) => Ok(ResolvedType::Felt),
            Expr::BinaryOp(left, op, _, _) => match op {
                BinOp::Eq | BinOp::Neq | BinOp::Lt | BinOp::Lte | BinOp::Gt | BinOp::Gte => Ok(ResolvedType::Bool),
                BinOp::And | BinOp::Or => Ok(ResolvedType::Bool),
                _ => self.infer_expr_type(left, locals, constants, contract_layout, struct_layouts),
            },
            Expr::UnaryOp(UnaryOp::Not, _, _) => Ok(ResolvedType::Bool),
            Expr::UnaryOp(UnaryOp::Neg, inner, _) => self.infer_expr_type(inner, locals, constants, contract_layout, struct_layouts),
            Expr::MethodCall { method, receiver, .. } => {
                match method.as_str() {
                    "to_felt" | "as_felt" => Ok(ResolvedType::Felt),
                    "to_u32" | "as_u32" => Ok(ResolvedType::U32),
                    "to_felts" => Ok(ResolvedType::Array {
                        element: Box::new(ResolvedType::Felt),
                        count: 0, // unknown at type-check time
                    }),
                    "concat" => Ok(ResolvedType::Array {
                        element: Box::new(ResolvedType::Felt),
                        count: 0,
                    }),
                    "into" => {
                        // Best-effort: infer from receiver type
                        let recv_ty = self.infer_expr_type(receiver, locals, constants, contract_layout, struct_layouts)?;
                        match recv_ty {
                            ResolvedType::Bool | ResolvedType::U32 => Ok(ResolvedType::Felt),
                            ResolvedType::Array { ref element, count } if count == 4 => match element.as_ref() {
                                ResolvedType::Felt | ResolvedType::Bool | ResolvedType::U32 => Ok(ResolvedType::Hash),
                                _ => Ok(recv_ty),
                            },
                            _ => Ok(recv_ty),
                        }
                    }
                    _ => Ok(ResolvedType::Felt),
                }
            }
            Expr::FunctionCall { name, .. } => {
                match name.as_str() {
                    "require" | "psystd::emit_event" => Ok(ResolvedType::Bool), // void
                    "psystd::poseidon_hash" | "psystd::poseidon_two_to_one" => Ok(ResolvedType::Hash),
                    "psystd::keccak256" | "psystd::keccak_two_to_one" => Ok(ResolvedType::Array {
                        element: Box::new(ResolvedType::U32),
                        count: 8,
                    }),
                    "psystd::secp256k1_verify" | "psystd::cast_bool" => Ok(ResolvedType::Bool),
                    "psystd::cast_u32" => Ok(ResolvedType::U32),
                    "psystd::exp" | "psystd::field_inverse" | "psystd::sum_bits" => Ok(ResolvedType::Felt),
                    "psystd::split_bits" => Ok(ResolvedType::Array {
                        element: Box::new(ResolvedType::Bool),
                        count: 0, // dynamic at type-check time
                    }),
                    _ => Ok(ResolvedType::Felt),
                }
            }
            Expr::ArrayLiteral(elements, _) => {
                if elements.is_empty() {
                    Ok(ResolvedType::Array {
                        element: Box::new(ResolvedType::Felt),
                        count: 0,
                    })
                } else {
                    let elem_ty = self.infer_expr_type(&elements[0], locals, constants, contract_layout, struct_layouts)?;
                    Ok(ResolvedType::Array {
                        element: Box::new(elem_ty),
                        count: elements.len(),
                    })
                }
            }
            Expr::StructLiteral { name, .. } => Ok(ResolvedType::Struct(name.clone())),
            Expr::TypedContractAccess { .. } => Ok(ResolvedType::Felt),
        }
    }

    fn try_eval_const(&self, expr: &Expr, constants: &HashMap<String, u64>) -> Option<u64> {
        match expr {
            Expr::IntLiteral(n, _) => Some(*n),
            Expr::Ident(name, _) => constants.get(name).copied(),
            Expr::BinaryOp(left, op, right, _) => {
                let l = self.try_eval_const(left, constants)?;
                let r = self.try_eval_const(right, constants)?;
                match op {
                    BinOp::Add => Some(l + r),
                    BinOp::Sub => Some(l - r),
                    BinOp::Mul => Some(l * r),
                    BinOp::Div => Some(l / r),
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

/// Compute method ID from contract + method name + params.
pub fn compute_method_id(contract_name: &str, method_name: &str, params: &[ResolvedParam]) -> u32 {
    use sha2::{Digest, Sha256};

    let param_types: Vec<String> = params
        .iter()
        .filter_map(|p| match &p.ty {
            ResolvedParamType::SelfRef { .. } => None,
            ResolvedParamType::Typed { ty, .. } => {
                if *ty == ResolvedType::Struct("ChainContext".to_string()) {
                    None // ChainContext is implicit
                } else {
                    Some(format!("{:?}", ty))
                }
            }
        })
        .collect();

    let signature = format!("{}::{}({})", contract_name, method_name, param_types.join(","));
    let hash = Sha256::digest(signature.as_bytes());
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}
