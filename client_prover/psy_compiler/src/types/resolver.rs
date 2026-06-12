use std::collections::HashMap;

use anyhow::{bail, Result};

use super::layout::*;
use crate::parse::ast::*;

/// A resolved trait definition.
#[derive(Debug, Clone)]
pub struct ResolvedTrait {
    pub name: String,
    pub methods: Vec<ResolvedTraitMethod>,
}

/// A method signature from a trait definition.
#[derive(Debug, Clone)]
pub struct ResolvedTraitMethod {
    pub name: String,
    pub params: Vec<ResolvedParam>,
    pub return_type: Option<ResolvedType>,
    pub has_default: bool,
}

/// The result of name resolution and layout computation.
#[derive(Debug, Clone)]
pub struct ResolvedProgram {
    pub constants: HashMap<String, u64>,
    pub struct_layouts: HashMap<String, StructLayout>,
    pub contract_layout: Option<ContractStateLayout>,
    pub contract_name: Option<String>,
    pub impl_block: Option<ResolvedImplBlock>,
    pub traits: HashMap<String, ResolvedTrait>,
    pub trait_impls: Vec<ResolvedTraitImpl>,
    pub ast: Program,
}

/// A resolved trait implementation.
#[derive(Debug, Clone)]
pub struct ResolvedTraitImpl {
    pub trait_name: String,
    pub target_name: String,
    pub methods: Vec<ResolvedMethod>,
}

#[derive(Debug, Clone)]
pub struct ResolvedImplBlock {
    pub contract_name: String,
    pub methods: Vec<ResolvedMethod>,
}

#[derive(Debug, Clone)]
pub struct ResolvedMethod {
    pub name: String,
    pub is_contract_method: bool,
    pub is_pub: bool,
    pub generics: Vec<ConstGenericParam>,
    pub params: Vec<ResolvedParam>,
    pub return_type: Option<ResolvedType>,
    pub body: Vec<Stmt>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct ResolvedParam {
    pub name: String,
    pub ty: ResolvedParamType,
}

#[derive(Debug, Clone)]
pub enum ResolvedParamType {
    SelfRef { mutable: bool },
    Typed { ty: ResolvedType, is_ref: bool },
}

pub struct Resolver;

impl Resolver {
    pub fn new() -> Self {
        Resolver
    }

    pub fn resolve(&self, program: &Program) -> Result<ResolvedProgram> {
        let mut constants: HashMap<String, u64> = HashMap::new();
        let mut struct_layouts: HashMap<String, StructLayout> = HashMap::new();
        let mut struct_names: HashMap<String, bool> = HashMap::new();
        let mut contract_layout: Option<ContractStateLayout> = None;
        let mut contract_name: Option<String> = None;
        let mut impl_block: Option<ResolvedImplBlock> = None;
        let mut traits: HashMap<String, ResolvedTrait> = HashMap::new();
        let mut trait_impls: Vec<ResolvedTraitImpl> = Vec::new();

        // First pass: collect all struct names (for forward references)
        for item in &program.items {
            match item {
                Item::StructDef(sd) => {
                    struct_names.insert(sd.name.clone(), true);
                }
                Item::ContractDef(cd) => {
                    struct_names.insert(cd.name.clone(), true);
                }
                _ => {}
            }
        }

        // Second pass: resolve items in order
        for item in &program.items {
            match item {
                Item::ConstDecl(cd) => {
                    let value = self.eval_const_expr(&cd.value, &constants)?;
                    constants.insert(cd.name.clone(), value);
                }
                Item::StructDef(sd) => {
                    let fields: Vec<(String, ResolvedType)> = sd
                        .fields
                        .iter()
                        .map(|f| {
                            let ty = resolve_type(&f.ty, &constants, &struct_names)?;
                            Ok((f.name.clone(), ty))
                        })
                        .collect::<Result<_>>()?;

                    let layout = compute_struct_layout(&sd.name, &fields, &struct_layouts)?;
                    struct_layouts.insert(sd.name.clone(), layout);
                }
                Item::ContractDef(cd) => {
                    let fields: Vec<(String, ResolvedType)> = cd
                        .fields
                        .iter()
                        .map(|f| {
                            let ty = resolve_type(&f.ty, &constants, &struct_names)?;
                            Ok((f.name.clone(), ty))
                        })
                        .collect::<Result<_>>()?;

                    let layout = compute_contract_layout(&cd.name, &fields, &struct_layouts)?;
                    contract_layout = Some(layout);
                    contract_name = Some(cd.name.clone());
                }
                Item::ImplBlock(ib) => {
                    let resolved_methods: Vec<ResolvedMethod> = ib
                        .methods
                        .iter()
                        .map(|m| self.resolve_method(m, &constants, &struct_names))
                        .collect::<Result<_>>()?;

                    impl_block = Some(ResolvedImplBlock {
                        contract_name: ib.contract_name.clone(),
                        methods: resolved_methods,
                    });
                }
                Item::TraitDef(td) => {
                    let resolved_methods: Vec<ResolvedTraitMethod> = td
                        .methods
                        .iter()
                        .map(|m| {
                            let params: Vec<ResolvedParam> = m
                                .params
                                .iter()
                                .map(|p| {
                                    let ty = match &p.ty {
                                        ParamType::SelfRef { mutable } => ResolvedParamType::SelfRef { mutable: *mutable },
                                        ParamType::Typed { ty, is_ref, .. } => {
                                            let resolved = resolve_type(ty, &constants, &struct_names)?;
                                            ResolvedParamType::Typed {
                                                ty: resolved,
                                                is_ref: *is_ref,
                                            }
                                        }
                                    };
                                    Ok(ResolvedParam { name: p.name.clone(), ty })
                                })
                                .collect::<Result<_>>()?;

                            let return_type = m.return_type.as_ref().map(|t| resolve_type(t, &constants, &struct_names)).transpose()?;

                            Ok(ResolvedTraitMethod {
                                name: m.name.clone(),
                                params,
                                return_type,
                                has_default: m.default_body.is_some(),
                            })
                        })
                        .collect::<Result<_>>()?;

                    traits.insert(
                        td.name.clone(),
                        ResolvedTrait {
                            name: td.name.clone(),
                            methods: resolved_methods,
                        },
                    );
                }
                Item::TraitImplBlock(tib) => {
                    // Verify the trait exists
                    if !traits.contains_key(&tib.trait_name) {
                        bail!("Unknown trait: {}", tib.trait_name);
                    }

                    let resolved_methods: Vec<ResolvedMethod> = tib
                        .methods
                        .iter()
                        .map(|m| self.resolve_method(m, &constants, &struct_names))
                        .collect::<Result<_>>()?;

                    trait_impls.push(ResolvedTraitImpl {
                        trait_name: tib.trait_name.clone(),
                        target_name: tib.target_name.clone(),
                        methods: resolved_methods,
                    });
                }
                // ModDecl and UseDecl are handled by the module resolver before
                // reaching this stage; they don't need processing here.
                Item::ModDecl(_) | Item::UseDecl(_) => {}
            }
        }

        Ok(ResolvedProgram {
            constants,
            struct_layouts,
            contract_layout,
            contract_name,
            impl_block,
            traits,
            trait_impls,
            ast: program.clone(),
        })
    }

    fn resolve_method(&self, method: &MethodDef, constants: &HashMap<String, u64>, struct_names: &HashMap<String, bool>) -> Result<ResolvedMethod> {
        // Add const generic parameters as temporary constants for type resolution.
        // The actual values are determined at monomorphization time during lowering.
        // We use a placeholder value of 0 here since helper methods with const generics
        // are inlined and their parameter types are not used to allocate circuit
        // inputs.
        let mut method_constants = constants.clone();
        for g in &method.generics {
            method_constants.insert(g.name.clone(), 0);
        }

        let params: Vec<ResolvedParam> = method
            .params
            .iter()
            .map(|p| {
                let ty = match &p.ty {
                    ParamType::SelfRef { mutable } => ResolvedParamType::SelfRef { mutable: *mutable },
                    ParamType::Typed { ty, is_ref, .. } => {
                        let resolved = resolve_type(ty, &method_constants, struct_names)?;
                        ResolvedParamType::Typed {
                            ty: resolved,
                            is_ref: *is_ref,
                        }
                    }
                };
                Ok(ResolvedParam { name: p.name.clone(), ty })
            })
            .collect::<Result<_>>()?;

        let return_type = method
            .return_type
            .as_ref()
            .map(|t| resolve_type(t, constants, struct_names))
            .transpose()?;

        Ok(ResolvedMethod {
            name: method.name.clone(),
            is_contract_method: method.is_contract_method,
            is_pub: method.is_pub,
            generics: method.generics.clone(),
            params,
            return_type,
            body: method.body.clone(),
            span: method.span,
        })
    }

    /// Evaluate a const expression to a u64 value.
    fn eval_const_expr(&self, expr: &Expr, constants: &HashMap<String, u64>) -> Result<u64> {
        match expr {
            Expr::IntLiteral(n, _) => Ok(*n),
            Expr::Ident(name, _) => constants.get(name).copied().ok_or_else(|| anyhow::anyhow!("Unknown constant: {}", name)),
            Expr::BinaryOp(left, op, right, _) => {
                let l = self.eval_const_expr(left, constants)?;
                let r = self.eval_const_expr(right, constants)?;
                match op {
                    BinOp::Add => Ok(l + r),
                    BinOp::Sub => Ok(l - r),
                    BinOp::Mul => Ok(l * r),
                    BinOp::Div => Ok(l / r),
                    BinOp::Mod => Ok(l % r),
                    BinOp::Shl => Ok(l << r),
                    BinOp::Shr => Ok(l >> r),
                    _ => bail!("Unsupported operator in const expression: {:?}", op),
                }
            }
            _ => bail!("Non-constant expression in const declaration"),
        }
    }
}
