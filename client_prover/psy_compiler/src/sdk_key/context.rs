use std::collections::HashMap;

use anyhow::{bail, Result};
use psy_client_data::dpn::sd_key::SDKeyConfig;
use psy_vm::dpn::{
    ops::{context_trait::DPNContext, exec_context::QExecContext, sym_felt::SymFeltRef},
    vm::{compile::PsyCompileResult, def::DPNFunctionCircuitDefinition},
};

use crate::{
    lower::context::SymValue,
    parse::ast::*,
    types::{checker::*, layout::*},
};

/// Output of the SDK key compilation pipeline.
#[derive(Debug, Clone)]
pub struct SDKKeyCompileOutput {
    /// The compiled authorization circuit definition.
    pub circuit_def: DPNFunctionCircuitDefinition,
    /// The SDK key configuration derived from the contract.
    pub config: SDKeyConfig,
    /// The contract name (used as the key definition name).
    pub name: String,
}

/// Compiler context for SDK key compilation.
///
/// Similar to the standard CompilerContext but with SDK key-specific features:
/// - Transaction introspection via `tx` context object
/// - Read-only state access (no mutations allowed)
/// - Secp256k1 verification tracking
/// - Checkpoint state reading
pub struct SDKKeyCompilerContext<'a> {
    pub checked: &'a CheckedProgram,
    assertion_messages: Vec<&'static str>,
    /// Track how many transactions are introspected.
    num_introspected_transactions: u32,
    /// Track if state reading is used.
    state_reading_used: bool,
    /// Track secp256k1 verification count.
    num_secp256k1_verifications: u32,
}

impl<'a> SDKKeyCompilerContext<'a> {
    pub fn new(checked: &'a CheckedProgram) -> Self {
        SDKKeyCompilerContext {
            checked,
            assertion_messages: Vec::new(),
            num_introspected_transactions: 0,
            state_reading_used: false,
            num_secp256k1_verifications: 0,
        }
    }

    /// Compile the SDK key definition from the checked program.
    ///
    /// The contract must have a single `authorize` method (or a method
    /// annotated as the authorization entry point). This method defines
    /// the key's authorization logic.
    pub fn compile_sdk_key(&mut self) -> Result<SDKKeyCompileOutput> {
        let layout = &self.checked.contract_layout;

        // Find the authorization method
        let methods: Vec<&CheckedMethod> = self.checked.methods.iter().collect();
        let helper_methods: HashMap<String, &CheckedMethod> =
            methods.iter().filter(|m| !m.is_contract_method).map(|m| (m.name.clone(), *m)).collect();

        // Find the authorize method (first contract method, or one named "authorize")
        let auth_method = methods
            .iter()
            .find(|m| m.is_contract_method && m.name == "authorize")
            .or_else(|| methods.iter().find(|m| m.is_contract_method))
            .ok_or_else(|| anyhow::anyhow!("No authorization method found. SDK key contracts must have an 'authorize' method."))?;

        let circuit_def = self.compile_authorize_method(auth_method, &helper_methods)?;

        let config = SDKeyConfig {
            num_introspectable_transactions: self.num_introspected_transactions,
            can_read_state: self.state_reading_used,
            contract_state_tree_height: layout.state_tree_height as u8,
            requires_secp256k1: self.num_secp256k1_verifications > 0,
            num_secp256k1_slots: self.num_secp256k1_verifications,
        };

        Ok(SDKKeyCompileOutput {
            circuit_def,
            config,
            name: self.checked.contract_name.clone(),
        })
    }

    /// Compile the authorize method into a DPN circuit definition.
    fn compile_authorize_method(
        &mut self,
        method: &CheckedMethod,
        helpers: &HashMap<String, &CheckedMethod>,
    ) -> Result<DPNFunctionCircuitDefinition> {
        let layout = &self.checked.contract_layout;
        let mut exec = QExecContext::new_with_contract_state_tree_height(layout.state_tree_height);

        // Register inputs for non-self, non-ctx parameters
        let mut locals: HashMap<String, SymValue> = HashMap::new();
        for param in &method.params {
            match &param.ty {
                crate::types::resolver::ResolvedParamType::SelfRef { .. } => continue,
                crate::types::resolver::ResolvedParamType::Typed { ty, .. } => {
                    if *ty == ResolvedType::Struct("ChainContext".to_string()) {
                        continue;
                    }
                    if *ty == ResolvedType::Struct("SDKKeyContext".to_string()) {
                        continue; // SDK key context is handled via special
                                  // getters
                    }
                    let sym = create_inputs_for_type(&self.checked, &mut exec, ty)?;
                    locals.insert(param.name.clone(), sym);
                }
            }
        }

        // Compile the body with SDK key restrictions
        let mut method_ctx = SDKKeyMethodCompileContext {
            exec: &mut exec,
            locals,
            layout,
            struct_layouts: &self.checked.struct_layouts,
            constants: &self.checked.constants,
            helpers,
            _contract_name: &self.checked.contract_name,
            assertion_messages: &mut self.assertion_messages,
            num_introspected_transactions: &mut self.num_introspected_transactions,
            state_reading_used: &mut self.state_reading_used,
            num_secp256k1_verifications: &mut self.num_secp256k1_verifications,
        };

        for stmt in &method.body {
            method_ctx.compile_stmt(stmt)?;
        }

        method_ctx.exec.finalize();

        let method_id = compute_method_id(&self.checked.contract_name, &method.name, &method.params);

        let outputs: Vec<SymFeltRef> = vec![];
        let def = PsyCompileResult::compile_exec(method.name.clone(), method_id, &exec.store, &exec, &outputs);

        Ok(def)
    }
}

/// Create symbolic inputs for a type in the exec context.
fn create_inputs_for_type(checked: &CheckedProgram, exec: &mut QExecContext, ty: &ResolvedType) -> Result<SymValue> {
    match ty {
        ResolvedType::Felt => Ok(SymValue::Felt(exec.add_input())),
        ResolvedType::Bool => Ok(SymValue::Bool(exec.add_bool_input())),
        ResolvedType::U32 => Ok(SymValue::U32(exec.add_u32_input())),
        ResolvedType::Hash => {
            let refs: Vec<SymFeltRef> = (0..4).map(|_| exec.add_input()).collect();
            Ok(SymValue::Hash([refs[0], refs[1], refs[2], refs[3]]))
        }
        ResolvedType::Array { element, count } => {
            let mut elems = Vec::new();
            for _ in 0..*count {
                elems.push(create_inputs_for_type(checked, exec, element)?);
            }
            Ok(SymValue::Array(elems))
        }
        ResolvedType::Struct(name) => {
            if let Some(struct_layout) = checked.struct_layouts.get(name) {
                let mut fields = Vec::new();
                for field in &struct_layout.fields {
                    let val = create_inputs_for_type(checked, exec, &field.ty)?;
                    fields.push((field.name.clone(), val));
                }
                Ok(SymValue::Struct { name: name.clone(), fields })
            } else {
                bail!("Unknown struct type for input: {}", name)
            }
        }
        ResolvedType::ContractStateArray { .. } => {
            bail!("ContractStateArray cannot be a function parameter")
        }
        ResolvedType::ContractHashMap { .. } => {
            bail!("ContractHashMap cannot be a function parameter")
        }
    }
}

/// Per-method compilation context for SDK key authorization logic.
struct SDKKeyMethodCompileContext<'a, 'b> {
    exec: &'a mut QExecContext,
    locals: HashMap<String, SymValue>,
    layout: &'b ContractStateLayout,
    struct_layouts: &'b HashMap<String, StructLayout>,
    constants: &'b HashMap<String, u64>,
    helpers: &'b HashMap<String, &'b CheckedMethod>,
    _contract_name: &'b str,
    assertion_messages: &'a mut Vec<&'static str>,
    num_introspected_transactions: &'a mut u32,
    state_reading_used: &'a mut bool,
    num_secp256k1_verifications: &'a mut u32,
}

impl<'a, 'b> SDKKeyMethodCompileContext<'a, 'b> {
    fn leak_str(&mut self, s: &str) -> &'static str {
        let leaked: &'static str = Box::leak(s.to_string().into_boxed_str());
        self.assertion_messages.push(leaked);
        leaked
    }

    // ─── Statement compilation ───────────────────────────────────────────

    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<()> {
        match stmt {
            Stmt::Let { name, value, .. } => {
                let val = self.compile_expr(value)?;
                self.locals.insert(name.clone(), val);
                Ok(())
            }
            Stmt::Assign { target, value, .. } => {
                let val = self.compile_expr(value)?;
                self.compile_assignment(target, val)
            }
            Stmt::CompoundAssign { target, op, value, .. } => {
                let current = self.compile_expr(target)?;
                let rhs = self.compile_expr(value)?;
                let result = self.compile_binop(*op, &current, &rhs)?;
                self.compile_assignment(target, result)
            }
            Stmt::Expr(expr) => {
                self.compile_expr(expr)?;
                Ok(())
            }
            Stmt::If {
                condition,
                then_block,
                else_if_blocks,
                else_block,
                ..
            } => {
                let cond = self.compile_expr(condition)?;
                self.exec.start_if_block(cond.as_felt());

                for s in then_block {
                    self.compile_stmt(s)?;
                }

                for (elif_cond, elif_body) in else_if_blocks {
                    let c = self.compile_expr(elif_cond)?;
                    self.exec.start_else_if_block(c.as_felt());
                    for s in elif_body {
                        self.compile_stmt(s)?;
                    }
                }

                if let Some(else_body) = else_block {
                    self.exec.start_else_block();
                    for s in else_body {
                        self.compile_stmt(s)?;
                    }
                }

                self.exec.end_if_block();
                Ok(())
            }
            Stmt::For { var, start, end, body, .. } => {
                let start_val = self.eval_const_expr(start)?;
                let end_val = self.eval_const_expr(end)?;

                for i in start_val..end_val {
                    self.locals.insert(var.clone(), SymValue::Felt(self.exec.op_const(i)));
                    for s in body {
                        self.compile_stmt(s)?;
                    }
                }
                Ok(())
            }
            Stmt::While { condition, body, .. } => {
                // While loops in SDK keys are treated like guarded blocks
                let cond = self.compile_expr(condition)?;
                let cond_ref = cond.as_felt();
                if cond_ref.is_constant_type() && cond_ref.get_constant_value() == 0 {
                    return Ok(());
                }
                self.exec.start_if_block(cond_ref);
                for s in body {
                    self.compile_stmt(s)?;
                }
                self.exec.end_if_block();
                Ok(())
            }
            Stmt::Return { .. } => Ok(()),
        }
    }

    fn compile_assignment(&mut self, target: &Expr, value: SymValue) -> Result<()> {
        match target {
            Expr::Ident(name, _) => {
                self.locals.insert(name.clone(), value);
                Ok(())
            }
            Expr::FieldAccess(receiver, _field, _) => {
                // SDK keys are read-only for contract state
                if let Expr::Ident(name, _) = receiver.as_ref() {
                    if name == "self" {
                        bail!("SDK key authorization circuits cannot modify contract state. State access is read-only.");
                    }
                }
                bail!("Unsupported assignment target in SDK key")
            }
            Expr::IndexAccess(arr, _idx, _) => {
                if let Expr::FieldAccess(self_expr, _field, _) = arr.as_ref() {
                    if let Expr::Ident(self_name, _) = self_expr.as_ref() {
                        if self_name == "self" {
                            bail!("SDK key authorization circuits cannot modify contract state. State access is read-only.");
                        }
                    }
                }
                bail!("Unsupported assignment target in SDK key")
            }
            _ => bail!("Invalid assignment target in SDK key"),
        }
    }

    // ─── Expression compilation ──────────────────────────────────────────

    fn compile_expr(&mut self, expr: &Expr) -> Result<SymValue> {
        match expr {
            Expr::IntLiteral(n, _) => Ok(SymValue::Felt(self.exec.op_const(*n))),
            Expr::BoolLiteral(b, _) => {
                if *b {
                    Ok(SymValue::Bool(self.exec.op_true()))
                } else {
                    Ok(SymValue::Bool(self.exec.op_false()))
                }
            }
            Expr::StringLiteral(_, _) => Ok(SymValue::Void),
            Expr::Ident(name, _) => {
                if let Some(val) = self.locals.get(name) {
                    Ok(val.clone())
                } else if let Some(c) = self.constants.get(name) {
                    Ok(SymValue::Felt(self.exec.op_const(*c)))
                } else if name == "self" || name == "ctx" || name == "sdk" {
                    Ok(SymValue::Void)
                } else {
                    bail!("Undefined variable: {}", name)
                }
            }
            Expr::FieldAccess(receiver, field, _) => self.compile_field_access(receiver, field),
            Expr::IndexAccess(arr, idx, _) => self.compile_index_access(arr, idx),
            Expr::BinaryOp(left, op, right, _) => {
                let l = self.compile_expr(left)?;
                let r = self.compile_expr(right)?;
                self.compile_binop(*op, &l, &r)
            }
            Expr::UnaryOp(op, inner, _) => {
                let val = self.compile_expr(inner)?;
                match op {
                    UnaryOp::Not => Ok(SymValue::Bool(self.exec.op_bool_not(val.as_felt()))),
                    UnaryOp::Neg => Ok(SymValue::Felt(self.exec.op_neg(val.as_felt()))),
                }
            }
            Expr::MethodCall { receiver, method, args, .. } => self.compile_method_call(receiver, method, args),
            Expr::FunctionCall { name, args, .. } => self.compile_function_call(name, args),
            Expr::ArrayLiteral(elements, _) => {
                let mut vals = Vec::new();
                for e in elements {
                    vals.push(self.compile_expr(e)?);
                }
                Ok(SymValue::Array(vals))
            }
            Expr::StructLiteral { name, fields, .. } => {
                let mut sym_fields = Vec::new();
                for (fname, fval) in fields {
                    let val = self.compile_expr(fval)?;
                    sym_fields.push((fname.clone(), val));
                }
                Ok(SymValue::Struct {
                    name: name.clone(),
                    fields: sym_fields,
                })
            }
            Expr::TypedContractAccess {
                user_expr,
                abi_type,
                contract_id,
                access_chain,
                ..
            } => self.compile_typed_contract_access(user_expr, abi_type, contract_id, access_chain),
        }
    }

    fn compile_binop(&mut self, op: BinOp, left: &SymValue, right: &SymValue) -> Result<SymValue> {
        let l = left.as_felt();
        let r = right.as_felt();
        match op {
            BinOp::Add => Ok(SymValue::Felt(self.exec.op_add(l, r))),
            BinOp::Sub => Ok(SymValue::Felt(self.exec.op_sub(l, r))),
            BinOp::Mul => Ok(SymValue::Felt(self.exec.op_mul(l, r))),
            BinOp::Div => Ok(SymValue::Felt(self.exec.op_div(l, r))),
            BinOp::Mod => Ok(SymValue::Felt(self.exec.op_mod(l, r))),
            BinOp::Eq => Ok(SymValue::Bool(self.exec.op_eq(l, r))),
            BinOp::Neq => Ok(SymValue::Bool(self.exec.op_neq(l, r))),
            BinOp::Lt => Ok(SymValue::Bool(self.exec.op_lt(l, r))),
            BinOp::Lte => Ok(SymValue::Bool(self.exec.op_lte(l, r))),
            BinOp::Gt => Ok(SymValue::Bool(self.exec.op_gt(l, r))),
            BinOp::Gte => Ok(SymValue::Bool(self.exec.op_gte(l, r))),
            BinOp::And => Ok(SymValue::Bool(self.exec.op_bool_and(l, r))),
            BinOp::Or => Ok(SymValue::Bool(self.exec.op_bool_or(l, r))),
            BinOp::BitAnd => Ok(SymValue::Felt(self.exec.op_u32_and(l, r))),
            BinOp::BitOr => Ok(SymValue::Felt(self.exec.op_u32_or(l, r))),
            BinOp::BitXor => Ok(SymValue::Felt(self.exec.op_u32_xor(l, r))),
            BinOp::Shl => Ok(SymValue::Felt(self.exec.op_u32_shl(l, r))),
            BinOp::Shr => Ok(SymValue::Felt(self.exec.op_u32_shr(l, r))),
        }
    }

    // ─── Field access ────────────────────────────────────────────────────

    fn compile_field_access(&mut self, receiver: &Expr, field: &str) -> Result<SymValue> {
        if let Expr::Ident(name, _) = receiver {
            if name == "self" {
                *self.state_reading_used = true;
                return self.compile_self_field_read(field);
            }
            if name == "ctx" {
                return self.compile_ctx_field(field);
            }
            // sdk.num_transactions — total transaction count in the proving session
            if name == "sdk" {
                return self.compile_sdk_field(field);
            }
        }

        // Check for sdk.tx[n].field — transaction introspection
        if let Expr::IndexAccess(arr_expr, idx_expr, _) = receiver {
            if let Expr::FieldAccess(sdk_expr, arr_field, _) = arr_expr.as_ref() {
                if let Expr::Ident(sdk_name, _) = sdk_expr.as_ref() {
                    if sdk_name == "sdk" && arr_field == "tx" {
                        return self.compile_tx_introspection_field(idx_expr, field);
                    }
                }
            }
        }

        // Check for local variable field access
        if let Expr::Ident(name, _) = receiver {
            if let Some(val) = self.locals.get(name) {
                return self.get_struct_field(val, field);
            }
        }

        let recv_val = self.compile_expr(receiver)?;
        self.get_struct_field(&recv_val, field)
    }

    fn get_struct_field(&self, val: &SymValue, field: &str) -> Result<SymValue> {
        match val {
            SymValue::Struct { fields, .. } => {
                for (fname, fval) in fields {
                    if fname == field {
                        return Ok(fval.clone());
                    }
                }
                bail!("Field {} not found in struct", field)
            }
            _ => bail!("Cannot access field {} on non-struct value", field),
        }
    }

    // ─── Transaction introspection ──────────────────────────────────────

    /// Maximum number of transactions that can be introspected in an SDK key
    /// circuit. This limits circuit size growth from transaction
    /// introspection slots.
    const MAX_TX_INTROSPECTION_SLOTS: u32 = 64;

    /// Compile access to sdk.tx[n].field where n must be a compile-time
    /// constant.
    fn compile_tx_introspection_field(&mut self, idx_expr: &Expr, field: &str) -> Result<SymValue> {
        let n = self.eval_const_expr(idx_expr)?;

        // Track the max transaction index
        let tx_index = n as u32;
        if tx_index >= Self::MAX_TX_INTROSPECTION_SLOTS {
            bail!(
                "Transaction index {} exceeds maximum allowed introspectable transactions ({}). \
                 sdk.tx[n] requires a compile-time constant index in range 0..{}.",
                tx_index,
                Self::MAX_TX_INTROSPECTION_SLOTS,
                Self::MAX_TX_INTROSPECTION_SLOTS
            );
        }
        if tx_index >= *self.num_introspected_transactions {
            *self.num_introspected_transactions = tx_index + 1;
        }

        // Transaction fields map to DPN context getters.
        // The actual circuit will provide these via the tx introspection gadget.
        // In the DPN IR, we represent tx introspection as state queries
        // with a special encoding.
        match field {
            "contract_id" => {
                // Encode as a constant-indexed getter
                // The circuit gadget will map this to the right target
                let n_const = self.exec.op_const(n);
                let magic = self.exec.op_const(0x5458_434F4E5452u64); // "TXCONTR"
                let result = self.exec.hash(&[magic, n_const]);
                Ok(SymValue::Felt(result[0]))
            }
            "method_id" => {
                let n_const = self.exec.op_const(n);
                let magic = self.exec.op_const(0x54584D4554484Fu64); // "TXMETHO"
                let result = self.exec.hash(&[magic, n_const]);
                Ok(SymValue::Felt(result[0]))
            }
            "caller_contract_id" => {
                let n_const = self.exec.op_const(n);
                let magic = self.exec.op_const(0x545843414C4C52u64); // "TXCALLR"
                let result = self.exec.hash(&[magic, n_const]);
                Ok(SymValue::Felt(result[0]))
            }
            "inputs_length" => {
                let n_const = self.exec.op_const(n);
                let magic = self.exec.op_const(0x5458494E4C454Eu64); // "TXINLEN"
                let result = self.exec.hash(&[magic, n_const]);
                Ok(SymValue::Felt(result[0]))
            }
            "inputs_hash" => {
                let n_const = self.exec.op_const(n);
                let magic = self.exec.op_const(0x5458494E48415348u64); // "TXINHASH"
                let result = self.exec.hash(&[magic, n_const]);
                Ok(SymValue::Hash(result))
            }
            _ => bail!(
                "Unknown transaction field: {}. Available: contract_id, method_id, caller_contract_id, inputs_length, inputs_hash",
                field
            ),
        }
    }

    // ─── Self state reads (read-only) ──────────────────────────────────

    fn compile_self_field_read(&mut self, field: &str) -> Result<SymValue> {
        let contract_field = self
            .layout
            .get_field(field)
            .ok_or_else(|| anyhow::anyhow!("Unknown contract field: {}", field))?
            .clone();

        if contract_field.is_array {
            bail!(
                "Cannot read entire ContractStateArray '{}'. Use indexed access: self.{}[index]",
                field,
                field
            );
        }

        if contract_field.is_imt_map {
            return Ok(SymValue::IMTMapRef {
                field_name: field.to_string(),
            });
        }

        let offset = self.exec.op_const(contract_field.base_offset as u64);

        match &contract_field.ty {
            ResolvedType::Felt => {
                let len = self.exec.op_const(1);
                let result = self.exec.get_state_range_at(offset, len);
                Ok(SymValue::Felt(result[0]))
            }
            ResolvedType::Bool => {
                let len = self.exec.op_const(1);
                let result = self.exec.get_state_range_at(offset, len);
                Ok(SymValue::Bool(result[0]))
            }
            ResolvedType::U32 => {
                let len = self.exec.op_const(1);
                let result = self.exec.get_state_range_at(offset, len);
                Ok(SymValue::U32(result[0]))
            }
            ResolvedType::Hash => {
                let result = self.exec.get_state_hash_at(offset);
                Ok(SymValue::Hash(result))
            }
            _ => {
                let len = self.exec.op_const(contract_field.felt_size as u64);
                let result = self.exec.get_state_range_at(offset, len);
                self.reconstruct_value_from_felts(&contract_field.ty, &result)
            }
        }
    }

    // ─── Context field access ────────────────────────────────────────────

    fn compile_ctx_field(&mut self, field: &str) -> Result<SymValue> {
        match field {
            "user_id" => Ok(SymValue::Felt(self.exec.get_user_id())),
            "contract_id" => Ok(SymValue::Felt(self.exec.get_contract_id())),
            "calling_contract" => Ok(SymValue::Felt(self.exec.get_caller_contract_id())),
            "nonce" => Ok(SymValue::Felt(self.exec.get_last_nonce())),
            "checkpoint_id" => Ok(SymValue::Felt(self.exec.get_checkpoint_id())),
            "user_public_key" => {
                let h = self.exec.get_user_public_key_hash();
                Ok(SymValue::Hash(h))
            }
            "users" => Ok(SymValue::Void),
            _ => bail!("Unknown ChainContext field: {}", field),
        }
    }

    // ─── SDK context field access ───────────────────────────────────────

    fn compile_sdk_field(&mut self, field: &str) -> Result<SymValue> {
        match field {
            "num_transactions" => {
                // The total number of transactions in the proving session.
                // This is a runtime value provided by the tx introspection gadget.
                // Encoded as a magic constant hash so the DPN circuit builder
                // can resolve it to the actual tx_count target.
                let magic = self.exec.op_const(0x53444B5458434E54u64); // "SDKTXCNT"
                let result = self.exec.hash(&[magic]);
                Ok(SymValue::Felt(result[0]))
            }
            "tx" => {
                // sdk.tx is accessed via index: sdk.tx[n], handled by compile_index_access
                Ok(SymValue::Void)
            }
            _ => bail!("Unknown SDKKeyContext field: {}. Available: num_transactions, tx", field),
        }
    }

    // ─── Index access ────────────────────────────────────────────────────

    fn compile_index_access(&mut self, arr_expr: &Expr, idx_expr: &Expr) -> Result<SymValue> {
        // Check for sdk.tx[n]
        if let Expr::FieldAccess(sdk_expr, field, _) = arr_expr {
            if let Expr::Ident(sdk_name, _) = sdk_expr.as_ref() {
                if sdk_name == "sdk" && field == "tx" {
                    // Return a transaction accessor struct
                    let n = self.eval_const_expr(idx_expr)?;
                    let tx_index = n as u32;
                    if tx_index >= Self::MAX_TX_INTROSPECTION_SLOTS {
                        bail!(
                            "Transaction index {} exceeds maximum allowed introspectable transactions ({}). \
                             sdk.tx[n] requires a compile-time constant index in range 0..{}.",
                            tx_index,
                            Self::MAX_TX_INTROSPECTION_SLOTS,
                            Self::MAX_TX_INTROSPECTION_SLOTS
                        );
                    }
                    if tx_index >= *self.num_introspected_transactions {
                        *self.num_introspected_transactions = tx_index + 1;
                    }
                    return Ok(SymValue::Struct {
                        name: "__SDKTxAccessor".to_string(),
                        fields: vec![("tx_index".to_string(), SymValue::Felt(self.exec.op_const(n)))],
                    });
                }
            }
        }

        // Check for self.field[idx] (read-only)
        if let Expr::FieldAccess(self_expr, field, _) = arr_expr {
            if let Expr::Ident(self_name, _) = self_expr.as_ref() {
                if self_name == "self" {
                    *self.state_reading_used = true;
                    return self.compile_array_element_read(field, idx_expr);
                }
            }
        }

        // Check for ctx.users[idx]
        if let Expr::FieldAccess(ctx_expr, field, _) = arr_expr {
            if let Expr::Ident(ctx_name, _) = ctx_expr.as_ref() {
                if ctx_name == "ctx" && field == "users" {
                    let user_id = self.compile_expr(idx_expr)?;
                    return Ok(SymValue::Struct {
                        name: "__UserAccessor".to_string(),
                        fields: vec![("user_id".to_string(), user_id)],
                    });
                }
            }
        }

        // Local array indexing
        let arr_val = self.compile_expr(arr_expr)?;
        let idx_val = self.compile_expr(idx_expr)?;

        match arr_val {
            SymValue::Array(elements) => {
                if let SymValue::Felt(idx_ref) = &idx_val {
                    if idx_ref.is_constant_type() {
                        let i = idx_ref.get_constant_value() as usize;
                        if i < elements.len() {
                            return Ok(elements[i].clone());
                        } else {
                            bail!("Array index {} out of bounds (len {})", i, elements.len());
                        }
                    }
                }
                bail!("Dynamic indexing into local arrays is not supported")
            }
            SymValue::Hash(h) => {
                if let SymValue::Felt(idx_ref) = &idx_val {
                    if idx_ref.is_constant_type() {
                        let i = idx_ref.get_constant_value() as usize;
                        if i < 4 {
                            return Ok(SymValue::Felt(h[i]));
                        }
                    }
                }
                bail!("Dynamic indexing into Hash values is not supported")
            }
            _ => bail!("Cannot index into non-array value"),
        }
    }

    fn compile_array_element_read(&mut self, array_field: &str, idx_expr: &Expr) -> Result<SymValue> {
        let contract_field = self
            .layout
            .get_field(array_field)
            .ok_or_else(|| anyhow::anyhow!("Unknown contract field: {}", array_field))?
            .clone();

        if !contract_field.is_array {
            bail!("Field '{}' is not a ContractStateArray", array_field);
        }

        let elem_size = contract_field.element_felt_size.unwrap();
        let idx = self.compile_expr(idx_expr)?;

        let base = self.exec.op_const(contract_field.base_offset as u64);
        let stride = self.exec.op_const(elem_size as u64);
        let idx_times_stride = self.exec.op_mul(idx.as_felt(), stride);
        let offset = self.exec.op_add(base, idx_times_stride);

        let len = self.exec.op_const(elem_size as u64);
        let result = self.exec.get_state_range_at(offset, len);

        if let ResolvedType::ContractStateArray { element, .. } = &contract_field.ty {
            self.reconstruct_value_from_felts(element, &result)
        } else {
            bail!("Expected ContractStateArray type for field {}", array_field)
        }
    }

    // ─── Typed contract access (cross-user, read-only) ──────────────────

    fn compile_typed_contract_access(
        &mut self,
        user_expr: &Expr,
        _abi_type: &str,
        contract_id_expr: &Expr,
        access_chain: &[AccessStep],
    ) -> Result<SymValue> {
        *self.state_reading_used = true;

        let user_val = self.compile_expr(user_expr)?;
        let user_id = match &user_val {
            SymValue::Struct { name, fields } if name == "__UserAccessor" => fields
                .iter()
                .find(|(n, _)| n == "user_id")
                .map(|(_, v)| v.as_felt())
                .ok_or_else(|| anyhow::anyhow!("Invalid user accessor"))?,
            _ => bail!("Expected ctx.users[user_id] for typed contract access"),
        };

        let contract_id = self.compile_expr(contract_id_expr)?;

        let (offset, read_size) = self.compute_access_chain_offset(access_chain)?;

        let state_tree_height = self.layout.state_tree_height;
        let len_const = self.exec.op_const(read_size as u64);
        let height_ref = self.exec.op_const(state_tree_height as u64);

        let result = self
            .exec
            .get_other_user_contract_state_range_at(height_ref, user_id, contract_id.as_felt(), offset, len_const);

        if read_size == 1 {
            Ok(SymValue::Felt(result[0]))
        } else if read_size == 4 {
            Ok(SymValue::Hash([result[0], result[1], result[2], result[3]]))
        } else {
            Ok(SymValue::Array(result.into_iter().map(SymValue::Felt).collect()))
        }
    }

    fn compute_access_chain_offset(&mut self, chain: &[AccessStep]) -> Result<(SymFeltRef, usize)> {
        let mut offset = self.exec.op_const(0);
        let mut current_type: Option<&ResolvedType> = None;
        let mut read_size = 1usize;

        for (i, step) in chain.iter().enumerate() {
            match step {
                AccessStep::Field(field_name) => {
                    if i == 0 {
                        let contract_field = self
                            .layout
                            .get_field(field_name)
                            .ok_or_else(|| anyhow::anyhow!("Unknown field {}", field_name))?;
                        let base = self.exec.op_const(contract_field.base_offset as u64);
                        offset = self.exec.op_add(offset, base);
                        current_type = Some(&contract_field.ty);
                        read_size = contract_field.felt_size;
                    } else {
                        let struct_name = match current_type {
                            Some(ResolvedType::ContractStateArray { element, .. }) => {
                                if let ResolvedType::Struct(name) = element.as_ref() {
                                    name.clone()
                                } else {
                                    bail!("Expected struct element type")
                                }
                            }
                            Some(ResolvedType::Struct(name)) => name.clone(),
                            _ => bail!("Cannot access field on non-struct type"),
                        };

                        let struct_layout = self
                            .struct_layouts
                            .get(&struct_name)
                            .ok_or_else(|| anyhow::anyhow!("Unknown struct: {}", struct_name))?;

                        let field = struct_layout
                            .fields
                            .iter()
                            .find(|f| f.name == *field_name)
                            .ok_or_else(|| anyhow::anyhow!("Unknown field {} in {}", field_name, struct_name))?;

                        let f_off = self.exec.op_const(field.offset as u64);
                        offset = self.exec.op_add(offset, f_off);
                        current_type = Some(&field.ty);
                        read_size = field.felt_size;
                    }
                }
                AccessStep::Index(idx_expr) => {
                    let idx = self.compile_expr(idx_expr)?;
                    if let Some(ResolvedType::ContractStateArray { element, .. }) = current_type {
                        let elem_size = element.felt_size(self.struct_layouts)?;
                        let stride = self.exec.op_const(elem_size as u64);
                        let idx_offset = self.exec.op_mul(idx.as_felt(), stride);
                        offset = self.exec.op_add(offset, idx_offset);
                        current_type = Some(element);
                        read_size = elem_size;
                    } else {
                        bail!("Cannot index into non-array type")
                    }
                }
            }
        }

        Ok((offset, read_size))
    }

    // ─── Method calls ────────────────────────────────────────────────────

    fn compile_method_call(&mut self, receiver: &Expr, method: &str, args: &[Expr]) -> Result<SymValue> {
        // Handle self.helper_method(args) — helper function call
        if let Expr::Ident(name, _) = receiver {
            if name == "self" {
                return self.compile_helper_call(method, args);
            }
        }

        // Handle self.imt_field.get(key) — read-only IMT access
        if let Expr::FieldAccess(inner, field_name, _) = receiver {
            if let Expr::Ident(self_name, _) = inner.as_ref() {
                if self_name == "self" {
                    if let Some(contract_field) = self.layout.get_field(field_name) {
                        if contract_field.is_imt_map {
                            return self.compile_imt_map_method_call(field_name, method, args);
                        }
                    }
                }
            }
        }

        // Type conversion methods
        let recv_val = self.compile_expr(receiver)?;
        match method {
            "to_felt" | "as_felt" => match &recv_val {
                SymValue::Felt(_) => Ok(recv_val),
                SymValue::Bool(r) | SymValue::U32(r) => Ok(SymValue::Felt(*r)),
                _ => bail!("to_felt() can only be called on Felt, Bool, or U32"),
            },
            "to_u32" | "as_u32" => match &recv_val {
                SymValue::U32(_) => Ok(recv_val),
                SymValue::Bool(r) => Ok(SymValue::U32(*r)),
                _ => bail!("to_u32() can only be called on U32 or Bool"),
            },
            "to_felts" => {
                let refs = recv_val.to_felt_refs();
                Ok(SymValue::Array(refs.into_iter().map(SymValue::Felt).collect()))
            }
            "into" => match recv_val {
                SymValue::Bool(r) => Ok(SymValue::Felt(r)),
                SymValue::U32(r) => Ok(SymValue::Felt(r)),
                SymValue::Array(ref elems) if elems.len() == 4 => {
                    let h = recv_val.as_hash_coerce();
                    Ok(SymValue::Hash(h))
                }
                SymValue::Hash(h) => Ok(SymValue::Array(h.iter().map(|r| SymValue::Felt(*r)).collect())),
                other => Ok(other),
            },
            _ => bail!("Unknown method call: {}", method),
        }
    }

    fn compile_helper_call(&mut self, method_name: &str, args: &[Expr]) -> Result<SymValue> {
        let helper = *self
            .helpers
            .get(method_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown helper method: {}", method_name))?;

        let mut compiled_args: Vec<SymValue> = Vec::new();
        for arg in args {
            compiled_args.push(self.compile_expr(arg)?);
        }

        let saved_locals = self.locals.clone();

        let mut arg_idx = 0;
        for param in &helper.params {
            match &param.ty {
                crate::types::resolver::ResolvedParamType::SelfRef { .. } => continue,
                crate::types::resolver::ResolvedParamType::Typed { ty, .. } => {
                    // ChainContext and SDKKeyContext are implicit parameters —
                    // the caller does not pass them, so don't consume from compiled_args.
                    if *ty == ResolvedType::Struct("ChainContext".to_string()) || *ty == ResolvedType::Struct("SDKKeyContext".to_string()) {
                        continue;
                    }
                    if arg_idx < compiled_args.len() {
                        self.locals.insert(param.name.clone(), compiled_args[arg_idx].clone());
                        arg_idx += 1;
                    }
                }
            }
        }

        for stmt in &helper.body {
            self.compile_stmt(stmt)?;
        }

        self.locals = saved_locals;
        Ok(SymValue::Void)
    }

    fn compile_function_call(&mut self, name: &str, args: &[Expr]) -> Result<SymValue> {
        match name {
            "require" => {
                if args.len() < 2 {
                    bail!("require() expects (condition, message)");
                }
                let cond = self.compile_expr(&args[0])?;
                let msg = if let Expr::StringLiteral(s, _) = &args[1] {
                    s.clone()
                } else {
                    "assertion failed".to_string()
                };
                let msg_static = self.leak_str(&msg);
                self.exec.assert_true(cond.as_felt(), msg_static);
                Ok(SymValue::Void)
            }
            "psystd::poseidon_hash" => {
                let mut felt_refs = Vec::new();
                for arg in args {
                    let val = self.compile_expr(arg)?;
                    felt_refs.extend(val.to_felt_refs());
                }
                let result = self.exec.hash(&felt_refs);
                Ok(SymValue::Hash(result))
            }
            "psystd::keccak256" => {
                let mut felt_refs = Vec::new();
                for arg in args {
                    let val = self.compile_expr(arg)?;
                    felt_refs.extend(val.to_felt_refs());
                }
                let result = self.exec.keccak256(&felt_refs);
                Ok(SymValue::Array(result.into_iter().map(SymValue::U32).collect()))
            }
            "psystd::poseidon_two_to_one" => {
                if args.len() != 2 {
                    bail!("psystd::poseidon_two_to_one() expects exactly 2 arguments");
                }
                let left = self.compile_expr(&args[0])?;
                let right = self.compile_expr(&args[1])?;
                let l = left
                    .try_as_hash_coerce()
                    .ok_or_else(|| anyhow::anyhow!("Expected Hash or 4-element array"))?;
                let r = right
                    .try_as_hash_coerce()
                    .ok_or_else(|| anyhow::anyhow!("Expected Hash or 4-element array"))?;
                let result = self.exec.hash_two_to_one(&l, &r);
                Ok(SymValue::Hash(result))
            }
            "psystd::keccak_two_to_one" => {
                if args.len() != 2 {
                    bail!("psystd::keccak_two_to_one() expects exactly 2 arguments");
                }
                let left = self.compile_expr(&args[0])?;
                let right = self.compile_expr(&args[1])?;
                let l = left
                    .try_as_hash_coerce()
                    .ok_or_else(|| anyhow::anyhow!("Expected Hash or 4-element array"))?;
                let r = right
                    .try_as_hash_coerce()
                    .ok_or_else(|| anyhow::anyhow!("Expected Hash or 4-element array"))?;
                let mut values = Vec::with_capacity(8);
                values.extend_from_slice(&l);
                values.extend_from_slice(&r);
                let result = self.exec.keccak256(&values);
                Ok(SymValue::Array(result.into_iter().map(SymValue::U32).collect()))
            }
            "psystd::secp256k1_verify" => {
                if args.len() != 3 {
                    bail!("psystd::secp256k1_verify() expects exactly 3 arguments");
                }
                *self.num_secp256k1_verifications += 1;

                let pk_val = self.compile_expr(&args[0])?;
                let msg_val = self.compile_expr(&args[1])?;
                let sig_val = self.compile_expr(&args[2])?;

                let pk_refs = pk_val.to_felt_refs();
                if pk_refs.len() != 16 {
                    bail!("secp256k1_verify() public_key must be 16 Felts");
                }
                let msg_hash = msg_val
                    .try_as_hash_coerce()
                    .ok_or_else(|| anyhow::anyhow!("secp256k1_verify() msg_hash must be Hash"))?;
                let sig_refs = sig_val.to_felt_refs();
                if sig_refs.len() != 16 {
                    bail!("secp256k1_verify() signature must be 16 Felts");
                }

                let pk: [SymFeltRef; 16] = pk_refs.try_into().unwrap();
                let sig: [SymFeltRef; 16] = sig_refs.try_into().unwrap();
                let result = self.exec.op_secp256k1_verify(pk, msg_hash, sig);
                Ok(SymValue::Bool(result))
            }
            "psystd::exp" => {
                if args.len() != 2 {
                    bail!("psystd::exp() expects exactly 2 arguments");
                }
                let base = self.compile_expr(&args[0])?.as_felt();
                let power = self.compile_expr(&args[1])?.as_felt();
                let result = self.exec.op_exp(base, power);
                Ok(SymValue::Felt(result))
            }
            "psystd::split_bits" => {
                if args.len() != 2 {
                    bail!("psystd::split_bits() expects 2 arguments");
                }
                let val = self.compile_expr(&args[0])?.as_felt();
                let num_bits_val = self.compile_expr(&args[1])?;
                let num_bits = match &num_bits_val {
                    SymValue::Felt(r) | SymValue::U32(r) if r.is_constant_type() => r.get_constant_value(),
                    _ => bail!("psystd::split_bits() num_bits must be a compile-time constant"),
                };
                let bits = self.exec.split_bits(val, num_bits);
                Ok(SymValue::Array(bits.into_iter().map(SymValue::Bool).collect()))
            }
            "psystd::sum_bits" => {
                if args.len() != 1 {
                    bail!("psystd::sum_bits() expects 1 argument");
                }
                let bits_val = self.compile_expr(&args[0])?;
                let bit_refs = bits_val.to_felt_refs();
                let result = self.exec.sum_bits(&bit_refs);
                Ok(SymValue::Felt(result))
            }
            "psystd::cast_bool" => {
                if args.len() != 1 {
                    bail!("psystd::cast_bool() expects 1 argument");
                }
                let val = self.compile_expr(&args[0])?.as_felt();
                let result = self.exec.op_cast_bool(val);
                Ok(SymValue::Bool(result))
            }
            "psystd::cast_u32" => {
                if args.len() != 1 {
                    bail!("psystd::cast_u32() expects 1 argument");
                }
                let val = self.compile_expr(&args[0])?.as_felt();
                let result = self.exec.op_cast_u32(val);
                Ok(SymValue::U32(result))
            }
            _ => bail!("Unknown function: {}", name),
        }
    }

    // ─── ContractHashMap operations (read-only for SDK keys) ─────────────

    fn compile_imt_map_method_call(&mut self, field_name: &str, method: &str, args: &[Expr]) -> Result<SymValue> {
        *self.state_reading_used = true;
        let contract_field = self
            .layout
            .get_field(field_name)
            .ok_or_else(|| anyhow::anyhow!("Unknown contract field: {}", field_name))?
            .clone();
        let imt_capacity = contract_field
            .imt_capacity
            .ok_or_else(|| anyhow::anyhow!("IMT map field '{}' missing capacity in layout", field_name))?;
        let base_offset = self.exec.op_const(contract_field.base_offset as u64);
        let capacity = self.exec.op_const(imt_capacity as u64);

        match method {
            "get" => {
                if args.len() != 1 {
                    bail!("ContractHashMap.get() expects 1 argument (key)");
                }
                let key_val = self.compile_expr(&args[0])?;
                let key = key_val.as_hash_coerce();
                let result = self.exec.imt_get_value(key, base_offset, capacity);
                Ok(SymValue::Hash(result))
            }
            "contains" => {
                if args.len() != 1 {
                    bail!("ContractHashMap.contains() expects 1 argument (key)");
                }
                let key_val = self.compile_expr(&args[0])?;
                let key = key_val.as_hash_coerce();
                let result = self.exec.imt_contains(key, base_offset, capacity);
                Ok(SymValue::Bool(result))
            }
            "set" | "insert" | "update" => {
                bail!(
                    "SDK key authorization circuits cannot modify ContractHashMap ({}). Use .get() for read-only access.",
                    method
                )
            }
            _ => bail!("Unknown ContractHashMap method: {}", method),
        }
    }

    // ─── Helpers ─────────────────────────────────────────────────────────

    fn eval_const_expr(&self, expr: &Expr) -> Result<u64> {
        match expr {
            Expr::IntLiteral(n, _) => Ok(*n),
            Expr::Ident(name, _) => self
                .constants
                .get(name)
                .copied()
                .or_else(|| {
                    if let Some(SymValue::Felt(r)) = self.locals.get(name) {
                        if r.is_constant_type() {
                            return Some(r.get_constant_value());
                        }
                    }
                    None
                })
                .ok_or_else(|| anyhow::anyhow!("Not a compile-time constant: {}", name)),
            Expr::BinaryOp(left, op, right, _) => {
                let l = self.eval_const_expr(left)?;
                let r = self.eval_const_expr(right)?;
                match op {
                    BinOp::Add => Ok(l + r),
                    BinOp::Sub => Ok(l - r),
                    BinOp::Mul => Ok(l * r),
                    BinOp::Div => Ok(l / r),
                    _ => bail!("Unsupported operator in const expression"),
                }
            }
            _ => bail!("Not a compile-time constant expression"),
        }
    }

    fn reconstruct_value_from_felts(&self, ty: &ResolvedType, felts: &[SymFeltRef]) -> Result<SymValue> {
        match ty {
            ResolvedType::Felt => Ok(SymValue::Felt(felts[0])),
            ResolvedType::Bool => Ok(SymValue::Bool(felts[0])),
            ResolvedType::U32 => Ok(SymValue::U32(felts[0])),
            ResolvedType::Hash => {
                if felts.len() < 4 {
                    bail!("Not enough felts to reconstruct Hash");
                }
                Ok(SymValue::Hash([felts[0], felts[1], felts[2], felts[3]]))
            }
            ResolvedType::Struct(name) => {
                let layout = self.struct_layouts.get(name).ok_or_else(|| anyhow::anyhow!("Unknown struct: {}", name))?;

                let mut fields = Vec::new();
                for field in &layout.fields {
                    let start = field.offset;
                    let end = start + field.felt_size;
                    let field_val = self.reconstruct_value_from_felts(&field.ty, &felts[start..end])?;
                    fields.push((field.name.clone(), field_val));
                }
                Ok(SymValue::Struct { name: name.clone(), fields })
            }
            ResolvedType::Array { element, count } => {
                let elem_size = element.felt_size(self.struct_layouts)?;
                let mut elems = Vec::new();
                for i in 0..*count {
                    let start = i * elem_size;
                    let end = start + elem_size;
                    let elem_val = self.reconstruct_value_from_felts(element, &felts[start..end])?;
                    elems.push(elem_val);
                }
                Ok(SymValue::Array(elems))
            }
            ResolvedType::ContractStateArray { .. } => {
                bail!("Cannot reconstruct ContractStateArray from felts")
            }
            ResolvedType::ContractHashMap { .. } => {
                bail!("Cannot reconstruct ContractHashMap from felts")
            }
        }
    }
}
