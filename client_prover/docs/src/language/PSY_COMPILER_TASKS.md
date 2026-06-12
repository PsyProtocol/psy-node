# PSY Compiler Implementation Task List

## Phase 1: Foundation (Core Types & Parsing)
- [ ] Task 1.1: Create `psy_compiler` crate with Cargo.toml and workspace integration
- [ ] Task 1.2: Define AST types (all node types for the PSY DSL)
- [ ] Task 1.3: Implement token types and lexer
- [ ] Task 1.4: Implement recursive-descent parser producing AST
- [ ] Task 1.5: Unit tests — parse the example token contract and verify AST

## Phase 2: Type System & Layout
- [ ] Task 2.1: Implement FeltSized layout computation (struct sizes, field offsets)
- [ ] Task 2.2: Implement name resolver and symbol table
- [ ] Task 2.3: Implement type checker (validate type constraints)
- [ ] Task 2.4: Implement contract state layout computation (state tree mapping, state_tree_height)
- [ ] Task 2.5: Implement const generic monomorphization
- [ ] Task 2.6: Unit tests for type system (layout, type errors)

## Phase 3: Lowering to DPN IR
- [ ] Task 3.1: Implement CompilerContext (wrapper around QExecContext)
- [ ] Task 3.2: Implement expression lowering (AST expressions → SymFeltRef ops)
- [ ] Task 3.3: Implement statement lowering (assignments, let, if/for)
- [ ] Task 3.4: Implement state access lowering (self, cross-user, arrays)
- [ ] Task 3.5: Implement built-in function lowering (require, hash, checked_add)
- [ ] Task 3.6: Implement helper function inlining
- [ ] Task 3.7: Integration tests — compile example methods, verify QExecContext

## Phase 4: Output & ABI
- [ ] Task 4.1: Implement ABI generation (ContractABI from typed AST)
- [ ] Task 4.2: Implement serialization (PsyCompileResult → DPNFunctionCircuitDefinition)
- [ ] Task 4.3: Implement contract packaging (ContractCodeDefinition output)
- [ ] Task 4.4: End-to-end tests — compile → CBOR → deserialize → verify

## Phase 5: Integration & Verification
- [ ] Task 5.1: Integration with psy_dpn_circuit (verify valid plonky2 circuits)
- [ ] Task 5.2: Witness generation test (proofs with mock state)
- [ ] Task 5.3: Error message quality (source locations, clear messages)
- [ ] Task 5.4: Documentation (usage guide, DSL reference, examples)
