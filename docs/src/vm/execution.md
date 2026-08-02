# VM Execution

VM execution takes a `DPNFunctionCircuitDefinition` and generates witness data for zero-knowledge proof construction.

## SimpleDPNExecutor

The executor maintains type-specific storage arrays:

```rust
pub struct SimpleDPNExecutor<F: RichField> {
    pub targets: Vec<F>,           // Field elements
    pub target_arrays: Vec<Vec<F>>, 
    pub hashes: Vec<[F; 4]>,       
    pub bools: Vec<bool>,          
    pub bool_arrays: Vec<Vec<bool>>, 
    pub u32s: Vec<u32>,            
    pub u32_arrays: Vec<Vec<u32>>, 
    
    pub user_id: F,                
    pub contract_id: F,            
    pub caller_contract_id: F,     
    pub checkpoint_id: F,          
    pub user_public_key: [F; 4],   
    pub nonce: F,                  
    pub inputs: Vec<F>,            
}
```

## Input

- **DPNFunctionCircuitDefinition**: Compiled bytecode with operations and state commands
- **Function Parameters**: Concrete values for function inputs
- **Blockchain Context**: User ID, contract ID, block height, nonce
- **External State**: Storage values from blockchain state tree

## Execution Process

1. Initialize executor with function inputs and blockchain context
2. Process each `DPNIndexedVarDef` operation in sequence
3. Resolve input references to concrete values from storage arrays
4. Execute operation and store result in appropriate type array
5. Generate complete witness for proof construction

## Output

- **Witness Arrays**: Computed values in type-specific storage (targets, bools, u32s, etc.)
- **State Command Witness**: Results from blockchain state operations
- **Execution Context**: Final blockchain state after execution
- **State Changes**: Modified storage slots and new values
- **Events**: Emitted contract events with parameters

## Key Functions

```rust
pub fn resolve_target(&self, id: u64) -> F {
    let (data_type, index) = decode_indexed_op_id(id);
    match data_type {
        DPNBuiltInDataType::Target => self.targets[index],
        DPNBuiltInDataType::Bool => if self.bools[index] { F::ONE } else { F::ZERO },
        DPNBuiltInDataType::U32Target => F::from_canonical_u32(self.u32s[index]),
        _ => panic!("Invalid data type"),
    }
}

pub fn process_var_def(&mut self, op: &DPNIndexedVarDef) {
    match op.op_type {
        DPNOpType::Add => {
            let left = self.resolve_target(op.inputs[0]);
            let right = self.resolve_target(op.inputs[1]);
            self.targets.push(left + right);
        },
        DPNOpType::Constant => {
            self.targets.push(F::from_canonical_u64(op.inputs[0]));
        },
        // ... other operations
    }
}
```

## Output

Execution produces witness data containing computed values in type-specific arrays, which are used for zero-knowledge proof generation.