# Dargo - Psy Language Package Manager and Build Tool

Dargo is the official package manager and build system for the Psy Smart Contract Language. It handles project creation, dependency management, compilation, testing, and execution of Psy smart contracts.

## Project Management

### `dargo new`

Creates a new Psy language project with a standard directory structure.

```bash
dargo new my_project
```

This creates:
```
my_project/
├── Dargo.toml          # Project configuration
├── src/
│   ├── main.psy        # Main source file
│   └── lib.psy         # Library source file
└── target/             # Build output directory
```

**Project Structure:**
- `Dargo.toml` - Project metadata and dependencies
- `src/main.psy` - Entry point for binary projects
- `src/lib.psy` - Library code (if applicable)
- `target/` - Compiled artifacts and intermediate files

### `dargo init`

Initializes a Psy project in the current directory.

```bash
cd existing_directory
dargo init
```

Use this when you want to add Psy project structure to an existing directory.

## Compilation

### `dargo compile`

Compiles your Psy project to zero-knowledge proof (ZKP) circuits.

#### Basic Compilation

```bash
# Compile main function
dargo compile

# Compile specific contract methods
dargo compile --contract-name MyContract --method-names transfer mint

# Compile multiple methods
dargo compile -c TokenContract -m transfer burn mint approve
```

#### Contract Compilation Examples

**Simple Contract:**
```psy
#[contract]
#[derive(Storage, StorageRef)]
pub struct TokenContract {
    pub total_supply: Felt,
    pub balances: [Felt; 1000000],
}

impl TokenContractRef {
    pub fn mint(to: Felt, amount: Felt) {
        let contract = TokenContractRef::new(ContractMetadata::current());
        let current_supply = contract.total_supply.get();
        contract.total_supply.set(current_supply + amount);
    }
    
    pub fn transfer(from: Felt, to: Felt, amount: Felt) {
        // Transfer implementation
    }
}

fn main() {
    TokenContractRef::mint(123, 100);
}
```

**Compilation Commands:**
```bash
# Compile just the main function
dargo compile

# Compile specific contract method
dargo compile --contract-name TokenContract --method-names mint

# Compile multiple contract methods
dargo compile -c TokenContract -m mint transfer

# This will generate ZK circuits for the specified methods
```

#### Compilation Output

The compile command generates:
- **Formatted Code**: Shows the processed and formatted version of your code
- **Circuit Files**: ZK circuit representations in `target/` directory
- **Constraint System**: Mathematical constraints for zero-knowledge proofs

## Execution and Testing

### `dargo execute`

Compiles and executes Psy programs with specified parameters.

```bash
# Execute main function
dargo execute

# Execute with parameters
dargo execute --parameters 100 200

# Execute contract method with parameters
dargo execute --contract-name TokenContract --method-names mint --parameters 123 50

# Execute multiple methods
dargo execute -c TokenContract -m transfer burn -p 123 456 100
```

#### Execution Examples

**Basic Function Execution:**
```psy
fn add(a: Felt, b: Felt) -> Felt {
    a + b
}

fn main(x: Felt, y: Felt) -> Felt {
    add(x, y)
}
```

```bash
# Execute with parameters x=10, y=20
dargo execute --parameters 10 20
# Returns: 30
```

**Contract Method Execution:**
```psy
#[contract] 
#[derive(Storage, StorageRef)]
pub struct Calculator {
    pub result: Felt,
}

impl CalculatorRef {
    pub fn multiply(a: Felt, b: Felt) -> Felt {
        a * b
    }
    
    pub fn divide(a: Felt, b: Felt) -> Felt {
        a / b  // Modular inverse in finite field
    }
}
```

```bash
# Execute multiply method
dargo execute -c Calculator -m multiply -p 6 7
# Returns: 42

# Execute divide method  
dargo execute -c Calculator -m divide -p 15 3
# Returns: modular inverse result
```

### `dargo test`

Runs tests for your Psy project.

```bash
# Test specific file
dargo test --file src/main.psy

# Test with short flag
dargo test -f tests/token_test.psy
```

#### Test File Example

```psy
#[test]
fn test_addition() {
    let result = 2 + 3;
    assert_eq(result, 5, "2 + 3 should equal 5");
}

#[test]
fn test_contract_mint() {
    TokenContractRef::mint(123, 100);
    let contract = TokenContractRef::new(ContractMetadata::current());
    let supply = contract.total_supply.get();
    assert_eq(supply, 100, "Total supply should be 100 after minting");
}

fn main() {
    // Main function for regular execution
}
```

## ABI Generation

### `dargo generate-abi`

Generates ABI (Application Binary Interface) files for contracts, which define the contract's interface for external interaction.

```bash
# Generate ABI for specific contract
dargo generate-abi --contract-name TokenContract

# Generate with short flag
dargo generate-abi -c TokenContract

# Specify output directory
dargo generate-abi -c TokenContract --output-dir ./abi

# Pretty print the ABI JSON
dargo generate-abi -c TokenContract --pretty
```

#### ABI Structure

The generated ABI contains:

**Contract Definition:**
```json
{
  "version": "1.0.0",
  "structs": [
    {
      "name": "TokenContract",
      "is_contract": true,
      "fields": [
        {
          "name": "balance",
          "type": "Felt"
        }
      ],
      "functions": [
        {
          "name": "transfer",
          "params": [
            {
              "name": "recipient",
              "type": "Felt"
            },
            {
              "name": "amount", 
              "type": "Felt"
            }
          ],
          "return": []
        }
      ]
    }
  ]
}
```

**ABI Components:**
- **structs**: Contract and data structure definitions
- **is_contract**: Indicates if struct is a contract
- **fields**: Contract storage fields and their types
- **functions**: Public methods with parameters and return types
- **params**: Function parameter names and types
- **return**: Function return types (empty array for void)

#### Type Mapping

Psy types map to ABI types as follows:

```psy
// Psy Code
#[contract]
#[derive(Storage, StorageRef)]
pub struct TokenContract {
    pub balance: Felt,
    pub users: [UserInfo; 1000],
}

impl TokenContractRef {
    pub fn transfer(to: Felt, amount: Felt) {
        // Implementation
    }
    
    pub fn get_balance() -> Felt {
        // Implementation
    }
}
```

```json
// Generated ABI
{
  "structs": [
    {
      "name": "TokenContract",
      "is_contract": true,
      "fields": [
        {
          "name": "balance",
          "type": "Felt"
        },
        {
          "name": "users",
          "type": {
            "type": "Array",
            "inner_type": "UserInfo",
            "length": 1000
          }
        }
      ],
      "functions": [
        {
          "name": "transfer",
          "params": [
            {"name": "to", "type": "Felt"},
            {"name": "amount", "type": "Felt"}
          ],
          "return": []
        },
        {
          "name": "get_balance",
          "params": [],
          "return": ["Felt"]
        }
      ]
    }
  ]
}
```

#### Usage with TypeScript SDK

The generated ABI is used by the TypeScript SDK to create typed contract interfaces:

```bash
# 1. Generate ABI
dargo generate-abi -c TokenContract -o ./target

# 2. Copy to TypeScript SDK
cp target/TokenContract.abi.json psy_sdk/psy-ts-sdk/packages/contract-sdk/abi/

# 3. Generate TypeScript bindings
cd psy_sdk/psy-ts-sdk/packages/contract-sdk
pnpm generate
```

## Code Formatting

### `dargo fmt`

Formats Psy source code according to standard style guidelines.

```bash
# Format specific file
dargo fmt src/main.psy

# Format all files in src directory
dargo fmt src/*.psy
```

**Before formatting:**
```psy
fn messy_function(a:Felt,b:Felt)->Felt{
if a>b{a}else{b}
}
```

**After formatting:**
```psy
fn messy_function(a: Felt, b: Felt) -> Felt {
    if a > b {
        a
    } else {
        b
    }
}
```

## Advanced Usage

### Contract-Specific Compilation

When working with multiple contracts, you can compile specific contracts and methods:

```psy
// File: src/contracts.psy

#[contract]
#[derive(Storage, StorageRef)]
pub struct TokenContract {
    pub supply: Felt,
}

#[contract]  
#[derive(Storage, StorageRef)]
pub struct GovernanceContract {
    pub proposals: [Felt; 1000],
}

impl TokenContractRef {
    pub fn mint(amount: Felt) { /* implementation */ }
    pub fn burn(amount: Felt) { /* implementation */ }
}

impl GovernanceContractRef {
    pub fn propose(proposal_id: Felt) { /* implementation */ }
    pub fn vote(proposal_id: Felt, vote: bool) { /* implementation */ }
}
```

**Compilation Commands:**
```bash
# Compile only token contract methods
dargo compile -c TokenContract -m mint burn

# Compile only governance contract methods  
dargo compile -c GovernanceContract -m propose vote

# Compile specific method from specific contract
dargo compile -c TokenContract -m mint
```

### Parameter Types and Formats

When using `--parameters`, different types are supported:

```bash
# Felt parameters
dargo execute -p 123 456 789

# Boolean parameters (represented as 0/1)
dargo execute -p 1 0  # true false

# Array parameters (space-separated elements)
dargo execute -m process_array -p 1 2 3 4 5

# Mixed parameter types
dargo execute -m complex_function -p 100 1 42
```

### Environment Variables

Dargo respects certain environment variables:

```bash
# Set default file for test command
export FILE=tests/my_test.psy
dargo test

# Build optimization level
export DARGO_OPTIMIZATION=release
dargo compile
```

## Project Configuration

### Dargo.toml

The project configuration file supports various settings:

```toml
[package]
name = "my_contract"
type = "bin"  # or "lib"
authors = ["Your Name <email@example.com>"]

[dependencies]
# Future: dependency management

[build]
# Future: build configuration
```

## Common Workflows

### Development Workflow

1. **Create Project:**
```bash
dargo new token_contract
cd token_contract
```

2. **Write Code:**
```psy
// src/main.psy
#[contract]
#[derive(Storage, StorageRef)]
pub struct Token {
    pub balances: [Felt; 1000000],
}

impl TokenRef {
    pub fn transfer(to: Felt, amount: Felt) {
        // Implementation
    }
}
```

3. **Compile and Test:**
```bash
# Check compilation
dargo compile

# Test specific methods
dargo compile -c Token -m transfer

# Execute with parameters
dargo execute -c Token -m transfer -p 123 50

# Run tests
dargo test -f src/main.psy
```

4. **Format Code:**
```bash
dargo fmt src/main.psy
```

### Debugging Workflow

1. **Check Compilation Errors:**
```bash
dargo compile
# Review any compilation errors in output
```

2. **Test Individual Methods:**
```bash
# Test one method at a time
dargo execute -c MyContract -m simple_method -p 10

# Add debug prints in your code and recompile
```

3. **Verify Circuit Generation:**
```bash
# Ensure circuits are generated correctly
dargo compile -c MyContract -m target_method
# Check target/ directory for output files
```

## Error Handling

### Common Errors and Solutions

**Error: "contract not found"**
```bash
# Make sure contract name matches exactly
dargo compile -c TokenContract  # Case-sensitive!
```

**Error: "method not found"**  
```bash
# Verify method exists in the contract implementation
# Check for typos in method name
dargo compile -c Token -m transfer  # Check spelling
```

**Error: "parameter mismatch"**
```bash
# Check parameter count and types
# Method expects: fn transfer(to: Felt, amount: Felt)
dargo execute -c Token -m transfer -p 123 50  # Correct: 2 parameters
```

**Compilation Errors:**
- Read the formatted output to see processed code
- Check for syntax errors in the formatted version
- Verify all imports and dependencies are available

## Performance Tips

1. **Incremental Compilation:**
   - Dargo compiles only changed files when possible
   - Use specific method compilation for faster iteration

2. **Method-Specific Testing:**
   - Test individual methods instead of entire contracts
   - Use `--method-names` to focus on specific functionality

3. **Circuit Optimization:**
   - Simpler methods generate more efficient circuits
   - Avoid complex control flow when possible

## Best Practices

1. **Project Organization:**
   ```
   my_project/
   ├── src/
   │   ├── main.psy       # Main contract
   │   ├── utils.psy      # Utility functions
   │   └── tests.psy      # Test functions
   └── examples/
       └── usage.psy      # Usage examples
   ```

2. **Testing Strategy:**
   - Write tests for each public contract method
   - Test edge cases and error conditions
   - Use descriptive test function names

3. **Development Process:**
   - Compile frequently during development
   - Test methods individually before integration
   - Format code regularly with `dargo fmt`

## Future Features

Planned features for future Dargo versions:

- **Dependency Management**: External package dependencies
- **Build Profiles**: Debug/release configurations  
- **Package Registry**: Shared package repository
- **IDE Integration**: Enhanced editor support
- **Profiling Tools**: Circuit complexity analysis

## Summary

Dargo provides a complete development environment for Psy smart contracts:

- **Project Management**: Create and organize Psy projects
- **Compilation**: Convert Psy code to ZK circuits
- **Execution**: Run and test contract methods
- **Testing**: Automated test execution
- **Formatting**: Consistent code style

Use Dargo for efficient development, testing, and deployment of zero-knowledge smart contracts in the Psy language.