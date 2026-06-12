# PsyIDE — Comprehensive Specification

## 1. Overview

PsyIDE is a browser-based smart contract development environment for the Psy blockchain, inspired by Remix IDE. It enables developers to write, compile, deploy, and interact with Psy smart contracts entirely in the browser — no backend server required.

### 1.1 Core Capabilities

| Capability | Description |
|---|---|
| **Code Editor** | Monaco editor with TextMate-based Psy syntax highlighting |
| **Multi-File Projects** | Virtual filesystem with file browser, multi-file `mod`/`use` support |
| **Compilation** | Psy compiler running as WASM in the browser |
| **In-Memory Chain** | Full blockchain simulation using `InMemoryStateBackend` |
| **Deployment** | Deploy compiled contracts to the in-memory chain |
| **VM Execution** | Execute contract methods via `VmExecutor` in WASM |
| **Account Management** | Create and manage multiple virtual user accounts |
| **ABI Interaction** | Auto-generated UI for calling contract methods and reading state |
| **Transaction Log** | Full history of transactions with state deltas |

### 1.2 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Browser (PsyIDE)                         │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              React Frontend (TypeScript)                 │    │
│  │                                                         │    │
│  │  ┌───────────┐  ┌──────────┐  ┌────────────────────┐   │    │
│  │  │  Monaco   │  │  File    │  │  ABI Interaction   │   │    │
│  │  │  Editor   │  │  Browser │  │  Panel             │   │    │
│  │  │  +TextMate│  │  (VFS)   │  │  (Call/Read/Deploy)│   │    │
│  │  └───────────┘  └──────────┘  └────────────────────┘   │    │
│  │                                                         │    │
│  │  ┌───────────┐  ┌──────────┐  ┌────────────────────┐   │    │
│  │  │  Account  │  │  TX Log  │  │  Compilation       │   │    │
│  │  │  Manager  │  │  Panel   │  │  Output/Errors     │   │    │
│  │  └───────────┘  └──────────┘  └────────────────────┘   │    │
│  │                                                         │    │
│  │  Resizable panes (allotment) + draggable tabs           │    │
│  └─────────────────────┬───────────────────────────────────┘    │
│                        │ wasm-bindgen calls                     │
│  ┌─────────────────────▼───────────────────────────────────┐    │
│  │              psy_wasm (Rust → WASM)                     │    │
│  │                                                         │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌───────────────┐   │    │
│  │  │ psy_compiler│  │ psy_vm      │  │ In-Memory     │   │    │
│  │  │ (compile,   │  │ (VmExecutor,│  │ Chain State   │   │    │
│  │  │  ABI gen)   │  │  execute)   │  │ (accounts,    │   │    │
│  │  └─────────────┘  └─────────────┘  │  contracts,   │   │    │
│  │                                     │  state trees) │   │    │
│  │                                     └───────────────┘   │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. WASM Bridge (`psy_wasm`)

### 2.1 Purpose

A Rust crate that compiles to WASM and exposes the Psy compiler, VM executor, and chain state management to JavaScript/TypeScript via `wasm-bindgen`.

### 2.2 Exported API

```rust
// Compilation
fn compile_source(source: &str) -> JsValue;  // Returns CompileResult
fn compile_project(files: JsValue) -> JsValue;  // Multi-file

// Chain State Management
fn create_chain() -> u32;  // Returns chain ID
fn create_account(chain_id: u32, name: &str) -> JsValue;  // Returns AccountInfo
fn deploy_contract(chain_id: u32, deployer_id: u32, compiled: JsValue) -> JsValue;
fn call_contract(chain_id: u32, caller_id: u32, contract_id: u32,
                 method: &str, args: JsValue) -> JsValue;
fn read_state(chain_id: u32, contract_id: u32, user_id: u32) -> JsValue;
fn get_accounts(chain_id: u32) -> JsValue;
fn get_contracts(chain_id: u32) -> JsValue;
fn get_transaction_log(chain_id: u32) -> JsValue;
```

### 2.3 In-Memory Chain State

The WASM module manages a complete in-memory blockchain simulation:

```rust
struct InMemoryChain {
    accounts: Vec<Account>,
    contracts: Vec<DeployedContract>,
    state: InMemoryStateBackend,
    transaction_log: Vec<TransactionRecord>,
    next_user_id: u64,
    next_contract_id: u64,
    checkpoint_id: u64,
}

struct Account {
    user_id: u64,
    name: String,
    public_key_hash: [u64; 4],
}

struct DeployedContract {
    contract_id: u64,
    name: String,
    deployer_id: u64,
    abi: ContractABI,
    circuit_definitions: Vec<DPNFunctionCircuitDefinition>,
    state_tree_height: u16,
}

struct TransactionRecord {
    tx_id: u64,
    caller_id: u64,
    contract_id: u64,
    method_name: String,
    args: Vec<u64>,
    result: ExecutionResult,
    timestamp: u64,
}
```

---

## 3. Frontend Architecture

### 3.1 Technology Stack

| Component | Technology |
|---|---|
| Framework | React 18 + TypeScript |
| Editor | Monaco Editor (`@monaco-editor/react`) |
| Syntax | TextMate grammar for Psy (via `monaco-textmate` + `vscode-oniguruma`) |
| Pane Layout | `allotment` (resizable split panes) |
| Tab Management | `react-dnd` for drag-and-drop tabs |
| State Management | Zustand |
| Build | Vite |
| Styling | CSS Modules + CSS custom properties for theming |

### 3.2 Layout

```
┌──────────────────────────────────────────────────────────────────┐
│  Toolbar: [Compile] [Deploy] [Account: ▼ Alice] [Theme: ▼]      │
├─────────────────┬────────────────────────────────────────────────┤
│                 │  ┌──────────────────────────────────────────┐  │
│  File Browser   │  │  Editor Tabs  [main.psy.rs] [types.psy] │  │
│                 │  │  ┌──────────────────────────────────────┐│  │
│  📁 project     │  │  │                                      ││  │
│  ├─ lib.psy.rs  │  │  │     Monaco Editor                    ││  │
│  ├─ types.psy.rs│  │  │     (Psy syntax highlighting)        ││  │
│  └─ helpers/    │  │  │                                      ││  │
│     └─ math.psy │  │  │                                      ││  │
│                 │  │  └──────────────────────────────────────┘│  │
│                 │  └──────────────────────────────────────────┘  │
│                 ├────────────────────────────────────────────────┤
│                 │  Bottom Panel (tabbed):                        │
│                 │  [Compiler Output] [Transactions] [State]      │
│                 │                                                │
│                 │  ┌───────────────────┬──────────────────────┐  │
│                 │  │ Contract Methods  │ State Inspector      │  │
│                 │  │                   │                      │  │
│                 │  │ ▶ set_value       │ value: 42            │  │
│                 │  │   new_value: [__] │ balance: 1000        │  │
│                 │  │   [Execute]       │ users[0].amount: 500 │  │
│                 │  │                   │                      │  │
│                 │  │ ▶ deposit         │ [Refresh]            │  │
│                 │  │   amount: [____]  │                      │  │
│                 │  │   [Execute]       │                      │  │
│                 │  └───────────────────┴──────────────────────┘  │
├─────────────────┴────────────────────────────────────────────────┤
│  Status Bar: Ready | Contract: MyToken (ID: 1) | Block: 100     │
└──────────────────────────────────────────────────────────────────┘
```

### 3.3 Pane System

Using `allotment` for resizable splits:
- **Horizontal split**: File browser | Main area
- **Vertical split**: Editor area | Bottom panel
- **Horizontal split** (bottom): Contract interaction | State inspector

All pane sizes are persisted in localStorage.

### 3.4 Tab System

Editor tabs support:
- Drag-and-drop reordering via `react-dnd`
- Close button (with unsaved indicator dot)
- Context menu (Close, Close Others, Close All)
- File type icons

---

## 4. Monaco Editor Integration

### 4.1 TextMate Grammar for Psy

```json
{
  "scopeName": "source.psy",
  "patterns": [
    { "include": "#comments" },
    { "include": "#attributes" },
    { "include": "#keywords" },
    { "include": "#types" },
    { "include": "#strings" },
    { "include": "#numbers" },
    { "include": "#operators" },
    { "include": "#functions" },
    { "include": "#variables" }
  ],
  "repository": {
    "comments": {
      "match": "//.*$",
      "name": "comment.line.double-slash.psy"
    },
    "attributes": {
      "patterns": [
        { "match": "#\\[(contract|contract_implementation|contract_method|derive\\(FeltSized\\))\\]",
          "name": "meta.attribute.psy" }
      ]
    },
    "keywords": {
      "match": "\\b(const|let|pub|struct|impl|fn|if|else|for|in|return|true|false|mut|mod|use|as|require)\\b",
      "name": "keyword.control.psy"
    },
    "types": {
      "match": "\\b(Felt|Bool|U32|Hash|usize|ContractStateArray|ChainContext|Self)\\b",
      "name": "entity.name.type.psy"
    },
    "strings": {
      "begin": "\"", "end": "\"",
      "name": "string.quoted.double.psy"
    },
    "numbers": {
      "match": "\\b[0-9][0-9_]*\\b",
      "name": "constant.numeric.psy"
    },
    "functions": {
      "match": "\\b([a-zA-Z_][a-zA-Z0-9_]*)\\s*(?=\\()",
      "captures": { "1": { "name": "entity.name.function.psy" } }
    }
  }
}
```

### 4.2 Editor Features

- Psy syntax highlighting (TextMate grammar)
- Auto-indentation
- Bracket matching
- Error markers from compilation (red underlines with messages)
- Minimap
- Go-to-definition (within project files)
- Auto-complete for Psy keywords, types, and contract fields

---

## 5. File Browser

### 5.1 Virtual Filesystem

The file browser manages an in-memory virtual filesystem stored in Zustand:

```typescript
interface VirtualFile {
  path: string;        // e.g., "/project/lib.psy.rs"
  content: string;
  isDirty: boolean;
  lastModified: number;
}

interface FileSystemState {
  files: Map<string, VirtualFile>;
  expandedDirs: Set<string>;
  selectedFile: string | null;

  createFile(path: string, content?: string): void;
  deleteFile(path: string): void;
  renameFile(oldPath: string, newPath: string): void;
  createDirectory(path: string): void;
  updateFileContent(path: string, content: string): void;
}
```

### 5.2 Features

- Tree view with expand/collapse directories
- Create file/folder buttons
- Right-click context menu (Rename, Delete, New File, New Folder)
- Drag-and-drop file reorganization
- File type icons (`.psy.rs` files get the Psy icon)
- Dirty indicator (dot on unsaved files)
- Default project template on first load

### 5.3 Default Project Template

```
project/
├── lib.psy.rs          # Root module with contract definition
└── types.psy.rs        # Shared types
```

**lib.psy.rs**:
```rust
pub mod types;
use types::*;

const PSY_TOTAL_USERS: usize = 16;
const PSY_TOTAL_CONTRACTS: usize = 4;

#[contract]
pub struct MyToken {
    pub total_supply: Felt,
    pub balances: ContractStateArray<PSY_TOTAL_USERS, TokenBalance>,
}

#[contract_implementation]
impl MyToken {
    #[contract_method]
    pub fn mint(&mut self, ctx: &ChainContext, amount: Felt) {
        let sender = ctx.user_id;
        self.total_supply = self.total_supply + amount;
        self.balances[sender].amount = self.balances[sender].amount + amount;
    }

    #[contract_method]
    pub fn transfer(&mut self, ctx: &ChainContext, to: Felt, amount: Felt) {
        let sender = ctx.user_id;
        require(self.balances[sender].amount >= amount, "insufficient balance");
        self.balances[sender].amount = self.balances[sender].amount - amount;
        self.balances[to].amount = self.balances[to].amount + amount;
    }

    #[contract_method]
    pub fn get_balance(&mut self, ctx: &ChainContext) -> Felt {
        return self.balances[ctx.user_id].amount;
    }
}
```

**types.psy.rs**:
```rust
#[derive(FeltSized)]
pub struct TokenBalance {
    pub amount: Felt,
}
```

---

## 6. Account & Wallet Management

### 6.1 Virtual Accounts

Each virtual account represents a user on the in-memory chain:

```typescript
interface Account {
  userId: number;
  name: string;
  publicKeyHash: string;  // Hex display
  color: string;          // For UI identification
}
```

### 6.2 Account Panel

- Dropdown to select active account (for executing transactions)
- "Create Account" button with name input
- Account list showing: name, user ID, color badge
- Quick-switch between accounts
- Pre-created default accounts: "Alice" (ID 1), "Bob" (ID 2)

---

## 7. Compilation System

### 7.1 Compile Flow

1. Gather all files from virtual filesystem
2. Map to `(ModulePath, String)` pairs
3. Call `psy_wasm::compile_project(files)`
4. Display results:
   - **Success**: Show ABI summary, method count, state tree height
   - **Error**: Show error messages with file/line markers in editor

### 7.2 Compiler Output Panel

```
┌────────────────────────────────────────────────────────────────┐
│  ✓ Compiled MyToken successfully                               │
│  State tree height: 5                                          │
│  Methods: mint (ID: 0xA3F2), transfer (ID: 0x7B1C),          │
│           get_balance (ID: 0x5E9D)                             │
│  Circuit definitions: 3                                        │
│                                                                │
│  ABI:                                                          │
│  ├─ State: total_supply (Felt, offset 0),                      │
│  │         balances (ContractStateArray<16, TokenBalance>)      │
│  └─ Methods:                                                   │
│     ├─ mint(amount: Felt)                                      │
│     ├─ transfer(to: Felt, amount: Felt)                        │
│     └─ get_balance() -> Felt                                   │
└────────────────────────────────────────────────────────────────┘
```

### 7.3 Error Display

Compilation errors are shown in:
1. The output panel (full error message)
2. Monaco editor markers (red underline with hover tooltip)
3. File browser (red indicator on files with errors)

---

## 8. Contract Deployment & Interaction

### 8.1 Deploy Flow

1. Compile the project (if not already compiled)
2. Select deployer account from dropdown
3. Click "Deploy" button
4. Contract is registered in the in-memory chain
5. ABI interaction panel populates with contract methods

### 8.2 ABI Interaction Panel

For each deployed contract, auto-generate a UI from the ABI:

**Method Call UI**:
```
┌────────────────────────────────────────┐
│  MyToken (Contract ID: 1)              │
│  Deployed by: Alice                    │
│                                        │
│  ▼ mint                                │
│    amount (Felt): [______________]     │
│    [Transact]                          │
│                                        │
│  ▼ transfer                            │
│    to (Felt):     [______________]     │
│    amount (Felt): [______________]     │
│    [Transact]                          │
│                                        │
│  ▼ get_balance                         │
│    (no parameters)                     │
│    [Call]                              │
│                                        │
│  Caller: [Alice ▼]                     │
└────────────────────────────────────────┘
```

### 8.3 State Inspector

Read and display current contract state for any user:

```
┌────────────────────────────────────────┐
│  State Inspector                       │
│  Contract: [MyToken ▼]  User: [All ▼]  │
│                                        │
│  total_supply: 5000                    │
│                                        │
│  balances (ContractStateArray<16>):    │
│  ├─ [0] Alice:   { amount: 3000 }     │
│  ├─ [1] Bob:     { amount: 2000 }     │
│  ├─ [2] Charlie: { amount: 0 }        │
│  └─ [3..15]: { amount: 0 }            │
│                                        │
│  [Refresh]                             │
└────────────────────────────────────────┘
```

---

## 9. Transaction Log

### 9.1 Transaction History

```
┌──────────────────────────────────────────────────────────────────┐
│  # │ Caller │ Contract │ Method   │ Status  │ Gas  │ Details    │
│────┼────────┼──────────┼──────────┼─────────┼──────┼────────────│
│  3 │ Bob    │ MyToken  │ transfer │ ✓ Pass  │ 47   │ [Expand ▼] │
│  2 │ Alice  │ MyToken  │ mint     │ ✓ Pass  │ 35   │ [Expand ▼] │
│  1 │ Alice  │ MyToken  │ mint     │ ✗ Fail  │ 12   │ [Expand ▼] │
└──────────────────────────────────────────────────────────────────┘
```

### 9.2 Transaction Detail (expanded)

```
Transaction #3: Bob → MyToken.transfer(to=1, amount=500)
Status: ✓ Success
Operations: 47 total (12 arithmetic, 3 state reads, 2 state writes)

State Changes:
  balances[1].amount: 2500 → 2000  (Bob)
  balances[0].amount: 3000 → 3500  (Alice)

Outputs: []
```

---

## 10. Theming

### 10.1 Color Scheme

PsyIDE uses a dark theme inspired by VSCode/Remix:

- Background: `#1e1e1e`
- Panel background: `#252526`
- Active tab: `#1e1e1e`
- Text: `#d4d4d4`
- Accent: `#569cd6` (blue)
- Success: `#4ec9b0`
- Error: `#f44747`
- Warning: `#ce9178`

### 10.2 Monaco Theme

Custom Monaco theme matching the IDE chrome, with Psy-specific token colors.

---

## 11. Persistence

### 11.1 LocalStorage

- Virtual filesystem files
- Pane sizes
- Account list
- Theme preference
- Last opened files/tabs

### 11.2 Session Restoration

On reload, PsyIDE restores:
- All files from the virtual filesystem
- Open editor tabs
- Account configuration
- Deployed contracts and chain state (optional — can choose "fresh session")
