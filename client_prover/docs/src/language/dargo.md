
# Basic Dargo Commands

Dargo is psy-lang's package manager and build system that handles project creation, dependency management, and
development workflows.

## Common Commands

### `dargo new`

Creates a new psy-lang project.

```bash
dargo new my_project
```

### `dargo init`

Initializes a psy-lang project in an current directory.

```bash
dargo init
```

### `dargo compile`

Compiles your project to zero-knowledge proof (ZKP) circuit.

```bash
dargo compile --contract-name=<contract_name> \
  --method-names <method_name_1> <method_name_2> ...
```

### `dargo execute`

Compiles your project to ZKP circuit and verify it

```bash
dargo execute --contract-name=<contract_name> \
  --method-names <method_name_1> <method_name_2> ... \
  --parameters <param_1> <param_2> ...
```

### `dargo fmt`

Formats your psy-lang code.

```bash
dargo fmt <file_name>
```
