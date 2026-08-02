# Hello, World!

This chapter walks you through creating your first [Psy Smart Contract Language] program.

## Creating a New Program

Create a new project:

```bash
dargo new hello_world
```

This creates a new directory with a basic project structure. Navigate to the project and edit the `src/main.psy` file:

```rust
// input: 2,3
// output: 5
fn main(a: Felt, b: Felt) -> Felt {
    assert(a < b, "a should be less than b");
    assert_eq(b - a, 1, "b - a should equal 1");
    return a + b;
}
```

This simple program:
- Takes two `Felt` parameters (`a` and `b`)
- Asserts that `a` is less than `b`
- Asserts that the difference is exactly 1
- Returns the sum of `a` and `b`

## Compiling

Compile the program using the compiler:
```bash
dargo compile
```

You will see a target directory created with the compiled output. The Psy compiler generates DPN opcodes and circuit data for each function.

```
[
    {
        "name": "main",
        "method_id": 680917438,
        "circuit_inputs": [
            0,
            1
        ],
        "circuit_outputs": [],
        "state_commands": [],
        "state_command_resolution_indices": [],
        "assertions": [
            {
                "left": 4294967296,
                "right": 4294967297,
                "message": "x != y"
            }
        ],
        "definitions": [
            {
                "data_type": 0,
                "index": 0,
                "op_type": 0,
                "inputs": [
                    0
                ]
            },
            {
                "data_type": 0,
                "index": 1,
                "op_type": 0,
                "inputs": [
                    1
                ]
            },
            {
                "data_type": 1,
                "index": 0,
                "op_type": 13,
                "inputs": [
                    0,
                    1
                ]
            },
            {
                "data_type": 1,
                "index": 1,
                "op_type": 2,
                "inputs": [
                    1
                ]
            }
        ]
    }
]
```

## Running

Execute the program with test inputs:

```bash
dargo execute --program-dir . --entry-path src/main.psy --parameters 2,3
```

This runs the `main` function with the parameters `2` and `3`. You should see the output `result_vm: [5]` as the result.
