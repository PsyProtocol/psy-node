# Hello, World!

This chapter walks you through creating your first [Psy Smart Contract Language] program.

## Creating a New Program

Create a new project:

```
dargo new hello_world
```

```rust
fn main(x: Felt, y: Felt) {
    assert(x == y, "x != y");
}

#[test]
fn test_main() {
    main(1, 1);

    // Uncomment to make test fail
    // main(1, 2);
}
```

## Compiling

run the program using the compiler:
```
dargo compile
```

You will see a target directory. Open the `hello_world.json` inside and you'll be able to see the target code for psy. The psy smart contract language generates this code for each function in the contract and deploys it to the blockchain.

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

```

```
