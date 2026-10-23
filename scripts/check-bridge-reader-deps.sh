#!/usr/bin/env bash
# Keeps the Bridge Reader crates free of prover, node and sqlx dependencies.
set -euo pipefail
cd "$(dirname "$0")/.."

core=$(cargo tree -p psy_bridge_reader_core -e normal --prefix none)
if bad=$(printf '%s\n' "$core" | grep -E '^(psy_plonky2_|psy_prover|psy_node_|sqlx)|_circuit '); then
    echo "forbidden dependency in psy_bridge_reader_core:" >&2
    printf '%s\n' "$bad" >&2
    exit 1
fi

# Depth 1 lists the crate itself, then its direct dependencies.
api=$(cargo tree -p psy_bridge_reader_api -e normal --depth 1 --prefix none | tail -n +2)
if bad=$(printf '%s\n' "$api" | grep -vE '^(serde|serde_derive) ' | grep -v '^$'); then
    echo "psy_bridge_reader_api may depend only on serde:" >&2
    printf '%s\n' "$bad" >&2
    exit 1
fi
echo "bridge reader dependency check ok"
