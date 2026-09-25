#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp "${TMPDIR:-/tmp}/psy-claim-l1-XXXXXX.json")"
trap 'rm -f "$fixture"' EXIT

cd "$repo_root"
PSY_CLAIM_L1_FIXTURE="$fixture" cargo test --release -p psy_network_circuit --test claim_rewards_l1_flow -- --nocapture

cd "$repo_root/psy-contracts"
PSY_CLAIM_L1_FIXTURE="$fixture" pnpm exec hardhat test test/hardhat/rewardsLedgerPlonky2Flow.test.ts
