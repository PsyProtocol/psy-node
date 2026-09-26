#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$(mktemp "${TMPDIR:-/tmp}/psy-claim-l1-groth16-XXXXXX.json")"
trap 'rm -f "$fixture"' EXIT

# The Hardhat test deploys token, verifier, root source, updates its root,
# then deploys the ledger from the first signer (nonce 4).
ledger_address="$(cd "$repo_root/psy-contracts" && node -e '
  const { ethers } = require("ethers");
  const signer = ethers.Wallet.fromMnemonic("test test test test test test test test test test test junk");
  process.stdout.write(ethers.utils.getContractAddress({ from: signer.address, nonce: 4 }));
')"

cd "$repo_root"
PSY_CLAIM_L1_LEDGER_ADDRESS="$ledger_address" \
PSY_CLAIM_L1_GROTH16_KEYSTORE="${PSY_CLAIM_L1_GROTH16_KEYSTORE:-$HOME/.psy/keystore/reward_batch}" \
PSY_CLAIM_L1_FIXTURE="$fixture" \
cargo test --release -p psy_network_circuit --test claim_rewards_l1_flow \
  five_users_with_one_three_five_seven_nine_rewards_then_batch -- --exact --nocapture

cd "$repo_root/psy-contracts"
PSY_CLAIM_L1_FIXTURE="$fixture" pnpm exec hardhat test test/hardhat/rewardsLedgerGroth16Flow.test.ts
