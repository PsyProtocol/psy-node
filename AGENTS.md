# AGENTS.md — psy-node

These rules apply to the entire repository unless a more specific checked-in rule file overrides them.

## Hard Constraints

Violating any rule below requires an immediate fix before other work continues.

1. **No unfinished content.** Do not land dummy implementations, unresolved markers, no-op fallbacks, or misleading scaffolding.
2. **No inference as conclusion.** Every judgment must trace to current repository evidence with `<file>:<line>` references and executable verification.
3. **No machine-local paths or secrets.** Use repository-relative paths or explicit path metavariables such as `<repo-root>` and `<workspace>`. Never add credentials, tokens, cookies, private endpoints, internal hostnames, or private IPs.
4. **Never push changes.** Do not run `git push`.
5. **Never auto-format.** Do not run formatters or perform style-only reformatting unless explicitly requested.
6. **Never discard worktree changes automatically.** Do not use destructive checkout, restore, reset, or equivalent rollback commands. Review and preserve existing work.
7. **Never print secrets or environment values.** Do not read or display secret files, credentials, keys, tokens, or environment-variable contents.
8. **Never access home-directory cloud credentials.** Do not read, list, or access cloud-provider credential directories in the user's home directory.
9. **Use structured web tooling.** Prefer repository readers or browser tooling over raw page dumps when those tools are available.
10. **Realm pipeline overlap is non-negotiable.** Candidate A proving, P2P consensus, and Coordinator inclusion must overlap with builder B accepting and speculatively aggregating real EndCaps on A's end root. Never replace this with a serial seal, inclusion wait, and resume barrier. Never keep B paused during A proving, consensus, or inclusion. A short seal and exact-root publication before A proving may seed B. Keep speculative intake separate from checkpoint-bound authoritative witness generation. Bind or rebuild B's authoritative graph only after a real checkpoint authenticates B's start root. Checkpoint proof guards remain fail-closed, and proof values must never be mutated.

## Core Engineering Principles

1. Converge on the simplest correct solution before editing. Prefer suitable data structures and flat control flow over repetitive branches and nested loops.
2. Do not add abstractions, layers, indirection, or generic interfaces for hypothetical needs.
3. Prefer readable, low-error code over cleverness or minimum line count.
4. Keep control flow flat. Prefer `match`, `switch`, and early returns. Do not exceed three levels of nesting.
5. Return errors immediately with context. Prefer `ok_or`, `ok_or_else`, `?`, or an explicit early-return match.
6. Reuse shared logic when the same non-trivial behavior appears at least twice and will remain shared.
7. Comments are exceptional. Use one short sentence only when an invariant or reason cannot be expressed in code.
8. Do not weaken requirements, drop behavior, or special-case an input to hide the underlying defect.
9. Maintain one optimal implementation. Migrate every caller and remove obsolete aliases, compatibility paths, and deprecated versions.
10. Solve only the current problem. Do not introduce speculative fields, stores, interfaces, retries, telemetry, or validation.
11. Stay within scope. Modify only files directly required by the current goal and treat unrelated changes as user-owned work.
12. Prefer existing repository patterns. A second convention beside an established one is prohibited.

## Error Handling

1. Fail fast with readable context including relevant identifiers and parameters.
2. Never swallow errors, use empty catches, unwrap production failures, or discard context during conversion.
3. Never delete failure paths to make verification pass. Handle the failure or reject it explicitly.
4. Model retry, rollback, and idempotency behavior explicitly.

## Naming

1. Functions state what they do, variables state what they represent, and types state what they model.
2. Avoid vague names such as `tmp`, `data`, `result`, `obj`, and `foo` in long-lived or public interfaces.
3. Use only universally understood abbreviations such as `ctx`, `id`, `cfg`, `db`, and `tx`.
4. Use the same name for the same concept throughout the repository.
5. Prefix booleans with `is_`, `has_`, `should_`, or `can_`.
6. Do not embed task identifiers, phase numbers, or step numbers in code names, file names, comments, or commit messages.

## Module Boundaries and Imports

1. Each module must own one coherent responsibility and expose a minimal public surface.
2. Prefer explicit or grouped imports. Use glob imports only where an established prelude or test convention requires them.
3. Rust public surfaces belong in `lib.rs` or `mod.rs`; implementation details should be `pub(crate)` or narrower.
4. TypeScript package exports belong in `index.ts`; internal modules use relative imports.
5. Do not import another module's private helpers or introduce circular dependencies.

## Dependencies

1. Define Rust dependencies at workspace level and reference them with `workspace = true`. Keep JavaScript dependencies owned by the repository root package configuration.
2. Follow the existing workspace version strategy. Any new exact pin requires an explicit compatibility or reproducibility reason.
3. Read existing dependency documentation and type definitions before deciding that a new dependency is required.
4. For each new dependency, document the problem solved, why existing dependencies are insufficient, maintenance activity, license, size, and attack surface.
5. Prefer mature libraries that reduce total complexity. Do not add a large dependency for a small utility.
6. Keep dependency upgrades separate from feature changes.

## Architecture

1. Build the smallest complete end-to-end behavior, then extend only from a stable working path.
2. Do not adopt a stopgap architecture expected to be replaced later.
3. Study established implementations before designing a new protocol, storage model, or concurrency mechanism.
4. Keep one source of truth for each datum. Derived state must name its owner and refresh contract.
5. Dependencies flow from interfaces and runtime orchestration toward domain behavior and infrastructure, never in cycles.

## Testing and Verification

1. Put Rust unit tests in the source file and TypeScript tests adjacent to the implementation when practical.
2. Use standalone integration tests only for cross-module contracts or framework requirements.
3. Tests must defend observable behavior, boundaries, invariants, transitions, precedence, and real errors.
4. Do not use tautological assertions, status-only checks, or mocks that bypass the contract under test.
5. Bug fixes require reproduction before the change and confirmation that the same reproduction no longer fails.
6. UI changes require browser execution. Runtime changes require launching and exercising the changed path.
7. Coverage tools supplement test design but do not replace it.

## Performance and Concurrency

1. Optimize only after correctness, readability, and measured evidence.
2. Every performance change requires benchmark results with the command, data, and environment recorded.
3. Model concurrency explicitly. Correctness must not depend on timing luck.
4. Cross-thread state requires documented ownership, lock order, visibility, and lifecycle invariants.
5. Avoid preventable allocation, copies, serialization, and repeated computation on hot paths.

## Security

1. Never write credentials, tokens, keys, cookies, session identifiers, private endpoints, or full user input into source, logs, fixtures, or documentation.
2. Treat network, filesystem, IPC, RPC, CLI, proof, and encoded inputs as malicious boundaries.
3. Filesystem operations must constrain path scope and must not concatenate untrusted input into paths.
4. Authorization and proof checks are fail-closed. Never weaken them to recover liveness.
5. Any `unsafe`, `eval`, `exec`, reflection, or dynamic loading change requires a threat model in the change description.

## Logging and Observability

1. `error` means human intervention is required; `warn` means follow-up is required; `info` records important state changes; `debug` records development detail.
2. Do not emit expected failures at `error` or flood control-flow detail at `info`.
3. Log external calls and important state transitions with correlating identifiers.
4. Use machine-parseable single-line fields. Do not log unescaped multiline content.
5. Critical paths require metrics and trace spans when the repository already exposes those mechanisms.

## Automatic Rejection Triggers

A change is rejected until any applicable item is corrected:

1. Unfinished markers, dummy behavior, no-op fallbacks, or incomplete scaffolding.
2. Swallowed errors, production unwraps, or context-free error conversion.
3. Dead code, commented-out code, permanently disabled branches, or unused functions.
4. More than three levels of conditional or loop nesting without extraction.
5. A function over roughly 60 lines or a file over roughly 800 lines without a documented language-specific reason.
6. Duplicated non-trivial logic with minor variations.
7. Style-only reformatting, broad renaming, or unrelated file moves mixed into a feature change.
8. Large or unreviewed dependencies, unexplained exact pins, or dependency upgrades piggy-backed on features.
9. Import pollution, cross-private API access, or circular dependencies.
10. Vague long-lived names or different names for the same concept.
11. Comments that restate code or reference short-lived task and review identifiers.
12. Complex optimization without profiling or benchmark evidence.
13. Undocumented unsafe execution, reflection, dynamic loading, or shared global state.
14. Credentials, private endpoints, machine-local absolute paths, home-directory credential paths, internal hostnames, or private IPs.
15. Log-level abuse or critical paths with no existing observability integration.
16. Tests that prove plumbing rather than the observable contract.

## Documentation Standards

1. Specs, reviews, and research documents must support factual claims with current `<file>:<line>` references.
2. Reviews accept verified facts or explicit open questions, not inference presented as evidence.
3. Test plans cover unit, integration, negative, and regression checks where applicable.
4. Acceptance criteria are executable commands or observable scenarios.
5. Mark inferred research statements explicitly as `Inference:` and list unchecked areas.
6. Separate `In Scope` and `Out of Scope` in every specification.

## Git Commit Rules

1. Commit each independent task or milestone separately.
2. Keep messages concise, concrete, and grounded in inspected changes.
3. Do not use vague summaries such as `update`, `misc`, or `changes`.
4. Do not mix unrelated work in one commit.
5. Do not add collaboration footers unless explicitly required.
6. Before committing, inspect every staged file and remove secrets, generated artifacts, binaries, logs, runtime data, backups, and machine-local configuration.

## Specification Workflow

1. Check the [psy-memory repository](https://github.com/PsyProtocol/psy-memory) before creating a duplicate specification.
2. Use the [parth-generic-v1 specifications directory](https://github.com/PsyProtocol/psy-memory/tree/main/src/repositories/parth-generic-v1/specs) as the external specification index.
3. Every specification defines the goal, in-scope and out-of-scope work, repository relationships, exact starting branch and commit, phases, and executable acceptance checks.
4. Maintain specification lifecycle state through the workflow documented in psy-memory. Do not hand-edit generated indexes or invent repository-local lifecycle conventions.
5. Reference psy-memory artifacts with canonical `https://github.com/PsyProtocol/psy-memory` URLs, never with machine-local checkout paths.

## Review Requirements

Every review must satisfy all items below.

### Prohibited Review Behavior

1. Do not approve unread changes or report an evidence-free clean review.
2. Read every changed file and its surrounding context.
3. Do not use style findings to cover correctness or security gaps.
4. Every finding must cite current source lines and an observable failure mode.
5. Unverifiable concerns are open questions, not findings.
6. Every P0 or P1 finding includes a concrete suggested fix.
7. Do not defer a blocking finding to the author without an actionable resolution.
8. Do not submit batch-formatting feedback as a code review.
9. Every `<file>:<line>` reference must resolve at the reviewed commit.
10. Review documents contain no sensitive values or machine-local paths.
11. Every section is complete or marked `Not applicable`.

### Review Coverage

A complete review answers:

1. Which files, functions, and types changed, and whether each was inspected.
2. Which changes affect external API, RPC, on-chain, proof, encoding, or FFI consumers.
3. Whether state machines, protocols, hashes, encodings, events, and error codes remain consistent.
4. Whether failure paths, retries, duplicate input, and state conflicts are handled.
5. Whether verification proves real behavior rather than a narrowed pass.
6. Whether cross-repository and cross-service boundaries remain synchronized.
7. Whether performance, resource, or security regressions were introduced.
8. Whether new ports, environment variables, directories, providers, or defaults were introduced.
9. Whether documentation, specifications, and comments match the implementation.

## External Psy Memory References

The canonical external knowledge repository is [PsyProtocol/psy-memory](https://github.com/PsyProtocol/psy-memory). Its current public structure uses `src/repositories/...`.

| Need | Canonical link |
|---|---|
| psy-node and Realm specifications | [parth-generic-v1 specifications](https://github.com/PsyProtocol/psy-memory/tree/main/src/repositories/parth-generic-v1/specs) |
| Realm rotation and P2P design | [realm-rotation-and-p2p.md](https://github.com/PsyProtocol/psy-memory/blob/main/src/repositories/parth-generic-v1/specs/in-review/realm-rotation-and-p2p.md) |
| parth-generic-v1 E2E references | [e2e directory](https://github.com/PsyProtocol/psy-memory/tree/main/src/repositories/parth-generic-v1/e2e) |
| Bridge E2E walkthrough | [bridge.md](https://github.com/PsyProtocol/psy-memory/blob/main/src/repositories/parth-generic-v1/e2e/bridge.md) |
| Claim-list E2E | [claim-list.md](https://github.com/PsyProtocol/psy-memory/blob/main/src/repositories/parth-generic-v1/e2e/claim-list.md) |
| IDE automation | [psy-ide E2E](https://github.com/PsyProtocol/psy-memory/blob/main/src/repositories/psy-ide/e2e/general.md) |
| Explorer automation | [psy-explorer E2E](https://github.com/PsyProtocol/psy-memory/blob/main/src/repositories/psy-explorer/e2e/general.md) |
| Wallet consumer E2E | [psy-wallet E2E](https://github.com/PsyProtocol/psy-memory/blob/main/src/repositories/psy-wallet/e2e/general.md) |

Use these GitHub artifacts as the reference source. Do not substitute a machine-local psy-memory checkout path in code, documentation, reviews, commands, or commit messages.

## Psy Devnet Operations

1. Use only `make shutdown` and `make run-all` to manage the complete devnet service set.
2. Do not restart individual services through Docker or tmux commands.
3. `make run-all` runs in the current foreground shell and does not create a tmux session.
4. To survive an SSH disconnect, create a tmux session first and run `make run-all` inside it.
5. Do not background `make run-all`; it starts interactive frontend processes.
6. Coordinator edge RPC methods require the `psy_` prefix. The `psy_user_cli` binaries apply it automatically.
7. Use release binaries for primary execution.
8. Mint and withdraw operations for the same user are serial. Different users may run independently.

## Psy E2E Reference Registry

When testing, reviewing, or documenting an E2E scenario, use the canonical links in `External Psy Memory References`. Stateful scenarios require a fresh purged stack and serial execution according to the linked runbook. A pass requires the real end-to-end state transition and committed result; HTTP admission, dummy proofs, empty transitions, or uncommitted candidate roots are not substitutes.
