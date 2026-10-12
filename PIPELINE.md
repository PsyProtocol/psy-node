# Mandatory Change Pipeline

Every agent MUST read this file and `AGENTS.md` before starting work or delegating it. Delegation MUST include the current stage, authorized scope, owned paths, artifact version, and unmet gates. This file owns workflow order; `AGENTS.md` retains repository-specific safety and release requirements. Apply the stricter rule; stop and report an unresolved conflict rather than bypassing a gate.

Quality assurance is abbreviated **QA** below. A stage passes only on recorded evidence for the exact artifact version reviewed. A worker's handoff is not approval, and a role label or model invocation is not evidence.

## Pipeline Applicability

The pipeline scales with change size; match the tier before starting.

| Tier | Trigger | Required order |
|---|---|---|
| Very small | At most ~50 changed production-source lines with one obvious correct form | Do it directly: no design stage, no review gate; ordinary care and the commit rules below apply |
| Medium | Production-source diff up to 2000 changed lines (generated artifacts, lockfiles, and documentation excluded from the count) | Reduced order: a design note in the owning document or task entry, direct implementation by the owner, one independent static review of the changed surface, QA scoped to that surface |
| Large | Production-source diff above 2000 changed lines | The complete [Required Order](#required-order) |

Checkpoint commits remain ungated at any size, and every `AGENTS.md` hard constraint, commit rule, and push/deploy authorization boundary applies regardless of tier. A change that grows past its tier during implementation adopts the next tier's order before its delivery commit; completed stages count toward it.

## Required Order

This is the **delivery** order. It gates push, release, and deployment — not every commit. See [Commit Classes](#commit-classes).

```text
researcher investigation -> technical-writer design
  -> multiple-model design review (at least two rounds) -> clean design
  -> design-reviewer gate -> implementation + authored tests
  -> reviewer static review/fix loop -> QA -> styler
  -> refresh affected QA after styler edits -> reviewer final -> auditor
  -> delivery commit
```

The QA refresh is a return to the QA stage, not permission to skip or reorder the primary stages. Repair loops below invalidate affected approvals.

## Commit Classes

Two commit classes exist. Do not confuse them.

| Class | When it is allowed | Prerequisite gates |
|---|---|---|
| **Checkpoint commit** | Any time work should be preserved — a completed subtask, a milestone, or a backup point before risky edits in a shared worktree. | None from this pipeline. Only the ownership and honesty rules below apply. |
| **Delivery commit** | The change is about to be pushed, released, or deployed. | The complete required order above, for the exact artifact version being delivered. |

A checkpoint commit is a bookkeeping act, not an approval. Do not hold completed work uncommitted until the whole pipeline passes; commit at any progress-preserving moment so work stays reviewable and recoverable. The gates above still gate **delivery**: an unreviewed or unverified change may be committed locally, but it MUST NOT be pushed, released, or deployed until the full order passes for its exact artifact version.

Rules that apply to **every** commit, checkpoint commits included:

1. Stage only paths you own. Never stage, unstage, or commit another contributor's work (`AGENTS.md` rules 2 and 4).
2. Never use `git add .`, `git add -A`, `git commit -a`, or broad pathspecs. List paths explicitly.
3. The message describes the change. It MUST NOT claim tests, review, QA, or audit that did not run for this change; unexecuted verification stays `PENDING`.
4. Never commit `ISSUES.md`, `TASKS.md`, `MEMORY.md`, local ledgers, secrets, or machine-local absolute paths.
5. A checkpoint commit never substitutes for the delivery gate and never authorizes a push.

| Stage / owner | Required entry | Required exit evidence |
|---|---|---|
| Researcher investigation | User request and authorized scope; required repository instructions read. | Source-backed findings with file paths and line numbers, existing behavior, affected boundaries, constraints, and concrete acceptance criteria. Investigation is static; no test execution. |
| Technical-writer design | Investigation findings and acceptance criteria. | Versioned, implementation-ready design specifying interfaces, data ownership, execution flow, failure handling, file impact, planned verification, and a naming table for each new or renamed domain concept, not every local variable: meaning, final spelling, declared equivalent-type sibling mapping, and the protected occurrences named by `AGENTS.md` Naming rule 18, each checked against `docs/src/dev/TERMINOLOGY.md`. No unresolved implementation decisions or automatic scope expansion. |
| Multiple-model design review | Identified design version and source evidence. | At least two distinct models review the SAME frozen design version in parallel; each review identifies its model, reviewed version, concrete findings with evidence, and verdict. One round suffices when it produces no blocking finding (correctness, security, scope, or an acceptance criterion); additional rounds run only on revised versions after findings, never as a fixed floor. Repeating the same model under different roles does not meet the model requirement. Proceed on the first consolidated verdict; a late diverging verdict reopens the affected artifact through the repair loop instead of justifying waiting. |
| Clean design | Completed review rounds and resolved findings. | One coherent design containing accepted decisions, without superseded alternatives, placeholders, or unresolved findings. Cleaning that changes meaning requires another parallel-model review of the changed design. |
| Design-reviewer gate | Exact clean design version and review evidence. | The gate is the FINAL review round's explicit pass on completeness, feasibility, consistency, simplicity, naming, and acceptance criteria, recorded as a distinct verdict inside that round — not a separate serial stage. That pass sweeps the design against every applicable `AGENTS.md` Naming rule, the Naming Quality Checklist, and the current frozen mapping; a substring hit is disposed under rule 18, and an undisposed hit or a domain concept missing from `docs/src/dev/TERMINOLOGY.md` or the naming table fails the gate. Implementation is blocked until this pass. |
| Implementation | Design-reviewer pass on the current design. | Complete in-scope implementation, affected callers and documentation, and authored or updated tests. Record the changed artifact version and handoff. Tests are written but NOT executed. |
| Reviewer static review/fix loop | Complete implementation and authored tests. | Independent static review of code, tests, and documentation; all findings resolved and fixes re-reviewed. Explicit pass that code and tests are complete and ready for QA. No test execution during this loop. |
| QA | Post-implementation reviewer pass on the exact candidate. | Executed, scope-appropriate verification against acceptance criteria, with commands or document-check procedures, environment, artifact version, observed outcomes, and remaining limitations. All failures resolved through the repair loop. |
| Styler | Passing QA evidence. | Behavior-preserving, in-scope refactoring or an explicit no-change decision. As the final naming backstop, the styler sweeps the changed surface against every applicable `AGENTS.md` Naming rule, the Naming Quality Checklist, and the current frozen mapping, and records a rule 18 disposition for each substring hit (a justified non-violation or protected occurrence is not a failure). Record that sweep as exit evidence. No feature expansion or unrelated cleanup; no formatter execution without explicit user authorization. Any edit requires static review and refreshed affected QA evidence before final approval. |
| Reviewer final | Styler handoff, current static-review pass, and current QA evidence. | Independent pass on the final candidate, acceptance criteria, scope, and evidence. Review every line of the exact staged delivery diff using a model different from the author of the changes. |
| Auditor | Final reviewer pass and exact staged delivery candidate. | Independent audit of gate compliance, authorization, security, scope, evidence provenance, and staged contents; no unresolved findings. |

Commit acts are not stages: checkpoint commits are allowed at any progress-preserving moment and delivery commits close the pipeline, both under the rules in [Commit Classes](#commit-classes).

## Terminal Events and Bounded Loops

Every delegated task and every status report must end in one of three terminal events:

1. **Committed artifact** — the commit identifier of the scoped checkpoint or delivery commit.
2. **Executable evidence** — a report with concrete numbers, command output, or `<file>:<line>` findings.
3. **Named blocker** — the exact missing fact, the inspected evidence, and the lookup needed to resolve it.

Pure process states are not progress. A status that only says collecting, awaiting, reviewing, coordinating, or preparing is not a terminal event and must not appear twice in a row for the same task. If a wait is genuinely necessary, name the owner being waited on and the exact expected artifact.

Loops are bounded by findings, not by rounds:

- **Static review/fix loop:** triage every finding as blocking (correctness, security, scope, or an acceptance criterion) or non-blocking (recorded in `ISSUES.md` for a later change). A round with zero blocking findings ends the loop and passes the gate. A repeated sweep that produces no new finding is prohibited; narrow the question instead (`AGENTS.md` Subagent Context rule 5).
- **Wait loops:** a wait is bounded when the owner and the expected artifact are named. Two consecutive status reports without a terminal event trigger escalation: the coordinator narrows the task to one concrete question and an updated current-state brief; a third stalled round triggers direct takeover with a stopped-editing handoff (`AGENTS.md` Multi-Agent Ownership).

## Execution Economy

Stage names name responsibilities, not required subprocesses. The owning agent performs any stage directly unless delegation has a concrete justification recorded in the handoff.

1. **No bounded-artifact delegation.** An artifact the owner can produce in one working pass — a design section or revision, an inventory, a summary of already-gathered evidence, a status report — is produced by the owner directly. Spawning a subagent or parallel worker for such an artifact, then recovering and checking its output, is prohibited overhead. Delegation remains for work needing genuinely separate execution (long builds, independent review, broad search).
2. **Facts once.** A measurement, log finding, or code location supplied by the coordinator with evidence (numbers, `<file>:<line>`) is an accepted input. Reviewers and workers may spot-check a claim, but re-deriving or re-measuring a supplied fact without new contrary evidence is prohibited duplication.
3. **One round-trip per deliverable.** A delegated task returns with its terminal event in one round; a second round on the same deliverable requires an explicit state delta, and a third triggers takeover per `AGENTS.md` Multi-Agent Ownership.
4. **Progress over ceremony.** A checkpoint-grade revision (not a delivery) may proceed from design revision directly into implementation with one combined review covering the revised design and the implementation diff; separate serial design and implementation reviews are required only for delivery commits.

## Hard Execution Boundary

Before the post-implementation reviewer gate passes, agents MUST NOT run tests. This prohibition includes baseline tests, reproductions, unit tests, integration tests, end-to-end tests, smoke checks, benchmarks, throwaway validation scripts, and launching the program to exercise changed behavior. Renaming execution as investigation, verification, or an experiment does not create an exception.

Static source reads, static diff inspection, design analysis, and test authoring are permitted. Compile checks, type checks, lint runs, and builds are also permitted at any time as construction feedback; they are not test execution, and their passing output is never a substitute for executed test evidence in QA. The gated actions remain: running the test suite, benchmarks, smoke checks, live E2E, or launching the program to exercise changed behavior before the post-implementation reviewer pass. Renaming execution as investigation, verification, or an experiment does not create an exception.

Never claim that an unexecuted check passed. Planned verification, static reasoning, historical output, and execution against an older candidate are not current execution evidence. If required evidence cannot be obtained, record the missing prerequisite and leave the gate blocked.

## Repair and Approval Rules

- **Design findings:** The owning agent revises the design; the changed version goes back to the same parallel-model panel once. A revised version with zero blocking findings closes design review; the two-round floor is abolished. The design-reviewer rejects any unresolved gap. A design change after its gate returns to design review and requires a new design-reviewer pass before dependent implementation proceeds.
- **Static-review findings:** Fix code, tests, or documentation within the approved design, then repeat independent static review. Enter QA only after the reviewer explicitly passes the complete revised candidate.
- **QA failures:** Record the failure and fix the responsible code and tests. Obtain independent static review of the fixes before rerunning affected verification in QA. Repeat until acceptance criteria pass. A failure requiring a design change returns to the design stages instead of expanding the implementation silently.
- **Styler edits:** Preserve observable behavior and authorized scope. Independently review the edits statically, return to QA for affected verification, then obtain final reviewer approval. A no-change styler decision retains existing QA evidence only when the candidate is unchanged.
- **Final-review or auditor findings:** Return each finding to its responsible stage. Repeat that stage and every affected downstream gate; refresh verification after changes, restage only owned paths, and repeat independent staged-diff review and audit before the delivery commit. An auditor's proposed fix is not an approval of that fix.
- **Rename batches:** Freeze the concept-family mapping (`AGENTS.md` Naming rule 22) in `docs/src/dev/TERMINOLOGY.md` and the design naming table, then make one coordinated cutover to the spellings authorized at freeze time. The cutover is not a literal single tool call and uses no intermediate spelling. A later user change of a spelling is a new freeze of the affected mapping only, not a retroactive failure of the earlier cutover. Do not place the batch in the post-QA styler slot merely because it renames. It is behavior-preserving work at its owning stage: it does not skip a required gate, and if it changes an already verified candidate the existing repair rules refresh the affected gates, including QA. It must not change wire semantics, hash preimages, or cryptographic literals; those move only through their own regeneration boundary. Exit evidence is the frozen mapping, the cutover, and the rule 18 dispositions. The styler sweep is the final backstop, not the cutover.
- **Candidate changes:** Any post-review edit invalidates approval of the affected artifact. Any change to staged contents requires another line-by-line staged-diff review. Unrelated work remains untouched and unstaged.

## Evidence and Independence

Keep evidence in the task's existing records rather than creating a parallel tracking system. Each handoff identifies the artifact version, owner, reviewed scope, findings, dispositions, verdict, and next unmet gate. Use a commit identifier for committed artifacts or a content digest for an uncommitted candidate; a mutable filename or branch name alone is not a version.

Reviewers MUST assess the actual artifact independently, not merely accept the author's summary. Authors MUST NOT approve their own changes. Preserve distinct reviewer, QA, and auditor judgments; one person's or model's pass does not imply another stage passed. If independent review or the required distinct models are unavailable, report the blocker instead of inventing a review.

## Documentation-Only Changes

Apply the same ordering and independent gates to documentation-only work that CREATES a new document or changes a delivered one. Revising the task's own design document during the task's active cycle is design-stage work under [Required Order](#required-order), not a documentation-only pipeline trigger. Investigation identifies authoritative instructions; design specifies the document contract; implementation writes the document; static review checks the complete candidate. Retain the multiple-model rounds, clean design, design-reviewer gate, final review, and audit.

QA verifies the documents themselves: instruction consistency, stage order, gate conditions, repair loops, links and cited paths, scope, and acceptance criteria. Record the version inspected and actual findings. Mark irrelevant runtime tests, code interfaces, and behavior refactoring as not applicable with a concrete reason; do not invent code, execute unrelated suites, or treat a documentation-only classification as permission to skip review. Styler limits its assessment to clarity without changing meaning; meaning changes return to design review.

## Delivery Safety

Stage and commit only explicitly owned paths; "approved" is a delivery-commit requirement, not a checkpoint-commit one. Preserve other contributors' changes. Do not read or expose secrets in review evidence. Stop editing after handoff; subsequent review or commit belongs to the designated owner unless a finding is assigned back.

Push is prohibited by this repository's safety rules. Deployment, publication, live-account migration, and feature-scope expansion require separate explicit user authorization. This pipeline grants none of them.
