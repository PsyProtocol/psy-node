# Mandatory Change Pipeline

Every agent MUST read this file and `AGENTS.md` before starting work or delegating it. Delegation MUST include the current stage, authorized scope, owned paths, artifact version, and unmet gates. This file owns workflow order; `AGENTS.md` retains repository-specific safety and release requirements. Apply the stricter rule; stop and report an unresolved conflict rather than bypassing a gate.

Quality assurance is abbreviated **QA** below. A stage passes only on recorded evidence for the exact artifact version reviewed. A worker's handoff is not approval, and a role label or model invocation is not evidence.

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
| Technical-writer design | Investigation findings and acceptance criteria. | Versioned, implementation-ready design specifying interfaces, data ownership, execution flow, failure handling, file impact, and planned verification. No unresolved implementation decisions or automatic scope expansion. |
| Multiple-model design review | Identified design version and source evidence. | At least two review rounds, each using at least two distinct models. Each review identifies its model, reviewed version, concrete findings with evidence, and verdict. Revision dispositions and re-review establish that every accepted correction is covered. Repeating the same model under different roles does not meet the model requirement. |
| Clean design | Completed review rounds and resolved findings. | One coherent design containing accepted decisions, without superseded alternatives, placeholders, or unresolved findings. Cleaning that changes meaning requires another multiple-model review of the changed design. |
| Design-reviewer gate | Exact clean design version and review evidence. | Explicit independent pass on completeness, feasibility, consistency, simplicity, naming, and acceptance criteria. Implementation is blocked until this pass. |
| Implementation | Design-reviewer pass on the current design. | Complete in-scope implementation, affected callers and documentation, and authored or updated tests. Record the changed artifact version and handoff. Tests are written but NOT executed. |
| Reviewer static review/fix loop | Complete implementation and authored tests. | Independent static review of code, tests, and documentation; all findings resolved and fixes re-reviewed. Explicit pass that code and tests are complete and ready for QA. No test execution during this loop. |
| QA | Post-implementation reviewer pass on the exact candidate. | Executed, scope-appropriate verification against acceptance criteria, with commands or document-check procedures, environment, artifact version, observed outcomes, and remaining limitations. All failures resolved through the repair loop. |
| Styler | Passing QA evidence. | Behavior-preserving, in-scope refactoring or an explicit no-change decision. No feature expansion or unrelated cleanup; no formatter execution without explicit user authorization. Any edit requires static review and refreshed affected QA evidence before final approval. |
| Reviewer final | Styler handoff, current static-review pass, and current QA evidence. | Independent pass on the final candidate, acceptance criteria, scope, and evidence. Review every line of the exact staged delivery diff using a model different from the author of the changes. |
| Auditor | Final reviewer pass and exact staged delivery candidate. | Independent audit of gate compliance, authorization, security, scope, evidence provenance, and staged contents; no unresolved findings. |
| Checkpoint commit | Any progress-preserving moment: completed subtask, verified milestone, or backup point; you are moving to the next one. | Authorized committer creates a scoped commit and records its identifier. Not an approval; does not authorize a push. |
| Delivery commit | Auditor pass on the unchanged, independently reviewed staged candidate; delivery authorization. | Authorized committer creates the delivery commit and records its identifier. A commit does not authorize a push. |

## Hard Execution Boundary

Before the post-implementation reviewer gate passes, agents MUST NOT run tests. This prohibition includes baseline tests, reproductions, unit tests, integration tests, end-to-end tests, smoke checks, benchmarks, throwaway validation scripts, and launching the program to exercise changed behavior. Renaming execution as investigation, verification, or an experiment does not create an exception.

Static source reads, static diff inspection, design analysis, and test authoring are permitted. Do not use builds, linters, formatters, generators, or other executable checks as a substitute for the prohibited early verification. Schedule executable verification in QA, subject to the user's command restrictions and repository safety rules. A task that prohibits a command remains prohibited after the gate.

Never claim that an unexecuted check passed. Planned verification, static reasoning, historical output, and execution against an older candidate are not current execution evidence. If required evidence cannot be obtained, record the missing prerequisite and leave the gate blocked.

## Repair and Approval Rules

- **Design findings:** The technical-writer revises the design; independent models re-review the changed version. Complete at least two rounds even when the first round finds no issue. The design-reviewer rejects any unresolved gap. A design change after its gate returns to design review and requires a new design-reviewer pass before dependent implementation proceeds.
- **Static-review findings:** Fix code, tests, or documentation within the approved design, then repeat independent static review. Enter QA only after the reviewer explicitly passes the complete revised candidate.
- **QA failures:** Record the failure and fix the responsible code and tests. Obtain independent static review of the fixes before rerunning affected verification in QA. Repeat until acceptance criteria pass. A failure requiring a design change returns to the design stages instead of expanding the implementation silently.
- **Styler edits:** Preserve observable behavior and authorized scope. Independently review the edits statically, return to QA for affected verification, then obtain final reviewer approval. A no-change styler decision retains existing QA evidence only when the candidate is unchanged.
- **Final-review or auditor findings:** Return each finding to its responsible stage. Repeat that stage and every affected downstream gate; refresh verification after changes, restage only owned paths, and repeat independent staged-diff review and audit before the delivery commit. An auditor's proposed fix is not an approval of that fix.
- **Candidate changes:** Any post-review edit invalidates approval of the affected artifact. Any change to staged contents requires another line-by-line staged-diff review. Unrelated work remains untouched and unstaged.

## Evidence and Independence

Keep evidence in the task's existing records rather than creating a parallel tracking system. Each handoff identifies the artifact version, owner, reviewed scope, findings, dispositions, verdict, and next unmet gate. Use a commit identifier for committed artifacts or a content digest for an uncommitted candidate; a mutable filename or branch name alone is not a version.

Reviewers MUST assess the actual artifact independently, not merely accept the author's summary. Authors MUST NOT approve their own changes. Preserve distinct reviewer, QA, and auditor judgments; one person's or model's pass does not imply another stage passed. If independent review or the required distinct models are unavailable, report the blocker instead of inventing a review.

## Documentation-Only Changes

Apply the same ordering and independent gates to documentation-only work. Investigation identifies authoritative instructions; design specifies the document contract; implementation writes the document; static review checks the complete candidate. Retain the multiple-model rounds, clean design, design-reviewer gate, final review, and audit.

QA verifies the documents themselves: instruction consistency, stage order, gate conditions, repair loops, links and cited paths, scope, and acceptance criteria. Record the version inspected and actual findings. Mark irrelevant runtime tests, code interfaces, and behavior refactoring as not applicable with a concrete reason; do not invent code, execute unrelated suites, or treat a documentation-only classification as permission to skip review. Styler limits its assessment to clarity without changing meaning; meaning changes return to design review.

## Delivery Safety

Stage and commit only explicitly owned paths; "approved" is a delivery-commit requirement, not a checkpoint-commit one. Preserve other contributors' changes. Do not read or expose secrets in review evidence. Stop editing after handoff; subsequent review or commit belongs to the designated owner unless a finding is assigned back.

Push is prohibited by this repository's safety rules. Deployment, publication, live-account migration, and feature-scope expansion require separate explicit user authorization. This pipeline grants none of them.
