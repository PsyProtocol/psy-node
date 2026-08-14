# Repo
/home/cj/Projects/mainnet-beta/psy-node
cwd MUST be this repo. Branch feat/p2p.

# Do not
- No formatters, linters, project-wide test suites
- No git push, no commit unless asked
- No new architecture terms (NeutralInbox, lineage, binding, snapshot, handoff, rebase, dead-letter, reconcil, fence, retirement, PSYHOF, PeerBinding, selection_digest)
- No dummy proofs, empty seals, HTTP-only shortcuts
- Do not serialize/pause speculative Realm intake
- Do not enable planner with_realm_finalize_identity or planner type 63
- Do not write TODOs/placeholders
- Do not print credentials
- No unit tests unless a compile-broken existing test must be updated to compile

# Memory (source of truth for Vote/backup semantics)
/mnt/nvme1n1/memory/src/blockchain/psy/parth-generic-v1/proposals/realm-rotation-and-coordinator-p2p.md

§6.1 items 8-9 (backup-output match, still required even though Proposal target was removed):
- parsed backup roots connect: old_realm_root matches local root before application; new_realm_root equals output.final_guta_header.state_transition.new_node_value (header field is new_node_value)
- backup identity fields (realm_id, proposer_sub_id) match the Proposal

§6.3 Vote: issue only after (1) full body received, (2) body/Proposal verified, (3) backup saved as file, (4) GUTA proof + commit output verified. NO replay of backup into local state.

§10.2 Non-proposer:
1. receive Proposal parts (drive.rs already reassembles → ProposalReady)
2. verify body, proof, metadata, root continuity
3. save backup file locally; verify GUTA proof and commit output WITHOUT replaying into local state
4. sign and publish one Vote
5. retain staged backup until coordinator inclusion (apply-after-inclusion is a later item; do not invent apply now)

# User overrides vs stale memory proposal
Memory still shows Proposal[218] with target_checkpoint_id. LIVE CODE already removed it:
- Proposal is 210 bytes, NO target_checkpoint_id (psy_data/src/p2p/messages.rs)
- Certificate is 200 bytes, NO target_checkpoint_id
- vote_message(chain_id, realm_id, validator_tree_root, proposal_id) — 4 args, no target
- proposal_from_parts(...) no longer takes target
- Coordinator decides inclusion T (latest+1). Proposal target is not authoritative.
- 410-byte finalize checkpoint_id MUST be 0 (unbound). Do not re-encode 410-byte output with a guessed target.
- Coordinator rotation at admission uses inclusion T = latest+1, not Proposal target.
- Realm is_scheduled_proposer still uses processing_checkpoint_id for produce-slot — leave that.

# Current broken state (must compile after you finish)
These still reference deleted fields and will not compile:

psy_cli/psy_node_cli/src/node/realm_p2p.rs
- 274-276: proposal.base_checkpoint_id <= proposal.target_checkpoint_id  (DELETE this check; Proposal has no target)
- 314: persist backup pending id uses proposal.target_checkpoint_id
  Persist under proposal_{hex(proposal_id)}/realm_end_cap_gatherer_realm_{id}_sub_{local_sub}_pending_{proposal_id_prefix_or_0}.backup
  Do NOT use a guessed target as pending id. Matching later is by proposal_id dir + end_root.

psy_node_common/src/realm/processor/consensus.rs
- verify_proposal_submission uses proposal.target_checkpoint_id for build_bound_finalize_output
  Use 0 for unbound checkpoint_id in the 410-byte output bind
- sign_vote / form_certificate / validate_certificate still pass target into vote_message / Certificate
  vote_message is 4-arg. Certificate has no target field.

psy_node_common/src/realm/processor/core/process_block.rs
- proposal_from_parts still passes `target` as 3rd arg (now that arg is base_checkpoint_id — check the live signature)
- vote_message still passes proposal.target_checkpoint_id
- build_p2p_finalize_output still binds processing_checkpoint_id into 410-byte output — change to 0

psy_node_common/src/coordinator/edge/handler.rs
- epoch / scheduled proposer / build_bound_finalize_output use proposal.target_checkpoint_id
  Use inclusion T = latest_checkpoint_id + 1 for rotation
  Use 0 for 410-byte finalize checkpoint_id so public_output_hash stays unbound
- log certificate.target_checkpoint_id — field gone

psy_data/src/p2p/messages.rs tests still construct Certificate with target and call vote_message(1,2,100,...)

# BackupVerify — design then implement (this is the hard part)

Problem: decode_proposal_body only checks sha256(backup)==backup_hash. A malicious proposer can put any bytes whose hash is advertised. Vote currently attests durable storage, not that backup matches the GUTA transition.

RGE1 header (psy_node_common/src/realm/processor/gatherers/realm_end_cap_gatherer.rs):
- magic u32 = 0x31_45_47_52 ('RGE1' LE)
- start_root [32]
- end_root [32]
- then more payload

GUTA header (psy_data/src/guta/header.rs + sub_tree_transition.rs):
- state_transition.old_node_value
- state_transition.new_node_value

REQUIRED cheap check (O(1), no tree replay, no gatherer mutation):
1. backup starts with RGE1 magic
2. backup long enough for header
3. start_root == output.final_guta_header.state_transition.old_node_value.into_owned_32bytes()
4. end_root == output.final_guta_header.state_transition.new_node_value.into_owned_32bytes()
5. optionally realm_id in backup path/filename is the proposal realm (do not invent extra header fields that are not on disk)

Do NOT replay the backup into the live gatherer tree.
Do NOT require full merkle rebuild for Vote.
If you evaluate that full replay is needed for safety, implement the cheap header bind NOW and document why full replay is deferred — but the header bind MUST land.

Put the helper next to decode_proposal_body / verify_proposal_submission in consensus.rs, e.g. verify_backup_matches_guta_output(backup, &output) -> Result<()>.
Call it from:
- verify_proposal_submission (so proposer-side verify and non-proposer share one path)
- and/or the non-proposer event consumer after decode

# Non-proposer implementation

Existing skeleton: spawn_processor_realm_network in realm_p2p.rs.
Drive already emits ProposalReady after reassembly (drive.rs handle_proposal_part).
Runner correctly skips produce when not scheduled proposer — do NOT put Vote into runner process_block.

Fix the event consumer so it:
1. skips own proposals (proposer_sub_id == local_sub_id)
2. checks chain_id, realm_id, compute_proposal_id, source NodeId == configured proposer for that sub
3. decode_proposal_body + infer GUTA job type + verify_proposal_submission (which now includes backup-output match)
4. persist backup under proposal_{hex}/... without using target as pending id
5. sign_vote + publish_vote
6. log info on success, warn+continue on reject

If the consumer cannot compile because consensus helpers still take target, fix those helpers in the same pass.

# Target semantics (implement, do not debate)

| Place | Rule |
|---|---|
| Proposal / Certificate / proposal_id / vote_message | no target field |
| 410-byte finalize checkpoint_id | 0 (unbound) |
| Coordinator rotation at GUTA admission | inclusion T = latest+1 |
| Realm produce-slot is_scheduled_proposer | keep processing_checkpoint_id |
| Non-proposer persist pending id | not a checkpoint target; use 0 or a non-target discriminator |

# Acceptance
- cargo check -p psy_data -p psy_node_common -p psy_node_cli  succeeds for the files you touch (or you report the exact remaining errors)
- realm_p2p.rs has no proposal.target_checkpoint_id
- consensus.rs sign_vote/form_certificate/validate_certificate/verify_proposal_submission compile against live Proposal/Certificate/vote_message
- handler.rs admission rotation uses latest+1
- verify_backup_matches_guta_output exists and is called before Vote
- no new files unless strictly required (prefer consensus.rs helper)

Return: files changed, key decisions with file:line, remaining compile errors if any.
