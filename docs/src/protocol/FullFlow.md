# Psy Protocol Wiki: Achieving Scalability with PARTH and ZK Proofs

This protocol reading guide links the architecture, circuit flow, and proof assumptions from user proving through parallel aggregation to the final block proof.

> Updated: 2026-09-08.

## 1. Scalability Challenge and Psy Approach

- [Horizontal scalability](HORIZONTAL_SCALABILITY.md): the serial execution bottleneck and Psy's parallel processing approach.
- [Node architecture](NodeArchitecture.md): the roles participating in transaction processing.

## 2. PARTH Architecture

- [Horizontal scalability](HORIZONTAL_SCALABILITY.md): per-user state isolation and reads anchored to previously finalized state.
- [Common Merkle gadgets](CommonMerkleGadgets.md): the Merkle primitives used by the circuit layers.

## 3. End-to-End Zero-Knowledge Proof Flow

- [Circuit flow](Circuits.md): User Proving Session → Global User Tree Aggregation → final block proof.
- [Proving jobs](ProvingJobs.md): the realm and coordinator job graphs.

## 4. User Proving Session Circuits

- [UPS circuits and gadgets](UPSGadgets.md): session start, standard transactions, deferred transactions, and End Cap.
- [UPS proof tree](UPSProofTree.md): recursive proof organization.
- [User proving assumptions](ZKCircuitJourney.md#1-user-proving-session-local-execution): guarantees carried between local steps.

## 5. Global User Tree Aggregation Circuits

- [GUTA v2 circuits](GUTAV2Circuits.md): End Cap admission, aggregation, checkpoint upgrades, and `RealmFinalizeGUTA` (63).
- [Realm and GUTA gadgets](RealmGUTAGadgets.md): dual variable-height merge, line proofs, and no-change transitions.
- [Realm proving jobs](ProvingJobs.md#2-realm-proving-jobs): P2P Proposal/Certificate submission; no in-circuit `WrappedSignatureProof` (64) after the BLS auth cutover.
- [Coordinator gadgets](CoordinatorGadgets.md): user registration through `BatchAppendUserRegistrationTree`.

## 6. Final Block Proof Generation

- [Coordinator circuits](CoordinatorGadgets.md#10-coordinator-circuits): Part-1 aggregation and checkpoint state transition.
- [Checkpoint proving jobs](ProvingJobs.md#6-checkpoint-state-transition): inputs and public input layout.
- [Bridge circuits](BridgeCircuits.md): checkpoint aggregation and L1 verification wrappers.
- [Privacy circuits](PrivacyCircuits.md): shield deposit claim and private note inclusion.

## 7. Assumption Reduction

- [ZK circuit journey](ZKCircuitJourney.md): assumptions made, discharged, and carried at each stage.
- [Final block proof](ZKCircuitJourney.md#4-final-block-proof): the dependency on the previous block's established state.

## 8. Conclusion

- [Circuit index](Circuits.md) for execution stages.
- [Gadget index](Gadgets.md) for reusable components.
- [Proving jobs](ProvingJobs.md) for dependencies and layouts.
