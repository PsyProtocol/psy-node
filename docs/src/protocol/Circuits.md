# Psy Circuit Flow

This protocol index follows circuit execution from local user proving to the final block proof and links to the specialized circuit references.

> Updated: 2026-09-08.

## 1. User Proving Session: Local Execution

The user builds a recursive proof chain locally or through a delegated prover.

- [UPS circuits](UPSGadgets.md#14-ups-circuits): session start, standard transactions, deferred transactions, and End Cap.
- [UPS gadgets](UPSGadgets.md): inputs, constraints, and session authorization.
- [Proofs and assumptions](ZKCircuitJourney.md#1-user-proving-session-local-execution): the guarantees carried between user proving steps.

## 2. Global User Tree Aggregation: Parallel Network Execution

Realm workers admit End Cap proofs, aggregate state transitions, and finalize realm roots.

- [GUTA v2 circuits](GUTAV2Circuits.md): Single/Two EndCap, TwoGUTA, linear and checkpoint-upgrade variants.
- [RealmFinalizeGUTACircuit](GUTAV2Circuits.md#5-realmfinalizegutacircuit): type 63, followed by P2P Proposal/Certificate before Coordinator `psy_submit_guta`; no in-circuit `WrappedSignatureProof` (64) after the BLS auth cutover.
- [Realm gadgets](RealmGUTAGadgets.md): verification, dual variable-height merge, line proofs, and no-change transitions.
- [Coordinator registration](CoordinatorGadgets.md#1-batchappenduserregistrationtreegadget): `BatchAppendUserRegistrationTree`, not a GUTA-named register circuit.
- [Proving jobs](ProvingJobs.md#2-realm-proving-jobs): live circuit types and the realm job graph.

## 3. Final Block Proof

Coordinator proofs combine registration, deployment, update, and GUTA roots into a checkpoint append.

- [Coordinator circuits](CoordinatorGadgets.md#10-coordinator-circuits): `CheckpointStateTransition` (32) and Part-1 `AggUserRegisterDeployContractsGUTA` (40).
- [Coordinator proving jobs](ProvingJobs.md#3-coordinator-proving-jobs): dependencies and public input layouts.
- [Final block proof assumptions](ZKCircuitJourney.md#4-final-block-proof): continuity with the previous checkpoint root.

## 4. Bridge and privacy (client / relayer)

- [Bridge circuits](BridgeCircuits.md): deposit append, withdrawal claim, and BridgeAgg Chain → Final → Wrap.
- [Privacy circuits](PrivacyCircuits.md): shield deposit claim and private note inclusion.
- [Common Merkle gadgets](CommonMerkleGadgets.md): shared Merkle primitives.
- [Gadget index](Gadgets.md) and [full-flow reading guide](FullFlow.md).
