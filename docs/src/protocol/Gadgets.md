# Psy Circuit Gadgets

This protocol index links reusable circuit components to their specialized gadget references and the circuit flow.

> Updated: 2026-09-08.

## 1. User Proving Session Gadgets

- [UPS gadgets](UPSGadgets.md): session initialization, contract function verification, state transitions, deferred debt, and End Cap authorization.
- [UPS circuits](UPSGadgets.md#14-ups-circuits): wrappers that compose the session gadgets.

## 2. Global User Tree Aggregation Gadgets

- [Realm and GUTA gadgets](RealmGUTAGadgets.md): statistics, headers, End Cap verification, recursive verification, line proofs, and no-change transitions.
- [GUTA v2 circuits](GUTAV2Circuits.md): live aggregation circuits and constraint pseudocode; `DualVariableHeightStateTransitionGadget` replaces obsolete `TwoNCAStateTransitionGadget`.
- [Legacy user-registration gadget sketches](RealmGUTAGadgets.md#10-legacy-user-registration-gadget-sketches): historical `GUTARegisterUser*` descriptions, not live proving-job circuits.
- [Coordinator gadgets](CoordinatorGadgets.md): live registration, deployment, update, and checkpoint aggregation.

## 3. Shared Merkle, Bridge, and Privacy Gadgets

- [Common Merkle gadgets](CommonMerkleGadgets.md): inclusion, delta, historical-root, Spiderman, variable-height, and append primitives.
- [Bridge circuits and gadgets](BridgeCircuits.md): deposit append, checkpoint aggregation, withdrawal claim, and wrappers.
- [Privacy circuits](PrivacyCircuits.md): shield deposit claim, private note inclusion, and contract-state slot binding.

## 4. Circuit Flow

- [Circuit index](Circuits.md): local proving, realm aggregation, and final block proof.
- [Proving jobs](ProvingJobs.md): circuit types, dependencies, and public input layouts.
- [ZK circuit journey](ZKCircuitJourney.md): proofs and assumptions at each stage.
- [Full-flow reading guide](FullFlow.md): architecture and end-to-end navigation.
