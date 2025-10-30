use parth_core::data::proof_input::CircuitInputWithDependencies;
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{agg::AggStateTransitionInput, proof_input::guta::{GUTAOnlyRegisterUsersInput, VerifyGUTARegisterUsersCircuitInputSimple, VerifyGUTAToCapCircuitInputSimple, VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple, VerifyLeftEndCapRightGUTAInputSimple, VerifyLeftGUTARightEndCapInputSimple, VerifySingleEndCapInput, VerifyTwoEndCapCircuitInput, VerifyTwoGUTAProofGadgetStandardInputSimple, VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple}, protocol::circuit_inputs::{agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput, append_user_registration_tree::QCAppendUserRegistrationTreeCircuitInput, checkpoint_transition::QCQEDCheckpointStateTransitionInput, deploy_contracts::QCBatchDeployContractsCircuitInput}};



pub type PCIGUTAOnlyRegisterUsers<Hash> = GUTAOnlyRegisterUsersInput<Hash>;

pub type PCIGUTARegisterUsers<F, Hash> = CircuitInputWithDependencies<VerifyGUTARegisterUsersCircuitInputSimple<F, Hash>, QProvingJobDataID>;
// input: GUTA


pub type PCIGUTAVerifyToCapWithCheckpointUpgrade<F, Hash> = CircuitInputWithDependencies<VerifyGUTAToCapUpgradeCheckpointCircuitInputSimple<F, Hash>, QProvingJobDataID>;

pub type PCIGUTAVerifyToCap<F, Hash> = CircuitInputWithDependencies<VerifyGUTAToCapCircuitInputSimple<F, Hash>, QProvingJobDataID>;

pub type PCIGUTALeftEndCapRightGUTA<F, Hash> = CircuitInputWithDependencies<VerifyLeftEndCapRightGUTAInputSimple<F, Hash>, QProvingJobDataID>;

pub type PCIGUTALeftGUTARightEndCap<F, Hash> = CircuitInputWithDependencies<VerifyLeftGUTARightEndCapInputSimple<F, Hash>, QProvingJobDataID>;

pub type PCIGUTASingleEndCap<F, Hash> = CircuitInputWithDependencies<VerifySingleEndCapInput<F, Hash>, QProvingJobDataID>;

pub type PCIGUTATwoEndCap<F, Hash> = CircuitInputWithDependencies<VerifyTwoEndCapCircuitInput<F, Hash>, QProvingJobDataID>;

pub type PCIGUTATwoGUTAWithCheckpointUpgrade<F, Hash> = CircuitInputWithDependencies<VerifyTwoGUTAProofUpgradeCheckpointStandardInputSimple<F, Hash>, QProvingJobDataID> ;

pub type PCIGUTATwoGUTA<F, Hash> = CircuitInputWithDependencies<VerifyTwoGUTAProofGadgetStandardInputSimple<F, Hash>, QProvingJobDataID>;

pub type PCIAggUserRegisterDeployContractsGUTA<F, Hash> = CircuitInputWithDependencies<QCAggUserRegistartionDeployContractsGUTAInput<F, Hash>, QProvingJobDataID>;

pub type PCIAppendUserRegistrationTree<Hash> = QCAppendUserRegistrationTreeCircuitInput<Hash>;

pub type PCIBatchDeployContracts<F, Hash> = QCBatchDeployContractsCircuitInput<F, Hash>;

pub type PCIGenerateRollupStateTransitionProof<F, Hash> = CircuitInputWithDependencies<QCQEDCheckpointStateTransitionInput<F, Hash>, QProvingJobDataID>;

pub type PCIAppendUserRegistrationTreeAggregate<Hash> = CircuitInputWithDependencies<AggStateTransitionInput<Hash>, QProvingJobDataID>;

pub type PCIBatchDeployContractsAggregate<Hash> = CircuitInputWithDependencies<AggStateTransitionInput<Hash>, QProvingJobDataID>;


