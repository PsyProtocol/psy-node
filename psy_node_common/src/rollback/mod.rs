//! Offline rollback-to(T): generator inlines keys; executor never reopens backups.

pub mod executor;
pub mod generator;
pub mod keys;
pub mod plan;
pub mod validate;

pub use executor::{
    decode_rollback_phase, execute_rollback_plan, AtomicRollbackPlanProgress,
    ExecutableRollbackPhase, ImtNextAppendIndex, RollbackExecutionStore,
    RollbackOperation, RollbackOutcome, RollbackProgressStore,
};
pub use generator::{
    collect_post_target_generations, generate_rollback_plan, generate_rollback_plan_from_backup_paths,
    BackupKeySource, CoordinatorBackupRequirements, CoordinatorGutaBackup,
    DeployContractBackup, ImtAppendIndexEntry,
    ImtAppendIndexSnapshot, RegisterUserBackup, RealmEndCapBackup,
    RollbackBackupDirectories, RollbackBackupRequirementReader,
    RollbackPlanFromBackupPathsInput, RollbackPlanInput, RollbackStateReader,
    RollbackTempEnumerator, UpdateContractBackup,
};
pub use keys::{
    processor_state_singleton_fields, transform_user_id, DoubleTreeMerkleKey, ImtKeyIndexKey,
    ImtLeafKey, MerkleNodeKey, SingleTreeMerkleKey, TempFieldKey, UserTransformParams,
};
pub use plan::{
    read_rollback_plan, write_rollback_plan_atomic, PostTargetGeneration,
    RollbackNatsConsumerKind, RollbackNatsConsumerTarget, RollbackPhase,
    RollbackPhaseStatus, RollbackPlan, RollbackRole, RollbackSnapshot,
    RollbackTempValueSnapshot, TargetContractState,
};
pub use validate::validate_rollback_plan;