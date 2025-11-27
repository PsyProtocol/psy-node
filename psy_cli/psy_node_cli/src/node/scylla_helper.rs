use parth_core::protocol::core_types::{QDBHashBase, QNetworkDatabaseTypes};
use psy_node_core::psy_core_db::v3_implementation::full::PsyUnifiedCoreDatabaseStore;
use psy_node_scylla::{core::ScyllaCoreStore, tables::{blob::ScyllaBiDirectionalBlobToBlobTablePreparedStatements, hash_to_many_ids::ScyllaHashToManyIdsTablePreparedStatements, merkle::{ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements, ScyllaMerkleNodesZeroPreparedStatements}, object::{ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements, ScyllaGenericObjectSingleIdTablePreparedStatements}, tag_tree::ScyllaTagTreeNodesPreparedStatements, u64_tbl::{ScyllaBidirectionalU64U128MappingPreparedStatements, ScyllaU64ToU64TablePreparedStatements}}};

type ScyllaUnifiedPsyStore<N, Hash, Hasher> = PsyUnifiedCoreDatabaseStore<N, ScyllaBiDirectionalBlobToBlobTablePreparedStatements, ScyllaBidirectionalU64U128MappingPreparedStatements, ScyllaU64ToU64TablePreparedStatements, ScyllaGenericObjectSingleIdTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements, ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaMerkleNodesPreparedStatements, ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesZeroPreparedStatements, ScyllaTagTreeNodesPreparedStatements, ScyllaHashToManyIdsTablePreparedStatements, ScyllaCoreStore<Hash, Hasher>>;

pub async fn setup_scylla_store<N: QNetworkDatabaseTypes>(
    connection_str: &str,
) -> anyhow::Result<ScyllaUnifiedPsyStore<N, N::QHash, N::HasherBase>> {
    todo!()
}