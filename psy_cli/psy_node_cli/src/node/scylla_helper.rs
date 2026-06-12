use parth_core::protocol::core_types::QNetworkDatabaseTypes;
use psy_node_core::psy_core_db::v3_implementation::full::PsyUnifiedCoreDatabaseStore;
use psy_node_scylla::{
    core::ScyllaCoreStore,
    tables::{
        blob::ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
        counter::u64_counter::ScyllaU64ToU64CounterTablePreparedStatements,
        hash_to_many_ids::ScyllaHashToManyIdsTablePreparedStatements,
        imt::{ScyllaIMTNextAppendIndexPreparedStatements, imt_key_index::ScyllaIMTKeyIndexPreparedStatements, imt_leaf::ScyllaIMTLeafPreparedStatements},
        merkle::{ScyllaDoubleMerkleNodesPreparedStatements, ScyllaMerkleNodesPreparedStatements, ScyllaMerkleNodesZeroPreparedStatements},
        object::{
            ScyllaGenericKeyIdValueTablePreparedStatements, ScyllaGenericObjectDoubleIdTablePreparedStatements,
            ScyllaGenericObjectSingleIdTablePreparedStatements,
        },
        tag_tree::ScyllaTagTreeNodesPreparedStatements,
        u64_table::{ScyllaBidirectionalU64U128MappingPreparedStatements, ScyllaU64ToU64TablePreparedStatements},
    },
};

type ScyllaUnifiedPsyStore<N, Hash, Hasher> = PsyUnifiedCoreDatabaseStore<
    N,
    ScyllaBiDirectionalBlobToBlobTablePreparedStatements,
    ScyllaBidirectionalU64U128MappingPreparedStatements,
    ScyllaU64ToU64TablePreparedStatements,
    ScyllaU64ToU64CounterTablePreparedStatements,
    ScyllaGenericObjectSingleIdTablePreparedStatements,
    ScyllaGenericObjectDoubleIdTablePreparedStatements,
    ScyllaGenericKeyIdValueTablePreparedStatements,
    ScyllaMerkleNodesPreparedStatements,
    ScyllaDoubleMerkleNodesPreparedStatements,
    ScyllaMerkleNodesZeroPreparedStatements,
    ScyllaTagTreeNodesPreparedStatements,
    ScyllaHashToManyIdsTablePreparedStatements,
    ScyllaIMTLeafPreparedStatements,
    ScyllaIMTKeyIndexPreparedStatements,
    ScyllaIMTNextAppendIndexPreparedStatements,
    ScyllaCoreStore<Hash, Hasher>,
>;

pub async fn setup_scylla_store<N: QNetworkDatabaseTypes>(
    _connection_str: &str,
) -> anyhow::Result<ScyllaUnifiedPsyStore<N, N::QHash, N::HasherBase>> {
    todo!()
}
