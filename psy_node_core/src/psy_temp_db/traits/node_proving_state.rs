use async_trait::async_trait;
use parth_core::node::realm_identifier::QRealmIdentifier;
use psy_data::node::node_proving_state::PsyNodeProvingState;



#[async_trait]
pub trait QTempDBNodeProvingStateReader {
    async fn get_psy_node_proving_state(&self, rid: &QRealmIdentifier) -> anyhow::Result<PsyNodeProvingState>;
}

#[async_trait]
pub trait QTempDBNodeProvingStateWriter {
    async fn set_psy_node_proving_state(&self, rid: &QRealmIdentifier, state: &PsyNodeProvingState) -> anyhow::Result<()>;
}

pub trait QTempDBNodeProvingStateStore: QTempDBNodeProvingStateReader + QTempDBNodeProvingStateWriter {}
impl<T: QTempDBNodeProvingStateReader + QTempDBNodeProvingStateWriter> QTempDBNodeProvingStateStore for T {}





