use parth_core::protocol::core_types::QNetworkTypesConfigHelper;
use psy_core::{
    constants::{
        chain_id::PsyChainNetworkType,
        proving_backends::PsyChainProvingBackendType,
    },
    job::job_id::QProvingJobDataID,
    network_config::PsyNetworkLocalDevnetConstants,
};
use psy_data::protocol::canonical_chain::NetworkId;
use psy_jtmb_testing_core::protocol_types::ZKTypesJTMBGoldilocksPoseidon;
use psy_node_scylla::psy_setup::{
    inspect_realm_branch_exact_readiness, RealmBranchExactReadinessSummary,
};
use psy_plonky2_circuits::protocol_types::ZKTypesPlonky2GoldilocksPoseidon;

pub async fn inspect(
    keyspace: &str,
    connection_string: &str,
    network: PsyChainNetworkType,
    realm_id: u32,
    realm_sub_id: u16,
    proving_backend: PsyChainProvingBackendType,
) -> anyhow::Result<RealmBranchExactReadinessSummary> {
    if network != PsyChainNetworkType::LocalDevnet {
        anyhow::bail!(
            "unsupported network type {network:?} for Realm rollback readiness inspection"
        );
    }
    let network_id = NetworkId::from_network_type(network);
    match proving_backend {
        PsyChainProvingBackendType::Plonky2PoseidonGoldilocks => {
            type N = QNetworkTypesConfigHelper<
                QProvingJobDataID,
                ZKTypesPlonky2GoldilocksPoseidon,
                PsyNetworkLocalDevnetConstants,
            >;
            inspect_realm_branch_exact_readiness::<N>(
                keyspace,
                connection_string,
                network_id,
                realm_id,
                realm_sub_id,
            )
            .await
        }
        PsyChainProvingBackendType::JTMBPoseidonGoldilocks => {
            type N = QNetworkTypesConfigHelper<
                QProvingJobDataID,
                ZKTypesJTMBGoldilocksPoseidon,
                PsyNetworkLocalDevnetConstants,
            >;
            inspect_realm_branch_exact_readiness::<N>(
                keyspace,
                connection_string,
                network_id,
                realm_id,
                realm_sub_id,
            )
            .await
        }
        unsupported => anyhow::bail!(
            "unsupported proving backend {unsupported:?} for Realm rollback readiness inspection"
        ),
    }
}
