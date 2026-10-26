use parth_core::pgoldilocks::QHashOut;
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_data::{
    config::network_config::{PsyNodeCircuitFingerprintConfig, PsyNodeCircuitFingerprintConfigProvider},
    genesis::genesis_block_setup::{PsyGenesisBlockSetupData, PsyGenesisBlockSetupDataProvider},
};

use crate::node::config::networks::local_devnet::{get_genesis_block_setup_data_for_local_devnet, get_psy_node_circuit_config_for_local_devnet};

type F = parth_core::PF;
type Hash = QHashOut<F>;

/// Network names, not magic values, distinguish localhost from public testnet.
pub fn get_compiled_plonky2_network() -> anyhow::Result<PsyChainNetworkType> {
    match psy_config::CURRENT_NETWORK {
        "localhost" => Ok(PsyChainNetworkType::LocalDevnet),
        "testnet" => Ok(PsyChainNetworkType::PsyPublicTestnet),
        name => anyhow::bail!("Unsupported compiled Plonky2 network: {name}"),
    }
}

/// The cached circuits use the existing shared tree layout, not the unused
/// historical public-testnet constants. Selecting a network must not change it.
pub fn ensure_plonky2_network(network: PsyChainNetworkType) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(network, PsyChainNetworkType::LocalDevnet | PsyChainNetworkType::PsyPublicTestnet),
        "Unsupported network type for Plonky2: {network:?}"
    );
    let name = network.config_key()?;
    anyhow::ensure!(
        name == psy_config::CURRENT_NETWORK && network.get_chain_id() == psy_config::PSY_NETWORK_MAGIC,
        "Plonky2 network {name} does not match binary network {}",
        psy_config::CURRENT_NETWORK
    );
    if let Some(selected) = std::env::var_os("PSY_NETWORK") {
        anyhow::ensure!(selected == name, "PSY_NETWORK does not match Plonky2 network {name}");
    }
    let path = std::env::var("PSY_CONFIG_PATH").unwrap_or_else(|_| "psy-genesis/config.json".to_string());
    let config = psy_config::PsyConfigGoldilocks::builder().path(&path).network(name).build()?;
    validate_plonky2_network_config(config.get_current_network()?)?;
    Ok(())
}

fn validate_plonky2_network_config(network: &psy_config::NetworkConfigGoldilocks) -> anyhow::Result<()> {
    use parth_core::protocol::core_types::QNetworkTreeConstants;
    use psy_core::network_config::PsyNetworkLocalDevnetConstants as N;
    anyhow::ensure!(
        network.global_user_tree_height == psy_config::GLOBAL_USER_TREE_HEIGHT
            && network.global_user_tree_height == N::GLOBAL_USER_TREE_HEIGHT
            && network.realm_user_tree_height == psy_config::REALM_USER_TREE_HEIGHT
            && network.realm_user_tree_height == N::REALM_GLOBAL_USER_TREE_HEIGHT
            && network.group_realm_height == psy_config::GROUP_REALM_HEIGHT
            && network.group_realm_height == N::GROUP_REALM_HEIGHT
            && network.users_per_realm == psy_config::USERS_PER_REALM
            && network.users_per_realm == u64::from(N::MAX_USERS_PER_REALM)
            && network.p2p.checkpoints_per_epoch == psy_config::CHECKPOINTS_PER_EPOCH,
        "Plonky2 network tree heights or epoch differ from the compiled circuit configuration"
    );
    Ok(())
}

#[derive(Clone, Debug, Copy)]
pub struct PsyPlonky2NodeConfigResolver {}
impl PsyPlonky2NodeConfigResolver {
    pub fn new() -> Self {
        Self {}
    }
}
impl PsyNodeCircuitFingerprintConfigProvider<Hash> for PsyPlonky2NodeConfigResolver {
    fn get_circuit_fingerprint_config_for_network(&self, network: PsyChainNetworkType) -> anyhow::Result<PsyNodeCircuitFingerprintConfig<Hash>> {
        ensure_plonky2_network(network)?;
        get_psy_node_circuit_config_for_local_devnet()
    }
}
impl PsyGenesisBlockSetupDataProvider<F, Hash> for PsyPlonky2NodeConfigResolver {
    fn get_genesis_block_setup_data_for_network(&self, network: PsyChainNetworkType, genesis_data_path: Option<String>) -> anyhow::Result<PsyGenesisBlockSetupData<F, Hash>> {
        ensure_plonky2_network(network)?;
        anyhow::ensure!(
            network != PsyChainNetworkType::PsyPublicTestnet || genesis_data_path.is_some(),
            "Public testnet requires --genesis-data-path; empty development Genesis is not allowed"
        );
        get_genesis_block_setup_data_for_local_devnet(genesis_data_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_plonky2_network_uses_stage_not_shared_magic() -> anyhow::Result<()> {
        if !matches!(psy_config::CURRENT_NETWORK, "localhost" | "testnet") {
            assert!(get_compiled_plonky2_network().is_err());
            return Ok(());
        }
        let network = get_compiled_plonky2_network()?;
        assert_eq!(network.config_key()?, psy_config::CURRENT_NETWORK);
        assert_eq!(network.get_chain_id(), psy_config::PSY_NETWORK_MAGIC);
        ensure_plonky2_network(network)?;
        Ok(())
    }

    #[test]
    fn plonky2_network_requires_the_compiled_stage() {
        for (network, stage) in [
            (PsyChainNetworkType::LocalDevnet, "localhost"),
            (PsyChainNetworkType::PsyPublicTestnet, "testnet"),
        ] {
            assert_eq!(ensure_plonky2_network(network).is_ok(), psy_config::CURRENT_NETWORK == stage);
        }
        for network in [PsyChainNetworkType::PsyMainnet, PsyChainNetworkType::PsyTeamDevnet,
            PsyChainNetworkType::InternalDevnet, PsyChainNetworkType::InternalTestnet,
            PsyChainNetworkType::InternalPreProduction, PsyChainNetworkType::PsyPublicCanary] {
            assert!(ensure_plonky2_network(network).is_err());
        }
    }

    #[test]
    fn testnet_resolver_keeps_cached_fingerprints_and_requires_genesis() -> anyhow::Result<()> {
        let resolver = PsyPlonky2NodeConfigResolver::new();
        let network = PsyChainNetworkType::PsyPublicTestnet;
        if psy_config::CURRENT_NETWORK != "testnet" {
            assert!(resolver.get_circuit_fingerprint_config_for_network(network).is_err());
            return Ok(());
        }
        assert_eq!(
            resolver.get_circuit_fingerprint_config_for_network(network)?,
            get_psy_node_circuit_config_for_local_devnet()?
        );
        let error = resolver.get_genesis_block_setup_data_for_network(network, None).unwrap_err();
        assert!(error.to_string().contains("requires --genesis-data-path"));
        Ok(())
    }

    #[test]
    fn testnet_genesis_is_read_from_the_supplied_file() -> anyhow::Result<()> {
        if psy_config::CURRENT_NETWORK != "testnet" {
            assert!(ensure_plonky2_network(PsyChainNetworkType::PsyPublicTestnet).is_err());
            return Ok(());
        }
        let genesis = crate::node::config::networks::local_devnet::get_genesis_block_setup_data_for_local_devnet_default()?;
        let bytes = serde_json::to_vec(&genesis)?;
        let path = std::env::temp_dir().join(format!("psy-testnet-genesis-{}-{}.json", std::process::id(), rand::random::<u64>()));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
        std::io::Write::write_all(&mut file, &bytes)?;
        drop(file);
        let loaded = PsyPlonky2NodeConfigResolver::new().get_genesis_block_setup_data_for_network(
            PsyChainNetworkType::PsyPublicTestnet, Some(path.to_string_lossy().into_owned())
        );
        std::fs::remove_file(&path)?;
        assert_eq!(serde_json::to_value(loaded?)?, serde_json::to_value(genesis)?);
        assert!(PsyPlonky2NodeConfigResolver::new().get_genesis_block_setup_data_for_network(
            PsyChainNetworkType::PsyPublicTestnet, Some(path.to_string_lossy().into_owned())
        ).is_err());
        Ok(())
    }

    #[test]
    fn plonky2_rejects_configured_tree_or_epoch_changes() -> anyhow::Result<()> {
        let config = psy_config::PsyConfigGoldilocks::builder()
            .json(include_str!("../../../../../psy-genesis/config.json"))
            .network(psy_config::CURRENT_NETWORK).build()?;
        let network = config.get_current_network()?;
        validate_plonky2_network_config(network)?;
        let mut changed = network.clone();
        changed.global_user_tree_height += 1;
        assert!(validate_plonky2_network_config(&changed).is_err());
        changed = network.clone();
        changed.realm_user_tree_height += 1;
        assert!(validate_plonky2_network_config(&changed).is_err());
        changed = network.clone();
        changed.group_realm_height += 1;
        assert!(validate_plonky2_network_config(&changed).is_err());
        changed = network.clone();
        changed.users_per_realm += 1;
        assert!(validate_plonky2_network_config(&changed).is_err());
        changed = network.clone();
        changed.p2p.checkpoints_per_epoch += 1;
        assert!(validate_plonky2_network_config(&changed).is_err());
        Ok(())
    }
}
