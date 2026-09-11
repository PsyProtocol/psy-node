use psy_core::constants::chain_id::PsyChainNetworkType;

use crate::v1::qdata::checkpoint::PQEDCheckpointLeafStats;
use crate::v1::qdata::contract::PQBCDeployContract;
use crate::user::complete_user_record::PsyCompactUserDefinition;


#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyGenesisBlockSetupData<F, Hash> {
    pub contracts: Vec<PQBCDeployContract<Hash>>,
    pub users: Vec<PsyCompactUserDefinition<Hash>>,
    pub checkpoint_stats: PQEDCheckpointLeafStats<F, Hash>,
    pub deposit_tree_root: Hash,
    pub withdrawal_tree_root: Hash,
}




impl<F, Hash> PsyGenesisBlockSetupData<F, Hash> {
    pub fn get_contract_state_tree_height(&self, contract_id: u64) -> anyhow::Result<u8> {
        let index = contract_id as usize;
        if index < self.contracts.len() {
            Ok(self.contracts[index].code_definition.state_tree_height as u8)
        } else {
            anyhow::bail!("Attempted to get state tree height for an undefined Contract ID {}, which is not defined in the genesis block setup (max defined contract id {})", contract_id, self.contracts.len());
        }
    }
}

pub trait PsyGenesisBlockSetupDataProvider<F, Hash> {
    fn get_genesis_block_setup_data_for_network(&self, network: PsyChainNetworkType, genesis_data_path: Option<String>) -> anyhow::Result<PsyGenesisBlockSetupData<F, Hash>>;
}

#[cfg(test)]
mod tests {
    use parth_core::{pgoldilocks::QHashOut, utils::QPGenRandom, PF};
    use psy_core::constants::chain_id::PsyChainNetworkType;

    use super::*;
    use crate::v1::qdata::contract::ContractCodeDefinition;

    type Hash = QHashOut<PF>;

    fn deploy_contract(state_tree_height: u16) -> PQBCDeployContract<Hash> {
        PQBCDeployContract::new(
            QHashOut::<PF>::from_values(1, 0, 0, 0),
            ContractCodeDefinition { state_tree_height, functions: vec![] },
            vec![QHashOut::<PF>::from_values(2, 0, 0, 0)],
            QHashOut::<PF>::from_values(3, 0, 0, 0),
        )
    }

    #[cfg(feature = "rand_gen")]
    fn setup_data(contracts: Vec<PQBCDeployContract<Hash>>) -> PsyGenesisBlockSetupData<PF, Hash> {
        PsyGenesisBlockSetupData {
            contracts,
            users: vec![],
            checkpoint_stats: PQEDCheckpointLeafStats::qp_rand_gen(),
            deposit_tree_root: QHashOut::<PF>::from_values(4, 0, 0, 0),
            withdrawal_tree_root: QHashOut::<PF>::from_values(5, 0, 0, 0),
        }
    }

    #[cfg(feature = "rand_gen")]
    #[test]
    fn state_tree_height_resolves_defined_contracts_and_errors_on_unknown_ids() {
        let data = setup_data(vec![deploy_contract(10), deploy_contract(20)]);
        assert_eq!(data.get_contract_state_tree_height(0).unwrap(), 10);
        assert_eq!(data.get_contract_state_tree_height(1).unwrap(), 20);

        let err = data.get_contract_state_tree_height(2).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("undefined Contract ID 2"), "unexpected error message: {}", message);
        assert!(message.contains("max defined contract id 2"), "unexpected error message: {}", message);

        let empty = setup_data(vec![]);
        assert!(empty.get_contract_state_tree_height(0).is_err());
    }

    #[cfg(feature = "rand_gen")]
    #[test]
    fn provider_trait_serves_setup_data_for_any_network() {
        struct FixedProvider(PsyGenesisBlockSetupData<PF, Hash>);

        impl PsyGenesisBlockSetupDataProvider<PF, Hash> for FixedProvider {
            fn get_genesis_block_setup_data_for_network(
                &self,
                _network: PsyChainNetworkType,
                _genesis_data_path: Option<String>,
            ) -> anyhow::Result<PsyGenesisBlockSetupData<PF, Hash>> {
                Ok(self.0.clone())
            }
        }

        let data = setup_data(vec![deploy_contract(30)]);
        let provider = FixedProvider(data.clone());
        let for_network = provider
            .get_genesis_block_setup_data_for_network(PsyChainNetworkType::InternalDevnet, None)
            .unwrap();
        assert_eq!(for_network.get_contract_state_tree_height(0).unwrap(), 30);
        assert_eq!(for_network.users.len(), 0);

        let with_path = provider
            .get_genesis_block_setup_data_for_network(
                PsyChainNetworkType::PsyMainnet,
                Some("unused/path.json".to_string()),
            )
            .unwrap();
        assert_eq!(with_path.deposit_tree_root, data.deposit_tree_root);
        assert_eq!(with_path.withdrawal_tree_root, data.withdrawal_tree_root);
        assert_eq!(with_path.contracts.len(), data.contracts.len());
    }
}