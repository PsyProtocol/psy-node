use psy_core::constants::chain_id::PsyChainNetworkType;
use serde_with::serde_as;

use crate::v1::qdata::checkpoint::PQEDCheckpointLeafStats;
use crate::v1::qdata::contract::PQBCDeployContract;
use crate::user::complete_user_record::PsyCompactUserDefinition;


#[serde_as]
#[pderive::serialize_copy]
pub struct ValidatorGenesisEntry {
    pub realm_id: u32,
    pub realm_sub_id: u16,
    pub validator_user_id: u64,
    #[serde(default = "default_zero_node_id")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub node_id: [u8; 38],
    #[serde(default = "default_zero_bls_public_key")]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub bls_public_key: [u8; 48],
}

fn default_zero_node_id() -> [u8; 38] {
    [0u8; 38]
}

fn default_zero_bls_public_key() -> [u8; 48] {
    [0u8; 48]
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyGenesisBlockSetupData<F, Hash> {
    pub contracts: Vec<PQBCDeployContract<Hash>>,
    pub users: Vec<PsyCompactUserDefinition<Hash>>,
    pub checkpoint_stats: PQEDCheckpointLeafStats<F, Hash>,
    pub deposit_tree_root: Hash,
    pub withdrawal_tree_root: Hash,
    #[serde(default)]
    #[ts(skip)]
    pub validators: Vec<ValidatorGenesisEntry>,
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