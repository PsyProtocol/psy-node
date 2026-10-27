use psy_core::constants::chain_id::PsyChainNetworkType;
use serde_with::serde_as;

use crate::v1::qdata::checkpoint::PQEDCheckpointLeafStats;
use crate::v1::qdata::contract::{CanonicalLayoutManifest, PQBCDeployContract};
use crate::user::complete_user_record::PsyCompactUserDefinition;


#[serde_as]
#[pderive::serialize_copy]
pub struct GenesisValidator {
    pub realm_id: u32,
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

/// Genesis metadata is mandatory and distinct from proof-bearing deploy RPCs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize, ts_rs::TS)]
#[serde(bound = "for<'de2> Hash: serde::Deserialize<'de2> + serde::Serialize")]
#[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "serialize_rkyv", rkyv(archive_bounds(Hash: rkyv::Archive)))]
#[cfg_attr(feature = "serialize_speedy", derive(speedy::Readable, speedy::Writable))]
#[ts(bound = "Hash: ts_rs::TS")]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct PsyGenesisContract<Hash> {
    #[serde(flatten)]
    #[ts(flatten)]
    pub deploy_contract: PQBCDeployContract<Hash>,
    pub state_layout: CanonicalLayoutManifest<Hash>,
}

impl<Hash> std::ops::Deref for PsyGenesisContract<Hash> {
    type Target = PQBCDeployContract<Hash>;

    fn deref(&self) -> &Self::Target {
        &self.deploy_contract
    }
}

/// Explicit layout for storage-free test deployments; never used by the generator.
#[cfg(any(test, feature = "testbed"))]
pub fn genesis_contract_with_empty_layout_fixture(
    deploy_contract: PQBCDeployContract<parth_core::PHash>,
) -> PsyGenesisContract<parth_core::PHash> {
    use parth_core::pgoldilocks::PoseidonHasher;
    use crate::v1::qdata::contract::{
        contract_state_layout, CanonicalContractStateLayout, STATE_LAYOUT_VERSION,
    };
    let state_tree_height = deploy_contract.code_definition.state_tree_height;
    let contract_layout = contract_state_layout::<PoseidonHasher, parth_core::PF, parth_core::PHash>(
        &[], psy_core::constants::protocol::STATE_LAYOUT_TREE_HEIGHT,
        usize::from(state_tree_height),
    ).expect("valid empty test layout");
    PsyGenesisContract {
        deploy_contract,
        state_layout: CanonicalLayoutManifest {
            layout_version: STATE_LAYOUT_VERSION,
            state_tree_height,
            layout: CanonicalContractStateLayout {
                contract_layout, field_type_layouts: vec![], struct_layouts: Default::default(),
            },
            field_type_dags: vec![],
        },
    }
}

#[pderive::serialize_clone_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyGenesisBlockSetupData<F, Hash> {
    pub contracts: Vec<PsyGenesisContract<Hash>>,
    pub users: Vec<PsyCompactUserDefinition<Hash>>,
    pub checkpoint_stats: PQEDCheckpointLeafStats<F, Hash>,
    pub deposit_tree_root: Hash,
    pub withdrawal_tree_root: Hash,
    #[serde(default)]
    #[ts(skip)]
    pub validators: Vec<GenesisValidator>,
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

    fn genesis_layout_json_fixture() -> serde_json::Value {
        serde_json::json!({
            "contracts": [deploy_contract(32)],
            "users": [],
            "checkpoint_stats": PQEDCheckpointLeafStats::<PF, Hash>::new_empty(),
            "deposit_tree_root": Hash::from_values(4, 0, 0, 0),
            "withdrawal_tree_root": Hash::from_values(5, 0, 0, 0),
            "validators": []
        })
    }

    #[test]
    fn genesis_layout_missing_metadata_is_rejected() {
        let json = genesis_layout_json_fixture();
        let result = serde_json::from_value::<PsyGenesisBlockSetupData<PF, Hash>>(json);
        assert!(result.is_err(), "legacy Genesis must not silently acquire zero layout metadata");
    }

    #[test]
    fn genesis_layout_metadata_survives_json_round_trip() {
        use parth_core::pgoldilocks::PoseidonHasher;
        use psy_core::constants::protocol::STATE_LAYOUT_TREE_HEIGHT;
        use crate::v1::qdata::contract::{
            canonical_layout_manifest_from_compiler_abi_json,
            CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT,
            STATE_LAYOUT_ENCODING_VERSION, STATE_LAYOUT_VERSION,
        };
        let abi = serde_json::json!({
            "contract": {
                "state_tree_height": 32,
                "state_layout": {
                    "layout_version": STATE_LAYOUT_VERSION,
                    "encoding_version": STATE_LAYOUT_ENCODING_VERSION,
                    "field_count": 1, "slot_count": 1,
                    "fields": [{
                        "field_id": 1, "type": {"kind": "primitive", "name": "Felt"},
                        "start_slot": 0, "payload_offset": 0, "slot_count": 1
                    }]
                }
            },
            "types": []
        });
        let manifest = canonical_layout_manifest_from_compiler_abi_json::<PoseidonHasher, PF, Hash>(
            &abi.to_string(), STATE_LAYOUT_TREE_HEIGHT, CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT,
        ).unwrap();
        let expected = serde_json::to_value(manifest).unwrap();
        let mut json = genesis_layout_json_fixture();
        json["contracts"][0]["state_layout"] = expected.clone();
        let decoded: PsyGenesisBlockSetupData<PF, Hash> = serde_json::from_value(json).unwrap();
        let encoded = serde_json::to_value(decoded).unwrap();
        assert_eq!(encoded["contracts"][0]["state_layout"], expected,
            "Genesis DTO must retain the canonical layout used by the builder");
    }

    fn deploy_contract(state_tree_height: u16) -> PQBCDeployContract<Hash> {
        PQBCDeployContract::new(
            1,
            ContractCodeDefinition { state_tree_height, functions: vec![] },
            vec![QHashOut::<PF>::from_values(2, 0, 0, 0)],
            QHashOut::<PF>::from_values(3, 0, 0, 0),
        )
    }

    #[cfg(feature = "rand_gen")]
    fn setup_data(contracts: Vec<PQBCDeployContract<Hash>>) -> PsyGenesisBlockSetupData<PF, Hash> {
        PsyGenesisBlockSetupData {
            contracts: contracts.into_iter().map(genesis_contract_with_empty_layout_fixture).collect(),
            users: vec![],
            checkpoint_stats: PQEDCheckpointLeafStats::qp_rand_gen(),
            deposit_tree_root: QHashOut::<PF>::from_values(4, 0, 0, 0),
            withdrawal_tree_root: QHashOut::<PF>::from_values(5, 0, 0, 0),
            validators: vec![],
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
