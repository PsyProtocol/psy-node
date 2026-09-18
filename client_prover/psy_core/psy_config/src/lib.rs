use std::collections::HashMap;

use indexmap::IndexMap;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::hash_types::{HashOut, RichField},
    plonk::config::Hasher,
};
use psy_client_common::data::qhashout::QHashOut;
use serde::{Deserialize, Serialize};
use thiserror::Error;

include!(concat!(env!("OUT_DIR"), "/generated_constants.rs"));
include!("stage_magic.rs");

pub mod network_constants;

pub use network_constants::DEFAULT_USER_STATE_TREE_ROOT_U64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct GenesisUser<F: RichField> {
    pub public_key_param: QHashOut<F>,
    pub fingerprint: QHashOut<F>,
}

impl<F: RichField> GenesisUser<F> {
    pub fn qfhash<H>(&self) -> QHashOut<F>
    where
        H: Hasher<F, Hash = HashOut<F>>,
    {
        QHashOut(H::two_to_one(self.fingerprint.0, self.public_key_param.0))
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Network '{0}' not found")]
    NetworkNotFound(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error(
        "chain identity mismatch: config network '{network}' has magic {config_magic:#018X}, \
         but this binary was built for '{binary_network}' with magic {binary_magic:#018X}"
    )]
    ChainIdentityMismatch {
        network: String,
        config_magic: u64,
        binary_magic: u64,
        binary_network: &'static str,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct NetworkConfig<F: RichField> {
    pub magic: String,
    pub users_per_realm: u64,
    pub global_user_tree_height: u8,
    pub realm_user_tree_height: u8,
    pub group_realm_height: u8,
    pub realm_configs: Vec<RealmConfig>,
    pub coordinator_configs: Vec<CoordinatorConfig>,
    pub prove_proxy_url: Vec<String>,
    pub faucet_rpc_url: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_services_url: Option<Vec<String>>,
    /// Nostr relay for private-note delivery. This is required per network;
    /// clients must not silently fall back to another network's relay.
    pub nostr_relay_url: String,
    pub native_currency: String,
    pub native_currency_decimal: u8,
    pub native_currency_name: String,
    pub fees: FeeConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis: Option<GenesisConfig<F>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whitelist: Option<WhitelistConfig>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmConfig {
    pub id: u64,
    pub rpc_url: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorConfig {
    pub id: u64,
    pub rpc_url: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeConfig {
    pub register_user_fee: u64,
    pub deploy_contract_fee: u64,
    pub guta_fee: u64,
    pub da_fee: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct GenesisConfig<F: RichField> {
    #[serde(default)]
    pub precompiles: Vec<GenesisPrecompile<F>>,
    #[serde(default)]
    pub contracts: IndexMap<u64, IndexMap<u64, GenesisUserContractState<F>>>,
    #[serde(default)]
    pub users: Vec<GenesisUser<F>>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct ContractConfig<F: RichField> {
    pub name: String,
    pub path: String,
    pub contract_name: String,
    pub method_names: Vec<String>,
    #[serde(default)]
    pub deployer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytecode: Option<String>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PrecompileConfig<F: RichField> {
    pub precompiles: Vec<GenesisPrecompile<F>>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PrecompilesBuildConfig<F: RichField> {
    pub contracts: Vec<ContractConfig<F>>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct GenesisPrecompile<F: RichField> {
    pub name: String,
    pub deployer: QHashOut<F>,
    pub bytecode: Vec<serde_json::Value>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct GenesisUserContractState<F: RichField> {
    pub slots: IndexMap<u64, QHashOut<F>>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct NodesConfig<F: RichField> {
    pub coordinator: CoordinatorNode,
    pub realms: Vec<RealmNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prover: Option<ServiceConfig>,
    pub deployment: DeploymentConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workers: Option<WorkerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_api_services: Option<GlobalApiServices>,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorNode {
    pub id: u64,
    pub redis: Option<RedisInstance>,
    pub backend: Option<BackendConfig>,
    pub processor: ServiceConfig,
    pub edge: ServiceConfig,
    pub watcher: Option<ServiceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealmNode {
    pub id: u64,
    pub redis: Option<RedisInstance>,
    pub backend: Option<BackendConfig>,
    pub processor: ServiceConfig,
    pub edge: ServiceConfig,
    pub watcher: Option<ServiceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instances: Option<u32>,
    pub args: HashMap<String, serde_json::Value>,
    pub env: HashMap<String, String>,
    pub aws: Option<AwsServiceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsServiceConfig {
    pub cpu: u32,
    pub memory: u32,
    pub deployment_type: Option<DeploymentType>,
    pub load_balancer: Option<LoadBalancerConfig>,
    pub ec2: Option<Ec2ServiceConfig>,
    pub ecs: Option<EcsServiceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisConfig {
    pub uri: String,
    pub pool_size: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws: Option<AwsServiceConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackendConfig {
    #[serde(rename = "type")]
    pub database: String,
    pub lmdbx: Option<LmdbxConfig>,
    pub scylla: Option<ScyllaConfig>,
    pub tikv: Option<TikvConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LmdbxConfig {
    pub path: String,
    pub mmap_size_gb: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws: Option<LmdbxAwsConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LmdbxAwsConfig {
    pub volume_size: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScyllaConfig {
    pub endpoints: Vec<String>,
    pub replication_factor: u32,
    pub consistency_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws: Option<ScyllaAwsConfig>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScyllaAwsConfig {
    pub cpu: u32,
    pub memory: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_type: Option<DeploymentType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec2: Option<Ec2Config>,
    #[serde(default = "default_data_volume_size")]
    pub data_volume_size: u32,
    #[serde(default = "default_commitlog_volume_size")]
    pub commitlog_volume_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TikvConfig {
    pub pd_endpoints: Vec<String>,
    pub namespace: String,
    pub aws: Option<TikvAwsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TikvAwsConfig {
    pub cpu: u32,
    pub memory: u32,
    pub deployment_type: Option<DeploymentType>,
    pub ec2: Option<Ec2ServiceConfig>,
    #[serde(default = "default_data_volume_size")]
    pub data_volume_size: u32,
    #[serde(default = "default_pd_count")]
    pub pd_count: u32,
    #[serde(default = "default_tikv_count")]
    pub tikv_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub aws: AwsDeploymentConfig,
    pub docker: DockerDeploymentConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsDeploymentConfig {
    pub region: String,
    pub project_name: String,
    pub vpc: VpcConfig,
    pub ecs: EcsConfig,
    pub ecr: EcrConfig,
    pub s3: S3Config,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpcConfig {
    pub cidr: String,
    pub availability_zones: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsConfig {
    pub cluster_name: String,
    pub log_group: String,
    pub ec2: Option<Ec2Config>,
    pub fargate: Option<FargateConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ec2Config {
    pub instance_type: Option<String>,
    pub min_instances: u32,
    pub max_instances: u32,
    pub desired_instances: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FargateConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcrConfig {
    pub repository_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    pub bucket_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerDeploymentConfig {
    pub network_name: String,
    pub network_subnet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    pub enabled: bool,
    pub args: HashMap<String, serde_json::Value>,
    pub env: HashMap<String, String>,
    pub aws: Option<AwsServiceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerGlobalConfig {
    pub task_discovery_interval: u32,
    pub max_concurrent_tasks: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisInstance {
    pub uri: String,
    pub pool_size: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws: Option<RedisAwsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisAwsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_type: Option<RedisDeploymentType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elasticache: Option<ElastiCacheConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec2: Option<RedisEc2Config>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedisDeploymentType {
    ElastiCache,
    EC2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElastiCacheConfig {
    pub node_type: String,
    pub num_cache_nodes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisEc2Config {
    pub min_instances: u32,
    pub max_instances: u32,
    pub desired_instances: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisRealm {
    pub id: u64,
    pub uri: String,
    pub pool_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    pub port: u16,
    pub health_check_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeploymentType {
    #[serde(rename = "ecs")]
    ECS,
    #[serde(rename = "ec2")]
    EC2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ec2ServiceConfig {
    pub instance_type: Option<String>,
    pub min_instances: u32,
    pub max_instances: u32,
    pub desired_instances: u32,
    pub security_groups: Option<Vec<String>>,
    pub iam_role: Option<String>,
    pub user_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsServiceConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instances: Option<u32>,
    pub task_count: u32,
    pub deployment_configuration: Option<EcsDeploymentConfig>,
    pub network_mode: Option<String>,
    pub placement_strategy: Option<Vec<PlacementStrategy>>,
    pub placement_constraints: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcsDeploymentConfig {
    pub maximum_percent: Option<u32>,
    pub minimum_healthy_percent: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlacementStrategy {
    pub r#type: String,
    pub field: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalApiServices {
    pub api_service: Option<ServiceConfig>,
    pub timescaledb: Option<TimescaleDbConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimescaleDbConfig {
    pub enabled: bool,
    pub connection_string: String,
    pub aws: Option<RdsConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdsConfig {
    pub instance_class: String,
    pub allocated_storage: u32,
    pub multi_az: bool,
}

fn default_data_volume_size() -> u32 {
    500
}

fn default_commitlog_volume_size() -> u32 {
    100
}

fn default_pd_count() -> u32 {
    3
}

fn default_tikv_count() -> u32 {
    3
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistConfig {
    pub enabled: bool,
    pub secp256k1: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct Config<F: RichField> {
    pub networks: HashMap<String, NetworkConfig<F>>,
    #[serde(rename = "defaultNetwork")]
    pub default_network: String,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<F>,
}

#[derive(Debug)]
pub struct PsyConfig<F: RichField> {
    config: Config<F>,
    current_network: String,
    nodes_config: Option<NodesConfig<F>>,
}

impl<F: RichField> PsyConfig<F> {
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(err) => {
                // Canonical config lives in the psy-genesis submodule at
                // psy-genesis/config.json. The CLI default --rpc-config is the
                // bare "config.json"; resolve that to the canonical path.
                let canonical_path = "psy-genesis/config.json";
                if path == "config.json" {
                    std::fs::read_to_string(canonical_path).map_err(|_| ConfigError::IoError(err))?
                } else {
                    return Err(ConfigError::IoError(err));
                }
            }
        };
        let config: Config<F> = serde_json::from_str(&content)?;

        if !config.networks.contains_key(&config.default_network) {
            return Err(ConfigError::InvalidConfig(format!(
                "Configuration must contain '{}' network",
                config.default_network
            )));
        }

        let current_network = config.default_network.clone();

        let config = Self {
            config,
            current_network,
            nodes_config: None,
        };
        config.verify_chain_identity()?;
        Ok(config)
    }

    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let config: Config<F> = serde_json::from_str(json)?;

        if !config.networks.contains_key(&config.default_network) {
            return Err(ConfigError::InvalidConfig(format!(
                "Configuration must contain '{}' network",
                config.default_network
            )));
        }

        let current_network = config.default_network.clone();

        let config = Self {
            config,
            current_network,
            nodes_config: None,
        };
        config.verify_chain_identity()?;
        Ok(config)
    }

    pub fn builder() -> PsyConfigBuilder<F> {
        PsyConfigBuilder::new()
    }

    /// 当前网络的 magic 必须等于编译进本二进制的 magic。
    ///
    /// 比的是 magic 而不是网络名：localhost 与 testnet 共用同一个 magic，
    /// 一套产物可以同时服务两者；mainnet 的 magic 不同，会在这里被挡住。
    pub fn verify_chain_identity(&self) -> Result<(), ConfigError> {
        let network = self.get_current_network()?;
        let config_magic = parse_magic_hex(&network.magic).map_err(ConfigError::InvalidConfig)?;
        if config_magic != PSY_NETWORK_MAGIC {
            return Err(ConfigError::ChainIdentityMismatch {
                network: self.current_network.clone(),
                config_magic,
                binary_magic: PSY_NETWORK_MAGIC,
                binary_network: CURRENT_NETWORK,
            });
        }
        Ok(())
    }

    /// 切换网络但不做链身份校验。只给查看类工具用（例如 `psy_dev_cli chain-info`）。
    pub fn use_network_unchecked(&mut self, network_name: &str) -> Result<(), ConfigError> {
        if !self.config.networks.contains_key(network_name) {
            return Err(ConfigError::NetworkNotFound(network_name.to_string()));
        }
        self.current_network = network_name.to_string();
        Ok(())
    }

    pub fn use_network(&mut self, network_name: &str) -> Result<(), ConfigError> {
        let previous = self.current_network.clone();
        self.use_network_unchecked(network_name)?;
        if let Err(e) = self.verify_chain_identity() {
            self.current_network = previous;
            return Err(e);
        }
        Ok(())
    }

    pub fn get_current_network(&self) -> Result<&NetworkConfig<F>, ConfigError> {
        self.get_network(&self.current_network)
    }

    pub fn get_network(&self, network_name: &str) -> Result<&NetworkConfig<F>, ConfigError> {
        self.config
            .networks
            .get(network_name)
            .ok_or_else(|| ConfigError::NetworkNotFound(network_name.to_string()))
    }

    pub fn list_networks(&self) -> Vec<&String> {
        self.config.networks.keys().collect()
    }

    pub fn current_network_name(&self) -> &str {
        &self.current_network
    }

    pub fn load_deploy_config(&mut self, path: &str) -> Result<(), ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let nodes_config: NodesConfig<F> = serde_json::from_str(&content)?;
        self.nodes_config = Some(nodes_config);
        Ok(())
    }

    pub fn get_nodes_config(&self) -> Option<&NodesConfig<F>> {
        self.nodes_config.as_ref()
    }

    pub fn get_genesis_config(&self) -> Result<Option<&GenesisConfig<F>>, ConfigError> {
        let network = self.get_current_network()?;
        Ok(network.genesis.as_ref())
    }

    pub fn from_files(config_path: &str, deploy_path: Option<&str>) -> Result<Self, ConfigError> {
        let mut psy_config = Self::from_file(config_path)?;

        if let Some(deploy_path) = deploy_path {
            psy_config.load_deploy_config(deploy_path)?;
        }

        Ok(psy_config)
    }
}

pub struct PsyConfigBuilder<F: RichField> {
    config_json: Option<String>,
    config_path: Option<String>,
    deploy_path: Option<String>,
    initial_network: Option<String>,
    _phantom: std::marker::PhantomData<F>,
}

impl<F: RichField> PsyConfigBuilder<F> {
    pub fn new() -> Self {
        Self {
            config_json: None,
            config_path: None,
            deploy_path: None,
            initial_network: None,
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn json(mut self, json: &str) -> Self {
        self.config_json = Some(json.to_string());
        self
    }

    pub fn path(mut self, path: &str) -> Self {
        self.config_path = Some(path.to_string());
        self
    }

    pub fn network(mut self, network: &str) -> Self {
        self.initial_network = Some(network.to_string());
        self
    }

    pub fn deploy(mut self, path: &str) -> Self {
        self.deploy_path = Some(path.to_string());
        self
    }

    pub fn build(self) -> Result<PsyConfig<F>, ConfigError> {
        let mut config = if let Some(json) = self.config_json {
            PsyConfig::from_json(&json)?
        } else if let Some(path) = self.config_path {
            PsyConfig::from_file(&path)?
        } else {
            PsyConfig::from_file("config.json")?
        };

        if let Some(deploy_path) = self.deploy_path {
            config.load_deploy_config(&deploy_path)?;
        }

        if let Some(network) = self.initial_network {
            config.use_network(&network)?;
        }

        Ok(config)
    }
}

impl<F: RichField> Default for PsyConfigBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Constants;

impl Constants {
    pub const GLOBAL_USER_TREE_HEIGHT: u8 = GLOBAL_USER_TREE_HEIGHT;
    pub const COORDINATOR_USER_TREE_HEIGHT: u8 = COORDINATOR_USER_TREE_HEIGHT;
    pub const REALM_USER_TREE_HEIGHT: u8 = REALM_USER_TREE_HEIGHT;
    pub const GROUP_REALM_HEIGHT: u8 = GROUP_REALM_HEIGHT;
    pub const USERS_PER_REALM: u64 = USERS_PER_REALM;
    pub const NATIVE_CURRENCY_DECIMAL: u8 = NATIVE_CURRENCY_DECIMAL;
    pub const NATIVE_CURRENCY: &'static str = NATIVE_CURRENCY;
    pub const NATIVE_CURRENCY_NAME: &'static str = NATIVE_CURRENCY_NAME;
    pub const REGISTER_USER_FEE: u64 = REGISTER_USER_FEE;
    pub const DEPLOY_CONTRACT_FEE: u64 = DEPLOY_CONTRACT_FEE;
    pub const GUTA_FEE: u64 = GUTA_FEE;
    pub const DA_FEE: u64 = DA_FEE;
    pub const CURRENT_NETWORK: &'static str = CURRENT_NETWORK;
    pub const COORDINATOR_RPC_URL: &'static str = COORDINATOR_RPC_URL;
    pub const REALM_RPC_URLS: &'static [&'static str] = REALM_RPC_URLS;

    pub const DEFAULT_USER_STATE_TREE_ROOT_U64: [u64; 4] = DEFAULT_USER_STATE_TREE_ROOT_U64;
    pub const DEFAULT_WORKER_PUBLIC_KEY_U64: [u64; 4] = network_constants::DEFAULT_WORKER_PUBLIC_KEY_U64;
    pub const REALM_PROCESSOR_TO_EDGE_CHANNEL: u64 = network_constants::REALM_PROCESSOR_TO_EDGE_CHANNEL;
}

pub fn get_default_user_state_tree_root<F: RichField>() -> QHashOut<F> {
    QHashOut(HashOut {
        elements: [
            F::from_canonical_u64(DEFAULT_USER_STATE_TREE_ROOT_U64[0]),
            F::from_canonical_u64(DEFAULT_USER_STATE_TREE_ROOT_U64[1]),
            F::from_canonical_u64(DEFAULT_USER_STATE_TREE_ROOT_U64[2]),
            F::from_canonical_u64(DEFAULT_USER_STATE_TREE_ROOT_U64[3]),
        ],
    })
}

pub fn get_default_worker_public_key<F: RichField>() -> QHashOut<F> {
    QHashOut(HashOut {
        elements: [
            F::from_canonical_u64(network_constants::DEFAULT_WORKER_PUBLIC_KEY_U64[0]),
            F::from_canonical_u64(network_constants::DEFAULT_WORKER_PUBLIC_KEY_U64[1]),
            F::from_canonical_u64(network_constants::DEFAULT_WORKER_PUBLIC_KEY_U64[2]),
            F::from_canonical_u64(network_constants::DEFAULT_WORKER_PUBLIC_KEY_U64[3]),
        ],
    })
}

pub type PsyConfigGoldilocks = PsyConfig<GoldilocksField>;
pub type ConfigGoldilocks = Config<GoldilocksField>;
pub type NetworkConfigGoldilocks = NetworkConfig<GoldilocksField>;
pub type NodesConfigGoldilocks = NodesConfig<GoldilocksField>;

pub type GenesisConfigGoldilocks = GenesisConfig<GoldilocksField>;
pub type ContractConfigGoldilocks = ContractConfig<GoldilocksField>;
pub type PrecompileConfigGoldilocks = PrecompileConfig<GoldilocksField>;
pub type PrecompilesBuildConfigGoldilocks = PrecompilesBuildConfig<GoldilocksField>;
pub type GenesisPrecompileGoldilocks = GenesisPrecompile<GoldilocksField>;
pub type GenesisUserContractStateGoldilocks = GenesisUserContractState<GoldilocksField>;
pub type ZKPublicKeyInfoGoldilocks = GenesisUser<GoldilocksField>;

pub type PsyConfigBuilderGoldilocks = PsyConfigBuilder<GoldilocksField>;

impl<F: RichField> GenesisConfig<F> {
    pub fn from_json(json_str: &str) -> anyhow::Result<Self> {
        let mut config: GenesisConfig<F> = serde_json::from_str(json_str)?;
        config._phantom = std::marker::PhantomData;
        Ok(config)
    }

    pub fn get_precompile_configs(&self) -> &[GenesisPrecompile<F>] {
        &self.precompiles
    }

    pub fn get_all_contracts(&self) -> &IndexMap<u64, IndexMap<u64, GenesisUserContractState<F>>> {
        &self.contracts
    }

    pub fn get_genesis_users(&self) -> &[GenesisUser<F>] {
        &self.users
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCALHOST_MAGIC_HEX: &str = "0x1337CF514544CF69";
    const TESTNET_MAGIC_HEX: &str = "0x1337CF514544CF69";

    /// 一个能被 `NetworkConfig` 正确反序列化的最小网络块。
    /// 真实结构是平铺的：没有 `"network"` 这层包装，`magic` 与 `fees.da_fee` 都是必填。
    fn network_json(magic: &str, users_per_realm: u64, currency: &str) -> String {
        format!(
            r#"{{
                "magic": "{magic}",
                "users_per_realm": {users_per_realm},
                "global_user_tree_height": 32,
                "realm_user_tree_height": 20,
                "group_realm_height": 1,
                "realm_configs": [{{"id": 0, "rpc_url": ["http://127.0.0.1:13380"]}}],
                "coordinator_configs": [{{"id": 0, "rpc_url": ["http://127.0.0.1:1337"]}}],
                "prove_proxy_url": ["http://127.0.0.1:9999"],
                "faucet_rpc_url": ["http://127.0.0.1:9998"],
                "nostr_relay_url": "ws://127.0.0.1:8081",
                "native_currency": "{currency}",
                "native_currency_decimal": 9,
                "native_currency_name": "Psy",
                "fees": {{
                    "register_user_fee": 0,
                    "deploy_contract_fee": 0,
                    "guta_fee": 1000000000,
                    "da_fee": 0
                }}
            }}"#
        )
    }

    fn config_json(default_network: &str, networks: &[(&str, String)]) -> String {
        let body = networks
            .iter()
            .map(|(name, json)| format!(r#""{name}": {json}"#))
            .collect::<Vec<_>>()
            .join(",\n");
        format!(r#"{{ "networks": {{ {body} }}, "defaultNetwork": "{default_network}" }}"#)
    }

    #[test]
    fn test_config_loading() {
        // Prefer PSY_CONFIG_PATH (what build.rs uses); fall back to the tracked
        // psy-genesis submodule config so this test still checks something real
        // even when no env var is set. Only skip if neither resolves to a file.
        let config_path = std::env::var("PSY_CONFIG_PATH").map(std::path::PathBuf::from).unwrap_or_else(|_| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../psy-genesis/config.json")
        });
        if !config_path.exists() {
            eprintln!("skipping: {} does not exist in this checkout", config_path.display());
            return;
        }
        let config = PsyConfigGoldilocks::from_file(config_path.to_str().unwrap()).unwrap();
        let name = config.current_network_name().to_string();
        assert!(
            ["localhost", "testnet", "mainnet"].contains(&name.as_str()),
            "unexpected network name in rendered config: {name}"
        );
        let network = config.get_current_network().unwrap();
        assert!(network.users_per_realm > 0);

        let magic = parse_magic_hex(&network.magic)
            .unwrap_or_else(|e| panic!("magic '{}' is not valid hex: {e}", network.magic));
        assert_ne!(magic, 0, "magic must be non-zero");
    }

    #[test]
    fn test_network_switching() {
        let json = config_json(
            "localhost",
            &[
                ("localhost", network_json(LOCALHOST_MAGIC_HEX, 1048576, "0")),
                ("testnet", network_json(TESTNET_MAGIC_HEX, 1048576, "0")),
            ],
        );

        let mut config = PsyConfigGoldilocks::from_json(&json).unwrap();
        assert_eq!(config.current_network_name(), "localhost");

        config.use_network("testnet").unwrap();
        assert_eq!(config.current_network_name(), "testnet");
        assert_eq!(config.get_current_network().unwrap().users_per_realm, 1048576);
    }

    #[test]
    fn test_flexible_config_creation() {
        let json = config_json(
            "localhost",
            &[
                ("localhost", network_json(LOCALHOST_MAGIC_HEX, 1048576, "0")),
                ("testnet", network_json(TESTNET_MAGIC_HEX, 1048576, "1")),
            ],
        );

        let config1 = PsyConfigGoldilocks::from_json(&json).unwrap();
        assert_eq!(config1.current_network_name(), "localhost");
        assert_eq!(config1.get_current_network().unwrap().native_currency, "0");

        let config3 = PsyConfigGoldilocks::builder().json(&json).build().unwrap();
        assert_eq!(config3.current_network_name(), "localhost");
    }

    #[test]
    fn test_runtime_network_switching() {
        let json = config_json(
            "localhost",
            &[
                ("localhost", network_json(LOCALHOST_MAGIC_HEX, 1048576, "0")),
                ("testnet", network_json(TESTNET_MAGIC_HEX, 1048576, "1")),
            ],
        );

        let mut config = PsyConfigGoldilocks::from_json(&json).unwrap();
        assert_eq!(config.current_network_name(), "localhost");

        config.use_network("testnet").unwrap();
        assert_eq!(config.get_current_network().unwrap().native_currency, "1");

        config.use_network("localhost").unwrap();
        assert_eq!(config.get_current_network().unwrap().native_currency, "0");

        let networks = config.list_networks();
        assert_eq!(networks.len(), 2);
        assert!(networks.contains(&&"testnet".to_string()));
    }

    #[test]
    fn test_error_handling() {
        // defaultNetwork 指向一个不存在的网络。
        let json = config_json(
            "missing_network",
            &[("localhost", network_json(LOCALHOST_MAGIC_HEX, 1048576, "0"))],
        );
        let result = PsyConfigGoldilocks::from_json(&json);
        assert!(matches!(result.unwrap_err(), ConfigError::InvalidConfig(_)));

        let bad_json = r#"{"invalid": json}"#;
        let result = PsyConfigGoldilocks::from_json(bad_json);
        assert!(matches!(result.unwrap_err(), ConfigError::JsonError(_)));
    }

    #[test]
    fn stage_magic_table_matches_the_protocol_constants() {
        // psy_core/src/constants/protocol.rs 定义的三个值。
        // testnet 沿用 REGTEST 的值：现网就是这么跑的，换它需要一次全新部署。
        assert_eq!(magic_for_stage("localhost"), Some(0x1337CF514544CF69));
        assert_eq!(magic_for_stage("testnet"), Some(0x1337CF514544CF69));
        assert_eq!(magic_for_stage("mainnet"), Some(0x1337CF514544C069));
        assert_eq!(magic_for_stage("sepolia"), None);
        assert_eq!(magic_for_stage(""), None);
    }

    #[test]
    fn magic_hex_parses_with_or_without_prefix() {
        assert_eq!(parse_magic_hex("0x1337CF514544CF69"), Ok(0x1337CF514544CF69));
        assert_eq!(parse_magic_hex("1337cf514544cf69"), Ok(0x1337CF514544CF69));
        assert!(parse_magic_hex("0xnothex").is_err());
        assert!(parse_magic_hex("").is_err());
    }

    #[test]
    fn loading_a_config_whose_magic_differs_from_the_binary_is_refused() {
        // mainnet 的 magic 与本二进制（localhost/testnet）不同，必须被拒绝。
        let json = config_json(
            "mainnet",
            &[("mainnet", network_json("0x1337CF514544C069", 1048576, "0"))],
        );
        let err = PsyConfigGoldilocks::from_json(&json).unwrap_err();
        assert!(
            matches!(err, ConfigError::ChainIdentityMismatch { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn loading_a_config_with_the_same_magic_is_accepted() {
        let json = config_json(
            "testnet",
            &[("testnet", network_json(TESTNET_MAGIC_HEX, 1048576, "0"))],
        );
        let config = PsyConfigGoldilocks::from_json(&json).unwrap();
        assert_eq!(config.current_network_name(), "testnet");
    }

    #[test]
    fn switching_to_a_foreign_magic_is_refused_but_inspection_still_works() {
        let json = config_json(
            "localhost",
            &[
                ("localhost", network_json(LOCALHOST_MAGIC_HEX, 1048576, "0")),
                ("mainnet", network_json("0x1337CF514544C069", 1048576, "0")),
            ],
        );
        let mut config = PsyConfigGoldilocks::from_json(&json).unwrap();

        assert!(matches!(
            config.use_network("mainnet").unwrap_err(),
            ConfigError::ChainIdentityMismatch { .. }
        ));
        assert_eq!(config.current_network_name(), "localhost", "失败的切换不应该改变当前网络");

        // 查看用的入口不校验，chain-info 这类工具靠它。
        config.use_network_unchecked("mainnet").unwrap();
        assert_eq!(config.current_network_name(), "mainnet");
    }
}
