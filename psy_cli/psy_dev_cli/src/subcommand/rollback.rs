use std::{path::{Path, PathBuf}, time::Duration};

use anyhow::{Context, bail, ensure};
use clap::{Args, ValueEnum};
use psy_core::constants::{chain_id::PsyChainNetworkType, proving_backends::PsyChainProvingBackendTypeInput};
use psy_node_common::rollback::{
    RollbackRole, TargetContractState, read_rollback_plan, validate_rollback_plan,
};
use psy_node_core::config::{
    node_cli_config::load_cli_config_from_file,
    node_start_config::{CoordinatorProcessorStartConfig, RealmProcessorStartConfig},
};
use serde::de::DeserializeOwned;
use url::Url;

const SHUTDOWN_SENTINEL_CONTENT: &str =
    "rollback offline: all processors and relayer stopped; Scylla Redis NATS and checkpoints retained";
const DEFAULT_PROBE_TIMEOUT_MS: u64 = 500;
const MAX_PROBE_TIMEOUT_MS: u64 = 5_000;

#[derive(Args, Debug)]
pub struct RollbackArgs {
    #[arg(long, conflicts_with = "execute", help = "Generate and atomically persist one role-local rollback plan.")]
    pub generate: bool,
    #[arg(long, conflicts_with = "generate", help = "Validate and execute one previously generated role-local rollback plan.")]
    pub execute: bool,
    #[command(flatten)]
    pub common: CommonArgs,
    #[arg(long = "reward-realm-id", requires = "generate", conflicts_with = "execute", help = "Coordinator realm IDs used to materialize reward cleanup keys. Realm generation uses its own realm id.")]
    pub reward_realm_ids: Vec<u64>,
    #[arg(long = "target-contract-state", requires = "generate", conflicts_with = "execute", help = "Optional target contract-state JSON. Retained only when its last_finalized_checkpoint_id equals the rollback target.")]
    pub target_contract_state: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ProcessorRole {
    Coordinator,
    Realm,
}

impl From<ProcessorRole> for RollbackRole {
    fn from(value: ProcessorRole) -> Self {
        match value {
            ProcessorRole::Coordinator => Self::Coordinator,
            ProcessorRole::Realm => Self::Realm,
        }
    }
}

#[derive(Args, Clone, Debug)]
pub struct CommonArgs {
    #[arg(long, value_enum, help = "Processor role owning this independent rollback plan.")]
    pub role: ProcessorRole,
    #[arg(long = "processor-config", help = "Path to the role's processor YAML/JSON config.")]
    pub processor_config: PathBuf,
    #[arg(long, help = "Target checkpoint T.")]
    pub target: u64,
    #[arg(long = "rp-path", help = "Rollback-plan JSON path.")]
    pub rp_path: PathBuf,
    #[arg(long = "realm-id", requires = "realm_sub_id", help = "Realm identity required for Realm plans and checked against processor config/RP.")]
    pub realm_id: Option<u64>,
    #[arg(long = "realm-sub-id", requires = "realm_id", help = "Realm sub-identity required for Realm plans and checked against processor config/RP.")]
    pub realm_sub_id: Option<u16>,
    #[arg(long = "proving-backend", value_enum, help = "Runtime proving backend identity. Rollback operates on the shared Poseidon-Goldilocks database format.")]
    pub proving_backend: PsyChainProvingBackendTypeInput,
    #[arg(long = "stop-sentinel", help = "Operator attestation that processors/relayer are stopped and rollback stores retained.")]
    pub stop_sentinel: PathBuf,
    #[arg(long = "coordinator-endpoint", required = true, help = "Coordinator processor/edge endpoints that must all be unreachable.")]
    pub coordinator_endpoints: Vec<String>,
    #[arg(long = "realm-endpoint", help = "Realm processor/edge endpoints that must all be unreachable. Required for Realm plans.")]
    pub realm_endpoints: Vec<String>,
    #[arg(long = "probe-timeout-ms", default_value_t = DEFAULT_PROBE_TIMEOUT_MS, help = "Per-endpoint bounded TCP reachability probe timeout.")]
    pub probe_timeout_ms: u64,
}

#[derive(Debug)]
pub struct GenerateArgs {
    pub common: CommonArgs,
    pub reward_realm_ids: Vec<u64>,
    pub target_contract_state: Option<TargetContractState>,
}

#[derive(Debug)]
pub struct ExecuteArgs {
    pub common: CommonArgs,
}

#[derive(Clone, Debug)]
pub enum ProcessorConfig {
    Coordinator(CoordinatorProcessorStartConfig),
    Realm(RealmProcessorStartConfig),
}

impl ProcessorConfig {
    pub fn role(&self) -> ProcessorRole {
        match self {
            Self::Coordinator(_) => ProcessorRole::Coordinator,
            Self::Realm(_) => ProcessorRole::Realm,
        }
    }

    pub fn network(&self) -> PsyChainNetworkType {
        match self {
            Self::Coordinator(config) => config.network,
            Self::Realm(config) => config.network,
        }
    }

    pub fn realm_identity(&self) -> (u64, u16) {
        match self {
            Self::Coordinator(config) => (config.coordinator_id, config.coordinator_sub_id),
            Self::Realm(config) => (config.realm_id, config.realm_sub_id),
        }
    }
}

pub async fn run(args: RollbackArgs) -> anyhow::Result<()> {
    match (args.generate, args.execute) {
        (true, false) => run_generate(args).await,
        (false, true) => run_execute(args).await,
        _ => bail!("specify exactly one of --generate or --execute"),
    }
}

async fn run_generate(args: RollbackArgs) -> anyhow::Result<()> {
    let target_contract_state = match &args.target_contract_state {
        Some(path) => Some(read_json::<TargetContractState>(path).await?),
        None => None,
    };
    let generate = GenerateArgs {
        common: args.common.clone(),
        reward_realm_ids: args.reward_realm_ids,
        target_contract_state,
    };
    let config = prepare_offline_operation(&generate.common).await?;
    let plan = generate::generate(&generate, &config).await?;
    validate_rollback_plan(&plan).context("generated rollback plan failed validation")?;
    psy_node_common::rollback::write_rollback_plan_atomic(&generate.common.rp_path, &plan, true).await?;
    println!(
        "Generated validated {:?} rollback plan for checkpoint {} at {}. Keep processors and relayer stopped. The local executor does not perform shared L1/relayer recovery; do not restart until every role-local plan and external recovery are verified complete, then use `make run-all` and wait for Coordinator readiness before Realm readiness.",
        plan.role,
        plan.target_checkpoint_id,
        generate.common.rp_path.display()
    );
    Ok(())
}

async fn run_execute(args: RollbackArgs) -> anyhow::Result<()> {
    let execute = ExecuteArgs { common: args.common };
    let config = prepare_offline_operation(&execute.common).await?;
    let mut plan = read_rollback_plan(&execute.common.rp_path).await?;
    validate_rollback_plan(&plan).context("rollback plan failed validation; no stores were mutated")?;
    validate_plan_identity(&execute.common, &config, &plan)?;
    execute::execute(&execute, &config, &mut plan).await?;
    println!(
        "Executed validated {:?} local rollback plan to checkpoint {}. Keep processors and relayer stopped. The local executor does not perform shared L1/relayer recovery; restart with `make run-all` only after every role-local plan and external recovery are verified complete, then confirm Coordinator readiness before Realm readiness.",
        plan.role,
        plan.target_checkpoint_id
    );
    Ok(())
}

async fn prepare_offline_operation(args: &CommonArgs) -> anyhow::Result<ProcessorConfig> {
    validate_static_args(args)?;
    let config = load_processor_config(args).await?;
    validate_config(args, &config)?;
    require_shutdown_sentinel(&args.stop_sentinel).await?;
    reject_reachable_processors(args).await?;
    Ok(config)
}

fn validate_static_args(args: &CommonArgs) -> anyhow::Result<()> {
    ensure!(
        args.proving_backend == PsyChainProvingBackendTypeInput::Plonky2PoseidonGoldilocks,
        "rollback requires the plonky2-poseidon-goldilocks backend"
    );
    ensure!(
        (1..=MAX_PROBE_TIMEOUT_MS).contains(&args.probe_timeout_ms),
        "probe-timeout-ms must be between 1 and {MAX_PROBE_TIMEOUT_MS}"
    );
    ensure!(!args.coordinator_endpoints.is_empty(), "at least one coordinator endpoint is required");
    match args.role {
        ProcessorRole::Coordinator => {
            ensure!(
                args.realm_id.is_none() && args.realm_sub_id.is_none(),
                "realm identity must not be supplied for a Coordinator rollback plan"
            );
        }
        ProcessorRole::Realm => {
            ensure!(args.realm_id.is_some() && args.realm_sub_id.is_some(), "Realm rollback requires --realm-id and --realm-sub-id");
            ensure!(!args.realm_endpoints.is_empty(), "Realm rollback requires at least one --realm-endpoint");
        }
    }
    Ok(())
}

async fn load_processor_config(args: &CommonArgs) -> anyhow::Result<ProcessorConfig> {
    let path = args.processor_config.to_str().ok_or_else(|| anyhow::anyhow!("processor config path is not valid UTF-8"))?.to_owned();
    match args.role {
        ProcessorRole::Coordinator => {
            psy_node_core::config::node_cli_config::CoordinatorProcessorCliConfig::get_start_config(
                Some(path),
                None, None, None, None, None, None, None,
                false,
                None,
                None,
            )
            .await
            .map(ProcessorConfig::Coordinator)
        }
        ProcessorRole::Realm => {
            psy_node_core::config::node_cli_config::RealmProcessorCliConfig::get_start_config(
                Some(path),
                None, None, None, None, None, None, None,
                false,
                None,
                Vec::new(),
                None,
                None,
                None,
                None,
                Vec::new(),
                None,
                Vec::new(),
                None,
                Vec::new(),
                None,
                None,
            )
            .await
            .map(ProcessorConfig::Realm)
        }
    }
    .with_context(|| format!("failed to load {:?} processor config at {}", args.role, args.processor_config.display()))
}

fn validate_config(args: &CommonArgs, config: &ProcessorConfig) -> anyhow::Result<()> {
    ensure!(config.role() == args.role, "processor config role does not match --role");
    ensure!(
        config.network() == PsyChainNetworkType::LocalDevnet,
        "rollback is restricted to the local-devnet network"
    );
    if args.role == ProcessorRole::Realm {
        let expected = (args.realm_id.expect("validated"), args.realm_sub_id.expect("validated"));
        ensure!(config.realm_identity() == expected, "Realm identity {:?} does not match processor config identity {:?}", expected, config.realm_identity());
    }
    Ok(())
}

fn validate_plan_identity(
    args: &CommonArgs,
    config: &ProcessorConfig,
    plan: &psy_node_common::rollback::RollbackPlan,
) -> anyhow::Result<()> {
    ensure!(plan.role == args.role.into(), "RP role does not match --role");
    ensure!(plan.target_checkpoint_id == args.target, "RP target {} does not match --target {}", plan.target_checkpoint_id, args.target);
    let (realm_id, realm_sub_id) = config.realm_identity();
    ensure!(plan.realm_id == realm_id && plan.realm_sub_id == u64::from(realm_sub_id), "RP processor identity ({}, {}) does not match config identity ({}, {})", plan.realm_id, plan.realm_sub_id, realm_id, realm_sub_id);
    Ok(())
}

async fn require_shutdown_sentinel(path: &Path) -> anyhow::Result<()> {
    let metadata = tokio::fs::metadata(path)
        .await
        .with_context(|| format!("missing operator stop sentinel {}; stop every processor and the relayer without purging Scylla/Redis/NATS/checkpoints, then create the sentinel containing exactly `{SHUTDOWN_SENTINEL_CONTENT}`", path.display()))?;
    ensure!(metadata.is_file(), "operator stop sentinel {} is not a regular file", path.display());
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read operator stop sentinel {}", path.display()))?;
    ensure!(
        content.trim() == SHUTDOWN_SENTINEL_CONTENT,
        "invalid operator stop sentinel {}; stop every processor and the relayer without purging Scylla/Redis/NATS/checkpoints, then write exactly `{SHUTDOWN_SENTINEL_CONTENT}`",
        path.display()
    );
    Ok(())
}

async fn reject_reachable_processors(args: &CommonArgs) -> anyhow::Result<()> {
    let timeout = Duration::from_millis(args.probe_timeout_ms);
    for (kind, endpoints) in [
        ("Coordinator", args.coordinator_endpoints.as_slice()),
        ("Realm", args.realm_endpoints.as_slice()),
    ] {
        for endpoint in endpoints {
            if endpoint_is_reachable(endpoint, timeout).await? {
                anyhow::bail!("{kind} processor endpoint {endpoint} is reachable; stop every Coordinator/Realm processor without purging rollback stores before rollback");
            }
        }
    }
    Ok(())
}

async fn endpoint_is_reachable(endpoint: &str, timeout: Duration) -> anyhow::Result<bool> {
    let parsed = Url::parse(endpoint).with_context(|| format!("invalid processor endpoint URL {endpoint}"))?;
    ensure!(matches!(parsed.scheme(), "http" | "https"), "processor endpoint {endpoint} must use http or https");
    let host = parsed.host_str().ok_or_else(|| anyhow::anyhow!("processor endpoint {endpoint} has no host"))?.to_owned();
    let port = parsed.port_or_known_default().ok_or_else(|| anyhow::anyhow!("processor endpoint {endpoint} has no port"))?;
    tokio::task::spawn_blocking(move || {
        use std::net::{TcpStream, ToSocketAddrs};

        let addresses = (host.as_str(), port).to_socket_addrs()?;
        for address in addresses {
            if TcpStream::connect_timeout(&address, timeout).is_ok() {
                return Ok(true);
            }
        }
        Ok(false)
    })
    .await
    .context("processor reachability probe task failed")?
}

async fn read_json<T: DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let bytes = tokio::fs::read(path).await.with_context(|| format!("failed to read JSON at {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("failed to parse JSON at {}", path.display()))
}

mod execute;
mod generate;

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        rollback: RollbackArgs,
    }

    fn parse(args: &[&str]) -> anyhow::Result<RollbackArgs> {
        Ok(TestCli::try_parse_from(args)?.rollback)
    }

    pub(super) fn common(role: ProcessorRole) -> CommonArgs {
        CommonArgs {
            role,
            processor_config: "processor.yaml".into(),
            target: 7,
            rp_path: "rollback.json".into(),
            realm_id: None,
            realm_sub_id: None,
            proving_backend: PsyChainProvingBackendTypeInput::Plonky2PoseidonGoldilocks,
            stop_sentinel: "stopped".into(),
            coordinator_endpoints: vec!["http://127.0.0.1:1337".into()],
            realm_endpoints: Vec::new(),
            probe_timeout_ms: 100,
        }
    }

    #[test]
    fn new_generate_contract_state_flag_is_optional() {
        let parsed = parse(&[
            "test", "--generate", "--role", "coordinator", "--processor-config", "coordinator.yaml",
            "--target", "42", "--rp-path", "rp.json", "--proving-backend", "plonky2-poseidon-goldilocks",
            "--stop-sentinel", "stopped", "--coordinator-endpoint", "http://127.0.0.1:1337",
        ]).unwrap();
        assert!(parsed.generate);
        assert!(parsed.target_contract_state.is_none());

        let parsed = parse(&[
            "test", "--generate", "--role", "coordinator", "--processor-config", "coordinator.yaml",
            "--target", "42", "--rp-path", "rp.json", "--proving-backend", "plonky2-poseidon-goldilocks",
            "--stop-sentinel", "stopped", "--coordinator-endpoint", "http://127.0.0.1:1337",
            "--target-contract-state", "target.json",
        ]).unwrap();
        assert_eq!(parsed.target_contract_state.as_deref(), Some(Path::new("target.json")));
    }

    #[test]
    fn old_contract_state_flags_are_rejected() {
        for flag in ["--l1-contracts", "--skip-l1-state"] {
            assert!(parse(&[
                "test", "--generate", "--role", "coordinator", "--processor-config", "coordinator.yaml",
                "--target", "42", "--rp-path", "rp.json", "--proving-backend", "plonky2-poseidon-goldilocks",
                "--stop-sentinel", "stopped", "--coordinator-endpoint", "http://127.0.0.1:1337", flag,
            ]).is_err());
        }
    }

    #[test]
    fn parses_explicit_execute_mode() {
        let parsed = parse(&[
            "test", "--execute", "--role", "realm", "--processor-config", "realm.yaml",
            "--target", "9", "--rp-path", "rp.json", "--realm-id", "3", "--realm-sub-id", "1",
            "--proving-backend", "plonky2-poseidon-goldilocks", "--stop-sentinel", "stopped",
            "--coordinator-endpoint", "http://127.0.0.1:1337", "--realm-endpoint", "http://127.0.0.1:13380",
        ]).unwrap();
        assert!(parsed.execute);
        assert!(!parsed.generate);
        assert_eq!(parsed.common.realm_id, Some(3));
        assert_eq!(parsed.common.realm_sub_id, Some(1));
    }

    #[test]
    fn clap_requires_named_inputs() {
        assert!(parse(&["test", "--generate"]).is_err());
        assert!(parse(&["test", "--execute", "--role", "realm"]).is_err());
    }

    #[test]
    fn rejects_both_generate_and_execute() {
        assert!(parse(&[
            "test", "--generate", "--execute", "--role", "coordinator", "--processor-config", "coordinator.yaml",
            "--target", "42", "--rp-path", "rp.json", "--proving-backend", "plonky2-poseidon-goldilocks",
            "--stop-sentinel", "stopped", "--coordinator-endpoint", "http://127.0.0.1:1337",
            "--target-contract-state", "target.json",
        ]).is_err());
    }

    #[test]
    fn execute_rejects_generate_only_flags() {
        assert!(parse(&[
            "test", "--execute", "--role", "coordinator", "--processor-config", "coordinator.yaml",
            "--target", "42", "--rp-path", "rp.json", "--proving-backend", "plonky2-poseidon-goldilocks",
            "--stop-sentinel", "stopped", "--coordinator-endpoint", "http://127.0.0.1:1337",
            "--target-contract-state", "target.json",
        ]).is_err());
    }

    #[test]
    fn realm_requires_identity_and_realm_endpoint() {
        let args = common(ProcessorRole::Realm);
        assert!(validate_static_args(&args).is_err());
    }

    #[test]
    fn rejects_non_plonky2_backend() {
        let mut args = common(ProcessorRole::Coordinator);
        args.proving_backend = PsyChainProvingBackendTypeInput::JTMBPoseidonGoldilocks;
        assert!(validate_static_args(&args).is_err());
    }

    #[test]
    fn rejects_unbounded_probe_timeout() {
        let mut args = common(ProcessorRole::Coordinator);
        args.probe_timeout_ms = MAX_PROBE_TIMEOUT_MS + 1;
        assert!(validate_static_args(&args).is_err());
    }

    #[tokio::test]
    async fn rejects_malformed_endpoint() {
        assert!(endpoint_is_reachable("not-a-url", Duration::from_millis(1)).await.is_err());
    }

    #[tokio::test]
    async fn stop_sentinel_rejects_destructive_shutdown_label() {
        let path = std::env::temp_dir().join(format!(
            "psy-rollback-stop-sentinel-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        tokio::fs::write(&path, "make shutdown").await.unwrap();

        assert!(require_shutdown_sentinel(&path).await.is_err());

        tokio::fs::write(&path, SHUTDOWN_SENTINEL_CONTENT).await.unwrap();
        require_shutdown_sentinel(&path).await.unwrap();
        tokio::fs::remove_file(path).await.unwrap();
    }
}
