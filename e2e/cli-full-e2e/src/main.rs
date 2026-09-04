use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use alloy_signer_local::PrivateKeySigner;
use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::{Args, Parser, Subcommand};
use rand::{rngs::OsRng, RngCore};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const SIMPLE_CLAIM_METHOD_ID: u64 = 2_293_029_357;
const SIMPLE_TRANSFER_METHOD_ID: u64 = 354_447_671;
const PRIVATE_CLAIM_METHOD_ID: u64 = 635_905_178;
const CLAIM_DEPOSIT_METHOD_ID: u64 = 1_577_908_089;
const WITHDRAW_METHOD_ID: u64 = 3_055_054_724;
const DEFAULT_NETWORK: &str = "bsc-testnet";
const DEFAULT_MINIMUM_L1_NATIVE_WEI: u128 = 5_000_000_000_000_000;

#[derive(Parser)]
#[command(name = "psy-cli-full-e2e")]
#[command(about = "Resumable full-business E2E orchestrator for Psy public staging")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create fresh p1, p2, and e wallets for the selected staging network.
    Init(InitArgs),
    /// Show funding, chain health, and phase checkpoint status without mutations.
    Status(StatusArgs),
    /// Execute every mutating phase after explicit staging authorization.
    Run(RunArgs),
}

#[derive(Args)]
struct InitArgs {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long)]
    run_dir: Option<PathBuf>,
    /// Import a disposable funded EVM key instead of generating e.
    #[arg(long)]
    evm_key_file: Option<PathBuf>,
    /// Network key in the Psy client config.
    #[arg(long, default_value = DEFAULT_NETWORK)]
    network: String,
    /// Source client config. Defaults to psy-genesis/config.json.
    #[arg(long)]
    config_path: Option<PathBuf>,
    /// Directory name below psy-contracts/deployments. Defaults to --network.
    #[arg(long)]
    deployments_network: Option<String>,
    /// Protocol bridge chain index. Inferred for known networks when omitted.
    #[arg(long)]
    l1_chain_index: Option<u32>,
}

#[derive(Args)]
struct StatusArgs {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long)]
    run_dir: PathBuf,
    /// L1 RPC override. Defaults to the first l1_rpc_urls entry in the run config.
    #[arg(long)]
    l1_rpc_url: Option<String>,
    #[arg(long, default_value_t = DEFAULT_MINIMUM_L1_NATIVE_WEI)]
    minimum_l1_native_wei: u128,
}

#[derive(Args, Clone)]
struct RunArgs {
    #[arg(long, default_value = ".")]
    root: PathBuf,
    #[arg(long)]
    run_dir: PathBuf,
    /// Required acknowledgement that this command creates public-staging transactions.
    #[arg(long)]
    authorized_staging_transactions: bool,
    /// L1 RPC override. Defaults to the first l1_rpc_urls entry in the run config.
    #[arg(long)]
    l1_rpc_url: Option<String>,
    #[arg(long)]
    contract_artifact: Option<PathBuf>,
    #[arg(long)]
    contract_abi: Option<PathBuf>,
    #[arg(long, default_value_t = DEFAULT_MINIMUM_L1_NATIVE_WEI)]
    minimum_l1_native_wei: u128,
    #[arg(long, default_value_t = 1_000_000_u128)]
    deposit_usdt: u128,
    #[arg(long, default_value_t = 1_000_000_000_u128)]
    deposit_psy: u128,
    #[arg(long, default_value_t = 500_000_u128)]
    withdraw_usdt: u128,
    #[arg(long, default_value_t = 1_000_000_000_u128)]
    withdraw_psy: u128,
    #[arg(long, default_value_t = 1_000_000_000_u128)]
    public_transfer_psy: u128,
    #[arg(long, default_value_t = 1_000_000_000_u128)]
    private_transfer_psy: u128,
    #[arg(long, default_value_t = 1_200_u64)]
    poll_timeout_secs: u64,
}

#[derive(Clone, Debug)]
struct Network {
    coordinator: String,
    realms: Vec<String>,
    faucet: String,
    services: String,
    l1_rpc_urls: Vec<String>,
}

#[derive(Clone, Debug)]
struct Contracts {
    bridge: String,
    router: String,
    gateway: String,
    token_faucet: String,
    psy: String,
    usdt: String,
}

#[derive(Clone, Debug)]
struct Token {
    symbol: &'static str,
    l1_address: String,
    l2_contract_id: u64,
    deposit_amount: u128,
    withdraw_amount: u128,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    version: u32,
    created_at_epoch: u64,
    root: String,
    network: String,
    deployments_network: String,
    l1_chain_id: u64,
    l1_chain_index: u32,
    evm_address: String,
}

#[derive(Debug)]
struct Captured {
    stdout: String,
    stderr: String,
}

struct Runner {
    run_dir: PathBuf,
    cli: PathBuf,
    rpc_config: PathBuf,
    network: Network,
    contracts: Contracts,
    http: Client,
    l1_rpc_url: String,
    poll_timeout: Duration,
    contract_artifact: PathBuf,
    contract_abi: Option<PathBuf>,
    p1_key: String,
    p2_key: String,
    e_key: String,
    e_address: String,
    psy: Token,
    usdt: Token,
    public_transfer_amount: u128,
    private_transfer_amount: u128,
    minimum_l1_native_wei: u128,
    l1_chain_index: u32,
    expected_l1_chain_id: u64,
}

fn main() -> Result<()> {
    // SAFETY: setting the process-wide Unix umask before creating files is
    // single-threaded and does not dereference pointers.
    unsafe {
        libc::umask(0o077);
    }
    let cli = Cli::parse();
    match cli.command {
        Commands::Init(args) => init(args),
        Commands::Status(args) => status(args),
        Commands::Run(args) => run(args),
    }
}

fn init(args: InitArgs) -> Result<()> {
    let root = canonical_root(&args.root)?;
    let source_config = args
        .config_path
        .unwrap_or_else(|| root.join("psy-genesis/config.json"));
    let deployments_network = args
        .deployments_network
        .unwrap_or_else(|| args.network.clone());
    let deployments_dir = deployment_dir(&root, &deployments_network);
    let deployments = deployments_dir.join("deployed-contracts.json");
    ensure!(source_config.is_file(), "missing {}", source_config.display());
    ensure!(deployments.is_file(), "missing {}", deployments.display());

    let mut config: Value = serde_json::from_slice(&fs::read(&source_config)?)?;
    let selected_network = config
        .pointer(&format!("/networks/{}", args.network))
        .with_context(|| format!("client config has no {} network", args.network))?;
    let l1_chain_id = selected_network
        .get("l1_chain_id")
        .and_then(value_as_u64)
        .with_context(|| format!("network {} has no numeric l1_chain_id", args.network))?;
    let l1_chain_index = args
        .l1_chain_index
        .map(Ok)
        .unwrap_or_else(|| inferred_l1_chain_index(&args.network))?;

    let run_dir = match args.run_dir {
        Some(path) => path,
        None => {
            let private_dir = root.join(".private");
            let runs_dir = private_dir.join("e2e-runs");
            fs::create_dir_all(&runs_dir)?;
            fs::set_permissions(&private_dir, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&runs_dir, fs::Permissions::from_mode(0o700))?;
            runs_dir.join(format!(
                "psy-cli-full-e2e.{}.{}",
                std::process::id(),
                epoch_seconds()
            ))
        }
    };
    ensure!(!run_dir.exists(), "run directory already exists: {}", run_dir.display());
    fs::create_dir_all(&run_dir)?;
    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700))?;
    fs::create_dir_all(run_dir.join("phases"))?;
    fs::create_dir_all(run_dir.join("logs"))?;
    fs::create_dir_all(run_dir.join("secrets"))?;
    fs::create_dir_all(run_dir.join("deployments"))?;
    for dir in ["phases", "logs", "secrets", "deployments"] {
        fs::set_permissions(run_dir.join(dir), fs::Permissions::from_mode(0o700))?;
    }
    config["defaultNetwork"] = Value::String(args.network.clone());
    write_json_secure(&run_dir.join("config.json"), &config)?;
    copy_deployment_artifacts(
        &deployments_dir,
        &run_dir.join("deployments").join(&deployments_network),
    )?;
    if deployments_network != "localhost" {
        // The current deposit/claim CLI resolves Bridge_Proxy.json through a
        // legacy `localhost` deployment key. Keep that compatibility mapping
        // isolated inside the private run directory.
        copy_deployment_artifacts(
            &deployments_dir,
            &run_dir.join("deployments/localhost"),
        )?;
    }

    let p1 = random_hex_32();
    let p2 = random_hex_32();
    write_secret(&run_dir.join("secrets/p1.key"), &p1)?;
    write_secret(&run_dir.join("secrets/p2.key"), &p2)?;

    let e_key = if let Some(path) = args.evm_key_file {
        read_key(&path).with_context(|| format!("invalid EVM key file {}", path.display()))?
    } else {
        loop {
            let candidate = random_hex_32();
            if PrivateKeySigner::from_str(&candidate).is_ok() {
                break candidate;
            }
        }
    };
    let signer = PrivateKeySigner::from_str(e_key.trim_start_matches("0x"))?;
    let e_address = format!("{:#x}", signer.address());
    write_secret(&run_dir.join("secrets/e.key"), e_key.trim_start_matches("0x"))?;

    let manifest = Manifest {
        version: 2,
        created_at_epoch: epoch_seconds(),
        root: root.display().to_string(),
        network: args.network.clone(),
        deployments_network,
        l1_chain_id,
        l1_chain_index,
        evm_address: e_address.clone(),
    };
    write_json_secure(
        &run_dir.join("manifest.json"),
        &serde_json::to_value(manifest)?,
    )?;

    println!("run_dir={}", run_dir.display());
    println!("network={}", args.network);
    println!("l1_chain_id={l1_chain_id}");
    println!("l1_chain_index={l1_chain_index}");
    println!("e_l1_address={e_address}");
    println!("next=Fund this address with L1 native gas, then run status.");
    println!("secret_warning=Do not share or archive the run directory.");
    Ok(())
}

fn status(args: StatusArgs) -> Result<()> {
    let root = canonical_root(&args.root)?;
    let run_dir = args.run_dir;
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(run_dir.join("manifest.json"))
            .with_context(|| format!("missing manifest in {}", run_dir.display()))?,
    )?;
    let config: Value = serde_json::from_slice(&fs::read(run_dir.join("config.json"))?)?;
    let network = parse_network(&config, &manifest.network)?;
    let deployment: Value = serde_json::from_slice(&fs::read(
        run_dir
            .join("deployments")
            .join(&manifest.deployments_network)
            .join("deployed-contracts.json"),
    )?)?;
    let contracts = parse_contracts(&deployment)?;
    let l1_rpc_url = resolve_l1_rpc_url(args.l1_rpc_url, &network)?;

    let observed_l1_chain_id = cast_u128(&["chain-id", "--rpc-url", &l1_rpc_url])?;
    ensure!(
        observed_l1_chain_id == u128::from(manifest.l1_chain_id),
        "unexpected L1 chain ID: expected {}, got {}",
        manifest.l1_chain_id,
        observed_l1_chain_id
    );
    let eth = cast_u128(&[
        "balance",
        &manifest.evm_address,
        "--rpc-url",
        &l1_rpc_url,
    ])?;
    let psy = erc20_balance(&contracts.psy, &manifest.evm_address, &l1_rpc_url)?;
    let usdt = erc20_balance(&contracts.usdt, &manifest.evm_address, &l1_rpc_url)?;
    println!("root={}", root.display());
    println!("run_dir={}", run_dir.display());
    println!("network={}", manifest.network);
    println!("l1_chain_id={}", manifest.l1_chain_id);
    println!("observed_l1_chain_id={observed_l1_chain_id}");
    println!("l1_chain_index={}", manifest.l1_chain_index);
    println!("e_address={}", manifest.evm_address);
    println!("e_l1_native_wei={eth}");
    println!("e_ready_for_run={}", eth >= args.minimum_l1_native_wei);
    println!("e_l1_psy_raw={psy}");
    println!("e_l1_usdt_raw={usdt}");

    let http = Client::builder().timeout(Duration::from_secs(20)).build()?;
    for (name, url) in [
        ("coordinator", network.coordinator.as_str()),
        ("realm0", network.realms[0].as_str()),
        ("realm1", network.realms[1].as_str()),
    ] {
        let cp = rpc_checkpoint(&http, url)?;
        println!("{name}_checkpoint={cp}");
    }

    let phases = run_dir.join("phases");
    let mut entries = fs::read_dir(&phases)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    entries.sort();
    for entry in entries {
        println!("phase_file={entry}");
    }
    Ok(())
}

fn run(args: RunArgs) -> Result<()> {
    ensure!(
        args.authorized_staging_transactions,
        "pass --authorized-staging-transactions only after explicit authorization"
    );
    let runner = Runner::load(args)?;
    runner.run_all()
}

impl Runner {
    fn load(args: RunArgs) -> Result<Self> {
        let root = canonical_root(&args.root)?;
        let run_dir = args.run_dir.canonicalize().with_context(|| {
            format!("run directory does not exist: {}", args.run_dir.display())
        })?;
        let cli = root.join("target/release/psy_user_cli");
        ensure!(cli.is_file(), "missing release CLI: {}", cli.display());
        let rpc_config = run_dir.join("config.json");
        let config: Value = serde_json::from_slice(&fs::read(&rpc_config)?)?;
        let manifest: Manifest =
            serde_json::from_slice(&fs::read(run_dir.join("manifest.json"))?)?;
        ensure!(manifest.version == 2, "unsupported E2E manifest version {}", manifest.version);
        let network = parse_network(&config, &manifest.network)?;
        ensure!(network.realms.len() >= 2, "staging config needs realm0 and realm1");
        let deployment: Value = serde_json::from_slice(&fs::read(
            run_dir
                .join("deployments")
                .join(&manifest.deployments_network)
                .join("deployed-contracts.json"),
        )?)?;
        let contracts = parse_contracts(&deployment)?;
        let l1_rpc_url = resolve_l1_rpc_url(args.l1_rpc_url, &network)?;
        let p1_key = read_key(&run_dir.join("secrets/p1.key"))?;
        let p2_key = read_key(&run_dir.join("secrets/p2.key"))?;
        let e_key = read_key(&run_dir.join("secrets/e.key"))?;
        let signer = PrivateKeySigner::from_str(e_key.trim_start_matches("0x"))?;
        let derived_address = format!("{:#x}", signer.address());
        ensure!(
            derived_address.eq_ignore_ascii_case(&manifest.evm_address),
            "e.key does not match manifest address"
        );
        let contract_artifact = args
            .contract_artifact
            .unwrap_or_else(|| root.join("e2e/staging/fixtures/e2e-contract.json"));
        ensure!(
            contract_artifact.is_file(),
            "missing contract artifact {}",
            contract_artifact.display()
        );
        if let Some(path) = &args.contract_abi {
            ensure!(path.is_file(), "missing contract ABI {}", path.display());
        }
        ensure!(
            args.withdraw_psy >= args.deposit_psy,
            "PSY withdraw amount must fund the later PSY deposit"
        );
        ensure!(
            args.deposit_usdt >= args.withdraw_usdt,
            "USDT deposit amount must fund the later USDT withdrawal"
        );

        Ok(Self {
            run_dir,
            cli,
            rpc_config,
            network,
            contracts: contracts.clone(),
            http: Client::builder().timeout(Duration::from_secs(30)).build()?,
            l1_rpc_url,
            poll_timeout: Duration::from_secs(args.poll_timeout_secs),
            contract_artifact,
            contract_abi: args.contract_abi,
            p1_key,
            p2_key,
            e_key,
            e_address: manifest.evm_address,
            psy: Token {
                symbol: "PSY",
                l1_address: contracts.psy,
                l2_contract_id: 0,
                deposit_amount: args.deposit_psy,
                withdraw_amount: args.withdraw_psy,
            },
            usdt: Token {
                symbol: "USDT",
                l1_address: contracts.usdt,
                l2_contract_id: 4,
                deposit_amount: args.deposit_usdt,
                withdraw_amount: args.withdraw_usdt,
            },
            public_transfer_amount: args.public_transfer_psy,
            private_transfer_amount: args.private_transfer_psy,
            minimum_l1_native_wei: args.minimum_l1_native_wei,
            l1_chain_index: manifest.l1_chain_index,
            expected_l1_chain_id: manifest.l1_chain_id,
        })
    }

    fn run_all(&self) -> Result<()> {
        self.preflight(false)?;
        let p1 = self.register_user("p1", &self.p1_key)?;
        let p2 = self.register_user("p2", &self.p2_key)?;
        self.deploy_contract(&p1)?;

        self.l2_faucet_and_claim("p1", &self.p1_key, p1.user_id)?;
        self.l2_faucet_and_claim("p2", &self.p2_key, p2.user_id)?;
        self.l1_token_faucet(&self.usdt)?;

        self.deposit_and_claim(&self.usdt, &self.p1_key, p1.user_id)?;
        self.withdraw_and_settle(&self.psy, &self.p1_key, p1.user_id)?;
        self.deposit_and_claim(&self.psy, &self.p1_key, p1.user_id)?;
        self.withdraw_and_settle(&self.usdt, &self.p1_key, p1.user_id)?;

        self.public_transfer(
            "p1-to-p2",
            &self.p1_key,
            p1.user_id,
            &self.p2_key,
            p2.user_id,
        )?;
        self.public_transfer(
            "p2-to-p1",
            &self.p2_key,
            p2.user_id,
            &self.p1_key,
            p1.user_id,
        )?;
        self.private_transfer(
            "p1-to-p2",
            &self.p1_key,
            p1.user_id,
            &self.p2_key,
            p2.user_id,
        )?;
        self.private_transfer(
            "p2-to-p1",
            &self.p2_key,
            p2.user_id,
            &self.p1_key,
            p1.user_id,
        )?;

        let final_state = self.preflight(true)?;
        let result = json!({
            "status": "PASS",
            "finished_at_epoch": epoch_seconds(),
            "run_dir": self.run_dir,
            "users": {"p1": p1, "p2": p2},
            "e_address": self.e_address,
            "final": final_state
        });
        write_json_secure(&self.run_dir.join("result.json"), &result)?;
        println!("PASS run_dir={}", self.run_dir.display());
        println!("secret_warning=Remove all secrets before sharing or archiving.");
        Ok(())
    }

    fn preflight(&self, strict_final: bool) -> Result<Value> {
        let coordinator = rpc_checkpoint(&self.http, &self.network.coordinator)?;
        let realm0 = rpc_checkpoint(&self.http, &self.network.realms[0])?;
        let realm1 = rpc_checkpoint(&self.http, &self.network.realms[1])?;
        let min = coordinator.min(realm0).min(realm1);
        let max = coordinator.max(realm0).max(realm1);
        ensure!(max - min <= 2, "node checkpoints diverged: {coordinator}/{realm0}/{realm1}");

        let faucet = self.rpc(
            &self.network.faucet,
            "psy_get_psy_faucet_config",
            json!([]),
        )?;
        ensure!(
            faucet.pointer("/result/enabled").and_then(Value::as_bool) == Some(true),
            "standalone faucet is disabled"
        );
        ensure!(
            faucet
                .pointer("/result/turnstile_required")
                .and_then(Value::as_bool)
                == Some(false),
            "standalone faucet requires Turnstile"
        );
        let faucet_amount = faucet
            .pointer("/result/amount")
            .and_then(value_as_u128)
            .context("standalone faucet config has no numeric amount")?;
        let required_l2_psy = self
            .psy
            .withdraw_amount
            .saturating_add(self.public_transfer_amount)
            .saturating_add(self.private_transfer_amount);
        ensure!(
            faucet_amount >= required_l2_psy,
            "standalone faucet amount {faucet_amount} is below required L2 PSY {required_l2_psy}"
        );
        let health = self
            .http
            .get(format!("{}/health", self.network.services.trim_end_matches('/')))
            .send()?;
        ensure!(health.status().is_success(), "psy-services health failed");

        let chain_id = self.cast(&["chain-id", "--rpc-url", &self.l1_rpc_url])?;
        ensure!(
            chain_id.stdout.trim() == self.expected_l1_chain_id.to_string(),
            "unexpected L1 chain ID: expected {}, got {}",
            self.expected_l1_chain_id,
            chain_id.stdout.trim()
        );
        let eth = cast_u128(&[
            "balance",
            &self.e_address,
            "--rpc-url",
            &self.l1_rpc_url,
        ])?;
        let usdt_listed = self.cast(&[
            "call",
            &self.contracts.token_faucet,
            "isListed(address)(bool)",
            &self.usdt.l1_address,
            "--rpc-url",
            &self.l1_rpc_url,
        ])?;
        ensure!(
            usdt_listed.stdout.split_whitespace().next() == Some("true"),
            "staging L1 faucet does not list USDT"
        );
        let usdt_can_claim = self.cast(&[
            "call",
            &self.contracts.token_faucet,
            "canClaim(address,address)(bool,uint64)",
            &self.e_address,
            &self.usdt.l1_address,
            "--rpc-url",
            &self.l1_rpc_url,
        ])?;
        let l1_usdt_faucet_eligible =
            usdt_can_claim.stdout.split_whitespace().next() == Some("true");
        if !strict_final
            && !self
                .run_dir
                .join("phases/l1-faucet-usdt.ok.json")
                .is_file()
        {
            ensure!(
                l1_usdt_faucet_eligible,
                "e is not currently eligible for the L1 USDT faucet"
            );
        }
        let pending = self.bridge_count("pendingDepositCount()(uint256)")?;
        let proved = self.bridge_count("provedDepositCount()(uint256)")?;
        ensure!(pending >= proved, "pendingDepositCount is behind provedDepositCount");
        if strict_final {
            ensure!(
                pending == proved,
                "final pending/proved mismatch: {pending}/{proved}"
            );
        }
        let evidence = json!({
            "coordinator": coordinator,
            "realm0": realm0,
            "realm1": realm1,
            "l1_chain_id": self.expected_l1_chain_id,
            "l1_chain_index": self.l1_chain_index,
            "e_l1_native_wei": eth.to_string(),
            "l2_faucet_psy_raw": faucet_amount.to_string(),
            "l1_usdt_faucet_eligible": l1_usdt_faucet_eligible,
            "pending_deposit_count": pending,
            "proved_deposit_count": proved
        });
        let evidence_path = if strict_final {
            self.run_dir.join("final-preflight.json")
        } else {
            let initial = self.run_dir.join("initial-preflight.json");
            if initial.exists() {
                self.run_dir
                    .join(format!("resume-preflight-{}.json", epoch_seconds()))
            } else {
                initial
            }
        };
        write_json_secure(&evidence_path, &evidence)?;
        if !strict_final {
            ensure!(
                eth >= self.minimum_l1_native_wei,
                "e needs at least {} L1 native wei; address={}",
                self.minimum_l1_native_wei,
                self.e_address
            );
        }
        Ok(evidence)
    }

    fn register_user(&self, label: &str, key: &str) -> Result<UserEvidence> {
        let phase = format!("register-{label}");
        let evidence = self.mutation(&phase, || {
            let captured = self.cli(
                &phase,
                vec![
                    "register-user".into(),
                    "--rpc-config".into(),
                    self.rpc_config.clone().into_os_string(),
                    "--sign-type".into(),
                    "zk".into(),
                    "--private-key".into(),
                    key.into(),
                ],
                240,
                &[],
            )?;
            let combined = format!("{}\n{}", captured.stdout, captured.stderr);
            let pubkey = parse_quoted_field(&combined, "public_key_hash")
                .ok_or_else(|| anyhow!("register output has no public_key_hash"))?;
            let started = Instant::now();
            let user_id = loop {
                let (lookup, succeeded) = self.cli_allow_failure(
                    &format!("get-user-id-{label}"),
                    vec![
                        "get-user-id".into(),
                        "--rpc-config".into(),
                        self.rpc_config.clone().into_os_string(),
                        "--pub-key".into(),
                        pubkey.clone().into(),
                    ],
                    30,
                    &[],
                )?;
                if succeeded {
                    if let Some(id) = parse_prefixed_u64(&lookup.stdout, "user_id:") {
                        break id;
                    }
                }
                ensure!(
                    started.elapsed() < Duration::from_secs(120),
                    "user ID lookup timed out"
                );
                thread::sleep(Duration::from_secs(2));
            };
            let user_info = self.poll_get(
                &format!(
                    "{}/api/v1/get/user/info?user_id={user_id}",
                    self.network.services.trim_end_matches('/')
                ),
                |body| body.pointer("/data/user_id").and_then(Value::as_u64) == Some(user_id),
            )?;
            Ok(json!({
                "label": label,
                "public_key_hash": pubkey,
                "user_id": user_id,
                "realm": user_id >> 20,
                "services": user_info
            }))
        })?;
        Ok(UserEvidence {
            user_id: evidence["user_id"]
                .as_u64()
                .context("register evidence missing user_id")?,
            public_key_hash: evidence["public_key_hash"]
                .as_str()
                .context("register evidence missing public_key_hash")?
                .to_string(),
            realm: evidence["realm"]
                .as_u64()
                .context("register evidence missing realm")?,
        })
    }

    fn deploy_contract(&self, p1: &UserEvidence) -> Result<Value> {
        self.mutation("deploy-contract", || {
            let list_url = format!(
                "{}/api/v1/get/contract/list?limit=20&offset=0&summary=true&abi_format=none",
                self.network.services.trim_end_matches('/')
            );
            let before: Value = self
                .http
                .get(&list_url)
                .send()?
                .error_for_status()?
                .json()?;
            let contract_id_before = contract_rows(&before)
                .and_then(|rows| {
                    rows.iter()
                        .filter_map(|row| row.get("contract_id").and_then(Value::as_u64))
                        .max()
                })
                .unwrap_or(0);
            let output_path = self.run_dir.join("deployed-contract-command.json");
            let mut args = vec![
                "deploy-contract".into(),
                "--rpc-config".into(),
                self.rpc_config.clone().into_os_string(),
                "--private-key".into(),
                self.p1_key.clone().into(),
                "--contract-path".into(),
                self.contract_artifact.clone().into_os_string(),
                "--output-path".into(),
                output_path.into_os_string(),
                "--is-deploy".into(),
            ];
            if let Some(abi) = &self.contract_abi {
                args.push("--abi-path".into());
                args.push(abi.clone().into_os_string());
            }
            let captured = self.cli(
                "deploy-contract",
                args,
                600,
                &[("RUST_LOG", "info".to_string())],
            )?;
            let combined = format!("{}\n{}", captured.stdout, captured.stderr);
            let deployment_hash = parse_last_token_after(&combined, "contract deployed:")
                .context("could not parse deployed contract hash")?;
            let contracts = self.poll_get(&list_url, |body| {
                find_new_contract(body, &p1.public_key_hash, contract_id_before).is_some()
            })?;
            let contract_id = find_new_contract(
                &contracts,
                &p1.public_key_hash,
                contract_id_before,
            )
            .and_then(|row| row.get("contract_id"))
            .and_then(Value::as_u64)
            .context("new contract disappeared from services list")?;
            let info_url = format!(
                "{}/api/v1/get/contract/info?contract_id={contract_id}&abi_format=none",
                self.network.services.trim_end_matches('/')
            );
            let info = self.poll_get(&info_url, |body| {
                body.pointer("/data/contract_id").and_then(Value::as_u64)
                    == Some(contract_id)
                    && body
                        .pointer("/data/deployer")
                        .and_then(Value::as_str)
                        .is_some_and(|value| {
                            value.eq_ignore_ascii_case(&p1.public_key_hash)
                        })
            })?;
            Ok(json!({
                "deployment_hash": deployment_hash,
                "contract_uuid": info.pointer("/data/contract_uuid"),
                "deployer_user_id": p1.user_id,
                "contract_id": contract_id,
                "checkpoint_id": info.pointer("/data/checkpoint_id"),
                "services": info
            }))
        })
    }

    fn l2_faucet_and_claim(&self, label: &str, key: &str, user_id: u64) -> Result<()> {
        let faucet_phase = format!("l2-faucet-{label}");
        let faucet = self.mutation(&faucet_phase, || {
            let pubkey = self.read_phase(&format!("register-{label}"))?["public_key_hash"]
                .as_str()
                .context("missing public key")?
                .to_string();
            let response = self.rpc(
                &self.network.faucet,
                "psy_claim_faucet",
                json!([{
                    "recipient_user_id": user_id,
                    "recipient_public_key": pubkey
                }]),
            )?;
            ensure!(response.get("error").is_none_or(Value::is_null), "faucet RPC failed: {response}");
            let operator = response
                .pointer("/result/operator_user_id")
                .and_then(Value::as_u64)
                .context("faucet response missing operator_user_id")?;
            let tx_hash = response
                .pointer("/result/tx_hash")
                .and_then(Value::as_str)
                .context("faucet response missing tx_hash")?;
            let claimable = self.poll_public_claimable(user_id, operator, Some(1), false)?;
            Ok(json!({
                "operator_user_id": operator,
                "tx_hash": tx_hash,
                "checkpoint_id": response.pointer("/result/checkpoint_id"),
                "claimable": claimable
            }))
        })?;
        let operator = faucet["operator_user_id"]
            .as_u64()
            .context("faucet evidence missing operator")?;
        let claim_phase = format!("l2-faucet-claim-{label}");
        self.mutation(&claim_phase, || {
            let before = self.latest_checkpoint()?;
            self.cli(
                &claim_phase,
                vec![
                    "call".into(),
                    "--rpc-config".into(),
                    self.rpc_config.clone().into_os_string(),
                    "--sign-type".into(),
                    "zk".into(),
                    "--private-key".into(),
                    key.into(),
                    "--contract-id".into(),
                    "0".into(),
                    "--method-name".into(),
                    "simple_claim".into(),
                    "--inputs".into(),
                    format!("[{operator}]").into(),
                    "--wait-until-confirmation".into(),
                ],
                300,
                &[],
            )?;
            let event = self.poll_event(user_id, 0, SIMPLE_CLAIM_METHOD_ID, before)?;
            let cleared = self.poll_public_claimable(user_id, operator, None, true)?;
            Ok(json!({"event": event, "claimable_after": cleared}))
        })?;
        Ok(())
    }

    fn l1_token_faucet(&self, token: &Token) -> Result<Value> {
        let phase = format!("l1-faucet-{}", token.symbol.to_ascii_lowercase());
        self.mutation(&phase, || {
            let before = erc20_balance(&token.l1_address, &self.e_address, &self.l1_rpc_url)?;
            let captured = self.cast_named(
                &phase,
                vec![
                    "send".into(),
                    self.contracts.token_faucet.clone().into(),
                    "claim(address)".into(),
                    token.l1_address.clone().into(),
                    "--private-key".into(),
                    self.e_key.clone().into(),
                    "--rpc-url".into(),
                    self.l1_rpc_url.clone().into(),
                    "--json".into(),
                ],
                180,
            )?;
            let receipt: Value =
                serde_json::from_str(&captured.stdout).context("cast send did not return JSON")?;
            ensure!(receipt_status_success(&receipt), "token faucet receipt failed");
            let after = erc20_balance(&token.l1_address, &self.e_address, &self.l1_rpc_url)?;
            ensure!(after > before, "{} faucet did not increase balance", token.symbol);
            Ok(json!({
                "token": token.symbol,
                "token_address": token.l1_address,
                "tx_hash": receipt_tx_hash(&receipt),
                "balance_before": before.to_string(),
                "balance_after": after.to_string()
            }))
        })
    }

    fn deposit_and_claim(&self, token: &Token, p_key: &str, p_user_id: u64) -> Result<()> {
        self.approve_token(token, "router", &self.contracts.router)?;
        self.approve_token(token, "gateway", &self.contracts.gateway)?;
        let slug = token.symbol.to_ascii_lowercase();
        let deposit_phase = format!("deposit-{slug}");
        let deposit = self.mutation(&deposit_phase, || {
            let l1_balance =
                erc20_balance(&token.l1_address, &self.e_address, &self.l1_rpc_url)?;
            ensure!(
                l1_balance >= token.deposit_amount,
                "insufficient L1 {} for deposit",
                token.symbol
            );
            let pending_before = self.bridge_count("pendingDepositCount()(uint256)")?;
            let proved_before = self.bridge_count("provedDepositCount()(uint256)")?;
            let r0 = random_u32();
            let r1 = random_u32();
            let note_secret = random_limbs();
            let nullifier_secret = random_limbs();
            write_secret(
                &self.run_dir.join(format!("secrets/deposit-{slug}-r0")),
                &r0.to_string(),
            )?;
            write_secret(
                &self.run_dir.join(format!("secrets/deposit-{slug}-r1")),
                &r1.to_string(),
            )?;
            write_secret(
                &self
                    .run_dir
                    .join(format!("secrets/deposit-{slug}-note-secret")),
                &note_secret,
            )?;
            write_secret(
                &self
                    .run_dir
                    .join(format!("secrets/deposit-{slug}-nullifier-secret")),
                &nullifier_secret,
            )?;
            let proof = self.run_dir.join(format!("deposit-{slug}-proof.json"));
            let captured = self.cli(
                &deposit_phase,
                vec![
                    "deposit".into(),
                    "--l1-rpc-url".into(),
                    self.l1_rpc_url.clone().into(),
                    "--private-key".into(),
                    self.e_key.clone().into(),
                    "--router-address".into(),
                    self.contracts.router.clone().into(),
                    "--token".into(),
                    token.l1_address.clone().into(),
                    "--amount".into(),
                    token.deposit_amount.to_string().into(),
                    "--r0".into(),
                    r0.to_string().into(),
                    "--r1".into(),
                    r1.to_string().into(),
                    "--user-id".into(),
                    p_user_id.to_string().into(),
                    "--note-secret".into(),
                    note_secret.clone().into(),
                    "--nullifier-secret".into(),
                    nullifier_secret.clone().into(),
                    "--source-chain-index".into(),
                    self.l1_chain_index.to_string().into(),
                    "--l2-token-contract-id".into(),
                    token.l2_contract_id.to_string().into(),
                    "--rpc-config".into(),
                    self.rpc_config.clone().into_os_string(),
                    "--deposit-proof-output".into(),
                    proof.clone().into_os_string(),
                ],
                900,
                &[(
                    "PSY_DEPLOYMENTS_DIR",
                    self.run_dir.join("deployments").display().to_string(),
                )],
            )?;
            let combined = format!("{}\n{}", captured.stdout, captured.stderr);
            let tx_hash = parse_last_token_after(&combined, "deposit tx:")
                .context("deposit output missing tx hash")?;
            let deposit_index = parse_prefixed_u64(&combined, "deposit_index:")
                .context("deposit output missing deposit_index")?;
            ensure!(combined.contains("status: success"), "deposit L1 receipt failed");
            ensure!(
                proof.is_file() && fs::metadata(&proof)?.len() > 0,
                "deposit proof missing"
            );
            fs::set_permissions(&proof, fs::Permissions::from_mode(0o600))?;
            let proved_after = self.poll_bridge_count(
                "provedDepositCount()(uint256)",
                deposit_index + 1,
            )?;
            let pending_after = self.bridge_count("pendingDepositCount()(uint256)")?;
            ensure!(
                pending_after > deposit_index,
                "pending count did not include deposit"
            );
            Ok(json!({
                "token": token.symbol,
                "tx_hash": tx_hash,
                "deposit_index": deposit_index,
                "amount": token.deposit_amount.to_string(),
                "pending_before": pending_before,
                "proved_before": proved_before,
                "pending_after": pending_after,
                "proved_after": proved_after,
                "r0_file": format!("secrets/deposit-{slug}-r0"),
                "r1_file": format!("secrets/deposit-{slug}-r1"),
                "proof_file": proof.file_name().and_then(|s| s.to_str())
            }))
        })?;

        let deposit_index = deposit["deposit_index"]
            .as_u64()
            .context("deposit evidence missing index")?;
        let r0 = read_secret_value(
            &self.run_dir.join(format!("secrets/deposit-{slug}-r0")),
        )?;
        let r1 = read_secret_value(
            &self.run_dir.join(format!("secrets/deposit-{slug}-r1")),
        )?;
        let proof = self.run_dir.join(format!("deposit-{slug}-proof.json"));
        let claim_phase = format!("claim-deposit-{slug}");
        self.mutation(&claim_phase, || {
            let before = self.latest_checkpoint()?;
            self.cli(
                &claim_phase,
                vec![
                    "claim-deposit".into(),
                    "--rpc-config".into(),
                    self.rpc_config.clone().into_os_string(),
                    "--sign-type".into(),
                    "zk".into(),
                    "--private-key".into(),
                    p_key.into(),
                    "--l1-rpc-url".into(),
                    self.l1_rpc_url.clone().into(),
                    "--token-l1-address".into(),
                    token.l1_address.clone().into(),
                    "--amount".into(),
                    token.deposit_amount.to_string().into(),
                    "--source-chain-index".into(),
                    self.l1_chain_index.to_string().into(),
                    "--user-id".into(),
                    p_user_id.to_string().into(),
                    "--deposit-index".into(),
                    deposit_index.to_string().into(),
                    "--r0".into(),
                    r0.into(),
                    "--r1".into(),
                    r1.into(),
                    "--deposit-proof".into(),
                    proof.clone().into_os_string(),
                ],
                900,
                &[(
                    "PSY_DEPLOYMENTS_DIR",
                    self.run_dir.join("deployments").display().to_string(),
                )],
            )?;
            let event =
                self.poll_event(p_user_id, token.l2_contract_id, CLAIM_DEPOSIT_METHOD_ID, before)?;
            Ok(json!({
                "token": token.symbol,
                "deposit_index": deposit_index,
                "event": event
            }))
        })?;
        Ok(())
    }

    fn withdraw_and_settle(&self, token: &Token, p_key: &str, p_user_id: u64) -> Result<Value> {
        let slug = token.symbol.to_ascii_lowercase();
        let phase = format!("withdraw-{slug}");
        self.mutation(&phase, || {
            let nonce = format!("0x{}", random_hex_32());
            write_secret(
                &self.run_dir.join(format!("secrets/withdraw-{slug}-nonce")),
                &nonce,
            )?;
            let balance_before =
                erc20_balance(&token.l1_address, &self.e_address, &self.l1_rpc_url)?;
            let checkpoint_before = self.latest_checkpoint()?;
            self.cli(
                &phase,
                vec![
                    "withdraw".into(),
                    "--rpc-config".into(),
                    self.rpc_config.clone().into_os_string(),
                    "--sign-type".into(),
                    "zk".into(),
                    "--private-key".into(),
                    p_key.into(),
                    "--destination-chain-index".into(),
                    self.l1_chain_index.to_string().into(),
                    "--token-address".into(),
                    token.l1_address.clone().into(),
                    "--amount".into(),
                    token.withdraw_amount.to_string().into(),
                    "--recipient".into(),
                    self.e_address.clone().into(),
                    "--nonce".into(),
                    nonce.clone().into(),
                    "--l1-rpc-url".into(),
                    self.l1_rpc_url.clone().into(),
                    "--contract-id".into(),
                    token.l2_contract_id.to_string().into(),
                ],
                600,
                &[],
            )?;
            let event =
                self.poll_event(p_user_id, token.l2_contract_id, WITHDRAW_METHOD_ID, checkpoint_before)?;
            let row = self.poll_withdrawal(p_user_id, &nonce, token)?;
            let l1_tx_hash = row
                .get("l1_tx_hash")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .context("settled withdrawal has no l1_tx_hash")?;
            ensure!(
                row.get("claimed").and_then(Value::as_bool) == Some(true),
                "withdrawal row is not claimed"
            );
            let balance_after =
                erc20_balance(&token.l1_address, &self.e_address, &self.l1_rpc_url)?;
            ensure!(
                balance_after >= balance_before + token.withdraw_amount,
                "L1 {} balance did not increase by withdrawal amount",
                token.symbol
            );
            Ok(json!({
                "token": token.symbol,
                "nonce": nonce,
                "amount": token.withdraw_amount.to_string(),
                "l2_event": event,
                "l1_tx_hash": l1_tx_hash,
                "l1_balance_before": balance_before.to_string(),
                "l1_balance_after": balance_after.to_string(),
                "services": row
            }))
        })
    }

    fn public_transfer(
        &self,
        direction: &str,
        sender_key: &str,
        sender_id: u64,
        receiver_key: &str,
        receiver_id: u64,
    ) -> Result<()> {
        let send_phase = format!("public-transfer-{direction}");
        self.mutation(&send_phase, || {
            let before = self.latest_checkpoint()?;
            self.cli(
                &send_phase,
                vec![
                    "call".into(),
                    "--rpc-config".into(),
                    self.rpc_config.clone().into_os_string(),
                    "--sign-type".into(),
                    "zk".into(),
                    "--private-key".into(),
                    sender_key.into(),
                    "--contract-id".into(),
                    "0".into(),
                    "--method-name".into(),
                    "simple_transfer".into(),
                    "--inputs".into(),
                    format!("[{receiver_id},{}]", self.public_transfer_amount).into(),
                    "--wait-until-confirmation".into(),
                ],
                300,
                &[],
            )?;
            let event =
                self.poll_event(sender_id, 0, SIMPLE_TRANSFER_METHOD_ID, before)?;
            let claimable = self.poll_public_claimable(
                receiver_id,
                sender_id,
                Some(self.public_transfer_amount),
                false,
            )?;
            Ok(json!({"event": event, "claimable": claimable}))
        })?;
        let claim_phase = format!("public-claim-{direction}");
        self.mutation(&claim_phase, || {
            let before = self.latest_checkpoint()?;
            self.cli(
                &claim_phase,
                vec![
                    "call".into(),
                    "--rpc-config".into(),
                    self.rpc_config.clone().into_os_string(),
                    "--sign-type".into(),
                    "zk".into(),
                    "--private-key".into(),
                    receiver_key.into(),
                    "--contract-id".into(),
                    "0".into(),
                    "--method-name".into(),
                    "simple_claim".into(),
                    "--inputs".into(),
                    format!("[{sender_id}]").into(),
                    "--wait-until-confirmation".into(),
                ],
                300,
                &[],
            )?;
            let event = self.poll_event(receiver_id, 0, SIMPLE_CLAIM_METHOD_ID, before)?;
            let cleared =
                self.poll_public_claimable(receiver_id, sender_id, None, true)?;
            Ok(json!({"event": event, "claimable_after": cleared}))
        })?;
        Ok(())
    }

    fn private_transfer(
        &self,
        direction: &str,
        sender_key: &str,
        sender_id: u64,
        receiver_key: &str,
        receiver_id: u64,
    ) -> Result<()> {
        let r0 = random_u32();
        let r1 = random_u32();
        let binding = self
            .run_dir
            .join(format!("secrets/private-{direction}-binding.json"));
        if !binding.exists() {
            write_json_secure(&binding, &json!({"r0": r0, "r1": r1}))?;
        }
        let binding_json: Value = serde_json::from_slice(&fs::read(&binding)?)?;
        let r0 = binding_json["r0"].as_u64().context("binding missing r0")?;
        let r1 = binding_json["r1"].as_u64().context("binding missing r1")?;
        let derived = self.cli(
            &format!("derive-note-owner-{direction}"),
            vec![
                "derive-note-owner".into(),
                "--rpc-config".into(),
                self.rpc_config.clone().into_os_string(),
                "--private-key".into(),
                receiver_key.into(),
                "--random0".into(),
                r0.to_string().into(),
                "--random1".into(),
                r1.to_string().into(),
            ],
            120,
            &[],
        )?;
        let note_owner = parse_last_token_after(&derived.stdout, "note_owner:")
            .context("derive-note-owner output missing note_owner")?;
        let note_file = self.run_dir.join(format!("private-{direction}-note.json"));
        let send_phase = format!("private-transfer-{direction}");
        self.mutation(&send_phase, || {
            self.cli(
                &send_phase,
                vec![
                    "private-transfer".into(),
                    "--rpc-config".into(),
                    self.rpc_config.clone().into_os_string(),
                    "--private-key".into(),
                    sender_key.into(),
                    "--contract-id".into(),
                    "0".into(),
                    "--amount".into(),
                    self.private_transfer_amount.to_string().into(),
                    "--receiver".into(),
                    note_owner.clone().into(),
                    "--output".into(),
                    note_file.clone().into_os_string(),
                ],
                600,
                &[],
            )?;
            ensure!(
                note_file.is_file() && fs::metadata(&note_file)?.len() > 0,
                "private note proof file is missing"
            );
            fs::set_permissions(&note_file, fs::Permissions::from_mode(0o600))?;
            Ok(json!({
                "sender_user_id": sender_id,
                "note_file": note_file.file_name()
            }))
        })?;
        let claim_phase = format!("private-claim-{direction}");
        self.mutation(&claim_phase, || {
            let before = self.latest_checkpoint()?;
            self.cli(
                &claim_phase,
                vec![
                    "private-claim".into(),
                    "--rpc-config".into(),
                    self.rpc_config.clone().into_os_string(),
                    "--private-key".into(),
                    receiver_key.into(),
                    "--contract-id".into(),
                    "0".into(),
                    "--note-proof".into(),
                    note_file.clone().into_os_string(),
                    "--random0".into(),
                    r0.to_string().into(),
                    "--random1".into(),
                    r1.to_string().into(),
                ],
                600,
                &[],
            )?;
            let event = self.poll_event(receiver_id, 0, PRIVATE_CLAIM_METHOD_ID, before)?;
            Ok(json!({"receiver_user_id": receiver_id, "event": event}))
        })?;
        Ok(())
    }

    fn approve_token(&self, token: &Token, target_name: &str, target: &str) -> Result<Value> {
        let phase = format!(
            "approve-{}-{target_name}",
            token.symbol.to_ascii_lowercase()
        );
        self.mutation(&phase, || {
            let amount = token.deposit_amount.saturating_mul(2);
            let captured = self.cast_named(
                &phase,
                vec![
                    "send".into(),
                    token.l1_address.clone().into(),
                    "approve(address,uint256)(bool)".into(),
                    target.into(),
                    amount.to_string().into(),
                    "--private-key".into(),
                    self.e_key.clone().into(),
                    "--rpc-url".into(),
                    self.l1_rpc_url.clone().into(),
                    "--json".into(),
                ],
                180,
            )?;
            let receipt: Value = serde_json::from_str(&captured.stdout)?;
            ensure!(receipt_status_success(&receipt), "approval receipt failed");
            let allowance = self.cast(&[
                "call",
                &token.l1_address,
                "allowance(address,address)(uint256)",
                &self.e_address,
                target,
                "--rpc-url",
                &self.l1_rpc_url,
            ])?;
            let allowance = parse_first_u128(&allowance.stdout)?;
            ensure!(allowance >= token.deposit_amount, "allowance is too small");
            Ok(json!({
                "token": token.symbol,
                "spender": target,
                "tx_hash": receipt_tx_hash(&receipt),
                "allowance": allowance.to_string()
            }))
        })
    }

    fn mutation<F>(&self, name: &str, action: F) -> Result<Value>
    where
        F: FnOnce() -> Result<Value>,
    {
        let ok_path = self.run_dir.join("phases").join(format!("{name}.ok.json"));
        if ok_path.is_file() {
            return Ok(serde_json::from_slice(&fs::read(ok_path)?)?);
        }
        let intent_path = self
            .run_dir
            .join("phases")
            .join(format!("{name}.intent.json"));
        if intent_path.exists() {
            bail!(
                "ambiguous phase {name}: intent exists without OK; inspect chain/log evidence before retrying"
            );
        }
        write_json_secure(
            &intent_path,
            &json!({
                "phase": name,
                "started_at_epoch": epoch_seconds(),
                "automatic_retry_forbidden": true
            }),
        )?;
        let started = Instant::now();
        let mut evidence = action().with_context(|| {
            format!(
                "phase {name} failed; intent retained at {}",
                intent_path.display()
            )
        })?;
        evidence["phase"] = Value::String(name.to_string());
        evidence["duration_ms"] = Value::from(started.elapsed().as_millis() as u64);
        evidence["completed_at_epoch"] = Value::from(epoch_seconds());
        write_json_secure(&ok_path, &evidence)?;
        println!("PASS phase={name} duration_ms={}", started.elapsed().as_millis());
        Ok(evidence)
    }

    fn read_phase(&self, name: &str) -> Result<Value> {
        let path = self.run_dir.join("phases").join(format!("{name}.ok.json"));
        Ok(serde_json::from_slice(
            &fs::read(&path).with_context(|| format!("missing phase evidence {}", path.display()))?,
        )?)
    }

    fn cli(
        &self,
        log_name: &str,
        args: Vec<OsString>,
        timeout_secs: u64,
        envs: &[(&str, String)],
    ) -> Result<Captured> {
        self.command(log_name, self.cli.as_os_str().into(), args, timeout_secs, envs)
    }

    fn cli_allow_failure(
        &self,
        log_name: &str,
        args: Vec<OsString>,
        timeout_secs: u64,
        envs: &[(&str, String)],
    ) -> Result<(Captured, bool)> {
        self.command_capture(
            log_name,
            self.cli.as_os_str().into(),
            args,
            timeout_secs,
            envs,
        )
    }

    fn cast(&self, args: &[&str]) -> Result<Captured> {
        self.command(
            "cast-readonly",
            OsString::from("cast"),
            args.iter().map(OsString::from).collect(),
            60,
            &[],
        )
    }

    fn cast_named(&self, name: &str, args: Vec<OsString>, timeout_secs: u64) -> Result<Captured> {
        self.command(name, OsString::from("cast"), args, timeout_secs, &[])
    }

    fn command(
        &self,
        log_name: &str,
        program: OsString,
        args: Vec<OsString>,
        timeout_secs: u64,
        envs: &[(&str, String)],
    ) -> Result<Captured> {
        let (captured, succeeded) =
            self.command_capture(log_name, program, args, timeout_secs, envs)?;
        ensure!(succeeded, "{log_name} failed; inspect mode-600 logs");
        Ok(captured)
    }

    fn command_capture(
        &self,
        log_name: &str,
        program: OsString,
        args: Vec<OsString>,
        timeout_secs: u64,
        envs: &[(&str, String)],
    ) -> Result<(Captured, bool)> {
        let mut command = Command::new("timeout");
        command.arg(timeout_secs.to_string()).arg(program).args(args);
        for (key, value) in envs {
            command.env(key, value);
        }
        let output = command.output().with_context(|| format!("failed to start {log_name}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        write_secret(
            &self.run_dir.join("logs").join(format!("{log_name}.stdout.log")),
            &stdout,
        )?;
        write_secret(
            &self.run_dir.join("logs").join(format!("{log_name}.stderr.log")),
            &stderr,
        )?;
        Ok((Captured { stdout, stderr }, output.status.success()))
    }

    fn rpc(&self, url: &str, method: &str, params: Value) -> Result<Value> {
        let response = self
            .http
            .post(url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()?;
        ensure!(response.status().is_success(), "RPC {method} HTTP {}", response.status());
        Ok(response.json()?)
    }

    fn latest_checkpoint(&self) -> Result<u64> {
        rpc_checkpoint(&self.http, &self.network.coordinator)
    }

    fn poll_get<F>(&self, url: &str, predicate: F) -> Result<Value>
    where
        F: Fn(&Value) -> bool,
    {
        let started = Instant::now();
        let mut last = Value::Null;
        loop {
            if let Ok(response) = self.http.get(url).send() {
                if response.status().is_success() {
                    last = response.json()?;
                    if predicate(&last) {
                        return Ok(last);
                    }
                }
            }
            ensure!(
                started.elapsed() < self.poll_timeout,
                "timeout polling {url}; last={last}"
            );
            thread::sleep(Duration::from_secs(3));
        }
    }

    fn poll_event(
        &self,
        user_id: u64,
        contract_id: u64,
        method_id: u64,
        after_checkpoint: u64,
    ) -> Result<Value> {
        let url = format!(
            "{}/api/v1/events?user_ids={user_id}&contract_ids={contract_id}&method_ids={method_id}&limit=50",
            self.network.services.trim_end_matches('/')
        );
        let body = self.poll_get(&url, |body| {
            body.pointer("/data/events")
                .and_then(Value::as_array)
                .is_some_and(|events| {
                    events.iter().any(|event| {
                        event.get("checkpoint_id").and_then(Value::as_u64)
                            > Some(after_checkpoint)
                            && event.get("method_id").and_then(Value::as_u64) == Some(method_id)
                    })
                })
        })?;
        body.pointer("/data/events")
            .and_then(Value::as_array)
            .and_then(|events| {
                events
                    .iter()
                    .filter(|event| {
                        event.get("checkpoint_id").and_then(Value::as_u64)
                            > Some(after_checkpoint)
                            && event.get("method_id").and_then(Value::as_u64) == Some(method_id)
                    })
                    .max_by_key(|event| event.get("checkpoint_id").and_then(Value::as_u64))
                    .cloned()
            })
            .context("event disappeared from services response")
    }

    fn poll_public_claimable(
        &self,
        user_id: u64,
        sender_id: u64,
        minimum_amount: Option<u128>,
        expect_clear: bool,
    ) -> Result<Value> {
        let url = format!(
            "{}/api/v1/wallet/public-claimable",
            self.network.services.trim_end_matches('/')
        );
        let started = Instant::now();
        let mut attempt = 0_u64;
        loop {
            attempt += 1;
            let response = self
                .http
                .post(&url)
                .json(&json!({"user_id":user_id,"token_contract_ids":[0]}))
                .send();
            let (curl_ok, status, body) = match response {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let body: Value = response.json().unwrap_or(Value::Null);
                    (true, status, body)
                }
                Err(_) => (false, 0, Value::Null),
            };
            let response_name = format!(
                "public-claimable-{user_id}-{sender_id}-attempt-{attempt:04}.json"
            );
            write_json_secure(
                &self.run_dir.join("logs").join(&response_name),
                &body,
            )?;
            let attempt_label = format!("user-{user_id}-sender-{sender_id}");
            append_line_secure(
                &self.run_dir.join("public-claimable-http-attempts.tsv"),
                &format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\n",
                    epoch_seconds(),
                    attempt_label,
                    attempt,
                    if curl_ok { 0 } else { 1 },
                    status,
                    response_name
                ),
            )?;
            let last = body;
            if curl_ok && (200..300).contains(&status) {
                let active = last
                    .pointer("/data/items")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items.iter().filter(|item| {
                            item.get("sender_user_id")
                                .and_then(value_as_u64)
                                == Some(sender_id)
                                && item.get("claimed").and_then(Value::as_bool) == Some(false)
                                && item
                                    .get("amount")
                                    .and_then(value_as_u128)
                                    .is_some_and(|amount| amount > 0)
                        })
                    });
                let matches = active
                    .as_ref()
                    .map(|items| {
                        items.clone().any(|item| {
                            minimum_amount.is_none_or(|minimum| {
                                item.get("amount")
                                    .and_then(value_as_u128)
                                    .is_some_and(|amount| amount >= minimum)
                            })
                        })
                    })
                    .unwrap_or(false);
                if (expect_clear && !matches) || (!expect_clear && matches) {
                    return Ok(last);
                }
            }
            ensure!(
                started.elapsed() < self.poll_timeout,
                "public claimable timeout for user {user_id}; last={last}"
            );
            thread::sleep(Duration::from_secs(2));
        }
    }

    fn poll_withdrawal(&self, user_id: u64, nonce: &str, token: &Token) -> Result<Value> {
        let url = format!(
            "{}/api/v1/get/bridge/withdrawals?user_id={user_id}&limit=50",
            self.network.services.trim_end_matches('/')
        );
        let normalized_nonce = nonce.to_ascii_lowercase();
        let normalized_token = normalize_address(&token.l1_address);
        let body = self.poll_get(&url, |body| {
            body.pointer("/data/withdrawals")
                .and_then(Value::as_array)
                .is_some_and(|rows| {
                    rows.iter().any(|row| {
                        row.get("nonce_hex")
                            .and_then(Value::as_str)
                            .is_some_and(|value| value.eq_ignore_ascii_case(&normalized_nonce))
                            && row.get("claimed").and_then(Value::as_bool) == Some(true)
                            && row
                                .get("l1_tx_hash")
                                .and_then(Value::as_str)
                                .is_some_and(|value| !value.is_empty())
                    })
                })
        })?;
        let row = body
            .pointer("/data/withdrawals")
            .and_then(Value::as_array)
            .and_then(|rows| {
                rows.iter().find(|row| {
                    row.get("nonce_hex")
                        .and_then(Value::as_str)
                        .is_some_and(|value| value.eq_ignore_ascii_case(&normalized_nonce))
                })
            })
            .cloned()
            .context("withdrawal disappeared")?;
        ensure!(
            row.get("amount_hex")
                .and_then(Value::as_str)
                .and_then(parse_hex_u128)
                == Some(token.withdraw_amount),
            "withdrawal amount mismatch"
        );
        let row_token = normalize_address(
            row
            .get("token_address_hex")
            .and_then(Value::as_str)
            .context("withdrawal has no token address")?,
        );
        ensure!(row_token == normalized_token, "withdrawal token mismatch");
        Ok(row)
    }

    fn bridge_count(&self, signature: &str) -> Result<u64> {
        let captured = self.cast(&[
            "call",
            &self.contracts.bridge,
            signature,
            "--rpc-url",
            &self.l1_rpc_url,
        ])?;
        parse_first_u64(&captured.stdout)
    }

    fn poll_bridge_count(&self, signature: &str, target: u64) -> Result<u64> {
        let started = Instant::now();
        loop {
            let count = self.bridge_count(signature)?;
            if count >= target {
                return Ok(count);
            }
            ensure!(
                started.elapsed() < self.poll_timeout,
                "timeout waiting for {signature} >= {target}"
            );
            thread::sleep(Duration::from_secs(5));
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct UserEvidence {
    user_id: u64,
    public_key_hash: String,
    realm: u64,
}

fn canonical_root(path: &Path) -> Result<PathBuf> {
    path.canonicalize()
        .with_context(|| format!("invalid root {}", path.display()))
}

fn deployment_dir(root: &Path, network: &str) -> PathBuf {
    root.join("psy-contracts")
        .join("deployments")
        .join(network)
}

fn copy_deployment_artifacts(source: &Path, destination: &Path) -> Result<()> {
    ensure!(source.is_dir(), "missing deployment directory {}", source.display());
    fs::create_dir_all(destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let target = destination.join(entry.file_name());
        fs::copy(entry.path(), &target)?;
        fs::set_permissions(target, fs::Permissions::from_mode(0o600))?;
    }
    ensure!(
        destination.join("deployed-contracts.json").is_file(),
        "deployment directory {} has no deployed-contracts.json",
        source.display()
    );
    Ok(())
}

fn inferred_l1_chain_index(network: &str) -> Result<u32> {
    match network {
        "sepolia" => Ok(0),
        "bsc-testnet" | "bscTestnet" => Ok(1),
        "base-sepolia" | "baseSepolia" => Ok(2),
        _ => bail!(
            "cannot infer protocol bridge chain index for {network}; pass --l1-chain-index"
        ),
    }
}

fn resolve_l1_rpc_url(explicit: Option<String>, network: &Network) -> Result<String> {
    explicit
        .or_else(|| network.l1_rpc_urls.first().cloned())
        .context("no L1 RPC configured; pass --l1-rpc-url or add l1_rpc_urls to the network")
}

fn parse_network(config: &Value, network_name: &str) -> Result<Network> {
    let network = config
        .pointer(&format!("/networks/{network_name}"))
        .with_context(|| format!("config has no {network_name} network"))?;
    let coordinator = network
        .pointer("/coordinator_configs/0/rpc_url/0")
        .and_then(Value::as_str)
        .context("missing coordinator URL")?
        .to_string();
    let realms = network
        .get("realm_configs")
        .and_then(Value::as_array)
        .context("missing realm configs")?
        .iter()
        .filter_map(|realm| {
            realm
                .pointer("/rpc_url/0")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    let faucet = network
        .pointer("/faucet_rpc_url/0")
        .and_then(Value::as_str)
        .context("missing faucet URL")?
        .to_string();
    let services = network
        .pointer("/api_services_url/0")
        .and_then(Value::as_str)
        .context("missing services URL")?
        .to_string();
    let l1_rpc_urls = network
        .get("l1_rpc_urls")
        .and_then(Value::as_array)
        .context("missing l1_rpc_urls")?
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    ensure!(!l1_rpc_urls.is_empty(), "l1_rpc_urls is empty");
    Ok(Network {
        coordinator,
        realms,
        faucet,
        services,
        l1_rpc_urls,
    })
}

fn parse_contracts(deployment: &Value) -> Result<Contracts> {
    let address = |name: &str| -> Result<String> {
        deployment
            .pointer(&format!("/contracts/{name}"))
            .or_else(|| deployment.pointer(&format!("/core/{name}")))
            .and_then(Value::as_str)
            .map(str::to_string)
            .with_context(|| format!("deployment missing {name}"))
    };
    Ok(Contracts {
        bridge: address("Bridge")?,
        router: address("Router")?,
        gateway: address("ERC20Gateway")?,
        token_faucet: address("TokenFaucetManager")?,
        psy: address("PsyToken")?,
        usdt: address("USDTToken")?,
    })
}

fn rpc_checkpoint(client: &Client, url: &str) -> Result<u64> {
    let response: Value = client
        .post(url)
        .json(&json!({
            "jsonrpc":"2.0",
            "id":1,
            "method":"psy_get_latest_checkpoint_id",
            "params":[]
        }))
        .send()?
        .error_for_status()?
        .json()?;
    response
        .get("result")
        .and_then(Value::as_u64)
        .context("checkpoint RPC missing numeric result")
}

fn cast_u128(args: &[&str]) -> Result<u128> {
    let output = Command::new("timeout")
        .arg("60")
        .arg("cast")
        .args(args)
        .output()?;
    if !output.status.success() {
        let rpc_url = args
            .windows(2)
            .find(|pair| pair[0] == "--rpc-url")
            .map(|pair| pair[1]);
        let mut stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if let Some(rpc_url) = rpc_url {
            stderr = stderr.replace(rpc_url, "<redacted-rpc-url>");
        }
        bail!(
            "cast {} failed with {}: {}",
            args.first().copied().unwrap_or("<unknown>"),
            output.status,
            stderr.trim()
        );
    }
    parse_first_u128(&String::from_utf8_lossy(&output.stdout))
}

fn erc20_balance(token: &str, owner: &str, rpc_url: &str) -> Result<u128> {
    cast_u128(&[
        "call",
        token,
        "balanceOf(address)(uint256)",
        owner,
        "--rpc-url",
        rpc_url,
    ])
}

fn parse_first_u128(text: &str) -> Result<u128> {
    let token = text.split_whitespace().next().context("empty numeric output")?;
    if let Some(hex) = token.strip_prefix("0x") {
        Ok(u128::from_str_radix(hex, 16)?)
    } else {
        Ok(token.parse()?)
    }
}

fn parse_first_u64(text: &str) -> Result<u64> {
    let value = parse_first_u128(text)?;
    value.try_into().context("value does not fit u64")
}

fn parse_hex_u128(text: &str) -> Option<u128> {
    u128::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

fn normalize_address(value: &str) -> String {
    value
        .trim_start_matches("0x")
        .trim_start_matches('0')
        .to_ascii_lowercase()
}

fn receipt_status_success(receipt: &Value) -> bool {
    receipt
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|value| value == "0x1" || value == "1")
        || receipt.get("status").and_then(Value::as_u64) == Some(1)
}

fn receipt_tx_hash(receipt: &Value) -> Option<&str> {
    receipt
        .get("transactionHash")
        .or_else(|| receipt.get("transaction_hash"))
        .and_then(Value::as_str)
}

fn parse_quoted_field(text: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    text.lines().find_map(|line| {
        let position = line.find(&needle)?;
        let rest = &line[position + needle.len()..];
        let start = rest.find('"')?;
        let rest = &rest[start + 1..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    })
}

fn parse_last_token_after(text: &str, marker: &str) -> Option<String> {
    let clean = strip_ansi(text);
    clean
        .lines()
        .filter_map(|line| {
            let position = line.find(marker)?;
            line[position + marker.len()..]
                .split_whitespace()
                .next()
                .map(|value| {
                    value
                        .trim_matches(|ch: char| {
                            !ch.is_ascii_alphanumeric() && ch != 'x' && ch != '_'
                        })
                        .to_string()
                })
        })
        .next_back()
}

fn strip_ansi(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for code in chars.by_ref() {
                if ('@'..='~').contains(&code) {
                    break;
                }
            }
        } else {
            output.push(ch);
        }
    }
    output
}

fn parse_prefixed_u64(text: &str, marker: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let position = line.find(marker)?;
        line[position + marker.len()..]
            .split_whitespace()
            .next()?
            .trim_matches(|ch: char| !ch.is_ascii_digit())
            .parse()
            .ok()
    })
}

fn value_as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn value_as_u128(value: &Value) -> Option<u128> {
    value
        .as_u64()
        .map(u128::from)
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
}

fn find_new_contract<'a>(
    body: &'a Value,
    deployer_public_key_hash: &str,
    contract_id_before: u64,
) -> Option<&'a Value> {
    contract_rows(body)?
        .iter()
        .filter(|row| {
            row.get("contract_id").and_then(Value::as_u64) > Some(contract_id_before)
                && row
                    .get("deployer")
                    .and_then(Value::as_str)
                    .is_some_and(|value| {
                        value.eq_ignore_ascii_case(deployer_public_key_hash)
                    })
        })
        .max_by_key(|row| row.get("contract_id").and_then(Value::as_u64))
}

fn contract_rows(body: &Value) -> Option<&Vec<Value>> {
    body.pointer("/data/items")
        .or_else(|| body.pointer("/data/contracts"))
        .and_then(Value::as_array)
}

fn random_hex_32() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn random_u32() -> u32 {
    OsRng.next_u32()
}

fn random_limbs() -> String {
    (0..4)
        .map(|_| OsRng.next_u32().to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn read_key(path: &Path) -> Result<String> {
    let key = read_secret_value(path)?
        .trim_start_matches("0x")
        .to_string();
    ensure!(
        key.len() == 64 && key.chars().all(|ch| ch.is_ascii_hexdigit()),
        "expected 32-byte hex key"
    );
    Ok(key)
}

fn read_secret_value(path: &Path) -> Result<String> {
    let value = fs::read_to_string(path)?.trim().to_string();
    ensure!(!value.is_empty(), "secret value is empty");
    Ok(value)
}

fn write_secret(path: &Path, value: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(value.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn append_line_secure(path: &Path, value: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create(true).append(true).mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(value.as_bytes())?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn write_json_secure(path: &Path, value: &Value) -> Result<()> {
    write_secret(path, &serde_json::to_string_pretty(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_registration_public_key() {
        let log = r#"{
  "public_key_hash": "442c1dd70972096bde806269a3499968b1fe12c23fbe962ce3d3e856b90a0f39",
  "fingerprint": "abc"
}"#;
        assert_eq!(
            parse_quoted_field(log, "public_key_hash").as_deref(),
            Some("442c1dd70972096bde806269a3499968b1fe12c23fbe962ce3d3e856b90a0f39")
        );
    }

    #[test]
    fn parses_ansi_wrapped_contract_uuid() {
        let log = "\u{1b}[32m INFO contract deployed: deadbeef0123\u{1b}[0m";
        assert_eq!(
            parse_last_token_after(log, "contract deployed:").as_deref(),
            Some("deadbeef0123")
        );
    }

    #[test]
    fn parses_deposit_evidence() {
        let log = "deposit tx: 0xabc123\nstatus: success\ndeposit_index: 7\n";
        assert_eq!(
            parse_last_token_after(log, "deposit tx:").as_deref(),
            Some("0xabc123")
        );
        assert_eq!(parse_prefixed_u64(log, "deposit_index:"), Some(7));
    }

    #[test]
    fn recognizes_cast_receipt_statuses() {
        assert!(receipt_status_success(&json!({"status":"0x1"})));
        assert!(receipt_status_success(&json!({"status":1})));
        assert!(!receipt_status_success(&json!({"status":"0x0"})));
    }

    #[test]
    fn generated_l2_keys_are_32_bytes() {
        let key = random_hex_32();
        assert_eq!(key.len(), 64);
        assert!(key.chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn normalizes_padded_addresses() {
        assert_eq!(
            normalize_address(
                "0x000000000000000000000000d8B4F2bf23daaeC19686190d1013E4778E003dFb"
            ),
            normalize_address("0xd8B4F2bf23daaeC19686190d1013E4778E003dFb")
        );
    }

    #[test]
    fn accepts_both_contract_list_response_shapes() {
        let item = json!({
            "contract_id": 7,
            "deployer": "abc"
        });
        for body in [
            json!({"data":{"items":[item.clone()]}}),
            json!({"data":{"contracts":[item.clone()]}}),
        ] {
            assert_eq!(
                find_new_contract(&body, "abc", 6)
                    .and_then(|row| row.get("contract_id"))
                    .and_then(Value::as_u64),
                Some(7)
            );
        }
    }

    #[test]
    fn parses_selected_bsc_testnet_network() {
        let config = json!({
            "networks": {
                "sepolia": {},
                "bsc-testnet": {
                    "coordinator_configs": [{"rpc_url": ["https://coordinator.example"]}],
                    "realm_configs": [
                        {"rpc_url": ["https://realm0.example"]},
                        {"rpc_url": ["https://realm1.example"]}
                    ],
                    "faucet_rpc_url": ["https://faucet.example"],
                    "api_services_url": ["https://services.example"],
                    "l1_rpc_urls": ["https://bsc-rpc.example"]
                }
            }
        });

        let network = parse_network(&config, "bsc-testnet").unwrap();
        assert_eq!(network.coordinator, "https://coordinator.example");
        assert_eq!(network.realms.len(), 2);
        assert_eq!(network.l1_rpc_urls, vec!["https://bsc-rpc.example"]);
    }

    #[test]
    fn bridge_chain_index_is_explicit_for_known_networks() {
        assert_eq!(inferred_l1_chain_index("sepolia").unwrap(), 0);
        assert_eq!(inferred_l1_chain_index("bsc-testnet").unwrap(), 1);
        assert_eq!(inferred_l1_chain_index("bscTestnet").unwrap(), 1);
        assert_eq!(inferred_l1_chain_index("base-sepolia").unwrap(), 2);
        assert_eq!(inferred_l1_chain_index("baseSepolia").unwrap(), 2);
        assert!(inferred_l1_chain_index("unknown").is_err());
    }

    #[test]
    fn copies_complete_deployment_artifact_set() {
        let root = std::env::temp_dir().join(format!(
            "psy-e2e-deployments-{}-{}",
            std::process::id(),
            epoch_seconds()
        ));
        let source = root.join("source");
        let destination = root.join("destination");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("deployed-contracts.json"), b"{}").unwrap();
        fs::write(source.join("Bridge_Proxy.json"), b"{\"address\":\"0x1\"}").unwrap();

        copy_deployment_artifacts(&source, &destination).unwrap();

        assert!(destination.join("deployed-contracts.json").is_file());
        assert!(destination.join("Bridge_Proxy.json").is_file());
        assert_eq!(
            fs::metadata(destination.join("Bridge_Proxy.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn explicit_l1_rpc_overrides_network_default() {
        let network = Network {
            coordinator: String::new(),
            realms: Vec::new(),
            faucet: String::new(),
            services: String::new(),
            l1_rpc_urls: vec!["https://default.example".into()],
        };
        assert_eq!(
            resolve_l1_rpc_url(Some("https://override.example".into()), &network).unwrap(),
            "https://override.example"
        );
        assert_eq!(
            resolve_l1_rpc_url(None, &network).unwrap(),
            "https://default.example"
        );
    }
}
