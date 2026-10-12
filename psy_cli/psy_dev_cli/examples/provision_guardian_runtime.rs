//! Guardian runtime provisioning example.
//!
//! Composes existing public APIs and mirrors the guardian wire schemas that
//! live in the `psy_relayer_cli` binary crate, cited per struct. Runtime
//! consumers (`psy_relayer_cli guardian-create-db` / `guardian-service`, the
//! relayer `GuardianClientConfig` loader, and `guardian_acceptance`) re-validate
//! every emitted file with `deny_unknown_fields`, SHA-256 index checks and
//! live-chain Genesis authentication, so drift here fails closed at consume time.
//!
//! Owns the guardian-security boundary under `<guardians-root>/provision/` and
//! the documented acceptance configs that have no separate source template:
//! `manifest.json`, `relayer.guardian-client.json`, `relayer.daemon.toml`, and
//! `next-members.json`. Chain contract addresses and deployment checkpoints are
//! not guessed: `--chains` must already carry them. It never reads
//! `<guardians-root>/secrets/*` (referenced by path only; consumed later by
//! `guardian::runtime::load_signing_key`) and never prints secret material.
//!
//! Real-input requirements (no fakes):
//! - `--genesis-hash` is the real checkpoint 0 identity
//!   `Hash256::from(checkpoint_leaf.qfhash::<PsyHasher>())`
//!   (`psy_cli/psy_relayer_cli/src/guardian/service.rs:51`). Omit it only when
//!   the coordinator at `--l2-rpc` is already up.
//! - `--chains`: real `ChainAuthorization` values. Schema mirror of
//!   `psy_cli/psy_relayer_cli/src/guardian/protocol.rs:187-199`.
//! - `--approved-contracts`: real compiler artifacts and contract leaves for
//!   contract ids {0,2,3,6}. Schema mirror of protocol.rs:150-157.
//! - `--max-fee`: operator-set guard consumed by
//!   `psy_cli/psy_relayer_cli/src/guardian/verify.rs`.
//! - `--next-members`: canonical `[QHashOut; 3]` JSON changing at least one
//!   initial member (`psy_cli/psy_relayer_cli/src/main.rs:211-213`).
//!
//! Usage:
//! ```text
//! cargo run --release -p psy_dev_cli --example provision_guardian_runtime -- \
//!   --guardians-root /absolute/localhost-guardians \
//!   --genesis-hash 0x<checkpoint0 identity> \
//!   --chains <chains.json> --approved-contracts <approved.json> \
//!   --next-members <next-members.json> --max-fee 100000000
//! ```
//!
//! Verification boundary: authored without compile/test execution per task
//! directive; independent static review and first execution are separate gates.

use std::{
    ffi::{CString, OsStr},
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read as _, Write as _},
    net::TcpStream,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
            process::CommandExt as _,
        },
    },
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    field::types::PrimeField64,
    hash::poseidon::PoseidonHash,
    plonk::{
        circuit_data::CommonCircuitData,
        config::{Hasher as _, PoseidonGoldilocksConfig},
    },
};
use psy_client_common::data::{
    base_types::hash256::Hash256,
    qhashout::QHashOut,
};
use psy_client_data::{
    config::store_config::PsyHasher,
    qdata::{checkpoint::PsyCheckpointLeaf, contract::PsyContractLeaf},
};
use psy_config::{
    DA_FEE, FeeConfig, GUTA_FEE, GLOBAL_USER_TREE_HEIGHT, GROUP_REALM_HEIGHT,
    NetworkConfigGoldilocks, PSY_NETWORK_MAGIC, REALM_USER_TREE_HEIGHT, USERS_PER_REALM,
};
use psy_crypto::{
    hash::{core::sha256::CoreSha256Hasher, traits::qhashable::QFieldHashable},
};
use psy_ups_circuit::signature::multisig::MultisigSignatureCircuit;
use psy_vm::ups::multisig::MultisigAccount;
use serde::{Deserialize, Serialize};

type F = GoldilocksField;

const GUARDIANS: usize = 3;
const USER_524288: u64 = 524288;
const MULTISIG_POLICY_CONTRACT_ID: u32 = 6;
const DEPOSIT_CONTRACT_ID: u32 = 2;
const WITHDRAWAL_CONTRACT_ID: u32 = 3;
const FEE_CONTRACT_ID: u32 = 0;
const AUTHORIZATION_VERSION: u32 = 1;
/// psy_dev_cli does not call the provider. The raw loopback envelope mirrors
/// `RequestParams` serde `tag="method", content="params"`
/// (`client_prover/psy_provider/src/request.rs:64-68`) and the rename at
/// request.rs:238.
const RPC_CHECKPOINT_LEAF_METHOD: &str = "psy_get_checkpoint_leaf_data";

fn main() {
    if let Err(error) = provision() {
        eprintln!("guardian runtime provisioning failed: {error:#}");
        std::process::exit(1);
    }
}

struct Args {
    guardians_root: PathBuf,
    config_network: String,
    l2_rpc: String,
    genesis_hash: Option<[u8; 32]>,
    chains_path: PathBuf,
    approved_path: PathBuf,
    next_members_path: PathBuf,
    max_fee: u64,
    guardian_ports: [u16; GUARDIANS],
    history_port: u16,
    validity_days: u64,
    services_url: String,
    withdraw_method_id: u64,
    proof_dir: String,
}

fn parse_args() -> Result<Args> {
    let mut guardians_root = None;
    let mut config_network = "localhost".to_string();
    let mut l2_rpc = "http://127.0.0.1:1337".to_string();
    let mut genesis_hash = None;
    let mut chains_path = None;
    let mut approved_path = None;
    let mut next_members_path = None;
    let mut max_fee = None;
    let mut guardian_ports = [15441u16, 15442, 15443];
    let mut history_port = 15450u16;
    let mut validity_days = 30u64;
    let mut services_url = "http://127.0.0.1:3000".to_string();
    let mut withdraw_method_id = 3_055_054_724u64;
    let mut proof_dir = "provision/proofs".to_string();
    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| -> Result<String> {
            args.next()
                .ok_or_else(|| anyhow!("{name} requires a value"))?
                .into_string()
                .map_err(|_| anyhow!("{name} must be valid UTF-8"))
        };
        match arg.to_string_lossy().as_ref() {
            "--guardians-root" => guardians_root = Some(PathBuf::from(value("--guardians-root")?)),
            "--config-network" => config_network = value("--config-network")?,
            "--l2-rpc" => l2_rpc = value("--l2-rpc")?,
            "--chains" => chains_path = Some(PathBuf::from(value("--chains")?)),
            "--approved-contracts" => approved_path = Some(PathBuf::from(value("--approved-contracts")?)),
            "--next-members" => next_members_path = Some(PathBuf::from(value("--next-members")?)),
            "--max-fee" => max_fee = Some(value("--max-fee")?.parse().context("parsing --max-fee")?),
            "--guardian-ports" => {
                let raw = value("--guardian-ports")?;
                let ports: Vec<u16> = raw.split(',').map(|port| port.parse().context("parsing guardian port")).collect::<Result<_>>()?;
                anyhow::ensure!(ports.len() == GUARDIANS, "exactly {GUARDIANS} guardian ports required");
                guardian_ports = ports.try_into().unwrap();
            }
            "--history-port" => history_port = value("--history-port")?.parse().context("parsing --history-port")?,
            "--validity-days" => validity_days = value("--validity-days")?.parse().context("parsing --validity-days")?,
            "--services-url" => services_url = value("--services-url")?,
            "--withdraw-method-id" => {
                withdraw_method_id = value("--withdraw-method-id")?.parse().context("parsing --withdraw-method-id")?
            }
            "--proof-dir" => proof_dir = value("--proof-dir")?,
            "--genesis-hash" => {
                let raw = value("--genesis-hash")?;
                genesis_hash = Some(parse_hex32(&raw).context("--genesis-hash must be 0x-prefixed 64 hex chars")?);
            }
            other => bail!("unknown argument {other}"),
        }
    }
    anyhow::ensure!(validity_days > 0, "--validity-days must be positive");
    anyhow::ensure!(
        guardian_ports.iter().all(|port| *port != 0) && history_port != 0,
        "listener ports must be nonzero"
    );
    let mut ports = guardian_ports.to_vec();
    ports.push(history_port);
    ports.sort_unstable();
    anyhow::ensure!(ports.windows(2).all(|window| window[0] != window[1]), "listener ports must be unique");
    anyhow::ensure!(
        !proof_dir.is_empty() && Path::new(&proof_dir).components().all(|part| matches!(part, Component::Normal(_))),
        "--proof-dir must be a nonempty fixture-relative path without . or .."
    );
    let missing = |name: &str| anyhow!("{name} is required");
    Ok(Args {
        guardians_root: guardians_root.ok_or_else(|| missing("--guardians-root"))?,
        config_network,
        l2_rpc,
        genesis_hash,
        chains_path: chains_path.ok_or_else(|| missing("--chains"))?,
        approved_path: approved_path.ok_or_else(|| missing("--approved-contracts"))?,
        next_members_path: next_members_path.ok_or_else(|| missing("--next-members"))?,
        max_fee: max_fee.ok_or_else(|| missing("--max-fee"))?,
        guardian_ports,
        history_port,
        validity_days,
        services_url,
        withdraw_method_id,
        proof_dir,
    })
}

fn provision() -> Result<()> {
    let args = parse_args()?;
    let uid = current_uid()?;
    check_protected_ancestors(&args.guardians_root, uid)?;
    let provision = args.guardians_root.join("provision");

    let account_bytes = read_nofollow(&args.guardians_root.join("public/multisig-account.json"))?;
    let account: MultisigAccount = serde_json::from_slice(&account_bytes).context("parsing public/multisig-account.json")?;
    account.initial_policy.validate().context("retained multisig policy invalid")?;
    anyhow::ensure!(
        account.contract_id == MULTISIG_POLICY_CONTRACT_ID && account.initial_policy.version == 1,
        "retained multisig account must be the contract 6 version-1 two-of-three policy"
    );
    let account_json = trimmed_json(&account_bytes)?;
    let param = account.public_key_param().context("retained account policy invalid")?;
    let members = load_members(&args.guardians_root, &account, param)?;
    let next_members = load_next_members(&args.next_members_path, &account)?;
    let chains = load_chains(&args.chains_path)?;
    let approved_inputs: Vec<ApprovedContractInput> = load_json(&args.approved_path).context("parsing --approved-contracts")?;
    for input in &approved_inputs {
        reject_output_collision(&args.guardians_root, &input.artifact_path)?;
        reject_output_collision(&args.guardians_root, &input.contract_leaf_path)?;
    }
    preflight_outputs(&args)?;
    preflight_proof_dir(&args.guardians_root, &args.proof_dir, uid)?;

    let circuit = MultisigSignatureCircuit::new().context("constructing MultisigSignatureCircuit")?;
    let fingerprint = QHashOut::<F>(circuit.get_fingerprint().0);
    let account_public_key = QHashOut(PoseidonHash::two_to_one(fingerprint.0, param.0));
    let genesis_hash = match args.genesis_hash {
        Some(hash) => hash,
        None => derive_genesis_hash(&args.l2_rpc)?,
    };
    anyhow::ensure!(genesis_hash != [0; 32], "genesis hash must be nonzero");
    let approved_contracts = build_approved_contracts(approved_inputs, &chains)?;
    let network = build_network_config(&args)?;
    let max_endcap_proof_bytes = approved_endcap_max_proof_bytes()?;

    let provision = args.guardians_root.join("provision");
    create_exclusive_dir(&provision)?;
    for directory in ["authorization", "authorization/versions", "tls", "signing", "journal", "archive", "archive/relayer-journal"] {
        create_exclusive_dir(&provision.join(directory))?;
    }
    create_relative_dir(&args.guardians_root, &args.proof_dir, uid)?;

    let tls = provision.join("tls");
    generate_tls(&tls, args.validity_days)?;
    let pins = client_cert_pins(&tls)?;

    let authorization = AuthorizationDoc {
        version: AUTHORIZATION_VERSION,
        network_magic: PSY_NETWORK_MAGIC,
        genesis_hash: hex32(&genesis_hash),
        user_id: USER_524288,
        account_json,
        account_public_key,
        multisig_fingerprint: fingerprint,
        deposit_contract_id: DEPOSIT_CONTRACT_ID,
        withdrawal_contract_id: WITHDRAWAL_CONTRACT_ID,
        fee_contract_id: FEE_CONTRACT_ID,
        guta_fee: GUTA_FEE,
        da_fee: DA_FEE,
        max_fee: args.max_fee,
        max_endcap_proof_bytes,
        approved_contracts,
        chains,
    };
    let authorization_path = provision.join("authorization/versions/1.json");
    let authorization_bytes = write_json_new(&authorization_path, &authorization)?;
    let index = AuthorizationIndex {
        active_version: AUTHORIZATION_VERSION,
        versions: vec![AuthorizationVersion {
            version: AUTHORIZATION_VERSION,
            sha256: hex32(&sha256(&authorization_bytes)),
        }],
    };
    write_json_new(&provision.join("authorization/index.json"), &index)?;
    write_json_new(&provision.join("network.rpc.json"), &network)?;
    write_json_new(&provision.join("relayer.network.json"), &NetworkConfigWrapper {
        networks: std::collections::BTreeMap::from([(args.config_network.clone(), network.clone())]),
        default_network: args.config_network.clone(),
    })?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expires_at = now.checked_add(args.validity_days.checked_mul(24 * 60 * 60).context("validity overflow")?)
        .context("signing authorization expiry overflow")?;
    let l2_rpc_url = network.coordinator_configs[0].rpc_url[0].clone();
    let endpoint_pins = l2_endpoint_pins(&network)?;
    for (slot, member) in members.iter().enumerate() {
        let db_path = format!("provision/journal/guardian-{}.redb", slot + 1);
        let signing = SigningAuthorization {
            network_magic: PSY_NETWORK_MAGIC,
            user_id: USER_524288,
            public_key: member.compressed_public_key.clone(),
            db_path: db_path.clone(),
            not_before_unix: now,
            expires_at_unix: expires_at,
            exclusive_key_use: true,
            complete_journal: true,
            revoked: false,
        };
        write_json_new(
            &provision.join(format!("signing/guardian-{}.signing-authorization.json", slot + 1)),
            &signing,
        )?;

        let mut history_urls = Vec::new();
        for peer in 0..GUARDIANS {
            if peer != slot {
                history_urls.push(origin(args.guardian_ports[peer]));
            }
        }
        history_urls.push(origin(args.history_port));
        let mut allowed = vec![pins.relayer_client.clone()];
        allowed.extend(pins.guardians.iter().cloned());
        let runtime = RuntimeConfig {
            authorization_path: "provision/authorization/versions/1.json".to_string(),
            authorization_archive_path: "provision/authorization/versions".to_string(),
            authorization_index_path: "provision/authorization/index.json".to_string(),
            rpc_config_path: "provision/network.rpc.json".to_string(),
            listen_address: format!("127.0.0.1:{}", args.guardian_ports[slot]),
            tls_certificate_path: format!("provision/tls/guardian-{}-server-cert.pem", slot + 1),
            tls_private_key_path: format!("provision/tls/guardian-{}-server-key.pem", slot + 1),
            client_ca_path: "provision/tls/ca.pem".to_string(),
            allowed_client_certificate_sha256: allowed,
            db_path,
            signing_key_secret_path: format!("secrets/guardian-{}.keystore.json", member.provision_index),
            signing_key_password_secret_path: format!("secrets/guardian-{}.password", member.provision_index),
            signing_authorization_path: format!(
                "provision/signing/guardian-{}.signing-authorization.json",
                slot + 1
            ),
            l2_rpc_url: l2_rpc_url.clone(),
            l2_rpc_endpoint_pins: endpoint_pins.clone(),
            l1_rpc_urls: authorization.chains.iter().map(|chain| ChainEndpointRef {
                chain_index: chain.chain_index,
                rpc_url: chain.rpc_url.clone(),
            }).collect(),
            history_urls,
        };
        write_json_new(&args.guardians_root.join(format!("guardian-{}.runtime.json", slot + 1)), &runtime)?;
    }

    write_acceptance_configs(&args, &pins, &next_members, &authorization.chains)?;
    write_json_new(&tls.join("client-cert-sha256.json"), &ClientCertPins {
        relayer_client: pins.relayer_client.clone(),
        guardians: pins.guardians.clone(),
    })?;

    println!("provisioned guardian runtime inputs under {}", provision.display());
    println!("relayer_client_pin={} guardian_pins={}", pins.relayer_client, pins.guardians.join(","));
    println!(
        "genesis_hash={} fingerprint={} account_public_key={}",
        hex32(&genesis_hash),
        qhash_text(&fingerprint),
        qhash_text(&account_public_key)
    );
    println!(
        "max_endcap_proof_bytes={max_endcap_proof_bytes} network_magic={PSY_NETWORK_MAGIC:#x} guta_fee={GUTA_FEE} da_fee={DA_FEE}"
    );
    Ok(())
}

/// `guardian_acceptance` manifest and the client/daemon files it names.
/// Schema: `psy_cli/psy_relayer_cli/tests/guardian_acceptance.rs:15-38` and
/// `docs/src/dev/bridge-design.md` §27 Real-network guardian acceptance.
/// `BridgeProposeDaemonConfig` on this tree has no aggregate-setup fields
/// (`daemon.rs:89-115`); those retired keys are not emitted.
fn write_acceptance_configs(args: &Args, pins: &TlsPins, next_members: &[QHashOut<F>; 3], chains: &[ChainAuthorization]) -> Result<()> {
    let root = &args.guardians_root;
    let client = GuardianClientConfig {
        authorization_path: "provision/authorization/versions/1.json".to_string(),
        archive_path: "provision/archive/relayer-journal".to_string(),
        endpoints: [
            origin(args.guardian_ports[0]),
            origin(args.guardian_ports[1]),
            origin(args.guardian_ports[2]),
        ],
        tls_identity_path: "provision/tls/relayer-client-identity.pem".to_string(),
        server_ca_path: "provision/tls/ca.pem".to_string(),
        authorization_archive_path: "provision/authorization/versions".to_string(),
        authorization_index_path: "provision/authorization/index.json".to_string(),
        l1_endpoints: chains.iter().map(|chain| ChainEndpointRef {
            chain_index: chain.chain_index,
            rpc_url: chain.rpc_url.clone(),
        }).collect(),
        listen_address: format!("127.0.0.1:{}", args.history_port),
        history_tls_certificate_path: "provision/tls/relayer-history-cert.pem".to_string(),
        history_tls_private_key_path: "provision/tls/relayer-history-key.pem".to_string(),
        history_client_ca_path: "provision/tls/ca.pem".to_string(),
        allowed_client_certificate_sha256: pins.guardians.clone(),
    };
    write_json_new(&root.join("relayer.guardian-client.json"), &client)?;
    write_json_new(&root.join("next-members.json"), next_members)?;

    let daemon = DaemonConfig {
        rpc_config: "provision/relayer.network.json".to_string(),
        services_url: args.services_url.clone(),
        withdraw_method_id: args.withdraw_method_id,
        proof_dir: args.proof_dir.clone(),
        guardian_config: "relayer.guardian-client.json".to_string(),
        chains: chains.iter().map(|chain| DaemonChain {
            family: "evm".to_string(),
            chain_index: chain.chain_index,
            network_id: chain.chain_id.clone(),
            rpc_urls: vec![chain.rpc_url.clone()],
            deployments_network: chain.deployments_network.clone(),
        }).collect(),
    };
    let daemon_text = toml::to_string_pretty(&daemon).context("serializing relayer daemon config")?;
    write_new(&root.join("relayer.daemon.toml"), daemon_text.as_bytes(), 0o600)?;

    let manifest = AcceptanceManifest {
        disposable: true,
        network_magic: PSY_NETWORK_MAGIC,
        relayer_rpc_config: "provision/relayer.network.json".to_string(),
        relayer_guardian_config: "relayer.guardian-client.json".to_string(),
        relayer_daemon_config: "relayer.daemon.toml".to_string(),
        relayer_archive: "provision/archive/relayer-journal".to_string(),
        next_members: "next-members.json".to_string(),
        guardians: (1..=GUARDIANS).map(|index| format!("guardian-{index}.runtime.json")).collect(),
        db_files: (1..=GUARDIANS).map(|index| format!("provision/journal/guardian-{index}.redb")).collect(),
        guardian_listen_addresses: args.guardian_ports.iter().map(|port| format!("127.0.0.1:{port}")).collect(),
        relayer_history_listen_address: format!("127.0.0.1:{}", args.history_port),
    };
    write_json_new(&root.join("manifest.json"), &manifest)?;
    Ok(())
}

/// Mirror of `provision_guardians.rs` MemberRow.
#[derive(Clone, Serialize, Deserialize)]
struct MemberRow {
    public_key_param: QHashOut<F>,
    provision_index: usize,
    sorted_slot: usize,
    compressed_public_key: String,
    member_commitment: QHashOut<F>,
}

/// Mirror of protocol.rs:150-157. Nested JSON is retained text.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedContract {
    contract_id: u32,
    contract_leaf_json: String,
    compiler_artifact_json: String,
    compiler_artifact_sha256: String,
}

/// Mirror of protocol.rs:178-186. Field order is the consumer declaration order.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationDoc {
    version: u32,
    network_magic: u64,
    genesis_hash: String,
    user_id: u64,
    account_json: String,
    account_public_key: QHashOut<F>,
    multisig_fingerprint: QHashOut<F>,
    deposit_contract_id: u32,
    withdrawal_contract_id: u32,
    fee_contract_id: u32,
    guta_fee: u64,
    da_fee: u64,
    max_fee: u64,
    max_endcap_proof_bytes: u32,
    approved_contracts: Vec<ApprovedContract>,
    chains: Vec<ChainAuthorization>,
}

/// Mirror of protocol.rs:187-199. Addresses stay strings because `Hex<N>` and
/// alloy `U256` both serialize as canonical text.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainAuthorization {
    chain_index: u8,
    chain_id: String,
    genesis_hash: String,
    bridge: String,
    state_manager: String,
    bridge_code_hash: String,
    bridge_implementation: String,
    bridge_implementation_code_hash: String,
    state_manager_code_hash: String,
    state_manager_implementation: String,
    state_manager_implementation_code_hash: String,
    deployment_block: u64,
    token_mappings: Vec<TokenMapping>,
    #[serde(skip)]
    rpc_url: String,
    #[serde(skip)]
    deployments_network: String,
}

/// Mirror of protocol.rs:197-199.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenMapping {
    token: String,
    l2_contract_id: u32,
}

/// Mirror of protocol.rs:230-235.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationIndex {
    active_version: u32,
    versions: Vec<AuthorizationVersion>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationVersion {
    version: u32,
    sha256: String,
}

/// Mirror of protocol.rs:201-211 (`GuardianRuntimeConfig`).
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeConfig {
    authorization_path: String,
    authorization_archive_path: String,
    authorization_index_path: String,
    rpc_config_path: String,
    listen_address: String,
    tls_certificate_path: String,
    tls_private_key_path: String,
    client_ca_path: String,
    allowed_client_certificate_sha256: Vec<String>,
    db_path: String,
    signing_key_secret_path: String,
    signing_key_password_secret_path: String,
    signing_authorization_path: String,
    l2_rpc_url: String,
    l2_rpc_endpoint_pins: Vec<EndpointPin>,
    l1_rpc_urls: Vec<ChainEndpointRef>,
    history_urls: Vec<String>,
}

/// Mirror of protocol.rs:218-222. Role names are the default serde variants.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointPin {
    role: String,
    config_id: u64,
    rpc_url: String,
    tls_certificate_sha256: Option<String>,
}

/// Mirror of protocol.rs:212-214 (`ChainEndpoint`).
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainEndpointRef {
    chain_index: u8,
    rpc_url: String,
}

/// Mirror of protocol.rs:223-229 (`SigningAuthorization`).
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningAuthorization {
    network_magic: u64,
    user_id: u64,
    public_key: String,
    db_path: String,
    not_before_unix: u64,
    expires_at_unix: u64,
    exclusive_key_use: bool,
    complete_journal: bool,
    revoked: bool,
}

/// Mirror of `guardian_client.rs:14-31`. `config_dir` is skipped by serde.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardianClientConfig {
    authorization_path: String,
    archive_path: String,
    endpoints: [String; 3],
    tls_identity_path: String,
    server_ca_path: String,
    authorization_archive_path: String,
    authorization_index_path: String,
    l1_endpoints: Vec<ChainEndpointRef>,
    listen_address: String,
    history_tls_certificate_path: String,
    history_tls_private_key_path: String,
    history_client_ca_path: String,
    allowed_client_certificate_sha256: Vec<String>,
}

/// Mirror of `daemon.rs:89-140` required fields. No L1 keystore is written.
#[derive(Clone, Serialize)]
struct DaemonConfig {
    rpc_config: String,
    services_url: String,
    withdraw_method_id: u64,
    proof_dir: String,
    guardian_config: String,
    chains: Vec<DaemonChain>,
}

#[derive(Clone, Serialize)]
struct DaemonChain {
    family: String,
    chain_index: u8,
    network_id: String,
    rpc_urls: Vec<String>,
    deployments_network: String,
}

/// Mirror of `guardian_acceptance.rs:15-23`.
#[derive(Clone, Serialize)]
struct AcceptanceManifest {
    disposable: bool,
    network_magic: u64,
    relayer_rpc_config: String,
    relayer_guardian_config: String,
    relayer_daemon_config: String,
    relayer_archive: String,
    next_members: String,
    guardians: Vec<String>,
    db_files: Vec<String>,
    guardian_listen_addresses: Vec<String>,
    relayer_history_listen_address: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientCertPins {
    relayer_client: String,
    guardians: Vec<String>,
}
#[derive(Serialize)]
struct NetworkConfigWrapper {
    networks: std::collections::BTreeMap<String, NetworkConfigGoldilocks>,
    #[serde(rename = "defaultNetwork")]
    default_network: String,
}

fn validate_endpoint(value: &str) -> Result<()> {
    let url = url::Url::parse(value).context("parsing operator endpoint")?;
    anyhow::ensure!((url.scheme() == "http" || url.scheme() == "https") && url.host().is_some() && url.username().is_empty() && url.password().is_none() && url.fragment().is_none(), "operator endpoint must be a credential-free http(s) URL");
    Ok(())
}

fn load_chains(path: &Path) -> Result<Vec<ChainAuthorization>> {
    let inputs: Vec<ChainInput> = load_json(path).context("parsing --chains")?;
    anyhow::ensure!(!inputs.is_empty() && inputs.len() <= 256, "authorization requires 1..=256 chains");
    let mut chains = Vec::new();
    let mut indexes = std::collections::BTreeSet::new();
    let mut identities = std::collections::BTreeSet::new();
    let mut networks = std::collections::BTreeSet::new();
    for window in inputs.windows(2) {
        anyhow::ensure!(window[0].chain_index < window[1].chain_index, "chains must be sorted with unique chain_index");
    }
    for input in inputs {
        anyhow::ensure!(indexes.insert(input.chain_index), "duplicate chain index");
        let chain_id = canonical_chain_id(&input.chain_id)?;
        anyhow::ensure!(identities.insert(chain_id.clone()), "chain identities must be unique");
        anyhow::ensure!(networks.insert((input.chain_index, input.deployments_network.clone())), "duplicate deployment mapping");
        validate_endpoint(&input.rpc_url)?;
        for hash in [
            &input.genesis_hash, &input.bridge_code_hash, &input.bridge_implementation_code_hash,
            &input.state_manager_code_hash, &input.state_manager_implementation_code_hash,
        ] {
            anyhow::ensure!(parse_hex32(hash)? != [0; 32], "chain hash must be nonzero lowercase 0x hex");
        }
        for address in [&input.bridge, &input.state_manager, &input.bridge_implementation, &input.state_manager_implementation] {
            anyhow::ensure!(parse_fixed_hex(address, 20)?.iter().any(|byte| *byte != 0), "chain address must be nonzero lowercase 0x hex");
        }
        anyhow::ensure!(!input.token_mappings.is_empty() && input.token_mappings.len() <= 65536, "chain requires 1..=65536 token mappings");
        for window in input.token_mappings.windows(2) {
            anyhow::ensure!(window[0].token < window[1].token, "token mappings must be sorted and unique");
        }
        for mapping in &input.token_mappings {
            parse_fixed_hex(&mapping.token, 20).context("token mapping address malformed")?;
        }
        anyhow::ensure!(!input.deployments_network.is_empty() && input.deployments_network.chars().all(|char| char.is_ascii_alphanumeric()),
            "deployments_network must name one deployment export");
        chains.push(ChainAuthorization {
            chain_index: input.chain_index, chain_id, genesis_hash: input.genesis_hash, bridge: input.bridge,
            state_manager: input.state_manager, bridge_code_hash: input.bridge_code_hash,
            bridge_implementation: input.bridge_implementation, bridge_implementation_code_hash: input.bridge_implementation_code_hash,
            state_manager_code_hash: input.state_manager_code_hash, state_manager_implementation: input.state_manager_implementation,
            state_manager_implementation_code_hash: input.state_manager_implementation_code_hash,
            deployment_block: input.deployment_block, token_mappings: input.token_mappings,
            rpc_url: input.rpc_url, deployments_network: input.deployments_network,
        });
    }
    Ok(chains)
}

fn canonical_chain_id(value: &str) -> Result<String> {
    let digits = value.strip_prefix("0x").context("chain_id must be canonical 0x hex")?;
    anyhow::ensure!(!digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "chain_id must be lowercase hex");
    let parsed = alloy_primitives::U256::from_str_radix(digits, 16).context("parsing chain_id")?;
    anyhow::ensure!(parsed != alloy_primitives::U256::ZERO, "chain_id must be nonzero");
    Ok(format!("{parsed:#x}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainInput {
    chain_index: u8,
    chain_id: String,
    genesis_hash: String,
    bridge: String,
    state_manager: String,
    bridge_code_hash: String,
    bridge_implementation: String,
    bridge_implementation_code_hash: String,
    state_manager_code_hash: String,
    state_manager_implementation: String,
    state_manager_implementation_code_hash: String,
    deployment_block: u64,
    token_mappings: Vec<TokenMapping>,
    rpc_url: String,
    deployments_network: String,
}

fn build_approved_contracts(inputs: Vec<ApprovedContractInput>, chains: &[ChainAuthorization]) -> Result<Vec<ApprovedContract>> {
    let mut contracts = Vec::new();
    for window in inputs.windows(2) {
        anyhow::ensure!(window[0].contract_id < window[1].contract_id, "approved contracts must be sorted unique by id");
    }
    let mut mapped = std::collections::BTreeSet::new();
    for chain in chains {
        for mapping in &chain.token_mappings {
            mapped.insert(mapping.l2_contract_id);
        }
    }
    for input in inputs {
        let artifact_bytes = read_nofollow(&input.artifact_path)?;
        let artifact_json = trimmed_json(&artifact_bytes)?;
        let artifact: CompilerArtifactMirror = serde_json::from_str(&artifact_json)
            .with_context(|| format!("parsing {}", input.artifact_path.display()))?;
        let abi_version = artifact.abi.get("schema_version").and_then(serde_json::Value::as_str);
        let abi_height = artifact.abi.get("contract").and_then(|contract| contract.get("state_tree_height")).and_then(serde_json::Value::as_u64);
        anyhow::ensure!(
            abi_version == Some("2.0.0") && abi_height == Some(u64::from(artifact.state_tree_height)),
            "compiler artifact {} must be ABI 2.0.0 with a matching state tree height",
            input.contract_id
        );
        let digest = sha256(artifact_json.as_bytes());
        if !input.compiler_artifact_sha256.is_empty() && parse_hex32(&input.compiler_artifact_sha256)?.as_slice() != digest {
            bail!("--approved-contracts compiler_artifact_sha256 mismatch for contract {}", input.contract_id);
        }
        let leaf_bytes = read_nofollow(&input.contract_leaf_path)?;
        let leaf_json = trimmed_json(&leaf_bytes)?;
        let _: PsyContractLeaf<F> = serde_json::from_str(&leaf_json)
            .with_context(|| format!("parsing contract {} leaf", input.contract_id))?;
        contracts.push(ApprovedContract {
            contract_id: input.contract_id,
            contract_leaf_json: leaf_json,
            compiler_artifact_json: artifact_json,
            compiler_artifact_sha256: hex32(&digest),
        });
    }
    let ids: std::collections::BTreeSet<u32> = contracts.iter().map(|contract| contract.contract_id).collect();
    for required in [FEE_CONTRACT_ID, DEPOSIT_CONTRACT_ID, WITHDRAWAL_CONTRACT_ID, MULTISIG_POLICY_CONTRACT_ID] {
        anyhow::ensure!(ids.contains(&required), "approved contracts must cover id {required}");
    }
    for contract_id in mapped {
        anyhow::ensure!(ids.contains(&contract_id), "token mapping contract {contract_id} is not approved");
    }
    Ok(contracts)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedContractInput {
    contract_id: u32,
    contract_leaf_path: PathBuf,
    artifact_path: PathBuf,
    #[serde(default)]
    compiler_artifact_sha256: String,
}

/// Minimum mirror of protocol.rs:158-164. The consumer enforces the rest.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompilerArtifactMirror {
    state_tree_height: u16,
    circuit_definitions: serde_json::Value,
    abi: serde_json::Value,
}

fn load_members(root: &Path, account: &MultisigAccount, public_key_param: QHashOut<F>) -> Result<Vec<MemberRow>> {
    let bytes = read_nofollow(&root.join("public/members.json"))?;
    let members: Vec<MemberRow> = serde_json::from_slice(&bytes).context("parsing public/members.json")?;
    anyhow::ensure!(members.len() == GUARDIANS, "exactly three retained members required");
    let mut members = members;
    members.sort_by_key(|member| member.sorted_slot);
    let mut indexes = std::collections::BTreeSet::new();
    let mut keys = std::collections::BTreeSet::new();
    for (slot, member) in members.iter().enumerate() {
        anyhow::ensure!(member.sorted_slot == slot, "member sorted_slot must be dense 0..2");
        anyhow::ensure!((1..=GUARDIANS).contains(&member.provision_index) && indexes.insert(member.provision_index), "provision_index must be a permutation of 1..3");
        anyhow::ensure!(member.public_key_param == public_key_param, "member public_key_param disagrees with retained account");
        anyhow::ensure!(member.member_commitment == account.initial_policy.member_hashes[slot], "member commitment disagrees with retained account order");
        let key = parse_compressed_key(&member.compressed_public_key)?;
        anyhow::ensure!(matches!(key[0], 2 | 3) && keys.insert(key), "member compressed keys must be unique and prefixed 2 or 3");
        let commitment = psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key::<F, plonky2::hash::poseidon::PoseidonPermutation<F>>(psy_client_common::data::secp256k1::CompressedPublicKey(key));
        anyhow::ensure!(commitment == member.member_commitment, "compressed key does not hash to its member commitment");
        anyhow::ensure!(fs::symlink_metadata(root.join(format!("secrets/guardian-{}.keystore.json", member.provision_index))).is_ok(), "provisioned keystore missing");
        anyhow::ensure!(fs::symlink_metadata(root.join(format!("secrets/guardian-{}.password", member.provision_index))).is_ok(), "provisioned password missing");
    }
    Ok(members)
}

fn load_next_members(path: &Path, account: &MultisigAccount) -> Result<[QHashOut<F>; 3]> {
    reject_output_name(path)?;
    let bytes = read_nofollow(path)?;
    let members: [QHashOut<F>; 3] = serde_json::from_slice(&bytes).context("parsing --next-members")?;
    let mut policy = account.initial_policy.clone();
    policy.member_hashes[..3].copy_from_slice(&members);
    policy.validate().context("next members must form a real nonzero strictly ordered unique policy")?;
    anyhow::ensure!(members.iter().any(|member| !account.initial_policy.member_hashes[..3].contains(member)), "next members must change at least one initial member");
    Ok(members)
}

fn build_network_config(args: &Args) -> Result<NetworkConfigGoldilocks> {
    let config_path = repo_root()?.join("psy-genesis/config.json");
    let config: serde_json::Value = load_json(&config_path).context("reading psy-genesis/config.json")?;
    let network = config.pointer(&format!("/networks/{}", args.config_network))
        .cloned()
        .ok_or_else(|| anyhow!("network {} missing from psy-genesis/config.json", args.config_network))?;
    let object = network.as_object().context("network entry must be an object")?.clone();
    let magic = object.get("magic").and_then(serde_json::Value::as_str).context("network magic missing")?;
    let compiled = parse_magic(magic)?;
    anyhow::ensure!(compiled == PSY_NETWORK_MAGIC, "psy-genesis magic {magic} does not match compiled PSY_NETWORK_MAGIC {PSY_NETWORK_MAGIC:#x}");
    let fees: FeeConfig = serde_json::from_value(object.get("fees").cloned().context("fees missing")?).context("parsing fees")?;
    anyhow::ensure!(fees.guta_fee == GUTA_FEE && fees.da_fee == DA_FEE, "psy-genesis fees disagree with compiled GUTA_FEE/DA_FEE");
    anyhow::ensure!(
        object.get("users_per_realm").and_then(serde_json::Value::as_u64) == Some(USERS_PER_REALM)
            && object.get("global_user_tree_height").and_then(serde_json::Value::as_u64) == Some(u64::from(GLOBAL_USER_TREE_HEIGHT))
            && object.get("realm_user_tree_height").and_then(serde_json::Value::as_u64) == Some(u64::from(REALM_USER_TREE_HEIGHT))
            && object.get("group_realm_height").and_then(serde_json::Value::as_u64) == Some(u64::from(GROUP_REALM_HEIGHT)),
        "psy-genesis dimensions disagree with compiled constants"
    );
    let mut guardian = object;
    guardian.insert("prove_proxy_url".to_string(), serde_json::Value::Array(vec![]));
    guardian.remove("genesis");
    guardian.remove("system_prove_proxy_url");
    serde_json::from_value(serde_json::Value::Object(guardian)).context("building NetworkConfigGoldilocks")
}

fn l2_endpoint_pins(network: &NetworkConfigGoldilocks) -> Result<Vec<EndpointPin>> {
    let mut pins = Vec::new();
    let mut push = |role: &str, config_id: u64, urls: &[String]| -> Result<()> {
        anyhow::ensure!(!urls.is_empty(), "{role} {config_id} has no RPC URL");
        for url in urls {
            pins.push(EndpointPin {
                role: role.to_string(),
                config_id,
                rpc_url: url.clone(),
                tls_certificate_sha256: loopback_pin(url)?,
            });
        }
        Ok(())
    };
    for config in &network.coordinator_configs {
        push("Coordinator", config.id, &config.rpc_url)?;
    }
    for config in &network.realm_configs {
        push("Realm", config.id, &config.rpc_url)?;
    }

    Ok(pins)
}

fn loopback_pin(url: &str) -> Result<Option<String>> {
    let parsed = url::Url::parse(url).context("parsing L2 endpoint URL")?;
    match parsed.scheme() {
        "https" => bail!("https L2 endpoint {url} needs its real DER pin in the source network config; this example does not invent one"),
        "http" => {
            anyhow::ensure!(parsed.host_str() == Some("127.0.0.1"), "http L2 endpoints must target numeric 127.0.0.1");
            Ok(None)
        }
        other => bail!("unsupported L2 endpoint scheme {other}"),
    }
}


fn derive_genesis_hash(l2_rpc: &str) -> Result<[u8; 32]> {
    let parsed = url::Url::parse(l2_rpc).context("parsing --l2-rpc")?;
    anyhow::ensure!(parsed.scheme() == "http" && parsed.host_str() == Some("127.0.0.1"), "genesis derivation expects the loopback http coordinator");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": RPC_CHECKPOINT_LEAF_METHOD,
        "params": { "checkpoint_id": 0 },
    });
    let raw = raw_loopback_post(&parsed, &serde_json::to_vec(&body)?)?;
    let response: serde_json::Value = serde_json::from_slice(&raw).context("parsing genesis RPC response")?;
    anyhow::ensure!(response.get("error").is_none(), "genesis RPC error: {}", response.get("error").map(serde_json::Value::to_string).unwrap_or_default());
    let leaf: PsyCheckpointLeaf<F> = serde_json::from_value(response.get("result").cloned().context("genesis RPC result missing")?)
        .context("decoding checkpoint 0 leaf")?;
    Ok(Hash256::from(leaf.qfhash::<PsyHasher>()).0)
}

fn raw_loopback_post(url: &url::Url, body: &[u8]) -> Result<Vec<u8>> {
    let port = url.port().context("RPC port missing")?;
    let mut stream = TcpStream::connect(("127.0.0.1", port)).with_context(|| format!("connecting to {url}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        url.path(),
        body.len(),
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let split = response.windows(4).position(|window| window == b"\r\n\r\n").context("malformed HTTP response")?;
    Ok(response[split + 4..].to_vec())
}

/// Frozen copy of `approved_endcap_proof_bound`
/// (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:427-476`). The function is
/// `pub(crate)` in a binary crate, so this example cannot call it.
fn approved_endcap_max_proof_bytes() -> Result<u32> {
    let common = psy_plonky2_basic_helpers::lookalike::standard::get_end_cap_type_e_common_data::<PoseidonGoldilocksConfig, 2>();
    u32::try_from(approved_endcap_proof_bound(&common)?).context("EndCap proof bound exceeds u32")
}

fn approved_endcap_proof_bound(common: &CommonCircuitData<F, 2>) -> Result<usize> {
    let c = &common.config;
    let f = &common.fri_params;
    anyhow::ensure!(
        c.fri_config.cap_height == f.config.cap_height
            && c.fri_config.rate_bits == f.config.rate_bits
            && c.fri_config.num_query_rounds == f.config.num_query_rounds,
        "inconsistent EndCap FRI configuration"
    );
    let bytes = (|| -> Option<usize> {
        let power = |bits: usize| 1usize.checked_shl(u32::try_from(bits).ok()?);
        let challenges = c.num_challenges;
        let preprocessed = common.num_constants.checked_add(c.num_routed_wires)?;
        let lookups = challenges.checked_mul(common.num_lookup_polys)?;
        let partial = challenges.checked_mul(common.num_partial_products)?;
        let quotient = challenges.checked_mul(common.quotient_degree_factor)?;
        let openings = preprocessed.checked_add(c.num_wires)?.checked_add(challenges.checked_mul(2)?)?
            .checked_add(lookups.checked_mul(2)?)?.checked_add(partial)?.checked_add(quotient)?;
        let salt = plonky2::plonk::plonk_common::salt_size(f.hiding);
        let leaves = preprocessed.checked_add(c.num_wires)?.checked_add(challenges)?.checked_add(partial)?
            .checked_add(lookups)?.checked_add(quotient)?.checked_add(salt.checked_mul(3)?)?;
        let mut depth = f.degree_bits.checked_add(f.config.rate_bits)?.checked_sub(f.config.cap_height)?;
        let mut query_bytes = leaves.checked_mul(8)?.checked_add(depth.checked_mul(32)?.checked_add(16)?.checked_mul(4)?)?.checked_add(16)?;
        let mut final_bits = f.degree_bits;
        for &arity_bits in &f.reduction_arity_bits {
            depth = depth.checked_sub(arity_bits)?;
            final_bits = final_bits.checked_sub(arity_bits)?;
            query_bytes = query_bytes.checked_add(power(arity_bits)?.checked_mul(16)?)?.checked_add(16)?.checked_add(depth.checked_mul(32)?)?;
        }
        let cap_bytes = power(f.config.cap_height)?.checked_mul(32)?.checked_add(8)?;
        let caps = f.reduction_arity_bits.len().checked_add(3)?.checked_mul(cap_bytes)?;
        caps.checked_add(openings.checked_mul(16)?)?.checked_add(9 * 8)?
            .checked_add(query_bytes.checked_mul(f.config.num_query_rounds)?)?
            .checked_add(power(final_bits)?.checked_mul(16)?)?.checked_add(40)?
            .checked_add(common.num_public_inputs.checked_mul(8)?)
    })().ok_or_else(|| anyhow!("invalid or overflowing EndCap proof shape"))?;
    Ok(bytes)
}

struct TlsPins {
    relayer_client: String,
    guardians: Vec<String>,
}

fn generate_tls(tls: &Path, validity_days: u64) -> Result<()> {
    let days = validity_days.to_string();
    openssl(tls, &[
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", "ca.key.pem", "-out", "ca.pem", "-days", &days, "-sha256",
        "-subj", "/CN=psy-localhost-guardian-ca",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    ])?;
    chmod(&tls.join("ca.key.pem"), 0o600)?;
    chmod(&tls.join("ca.pem"), 0o600)?;

    let mut leaf = |name: &str, san: Option<&str>, eku: &str| -> Result<()> {
        let csr = format!("tmp-{name}.csr");
        let key = format!("{name}-key.pem");
        let cert = format!("{name}-cert.pem");
        openssl(tls, &[
            "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-keyout", &key, "-out", &csr, "-sha256", "-subj", &format!("/CN={name}"),
        ])?;
        let ext_path = tls.join(format!("tmp-{name}.ext"));
        let mut ext = String::from("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n");
        ext.push_str(&format!("extendedKeyUsage={eku}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"));
        if let Some(san) = san {
            ext.push_str(&format!("subjectAltName={san}\n"));
        }
        write_new(&ext_path, ext.as_bytes(), 0o600)?;
        openssl(tls, &[
            "x509", "-req", "-in", &csr, "-CA", "ca.pem", "-CAkey", "ca.key.pem",
            "-CAcreateserial", "-CAserial", "ca.srl", "-out", &cert, "-days", &days, "-sha256",
            "-extfile", ext_path.file_name().and_then(OsStr::to_str).context("extension filename")?,
        ])?;
        fs::remove_file(tls.join(&csr))?;
        fs::remove_file(ext_path)?;
        chmod(&tls.join(&key), 0o600)?;
        chmod(&tls.join(&cert), 0o600)?;
        Ok(())
    };

    for index in 1..=GUARDIANS {
        leaf(&format!("guardian-{index}-server"), Some("IP:127.0.0.1,DNS:localhost"), "serverAuth,clientAuth")?;
        let cert = fs::read(tls.join(format!("guardian-{index}-server-cert.pem")))?;
        let key = fs::read(tls.join(format!("guardian-{index}-server-key.pem")))?;
        let mut bundle = cert;
        bundle.extend_from_slice(&key);
        write_new(&tls.join(format!("guardian-{index}-identity.pem")), &bundle, 0o600)?;
    }
    leaf("relayer-client", None, "clientAuth")?;
    let relayer_cert = fs::read(tls.join("relayer-client-cert.pem"))?;
    let relayer_key = fs::read(tls.join("relayer-client-key.pem"))?;
    let mut bundle = relayer_cert;
    bundle.extend_from_slice(&relayer_key);
    write_new(&tls.join("relayer-client-identity.pem"), &bundle, 0o600)?;
    leaf("relayer-history", Some("IP:127.0.0.1,DNS:localhost"), "serverAuth")?;
    Ok(())
}

fn openssl(directory: &Path, argv: &[&str]) -> Result<()> {
    let status = Command::new("openssl").args(argv).current_dir(directory).uid(current_uid()?).status()
        .with_context(|| format!("running openssl {argv:?}"))?;
    anyhow::ensure!(status.success(), "openssl {argv:?} failed");
    Ok(())
}

fn openssl_output(directory: &Path, argv: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("openssl").args(argv).current_dir(directory).uid(current_uid()?).output()
        .with_context(|| format!("running openssl {argv:?}"))?;
    anyhow::ensure!(output.status.success(), "openssl {argv:?} failed");
    Ok(output.stdout)
}

fn client_cert_pins(tls: &Path) -> Result<TlsPins> {
    let mut guardians = Vec::new();
    for index in 1..=GUARDIANS {
        let der = openssl_output(tls, &["x509", "-in", &format!("guardian-{index}-server-cert.pem"), "-outform", "DER"])?;
        guardians.push(hex32(&sha256(&der)));
    }
    let relayer = openssl_output(tls, &["x509", "-in", "relayer-client-cert.pem", "-outform", "DER"])?;
    Ok(TlsPins { relayer_client: hex32(&sha256(&relayer)), guardians })
}

fn check_protected_ancestors(root: &Path, uid: u32) -> Result<()> {
    anyhow::ensure!(
        root.is_absolute()
            && !root.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir))
            && root.components().any(|part| part == Component::Normal(OsStr::new("localhost-guardians"))),
        "guardians root must be the absolute localhost-guardians directory"
    );
    let mut ancestor = PathBuf::new();
    for part in root.components() {
        ancestor.push(part);
        if matches!(part, Component::RootDir) {
            continue;
        }
        let metadata = fs::symlink_metadata(&ancestor).context("reading protected ancestor")?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink() && metadata.is_dir() && [0, uid].contains(&metadata.uid()) && metadata.mode() & 0o022 == 0,
            "protected ancestor {} owner or mode is unsuitable", ancestor.display()
        );
    }
    Ok(())
}

fn current_uid() -> Result<u32> {
    let status = fs::read_to_string("/proc/self/status").context("reading process status")?;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            return value.split_whitespace().next().context("uid missing")?.parse().context("parsing uid");
        }
    }
    bail!("uid missing")
}

fn create_exclusive_dir(directory: &Path) -> Result<()> {
    DirBuilder::new().recursive(false).mode(0o700).create(directory).with_context(|| format!("creating {}", directory.display()))?;
    let metadata = fs::symlink_metadata(directory).context("reading created directory")?;
    anyhow::ensure!(!metadata.file_type().is_symlink() && metadata.is_dir() && metadata.mode() & 0o777 == 0o700, "created directory {} lost mode 0700", directory.display());
    Ok(())
}
fn preflight_proof_dir(root: &Path, relative: &str, uid: u32) -> Result<()> {
    let mut current = File::open(root).with_context(|| format!("opening {}", root.display()))?;
    for part in Path::new(relative).components() {
        let Component::Normal(name) = part else { bail!("proof directory component rejected"); };
        let c_name = CString::new(name.as_bytes()).context("proof directory contains NUL")?;
        let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_RDONLY | libc::O_DIRECTORY;
        let fd = unsafe { libc::openat(current.as_raw_fd(), c_name.as_ptr(), flags, 0) };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            anyhow::ensure!(error.raw_os_error() == Some(libc::ENOENT), "proof directory component unavailable: {error}");
            break;
        }
        let opened = unsafe { File::from_raw_fd(fd) };
        let metadata = opened.metadata().context("reading proof directory component")?;
        anyhow::ensure!(metadata.is_dir() && [0, uid].contains(&metadata.uid()) && metadata.mode() & 0o022 == 0, "existing proof directory component is not a protected real directory");
        current = opened;
    }
    Ok(())
}

fn create_relative_dir(root: &Path, relative: &str, _uid: u32) -> Result<()> {
    let mut current = File::open(root).with_context(|| format!("opening {}", root.display()))?;
    for part in Path::new(relative).components() {
        let Component::Normal(name) = part else { bail!("proof directory component rejected"); };
        let c_name = CString::new(name.as_bytes()).context("proof directory contains NUL")?;
        let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_RDONLY | libc::O_DIRECTORY;
        let fd = unsafe { libc::openat(current.as_raw_fd(), c_name.as_ptr(), flags, 0) };
        if fd >= 0 {
            current = unsafe { File::from_raw_fd(fd) };
        } else {
            anyhow::ensure!(unsafe { libc::mkdirat(current.as_raw_fd(), c_name.as_ptr(), 0o700) } == 0, "creating proof directory component failed");
            let fd = unsafe { libc::openat(current.as_raw_fd(), c_name.as_ptr(), flags, 0) };
            anyhow::ensure!(fd >= 0, "opening created proof directory component failed");
            current = unsafe { File::from_raw_fd(fd) };
        }
    }
    Ok(())
}

fn preflight_outputs(args: &Args) -> Result<()> {
    let root = &args.guardians_root;
    let mut outputs = vec![
        root.join("provision"), root.join("manifest.json"), root.join("relayer.guardian-client.json"),
        root.join("relayer.daemon.toml"), root.join("next-members.json"),
    ];
    for index in 1..=GUARDIANS { outputs.push(root.join(format!("guardian-{index}.runtime.json"))); }
    for output in outputs {
        anyhow::ensure!(fs::symlink_metadata(&output).is_err(), "output {} already exists; refusing before mutation", output.display());
    }
    reject_output_collision(root, &args.chains_path)?;
    reject_output_collision(root, &args.approved_path)?;
    reject_output_collision(root, &args.next_members_path)?;
    Ok(())
}

fn reject_output_name(path: &Path) -> Result<()> {
    anyhow::ensure!(path.file_name() != Some(OsStr::new("next-members.json")), "--next-members must not name the generated output");
    Ok(())
}

fn reject_output_collision(root: &Path, input: &Path) -> Result<()> {
    let input = std::fs::canonicalize(input).unwrap_or_else(|_| input.to_path_buf());
    anyhow::ensure!(!input.starts_with(root.join("provision")) && input != root.join("next-members.json"), "input {} collides with generated output", input.display());
    Ok(())
}

fn read_nofollow(path: &Path) -> Result<Vec<u8>> {
    anyhow::ensure!(path.is_absolute() && !path.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir)), "input {} must be absolute without . or ..", path.display());
    if path.components().any(|part| matches!(part.as_os_str().to_string_lossy().as_ref(), ".aws" | ".config" | ".ssh" | "secrets")) {
        bail!("refusing credential or secret input {}", path.display());
    }
    let mut current = File::open("/").context("opening filesystem root")?;
    let parts = path.components().filter(|part| !matches!(part, Component::RootDir)).collect::<Vec<_>>();
    for (index, part) in parts.iter().enumerate() {
        let Component::Normal(name) = part else { bail!("input path component rejected"); };
        let final_file = index + 1 == parts.len();
        let name = CString::new(name.as_bytes()).context("input path contains NUL")?;
        let flags = libc::O_CLOEXEC | libc::O_NOFOLLOW | if final_file { libc::O_RDONLY } else { libc::O_RDONLY | libc::O_DIRECTORY };
        let fd = unsafe { libc::openat(current.as_raw_fd(), name.as_ptr(), flags, 0) };
        anyhow::ensure!(fd >= 0, "nofollow open failed for {}", path.display());
        let opened = unsafe { File::from_raw_fd(fd) };
        let metadata = opened.metadata().context("reading nofollow descriptor")?;
        if final_file { anyhow::ensure!(metadata.is_file(), "{} must be a regular file", path.display()); }
        else { anyhow::ensure!(metadata.is_dir(), "input ancestor must be a real directory"); }
        current = opened;
    }
    let mut bytes = Vec::new();
    (&current).read_to_end(&mut bytes).with_context(|| format!("reading {}", path.display()))?;
    Ok(bytes)
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read_nofollow(path)?).with_context(|| format!("parsing {}", path.display()))
}

fn trimmed_json(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes).context("JSON input must be UTF-8")?;
    Ok(text.trim().to_string())
}

fn chmod(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).with_context(|| format!("chmod {mode:o} {}", path.display()))
}
fn write_new(path: &Path, body: &[u8], mode: u32) -> Result<()> {
    anyhow::ensure!(fs::symlink_metadata(path).is_err(), "output {} already exists", path.display());
    let mut file = OpenOptions::new().write(true).create_new(true).mode(mode).open(path)
        .with_context(|| format!("reserving {}", path.display()))?;
    file.write_all(body).with_context(|| format!("writing {}", path.display()))?;
    file.sync_all().with_context(|| format!("syncing {}", path.display()))?;
    let metadata = file.metadata().with_context(|| format!("reading {}", path.display()))?;
    anyhow::ensure!(metadata.is_file() && metadata.mode() & 0o777 == mode, "reserved {} lost mode {mode:o}", path.display());
    Ok(())
}

fn write_json_new<T: Serialize>(path: &Path, value: &T) -> Result<Vec<u8>> {
    let mut body = serde_json::to_vec(value).context("serializing provisioning output")?;
    body.push(b'\n');
    write_new(path, &body, 0o600)?;
    Ok(body)
}

fn origin(port: u16) -> String {
    format!("https://127.0.0.1:{port}/")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    CoreSha256Hasher::hash_bytes(bytes).0
}

/// `Hex<N>` wire form: `0x` plus lowercase hex (`protocol.rs:27-45`).
fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn qhash_text(hash: &QHashOut<F>) -> String {
    serde_json::to_string(hash).unwrap_or_else(|_| "unprintable".to_string())
}

fn parse_magic(magic: &str) -> Result<u64> {
    if let Some(hex_text) = magic.strip_prefix("0x").or_else(|| magic.strip_prefix("0X")) {
        return u64::from_str_radix(hex_text, 16).context("parsing magic hex");
    }
    magic.parse::<u64>().context("parsing magic decimal")
}

fn repo_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest.parent().and_then(Path::parent).context("resolving repository root from psy_dev_cli")?.to_path_buf())
}

fn parse_compressed_key(value: &str) -> Result<[u8; 33]> {
    let bytes = parse_fixed_hex(value, 33).context("member compressed public key must be 0x plus 66 lowercase hex chars")?;
    let mut key = [0u8; 33];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn parse_hex32(value: &str) -> Result<[u8; 32]> {
    let bytes = parse_fixed_hex(value, 32)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_fixed_hex(value: &str, width: usize) -> Result<Vec<u8>> {
    let raw = value.strip_prefix("0x").context("expected 0x-prefixed lowercase hex")?;
    anyhow::ensure!(raw.len() == width * 2 && raw.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "expected {width} lowercase hex bytes");
    hex::decode(raw).context("decoding hex")
}
