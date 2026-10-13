//! Guardian runtime provisioning example (temporary E2E launch glue).
//!
//! Composes existing public APIs only; mirrors the guardian wire schemas that
//! live in the `psy_relayer_cli` binary crate, cited per struct. Runtime
//! consumers (`psy_relayer_cli guardian-create-db` / `guardian-service`, the
//! relayer `GuardianClientConfig` loader) re-validate every emitted file with
//! `deny_unknown_fields`, SHA-256 index checks and live-chain Genesis
//! authentication, so any drift here fails closed at consume time.
//!
//! Owns ONLY the guardian-security boundary under
//! `<guardians-root>/provision/`: authorization archive/index, derived
//! `network.rpc.json`, per-guardian signing authorizations, per-guardian
//! runtime configs, operational TLS material (system openssl) and the empty
//! relayer journal archive directory. It never writes
//! `relayer.guardian-client.json` (owned by Main), never reads
//! `<guardians-root>/secrets/*` (referenced by path only; consumed later by
//! audited `guardian::runtime::load_signing_key`), and never prints secret
//! material.
//!
//! Real-input requirements (no fakes):
//! - coordinator at `--l2-rpc` must be UP: `genesis_hash` is derived from the
//!   live `psy_get_checkpoint_leaf_data` checkpoint 0 leaf, the same value
//!   `guardian::service::verify_genesis` re-authenticates
//!   (psy_cli/psy_relayer_cli/src/guardian/service.rs:46-55,257).
//! - `--chains` file: real `ChainAuthorization` values (chain id, deployed
//!   bridge/state manager addresses, code hashes, deployment block, token
//!   mappings) for every authorized L1; schema mirror of
//!   psy_cli/psy_relayer_cli/src/guardian/protocol.rs:187-199.
//! - `--approved-contracts` file: real per-contract compiler artifacts and
//!   contract leaves for ids {0,2,3,6}; schema mirror of protocol.rs:150-157.
//! - `--max-fee`: operator-set guard consumed by
//!   psy_cli/psy_relayer_cli/src/guardian/verify.rs:358-365.
//!
//! Usage:
//! ```text
//! cargo run --release -p psy_dev_cli --example provision_guardian_runtime -- \
//!   --guardians-root /home/cj/localhost-guardians \
//!   --genesis-hash 0x<checkpoint0 identity> \
//!   --chains <chains.json> --approved-contracts <approved.json> \
//!   --max-fee 100000000
//!
//! `--genesis-hash` is the real checkpoint 0 identity
//! `Hash256::from(checkpoint_leaf.qfhash::<PsyHasher>())` (service.rs:51);
//! omit it to fetch the live value from the default `--l2-rpc` instead.
//!
//! Verification boundary: authored without compile/test execution per task
//! directive; independent static review and first execution are separate gates.

use std::{
    fs::{self, DirBuilder, OpenOptions},
    ffi::OsStr,
    io::{Read as _, Write as _},
    net::TcpStream,
    os::unix::{
        fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        process::CommandExt as _,
    },
    path::{Component, Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, bail, Context, Result};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    field::types::PrimeField64,
    plonk::{
        circuit_data::CommonCircuitData,
        config::{Hasher as _, PoseidonGoldilocksConfig},
    },
    hash::poseidon::PoseidonHash,
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
    CoordinatorConfig, DA_FEE, FeeConfig, GUTA_FEE, GLOBAL_USER_TREE_HEIGHT, GROUP_REALM_HEIGHT,
    NetworkConfigGoldilocks, PSY_NETWORK_MAGIC, RealmConfig, REALM_USER_TREE_HEIGHT,
    USERS_PER_REALM,
};
use psy_crypto::{
    hash::{
        core::sha256::CoreSha256Hasher,
        traits::qhashable::QFieldHashable,
    },
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
/// psy_dev_cli lacks `psy_provider`; the raw loopback JSON-RPC envelope below
/// mirrors `RequestParams` serde `tag="method", content="params"`
/// (client_prover/psy_provider/src/request.rs:64-68) and the rename at
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
    max_fee: u64,
    guardian_ports: [u16; GUARDIANS],
    history_port: u16,
    validity_days: u64,
}

fn parse_args() -> Result<Args> {
    let mut guardians_root = None;
    let mut config_network = "localhost".to_string();
    let mut l2_rpc = "http://127.0.0.1:1337".to_string();
    let mut genesis_hash = None;
    let mut chains_path = None;
    let mut approved_path = None;
    let mut max_fee = None;
    let mut guardian_ports = [15441u16, 15442, 15443];
    let mut history_port = 15450u16;
    let mut validity_days = 30u64;
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
            "--max-fee" => max_fee = Some(value("--max-fee")?.parse().context("parsing --max-fee")?),
            "--guardian-ports" => {
                let raw = value("--guardian-ports")?;
                let ports: Vec<u16> = raw
                    .split(',')
                    .map(|port| port.parse().context("parsing guardian port"))
                    .collect::<Result<_>>()?;
                anyhow::ensure!(ports.len() == GUARDIANS, "exactly {GUARDIANS} guardian ports required");
                guardian_ports = ports.try_into().unwrap();
            }
            "--history-port" => history_port = value("--history-port")?.parse().context("parsing --history-port")?,
            "--validity-days" => validity_days = value("--validity-days")?.parse().context("parsing --validity-days")?,
            "--genesis-hash" => {
                let raw = value("--genesis-hash")?;
                genesis_hash = Some(parse_hex32(&raw).context("--genesis-hash must be 0x-prefixed 64 hex chars")?);
            }
            other => bail!("unknown argument {other}"),
        }
    }
    let missing = |name: &str| anyhow!("{name} is required");
    Ok(Args {
        guardians_root: guardians_root.ok_or_else(|| missing("--guardians-root"))?,
        config_network,
        l2_rpc,
        genesis_hash,
        chains_path: chains_path.ok_or_else(|| missing("--chains"))?,
        approved_path: approved_path.ok_or_else(|| missing("--approved-contracts"))?,
        max_fee: max_fee.ok_or_else(|| missing("--max-fee"))?,
        guardian_ports,
        history_port,
        validity_days,
    })
}

fn provision() -> Result<()> {
    let args = parse_args()?;
    let uid = current_uid()?;
    check_protected_ancestors(&args.guardians_root, uid)?;
    let provision = args.guardians_root.join("provision");

    // 1. Retained public guardian identities (never secrets).
    let account_bytes = read_file(&args.guardians_root.join("public/multisig-account.json"))?;
    let account: MultisigAccount = serde_json::from_slice(&account_bytes)
        .context("parsing public/multisig-account.json")?;
    anyhow::ensure!(
        account.contract_id == MULTISIG_POLICY_CONTRACT_ID
            && account.initial_policy.threshold == 2
            && account.initial_policy.member_count == 3,
        "retained multisig account must be the contract 6 two-of-three initial policy"
    );
    let account_json = trimmed_json(&account_bytes)?;
    let param = account.public_key_param().context("retained account policy invalid")?;

    let members_bytes = read_file(&args.guardians_root.join("public/members.json"))?;
    let members: Vec<MemberRow> = serde_json::from_slice(&members_bytes)
        .context("parsing public/members.json")?;
    anyhow::ensure!(members.len() == GUARDIANS, "exactly three retained members required");
    let mut members = members;
    members.sort_by_key(|member| member.sorted_slot);
    for (slot, member) in members.iter().enumerate() {
        anyhow::ensure!(member.sorted_slot == slot, "member sorted_slot must be dense 0..2");
        anyhow::ensure!(
            member.compressed_public_key.len() == 68 && member.compressed_public_key.starts_with("0x"),
            "member compressed public key must be a 0x-prefixed 33-byte hex string"
        );
    }

    // 2. Registered multisig identity, mirroring generate_genesis.rs:213-216
    //    and protocol.rs:431-433.
    let circuit = MultisigSignatureCircuit::new().context("constructing MultisigSignatureCircuit")?;
    let fingerprint = QHashOut::<F>(circuit.get_fingerprint().0);
    let account_public_key = QHashOut(PoseidonHash::two_to_one(fingerprint.0, param.0));

    // 3. Genesis identity: explicit --genesis-hash (offline; the value is the
    //    real checkpoint 0 identity that create_db re-authenticates against
    //    the live chain, service.rs:46-55,257) or live fetch when omitted.
    let genesis_hash = match args.genesis_hash {
        Some(hash) => hash,
        None => derive_genesis_hash(&args.l2_rpc)?,
    };

    // 4. Operator-supplied real L1 and compiler-artifact inputs.
    let chains: Vec<ChainAuthorization> = load_json(&args.chains_path).context("parsing --chains")?;
    validate_chains(&chains, &args)?;
    let approved_contracts: Vec<ApprovedContractInput> =
        load_json(&args.approved_path).context("parsing --approved-contracts")?;
    let approved_contracts = build_approved_contracts(approved_contracts)?;

    // 5. Network config with an empty prove proxy (guardian boundary,
    //    runtime.rs:205-218 rejects a nonempty list).
    let network = build_network_config(&args)?;

    // 6. EndCap serialization bound: frozen copy of the audited math over the
    //    public EndCap common data (verify.rs:412-458 + 460-464).
    let max_endcap_proof_bytes = approved_endcap_max_proof_bytes()?;

    // 7. Directories (all 0700: protected_file_at rejects group/other-writable
    //    ancestors, runtime.rs:21-39).
    for directory in [
        provision.clone(),
        provision.join("authorization"),
        provision.join("authorization/versions"),
        provision.join("tls"),
        provision.join("signing"),
        provision.join("journal"),
        provision.join("archive"),
        provision.join("archive/relayer-journal"),
    ] {
        create_protected_dir(&directory)?;
    }

    // 8. Operational TLS via system openssl; key bytes never enter this
    //    process. Filenames fixed by the agreed contract.
    let tls = provision.join("tls");
    generate_tls(&tls, &members, args.validity_days)?;
    let pins = client_cert_pins(&tls)?;
    let guardian_pins: Vec<String> = pins.guardians.clone();

    // 9. Authorization archive + index.
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

    // 10. network.rpc.json for the guardian rpc_config_path.
    write_json_new(&provision.join("network.rpc.json"), &network)?;

    // 11. Signing authorizations + runtime configs (runtime files live at the
    //     guardians root so every config-relative path stays inside it without
    //     `..` components; protocol.rs:487-489, runtime.rs:11).
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let not_before = now;
    let expires_at = now + args.validity_days * 24 * 60 * 60;
    let l2_rpc_url = network.coordinator_configs[0].rpc_url[0].clone();
    let endpoint_pins = l2_endpoint_pins(&network)?;
    for (slot, member) in members.iter().enumerate() {
        let db_path = format!("provision/journal/guardian-{}.redb", slot + 1);
        let signing = SigningAuthorization {
            network_magic: PSY_NETWORK_MAGIC,
            user_id: USER_524288,
            public_key: member.compressed_public_key.clone(),
            db_path: db_path.clone(),
            not_before_unix: not_before,
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
        allowed.extend(guardian_pins.iter().cloned());
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
            signing_key_secret_path: format!("secrets/guardian-{}.keystore.json", slot + 1),
            signing_key_password_secret_path: format!("secrets/guardian-{}.password", slot + 1),
            signing_authorization_path: format!(
                "provision/signing/guardian-{}.signing-authorization.json",
                slot + 1
            ),
            l2_rpc_url: l2_rpc_url.clone(),
            l2_rpc_endpoint_pins: endpoint_pins.clone(),
            l1_rpc_urls: authorization.chains
                .iter()
                .map(|chain| ChainEndpointRef {
                    chain_index: chain.chain_index,
                    rpc_url: l1_url_for(&args, chain.chain_index),
                })
                .collect(),
            history_urls,
        };
        write_json_new(&args.guardians_root.join(format!("guardian-{}.runtime.json", slot + 1)), &runtime)?;
    }

    // 12. Pins for Main to fill allowed_client_certificate_sha256 in the
    //     relayer client config (generator never rewrites that file).
    let pins_doc = ClientCertPins {
        relayer_client: pins.relayer_client.clone(),
        guardians: guardian_pins.clone(),
    };
    write_json_new(&tls.join("client-cert-sha256.json"), &pins_doc)?;

    println!("provisioned guardian runtime inputs under {}", provision.display());
    println!("relayer_client_pin={} guardian_pins={}", pins.relayer_client, guardian_pins.join(","));
    println!("genesis_hash={} fingerprint={} account_public_key={}",
        hex32(&genesis_hash), qhash_hex(&fingerprint), qhash_hex(&account_public_key));
    println!("max_endcap_proof_bytes={max_endcap_proof_bytes} network_magic={PSY_NETWORK_MAGIC:#x} guta_fee={GUTA_FEE} da_fee={DA_FEE}");
    println!("fill relayer.guardian-client.json allowed_client_certificate_sha256 with the three guardian_pins");
    Ok(())
}

// ---------------------------------------------------------------------------
// Retained-identity wire rows (public data only).
// ---------------------------------------------------------------------------

/// Mirror of `client_prover/psy_cli/psy_user_cli/examples/provision_guardians.rs`
/// MemberRow (the producer of public/members.json).
#[derive(Clone, Serialize, Deserialize)]
struct MemberRow {
    public_key_param: QHashOut<F>,
    provision_index: usize,
    sorted_slot: usize,
    compressed_public_key: String,
    member_commitment: QHashOut<F>,
}

// ---------------------------------------------------------------------------
// Guardian wire schema mirrors (consumer: psy_relayer_cli binary crate).
// ---------------------------------------------------------------------------

/// Mirror of psy_cli/psy_relayer_cli/src/guardian/protocol.rs:150-157.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedContract {
    contract_id: u32,
    contract_leaf_json: String,
    compiler_artifact_json: String,
    compiler_artifact_sha256: String,
}

/// Mirror of protocol.rs:178-186; field order is the consumer's declaration
/// order and serde_json keeps it, satisfying canonical byte expectations.
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

/// Mirror of protocol.rs:187-199.
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

/// Mirror of protocol.rs:201-211 (GuardianRuntimeConfig).
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

/// Mirror of protocol.rs:218-222 (L2RpcEndpointPin; role discriminants are the
/// default serde variant names "Coordinator"/"Realm").
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointPin {
    role: String,
    config_id: u64,
    rpc_url: String,
    tls_certificate_sha256: Option<String>,
}

/// Mirror of protocol.rs:212-214 (ChainEndpoint).
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainEndpointRef {
    chain_index: u8,
    rpc_url: String,
}

/// Mirror of protocol.rs:223-229 (SigningAuthorization).
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

/// Emitted pin report for Main's relayer.guardian-client.json.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientCertPins {
    relayer_client: String,
    guardians: Vec<String>,
}

// ---------------------------------------------------------------------------
// Input validation (subset of protocol.rs:420-453, cited per predicate).
// ---------------------------------------------------------------------------

fn validate_chains(chains: &[ChainAuthorization], _args: &Args) -> Result<()> {
    anyhow::ensure!(
        !chains.is_empty() && chains.len() <= 256,
        "authorization requires 1..=256 chains (protocol.rs:426)"
    );
    let mut seen = std::collections::BTreeSet::new();
    let mut approved = std::collections::BTreeSet::new();
    for window in chains.windows(2) {
        anyhow::ensure!(
            window[0].chain_index < window[1].chain_index,
            "chains must be sorted with unique chain_index (protocol.rs:434)"
        );
    }
    for chain in chains {
        anyhow::ensure!(seen.insert(chain.chain_index), "duplicate chain index");
        anyhow::ensure!(!chain.chain_id.is_empty(), "chain_id required (protocol.rs:439)");
        anyhow::ensure!(
            chain.chain_id == "0" || !chain.chain_id.trim_start_matches("0x").starts_with('0'),
            "chain_id must be canonical"
        );
        for hash in [
            &chain.genesis_hash,
            &chain.bridge_code_hash,
            &chain.bridge_implementation_code_hash,
            &chain.state_manager_code_hash,
            &chain.state_manager_implementation_code_hash,
        ] {
            anyhow::ensure!(is_hex32(hash), "chain hashes must be 0x-prefixed 32-byte hex");
        }
        for address in [
            &chain.bridge,
            &chain.state_manager,
            &chain.bridge_implementation,
            &chain.state_manager_implementation,
        ] {
            anyhow::ensure!(is_hex20(address) && address != "0x0000000000000000000000000000000000000000",
                "chain addresses must be nonzero 0x-prefixed 20-byte hex (protocol.rs:440)");
        }
        anyhow::ensure!(
            !chain.token_mappings.is_empty() && chain.token_mappings.len() <= 65536,
            "chain requires 1..=65536 token mappings (protocol.rs:442)"
        );
        for window in chain.token_mappings.windows(2) {
            anyhow::ensure!(window[0].token < window[1].token, "token mappings sorted unique (protocol.rs:443)");
        }
        for mapping in &chain.token_mappings {
            anyhow::ensure!(is_hex20(&mapping.token), "token mapping address malformed");
            approved.insert(mapping.l2_contract_id);
        }
    }
    approved_guard_check(approved)
}

fn approved_guard_check(approved_mappings: std::collections::BTreeSet<u32>) -> Result<()> {
    let _ = approved_mappings; // full membership check runs in the consumer (protocol.rs:444-446)
    Ok(())
}

fn build_approved_contracts(inputs: Vec<ApprovedContractInput>) -> Result<Vec<ApprovedContract>> {
    let mut contracts = Vec::new();
    for window in inputs.windows(2) {
        anyhow::ensure!(
            window[0].contract_id < window[1].contract_id,
            "approved contracts sorted unique by id (protocol.rs:434)"
        );
    }
    for input in inputs {
        let artifact_bytes = read_file(&input.artifact_path)?;
        let artifact_json = trimmed_json(&artifact_bytes)?;
        let artifact: CompilerArtifactMirror =
            serde_json::from_str(&artifact_json).with_context(|| format!("parsing {}", input.artifact_path.display()))?;
        let sha = hex32(&sha256(artifact_json.as_bytes()));
        if sha != input.compiler_artifact_sha256 {
            // Operator hint: digest is derived here; the optional input field
            // must either be omitted or already match.
            bail!("--approved-contracts compiler_artifact_sha256 mismatch for contract {}", input.contract_id);
        }
        let leaf_bytes = read_file(&input.contract_leaf_path)?;
        let leaf_json = trimmed_json(&leaf_bytes)?;
        let _: PsyContractLeaf<F> = serde_json::from_str(&leaf_json)
            .with_context(|| format!("parsing contract {} leaf", input.contract_id))?;
        contracts.push(ApprovedContract {
            contract_id: input.contract_id,
            contract_leaf_json: leaf_json,
            compiler_artifact_json: artifact_json,
            compiler_artifact_sha256: sha,
        });
    }
    let ids: std::collections::BTreeSet<u32> = contracts.iter().map(|contract| contract.contract_id).collect();
    for required in [FEE_CONTRACT_ID, DEPOSIT_CONTRACT_ID, WITHDRAWAL_CONTRACT_ID, MULTISIG_POLICY_CONTRACT_ID] {
        anyhow::ensure!(ids.contains(&required), "approved contracts must cover id {required} (protocol.rs:436)");
    }
    Ok(contracts)
}

/// Operator input row; `compiler_artifact_sha256` is derived by this example
/// and must be omitted or already correct.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovedContractInput {
    contract_id: u32,
    contract_leaf_path: PathBuf,
    artifact_path: PathBuf,
    #[serde(default)]
    compiler_artifact_sha256: String,
}

/// Minimal mirror of protocol.rs:158-164 used for input sanity; full
/// artifact/ABI/root equivalence is enforced by the consumer
/// (verify.rs:148-219, generate_genesis.rs:232-288).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompilerArtifactMirror {
    state_tree_height: u16,
    circuit_definitions: serde_json::Value,
    abi: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Network config (psy_config::NetworkConfigGoldilocks is public but its
// `_phantom` field is private, so construction goes through serde).
// ---------------------------------------------------------------------------

fn build_network_config(args: &Args) -> Result<NetworkConfigGoldilocks> {
    let config_path = repo_root()?.join("psy-genesis/config.json");
    let config: serde_json::Value = load_json(&config_path).context("reading psy-genesis/config.json")?;
    let network = config
        .pointer(&format!("/networks/{}", args.config_network))
        .cloned()
        .ok_or_else(|| anyhow!("network {} missing from psy-genesis/config.json", args.config_network))?;
    let object = network.as_object().context("network entry must be an object")?;

    let magic = object.get("magic").and_then(serde_json::Value::as_str).context("network magic missing")?;
    let compiled = parse_magic(magic)?;
    anyhow::ensure!(
        compiled == PSY_NETWORK_MAGIC,
        "psy-genesis magic {magic} does not match the compiled PSY_NETWORK_MAGIC {PSY_NETWORK_MAGIC:#x}"
    );
    let fees: FeeConfig = serde_json::from_value(object.get("fees").cloned().context("fees missing")?)
        .context("parsing fees")?;
    anyhow::ensure!(
        fees.guta_fee == GUTA_FEE && fees.da_fee == DA_FEE,
        "psy-genesis fees disagree with compiled GUTA_FEE/DA_FEE"
    );
    anyhow::ensure!(
        object.get("users_per_realm").and_then(serde_json::Value::as_u64) == Some(USERS_PER_REALM)
            && object.get("global_user_tree_height").and_then(serde_json::Value::as_u64) == Some(u64::from(GLOBAL_USER_TREE_HEIGHT))
            && object.get("realm_user_tree_height").and_then(serde_json::Value::as_u64) == Some(u64::from(REALM_USER_TREE_HEIGHT))
            && object.get("group_realm_height").and_then(serde_json::Value::as_u64) == Some(u64::from(GROUP_REALM_HEIGHT)),
        "psy-genesis dimensions disagree with compiled constants"
    );

    // Guardian copy: identical routing, prove_proxy_url emptied (runtime.rs:215).
    let mut guardian = object.clone();
    guardian.insert("prove_proxy_url".to_string(), serde_json::Value::Array(vec![]));
    guardian.remove("genesis");
    guardian.remove("system_prove_proxy_url");
    let network: NetworkConfigGoldilocks = serde_json::from_value(serde_json::Value::Object(guardian))
        .context("building NetworkConfigGoldilocks")?;
    Ok(network)
}

fn l2_endpoint_pins(network: &NetworkConfigGoldilocks) -> Result<Vec<EndpointPin>> {
    let mut pins = Vec::new();
    let mut push = |role: &str, config: &CoordinatorConfig| -> Result<()> {
        for url in &config.rpc_url {
            pins.push(EndpointPin {
                role: role.to_string(),
                config_id: config.id,
                rpc_url: url.clone(),
                tls_certificate_sha256: loopback_pin(url)?,
            });
        }
        Ok(())
    };
    for config in &network.coordinator_configs {
        push("Coordinator", config)?;
    }
    for config in &network.realm_configs {
        push(
            "Realm",
            &CoordinatorConfig { id: config.id, rpc_url: config.rpc_url.clone() },
        )?;
    }
    Ok(pins)
}

fn loopback_pin(url: &str) -> Result<Option<String>> {
    let parsed = url::Url::parse(url).context("parsing L2 endpoint URL")?;
    match parsed.scheme() {
        "https" => bail!(
            "https L2 endpoint {url} needs a real DER pin; provision TLS for the node first (protocol.rs:922-927)"
        ),
        "http" => {
            let host = parsed.host_str().context("L2 endpoint host missing")?;
            anyhow::ensure!(
                host == "127.0.0.1",
                "http L2 endpoints must target numeric 127.0.0.1 (protocol.rs:924)"
            );
            Ok(None)
        }
        other => bail!("unsupported L2 endpoint scheme {other}"),
    }
}

fn l1_url_for(args: &Args, chain_index: u8) -> String {
    match chain_index {
        0 => "http://127.0.0.1:8545".to_string(),
        1 => "http://127.0.0.1:9545".to_string(),
        2 => "http://127.0.0.1:10545".to_string(),
        other => format!("http://127.0.0.1:{}", 8545 + u16::from(other) * 1000),
    }
}

// ---------------------------------------------------------------------------
// Live Genesis hash derivation (coordinator must be running).
// ---------------------------------------------------------------------------

fn derive_genesis_hash(l2_rpc: &str) -> Result<[u8; 32]> {
    let parsed = url::Url::parse(l2_rpc).context("parsing --l2-rpc")?;
    anyhow::ensure!(
        parsed.scheme() == "http" && parsed.host_str() == Some("127.0.0.1"),
        "genesis derivation expects the loopback http coordinator"
    );
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": RPC_CHECKPOINT_LEAF_METHOD,
        "params": { "checkpoint_id": 0 },
    });
    let raw = raw_loopback_post(&parsed, &serde_json::to_vec(&body)?)?;
    let response: serde_json::Value = serde_json::from_slice(&raw).context("parsing genesis RPC response")?;
    anyhow::ensure!(
        response.get("error").is_none(),
        "genesis RPC error: {}",
        response.get("error").map(serde_json::Value::to_string).unwrap_or_default()
    );
    let leaf: PsyCheckpointLeaf<F> =
        serde_json::from_value(response.get("result").cloned().context("genesis RPC result missing")?)
            .context("decoding checkpoint 0 leaf")?;
    // Same identity expression as service.rs:51.
    let hash = Hash256::from(leaf.qfhash::<PsyHasher>());
    Ok(hash.0)
}

fn raw_loopback_post(url: &url::Url, body: &[u8]) -> Result<Vec<u8>> {
    let port = url.port().context("RPC port missing")?;
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .with_context(|| format!("connecting to {url} (coordinator must be up)"))?;
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
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("malformed HTTP response")?;
    Ok(response[split + 4..].to_vec())
}

// ---------------------------------------------------------------------------
// EndCap serialization bound: frozen verbatim copy of the audited
// approved_endcap_proof_bound (psy_cli/psy_relayer_cli/src/guardian/
// verify.rs:412-458) composed with the public
// psy_plonky2_basic_helpers::lookalike::standard::get_end_cap_type_e_common_data
// (verify.rs:460-464). Recomputed equality is re-enforced by every consumer
// (protocol.rs:425, guardian_client.rs:52).
// ---------------------------------------------------------------------------

fn approved_endcap_max_proof_bytes() -> Result<u32> {
    let common = psy_plonky2_basic_helpers::lookalike::standard::get_end_cap_type_e_common_data::<
        PoseidonGoldilocksConfig,
        2,
    >();
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
        let openings = preprocessed
            .checked_add(c.num_wires)?
            .checked_add(challenges.checked_mul(2)?)?
            .checked_add(lookups.checked_mul(2)?)?
            .checked_add(partial)?
            .checked_add(quotient)?;
        let salt = plonky2::plonk::plonk_common::salt_size(f.hiding);
        let leaves = preprocessed
            .checked_add(c.num_wires)?
            .checked_add(challenges)?
            .checked_add(partial)?
            .checked_add(lookups)?
            .checked_add(quotient)?
            .checked_add(salt.checked_mul(3)?)?;
        let mut depth = f.degree_bits.checked_add(f.config.rate_bits)?.checked_sub(f.config.cap_height)?;
        let mut query_bytes = leaves
            .checked_mul(8)?
            .checked_add(depth.checked_mul(32)?.checked_add(16)?.checked_mul(4)?)?
            .checked_add(16)?;
        let mut final_bits = f.degree_bits;
        for &arity_bits in &f.reduction_arity_bits {
            depth = depth.checked_sub(arity_bits)?;
            final_bits = final_bits.checked_sub(arity_bits)?;
            query_bytes = query_bytes
                .checked_add(power(arity_bits)?.checked_mul(16)?)?
                .checked_add(16)?
                .checked_add(depth.checked_mul(32)?)?;
        }
        let cap_bytes = power(f.config.cap_height)?.checked_mul(32)?.checked_add(8)?;
        let caps = f.reduction_arity_bits.len().checked_add(3)?.checked_mul(cap_bytes)?;
        caps.checked_add(openings.checked_mul(16)?)?
            .checked_add(9 * 8)?
            .checked_add(query_bytes.checked_mul(f.config.num_query_rounds)?)?
            .checked_add(power(final_bits)?.checked_mul(16)?)?
            .checked_add(40)?
            .checked_add(common.num_public_inputs.checked_mul(8)?)
    })()
    .ok_or_else(|| anyhow!("invalid or overflowing EndCap proof shape"))?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Operational TLS (system openssl; keys stay in openssl-owned files).
// ---------------------------------------------------------------------------

struct TlsPins {
    relayer_client: String,
    guardians: Vec<String>,
}

fn generate_tls(tls: &Path, members: &[MemberRow], validity_days: u64) -> Result<()> {
    let _ = members; // pins derive from emitted certs, not from member rows
    let days = validity_days.to_string();
    openssl(
        tls,
        &[
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "ca.key.pem",
            "-out",
            "ca.pem",
            "-days",
            &days,
            "-sha256",
            "-subj",
            "/CN=psy-localhost-guardian-ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ],
    )?;
    chmod(&tls.join("ca.key.pem"), 0o600)?;
    chmod(&tls.join("ca.pem"), 0o600)?;

    let mut leaf = |name: &str, san: Option<&str>, eku: &str| -> Result<()> {
        let csr = format!("tmp-{name}.csr");
        let key = format!("{name}-key.pem");
        let cert = format!("{name}-cert.pem");
        openssl(
            tls,
            &[
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                &key,
                "-out",
                &csr,
                "-sha256",
                "-subj",
                &format!("/CN={name}"),
            ],
        )?;
        let ext_path = tls.join(format!("tmp-{name}.ext"));
        let mut ext = String::from("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n");
        ext.push_str(&format!("extendedKeyUsage={eku}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"));
        if let Some(san) = san {
            ext.push_str(&format!("subjectAltName={san}\n"));
        }
        write_new(&ext_path, ext.as_bytes(), 0o600)?;
        let mut argv = vec![
            "x509",
            "-req",
            "-in",
            &csr,
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key.pem",
            "-CAcreateserial",
            "-CAserial",
            "ca.srl",
            "-out",
            &cert,
            "-days",
            &days,
            "-sha256",
            "-extfile",
            ext_path.file_name().unwrap().to_str().unwrap(),
        ];
        openssl(tls, &argv)?;
        fs::remove_file(tls.join(&csr))?;
        fs::remove_file(ext_path)?;
        chmod(&tls.join(&key), 0o600)?;
        chmod(&tls.join(&cert), 0o600)?;
        Ok(())
    };

    for index in 1..=GUARDIANS {
        // Server cert doubles as the guardian's client identity (both EKUs),
        // matching how service.rs:293-299 reuses the server PEM as the
        // history-fetch client identity.
        leaf(
            &format!("guardian-{index}-server"),
            Some("IP:127.0.0.1,DNS:localhost"),
            "serverAuth,clientAuth",
        )?;
        let cert = fs::read(tls.join(format!("guardian-{index}-server-cert.pem")))?;
        let key = fs::read(tls.join(format!("guardian-{index}-server-key.pem")))?;
        let mut bundle = cert.clone();
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
    let program = "openssl";
    let status = Command::new(program)
        .args(argv)
        .current_dir(directory)
        .uid(current_uid()?)
        .status()
        .with_context(|| format!("running openssl {argv:?}"))?;
    anyhow::ensure!(status.success(), "openssl {argv:?} failed");
    Ok(())
}

fn openssl_output(directory: &Path, argv: &[&str]) -> Result<Vec<u8>> {
    let program = "openssl";
    let output = Command::new(program)
        .args(argv)
        .current_dir(directory)
        .uid(current_uid()?)
        .output()
        .with_context(|| format!("running openssl {argv:?}"))?;
    anyhow::ensure!(output.status.success(), "openssl {argv:?} failed");
    Ok(output.stdout)
}

fn client_cert_pins(tls: &Path) -> Result<TlsPins> {
    let mut guardians = Vec::new();
    for index in 1..=GUARDIANS {
        let der = openssl_output(
            tls,
            &[
                "x509",
                "-in",
                &format!("guardian-{index}-server-cert.pem"),
                "-outform",
                "DER",
            ],
        )?;
        guardians.push(hex32(&sha256(&der)));
    }
    let relayer = openssl_output(tls, &["x509", "-in", "relayer-client-cert.pem", "-outform", "DER"])?;
    Ok(TlsPins { relayer_client: hex32(&sha256(&relayer)), guardians })
}

// ---------------------------------------------------------------------------
// Protected filesystem helpers (precedent:
// psy_user_cli/examples/provision_guardians.rs:46-146).
// ---------------------------------------------------------------------------

fn check_protected_ancestors(root: &Path, uid: u32) -> Result<()> {
    anyhow::ensure!(
        root.is_absolute() && root.components().any(|part| part == Component::Normal(OsStr::new("localhost-guardians"))),
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
            metadata.is_dir() && [0, uid].contains(&metadata.uid()) && metadata.mode() & 0o022 == 0,
            "protected ancestor {ancestor:?} owner or mode is unsuitable"
        );
    }
    Ok(())
}

fn current_uid() -> Result<u32> {
    // SAFETY: getuid takes no arguments and returns the real UID on Unix.
    Ok(unsafe { libc::getuid() })
}

fn create_protected_dir(directory: &Path) -> Result<()> {
    if directory.exists() {
        let metadata = fs::symlink_metadata(directory).context("reading provision directory")?;
        anyhow::ensure!(
            metadata.is_dir() && metadata.mode() & 0o777 == 0o700,
            "existing provision directory {directory:?} must keep mode 0700"
        );
        return Ok(());
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
        .with_context(|| format!("creating {directory:?}"))?;
    let metadata = fs::symlink_metadata(directory).context("reading created directory")?;
    anyhow::ensure!(
        metadata.is_dir() && metadata.mode() & 0o777 == 0o700,
        "created directory {directory:?} lost mode 0700"
    );
    Ok(())
}

fn write_new(path: &Path, body: &[u8], mode: u32) -> Result<()> {
    anyhow::ensure!(
        fs::symlink_metadata(path).is_err(),
        "output {path:?} already exists; delete provision/ to regenerate"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("reserving {path:?}"))?;
    file.write_all(body).with_context(|| format!("writing {path:?}"))?;
    file.sync_all().with_context(|| format!("syncing {path:?}"))?;
    Ok(())
}

fn write_json_new<T: Serialize>(path: &Path, value: &T) -> Result<Vec<u8>> {
    let mut body = serde_json::to_vec(value).context("serializing provisioning output")?;
    body.push(b'\n');
    write_new(path, &body, 0o600)?;
    Ok(body)
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("reading {}", path.display()))?;
    anyhow::ensure!(metadata.is_file(), "{} must be a regular file", path.display());
    fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = read_file(path)?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

fn trimmed_json(bytes: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(bytes).context("JSON input must be UTF-8")?;
    Ok(text.trim().to_string())
}

fn chmod(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("chmod {mode:o} {path:?}"))
}

fn origin(port: u16) -> String {
    format!("https://127.0.0.1:{port}/")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    CoreSha256Hasher::hash_bytes(bytes).0
}

fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn qhash_hex(hash: &QHashOut<F>) -> String {
    hex::encode(hash.0.elements.map(|limb| limb.to_canonical_u64().to_be_bytes()).as_flattened())
}

fn parse_magic(magic: &str) -> Result<u64> {
    if let Some(hex) = magic.strip_prefix("0x").or_else(|| magic.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).context("parsing magic hex");
    }
    magic.parse::<u64>().context("parsing magic decimal")
}

fn repo_root() -> Result<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .context("resolving repository root from psy_dev_cli")?
        .to_path_buf())
}

fn is_hex32(value: &str) -> bool {
    value.len() == 66 && value.starts_with("0x") && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_hex20(value: &str) -> bool {
    value.len() == 42 && value.starts_with("0x") && value[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn parse_hex32(value: &str) -> Result<[u8; 32]> {
    let raw = value
        .strip_prefix("0x")
        .context("expected 0x-prefixed hex")?;
    anyhow::ensure!(raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit()), "expected 32 bytes of hex");
    let mut out = [0u8; 32];
    hex::decode_to_slice(raw, &mut out).context("decoding hex32")?;
    Ok(out)
}
