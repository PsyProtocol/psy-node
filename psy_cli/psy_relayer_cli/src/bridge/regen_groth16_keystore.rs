use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::Context;
use clap::Args;
use parth_core::{
    crypto::hash::{
        merkle_proof::compute_root_merkle_proof_generic,
    },
    pgoldilocks::QHashOut,
    protocol::core_types::QNetworkTreeConstants,
};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::poseidon::PoseidonHash,
    plonk::{config::{Hasher, PoseidonGoldilocksConfig}, proof::ProofWithPublicInputs},
};
use psy_core::network_config::PsyNetworkLocalDevnetConstants;
use psy_plonky2_circuits::{
    bridge::circuits::bridge_wrap::{DepositBatchWrapCircuit, WithdrawalClaimWrapCircuit},
    proof_minifier::pm_chain::QEDProofMinifierChain,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};

use psy_plonky2_common_circuits::bridge::{
    deposit_batch_append_circuit::{BatchAppendInputs, DepositBatchAppendCircuit, DepositLeafData, MAX_DEPOSIT_BATCH_SIZE},
    withdrawal_batch_claim_circuit::{WithdrawalBatchClaimCircuit, WithdrawalBatchClaimInputs, WithdrawalBatchClaimSlotInputs},
};

use crate::bridge::{
    constants::{BRIDGE_USER_ID_U32, WITHDRAWAL_TREE_CONTRACT_ID},
    prove_bridge::cached_bridge_coordinator_circuits,
};

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;

const DEPOSIT_BATCH_TREE_HEIGHT: usize = 32;
const WITHDRAWAL_TREE_HEIGHT: usize = 32;
const CHECKPOINT_TREE_HEIGHT: usize = PsyNetworkLocalDevnetConstants::CHECKPOINT_TREE_HEIGHT_USIZE;
const GLOBAL_USER_TREE_HEIGHT: usize = PsyNetworkLocalDevnetConstants::GLOBAL_USER_TREE_HEIGHT_USIZE;
const GLOBAL_CONTRACT_TREE_HEIGHT: usize = PsyNetworkLocalDevnetConstants::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE;
const DEPOSIT_CONTRACT_STATE_TREE_HEIGHT: usize =
    psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT as usize;
const WITHDRAWAL_CONTRACT_STATE_TREE_HEIGHT: usize =
    psy_config::network_constants::WITHDRAWAL_TREE_CONTRACT_STATE_TREE_HEIGHT as usize;
const GROTH16_FILES: [&str; 3] = ["circuit_groth16.bin", "pk_groth16.bin", "vk_groth16.bin"];

pub(crate) use psy_plonky2_circuits::bridge::aggregate_circuits::{load_aggregate_setup_config, AggregateSetupConfig};

const BRIDGE_OPENING_FILES: [&str; 6] = [
    "circuit_groth16.bin", "identity.json", "manifest.json", "pk_groth16.bin", "verifier.sol", "vk_groth16.bin",
];
const BRIDGE_OPENING_MANIFEST_FILES: [&str; 5] = [
    "circuit_groth16.bin", "identity.json", "pk_groth16.bin", "verifier.sol", "vk_groth16.bin",
];

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeOpeningManifest {
    schema: u32,
    identity_hash: String,
    files: Vec<BridgeOpeningManifestFile>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeOpeningManifestFile {
    name: String,
    sha256: String,
}

fn canonical_identity_bytes(identity: &psy_plonky2_circuits::bridge::circuits::bridge_wrap::BridgeOpeningIdentity) -> anyhow::Result<String> {
    Ok(serde_json::to_string(identity)?)
}

/// Strict product setup check. `expected` must come from the approved reconstructed wrapper.
/// Matching local identity and manifest hashes detect corruption of that trusted set. They do
/// not authenticate a coherently replaced keystore, because the loaded generic CCS validates
/// shape only and `IsSolved` does not bind the requested identity.
pub(crate) fn validate_bridge_opening_setup(
    dir: &Path,
    expected: &psy_plonky2_circuits::bridge::circuits::bridge_wrap::BridgeOpeningIdentity,
) -> anyhow::Result<String> {
    use psy_crypto::hash::core::sha256::CoreSha256Hasher;
    use psy_plonky2_circuits::bridge::circuits::bridge_wrap::BridgeOpeningIdentity;
    for name in BRIDGE_OPENING_FILES {
        let path = dir.join(name);
        let metadata = fs::symlink_metadata(&path).with_context(|| format!("setup artifact {name} is missing"))?;
        anyhow::ensure!(metadata.file_type().is_file(), "setup artifact {name} is not a regular file");
        anyhow::ensure!(metadata.len() > 0, "setup artifact {name} is empty");
    }
    let identity_bytes = fs::read(dir.join("identity.json"))?;
    let loaded: BridgeOpeningIdentity = serde_json::from_slice(&identity_bytes)?;
    let canonical = canonical_identity_bytes(expected)?;
    anyhow::ensure!(std::str::from_utf8(&identity_bytes)? == canonical, "strict setup identity bytes differ from actual wrapper");
    anyhow::ensure!(&loaded == expected, "native setup identity differs from actual wrapper");
    let identity_hash = loaded.identity_hash()?;
    anyhow::ensure!(identity_hash == expected.identity_hash()?, "setup identity hash differs from actual wrapper");
    let manifest_bytes = fs::read(dir.join("manifest.json"))?;
    let manifest: BridgeOpeningManifest = serde_json::from_slice(&manifest_bytes)?;
    anyhow::ensure!(manifest_bytes == serde_json::to_vec(&manifest)?, "setup manifest bytes are not canonical");
    anyhow::ensure!(manifest.schema == 1, "setup manifest schema is not 1");
    anyhow::ensure!(manifest.identity_hash == identity_hash, "setup manifest identity hash differs from computed identity");
    anyhow::ensure!(manifest.files.len() == BRIDGE_OPENING_MANIFEST_FILES.len(), "incomplete setup manifest");
    for (file, name) in manifest.files.iter().zip(BRIDGE_OPENING_MANIFEST_FILES) {
        anyhow::ensure!(file.name == name, "noncanonical setup manifest files");
        let path = dir.join(name);
        let bytes = fs::read(&path)?;
        anyhow::ensure!(!bytes.is_empty() && file.sha256 == hex::encode(CoreSha256Hasher::hash_bytes(&bytes).0), "setup artifact digest mismatch: {name}");
    }
    let verifier = fs::read_to_string(dir.join("verifier.sol"))?;
    let rendered = expected.render_verifier(&verifier)?;
    anyhow::ensure!(rendered == verifier, "installed verifier is not the identity-owned product verifier");
    for name in BRIDGE_OPENING_FILES {
        fs::File::open(dir.join(name))?.sync_all()?;
    }
    fs::File::open(dir)?.sync_all()?;
    Ok(identity_hash)
}

fn read_verified_aggregate_proof(
    path: &Path,
    circuit_data: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
    chain_count: usize,
) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    use psy_plonky2_circuits::bridge::circuits::bridge_aggregate::bridge_aggregate_pi_len;
    let bytes = fs::read(path).context("aggregate proof is missing")?;
    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(bytes.clone(), &circuit_data.common).context("aggregate proof does not decode against the reconstructed top common")?;
    let canonical = proof.to_bytes();
    anyhow::ensure!(canonical == bytes, "aggregate proof bytes are not canonical");
    let width = bridge_aggregate_pi_len(chain_count);
    anyhow::ensure!(circuit_data.common.num_public_inputs == width && proof.public_inputs.len() == width, "aggregate proof width differs from the reconstructed bridge aggregate");
    anyhow::ensure!(
        proof.public_inputs[..4] == [F::from_canonical_u64(4), F::from_canonical_u64(12), F::ZERO, F::ZERO],
        "aggregate proof prefix is not [4,12,0,0]"
    );
    circuit_data.verify(proof.clone()).context("aggregate proof failed reconstructed top verification")?;
    Ok(proof)
}

fn regenerate_aggregate_proofs(config_path: &Path, aggregate_proof_path: &Path, output: &Path) -> anyhow::Result<()> {
    use psy_plonky2_circuits::bridge::aggregate_circuits::{AggregateCircuitHeights, AggregateCircuits};
    use psy_plonky2_circuits::bridge::circuits::bridge_wrap::BridgeOpeningWrapper;
    anyhow::ensure!(matches!(fs::symlink_metadata(output), Err(error) if error.kind() == std::io::ErrorKind::NotFound), "aggregate output must not exist");
    anyhow::ensure!(fs::symlink_metadata(aggregate_proof_path)?.file_type().is_file(), "aggregate proof must be a regular file");
    let approved = load_aggregate_setup_config(config_path)?;
    let policies = approved.withdrawal_policies.clone();
    let config = psy_client_data::bridge_aggregate::NetworkConfig::decode(&hex::decode(&approved.network_config)?)
        .map_err(|error| anyhow::anyhow!("invalid approved aggregate configuration: {error:?}"))?;
    let chain_indices: Vec<_> = config.chains.iter().map(|chain| chain.chain_index).collect();
    let coordinator = cached_bridge_coordinator_circuits()?;
    let (checkpoint_common_data, checkpoint_cap_height, checkpoint_fingerprint) = {
        let checkpoint = &coordinator.checkpoint_root_transition;
        (checkpoint.get_common_circuit_data_ref(), checkpoint.get_verifier_config_ref().constants_sigmas_cap.height(), checkpoint.get_fingerprint())
    };
    let circuits = AggregateCircuits::build::<PsyNetworkLocalDevnetConstants>(&chain_indices, checkpoint_common_data, checkpoint_cap_height, checkpoint_fingerprint, AggregateCircuitHeights {
        deposit_state_tree: DEPOSIT_CONTRACT_STATE_TREE_HEIGHT,
    }, policies.clone(), config.ethereum_index)?;
    circuits.validate_config(&config)?;
    let circuit_set = psy_client_data::bridge_aggregate::encode_circuit_set(circuits.registrations())?;
    let top = &circuits.bridge_aggregate.circuit_data;
    let policy_source = circuits.withdrawal_claim_data();
    let chains: Vec<_> = config.chains.iter().map(|chain| psy_plonky2_circuits::bridge::circuits::bridge_wrap::BridgeOpeningChain {
        chain_index: chain.chain_index, bootstrap_id: chain.bootstrap_id, bootstrap_root: chain.bootstrap_root,
    }).collect();
    let opening = BridgeOpeningWrapper::build(
        &top.common, &top.verifier_only, &policy_source.common, &policy_source.verifier_only,
        approved.sources, config.config_hash().map_err(|error| anyhow::anyhow!("approved configuration hash: {error:?}"))?, &chains, &policies,
    )?;
    anyhow::ensure!(opening.identity().matches_source(&top.common, &top.verifier_only)?, "opening source is not the constructed bridge aggregate verifier");
    let child_common = serde_json::to_string(&policy_source.common)?;
    let child_verifier = serde_json::to_string(&policy_source.verifier_only)?;
    anyhow::ensure!(opening.identity().child_common_json == child_common && opening.identity().child_verifier_json == child_verifier, "opening child is not the constructed withdrawal policy circuit");
    anyhow::ensure!(opening.identity().top_common_json == serde_json::to_string(&top.common)? && opening.identity().top_verifier_json == serde_json::to_string(&top.verifier_only)?, "opening top is not the constructed bridge aggregate");
    let source_proof = read_verified_aggregate_proof(aggregate_proof_path, top, chain_indices.len())?;
    let parent = output.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let name = output.file_name().context("aggregate output must name a directory")?;
    let mut staging_name = name.to_os_string();
    staging_name.push(format!(".staging-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()));
    let staging = parent.join(staging_name);
    fs::create_dir(&staging)?;
    let result = (|| -> anyhow::Result<()> {
        fs::write(staging.join("circuit_set.bin"), &circuit_set)?;
        fs::File::open(staging.join("circuit_set.bin"))?.sync_all()?;
        let opening_dir = staging.join("BridgeOpening");
        fs::create_dir(&opening_dir)?;
        let artifact = opening_dir.to_str().context("aggregate artifact path must be UTF-8")?;
        let _proved = opening.prove_groth16(&source_proof, artifact)?;
        let generic = gnark_plonky2_verifier_ffi::export_solidity_verifier(artifact);
        anyhow::ensure!(!generic.starts_with("error:"), "generic solidity export failed: {generic}");
        let verifier = opening.identity().render_verifier(&generic)?;
        fs::write(opening_dir.join("verifier.sol"), verifier.as_bytes())?;
        fs::File::open(opening_dir.join("verifier.sol"))?.sync_all()?;
        let identity = canonical_identity_bytes(opening.identity())?;
        fs::write(opening_dir.join("identity.json"), identity.as_bytes())?;
        fs::File::open(opening_dir.join("identity.json"))?.sync_all()?;
        write_bridge_opening_manifest(&opening_dir, opening.identity())?;
        validate_bridge_opening_setup(&opening_dir, opening.identity())?;
        fs::File::open(&staging)?.sync_all()?;
        install_aggregate_proofs(&staging, output)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() && staging.exists() {
        if let Err(error) = fs::remove_dir_all(&staging) {
            return Err(result.expect_err("aggregate staging failed")).context(format!("aggregate staging cleanup failed for {}: {error}", staging.display()));
        }
    }
    result
}

fn write_bridge_opening_manifest(
    dir: &Path,
    identity: &psy_plonky2_circuits::bridge::circuits::bridge_wrap::BridgeOpeningIdentity,
) -> anyhow::Result<()> {
    use psy_crypto::hash::core::sha256::CoreSha256Hasher;
    let mut files = Vec::with_capacity(BRIDGE_OPENING_MANIFEST_FILES.len());
    for name in BRIDGE_OPENING_MANIFEST_FILES {
        let bytes = fs::read(dir.join(name))?;
        anyhow::ensure!(!bytes.is_empty(), "setup artifact {name} is empty");
        files.push(BridgeOpeningManifestFile { name: name.to_string(), sha256: hex::encode(CoreSha256Hasher::hash_bytes(&bytes).0) });
    }
    let manifest = BridgeOpeningManifest { schema: 1, identity_hash: identity.identity_hash()?, files };
    let bytes = serde_json::to_vec(&manifest)?;
    anyhow::ensure!(bytes == serde_json::to_vec(&serde_json::from_slice::<BridgeOpeningManifest>(&bytes)?)?, "setup manifest bytes are not canonical");
    fs::write(dir.join("manifest.json"), bytes)?;
    fs::File::open(dir.join("manifest.json"))?.sync_all()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_aggregate_proofs(staging: &Path, output: &Path) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let staging = std::ffi::CString::new(staging.as_os_str().as_bytes())?;
    let output = std::ffi::CString::new(output.as_os_str().as_bytes())?;
    let result = unsafe { libc::renameat2(libc::AT_FDCWD, staging.as_ptr(), libc::AT_FDCWD, output.as_ptr(), libc::RENAME_NOREPLACE) };
    if result != 0 { return Err(std::io::Error::last_os_error().into()); }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_aggregate_proofs(_staging: &Path, _output: &Path) -> anyhow::Result<()> {
    anyhow::bail!("atomic no-replace aggregate keystore install requires Linux renameat2")
}

#[cfg(test)]
mod aggregate_setup_tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        args: RegenerateGroth16KeystoreArgs,
    }

    #[test]
    fn aggregate_proofs_requires_complete_exclusive_arguments() {
        assert!(Command::try_parse_from(["setup", "--aggregate-pair", "--aggregate-config", "config.json", "--aggregate-proof", "bound.proof", "--output-dir", "aggregates"]).is_err());
        assert!(Command::try_parse_from(["setup", "--aggregate-proofs"]).is_err());
        assert!(Command::try_parse_from(["setup", "--aggregate-config", "config.json", "--output-dir", "aggregates"]).is_err());
        assert!(Command::try_parse_from(["setup", "--aggregate-proofs", "--aggregate-config", "config.json", "--output-dir", "aggregates"]).is_err());
        for option in ["--keystore-dir=keys", "--skip-deposit-append", "--skip-withdrawal-claim"] {
            assert!(Command::try_parse_from(["setup", "--aggregate-proofs", "--aggregate-config", "config.json", "--aggregate-proof", "bound.proof", "--output-dir", "aggregates", option]).is_err());
        }
        let command = Command::try_parse_from(["setup", "--aggregate-proofs", "--aggregate-config", "config.json", "--aggregate-proof", "bound.proof", "--output-dir", "aggregates"]).unwrap();
        assert_eq!(command.args.aggregate_config.as_deref(), Some(Path::new("config.json")));
        assert_eq!(command.args.aggregate_proof.as_deref(), Some(Path::new("bound.proof")));
        assert_eq!(command.args.output_dir.as_deref(), Some(Path::new("aggregates")));
        assert!(run(RegenerateGroth16KeystoreArgs {
            keystore_dir: None, skip_deposit_append: false, skip_withdrawal_claim: false, aggregate_proofs: true,
            aggregate_config: Some(PathBuf::from("config.json")), aggregate_proof: None, output_dir: Some(PathBuf::from("aggregates")),
        }).unwrap_err().to_string().contains("aggregate-proof"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn aggregate_install_never_replaces_existing_destination() {
        let root = std::env::temp_dir().join(format!("aggregate-install-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&root).unwrap();
        let staging = root.join("staging");
        let output = root.join("output");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("setup-aggregates.json"), b"candidate").unwrap();
        fs::create_dir(&output).unwrap();
        fs::write(output.join("setup-aggregates.json"), b"retained").unwrap();
        assert!(install_aggregate_proofs(&staging, &output).is_err());
        assert_eq!(fs::read(output.join("setup-aggregates.json")).unwrap(), b"retained");
        assert_eq!(fs::read(staging.join("setup-aggregates.json")).unwrap(), b"candidate");
        let fresh = root.join("fresh");
        install_aggregate_proofs(&staging, &fresh).unwrap();
        assert_eq!(fs::read(fresh.join("setup-aggregates.json")).unwrap(), b"candidate");
        assert!(!staging.exists());
        fs::remove_dir_all(root).unwrap();
    }

    fn fixture_identity() -> psy_plonky2_circuits::bridge::circuits::bridge_wrap::BridgeOpeningIdentity {
        use psy_plonky2_circuits::bridge::circuits::bridge_wrap::{BridgeOpeningChain, BridgeOpeningIdentity};
        BridgeOpeningIdentity {
            schema: 1, mode: "BridgeOpening".into(), version: 4,
            deposit_capacity: 32, withdrawal_capacity: 32, reward_capacity: 32,
            chain_count: 1, raw_pi_width: 8604,
            node_source: "local:11".to_string() + &"11".repeat(31),
            native_source: "local:22".to_string() + &"22".repeat(31),
            plonky2_source: "local:33".to_string() + &"33".repeat(31),
            wrapper_source: "local:44".to_string() + &"44".repeat(31),
            config_hash: "ab".repeat(32),
            chains: vec![BridgeOpeningChain { chain_index: 0, bootstrap_id: 1, bootstrap_root: [1, 2, 3, 4] }],
            token_policies: Vec::new(),
            source_fingerprint: [1, 2, 3, 4], wrapper_fingerprint: [5, 6, 7, 8],
            child_fingerprint: [9, 10, 11, 12], top_fingerprint: [13, 14, 15, 16],
            source_common: "aa".into(), source_verifier: "bb".into(),
            child_common_json: "{}".into(), child_verifier_json: "{}".into(),
            top_common_json: "{}".into(), top_verifier_json: "{}".into(),
            wrapper_common_json: "{}".into(), wrapper_verifier_json: "{}".into(),
        }
    }
    #[test]
    fn strict_setup_rejects_incomplete_symlink_and_noncanonical_identity() {
        use psy_crypto::hash::core::sha256::CoreSha256Hasher;
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("bridge-opening-setup-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&root).unwrap();
        let expected = fixture_identity();
        assert!(validate_bridge_opening_setup(&root, &expected).is_err());
        let verifier = expected.render_verifier("contract Verifier {\n}\n").unwrap();
        for name in BRIDGE_OPENING_FILES {
            let bytes: &[u8] = if name == "identity.json" {
                &[]
            } else if name == "verifier.sol" {
                verifier.as_bytes()
            } else {
                b"x"
            };
            if !bytes.is_empty() { fs::write(root.join(name), bytes).unwrap(); }
        }
        fs::write(root.join("identity.json"), canonical_identity_bytes(&expected).unwrap()).unwrap();
        let files = BRIDGE_OPENING_MANIFEST_FILES.iter().map(|name| {
            let bytes = fs::read(root.join(name)).unwrap();
            BridgeOpeningManifestFile { name: (*name).to_string(), sha256: hex::encode(CoreSha256Hasher::hash_bytes(&bytes).0) }
        }).collect();
        let manifest = BridgeOpeningManifest { schema: 1, identity_hash: expected.identity_hash().unwrap(), files };
        fs::write(root.join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::remove_file(root.join("vk_groth16.bin")).unwrap();
        symlink(root.join("identity.json"), root.join("vk_groth16.bin")).unwrap();
        assert!(validate_bridge_opening_setup(&root, &expected).is_err());
        fs::remove_file(root.join("vk_groth16.bin")).unwrap();
        fs::write(root.join("vk_groth16.bin"), b"vk").unwrap();
        let files = BRIDGE_OPENING_MANIFEST_FILES.iter().map(|name| {
            let bytes = fs::read(root.join(name)).unwrap();
            BridgeOpeningManifestFile { name: (*name).to_string(), sha256: hex::encode(CoreSha256Hasher::hash_bytes(&bytes).0) }
        }).collect();
        let mut manifest = BridgeOpeningManifest { schema: 2, identity_hash: expected.identity_hash().unwrap(), files };
        fs::write(root.join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(validate_bridge_opening_setup(&root, &expected).is_err());
        manifest.schema = 1;
        manifest.identity_hash = "00".repeat(32);
        fs::write(root.join("manifest.json"), serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(validate_bridge_opening_setup(&root, &expected).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn aggregate_proof_rejects_noncanonical_bytes_before_any_write() {
        let root = std::env::temp_dir().join(format!("bridge-opening-proof-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        fs::create_dir(&root).unwrap();
        let proof = root.join("bound.proof");
        fs::write(&proof, b"not-a-proof").unwrap();
        let circuit_data = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(
            plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config(),
        ).build::<C>();
        let error = read_verified_aggregate_proof(&proof, &circuit_data, 1).unwrap_err();
        assert!(error.to_string().contains("canonical") || error.to_string().contains("decode") || error.to_string().contains("proof"), "{error}");
        assert!(fs::read_dir(&root).unwrap().all(|entry| entry.unwrap().path() == proof), "proof validation must not write staging");
        fs::remove_dir_all(root).unwrap();
    }
}

#[derive(Debug, Clone, Args)]
pub struct RegenerateGroth16KeystoreArgs {
    /// Keystore root directory. Defaults to ~/.psy/keystore.
    #[arg(long)]
    pub keystore_dir: Option<PathBuf>,

    /// Do not regenerate deposit_append.
    #[arg(long, default_value_t = false)]
    pub skip_deposit_append: bool,
    /// Do not regenerate withdrawal_claim.
    #[arg(long, default_value_t = false)]
    pub skip_withdrawal_claim: bool,
    /// Generate and publish the full opening verifier to a fresh destination.
    #[arg(long, requires_all = ["aggregate_config", "aggregate_proof", "output_dir"], conflicts_with_all = ["keystore_dir", "skip_deposit_append", "skip_withdrawal_claim"])]
    pub aggregate_proofs: bool,
    /// Approved canonical configuration and reviewed source identities as JSON.
    #[arg(long)]
    pub aggregate_config: Option<PathBuf>,
    /// Canonical aggregate proof bytes from prove-bridge-aggregate-proof, verified before any setup write.
    #[arg(long, requires = "aggregate_proofs")]
    pub aggregate_proof: Option<PathBuf>,
    /// Fresh directory receiving the deposit and window-finalization setup pair in one atomic install.
    #[arg(long, requires = "aggregate_proofs")]
    pub output_dir: Option<PathBuf>,
}

pub fn run(args: RegenerateGroth16KeystoreArgs) -> anyhow::Result<()> {
    if args.aggregate_proofs {
        anyhow::ensure!(!args.skip_deposit_append && !args.skip_withdrawal_claim && args.keystore_dir.is_none(), "aggregate-proofs cannot use batch keystore options");
        anyhow::ensure!(args.aggregate_proof.is_some(), "aggregate-proofs requires aggregate-proof");
        return regenerate_aggregate_proofs(
            args.aggregate_config.as_deref().context("aggregate-proofs requires aggregate-config")?,
            args.aggregate_proof.as_deref().context("aggregate-proofs requires aggregate-proof")?,
            args.output_dir.as_deref().context("aggregate-proofs requires output-dir")?,
        );
    }
    anyhow::ensure!(args.output_dir.is_none() && args.aggregate_config.is_none() && args.aggregate_proof.is_none(), "aggregate-config requires aggregate-proofs");
    let keystore_dir = args.keystore_dir.unwrap_or_else(default_keystore_dir);

    fs::create_dir_all(&keystore_dir)
        .with_context(|| format!("failed to create keystore dir: {}", keystore_dir.display()))?;

    if !args.skip_deposit_append {
        regenerate_deposit_append(&keystore_dir)?;
    }
    if !args.skip_withdrawal_claim {
        regenerate_withdrawal_claim(&keystore_dir)?;
    }

    println!("regenerated local Groth16 keystore files under {}", keystore_dir.display());
    Ok(())
}


fn regenerate_deposit_append(keystore_dir: &Path) -> anyhow::Result<()> {
    let out_dir = keystore_dir.join("deposit_append");
    clear_groth16_files(&out_dir)?;

    println!("building deposit append circuit...");
    let circuit =
        DepositBatchAppendCircuit::<C, D>::build(MAX_DEPOSIT_BATCH_SIZE, DEPOSIT_BATCH_TREE_HEIGHT);
    let inputs = BatchAppendInputs {
        frontier: [QHashOut::ZERO; DEPOSIT_BATCH_TREE_HEIGHT],
        from_index: 0,
        deposits: vec![sample_deposit()],
        bridge_user_id: BRIDGE_USER_ID_U32,
    };
    let proof = circuit.generate_proof(&inputs)?;
    let minifier =
        QEDProofMinifierChain::<D, F, C>::new(&circuit.circuit_data.verifier_only, &circuit.circuit_data.common, 2);
    let minified_proof = minifier.prove(&proof)?;
    let fingerprint = QHashOut(minifier.get_fingerprint());
    println!(
        "deposit_append inner fingerprint: {:?}, keystore: {}",
        fingerprint,
        out_dir.display()
    );
    let wrap = DepositBatchWrapCircuit::new(
        minifier.get_common_data(),
        fingerprint,
        minifier.get_verifier_data().constants_sigmas_cap.height(),
    );
    let shared_wrapper = DepositBatchWrapCircuit::new(
        minifier.get_common_data(),
        fingerprint,
        minifier.get_verifier_data().constants_sigmas_cap.height(),
    )
    .into_shared_groth16_wrapper(format!("{}/", out_dir.display()));
    println!("generating deposit_append Groth16 setup/proof...");
    wrap.prove_groth16_with_shared_wrapper(
        &shared_wrapper,
        minifier.get_verifier_data(),
        &minified_proof,
    )?;
    require_groth16_files(&out_dir)?;
    println!("updated {}", out_dir.display());
    Ok(())
}

fn regenerate_withdrawal_claim(keystore_dir: &Path) -> anyhow::Result<()> {
    let out_dir = keystore_dir.join("withdrawal_claim");
    clear_groth16_files(&out_dir)?;

    println!("building withdrawal claim circuit...");
    let circuit = WithdrawalBatchClaimCircuit::<C, D>::build(WITHDRAWAL_TREE_HEIGHT);
    let withdrawal = sample_withdrawal();
    let withdrawal_root = compute_root_merkle_proof_generic::<QHashOut<F>, PoseidonHash>(
        sample_withdrawal_leaf_hash(),
        withdrawal.leaf_index as u64,
        &withdrawal.siblings,
    );
    let inputs = WithdrawalBatchClaimInputs::<F> {
        withdrawal_root,
        bridge_user_id: BRIDGE_USER_ID_U32,
        withdrawals: vec![withdrawal],
    };
    let proof = circuit.generate_proof(&inputs)?;
    let fingerprint = QHashOut(get_circuit_fingerprint_generic(&circuit.circuit_data.verifier_only));
    println!(
        "withdrawal_claim inner fingerprint: {:?}, keystore: {}",
        fingerprint,
        out_dir.display()
    );
    let wrap = WithdrawalClaimWrapCircuit::new(
        &circuit.circuit_data.common,
        fingerprint,
        circuit.circuit_data.verifier_only.constants_sigmas_cap.height(),
    );
    let shared_wrapper = WithdrawalClaimWrapCircuit::new(
        &circuit.circuit_data.common,
        fingerprint,
        circuit.circuit_data.verifier_only.constants_sigmas_cap.height(),
    )
    .into_shared_groth16_wrapper(format!("{}/", out_dir.display()));
    println!("generating withdrawal_claim Groth16 setup/proof...");
    wrap.prove_groth16_with_shared_wrapper(
        &shared_wrapper,
        &circuit.circuit_data.verifier_only,
        &proof,
    )?;
    require_groth16_files(&out_dir)?;
    println!("updated {}", out_dir.display());
    Ok(())
}

fn default_keystore_dir() -> PathBuf {
    home::home_dir()
        .expect("HOME is required to resolve default Groth16 keystore path")
        .join(".psy")
        .join("keystore")
}

fn clear_groth16_files(dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create Groth16 keystore dir: {}", dir.display()))?;
    for name in GROTH16_FILES {
        let path = dir.join(name);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("failed to remove {}", path.display())),
        }
    }
    Ok(())
}

fn require_groth16_files(dir: &Path) -> anyhow::Result<()> {
    for name in GROTH16_FILES {
        let path = dir.join(name);
        anyhow::ensure!(path.exists(), "expected generated file missing: {}", path.display());
    }
    Ok(())
}

fn sample_deposit() -> DepositLeafData {
    DepositLeafData {
        shield_address: sample_words(1),
        token: sample_words(11),
        l2_token_contract_id: sample_words(21),
        amount: sample_words(31),
        chain_index: 0,
        note_commitment: sample_words(41),
    }
}

fn sample_withdrawal() -> WithdrawalBatchClaimSlotInputs<F> {
    WithdrawalBatchClaimSlotInputs {
        sender_user_id: 7,
        recipient: sample_words(101),
        token: sample_words(111),
        amount: sample_words(121),
        nonce: sample_words(131),
        destination_chain_index: 0,
        leaf_index: 0,
        siblings: zero_siblings(WITHDRAWAL_TREE_HEIGHT),
    }
}

fn sample_words(seed: u32) -> [u32; 8] {
    [
        seed,
        seed + 1,
        seed + 2,
        seed + 3,
        seed + 4,
        seed + 5,
        seed + 6,
        seed + 7,
    ]
}


fn hash_two(left: QHashOut<F>, right: QHashOut<F>) -> QHashOut<F> {
    QHashOut(<PoseidonHash as Hasher<F>>::two_to_one(left.0, right.0))
}

fn zero_siblings(height: usize) -> Vec<QHashOut<F>> {
    let mut siblings = Vec::with_capacity(height);
    let mut current = QHashOut::ZERO;
    for _ in 0..height {
        siblings.push(current);
        current = hash_two(current, current);
    }
    siblings
}


fn sample_withdrawal_leaf_hash() -> QHashOut<F> {
    let withdrawal = sample_withdrawal();
    let felts = std::iter::once(withdrawal.sender_user_id as u64)
        .chain(withdrawal.recipient.into_iter().map(u64::from))
        .chain(withdrawal.token.into_iter().map(u64::from))
        .chain(withdrawal.amount.into_iter().map(u64::from))
        .chain(withdrawal.nonce.into_iter().map(u64::from))
        .chain(std::iter::once(withdrawal.destination_chain_index as u64))
        .map(F::from_noncanonical_u64)
        .collect::<Vec<_>>();
    QHashOut(PoseidonHash::hash_no_pad(&felts))
}

#[cfg(test)]
#[test]
fn generated_aggregate_setup_config_loads() -> anyhow::Result<()> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../dev/aggregate-setup-config.json");
    let approved = load_aggregate_setup_config(&path)?;
    anyhow::ensure!(!approved.network_config.is_empty(), "generated network config is empty");
    Ok(())
}
