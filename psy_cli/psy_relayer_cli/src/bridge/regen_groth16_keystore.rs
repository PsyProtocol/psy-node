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
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::poseidon::PoseidonHash,
    plonk::config::{Hasher, PoseidonGoldilocksConfig},
};
use psy_core::{
    job::job_id::ProvingJobCircuitType,
    network_config::PsyNetworkLocalDevnetConstants,
};
use psy_plonky2_circuits::{
    bridge::{
        circuits::{
            bridge_agg_final::BridgeAggFinalCircuit,
            bridge_wrap::{BridgeWrapCircuit, DepositBatchWrapCircuit, WithdrawalClaimWrapCircuit},
        },
    },
    proof_minifier::pm_chain::QEDProofMinifierChain,
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
    qstandard::QStandardCircuit,
};
use psy_plonky2_basic_helpers::verifier::circuit_library::CircuitInfoLibraryCore;
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

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AggregateSetupConfig {
    pub(crate) network_config: String,
    pub(crate) sources: psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestBitsSources,
}

pub(crate) fn load_aggregate_setup_config(path: &Path) -> anyhow::Result<AggregateSetupConfig> {
    let approved: AggregateSetupConfig = serde_json::from_slice(&fs::read(path)?)?;
    approved.sources.validate()?;
    let config_bytes = hex::decode(&approved.network_config)?;
    anyhow::ensure!(hex::encode(&config_bytes) == approved.network_config, "network_config must be lowercase canonical hex without 0x");
    psy_client_data::bridge_aggregate::NetworkConfig::decode(&config_bytes)
        .map_err(|error| anyhow::anyhow!("invalid approved aggregate configuration: {error:?}"))?;
    Ok(approved)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestBitsManifest {
    schema: u32,
    identity_hash: String,
    files: Vec<DigestBitsManifestFile>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DigestBitsManifestFile {
    name: String,
    sha256: String,
}

pub(crate) fn validate_digest_bits_setup(dir: &Path, expected: &psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestBitsIdentity) -> anyhow::Result<String> {
    use psy_plonky2_circuits::bridge::circuits::bridge_wrap::DigestBitsIdentity;
    use psy_crypto::hash::core::sha256::CoreSha256Hasher;
    let identity: DigestBitsIdentity = serde_json::from_slice(&fs::read(dir.join("identity.json"))?)?;
    anyhow::ensure!(&identity == expected, "native setup identity differs from actual wrapper");
    let identity_hash = identity.identity_hash()?;
    let manifest: DigestBitsManifest = serde_json::from_slice(&fs::read(dir.join("manifest.json"))?)?;
    anyhow::ensure!(manifest.schema == 1 && manifest.identity_hash == identity_hash, "setup manifest identity mismatch");
    let names = ["circuit_groth16.bin", "identity.json", "pk_groth16.bin", "verifier.sol", "vk_groth16.bin"];
    anyhow::ensure!(manifest.files.len() == names.len(), "incomplete setup manifest");
    for (file, name) in manifest.files.iter().zip(names) {
        anyhow::ensure!(file.name == name, "noncanonical setup manifest files");
        let path = dir.join(name);
        anyhow::ensure!(fs::symlink_metadata(&path)?.file_type().is_file(), "setup artifact is not a regular file");
        let bytes = fs::read(&path)?;
        anyhow::ensure!(!bytes.is_empty() && file.sha256 == hex::encode(CoreSha256Hasher::hash_bytes(&bytes).0), "setup artifact digest mismatch: {name}");
        fs::File::open(path)?.sync_all()?;
    }
    fs::File::open(dir.join("manifest.json"))?.sync_all()?;
    fs::File::open(dir)?.sync_all()?;
    Ok(identity_hash)
}

fn regenerate_aggregate_proofs(config_path: &Path, output: &Path) -> anyhow::Result<()> {
    use psy_plonky2_circuits::bridge::{aggregate_circuits::{AggregateCircuitHeights, AggregateCircuits}, circuits::bridge_wrap::{DigestArtifact, DigestBitsAdapter}};
    anyhow::ensure!(matches!(fs::symlink_metadata(output), Err(error) if error.kind() == std::io::ErrorKind::NotFound), "aggregate output must not exist");
    let approved = load_aggregate_setup_config(config_path)?;
    let config = psy_client_data::bridge_aggregate::NetworkConfig::decode(&hex::decode(&approved.network_config)?)
        .map_err(|error| anyhow::anyhow!("invalid approved aggregate configuration: {error:?}"))?;
    let chain_indices: Vec<_> = config.chains.iter().map(|chain| chain.chain_index).collect();
    let circuits = AggregateCircuits::build::<PsyNetworkLocalDevnetConstants>(&chain_indices, cached_bridge_coordinator_circuits()?, AggregateCircuitHeights {
        deposit_state_tree: DEPOSIT_CONTRACT_STATE_TREE_HEIGHT,
        withdrawal_state_tree: WITHDRAWAL_CONTRACT_STATE_TREE_HEIGHT,
    })?;
    circuits.validate_config(&config)?;
    let circuit_set = psy_client_data::bridge_aggregate::encode_circuit_set(circuits.entries())?;
    let (source_deposit, source_withdrawal, source_reward) = circuits.into_digest_sources();
    let adapter_deposit = DigestBitsAdapter::build(DigestArtifact::DepositAggregate, &source_deposit.common, &source_deposit.verifier_only)?;
    let adapter_withdrawal = DigestBitsAdapter::build(DigestArtifact::WithdrawalAggregate, &source_withdrawal.common, &source_withdrawal.verifier_only)?;
    let adapter_reward = DigestBitsAdapter::build(DigestArtifact::RewardAggregate, &source_reward.common, &source_reward.verifier_only)?;
    drop((source_deposit, source_withdrawal, source_reward));
    let deposit = adapter_deposit.into_wrapper(approved.sources.clone())?;
    let withdrawal = adapter_withdrawal.into_wrapper(approved.sources.clone())?;
    let reward = adapter_reward.into_wrapper(approved.sources)?;
    let parent = output.parent().filter(|path| !path.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let name = output.file_name().context("aggregate output must name a directory")?;
    let mut staging_name = name.to_os_string();
    staging_name.push(format!(".staging-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()));
    let staging = parent.join(staging_name);
    fs::create_dir(&staging)?;
    let result = (|| -> anyhow::Result<()> {
        fs::write(staging.join("circuit_set.bin"), &circuit_set)?;
        fs::File::open(staging.join("circuit_set.bin"))?.sync_all()?;
        let mut hashes = Vec::with_capacity(3);
        for (name, wrapper) in [("DepositAggregate", &deposit), ("WithdrawalAggregate", &withdrawal), ("RewardAggregate", &reward)] {
            let directory = staging.join(name);
            wrapper.setup(directory.to_str().context("aggregate artifact path must be UTF-8")?)?;
            hashes.push(validate_digest_bits_setup(&directory, wrapper.identity())?);
        }
        let aggregates = serde_json::json!({"schema": 1, "DepositAggregate": hashes[0], "WithdrawalAggregate": hashes[1], "RewardAggregate": hashes[2]});
        fs::write(staging.join("setup-aggregates.json"), serde_json::to_vec(&aggregates)?)?;
        fs::File::open(staging.join("setup-aggregates.json"))?.sync_all()?;
        fs::File::open(&staging)?.sync_all()?;
        install_aggregate_proofs(&staging, output)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() && staging.exists() { let _ = fs::remove_dir_all(&staging); }
    result
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
    anyhow::bail!("atomic no-replace aggregate publication requires Linux renameat2")
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
        assert!(Command::try_parse_from(["setup", "--aggregate-pair", "--aggregate-config", "config.json", "--output-dir", "aggregates"]).is_err());
        assert!(Command::try_parse_from(["setup", "--aggregate-proofs"]).is_err());
        assert!(Command::try_parse_from(["setup", "--aggregate-config", "config.json", "--output-dir", "aggregates"]).is_err());
        for option in ["--keystore-dir=keys", "--include-bridge-agg", "--skip-deposit-append", "--skip-withdrawal-claim"] {
            assert!(Command::try_parse_from(["setup", "--aggregate-proofs", "--aggregate-config", "config.json", "--output-dir", "aggregates", option]).is_err());
        }
        let command = Command::try_parse_from(["setup", "--aggregate-proofs", "--aggregate-config", "config.json", "--output-dir", "aggregates"]).unwrap();
        assert_eq!(command.args.aggregate_config.as_deref(), Some(Path::new("config.json")));
        assert_eq!(command.args.output_dir.as_deref(), Some(Path::new("aggregates")));
    }

    #[test]
    fn finalize_setup_requires_config_and_standalone_destination() {
        assert!(Command::try_parse_from(["setup", "--include-bridge-agg"]).is_err());
        assert!(Command::try_parse_from(["setup", "--include-bridge-agg", "--aggregate-config", "config.json"]).is_err());
        let command = Command::try_parse_from(["setup", "--include-bridge-agg", "--aggregate-config", "config.json", "--skip-deposit-append", "--skip-withdrawal-claim", "--keystore-dir", "fresh-finalize"]).unwrap();
        assert!(command.args.include_bridge_agg);
        assert_eq!(command.args.keystore_dir.as_deref(), Some(Path::new("fresh-finalize")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn aggregate_publication_never_replaces_existing_destination() {
        let root = std::env::temp_dir().join(format!("aggregate-publication-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
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
}

#[derive(Debug, Clone, Args)]
pub struct RegenerateGroth16KeystoreArgs {
    /// Keystore root directory. Defaults to ~/.psy/keystore.
    #[arg(long)]
    pub keystore_dir: Option<PathBuf>,
    /// Also regenerate the bridge aggregation wrapper keystore.
    #[arg(long, default_value_t = false, requires_all = ["aggregate_config", "skip_deposit_append", "skip_withdrawal_claim"])]
    pub include_bridge_agg: bool,
    /// Do not regenerate deposit_append.
    #[arg(long, default_value_t = false)]
    pub skip_deposit_append: bool,
    /// Do not regenerate withdrawal_claim.
    #[arg(long, default_value_t = false)]
    pub skip_withdrawal_claim: bool,
    /// Generate and publish DepositAggregate, WithdrawalAggregate and RewardAggregate setups to a fresh destination.
    #[arg(long, requires_all = ["aggregate_config", "output_dir"], conflicts_with_all = ["keystore_dir", "include_bridge_agg", "skip_deposit_append", "skip_withdrawal_claim"])]
    pub aggregate_proofs: bool,
    /// Approved canonical configuration and reviewed source identities as JSON.
    #[arg(long)]
    pub aggregate_config: Option<PathBuf>,
    /// Fresh directory receiving all three digest setups in one atomic publication.
    #[arg(long, requires = "aggregate_proofs")]
    pub output_dir: Option<PathBuf>,
}

pub fn run(args: RegenerateGroth16KeystoreArgs) -> anyhow::Result<()> {
    if args.aggregate_proofs {
        anyhow::ensure!(!args.include_bridge_agg && !args.skip_deposit_append && !args.skip_withdrawal_claim && args.keystore_dir.is_none(), "aggregate-proofs cannot use old keystore options");
        return regenerate_aggregate_proofs(args.aggregate_config.as_deref().context("aggregate-proofs requires aggregate-config")?, args.output_dir.as_deref().context("aggregate-proofs requires output-dir")?);
    }
    anyhow::ensure!(args.output_dir.is_none() && (args.aggregate_config.is_none() || args.include_bridge_agg), "aggregate-config requires aggregate-proofs or include-bridge-agg");
    let keystore_dir = args.keystore_dir.unwrap_or_else(default_keystore_dir);
    if args.include_bridge_agg {
        anyhow::ensure!(args.skip_deposit_append && args.skip_withdrawal_claim, "finalize setup requires both skip flags and a fresh standalone directory");
        return regenerate_bridge_agg(&keystore_dir, args.aggregate_config.as_deref().context("finalize setup requires aggregate-config")?);
    }
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

fn regenerate_bridge_agg(keystore_dir: &Path, config_path: &Path) -> anyhow::Result<()> {
    let approved = load_aggregate_setup_config(config_path)?;
    let config = psy_client_data::bridge_aggregate::NetworkConfig::decode(&hex::decode(&approved.network_config)?)
        .map_err(|error| anyhow::anyhow!("invalid approved aggregate configuration: {error:?}"))?;
    let chain_indices: Vec<_> = config.chains.iter().map(|chain| chain.chain_index).collect();
    let coordinator = cached_bridge_coordinator_circuits()?;
    let checkpoint = &coordinator.checkpoint_root_transition;
    let cached = psy_plonky2_circuits::generated::cached_circuit_library::get_cached_circuit_library::<F>();
    let checkpoint_base = cached.get_fingerprint(ProvingJobCircuitType::GenerateRollupStateTransitionProof)
        .context("GenerateRollupStateTransitionProof not found in cached circuit library")?;
    anyhow::ensure!(checkpoint.get_fingerprint() == checkpoint_base, "finalize setup fingerprint differs from cached GenerateRollupStateTransitionProof");
    let finalizer = BridgeAggFinalCircuit::<C, D>::prebuild_final_circuit(
        checkpoint.get_common_circuit_data_ref(),
        checkpoint.get_verifier_config_ref().constants_sigmas_cap.height(),
        checkpoint.get_fingerprint(), checkpoint_base,
        CHECKPOINT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT,
        DEPOSIT_CONTRACT_STATE_TREE_HEIGHT, WITHDRAWAL_CONTRACT_STATE_TREE_HEIGHT,
        &chain_indices,
    );
    let wrapper = BridgeWrapCircuit::new(&finalizer)?.into_shared_groth16_wrapper(keystore_dir.to_str().context("finalize directory must be UTF-8")?.into());
    wrapper.setup_finalize()?;
    require_groth16_files(keystore_dir)?;
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
        bridge_user_id: BRIDGE_USER_ID_U64 as u32,
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

