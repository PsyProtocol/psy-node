use std::io::Read;
use std::path::Path;

use anyhow::{Context, ensure};
use psy_data::v1::qdata::contract::PQBCDeployContract;
use psy_vm::ups::multisig::MULTISIG_POLICY_CONTRACT_ID;

use crate::protocol::sha256;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GenesisContractsArtifactStamp {
    pub compiler_revision: String,
    pub compiler_sources_hash: String,
    pub artifact_sha256: String,
    pub artifact_byte_size: u64,
    pub token_artifact_sha256: String,
    pub token_artifact_byte_size: u64,
    pub token_update_artifact_sha256: String,
    pub token_update_artifact_byte_size: u64,
}

pub fn validate_genesis_contracts_stamp(bytes: &[u8], bundle: &[u8]) -> anyhow::Result<()> {
    ensure!(bytes.len() <= 65_536, "Genesis compiler stamp exceeds 65536 bytes");
    let stamp: GenesisContractsArtifactStamp = serde_json::from_slice(bytes).context("invalid Genesis compiler stamp")?;
    for (value, length) in [
        (&stamp.compiler_revision, 40),
        (&stamp.compiler_sources_hash, 64),
        (&stamp.artifact_sha256, 64),
        (&stamp.token_artifact_sha256, 64),
        (&stamp.token_update_artifact_sha256, 64),
    ] {
        ensure!(
            value.len() == length && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "Genesis compiler stamp requires lowercase fixed-width hexadecimal identities"
        );
    }
    let _ = (stamp.token_artifact_byte_size, stamp.token_update_artifact_byte_size);
    ensure!(stamp.artifact_byte_size == u64::try_from(bundle.len())?, "Genesis compiler stamp byte size mismatch");
    ensure!(stamp.artifact_sha256 == hex::encode(sha256(bundle).0), "Genesis compiler stamp SHA-256 mismatch");
    Ok(())
}

pub fn load_genesis_contracts<F: serde::de::DeserializeOwned + serde::Serialize>(path: &Path) -> anyhow::Result<Vec<PQBCDeployContract<F>>> {
    let genesis_bytes = std::fs::read(path).with_context(|| format!("reading genesis contracts {}", path.display()))?;
    let stamp_path = path.parent().context("Genesis contracts path has no parent")?.join(".genesis_contracts.compiler-artifact.json");
    let stamp_file = std::fs::File::open(&stamp_path).context("opening locally approved Genesis compiler stamp")?;
    let metadata = stamp_file.metadata()?;
    ensure!(metadata.is_file() && metadata.len() <= 65_536, "Genesis compiler stamp must be a regular file of at most 65536 bytes");
    let mut stamp_bytes = Vec::with_capacity(metadata.len() as usize);
    (&stamp_file).take(65_536).read_to_end(&mut stamp_bytes)?;
    ensure!(stamp_file.metadata()?.len() == stamp_bytes.len() as u64, "Genesis compiler stamp changed size while reading");
    validate_genesis_contracts_stamp(&stamp_bytes, &genesis_bytes)?;
    let decoded;
    let json = if genesis_bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        decoded = zstd::stream::decode_all(genesis_bytes.as_slice()).context("decoding zstd genesis_contracts.json")?;
        decoded.as_slice()
    } else {
        genesis_bytes.as_slice()
    };
    let named: Vec<serde_json::Value> = serde_json::from_slice(json).context("parsing flat named Genesis deployments")?;
    let mut names = std::collections::HashSet::with_capacity(named.len());
    let mut deployments = Vec::with_capacity(named.len());
    for entry in &named {
        let name = entry.get("name").and_then(serde_json::Value::as_str).unwrap_or_default();
        ensure!(!name.trim().is_empty() && names.insert(name.to_owned()), "Genesis contract names must be nonempty and unique");
        deployments.push(serde_json::from_value::<PQBCDeployContract<F>>(entry.clone()).context("parsing Genesis contract deployment")?);
    }
    ensure!(
        named.get(MULTISIG_POLICY_CONTRACT_ID as usize).and_then(|entry| entry.get("name")).and_then(serde_json::Value::as_str) == Some("multisig_policy"),
        "Genesis contract 1 must be multisig_policy"
    );
    Ok(deployments)
}
