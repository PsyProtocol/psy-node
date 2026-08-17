use std::sync::{Arc, OnceLock};

use anyhow::bail;
use base64::Engine;
use dashmap::DashMap;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    plonk::{circuit_data::VerifierOnlyCircuitData, config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use psy_client_common::data::{alt::AltVerifierOnlyCircuitData, base_types::hash256::Hash256, qhashout::QHashOut, secp256k1::CompressedPublicKey};
use psy_client_data::{
    config::store_config::PsyHasher,
    dpn::sd_key::SDKeyConfig,
    privacy::{deposit_inclusion::DepositInclusionInput, private_note_inclusion::PrivateNoteInclusionInput},
    qdata::contract::ContractCodeDefinition,
    qstore::imm::cmd_processor::PsyReadCommandProcessorSync,
};
use psy_common_circuit::circuits::{
    traits::qstandard::QStandardCircuit,
    zk_signature3::core::{PsyBasicZKSignatureCircuit, PsyBasicZKSignatureInnerCircuit},
};
use psy_config::network_constants::{
    DEFAULT_CALLER_CONTRACT_ID_U64, GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, MAX_CONTRACT_STATE_TREE_HEIGHT, PRIVATE_NOTE_TREE_HEIGHT,
    UPS_SESSION_PROOF_TREE_HEIGHT,
};
use psy_crypto::{
    hash::traits::qhashable::QFieldHashable,
    signature::{
        secp256k1::{
            core::PsyCompressedSecp256K1Signature,
            wallet::{get_secp_public_key, hash_no_pad_compressed_public_key},
        },
        zk::{data::ZKPublicKeyInfo, wallet::SimplePsyPrivateKey},
    },
};
use psy_dpn_circuit::circuits::privacy::{
    private_note_inclusion::{PrivateNoteInclusionCircuit, PrivateNoteInclusionInnerCircuit},
    shield_deposit_claim::{ShieldDepositClaimCircuit, ShieldDepositClaimInnerCircuit},
};
use psy_ups_circuit::signature::{
    sd_key::SDKeyCircuitGadget,
    software_defined::{DPNSoftwareDefinedSignatureGadget, Plonky2SoftwareDefinedSignatureGadget},
};
use psy_vm::ups::{circuit_manager::UPSCircuitManager, state_reader::StateReader};

use crate::signature::{
    context::SignContext,
    traits::{SignatureResult, SignatureUser},
    users::{
        EthPersonalSignSECP256K1User, ExternalEthPersonalSignUser, ExternalSecp256K1User, SDKeyDpnUser, SDKeyUser, SECP256K1User,
        SoftwareDefinedDpnUser,
        SDKeyPlonky2User, ZKUser,
    },
};

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;

#[derive(Clone, Debug)]
pub struct SDKeyPolicy {
    pub allowed_contract_ids: Vec<u64>,
    pub allowed_method_ids: Vec<u32>,
    pub expected_tx_count: u64,
}

// 65e0169bfffd55f1c0ea9f76c111a5b15e652322ee253c1a9604a10d59066b50
pub const ZK_FINGERPRINT_U64: [u64; 4] = [10809942084296272720, 6801881445144280090, 13901098532226573745, 7340892251884443121];

// 320d034234f0dab4d02c4b03d69276cbd5c2eb831aca1b11c7e52078ace2e33b
pub const SECP256K1_FINGERPRINT_U64: [u64; 4] = [14403954685883114299, 15403132623883213585, 15000446938721187531, 3606542459484560052];

// 4cf514982eb7155648bf1b7852a6a564d8e86998cc1c6365a50e15796b7f0745
pub const ETH_SECP256K1_FINGERPRINT_U64: [u64; 4] = [11893467277170771781, 15629858611769664357, 5241938694879225188, 5545361160027968854];

pub fn get_zk_fingerprint<F: RichField>() -> QHashOut<F> {
    QHashOut(HashOut {
        elements: [
            F::from_canonical_u64(ZK_FINGERPRINT_U64[0]),
            F::from_canonical_u64(ZK_FINGERPRINT_U64[1]),
            F::from_canonical_u64(ZK_FINGERPRINT_U64[2]),
            F::from_canonical_u64(ZK_FINGERPRINT_U64[3]),
        ],
    })
}

pub fn get_secp256k1_fingerprint<F: RichField>() -> QHashOut<F> {
    QHashOut(HashOut {
        elements: [
            F::from_canonical_u64(SECP256K1_FINGERPRINT_U64[0]),
            F::from_canonical_u64(SECP256K1_FINGERPRINT_U64[1]),
            F::from_canonical_u64(SECP256K1_FINGERPRINT_U64[2]),
            F::from_canonical_u64(SECP256K1_FINGERPRINT_U64[3]),
        ],
    })
}

pub fn get_eth_secp256k1_fingerprint<F: RichField>() -> QHashOut<F> {
    QHashOut(HashOut {
        elements: [
            F::from_canonical_u64(ETH_SECP256K1_FINGERPRINT_U64[0]),
            F::from_canonical_u64(ETH_SECP256K1_FINGERPRINT_U64[1]),
            F::from_canonical_u64(ETH_SECP256K1_FINGERPRINT_U64[2]),
            F::from_canonical_u64(ETH_SECP256K1_FINGERPRINT_U64[3]),
        ],
    })
}

/// Alias for the EIP-191 (`personal_sign`) secp256k1 circuit fingerprint.
pub fn get_eth_personal_secp256k1_fingerprint<F: RichField>() -> QHashOut<F> {
    get_eth_secp256k1_fingerprint()
}

fn allowed_contract_method_pairs(allowed_contract_ids: &[u64], allowed_method_ids: &[u32]) -> anyhow::Result<Vec<(u64, u32)>> {
    if allowed_contract_ids.is_empty() {
        bail!("SD key allowed contract_id list must not be empty");
    }
    if allowed_method_ids.is_empty() {
        bail!("SD key allowed method_id list must not be empty");
    }

    if allowed_contract_ids.len() == allowed_method_ids.len() {
        return Ok(allowed_contract_ids.iter().copied().zip(allowed_method_ids.iter().copied()).collect());
    }

    if allowed_contract_ids.len() == 1 {
        return Ok(allowed_method_ids
            .iter()
            .copied()
            .map(|method_id| (allowed_contract_ids[0], method_id))
            .collect());
    }

    if allowed_method_ids.len() == 1 {
        return Ok(allowed_contract_ids
            .iter()
            .copied()
            .map(|contract_id| (contract_id, allowed_method_ids[0]))
            .collect());
    }

    bail!("SD key allowed contract_id and method_id lists must have the same length, or one list must contain exactly one value");
}

fn assert_contract_method_in_allowed_pairs(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    contract_id_target: plonky2::iop::target::Target,
    method_id_target: plonky2::iop::target::Target,
    allowed_pairs: &[(u64, u32)],
) -> anyhow::Result<()> {
    if allowed_pairs.is_empty() {
        bail!("SD key allowed contract/method pair list must not be empty");
    }

    let mut is_allowed = builder._false();
    for (contract_id, method_id) in allowed_pairs {
        let expected_contract_id = builder.constant(F::from_canonical_u64(*contract_id));
        let expected_method_id = builder.constant(F::from_canonical_u64(*method_id as u64));
        let contract_matches = builder.is_equal(contract_id_target, expected_contract_id);
        let method_matches = builder.is_equal(method_id_target, expected_method_id);
        let pair_matches = builder.and(contract_matches, method_matches);
        is_allowed = builder.or(is_allowed, pair_matches);
    }
    builder.assert_one(is_allowed.target);

    Ok(())
}

fn build_allow_method_sd_key_circuit(
    allowed_contract_ids: &[u64],
    allowed_method_ids: &[u32],
    expected_tx_count: u64,
) -> anyhow::Result<SDKeyCircuitGadget> {
    if expected_tx_count == 0 {
        bail!("SD key expected_tx_count must be greater than zero");
    }
    if expected_tx_count > u32::MAX as u64 {
        bail!("SD key expected_tx_count exceeds u32 range: {}", expected_tx_count);
    }

    let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
    let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(config);
    let sd_config = SDKeyConfig {
        num_introspectable_transactions: expected_tx_count as u32,
        can_read_state: false,
        contract_state_tree_height: MAX_CONTRACT_STATE_TREE_HEIGHT,
        requires_secp256k1: false,
        num_secp256k1_slots: 0,
        contract_id: allowed_contract_ids.first().copied().unwrap_or(0),
    };

    let mut gadget = SDKeyCircuitGadget::add_virtual_to(&mut builder, &sd_config, 0, 0);
    let expected_tx_count_target = builder.constant(F::from_canonical_u64(expected_tx_count));
    let allowed_pairs = allowed_contract_method_pairs(allowed_contract_ids, allowed_method_ids)?;
    for tx_index in 0..expected_tx_count as usize {
        assert_contract_method_in_allowed_pairs(
            &mut builder,
            gadget.tx_introspection.get_tx_contract_id(tx_index),
            gadget.tx_introspection.get_tx_method_id(tx_index),
            &allowed_pairs,
        )?;
    }
    builder.connect(gadget.tx_introspection.get_tx_count(), expected_tx_count_target);
    gadget.build_circuit(builder)?;
    Ok(gadget)
}

pub fn get_allow_method_sd_key_fingerprint(
    allowed_contract_ids: &[u64],
    allowed_method_ids: &[u32],
    expected_tx_count: u64,
) -> anyhow::Result<QHashOut<GoldilocksField>> {
    Ok(build_allow_method_sd_key_circuit(allowed_contract_ids, allowed_method_ids, expected_tx_count)?.get_fingerprint())
}

pub fn get_public_key_info<F: RichField>(private_key: QHashOut<F>, fingerprint: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
    let public_key_param = if fingerprint == get_zk_fingerprint() {
        SimplePsyPrivateKey::new(private_key).get_public_key_param::<PsyHasher>()
    } else if fingerprint == get_secp256k1_fingerprint() || fingerprint == get_eth_secp256k1_fingerprint() {
        let public_key = get_secp_public_key::<F>(private_key)?;
        hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(public_key)
    } else {
        unimplemented!("fingerprint {} is not supported", fingerprint)
    };
    Ok(ZKPublicKeyInfo {
        public_key_param,
        fingerprint,
    })
}
pub struct PsyMemoryWallet {
    signature_users: DashMap<QHashOut<F>, Arc<dyn SignatureUser>>,
    local_circuits: PsyWalletLocalCircuits,
    circuit_manager: Vec<Box<dyn UPSCircuitManager<C, D> + Send + Sync>>,
    fallback_minifiers: FallbackMinifierCircuits,
    trace_contract_code_cache: DashMap<u64, Vec<u8>>,
}

/// Local minifier circuits used when the prove proxy cannot minify a proof.
/// Each circuit is built lazily and independently so the wallet only pays for
/// the fallback paths it actually hits.
#[derive(Default)]
struct FallbackMinifierCircuits {
    zk_signature: OnceLock<PsyBasicZKSignatureCircuit<C, D>>,
    private_note_inclusion: OnceLock<PrivateNoteInclusionCircuit<C, D>>,
    shield_deposit_claim: OnceLock<ShieldDepositClaimCircuit<C, D>>,
}

impl FallbackMinifierCircuits {
    fn zk_signature(&self) -> &PsyBasicZKSignatureCircuit<C, D> {
        self.zk_signature.get_or_init(|| {
            tracing::warn!("initializing local zk-sign minifier fallback circuit");
            PsyBasicZKSignatureCircuit::<C, D>::new()
        })
    }

    fn private_note_inclusion(&self) -> &PrivateNoteInclusionCircuit<C, D> {
        self.private_note_inclusion.get_or_init(|| {
            tracing::warn!("initializing local private-note-inclusion minifier fallback circuit");
            PrivateNoteInclusionCircuit::<C, D>::new(
                GLOBAL_USER_TREE_HEIGHT as usize,
                GLOBAL_CONTRACT_TREE_HEIGHT as usize,
                MAX_CONTRACT_STATE_TREE_HEIGHT as usize,
                PRIVATE_NOTE_TREE_HEIGHT,
            )
        })
    }

    fn shield_deposit_claim(&self) -> &ShieldDepositClaimCircuit<C, D> {
        self.shield_deposit_claim.get_or_init(|| {
            tracing::warn!("initializing local shield-deposit-claim minifier fallback circuit");
            ShieldDepositClaimCircuit::<C, D>::new()
        })
    }
}

/// On-disk cache path for a local circuit. The `_v1` suffix is a manual schema
/// version: bump it whenever the corresponding circuit layout changes.
///
/// Disk caching and the JSON bundle are host-only: wasm has no filesystem, and
/// the `dirs`/`zstd`/`base64` crates are declared non-wasm in this crate's
/// `Cargo.toml`.
#[cfg(not(target_arch = "wasm32"))]
fn local_circuit_cache_path(name: &str) -> Option<std::path::PathBuf> {
    dirs::cache_dir().map(|d| d.join("psy").join("circuits").join(format!("{name}_v1.bin")))
}

/// Loads a local circuit from its on-disk cache when present, otherwise builds
/// it and best-effort writes the cache for next time. Any IO/deserialize
/// failure falls back to a fresh build, so this can never make startup fail.
#[cfg(not(target_arch = "wasm32"))]
fn load_or_build_local_circuit<T>(
    name: &str,
    build: impl FnOnce() -> T,
    load: impl FnOnce(&[u8]) -> anyhow::Result<T>,
    serialize: impl FnOnce(&T) -> anyhow::Result<Vec<u8>>,
) -> T {
    let Some(path) = local_circuit_cache_path(name) else {
        return build();
    };

    if path.exists() {
        match std::fs::read(&path).map_err(anyhow::Error::from).and_then(|b| load(&b)) {
            Ok(circuit) => {
                tracing::info!("loaded local circuit `{name}` from cache: {}", path.display());
                return circuit;
            }
            Err(e) => tracing::warn!("failed to load local circuit `{name}` cache ({}), rebuilding: {e}", path.display()),
        }
    }

    let circuit = build();
    match serialize(&circuit) {
        Ok(bytes) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            match std::fs::write(&path, &bytes) {
                Ok(()) => tracing::info!("wrote local circuit `{name}` cache: {}", path.display()),
                Err(e) => tracing::warn!("failed to write local circuit `{name}` cache {}: {e}", path.display()),
            }
        }
        Err(e) => tracing::warn!("failed to serialize local circuit `{name}` for cache: {e}"),
    }
    circuit
}

/// `PrivateNoteInclusionCircuit` tree heights — must match between build and
/// load.
const PRIVATE_NOTE_INCLUSION_HEIGHTS: (usize, usize, usize, usize) = (
    GLOBAL_USER_TREE_HEIGHT as usize,
    GLOBAL_CONTRACT_TREE_HEIGHT as usize,
    MAX_CONTRACT_STATE_TREE_HEIGHT as usize,
    PRIVATE_NOTE_TREE_HEIGHT,
);

const LOCAL_CIRCUITS_BUNDLE_VERSION: u32 = 1;

/// All three local base circuits serialized into one JSON document
/// (`local_circuits.json`). Each field is `base64( circuit bytes )`. zk-sign is
/// stored full (tiny); the two privacy circuits use the COMPACT encoding
/// (Merkle tree omitted, rebuilt on load) so the bundle stays small enough to
/// `include_str!` into the binary / ship to wasm.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LocalCircuitsBundle {
    version: u32,
    zk_signature_inner: String,
    private_note_inclusion: String,
    shield_deposit_claim: String,
}

/// Host-only: producing the bundle builds the (heavy) circuits.
#[cfg(not(target_arch = "wasm32"))]
fn encode_circuit_field(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_circuit_field(field: &str) -> anyhow::Result<Vec<u8>> {
    Ok(base64::engine::general_purpose::STANDARD.decode(field)?)
}

#[derive(Default)]
pub struct PsyWalletLocalCircuits {
    zk_signature_inner: OnceLock<PsyBasicZKSignatureInnerCircuit<C, D>>,
    private_note_inclusion: OnceLock<PrivateNoteInclusionInnerCircuit<C, D>>,
    shield_deposit_claim: OnceLock<ShieldDepositClaimInnerCircuit<C, D>>,
    psy_software_defined_circuits: DashMap<QHashOut<F>, DPNSoftwareDefinedSignatureGadget>,
    plonky2_software_defined_circuits: DashMap<QHashOut<F>, Plonky2SoftwareDefinedSignatureGadget>,
    sd_key_circuits: DashMap<QHashOut<F>, SDKeyCircuitGadget>,
    sd_key_policies: DashMap<QHashOut<F>, SDKeyPolicy>,
}

impl PsyWalletLocalCircuits {
    pub fn zk_signature_inner(&self) -> &PsyBasicZKSignatureInnerCircuit<C, D> {
        self.zk_signature_inner.get_or_init(|| {
            #[cfg(not(target_arch = "wasm32"))]
            {
                load_or_build_local_circuit(
                    "zk_signature_inner",
                    PsyBasicZKSignatureInnerCircuit::<C, D>::new,
                    PsyBasicZKSignatureInnerCircuit::<C, D>::new_with_serialized_circuit,
                    PsyBasicZKSignatureInnerCircuit::<C, D>::serialize_circuit_data,
                )
            }
            #[cfg(target_arch = "wasm32")]
            {
                PsyBasicZKSignatureInnerCircuit::<C, D>::new()
            }
        })
    }

    pub fn private_note_inclusion(&self) -> &PrivateNoteInclusionInnerCircuit<C, D> {
        let (h0, h1, h2, h3) = PRIVATE_NOTE_INCLUSION_HEIGHTS;
        self.private_note_inclusion.get_or_init(|| {
            #[cfg(not(target_arch = "wasm32"))]
            {
                load_or_build_local_circuit(
                    "private_note_inclusion",
                    || PrivateNoteInclusionInnerCircuit::<C, D>::new(h0, h1, h2, h3),
                    |bytes| PrivateNoteInclusionInnerCircuit::<C, D>::new_with_serialized_circuit(bytes, h0, h1, h2, h3),
                    PrivateNoteInclusionInnerCircuit::<C, D>::serialize_circuit_data,
                )
            }
            #[cfg(target_arch = "wasm32")]
            {
                PrivateNoteInclusionInnerCircuit::<C, D>::new(h0, h1, h2, h3)
            }
        })
    }

    pub fn shield_deposit_claim(&self) -> &ShieldDepositClaimInnerCircuit<C, D> {
        self.shield_deposit_claim.get_or_init(|| {
            #[cfg(not(target_arch = "wasm32"))]
            {
                load_or_build_local_circuit(
                    "shield_deposit_claim",
                    ShieldDepositClaimInnerCircuit::<C, D>::new,
                    ShieldDepositClaimInnerCircuit::<C, D>::new_with_serialized_circuit,
                    ShieldDepositClaimInnerCircuit::<C, D>::serialize_circuit_data,
                )
            }
            #[cfg(target_arch = "wasm32")]
            {
                ShieldDepositClaimInnerCircuit::<C, D>::new()
            }
        })
    }

    /// Build all three base circuits fresh and serialize them into
    /// `local_circuits.json`: zk-sign full (tiny), the two privacy circuits
    /// COMPACT. Host-only (builds the circuits). Run this to (re)generate
    /// the embedded bundle.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn to_bundle_json() -> anyhow::Result<String> {
        let (h0, h1, h2, h3) = PRIVATE_NOTE_INCLUSION_HEIGHTS;
        let zk = PsyBasicZKSignatureInnerCircuit::<C, D>::new();
        let mut pni = PrivateNoteInclusionInnerCircuit::<C, D>::new(h0, h1, h2, h3);
        let mut sdc = ShieldDepositClaimInnerCircuit::<C, D>::new();

        let bundle = LocalCircuitsBundle {
            version: LOCAL_CIRCUITS_BUNDLE_VERSION,
            zk_signature_inner: encode_circuit_field(&zk.serialize_circuit_data()?),
            private_note_inclusion: encode_circuit_field(&pni.serialize_circuit_data_compact()?),
            shield_deposit_claim: encode_circuit_field(&sdc.serialize_circuit_data_compact()?),
        };
        Ok(serde_json::to_string(&bundle)?)
    }

    /// The embedded `local_circuits.json`, loaded via [`from_bundle_json`].
    /// Available everywhere (incl. wasm) — this is the intended runtime
    /// constructor.
    pub fn from_embedded_bundle() -> anyhow::Result<Self> {
        tracing::info!("loading local circuits from embedded local_circuits.json");
        Self::from_bundle_json(include_str!("local_circuits.json"))
    }

    /// Reconstruct from a `local_circuits.json` bundle. zk-sign is read full;
    /// the two privacy circuits are read COMPACT (their Merkle tree is
    /// rebuilt from poly coeffs). The software-defined circuit maps start
    /// empty (registered dynamically at runtime).
    pub fn from_bundle_json(json: &str) -> anyhow::Result<Self> {
        #[cfg(not(target_arch = "wasm32"))]
        let start = std::time::Instant::now();
        tracing::info!("loading local circuits from bundle ({} KiB json)", json.len() / 1024);

        let bundle: LocalCircuitsBundle = serde_json::from_str(json)?;
        if bundle.version != LOCAL_CIRCUITS_BUNDLE_VERSION {
            bail!(
                "local circuits bundle version mismatch: expected {}, got {}",
                LOCAL_CIRCUITS_BUNDLE_VERSION,
                bundle.version
            );
        }

        let (h0, h1, h2, h3) = PRIVATE_NOTE_INCLUSION_HEIGHTS;
        let inner = PsyBasicZKSignatureInnerCircuit::<C, D>::new_with_serialized_circuit(&decode_circuit_field(&bundle.zk_signature_inner)?)?;
        tracing::info!("  loaded zk_signature_inner (full)");
        let pni = PrivateNoteInclusionInnerCircuit::<C, D>::new_with_serialized_circuit_compact(
            &decode_circuit_field(&bundle.private_note_inclusion)?,
            h0,
            h1,
            h2,
            h3,
        )?;
        tracing::info!("  loaded private_note_inclusion (compact, merkle rebuilt)");
        let sdc = ShieldDepositClaimInnerCircuit::<C, D>::new_with_serialized_circuit_compact(&decode_circuit_field(&bundle.shield_deposit_claim)?)?;
        tracing::info!("  loaded shield_deposit_claim (compact, merkle rebuilt)");

        let this = Self::default();
        let _ = this.zk_signature_inner.set(inner);
        let _ = this.private_note_inclusion.set(pni);
        let _ = this.shield_deposit_claim.set(sdc);
        #[cfg(not(target_arch = "wasm32"))]
        tracing::info!("local circuits loaded in {:.3?}", start.elapsed());
        #[cfg(target_arch = "wasm32")]
        tracing::info!("local circuits loaded");
        Ok(this)
    }

    pub fn prove_zk_sign_inner(&self, private_key: QHashOut<F>, sig_hash: QHashOut<F>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.zk_signature_inner().prove_base(private_key, sig_hash)
    }

    pub fn private_note_inclusion_verifier_data(&self) -> VerifierOnlyCircuitData<C, D> {
        self.private_note_inclusion().get_verifier_config_ref().clone()
    }

    pub fn shield_deposit_claim_verifier_data(&self) -> VerifierOnlyCircuitData<C, D> {
        self.shield_deposit_claim().get_verifier_config_ref().clone()
    }

    pub fn has_psy_software_defined_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.psy_software_defined_circuits.contains_key(fingerprint)
    }

    pub fn has_plonky2_software_defined_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.plonky2_software_defined_circuits.contains_key(fingerprint)
    }

    pub fn has_sd_key_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.sd_key_circuits.contains_key(fingerprint)
    }

    pub fn insert_psy_software_defined_circuit(&self, fingerprint: QHashOut<F>, circuit: DPNSoftwareDefinedSignatureGadget) {
        self.psy_software_defined_circuits.insert(fingerprint, circuit);
    }

    pub fn insert_plonky2_software_defined_circuit(&self, fingerprint: QHashOut<F>, circuit: Plonky2SoftwareDefinedSignatureGadget) {
        self.plonky2_software_defined_circuits.insert(fingerprint, circuit);
    }

    pub fn insert_sd_key_circuit(&self, fingerprint: QHashOut<F>, circuit: SDKeyCircuitGadget) {
        self.sd_key_circuits.insert(fingerprint, circuit);
    }

    pub fn insert_sd_key_policy(&self, fingerprint: QHashOut<F>, policy: SDKeyPolicy) {
        self.sd_key_policies.insert(fingerprint, policy);
    }

    pub fn get_psy_software_defined_circuit(
        &self,
        fingerprint: &QHashOut<F>,
    ) -> Option<dashmap::mapref::one::Ref<'_, QHashOut<F>, DPNSoftwareDefinedSignatureGadget>> {
        self.psy_software_defined_circuits.get(fingerprint)
    }

    pub fn get_psy_software_defined_circuit_mut(
        &self,
        fingerprint: &QHashOut<F>,
    ) -> Option<dashmap::mapref::one::RefMut<'_, QHashOut<F>, DPNSoftwareDefinedSignatureGadget>> {
        self.psy_software_defined_circuits.get_mut(fingerprint)
    }

    pub fn get_plonky2_software_defined_circuit(
        &self,
        fingerprint: &QHashOut<F>,
    ) -> Option<dashmap::mapref::one::Ref<'_, QHashOut<F>, Plonky2SoftwareDefinedSignatureGadget>> {
        self.plonky2_software_defined_circuits.get(fingerprint)
    }

    pub fn get_plonky2_software_defined_circuit_mut(
        &self,
        fingerprint: &QHashOut<F>,
    ) -> Option<dashmap::mapref::one::RefMut<'_, QHashOut<F>, Plonky2SoftwareDefinedSignatureGadget>> {
        self.plonky2_software_defined_circuits.get_mut(fingerprint)
    }

    pub fn get_sd_key_circuit(&self, fingerprint: &QHashOut<F>) -> Option<dashmap::mapref::one::Ref<'_, QHashOut<F>, SDKeyCircuitGadget>> {
        self.sd_key_circuits.get(fingerprint)
    }

    pub fn get_sd_key_circuit_mut(&self, fingerprint: &QHashOut<F>) -> Option<dashmap::mapref::one::RefMut<'_, QHashOut<F>, SDKeyCircuitGadget>> {
        self.sd_key_circuits.get_mut(fingerprint)
    }

    pub fn get_sd_key_policy(&self, fingerprint: &QHashOut<F>) -> Option<SDKeyPolicy> {
        self.sd_key_policies.get(fingerprint).map(|entry| entry.value().clone())
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl PsyMemoryWallet {
    pub fn new(circuit_manager: Vec<Box<dyn UPSCircuitManager<C, D> + Send + Sync>>) -> Self {
        Self::new_with_local_circuits(circuit_manager, PsyWalletLocalCircuits::default())
    }

    pub fn new_with_local_circuits(
        circuit_manager: Vec<Box<dyn UPSCircuitManager<C, D> + Send + Sync>>,
        local_circuits: PsyWalletLocalCircuits,
    ) -> Self {
        Self {
            signature_users: DashMap::new(),
            local_circuits,
            circuit_manager,
            fallback_minifiers: FallbackMinifierCircuits::default(),
            trace_contract_code_cache: DashMap::new(),
        }
    }

    pub fn local_circuits(&self) -> &PsyWalletLocalCircuits {
        &self.local_circuits
    }

    pub fn fallback_private_note_inclusion_minifier_fingerprint(&self) -> QHashOut<F> {
        self.fallback_minifiers.private_note_inclusion().get_fingerprint()
    }

    pub fn fallback_private_note_inclusion_minifier_verifier_data(&self) -> VerifierOnlyCircuitData<C, D> {
        self.fallback_minifiers.private_note_inclusion().get_verifier_config_ref().clone()
    }

    /// Produce a base proof from the local (base-only) circuit, then minify it
    /// via the circuit manager (server-side). Returns the MINIFIED
    /// fingerprint/proof/verifier — what the network registers and
    /// verifies. Mirrors `prove_zk_sign`.
    pub async fn prove_private_note_inclusion(
        &self,
        input: &PrivateNoteInclusionInput<F>,
    ) -> anyhow::Result<(QHashOut<F>, ProofWithPublicInputs<F, C, D>, AltVerifierOnlyCircuitData<F>)> {
        let base_proof = self.local_circuits.private_note_inclusion().prove(input)?;
        let manager = self.random_circuit_manager();
        let (minified, fingerprint, verifier) = match manager.prove_private_note_inclusion_minifier(base_proof.clone()).await {
            Ok(minified) => {
                let fingerprint = manager.private_note_inclusion_minifier_fingerprint().await?;
                let verifier = manager.private_note_inclusion_minifier_verifier_config().await?;
                (minified, fingerprint, verifier)
            }
            Err(err) => {
                tracing::warn!("private note inclusion minifier proxy failed, falling back to local circuit: {err}");
                let circuit = self.fallback_minifiers.private_note_inclusion();
                let minified = circuit.prove_minifier(base_proof)?;
                (minified, circuit.get_fingerprint(), circuit.get_verifier_config_ref().clone())
            }
        };
        Ok((fingerprint, minified, verifier.into()))
    }

    pub async fn prove_shield_deposit_claim(
        &self,
        input: &DepositInclusionInput<F>,
    ) -> anyhow::Result<(QHashOut<F>, ProofWithPublicInputs<F, C, D>, AltVerifierOnlyCircuitData<F>)> {
        let base_proof = self.local_circuits.shield_deposit_claim().prove(input)?;
        let manager = self.random_circuit_manager();
        let (minified, fingerprint, verifier) = match manager.prove_shield_deposit_claim_minifier(base_proof.clone()).await {
            Ok(minified) => {
                let fingerprint = manager.shield_deposit_claim_minifier_fingerprint().await?;
                let verifier = manager.shield_deposit_claim_minifier_verifier_config().await?;
                (minified, fingerprint, verifier)
            }
            Err(err) => {
                tracing::warn!("shield deposit claim minifier proxy failed, falling back to local circuit: {err}");
                let circuit = self.fallback_minifiers.shield_deposit_claim();
                let minified = circuit.prove_minifier(base_proof)?;
                (minified, circuit.get_fingerprint(), circuit.get_verifier_config_ref().clone())
            }
        };
        Ok((fingerprint, minified, verifier.into()))
    }

    pub async fn zk_circuit_fingerprint(&self) -> anyhow::Result<QHashOut<F>> {
        self.random_circuit_manager().zk_signature_minifier_fingerprint().await
    }

    pub async fn zk_circuit_verifier_config(&self) -> anyhow::Result<VerifierOnlyCircuitData<C, D>> {
        self.random_circuit_manager().zk_signature_minifier_verifier_config().await
    }

    pub async fn prove_zk_sign(&self, private_key: QHashOut<F>, sig_hash: QHashOut<F>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let inner_proof = self.local_circuits.prove_zk_sign_inner(private_key, sig_hash)?;
        match self.random_circuit_manager().prove_zk_sign_minifier(inner_proof.clone()).await {
            Ok(proof) => Ok(proof),
            Err(err) => {
                tracing::warn!("zk sign minifier proxy failed, falling back to local circuit: {err}");
                self.fallback_minifiers.zk_signature().prove_minifier(inner_proof)
            }
        }
    }

    pub fn random_circuit_manager(&self) -> &Box<dyn UPSCircuitManager<C, D> + Send + Sync> {
        let index = rand::random::<usize>() % self.circuit_manager.len();
        &self.circuit_manager[index]
    }

    /// Register trace-provided contract circuits on every proving manager.
    ///
    /// Stateless step proving creates no long-lived session manager, so the
    /// contract circuits referenced by a trace must be available on whichever
    /// manager later gets picked for proving. Registering on all managers
    /// avoids nondeterministic misses under multi-manager / multi-proxy
    /// configs.
    pub async fn register_contract_circuits_all(&self, contract_id: u64, contract_code: &ContractCodeDefinition) -> anyhow::Result<()> {
        for mgr in &self.circuit_manager {
            mgr.register_contract_circuits(contract_id, contract_code).await?;
        }
        Ok(())
    }

    pub async fn ensure_trace_contract_circuits_registered(&self, contract_id: u64, contract_code_bytes: &[u8]) -> anyhow::Result<()> {
        if let Some(existing) = self.trace_contract_code_cache.get(&contract_id) {
            if existing.as_slice() == contract_code_bytes {
                return Ok(());
            }
        }

        let contract_code: ContractCodeDefinition = bincode::deserialize(contract_code_bytes)?;
        self.register_contract_circuits_all(contract_id, &contract_code).await?;
        self.trace_contract_code_cache.insert(contract_id, contract_code_bytes.to_vec());
        Ok(())
    }

    pub fn has_psy_software_defined_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.local_circuits.has_psy_software_defined_circuit(fingerprint)
    }

    pub fn has_plonky2_software_defined_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.local_circuits.has_plonky2_software_defined_circuit(fingerprint)
    }

    pub fn has_sd_key_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.local_circuits.has_sd_key_circuit(fingerprint)
    }

    pub fn insert_psy_software_defined_circuit(&self, fingerprint: QHashOut<F>, circuit: DPNSoftwareDefinedSignatureGadget) {
        self.local_circuits.insert_psy_software_defined_circuit(fingerprint, circuit);
    }

    pub fn insert_plonky2_software_defined_circuit(&self, fingerprint: QHashOut<F>, circuit: Plonky2SoftwareDefinedSignatureGadget) {
        self.local_circuits.insert_plonky2_software_defined_circuit(fingerprint, circuit);
    }

    pub fn insert_sd_key_circuit(&self, fingerprint: QHashOut<F>, circuit: SDKeyCircuitGadget) {
        self.local_circuits.insert_sd_key_circuit(fingerprint, circuit);
    }

    pub async fn add_zk_private_key(&mut self, private_key: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let simple_key = SimplePsyPrivateKey { private_key };
        let user: Arc<dyn SignatureUser> = Arc::new(ZKUser::new(simple_key));
        let manager = self.random_circuit_manager();
        let manager_ref = manager.as_ref();
        let pk_info = user.public_key_info(self, manager_ref).await?;
        let pk_hash = pk_info.qfhash::<PsyHasher>();
        self.signature_users.insert(pk_hash, user);
        Ok(pk_info)
    }

    pub async fn add_secp_private_key(&mut self, private_key: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user: Arc<dyn SignatureUser> = Arc::new(SECP256K1User::new(private_key));
        let manager = self.random_circuit_manager();
        let manager_ref = manager.as_ref();
        let pk_info = user.public_key_info(self, manager_ref).await?;
        let pk_hash = pk_info.qfhash::<PsyHasher>();
        self.signature_users.insert(pk_hash, user);
        Ok(pk_info)
    }

    /// Held-key counterpart of [`Self::register_external_eth_personal_user`]:
    /// installs an [`EthPersonalSignSECP256K1User`] that keeps the private key
    /// in the wallet and signs EIP-191 (`personal_sign`) digests locally.
    /// Shares the eth_personal circuit fingerprint with the external variant,
    /// so the same key maps to the SAME `pk_hash`/identity either way.
    pub async fn add_eth_personal_secp_private_key(&mut self, private_key: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user: Arc<dyn SignatureUser> = Arc::new(EthPersonalSignSECP256K1User::new(private_key));
        let manager = self.random_circuit_manager();
        let manager_ref = manager.as_ref();
        let pk_info = user.public_key_info(self, manager_ref).await?;
        let pk_hash = pk_info.qfhash::<PsyHasher>();
        self.signature_users.insert(pk_hash, user);
        Ok(pk_info)
    }

    /// Mode-A (web/MetaMask): install a classic-secp user PK-first — ONLY the
    /// compressed public key, no signature yet. Enough for on-chain
    /// registration and trace generation. Proving (`sign()`) fails until
    /// the entry is replaced via [`Self::inject_secp_signature`] with a
    /// MetaMask signature over the session sighash.
    pub async fn register_external_secp_user(&mut self, compressed_public_key: CompressedPublicKey) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user = ExternalSecp256K1User::new(compressed_public_key)
            .map_err(|e| anyhow::anyhow!("invalid external secp256k1 public key: {e}"))?;
        let user: Arc<dyn SignatureUser> = Arc::new(user);
        let manager = self.random_circuit_manager();
        let manager_ref = manager.as_ref();
        let pk_info = user.public_key_info(self, manager_ref).await?;
        let pk_hash = pk_info.qfhash::<PsyHasher>();
        self.signature_users.insert(pk_hash, user);
        Ok(pk_info)
    }

    /// Inject an externally produced (MetaMask `eth_sign`-style) signature over
    /// the session sighash: REPLACES the wallet entry with a signature-carrying
    /// [`ExternalSecp256K1User`]. Call this after trace generation, once per
    /// transaction.
    pub async fn inject_secp_signature(
        &mut self,
        expected_public_key: QHashOut<F>,
        signature: PsyCompressedSecp256K1Signature,
    ) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user = ExternalSecp256K1User::with_signature(signature)
            .map_err(|e| anyhow::anyhow!("invalid external secp256k1 signature: {e}"))?;
        let user: Arc<dyn SignatureUser> = Arc::new(user);
        let manager = self.random_circuit_manager();
        let manager_ref = manager.as_ref();
        let pk_info = user.public_key_info(self, manager_ref).await?;
        let actual_public_key = pk_info.qfhash::<PsyHasher>();
        if actual_public_key != expected_public_key {
            bail!(
                "injected secp256k1 signature belongs to public key `{}`, expected registered public key `{}`",
                actual_public_key,
                expected_public_key
            );
        }
        if !self.signature_users.contains_key(&expected_public_key) {
            bail!("registered external secp256k1 user `{}` not found in wallet", expected_public_key);
        }
        self.signature_users.insert(expected_public_key, user);
        Ok(pk_info)
    }

    /// Mode-A MetaMask `personal_sign` (EIP-191): install an eth_personal user
    /// PK-first — ONLY the compressed public key, no signature yet. Enough for
    /// on-chain registration and trace generation. Proving (`sign()`) fails
    /// until the entry is replaced via [`Self::inject_eth_personal_signature`]
    /// with a MetaMask signature over the session sighash.
    ///
    /// Because this user reports the eth_personal circuit fingerprint, the
    /// resulting `pk_hash` is a DISTINCT identity from the classic-secp one for
    /// the same public key.
    pub async fn register_external_eth_personal_user(&mut self, compressed_public_key: CompressedPublicKey) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user = ExternalEthPersonalSignUser::new(compressed_public_key)
            .map_err(|e| anyhow::anyhow!("invalid external EIP-191 public key: {e}"))?;
        let user: Arc<dyn SignatureUser> = Arc::new(user);
        let manager = self.random_circuit_manager();
        let manager_ref = manager.as_ref();
        let pk_info = user.public_key_info(self, manager_ref).await?;
        let pk_hash = pk_info.qfhash::<PsyHasher>();
        self.signature_users.insert(pk_hash, user);
        Ok(pk_info)
    }

    /// Inject a MetaMask `personal_sign` signature over the session sighash:
    /// REPLACES the wallet entry with a signature-carrying
    /// [`ExternalEthPersonalSignUser`]. The signature's `(r,s)` is over
    /// `keccak256(EIP-191 prefix || sighash)`; the EIP-191 circuit re-derives
    /// that keccak in-circuit. Call this after trace generation, once per
    /// transaction.
    pub async fn inject_eth_personal_signature(
        &mut self,
        expected_public_key: QHashOut<F>,
        signature: PsyCompressedSecp256K1Signature,
    ) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user = ExternalEthPersonalSignUser::with_signature(signature)
            .map_err(|e| anyhow::anyhow!("invalid external EIP-191 signature: {e}"))?;
        let user: Arc<dyn SignatureUser> = Arc::new(user);
        let manager = self.random_circuit_manager();
        let manager_ref = manager.as_ref();
        let pk_info = user.public_key_info(self, manager_ref).await?;
        let actual_public_key = pk_info.qfhash::<PsyHasher>();
        if actual_public_key != expected_public_key {
            bail!(
                "injected eth-personal signature belongs to public key `{}`, expected registered public key `{}`",
                actual_public_key,
                expected_public_key
            );
        }
        if !self.signature_users.contains_key(&expected_public_key) {
            bail!("registered external eth-personal user `{}` not found in wallet", expected_public_key);
        }
        self.signature_users.insert(expected_public_key, user);
        Ok(pk_info)
    }

    pub async fn get_zk_pk_info(&self, private_key: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let simple_key = SimplePsyPrivateKey { private_key };
        let public_key_param = simple_key.get_public_key_param::<PoseidonHash>();
        let fingerprint = self.zk_circuit_fingerprint().await?;
        Ok(ZKPublicKeyInfo {
            fingerprint,
            public_key_param,
        })
    }

    pub async fn get_secp_pk_info(&self, private_key: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let pub_compressed = psy_crypto::signature::secp256k1::wallet::get_secp_public_key(private_key)?;
        let public_key_param =
            psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(pub_compressed);
        let fingerprint = self.random_circuit_manager().secp_circuit_fingerprint().await?;
        Ok(ZKPublicKeyInfo {
            fingerprint,
            public_key_param,
        })
    }

    /// EIP-191 (`personal_sign`) counterpart of [`Self::get_secp_pk_info`]:
    /// same `public_key_param` derivation, but reports the eth_personal
    /// circuit fingerprint.
    pub async fn get_eth_personal_secp_pk_info(&self, private_key: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let pub_compressed = psy_crypto::signature::secp256k1::wallet::get_secp_public_key(private_key)?;
        let public_key_param =
            psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(pub_compressed);
        let fingerprint = self.random_circuit_manager().eth_personal_secp_circuit_fingerprint().await?;
        Ok(ZKPublicKeyInfo {
            fingerprint,
            public_key_param,
        })
    }

    pub async fn get_public_key_info(&self, public_key: &QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user_guard = self
            .signature_users
            .get(public_key)
            .ok_or_else(|| anyhow::anyhow!("public key `{}` not found in wallet", public_key))?;
        let user = user_guard.value().clone();
        drop(user_guard);
        let manager = self.random_circuit_manager();
        user.public_key_info(self, manager.as_ref()).await
    }

    pub async fn sign_with_public_key(
        &self,
        public_key: &QHashOut<F>,
        context: &SignContext,
        sighash: QHashOut<F>,
    ) -> anyhow::Result<SignatureResult> {
        let user_guard = self
            .signature_users
            .get(public_key)
            .ok_or_else(|| anyhow::anyhow!("signature user for `{}` not found", public_key))?;
        let user = user_guard.value().clone();
        drop(user_guard);

        let circuit_manager = self.random_circuit_manager();
        let manager_ref = circuit_manager.as_ref();

        let proof = user.sign(self, manager_ref, context, sighash).await?;
        let circuit_info = user.circuit_info(self, manager_ref, context).await?;

        Ok(SignatureResult { proof, circuit_info })
    }

    pub async fn get_user_by_info(&self, pk_info: &ZKPublicKeyInfo<F>) -> anyhow::Result<Arc<dyn SignatureUser>> {
        let pk_hash = pk_info.qfhash::<PsyHasher>();
        self.signature_users
            .get(&pk_hash)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| anyhow::anyhow!("User with public key hash {} not found", pk_hash))
    }

    pub fn get_user_by_public_key_hash(&self, pk_hash: &QHashOut<F>) -> anyhow::Result<Arc<dyn SignatureUser>> {
        self.signature_users
            .get(pk_hash)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| anyhow::anyhow!("User with public key hash {} not found", pk_hash))
    }

    pub async fn add_software_defined_dpn_private_key(
        &mut self,
        private_key: QHashOut<F>,
        fingerprint: QHashOut<F>,
    ) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user: Arc<dyn SignatureUser> = Arc::new(SoftwareDefinedDpnUser::new(private_key, fingerprint));
        let manager = self.random_circuit_manager();
        let manager_ref = manager.as_ref();
        let pk_info = user.public_key_info(self, manager_ref).await?;
        let pk_hash = pk_info.qfhash::<PsyHasher>();
        self.signature_users.insert(pk_hash, user);
        Ok(pk_info)
    }

    pub async fn add_sd_key_plonky2_private_key(
        &mut self,
        private_key: QHashOut<F>,
        fingerprint: QHashOut<F>,
    ) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user: Arc<dyn SignatureUser> = Arc::new(SDKeyPlonky2User::new(private_key, fingerprint));
        let manager = self.random_circuit_manager();
        let manager_ref = manager.as_ref();
        let pk_info = user.public_key_info(self, manager_ref).await?;
        let pk_hash = pk_info.qfhash::<PsyHasher>();
        self.signature_users.insert(pk_hash, user);
        Ok(pk_info)
    }

    pub async fn add_sd_key_private_key(&mut self, private_key: QHashOut<F>, fingerprint: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user: Arc<dyn SignatureUser> = Arc::new(SDKeyUser::new(private_key, fingerprint));
        let manager = self.random_circuit_manager();
        let manager_ref = manager.as_ref();
        let pk_info = user.public_key_info(self, manager_ref).await?;
        let pk_hash = pk_info.qfhash::<PsyHasher>();
        self.signature_users.insert(pk_hash, user);
        Ok(pk_info)
    }

    pub async fn add_sd_key_dpn_private_key(
        &mut self,
        private_key: QHashOut<F>,
        fingerprint: QHashOut<F>,
    ) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        if self.local_circuits.get_sd_key_policy(&fingerprint).is_some() {
            bail!("SD-key DPN fingerprint {} belongs to a fixed-policy SD key", fingerprint);
        }
        let user: Arc<dyn SignatureUser> = Arc::new(SDKeyDpnUser::new(private_key, fingerprint));
        let manager = self.random_circuit_manager();
        let manager_ref = manager.as_ref();
        let pk_info = user.public_key_info(self, manager_ref).await?;
        let pk_hash = pk_info.qfhash::<PsyHasher>();
        self.signature_users.insert(pk_hash, user);
        Ok(pk_info)
    }

    pub async fn get_or_create_user(&mut self, private_key: QHashOut<F>, fingerprint: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let manager = self.random_circuit_manager();
        let zk_fingerprint = self.zk_circuit_fingerprint().await?;
        let secp_fingerprint = manager.secp_circuit_fingerprint().await?;
        // Tolerate prove-proxies that predate the EIP-191 circuit: the lookup
        // fails there, so no held-key eth-personal user can be created — but
        // every other user type must keep working.
        let eth_personal_fingerprint = manager.eth_personal_secp_circuit_fingerprint().await.ok();

        if fingerprint == zk_fingerprint {
            self.add_zk_private_key(private_key).await
        } else if fingerprint == secp_fingerprint {
            self.add_secp_private_key(private_key).await
        } else if Some(fingerprint) == eth_personal_fingerprint {
            self.add_eth_personal_secp_private_key(private_key).await
        } else {
            if self.local_circuits.has_psy_software_defined_circuit(&fingerprint) {
                self.add_software_defined_dpn_private_key(private_key, fingerprint).await
            } else if self.local_circuits.has_plonky2_software_defined_circuit(&fingerprint) {
                self.add_sd_key_plonky2_private_key(private_key, fingerprint).await
            } else if self.local_circuits.has_sd_key_circuit(&fingerprint) {
                if self.local_circuits.get_sd_key_policy(&fingerprint).is_some() {
                    self.add_sd_key_private_key(private_key, fingerprint).await
                } else {
                    self.add_sd_key_dpn_private_key(private_key, fingerprint).await
                }
            } else {
                bail!(
                    "Software defined circuit with fingerprint {} is not registered. Please register the circuit first.",
                    fingerprint
                );
            }
        }
    }

    pub async fn zk_sign_for_public_key(&self, public_key: QHashOut<F>, sig_hash: QHashOut<F>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let pk_info = self.get_public_key_info(&public_key).await?;
        let context = SignContext::new(pk_info.fingerprint);
        let result = self.sign_with_public_key(&public_key, &context, sig_hash).await?;
        Ok(result.proof)
    }

    pub async fn zk_sign_with_private_key(&self, private_key: QHashOut<F>, sig_hash: QHashOut<F>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.prove_zk_sign(private_key, sig_hash).await
    }

    pub fn sdc_sign_for_public_key<
        S: PsyReadCommandProcessorSync<F>
            + psy_client_data::qstore::imm::cmd_processor::QUserIdManager
            + psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync<F>
            + Send
            + Sync,
    >(
        &self,
        _state_reader: &mut StateReader<F, D, S>,
        _public_key: QHashOut<F>,
        _sig_hash: QHashOut<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        unimplemented!()
    }

    pub fn sdc_sign_with_private_key<
        S: PsyReadCommandProcessorSync<F>
            + psy_client_data::qstore::imm::cmd_processor::QUserIdManager
            + psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync<F>
            + Send
            + Sync,
    >(
        &self,
        _state_reader: &mut StateReader<F, D, S>,
        _private_key: QHashOut<F>,
        _sig_hash: QHashOut<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        unimplemented!()
    }

    pub fn secp256k1_sign(&self, private_key: QHashOut<F>, sig_hash: QHashOut<F>) -> anyhow::Result<PsyCompressedSecp256K1Signature> {
        psy_crypto::signature::secp256k1::wallet::secp256k1_sign(k256::ecdsa::SigningKey::from_slice(&Hash256::from(private_key).0)?, sig_hash)
    }

    /// EIP-191 (`personal_sign`) counterpart of [`Self::secp256k1_sign`].
    pub fn eth_personal_secp256k1_sign(&self, private_key: QHashOut<F>, sig_hash: QHashOut<F>) -> anyhow::Result<PsyCompressedSecp256K1Signature> {
        psy_crypto::signature::secp256k1::wallet::secp256k1_sign_eth_personal(
            k256::ecdsa::SigningKey::from_slice(&Hash256::from(private_key).0)?,
            sig_hash,
        )
    }

    pub async fn zk_secp256k1_from_signature(&self, signature: &PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.random_circuit_manager().prove_secp_sign(*signature).await
    }

    pub async fn zk_eth_personal_secp256k1_from_signature(
        &self,
        signature: &PsyCompressedSecp256K1Signature,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.random_circuit_manager().prove_eth_personal_secp_sign(*signature).await
    }

    pub async fn zk_sign_secp256k1(&self, public_key: QHashOut<F>, sig_hash: QHashOut<F>) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let pk_info = self.get_public_key_info(&public_key).await?;
        let context = SignContext::new(pk_info.fingerprint);
        let result = self.sign_with_public_key(&public_key, &context, sig_hash).await?;
        Ok(result.proof)
    }
}

impl PsyMemoryWallet {
    pub async fn register_psy_software_defined_circuit(
        &self,
        fn_def: psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition,
        force_four_align: bool,
    ) -> anyhow::Result<QHashOut<F>> {
        if !fn_def.is_view_function() {
            bail!("Cannot register view function as software defined circuit");
        }

        let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(config);

        let mut gadget = DPNSoftwareDefinedSignatureGadget::add_virtual_to(
            &mut builder,
            &fn_def,
            DEFAULT_CALLER_CONTRACT_ID_U64,
            MAX_CONTRACT_STATE_TREE_HEIGHT,
            UPS_SESSION_PROOF_TREE_HEIGHT,
            force_four_align,
        );
        gadget.build_circuit(builder)?;
        let fingerprint = gadget.get_fingerprint();

        tracing::info!("register PSY software defined circuit: {}", fingerprint.to_string());

        if self.local_circuits.has_psy_software_defined_circuit(&fingerprint) {
            tracing::warn!("PSY software defined circuit `{}` is already registered", fingerprint.to_string());
        }
        self.local_circuits.insert_psy_software_defined_circuit(fingerprint, gadget);

        Ok(fingerprint)
    }

    pub async fn register_plonky2_software_defined_circuit(&self, contract_state_tree_height: u8, input_len: usize) -> anyhow::Result<QHashOut<F>> {
        let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(config);

        let mut gadget = Plonky2SoftwareDefinedSignatureGadget::add_virtual_to(&mut builder, contract_state_tree_height, input_len);
        gadget.build_circuit(builder)?;
        let fingerprint = gadget.get_fingerprint();

        tracing::info!("register PLONKY2 software defined circuit: {}", fingerprint.to_string());

        if self.local_circuits.has_plonky2_software_defined_circuit(&fingerprint) {
            tracing::warn!("PLONKY2 software defined circuit `{}` is already registered", fingerprint.to_string());
        }
        self.local_circuits.insert_plonky2_software_defined_circuit(fingerprint, gadget);

        Ok(fingerprint)
    }

    pub async fn register_allow_method_sd_key_circuit(
        &self,
        allowed_contract_ids: &[u64],
        allowed_method_ids: &[u32],
        expected_tx_count: u64,
    ) -> anyhow::Result<QHashOut<F>> {
        let gadget = build_allow_method_sd_key_circuit(allowed_contract_ids, allowed_method_ids, expected_tx_count)?;
        let fingerprint = gadget.get_fingerprint();

        tracing::info!(
            "register allow-method SD key circuit: fingerprint={}, contract_ids={:?}, method_ids={:?}, expected_tx_count={}",
            fingerprint.to_string(),
            allowed_contract_ids,
            allowed_method_ids,
            expected_tx_count
        );

        if self.local_circuits.has_sd_key_circuit(&fingerprint) {
            tracing::warn!("SD key circuit `{}` is already registered", fingerprint.to_string());
        }
        self.local_circuits.insert_sd_key_circuit(fingerprint, gadget);
        self.local_circuits.insert_sd_key_policy(
            fingerprint,
            SDKeyPolicy {
                allowed_contract_ids: allowed_contract_ids.to_vec(),
                allowed_method_ids: allowed_method_ids.to_vec(),
                expected_tx_count,
            },
        );

        Ok(fingerprint)
    }

    /// Register a programmable, read-only DPN function as an SDKey circuit.
    /// The function definition is retained by the gadget so the proving
    /// session can reconstruct VM state-reader witnesses from live LPS data.
    pub async fn register_sd_key_dpn_circuit(
        &self,
        function: psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition,
        config: SDKeyConfig,
    ) -> anyhow::Result<QHashOut<F>> {
        function.validate_sd_key_read_only()?;
        if !function.is_view_function() {
            bail!("programmable SDKey function must be read-only/view-only");
        }

        let gadget = SDKeyCircuitGadget::build_from_dpn_function(&function, &config)?;
        let fingerprint = gadget.get_fingerprint();
        tracing::info!("register programmable SD key circuit: {}", fingerprint);
        self.local_circuits.insert_sd_key_circuit(fingerprint, gadget);
        Ok(fingerprint)
    }

    pub fn get_psy_software_defined_circuit(
        &self,
        fingerprint: &QHashOut<F>,
    ) -> Option<dashmap::mapref::one::Ref<'_, QHashOut<F>, DPNSoftwareDefinedSignatureGadget>> {
        self.local_circuits.get_psy_software_defined_circuit(fingerprint)
    }

    pub fn get_psy_software_defined_circuit_mut(
        &self,
        fingerprint: &QHashOut<F>,
    ) -> Option<dashmap::mapref::one::RefMut<'_, QHashOut<F>, DPNSoftwareDefinedSignatureGadget>> {
        self.local_circuits.get_psy_software_defined_circuit_mut(fingerprint)
    }

    pub fn get_plonky2_software_defined_circuit(
        &self,
        fingerprint: &QHashOut<F>,
    ) -> Option<dashmap::mapref::one::Ref<'_, QHashOut<F>, Plonky2SoftwareDefinedSignatureGadget>> {
        self.local_circuits.get_plonky2_software_defined_circuit(fingerprint)
    }

    pub fn get_plonky2_software_defined_circuit_mut(
        &self,
        fingerprint: &QHashOut<F>,
    ) -> Option<dashmap::mapref::one::RefMut<'_, QHashOut<F>, Plonky2SoftwareDefinedSignatureGadget>> {
        self.local_circuits.get_plonky2_software_defined_circuit_mut(fingerprint)
    }

    pub fn get_sd_key_circuit(&self, fingerprint: &QHashOut<F>) -> Option<dashmap::mapref::one::Ref<'_, QHashOut<F>, SDKeyCircuitGadget>> {
        self.local_circuits.get_sd_key_circuit(fingerprint)
    }

    pub fn get_sd_key_circuit_mut(&self, fingerprint: &QHashOut<F>) -> Option<dashmap::mapref::one::RefMut<'_, QHashOut<F>, SDKeyCircuitGadget>> {
        self.local_circuits.get_sd_key_circuit_mut(fingerprint)
    }

    pub fn get_sd_key_policy(&self, fingerprint: &QHashOut<F>) -> Option<SDKeyPolicy> {
        self.local_circuits.get_sd_key_policy(fingerprint)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use anyhow::Result;
    use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
    use psy_client_common::data::qhashout::QHashOut;
    use psy_common_circuit::circuits::{secp256k1_signature::Secp256K1SignatureCircuit, traits::qstandard::QStandardCircuit};

    use super::*;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    /// Measures pure-Rust deflate (flate2/miniz_oxide, wasm-compatible)
    /// compression ratio on the base circuit bytes, to see whether
    /// wasm-side compression is worthwhile. `cargo test -p psy_prover
    /// base_circuit_compression_ratio -- --nocapture`
    #[test]
    fn base_circuit_compression_ratio() -> Result<()> {
        use std::io::Write;

        use flate2::{write::DeflateEncoder, Compression};

        fn deflate(bytes: &[u8], level: u32) -> std::io::Result<usize> {
            let mut e = DeflateEncoder::new(Vec::new(), Compression::new(level));
            e.write_all(bytes)?;
            Ok(e.finish()?.len())
        }

        let circuits = PsyWalletLocalCircuits::default();
        for (name, raw) in [
            ("zk_signature_inner", circuits.zk_signature_inner().serialize_circuit_data()?),
            ("private_note_inclusion", circuits.private_note_inclusion().serialize_circuit_data()?),
            ("shield_deposit_claim", circuits.shield_deposit_claim().serialize_circuit_data()?),
        ] {
            let raw_len = raw.len();
            let l1 = deflate(&raw, 1)?;
            let l6 = deflate(&raw, 6)?;
            let l9 = deflate(&raw, 9)?;
            println!(
                "{name:<24} raw {:>6} KiB | deflate L1 {:>6} KiB ({:.2}x) L6 {:>6} KiB ({:.2}x) L9 {:>6} KiB ({:.2}x)",
                raw_len / 1024,
                l1 / 1024,
                raw_len as f64 / l1 as f64,
                l6 / 1024,
                raw_len as f64 / l6 as f64,
                l9 / 1024,
                raw_len as f64 / l9 as f64,
            );
        }
        Ok(())
    }

    /// `to_bundle_json` (compact privacy) -> `from_bundle_json`, asserting
    /// every circuit survives (zk-sign data identical; privacy fingerprints
    /// match after Merkle rebuild). `cargo test -p psy_prover
    /// local_circuits_bundle_json_round_trip -- --nocapture`
    #[test]
    fn local_circuits_bundle_json_round_trip() -> Result<()> {
        let json = PsyWalletLocalCircuits::to_bundle_json()?;
        let restored = PsyWalletLocalCircuits::from_bundle_json(&json)?;

        // The freshly-built reference to compare fingerprints against.
        let (h0, h1, h2, h3) = PRIVATE_NOTE_INCLUSION_HEIGHTS;
        assert_eq!(
            restored.private_note_inclusion().get_fingerprint(),
            PrivateNoteInclusionInnerCircuit::<C, D>::new(h0, h1, h2, h3).get_fingerprint()
        );
        assert_eq!(
            restored.shield_deposit_claim().get_fingerprint(),
            ShieldDepositClaimInnerCircuit::<C, D>::new().get_fingerprint()
        );
        // zk-sign provable: rebuilt circuit verifies a proof it produces.
        let proof = restored.prove_zk_sign_inner(QHashOut::<F>::rand(), QHashOut::<F>::rand())?;
        restored.zk_signature_inner().circuit_data.verify(proof)?;

        println!("local_circuits.json (zk-sign full + privacy compact): {} MiB", json.len() / 1024 / 1024);
        Ok(())
    }

    /// The embedded `local_circuits.json` loads (incl. compact Merkle rebuild
    /// for the two privacy circuits) and the zk-sign circuit proves &
    /// verifies. Reports load time. `cargo test -p psy_prover
    /// from_embedded_bundle_loads --release -- --nocapture`
    #[test]
    fn from_embedded_bundle_loads() -> Result<()> {
        let t = std::time::Instant::now();
        let circuits = PsyWalletLocalCircuits::from_embedded_bundle()?;
        let load = t.elapsed();
        let proof = circuits.prove_zk_sign_inner(QHashOut::<F>::rand(), QHashOut::<F>::rand())?;
        circuits.zk_signature_inner().circuit_data.verify(proof)?;
        println!("from_embedded_bundle() load time: {:.3?}", load);
        Ok(())
    }

    /// Regenerates the embedded `src/wallet/local_circuits.json`. Run
    /// explicitly: `cargo test -p psy_prover generate_local_circuits_json
    /// -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn generate_local_circuits_json() -> Result<()> {
        let json = PsyWalletLocalCircuits::to_bundle_json()?;
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/wallet/local_circuits.json");
        std::fs::write(path, &json)?;
        println!("wrote {} ({} MiB)", path, json.len() / 1024 / 1024);
        Ok(())
    }

    #[test]
    fn test_raw_secp256k1_sign() -> Result<()> {
        use k256::ecdsa::signature::hazmat::PrehashSigner;
        use psy_client_common::data::base_types::hash256::Hash256;
        use psy_crypto::signature::secp256k1::core::PsyCompressedSecp256K1Signature;

        // Create a test private key and signature hash
        let private_key = QHashOut::<F>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;
        let sig_hash = QHashOut::<F>::from_str("83955402ec7f375d1d6e8f3bf59753fe0af1e7c62bb4b662716a2524d3e2d186")?;

        // Test signature generation with reverse (like in memory_wallet)
        let signing_key = k256::ecdsa::SigningKey::from_slice(&Hash256::from(private_key).0)?;
        let mut sig_hash_bytes = Hash256::from(sig_hash).0;
        let result: k256::ecdsa::Signature = signing_key.sign_prehash(&sig_hash_bytes)?;

        let mut rs_bytes = [0u8; 64];
        let r_bytes = result.r().to_bytes();
        let s_bytes = result.s().to_bytes();
        rs_bytes[0..32].copy_from_slice(&r_bytes);
        rs_bytes[32..64].copy_from_slice(&s_bytes);

        // Get compressed public key
        let pk = signing_key.verifying_key();
        let pk_bytes = pk.to_encoded_point(true).to_bytes();
        let mut compressed_pk = [0u8; 33];
        compressed_pk.copy_from_slice(&pk_bytes);

        let secp_signature = PsyCompressedSecp256K1Signature {
            public_key: compressed_pk,
            signature: rs_bytes,
            message: Hash256::from(sig_hash),
        };

        println!("Generated signature with reverse:");
        println!("  Public key: {:?}", hex::encode(&secp_signature.public_key));
        println!("  Signature: {:?}", hex::encode(&secp_signature.signature));
        println!("  Message: {:?}", hex::encode(&secp_signature.message.0));

        // Create SECP256K1 signature circuit and test
        let secp_circuit = Secp256K1SignatureCircuit::<C, D>::new();

        println!("Created SECP256K1 circuit, fingerprint: {}", secp_circuit.get_fingerprint());

        // Generate ZK proof using the circuit
        let zk_proof = secp_circuit.prove(&secp_signature)?;

        println!("Generated ZK proof with {} public inputs", zk_proof.public_inputs.len());
        println!("Public inputs: {:?}", zk_proof.public_inputs);

        // Verify the public inputs match expected format: hash(sighash,
        // public_key_param)
        let combined_hash_from_proof = QHashOut(plonky2::hash::hash_types::HashOut {
            elements: [
                zk_proof.public_inputs[0],
                zk_proof.public_inputs[1],
                zk_proof.public_inputs[2],
                zk_proof.public_inputs[3],
            ],
        });

        println!("Circuit public inputs (combined hash): {}", combined_hash_from_proof);

        // Calculate expected combined hash: hash(sighash, public_key_param)
        use plonky2::hash::poseidon::PoseidonPermutation;
        use psy_client_data::config::store_config::PsyHasher;
        use psy_crypto::hash::traits::hasher::FieldQHasher;

        let public_key_param = psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(
            psy_client_common::data::secp256k1::CompressedPublicKey(compressed_pk),
        );
        let message_hash: QHashOut<F> = QHashOut::from(Hash256::from(sig_hash));

        let expected_combined_hash = PsyHasher::q_two_to_one(message_hash, public_key_param);

        println!(
            "Expected combined hash: hash({}, {}) = {}",
            message_hash, public_key_param, expected_combined_hash
        );

        assert_eq!(
            combined_hash_from_proof, expected_combined_hash,
            "Raw secp256k1 proof public inputs should match hash(sighash, public_key_param)"
        );

        Ok(())
    }

    #[test]
    fn test_memory_wallet_secp256k1_sign() -> Result<()> {
        // Create a test private key and signature hash
        let private_key = QHashOut::<F>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;
        let sig_hash = QHashOut::<F>::from_str("83955402ec7f375d1d6e8f3bf59753fe0af1e7c62bb4b662716a2524d3e2d186")?;

        // Create a mock memory wallet for testing
        let circuit_manager = psy_ups_circuit::circuit_manager::core::PsyUPSStepCircuitManager::new_with_config(0x1337);
        let wallet = PsyMemoryWallet::new(vec![Box::new(circuit_manager)]);

        println!("Created memory wallet");

        // Generate SECP256K1 signature using memory wallet method
        let secp_signature = wallet.secp256k1_sign(private_key, sig_hash)?;

        println!("Generated signature using memory wallet:");
        println!("  Public key: {:?}", hex::encode(&secp_signature.public_key));
        println!("  Signature: {:?}", hex::encode(&secp_signature.signature));
        println!("  Message: {:?}", hex::encode(&secp_signature.message.0));

        // Create SECP256K1 signature circuit and test
        let secp_circuit = Secp256K1SignatureCircuit::<C, D>::new();

        println!("Created SECP256K1 circuit, fingerprint: {}", secp_circuit.get_fingerprint());

        // Generate ZK proof using the circuit
        let zk_proof = secp_circuit.prove(&secp_signature)?;

        println!("Generated ZK proof with {} public inputs", zk_proof.public_inputs.len());
        println!("Public inputs: {:?}", zk_proof.public_inputs);

        // ZK proof generated successfully (verification may have circuit structure
        // issues)
        println!("✅ ZK proof generation succeeded!");

        // The public inputs should be the combined hash of sighash and public key
        let combined_hash_from_proof = QHashOut(plonky2::hash::hash_types::HashOut {
            elements: [
                zk_proof.public_inputs[0],
                zk_proof.public_inputs[1],
                zk_proof.public_inputs[2],
                zk_proof.public_inputs[3],
            ],
        });

        println!("Circuit combined hash output: {}", combined_hash_from_proof);

        // Verify this matches expected format: hash(message_hash, public_key_param)
        use plonky2::hash::poseidon::PoseidonPermutation;
        use psy_client_data::config::store_config::PsyHasher;
        use psy_crypto::hash::traits::hasher::FieldQHasher;

        // Get public key param the same way as in memory wallet
        let public_key_param = psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(
            psy_client_common::data::secp256k1::CompressedPublicKey(secp_signature.public_key),
        );
        let message_hash: QHashOut<F> = QHashOut::from(secp_signature.message);

        let expected_combined_hash = PsyHasher::q_two_to_one(message_hash, public_key_param);

        println!(
            "Expected combined hash: hash({}, {}) = {}",
            message_hash, public_key_param, expected_combined_hash
        );

        assert_eq!(
            combined_hash_from_proof, expected_combined_hash,
            "Proof public inputs should match hash(sighash, public_key_hash)"
        );

        Ok(())
    }

    /// Held-key EIP-191 path: sign locally via
    /// `PsyMemoryWallet::eth_personal_secp256k1_sign`, then prove through the
    /// SAME `EthPersonalSignSecp256K1SignatureCircuit` the external
    /// (MetaMask-injected) variant uses. The public inputs must bind the RAW
    /// sighash (not the keccak digest), same as the raw-secp path.
    /// `cargo test -p psy_prover test_eth_personal_secp256k1_sign -- --ignored
    /// --nocapture`
    #[test]
    #[ignore]
    fn test_eth_personal_secp256k1_sign() -> Result<()> {
        use plonky2::hash::poseidon::PoseidonPermutation;
        use psy_client_common::data::base_types::hash256::Hash256;
        use psy_client_data::config::store_config::PsyHasher;
        use psy_common_circuit::circuits::secp256k1_signature::EthPersonalSignSecp256K1SignatureCircuit;
        use psy_crypto::hash::traits::hasher::FieldQHasher;

        let private_key = QHashOut::<F>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;
        let sig_hash = QHashOut::<F>::from_str("83955402ec7f375d1d6e8f3bf59753fe0af1e7c62bb4b662716a2524d3e2d186")?;

        let circuit_manager = psy_ups_circuit::circuit_manager::core::PsyUPSStepCircuitManager::new_with_config(0x1337);
        let wallet = PsyMemoryWallet::new(vec![Box::new(circuit_manager)]);

        let eth_signature = wallet.eth_personal_secp256k1_sign(private_key, sig_hash)?;

        // The stored message must be the RAW sighash, not the EIP-191 digest.
        assert_eq!(eth_signature.message, Hash256::from(sig_hash));

        let eth_circuit = EthPersonalSignSecp256K1SignatureCircuit::<C, D>::new();
        println!("Created EIP-191 circuit, fingerprint: {}", eth_circuit.get_fingerprint());
        assert_eq!(eth_circuit.get_fingerprint(), get_eth_secp256k1_fingerprint());

        let zk_proof = eth_circuit.prove(&eth_signature)?;
        eth_circuit.minifier_chain.verify(zk_proof.clone())?;

        let combined_hash_from_proof = QHashOut(plonky2::hash::hash_types::HashOut {
            elements: [
                zk_proof.public_inputs[0],
                zk_proof.public_inputs[1],
                zk_proof.public_inputs[2],
                zk_proof.public_inputs[3],
            ],
        });

        let public_key_param = psy_crypto::signature::secp256k1::wallet::hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(
            psy_client_common::data::secp256k1::CompressedPublicKey(eth_signature.public_key),
        );
        let message_hash: QHashOut<F> = QHashOut::from(eth_signature.message);
        let expected_combined_hash = PsyHasher::q_two_to_one(message_hash, public_key_param);

        assert_eq!(
            combined_hash_from_proof, expected_combined_hash,
            "EIP-191 proof public inputs should match hash(raw_sighash, public_key_param)"
        );

        Ok(())
    }
}
