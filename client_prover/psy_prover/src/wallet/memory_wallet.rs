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
use psy_client_common::data::{
    alt::AltVerifierOnlyCircuitData, base_types::hash256::Hash256, qhashout::QHashOut, secp256k1::CompressedPublicKey,
};
use psy_client_data::{
    config::store_config::PsyHasher,
    dpn::sd_key::SDKeyConfig,
    privacy::{deposit_inclusion::DepositInclusionInput, private_note_inclusion::PrivateNoteInclusionInput},
    qdata::contract::ContractCodeDefinition,
    qstore::imm::cmd_processor::PsyReadCommandProcessorSync,
};
use psy_common_circuit::{
    circuits::{
        traits::qstandard::QStandardCircuit,
        zk_signature3::core::{PsyBasicZKSignatureCircuit, PsyBasicZKSignatureInnerCircuit},
    },
    proof_minifier::pm_core::get_circuit_fingerprint_generic,
};
use psy_config::network_constants::{
    DEFAULT_CALLER_CONTRACT_ID_U64, GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, MAX_CONTRACT_STATE_TREE_HEIGHT, PRIVATE_NOTE_TREE_HEIGHT,
    TOKEN_CONTRACT_STATE_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT,
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
        EthPersonalSignSECP256K1User, ExternalEthPersonalSignUser, ExternalSecp256K1User, SDKeyUser, SECP256K1User, SoftwareDefinedDpnUser,
        SoftwareDefinedPlonky2User, ZKUser,
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
pub const ETH_PERSONAL_SECP256K1_FINGERPRINT_U64: [u64; 4] =
    [11893467277170771781, 15629858611769664357, 5241938694879225188, 5545361160027968854];

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

pub fn get_eth_personal_secp256k1_fingerprint<F: RichField>() -> QHashOut<F> {
    QHashOut(HashOut {
        elements: ETH_PERSONAL_SECP256K1_FINGERPRINT_U64.map(F::from_canonical_u64),
    })
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
    };

    let mut gadget = SDKeyCircuitGadget::add_virtual_to(&mut builder, &sd_config, 0);
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
    } else if fingerprint == get_secp256k1_fingerprint() || fingerprint == get_eth_personal_secp256k1_fingerprint() {
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
                TOKEN_CONTRACT_STATE_TREE_HEIGHT as usize,
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
    TOKEN_CONTRACT_STATE_TREE_HEIGHT as usize,
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

    pub(crate) async fn eth_personal_circuit_manager(&self) -> anyhow::Result<&Box<dyn UPSCircuitManager<C, D> + Send + Sync>> {
        let expected_fingerprint = get_eth_personal_secp256k1_fingerprint();
        for manager in &self.circuit_manager {
            if manager.eth_personal_secp_circuit_fingerprint().await.ok() != Some(expected_fingerprint) {
                continue;
            }
            if manager.eth_personal_secp_circuit_verifier_config().await.is_ok() {
                return Ok(manager);
            }
        }
        anyhow::bail!("no prove manager exposes the expected EIP-191 circuit metadata")
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
    /// Held-key counterpart of [`Self::register_external_eth_personal_user`].
    pub async fn add_eth_personal_secp_private_key(&mut self, private_key: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user: Arc<dyn SignatureUser> = Arc::new(EthPersonalSignSECP256K1User::new(private_key));
        let pk_info = user.public_key_info(self, self.eth_personal_circuit_manager().await?.as_ref()).await?;
        self.signature_users.insert(pk_info.qfhash::<PsyHasher>(), user);
        Ok(pk_info)
    }

    /// Mode-A (web/MetaMask): install a classic-secp user PK-first — ONLY the
    /// compressed public key, no signature yet. Enough for on-chain
    /// registration and trace generation. Proving (`sign()`) fails until
    /// the entry is replaced via [`Self::inject_secp_signature`] with a
    /// MetaMask signature over the session sighash.
    pub async fn register_external_secp_user(&mut self, compressed_public_key: CompressedPublicKey) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user: Arc<dyn SignatureUser> = Arc::new(ExternalSecp256K1User::new(compressed_public_key)?);
        let pk_info = user.public_key_info(self, self.random_circuit_manager().as_ref()).await?;
        self.signature_users.insert(pk_info.qfhash::<PsyHasher>(), user);
        Ok(pk_info)
    }
    /// Install an EIP-191 external user PK-first using the compatible proving cohort.
    pub async fn register_external_eth_personal_user(
        &mut self,
        compressed_public_key: CompressedPublicKey,
    ) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user: Arc<dyn SignatureUser> = Arc::new(ExternalEthPersonalSignUser::new(compressed_public_key)?);
        let pk_info = user.public_key_info(self, self.eth_personal_circuit_manager().await?.as_ref()).await?;
        self.signature_users.insert(pk_info.qfhash::<PsyHasher>(), user);
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
        let user: Arc<dyn SignatureUser> = Arc::new(ExternalSecp256K1User::with_signature(signature)?);
        self.replace_external_signature_user(expected_public_key, user, "secp256k1").await
    }
    /// Replace a registered EIP-191 PK-only user with a validated signature user.
    pub async fn inject_eth_personal_signature(
        &mut self,
        expected_public_key: QHashOut<F>,
        signature: PsyCompressedSecp256K1Signature,
    ) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user: Arc<dyn SignatureUser> = Arc::new(ExternalEthPersonalSignUser::with_signature(signature)?);
        if !self.signature_users.contains_key(&expected_public_key) {
            bail!("registered external EIP-191 user `{}` not found in wallet", expected_public_key);
        }
        let pk_info = {
            let manager = self.eth_personal_circuit_manager().await?;
            user.public_key_info(self, manager.as_ref()).await?
        };
        let actual_public_key = pk_info.qfhash::<PsyHasher>();
        if actual_public_key != expected_public_key {
            bail!(
                "injected EIP-191 signature belongs to public key `{}`, expected `{}`",
                actual_public_key,
                expected_public_key
            );
        }
        self.signature_users.insert(expected_public_key, user);
        Ok(pk_info)
    }

    async fn replace_external_signature_user(
        &mut self,
        expected_public_key: QHashOut<F>,
        user: Arc<dyn SignatureUser>,
        label: &str,
    ) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        if !self.signature_users.contains_key(&expected_public_key) {
            bail!("registered external {} user `{}` not found in wallet", label, expected_public_key);
        }
        let pk_info = user.public_key_info(self, self.random_circuit_manager().as_ref()).await?;
        let actual_public_key = pk_info.qfhash::<PsyHasher>();
        if actual_public_key != expected_public_key {
            bail!(
                "injected {} signature belongs to public key `{}`, expected `{}`",
                label,
                actual_public_key,
                expected_public_key
            );
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

    /// EIP-191 (`personal_sign`) counterpart of [`Self::get_secp_pk_info`].
    pub async fn get_eth_personal_secp_pk_info(&self, private_key: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let public_key = get_secp_public_key(private_key)?;
        Ok(ZKPublicKeyInfo {
            fingerprint: self.eth_personal_circuit_manager().await?.eth_personal_secp_circuit_fingerprint().await?,
            public_key_param: hash_no_pad_compressed_public_key::<F, PoseidonPermutation<F>>(public_key),
        })
    }

    pub async fn get_public_key_info(&self, public_key: &QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user_guard = self
            .signature_users
            .get(public_key)
            .ok_or_else(|| anyhow::anyhow!("public key `{}` not found in wallet", public_key))?;
        let user = user_guard.value().clone();
        drop(user_guard);
        let mut last_error = None;
        for manager in &self.circuit_manager {
            match user.public_key_info(self, manager.as_ref()).await {
                Ok(info) => return Ok(info),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("wallet has no prove managers")))
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

        let manager = if context.fingerprint == get_eth_personal_secp256k1_fingerprint() {
            self.eth_personal_circuit_manager().await?
        } else {
            self.random_circuit_manager()
        };
        let manager_ref = manager.as_ref();

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

    pub async fn add_software_defined_plonky2_private_key(
        &mut self,
        private_key: QHashOut<F>,
        fingerprint: QHashOut<F>,
    ) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user: Arc<dyn SignatureUser> = Arc::new(SoftwareDefinedPlonky2User::new(private_key, fingerprint));
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
                self.add_software_defined_plonky2_private_key(private_key, fingerprint).await
            } else if self.local_circuits.has_sd_key_circuit(&fingerprint) {
                self.add_sd_key_private_key(private_key, fingerprint).await
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
    pub fn eth_personal_secp256k1_sign(
        &self,
        private_key: QHashOut<F>,
        sig_hash: QHashOut<F>,
    ) -> anyhow::Result<PsyCompressedSecp256K1Signature> {
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
        self.eth_personal_circuit_manager().await?.prove_eth_personal_secp_sign(*signature).await
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
#[cfg_attr(coverage_nightly, coverage(off))]
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

    #[test]
    fn built_in_fingerprints_are_distinct_and_stable() {
        let zk = get_zk_fingerprint::<F>();
        let secp = get_secp256k1_fingerprint::<F>();
        let personal = get_eth_personal_secp256k1_fingerprint::<F>();

        assert_ne!(zk, secp);
        assert_ne!(zk, personal);
        assert_ne!(secp, personal);
        assert_eq!(zk.0.elements, ZK_FINGERPRINT_U64.map(F::from_canonical_u64));
        assert_eq!(secp.0.elements, SECP256K1_FINGERPRINT_U64.map(F::from_canonical_u64));
        assert_eq!(personal.0.elements, ETH_PERSONAL_SECP256K1_FINGERPRINT_U64.map(F::from_canonical_u64));
    }

    #[test]
    fn allowed_contract_method_pairs_support_zip_and_broadcast() {
        assert_eq!(allowed_contract_method_pairs(&[1, 2], &[10, 20]).unwrap(), vec![(1, 10), (2, 20)]);
        assert_eq!(allowed_contract_method_pairs(&[7], &[10, 20]).unwrap(), vec![(7, 10), (7, 20)]);
        assert_eq!(allowed_contract_method_pairs(&[1, 2], &[99]).unwrap(), vec![(1, 99), (2, 99)]);
    }

    #[test]
    fn allowed_contract_method_pairs_reject_invalid_shapes() {
        assert!(allowed_contract_method_pairs(&[], &[1])
            .unwrap_err()
            .to_string()
            .contains("contract_id list"));
        assert!(allowed_contract_method_pairs(&[1], &[])
            .unwrap_err()
            .to_string()
            .contains("method_id list"));
        assert!(allowed_contract_method_pairs(&[1, 2], &[3, 4, 5])
            .unwrap_err()
            .to_string()
            .contains("same length"));
    }

    #[test]
    fn allow_method_circuit_rejects_invalid_transaction_counts_early() {
        assert!(build_allow_method_sd_key_circuit(&[1], &[2], 0)
            .unwrap_err()
            .to_string()
            .contains("greater than zero"));
        assert!(build_allow_method_sd_key_circuit(&[1], &[2], u32::MAX as u64 + 1)
            .unwrap_err()
            .to_string()
            .contains("exceeds u32 range"));
    }

    #[test]
    fn circuit_bundle_fields_round_trip_and_reject_invalid_base64() {
        let encoded = encode_circuit_field(&[0, 1, 2, 254, 255]);
        assert_eq!(decode_circuit_field(&encoded).unwrap(), vec![0, 1, 2, 254, 255]);
        assert!(decode_circuit_field("not-base64!").is_err());
    }

    #[test]
    fn public_key_info_supports_zk_and_secp_builtin_fingerprints() -> Result<()> {
        let private_key = QHashOut::<F>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;
        let zk = get_public_key_info(private_key, get_zk_fingerprint())?;
        let secp = get_public_key_info(private_key, get_secp256k1_fingerprint())?;
        let personal = get_public_key_info(private_key, get_eth_personal_secp256k1_fingerprint())?;

        assert_eq!(zk.fingerprint, get_zk_fingerprint());
        assert_eq!(secp.fingerprint, get_secp256k1_fingerprint());
        assert_eq!(personal.fingerprint, get_eth_personal_secp256k1_fingerprint());
        assert_ne!(zk.public_key_param, secp.public_key_param);
        assert_eq!(secp.public_key_param, personal.public_key_param);
        Ok(())
    }

    #[test]
    fn local_circuit_registry_tracks_sd_key_policy_without_loading_circuits() {
        let circuits = PsyWalletLocalCircuits::default();
        let fingerprint = get_zk_fingerprint::<F>();
        assert!(!circuits.has_sd_key_circuit(&fingerprint));
        assert!(circuits.get_sd_key_policy(&fingerprint).is_none());

        circuits.insert_sd_key_policy(
            fingerprint,
            SDKeyPolicy {
                allowed_contract_ids: vec![7, 8],
                allowed_method_ids: vec![11],
                expected_tx_count: 2,
            },
        );
        let policy = circuits.get_sd_key_policy(&fingerprint).unwrap();
        assert_eq!(policy.allowed_contract_ids, vec![7, 8]);
        assert_eq!(policy.allowed_method_ids, vec![11]);
        assert_eq!(policy.expected_tx_count, 2);
    }

    #[test]
    fn empty_wallet_reports_missing_user_by_public_key_hash() {
        let wallet = PsyMemoryWallet::new(Vec::new());
        let missing = get_zk_fingerprint::<F>();
        assert!(wallet
            .get_user_by_public_key_hash(&missing)
            .unwrap_err()
            .to_string()
            .contains("not found"));
    }

    #[test]
    fn allow_method_fingerprint_helper_builds_the_circuit() -> Result<()> {
        let fingerprint = get_allow_method_sd_key_fingerprint(&[5], &[6], 1)?;
        assert_ne!(fingerprint, QHashOut::<F>::ZERO);
        Ok(())
    }

    #[test]
    fn bundle_loader_rejects_malformed_json() {
        assert!(PsyWalletLocalCircuits::from_bundle_json("not json").is_err());
    }

    #[tokio::test]
    async fn wallet_manages_held_key_and_external_users_offline() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let key = QHashOut::<F>::from_values(201, 202, 203, 204);
        let other_key = QHashOut::<F>::from_values(205, 206, 207, 208);
        let sighash = QHashOut::<F>::from_values(9, 9, 9, 9);

        let (zk_fingerprint, secp_fingerprint, eth_personal_fingerprint) = {
            let read = session.read();
            let wallet = &read.wallet;
            let manager = wallet.random_circuit_manager();
            (
                wallet.zk_circuit_fingerprint().await.unwrap(),
                manager.secp_circuit_fingerprint().await.unwrap(),
                manager.eth_personal_secp_circuit_fingerprint().await.unwrap(),
            )
        };

        // get_or_create_user dispatches by fingerprint across the held-key types
        let zk_info = session.write().wallet.get_or_create_user(key, zk_fingerprint).await.unwrap();
        let secp_info = session.write().wallet.get_or_create_user(key, secp_fingerprint).await.unwrap();
        let eth_info = session.write().wallet.get_or_create_user(key, eth_personal_fingerprint).await.unwrap();
        assert_eq!(zk_info.fingerprint, zk_fingerprint);
        assert_eq!(secp_info.fingerprint, secp_fingerprint);
        assert_eq!(eth_info.fingerprint, eth_personal_fingerprint);
        assert_ne!(zk_info.public_key_param, secp_info.public_key_param);
        assert_eq!(secp_info.public_key_param, eth_info.public_key_param);

        // sd-key users dispatch through the registered sd-key circuit
        let sd_key_fingerprint = session.write().register_sd_key_circuit(&[3], &[4], 2).await.unwrap();
        let sd_key_info = session.write().wallet.get_or_create_user(key, sd_key_fingerprint).await.unwrap();
        assert_eq!(sd_key_info.fingerprint, sd_key_fingerprint);

        // unregistered software-defined fingerprints are rejected
        let error = session
            .write()
            .wallet
            .get_or_create_user(key, QHashOut::from_values(77, 77, 77, 77))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("is not registered"));

        // the per-type pk-info getters agree with the dispatch results
        {
            let read = session.read();
            let wallet = &read.wallet;
            assert_eq!(wallet.get_zk_pk_info(key).await.unwrap().public_key_param, zk_info.public_key_param);
            assert_eq!(wallet.get_secp_pk_info(key).await.unwrap().public_key_param, secp_info.public_key_param);
            assert_eq!(
                wallet.get_eth_personal_secp_pk_info(key).await.unwrap().public_key_param,
                eth_info.public_key_param
            );
        }

        // registered users resolve by info, hash, and public key
        {
            let read = session.read();
            let wallet = &read.wallet;
            let zk_hash = zk_info.qfhash::<psy_client_data::config::store_config::PsyHasher>();
            assert!(wallet.get_user_by_info(&zk_info).await.is_ok());
            assert!(wallet.get_user_by_public_key_hash(&zk_hash).is_ok());
            assert_eq!(wallet.get_public_key_info(&zk_hash).await.unwrap().fingerprint, zk_fingerprint);
            assert!(wallet
                .get_user_by_info(&ZKPublicKeyInfo {
                    fingerprint: zk_fingerprint,
                    public_key_param: QHashOut::ZERO,
                })
                .await
                .is_err());
            assert!(wallet.get_public_key_info(&QHashOut::ZERO).await.is_err());
        }

        // raw secp signing stays offline and feeds the external-user injection
        let compressed = psy_crypto::signature::secp256k1::wallet::get_secp_public_key::<F>(key).unwrap();
        let (external_info, personal_external) = {
            let mut write = session.write();
            let external_info = write.wallet.register_external_secp_user(compressed).await.unwrap();
            let personal_external = write.wallet.register_external_eth_personal_user(compressed).await.unwrap();
            (external_info, personal_external)
        };
        let external_hash = external_info.qfhash::<psy_client_data::config::store_config::PsyHasher>();
        let personal_hash = personal_external.qfhash::<psy_client_data::config::store_config::PsyHasher>();

        let signature = session.read().wallet.secp256k1_sign(key, sighash).unwrap();
        let error = session
            .write()
            .wallet
            .inject_secp_signature(QHashOut::ZERO, signature.clone())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not found in wallet"));

        let foreign = session.read().wallet.secp256k1_sign(other_key, sighash).unwrap();
        let error = session.write().wallet.inject_secp_signature(external_hash, foreign).await.unwrap_err();
        assert!(error.to_string().contains("belongs to public key"));

        let injected = session.write().wallet.inject_secp_signature(external_hash, signature).await.unwrap();
        assert_eq!(injected.public_key_param, external_info.public_key_param);

        // EIP-191 raw signing round-trips through the same wallet surface
        let personal = session.read().wallet.eth_personal_secp256k1_sign(key, sighash).unwrap();
        assert_eq!(personal.message.0, psy_client_common::data::base_types::hash256::Hash256::from(sighash).0);

        // signing through the wallet dispatches per fingerprint and fails
        // cleanly for unknown users or missing external signatures
        {
            let read = session.read();
            let wallet = &read.wallet;
            let zk_hash = zk_info.qfhash::<psy_client_data::config::store_config::PsyHasher>();
            let proof = wallet.zk_sign_for_public_key(zk_hash, sighash).await.unwrap();
            assert!(!proof.proof.wires_cap.0.is_empty());
            assert!(wallet.zk_sign_with_private_key(key, sighash).await.is_ok());
            assert!(wallet
                .sign_with_public_key(&QHashOut::ZERO, &SignContext::new(zk_fingerprint), sighash)
                .await
                .is_err());
            assert!(wallet.zk_sign_secp256k1(QHashOut::ZERO, sighash).await.is_err());

            // the eth-personal manager selection path fails before proving on
            // the PK-only external user (no signature injected yet)
            let error = wallet
                .sign_with_public_key(&personal_hash, &SignContext::new(get_eth_personal_secp256k1_fingerprint()), sighash)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("signature missing"));
        }

        // privacy fallback minifier metadata is available offline
        {
            let read = session.read();
            let wallet = &read.wallet;
            assert_ne!(wallet.fallback_private_note_inclusion_minifier_fingerprint(), QHashOut::ZERO);
            assert!(!wallet
                .local_circuits()
                .private_note_inclusion_verifier_data()
                .constants_sigmas_cap
                .is_empty());
        }
    }

    const VIEW_AND_MUTATE_CONTRACT: &str = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub value: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn set_value(&mut self, ctx: &ChainContext, new_value: Felt) {
                self.value = new_value;
            }

            #[contract_method]
            pub fn get_value(&mut self, ctx: &ChainContext) -> Felt {
                return self.value;
            }
        }
    "#;

    #[tokio::test]
    async fn wallet_registers_software_defined_and_contract_circuits() {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let output = psy_compiler::compile(VIEW_AND_MUTATE_CONTRACT).expect("contract should compile");
        let view_def = output
            .circuit_definitions
            .iter()
            .find(|def| def.is_view_function())
            .expect("getter should lower to a view function")
            .clone();
        let mutating_def = output
            .circuit_definitions
            .iter()
            .find(|def| !def.is_view_function())
            .expect("setter should lower to a mutating function")
            .clone();

        let (psy_fingerprint, plonky2_fingerprint) = {
            let read = session.read();
            let wallet = &read.wallet;

            let error = wallet.register_psy_software_defined_circuit(mutating_def, false).await.unwrap_err();
            assert!(error.to_string().contains("Cannot register view function"));

            let psy_fingerprint = wallet.register_psy_software_defined_circuit(view_def.clone(), false).await.unwrap();
            assert_ne!(psy_fingerprint, QHashOut::<F>::ZERO);
            assert!(wallet.has_psy_software_defined_circuit(&psy_fingerprint));
            // re-registration keeps the fingerprint and only warns
            assert_eq!(
                wallet.register_psy_software_defined_circuit(view_def.clone(), false).await.unwrap(),
                psy_fingerprint
            );

            let plonky2_fingerprint = wallet.register_plonky2_software_defined_circuit(10, 4).await.unwrap();
            assert_ne!(plonky2_fingerprint, QHashOut::<F>::ZERO);
            assert!(wallet.has_plonky2_software_defined_circuit(&plonky2_fingerprint));
            assert!(!wallet.has_plonky2_software_defined_circuit(&psy_fingerprint));
            assert_eq!(
                wallet.register_plonky2_software_defined_circuit(10, 4).await.unwrap(),
                plonky2_fingerprint
            );

            (psy_fingerprint, plonky2_fingerprint)
        };

        // the registered fingerprints create users through the dispatch
        let key = QHashOut::<F>::from_values(151, 152, 153, 154);
        let psy_info = session.write().wallet.get_or_create_user(key, psy_fingerprint).await.unwrap();
        assert_eq!(psy_info.fingerprint, psy_fingerprint);
        let plonky2_info = session.write().wallet.get_or_create_user(key, plonky2_fingerprint).await.unwrap();
        assert_eq!(plonky2_info.fingerprint, plonky2_fingerprint);

        // registered sd-key circuits expose their gadget and policy accessors
        let sd_key_fingerprint = session.write().register_sd_key_circuit(&[3], &[4], 2).await.unwrap();
        {
            let read = session.read();
            let wallet = &read.wallet;
            assert!(wallet.get_sd_key_circuit(&sd_key_fingerprint).is_some());
            assert!(wallet.get_sd_key_circuit_mut(&sd_key_fingerprint).is_some());
            let policy = wallet
                .get_sd_key_policy(&sd_key_fingerprint)
                .expect("allow-method sd key circuit carries its policy");
            assert_eq!(policy.expected_tx_count, 2);
            assert!(wallet.local_circuits().get_sd_key_circuit_mut(&sd_key_fingerprint).is_some());
            assert!(!wallet
                .fallback_private_note_inclusion_minifier_verifier_data()
                .constants_sigmas_cap
                .is_empty());
        }

        // trace-provided contract code registers on every manager and caches
        let deployer = QHashOut::<F>::from_values(161, 162, 163, 164);
        let contract_bytes = {
            let read = session.read();
            let update_cmd = read.get_update_contract_cmd(9001, deployer, output.circuit_definitions.clone()).unwrap();
            assert_eq!(update_cmd.contract_id, 9001);
            bincode::serialize(&update_cmd.code_definition).unwrap()
        };
        {
            let read = session.read();
            let wallet = &read.wallet;
            wallet.ensure_trace_contract_circuits_registered(9001, &contract_bytes).await.unwrap();
            // the second registration hits the byte cache without recompiling
            wallet.ensure_trace_contract_circuits_registered(9001, &contract_bytes).await.unwrap();
            assert!(wallet.ensure_trace_contract_circuits_registered(9001, &[1, 2, 3]).await.is_err());
        }
    }

    /// `prove_private_note_inclusion` proves through the local fallback when
    /// the circuit-manager proxy is unreachable: the dead-network session's
    /// manager call fails, so the in-process minifier chain re-wraps the base
    /// proof instead. The public input is the circuit's 16-value commitment
    /// hash: owner ‖ amount ‖ user_tree_root ‖ checkpoint ‖ slot ‖
    /// contract_id ‖ nullifier.
    #[tokio::test]
    async fn private_note_inclusion_proves_via_the_local_fallback_minifier() -> Result<()> {
        use psy_client_data::qdata::user::PsyUserLeaf;
        use psy_crypto::hash::{
            merkle::utils::simple_merkle_tree::SimpleMerkleTree,
            traits::hasher::FieldQHasher,
        };

        type OfflineTree = SimpleMerkleTree<PsyHasher, QHashOut<F>>;

        let nullifier_secret = QHashOut::from_values(31, 32, 33, 34);
        let note_secret = QHashOut::from_values(41, 42, 43, 44);
        let owner = QHashOut::from_values(51, 52, 53, 54);
        let amount = F::from_canonical_u64(777);
        let checkpoint_id = F::from_canonical_u64(33);

        // commitment = two_to_one(two_to_one(owner, [amount, 0, 0, 0]),
        // hash8(nullifier_secret ‖ note_secret))
        let value_hash = QHashOut(HashOut { elements: [amount, F::ZERO, F::ZERO, F::ZERO] });
        let inner_hash = PsyHasher::q_two_to_one(owner, value_hash);
        let note_commitment = PsyHasher::q_hash_many(
            &nullifier_secret
                .0
                .elements
                .iter()
                .chain(&note_secret.0.elements)
                .copied()
                .collect::<Vec<_>>(),
        );
        let commitment = PsyHasher::q_two_to_one(inner_hash, note_commitment);

        let note_index = 5u64;
        let mut note_tree = OfflineTree::new(PRIVATE_NOTE_TREE_HEIGHT as u8);
        note_tree.set_leaf(note_index, commitment);
        let note_membership_proof = note_tree.get_leaf(note_index);

        let note_root_slot = 3u64;
        let contract_id = 9u64;
        let mut state_tree = OfflineTree::new(TOKEN_CONTRACT_STATE_TREE_HEIGHT);
        state_tree.set_leaf(note_root_slot, note_membership_proof.root);
        let note_root_slot_proof = state_tree.get_leaf(note_root_slot);

        let mut user_state_tree = OfflineTree::new(GLOBAL_CONTRACT_TREE_HEIGHT);
        user_state_tree.set_leaf(contract_id, note_root_slot_proof.root);
        let contract_proof = user_state_tree.get_leaf(contract_id);

        let sender_user_id = 2u64;
        let user_leaf = PsyUserLeaf::new_user_default(
            F::from_canonical_u64(sender_user_id),
            QHashOut::from_values(61, 62, 63, 64),
            contract_proof.root,
        );
        let mut user_tree = OfflineTree::new(GLOBAL_USER_TREE_HEIGHT);
        user_tree.set_leaf(sender_user_id, user_leaf.qfhash::<PsyHasher>());
        let user_tree_proof = user_tree.get_leaf(sender_user_id);
        let user_tree_root = user_tree_proof.root;

        let input = PrivateNoteInclusionInput {
            nullifier_secret,
            sender_user_id,
            contract_id,
            user_leaf,
            owner,
            amount,
            note_secret,
            note_membership_proof,
            note_root_slot,
            note_root_slot_proof,
            contract_proof,
            user_tree_proof,
            checkpoint_id,
        };

        let session = crate::test_support::shared_offline_wallet_session().await;
        let (fingerprint, proof, _verifier) = session.read().wallet.prove_private_note_inclusion(&input).await?;
        assert_ne!(fingerprint, QHashOut::<F>::ZERO);

        let nullifier = PsyHasher::q_hash_many(&nullifier_secret.0.elements);
        let expected_public_inputs = PsyHasher::q_hash_many(
            &owner
                .0
                .elements
                .iter()
                .copied()
                .chain([amount])
                .chain(user_tree_root.0.elements)
                .chain([
                    checkpoint_id,
                    F::from_canonical_u64(note_root_slot),
                    F::from_canonical_u64(contract_id),
                ])
                .chain(nullifier.0.elements)
                .collect::<Vec<_>>(),
        );
        assert_eq!(proof.public_inputs.len(), 4);
        assert_eq!(proof.public_inputs, expected_public_inputs.0.elements.to_vec());
        Ok(())
    }

    /// `prove_shield_deposit_claim` walks the same fallback for the
    /// deposit-inclusion circuit. The 41-value deposit commitment follows the
    /// relayer leaf layout (u32 words, HIGH then LOW per field element); the
    /// 42-value public hash mixes the public metadata, deposit root/index,
    /// nullifier and note commitment.
    #[tokio::test]
    async fn shield_deposit_claim_proves_via_the_local_fallback_minifier() -> Result<()> {
        use plonky2::field::types::PrimeField64;
        use psy_crypto::hash::{
            merkle::utils::simple_merkle_tree::SimpleMerkleTree,
            traits::hasher::FieldQHasher,
        };

        type OfflineTree = SimpleMerkleTree<PsyHasher, QHashOut<F>>;

        // mirrors the deposit circuit's private DEPOSIT_TREE_HEIGHT constant
        const DEPOSIT_TREE_HEIGHT: u8 = psy_config::network_constants::GLOBAL_DEPOSIT_TREE_HEIGHT;

        let nullifier_secret =
            [F::from_canonical_u64(71), F::from_canonical_u64(72), F::from_canonical_u64(73), F::from_canonical_u64(74)];
        let note_secret =
            [F::from_canonical_u64(81), F::from_canonical_u64(82), F::from_canonical_u64(83), F::from_canonical_u64(84)];
        let shield_address = QHashOut::from_values(91, 92, 93, 94);
        let deposit_index = 6u64;
        let token_address = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let l2_token_contract_id = [9u32, 10, 11, 12, 13, 14, 15, 16];
        // words 0..6 are constrained to zero; the amount value lives in the
        // final (high, low) pair
        let amount_value: u64 = 9876543210;
        let amount = [0u32, 0, 0, 0, 0, 0, (amount_value >> 32) as u32, amount_value as u32];
        let source_chain_index = 3u32;

        let split_words = |hash: &QHashOut<F>| -> [F; 8] {
            std::array::from_fn(|i| {
                let value = hash.0.elements[i / 2].to_canonical_u64();
                if i % 2 == 0 {
                    F::from_canonical_u64(value >> 32)
                } else {
                    F::from_canonical_u64(value & 0xffffffff)
                }
            })
        };

        let nullifier_hash = PsyHasher::q_hash_many(&nullifier_secret);
        let note_commitment =
            PsyHasher::q_hash_many(&nullifier_secret.iter().chain(&note_secret).copied().collect::<Vec<_>>());
        let shield_words = split_words(&shield_address);
        let note_words = split_words(&note_commitment);

        let mut preimage = Vec::with_capacity(41);
        preimage.extend_from_slice(&shield_words);
        preimage.extend_from_slice(&token_address.iter().map(|word| F::from_canonical_u32(*word)).collect::<Vec<_>>());
        preimage
            .extend_from_slice(&l2_token_contract_id.iter().map(|word| F::from_canonical_u32(*word)).collect::<Vec<_>>());
        preimage.extend_from_slice(&amount.iter().map(|word| F::from_canonical_u32(*word)).collect::<Vec<_>>());
        preimage.push(F::from_canonical_u32(source_chain_index));
        preimage.extend_from_slice(&note_words);
        let deposit_commitment = PsyHasher::q_hash_many(&preimage);

        let mut deposit_tree = OfflineTree::new(DEPOSIT_TREE_HEIGHT);
        deposit_tree.set_leaf(deposit_index, deposit_commitment);
        let deposit_proof = deposit_tree.get_leaf(deposit_index);
        let deposit_root = deposit_proof.root;

        let input = DepositInclusionInput {
            nullifier_secret,
            note_secret,
            shield_address,
            deposit_index,
            token_address,
            l2_token_contract_id,
            amount,
            source_chain_index,
            deposit_root,
            deposit_proof,
        };

        let session = crate::test_support::shared_offline_wallet_session().await;
        let (fingerprint, proof, _verifier) = session.read().wallet.prove_shield_deposit_claim(&input).await?;
        assert_ne!(fingerprint, QHashOut::<F>::ZERO);

        let mut expected_preimage = Vec::with_capacity(42);
        expected_preimage.extend_from_slice(&shield_address.0.elements);
        expected_preimage.extend_from_slice(&amount.iter().map(|word| F::from_canonical_u32(*word)).collect::<Vec<_>>());
        expected_preimage.extend_from_slice(&token_address.iter().map(|word| F::from_canonical_u32(*word)).collect::<Vec<_>>());
        expected_preimage.extend_from_slice(&l2_token_contract_id.iter().map(|word| F::from_canonical_u32(*word)).collect::<Vec<_>>());
        expected_preimage.push(F::from_canonical_u32(source_chain_index));
        expected_preimage.extend_from_slice(&deposit_root.0.elements);
        expected_preimage.extend_from_slice(&nullifier_hash.0.elements);
        expected_preimage.extend_from_slice(&note_commitment.0.elements);
        expected_preimage.push(F::from_canonical_u64(deposit_index));
        let expected_public_inputs = PsyHasher::q_hash_many(&expected_preimage);

        assert_eq!(proof.public_inputs.len(), 4);
        assert_eq!(proof.public_inputs, expected_public_inputs.0.elements.to_vec());
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn local_circuit_disk_cache_round_trips_and_survives_corruption() {
        let name = format!(
            "test_lolc_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        );
        let path = local_circuit_cache_path(&name).expect("host cache dir should be available");

        let build = || 7u32;
        let load = |bytes: &[u8]| -> anyhow::Result<u32> {
            let text = String::from_utf8(bytes.to_vec())?;
            text.parse::<u32>().map_err(Into::into)
        };
        let serialize = |value: &u32| -> anyhow::Result<Vec<u8>> { Ok(value.to_string().into_bytes()) };

        // the first call builds the value and writes the cache
        assert_eq!(load_or_build_local_circuit(&name, build, load, serialize), 7);
        assert!(path.exists());

        // the second call loads from the cache without rebuilding
        assert_eq!(
            load_or_build_local_circuit(&name, || unreachable!("cache should hit"), load, serialize),
            7
        );

        // a corrupt cache falls back to a rebuild and rewrites the file
        std::fs::write(&path, b"garbage").unwrap();
        assert_eq!(load_or_build_local_circuit(&name, build, load, serialize), 7);

        // serialization failures only skip the cache write
        std::fs::remove_file(&path).unwrap();
        assert_eq!(
            load_or_build_local_circuit(&name, build, load, |_| -> anyhow::Result<Vec<u8>> {
                anyhow::bail!("serialization disabled")
            }),
            7
        );
        assert!(!path.exists());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn bundle_loader_rejects_version_mismatches() {
        let bad_version = serde_json::json!({
            "version": 999999,
            "zk_signature_inner": "",
            "private_note_inclusion": "",
            "shield_deposit_claim": ""
        })
        .to_string();
        let error = PsyWalletLocalCircuits::from_bundle_json(&bad_version)
            .err()
            .expect("bundle with wrong version should be rejected");
        assert!(error.to_string().contains("version mismatch"));
    }

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

    #[test]
    fn embedded_local_circuits_match_current_sources() -> Result<()> {
        let embedded = PsyWalletLocalCircuits::from_embedded_bundle()?;
        let (global_user_height, global_contract_height, contract_state_height, note_height) = PRIVATE_NOTE_INCLUSION_HEIGHTS;
        let current_private_note = PrivateNoteInclusionInnerCircuit::<C, D>::new(
            global_user_height,
            global_contract_height,
            contract_state_height,
            note_height,
        );
        let current_shield_deposit = ShieldDepositClaimInnerCircuit::<C, D>::new();
        let current_zk_signature = PsyBasicZKSignatureInnerCircuit::<C, D>::new();

        assert_eq!(
            get_circuit_fingerprint_generic(&embedded.zk_signature_inner().circuit_data.verifier_only),
            get_circuit_fingerprint_generic(&current_zk_signature.circuit_data.verifier_only),
            "embedded zk-signature circuit is stale; regenerate local_circuits.json",
        );
        assert_eq!(
            embedded.private_note_inclusion().get_fingerprint(),
            current_private_note.get_fingerprint(),
            "embedded private-note circuit is stale; regenerate local_circuits.json",
        );
        assert_eq!(
            embedded.shield_deposit_claim().get_fingerprint(),
            current_shield_deposit.get_fingerprint(),
            "embedded shield-deposit circuit is stale; regenerate local_circuits.json",
        );
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
        assert_eq!(eth_signature.message, Hash256::from(sig_hash));

        let eth_circuit = EthPersonalSignSecp256K1SignatureCircuit::<C, D>::new();
        println!("Created EIP-191 circuit, fingerprint: {}", eth_circuit.get_fingerprint());
        assert_eq!(eth_circuit.get_fingerprint(), get_eth_personal_secp256k1_fingerprint());

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

    /// The raw secp signing helpers bind the sighash into a compressed
    /// signature, and the signature-to-proof bridges turn either flavor into
    /// a verifiable plonky2 proof through the offline circuit manager.
    #[tokio::test]
    async fn raw_secp_sign_helpers_and_signature_proofs_round_trip() -> Result<()> {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let wallet = &session.read().wallet;

        let private_key = QHashOut::<F>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;
        let sig_hash = QHashOut::<F>::from_str("83955402ec7f375d1d6e8f3bf59753fe0af1e7c62bb4b662716a2524d3e2d186")?;

        let signature = wallet.secp256k1_sign(private_key, sig_hash)?;
        let personal = wallet.eth_personal_secp256k1_sign(private_key, sig_hash)?;
        assert_ne!(signature.signature, personal.signature);

        let proof = wallet.zk_secp256k1_from_signature(&signature).await?;
        assert!(proof.public_inputs.len() >= 4);
        let personal_proof = wallet.zk_eth_personal_secp256k1_from_signature(&personal).await?;
        assert!(personal_proof.public_inputs.len() >= 4);
        Ok(())
    }

    /// Software-defined circuit registration installs every flavor and the
    /// lookup helpers agree; only view functions are accepted for the psy
    /// software-defined flavor.
    #[tokio::test]
    async fn software_defined_circuits_register_and_report_their_fingerprints() -> Result<()> {
        let session = crate::test_support::shared_offline_wallet_session().await;
        let wallet = &session.read().wallet;

        // sd-key allow-method circuit: registering twice keeps the fingerprint
        let sd_fingerprint = wallet.register_allow_method_sd_key_circuit(&[7], &[2], 3).await?;
        assert!(wallet.has_sd_key_circuit(&sd_fingerprint));
        assert_eq!(wallet.register_allow_method_sd_key_circuit(&[7], &[2], 3).await?, sd_fingerprint);

        // plonky2 software-defined flavor
        let plonky2_fingerprint = wallet.register_plonky2_software_defined_circuit(8, 4).await?;
        assert!(wallet.has_plonky2_software_defined_circuit(&plonky2_fingerprint));

        // psy software-defined flavor needs a view function; the helper
        // contract's getter qualifies, its setter does not
        let source = r#"
            const PSY_TOTAL_USERS: usize = 4;
            const PSY_TOTAL_CONTRACTS: usize = 4;

            #[contract]
            pub struct WalletTestContract {
                pub value: Felt,
            }

            #[contract_implementation]
            impl WalletTestContract {
                #[contract_method]
                pub fn set_value(&mut self, ctx: &ChainContext, new_value: Felt) {
                    self.value = new_value;
                }

                #[contract_method]
                pub fn get_value(&mut self, ctx: &ChainContext) -> Felt {
                    return self.value;
                }
            }
        "#;
        let output = crate::session::compile_bridge::compile_contract_output(source)?;
        let view_def = output
            .circuit_definitions
            .iter()
            .find(|def| def.is_view_function())
            .cloned()
            .expect("the getter must compile to a view function");
        let mutating_def = output
            .circuit_definitions
            .iter()
            .find(|def| !def.is_view_function())
            .cloned()
            .expect("the setter must compile to a mutating function");

        let psy_fingerprint = wallet.register_psy_software_defined_circuit(view_def, false).await?;
        assert!(wallet.has_psy_software_defined_circuit(&psy_fingerprint));

        let error = wallet.register_psy_software_defined_circuit(mutating_def, false).await.unwrap_err();
        assert!(error.to_string().contains("Cannot register view function"));
        Ok(())
    }
}
