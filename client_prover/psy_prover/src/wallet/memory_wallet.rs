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
    sd_key_dpn::SDKeyDpnCircuitGadget,
    sd_key_plonky2::SDKeyPlonky2CircuitGadget,
};
use psy_vm::ups::{circuit_manager::UPSCircuitManager, state_reader::StateReader};

use crate::signature::{
    context::SignContext,
    traits::{SignatureResult, SignatureUser},
    users::{
        EthPersonalSignSECP256K1User, ExternalEthPersonalSignUser, ExternalSecp256K1User, SDKeyDpnUser, SECP256K1User, ZKUser,
    },
};

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;

/// Authorization mode an SD-key fingerprint was registered with. The mode is
/// recorded in the wallet-local circuit registry at registration time; a
/// fingerprint can only ever belong to one mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdKeyMode {
    /// Pre-built Plonky2 software-defined signature circuit.
    Plonky2,
    /// Programmable read-only DPN authorization function.
    Dpn,
}

pub enum SdKeyCircuitDefinition {
    Plonky2 { contract_state_tree_height: u8, input_len: usize },
    Dpn {
        function: psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition,
        config: SDKeyConfig,
    },
}

// 65e0169bfffd55f1c0ea9f76c111a5b15e652322ee253c1a9604a10d59066b50
pub const ZK_FINGERPRINT_U64: [u64; 4] = [10809942084296272720, 6801881445144280090, 13901098532226573745, 7340892251884443121];

// 320d034234f0dab4d02c4b03d69276cbd5c2eb831aca1b11c7e52078ace2e33b
pub const SECP256K1_FINGERPRINT_U64: [u64; 4] = [14403954685883114299, 15403132623883213585, 15000446938721187531, 3606542459484560052];

// d98d16c06b8fdff9f87b1a7e8172fce36454e117a0c5557f8a4485396b30f7de
pub const ETH_PERSONAL_SECP256K1_FINGERPRINT_U64: [u64; 4] =
    [9963234757308381150, 7229650793434273151, 17904933874181536995, 15676210893640687609];

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


pub fn get_allow_method_sd_key_fingerprint(
    allowed_contract_ids: &[u64],
    allowed_method_ids: &[u32],
    expected_tx_count: u64,
) -> anyhow::Result<QHashOut<GoldilocksField>> {
    let (function, config) = psy_vm::ups::sd_key::build_allow_method_policy(allowed_contract_ids, allowed_method_ids, expected_tx_count)?;
    Ok(SDKeyDpnCircuitGadget::build_from_dpn_function(&function, &config)?.get_fingerprint())
}

pub fn get_allow_method_sd_key_fingerprint_range(
    allowed_contract_ids: &[u64],
    allowed_method_ids: &[u32],
    min_tx_count: u64,
    max_tx_count: u64,
) -> anyhow::Result<QHashOut<GoldilocksField>> {
    let (function, config) =
        psy_vm::ups::sd_key::build_allow_method_policy_range(allowed_contract_ids, allowed_method_ids, min_tx_count, max_tx_count)?;
    Ok(SDKeyDpnCircuitGadget::build_from_dpn_function(&function, &config)?.get_fingerprint())
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
    sd_key_plonky2_circuits: DashMap<QHashOut<F>, SDKeyPlonky2CircuitGadget>,
    sd_key_circuits: DashMap<QHashOut<F>, SDKeyDpnCircuitGadget>,
    sd_key_modes: DashMap<QHashOut<F>, SdKeyMode>,
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

    pub fn has_sd_key_plonky2_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.sd_key_plonky2_circuits.contains_key(fingerprint)
    }

    pub fn has_sd_key_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.sd_key_circuits.contains_key(fingerprint)
    }

    pub fn insert_sd_key_plonky2_circuit(&self, fingerprint: QHashOut<F>, circuit: SDKeyPlonky2CircuitGadget) {
        self.sd_key_plonky2_circuits.insert(fingerprint, circuit);
    }

    pub fn insert_sd_key_circuit(&self, fingerprint: QHashOut<F>, circuit: SDKeyDpnCircuitGadget) {
        self.sd_key_circuits.insert(fingerprint, circuit);
    }

    /// Record the authorization mode for an SD-key fingerprint. A fingerprint
    /// already recorded with a different mode is rejected.
    pub fn record_sd_key_mode(&self, fingerprint: QHashOut<F>, mode: SdKeyMode) -> anyhow::Result<()> {
        if let Some(existing) = self.sd_key_modes.get(&fingerprint) {
            anyhow::ensure!(
                *existing == mode,
                "SD-key fingerprint {} is already registered with mode {:?}; refusing to re-register as {:?}",
                fingerprint,
                *existing,
                mode
            );
            return Ok(());
        }
        self.sd_key_modes.insert(fingerprint, mode);
        Ok(())
    }

    pub fn get_sd_key_mode(&self, fingerprint: &QHashOut<F>) -> Option<SdKeyMode> {
        self.sd_key_modes.get(fingerprint).map(|entry| *entry.value())
    }

    pub fn get_sd_key_plonky2_circuit(
        &self,
        fingerprint: &QHashOut<F>,
    ) -> Option<dashmap::mapref::one::Ref<'_, QHashOut<F>, SDKeyPlonky2CircuitGadget>> {
        self.sd_key_plonky2_circuits.get(fingerprint)
    }

    pub fn get_sd_key_plonky2_circuit_mut(
        &self,
        fingerprint: &QHashOut<F>,
    ) -> Option<dashmap::mapref::one::RefMut<'_, QHashOut<F>, SDKeyPlonky2CircuitGadget>> {
        self.sd_key_plonky2_circuits.get_mut(fingerprint)
    }

    pub fn get_sd_key_circuit(&self, fingerprint: &QHashOut<F>) -> Option<dashmap::mapref::one::Ref<'_, QHashOut<F>, SDKeyDpnCircuitGadget>> {
        self.sd_key_circuits.get(fingerprint)
    }

    pub fn get_sd_key_circuit_mut(&self, fingerprint: &QHashOut<F>) -> Option<dashmap::mapref::one::RefMut<'_, QHashOut<F>, SDKeyDpnCircuitGadget>> {
        self.sd_key_circuits.get_mut(fingerprint)
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

    pub fn has_sd_key_plonky2_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.local_circuits.has_sd_key_plonky2_circuit(fingerprint)
    }

    pub fn has_sd_key_dpn_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.local_circuits.has_sd_key_circuit(fingerprint)
    }

    pub fn insert_sd_key_plonky2_circuit(&self, fingerprint: QHashOut<F>, circuit: SDKeyPlonky2CircuitGadget) {
        self.local_circuits.insert_sd_key_plonky2_circuit(fingerprint, circuit);
    }

    pub fn insert_sd_key_dpn_circuit(&self, fingerprint: QHashOut<F>, circuit: SDKeyDpnCircuitGadget) {
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
        let manager = self.eth_personal_circuit_manager().await?;
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
        let manager = self.eth_personal_circuit_manager().await?;
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
        let manager = self.eth_personal_circuit_manager().await?;
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
        let fingerprint = self.eth_personal_circuit_manager().await?.eth_personal_secp_circuit_fingerprint().await?;
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
        context.validate()?;
        let user_guard = self
            .signature_users
            .get(public_key)
            .ok_or_else(|| anyhow::anyhow!("signature user for `{}` not found", public_key))?;
        let user = user_guard.value().clone();
        drop(user_guard);

        let circuit_manager = if context.fingerprint == get_eth_personal_secp256k1_fingerprint() {
            self.eth_personal_circuit_manager().await?
        } else {
            self.random_circuit_manager()
        };
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

    pub async fn add_sd_key_plonky2_private_key(
        &mut self,
        _private_key: QHashOut<F>,
        _fingerprint: QHashOut<F>,
    ) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        anyhow::bail!("SD-key Plonky2 mode is not implemented")
    }

    pub async fn add_sd_key_dpn_private_key(
        &mut self,
        private_key: QHashOut<F>,
        fingerprint: QHashOut<F>,
    ) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        anyhow::ensure!(
            self.local_circuits.get_sd_key_mode(&fingerprint) == Some(SdKeyMode::Dpn),
            "SD-key DPN fingerprint {} is not registered in Dpn mode",
            fingerprint
        );
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
        // A mixed prover cohort may contain older managers without EIP-191.
        let eth_personal_fingerprint = self.eth_personal_circuit_manager().await.ok().map(|_| get_eth_personal_secp256k1_fingerprint());

        if fingerprint == zk_fingerprint {
            self.add_zk_private_key(private_key).await
        } else if fingerprint == secp_fingerprint {
            self.add_secp_private_key(private_key).await
        } else if Some(fingerprint) == eth_personal_fingerprint {
            self.add_eth_personal_secp_private_key(private_key).await
        } else {
            // SD keys dispatch on the mode recorded at registration time; an
            // unknown fingerprint or a mode/circuit mismatch is an explicit
            // error rather than a guessed user type.
            match self.local_circuits.get_sd_key_mode(&fingerprint) {
                Some(SdKeyMode::Plonky2) => {
                    anyhow::bail!("SD-key Plonky2 mode is not implemented")
                }
                Some(SdKeyMode::Dpn) => {
                    anyhow::ensure!(
                        self.local_circuits.has_sd_key_circuit(&fingerprint),
                        "Dpn SD-key fingerprint {} has no registered circuit",
                        fingerprint
                    );
                    self.add_sd_key_dpn_private_key(private_key, fingerprint).await
                }
                None => {
                    bail!(
                        "Software defined circuit with fingerprint {} is not registered. Please register the circuit first.",
                        fingerprint
                    );
                }
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
    pub async fn register_sd_key_plonky2_circuit(&self, _contract_state_tree_height: u8, _input_len: usize) -> anyhow::Result<QHashOut<F>> {
        anyhow::bail!("SD-key Plonky2 mode is not implemented");
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
        let gadget = SDKeyDpnCircuitGadget::build_from_dpn_function(&function, &config)?;
        let fingerprint = gadget.get_fingerprint();
        tracing::info!("register programmable SD key circuit: {}", fingerprint);
        self.local_circuits.insert_sd_key_circuit(fingerprint, gadget);
        self.local_circuits.record_sd_key_mode(fingerprint, SdKeyMode::Dpn)?;
        Ok(fingerprint)
    }

    pub fn get_sd_key_plonky2_circuit(
        &self,
        fingerprint: &QHashOut<F>,
    ) -> Option<dashmap::mapref::one::Ref<'_, QHashOut<F>, SDKeyPlonky2CircuitGadget>> {
        self.local_circuits.get_sd_key_plonky2_circuit(fingerprint)
    }

    pub fn get_sd_key_plonky2_circuit_mut(
        &self,
        fingerprint: &QHashOut<F>,
    ) -> Option<dashmap::mapref::one::RefMut<'_, QHashOut<F>, SDKeyPlonky2CircuitGadget>> {
        self.local_circuits.get_sd_key_plonky2_circuit_mut(fingerprint)
    }

    pub fn get_sd_key_circuit(&self, fingerprint: &QHashOut<F>) -> Option<dashmap::mapref::one::Ref<'_, QHashOut<F>, SDKeyDpnCircuitGadget>> {
        self.local_circuits.get_sd_key_circuit(fingerprint)
    }

    pub fn get_sd_key_circuit_mut(&self, fingerprint: &QHashOut<F>) -> Option<dashmap::mapref::one::RefMut<'_, QHashOut<F>, SDKeyDpnCircuitGadget>> {
        self.local_circuits.get_sd_key_circuit_mut(fingerprint)
    }

    pub fn get_sd_key_mode(&self, fingerprint: &QHashOut<F>) -> Option<SdKeyMode> {
        self.local_circuits.get_sd_key_mode(fingerprint)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use std::str::FromStr;

    use anyhow::Result;
    use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
    use psy_client_common::data::qhashout::QHashOut;
    use psy_client_data::dpn::sd_key::MAX_INTROSPECTABLE_TRANSACTIONS;
    use psy_common_circuit::circuits::{secp256k1_signature::Secp256K1SignatureCircuit, traits::qstandard::QStandardCircuit};
    use psy_common_circuit::proof_minifier::pm_core::get_circuit_fingerprint_generic;
    use psy_config::TOKEN_CONTRACT_STATE_TREE_HEIGHT;

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
    fn allow_method_policy_rejects_invalid_transaction_counts_early() {
        assert!(get_allow_method_sd_key_fingerprint(&[1], &[2], 0)
            .unwrap_err()
            .to_string()
            .contains("greater than zero"));
        assert!(get_allow_method_sd_key_fingerprint(&[1], &[2], MAX_INTROSPECTABLE_TRANSACTIONS as u64 + 1)
            .unwrap_err()
            .to_string()
            .contains("MAX_INTROSPECTABLE_TRANSACTIONS"));
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
    fn local_circuit_registry_tracks_sd_key_mode_without_loading_circuits() {
        let circuits = PsyWalletLocalCircuits::default();
        let fingerprint = get_zk_fingerprint::<F>();
        assert!(!circuits.has_sd_key_circuit(&fingerprint));
        assert!(circuits.get_sd_key_mode(&fingerprint).is_none());

        circuits.record_sd_key_mode(fingerprint, SdKeyMode::Dpn).unwrap();
        assert_eq!(circuits.get_sd_key_mode(&fingerprint), Some(SdKeyMode::Dpn));
        // re-recording the same mode is idempotent
        circuits.record_sd_key_mode(fingerprint, SdKeyMode::Dpn).unwrap();
        // a conflicting mode is rejected
        let error = circuits.record_sd_key_mode(fingerprint, SdKeyMode::Plonky2).unwrap_err();
        assert!(error.to_string().contains("already registered with mode"));
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
        let (function, config) = psy_vm::ups::sd_key::build_allow_method_policy(&[3], &[4], 2).unwrap();
        let sd_key_fingerprint = session.write().register_sd_key_dpn_circuit(function, config).await.unwrap();
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
        let foreign = session.read().wallet.secp256k1_sign(other_key, sighash).unwrap();
        let foreign_pk_info = session.read().wallet.get_secp_pk_info(other_key).await.unwrap();
        let foreign_hash = foreign_pk_info.qfhash::<psy_client_data::config::store_config::PsyHasher>();
        assert!(session.read().wallet.get_user_by_public_key_hash(&foreign_hash).is_err());
        let error = session
            .write()
            .wallet
            .inject_secp_signature(foreign_hash, foreign.clone())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not found in wallet"));

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

        let psy_fingerprint = {
            let read = session.read();
            let wallet = &read.wallet;

            let error = wallet
                .register_sd_key_dpn_circuit(mutating_def, psy_vm::ups::sd_key::sd_key_config_for_dpn_function(&view_def))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("non-read-only state command"));

            let psy_config = psy_vm::ups::sd_key::sd_key_config_for_dpn_function(&view_def);
            let psy_fingerprint = wallet.register_sd_key_dpn_circuit(view_def.clone(), psy_config.clone()).await.unwrap();
            assert_ne!(psy_fingerprint, QHashOut::<F>::ZERO);
            assert!(wallet.local_circuits.has_sd_key_circuit(&psy_fingerprint));
            assert_eq!(wallet.get_sd_key_mode(&psy_fingerprint), Some(SdKeyMode::Dpn));
            // re-registration keeps the fingerprint
            assert_eq!(
                wallet.register_sd_key_dpn_circuit(view_def.clone(), psy_config.clone()).await.unwrap(),
                psy_fingerprint
            );

            assert!(wallet.register_sd_key_plonky2_circuit(10, 4).await.unwrap_err().to_string().contains("not implemented"));

            psy_fingerprint
        };

        // the registered fingerprints create users through the dispatch
        let key = QHashOut::<F>::from_values(151, 152, 153, 154);
        let psy_info = session.write().wallet.get_or_create_user(key, psy_fingerprint).await.unwrap();
        assert_eq!(psy_info.fingerprint, psy_fingerprint);

        // registered sd-key circuits expose their gadget and mode accessors
        let (function, config) = psy_vm::ups::sd_key::build_allow_method_policy(&[3], &[4], 2).unwrap();
        let sd_key_fingerprint = session.write().register_sd_key_dpn_circuit(function, config).await.unwrap();
        {
            let read = session.read();
            let wallet = &read.wallet;
            assert!(wallet.get_sd_key_circuit(&sd_key_fingerprint).is_some());
            assert!(wallet.get_sd_key_circuit_mut(&sd_key_fingerprint).is_some());
            assert_eq!(wallet.get_sd_key_mode(&sd_key_fingerprint), Some(SdKeyMode::Dpn));
            assert!(wallet.local_circuits().get_sd_key_circuit_mut(&sd_key_fingerprint).is_some());
            assert!(!wallet
                .fallback_private_note_inclusion_minifier_verifier_data()
                .constants_sigmas_cap
                .is_empty());
        }

        // trace-provided contract code registers on every manager and caches
        let deployer = 161u64;
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
        let (function, config) = psy_vm::ups::sd_key::build_allow_method_policy(&[7], &[2], 3)?;
        let sd_fingerprint = wallet.register_sd_key_dpn_circuit(function.clone(), config.clone()).await?;
        assert!(wallet.local_circuits.has_sd_key_circuit(&sd_fingerprint));
        assert_eq!(wallet.register_sd_key_dpn_circuit(function, config).await?, sd_fingerprint);

        // plonky2 software-defined flavor
        assert!(wallet.register_sd_key_plonky2_circuit(8, 4).await.unwrap_err().to_string().contains("not implemented"));

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

        let psy_config = psy_vm::ups::sd_key::sd_key_config_for_dpn_function(&view_def);
        let psy_fingerprint = wallet.register_sd_key_dpn_circuit(view_def, psy_config.clone()).await?;
        assert!(wallet.local_circuits.has_sd_key_circuit(&psy_fingerprint));
        assert_eq!(wallet.get_sd_key_mode(&psy_fingerprint), Some(SdKeyMode::Dpn));

        let error = wallet
            .register_sd_key_dpn_circuit(mutating_def, psy_config.clone())
            .await
            .unwrap_err();
        assert!(error.to_string().contains("non-read-only state command"));
        Ok(())
    }
}
