use std::sync::Arc;

use anyhow::bail;
use dashmap::DashMap;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::Field},
    hash::{
        hash_types::{HashOut, RichField},
        poseidon::{PoseidonHash, PoseidonPermutation},
    },
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut};
use psy_client_data::{config::store_config::PsyHasher, dpn::sdk_key::SDKKeyConfig, qstore::imm::cmd_processor::PsyReadCommandProcessorSync};
use psy_config::network_constants::{DEFAULT_CALLER_CONTRACT_ID_U64, MAX_CONTRACT_STATE_TREE_HEIGHT, UPS_SESSION_PROOF_TREE_HEIGHT};
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
use psy_ups_circuit::signature::{
    sdk_key::SDKKeyCircuitGadget,
    software_defined::{DPNSoftwareDefinedSignatureGadget, Plonky2SoftwareDefinedSignatureGadget},
};
use psy_vm::ups::{circuit_manager::UPSCircuitManager, state_reader::StateReader};

use crate::signature::{
    context::SignContext,
    traits::{SignatureResult, SignatureUser},
    users::{SDKKeyUser, SECP256K1User, SoftwareDefinedDpnUser, SoftwareDefinedPlonky2User, ZKUser},
};

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type F = GoldilocksField;

// 65e0169bfffd55f1c0ea9f76c111a5b15e652322ee253c1a9604a10d59066b50
pub const ZK_FINGERPRINT_U64: [u64; 4] = [10809942084296272720, 6801881445144280090, 13901098532226573745, 7340892251884443121];

// 320d034234f0dab4d02c4b03d69276cbd5c2eb831aca1b11c7e52078ace2e33b
pub const SECP256K1_FINGERPRINT_U64: [u64; 4] = [14403954685883114299, 15403132623883213585, 15000446938721187531, 3606542459484560052];

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

fn allowed_contract_method_pairs(allowed_contract_ids: &[u64], allowed_method_ids: &[u64]) -> anyhow::Result<Vec<(u64, u64)>> {
    if allowed_contract_ids.is_empty() {
        bail!("SDK key allowed contract_id list must not be empty");
    }
    if allowed_method_ids.is_empty() {
        bail!("SDK key allowed method_id list must not be empty");
    }

    if allowed_contract_ids.len() == allowed_method_ids.len() {
        return Ok(allowed_contract_ids
            .iter()
            .copied()
            .zip(allowed_method_ids.iter().copied())
            .collect());
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

    bail!(
        "SDK key allowed contract_id and method_id lists must have the same length, or one list must contain exactly one value"
    );
}

fn assert_contract_method_in_allowed_pairs(
    builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    contract_id_target: plonky2::iop::target::Target,
    method_id_target: plonky2::iop::target::Target,
    allowed_pairs: &[(u64, u64)],
) -> anyhow::Result<()> {
    if allowed_pairs.is_empty() {
        bail!("SDK key allowed contract/method pair list must not be empty");
    }

    let mut is_allowed = builder._false();
    for (contract_id, method_id) in allowed_pairs {
        let expected_contract_id = builder.constant(F::from_canonical_u64(*contract_id));
        let expected_method_id = builder.constant(F::from_canonical_u64(*method_id));
        let contract_matches = builder.is_equal(contract_id_target, expected_contract_id);
        let method_matches = builder.is_equal(method_id_target, expected_method_id);
        let pair_matches = builder.and(contract_matches, method_matches);
        is_allowed = builder.or(is_allowed, pair_matches);
    }
    builder.assert_one(is_allowed.target);

    Ok(())
}

fn build_allow_method_sdk_key_circuit(allowed_contract_ids: &[u64], allowed_method_ids: &[u64], expected_tx_count: u64) -> anyhow::Result<SDKKeyCircuitGadget> {
    if expected_tx_count == 0 {
        bail!("SDK key expected_tx_count must be greater than zero");
    }
    if expected_tx_count > u32::MAX as u64 {
        bail!("SDK key expected_tx_count exceeds u32 range: {}", expected_tx_count);
    }

    let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
    let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(config);
    let sdk_config = SDKKeyConfig {
        num_introspectable_transactions: expected_tx_count as u32,
        can_read_state: false,
        contract_state_tree_height: MAX_CONTRACT_STATE_TREE_HEIGHT,
        requires_secp256k1: false,
        num_secp256k1_slots: 0,
    };

    let mut gadget = SDKKeyCircuitGadget::add_virtual_to(&mut builder, &sdk_config, 0);
    let expected_tx_count_target = builder.constant(F::from_canonical_u64(expected_tx_count));
    let allowed_pairs = allowed_contract_method_pairs(allowed_contract_ids, allowed_method_ids)?;
    assert_contract_method_in_allowed_pairs(
        &mut builder,
        gadget.tx_introspection.get_tx_contract_id(0),
        gadget.tx_introspection.get_tx_method_id(0),
        &allowed_pairs,
    )?;
    builder.connect(gadget.tx_introspection.get_tx_count(), expected_tx_count_target);
    gadget.build_circuit(builder)?;
    Ok(gadget)
}

pub fn get_allow_method_sdk_key_fingerprint(
    allowed_contract_ids: &[u64],
    allowed_method_ids: &[u64],
    expected_tx_count: u64,
) -> anyhow::Result<QHashOut<GoldilocksField>> {
    Ok(build_allow_method_sdk_key_circuit(allowed_contract_ids, allowed_method_ids, expected_tx_count)?.get_fingerprint())
}

pub fn get_public_key_info<F: RichField>(private_key: QHashOut<F>, fingerprint: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
    let public_key_param = if fingerprint == get_zk_fingerprint() {
        SimplePsyPrivateKey::new(private_key).get_public_key_param::<PsyHasher>()
    } else if fingerprint == get_secp256k1_fingerprint() {
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
    psy_software_defined_circuits: DashMap<QHashOut<F>, DPNSoftwareDefinedSignatureGadget>,
    plonky2_software_defined_circuits: DashMap<QHashOut<F>, Plonky2SoftwareDefinedSignatureGadget>,
    sdk_key_circuits: DashMap<QHashOut<F>, SDKKeyCircuitGadget>,
    circuit_manager: Vec<Box<dyn UPSCircuitManager<C, D> + Send + Sync>>,
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl PsyMemoryWallet {
    pub fn new(circuit_manager: Vec<Box<dyn UPSCircuitManager<C, D> + Send + Sync>>) -> Self {
        Self {
            signature_users: DashMap::new(),
            psy_software_defined_circuits: DashMap::new(),
            plonky2_software_defined_circuits: DashMap::new(),
            sdk_key_circuits: DashMap::new(),
            circuit_manager,
        }
    }

    pub fn random_circuit_manager(&self) -> &Box<dyn UPSCircuitManager<C, D> + Send + Sync> {
        let index = rand::random::<usize>() % self.circuit_manager.len();
        &self.circuit_manager[index]
    }

    pub fn has_psy_software_defined_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.psy_software_defined_circuits.contains_key(fingerprint)
    }

    pub fn has_plonky2_software_defined_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.plonky2_software_defined_circuits.contains_key(fingerprint)
    }

    pub fn has_sdk_key_circuit(&self, fingerprint: &QHashOut<F>) -> bool {
        self.sdk_key_circuits.contains_key(fingerprint)
    }

    pub fn insert_psy_software_defined_circuit(&self, fingerprint: QHashOut<F>, circuit: DPNSoftwareDefinedSignatureGadget) {
        self.psy_software_defined_circuits.insert(fingerprint, circuit);
    }

    pub fn insert_plonky2_software_defined_circuit(&self, fingerprint: QHashOut<F>, circuit: Plonky2SoftwareDefinedSignatureGadget) {
        self.plonky2_software_defined_circuits.insert(fingerprint, circuit);
    }

    pub fn insert_sdk_key_circuit(&self, fingerprint: QHashOut<F>, circuit: SDKKeyCircuitGadget) {
        self.sdk_key_circuits.insert(fingerprint, circuit);
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

    pub async fn get_zk_pk_info(&self, private_key: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let simple_key = SimplePsyPrivateKey { private_key };
        let public_key_param = simple_key.get_public_key_param::<PoseidonHash>();
        let fingerprint = self.random_circuit_manager().zk_circuit_fingerprint().await?;
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

    pub async fn add_sdk_key_private_key(&mut self, private_key: QHashOut<F>, fingerprint: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let user: Arc<dyn SignatureUser> = Arc::new(SDKKeyUser::new(private_key, fingerprint));
        let manager = self.random_circuit_manager();
        let manager_ref = manager.as_ref();
        let pk_info = user.public_key_info(self, manager_ref).await?;
        let pk_hash = pk_info.qfhash::<PsyHasher>();
        self.signature_users.insert(pk_hash, user);
        Ok(pk_info)
    }

    pub async fn get_or_create_user(&mut self, private_key: QHashOut<F>, fingerprint: QHashOut<F>) -> anyhow::Result<ZKPublicKeyInfo<F>> {
        let manager = self.random_circuit_manager();
        let zk_fingerprint = manager.zk_circuit_fingerprint().await?;
        let secp_fingerprint = manager.secp_circuit_fingerprint().await?;

        if fingerprint == zk_fingerprint {
            self.add_zk_private_key(private_key).await
        } else if fingerprint == secp_fingerprint {
            self.add_secp_private_key(private_key).await
        } else {
            if self.psy_software_defined_circuits.contains_key(&fingerprint) {
                self.add_software_defined_dpn_private_key(private_key, fingerprint).await
            } else if self.plonky2_software_defined_circuits.contains_key(&fingerprint) {
                self.add_software_defined_plonky2_private_key(private_key, fingerprint).await
            } else if self.sdk_key_circuits.contains_key(&fingerprint) {
                self.add_sdk_key_private_key(private_key, fingerprint).await
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
        self.random_circuit_manager().prove_zk_sign(private_key, sig_hash).await
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

    pub async fn zk_secp256k1_from_signature(&self, signature: &PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.random_circuit_manager().prove_secp_sign(*signature).await
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
        &mut self,
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

        if let Some(_) = self.psy_software_defined_circuits.insert(fingerprint, gadget) {
            tracing::warn!("PSY software defined circuit `{}` is already registered", fingerprint.to_string());
        }

        Ok(fingerprint)
    }

    pub async fn register_plonky2_software_defined_circuit(
        &mut self,
        contract_state_tree_height: u8,
        input_len: usize,
    ) -> anyhow::Result<QHashOut<F>> {
        let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder = plonky2::plonk::circuit_builder::CircuitBuilder::<F, D>::new(config);

        let mut gadget = Plonky2SoftwareDefinedSignatureGadget::add_virtual_to(&mut builder, contract_state_tree_height, input_len);
        gadget.build_circuit(builder)?;
        let fingerprint = gadget.get_fingerprint();

        tracing::info!("register PLONKY2 software defined circuit: {}", fingerprint.to_string());

        if let Some(_) = self.plonky2_software_defined_circuits.insert(fingerprint, gadget) {
            tracing::warn!("PLONKY2 software defined circuit `{}` is already registered", fingerprint.to_string());
        }

        Ok(fingerprint)
    }

    pub async fn register_allow_method_sdk_key_circuit(
        &mut self,
        allowed_contract_ids: &[u64],
        allowed_method_ids: &[u64],
        expected_tx_count: u64,
    ) -> anyhow::Result<QHashOut<F>> {
        let gadget = build_allow_method_sdk_key_circuit(allowed_contract_ids, allowed_method_ids, expected_tx_count)?;
        let fingerprint = gadget.get_fingerprint();

        tracing::info!(
            "register allow-method SDK key circuit: fingerprint={}, contract_ids={:?}, method_ids={:?}, expected_tx_count={}",
            fingerprint.to_string(),
            allowed_contract_ids,
            allowed_method_ids,
            expected_tx_count
        );

        if let Some(_) = self.sdk_key_circuits.insert(fingerprint, gadget) {
            tracing::warn!("SDK key circuit `{}` is already registered", fingerprint.to_string());
        }

        Ok(fingerprint)
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

    pub fn get_sdk_key_circuit(&self, fingerprint: &QHashOut<F>) -> Option<dashmap::mapref::one::Ref<'_, QHashOut<F>, SDKKeyCircuitGadget>> {
        self.sdk_key_circuits.get(fingerprint)
    }

    pub fn get_sdk_key_circuit_mut(&self, fingerprint: &QHashOut<F>) -> Option<dashmap::mapref::one::RefMut<'_, QHashOut<F>, SDKKeyCircuitGadget>> {
        self.sdk_key_circuits.get_mut(fingerprint)
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
}
