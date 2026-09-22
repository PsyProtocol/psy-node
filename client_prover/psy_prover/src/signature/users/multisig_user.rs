use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::{PoseidonHash, PoseidonPermutation}};
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut, secp256k1::CompressedPublicKey};
use psy_client_data::config::store_config::{PsyHasher, PsyPlonky2Config, PsyProof};
use psy_config::network_constants::PSY_NETWORK_MAGIC;
use psy_crypto::{hash::traits::qhashable::QFieldHashable, signature::{secp256k1::wallet::hash_no_pad_compressed_public_key, zk::data::ZKPublicKeyInfo}};
use psy_vm::ups::{circuit_manager::UPSCircuitManager, multisig::{MultisigAccount, MultisigPolicy, MultisigSignatureInput, MultisigSignatureWitness, MultisigSignatures}};

use crate::{signature::{context::SignContext, traits::{SignatureCircuitInfo, SignatureUser}}, wallet::memory_wallet::PsyMemoryWallet};
use super::external_secp256k1_user::{validate_compressed_public_key, validate_signature_prehash};

#[derive(Debug, Clone)]
pub struct MultisigUser {
    account: MultisigAccount,
    policies: Option<(MultisigPolicy, MultisigPolicy)>,
    signatures: Option<MultisigSignatures>,
}

impl MultisigUser {
    pub fn new(account: MultisigAccount) -> Result<Self> {
        account.public_key_param()?;
        Ok(Self { account, policies: None, signatures: None })
    }

    pub fn account(&self) -> &MultisigAccount {
        &self.account
    }

    pub fn policies(&self) -> Result<(&MultisigPolicy, &MultisigPolicy)> {
        let (current, ending) = self.policies.as_ref().context("multisig policy preimages missing")?;
        Ok((current, ending))
    }

    pub fn set_policy(&mut self, current: MultisigPolicy, ending: MultisigPolicy) -> Result<()> {
        current.commitment()?;
        ending.commitment()?;
        self.policies = Some((current, ending));
        Ok(())
    }

    pub fn inject_signatures(&mut self, signatures: MultisigSignatures) -> Result<()> {
        validate_signatures(&signatures)?;
        self.signatures = Some(signatures);
        Ok(())
    }

    fn signature_input(&self, witness: &MultisigSignatureWitness, sighash: QHashOut<GoldilocksField>) -> Result<MultisigSignatureInput> {
        ensure!(witness.account.public_key_param()? == self.account.public_key_param()?, "multisig witness account identity mismatch");
        witness.current_policy.commitment()?;
        witness.ending_policy.commitment()?;
        let expected = witness.sig_data.get_sig_action_for_user::<PoseidonHash>(
            PSY_NETWORK_MAGIC,
            witness.sign_context.user_leaf.user_id,
            witness.nonce,
            witness.sign_context.clone(),
        ).get_qhash::<PoseidonHash>();
        ensure!(expected == sighash, "multisig witness sighash mismatch");
        let signatures = self.signatures.as_ref().context("multisig signatures missing")?;
        validate_policy_signatures(signatures, &witness.current_policy, sighash)?;
        Ok(MultisigSignatureInput { witness: witness.clone(), signatures: signatures.clone() })
    }
}

fn validate_signatures(signatures: &MultisigSignatures) -> Result<()> {
    ensure!((1..=8).contains(&signatures.signatures.len()), "multisig requires 1..=8 signatures");
    ensure!(signatures.member_indices.len() == signatures.signatures.len(), "multisig signature and index counts differ");
    let message = signatures.signatures[0].message;
    for (slot, (&index, signature)) in signatures.member_indices.iter().zip(&signatures.signatures).enumerate() {
        ensure!(index < 8, "multisig member index out of range");
        ensure!(slot == 0 || signatures.member_indices[slot - 1] < index, "multisig member indices must be strictly increasing");
        ensure!(signature.message == message, "multisig signatures must share one message");
        validate_compressed_public_key(CompressedPublicKey(signature.public_key))?;
        validate_signature_prehash(signature, &message.0, "multisig")?;
    }
    Ok(())
}

fn validate_policy_signatures(signatures: &MultisigSignatures, policy: &MultisigPolicy, sighash: QHashOut<GoldilocksField>) -> Result<()> {
    policy.validate()?;
    validate_signatures(signatures)?;
    ensure!(signatures.signatures.len() == usize::from(policy.threshold), "multisig signature count must equal current threshold");
    let message = Hash256::from(sighash);
    for (&index, signature) in signatures.member_indices.iter().zip(&signatures.signatures) {
        ensure!(signature.message == message, "multisig signature message does not match session sighash");
        ensure!(index < policy.member_count, "multisig signer is outside current policy");
        let member = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(CompressedPublicKey(signature.public_key));
        ensure!(member == policy.member_hashes[usize::from(index)], "multisig signer does not match current policy member");
    }
    Ok(())
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
impl SignatureUser for MultisigUser {
    async fn public_key_info(&self, wallet: &PsyMemoryWallet, _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync)) -> Result<ZKPublicKeyInfo<GoldilocksField>> {
        Ok(ZKPublicKeyInfo {
            fingerprint: wallet.get_multisig_circuit()?.get_fingerprint(),
            public_key_param: self.account.public_key_param()?,
        })
    }

    async fn sign(&self, wallet: &PsyMemoryWallet, _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync), context: &SignContext, sighash: QHashOut<GoldilocksField>) -> Result<PsyProof> {
        let witness = context.multisig_signature_witness.as_ref().context("multisig signature witness missing")?;
        ensure!(context.psy_signature_input.is_none() && context.plonky2_signature_input.is_none() && context.sd_key_signature_input.is_none(), "multisig cannot use another signature scheme's witness");
        let input = self.signature_input(witness, sighash)?;
        let circuit = wallet.get_multisig_circuit()?;
        ensure!(context.fingerprint == circuit.get_fingerprint(), "multisig circuit fingerprint mismatch");
        let info = ZKPublicKeyInfo { fingerprint: circuit.get_fingerprint(), public_key_param: self.account.public_key_param()? };
        ensure!(witness.start_session_user_leaf.public_key == info.qfhash::<PsyHasher>(), "multisig starting user identity mismatch");
        ensure!(witness.sign_context.user_leaf.public_key == info.qfhash::<PsyHasher>(), "multisig ending user identity mismatch");
        circuit.prove(&input, sighash)
    }

    async fn circuit_info(&self, wallet: &PsyMemoryWallet, _circuit_manager: &(dyn UPSCircuitManager<PsyPlonky2Config, 2> + Send + Sync), context: &SignContext) -> Result<SignatureCircuitInfo> {
        let circuit = wallet.get_multisig_circuit()?;
        ensure!(context.fingerprint == circuit.get_fingerprint(), "multisig circuit fingerprint mismatch");
        Ok(SignatureCircuitInfo { circuit_fingerprint: circuit.get_fingerprint(), verifier_config: circuit.get_verifier_config_ref().clone() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_crypto::signature::secp256k1::wallet::secp256k1_sign;

    fn signatures(sighash: QHashOut<GoldilocksField>) -> MultisigSignatures {
        let key = k256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        MultisigSignatures { member_indices: vec![0], signatures: vec![secp256k1_sign(key, sighash).unwrap()] }
    }

    fn account(signatures: &MultisigSignatures) -> MultisigAccount {
        let mut member_hashes = [QHashOut::ZERO; 8];
        member_hashes[0] = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(
            CompressedPublicKey(signatures.signatures[0].public_key),
        );
        MultisigAccount { contract_id: 42, initial_policy: MultisigPolicy { version: 1, threshold: 1, member_count: 1, member_hashes } }
    }

    #[test]
    fn signature_reuse_requires_same_message_and_current_member() {
        let sighash = QHashOut::from_values(1, 2, 3, 4);
        let signatures = signatures(sighash);
        let mut policy = account(&signatures).initial_policy;
        assert!(validate_policy_signatures(&signatures, &policy, sighash).is_ok());
        assert!(validate_policy_signatures(&signatures, &policy, QHashOut::from_values(1, 2, 3, 5)).is_err());
        policy.member_hashes[0] = QHashOut::from_values(1, 0, 0, 0);
        assert!(validate_policy_signatures(&signatures, &policy, sighash).is_err());
    }

    #[test]
    fn injection_rejects_duplicate_indices_and_mixed_messages() {
        let mut signatures = signatures(QHashOut::from_values(1, 2, 3, 4));
        signatures.signatures.push(signatures.signatures[0]);
        signatures.member_indices.push(0);
        assert!(validate_signatures(&signatures).is_err());
        signatures.member_indices[1] = 1;
        signatures.signatures[1] = self::signatures(QHashOut::from_values(4, 3, 2, 1)).signatures[0];
        assert!(validate_signatures(&signatures).is_err());
    }

    #[test]
    fn policy_preimages_are_required_only_for_generation() {
        let signatures = signatures(QHashOut::from_values(1, 2, 3, 4));
        let account = account(&signatures);
        let mut user = MultisigUser::new(account.clone()).unwrap();
        assert!(user.policies().is_err());
        user.inject_signatures(signatures).unwrap();
        assert!(user.policies().is_err());
        user.set_policy(account.initial_policy.clone(), account.initial_policy.clone()).unwrap();
        let mut invalid = account.initial_policy.clone();
        invalid.threshold = 0;
        assert!(user.set_policy(invalid, account.initial_policy.clone()).is_err());
        let (current, ending) = user.policies().unwrap();
        assert_eq!(current.commitment().unwrap(), account.initial_policy.commitment().unwrap());
        assert_eq!(ending.commitment().unwrap(), current.commitment().unwrap());
    }

    #[test]
    fn signatures_must_meet_exact_current_threshold() {
        let sighash = QHashOut::from_values(1, 2, 3, 4);
        let signatures = signatures(sighash);
        let mut policy = account(&signatures).initial_policy;
        policy.member_hashes[1] = QHashOut::from_values(1, 0, 0, 0);
        policy.member_count = 2;
        policy.threshold = 2;
        use plonky2::field::types::PrimeField64;
        policy.member_hashes[..2].sort_by_key(|hash| hash.0.elements.map(|limb| limb.to_canonical_u64()));
        assert!(policy.validate().is_ok());
        assert!(validate_policy_signatures(&signatures, &policy, sighash).is_err());
    }
}
