use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::{PoseidonHash, PoseidonPermutation}};
use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut, secp256k1::CompressedPublicKey};
use psy_client_data::config::store_config::{PsyHasher, PsyPlonky2Config, PsyProof};
use psy_config::network_constants::PSY_NETWORK_MAGIC;
use psy_crypto::{hash::traits::qhashable::QFieldHashable, signature::{secp256k1::wallet::hash_no_pad_compressed_public_key, zk::data::ZKPublicKeyInfo}};
use psy_ups_circuit::signature::reward_authorization::{RewardAuthorizationCircuits, RewardAuthorizationContext};
use psy_vm::ups::{circuit_manager::UPSCircuitManager, multisig::{MultisigAccount, MultisigPolicy, MultisigSignatureInput, MultisigSignatureWitness, MultisigSignatures}};

use crate::{signature::{context::SignContext, traits::{SignatureCircuitInfo, SignatureUser}}, wallet::memory_wallet::PsyMemoryWallet};
use super::external_secp256k1_user::{validate_compressed_public_key, validate_signature_prehash};

#[derive(Debug, Clone)]
pub struct MultisigUser {
    account: MultisigAccount,
    signatures: Option<MultisigSignatures>,
}

impl MultisigUser {
    pub fn new(account: MultisigAccount) -> Result<Self> {
        account.public_key_param()?;
        Ok(Self { account, signatures: None })
    }

    pub fn account(&self) -> &MultisigAccount {
        &self.account
    }


    pub fn inject_signatures(&mut self, signatures: MultisigSignatures) -> Result<()> {
        validate_signatures(&signatures)?;
        self.signatures = Some(signatures);
        Ok(())
    }

    fn signature_input(&self, witness: &MultisigSignatureWitness, sighash: QHashOut<GoldilocksField>) -> Result<MultisigSignatureInput> {
        ensure!(witness.account.public_key_param()? == self.account.public_key_param()?, "multisig witness account identity mismatch");
        let (current_policy, _) = witness.policies()?;
        let expected = witness.sig_data.get_sig_action_for_user::<PoseidonHash>(
            PSY_NETWORK_MAGIC,
            witness.sign_context.user_leaf.user_id,
            witness.nonce,
            witness.sign_context.clone(),
        ).get_qhash::<PoseidonHash>();
        ensure!(expected == sighash, "multisig witness sighash mismatch");
        let signatures = self.signatures.as_ref().context("multisig signatures missing")?;
        validate_policy_signatures(signatures, &current_policy, sighash)?;
        Ok(MultisigSignatureInput { witness: witness.clone(), signatures: signatures.clone() })
    }
}

fn validate_signatures(signatures: &MultisigSignatures) -> Result<()> {
    ensure!(signatures.signatures.len() == 2, "multisig requires exactly two signatures");
    ensure!(signatures.member_indices.len() == signatures.signatures.len(), "multisig signature and index counts differ");
    let message = signatures.signatures[0].message;
    for (slot, (&index, signature)) in signatures.member_indices.iter().zip(&signatures.signatures).enumerate() {
        ensure!(index < 3, "multisig member index out of range");
        ensure!(slot == 0 || signatures.member_indices[slot - 1] < index, "multisig member indices must be strictly increasing");
        ensure!(signature.message == message, "multisig signatures must share one message");
        validate_compressed_public_key(CompressedPublicKey(signature.public_key))?;
        validate_signature_prehash(signature, &message.0, "multisig")?;
    }
    Ok(())
}

pub fn validate_policy_signatures(signatures: &MultisigSignatures, policy: &MultisigPolicy, sighash: QHashOut<GoldilocksField>) -> Result<()> {
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
    fn prove_reward_authorization(&self, _context: &RewardAuthorizationContext, _circuits: &RewardAuthorizationCircuits) -> Result<Option<PsyProof>> {
        Ok(None)
    }

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
    use plonky2::field::types::PrimeField64;
    use psy_crypto::signature::secp256k1::wallet::secp256k1_sign;

    fn fixture(sighash: QHashOut<GoldilocksField>) -> (MultisigAccount, MultisigSignatures) {
        let mut members: Vec<_> = (1u8..=3).map(|byte| {
            let key = k256::ecdsa::SigningKey::from_slice(&[byte; 32]).unwrap();
            let signature = secp256k1_sign(key, sighash).unwrap();
            let hash = hash_no_pad_compressed_public_key::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(CompressedPublicKey(signature.public_key));
            (hash, signature)
        }).collect();
        members.sort_by_key(|(hash, _)| hash.0.elements.map(|limb| limb.to_canonical_u64()));
        let mut member_hashes = [QHashOut::ZERO; 8];
        for (index, (hash, _)) in members.iter().enumerate() { member_hashes[index] = *hash; }
        let account = MultisigAccount { contract_id: 6, initial_policy: MultisigPolicy { version: 1, threshold: 2, member_count: 3, member_hashes } };
        (account, MultisigSignatures { member_indices: vec![0, 2], signatures: vec![members[0].1, members[2].1] })
    }

    #[test]
    fn signatures_bind_message_and_current_members() {
        let sighash = QHashOut::from_values(1, 2, 3, 4);
        let (account, signatures) = fixture(sighash);
        validate_policy_signatures(&signatures, &account.initial_policy, sighash).unwrap();
        assert!(validate_policy_signatures(&signatures, &account.initial_policy, QHashOut::from_values(4, 3, 2, 1)).is_err());
        let mut wrong_members = account.initial_policy;
        wrong_members.member_hashes[0] = QHashOut::from_values(1, 0, 0, 0);
        assert!(validate_policy_signatures(&signatures, &wrong_members, sighash).is_err());
    }

    #[test]
    fn injection_requires_two_distinct_current_indices_and_one_message() {
        let (_, valid) = fixture(QHashOut::from_values(1, 2, 3, 4));
        for indices in [vec![0], vec![0, 0], vec![2, 0], vec![0, 3]] {
            let mut invalid = valid.clone();
            invalid.member_indices = indices;
            assert!(validate_signatures(&invalid).is_err());
        }
        let mut invalid = valid.clone();
        invalid.signatures.pop();
        invalid.member_indices.pop();
        assert!(validate_signatures(&invalid).is_err());
        let (_, other) = fixture(QHashOut::from_values(4, 3, 2, 1));
        invalid = valid;
        invalid.signatures[1] = other.signatures[1];
        assert!(validate_signatures(&invalid).is_err());
    }

    #[test]
    fn public_enrollment_identity_survives_signature_injection() {
        let (account, signatures) = fixture(QHashOut::from_values(1, 2, 3, 4));
        let identity = account.public_key_param().unwrap();
        let mut user = MultisigUser::new(account).unwrap();
        user.inject_signatures(signatures).unwrap();
        assert_eq!(user.account().public_key_param().unwrap(), identity);
    }
}
