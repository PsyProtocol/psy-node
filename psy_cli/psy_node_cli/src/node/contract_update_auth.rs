use std::sync::Arc;

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    field::types::Field,
    hash::hash_types::HashOut,
    hash::poseidon::PoseidonHash,
    plonk::config::PoseidonGoldilocksConfig,
    plonk::config::Hasher,
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::circuits::zk_signature3::manager::SimplePsyZKSignatureManager;
use psy_node_common::coordinator::edge::handler::{ContractUpdateAuthContext, ContractUpdateAuthVerifier};

type C = PoseidonGoldilocksConfig;
const D: usize = 2;

/// Same felt encoding as the coordinator's `hash_to_bytes`: four LE u64 limbs.
fn qhash_out_from_le_bytes(bytes: &[u8; 32]) -> QHashOut<GoldilocksField> {
    let limb = |range: std::ops::Range<usize>| {
        GoldilocksField::from_canonical_u64(u64::from_le_bytes(bytes[range].try_into().unwrap()))
    };
    QHashOut(HashOut {
        elements: [limb(0..8), limb(8..16), limb(16..24), limb(24..32)],
    })
}

/// Builds the node-side verifier for contract update authorizations: the
/// registered fingerprint must be the PsyBasicZKSignatureCircuit fingerprint,
/// and the proof must verify over the auth hash for the deployer's key param.
pub fn make_contract_update_auth_verifier() -> Arc<ContractUpdateAuthVerifier> {
    let manager = SimplePsyZKSignatureManager::<C, D>::new();
    Arc::new(move |context: &ContractUpdateAuthContext| {
        let proof: plonky2::plonk::proof::ProofWithPublicInputs<GoldilocksField, C, D> =
            serde_json::from_str(&context.proof_json)
                .map_err(|error| anyhow::anyhow!("malformed authorization proof json: {error}"))?;
        let public_key_param = qhash_out_from_le_bytes(&context.public_key_param);
        let circuit_fingerprint = manager.get_zksig_circuit_fingerprint();
        let registered_fingerprint = qhash_out_from_le_bytes(&context.fingerprint);
        anyhow::ensure!(
            registered_fingerprint == circuit_fingerprint,
            "registered fingerprint does not match the ZK signature circuit"
        );
        let public_key = QHashOut(<PoseidonHash as Hasher<GoldilocksField>>::two_to_one(
            circuit_fingerprint.0,
            public_key_param.0,
        ));
        let sig_hash = qhash_out_from_le_bytes(&context.auth_hash);
        anyhow::ensure!(
            manager.verify_simple_zk_signature(public_key, public_key_param, sig_hash, proof),
            "ZK signature proof is invalid"
        );
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_crypto::signature::zk::wallet::SimplePsyPrivateKey;

    /// End-to-end: prove with PsyBasicZKSignatureCircuit and pass the produced
    /// authorization through the real verifier closure.
    #[test]
    fn proves_and_verifies_a_contract_update_authorization() -> anyhow::Result<()> {
        let verifier = make_contract_update_auth_verifier();

        let signer = SimplePsyZKSignatureManager::<C, D>::new();
        let private_key_value = QHashOut::rand();
        let private_key = SimplePsyPrivateKey::new(private_key_value);
        let public_key_param = private_key.get_public_key_param::<PoseidonHash>();
        let fingerprint = signer.get_zksig_circuit_fingerprint();

        let auth_hash = [0x42u8; 32];
        let sig_hash = qhash_out_from_le_bytes(&auth_hash);
        let proof = signer.zk_sign_for_private_key_value(private_key_value, sig_hash)?;
        let proof_json = serde_json::to_string(&proof)?;

        let context = ContractUpdateAuthContext {
            auth_hash,
            fingerprint: fingerprint.to_le_bytes(),
            public_key_param: public_key_param.to_le_bytes(),
            proof_json: proof_json.clone(),
        };
        verifier(&context)?;

        // a tampered auth hash must fail
        let mut tampered = ContractUpdateAuthContext {
            auth_hash: [0x43u8; 32],
            fingerprint: fingerprint.to_le_bytes(),
            public_key_param: public_key_param.to_le_bytes(),
            proof_json,
        };
        assert!(verifier(&tampered).is_err());

        // an unregistered fingerprint must fail closed
        tampered.auth_hash = auth_hash;
        tampered.fingerprint = [0u8; 32];
        assert!(verifier(&tampered).is_err());
        Ok(())
    }
}
