use crate::{crypto::secp256k1::{CompressedPublicKey, QEDCompressedSecp256K1Signature}, data::hash::hash256::Hash256};

pub trait Secp256K1Verifier {
    fn secp256k1_verify(
        signature: &QEDCompressedSecp256K1Signature,
    ) -> anyhow::Result<()>;
}
pub trait Secp256K1WalletProvider {
    fn sign(
        &self,
        public_key: &CompressedPublicKey,
        message: Hash256,
    ) -> anyhow::Result<QEDCompressedSecp256K1Signature>;
    fn contains_public_key(&self, public_key: &CompressedPublicKey) -> bool;
    fn get_public_keys(&self) -> Vec<CompressedPublicKey>;
}


