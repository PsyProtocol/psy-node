use psy_client_common::data::base_types::hash256::Hash256;
use psy_crypto::hash::core::sha256::CoreSha256Hasher;

pub trait SimpleEncryptionHelper: Clone + Send + Sync {
    fn encrypt_32(&self, salt: Hash256, data: Hash256) -> Hash256;
    fn decrypt_32(&self, salt: Hash256, encrypted_data: Hash256) -> Hash256;
}

#[derive(Clone)]
pub struct SimpleZeroPadEncryptionHelper {
    key: Hash256,
}

impl SimpleZeroPadEncryptionHelper {
    pub fn new(key: Hash256) -> Self {
        Self { key }
    }
    pub fn new_rand() -> Self {
        Self { key: Hash256::rand() }
    }
    pub fn new_no_encrypt() -> Self {
        Self { key: Hash256::ZERO }
    }
    pub fn get_decryption_key(&self) -> Hash256 {
        self.key
    }
}

impl SimpleEncryptionHelper for SimpleZeroPadEncryptionHelper {
    fn encrypt_32(&self, salt: Hash256, data: Hash256) -> Hash256 {
        let mut hasher = CoreSha256Hasher::new();
        hasher.update(&self.key.0);
        hasher.update(&salt.0);
        let key = hasher.finalize();
        data ^ key
    }
    fn decrypt_32(&self, salt: Hash256, encrypted_data: Hash256) -> Hash256 {
        let mut hasher = CoreSha256Hasher::new();
        hasher.update(&self.key.0);
        hasher.update(&salt.0);
        let key = hasher.finalize();
        encrypted_data ^ key
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn encryption_round_trip_depends_on_key_and_salt() {
        let key = Hash256([7; 32]);
        let salt = Hash256([11; 32]);
        let data = Hash256([19; 32]);
        let helper = SimpleZeroPadEncryptionHelper::new(key);

        let encrypted = helper.encrypt_32(salt, data);

        assert_ne!(encrypted, data);
        assert_eq!(helper.decrypt_32(salt, encrypted), data);
        assert_ne!(helper.encrypt_32(Hash256([12; 32]), data), encrypted);
        assert_ne!(SimpleZeroPadEncryptionHelper::new(Hash256([8; 32])).encrypt_32(salt, data), encrypted);
        assert_eq!(helper.get_decryption_key(), key);
    }

    #[test]
    fn no_encrypt_constructor_still_round_trips() {
        let helper = SimpleZeroPadEncryptionHelper::new_no_encrypt();
        let salt = Hash256([1; 32]);
        let data = Hash256([2; 32]);

        assert_eq!(helper.get_decryption_key(), Hash256::ZERO);
        assert_eq!(helper.decrypt_32(salt, helper.encrypt_32(salt, data)), data);
    }

    #[test]
    fn random_constructor_produces_a_usable_key() {
        let helper = SimpleZeroPadEncryptionHelper::new_rand();
        let salt = Hash256([3; 32]);
        let data = Hash256([4; 32]);

        assert_eq!(helper.decrypt_32(salt, helper.encrypt_32(salt, data)), data);
    }
}
