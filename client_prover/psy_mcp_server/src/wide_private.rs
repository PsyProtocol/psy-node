//! U124 private FT wire format, owner-pinned assets, and durable local journal.
//! Money is decimal text on the wire. No private wallet key is serialized here.
use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use alloy_primitives::U256;
use anyhow::{Context, Result, ensure};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField as F,
        types::{Field, PrimeField64},
    },
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::Hasher,
};
use psy_client_common::data::qhashout::QHashOut;
use rand::RngCore;
use serde::{Deserialize, Serialize};
pub const ROOTS: [u64; 2] = [293601306, 293601307];
pub const COUNTS: [u64; 2] = [1174405232, 1174405233];
pub const PATHS: [u64; 2] = [1174405234, 1174405314];
pub const FP: [u64; 4] = [2482434993266711942, 6028864160300535936, 2827549014984201026, 3018365102481798071];
pub const P: u64 = 18446744069414584321;
pub const B: u128 = 1u128 << 62;
/// Versioned adapters, selected by the owner registry and authenticated code/
/// layout pins. Amount size and token decimals never select an adapter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    SingleFeltNativeV1,
    SingleFeltPsy20V1,
    #[default]
    U124PrivateV1,
}
impl Profile {
    pub fn is_wide(self) -> bool {
        self == Self::U124PrivateV1
    }
    pub fn kind(self) -> &'static str {
        if self.is_wide() {
            "psy_private_ft_u124_v1"
        } else {
            "psy_private_ft_single_v1"
        }
    }
    pub fn roots(self) -> [u64; 2] {
        match self {
            Self::SingleFeltNativeV1 => [2147483649, 0],
            Self::SingleFeltPsy20V1 => [8388609, 0],
            Self::U124PrivateV1 => ROOTS,
        }
    }
    pub fn counts(self) -> [u64; 2] {
        match self {
            Self::SingleFeltNativeV1 => [8589934595, 0],
            Self::SingleFeltPsy20V1 => [33554435, 0],
            Self::U124PrivateV1 => COUNTS,
        }
    }
    pub fn paths(self) -> [u64; 2] {
        match self {
            Self::SingleFeltNativeV1 => [8589934600, 0],
            Self::SingleFeltPsy20V1 => [33554440, 0],
            Self::U124PrivateV1 => PATHS,
        }
    }
    pub fn fields_slots(self) -> (u64, u64) {
        match self {
            Self::SingleFeltNativeV1 => (0, 0),
            Self::SingleFeltPsy20V1 => (22, 2149832488),
            Self::U124PrivateV1 => (24, 2178599700),
        }
    }
    pub fn public_claim_method(self) -> &'static str {
        if self == Self::SingleFeltNativeV1 { "simple_claim" } else { "claim" }
    }
    pub fn encode(self, n: u128) -> Result<[u64; 2]> {
        ensure!(n > 0, "amount must be positive");
        if self.is_wide() {
            ensure!(n < (1u128 << 124), "amount exceeds U124 range");
            Ok(limbs(n))
        } else {
            ensure!(n < P as u128, "amount exceeds single-Felt range");
            Ok([n as u64, 0])
        }
    }
    pub fn decode(self, v: [u64; 2]) -> Result<u128> {
        if self.is_wide() {
            from_limbs(v)
        } else {
            ensure!(v[0] < P && v[1] == 0, "noncanonical single-Felt amount");
            Ok(v[0] as u128)
        }
    }
    pub fn maximum(self) -> u128 {
        if self.is_wide() { (1u128 << 124) - 1 } else { P as u128 - 1 }
    }
}
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub assets: Vec<Asset>,
    #[serde(default)]
    pub contacts: Vec<Contact>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    pub network: String,
    pub contract_id: u64,
    pub code_root: String,
    pub layout_root: String,
    /// Omitted in old U124 configuration files; preserves their exact adapter.
    #[serde(default)]
    pub profile: Profile,
    pub decimals: u32,
    /// Owner-chosen budget weight, NOT a market exchange rate. Never supplied
    /// by an agent.
    pub policy_nano_per_token: u64,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contact {
    pub network: String,
    pub user_id: u64,
    pub shielded_address: String,
    pub npub: String,
}
impl Config {
    pub fn load() -> Result<Self> {
        let Some(path) = std::env::var_os("PSY_MCP_PRIVATE_FT_CONFIG") else {
            return Ok(Self::default());
        };
        let bytes = fs::read(path)?;
        ensure!(bytes.len() <= 1024 * 1024, "private FT config too large");
        let c: Self = serde_json::from_slice(&bytes)?;
        c.validate()?;
        Ok(c)
    }
    pub fn validate(&self) -> Result<()> {
        let mut assets = std::collections::HashSet::new();
        let mut contacts = std::collections::HashSet::new();
        for a in &self.assets {
            ensure!(
                !a.network.trim().is_empty() && a.contract_id < 16777216 && a.decimals <= 18 && a.policy_nano_per_token > 0,
                "invalid owner asset configuration"
            );
            ensure!(
                match a.profile {
                    Profile::SingleFeltNativeV1 => matches!(a.contract_id, 0 | 4),
                    _ => a.contract_id >= 5,
                },
                "profile does not support this contract ID"
            );
            ensure!(
                a.contract_id != 0 || (a.decimals == 9 && a.policy_nano_per_token == 1_000_000_000),
                "Native PSY must use exact NanoPSY policy accounting"
            );
            a.code_root.parse::<QHashOut<F>>()?;
            a.layout_root.parse::<QHashOut<F>>()?;
            ensure!(assets.insert((&a.network, a.contract_id)), "duplicate asset configuration");
        }
        for c in &self.contacts {
            ensure!(
                !c.network.trim().is_empty() && c.user_id > 0 && c.user_id < 16777216,
                "invalid contact identity"
            );
            canonical(&crate::wallet::parse_shield_elements_hex_pub(&c.shielded_address)?)?;
            nostr::PublicKey::parse(&c.npub)?;
            ensure!(contacts.insert((&c.network, c.user_id)), "duplicate contact");
        }
        Ok(())
    }
    pub fn asset(&self, network: &str, id: u64) -> Result<Asset> {
        self.assets
            .iter()
            .find(|a| a.network == network && a.contract_id == id)
            .cloned()
            .context("asset is not registered in the owner private FT configuration")
    }
    pub fn contact(&self, network: &str, id: u64) -> Result<Contact> {
        self.contacts
            .iter()
            .find(|a| a.network == network && a.user_id == id)
            .cloned()
            .context("recipient has no owner-registered private FT contact")
    }
}
pub fn amount(text: &str) -> Result<u128> {
    ensure!(
        !text.is_empty() && text.len() <= 38 && text.bytes().all(|b| b.is_ascii_digit()) && (text == "0" || !text.starts_with('0')),
        "canonical decimal amount string required"
    );
    let n = text.parse::<u128>()?;
    ensure!(n > 0 && n < (1u128 << 124), "amount must be in 1..2^124-1");
    Ok(n)
}
pub fn limbs(n: u128) -> [u64; 2] {
    [(n % B) as u64, (n / B) as u64]
}
pub fn from_limbs(v: [u64; 2]) -> Result<u128> {
    ensure!(v.iter().all(|x| (*x as u128) < B), "noncanonical amount limbs");
    Ok(v[0] as u128 + B * v[1] as u128)
}
pub fn charge(a: &Asset, n: u128) -> Result<u64> {
    let denominator = U256::from(10u128.pow(a.decimals));
    let raw = U256::from(n) * U256::from(a.policy_nano_per_token);
    let rounded = (raw + denominator - U256::from(1)) / denominator;
    ensure!(rounded <= U256::from(u64::MAX), "amount exceeds policy accounting range");
    Ok(rounded.to::<u64>())
}
pub fn canonical(v: &[u64]) -> Result<()> {
    ensure!(v.iter().all(|x| *x < P), "noncanonical Felt");
    Ok(())
}
pub fn hash(v: &[u64]) -> QHashOut<F> {
    QHashOut(PoseidonHash::hash_no_pad(
        &v.iter().map(|x| F::from_canonical_u64(*x)).collect::<Vec<_>>(),
    ))
}
pub fn words(h: QHashOut<F>) -> [u64; 4] {
    h.0.elements.map(|x| x.to_canonical_u64())
}
pub fn hh(a: QHashOut<F>, b: QHashOut<F>) -> QHashOut<F> {
    QHashOut(PoseidonHash::two_to_one(a.0, b.0))
}
pub fn zero() -> QHashOut<F> {
    QHashOut(HashOut { elements: [F::ZERO; 4] })
}
pub fn sample() -> u64 {
    loop {
        let n = rand::thread_rng().next_u64();
        if n < P {
            return n;
        }
    }
}
pub fn new_id() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}
pub fn validate_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid note/recovery id"
    );
    Ok(())
}
pub fn directory(network: &str) -> Result<PathBuf> {
    use sha2::{Digest, Sha256};
    let p = crate::keystore::keystore_dir()
        .join("private-ft-u124")
        .join(hex::encode(Sha256::digest(network.as_bytes())));
    fs::create_dir_all(&p)?;
    Ok(p)
}
pub fn operation_lock(network: &str, user: u64) -> Result<fs::File> {
    operation_lock_in(&directory(network)?, user)
}

// Separate the location from lock semantics so isolated tests never touch a
// real wallet keystore. All callers use the same per-wallet advisory lock.
pub(crate) fn operation_lock_in(directory: &Path, user: u64) -> Result<fs::File> {
    let p = directory.join(format!("wallet-{user}.lock"));
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(p)?;
    fs2::FileExt::try_lock_exclusive(&f).context("another private FT operation is running for this wallet")?;
    Ok(f)
}
pub fn save(path: &Path, v: &impl Serialize, create: bool) -> Result<()> {
    let lock_path = path.with_extension("lock");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock_path)?;
    fs2::FileExt::lock_exclusive(&lock)?;
    ensure!(!create || !path.exists(), "record already exists");
    let tmp = path.with_extension(format!("{}.tmp", new_id()));
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(&serde_json::to_vec(v)?)?;
    f.sync_all()?;
    fs::rename(tmp, path)?;
    fs::File::open(path.parent().context("record parent")?)?.sync_all()?;
    Ok(())
}
pub fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = fs::read(path)?;
    ensure!(bytes.len() <= 8 * 1024 * 1024, "private record too large");
    Ok(serde_json::from_slice(&bytes)?)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    pub kind: String,
    pub contract_id: u64,
    pub owner: [u64; 4],
    pub amount: [u64; 2],
    pub checkpoint: u64,
    pub user_tree_root: [u64; 4],
    pub nullifiers: [[u64; 4]; 2],
    pub proofs: [Option<String>; 2],
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub kind: String,
    pub ephemeral_pubkey: String,
    pub ciphertexts: Vec<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Chunk {
    package_id: String,
    index: usize,
    total: usize,
    digest: String,
    body: String,
}
pub fn encrypt(contact: &Contact, packet: &Packet) -> Result<Delivery> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(packet)?;
    ensure!(bytes.len() <= 4 * 1024 * 1024, "private packet too large");
    let sender = nostr::Keys::generate();
    let pk = nostr::PublicKey::parse(&contact.npub)?;
    let package_id = new_id();
    let digest = hex::encode(Sha256::digest(&bytes));
    let total = bytes.len().div_ceil(32000);
    let mut ciphertexts = Vec::with_capacity(total);
    for (index, bytes) in bytes.chunks(32000).enumerate() {
        let body = base64::engine::general_purpose::STANDARD.encode(bytes);
        let plaintext = serde_json::to_string(&Chunk {
            package_id: package_id.clone(),
            index,
            total,
            digest: digest.clone(),
            body,
        })?;
        ensure!(plaintext.len() <= 65408, "private chunk exceeds NIP44 limit");
        ciphertexts.push(nostr::nips::nip44::encrypt(
            sender.secret_key(),
            &pk,
            plaintext,
            nostr::nips::nip44::Version::V2,
        )?);
    }
    Ok(Delivery {
        kind: packet.kind.clone(),
        ephemeral_pubkey: sender.public_key().to_string(),
        ciphertexts,
    })
}
pub fn decrypt(nsec: &str, delivery: &Delivery) -> Result<Packet> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    ensure!(
        matches!(delivery.kind.as_str(), "psy_private_ft_u124_v1" | "psy_private_ft_single_v1")
            && !delivery.ciphertexts.is_empty()
            && delivery.ciphertexts.len() <= 132
            && delivery.ciphertexts.iter().all(|x| x.len() <= 90000)
            && delivery.ciphertexts.iter().map(String::len).sum::<usize>() <= 8 * 1024 * 1024,
        "invalid private FT delivery"
    );
    let secret = nostr::SecretKey::parse(nsec)?;
    let pk = nostr::PublicKey::parse(&delivery.ephemeral_pubkey)?;
    let mut bytes = vec![];
    let mut group = None;
    let mut digest = None;
    for (index, ciphertext) in delivery.ciphertexts.iter().enumerate() {
        let plaintext = nostr::nips::nip44::decrypt(&secret, &pk, ciphertext)?;
        let part: Chunk = serde_json::from_str(&plaintext)?;
        validate_id(&part.package_id)?;
        validate_id(&part.digest)?;
        ensure!(
            part.index == index && part.total == delivery.ciphertexts.len(),
            "missing/reordered private FT chunk"
        );
        if let Some(g) = group.as_ref() {
            ensure!(g == &part.package_id && digest.as_ref() == Some(&part.digest), "mixed private FT chunks")
        } else {
            group = Some(part.package_id);
            digest = Some(part.digest)
        }
        let data = base64::engine::general_purpose::STANDARD.decode(part.body)?;
        ensure!(
            data.len() <= 32000 && (index + 1 == delivery.ciphertexts.len() || data.len() == 32000),
            "invalid chunk length"
        );
        bytes.extend(data);
    }
    ensure!(
        bytes.len() <= 4 * 1024 * 1024 && Some(hex::encode(Sha256::digest(&bytes))) == digest,
        "private FT packet checksum mismatch"
    );
    let packet: Packet = serde_json::from_slice(&bytes)?;
    ensure!(packet.kind == delivery.kind, "encrypted packet/delivery format mismatch");
    Ok(packet)
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Recovery {
    pub sender: u64,
    pub recipient: u64,
    pub contract_id: u64,
    #[serde(default)]
    pub profile: Profile,
    pub amount: [u64; 2],
    pub owner: [u64; 4],
    pub secrets: [[u64; 4]; 2],
    pub nullifier_secrets: [[u64; 4]; 2],
    pub indices: [u64; 2],
    pub status: String,
    pub end_leaf: Option<String>,
    pub nonce: Option<u64>,
    #[serde(default)]
    pub checkpoint_before: Option<u64>,
    pub checkpoint: Option<u64>,
    pub delivery: Option<Delivery>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Inbox {
    pub user_id: u64,
    pub contract_id: u64,
    pub delivery: Delivery,
    pub status: String,
    pub end_leaf: Option<String>,
    pub nonce: Option<u64>,
    #[serde(default)]
    pub checkpoint_before: Option<u64>,
    pub checkpoint: Option<u64>,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn single_felt_boundaries_and_legacy_profile_default() -> Result<()> {
        let s = Profile::SingleFeltPsy20V1;
        for n in [1, B - 1, B, B + 1, P as u128 - 1] {
            assert_eq!(s.decode(s.encode(n)?)?, n);
        }
        assert!(s.encode(P as u128).is_err());
        assert!(s.encode(P as u128 + 1).is_err());
        assert!(s.decode([1, 1]).is_err());
        assert!(s.decode([P, 0]).is_err());
        assert!(Profile::U124PrivateV1.decode([B as u64, 0]).is_err());
        let raw = serde_json::json!({"network":"n","contract_id":2457,"code_root":"0".repeat(64),"layout_root":"0".repeat(64),"decimals":18,"policy_nano_per_token":100000000});
        let a: Asset = serde_json::from_value(raw.clone())?;
        assert_eq!(a.profile, Profile::U124PrivateV1);
        let mut c = Config {
            assets: vec![a],
            contacts: vec![],
        };
        c.validate()?;
        c.assets[0].contract_id = 0;
        assert!(c.validate().is_err());
        c.assets[0].profile = Profile::SingleFeltNativeV1;
        assert!(c.validate().is_err());
        c.assets[0].decimals = 9;
        c.assets[0].policy_nano_per_token = 1_000_000_000;
        c.validate()?;
        c.assets[0].contract_id = 53;
        assert!(c.validate().is_err());
        c.assets[0].profile = s;
        c.validate()?;
        let mut invalid = raw;
        invalid["profile"] = serde_json::json!("guess_from_decimals");
        assert!(serde_json::from_value::<Asset>(invalid).is_err());
        Ok(())
    }
    #[test]
    fn single_delivery_accepts_full_felt_and_rejects_relabeling() -> Result<()> {
        let keys = nostr::Keys::generate();
        let contact = Contact {
            network: "n".into(),
            user_id: 42,
            shielded_address: "".into(),
            npub: keys.public_key().to_string(),
        };
        let packet = Packet {
            kind: Profile::SingleFeltNativeV1.kind().into(),
            contract_id: 0,
            owner: [1, 2, 3, 4],
            amount: [P - 1, 0],
            checkpoint: 123,
            user_tree_root: [1; 4],
            nullifiers: [[2; 4], [0; 4]],
            proofs: [Some("fixture".into()), None],
        };
        let mut delivery = encrypt(&contact, &packet)?;
        assert_eq!(decrypt(&keys.secret_key().to_secret_hex(), &delivery)?.amount, [P - 1, 0]);
        delivery.kind = Profile::U124PrivateV1.kind().into();
        assert!(decrypt(&keys.secret_key().to_secret_hex(), &delivery).is_err());
        Ok(())
    }
    #[test]
    fn decimal_u124_rounding_and_noncanonical_limits() -> Result<()> {
        let mut a = Asset {
            profile: Profile::default(),
            network: "n".into(),
            contract_id: 2457,
            code_root: "".into(),
            layout_root: "".into(),
            decimals: 18,
            policy_nano_per_token: 1000000000,
        };
        for n in [1, B - 1, B, B + 1, (1 << 124) - 1] {
            assert_eq!(from_limbs(limbs(amount(&n.to_string())?))?, n)
        }
        for x in ["0", "-1", "1e18", "01", "1.0", " 1", "21267647932558653966460912964485513216"] {
            assert!(amount(x).is_err())
        }
        assert_eq!(charge(&a, 4700000000000000017)?, 4700000001);
        assert_eq!(charge(&a, 1)?, 1);
        a.decimals = 0;
        assert!(charge(&a, (1 << 124) - 1).is_err());
        assert!(from_limbs([1 << 62, 0]).is_err());
        Ok(())
    }
    #[test]
    fn encrypted_delivery_is_recipient_bound_and_preserves_large_limbs() -> Result<()> {
        let keys = nostr::Keys::generate();
        let wrong = nostr::Keys::generate();
        let c = Contact {
            network: "n".into(),
            user_id: 4,
            shielded_address: "".into(),
            npub: keys.public_key().to_string(),
        };
        let p = Packet {
            kind: "psy_private_ft_u124_v1".into(),
            contract_id: 2457,
            owner: [0; 4],
            amount: limbs(20000000000000000017),
            checkpoint: 23,
            user_tree_root: [0; 4],
            nullifiers: [[0; 4]; 2],
            proofs: [None, None],
        };
        let d = encrypt(&c, &p)?;
        assert_eq!(decrypt(&keys.secret_key().to_secret_hex(), &d)?.amount, p.amount);
        assert!(decrypt(&wrong.secret_key().to_secret_hex(), &d).is_err());
        let mut bad = d;
        bad.ciphertexts[0].push('a');
        assert!(decrypt(&keys.secret_key().to_secret_hex(), &bad).is_err());
        Ok(())
    }
    #[test]
    fn durable_records_cannot_be_overwritten_at_creation_or_escape_directory() -> Result<()> {
        let d = tempfile::tempdir()?;
        let p = d.path().join("note.json");
        save(&p, &vec![1], true)?;
        assert!(save(&p, &vec![2], true).is_err());
        assert_eq!(read::<Vec<u32>>(&p)?, vec![1]);
        for id in ["../key", "", "x", &"f".repeat(63)] {
            assert!(validate_id(id).is_err())
        }
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(p)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }
    #[test]
    fn large_chunked_packet_rejects_missing_reordered_and_spliced_parts() -> Result<()> {
        let keys = nostr::Keys::generate();
        let contact = Contact {
            network: "n".into(),
            user_id: 1,
            shielded_address: String::new(),
            npub: keys.public_key().to_string(),
        };
        let packet = Packet {
            kind: "psy_private_ft_u124_v1".into(),
            contract_id: 2457,
            owner: [1; 4],
            amount: [1, 4],
            checkpoint: 100,
            user_tree_root: [2; 4],
            nullifiers: [[3; 4], [4; 4]],
            proofs: [Some("x".repeat(180000)), Some("y".repeat(180000))],
        };
        let d = encrypt(&contact, &packet)?;
        assert!(d.ciphertexts.len() > 2);
        let secret = keys.secret_key().to_secret_hex();
        assert_eq!(decrypt(&secret, &d)?.proofs, packet.proofs);
        let mut missing = d.clone();
        missing.ciphertexts.pop();
        assert!(decrypt(&secret, &missing).is_err());
        let mut order = d.clone();
        order.ciphertexts.swap(0, 1);
        assert!(decrypt(&secret, &order).is_err());
        let other = encrypt(&contact, &packet)?;
        let mut mixed = d;
        mixed.ciphertexts[1] = other.ciphertexts[1].clone();
        assert!(decrypt(&secret, &mixed).is_err());
        Ok(())
    }
    #[test]
    #[ignore = "requires an explicitly supplied local native-proof fixture; run for release verification"]
    fn real_two_native_proofs_roundtrip_without_exceeding_nip44() -> Result<()> {
        let path = std::env::var("PSY_MCP_U124_TEST_PACKET").context("provide a local native two-proof fixture via PSY_MCP_U124_TEST_PACKET")?;
        let fixture: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        let mut proofs = [None, None];
        use base64::Engine;
        use plonky2::plonk::proof::ProofWithPublicInputs;
        use psy_client_data::config::store_config::{C, D};
        for value in fixture["proofs"].as_array().context("native fixture proofs")? {
            let i = value[0].as_u64().context("limb")? as usize;
            ensure!(i < 2, "limb");
            let proof: ProofWithPublicInputs<F, C, D> = serde_json::from_str(value[1].as_str().context("opaque native proof JSON")?)?;
            proofs[i] = Some(base64::engine::general_purpose::STANDARD.encode(bincode::serialize(&proof)?));
        }
        ensure!(proofs.iter().all(Option::is_some), "both denomination fixtures required");
        let packet = Packet {
            kind: "psy_private_ft_u124_v1".into(),
            contract_id: 2457,
            owner: [0; 4],
            amount: [1, 4],
            checkpoint: 1,
            user_tree_root: [0; 4],
            nullifiers: [[1; 4], [2; 4]],
            proofs,
        };
        let keys = nostr::Keys::generate();
        let contact = Contact {
            network: "n".into(),
            user_id: 1,
            shielded_address: String::new(),
            npub: keys.public_key().to_string(),
        };
        let size = serde_json::to_vec(&packet)?.len();
        ensure!(size > 65408, "fixture must exercise oversized native packets");
        let d = encrypt(&contact, &packet)?;
        assert_eq!(decrypt(&keys.secret_key().to_secret_hex(), &d)?.proofs, packet.proofs);
        println!("real native two-proof packet bytes={size}, encrypted chunks={}", d.ciphertexts.len());
        Ok(())
    }
    #[test]
    fn owner_budget_weight_preserves_policy_caps_and_numeric_recipient_binding() -> Result<()> {
        use crate::policy::{Limits, PolicyEngine};
        let mut engine = PolicyEngine::new();
        engine.set_current_wallet("n", 123);
        let policy = engine.create_policy(
            "test",
            Limits {
                per_transaction: 5000000000,
                per_day: 50000000000,
                per_month: None,
                total_budget: Some(50000000000),
            },
            Some(vec!["456".into()]),
            vec!["private_transfer".into()],
        );
        let (token, _) = engine.issue_session(&policy, 60, None)?;
        let asset = Asset {
            profile: Profile::default(),
            network: "n".into(),
            contract_id: 2457,
            code_root: String::new(),
            layout_root: String::new(),
            decimals: 18,
            policy_nano_per_token: 100000000,
        };
        let valid = charge(&asset, 20000000000000000017)?;
        assert_eq!(valid, 2000000001);
        assert!(engine.authorize_for("n", Some(123), &token, "789", valid, "private_transfer").is_err());
        assert!(engine.authorize_for("n", Some(999), &token, "456", valid, "private_transfer").is_err());
        assert!(
            engine
                .authorize_for("n", Some(123), &token, "456", charge(&asset, 60000000000000000000)?, "private_transfer")
                .is_err()
        );
        assert!(engine.authorize_for("n", Some(123), &token, "456", valid, "private_transfer").is_ok());
        Ok(())
    }
}
