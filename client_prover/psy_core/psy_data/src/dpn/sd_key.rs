use kvq::traits::KVQSerializable;
use plonky2::{field::{goldilocks_field::GoldilocksField, types::{Field64, PrimeField64}}, hash::hash_types::RichField};
use psy_client_common::{
    data::qhashout::QHashOut,
    traits::to_qfelts::{QFeltSized, ToQFelts},
};
use psy_crypto::hash::traits::{hasher::FieldQHasher, qhashable::QFieldHashable};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::dpn::proving_session::DPNProvingSessionCompactMethodCall;

/// Maximum number of transactions available to transaction introspection.
pub const MAX_INTROSPECTABLE_TRANSACTIONS: u32 = 64;
/// Bits needed to compare a transaction count against the inclusive capacity.
pub const SDKEY_TX_COUNT_BITS: usize = (u32::BITS - (MAX_INTROSPECTABLE_TRANSACTIONS + 1).leading_zeros()) as usize;

/// Maximum number of Felt words available from each transaction's calldata.
pub const SDKEY_MAX_CALLDATA_WORDS: u32 = 128;

/// Compact transaction info for SD key introspection.
///
/// Each transaction in a proving session can be introspected by the SD key
/// circuit at a compile-time-constant index. This struct holds the information
/// available for each transaction: the contract being called, the method,
/// and a hash of the inputs.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct SDKeyTransactionInfo<F: RichField> {
    /// Which contract this transaction calls.
    pub contract_id: F,
    /// The method ordinal (method_id) of the contract function being called.
    pub method_id: F,
    /// The calling contract id (or default caller for user-initiated txs).
    pub caller_contract_id: F,
    /// Number of inputs to the function call.
    pub inputs_length: F,
    /// Hash of the inputs.
    pub inputs_hash: QHashOut<F>,
}

impl<F: RichField> From<DPNProvingSessionCompactMethodCall<F>> for SDKeyTransactionInfo<F> {
    fn from(call: DPNProvingSessionCompactMethodCall<F>) -> Self {
        Self {
            contract_id: call.contract_id,
            method_id: call.method_id,
            caller_contract_id: call.caller_contract_id,
            inputs_length: call.inputs_length,
            inputs_hash: call.inputs_hash,
        }
    }
}

impl<F: RichField> QFeltSized for SDKeyTransactionInfo<F> {
    fn q_felt_size() -> usize {
        8
    }
}

impl<F: RichField> ToQFelts<F> for SDKeyTransactionInfo<F> {
    fn to_qfelts(&self) -> Vec<F> {
        vec![
            self.contract_id,
            self.method_id,
            self.caller_contract_id,
            self.inputs_length,
            self.inputs_hash.0.elements[0],
            self.inputs_hash.0.elements[1],
            self.inputs_hash.0.elements[2],
            self.inputs_hash.0.elements[3],
        ]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 8 {
            panic!("Invalid number of elements for SDKeyTransactionInfo, expected 8, got {}", felts.len());
        }
        Self {
            contract_id: felts[0],
            method_id: felts[1],
            caller_contract_id: felts[2],
            inputs_length: felts[3],
            inputs_hash: QHashOut::from_felt_slice(&felts[4..]),
        }
    }
}

impl<F: RichField> QFieldHashable<F> for SDKeyTransactionInfo<F> {
    fn qfhash<H: FieldQHasher<F>>(&self) -> QHashOut<F> {
        H::q_hash_many(&self.to_qfelts())
    }
}

impl<F: RichField> KVQSerializable for SDKeyTransactionInfo<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

/// Configuration for a software-defined key circuit.
///
/// Defines what capabilities the key circuit has and what it can introspect.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[ts(export)]
pub struct SDKeyAllowedTransactionCall {
    pub contract_id: u64,
    pub method_id: u32,
    /// None preserves the legacy allow-method behavior for this call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_contract_id: Option<u64>,
}

/// Optional allow-method policy with a bounded, variable transaction count.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[ts(export)]
pub struct SDKeyTransactionCountPolicy {
    pub min_tx_count: u32,
    pub max_tx_count: u32,
    pub allowed_calls: Vec<SDKeyAllowedTransactionCall>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composed: Option<SDKeyComposedPolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[ts(export)]
pub enum SDKeyCallRule {
    All(Vec<SDKeyCallRule>),
    Any(Vec<SDKeyCallRule>),
    Contract(u64),
    Method(u32),
    Caller(u64),
    Input { word: u32, comparison: SDKeyComparison, value: u64 },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[ts(export)]
pub enum SDKeyComparison { Eq, Lt, Lte, Gt, Gte }

/// A session-wide sum of one positional calldata word across transactions.
/// The caller must verify from each allowed method's ABI that this word has
/// the intended meaning and units. This policy does not identify amounts.
/// `max_per_tx` prevents field wraparound in the aggregate.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[ts(export)]
pub struct SDKeyInputTotalLimit {
    pub word: u32,
    pub max_per_tx: u64,
    pub max_total: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[ts(export)]
pub struct SDKeyComposedPolicy {
    pub per_transaction: SDKeyCallRule,
    pub ordered: Vec<SDKeyCallRule>,
    pub totals: Vec<SDKeyInputTotalLimit>,
}

impl SDKeyCallRule {
    /// Validate that a rule is structurally sound and that every leaf
    /// constant is a canonical field element the introspection circuit can
    /// compare against a witness target.
    pub fn validate(&self) -> anyhow::Result<()> {
        match self {
            Self::All(children) | Self::Any(children) => {
                anyhow::ensure!(!children.is_empty(), "SD key All/Any rule must not be empty");
                for child in children {
                    child.validate()?;
                }
            }
            Self::Input { word, value, .. } => {
                anyhow::ensure!(*word < SDKEY_MAX_CALLDATA_WORDS, "SD key input word {} exceeds calldata capacity", word);
                anyhow::ensure!(*value < GoldilocksField::ORDER, "SD key input comparison value must be a canonical field value");
            }
            Self::Contract(value) | Self::Caller(value) => {
                anyhow::ensure!(*value < GoldilocksField::ORDER, "SD key contract id must be a canonical field value");
            }
            Self::Method(_) => {}
        }
        Ok(())
    }
}

impl SDKeyInputTotalLimit {
    /// Validate the word range, canonical bounds, and that the worst-case sum
    /// cannot wrap the field at the given transaction capacity.
    pub fn validate(&self, max_tx_count: u32) -> anyhow::Result<()> {
        anyhow::ensure!(self.word < SDKEY_MAX_CALLDATA_WORDS, "SD key total input word {} exceeds calldata capacity", self.word);
        anyhow::ensure!(self.max_per_tx < GoldilocksField::ORDER && self.max_total < GoldilocksField::ORDER,
            "SD key total limit must be a canonical field value");
        anyhow::ensure!((self.max_per_tx as u128) * (max_tx_count as u128) < GoldilocksField::ORDER as u128,
            "SD key total could overflow the field");
        Ok(())
    }
}

impl SDKeyComposedPolicy {
    /// Validate rule structure, the ordered prefix against the minimum
    /// transaction count, and every total against the count capacity.
    pub fn validate(&self, min_tx_count: u32, max_tx_count: u32) -> anyhow::Result<()> {
        anyhow::ensure!(self.ordered.len() <= min_tx_count as usize, "SD key ordered rules exceed minimum transaction count");
        self.per_transaction.validate()?;
        for rule in &self.ordered {
            rule.validate()?;
        }
        for total in &self.totals {
            total.validate(max_tx_count)?;
        }
        Ok(())
    }

    /// Natively evaluate this policy against the transaction introspection
    /// data the SD key circuit will see, so a violating session fails with a
    /// descriptive error instead of an unsatisfied constraint at prove time.
    ///
    /// Mirrors the circuit constraints: `per_transaction` applies to every
    /// transaction, `ordered` rules additionally constrain the leading slots,
    /// and totals sum one calldata word across all transactions. The
    /// transaction count itself is checked separately by the prover against
    /// the configured range.
    pub fn check_transaction_infos<F: RichField + PrimeField64>(
        &self,
        infos: &[SDKeyTransactionInfo<F>],
        inputs: &[Vec<F>],
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            inputs.len() == infos.len(),
            "composed policy check received {} input vectors for {} transactions",
            inputs.len(),
            infos.len()
        );
        for (index, (info, words)) in infos.iter().zip(inputs.iter()).enumerate() {
            if !Self::rule_matches(&self.per_transaction, info, words) {
                anyhow::bail!("SD key policy denies transaction {}: rule {:?}", index, self.per_transaction);
            }
            if let Some(rule) = self.ordered.get(index) {
                if !Self::rule_matches(rule, info, words) {
                    anyhow::bail!("SD key policy denies transaction {}: ordered slot rule {:?}", index, rule);
                }
            }
        }
        for total in &self.totals {
            let mut sum: u128 = 0;
            for (index, (info, words)) in infos.iter().zip(inputs.iter()).enumerate() {
                let present = info.inputs_length.to_canonical_u64() as usize > total.word as usize;
                anyhow::ensure!(present, "SD key total requires calldata word {} in transaction {}", total.word, index);
                let value = words
                    .get(total.word as usize)
                    .ok_or_else(|| anyhow::anyhow!("SD key total word {} missing from transaction {} inputs", total.word, index))?
                    .to_canonical_u64();
                anyhow::ensure!(
                    value <= total.max_per_tx,
                    "SD key total word {} in transaction {} is {}, above per-transaction limit {}",
                    total.word,
                    index,
                    value,
                    total.max_per_tx
                );
                sum += value as u128;
            }
            anyhow::ensure!(
                sum <= total.max_total as u128,
                "SD key total word {} sums to {} across transactions, above limit {}",
                total.word,
                sum,
                total.max_total
            );
        }
        Ok(())
    }

    fn rule_matches<F: RichField + PrimeField64>(
        rule: &SDKeyCallRule,
        info: &SDKeyTransactionInfo<F>,
        words: &[F],
    ) -> bool {
        match rule {
            SDKeyCallRule::All(children) => children.iter().all(|child| Self::rule_matches(child, info, words)),
            SDKeyCallRule::Any(children) => children.iter().any(|child| Self::rule_matches(child, info, words)),
            SDKeyCallRule::Contract(id) => info.contract_id.to_canonical_u64() == *id,
            SDKeyCallRule::Method(id) => info.method_id.to_canonical_u64() == *id as u64,
            SDKeyCallRule::Caller(id) => info.caller_contract_id.to_canonical_u64() == *id,
            SDKeyCallRule::Input { word, comparison, value } => {
                let present = info.inputs_length.to_canonical_u64() as usize > *word as usize;
                if !present {
                    return false;
                }
                let Some(actual) = words.get(*word as usize) else {
                    return false;
                };
                let actual = actual.to_canonical_u64();
                match comparison {
                    SDKeyComparison::Eq => actual == *value,
                    SDKeyComparison::Lt => actual < *value,
                    SDKeyComparison::Lte => actual <= *value,
                    SDKeyComparison::Gt => actual > *value,
                    SDKeyComparison::Gte => actual >= *value,
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[ts(export)]
pub struct SDKeyConfig {
    /// Maximum number of transactions the key circuit can introspect. This is
    /// the fixed capacity of the circuit; the actual count is a witness.
    pub num_introspectable_transactions: u32,

    /// Optional policy for circuits that authorize a range of transaction
    /// counts and restrict the calls in active transaction slots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_count_policy: Option<SDKeyTransactionCountPolicy>,

    /// Whether this key circuit can read contract state at the current
    /// checkpoint.
    pub can_read_state: bool,

    /// Height of the contract state tree if state reading is enabled.
    pub contract_state_tree_height: u8,

    /// Whether this key circuit verifies secp256k1 signatures.
    pub requires_secp256k1: bool,

    /// Number of secp256k1 signature verification slots in the circuit.
    pub num_secp256k1_slots: u32,

    /// Contract id used for DPN state reads.
    pub contract_id: u64,
}

/// Compiled output of an SD key definition.
///
/// This is the output of compiling a PSY source file as an SD key.
/// It contains the DPN circuit definition for the key authorization logic
/// plus the SD key configuration metadata.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, TS)]
#[ts(export)]
pub struct SDKeyDefinition {
    /// The compiled authorization logic as a DPN function circuit.
    pub authorization_circuit: Vec<u8>,

    /// SD key configuration.
    pub config: SDKeyConfig,

    /// Name of the key definition (from the contract name).
    pub name: String,
}

impl KVQSerializable for SDKeyDefinition {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

/// Secp256k1 signature data provided as witness to the SD key circuit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Default, TS)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
#[ts(export, concrete(F = GoldilocksField))]
pub struct SDKeySecp256k1WitnessSlot<F: RichField> {
    /// The compressed public key (as 16 field elements for circuit
    /// representation).
    pub public_key: [F; 16],
    /// The message hash being signed.
    pub msg_hash: QHashOut<F>,
    /// The signature (as 16 field elements for circuit representation).
    pub signature: [F; 16],
}

impl<F: RichField> KVQSerializable for SDKeySecp256k1WitnessSlot<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

#[cfg(test)]
mod composed_policy_tests {
    use super::*;
    use plonky2::field::types::Field;

    fn tx(contract_id: u64, method_id: u32, inputs: &[u64]) -> (SDKeyTransactionInfo<GoldilocksField>, Vec<GoldilocksField>) {
        (
            SDKeyTransactionInfo {
                contract_id: GoldilocksField::from_canonical_u64(contract_id),
                method_id: GoldilocksField::from_canonical_u32(method_id),
                caller_contract_id: GoldilocksField::from_canonical_u64(0),
                inputs_length: GoldilocksField::from_canonical_u64(inputs.len() as u64),
                inputs_hash: QHashOut::default(),
            },
            inputs.iter().map(|value| GoldilocksField::from_canonical_u64(*value)).collect(),
        )
    }

    fn pairs(calls: &[(u64, u32, &[u64])]) -> (Vec<SDKeyTransactionInfo<GoldilocksField>>, Vec<Vec<GoldilocksField>>) {
        let pairs: Vec<_> = calls.iter().map(|(contract, method, inputs)| tx(*contract, *method, inputs)).collect();
        (pairs.iter().map(|(info, _)| *info).collect(), pairs.into_iter().map(|(_, words)| words).collect())
    }

    fn sample_policy() -> SDKeyComposedPolicy {
        SDKeyComposedPolicy {
            per_transaction: SDKeyCallRule::All(vec![
                SDKeyCallRule::Contract(5),
                SDKeyCallRule::Any(vec![SDKeyCallRule::Method(10), SDKeyCallRule::Method(20)]),
            ]),
            ordered: vec![SDKeyCallRule::Method(10), SDKeyCallRule::Method(20)],
            totals: vec![SDKeyInputTotalLimit { word: 0, max_per_tx: 100, max_total: 150 }],
        }
    }

    #[test]
    fn accepts_conforming_session() {
        let policy = sample_policy();
        let (infos, inputs) = pairs(&[(5, 10, &[60]), (5, 20, &[80, 7])]);
        policy.check_transaction_infos(&infos, &inputs).unwrap();
    }

    #[test]
    fn rejects_wrong_contract_method_and_order() {
        let policy = sample_policy();
        let wrong_contract = pairs(&[(7, 10, &[0]), (5, 20, &[0])]);
        assert!(policy.check_transaction_infos(&wrong_contract.0, &wrong_contract.1).is_err());
        let wrong_method = pairs(&[(5, 30, &[0]), (5, 20, &[0])]);
        assert!(policy.check_transaction_infos(&wrong_method.0, &wrong_method.1).is_err());
        let wrong_order = pairs(&[(5, 20, &[0, 7]), (5, 10, &[0])]);
        assert!(policy.check_transaction_infos(&wrong_order.0, &wrong_order.1).is_err());
    }

    #[test]
    fn rejects_total_violations_and_missing_word() {
        let policy = sample_policy();
        let over_total = pairs(&[(5, 10, &[80]), (5, 20, &[80, 7])]);
        assert!(policy.check_transaction_infos(&over_total.0, &over_total.1).is_err());
        let missing_word = pairs(&[(5, 10, &[]), (5, 20, &[80, 7])]);
        assert!(policy.check_transaction_infos(&missing_word.0, &missing_word.1).is_err());
        let per_tx = pairs(&[(5, 10, &[101]), (5, 20, &[0, 7])]);
        assert!(policy.check_transaction_infos(&per_tx.0, &per_tx.1).is_err());
    }

    #[test]
    fn input_comparison_follows_word_presence() {
        let policy = SDKeyComposedPolicy {
            per_transaction: SDKeyCallRule::Input { word: 1, comparison: SDKeyComparison::Eq, value: 7 },
            ordered: vec![],
            totals: vec![],
        };
        let present = pairs(&[(5, 10, &[0, 7])]);
        policy.check_transaction_infos(&present.0, &present.1).unwrap();
        let wrong_value = pairs(&[(5, 10, &[0, 8])]);
        assert!(policy.check_transaction_infos(&wrong_value.0, &wrong_value.1).is_err());
        let absent = pairs(&[(5, 10, &[0])]);
        assert!(policy.check_transaction_infos(&absent.0, &absent.1).is_err());
    }

    #[test]
    fn ordered_rules_only_bind_leading_slots() {
        let policy = SDKeyComposedPolicy {
            per_transaction: SDKeyCallRule::Contract(5),
            ordered: vec![SDKeyCallRule::Method(10)],
            totals: vec![],
        };
        let trailing = pairs(&[(5, 10, &[0]), (5, 20, &[0]), (5, 30, &[0])]);
        policy.check_transaction_infos(&trailing.0, &trailing.1).unwrap();
    }
}
