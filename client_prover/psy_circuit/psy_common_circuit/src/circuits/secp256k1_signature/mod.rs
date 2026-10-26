use std::marker::PhantomData;

use plonky2::{
    gates::gate::GateRef,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::{data::qhashout::QHashOut, utils::debug_timer::DebugTimer};
use psy_crypto::signature::secp256k1::core::{PsyCompressedSecp256K1Signature, PsyPreparedSecp256K1Signature};

use super::traits::qstandard::QStandardCircuit;
use crate::{
    crypto::secp256k1::gadget::{Secp256K1Gadget, DOGE_PSY_PREFIX, EIP191_PREFIX_32},
    proof_minifier::pm_chain::PsyProofMinifierChain,
    u32::gates::comparison::ComparisonGate,
};

/// Identifies which message-prefix flavor a secp256k1 signature circuit is built
/// with. The prefix is the ONLY difference between flavors — the gadget wiring,
/// minifier chain and `prove` are fully shared via [`Secp256K1SignatureCircuitBase`].
pub trait Secp256K1SignatureFlavor: Send + Sync + 'static {
    const PREFIX: &'static [u8];
}

/// Classic Doge/Psy flavor: the ECDSA message is the raw sighash (no prefix).
#[derive(Debug, Clone, Copy)]
pub struct DogePsySignatureFlavor;
impl Secp256K1SignatureFlavor for DogePsySignatureFlavor {
    const PREFIX: &'static [u8] = DOGE_PSY_PREFIX;
}

/// EIP-191 `personal_sign` flavor: the ECDSA message is
/// `keccak256("\x19Ethereum Signed Message:\n32" || sighash)`, while the raw
/// sighash is still bound into `combined_hash`.
#[derive(Debug, Clone, Copy)]
pub struct EthPersonalSignSignatureFlavor;
impl Secp256K1SignatureFlavor for EthPersonalSignSignatureFlavor {
    const PREFIX: &'static [u8] = EIP191_PREFIX_32;
}

#[derive(Debug)]
pub struct Secp256K1SignatureCircuitBase<M: Secp256K1SignatureFlavor, C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub signature_gadget: Secp256K1Gadget,
    pub base_circuit_data: CircuitData<C::F, C, D>,
    pub minifier_chain: PsyProofMinifierChain<D, C::F, C>,
    _flavor: PhantomData<M>,
}

/// Classic Doge/Psy secp256k1 signature circuit (raw sighash, no prefix).
pub type Secp256K1SignatureCircuit<C, const D: usize> = Secp256K1SignatureCircuitBase<DogePsySignatureFlavor, C, D>;
/// EIP-191 `personal_sign` secp256k1 signature circuit (keccak-prefixed).
pub type EthPersonalSignSecp256K1SignatureCircuit<C, const D: usize> = Secp256K1SignatureCircuitBase<EthPersonalSignSignatureFlavor, C, D>;

impl<M: Secp256K1SignatureFlavor, C: GenericConfig<D>, const D: usize> Clone for Secp256K1SignatureCircuitBase<M, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<M: Secp256K1SignatureFlavor, C: GenericConfig<D>, const D: usize> Secp256K1SignatureCircuitBase<M, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    pub fn new() -> Self {
        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<C::F, D>::new(config);
        let signature_gadget = Secp256K1Gadget::add_virtual_to::<C::Hasher, C::F, D>(&mut builder, M::PREFIX);

        builder.register_public_inputs(&signature_gadget.combined_hash.elements);
        let circuit_data = builder.build::<C>();

        let added_gates_for_minifier = [GateRef::new(ComparisonGate::new(32, 16))];

        let minifier_chain =
            PsyProofMinifierChain::<D, C::F, C>::new_add_gates(&circuit_data.verifier_only, &circuit_data.common, 2, Some(&added_gates_for_minifier));

        Self {
            base_circuit_data: circuit_data,
            signature_gadget,
            minifier_chain,
            _flavor: PhantomData,
        }
    }
    pub fn prove(&self, compressed_signature: &PsyCompressedSecp256K1Signature) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        let prepared_signature: PsyPreparedSecp256K1Signature<C::F> = compressed_signature.try_into()?;

        let mut timer = DebugTimer::new("Secp256K1SignatureCircuit::Prove");
        tracing::info!("start prove base secp256k1 signature");
        timer.lap("start prove base");
        let mut pw = PartialWitness::new();
        self.signature_gadget.set_witness_public_keys_update(
            &mut pw,
            &prepared_signature.public_key,
            &prepared_signature.signature,
            prepared_signature.message,
        )?;
        let base_proof = self.base_circuit_data.prove(pw)?;
        timer.lap("end prove base");
        tracing::info!("end prove base secp256k1 signature");
        timer.lap("start minifier");
        let minified_proof = self.minifier_chain.prove(&base_proof)?;
        timer.lap("end minifier");
        Ok(minified_proof)
    }
}

impl<M: Secp256K1SignatureFlavor, C: GenericConfig<D>, const D: usize> QStandardCircuit<C, D> for Secp256K1SignatureCircuitBase<M, C, D>
where
    C::Hasher: AlgebraicHasher<C::F>,
{
    fn get_fingerprint(&self) -> QHashOut<C::F> {
        QHashOut(self.minifier_chain.get_fingerprint())
    }

    fn get_verifier_config_ref(&self) -> &VerifierOnlyCircuitData<C, D> {
        self.minifier_chain.get_verifier_data()
    }

    fn get_common_circuit_data_ref(&self) -> &CommonCircuitData<C::F, D> {
        self.minifier_chain.get_common_data()
    }
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        plonk::config::{Hasher, PoseidonGoldilocksConfig},
    };
    use psy_client_common::data::{qhashout::QHashOut, secp256k1::CompressedPublicKey};
    use psy_crypto::signature::secp256k1::wallet::{ethereum_address_for_verifying_key, hash_no_pad_compressed_public_key, recover_eth_personal_signature};

    use super::EthPersonalSignSecp256K1SignatureCircuit;

    #[test]
    fn eth_personal_host_signature_proves_and_binds_raw_message() {
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let circuit = EthPersonalSignSecp256K1SignatureCircuit::<C, D>::new();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();
        let message = psy_client_common::data::base_types::hash256::Hash256([0x51; 32]);
        let digest = psy_crypto::signature::secp256k1::wallet::eth_personal_sign_digest(&message.0);
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let address_digest = ethereum_address_for_verifying_key(signing_key.verifying_key());
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&signature.to_bytes());
        signature_bytes[64] = recovery_id.to_byte();
        let recovered = recover_eth_personal_signature(address_digest, message, signature_bytes).unwrap();

        let proof = circuit.prove(&recovered).unwrap();
        circuit.minifier_chain.verify(proof.clone()).unwrap();

        let public_key_hash = hash_no_pad_compressed_public_key::<GoldilocksField, plonky2::hash::poseidon::PoseidonPermutation<GoldilocksField>>(
            CompressedPublicKey(recovered.public_key),
        );
        let message_hash = QHashOut::<GoldilocksField>::from(recovered.message);
        let expected = plonky2::hash::poseidon::PoseidonHash::two_to_one(message_hash.0, public_key_hash.0);
        assert_eq!(proof.public_inputs, expected.elements);
    }

    /// H2 probe (PRE-FIX documentation; the gadget boundary now range-checks
    /// the y/r/s input limbs) — documents what a single-limb non-u32
    /// corruption does, and what this does NOT establish:
    ///
    /// - Residue-preserving corruption (limb + ORDER, same field element)
    ///   proves: witness representation freedom, harmless; every constraint is
    ///   a mod-p identity.
    /// - Genuine non-u32 residues (limb + 2^32) on y, s, or x all fail — but
    ///   at the WITNESS-GENERATION stage ("partition ... was set twice"), i.e.
    ///   generators disagree because they assume canonical u32 inputs.
    ///   Generators are prover-side convenience: an attacker supplying a full
    ///   witness never runs them, so these rejections say NOTHING about
    ///   soundness. They only rule out this one naive strategy of corrupting a
    ///   limb and letting generators fill the rest.
    ///
    /// Whether the constraint system itself (without the generators) admits a
    /// non-u32 limb assignment — the actual H2 question — is NOT answered
    /// here; it would require a fully hand-crafted witness search, and any
    /// successful candidate would additionally need `verify` plus a public
    /// input comparison against the honest statement before counting as a
    /// reproduction.
    #[test]
    fn h2_probe_single_limb_non_u32_corruption_fails_at_witness_generation() {
        use plonky2::{
            field::types::{Field, Field64, PrimeField64},
            iop::witness::{Witness, WitnessWrite},
        };
        use psy_crypto::signature::secp256k1::core::PsyPreparedSecp256K1Signature;

        use crate::hash::base_types::hash256bytes::WitnessHash256Bytes;

        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let circuit = EthPersonalSignSecp256K1SignatureCircuit::<C, D>::new();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();
        let message = psy_client_common::data::base_types::hash256::Hash256([0x51; 32]);
        let digest = psy_crypto::signature::secp256k1::wallet::eth_personal_sign_digest(&message.0);
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let address_digest = ethereum_address_for_verifying_key(signing_key.verifying_key());
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&signature.to_bytes());
        signature_bytes[64] = recovery_id.to_byte();
        let recovered = recover_eth_personal_signature(address_digest, message, signature_bytes).unwrap();
        let prepared: PsyPreparedSecp256K1Signature<GoldilocksField> = (&recovered).try_into().unwrap();

        // Manual replica of set_witness_public_keys_update (which double-sets
        // via set_biguint_target and cannot be overridden afterwards): set each
        // limb directly, optionally replacing one limb's residue with
        // honest + 2^32 — a genuinely non-u32 residue (< p, no wraparound).
        let u32_digits = |arr: &[u64; 4]| -> Vec<u32> {
            arr.iter().flat_map(|w| [*w as u32, (*w >> 32) as u32]).collect()
        };
        let set_limbs = |pw: &mut plonky2::iop::witness::PartialWitness<GoldilocksField>,
                         limbs: &[crate::u32::arithmetic_u32::U32Target],
                         digits: &[u32],
                         bad: Option<(usize, u64)>| {
            for (i, limb) in limbs.iter().enumerate() {
                let value = match bad {
                    Some((idx, v)) if i == idx => v,
                    _ => *digits.get(i).unwrap_or(&0) as u64,
                };
                pw.set_target(limb.0, GoldilocksField::from_canonical_u64(value)).unwrap();
            }
        };
        let x_digits = u32_digits(&prepared.public_key.0.x.0);
        let y_digits = u32_digits(&prepared.public_key.0.y.0);
        let r_digits = u32_digits(&prepared.signature.r.0);
        let s_digits = u32_digits(&prepared.signature.s.0);

        let fresh_witness = |bad_y: Option<(usize, u64)>, bad_s: Option<(usize, u64)>, bad_x: Option<(usize, u64)>| {
            let mut pw = plonky2::iop::witness::PartialWitness::new();
            let g = &circuit.signature_gadget;
            pw.set_hash256_bytes_target(&g.msg_bytes_target, &prepared.message.to_le_bytes()).unwrap();
            set_limbs(&mut pw, &g.public_key_x_target.limbs, &x_digits, bad_x);
            set_limbs(&mut pw, &g.public_key_y_target.limbs, &y_digits, bad_y);
            set_limbs(&mut pw, &g.signature_r_target.limbs, &r_digits, None);
            set_limbs(&mut pw, &g.signature_s_target.limbs, &s_digits, bad_s);
            pw
        };

        // Case 0: residue-preserving corruption (limb + ORDER, same field
        // element, non-canonical u64) — representation freedom, proves fine.
        // Pick a limb where digit + ORDER still fits in a u64.
        let alias_idx = (1..y_digits.len()).find(|&i| y_digits[i] <= 0xFFFF_FFFD).expect("a small y digit");
        let pw = fresh_witness(Some((alias_idx, y_digits[alias_idx] as u64 + GoldilocksField::ORDER)), None, None);
        let proved = circuit.base_circuit_data.prove(pw).is_ok();
        assert!(proved, "same-residue alias (honest+ORDER) is representation freedom and must prove");

        // Case 1: one pk.y limb with a genuine non-u32 residue (honest + 2^32).
        // NOTE: this only probes ONE specific corruption (single limb, everything
        // else generator-consistent). A rejection here does NOT establish that
        // the constraint system confines limbs to u32 — it only rules out this
        // particular attempt. If this case ever passes, the proof must be
        // verified and its public inputs compared against the honest statement
        // before calling it a reproduction.
        let pw = fresh_witness(Some((1, y_digits[1] as u64 + (1u64 << 32))), None, None);
        let err = circuit.base_circuit_data.prove(pw).err().expect("non-u32 pk.y limb corruption is currently rejected");
        println!("y corruption rejected by: {err:#}");

        // Case 2: same corruption on one signature s limb.
        let pw = fresh_witness(None, Some((1, s_digits[1] as u64 + (1u64 << 32))), None);
        let err = circuit.base_circuit_data.prove(pw).err().expect("non-u32 s limb corruption is currently rejected");
        println!("s corruption rejected by: {err:#}");

        // Control: the same corruption on a pk.x limb (explicitly range-checked).
        let pw = fresh_witness(None, None, Some((1, x_digits[1] as u64 + (1u64 << 32))));
        let err = circuit.base_circuit_data.prove(pw).err().expect("control: pk.x limb corruption is rejected");
        println!("x control rejected by: {err:#}");
    }

    /// H2 follow-up: integer-preserving non-u32 limb corruption.
    ///
    /// POST-FIX REGRESSION TEST: `Secp256K1Gadget::add_virtual_to` now
    /// range-checks every externally-supplied y/r/s limb at the gadget
    /// boundary (`range_check_u32_circuit` in crypto/secp256k1/gadget.rs; the
    /// x limbs were already confined by `u32_reverse_endian`'s
    /// `split_le(x, 32)`), so ALL corruptions attempted below must be
    /// REJECTED at the constraint level. The paragraphs below are kept as
    /// pre-fix documentation of how the s-limb malleability worked.
    ///
    /// Pre-fix documentation: corrupting a limb PAIR `(i, i+1)` as
    /// `limb[i] += 2^32, limb[i+1] -= 1` keeps the represented 256-bit
    /// integer (and hence every integer-level generator output) identical,
    /// while making `limb[i]` a genuine non-u32 residue.
    ///
    /// Static analysis motivating the cases below (pre-fix gadget state):
    /// - `add_virtual_u32_targets` performs no range check
    ///   (u32/gadgets/arithmetic_u32.rs:82-84), and `mul_nonnative` /
    ///   `inv_nonnative` range-check only their OUTPUTS
    ///   (crypto/secp256k1/ecdsa/gadgets/nonnative.rs:260-261,291-315), so the
    ///   s limbs (which feed only `inv_nonnative`'s `mul_biguint`) have no
    ///   explicit u32 confinement.
    /// - `U32ArithmeticGate` confines only its output halves via 2-bit limb
    ///   decomposition plus the high-limb canonicity trick
    ///   (u32/gates/arithmetic_u32.rs:92-149); inputs are raw field elements
    ///   and the gate equation holds mod p_goldilocks. A non-u32 input limb
    ///   therefore only breaks the surrounding integer semantics when a
    ///   product `(limb_i + 2^32) * limb_j >= p_goldilocks` wraps; the
    ///   wrap-free condition is checkable on the host.
    /// - Given the input limbs, each u32 gate's outputs are essentially
    ///   uniquely determined (the `combined + p < 2^64` ambiguity is killed by
    ///   the canonicity constraint except at output 0), so the values the
    ///   generators compute are the only candidate satisfying assignment; a
    ///   generator-consistent witness that passes `verify` is therefore a
    ///   genuine constraint-system pass, not an artifact of generator hints.
    ///
    /// Outcome legend printed by the test:
    /// - s corruption with a host-verified wrap-free limb pair: PRE-FIX this
    ///   proved AND verified with public inputs identical to the honest
    ///   statement (H2 reproduced: s is never hashed into `combined_hash`).
    ///   POST-FIX it must be rejected by the boundary range check.
    /// - r corruption: expected failure — pre-fix because
    ///   `connect_nonnative(r, x)` copy-ties r's limbs to the curve-computed,
    ///   range-checked x limbs; post-fix also via the boundary range check.
    /// - x corruption: expected failure via `u32_reverse_endian`'s
    ///   `split_le(x, 32)` — unchanged by the fix.
    /// - y corruption: post-fix rejected by the boundary range check; y limbs
    ///   are additionally Poseidon-hashed into `combined_hash`, so even a
    ///   successful proof would bind a DIFFERENT statement.
    #[test]
    fn h2_attempt_integer_preserving_non_u32_witness() {
        use plonky2::{
            field::types::{Field, PrimeField},
            iop::witness::WitnessWrite,
        };
        use psy_crypto::signature::secp256k1::core::PsyPreparedSecp256K1Signature;

        use crate::hash::base_types::hash256bytes::WitnessHash256Bytes;

        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;
        const P_GOLD: u128 = 0xFFFF_FFFF_0000_0001u128; // GoldilocksField::ORDER

        let circuit = EthPersonalSignSecp256K1SignatureCircuit::<C, D>::new();
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();

        let u32_digits = |arr: &[u64; 4]| -> Vec<u32> {
            arr.iter().flat_map(|w| [*w as u32, (*w >> 32) as u32]).collect()
        };

        let prepare = |msg_byte: u8| {
            let message = psy_client_common::data::base_types::hash256::Hash256([msg_byte; 32]);
            let digest = psy_crypto::signature::secp256k1::wallet::eth_personal_sign_digest(&message.0);
            let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
            let address_digest = ethereum_address_for_verifying_key(signing_key.verifying_key());
            let mut signature_bytes = [0u8; 65];
            signature_bytes[..64].copy_from_slice(&signature.to_bytes());
            signature_bytes[64] = recovery_id.to_byte();
            let recovered = recover_eth_personal_signature(address_digest, message, signature_bytes).unwrap();
            let prepared: PsyPreparedSecp256K1Signature<GoldilocksField> = (&recovered).try_into().unwrap();
            (message, prepared)
        };

        // Build a witness with optional integer-preserving pair corruptions:
        // (limb_index, delta) applied as limb[i] += delta, limb[i+1] -= 1.
        let build_witness = |prepared: &PsyPreparedSecp256K1Signature<GoldilocksField>,
                             bad_x: Option<usize>,
                             bad_y: Option<usize>,
                             bad_r: Option<usize>,
                             bad_s: Option<usize>|
         -> plonky2::iop::witness::PartialWitness<GoldilocksField> {
            let mut pw = plonky2::iop::witness::PartialWitness::new();
            let g = &circuit.signature_gadget;
            pw.set_hash256_bytes_target(&g.msg_bytes_target, &prepared.message.to_le_bytes()).unwrap();
            let apply = |digits: &[u32], bad: Option<usize>| -> Vec<u64> {
                let mut v: Vec<u64> = digits.iter().map(|&d| d as u64).collect();
                if let Some(i) = bad {
                    assert!(v[i + 1] >= 1, "compensation limb must be nonzero");
                    v[i] += 1u64 << 32;
                    v[i + 1] -= 1;
                }
                v
            };
            let set = |pw: &mut plonky2::iop::witness::PartialWitness<GoldilocksField>,
                       limbs: &[crate::u32::arithmetic_u32::U32Target],
                       vals: &[u64]| {
                for (limb, &val) in limbs.iter().zip(vals) {
                    pw.set_target(limb.0, GoldilocksField::from_canonical_u64(val)).unwrap();
                }
            };
            set(&mut pw, &g.public_key_x_target.limbs, &apply(&u32_digits(&prepared.public_key.0.x.0), bad_x));
            set(&mut pw, &g.public_key_y_target.limbs, &apply(&u32_digits(&prepared.public_key.0.y.0), bad_y));
            set(&mut pw, &g.signature_r_target.limbs, &apply(&u32_digits(&prepared.signature.r.0), bad_r));
            set(&mut pw, &g.signature_s_target.limbs, &apply(&u32_digits(&prepared.signature.s.0), bad_s));
            pw
        };

        // Honest baseline.
        let (_message, prepared) = prepare(0x51);
        let honest_proof = circuit
            .base_circuit_data
            .prove(build_witness(&prepared, None, None, None, None))
            .expect("honest prove");
        circuit.base_circuit_data.verify(honest_proof.clone()).expect("honest verify");
        let honest_pi = honest_proof.public_inputs.clone();
        println!("honest public inputs: {honest_pi:?}");

        // Case s (post-fix regression): find a signature where corrupting s
        // limb pair (i, i+1) keeps every u32-gate product wrap-free, i.e.
        // (s_i + 2^32) * max_limb(inv) < p_goldilocks, where inv = s^-1 mod n
        // is the only value s is ever multiplied with (inside inv_nonnative).
        // Pre-fix this corruption proved AND verified with public inputs
        // identical to the honest statement (H2 reproduced). Post-fix the
        // boundary range check on the s limbs must reject it at verify time
        // (witness generation still succeeds: the U32RangeCheckGenerator
        // truncates out-of-range inputs, and the wrap-free condition keeps
        // every other generator consistent).
        let mut s_candidates = 0usize;
        for attempt in 0..64u8 {
            let (_m, prepared) = prepare(0x60 + attempt);
            let s_digits = u32_digits(&prepared.signature.s.0);
            let s_scalar = plonky2::field::secp256k1_scalar::Secp256K1Scalar(prepared.signature.s.0);
            let inv_limbs = s_scalar.inverse().to_canonical_biguint().to_u32_digits();
            let inv_max = *inv_limbs.iter().max().unwrap() as u128;
            let candidate = (1..=6usize)
                .filter(|&i| s_digits[i + 1] >= 1)
                .filter(|&i| (s_digits[i] as u128 + (1u128 << 32)) * inv_max < P_GOLD)
                .min_by_key(|&i| s_digits[i]);
            let Some(i) = candidate else { continue };
            s_candidates += 1;
            println!(
                "s attempt {attempt}: corrupting s limbs ({i}, {}) with s[i]={}, inv_max={inv_max}",
                i + 1,
                s_digits[i]
            );
            let proof = circuit
                .base_circuit_data
                .prove(build_witness(&prepared, None, None, None, Some(i)))
                .expect("wrap-free corruption must still generate a complete witness");
            assert!(
                circuit.base_circuit_data.verify(proof).is_err(),
                "post-fix regression: the boundary range check must reject the non-u32 s limb"
            );
            println!("s attempt {attempt}: verify rejected by the boundary range check (regression covered)");
        }
        assert!(s_candidates > 0, "need at least one wrap-free s candidate to exercise the regression");
        println!("s corruption now rejected in all {s_candidates} wrap-free candidates (pre-fix: verified)");

        // Control r: integer-preserving corruption must fail — pre-fix because
        // r is copy-tied to the range-checked curve output x limbs; post-fix
        // the boundary range check on r's limbs rejects it as well.
        {
            let r_digits = u32_digits(&prepared.signature.r.0);
            let i = (1..=6usize).find(|&i| r_digits[i + 1] >= 1).expect("r compensation limb");
            match circuit.base_circuit_data.prove(build_witness(&prepared, None, None, Some(i), None)) {
                Ok(proof) => match circuit.base_circuit_data.verify(proof) {
                    Ok(()) => println!("UNEXPECTED: r corruption verified"),
                    Err(e) => println!("r corruption: prove ok, verify rejected: {e:#}"),
                },
                Err(e) => println!("r corruption: prove rejected: {e:#}"),
            }
        }

        // Control x: confined by u32_reverse_endian -> split_le(x, 32).
        {
            let x_digits = u32_digits(&prepared.public_key.0.x.0);
            let i = (1..=6usize).find(|&i| x_digits[i + 1] >= 1).expect("x compensation limb");
            match circuit.base_circuit_data.prove(build_witness(&prepared, Some(i), None, None, None)) {
                Ok(proof) => match circuit.base_circuit_data.verify(proof) {
                    Ok(()) => println!("UNEXPECTED: x corruption verified"),
                    Err(e) => println!("x corruption: prove ok, verify rejected: {e:#}"),
                },
                Err(e) => println!("x corruption: prove rejected: {e:#}"),
            }
        }

        // y attempt: pre-fix, y limbs 1..7 had no explicit range check (only
        // limb 0 was split for parity); post-fix the boundary range check
        // covers all of them. y limbs are additionally Poseidon-hashed into
        // combined_hash and feed curve multiplications. Try the smallest
        // corruptible limb pair and report.
        {
            let y_digits = u32_digits(&prepared.public_key.0.y.0);
            let i = (1..=6usize)
                .filter(|&i| y_digits[i + 1] >= 1)
                .min_by_key(|&i| y_digits[i])
                .expect("y compensation limb");
            println!("y attempt: corrupting y limbs ({i}, {}), y[i]={}", i + 1, y_digits[i]);
            match circuit.base_circuit_data.prove(build_witness(&prepared, None, Some(i), None, None)) {
                Ok(proof) => match circuit.base_circuit_data.verify(proof.clone()) {
                    Ok(()) => println!(
                        "H2 REPRODUCED on y (representation level): verified; public inputs match honest: {}",
                        proof.public_inputs == honest_pi
                    ),
                    Err(e) => println!("y corruption: prove ok, verify rejected: {e:#}"),
                },
                Err(e) => println!("y corruption: prove rejected: {e:#}"),
            }
        }
    }

    /// H2 Target B — constraint-level test of y-limb confinement via full
    /// generator bypass.
    ///
    /// POST-FIX NOTE: the gadget boundary now range-checks all y/r/s limbs, so
    /// the corrupted cases below are rejected by the boundary
    /// `U32RangeCheckGate` even if the internal network would accept them; the
    /// constraint-level analysis below is kept as pre-fix documentation and
    /// the harness remains a useful bypass rig.
    ///
    /// The previous y attempt died with a generator conflict ("partition set
    /// twice"), which says nothing about the constraint system. Here we:
    /// 1. build the exact same circuit ourselves (asserted identical via
    ///    `verifier_only`/`common` equality),
    /// 2. run a CUSTOM witness-generation loop that replicates plonky2's
    ///    `generate_partial_witness` but, instead of aborting on a conflict,
    ///    logs it (generator id, target, both values) and force-resolves it
    ///    via the public `PartitionWitness.values` (policy: keep-first or
    ///    keep-last — we run both),
    /// 3. feed the resulting fully-populated `PartitionWitness` directly to
    ///    `prove_with_partition_witness`, bypassing generators entirely, and
    ///    then `verify`.
    ///
    /// Under the forcedness argument (every u32-gate output is uniquely
    /// determined by its inputs — the `combined + p_goldilocks` ambiguity is
    /// killed by the canonicity constraint — and every nonnative intermediate
    /// is copy-tied to such an output), the generator-computed values are the
    /// ONLY candidate assignment given the input limbs. Hence:
    /// - if verify PASSES under some policy, the constraint system accepts a
    ///    non-u32 y limb (and the proof's public inputs tell us what statement
    ///    was actually proven — y is Poseidon-hashed into combined_hash);
    /// - if verify FAILS under both policies and the conflict log shows two
    ///    generator paths forcing different values onto one copy-partition,
    ///    that partition is the constraint-level confinement point for y.
    #[test]
    fn h2_target_b_y_limb_generator_bypass() {
        use std::collections::BTreeMap;

        use plonky2::{
            field::types::Field,
            hash::poseidon::PoseidonHash,
            iop::{
                generator::{GeneratedValues, WitnessGenerator},
                target::Target,
                witness::{PartitionWitness, Witness, WitnessWrite},
            },
            plonk::{
                circuit_builder::CircuitBuilder,
                circuit_data::{CircuitConfig, CircuitData},
                prover::prove_with_partition_witness,
            },
            util::timing::TimingTree,
        };
        use psy_crypto::signature::secp256k1::core::PsyPreparedSecp256K1Signature;

        use crate::{
            crypto::secp256k1::gadget::{Secp256K1Gadget, EIP191_PREFIX_32},
            hash::base_types::hash256bytes::WitnessHash256Bytes,
        };

        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        const D: usize = 2;

        // Build the exact circuit of EthPersonalSignSecp256K1SignatureCircuit,
        // but keep the CircuitData owned so we can drive the prover manually.
        let build = || {
            let config = CircuitConfig::standard_ecc_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let gadget = Secp256K1Gadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, EIP191_PREFIX_32);
            builder.register_public_inputs(&gadget.combined_hash.elements);
            let data: CircuitData<F, C, D> = builder.build::<C>();
            (gadget, data)
        };
        let (gadget, data) = build();
        let reference = EthPersonalSignSecp256K1SignatureCircuit::<C, D>::new();
        assert_eq!(data.verifier_only, reference.base_circuit_data.verifier_only, "test circuit must be identical");
        assert_eq!(data.common, reference.base_circuit_data.common);

        // Honest signature fixture (same as the other H2 tests).
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();
        let message = psy_client_common::data::base_types::hash256::Hash256([0x51; 32]);
        let digest = psy_crypto::signature::secp256k1::wallet::eth_personal_sign_digest(&message.0);
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let address_digest = ethereum_address_for_verifying_key(signing_key.verifying_key());
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&signature.to_bytes());
        signature_bytes[64] = recovery_id.to_byte();
        let recovered = recover_eth_personal_signature(address_digest, message, signature_bytes).unwrap();
        let prepared: PsyPreparedSecp256K1Signature<F> = (&recovered).try_into().unwrap();

        let u32_digits = |arr: &[u64; 4]| -> Vec<u32> {
            arr.iter().flat_map(|w| [*w as u32, (*w >> 32) as u32]).collect()
        };

        // Input-level witness: msg bytes + x,y,r,s limbs, with an optional
        // integer-preserving pair corruption on y: y[i] += 2^32, y[i+1] -= 1,
        // and an optional VALUE-CHANGING s corruption: s[i] += 2^32 (no
        // compensation, so the represented integer changes).
        let input_witness = |bad_y: Option<usize>, bad_s_additive: Option<usize>| -> plonky2::iop::witness::PartialWitness<F> {
            let mut pw = plonky2::iop::witness::PartialWitness::new();
            pw.set_hash256_bytes_target(&gadget.msg_bytes_target, &prepared.message.to_le_bytes()).unwrap();
            let set = |pw: &mut plonky2::iop::witness::PartialWitness<F>, limbs: &[crate::u32::arithmetic_u32::U32Target], digits: &[u32], bad: Option<usize>| {
                for (i, limb) in limbs.iter().enumerate() {
                    let mut v = digits[i] as u64;
                    if let Some(b) = bad {
                        if i == b {
                            v += 1u64 << 32;
                        } else if i == b + 1 {
                            assert!(v >= 1, "compensation limb must be nonzero");
                            v -= 1;
                        }
                    }
                    pw.set_target(limb.0, F::from_canonical_u64(v)).unwrap();
                }
            };
            let set_additive = |pw: &mut plonky2::iop::witness::PartialWitness<F>, limbs: &[crate::u32::arithmetic_u32::U32Target], digits: &[u32], bad: Option<usize>| {
                for (i, limb) in limbs.iter().enumerate() {
                    let mut v = digits[i] as u64;
                    if bad == Some(i) {
                        v += 1u64 << 32;
                    }
                    pw.set_target(limb.0, F::from_canonical_u64(v)).unwrap();
                }
            };
            set(&mut pw, &gadget.public_key_x_target.limbs, &u32_digits(&prepared.public_key.0.x.0), None);
            set(&mut pw, &gadget.public_key_y_target.limbs, &u32_digits(&prepared.public_key.0.y.0), bad_y);
            set(&mut pw, &gadget.signature_r_target.limbs, &u32_digits(&prepared.signature.r.0), None);
            set_additive(&mut pw, &gadget.signature_s_target.limbs, &u32_digits(&prepared.signature.s.0), bad_s_additive);
            pw
        };

        struct GenReport {
            conflicts: Vec<(String, Target, F, F)>,
            conflict_count_by_gen: BTreeMap<String, usize>,
            unfinished_generators: usize,
            unset_partitions: usize,
            rounds: usize,
            rng_partitions: std::collections::HashSet<usize>,
        }

        // Custom witness generation: replicate generate_partial_witness, but
        // log-and-force conflicts instead of aborting. Input partitions are
        // never overwritten. If new_wins, a conflicting generator output
        // overwrites the existing partition value; otherwise it is dropped.
        fn generate_logged(
            inputs: plonky2::iop::witness::PartialWitness<F>,
            data: &CircuitData<F, C, D>,
            new_wins: bool,
        ) -> (PartitionWitness<'_, F>, GenReport) {
            let prover = &data.prover_only;
            let common = &data.common;
            let num_wires = common.config.num_wires;
            let degree = common.degree();
            let mut witness = PartitionWitness::new(num_wires, degree, &prover.representative_map);
            let input_reps: std::collections::HashSet<usize> = inputs
                .target_values
                .keys()
                .map(|t| prover.representative_map[t.index(num_wires, degree)])
                .collect();
            for (t, v) in inputs.target_values.iter() {
                witness.set_target(*t, *v).unwrap();
            }
            let gens = &prover.generators;
            let mut buffer = GeneratedValues::empty();
            let mut report = GenReport {
                conflicts: Vec::new(),
                conflict_count_by_gen: BTreeMap::new(),
                unfinished_generators: 0,
                unset_partitions: 0,
                rounds: 0,
                rng_partitions: std::collections::HashSet::new(),
            };
            // Faithful replica of plonky2's generate_partial_witness scheduler
            // (watch-list driven, each generator expires after finishing), with
            // two changes: conflicts are logged instead of aborting, and under
            // `new_wins` a conflicting value force-overwrites its partition and
            // re-arms the (deterministic) watchers of that partition so the
            // overwrite cascades downstream. RandomValueGenerator is never
            // re-armed (it is non-deterministic by design).
            let mut pending: Vec<usize> = (0..gens.len()).collect();
            let mut expired = vec![false; gens.len()];
            let mut remaining = gens.len();
            while !pending.is_empty() {
                report.rounds += 1;
                if report.rounds > 100000 {
                    // No fixpoint: some partition oscillates between forced
                    // values — itself evidence of constraint-level conflict.
                    break;
                }
                let mut next_pending = Vec::new();
                for &i in &pending {
                    if expired[i] {
                        continue;
                    }
                    if gens[i].0.run(&witness, &mut buffer) {
                        expired[i] = true;
                        remaining -= 1;
                    }
                    let mut new_reps = Vec::new();
                    for (t, v) in buffer.target_values.drain(..) {
                        let rep = prover.representative_map[t.index(num_wires, degree)];
                        if gens[i].0.id() == "RandomValueGenerator" {
                            report.rng_partitions.insert(rep);
                        }
                        match witness.values[rep] {
                            None => {
                                witness.values[rep] = Some(v);
                                new_reps.push(rep);
                            }
                            Some(old) if old == v => {}
                            Some(old) => {
                                *report.conflict_count_by_gen.entry(gens[i].0.id()).or_default() += 1;
                                if report.conflicts.len() < 40 {
                                    report.conflicts.push((gens[i].0.id(), t, old, v));
                                }
                                if new_wins && !input_reps.contains(&rep) {
                                    witness.values[rep] = Some(v);
                                    new_reps.push(rep);
                                }
                            }
                        }
                    }
                    for rep in new_reps {
                        if let Some(watchers) = prover.generator_indices_by_watches.get(&rep) {
                            for &w in watchers {
                                if !expired[w] {
                                    next_pending.push(w);
                                } else if new_wins && gens[w].0.id() != "RandomValueGenerator" {
                                    // Re-arm deterministic finished generators
                                    // so the overwrite cascades downstream.
                                    expired[w] = false;
                                    remaining += 1;
                                    next_pending.push(w);
                                }
                            }
                        }
                    }
                }
                pending = next_pending;
                if std::env::var("H2_DEBUG").is_ok() {
                    println!("round {} done: pending={} remaining={}", report.rounds, pending.len(), remaining);
                }
            }
            report.unfinished_generators = remaining;
            report.unset_partitions = witness.values.iter().filter(|v| v.is_none()).count();
            (witness, report)
        }

        let run_case = |label: &str, bad_y: Option<usize>, bad_s_additive: Option<usize>, new_wins: bool| {
            let (witness, report) = generate_logged(input_witness(bad_y, bad_s_additive), &data, new_wins);
            println!(
                "[{label}] rounds={} unfinished_gens={} unset_partitions={} conflicts={} (by gen: {:?})",
                report.rounds,
                report.unfinished_generators,
                report.unset_partitions,
                report.conflict_count_by_gen.values().sum::<usize>(),
                report.conflict_count_by_gen
            );
            for (gen, t, old, new) in &report.conflicts {
                println!("[{label}] conflict: gen={gen} target={t:?} old={old:?} new={new:?}");
            }
            if label == "honest-control" {
                assert_eq!(report.unfinished_generators, 0, "control: all generators must run");
                assert_eq!(report.conflict_count_by_gen.values().sum::<usize>(), 0, "control: no conflicts expected");
                // The bypass loop must reproduce plonky2's own scheduler
                // bit-for-bit on honest inputs.
                let reference = plonky2::iop::generator::generate_partial_witness::<F, C, D>(
                    input_witness(bad_y, bad_s_additive),
                    &data.prover_only,
                    &data.common,
                )
                .expect("plonky2 reference witness generation");
                assert_eq!(witness.values.len(), reference.values.len());
                let mut mismatches = 0usize;
                let mut non_rng_mismatches = 0usize;
                for (i, (a, b)) in witness.values.iter().zip(reference.values.iter()).enumerate() {
                    if a != b {
                        mismatches += 1;
                        if !report.rng_partitions.contains(&i) {
                            non_rng_mismatches += 1;
                        }
                    }
                }
                assert_eq!(
                    non_rng_mismatches, 0,
                    "bypass loop must match plonky2's generate_partial_witness on every non-random partition"
                );
                println!(
                    "[{label}] bypass loop matches plonky2 reference on all non-random partitions \
                     ({} total mismatches, all from RandomValueGenerator fresh draws)",
                    mismatches
                );
            }
            if report.unfinished_generators != 0 || report.rounds > 100000 {
                println!("[{label}] generation incomplete or non-convergent; skipping prove");
                return;
            }
            let proof = prove_with_partition_witness(&data.prover_only, &data.common, witness, &mut TimingTree::default())
                .expect("prove from hand-driven witness");
            match data.verify(proof.clone()) {
                Ok(()) => println!("[{label}] VERIFY PASSED; public inputs: {:?}", proof.public_inputs),
                Err(e) => println!("[{label}] verify rejected: {e:#}"),
            }
        };

        // Control: honest inputs through the bypass machinery must verify, and
        // must produce zero conflicts (proves the loop replicates plonky2).
        run_case("honest-control", None, None, false);

        // y corruption, integer-preserving pair, two limb positions, both
        // conflict-resolution policies.
        let y_digits = u32_digits(&prepared.public_key.0.y.0);
        for i in [1usize, 6] {
            if y_digits[i + 1] < 1 {
                println!("skipping y pair ({i}, {}): compensation limb is zero", i + 1);
                continue;
            }
            println!("y limb values: y[{i}]={}, y[{}]={}", y_digits[i], i + 1, y_digits[i + 1]);
            run_case(&format!("y-corrupt-pair-{i}-keep-first"), Some(i), None, false);
            run_case(&format!("y-corrupt-pair-{i}-keep-last"), Some(i), None, true);
        }

        // Target A in-circuit: value-CHANGING s corruption (s[1] += 2^32, no
        // compensation, so the represented integer S' = S + 2^32). Generators
        // consistently recompute everything downstream (inverse c = S'^-1 mod
        // n, u1, u2, the point), so no constraint conflict arises inside the
        // arithmetic; the only possible backstop is the final x-check
        // connect_nonnative(r, x) at gadget.rs:69-72. Expected: prove OK,
        // verify FAILS.
        run_case("s-value-changed-plus-2^32", None, Some(1), false);
    }

    /// H2 Target C — the inv-relation quotient `div` and the inverse hint `c`.
    ///
    /// POST-FIX NOTE: the boundary range check on the external s limbs does not
    /// affect anything below — case (3) uses a canonical s' (passes the range
    /// check), and `div`/`c` are internal targets the boundary check does not
    /// touch.
    ///
    /// Static facts established by reading the gadgets:
    /// - `inv_nonnative` (crypto/secp256k1/ecdsa/gadgets/nonnative.rs:291-315)
    ///   creates BOTH the inverse hint `inv` (:293) and the quotient `div`
    ///   (:294) via `add_virtual_biguint_target(8)` -> `add_virtual_u32_targets`
    ///   (biguint.rs:147-151 -> u32/gadgets/arithmetic_u32.rs:82-84), which
    ///   performs NO range check. Unlike `mul_nonnative` (:260-261),
    ///   `sub_nonnative` (:235-236) and `add_many_nonnative` (:201-202),
    ///   `inv_nonnative` never calls `range_check_u32_circuit` on `inv`/`div`.
    ///   The ONLY constraint touching them is
    ///   `connect_biguint(mul_biguint(s, inv), mul_biguint(n, div) + 1)`
    ///   (:303-309) — one limb-wise (integer) equality between two product
    ///   networks. div's limb COUNT is fixed at 8 (:294), but each limb is a
    ///   raw field element in [0, p_gold).
    /// - With unconfined div limbs, F(n, div) = n*D - p_gold*W' where the wrap
    ///   count W' = sum k_ij * 2^{32(i+j)} has per-limb freedom
    ///   k_ij = floor(n_i * d_j / p_gold) in [0, n_i) (8 free d_j), so
    ///   F(n, .) mod n is effectively unrestricted: the inv relation does NOT
    ///   enforce F(s, c) == 1 (mod n). Its only semantic content is: "s is
    ///   SOME integer whose product-network with c differs from some
    ///   product-network of n by exactly 1". Since s is a free private input
    ///   (hashed nowhere; combined_hash binds only msg and the public key),
    ///   the inv relation is a completeness device, not a soundness anchor:
    ///   c is bound ONLY by the u1/u2/x-check chain
    ///   (gadget.rs:61-72 -> nonnative.rs:247-270 -> connect_nonnative(r, x)).
    /// - Canonical slack is capacity-limited: 2^256 - n ~= 2^128.6, so s + n
    ///   needs a 9th limb and cannot be represented even with canonical limbs;
    ///   representing it with a non-u32 top limb forces wraps in F(s, c)
    ///   (co-limbs of c are ~2^32), the Target A hard direction.
    ///
    /// Experiments below (full generator bypass, same harness as Target B):
    /// (1) capture the s-inverse generator's writes via its buffer to locate
    ///     the div/inv targets at runtime, and check them against host
    ///     arithmetic (identification sanity);
    /// (2) div binding control: force div[0] += 1 post-generation with
    ///     everything else honest -> verify MUST fail (div is bound by the
    ///     connect_biguint at nonnative.rs:309);
    /// (3) the decisive c-freedom test: replace the INPUT s by
    ///     s' = (C+1)^-1 mod n (C = honest s^-1). The inv generator then
    ///     produces c' = C+1 and a consistent div' — the inv relation is
    ///     fully satisfied, with NO witness manipulation downstream. If the
    ///     inv relation were the soundness anchor, this would verify. It must
    ///     fail at the x-check: x((C+1)*M*G + (C+1)*R*Q) != r w.h.p., and the
    ///     conflict log should show exactly the r/x copy-partition colliding.
    #[test]
    fn h2_target_c_quotient_hint_binding() {
        use std::collections::{BTreeMap, HashSet};

        use num::BigUint;
        use plonky2::{
            field::{
                secp256k1_scalar::Secp256K1Scalar,
                types::{Field, PrimeField},
            },
            hash::poseidon::PoseidonHash,
            iop::{
                generator::GeneratedValues,
                target::Target,
                witness::{PartitionWitness, Witness, WitnessWrite},
            },
            plonk::{
                circuit_builder::CircuitBuilder,
                circuit_data::{CircuitConfig, CircuitData},
                prover::prove_with_partition_witness,
            },
            util::timing::TimingTree,
        };
        use psy_crypto::signature::secp256k1::core::PsyPreparedSecp256K1Signature;

        use crate::{
            crypto::secp256k1::gadget::{Secp256K1Gadget, EIP191_PREFIX_32},
            hash::base_types::hash256bytes::WitnessHash256Bytes,
        };

        type C = PoseidonGoldilocksConfig;
        type F = GoldilocksField;
        const D: usize = 2;

        let build = || {
            let config = CircuitConfig::standard_ecc_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            let gadget = Secp256K1Gadget::add_virtual_to::<PoseidonHash, F, D>(&mut builder, EIP191_PREFIX_32);
            builder.register_public_inputs(&gadget.combined_hash.elements);
            let data: CircuitData<F, C, D> = builder.build::<C>();
            (gadget, data)
        };
        let (gadget, data) = build();
        let reference = EthPersonalSignSecp256K1SignatureCircuit::<C, D>::new();
        assert_eq!(data.verifier_only, reference.base_circuit_data.verifier_only, "test circuit must be identical");
        assert_eq!(data.common, reference.base_circuit_data.common);
        println!(
            "base circuit: {} gates, degree {}, {} generators",
            data.common.gates.len(),
            data.common.degree(),
            data.prover_only.generators.len()
        );
        println!("verifier_only circuit_digest: {:?}", data.verifier_only.circuit_digest);

        let signing_key = k256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();
        let message = psy_client_common::data::base_types::hash256::Hash256([0x51; 32]);
        let digest = psy_crypto::signature::secp256k1::wallet::eth_personal_sign_digest(&message.0);
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let address_digest = ethereum_address_for_verifying_key(signing_key.verifying_key());
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&signature.to_bytes());
        signature_bytes[64] = recovery_id.to_byte();
        let recovered = recover_eth_personal_signature(address_digest, message, signature_bytes).unwrap();
        let prepared: PsyPreparedSecp256K1Signature<F> = (&recovered).try_into().unwrap();

        let u32_digits = |arr: &[u64; 4]| -> Vec<u32> {
            arr.iter().flat_map(|w| [*w as u32, (*w >> 32) as u32]).collect()
        };

        // Input witness; s_override replaces the s limbs (canonical u32s).
        let input_witness = |s_override: Option<&[u32]>| -> plonky2::iop::witness::PartialWitness<F> {
            let mut pw = plonky2::iop::witness::PartialWitness::new();
            pw.set_hash256_bytes_target(&gadget.msg_bytes_target, &prepared.message.to_le_bytes()).unwrap();
            let set = |pw: &mut plonky2::iop::witness::PartialWitness<F>, limbs: &[crate::u32::arithmetic_u32::U32Target], digits: &[u32]| {
                for (i, limb) in limbs.iter().enumerate() {
                    pw.set_target(limb.0, F::from_canonical_u32(digits[i])).unwrap();
                }
            };
            set(&mut pw, &gadget.public_key_x_target.limbs, &u32_digits(&prepared.public_key.0.x.0));
            set(&mut pw, &gadget.public_key_y_target.limbs, &u32_digits(&prepared.public_key.0.y.0));
            set(&mut pw, &gadget.signature_r_target.limbs, &u32_digits(&prepared.signature.r.0));
            let s_digits = u32_digits(&prepared.signature.s.0);
            set(&mut pw, &gadget.signature_s_target.limbs, s_override.unwrap_or(&s_digits));
            pw
        };

        let s_limb_targets: HashSet<Target> = gadget.signature_s_target.limbs.iter().map(|l| l.0).collect();

        // Same faithful watch-list scheduler as Target B (keep-first policy —
        // no force-cascade needed here), plus capture of the s-inverse
        // generator's output buffer (div limbs first, then inv limbs;
        // nonnative.rs:818-819). The s-inverse generator is identified by its
        // watch list being exactly the s limb targets.
        #[allow(clippy::type_complexity)]
        fn generate_logged_capture<'a>(
            inputs: plonky2::iop::witness::PartialWitness<F>,
            data: &'a CircuitData<F, C, D>,
            s_limb_targets: &HashSet<Target>,
        ) -> (PartitionWitness<'a, F>, BTreeMap<String, usize>, Option<Vec<(Target, F)>>) {
            let prover = &data.prover_only;
            let common = &data.common;
            let num_wires = common.config.num_wires;
            let degree = common.degree();
            let mut witness = PartitionWitness::new(num_wires, degree, &prover.representative_map);
            for (t, v) in inputs.target_values.iter() {
                witness.set_target(*t, *v).unwrap();
            }
            let gens = &prover.generators;
            let mut buffer = GeneratedValues::empty();
            let mut conflicts: BTreeMap<String, usize> = BTreeMap::new();
            let mut capture: Option<Vec<(Target, F)>> = None;
            let mut pending: Vec<usize> = (0..gens.len()).collect();
            let mut expired = vec![false; gens.len()];
            let mut remaining = gens.len();
            let mut rounds = 0usize;
            while !pending.is_empty() {
                rounds += 1;
                assert!(rounds <= 100000, "scheduler failed to converge");
                let mut next_pending = Vec::new();
                for &i in &pending {
                    if expired[i] {
                        continue;
                    }
                    let is_s_inverse = gens[i].0.id() == "NonNativeInverseGenerator"
                        && gens[i].0.watch_list().into_iter().collect::<HashSet<_>>() == *s_limb_targets;
                    if gens[i].0.run(&witness, &mut buffer) {
                        expired[i] = true;
                        remaining -= 1;
                    }
                    if is_s_inverse && !buffer.target_values.is_empty() && capture.is_none() {
                        capture = Some(buffer.target_values.clone());
                    }
                    let mut new_reps = Vec::new();
                    for (t, v) in buffer.target_values.drain(..) {
                        let rep = prover.representative_map[t.index(num_wires, degree)];
                        match witness.values[rep] {
                            None => {
                                witness.values[rep] = Some(v);
                                new_reps.push(rep);
                            }
                            Some(old) if old == v => {}
                            Some(_) => {
                                *conflicts.entry(gens[i].0.id()).or_default() += 1;
                            }
                        }
                    }
                    for rep in new_reps {
                        if let Some(watchers) = prover.generator_indices_by_watches.get(&rep) {
                            for &w in watchers {
                                if !expired[w] {
                                    next_pending.push(w);
                                }
                            }
                        }
                    }
                }
                pending = next_pending;
            }
            assert_eq!(remaining, 0, "all generators must run");
            (witness, conflicts, capture)
        }

        let n = Secp256K1Scalar::order();
        let biguint_of = |limbs: &[(Target, F)]| -> BigUint {
            limbs.iter().enumerate().fold(BigUint::from(0u8), |acc, (i, (_, v))| {
                acc + (v.to_canonical_biguint() << (32 * i))
            })
        };

        // (1) Honest capture + identification sanity.
        let (witness, conflicts, capture) = generate_logged_capture(input_witness(None), &data, &s_limb_targets);
        assert_eq!(conflicts.values().sum::<usize>(), 0, "honest run must have no conflicts");
        let capture = capture.expect("s-inverse generator must be identified by its watch list");
        assert_eq!(capture.len(), 16, "s-inverse generator writes 8 div limbs then 8 inv limbs");
        let div_targets: Vec<Target> = capture[..8].iter().map(|(t, _)| *t).collect();
        let div_val = biguint_of(&capture[..8]);
        let inv_val = biguint_of(&capture[8..]);
        let s_scalar = Secp256K1Scalar(prepared.signature.s.0);
        let s_big = s_scalar.to_canonical_biguint();
        let c_expected = s_scalar.inverse().to_canonical_biguint();
        assert_eq!(inv_val, c_expected, "captured inv must be the true s^-1 mod n");
        assert_eq!(&s_big * &inv_val, BigUint::from(1u8) + &n * &div_val, "captured div must satisfy s*inv = 1 + n*div exactly");
        println!("[honest-capture] s-inverse generator identified; div/inv match host arithmetic");
        let proof = prove_with_partition_witness(&data.prover_only, &data.common, witness, &mut TimingTree::default()).expect("honest prove");
        data.verify(proof).expect("honest verify");
        println!("[honest-capture] VERIFY PASSED (control)");

        // (2) div binding control: corrupt one captured div limb post-hoc.
        {
            let (mut witness, conflicts, _) = generate_logged_capture(input_witness(None), &data, &s_limb_targets);
            assert_eq!(conflicts.values().sum::<usize>(), 0);
            let prover = &data.prover_only;
            let rep = prover.representative_map[div_targets[0].index(data.common.config.num_wires, data.common.degree())];
            let old = witness.values[rep].expect("div limb 0 must be set");
            witness.values[rep] = Some(old + F::ONE);
            let proof = prove_with_partition_witness(&data.prover_only, &data.common, witness, &mut TimingTree::default()).expect("prove with corrupted div");
            match data.verify(proof) {
                Ok(()) => println!("[div-limb0-plus-1] UNEXPECTED: verify PASSED -- div would be unbound!"),
                Err(e) => println!("[div-limb0-plus-1] verify rejected as expected (div bound by connect_biguint, nonnative.rs:309): {e:#}"),
            }
        }

        // (3) Decisive c-freedom test: s' = (C+1)^-1 mod n as input; the inv
        // relation is then honestly satisfied for c' = C+1, so any verify
        // failure is attributable to the u1/u2/x-check chain alone.
        {
            let c_plus_1 = s_scalar.inverse() + Secp256K1Scalar::ONE;
            let s_prime = c_plus_1.inverse().to_canonical_biguint();
            let s_prime_digits = s_prime.to_u32_digits();
            assert!(s_prime_digits.len() <= 8);
            let mut s_prime_limbs = s_prime_digits.clone();
            s_prime_limbs.resize(8, 0);
            let (witness, conflicts, capture) = generate_logged_capture(input_witness(Some(&s_prime_limbs)), &data, &s_limb_targets);
            let capture = capture.expect("s-inverse generator must run for swapped s");
            let inv_val = biguint_of(&capture[8..]);
            assert_eq!(inv_val, c_plus_1.to_canonical_biguint(), "with s' input the inv hint must become C+1: inv relation honestly satisfied");
            println!(
                "[s-swapped-c-plus-1] inv hint is honestly C+1; conflicts: total={} by_gen={:?}",
                conflicts.values().sum::<usize>(),
                conflicts
            );
            let proof = prove_with_partition_witness(&data.prover_only, &data.common, witness, &mut TimingTree::default())
                .expect("prove with s' = (C+1)^-1");
            match data.verify(proof.clone()) {
                Ok(()) => panic!(
                    "FORGERY: c = honest_s^-1 + 1 verified with public inputs {:?} -- the x-check failed to backstop",
                    proof.public_inputs
                ),
                Err(e) => println!("[s-swapped-c-plus-1] verify rejected as expected; inv relation fully satisfied, so the x-check connect_nonnative(r, x) (gadget.rs:69-72) is the binding constraint: {e:#}"),
            }
        }
    }


    /// H2 Target A — value-changing corruption: host-side exact model of the
    /// constraint system + search for a forgery witness.
    ///
    /// Model (derived from the gadgets, all arithmetic exact):
    /// - `U32ArithmeticGate` (u32/gates/arithmetic_u32.rs:92-149) enforces
    ///   `m0*m1 + a == low + high*2^32 (mod p_gold)` with `low, high` confined
    ///   to u32 via the internal 2-bit decomposition + canonicity; inputs are
    ///   raw field elements. So a limb-level product network over limb vectors
    ///   `a`, `b` computes EXACTLY
    ///       F(a, b) = sum_{i,j} ((a_i * b_j) mod p_gold) * 2^{32(i+j)}
    ///   (the downstream add gates never wrap: their sums stay < 2^40), and
    ///   `connect_biguint` forces limb-wise equality between two such
    ///   networks, i.e. INTEGER equality of the two F-values.
    /// - inv relation (nonnative.rs:303-309): F(s_limbs, c_limbs) = 1 + n*D,
    ///   D < 2^256 (div has 8 limbs).
    /// - u1 relation (nonnative.rs:247-270): F(msg_limbs, c_limbs) = u1 + n*O1
    ///   with u1 < 2^256 (range-checked, :260) and O1 < 2^256 (8 limbs).
    ///   Same for u2 with r_limbs.
    /// - Scalar consumption (split_nonnative.rs:26,38; glv.rs; curve_fixed_base.rs:34)
    ///   uses base-4 splits whose sums are < 2^32 < p_gold, so NO mod-p_gold
    ///   aliasing exists there: the effective scalars are exactly the limb
    ///   integers e1 = u1, e2 = GLV(u2) == u2 (mod n).
    /// - Final check (gadget.rs:59-72 via curve arithmetic, all of whose
    ///   inputs are range-checked u32 hence wrap-free = exact integer
    ///   semantics): x(e1*G + e2*Q) == r.
    ///
    /// Consequences established host-side below:
    /// (1) The inv relation binds NOTHING by itself: for ANY c-limb vector,
    ///     s' can be solved (fixed point over the forced wrap constant W0).
    ///     The circuit's only real semantic content is "exists integer C (the
    ///     inverse witness) with x((M*C mod n)*G + (R*C mod n)*Q) == R" —
    ///     i.e. exactly ECDSA verification of signature (R, C^{-1}).
    /// (2) Value-changing attacks need wraps (W != 0), which perturb the
    ///     effective scalars by FORCED multiples of p_gold mod n. The search
    ///     below samples such candidates and checks the full composed
    ///     condition; finding one is a random fixed point of a 256-bit
    ///     random-looking map (expected ~2^256 work) — the search is
    ///     expected to find nothing, and documents exactly where candidates
    ///     die.
    #[test]
    fn h2_target_a_value_change_search() {
        use num::BigUint;
        use plonky2::field::{
            secp256k1_scalar::Secp256K1Scalar,
            types::{Field, PrimeField},
        };
        use psy_crypto::signature::secp256k1::core::PsyPreparedSecp256K1Signature;
        use rand::Rng;

        type F = GoldilocksField;

        let p_gold = BigUint::from(0xFFFF_FFFF_0000_0001u64);
        let n = Secp256K1Scalar::order();
        let two256 = BigUint::from(1u8) << 256;

        let limbs8 = |v: &BigUint| -> [u64; 8] {
            let d = v.to_u32_digits();
            core::array::from_fn(|i| d.get(i).copied().unwrap_or(0) as u64)
        };
        let value_of = |limbs: &[u64; 8]| -> BigUint {
            limbs.iter().enumerate().fold(BigUint::from(0u8), |acc, (i, &l)| acc + (BigUint::from(l) << (32 * i)))
        };
        // Exact model of a mul_biguint network: sum of per-limb-pair products
        // reduced mod p_gold, weighted by 2^{32(i+j)}.
        let f_mul = |a: &[u64; 8], b: &[u64; 8]| -> BigUint {
            let mut acc = BigUint::from(0u8);
            for i in 0..8 {
                for j in 0..8 {
                    let prod = (a[i] as u128) * (b[j] as u128);
                    let v = (prod % 0xFFFF_FFFF_0000_0001u128) as u64;
                    acc += BigUint::from(v) << (32 * (i + j));
                }
            }
            acc
        };

        // Honest fixture.
        let signing_key = k256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();
        let message = psy_client_common::data::base_types::hash256::Hash256([0x51; 32]);
        let digest = psy_crypto::signature::secp256k1::wallet::eth_personal_sign_digest(&message.0);
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let address_digest = ethereum_address_for_verifying_key(signing_key.verifying_key());
        let mut signature_bytes = [0u8; 65];
        signature_bytes[..64].copy_from_slice(&signature.to_bytes());
        signature_bytes[64] = recovery_id.to_byte();
        let recovered = recover_eth_personal_signature(address_digest, message, signature_bytes).unwrap();
        let prepared: PsyPreparedSecp256K1Signature<F> = (&recovered).try_into().unwrap();

        let m_big = BigUint::from_bytes_be(&digest);
        let m_limbs = limbs8(&m_big);
        // 8 little-endian u32 limbs (as u64) from the packed [u64; 4] form.
        let limbs_of = |arr: &[u64; 4]| -> [u64; 8] {
            core::array::from_fn(|i| (arr[i / 2] >> (32 * (i % 2))) & 0xFFFF_FFFF)
        };
        let s_limbs_h = limbs_of(&prepared.signature.s.0);
        let r_big = value_of(&limbs_of(&prepared.signature.r.0));

        // k256 helpers for the x-check.
        use k256::elliptic_curve::{ff::PrimeField as _, sec1::{FromEncodedPoint as _, ToEncodedPoint as _}};
        let q_point = Option::<k256::ProjectivePoint>::from(k256::ProjectivePoint::from_encoded_point(
            &signing_key.verifying_key().to_encoded_point(false),
        ))
        .unwrap();
        let g_point = k256::ProjectivePoint::GENERATOR;
        let scalar_of = |v: &BigUint| -> k256::Scalar {
            let mut b = [0u8; 32];
            let be = (v % &n).to_bytes_be();
            b[32 - be.len()..].copy_from_slice(&be);
            Option::<k256::Scalar>::from(k256::Scalar::from_repr(b.into())).unwrap()
        };
        let x_of = |pt: k256::ProjectivePoint| -> BigUint {
            let ep = pt.to_affine().to_encoded_point(false);
            BigUint::from_bytes_be(ep.x().unwrap())
        };

        // (0) Model sanity: honest values reproduce the honest ECDSA relation.
        let c_honest_big = {
            let s_scalar = Secp256K1Scalar(prepared.signature.s.0);
            s_scalar.inverse().to_canonical_biguint()
        };
        let c_honest = limbs8(&c_honest_big);
        {
            let f = f_mul(&s_limbs_h, &c_honest);
            assert!(&f > &BigUint::from(0u8));
            let dm1 = &f - 1u8;
            let s_big = value_of(&s_limbs_h);
            let sc = &s_big * &c_honest_big;
            assert_eq!(f, sc, "wrap-free mul network must be exact integer product");
            assert_eq!(&dm1 % &n, BigUint::from(0u8), "honest inv relation must hold exactly");
            assert!(dm1 / &n < two256, "honest div fits 8 limbs");
            let u1 = f_mul(&m_limbs, &c_honest) % &n;
            let u2 = f_mul(&limbs8(&r_big), &c_honest) % &n;
            assert_eq!(x_of(g_point * scalar_of(&u1) + q_point * scalar_of(&u2)), r_big, "model sanity: honest x-check");
            println!("model sanity OK: honest inv relation and x-check reproduced exactly");
        }

        // (1) The inv relation alone binds nothing: for RANDOM value-changed
        // c (non-u32 limbs, C' != C mod n), solve s' via the forced-wrap fixed
        // point and report how often F(s', c') = 1 + n*D with D < 2^256.
        let mut rng = rand::thread_rng();
        let mut inv_satisfiable = 0usize;
        let mut inv_dead_d_too_big = 0usize;
        let mut inv_dead_no_fixpoint = 0usize;
        let mut wrap_free_route = 0usize;
        let trials_inv = 200;
        for _ in 0..trials_inv {
            let mut c = c_honest;
            // 1-2 boosted limbs: genuine non-u32, value-changing.
            let j = rng.gen_range(0..8);
            c[j] += 1u64 << 32;
            if rng.gen_bool(0.5) {
                let j2 = rng.gen_range(0..8);
                c[j2] += 2u64 << 32;
            }
            let c_big = value_of(&c);
            if &c_big % &n == BigUint::from(0u8) {
                continue;
            }
            let c_inv = Secp256K1Scalar::from_noncanonical_biguint(&c_big % &n).inverse();
            let mut w0 = BigUint::from(0u8);
            let mut ok = false;
            for _ in 0..8 {
                let s_target = (Secp256K1Scalar::from_noncanonical_biguint((&p_gold * &w0 + 1u8) % &n) * c_inv).to_canonical_biguint();
                let s_limbs = limbs8(&s_target);
                let f = f_mul(&s_limbs, &c);
                if f <= BigUint::from(1u8) {
                    break;
                }
                let dm1 = &f - 1u8;
                if &dm1 % &n == BigUint::from(0u8) {
                    if &dm1 / &n < two256 {
                        ok = true;
                    } else {
                        inv_dead_d_too_big += 1;
                    }
                    break;
                }
                // Next fixed-point iterate: W0 = (S*C - F) / p_gold (exact).
                let s_c = (&s_target % &n) * (&c_big % &n);
                w0 = if s_c > f { (&s_c - &f) / &p_gold } else { BigUint::from(0u8) };
            }
            if ok {
                inv_satisfiable += 1;
            } else {
                inv_dead_no_fixpoint += 1;
            }
            // Alternative route: exact-inverse S = C'^-1 mod n with a wrap-free
            // limb pairing (max_s_limb * max_c_limb < p_gold). When this route
            // exists, the relation reduces to the exact integer equality
            // S*C' = 1 + n*D, i.e. s' is the TRUE inverse of the (changed) C'
            // -- satisfiable, but semantically honest (no forgery).
            let s_exact = c_inv.to_canonical_biguint();
            let s_exact_limbs = limbs8(&s_exact);
            let max_s = *s_exact_limbs.iter().max().unwrap() as u128;
            let max_c = *c.iter().max().unwrap() as u128;
            let wrap_free = max_s * max_c < 0xFFFF_FFFF_0000_0001u128;
            if wrap_free {
                wrap_free_route += 1;
                // Exactness must then hold: F(s', c') = S*C' with no wraps.
                debug_assert_eq!(f_mul(&s_exact_limbs, &c), &s_exact * &c_big);
            }
        }
        println!(
            "inv relation with value-changed non-u32 c: satisfiable {inv_satisfiable}/{trials_inv} \
             (D-too-big {inv_dead_d_too_big}, no-fixpoint-or-other {inv_dead_no_fixpoint}); \
             wrap-free exact-inverse route available in {wrap_free_route}/{trials_inv} \
             (those are satisfiable but semantically honest: s' = C'^-1)"
        );

        // (2) Full composed condition: candidates that pass the inv relation
        // still must satisfy x(u1*G + u2*Q) == r with the FORCED wrap
        // perturbations u1 = M*C - p*W1 (mod n), u2 likewise. This is the
        // blocking point. We sample value-changed c vectors (boosted limbs),
        // run the exact model, and iterate the r fixed point (r is a free
        // witness, but it enters u2, so r must be a fixed point of the
        // random-looking map r -> x(e1*G + e2(r)*Q)).
        let mut died_inv = 0usize;
        let mut died_u_bounds = 0usize;
        let mut reached_x_check = 0usize;
        let mut jackpots = 0usize;
        let trials = 300;
        for _ in 0..trials {
            let mut c = c_honest;
            let j = rng.gen_range(0..8);
            c[j] += 1u64 << 32;
            if rng.gen_bool(0.5) {
                let j2 = rng.gen_range(0..8);
                c[j2] += (rng.gen_range(1..4u64)) << 32;
            }
            let c_big = value_of(&c);
            let c_mod_n = &c_big % &n;
            if c_mod_n == BigUint::from(0u8) {
                died_inv += 1;
                continue;
            }
            // inv relation (fixed point as above).
            let c_inv = Secp256K1Scalar::from_noncanonical_biguint(c_mod_n.clone()).inverse();
            let mut w0 = BigUint::from(0u8);
            let mut inv_ok = false;
            for _ in 0..8 {
                let s_target = (Secp256K1Scalar::from_noncanonical_biguint((&p_gold * &w0 + 1u8) % &n) * c_inv).to_canonical_biguint();
                let f = f_mul(&limbs8(&s_target), &c);
                if f <= BigUint::from(1u8) {
                    break;
                }
                let dm1 = &f - 1u8;
                if &dm1 % &n == BigUint::from(0u8) && &dm1 / &n < two256 {
                    inv_ok = true;
                    break;
                }
                let s_c = (&s_target % &n) * &c_mod_n;
                w0 = if s_c > f { (&s_c - &f) / &p_gold } else { BigUint::from(0u8) };
            }
            if !inv_ok {
                died_inv += 1;
                continue;
            }
            // u1 relation: U1 = F(m, c) must equal u1 + n*O1 with both < 2^256.
            let u1_full = f_mul(&m_limbs, &c);
            let u1 = &u1_full % &n;
            let o1 = (&u1_full - &u1) / &n;
            if o1 >= two256 {
                died_u_bounds += 1;
                continue;
            }
            // r fixed point with exact u2 relation per iterate.
            let mut r_cur = r_big.clone();
            let mut hit = false;
            for _ in 0..6 {
                let u2_full = f_mul(&limbs8(&r_cur), &c);
                let u2 = &u2_full % &n;
                let o2 = (&u2_full - &u2) / &n;
                if o2 >= two256 {
                    break;
                }
                let x = x_of(g_point * scalar_of(&u1) + q_point * scalar_of(&u2));
                if x == r_cur {
                    hit = true;
                    break;
                }
                r_cur = x;
            }
            reached_x_check += 1;
            if hit {
                jackpots += 1;
                println!("JACKPOT: forged (c, r) candidate satisfies the full composed condition! c limbs: {c:?}");
            }
        }
        println!(
            "forgery search: {trials} value-changed candidates; died at inv relation: {died_inv}, \
             died at u bounds: {died_u_bounds}, reached x-check: {reached_x_check}, fixed points found: {jackpots}"
        );
        assert_eq!(jackpots, 0, "a fixed point here would be a forgery witness");
    }
}
