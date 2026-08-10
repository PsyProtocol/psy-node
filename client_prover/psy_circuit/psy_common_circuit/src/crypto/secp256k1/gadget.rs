use std::marker::PhantomData;

use num::BigUint;
use plonky2::{
    field::{extension::Extendable, secp256k1_scalar::Secp256K1Scalar},
    hash::hash_types::{HashOut, HashOutTarget, RichField},
    iop::{
        target::{BoolTarget, Target},
        witness::Witness,
    },
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::{
    field::conversions::bytes33_to_public_key,
    signature::secp256k1::curve::{
        curve_types::Curve,
        ecdsa::{ECDSAPublicKey, ECDSASignature},
        secp256k1::Secp256K1,
    },
};
use psy_plonky2_common_circuits::hash::keccak::keccak256_bytes_targets;


use super::ecdsa::gadgets::{
    biguint::BigUintTarget,
    curve::CircuitBuilderCurve,
    curve_fixed_base::fixed_base_curve_mul_circuit,
    ecdsa::{ECDSAPublicKeyTarget, ECDSASignatureTarget},
    glv::CircuitBuilderGlv,
    nonnative::{CircuitBuilderNonNative, NonNativeTarget},
};
use crate::{
    builder::hash::core::CircuitBuilderHashCore,
    crypto::secp256k1::ecdsa::gadgets::biguint::WitnessBigUint,
    hash::base_types::hash256bytes::{CircuitBuilderHash256Bytes, Hash256BytesTarget, WitnessHash256Bytes},
    u32::arithmetic_u32::CircuitBuilderU32,
};
fn biguint_from_array(arr: [u64; 4]) -> BigUint {
    BigUint::from_slice(&[
        arr[0] as u32,
        (arr[0] >> 32) as u32,
        arr[1] as u32,
        (arr[1] >> 32) as u32,
        arr[2] as u32,
        (arr[2] >> 32) as u32,
        arr[3] as u32,
        (arr[3] >> 32) as u32,
    ])
}
pub fn verify_message_circuit_v2<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg: &NonNativeTarget<Secp256K1Scalar>,
    sig: &ECDSASignatureTarget<Secp256K1>,
    pk: &ECDSAPublicKeyTarget<Secp256K1>,
) {
    let ECDSASignatureTarget { r, s } = sig;

    builder.curve_assert_valid(&pk.0);

    let c = builder.inv_nonnative(&s);
    let u1 = builder.mul_nonnative(&msg, &c);
    let u2 = builder.mul_nonnative(&r, &c);

    let point1 = fixed_base_curve_mul_circuit(builder, Secp256K1::GENERATOR_AFFINE, &u1);
    let point2 = builder.glv_mul(&pk.0, &u2);
    let point = builder.curve_add(&point1, &point2);

    let x_value = builder.nonnative_to_canonical_biguint(&point.x);

    let x: NonNativeTarget<Secp256K1Scalar> = builder.biguint_to_nonnative(&x_value);
    builder.connect_nonnative(&r, &x);
}

pub fn verify_secp_sign_opcode<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg: &NonNativeTarget<Secp256K1Scalar>,
    sig: &ECDSASignatureTarget<Secp256K1>,
    pk: &ECDSAPublicKeyTarget<Secp256K1>,
) -> BoolTarget {
    let ECDSASignatureTarget { r, s } = sig;

    let verify_result = builder.curve_is_valid(&pk.0);

    let c = builder.inv_nonnative(&s);
    let u1 = builder.mul_nonnative(&msg, &c);
    let u2 = builder.mul_nonnative(&r, &c);

    let point1 = fixed_base_curve_mul_circuit(builder, Secp256K1::GENERATOR_AFFINE, &u1);
    let point2 = builder.glv_mul(&pk.0, &u2);
    let point = builder.curve_add(&point1, &point2);

    let x_value = builder.nonnative_to_canonical_biguint(&point.x);

    let x: NonNativeTarget<Secp256K1Scalar> = builder.biguint_to_nonnative(&x_value);
    let signature_is_valid = builder.is_equal_nonnative(&r, &x);
    builder.and(verify_result, signature_is_valid)
}

pub struct Secp256K1CircuitGadget {
    pub msg_biguint_target: BigUintTarget,
    pub public_key_x_target: BigUintTarget,
    pub public_key_y_target: BigUintTarget,
    pub signature_r_target: BigUintTarget,
    pub signature_s_target: BigUintTarget,
    pub combined_hash: HashOutTarget,
}

impl Secp256K1CircuitGadget {
    /* see
     */
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize, H: AlgebraicHasher<F>>(builder: &mut CircuitBuilder<F, D>) -> Self {
        type CURVE = Secp256K1;
        let msg_target = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let public_key_target = ECDSAPublicKeyTarget::<CURVE>(builder.add_virtual_affine_point_target::<CURVE>());
        let r = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let s = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let signature_r_target = builder.nonnative_to_canonical_biguint(&r);
        let signature_s_target = builder.nonnative_to_canonical_biguint(&s);

        let signature_target = ECDSASignatureTarget::<Secp256K1> { r: r, s: s };

        let bigint_msg_target = builder.nonnative_to_canonical_biguint(&msg_target);
        let public_key_x_target = builder.nonnative_to_canonical_biguint(&public_key_target.0.x);
        let public_key_y_target = builder.nonnative_to_canonical_biguint(&public_key_target.0.y);

        let msg_data_targets = bigint_msg_target.limbs.iter().map(|x| x.0).collect::<Vec<_>>();
        let public_key_x_data_targets = public_key_x_target.limbs.iter().map(|x| x.0).collect::<Vec<_>>();
        let public_key_y_data_targets = public_key_y_target.limbs.iter().map(|x| x.0).collect::<Vec<_>>();
        let pub_key_hash = builder.hash_n_to_hash_no_pad::<H>([public_key_x_data_targets, public_key_y_data_targets].concat());
        let msg_data_hash = builder.hash_n_to_hash_no_pad::<H>(msg_data_targets);
        let combined_hash = builder.hash_n_to_hash_no_pad::<H>([pub_key_hash.elements, msg_data_hash.elements].concat());
        verify_message_circuit_v2::<F, D>(builder, &msg_target, &signature_target, &public_key_target);
        Self {
            msg_biguint_target: bigint_msg_target,
            public_key_x_target,
            public_key_y_target,
            signature_r_target,
            signature_s_target,
            combined_hash,
        }
    }

    pub fn set_witness_public_keys_update<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        public_key: &ECDSAPublicKey<Secp256K1>,
        signature: &ECDSASignature<Secp256K1>,
        msg: &Secp256K1Scalar,
    ) -> anyhow::Result<()> {
        witness.set_biguint_target(&self.msg_biguint_target, &biguint_from_array(msg.0))?;
        witness.set_biguint_target(&self.public_key_x_target, &biguint_from_array(public_key.0.x.0))?;
        witness.set_biguint_target(&self.public_key_y_target, &biguint_from_array(public_key.0.y.0))?;
        witness.set_biguint_target(&self.signature_r_target, &biguint_from_array(signature.r.0))?;
        witness.set_biguint_target(&self.signature_s_target, &biguint_from_array(signature.s.0))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DogePsySignatureCombinedHashGadget {
    pub compressed_public_key: [Target; 9],
    pub message_hash: HashOutTarget,
    pub combined_hash: HashOutTarget,
}
impl DogePsySignatureCombinedHashGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let compressed_public_key = builder.add_virtual_target_arr();
        let message_hash = builder.add_virtual_hash();
        Self::add_virtual_to_known::<H, F, D>(builder, compressed_public_key, message_hash)
    }

    pub fn add_virtual_to_known<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        compressed_public_key: [Target; 9],
        message_hash: HashOutTarget,
    ) -> Self {
        let hash_public_key = builder.hash_n_to_hash_no_pad::<H>(compressed_public_key.to_vec());
        let combined_hash = builder.hash_two_to_one::<H>(message_hash, hash_public_key);

        Self {
            compressed_public_key,
            message_hash,
            combined_hash,
        }
    }

    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, public_key: &[F; 9], message_hash: HashOut<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.message_hash, message_hash)?;
        witness.set_target_arr(&self.compressed_public_key, public_key)?;
        anyhow::Ok(())
    }

    pub fn set_witness_bytes<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        public_key: &[u8; 33],
        message_hash: HashOut<F>,
    ) -> anyhow::Result<()> {
        let public_key_felts = bytes33_to_public_key(public_key);
        self.set_witness(witness, &public_key_felts, message_hash)?;
        Ok(())
    }
}

/// No domain separation: classic secp256k1 verifies the raw sighash.
pub const DOGE_PSY_PREFIX: &[u8] = b"";

/// Shared host/circuit prefix for the fixed 32-byte EIP-191 message.
pub use psy_crypto::signature::secp256k1::wallet::EIP191_PREFIX_32;

#[derive(Debug, Clone)]
pub struct Secp256K1Gadget {
    pub msg_bytes_target: Hash256BytesTarget,
    pub msg_hash_target: HashOutTarget,
    pub msg_biguint_target: BigUintTarget,
    pub public_key_x_target: BigUintTarget,
    pub public_key_y_target: BigUintTarget,
    pub signature_r_target: BigUintTarget,
    pub signature_s_target: BigUintTarget,
    pub combined_hash: HashOutTarget,
}

impl Secp256K1Gadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        prefix_bytes: &[u8],
    ) -> Self {
        type CURVE = Secp256K1;
        let msg_bytes_target = builder.add_virtual_hash256_bytes_target();
        let msg_u32_targets = if prefix_bytes.is_empty() {
            builder.hash256_bytes_to_hash256_be(msg_bytes_target)
        } else {
            let mut preimage = Vec::with_capacity(prefix_bytes.len() + msg_bytes_target.len());
            preimage.extend(prefix_bytes.iter().map(|byte| builder.constant(F::from_canonical_u8(*byte))));
            preimage.extend_from_slice(&msg_bytes_target);

            let digest_limbs = keccak256_bytes_targets(builder, &preimage);
            let mut digest_bytes = Vec::with_capacity(32);
            for limb in digest_limbs {
                let bits = builder.split_le(limb.0, 32);
                for byte_index in 0..4 {
                    digest_bytes.push(builder.le_sum(bits[byte_index * 8..(byte_index + 1) * 8].iter()));
                }
            }
            let digest_bytes: Hash256BytesTarget = digest_bytes
                .try_into()
                .expect("Keccak-256 output must contain exactly 32 bytes");
            builder.hash256_bytes_to_hash256_be(digest_bytes)
        };
        let msg_hash_target = builder.hash256_bytes_to_hashout(msg_bytes_target);

        let msg_target = NonNativeTarget::<Secp256K1Scalar> {
            value: BigUintTarget {
                limbs: msg_u32_targets.to_vec(),
            },
            _phantom: PhantomData,
        };

        let public_key_target = ECDSAPublicKeyTarget::<CURVE>(builder.add_virtual_affine_point_target::<CURVE>());
        let r = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let s = builder.add_virtual_nonnative_target::<Secp256K1Scalar>();
        let signature_r_target = builder.nonnative_to_canonical_biguint(&r);
        let signature_s_target = builder.nonnative_to_canonical_biguint(&s);

        let signature_target = ECDSASignatureTarget::<Secp256K1> { r: r, s: s };

        let bigint_msg_target = builder.nonnative_to_canonical_biguint(&msg_target);
        let public_key_x_target = builder.nonnative_to_canonical_biguint(&public_key_target.0.x);
        let public_key_y_target = builder.nonnative_to_canonical_biguint(&public_key_target.0.y);

        let public_key_x_endian_reversed = public_key_x_target
            .limbs
            .iter()
            .map(|x| builder.u32_reverse_endian(*x).0)
            .rev()
            .collect::<Vec<_>>();

        let public_key_y_data_targets = public_key_y_target.limbs.iter().map(|x| x.0).collect::<Vec<_>>();

        verify_message_circuit_v2::<F, D>(builder, &msg_target, &signature_target, &public_key_target);

        let y_low_32_bits = builder.split_le(public_key_y_data_targets[0], 32);
        let y_parity = y_low_32_bits[0];
        let two_target = builder.constant(F::from_canonical_u64(2));

        // a compressed public key is a 33 byte array, where the first byte is the
        // parity of the y coordinate if y is even then the parity byte is 0x02.
        // if y is odd, the the parity byte is 0x03
        let parity_byte = builder.add(two_target, y_parity.target);
        let compressed_public_key = core::array::from_fn(|i| if i == 0 { parity_byte } else { public_key_x_endian_reversed[i - 1] });

        let combo_gadget = DogePsySignatureCombinedHashGadget::add_virtual_to_known::<H, F, D>(builder, compressed_public_key, msg_hash_target);

        Self {
            msg_bytes_target,
            msg_hash_target,
            msg_biguint_target: bigint_msg_target,
            public_key_x_target,
            public_key_y_target,
            signature_r_target,
            signature_s_target,
            combined_hash: combo_gadget.combined_hash,
        }
    }

    pub fn set_witness_public_keys_update<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        public_key: &ECDSAPublicKey<Secp256K1>,
        signature: &ECDSASignature<Secp256K1>,
        msg: QHashOut<F>,
    ) -> anyhow::Result<()> {
        let msg_bytes = msg.to_le_bytes();
        //msg_bytes.reverse();
        witness.set_hash256_bytes_target(&self.msg_bytes_target, &msg_bytes)?;
        //witness.set_hash_target(self.msg_hash_target, msg.0);
        /*witness.set_biguint_target(
            &self.msg_biguint_target,
            &BigUint::from_bytes_be(&msg.to_le_bytes()),
        );*/
        witness.set_biguint_target(&self.public_key_x_target, &biguint_from_array(public_key.0.x.0))?;
        witness.set_biguint_target(&self.public_key_y_target, &biguint_from_array(public_key.0.y.0))?;
        witness.set_biguint_target(&self.signature_r_target, &biguint_from_array(signature.r.0))?;
        witness.set_biguint_target(&self.signature_s_target, &biguint_from_array(signature.s.0))
    }

    pub fn add_virtual_to_doge_psy<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::add_virtual_to::<H, F, D>(builder, DOGE_PSY_PREFIX)
    }

    pub fn add_virtual_to_eth_personal_sign<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::add_virtual_to::<H, F, D>(builder, EIP191_PREFIX_32)
    }
}

/// Retained as the classic circuit's public gadget name.
pub type DogePsySignatureGadget = Secp256K1Gadget;

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use anyhow::Result;
    use kvq::traits::KVQSerializable;
    use num::BigUint;
    use plonky2::{
        field::{
            secp256k1_base::Secp256K1Base,
            secp256k1_scalar::Secp256K1Scalar,
            types::{Field, Sample},
        },
        hash::poseidon::PoseidonHash,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };
    use psy_client_common::data::qhashout::QHashOut;
    use psy_crypto::signature::secp256k1::curve::{
        curve_types::{AffinePoint, Curve, CurveScalar},
        ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
        secp256k1::Secp256K1,
    };

    use crate::crypto::secp256k1::{
        ecdsa::gadgets::{
            curve::CircuitBuilderCurve,
            ecdsa::{verify_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget},
            nonnative::CircuitBuilderNonNative,
        },
        gadget::{Secp256K1CircuitGadget, Secp256K1Gadget},
    };

    fn test_ecdsa_circuit_with_config(config: CircuitConfig) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let msg = Secp256K1Scalar::rand();
        let msg_target = builder.constant_nonnative(msg);

        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));

        let sig = sign_message(msg, sk);

        let ECDSASignature { r, s } = sig;
        let r_target = builder.constant_nonnative(r);
        let s_target = builder.constant_nonnative(s);
        let sig_target = ECDSASignatureTarget { r: r_target, s: s_target };

        verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);

        dbg!(builder.num_gates());
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    fn test_ecdsa_circuit_with_config_v2(config: CircuitConfig) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let sig_gadget = Secp256K1CircuitGadget::add_virtual_to::<F, D, PoseidonHash>(&mut builder);
        builder.register_public_inputs(&sig_gadget.combined_hash.elements);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        let msg = Secp256K1Scalar::rand();

        let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
        let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

        let sig = sign_message(msg, sk);
        sig_gadget.set_witness_public_keys_update(&mut pw, &pk, &sig, &msg).unwrap();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    fn test_ecdsa_circuit_with_config_v3(config: CircuitConfig) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        // msg: 59516823202578934453231807837413051195901584431641309133515916306157505008006,
        // r: 46382090830721986485537520884209456015459577346611904846198514025443704074929
        // s: 1552372224772676730422293873878132316324342426499194332915447638702395075748
        // public_key:
        // [50013730234611584230439597283133877245741877311273264622332944843771023636024,
        // 48141770895752452309672524515321122504921566623690759896527638748277211309772]

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let sig_gadget = Secp256K1CircuitGadget::add_virtual_to::<F, D, PoseidonHash>(&mut builder);
        builder.register_public_inputs(&sig_gadget.combined_hash.elements);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        let msg = Secp256K1Scalar::from_noncanonical_biguint(
            BigUint::from_str("59516823202578934453231807837413051195901584431641309133515916306157505008006").unwrap(),
        );
        let r = Secp256K1Scalar::from_noncanonical_biguint(
            BigUint::from_str("46382090830721986485537520884209456015459577346611904846198514025443704074929").unwrap(),
        );

        let s = Secp256K1Scalar::from_noncanonical_biguint(
            BigUint::from_str("1552372224772676730422293873878132316324342426499194332915447638702395075748").unwrap(),
        );
        let pub_x = Secp256K1Base::from_noncanonical_biguint(
            BigUint::from_str("50013730234611584230439597283133877245741877311273264622332944843771023636024").unwrap(),
        );

        let pub_y = Secp256K1Base::from_noncanonical_biguint(
            BigUint::from_str("48141770895752452309672524515321122504921566623690759896527638748277211309772").unwrap(),
        );

        let pk = ECDSAPublicKey(AffinePoint::nonzero(pub_x, pub_y));

        let sig = ECDSASignature { r, s };
        sig_gadget.set_witness_public_keys_update(&mut pw, &pk, &sig, &msg).unwrap();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    fn test_ecdsa_circuit_with_config_v4(config: CircuitConfig) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        // msg: 59516823202578934453231807837413051195901584431641309133515916306157505008006,
        // r: 46382090830721986485537520884209456015459577346611904846198514025443704074929
        // s: 1552372224772676730422293873878132316324342426499194332915447638702395075748
        // public_key:
        // [50013730234611584230439597283133877245741877311273264622332944843771023636024,
        // 48141770895752452309672524515321122504921566623690759896527638748277211309772]

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let sig_gadget = Secp256K1Gadget::add_virtual_to_doge_psy::<PoseidonHash, F, D>(&mut builder);
        builder.register_public_inputs(&sig_gadget.msg_biguint_target.limbs.iter().map(|x| x.0).collect::<Vec<_>>());
        //builder.register_public_inputs(&sig_gadget.combined_hash.elements);
        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        let _msg = Secp256K1Scalar::from_noncanonical_biguint(
            BigUint::from_str("59516823202578934453231807837413051195901584431641309133515916306157505008006").unwrap(),
        );
        let r = Secp256K1Scalar::from_noncanonical_biguint(
            BigUint::from_str("46382090830721986485537520884209456015459577346611904846198514025443704074929").unwrap(),
        );

        let s = Secp256K1Scalar::from_noncanonical_biguint(
            BigUint::from_str("1552372224772676730422293873878132316324342426499194332915447638702395075748").unwrap(),
        );
        let pub_x = Secp256K1Base::from_noncanonical_biguint(
            BigUint::from_str("50013730234611584230439597283133877245741877311273264622332944843771023636024").unwrap(),
        );

        let pub_y = Secp256K1Base::from_noncanonical_biguint(
            BigUint::from_str("48141770895752452309672524515321122504921566623690759896527638748277211309772").unwrap(),
        );

        let pk = ECDSAPublicKey(AffinePoint::nonzero(pub_x, pub_y));

        let sig = ECDSASignature { r, s };
        let ho =
            <QHashOut<F> as KVQSerializable>::from_bytes(&hex::decode("83955402ec7f375d1d6e8f3bf59753fe0af1e7c62bb4b662716a2524d3e2d186").unwrap())
                .unwrap();
        sig_gadget.set_witness_public_keys_update(&mut pw, &pk, &sig, ho).unwrap();
        let proof = data.prove(pw).unwrap();
        tracing::info!("proof.public_inputs: {:?}", proof.public_inputs);
        data.verify(proof)
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_narrow() -> Result<()> {
        test_ecdsa_circuit_with_config(CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_narrow_v2() -> Result<()> {
        test_ecdsa_circuit_with_config_v2(CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_narrow_v3() -> Result<()> {
        test_ecdsa_circuit_with_config_v3(CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_narrow_v4() -> Result<()> {
        test_ecdsa_circuit_with_config_v4(CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_wide() -> Result<()> {
        test_ecdsa_circuit_with_config(CircuitConfig::wide_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_op_secp_sign() -> Result<()> {
        use std::{marker::PhantomData, str::FromStr};

        use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, VerifyingKey};
        use num::BigUint;
        use plonky2::{
            field::{secp256k1_base::Secp256K1Base, secp256k1_scalar::Secp256K1Scalar},
            iop::witness::PartialWitness,
            plonk::{
                circuit_builder::CircuitBuilder,
                circuit_data::CircuitConfig,
                config::{GenericConfig, PoseidonGoldilocksConfig},
            },
        };
        use psy_client_common::data::{base_types::hash256::Hash256, qhashout::QHashOut};
        use psy_crypto::signature::secp256k1::curve::secp256k1::Secp256K1;

        use crate::{
            crypto::secp256k1::{
                ecdsa::gadgets::{
                    biguint::{BigUintTarget, WitnessBigUint},
                    curve::AffinePointTarget,
                    ecdsa::{ECDSAPublicKeyTarget, ECDSASignatureTarget},
                    nonnative::NonNativeTarget,
                },
                gadget::verify_secp_sign_opcode,
            },
            u32::arithmetic_u32::CircuitBuilderU32,
        };

        type CURVE = Secp256K1;

        // let pub_key = [4203227662u32, 540940946u32, 962567723u32, 1830567167u32,
        // 3450763808u32, 3950740017u32, 3026903052u32, 3029228469u32, 1837759160u32,
        // 825683440u32, 3630293783u32, 436568768u32, 3543321651u32, 1044682747u32,
        // 168350425u32, 936127172u32]; let sig = [201339544u32, 2533129003u32,
        // 3911198242u32, 2163032835u32, 2488559593u32, 2971164201u32, 3572923983u32,
        // 3650316646u32, 3964687905u32, 1624041662u32, 2373224611u32, 3243422930u32,
        // 1353934640u32, 2321957132u32, 2691932396u32, 1560388502u32];
        // let msg = [6716978020874491267, 18326158388222717469, 7113070761591959818,
        // 9714795267687279217];

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_ecc_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);
        let msg_u32_targets = builder.add_virtual_u32_targets(8);

        let msg_target = NonNativeTarget::<Secp256K1Scalar> {
            value: BigUintTarget {
                limbs: msg_u32_targets.to_vec(),
            },
            _phantom: PhantomData,
        };

        let pk_x_u32_target = builder.add_virtual_u32_targets(8);
        let pk_x_target = NonNativeTarget::<Secp256K1Base> {
            value: BigUintTarget {
                limbs: pk_x_u32_target.to_vec(),
            },
            _phantom: PhantomData,
        };
        let pk_y_u32_target = builder.add_virtual_u32_targets(8);
        let pk_y_target = NonNativeTarget::<Secp256K1Base> {
            value: BigUintTarget {
                limbs: pk_y_u32_target.to_vec(),
            },
            _phantom: PhantomData,
        };
        let public_key_target = ECDSAPublicKeyTarget::<CURVE>(AffinePointTarget {
            x: pk_x_target.clone(),
            y: pk_y_target.clone(),
        });
        let r_u32_target = builder.add_virtual_u32_targets(8);
        let r_target = NonNativeTarget::<Secp256K1Scalar> {
            value: BigUintTarget {
                limbs: r_u32_target.to_vec(),
            },
            _phantom: PhantomData,
        };
        let s_u32_target = builder.add_virtual_u32_targets(8);
        let s_target = NonNativeTarget::<Secp256K1Scalar> {
            value: BigUintTarget {
                limbs: s_u32_target.to_vec(),
            },
            _phantom: PhantomData,
        };

        let signature_target = ECDSASignatureTarget::<Secp256K1> {
            r: r_target.clone(),
            s: s_target.clone(),
        };

        let vrfy_signature_is_valid = verify_secp_sign_opcode::<F, D>(&mut builder, &msg_target, &signature_target, &public_key_target);
        builder.assert_one(vrfy_signature_is_valid.target);

        let data = builder.build::<C>();
        let mut pw = PartialWitness::<F>::new();

        let sk = QHashOut::<F>::from_str("17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a")?;

        let mut sk_bytes = Hash256::from(sk).0;
        sk_bytes.reverse();
        let key_pair = k256::ecdsa::SigningKey::from_slice(&sk_bytes)?;
        let pk = key_pair.verifying_key();

        let sig_hash = QHashOut::<F>::from_str("83955402ec7f375d1d6e8f3bf59753fe0af1e7c62bb4b662716a2524d3e2d186")?;
        let mut sig_hash_bytes = Hash256::from(sig_hash).0;
        sig_hash_bytes.reverse();
        let signature: k256::ecdsa::Signature = key_pair.sign_prehash(&sig_hash_bytes)?;
        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        pk.verify_prehash(&sig_hash_bytes, &signature)?;

        let pk_bytes = pk.to_encoded_point(false).to_bytes();
        let pk_x = pk_bytes[1..33].to_vec();
        let pk_y = pk_bytes[33..65].to_vec();

        let pk2 = VerifyingKey::from_sec1_bytes(&pk_bytes).unwrap();
        assert_eq!(pk, &pk2);

        let mut _pk_x_u32 = pk_x.chunks(4).map(|c| u32::from_be_bytes(c.try_into().unwrap())).collect::<Vec<_>>();
        let pk_x_big = BigUint::from_bytes_be(&pk_x);
        let _pk_y_u32 = pk_y.chunks(4).map(|c| u32::from_be_bytes(c.try_into().unwrap())).collect::<Vec<_>>();
        let pk_y_big = BigUint::from_bytes_be(&pk_y);

        let r = signature.r().to_bytes().to_vec();
        let r_big = BigUint::from_bytes_be(&r);
        let s = signature.s().to_bytes().to_vec();
        let s_big = BigUint::from_bytes_be(&s);

        let sign_bytes = r.iter().chain(s.iter()).cloned().collect::<Vec<_>>();
        let sign_big = Signature::from_slice(&sign_bytes)?;
        assert_eq!(sign_big, signature);

        pw.set_biguint_target(&pk_x_target.value, &pk_x_big)?;
        pw.set_biguint_target(&pk_y_target.value, &pk_y_big)?;

        pw.set_biguint_target(&r_target.value, &r_big)?;
        pw.set_biguint_target(&s_target.value, &s_big)?;

        let msg_big = sig_hash.to_le_bytes();
        let msg_big = BigUint::from_bytes_be(&msg_big);
        pw.set_biguint_target(&msg_target.value, &msg_big)?;

        let proof = data.prove(pw)?;
        data.verify(proof)?;

        Ok(())
    }
}
