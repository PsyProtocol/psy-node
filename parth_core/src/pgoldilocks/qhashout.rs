use std::{fmt::Display, str::FromStr};

use anyhow::ensure;
use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable, PsyCanonicalSerializeMetadata};
use ts_rs::TS;
use crate::{crypto::hash::traits::{FromU64x4, HashTo4Felts, RandomHash, ToU64x4, ZeroableHash}, data::{hash::hash256::Hash256, serializable::{QPDSerializable, QPDSerializableFixed}}, felt::{QFelt64, ToQFelts}, generic_traits::QNamedType, protocol::core_types::{Q256BitHash, QHashBase}, utils::QPGenRandom};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, Sample},
    }, hash::hash_types::{HashOut, HashOutTarget, RichField}, iop::target::Target, plonk::config::GenericHashOut
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_with::serde_as;


#[derive(Clone, Debug, PartialEq, Eq, Copy, Hash, TS)]
#[cfg_attr(feature = "serialize_bytemuck", derive(bytemuck::Pod, bytemuck::Zeroable))]
#[cfg_attr(feature = "serialize_rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[ts(export, concrete(F = GoldilocksField))]
#[repr(transparent)]
pub struct QHashOut<F: Field>(pub HashOut<F>);

impl<F: QFelt64 + Field> PartialOrd for QHashOut<F> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let self_felts = [
            self.0.elements[0].to_u64_value(),
            self.0.elements[1].to_u64_value(),
            self.0.elements[2].to_u64_value(),
            self.0.elements[3].to_u64_value(),
        ];
        let other_felts = [
            other.0.elements[0].to_u64_value(),
            other.0.elements[1].to_u64_value(),
            other.0.elements[2].to_u64_value(),
            other.0.elements[3].to_u64_value(),
        ];
        self_felts.partial_cmp(&other_felts)
    }
}
impl<F: QFelt64 + Field> Ord for QHashOut<F> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let self_felts = [
            self.0.elements[0].to_u64_value(),
            self.0.elements[1].to_u64_value(),
            self.0.elements[2].to_u64_value(),
            self.0.elements[3].to_u64_value(),
        ];
        let other_felts = [
            other.0.elements[0].to_u64_value(),
            other.0.elements[1].to_u64_value(),
            other.0.elements[2].to_u64_value(),
            other.0.elements[3].to_u64_value(),
        ];
        self_felts.cmp(&other_felts)
    }
}

pub type GoldilocksHashOut = QHashOut<GoldilocksField>;

#[serde_as]
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct SerializableHashOut(#[serde_as(as = "serde_with::hex::Hex")] pub Vec<u8>);

impl<F: RichField> Serialize for QHashOut<F> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut bytes = GenericHashOut::to_bytes(&self.0);
        bytes.reverse();
        let raw = SerializableHashOut(bytes);

        raw.serialize(serializer)
    }
}

impl<'de, F: RichField> Deserialize<'de> for QHashOut<F> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = SerializableHashOut::deserialize(deserializer)?;
        let mut bytes = raw.0;
        if bytes.len() > 32 {
            return Err(serde::de::Error::custom("too long hexadecimal sequence"));
        }
        bytes.reverse();
        bytes.resize(32, 0);

        Ok(QHashOut(<HashOut<F> as GenericHashOut<F>>::from_bytes(
            &bytes,
        )))
    }
}

impl<F: RichField> QPDSerializableFixed for QHashOut<F> {
    fn get_fixed_size() -> usize {
        32
    }
}
impl<F: RichField> QPDSerializable for QHashOut<F> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.to_le_bytes().to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::from_le_bytes(bytes)
    }
}
impl<F: Field> Default for QHashOut<F> {
    fn default() -> Self {
        QHashOut(HashOut::ZERO)
    }
}

impl<F: Field> From<QHashOut<F>> for HashOut<F> {
    fn from(value: QHashOut<F>) -> Self {
        value.0
    }
}
impl<F: Field> From<HashOut<F>> for QHashOut<F> {
    fn from(value: HashOut<F>) -> Self {
        QHashOut(value)
    }
}

impl<F: RichField> TryFrom<&[F]> for QHashOut<F> {
    type Error = anyhow::Error;

    fn try_from(elements: &[F]) -> Result<Self, Self::Error> {
        ensure!(elements.len() == 4);
        Ok(Self(HashOut {
            elements: elements.try_into().unwrap(),
        }))
    }
}

impl<F: RichField> TryFrom<&[u64; 4]> for QHashOut<F> {
    type Error = anyhow::Error;

    fn try_from(elements: &[u64; 4]) -> Result<Self, Self::Error> {
        Ok(Self(HashOut {
            elements: [
                F::from_noncanonical_u64(elements[0]),
                F::from_noncanonical_u64(elements[1]),
                F::from_noncanonical_u64(elements[2]),
                F::from_noncanonical_u64(elements[3]),
            ],
        }))
    }
}
impl<F: RichField> Display for QHashOut<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_string(self)
            .map(|v| v.replace('\"', ""))
            .unwrap();

        write!(f, "{}", s)
    }
}

impl<F: RichField> FromStr for QHashOut<F> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let json = "\"".to_string() + s + "\"";

        serde_json::from_str(&json)
    }
}

impl<F: RichField> GenericHashOut<F> for QHashOut<F> {
    fn to_bytes(&self) -> Vec<u8> {
        GenericHashOut::to_bytes(&self.0)
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        QHashOut(<HashOut<F> as GenericHashOut<F>>::from_bytes(bytes))
    }

    fn to_vec(&self) -> Vec<F> {
        self.0.to_vec()
    }
}
impl<F: RichField> QHashOut<F> {
    pub const ZERO: Self = Self(HashOut::<F>::ZERO);

    pub fn from_string_or_panic(s: &str) -> Self {
        let json = "\"".to_string() + s + "\"";

        serde_json::from_str(&json).unwrap()
    }
    pub fn rand() -> Self {
        Self(HashOut::rand())
    }
    pub fn from_values(a: u64, b: u64, c: u64, d: u64) -> Self {
        Self(HashOut {
            elements: [
                F::from_noncanonical_u64(a),
                F::from_noncanonical_u64(b),
                F::from_noncanonical_u64(c),
                F::from_noncanonical_u64(d),
            ],
        })
    }
    fn from_values_no_canonical_conversion(a: u64, b: u64, c: u64, d: u64) -> Self {
        // TODO: For goldilocks, this is the same as from_values, but for other fields it might not be
        // If we directly do from_canonical_u64 on non-canonical values, it trigger a panic in debug_assert
        // See debug_assert and plonky2 code at https://github.com/PsyRepoForks/plonky2-hwa/blob/8d5b56f42fe87942312f270a5dc26c0059f973fb/field/src/goldilocks_field.rs#L183
        /*
            impl Field for GoldilocksField {
                // ...
                #[inline(always)]
                fn from_canonical_u64(n: u64) -> Self {
                    debug_assert!(n < Self::ORDER); // <-- This line triggers a panic if n >= ORDER
                    Self(n) // <-- this is the same as from_noncanonical_u64
                }

                // ...

                #[inline]
                fn from_noncanonical_u64(n: u64) -> Self {
                    Self(n) // <-- this is the same as from_canonical_u64, as the u64 value is not assumed to be stored in canonical form
                }
                // ...
            }
        
         */
        Self(HashOut {
            elements: [
                F::from_noncanonical_u64(a),
                F::from_noncanonical_u64(b),
                F::from_noncanonical_u64(c),
                F::from_noncanonical_u64(d),
            ],
        })
    }
    pub fn from_felt_slice(slice: &[F]) -> Self {
        Self(HashOut {
            elements: [slice[0], slice[1], slice[2], slice[3]],
        })
    }
    pub fn from_le_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() == 32, "Invalid byte length for HashOut");
        let elements_0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let elements_1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let elements_2 = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let elements_3 = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        Ok(Self::from_values(elements_0, elements_1, elements_2, elements_3))
    }
    pub fn to_le_bytes(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&self.0.elements[0].to_canonical_u64().to_le_bytes());
        result[8..16].copy_from_slice(&self.0.elements[1].to_canonical_u64().to_le_bytes());
        result[16..24].copy_from_slice(&self.0.elements[2].to_canonical_u64().to_le_bytes());
        result[24..32].copy_from_slice(&self.0.elements[3].to_canonical_u64().to_le_bytes());
        result
    }
    pub fn to_le_bytes_non_canonical(&self) -> [u8; 32] {
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&self.0.elements[0].to_noncanonical_u64().to_le_bytes());
        result[8..16].copy_from_slice(&self.0.elements[1].to_noncanonical_u64().to_le_bytes());
        result[16..24].copy_from_slice(&self.0.elements[2].to_noncanonical_u64().to_le_bytes());
        result[24..32].copy_from_slice(&self.0.elements[3].to_noncanonical_u64().to_le_bytes());
        result
    }
    pub fn from_le_bytes_no_canonical_conversion(bytes: &[u8]) -> anyhow::Result<Self> {
        ensure!(bytes.len() == 32, "Invalid byte length for HashOut");
        let elements_0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let elements_1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let elements_2 = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let elements_3 = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        Ok(Self::from_values_no_canonical_conversion(elements_0, elements_1, elements_2, elements_3))
    }
    pub fn from_hash256_le(hash: Hash256) -> Self {
        let u64_x4 = hash.to_le_u64_x4();
        Self(HashOut {
            elements: [
                F::from_noncanonical_u64(u64_x4[0]),
                F::from_noncanonical_u64(u64_x4[1]),
                F::from_noncanonical_u64(u64_x4[2]),
                F::from_noncanonical_u64(u64_x4[3]),
            ],
        })
    }
    pub fn to_string_le(&self) -> String {
        hex::encode(self.to_le_bytes())
    }
}



impl<F: RichField> RandomHash for QHashOut<F> {
    fn rand_hash() -> Self {
        Self::rand()
    }
}

impl<F: RichField> QPGenRandom for QHashOut<F> {
    fn qp_rand_gen() -> Self where Self: Sized {
        Self::rand()
    }
}


impl<F: Field> ToQFelts<F> for HashOut<F> {
    fn to_qfelts(&self) -> Vec<F> {
        self.elements.to_vec()
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 4 {
            panic!("Invalid number of elements for HashOut");
        }
        Self {
            elements: [felts[0], felts[1], felts[2], felts[3]],
        }
    }
}
impl<F: RichField> ToQFelts<F> for QHashOut<F> {
    fn to_qfelts(&self) -> Vec<F> {
        self.0.elements.to_vec()
    }
    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 4 {
            panic!("Invalid number of elements for QHashOut");
        }
        QHashOut(
            HashOut {elements: [felts[0], felts[1], felts[2], felts[3]]}
        )
    }
}
impl ToQFelts<Target> for HashOutTarget {
    fn to_qfelts(&self) -> Vec<Target> {
        self.elements.to_vec()
    }
    fn from_qfelts(felts: &[Target]) -> Self {
        if felts.len() != 4 {
            panic!("Invalid number of elements for QHashOut");
        }
        HashOutTarget {elements: [felts[0], felts[1], felts[2], felts[3]]}
    }
}


#[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
impl Q256BitHash for QHashOut<GoldilocksField> {
    #[inline]
    fn from_owned_32bytes(bytes: [u8; 32]) -> Self {
        // Zero-copy because the source is an owned, aligned array.
       bytemuck::cast(bytes)
    }

    #[inline]
    fn into_owned_32bytes(self) -> [u8; 32] {
        // Zero-copy because the type layouts are identical.
         bytemuck::cast(self)
    }

    #[inline]
    fn from_ref_32bytes(bytes: &[u8; 32]) -> Self {
        // Zero-copy cast from a reference. .clone() is a fast, full-register copy.
        bytemuck::cast(*bytes)
    }

    /// Tries to convert a byte slice into a QHashOut.
    ///
    /// This is the fastest possible implementation. It first attempts a
    /// zero-copy conversion. If the slice is not properly aligned for a
    /// direct cast, it falls back to a safe, one-time copy.
    #[inline]
    fn from_slice_32bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        // First, try the zero-copy path.
        // `try_from_bytes` will return a `Ok(&Self)` if the slice has the
        // correct length AND is aligned. This is the ideal and fastest case.
        if let Ok(hash_ref) = bytemuck::try_from_bytes(bytes) {
            return Ok(*hash_ref);
        }

        // If try_from_bytes failed, it's because of length or alignment.
        // We can fall back to a copy. `try_into()` checks the length and
        // creates an aligned stack array `[u8; 32]`, making the subsequent
        // `from_bytes` call a guaranteed zero-copy success.
        let owned_bytes: [u8; 32] = bytes.try_into()
            .map_err(|_| anyhow::anyhow!(
                "Input slice has incorrect length. Expected 32, got {}",
                bytes.len()
            ))?;

        Ok(Self::from_owned_32bytes(owned_bytes))
    }

    /// Converts the hash into an owned Vec<u8>.
    ///
    /// This is the fastest way to perform this conversion. It gets a byte
    /// slice view of `self` and calls `.to_vec()`, which performs a single
    //  allocation and a single `memcpy`.
    #[inline]
    fn to_vec_32bytes(&self) -> Vec<u8> {
        bytemuck::bytes_of(self).to_vec()
    }
}

#[cfg(any(not(feature = "serialize_bytemuck"), not(target_endian = "little")))]
impl Q256BitHash for QHashOut<GoldilocksField> {
    fn from_owned_32bytes(bytes: [u8; 32]) -> Self {
        Self::from_le_bytes(&bytes).unwrap()
    }
    fn into_owned_32bytes(self) -> [u8; 32] {
        self.to_le_bytes()
    }
    fn from_ref_32bytes(bytes: &[u8; 32]) -> Self {
        Self::from_le_bytes(bytes).unwrap()
    }
    fn from_slice_32bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::from_le_bytes(bytes)
    }
    fn to_vec_32bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl<F: QNamedType + Field> QNamedType for QHashOut<F> {
    fn q_type_name() -> String {
        format!("QHashOut<{}>", F::q_type_name())
    }
}

#[cfg(feature = "serialize_speedy")]
use speedy::{Readable, Writable, LittleEndian, Reader, Writer};

// ... (Your existing imports and code remain unchanged)


// Updated speedy implementations for QHashOut<F>
#[cfg(feature = "serialize_speedy")]
impl<'a, F: Field> Readable<'a, LittleEndian> for QHashOut<F>
where
    F: for<'b> Readable<'b, LittleEndian> + Writable<LittleEndian>,
{
    fn read_from<R: Reader<'a, LittleEndian>>(reader: &mut R) -> Result<Self, speedy::Error> {
        let elements = [
            F::read_from(reader)?,
            F::read_from(reader)?,
            F::read_from(reader)?,
            F::read_from(reader)?,
        ];
        Ok(QHashOut(HashOut { elements }))
    }
}

#[cfg(feature = "serialize_speedy")]
impl<F: Writable<LittleEndian> + Field> Writable<LittleEndian> for QHashOut<F> {
    fn write_to<T: ?Sized + Writer<LittleEndian>>(&self, writer: &mut T) -> Result<(), speedy::Error> {
        for element in self.0.elements.iter() {
            element.write_to(writer)?;
        }
        Ok(())
    }
}


impl FastFixedSerializable<32> for QHashOut<GoldilocksField> {
    fn ffs_from_owned_bytes(data: [u8; 32]) -> Self {
        Self::from_owned_32bytes(data)
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self::from_slice_32bytes(data).expect("Invalid number of bytes for QHashOut")
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        Self::from_slice_32bytes(data)
    }

    fn ffs_to_bytes(&self) -> [u8; 32] {
        self.into_owned_32bytes()
    }
    
    fn ffs_into_bytes(self) -> [u8; 32] {
        self.into_owned_32bytes()
    }
}

impl PsyCanonicalSerializeMetadata for QHashOut<GoldilocksField> {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 32;
}
type PGoldilocksHash = QHashOut<GoldilocksField>;
impl AutoDatabaseSerializationUseFastFixedSerialize<32> for QHashOut<GoldilocksField> {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(
    PGoldilocksHash, 
    32
);
// ... (Your existing code for QHashOut<F>, Serialize, Deserialize, QPDSerializable, etc., remains unchanged)

// QHashBase implementation (unchanged)

pser::impl_bytemuck_ffs_tests!(
    PGoldilocksHash,
    {},
    32,
    true
);



#[cfg(feature = "serialize_speedy")]
impl QHashBase for QHashOut<GoldilocksField> {}

#[cfg(not(feature = "serialize_speedy"))]
impl QHashBase for QHashOut<GoldilocksField> {}

#[cfg(test)]
mod tests_std {
    use crate::{crypto::hash::traits::{FieldQHasher, MerkleHasher}, pgoldilocks::PoseidonHasher};

    use super::*;
    use plonky2::field::{goldilocks_field::GoldilocksField as F, types::PrimeField64};


    fn ensure_used_hash_equal(hash_a: QHashOut<F>, hash_b: QHashOut<F>) -> QHashOut<F> {

        let elements_canonical_a = [
            hash_a.0.elements[0].to_canonical_u64(),
            hash_a.0.elements[1].to_canonical_u64(),
            hash_a.0.elements[2].to_canonical_u64(),
            hash_a.0.elements[3].to_canonical_u64(),
        ];
        let elements_canonical_b= [
            hash_b.0.elements[0].to_canonical_u64(),
            hash_b.0.elements[1].to_canonical_u64(),
            hash_b.0.elements[2].to_canonical_u64(),
            hash_b.0.elements[3].to_canonical_u64(),
        ];
        assert_eq!(elements_canonical_a, elements_canonical_b, "hash_a and hash_b have different canonical representations");

        let canonical_hash = QHashOut(HashOut { elements: [
            F::from_canonical_u64(elements_canonical_a[0]),
            F::from_canonical_u64(elements_canonical_a[1]),
            F::from_canonical_u64(elements_canonical_a[2]),
            F::from_canonical_u64(elements_canonical_a[3]),
        ]});
        assert_eq!(hash_a, canonical_hash, "hash_a does not match its canonical representation");
        assert_eq!(hash_b, canonical_hash, "hash_b does not match its canonical representation");

        // test hash(a,b) == hash(b,a) == hash(a,a) == hash(b,b) == hash(canonical_hash, canonical_hash)
        let t_same_same_0 = PoseidonHasher::two_to_one(&hash_a, &hash_b);
        let t_same_same_1 = PoseidonHasher::two_to_one(&hash_b, &hash_a);
        let t_same_same_2 = PoseidonHasher::two_to_one(&hash_a, &hash_a);
        let t_same_same_3 = PoseidonHasher::two_to_one(&hash_b, &hash_b);
        let t_same_same_4 = PoseidonHasher::two_to_one(&canonical_hash, &canonical_hash);
        assert_eq!(t_same_same_0, t_same_same_1, "PoseidonHasher produced different hashes for same inputs");
        assert_eq!(t_same_same_0, t_same_same_2, "PoseidonHasher produced different hashes for same inputs");
        assert_eq!(t_same_same_0, t_same_same_3, "PoseidonHasher produced different hashes for same inputs");
        assert_eq!(t_same_same_0, t_same_same_4, "PoseidonHasher produced different hashes for same inputs");

        assert_eq!(t_same_same_0.into_owned_32bytes(), t_same_same_1.into_owned_32bytes(), "hash(hash_a, hash_b) and hash(hash_b, hash_a) produced different byte arrays");
        assert_eq!(t_same_same_0.into_owned_32bytes(), t_same_same_2.into_owned_32bytes(), "hash(hash_a, hash_b) and hash(hash_b, hash_a) produced different byte arrays");
        assert_eq!(t_same_same_0.into_owned_32bytes(), t_same_same_3.into_owned_32bytes(), "hash(hash_a, hash_b) and hash(hash_a, hash_a) produced different byte arrays");
        assert_eq!(t_same_same_0.into_owned_32bytes(), t_same_same_4.into_owned_32bytes(), "hash(hash_a, hash_b) and hash(hash_b, hash_b) produced different byte arrays");

        // test hash(a) == hash(b) == hash(canonical_hash)
        let t_same_self_a: QHashOut<F> = PoseidonHasher::q_hash_many(&hash_a.0.elements);
        let t_same_self_b: QHashOut<F> = PoseidonHasher::q_hash_many(&hash_b.0.elements);
        let t_same_self_c: QHashOut<F> = PoseidonHasher::q_hash_many(&canonical_hash.0.elements);
        assert_eq!(t_same_self_a, t_same_self_b, "PoseidonHasher produced different hashes for same inputs");
        assert_eq!(t_same_self_a, t_same_self_c, "PoseidonHasher produced different hashes for same inputs");
        assert_eq!(t_same_self_a.into_owned_32bytes(), t_same_self_b.into_owned_32bytes(), "hash(hash_a) and hash(hash_b) produced different byte arrays");
        assert_eq!(t_same_self_a.into_owned_32bytes(), t_same_self_c.into_owned_32bytes(), "hash(hash_a) and hash(canonical_hash) produced different byte arrays");




        

        hash_a
        
    }

    fn ensure_q256bithash_round_trips_hash_result(hash: QHashOut<F>){
        // test if from_owned_32bytes and into_owned_32bytes are inverses
        let from_into_test_hash = hash.clone();
        let bytes_copy_bm = from_into_test_hash.into_owned_32bytes();
        let bytes_copy_fallback = from_into_test_hash.to_le_bytes_non_canonical();
        assert_eq!(bytes_copy_bm, bytes_copy_fallback, "bytemuck and fallback produced different byte arrays");
        let hash_from_bm = ensure_used_hash_equal(QHashOut::<F>::from_owned_32bytes(bytes_copy_bm), hash);
        assert_eq!(hash, hash_from_bm, "bytemuck and fallback produced different hashes");
        let hash_from_fallback = ensure_used_hash_equal(QHashOut::<F>::from_le_bytes_no_canonical_conversion(&bytes_copy_fallback).unwrap(), hash);
        assert_eq!(hash, hash_from_fallback, "bytemuck and fallback produced different hashes");
        let bm_hash_from_fallback_bytes = ensure_used_hash_equal(QHashOut::<F>::from_owned_32bytes(bytes_copy_fallback), hash);
        assert_eq!(hash, bm_hash_from_fallback_bytes, "bytemuck and fallback produced different hashes");
        let fallback_hash_from_bm_bytes = ensure_used_hash_equal(QHashOut::<F>::from_le_bytes(&bytes_copy_bm).unwrap(), hash);
        assert_eq!(hash, fallback_hash_from_bm_bytes, "bytemuck and fallback produced different hashes");


        // test if from_ref_32bytes works the same as from_le_bytes_no_canonical_conversion
        let from_ref_32bytes_test_hash = hash.clone();
        let from_ref_32bytes_correct_bytes = from_ref_32bytes_test_hash.to_le_bytes_non_canonical();
        let bm_hash_from_ref = ensure_used_hash_equal(QHashOut::<F>::from_ref_32bytes(&from_ref_32bytes_correct_bytes), hash);
        assert_eq!(from_ref_32bytes_test_hash, bm_hash_from_ref, "bytemuck and fallback produced different hashes");
        let fallback_hash_from_ref = ensure_used_hash_equal(QHashOut::<F>::from_le_bytes_no_canonical_conversion(&from_ref_32bytes_correct_bytes).unwrap(), hash);
        assert_eq!(from_ref_32bytes_test_hash, fallback_hash_from_ref, "bytemuck and fallback produced different hashes");
        let bm_hash_from_ref_bytes = bm_hash_from_ref.into_owned_32bytes();
        let fallback_hash_from_ref_bytes = fallback_hash_from_ref.to_le_bytes_non_canonical();
        assert_eq!(bm_hash_from_ref_bytes, fallback_hash_from_ref_bytes, "bytemuck and fallback produced different byte arrays");

        // test if from_slice_32bytes works the same as from_le_bytes_no_canonical_conversion
        let from_slice_32bytes_test_hash = hash.clone();
        let from_slice_32bytes_correct_bytes = from_slice_32bytes_test_hash.to_le_bytes_non_canonical();
        let bm_hash_from_slice = ensure_used_hash_equal(QHashOut::<F>::from_slice_32bytes(&from_slice_32bytes_correct_bytes).unwrap(), hash);
        assert_eq!(from_slice_32bytes_test_hash, bm_hash_from_slice, "bytemuck and fallback produced different hashes");
        let fallback_hash_from_slice = ensure_used_hash_equal(QHashOut::<F>::from_le_bytes_no_canonical_conversion(&from_slice_32bytes_correct_bytes).unwrap(), hash);
        assert_eq!(from_slice_32bytes_test_hash, fallback_hash_from_slice, "bytemuck and fallback produced different hashes");
        let bm_hash_from_slice_bytes = bm_hash_from_slice.into_owned_32bytes();
        let fallback_hash_from_slice_bytes = fallback_hash_from_slice.to_le_bytes_non_canonical();
        assert_eq!(bm_hash_from_slice_bytes, fallback_hash_from_slice_bytes, "bytemuck and fallback produced different byte arrays");

        // try creating canonical hashes from the arrays
        let canonical_hash_from_bm = ensure_used_hash_equal(QHashOut::<F>::from_le_bytes(&bm_hash_from_slice_bytes).unwrap(), hash);
        let canonical_hash_from_fallback = ensure_used_hash_equal(QHashOut::<F>::from_le_bytes(&fallback_hash_from_slice_bytes).unwrap(), hash);
        assert_eq!(canonical_hash_from_bm, canonical_hash_from_fallback, "bytemuck and fallback produced different hashes");
        assert_eq!(canonical_hash_from_bm, hash, "bytemuck and fallback produced different hashes");

        // test if to_vec_32bytes works the same as to_le_bytes_non_canonical
        let to_vec_32bytes_test_hash = hash.clone();
        let bm_bytes = to_vec_32bytes_test_hash.to_vec_32bytes();
        assert!(bm_bytes.len() == 32, "bytemuck and fallback produced different byte arrays");
        let fallback_bytes = to_vec_32bytes_test_hash.to_le_bytes_non_canonical().to_vec();
        assert!(fallback_bytes.len() == 32, "bytemuck and fallback produced different byte arrays");
        assert_eq!(bm_bytes, fallback_bytes, "bytemuck and fallback produced different byte arrays");
        let bm_bytes_vec = to_vec_32bytes_test_hash.clone().into_owned_32bytes().to_vec();
        assert_eq!(bm_bytes_vec, fallback_bytes, "bytemuck and fallback produced different byte arrays");
        let fallback_bytes_vec = to_vec_32bytes_test_hash.to_le_bytes_non_canonical().to_vec();
        assert_eq!(fallback_bytes_vec, fallback_bytes, "bytemuck and fallback produced different byte arrays");
        let vec_to_32bytes: [u8; 32] = fallback_bytes_vec.try_into().unwrap();
        assert_eq!(vec_to_32bytes, to_vec_32bytes_test_hash.to_le_bytes_non_canonical(), "bytemuck and fallback produced different byte arrays");
        assert_eq!(vec_to_32bytes, to_vec_32bytes_test_hash.into_owned_32bytes(), "bytemuck and fallback produced different byte arrays");

    }


    fn ensure_q256bithash_round_trips(hash: QHashOut<F>){
        // test if from_owned_32bytes and into_owned_32bytes are inverses
        let from_into_test_hash = hash.clone();
        let bytes_copy_bm = from_into_test_hash.into_owned_32bytes();
        let bytes_copy_fallback = from_into_test_hash.to_le_bytes_non_canonical();
        assert_eq!(bytes_copy_bm, bytes_copy_fallback, "bytemuck and fallback produced different byte arrays");
        let hash_from_bm = QHashOut::<F>::from_owned_32bytes(bytes_copy_bm);
        assert_eq!(hash, hash_from_bm, "bytemuck and fallback produced different hashes");
        let hash_from_fallback = QHashOut::<F>::from_le_bytes_no_canonical_conversion(&bytes_copy_fallback).unwrap();
        assert_eq!(hash, hash_from_fallback, "bytemuck and fallback produced different hashes");
        let bm_hash_from_fallback_bytes = QHashOut::<F>::from_owned_32bytes(bytes_copy_fallback);
        assert_eq!(hash, bm_hash_from_fallback_bytes, "bytemuck and fallback produced different hashes");
        let fallback_hash_from_bm_bytes = QHashOut::<F>::from_le_bytes(&bytes_copy_bm).unwrap();
        assert_eq!(hash, fallback_hash_from_bm_bytes, "bytemuck and fallback produced different hashes");


        // test if from_ref_32bytes works the same as from_le_bytes_no_canonical_conversion
        let from_ref_32bytes_test_hash = hash.clone();
        let from_ref_32bytes_correct_bytes = from_ref_32bytes_test_hash.to_le_bytes_non_canonical();
        let bm_hash_from_ref = QHashOut::<F>::from_ref_32bytes(&from_ref_32bytes_correct_bytes);
        assert_eq!(from_ref_32bytes_test_hash, bm_hash_from_ref, "bytemuck and fallback produced different hashes");
        let fallback_hash_from_ref = QHashOut::<F>::from_le_bytes_no_canonical_conversion(&from_ref_32bytes_correct_bytes).unwrap();
        assert_eq!(from_ref_32bytes_test_hash, fallback_hash_from_ref, "bytemuck and fallback produced different hashes");
        let bm_hash_from_ref_bytes = bm_hash_from_ref.into_owned_32bytes();
        let fallback_hash_from_ref_bytes = fallback_hash_from_ref.to_le_bytes_non_canonical();
        assert_eq!(bm_hash_from_ref_bytes, fallback_hash_from_ref_bytes, "bytemuck and fallback produced different byte arrays");

        // test if from_slice_32bytes works the same as from_le_bytes_no_canonical_conversion
        let from_slice_32bytes_test_hash = hash.clone();
        let from_slice_32bytes_correct_bytes = from_slice_32bytes_test_hash.to_le_bytes_non_canonical();
        let bm_hash_from_slice = QHashOut::<F>::from_slice_32bytes(&from_slice_32bytes_correct_bytes).unwrap();
        assert_eq!(from_slice_32bytes_test_hash, bm_hash_from_slice, "bytemuck and fallback produced different hashes");
        let fallback_hash_from_slice = QHashOut::<F>::from_le_bytes_no_canonical_conversion(&from_slice_32bytes_correct_bytes).unwrap();
        assert_eq!(from_slice_32bytes_test_hash, fallback_hash_from_slice, "bytemuck and fallback produced different hashes");
        let bm_hash_from_slice_bytes = bm_hash_from_slice.into_owned_32bytes();
        let fallback_hash_from_slice_bytes = fallback_hash_from_slice.to_le_bytes_non_canonical();
        assert_eq!(bm_hash_from_slice_bytes, fallback_hash_from_slice_bytes, "bytemuck and fallback produced different byte arrays");

        // try creating canonical hashes from the arrays
        let canonical_hash_from_bm = QHashOut::<F>::from_le_bytes(&bm_hash_from_slice_bytes).unwrap();
        let canonical_hash_from_fallback = QHashOut::<F>::from_le_bytes(&fallback_hash_from_slice_bytes).unwrap();
        assert_eq!(canonical_hash_from_bm, canonical_hash_from_fallback, "bytemuck and fallback produced different hashes");
        assert_eq!(canonical_hash_from_bm, hash, "bytemuck and fallback produced different hashes");

        // test if to_vec_32bytes works the same as to_le_bytes_non_canonical
        let to_vec_32bytes_test_hash = hash.clone();
        let bm_bytes = to_vec_32bytes_test_hash.to_vec_32bytes();
        assert!(bm_bytes.len() == 32, "bytemuck and fallback produced different byte arrays");
        let fallback_bytes = to_vec_32bytes_test_hash.to_le_bytes_non_canonical().to_vec();
        assert!(fallback_bytes.len() == 32, "bytemuck and fallback produced different byte arrays");
        assert_eq!(bm_bytes, fallback_bytes, "bytemuck and fallback produced different byte arrays");
        let bm_bytes_vec = to_vec_32bytes_test_hash.clone().into_owned_32bytes().to_vec();
        assert_eq!(bm_bytes_vec, fallback_bytes, "bytemuck and fallback produced different byte arrays");
        let fallback_bytes_vec = to_vec_32bytes_test_hash.to_le_bytes_non_canonical().to_vec();
        assert_eq!(fallback_bytes_vec, fallback_bytes, "bytemuck and fallback produced different byte arrays");
        let vec_to_32bytes: [u8; 32] = fallback_bytes_vec.try_into().unwrap();
        assert_eq!(vec_to_32bytes, to_vec_32bytes_test_hash.to_le_bytes_non_canonical(), "bytemuck and fallback produced different byte arrays");
        assert_eq!(vec_to_32bytes, to_vec_32bytes_test_hash.into_owned_32bytes(), "bytemuck and fallback produced different byte arrays");

    }

    
    #[test]
    fn test_q256bithash_basic_round_trips(){

        let base_test_hashes = [
            QHashOut::<F>::ZERO,
            QHashOut::from_values(0, 0, 0, 0),
            QHashOut::from_values(1, 0, 0, 0),
            QHashOut::from_values(0, 1, 0, 0),
            QHashOut::from_values(0, 0, 1, 0),
            QHashOut::from_values(0, 0, 0, 1),
            QHashOut::from_values(1, 1, 1, 1),
            QHashOut::from_values(u64::MAX, u64::MAX, u64::MAX, u64::MAX),
            QHashOut::from_values(u64::MAX - 1, u64::MAX - 1, u64::MAX - 1, u64::MAX - 1),
            QHashOut::from_values(u64::MAX, 0, 0, 0),
            QHashOut::from_values(0, u64::MAX, 0, 0),
            QHashOut::from_values(0, 0, u64::MAX, 0),
            QHashOut::from_values(0, 0, 0, u64::MAX),
            QHashOut::from_values(u64::MAX, u64::MAX, 0, 0),
            QHashOut::from_values(0, u64::MAX, u64::MAX, 0),
            QHashOut::from_values(0, 0, u64::MAX, u64::MAX),
            QHashOut::from_values(u64::MAX, 0, u64::MAX, 0),
            QHashOut::from_values(0, u64::MAX, 0, u64::MAX),
            QHashOut::from_values(u64::MAX, 0, 0, u64::MAX),
            QHashOut::from_values(0x0123456789ABCDEF, 0x1122334455667788, 0x99AABBCCDDEEFF00, 0xFFEEDDCCBBAA9988),
            QHashOut::from_values(123988, 123988, 123988, 123988),
            QHashOut::from_values(512523, 123921351288, 999123988, 29110101),
            QHashOut::from_values(18446744069414584321, 18446744069414584321, 999123988, 18446744069414584321),
            QHashOut::from_values(18446744069414584320, 189123913712983, 18446744069414584320, 18446744069414584322),
        ];
        for base_hash in base_test_hashes {
            ensure_q256bithash_round_trips(base_hash);
        }
        for _ in 0..1000 {
            let random_hash = QHashOut::<F>::rand();
            ensure_q256bithash_round_trips(random_hash);
        }
        for _ in 0..1000 {
            let rand_hash256 = Hash256::rand();
            let hash_from_hash256 = QHashOut::<F>::from_hash256_le(rand_hash256);
            ensure_q256bithash_round_trips(hash_from_hash256);
        }

        for _ in 0..1000 {
            let rand_hash256 = Hash256::rand();
            let hash = QHashOut::<F>::from_owned_32bytes(rand_hash256.0);
            ensure_q256bithash_round_trips(hash);

        }

    }

    #[test]
    fn test_q256bithash_basic_round_trips_hash_result(){

        let base_test_hashes = [
            QHashOut::<F>::ZERO,
            QHashOut::from_values(0, 0, 0, 0),
            QHashOut::from_values(1, 0, 0, 0),
            QHashOut::from_values(0, 1, 0, 0),
            QHashOut::from_values(0, 0, 1, 0),
            QHashOut::from_values(0, 0, 0, 1),
            QHashOut::from_values(1, 1, 1, 1),
            QHashOut::from_values(u64::MAX, u64::MAX, u64::MAX, u64::MAX),
            QHashOut::from_values(u64::MAX - 1, u64::MAX - 1, u64::MAX - 1, u64::MAX - 1),
            QHashOut::from_values(u64::MAX, 0, 0, 0),
            QHashOut::from_values(0, u64::MAX, 0, 0),
            QHashOut::from_values(0, 0, u64::MAX, 0),
            QHashOut::from_values(0, 0, 0, u64::MAX),
            QHashOut::from_values(u64::MAX, u64::MAX, 0, 0),
            QHashOut::from_values(0, u64::MAX, u64::MAX, 0),
            QHashOut::from_values(0, 0, u64::MAX, u64::MAX),
            QHashOut::from_values(u64::MAX, 0, u64::MAX, 0),
            QHashOut::from_values(0, u64::MAX, 0, u64::MAX),
            QHashOut::from_values(u64::MAX, 0, 0, u64::MAX),
            QHashOut::from_values(0x0123456789ABCDEF, 0x1122334455667788, 0x99AABBCCDDEEFF00, 0xFFEEDDCCBBAA9988),
            QHashOut::from_values(123988, 123988, 123988, 123988),
            QHashOut::from_values(512523, 123921351288, 999123988, 29110101),
            QHashOut::from_values(18446744069414584321, 18446744069414584321, 999123988, 18446744069414584321),
            QHashOut::from_values(18446744069414584320, 189123913712983, 18446744069414584320, 18446744069414584322),
        ];
        for base_hash in base_test_hashes {
            ensure_q256bithash_round_trips_hash_result(base_hash);
        }
        for _ in 0..1000 {
            let random_hash = QHashOut::<F>::rand();
            ensure_q256bithash_round_trips_hash_result(random_hash);
        }
        for _ in 0..1000 {
            let rand_hash256 = Hash256::rand();
            let hash_from_hash256 = QHashOut::<F>::from_hash256_le(rand_hash256);
            ensure_q256bithash_round_trips_hash_result(hash_from_hash256);
        }

        for _ in 0..1000 {
            let rand_hash256 = Hash256::rand();
            let hash = QHashOut::<F>::from_owned_32bytes(rand_hash256.0);
            ensure_q256bithash_round_trips_hash_result(hash);

        }

    }

    #[test]
    fn test_qhashout_serde_str() {
        let h = QHashOut::<F>::from_values(1, 2, 3, 4);
        let s = serde_json::to_string(&h).unwrap();
        println!("Serialized: {}", s);
        let h2: QHashOut<F> = serde_json::from_str(&s).unwrap();
        assert_eq!(h, h2);
    }
    #[test]
    fn test_qhashout_byte_order(){
        let h = QHashOut::<F>::from_values(0x0102030405060708, 0x1112131415161718, 0x2122232425262728, 0x3132333435363738);
        let known_le_serialization: [u8; 32] = [
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
            0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
            0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21,
            0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31,
        ];
        let bytes = h.to_le_bytes();
        assert_eq!(bytes, known_le_serialization);
        let ffs_serialization = h.ffs_to_bytes();
        assert_eq!(ffs_serialization, known_le_serialization);

        let h_from_bytes = QHashOut::<F>::ffs_from_owned_bytes(ffs_serialization);
        assert_eq!(h, h_from_bytes);

        // TODO: Add bincode tests
        //assert_eq!(bincode_bytes, known_le_serialization);
        //let h2: QHashOut<F> = bincode::deserialize(&bincode_bytes).unwrap();
        //assert_eq!(h, h2);


    }
}
impl<F: RichField> ZeroableHash for QHashOut<F> {
    fn get_zero_value() -> Self {
        Self::ZERO
    }
}
impl<F: RichField> ToU64x4 for QHashOut<F> {
    fn to_u64x4(&self) -> [u64; 4] {
        [
            self.0.elements[0].to_canonical_u64(),
            self.0.elements[1].to_canonical_u64(),
            self.0.elements[2].to_canonical_u64(),
            self.0.elements[3].to_canonical_u64(),
        ]
    }

    fn into_u64x4_serialize_non_canonical(self) -> [u64; 4] {
        [
            self.0.elements[0].to_noncanonical_u64(),
            self.0.elements[1].to_noncanonical_u64(),
            self.0.elements[2].to_noncanonical_u64(),
            self.0.elements[3].to_noncanonical_u64(),
        ]

    }
}
impl<F: RichField> HashTo4Felts<F> for QHashOut<F> {
    fn to_4_felts(&self) -> [F; 4] {
        self.0.elements
    }
    
    fn from_4_felts(felts: [F; 4]) -> Self {
        QHashOut(HashOut { elements: felts })
    }
}
impl<F: RichField> FromU64x4 for QHashOut<F> {
    fn from_u64x4(data: [u64; 4]) -> Self {
        Self::from_values(data[0], data[1], data[2], data[3])
    }
}
