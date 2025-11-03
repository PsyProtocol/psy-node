
use crate::{data::hash::hash256::Hash256, utils::QPGenRandom};

use serde_with::{serde_as, hex::Hex};

#[serde_as]
#[pderive::serialize_copy_ts_export]
pub struct QEDCompressedSecp256K1Signature {
    #[serde_as(as = "Hex<serde_with::formats::Lowercase>")]
    #[ts(as = "String")]
    pub public_key: [u8; 33],
    
    #[serde_as(as = "Hex<serde_with::formats::Lowercase>")]
    #[ts(as = "String")]
    pub signature: [u8; 64],

    pub message: Hash256,
}
impl QPGenRandom for QEDCompressedSecp256K1Signature {
    fn qp_rand_gen() -> Self {
        QEDCompressedSecp256K1Signature {
            public_key: QPGenRandom::qp_rand_gen(),
            signature: QPGenRandom::qp_rand_gen(),
            message: Hash256::qp_rand_gen(),
        }
    }
}

#[cfg(test)]
mod test_ser {
    use crate::utils::QPGenRandom;

    #[test]
    fn test_round_trip(){
        let sig = super::QEDCompressedSecp256K1Signature::qp_rand_gen();
        let ser = serde_json::to_string(&sig).unwrap();
        let de: super::QEDCompressedSecp256K1Signature = serde_json::from_str(&ser).unwrap();
        assert_eq!(sig, de);
    }
}
struct ByteArrayVisitor;

impl<'de> serde::de::Visitor<'de> for ByteArrayVisitor {
    type Value = [u8; 33];

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("an array of 33 bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if v.len() == 33 {
            let mut arr = [0u8; 33];
            arr.copy_from_slice(v);
            Ok(arr)
        } else {
            Err(E::invalid_length(v.len(), &self))
        }
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut arr = [0u8; 33];
        for (i, place) in arr.iter_mut().enumerate() {
            *place = seq
                .next_element()?
                .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
        }
        Ok(arr)
    }
}



#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct CompressedPublicKey(pub [u8; 33]);

impl serde::Serialize for CompressedPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}


impl<'de> serde::Deserialize<'de> for CompressedPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(CompressedPublicKey(
            deserializer.deserialize_bytes(ByteArrayVisitor)?,
        ))
    }
}


impl CompressedPublicKey {
    pub fn new_from_slice(slice: &[u8]) -> Self {
        let mut arr = [0u8; 33];
        arr.copy_from_slice(slice);
        CompressedPublicKey(arr)
    }
}


