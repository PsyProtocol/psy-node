use parth_core::utils::QPGenRandom;
use psy_serialize::{AutoDatabaseSerializationUseFastFixedSerialize, FastFixedSerializable, PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalSerializeMetadata};

pub struct Test123 {
    pub a: u32,
    pub b: u64,
    pub c: [u8; 16],
}
impl QPGenRandom for Test123 {
    
    fn qp_rand_gen() -> Self where Self: Sized {
        Test123 {
            a: QPGenRandom::qp_rand_gen(),
            b: QPGenRandom::qp_rand_gen(),
            c: QPGenRandom::qp_rand_gen(),
        }

    }
}
impl FastFixedSerializable<28> for Test123 {
    fn ffs_to_bytes(&self) -> [u8; 28] {
        let mut bytes = [0u8; 28];
        bytes[0..4].copy_from_slice(&self.a.to_le_bytes());
        bytes[4..12].copy_from_slice(&self.b.to_le_bytes());
        bytes[12..28].copy_from_slice(&self.c);
        bytes
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 28 {
            anyhow::bail!("Invalid data length for Test123: expected 28, got {}", data.len());
        }
        let a = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let b = u64::from_le_bytes(data[4..12].try_into().unwrap());
        let mut c = [0u8; 16];
        c.copy_from_slice(&data[12..28]);
        Ok(Test123 { a, b, c })
    }

    fn ffs_from_owned_bytes(bytes: [u8; 28]) -> Self {
        let a = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let b = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
        let mut c = [0u8; 16];
        c.copy_from_slice(&bytes[12..28]);
        Test123 { a, b, c }
    }

    fn ffs_into_bytes(self) -> [u8; 28] {
        self.ffs_to_bytes()
    }
    
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self::ffs_try_from_slice(data).expect("Failed to deserialize Test123 from slice")
    }
}


impl PsyCanonicalSerializeMetadata for Test123 {
    const IS_FIXED_SIZE: bool = true;
    const FIXED_SIZE: usize = 28;

}
impl AutoDatabaseSerializationUseFastFixedSerialize<28> for Test123 {}
psy_serialize::impl_psy_canonical_serialize_for_fixed_type!(Test123, 28);

fn run_demo() -> anyhow::Result<()> {
    let t = Test123::qp_rand_gen_vec(1337);
    let serialized = Test123::psy_ser_serialize_vec_of_self_ref(&t, false);
    let deserialized = Test123::psy_ser_deserialize_vec_of_self(&serialized, false)?;
    assert_eq!(t.len(), deserialized.len());
    for (original, deser) in t.iter().zip(deserialized.iter()) {
        assert_eq!(original.a, deser.a);
        assert_eq!(original.b, deser.b);
        assert_eq!(original.c, deser.c);
    }
    Ok(())
}


fn main() {
    run_demo().unwrap();
}