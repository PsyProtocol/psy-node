use postcard::fixint::le;
use psy_io::{PsyReaderExtensions, PsyWriterExtensions};
use psy_serialize::{impl_psy_canonical_serialize_for_speedy, AutoDatabaseSerializationUseFastFixedSerialize, AutoImplementFallbackPsySerializeCanonical, FallbackPsySerializeCanonical, PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata};
use speedy::Writable;

#[pderive::serialize_clone]
struct ExampleStruct {
    pub field_a: u32,
    pub field_b: Vec<u8>,
    pub field_c: [u8; 32],
}

impl_psy_canonical_serialize_for_speedy!(ExampleStruct);

impl PsyCanonicalSerializeMetadata for ExampleStruct {
    const IS_FIXED_SIZE: bool = false;
    const FIXED_SIZE: usize = 0;
}
impl FallbackPsySerializeCanonical for ExampleStruct {
    
    fn fallback_pio_serialized_size(&self) -> usize {
        4 + 32 + 4 + self.field_b.len()
    }
    
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
        writer.psy_write_u32(self.field_a)?;
        writer.psy_write_bytes_vec(&self.field_b)?;
        writer.psy_write_bytes_fixed(&self.field_c)?;
        Ok(())
    }
    
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        let field_a = reader.psy_read_u32()?;
        let field_b = reader.psy_read_bytes_vec()?;
        let field_c_bytes = reader.psy_read_bytes_fixed::<32>()?;
        Ok(
            ExampleStruct {
                field_a,
                field_b,
                field_c: field_c_bytes,
            }
        )


    }
}
//impl AutoImplementFallbackPsySerializeCanonical for ExampleStruct {}
fn run_test_speedy() -> anyhow::Result<()> {
    let example = ExampleStruct {
        field_a: 42,
        field_b: vec![1, 2, 3, 4, 5],
        field_c: [0u8; 32],
    };
    let speedy_bytes = example.write_to_vec().unwrap();
    let canonical_bytes = example.psy_ser_to_bytes_vec()?;

    let example_vec = vec![
        ExampleStruct {
            field_a: 1,
            field_b: vec![10, 20, 30],
            field_c: [1u8; 32],
        },
        ExampleStruct {
            field_a: 2,
            field_b: vec![40, 50, 60, 70],
            field_c: [2u8; 32],
        },
    ];
    let speedy_vec_bytes = example_vec.write_to_vec().unwrap();
    let canonical_vec_bytes = ExampleStruct::psy_ser_serialize_vec_of_self_ref(&example_vec, true);
    let back = ExampleStruct::psy_ser_deserialize_vec_of_self(&canonical_vec_bytes, true)?;
    assert_eq!(back.len(), example_vec.len());
    for (original, deserialized) in example_vec.iter().zip(back.iter()) {
        assert_eq!(original.field_a, deserialized.field_a);
        assert_eq!(original.field_b, deserialized.field_b);
        assert_eq!(original.field_c, deserialized.field_c);
    }
    println!("Speedy single bytes: {}", hex::encode(&speedy_bytes));
    println!("Canonical single bytes: {}", hex::encode(&canonical_bytes));
    println!("Speedy vec bytes: {}", hex::encode(&speedy_vec_bytes));
    println!("Canonical vec bytes: {}", hex::encode(&canonical_vec_bytes));


Ok(())}
fn main() {
    run_test_speedy().unwrap();

}