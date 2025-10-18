use crate::{PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate, PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate, PsyCanonicalDatabaseSerializeFixedBase, PsyCanonicalSerializeMetadata, PsyIOReadWrite, PsyIOReadWriteFixedTemplate};

pub trait PsySerializeCanonical: PsyCanonicalDatabaseSerializeBaseMulti + PsyCanonicalDatabaseSerializeBaseSingle + PsyIOReadWrite {
}

impl<T: PsyCanonicalDatabaseSerializeBaseMulti + PsyCanonicalDatabaseSerializeBaseSingle + PsyIOReadWrite> PsySerializeCanonical for T {
}
pub trait PsySerializeCanonicalFixedOnly<const SIZE: usize>: PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<SIZE> + PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<SIZE> + PsyIOReadWriteFixedTemplate<SIZE> + PsyCanonicalDatabaseSerializeFixedBase<SIZE> {
}
impl<const SIZE: usize, T: PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<SIZE> + PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<SIZE> + PsyIOReadWriteFixedTemplate<SIZE> + PsyCanonicalDatabaseSerializeFixedBase<SIZE>> PsySerializeCanonicalFixedOnly<SIZE> for T {
}

pub trait PsySerializeCanonicalFixed<const SIZE: usize>: PsySerializeCanonical + PsySerializeCanonicalFixedOnly<SIZE> {
}
impl<const SIZE: usize, T: PsySerializeCanonical + PsySerializeCanonicalFixedOnly<SIZE>> PsySerializeCanonicalFixed<SIZE> for T {
}

// Fallback trait incase the serializer of choice is not implemented
// It MUST produce the same output as PsySerializeCanonical
pub trait FallbackPsySerializeCanonical: PsyCanonicalSerializeMetadata + Sized {
    fn fallback_psy_ser_serialized_size(&self) -> usize;
    fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()>;
    fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self>;
}

pub trait AutoImplementFallbackPsySerializeCanonical: FallbackPsySerializeCanonical {}

impl<T: AutoImplementFallbackPsySerializeCanonical> PsyIOReadWrite for T {
    #[inline(always)]
    fn pio_serialized_size(&self) -> usize {
        self.fallback_psy_ser_serialized_size()
    }

    #[inline(always)]
    fn pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
       self.fallback_pio_write_to_io(writer)
    }

    #[inline(always)]
    fn pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
        Self::fallback_pio_read_from_io(reader)
    }
}

impl<T: AutoImplementFallbackPsySerializeCanonical> PsyCanonicalDatabaseSerializeBaseSingle for T {
    fn psy_ser_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        Self::fallback_pio_read_from_io(&mut &data[..])
    }

    fn psy_ser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>> {
        let mut data = Vec::<u8>::with_capacity(self.pio_serialized_size());
        self.pio_write_to_io(&mut data)?;
        Ok(data)
    }
}
impl<T: AutoImplementFallbackPsySerializeCanonical> PsyCanonicalDatabaseSerializeBaseMulti for T {}


#[cfg(test)]
mod tests {
    use psy_io::p_varuint_size;

    use crate::{AutoImplementFallbackPsySerializeCanonical, FallbackPsySerializeCanonical, PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalSerializeMetadata};

    struct ExampleFallbackStruct {
        pub a: Vec<u8>,
        pub b: u32, 
    }
    impl PsyCanonicalSerializeMetadata for ExampleFallbackStruct {
        const IS_FIXED_SIZE: bool = false;
        const FIXED_SIZE: usize = 0;
    }
    impl FallbackPsySerializeCanonical for ExampleFallbackStruct {
        
        fn fallback_psy_ser_serialized_size(&self) -> usize {
            4 + self.a.len() + 4
        }
        
        fn fallback_pio_write_to_io<W: psy_io::Write>(&self, writer: &mut W) -> anyhow::Result<()> {
            psy_io::p_write_inner_vec_size(self.a.len(), writer)?;
            writer.write_all(&self.a)?;
            writer.write_all(&self.b.to_le_bytes())?;
            Ok(())
        }
        
        fn fallback_pio_read_from_io<R: psy_io::Read>(reader: &mut R) -> anyhow::Result<Self> {
            let mut data = [0u8; 4];
            reader.read_exact(&mut data)?;
            let a_len = u32::from_le_bytes(data) as usize;
            let mut a = vec![0u8; a_len];
            reader.read_exact(&mut a)?;
            let mut b_data = [0u8; 4];
            reader.read_exact(&mut b_data)?;
            let b = u32::from_le_bytes(b_data);
            Ok(ExampleFallbackStruct { a, b })
        }
    }
    impl AutoImplementFallbackPsySerializeCanonical for ExampleFallbackStruct {}
    
    #[test]
    fn test_fallback_serialization() {
        let example = ExampleFallbackStruct {
            a: vec![1, 2, 3, 4, 5],
            b: 42,
        };
        let serialized = example.fallback_psy_ser_to_bytes_vec().unwrap();
        let deserialized = ExampleFallbackStruct::fallback_psy_ser_from_slice(&serialized).unwrap();
        assert_eq!(example.a, deserialized.a);
        assert_eq!(example.b, deserialized.b);

        let vec_ex = vec![
            ExampleFallbackStruct { a: vec![1u8;1024], b: 10 },
            ExampleFallbackStruct { a: vec![4, 5, 6, 7], b: 20 },
            ExampleFallbackStruct { a: vec![4, 5, 6, 7], b: 20 },
            ExampleFallbackStruct { a: vec![4, 5, 6, 7], b: 20 },
        ];
        let serialized_vec = ExampleFallbackStruct::psy_ser_serialize_vec_of_self_ref(&vec_ex, false);
        let deserialized_vec = ExampleFallbackStruct::psy_ser_deserialize_vec_of_self(&serialized_vec, false).unwrap();
        assert_eq!(vec_ex.len(), deserialized_vec.len());
        for (original, deserialized) in vec_ex.iter().zip(deserialized_vec.iter()) {
            assert_eq!(original.a, deserialized.a);
            assert_eq!(original.b, deserialized.b);
        }
    }
    
    
}