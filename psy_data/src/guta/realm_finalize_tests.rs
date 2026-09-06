use super::realm_finalize::RealmFinalizeGUTAInput;
use parth_core::{PHash, PF, utils::QPGenRandom};
use psy_serialize::FallbackPsySerializeCanonical;

struct UnbufferedInput<'a>(&'a [u8]);

impl psy_io::Read for UnbufferedInput<'_> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        let length = output.len().min(1);
        self.0.read(&mut output[..length])
    }
}

#[test]
fn non_speedy_fallback_round_trip_and_size() -> anyhow::Result<()> {
    let input = RealmFinalizeGUTAInput::<PF, PHash>::qp_rand_gen();
    let mut bytes = Vec::new();
    input.fallback_pio_write_to_io(&mut bytes)?;
    assert_eq!(bytes.len(), input.fallback_pio_serialized_size());
    // Prevent nested Speedy readers from buffering subsequent witness fields.
    let mut reader = UnbufferedInput(bytes.as_slice());
    let decoded = RealmFinalizeGUTAInput::<PF, PHash>::fallback_pio_read_from_io(&mut reader)?;
    assert_eq!(decoded, input);
    assert!(reader.0.is_empty());
    Ok(())
}
