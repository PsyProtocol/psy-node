// this trait ensures that our serialization matches exactly what we expect for tests
pub trait PsyCanonicalSerializationExamples: Sized {
    fn psy_ser_canoical_known_round_trip_serializations() -> Vec<(Self, Vec<u8>)>;
}

