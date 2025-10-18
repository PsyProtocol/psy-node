use crate::{PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate, PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate, PsyCanonicalDatabaseSerializeFixedBase, PsyIOReadWrite, PsyIOReadWriteFixedTemplate};

pub trait PsySerializeCanonical: PsyCanonicalDatabaseSerializeBaseMulti + PsyCanonicalDatabaseSerializeBaseSingle + PsyIOReadWrite {
}

pub trait PsySerializeCanonicalFixedOnly<const SIZE: usize>: PsyCanonicalDatabaseSerializeBaseMultiFixedTemplate<SIZE> + PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<SIZE> + PsyIOReadWriteFixedTemplate<SIZE> + PsyCanonicalDatabaseSerializeFixedBase<SIZE> {
}


pub trait PsySerializeCanonicalFixed<const SIZE: usize>: PsySerializeCanonical + PsySerializeCanonicalFixedOnly<SIZE> {
}
