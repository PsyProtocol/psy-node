use plonky2::plonk::config::{GenericConfig, Hasher};

use crate::data::maybe_serialization::MaybeSpeedy;

pub trait QGenericConfig<const D: usize>:
    GenericConfig<
    D,
    F: MaybeSpeedy,
    FE: MaybeSpeedy,
    Hasher: Hasher<Self::F, Hash: MaybeSpeedy>,
>
{
}
impl<T, const D: usize> QGenericConfig<D> for T
where
    T: GenericConfig<
        D,
        F: MaybeSpeedy,
        FE: MaybeSpeedy,
        Hasher: Hasher<Self::F, Hash: MaybeSpeedy>,
    >,
{
}