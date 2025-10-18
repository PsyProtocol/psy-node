use crate::{PsyIOReadWrite, PsyIOReadWriteFixedTemplate};


pub trait PsyCanonicalDatabaseSerializeBaseSingle: PsyIOReadWrite {
    fn psy_ser_from_slice(data: &[u8]) -> anyhow::Result<Self>;
    fn psy_ser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>>;
    #[inline]
    fn psy_ser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
        self.psy_ser_to_bytes_vec()
    }
    #[inline]
    fn psy_ser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
        Self::psy_ser_from_slice(&data)
    }
}


pub trait PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<const N: usize>: PsyIOReadWriteFixedTemplate<N> {
    fn fx_tpl_psy_ser_from_slice(data: &[u8]) -> anyhow::Result<Self>;
    fn fx_tpl_psy_ser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>>;
    #[inline]
    fn fx_tpl_psy_ser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
        self.fx_tpl_psy_ser_to_bytes_vec()
    }
    #[inline]
    fn fx_tpl_psy_ser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
        Self::fx_tpl_psy_ser_from_slice(&data)
    }
}