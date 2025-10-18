use crate::{PsyIOReadWrite, PsyIOReadWriteFixedTemplate};


pub trait PsyCanonicalDatabaseSerializeBaseSingle: PsyIOReadWrite {
    fn psydbser_from_slice(data: &[u8]) -> anyhow::Result<Self>;
    fn psydbser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>>;
    #[inline]
    fn psydbser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
        self.psydbser_to_bytes_vec()
    }
    #[inline]
    fn psydbser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
        Self::psydbser_from_slice(&data)
    }
}


pub trait PsyCanonicalDatabaseSerializeBaseSingleFixedTemplate<const N: usize>: PsyIOReadWriteFixedTemplate<N> {
    fn fx_tpl_psydbser_from_slice(data: &[u8]) -> anyhow::Result<Self>;
    fn fx_tpl_psydbser_to_bytes_vec(&self) -> anyhow::Result<Vec<u8>>;
    #[inline]
    fn fx_tpl_psydbser_into_bytes_vec(self) -> anyhow::Result<Vec<u8>> {
        self.fx_tpl_psydbser_to_bytes_vec()
    }
    #[inline]
    fn fx_tpl_psydbser_from_owned_bytes_vec(data: Vec<u8>) -> anyhow::Result<Self> {
        Self::fx_tpl_psydbser_from_slice(&data)
    }
}



