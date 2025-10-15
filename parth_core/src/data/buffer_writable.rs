pub const QFAST_FIXED_SERIALIZABLE_BLOB_V1_MAGIC: u32 = 0x51424631; // "QBF1" in ASCII


pub trait QBufferTyped {
    fn get_qbuffer_type() -> u16;
}

pub trait QBufferWritable: QBufferTyped + Sized {
    fn get_size_in_qbuffer(&self) -> usize;
    fn is_fixed_size() -> bool;
    fn read_from_qbuffer(buffer: &[u8]) -> anyhow::Result<(Self, usize)>;
    fn write_to_qbuffer(&self, buffer: &mut Vec<u8>) -> anyhow::Result<usize>;
}



pub struct QBufferWriter(pub Vec<u8>);
impl QBufferWriter {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
    pub fn write<T: QBufferWritable>(&mut self, value: &T) -> anyhow::Result<usize> {
        value.write_to_qbuffer(&mut self.0)
    }
}
