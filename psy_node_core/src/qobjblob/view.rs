pub const QFAST_FIXED_SERIALIZABLE_BLOB_V1_MAGIC: u32 = 0x51424631; // "QBF1" in ASCII


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QObjectBlobStore(pub Vec<u8>);



impl TryFrom<Vec<u8>> for QObjectBlobStore {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        QObjectBlobStore::from_owned_bytes(value)
    }
}
impl From<QObjectBlobStore> for Vec<u8> {
    fn from(value: QObjectBlobStore) -> Self {
        value.0
    }
}

impl QObjectBlobStore {
    pub fn new_with_capacity(capacity: usize) -> Self {
        let mut data = Vec::with_capacity(capacity + 4);
        data.extend_from_slice(&QFAST_FIXED_SERIALIZABLE_BLOB_V1_MAGIC.to_le_bytes());
        Self(data)
    }

    pub fn is_ffs_blob(data: &[u8]) -> bool {
        data.len() >= 4 && u32::from_le_bytes(data[0..4].try_into().unwrap()) == QFAST_FIXED_SERIALIZABLE_BLOB_V1_MAGIC
    }

    pub fn from_owned_bytes(data: Vec<u8>) -> anyhow::Result<Self> {
        if data.len() < 4 {
            anyhow::bail!("Data too short to be a valid QFastFixedSerializableBlobV1");
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != QFAST_FIXED_SERIALIZABLE_BLOB_V1_MAGIC {
            anyhow::bail!("Invalid magic number for QFastFixedSerializableBlobV1");
        }
        Ok(Self(data))
    }
    pub fn to_bytes_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 4 {
            anyhow::bail!("Data too short to be a valid QFastFixedSerializableBlobV1");
        }
        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != QFAST_FIXED_SERIALIZABLE_BLOB_V1_MAGIC {
            anyhow::bail!("Invalid magic number for QFastFixedSerializableBlobV1");
        }
        Ok(Self(data.to_vec()))
    }


}