use crate::data::serializable::{QPDSerializable, QPDSerializableFixed};

#[pderive::serialize_copy_default]
pub struct QRealmIdentifier {
    pub realm_id: u32,
    pub realm_sub_id: u16,
}

impl QPDSerializable for QRealmIdentifier {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(6);
        bytes.extend(&self.realm_id.to_le_bytes());
        bytes.extend(&self.realm_sub_id.to_le_bytes());
        Ok(bytes)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 6 {
            return Err(anyhow::anyhow!("Invalid byte length"));
        }
        let realm_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let realm_sub_id = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        Ok(QRealmIdentifier { realm_id, realm_sub_id })
    }
}
impl QPDSerializableFixed for QRealmIdentifier {
    fn get_fixed_size() -> usize {
        6
    }
}

