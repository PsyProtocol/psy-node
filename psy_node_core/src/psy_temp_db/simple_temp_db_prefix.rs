use parth_core::node::realm_identifier::QRealmIdentifier;


#[pderive::serialize_copy_default_bm]
#[repr(C)]
pub struct SimpleTempDBTablePrefix {
    pub realm_id: u32,
    pub realm_sub_id: u16,
    pub table_identifier: u16,
    pub unique_pending_id: u64,
}

impl SimpleTempDBTablePrefix {
    #[inline]
    pub fn with_slice_suffix(&self, suffix: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16 + suffix.len());
        bytes.extend_from_slice(&self.realm_id.to_le_bytes());
        bytes.extend_from_slice(&self.realm_sub_id.to_le_bytes());
        bytes.extend_from_slice(&self.table_identifier.to_le_bytes());
        bytes.extend_from_slice(&self.unique_pending_id.to_le_bytes());
        bytes.extend_from_slice(suffix);
        bytes
    }

    #[inline]
    pub fn with_32_byte_suffix(&self, suffix: &[u8; 32]) -> [u8; 48] {
        let mut bytes = [0u8; 48];
        bytes[0..4].copy_from_slice(&self.realm_id.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.realm_sub_id.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.table_identifier.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.unique_pending_id.to_le_bytes());
        bytes[16..48].copy_from_slice(suffix);
        bytes
    }
}

#[inline]
pub fn get_temp_db_full_key(rid: &QRealmIdentifier, table_identifier: u16, unique_pending_id: u64, suffix: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(16 + suffix.len());
    data.extend_from_slice(&rid.realm_id.to_le_bytes());
    data.extend_from_slice(&rid.realm_sub_id.to_le_bytes());
    data.extend_from_slice(&table_identifier.to_le_bytes());
    data.extend_from_slice(&unique_pending_id.to_le_bytes());
    data.extend_from_slice(suffix);
    data
}


