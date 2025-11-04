use parth_core::{QJobIdBase, QJobIdSerialized};

pub const TEMP_TABLE_ID_WORKER_PROOF_METADATA: u16 = 0x5045; // 'EP'
pub const TEMP_TABLE_ID_WORKER_PROOF_METADATA_BYTES: [u8; 2] = [0x45, 0x50]; // 'EP'
pub const TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE: usize = 40; // 4 + 2 + 2 + 8 + 24
//pub const TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE: usize = 32; // Q256BitHash

pub const TEMP_TABLE_ID_UNIQUE_PENDING_ID: u16 = 0x4950; // 'PI'
pub const TEMP_TABLE_ID_UNIQUE_PENDING_ID_BYTES: [u8; 2] = [0x50, 0x49]; // 'PI'
pub const TEMP_TABLE_UNIQUE_PENDING_ID_KEY_SIZE: usize = 8; // 4 + 2 + 2
pub const TEMP_TABLE_UNIQUE_PENDING_ID_VALUE_SIZE: usize = 24; // u64 + u128

pub const TEMP_TABLE_ID_PROOF_WITNESS_DATA: u16 = 0x5750; // 'PW'
pub const TEMP_TABLE_ID_PROOF_WITNESS_DATA_BYTES: [u8; 2] = [0x50, 0x57]; // 'PW'
pub const TEMP_TABLE_PROOF_WITNESS_DATA_KEY_SIZE: usize = 40; // 4 + 2 + 2 + 8 + 24

pub const TEMP_TABLE_ID_SUBMIT_STATUS: u16 = 0x5353; // 'SS'
pub const TEMP_TABLE_ID_SUBMIT_STATUS_BYTES: [u8; 2] = [0x53, 0x53]; // 'SS'
pub const TEMP_TABLE_SUBMIT_STATUS_KEY_SIZE: usize = 24; // 4 + 2 + 2 + 8 + 8
pub const TEMP_TABLE_SUBMIT_STAUTS_VALUE_SIZE: usize = 8; // u64

pub const TEMP_TABLE_ID_USER_CONTRACT_TREE_UPDATES: u16 = 0x5543; // 'CU'
pub const TEMP_TABLE_ID_USER_CONTRACT_TREE_UPDATES_BYTES: [u8; 2] = [0x43, 0x55]; // 'CU'
pub const TEMP_TABLE_USER_CONTRACT_TREE_UPDATES_KEY_SIZE: usize = 24; // 4 + 2 + 2 + 8 + 8

pub const TEMP_TABLE_ID_TAG_TREE_VALUES: u16 = 0x5654; // 'TV'
pub const TEMP_TABLE_ID_TAG_TREE_VALUES_BYTES: [u8; 2] = [0x54, 0x56]; // 'TV'
pub const TEMP_TABLE_TAG_TREE_VALUES_KEY_SIZE: usize = 40; // 4 + 2 + 2 + 8 + 24
pub const TEMP_TABLE_TAG_TREE_VALUES_VALUE_SIZE: usize = 32; // Q256BitHash

pub const TEMP_TABLE_ID_DEPLOY_CONTRACT_CODE_DEFINITION: u16 = 0x4344; // 'DC'
pub const TEMP_TABLE_ID_DEPLOY_CONTRACT_CODE_DEFINITION_BYTES: [u8; 2] = [0x44, 0x43]; // 'DC'
pub const TEMP_TABLE_ID_DEPLOY_CONTRACT_KEY_SIZE: usize = 32; // 4 + 2 + 2 + 8 + 16


// --- Expected Public Inputs ---

// (realm_id = 4) + (realm_sub_id = 2) + (table id length = 2) + (unique_pending_id = 8) + (QJOB_ID_SERIALIZED_SIZE = 24) = 40
#[inline(always)]
pub fn tt_get_proving_job_metadata_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id_bytes: &QJobIdSerialized,
) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_WORKER_PROOF_METADATA_BYTES);
    key[8..16].copy_from_slice(&unique_pending_id.to_le_bytes());
    key[16..40].copy_from_slice(job_id_bytes);
    key
}

#[inline(always)]
pub fn tt_write_proving_job_metadata_key<Writer: psy_io::Write>(
    writer: &mut Writer,
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id_bytes: &QJobIdSerialized,
) -> anyhow::Result<()> {
    writer.write_all(&realm_id.to_le_bytes())?;
    writer.write_all(&realm_sub_id.to_le_bytes())?;
    writer.write_all(&TEMP_TABLE_ID_WORKER_PROOF_METADATA_BYTES)?;
    writer.write_all(&unique_pending_id.to_le_bytes())?;
    writer.write_all(job_id_bytes)?;
    Ok(())
}

#[inline(always)]
pub fn tt_get_proving_job_metadata_key_from_job<JobId: QJobIdBase>(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id: &JobId,
) -> [u8; 40] {
    tt_get_proving_job_metadata_key(realm_id, realm_sub_id, unique_pending_id, &job_id.to_bytes_fixed())
}

// --- Unique Pending ID ---

// (realm_id = 4) + (realm_sub_id = 2) + (table id length = 2) = 8
#[inline(always)]
pub fn tt_get_unique_pending_id_key(realm_id: u32, realm_sub_id: u16) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_UNIQUE_PENDING_ID_BYTES);
    key
}

#[inline(always)]
pub fn tt_write_unique_pending_id_key<Writer: psy_io::Write>(
    writer: &mut Writer,
    realm_id: u32,
    realm_sub_id: u16,
) -> anyhow::Result<()> {
    writer.write_all(&realm_id.to_le_bytes())?;
    writer.write_all(&realm_sub_id.to_le_bytes())?;
    writer.write_all(&TEMP_TABLE_ID_UNIQUE_PENDING_ID_BYTES)?;
    Ok(())
}

// --- Proof Witness Data ---

// (realm_id = 4) + (realm_sub_id = 2) + (table id length = 2) + (unique_pending_id = 8) + (QJOB_ID_SERIALIZED_SIZE = 24) = 40
#[inline(always)]
pub fn tt_get_proof_witness_data_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id_bytes: &QJobIdSerialized,
) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_PROOF_WITNESS_DATA_BYTES);
    key[8..16].copy_from_slice(&unique_pending_id.to_le_bytes());
    key[16..40].copy_from_slice(job_id_bytes);
    key
}

#[inline(always)]
pub fn tt_write_proof_witness_data_key<Writer: psy_io::Write>(
    writer: &mut Writer,
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id_bytes: &QJobIdSerialized,
) -> anyhow::Result<()> {
    writer.write_all(&realm_id.to_le_bytes())?;
    writer.write_all(&realm_sub_id.to_le_bytes())?;
    writer.write_all(&TEMP_TABLE_ID_PROOF_WITNESS_DATA_BYTES)?;
    writer.write_all(&unique_pending_id.to_le_bytes())?;
    writer.write_all(job_id_bytes)?;
    Ok(())
}

#[inline(always)]
pub fn tt_get_proof_witness_data_key_from_job<JobId: QJobIdBase>(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id: &JobId,
) -> [u8; 40] {
    tt_get_proof_witness_data_key(realm_id, realm_sub_id, unique_pending_id, &job_id.to_bytes_fixed())
}

// --- Submit Status ---

// (realm_id = 4) + (realm_sub_id = 2) + (table id length = 2) + (unique_pending_id = 8) + (user_or_realm_id = 8) = 24
#[inline(always)]
pub fn tt_get_submit_status_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    user_or_realm_id: u64,
) -> [u8; 24] {
    let mut key = [0u8; 24];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    // CORRECTED: This now uses the correct table ID constant
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_SUBMIT_STATUS_BYTES);
    key[8..16].copy_from_slice(&unique_pending_id.to_le_bytes());
    key[16..24].copy_from_slice(&user_or_realm_id.to_le_bytes());
    key
}

#[inline(always)]
pub fn tt_write_submit_status_key<Writer: psy_io::Write>(
    writer: &mut Writer,
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    user_or_realm_id: u64,
) -> anyhow::Result<()> {
    writer.write_all(&realm_id.to_le_bytes())?;
    writer.write_all(&realm_sub_id.to_le_bytes())?;
    writer.write_all(&TEMP_TABLE_ID_SUBMIT_STATUS_BYTES)?;
    writer.write_all(&unique_pending_id.to_le_bytes())?;
    writer.write_all(&user_or_realm_id.to_le_bytes())?;
    Ok(())
}

// --- User Contract Tree Updates ---

// (realm_id = 4) + (realm_sub_id = 2) + (table id length = 2) + (unique_pending_id = 8) + (user_id = 8) = 24
#[inline(always)]
pub fn tt_get_contract_updates_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    user_id: u64,
) -> [u8; 24] {
    let mut key = [0u8; 24];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_USER_CONTRACT_TREE_UPDATES_BYTES);
    key[8..16].copy_from_slice(&unique_pending_id.to_le_bytes());
    key[16..24].copy_from_slice(&user_id.to_le_bytes());
    key
}

#[inline(always)]
pub fn tt_write_contract_updates_key<Writer: psy_io::Write>(
    writer: &mut Writer,
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    user_id: u64,
) -> anyhow::Result<()> {
    writer.write_all(&realm_id.to_le_bytes())?;
    writer.write_all(&realm_sub_id.to_le_bytes())?;
    writer.write_all(&TEMP_TABLE_ID_USER_CONTRACT_TREE_UPDATES_BYTES)?;
    writer.write_all(&unique_pending_id.to_le_bytes())?;
    writer.write_all(&user_id.to_le_bytes())?;
    Ok(())
}

// --- Tag Tree Values ---

// (realm_id = 4) + (realm_sub_id = 2) + (table id length = 2) + (unique_pending_id = 8) + (QJOB_ID_SERIALIZED_SIZE = 24) = 40
#[inline(always)]
pub fn tt_get_rewards_tag_tree_value_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id_bytes: &QJobIdSerialized,
) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_TAG_TREE_VALUES_BYTES);
    key[8..16].copy_from_slice(&unique_pending_id.to_le_bytes());
    key[16..40].copy_from_slice(job_id_bytes);
    key
}

#[inline(always)]
pub fn tt_write_rewards_tag_tree_value_key<Writer: psy_io::Write>(
    writer: &mut Writer,
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id_bytes: &QJobIdSerialized,
) -> anyhow::Result<()> {
    writer.write_all(&realm_id.to_le_bytes())?;
    writer.write_all(&realm_sub_id.to_le_bytes())?;
    writer.write_all(&TEMP_TABLE_ID_TAG_TREE_VALUES_BYTES)?;
    writer.write_all(&unique_pending_id.to_le_bytes())?;
    writer.write_all(job_id_bytes)?;
    Ok(())
}

#[inline(always)]
pub fn tt_get_rewards_tag_tree_value_key_from_job<JobId: QJobIdBase>(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id: &JobId,
) -> [u8; 40] {
    tt_get_rewards_tag_tree_value_key(realm_id, realm_sub_id, unique_pending_id, &job_id.to_bytes_fixed())
}





// --- User Contract Tree Updates ---

// (realm_id = 4) + (realm_sub_id = 2) + (table id length = 2) + (unique_pending_id = 8) + (rand_key = 16) = 32
#[inline(always)]
pub fn tt_get_deploy_contract_code_definition_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    rand_key: &[u8; 16],
) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_DEPLOY_CONTRACT_CODE_DEFINITION_BYTES);
    key[8..16].copy_from_slice(&unique_pending_id.to_le_bytes());
    key[16..32].copy_from_slice(rand_key);
    key
}

#[inline(always)]
pub fn tt_write_contract_code_definition_key<Writer: psy_io::Write>(
    writer: &mut Writer,
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    rand_key: &[u8; 16],
) -> anyhow::Result<()> {
    writer.write_all(&realm_id.to_le_bytes())?;
    writer.write_all(&realm_sub_id.to_le_bytes())?;
    writer.write_all(&TEMP_TABLE_ID_USER_CONTRACT_TREE_UPDATES_BYTES)?;
    writer.write_all(&unique_pending_id.to_le_bytes())?;
    writer.write_all(rand_key)?;
    Ok(())
}