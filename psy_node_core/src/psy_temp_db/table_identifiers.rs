use parth_core::{
    node::realm_identifier::QRealmIdentifier, protocol::core_types::Q256BitHash,
    QJobIdBase, QJobIdSerialized, QJOB_ID_SERIALIZED_SIZE,
};
use psy_data::protocol::chain_context::{
    AuthorityScope, PendingContext, PENDING_CONTEXT_V1_LEN,
};

pub const TEMP_TABLE_ID_WORKER_PROOF_METADATA: u16 = 0x5045; // 'EP'
pub const TEMP_TABLE_ID_WORKER_PROOF_METADATA_BYTES: [u8; 2] = [0x45, 0x50]; // 'EP'
pub const TEMP_TABLE_WORKER_PROOF_METADATA_KEY_SIZE: usize = 40; // 4 + 2 + 2 + 8 + 24
//pub const TEMP_TABLE_EXPECTED_PUBLIC_INPUTS_VALUE_SIZE: usize = 32; // Q256BitHash

pub const TEMP_TABLE_ID_UNIQUE_PENDING_ID: u16 = 0x4950; // 'PI'
pub const TEMP_TABLE_ID_UNIQUE_PENDING_ID_BYTES: [u8; 2] = [0x50, 0x49]; // 'PI'
pub const TEMP_TABLE_UNIQUE_PENDING_ID_KEY_SIZE: usize = 8; // 4 + 2 + 2
pub const TEMP_TABLE_UNIQUE_PENDING_ID_VALUE_SIZE: usize = 24; // u64 + u128


pub const TEMP_TABLE_ID_GATHERING_UNIQUE_PENDING_ID: u16 = 0x5047; // 'GP'
pub const TEMP_TABLE_ID_GATHERING_UNIQUE_PENDING_ID_BYTES: [u8; 2] = [0x47, 0x50]; // 'GP'
pub const TEMP_TABLE_GATHERING_UNIQUE_PENDING_ID_KEY_SIZE: usize = 8; // 4 + 2 + 2
pub const TEMP_TABLE_GATHERING_UNIQUE_PENDING_ID_VALUE_SIZE: usize = 24; // u64 + u128

/// Exact branch + authority + pending/proc tuple. The value is the fixed
/// `PendingContext` V1 canonical encoding.
pub const TEMP_TABLE_ID_CURRENT_PENDING_CONTEXT: u16 = 0x4350; // 'PC'
pub const TEMP_TABLE_ID_CURRENT_PENDING_CONTEXT_BYTES: [u8; 2] = [0x50, 0x43]; // 'PC'
pub const TEMP_TABLE_CURRENT_PENDING_CONTEXT_KEY_SIZE: usize = 8; // 4 + 2 + 2

/// Domain marker for branch-exact proof-work records in the temporary store.
///
/// V1 keys ended after `rid || table_id || pending_id || job_id`. V2 keeps the
/// stable rid/table prefix, adds this marker, then embeds the complete canonical
/// PendingContext before the job ID. Exact raw-KV lookup means V1 and V2 can
/// coexist during a full-stop rollout without any read fallback.
pub const TEMP_PROOF_WORK_CONTEXT_KEY_V2_MAGIC: [u8; 4] = *b"CTX2";
pub const TEMP_PROOF_WORK_CONTEXT_KEY_V2_SIZE: usize =
    4 + 2 + 2 + TEMP_PROOF_WORK_CONTEXT_KEY_V2_MAGIC.len()
        + PENDING_CONTEXT_V1_LEN
        + QJOB_ID_SERIALIZED_SIZE;

#[inline(always)]
pub fn tt_get_current_pending_context_key(
    realm_id: u32,
    realm_sub_id: u16,
) -> [u8; TEMP_TABLE_CURRENT_PENDING_CONTEXT_KEY_SIZE] {
    let mut key = [0u8; TEMP_TABLE_CURRENT_PENDING_CONTEXT_KEY_SIZE];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_CURRENT_PENDING_CONTEXT_BYTES);
    key
}

fn tt_get_context_job_key_v2<Hash: Q256BitHash, JobId: QJobIdBase>(
    rid: &QRealmIdentifier,
    table_id: [u8; 2],
    context: &PendingContext<Hash>,
    job_id: &JobId,
) -> anyhow::Result<[u8; TEMP_PROOF_WORK_CONTEXT_KEY_V2_SIZE]> {
    if !job_id.is_valid() {
        anyhow::bail!("V2 temp proof-work key contains an invalid job ID");
    }
    if let AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = context.authority()
    {
        if realm_id != rid.realm_id || realm_sub_id != rid.realm_sub_id {
            anyhow::bail!("V2 temp proof-work context authority does not match realm identifier");
        }
    }

    let mut key = [0u8; TEMP_PROOF_WORK_CONTEXT_KEY_V2_SIZE];
    key[0..4].copy_from_slice(&rid.realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&rid.realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&table_id);
    key[8..12].copy_from_slice(&TEMP_PROOF_WORK_CONTEXT_KEY_V2_MAGIC);
    key[12..(12 + PENDING_CONTEXT_V1_LEN)].copy_from_slice(&context.to_canonical_bytes());
    key[(12 + PENDING_CONTEXT_V1_LEN)..].copy_from_slice(&job_id.to_bytes_fixed());
    Ok(key)
}

pub fn tt_get_proving_job_metadata_key_v2<Hash: Q256BitHash, JobId: QJobIdBase>(
    rid: &QRealmIdentifier,
    context: &PendingContext<Hash>,
    job_id: &JobId,
) -> anyhow::Result<[u8; TEMP_PROOF_WORK_CONTEXT_KEY_V2_SIZE]> {
    tt_get_context_job_key_v2(
        rid,
        TEMP_TABLE_ID_WORKER_PROOF_METADATA_BYTES,
        context,
        job_id,
    )
}

pub fn tt_get_proof_witness_data_key_v2<Hash: Q256BitHash, JobId: QJobIdBase>(
    rid: &QRealmIdentifier,
    context: &PendingContext<Hash>,
    job_id: &JobId,
) -> anyhow::Result<[u8; TEMP_PROOF_WORK_CONTEXT_KEY_V2_SIZE]> {
    tt_get_context_job_key_v2(
        rid,
        TEMP_TABLE_ID_PROOF_WITNESS_DATA_BYTES,
        context,
        job_id,
    )
}

pub fn tt_get_rewards_tag_tree_value_key_v2<Hash: Q256BitHash, JobId: QJobIdBase>(
    rid: &QRealmIdentifier,
    context: &PendingContext<Hash>,
    job_id: &JobId,
) -> anyhow::Result<[u8; TEMP_PROOF_WORK_CONTEXT_KEY_V2_SIZE]> {
    tt_get_context_job_key_v2(
        rid,
        TEMP_TABLE_ID_TAG_TREE_VALUES_BYTES,
        context,
        job_id,
    )
}

pub fn tt_get_proof_claim_tag_key_v2<Hash: Q256BitHash, JobId: QJobIdBase>(
    rid: &QRealmIdentifier,
    context: &PendingContext<Hash>,
    job_id: &JobId,
) -> anyhow::Result<[u8; TEMP_PROOF_WORK_CONTEXT_KEY_V2_SIZE]> {
    tt_get_context_job_key_v2(
        rid,
        TEMP_TABLE_ID_PROOF_CLAIM_TAG_BYTES,
        context,
        job_id,
    )
}

pub fn tt_get_job_claim_key_v2<Hash: Q256BitHash, JobId: QJobIdBase>(
    rid: &QRealmIdentifier,
    context: &PendingContext<Hash>,
    job_id: &JobId,
) -> anyhow::Result<[u8; TEMP_PROOF_WORK_CONTEXT_KEY_V2_SIZE]> {
    tt_get_context_job_key_v2(rid, TEMP_TABLE_ID_JOB_CLAIM_BYTES, context, job_id)
}

pub const TEMP_TABLE_ID_PROOF_WITNESS_DATA: u16 = 0x5750; // 'PW'
pub const TEMP_TABLE_ID_PROOF_WITNESS_DATA_BYTES: [u8; 2] = [0x50, 0x57]; // 'PW'
pub const TEMP_TABLE_PROOF_WITNESS_DATA_KEY_SIZE: usize = 40; // 4 + 2 + 2 + 8 + 24

pub const TEMP_TABLE_ID_SUBMIT_STATUS: u16 = 0x5353; // 'SS'
pub const TEMP_TABLE_ID_SUBMIT_STATUS_BYTES: [u8; 2] = [0x53, 0x53]; // 'SS'
pub const TEMP_TABLE_SUBMIT_STATUS_KEY_SIZE: usize = 24; // 4 + 2 + 2 + 8 + 8
pub const TEMP_TABLE_SUBMIT_STAUTS_VALUE_SIZE: usize = 8; // u64

/// Content-bound, generation-exact Coordinator GUTA submission claim.
///
/// This is deliberately a distinct keyspace from the legacy random submit
/// status. The complete canonical `PendingContext` prevents pending/proc or
/// branch reuse, while the submitted Realm ID gives one immutable winner per
/// Realm in that generation.
pub const TEMP_TABLE_ID_COORDINATOR_GUTA_SUBMISSION: u16 = 0x5347; // 'GS'
pub const TEMP_TABLE_ID_COORDINATOR_GUTA_SUBMISSION_BYTES: [u8; 2] = [0x47, 0x53]; // 'GS'
pub const TEMP_COORDINATOR_GUTA_SUBMISSION_KEY_MAGIC: [u8; 4] = *b"CGS1";
pub const TEMP_COORDINATOR_GUTA_SUBMISSION_KEY_SIZE: usize =
    4 + 2 + 2 + TEMP_COORDINATOR_GUTA_SUBMISSION_KEY_MAGIC.len()
        + PENDING_CONTEXT_V1_LEN
        + 8;

pub const TEMP_TABLE_ID_USER_CONTRACT_TREE_UPDATES: u16 = 0x5543; // 'CU'
pub const TEMP_TABLE_ID_USER_CONTRACT_TREE_UPDATES_BYTES: [u8; 2] = [0x43, 0x55]; // 'CU'
pub const TEMP_TABLE_USER_CONTRACT_TREE_UPDATES_KEY_SIZE: usize = 24; // 4 + 2 + 2 + 8 + 8

pub const TEMP_TABLE_ID_USER_END_CAP_SLOT_UPDATES: u16 = 0x5553; // 'SU'
pub const TEMP_TABLE_ID_USER_END_CAP_SLOT_UPDATES_BYTES: [u8; 2] = [0x53, 0x55]; // 'SU'
pub const TEMP_TABLE_USER_END_CAP_SLOT_UPDATES_KEY_SIZE: usize = 24; // 4 + 2 + 2 + 8 + 8

pub const TEMP_TABLE_ID_TAG_TREE_VALUES: u16 = 0x5654; // 'TV'
pub const TEMP_TABLE_ID_TAG_TREE_VALUES_BYTES: [u8; 2] = [0x54, 0x56]; // 'TV'
pub const TEMP_TABLE_TAG_TREE_VALUES_KEY_SIZE: usize = 40; // 4 + 2 + 2 + 8 + 24
pub const TEMP_TABLE_TAG_TREE_VALUES_VALUE_SIZE: usize = 32; // Q256BitHash

pub const TEMP_TABLE_ID_NODE_PROVING_STATE: u16 = 0x5350; // 'PS'
pub const TEMP_TABLE_ID_NODE_PROVING_STATE_BYTES: [u8; 2] = [0x50, 0x53]; // 'PS'
pub const TEMP_TABLE_NODE_PROVING_STATE_KEY_SIZE: usize = 8; // 4 + 2 + 2
pub const TEMP_TABLE_NODE_PROVING_STATE_VALUE_SIZE: usize = 80; // PsyNodeProvingState

pub const TEMP_TABLE_ID_DEPLOY_CONTRACT_CODE_DEFINITION: u16 = 0x4344; // 'DC'
pub const TEMP_TABLE_ID_DEPLOY_CONTRACT_CODE_DEFINITION_BYTES: [u8; 2] = [0x44, 0x43]; // 'DC'
pub const TEMP_TABLE_ID_DEPLOY_CONTRACT_KEY_SIZE: usize = 32; // 4 + 2 + 2 + 8 + 16

pub const TEMP_TABLE_ID_JOB_CLAIM: u16 = 0x434A; // 'JC'
pub const TEMP_TABLE_ID_JOB_CLAIM_BYTES: [u8; 2] = [0x4A, 0x43]; // 'JC'
pub const TEMP_TABLE_JOB_CLAIM_KEY_SIZE: usize = 40; // 4 + 2 + 2 + 8 + 24
pub const TEMP_TABLE_JOB_CLAIM_VALUE_SIZE: usize = 41; // public_key 33 + claim_time_ms u64

pub const TEMP_TABLE_ID_JOB_STATS: u16 = 0x534A; // 'JS'
pub const TEMP_TABLE_ID_JOB_STATS_BYTES: [u8; 2] = [0x4A, 0x53]; // 'JS'
pub const TEMP_TABLE_JOB_STATS_KEY_SIZE: usize = 17; // 4 + 2 + 2 + 8 + 1
pub const JOB_STATS_COUNTER_COUNT: u8 = 0;
pub const JOB_STATS_COUNTER_TOTAL_DURATION: u8 = 1;
pub const JOB_STATS_COUNTER_MIN_DURATION: u8 = 2;
pub const JOB_STATS_COUNTER_MAX_DURATION: u8 = 3;

pub const TEMP_TABLE_ID_WORKER_REPUTATION: u16 = 0x5257; // 'WR'
pub const TEMP_TABLE_ID_WORKER_REPUTATION_BYTES: [u8; 2] = [0x57, 0x52]; // 'WR'
pub const TEMP_TABLE_WORKER_REPUTATION_KEY_SIZE: usize = 41; // 4 + 2 + 2 + 33 (compressed public key)
pub const TEMP_TABLE_WORKER_REPUTATION_VALUE_SIZE: usize = 8; // u64

#[inline(always)]
fn tt_get_job_stats_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    counter_type: u8,
) -> [u8; TEMP_TABLE_JOB_STATS_KEY_SIZE] {
    let mut key = [0u8; TEMP_TABLE_JOB_STATS_KEY_SIZE];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_JOB_STATS_BYTES);
    key[8..16].copy_from_slice(&unique_pending_id.to_le_bytes());
    key[16] = counter_type;
    key
}

#[inline(always)]
pub fn tt_get_job_stats_count_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
) -> [u8; TEMP_TABLE_JOB_STATS_KEY_SIZE] {
    tt_get_job_stats_key(realm_id, realm_sub_id, unique_pending_id, JOB_STATS_COUNTER_COUNT)
}

#[inline(always)]
pub fn tt_get_job_stats_total_duration_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
) -> [u8; TEMP_TABLE_JOB_STATS_KEY_SIZE] {
    tt_get_job_stats_key(
        realm_id,
        realm_sub_id,
        unique_pending_id,
        JOB_STATS_COUNTER_TOTAL_DURATION,
    )
}

#[inline(always)]
pub fn tt_get_job_stats_min_duration_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
) -> [u8; TEMP_TABLE_JOB_STATS_KEY_SIZE] {
    tt_get_job_stats_key(
        realm_id,
        realm_sub_id,
        unique_pending_id,
        JOB_STATS_COUNTER_MIN_DURATION,
    )
}

#[inline(always)]
pub fn tt_get_job_stats_max_duration_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
) -> [u8; TEMP_TABLE_JOB_STATS_KEY_SIZE] {
    tt_get_job_stats_key(
        realm_id,
        realm_sub_id,
        unique_pending_id,
        JOB_STATS_COUNTER_MAX_DURATION,
    )
}

// --- Psy Node Proving State ---
#[inline(always)]
pub fn tt_get_node_proving_state_key(realm_id: u32, realm_sub_id: u16) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_NODE_PROVING_STATE_BYTES);
    key
}
#[inline(always)]
pub fn tt_write_node_proving_state_key<Writer: psy_io::Write>(
    writer: &mut Writer,
    realm_id: u32,
    realm_sub_id: u16,
) -> anyhow::Result<()> {
    writer.write_all(&realm_id.to_le_bytes())?;
    writer.write_all(&realm_sub_id.to_le_bytes())?;
    writer.write_all(&TEMP_TABLE_ID_NODE_PROVING_STATE_BYTES)?;
    Ok(())
}




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

// --- Gathering Unique Pending ID ---

// (realm_id = 4) + (realm_sub_id = 2) + (table id length = 2) = 8
#[inline(always)]
pub fn tt_get_gathering_unique_pending_id_key(realm_id: u32, realm_sub_id: u16) -> [u8; 8] {
    let mut key = [0u8; 8];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_GATHERING_UNIQUE_PENDING_ID_BYTES);
    key
}

#[inline(always)]
pub fn tt_write_gathering_unique_pending_id_key<Writer: psy_io::Write>(
    writer: &mut Writer,
    realm_id: u32,
    realm_sub_id: u16,
) -> anyhow::Result<()> {
    writer.write_all(&realm_id.to_le_bytes())?;
    writer.write_all(&realm_sub_id.to_le_bytes())?;
    writer.write_all(&TEMP_TABLE_ID_GATHERING_UNIQUE_PENDING_ID_BYTES)?;
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

#[inline(always)]
pub fn tt_get_coordinator_guta_submission_key<Hash: Q256BitHash>(
    rid: &QRealmIdentifier,
    context: &PendingContext<Hash>,
    submitted_realm_id: u64,
) -> anyhow::Result<[u8; TEMP_COORDINATOR_GUTA_SUBMISSION_KEY_SIZE]> {
    if context.authority() != AuthorityScope::Coordinator {
        anyhow::bail!("Coordinator GUTA submission context must use Coordinator authority");
    }

    let mut key = [0u8; TEMP_COORDINATOR_GUTA_SUBMISSION_KEY_SIZE];
    key[0..4].copy_from_slice(&rid.realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&rid.realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_COORDINATOR_GUTA_SUBMISSION_BYTES);
    key[8..12].copy_from_slice(&TEMP_COORDINATOR_GUTA_SUBMISSION_KEY_MAGIC);
    key[12..(12 + PENDING_CONTEXT_V1_LEN)].copy_from_slice(&context.to_canonical_bytes());
    key[(12 + PENDING_CONTEXT_V1_LEN)..].copy_from_slice(&submitted_realm_id.to_le_bytes());
    Ok(key)
}

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
pub fn tt_get_user_end_cap_slot_updates_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    user_id: u64,
) -> [u8; 24] {
    let mut key = [0u8; 24];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_USER_END_CAP_SLOT_UPDATES_BYTES);
    key[8..16].copy_from_slice(&unique_pending_id.to_le_bytes());
    key[16..24].copy_from_slice(&user_id.to_le_bytes());
    key
}

#[inline(always)]
pub fn tt_write_user_end_cap_slot_updates_key<Writer: psy_io::Write>(
    writer: &mut Writer,
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    user_id: u64,
) -> anyhow::Result<()> {
    writer.write_all(&realm_id.to_le_bytes())?;
    writer.write_all(&realm_sub_id.to_le_bytes())?;
    writer.write_all(&TEMP_TABLE_ID_USER_END_CAP_SLOT_UPDATES_BYTES)?;
    writer.write_all(&unique_pending_id.to_le_bytes())?;
    writer.write_all(&user_id.to_le_bytes())?;
    Ok(())
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


// --- Proof Claim Tag (worker claim tag, distinct namespace from finalized reward values) ---

// (realm_id = 4) + (realm_sub_id = 2) + (table id length = 2) + (unique_pending_id = 8) + (QJOB_ID_SERIALIZED_SIZE = 24) = 40
pub const TEMP_TABLE_ID_PROOF_CLAIM_TAG: u16 = 0x4354; // 'CT'
pub const TEMP_TABLE_ID_PROOF_CLAIM_TAG_BYTES: [u8; 2] = [0x54, 0x43]; // 'CT'
pub const TEMP_TABLE_PROOF_CLAIM_TAG_KEY_SIZE: usize = 40; // 4 + 2 + 2 + 8 + 24
pub const TEMP_TABLE_PROOF_CLAIM_TAG_VALUE_SIZE: usize = 32; // Q256BitHash

#[inline(always)]
pub fn tt_get_proof_claim_tag_key(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id_bytes: &QJobIdSerialized,
) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_PROOF_CLAIM_TAG_BYTES);
    key[8..16].copy_from_slice(&unique_pending_id.to_le_bytes());
    key[16..40].copy_from_slice(job_id_bytes);
    key
}

#[inline(always)]
pub fn tt_write_proof_claim_tag_key<Writer: psy_io::Write>(
    writer: &mut Writer,
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id_bytes: &QJobIdSerialized,
) -> anyhow::Result<()> {
    writer.write_all(&realm_id.to_le_bytes())?;
    writer.write_all(&realm_sub_id.to_le_bytes())?;
    writer.write_all(&TEMP_TABLE_ID_PROOF_CLAIM_TAG_BYTES)?;
    writer.write_all(&unique_pending_id.to_le_bytes())?;
    writer.write_all(job_id_bytes)?;
    Ok(())
}

#[inline(always)]
pub fn tt_get_proof_claim_tag_key_from_job<JobId: QJobIdBase>(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id: &JobId,
) -> [u8; 40] {
    tt_get_proof_claim_tag_key(realm_id, realm_sub_id, unique_pending_id, &job_id.to_bytes_fixed())
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

// --- Job Claim (worker_id, claim_time_ms per job) ---
#[inline(always)]
pub fn tt_get_job_claim_key_from_bytes(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id_bytes: &QJobIdSerialized,
) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_JOB_CLAIM_BYTES);
    key[8..16].copy_from_slice(&unique_pending_id.to_le_bytes());
    key[16..40].copy_from_slice(job_id_bytes);
    key
}

#[inline(always)]
pub fn tt_get_job_claim_key_from_job<JobId: QJobIdBase>(
    realm_id: u32,
    realm_sub_id: u16,
    unique_pending_id: u64,
    job_id: &JobId,
) -> [u8; 40] {
    tt_get_job_claim_key_from_bytes(realm_id, realm_sub_id, unique_pending_id, &job_id.to_bytes_fixed())
}

// --- Worker Reputation (key = realm prefix + 33-byte compressed public key) ---
#[inline(always)]
pub fn tt_get_worker_reputation_key(realm_id: u32, realm_sub_id: u16, public_key: &[u8; 33]) -> [u8; 41] {
    let mut key = [0u8; 41];
    key[0..4].copy_from_slice(&realm_id.to_le_bytes());
    key[4..6].copy_from_slice(&realm_sub_id.to_le_bytes());
    key[6..8].copy_from_slice(&TEMP_TABLE_ID_WORKER_REPUTATION_BYTES);
    key[8..41].copy_from_slice(public_key);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::data::hash::hash256::Hash256;
    use psy_core::job::job_id::{
        ProvingJobCircuitType, ProvingJobDataType, QJobTopic,
        QProvingJobDataID,
    };
    use psy_data::protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        chain_context::{WorkProcCheckpointUniqueId, WorkUniquePendingId},
    };

    fn sample_job_id() -> QProvingJobDataID {
        QProvingJobDataID {
            topic: QJobTopic::GenerateStandardProof,
            goal_id: 0x1122_3344_5566_7788,
            circuit_type: ProvingJobCircuitType::BatchDeployContractsAggregate,
            group_id: 0x1122_3344,
            sub_group_id: 0x5566_7788,
            task_index: 0x99aa_bbcc,
            data_type: ProvingJobDataType::StandardProof,
            data_index: 1,
        }
    }

    fn sample_context(epoch: u64) -> PendingContext<Hash256> {
        PendingContext::new(
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(0x6979_7350).unwrap(),
                ChainEpoch::new(epoch),
                CheckpointRef::new(
                    CheckpointId::new(367),
                    CheckpointHash::from_last_chain_hash(Hash256([
                        epoch as u8;
                        32
                    ])),
                ),
            ),
            AuthorityScope::Realm {
                realm_id: 9,
                realm_sub_id: 2,
            },
            WorkUniquePendingId::new(411),
            WorkProcCheckpointUniqueId::from_u128(epoch as u128 + 1000),
        )
    }

    #[test]
    fn current_pending_context_key_has_stable_authority_layout() {
        let key = tt_get_current_pending_context_key(0x0102_0304, 0x0506);
        assert_eq!(
            key,
            [0x04, 0x03, 0x02, 0x01, 0x06, 0x05, 0x50, 0x43]
        );
        assert_eq!(&key[6..8], &TEMP_TABLE_ID_CURRENT_PENDING_CONTEXT_BYTES);
    }

    #[test]
    fn proof_work_v2_key_embeds_exact_context_and_never_aliases_v1() {
        let rid = QRealmIdentifier::new(9, 2);
        let job_id = sample_job_id();
        let context = sample_context(7);
        let key = tt_get_proof_witness_data_key_v2(&rid, &context, &job_id)
            .unwrap();
        let legacy = tt_get_proof_witness_data_key_from_job(
            rid.realm_id,
            rid.realm_sub_id,
            context.unique_pending_id().get(),
            &job_id,
        );

        assert_eq!(key.len(), TEMP_PROOF_WORK_CONTEXT_KEY_V2_SIZE);
        assert_eq!(&key[0..4], &rid.realm_id.to_le_bytes());
        assert_eq!(&key[4..6], &rid.realm_sub_id.to_le_bytes());
        assert_eq!(&key[6..8], &TEMP_TABLE_ID_PROOF_WITNESS_DATA_BYTES);
        assert_eq!(&key[8..12], &TEMP_PROOF_WORK_CONTEXT_KEY_V2_MAGIC);
        assert_eq!(
            &key[12..(12 + PENDING_CONTEXT_V1_LEN)],
            &context.to_canonical_bytes(),
        );
        assert_eq!(
            &key[(12 + PENDING_CONTEXT_V1_LEN)..],
            &job_id.to_bytes_fixed(),
        );
        assert_ne!(key.as_slice(), legacy.as_slice());
    }

    #[test]
    fn proof_work_v2_key_changes_with_branch_and_table_domain() {
        let rid = QRealmIdentifier::new(9, 2);
        let job_id = sample_job_id();
        let first = sample_context(7);
        let second = sample_context(8);

        assert_ne!(
            tt_get_proof_witness_data_key_v2(&rid, &first, &job_id)
                .unwrap(),
            tt_get_proof_witness_data_key_v2(&rid, &second, &job_id)
                .unwrap(),
        );

        let domain_keys = [
            tt_get_proving_job_metadata_key_v2(&rid, &first, &job_id)
                .unwrap(),
            tt_get_proof_witness_data_key_v2(&rid, &first, &job_id).unwrap(),
            tt_get_rewards_tag_tree_value_key_v2(&rid, &first, &job_id)
                .unwrap(),
            tt_get_proof_claim_tag_key_v2(&rid, &first, &job_id).unwrap(),
            tt_get_job_claim_key_v2(&rid, &first, &job_id).unwrap(),
        ];
        for left in 0..domain_keys.len() {
            for right in (left + 1)..domain_keys.len() {
                assert_ne!(domain_keys[left], domain_keys[right]);
            }
        }
    }

    #[test]
    fn proof_work_v2_key_rejects_realm_authority_mismatch() {
        let wrong_rid = QRealmIdentifier::new(10, 2);
        let error = tt_get_proof_witness_data_key_v2(
            &wrong_rid,
            &sample_context(7),
            &sample_job_id(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("authority"));
    }

    // For identical realm/pending/job-id, the proof claim-tag key must differ from the
    // finalized-reward key so that a worker's claimed tag can never alias a finalized
    // reward-tree value (the checkpoint-367 BridgeAgg divergence root cause).
    #[test]
    fn proof_claim_tag_key_never_aliases_rewards_tag_tree_value_key() {
        let realm_id: u32 = 0x0a0b_0c0d;
        let realm_sub_id: u16 = 0x0e0f;
        let unique_pending_id: u64 = 0x1122_3344_5566_7788;
        let job_id_bytes: QJobIdSerialized = [0xaau8; 24];

        let reward_key = tt_get_rewards_tag_tree_value_key(
            realm_id,
            realm_sub_id,
            unique_pending_id,
            &job_id_bytes,
        );
        let claim_key = tt_get_proof_claim_tag_key(
            realm_id,
            realm_sub_id,
            unique_pending_id,
            &job_id_bytes,
        );

        // Same realm/pending/job-id shape, but distinct table-id prefix bytes => distinct keys.
        assert_ne!(reward_key, claim_key);
        assert_eq!(&reward_key[6..8], &TEMP_TABLE_ID_TAG_TREE_VALUES_BYTES);
        assert_eq!(&claim_key[6..8], &TEMP_TABLE_ID_PROOF_CLAIM_TAG_BYTES);
        // Shared shape: realm/sub/pending/job-id bytes are identical across both keys.
        assert_eq!(&reward_key[0..6], &claim_key[0..6]);
        assert_eq!(&reward_key[8..40], &claim_key[8..40]);
        // The table-id prefix itself must not collide with the reward-tree prefix.
        assert_ne!(TEMP_TABLE_ID_PROOF_CLAIM_TAG, TEMP_TABLE_ID_TAG_TREE_VALUES);
        assert_ne!(
            TEMP_TABLE_ID_PROOF_CLAIM_TAG_BYTES,
            TEMP_TABLE_ID_TAG_TREE_VALUES_BYTES
        );
    }

    // The claim-tag prefix must be globally unique among all temp table ids so it cannot
    // collide with any other table namespace (e.g. job-claim, submit-status, witness data).
    #[test]
    fn proof_claim_tag_table_id_is_unique_among_known_temp_tables() {
        let known: [u16; 14] = [
            TEMP_TABLE_ID_WORKER_PROOF_METADATA,
            TEMP_TABLE_ID_UNIQUE_PENDING_ID,
            TEMP_TABLE_ID_GATHERING_UNIQUE_PENDING_ID,
            TEMP_TABLE_ID_CURRENT_PENDING_CONTEXT,
            TEMP_TABLE_ID_PROOF_WITNESS_DATA,
            TEMP_TABLE_ID_SUBMIT_STATUS,
            TEMP_TABLE_ID_USER_CONTRACT_TREE_UPDATES,
            TEMP_TABLE_ID_USER_END_CAP_SLOT_UPDATES,
            TEMP_TABLE_ID_TAG_TREE_VALUES,
            TEMP_TABLE_ID_NODE_PROVING_STATE,
            TEMP_TABLE_ID_DEPLOY_CONTRACT_CODE_DEFINITION,
            TEMP_TABLE_ID_JOB_CLAIM,
            TEMP_TABLE_ID_JOB_STATS,
            TEMP_TABLE_ID_WORKER_REPUTATION,
        ];
        for id in known {
            assert_ne!(
                TEMP_TABLE_ID_PROOF_CLAIM_TAG, id,
                "proof claim tag table id collides with existing temp table id {:#06x}",
                id
            );
        }
    }
    // Every temp-table id must occupy a globally unique u16 namespace slot. A future
    // addition (or accidental edit) that reuses an existing id would silently route one
    // table's KV rows through another table's key — the checkpoint-367 class of corruption,
    // generalized to the whole namespace. This checks ALL pairs (not just claim-tag vs
    // reward), so a collision anywhere reddens it with a named pair.
    #[test]
    fn all_known_temp_table_ids_are_pairwise_distinct() {
        let known: [(&str, u16); 15] = [
            ("WORKER_PROOF_METADATA", TEMP_TABLE_ID_WORKER_PROOF_METADATA),
            ("UNIQUE_PENDING_ID", TEMP_TABLE_ID_UNIQUE_PENDING_ID),
            ("GATHERING_UNIQUE_PENDING_ID", TEMP_TABLE_ID_GATHERING_UNIQUE_PENDING_ID),
            ("CURRENT_PENDING_CONTEXT", TEMP_TABLE_ID_CURRENT_PENDING_CONTEXT),
            ("PROOF_WITNESS_DATA", TEMP_TABLE_ID_PROOF_WITNESS_DATA),
            ("SUBMIT_STATUS", TEMP_TABLE_ID_SUBMIT_STATUS),
            ("USER_CONTRACT_TREE_UPDATES", TEMP_TABLE_ID_USER_CONTRACT_TREE_UPDATES),
            ("USER_END_CAP_SLOT_UPDATES", TEMP_TABLE_ID_USER_END_CAP_SLOT_UPDATES),
            ("TAG_TREE_VALUES", TEMP_TABLE_ID_TAG_TREE_VALUES),
            ("NODE_PROVING_STATE", TEMP_TABLE_ID_NODE_PROVING_STATE),
            ("DEPLOY_CONTRACT_CODE_DEFINITION", TEMP_TABLE_ID_DEPLOY_CONTRACT_CODE_DEFINITION),
            ("JOB_CLAIM", TEMP_TABLE_ID_JOB_CLAIM),
            ("JOB_STATS", TEMP_TABLE_ID_JOB_STATS),
            ("WORKER_REPUTATION", TEMP_TABLE_ID_WORKER_REPUTATION),
            ("PROOF_CLAIM_TAG", TEMP_TABLE_ID_PROOF_CLAIM_TAG),
        ];
        for i in 0..known.len() {
            for j in (i + 1)..known.len() {
                let (name_i, id_i) = known[i];
                let (name_j, id_j) = known[j];
                assert_ne!(
                    id_i, id_j,
                    "temp table id collision: {} ({:#06x}) == {} ({:#06x})",
                    name_i, id_i, name_j, id_j
                );
            }
        }
    }
}
