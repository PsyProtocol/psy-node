const G_MAX_CHECKPOINT_ID: u64 = 0x00FF_FFFF_FFFF_FFFF;
const G_MAX_CHECKPOINT_ID_RANDOM: u64 = 0x0000_0FFF_FFFF_FFFF;
const G_MAX_USER_ID: u64 = 0x00FF_FFFF_FFFF_FFFF;
const G_MAX_REALM_ID: u32 = 0xFFFF_FFFF;
const G_MAX_CONTRACT_ID: u32 = 0xFFFF_FFFF;


fn rand_checkpoint_id() -> u64 {
    rand::random::<u64>() % G_MAX_CHECKPOINT_ID_RANDOM
}

fn rand_user_id() -> u64 {
    rand::random::<u64>() % G_MAX_USER_ID
}
