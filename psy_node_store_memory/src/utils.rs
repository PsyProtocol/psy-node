
pub trait TIDBase: Clone + Send + Sync + Eq + std::hash::Hash {

}
impl<T: Clone + Send + Sync + Eq + std::hash::Hash> TIDBase for T {}




pub const fn u64_to_i64_exact(num: u64) -> i64 {
    i64::from_ne_bytes(num.to_ne_bytes())
}
pub const fn i64_to_u64_exact(num: i64) -> u64 {
    u64::from_ne_bytes(num.to_ne_bytes())
}
pub const fn u8_to_i8_exact(num: u8) -> i8 {
    i8::from_ne_bytes([num])
}
pub const fn i8_to_u8_exact(num: i8) -> u8 {
    u8::from_ne_bytes(num.to_ne_bytes())
}

pub const fn convert_checkpoint_id_to_i64(checkpoint_id: u64) -> i64 {
    if checkpoint_id > (i64::MAX as u64) {
        i64::MAX
    } else {
        checkpoint_id as i64
    }
}

pub const fn convert_i64_to_checkpoint_id(checkpoint_id: i64) -> u64 {
    if checkpoint_id < 0 {
        0
    } else {
        checkpoint_id as u64
    }
}