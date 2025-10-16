pub trait RandomHash {
    fn rand_hash() -> Self;
}

pub trait CodeSerializableHash {
    fn to_constant_code(&self) -> String;
    fn get_type_name() -> String;
}

pub trait ZeroableHash: Sized + Copy + Clone {
    fn get_zero_value() -> Self;
}
pub trait ToU64x4 {
    fn to_u64x4(&self) -> [u64; 4];
    fn into_u64x4_serialize_non_canonical(self) -> [u64; 4];
}
pub trait FromU64x4: Sized {
    fn from_u64x4(data: [u64; 4]) -> Self;
    fn from_u64s(a: u64, b: u64, c: u64, d: u64) -> Self {
        Self::from_u64x4([a, b, c, d])
    }
}

impl<const N: usize> ZeroableHash for [u8; N] {
    fn get_zero_value() -> Self {
       [0u8; N]
    }
}
impl<const N: usize> CodeSerializableHash for [u8; N] {
    fn to_constant_code(&self) -> String {
        let bytes_str = self.iter().map(|b| format!("0x{:02x}", b)).collect::<Vec<_>>().join(", ");
        format!("[{}]", bytes_str)
    }
    fn get_type_name() -> String {
        format!("[u8; {}]", N)
    }
}

