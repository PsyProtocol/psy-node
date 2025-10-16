#[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
pub trait MaybeBytemuck: bytemuck::Pod + bytemuck::Zeroable {}
#[cfg(all(feature = "serialize_bytemuck", target_endian = "little"))]
impl<T: bytemuck::Pod + bytemuck::Zeroable> MaybeBytemuck for T {}


#[cfg(not(all(feature = "serialize_bytemuck", target_endian = "little")))]
pub trait MaybeBytemuck {}
#[cfg(not(all(feature = "serialize_bytemuck", target_endian = "little")))]
impl<T> MaybeBytemuck for T {}
