#[cfg(feature = "serialize_speedy")]
use speedy::{Readable, Writable, Reader, LittleEndian};

#[cfg(feature = "serialize_speedy")]
pub trait SpeedyReadable {
    fn read_from<'a, R: Reader<'a, LittleEndian>>(reader: &mut R) -> Result<Self, speedy::Error>
    where
        Self: Sized;
}

#[cfg(feature = "serialize_speedy")]
impl<T> SpeedyReadable for T
where
    T: for<'a> Readable<'a, LittleEndian>,
{
    fn read_from<'a, R: Reader<'a, LittleEndian>>(reader: &mut R) -> Result<Self, speedy::Error>
    where
        Self: Sized,
    {
        <T as Readable<'a, LittleEndian>>::read_from(reader)
    }
}

#[cfg(feature = "serialize_speedy")]
pub trait MaybeSpeedy: SpeedyReadable + Writable<LittleEndian> + Readable<'static, LittleEndian> {}

#[cfg(feature = "serialize_speedy")]
impl<T: SpeedyReadable + Writable<LittleEndian> + Readable<'static, LittleEndian>> MaybeSpeedy for T {}

#[cfg(not(feature = "serialize_speedy"))]
pub trait MaybeSpeedy {}

#[cfg(not(feature = "serialize_speedy"))]
impl<T> MaybeSpeedy for T {}