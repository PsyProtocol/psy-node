use bytemuck::{Pod, Zeroable};
use parth_core::{crypto::hash::traits::FromU64x4, felt::ToU64Value, protocol::core_types::Q256BitHash, PF};



/// A struct with a C representation, guaranteed to be a contiguous 104-byte block.
/// The `Pod` trait (Plain Old Data) is a safety marker indicating that this type
/// is safe to treat as a sequence of bytes. `bytemuck`'s derive macro verifies this.
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable, PartialEq, Eq)]
pub struct SplitData {
    pub p1: [u8; 32],
    pub p2: [u8; 32],
    pub p3: [u8; 8],
    pub p4: [u8; 8],
    pub p5: [u8; 8],
    pub p6: [u8; 8],
    pub p7: [u8; 8],
}

/// Splits the 104-byte array into a structured format using bytemuck.
/// This is a true zero-copy operation.
fn split_owned_bytemuck(data: [u8; 104]) -> SplitData {
    bytemuck::cast(data)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub struct ExampleFelt(pub u64);


impl ToU64Value for ExampleFelt {
    #[inline(always)]
    fn to_u64_value(&self) -> u64 {
        self.0
    }
    
    #[inline(always)]
    fn into_u64_value_serialize_non_canonical(self) -> u64 {
        self.0
    }
    
    #[inline(always)]
    fn from_owned_u64(value: u64) -> Self {
        ExampleFelt(value)
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub struct ZHashOut<F> {
    pub elements: [F; 4],
}
impl<F: ToU64Value> FromU64x4 for ZHashOut<F> {
    #[inline(always)]
    fn from_u64x4(values: [u64; 4]) -> Self {
        Self {
            elements: [
                F::from_owned_u64(values[0]),
                F::from_owned_u64(values[1]),
                F::from_owned_u64(values[2]),
                F::from_owned_u64(values[3]),
            ],
        }
    }
    
    #[inline(always)]
    fn from_u64s(a: u64, b: u64, c: u64, d: u64) -> Self {
        Self {
            elements: [
                F::from_owned_u64(a),
                F::from_owned_u64(b),
                F::from_owned_u64(c),
                F::from_owned_u64(d),
            ],
        }
    }
}
impl Q256BitHash for ZHashOut<ExampleFelt> {
    fn from_owned_32bytes(bytes: [u8; 32]) -> Self {
        #[cfg(not(target_endian = "little"))]
        {
            return [
                ExampleFelt(u64::from_le_bytes(bytes[0..8].try_into().unwrap())),
                ExampleFelt(u64::from_le_bytes(bytes[8..16].try_into().unwrap())),
                ExampleFelt(u64::from_le_bytes(bytes[16..24].try_into().unwrap())),
                ExampleFelt(u64::from_le_bytes(bytes[24..32].try_into().unwrap())),
            ];
        }

        #[cfg(target_endian = "little")]
        bytemuck::cast(bytes)
    }
#[inline(always)]
    fn into_owned_32bytes(self) -> [u8; 32] {
        #[cfg(not(target_endian = "little"))]
        {
            let mut bytes = [0u8; 32];
            bytes[0..8].copy_from_slice(&self.elements[0].0.to_le_bytes());
            bytes[8..16].copy_from_slice(&self.elements[1].0.to_le_bytes());
            bytes[16..24].copy_from_slice(&self.elements[2].0.to_le_bytes());
            bytes[24..32].copy_from_slice(&self.elements[3].0.to_le_bytes());
            return bytes;
        }
        #[cfg(target_endian = "little")]
        {
            bytemuck::cast(self)
        }
    }

    fn from_ref_32bytes(bytes: &[u8; 32]) -> Self {
        Self::from_owned_32bytes(*bytes)
    }

    fn from_slice_32bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 32 {
            anyhow::bail!("Invalid length for 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self::from_owned_32bytes(arr))
    }

    fn to_vec_32bytes(&self) -> Vec<u8> {
        self.into_owned_32bytes().to_vec()
    }
}



impl Q256BitHash for ZHashOut<PF> {
    fn from_owned_32bytes(bytes: [u8; 32]) -> Self {
        #[cfg(not(target_endian = "little"))]
        {
            use parth_core::felt::ToU64Value;

            return [
                PF::from_owned_u64(u64::from_le_bytes(bytes[0..8].try_into().unwrap())),
                PF::from_owned_u64(u64::from_le_bytes(bytes[8..16].try_into().unwrap())),
                PF::from_owned_u64(u64::from_le_bytes(bytes[16..24].try_into().unwrap())),
                PF::from_owned_u64(u64::from_le_bytes(bytes[24..32].try_into().unwrap())),
            ];
        }

        #[cfg(target_endian = "little")]
        bytemuck::cast(bytes)
    }
#[inline(always)]
    fn into_owned_32bytes(self) -> [u8; 32] {
        #[cfg(not(target_endian = "little"))]
        {
            let mut bytes = [0u8; 32];
            bytes[0..8].copy_from_slice(&self.elements[0].0.to_le_bytes());
            bytes[8..16].copy_from_slice(&self.elements[1].0.to_le_bytes());
            bytes[16..24].copy_from_slice(&self.elements[2].0.to_le_bytes());
            bytes[24..32].copy_from_slice(&self.elements[3].0.to_le_bytes());
            return bytes;
        }
        #[cfg(target_endian = "little")]
        {
            bytemuck::cast(self)
        }
    }

    fn from_ref_32bytes(bytes: &[u8; 32]) -> Self {
        Self::from_owned_32bytes(*bytes)
    }

    fn from_slice_32bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 32 {
            anyhow::bail!("Invalid length for 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self::from_owned_32bytes(arr))
    }

    fn to_vec_32bytes(&self) -> Vec<u8> {
        self.into_owned_32bytes().to_vec()
    }
}
pub trait FastFixedSerializable<const N: usize>: Sized {
    fn ffs_from_owned_bytes(data: [u8; N]) -> Self;
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self;
    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self>;
    fn ffs_to_bytes(&self) -> [u8; N];
    fn ffs_into_bytes(self) -> [u8; N];

    fn ffs_serialize_vec_of_self_ref(data: &[Self]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(data.len() * N);
        for item in data {
            bytes.extend_from_slice(&item.ffs_to_bytes());
        }
        bytes
    }
    fn ffs_serialize_vec_of_self(data: Vec<Self>) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(data.len() * N);
        for item in data {
            bytes.extend_from_slice(&item.ffs_to_bytes());
        }
        bytes
    }
    fn ffs_deserialize_vec_of_self(data: &[u8]) -> anyhow::Result<Vec<Self>> {
        if data.len() % N != 0 {
            anyhow::bail!("Data length is not a multiple of item size");
        }
        let count = data.len() / N;
        let mut items = Vec::with_capacity(count);
        for i in 0..count {
            let start = i * N;
            let end = start + N;
            let item = Self::ffs_try_from_slice(&data[start..end])?;
            items.push(item);
        }
        Ok(items)
    }
    fn ffs_deserialize_vec_of_self_owned(data: Vec<u8>) -> anyhow::Result<Vec<Self>> {
        let items = Self::ffs_deserialize_vec_of_self(&data)?;
        Ok(items)
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(C)]
pub struct ExampleUser<F, Hash> {
    pub public_key: Hash,
    pub user_state_tree_root: Hash,
    pub balance: F,
    pub nonce: F,
    pub last_checkpoint_id: F,
    pub event_index: F,
    pub user_id: F,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct ExampleUserSerialize {
    pub public_key: [u8; 32],
    pub user_state_tree_root: [u8; 32],
    pub balance: u64,
    pub nonce: u64,
    pub last_checkpoint_id: u64,
    pub event_index: u64,
    pub user_id: u64,
}

impl<F: ToU64Value, Hash: Q256BitHash> ExampleUser<F, Hash> {
    #[inline(always)]
    pub fn to_serialize(self) -> ExampleUserSerialize {
        ExampleUserSerialize {
            public_key: self.public_key.into_owned_32bytes(),
            user_state_tree_root: self.user_state_tree_root.into_owned_32bytes(),
            balance: self.balance.into_u64_value_serialize_non_canonical(),
            nonce: self.nonce.into_u64_value_serialize_non_canonical(),
            last_checkpoint_id: self.last_checkpoint_id.into_u64_value_serialize_non_canonical(),
            event_index: self.event_index.into_u64_value_serialize_non_canonical(),
            user_id: self.user_id.into_u64_value_serialize_non_canonical(),
        }
    }
        #[inline(always)]
    pub fn from_serialize(data: ExampleUserSerialize) -> Self {
        Self {
            public_key: Hash::from_owned_32bytes(data.public_key),
            user_state_tree_root: Hash::from_owned_32bytes(data.user_state_tree_root),
            balance: F::from_owned_u64(data.balance),
            nonce: F::from_owned_u64(data.nonce),
            last_checkpoint_id: F::from_owned_u64(data.last_checkpoint_id),
            event_index: F::from_owned_u64(data.event_index),
            user_id: F::from_owned_u64(data.user_id),
        }
    }
    #[inline(always)]
    pub fn to_serialize_bytes(self) -> [u8; 104] {
        let data = self.to_serialize();
        data.ffs_to_bytes()
    }
    #[inline(always)]
    pub fn from_serialize_bytes(data: [u8; 104]) -> Self {
        let data = ExampleUserSerialize::ffs_from_owned_bytes(data);
        Self::from_serialize(data)
    }
    
}

impl FastFixedSerializable<104> for ExampleUserSerialize {
    #[inline(always)]
    fn ffs_from_owned_bytes(data: [u8; 104]) -> Self {
        #[cfg(not(target_endian = "little"))]
        {
            let public_key = data[0..32].try_into().unwrap();
            let user_state_tree_root = data[32..64].try_into().unwrap();
            let balance = u64::from_le_bytes(data[64..72].try_into().unwrap());
            let nonce = u64::from_le_bytes(data[72..80].try_into().unwrap());
            let last_checkpoint_id = u64::from_le_bytes(data[80..88].try_into().unwrap());
            let event_index = u64::from_le_bytes(data[88..96].try_into().unwrap());
            let user_id = u64::from_le_bytes(data[96..104].try_into().unwrap());
            return ExampleUserSerialize {
                public_key,
                user_state_tree_root,
                balance,
                nonce,
                last_checkpoint_id,
                event_index,
                user_id,
            };
        }
        #[cfg(target_endian = "little")]
        bytemuck::cast(data)
    }

    #[inline(always)]
    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        if data.len() != 104 {
            panic!("Invalid number of bytes for ExampleUserSerialize");
        }
        let mut arr = [0u8; 104];
        arr.copy_from_slice(data);
        Self::ffs_from_owned_bytes(arr)
    }

    #[inline(always)]
    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 104 {
            anyhow::bail!("Invalid number of bytes for ExampleUserSerialize");
        }
        let mut arr = [0u8; 104];
        arr.copy_from_slice(data);
        Ok(Self::ffs_from_owned_bytes(arr))
    }

    #[inline(always)]
    fn ffs_to_bytes(&self) -> [u8; 104] {
        #[cfg(not(target_endian = "little"))]
        {
            let mut bytes = [0u8; 104];
            bytes[0..32].copy_from_slice(&self.public_key);
            bytes[32..64].copy_from_slice(&self.user_state_tree_root);
            bytes[64..72].copy_from_slice(&self.balance.to_le_bytes());
            bytes[72..80].copy_from_slice(&self.nonce.to_le_bytes());
            bytes[80..88].copy_from_slice(&self.last_checkpoint_id.to_le_bytes());
            bytes[88..96].copy_from_slice(&self.event_index.to_le_bytes());
            bytes[96..104].copy_from_slice(&self.user_id.to_le_bytes());
            return bytes;
        }
        #[cfg(target_endian = "little")]
        bytemuck::cast(*self)
    }

    #[inline(always)]
    fn ffs_into_bytes(self) -> [u8; 104] {
        #[cfg(not(target_endian = "little"))]
        {
            let mut bytes = [0u8; 104];
            bytes[0..32].copy_from_slice(&self.public_key);
            bytes[32..64].copy_from_slice(&self.user_state_tree_root);
            bytes[64..72].copy_from_slice(&self.balance.to_le_bytes());
            bytes[72..80].copy_from_slice(&self.nonce.to_le_bytes());
            bytes[80..88].copy_from_slice(&self.last_checkpoint_id.to_le_bytes());
            bytes[88..96].copy_from_slice(&self.event_index.to_le_bytes());
            bytes[96..104].copy_from_slice(&self.user_id.to_le_bytes());
            return bytes;
        }
        #[cfg(target_endian = "little")]
        bytemuck::cast(self)
    }
}

type ZFelt = PF;
type ZHashOutFelt = ZHashOut<ZFelt>;
#[inline(always)]
pub fn test_a(x: ExampleUser<ZFelt, ZHashOutFelt>) -> [u8; 104] {
     x.to_serialize_bytes()
}
#[inline(always)]
pub fn test_a_back(x: [u8; 104]) ->  ExampleUser<ZFelt, ZHashOutFelt> {
     ExampleUser::<ZFelt, ZHashOutFelt>::from_serialize_bytes(x)
}
fn main() {

    let mut p = ExampleUser {
        public_key: ZHashOut { elements: [ZFelt::from_owned_u64(1), ZFelt::from_owned_u64(2), ZFelt::from_owned_u64(3), ZFelt::from_owned_u64(4)] },
        user_state_tree_root: ZHashOut { elements: [ZFelt::from_owned_u64(5), ZFelt::from_owned_u64(6), ZFelt::from_owned_u64(7), ZFelt::from_owned_u64(8)] },
        balance: ZFelt::from_owned_u64(100),
        nonce: ZFelt::from_owned_u64(1),
        last_checkpoint_id: ZFelt::from_owned_u64(10),
        event_index: ZFelt::from_owned_u64(0),
        user_id: ZFelt::from_owned_u64(42),
    };

    let mut ser: [u8; 104] = test_a(p);
    let start = std::time::Instant::now();
    const TOTAL_ITERATIONS: usize = 10_000_000;
    for _ in 0..TOTAL_ITERATIONS {
        ser = test_a(p);
        p = test_a_back(ser);
    }
    let duration = start.elapsed();
    println!("10 million round trips took: {:?}", duration);
    println!("Average per round trip: {:?}", duration / TOTAL_ITERATIONS as u32);
    let ser = test_a(p);
    println!("Serialized bytes: {:?}", ser);
    let de = ExampleUser::<ZFelt, ZHashOutFelt>::from_serialize_bytes(ser);
    println!("Deserialized struct: {:?}", de);
    assert_eq!(p, de);

}

