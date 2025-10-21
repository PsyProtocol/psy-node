// for benches, allow unused functions
#![allow(dead_code)]
use criterion::{black_box, BenchmarkId, Criterion};
use parth_core::{
    data::{
        hash::hash256::Hash256,
        serializable::{QPDSerializable, QPDSerializableFixed},
    }, pgoldilocks::PGoldilocksHash, protocol::core_types::Q256BitHash, utils::QPGenRandom
};
use speedy::{Readable, Writable};
use psy_serialize::FastFixedSerializable;


// NOTE on Cargo.toml for rkyv:
// For `` and the derive macros to work,
// you need to enable the correct features in your Cargo.toml.
// rkyv = { version = "0.7", features = ["derive", "validation"] }
// or a similar combination for your specific rkyv version.

#[pderive::serialize_copy_default]
pub struct QMerkleStoreSingleIdKey {
    pub tree_id: u64, // 8
    pub level: u8,    // 9
    pub index: u64,   // 17
}
impl FastFixedSerializable<17> for QMerkleStoreSingleIdKey {
    fn ffs_from_owned_bytes(data: [u8; 17]) -> Self {
        Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            level: data[8],
            index: u64::from_le_bytes(data[9..17].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            level: data[8],
            index: u64::from_le_bytes(data[9..17].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 17 {
            anyhow::bail!("invalid length for QMerkleStoreSingleIdKey, expected 17 bytes, got {}", data.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            level: data[8],
            index: u64::from_le_bytes(data[9..17].try_into().unwrap()),
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 17] {
        let mut data: [u8; 17] = [0u8; 17];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8] = self.level;

        data[9..17].copy_from_slice(&self.index.to_le_bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 17] {
        let mut data: [u8; 17] = [0u8; 17];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8] = self.level;

        data[9..17].copy_from_slice(&self.index.to_le_bytes());
        data
    }
}

impl QPDSerializable for QMerkleStoreSingleIdKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut data: [u8; 17] = [0u8; 17];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8] = self.level;

        data[9..17].copy_from_slice(&self.index.to_le_bytes());
        Ok(data.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 17 {
            anyhow::bail!("invalid length for QMerkleStoreSingleIdKey, expected 17 bytes, got {}", bytes.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            level: bytes[8],
            index: u64::from_le_bytes(bytes[9..17].try_into().unwrap()),
        })
    }
}

impl QPDSerializableFixed for QMerkleStoreSingleIdKey {
    fn get_fixed_size() -> usize {
        17
    }
}

impl QPGenRandom for QMerkleStoreSingleIdKey {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            tree_id: QPGenRandom::qp_rand_gen(),
            level: QPGenRandom::qp_rand_gen(),
            index: QPGenRandom::qp_rand_gen(),
        }
    }
}


#[pderive::serialize_copy_default]
pub struct QMerkleStoreSingleIdNode<Hash> {
    pub key: QMerkleStoreSingleIdKey,
    pub hash: Hash,
}
impl<Hash: QPGenRandom> QPGenRandom for QMerkleStoreSingleIdNode<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            key: QMerkleStoreSingleIdKey::qp_rand_gen(),
            hash: QPGenRandom::qp_rand_gen(),
        }
    }
}
impl<Hash: Q256BitHash> FastFixedSerializable<49> for QMerkleStoreSingleIdNode<Hash> {
    fn ffs_from_owned_bytes(data: [u8; 49]) -> Self {
        Self {
            key: QMerkleStoreSingleIdKey::ffs_from_owned_bytes(data[0..17].try_into().unwrap()),
            hash: Hash::from_ref_32bytes(data[17..49].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            key: QMerkleStoreSingleIdKey::ffs_from_slice_or_panic(&data[0..17]),
            hash: Hash::from_ref_32bytes(data[17..49].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 49 {
            anyhow::bail!("invalid length for QMerkleStoreSingleIdNode, expected 49 bytes, got {}", data.len());
        }
        Ok(Self {
            key: QMerkleStoreSingleIdKey::ffs_try_from_slice(&data[0..17])?,
            hash: Hash::from_slice_32bytes(&data[17..49])?,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 49] {
        let mut data: [u8; 49] = [0u8; 49];
        data[0..17].copy_from_slice(&self.key.ffs_to_bytes());
        data[17..49].copy_from_slice(&self.hash.into_owned_32bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 49] {
        let mut data: [u8; 49] = [0u8; 49];
        data[0..17].copy_from_slice(&self.key.ffs_into_bytes());
        data[17..49].copy_from_slice(&self.hash.into_owned_32bytes());
        data
    }
}


#[pderive::serialize_copy_default]
pub struct QMerkleStoreDoubleIdKey {
    pub tree_id: u64,     // 8
    pub tree_sub_id: u64, // 16
    pub level: u8,        // 17
    pub index: u64,       // 25
}

impl FastFixedSerializable<25> for QMerkleStoreDoubleIdKey {
    fn ffs_from_owned_bytes(data: [u8; 25]) -> Self {
        Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            level: data[16],
            index: u64::from_le_bytes(data[17..25].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            level: data[16],
            index: u64::from_le_bytes(data[17..25].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 25 {
            anyhow::bail!("invalid length for QMerkleStoreDoubleIdKey, expected 25 bytes, got {}", data.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(data[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(data[8..16].try_into().unwrap()),
            level: data[16],
            index: u64::from_le_bytes(data[17..25].try_into().unwrap()),
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 25] {
        let mut data: [u8; 25] = [0u8; 25];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8..16].copy_from_slice(&self.tree_sub_id.to_le_bytes());
        data[16] = self.level;

        data[17..25].copy_from_slice(&self.index.to_le_bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 25] {
        let mut data: [u8; 25] = [0u8; 25];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8..16].copy_from_slice(&self.tree_sub_id.to_le_bytes());
        data[16] = self.level;

        data[17..25].copy_from_slice(&self.index.to_le_bytes());
        data
    }
}
impl QPGenRandom for QMerkleStoreDoubleIdKey {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            tree_id: QPGenRandom::qp_rand_gen(),
            tree_sub_id: QPGenRandom::qp_rand_gen(),
            level: QPGenRandom::qp_rand_gen(),
            index: QPGenRandom::qp_rand_gen(),
        }
    }
}
impl QPDSerializable for QMerkleStoreDoubleIdKey {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut data: [u8; 25] = [0u8; 25];
        data[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        data[8..16].copy_from_slice(&self.tree_sub_id.to_le_bytes());
        data[16] = self.level;

        data[17..25].copy_from_slice(&self.index.to_le_bytes());
        Ok(data.to_vec())
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 25 {
            anyhow::bail!("invalid length for QMerkleStoreDoubleIdKey, expected 25 bytes, got {}", bytes.len());
        }
        Ok(Self {
            tree_id: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            tree_sub_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            level: bytes[16],
            index: u64::from_le_bytes(bytes[17..25].try_into().unwrap()),
        })
    }
}

impl QPDSerializableFixed for QMerkleStoreDoubleIdKey {
    fn get_fixed_size() -> usize {
        25
    }
}


#[pderive::serialize_copy_hash]
pub struct QMerkleStoreDoubleIdNode<Hash> {
    pub key: QMerkleStoreDoubleIdKey,
    pub hash: Hash,
}

impl<Hash: QPGenRandom> QPGenRandom for QMerkleStoreDoubleIdNode<Hash> {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        Self {
            key: QMerkleStoreDoubleIdKey::qp_rand_gen(),
            hash: QPGenRandom::qp_rand_gen(),
        }
    }
}
impl<Hash: Q256BitHash> FastFixedSerializable<57> for QMerkleStoreDoubleIdNode<Hash> {
    fn ffs_from_owned_bytes(data: [u8; 57]) -> Self {
        Self {
            key: QMerkleStoreDoubleIdKey::ffs_from_owned_bytes(data[0..25].try_into().unwrap()),
            hash: Hash::from_ref_32bytes(data[25..57].try_into().unwrap()),
        }
    }

    fn ffs_from_slice_or_panic(data: &[u8]) -> Self {
        Self {
            key: QMerkleStoreDoubleIdKey::ffs_from_slice_or_panic(&data[0..25]),
            hash: Hash::from_ref_32bytes(data[25..57].try_into().unwrap()),
        }
    }

    fn ffs_try_from_slice(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() != 57 {
            anyhow::bail!("invalid length for QMerkleStoreDoubleIdNode, expected 57 bytes, got {}", data.len());
        }
        Ok(Self {
            key: QMerkleStoreDoubleIdKey::ffs_try_from_slice(&data[0..25])?,
            hash: Hash::from_slice_32bytes(&data[25..57])?,
        })
    }

    fn ffs_to_bytes(&self) -> [u8; 57] {
        let mut data: [u8; 57] = [0u8; 57];
        data[0..25].copy_from_slice(&self.key.ffs_to_bytes());
        data[25..57].copy_from_slice(&self.hash.into_owned_32bytes());
        data
    }

    fn ffs_into_bytes(self) -> [u8; 57] {
        let mut data: [u8; 57] = [0u8; 57];
        data[0..25].copy_from_slice(&self.key.ffs_into_bytes());
        data[25..57].copy_from_slice(&self.hash.into_owned_32bytes());
        data
    }
}

pub fn convert_ffs_array_to_vec<T: FastFixedSerializable<N>, const N: usize>(data: &[T]) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::with_capacity(data.len() * N);
    for item in data {
        result.extend_from_slice(&item.ffs_to_bytes());
    }
    result
}
// for ffs only, rather than deserializing a group of groups back into the 2d
// array, we just flatten it into a 1d vec (this is what we actually want for
// our use case)
pub fn convert_ffs_group_of_groups_array_to_vec<T: FastFixedSerializable<N>, const N: usize>(data: &[Vec<T>]) -> Vec<u8> {
    let total_count = data.iter().map(|x| x.len()).sum::<usize>();

    let mut result: Vec<u8> = Vec::with_capacity(total_count * N);
    for group in data {
        for item in group {
            result.extend_from_slice(&item.ffs_to_bytes());
        }
    }
    result
}

fn gen_test_group<T: QPGenRandom + Copy + Sized>(group_size: usize) -> Vec<T> {
    let mut group: Vec<T> = Vec::with_capacity(group_size);
    for _ in 0..group_size {
        group.push(T::qp_rand_gen());
    }
    group
}
fn gen_test_group_variable_size<T: QPGenRandom + Copy + Sized>(group_size: usize, max_random_added_to_group_size: usize) -> Vec<T> {
    let real_group_size = group_size + (rand::random::<usize>() % max_random_added_to_group_size);
    let mut group: Vec<T> = Vec::with_capacity(real_group_size);
    for _ in 0..real_group_size {
        group.push(T::qp_rand_gen());
    }
    group
}
fn gen_test_group_of_groups<T: QPGenRandom + Copy + Sized>(group_size: usize, group_count: usize) -> Vec<Vec<T>> {
    let mut groups: Vec<Vec<T>> = Vec::with_capacity(group_count);
    for _ in 0..group_count {
        groups.push(gen_test_group::<T>(group_size));
    }
    groups
}
fn gen_test_group_of_groups_variable_size<T: QPGenRandom + Copy + Sized>(
    group_size: usize,
    _max_random_added_to_group_size: usize,
    group_count: usize,
) -> Vec<Vec<T>> {
    let mut groups: Vec<Vec<T>> = Vec::with_capacity(group_count);
    for _ in 0..group_count {
        groups.push(gen_test_group::<T>(group_size));
    }
    groups
}

fn gen_test_group_of_groups_variable_size_goldilocksqhash(
    group_size: usize,
    max_random_added_to_group_size: usize,
    group_count: usize,
) -> Vec<Vec<PGoldilocksHash>> {
    let mut groups: Vec<Vec<PGoldilocksHash>> = Vec::with_capacity(group_count);
    for _ in 0..group_count {
        let real_group_size = group_size + (rand::random::<usize>() % max_random_added_to_group_size);
        groups.push(fast_gen_rand_goldilocks_hashes_non_canonical_u64(real_group_size));
    }
    groups
}

pub fn convert_bytes_to_ffs_vec<T: FastFixedSerializable<N>, const N: usize>(data: &[u8]) -> anyhow::Result<Vec<T>> {
    if data.len() % N != 0 {
        anyhow::bail!("data length is not a multiple of {}", N);
    }
    let count = data.len() / N;
    let mut result: Vec<T> = Vec::with_capacity(count);
    for i in 0..count {
        let start = i * N;
        let end = start + N;
        result.push(T::ffs_from_slice_or_panic(&data[start..end]));
    }
    Ok(result)
}

pub fn benchmark_single_id_merkle_node_serialization_hash256(c: &mut Criterion) {
    let mut group = c.benchmark_group("Single Id Merkle Node Serialization - Hash256");

    type Hash = Hash256;
    for group_size in [100, 1000, 10000] {
        let leaves = gen_test_group::<QMerkleStoreSingleIdNode<Hash>>(group_size);
        //let bincode_serialized_data: Vec<u8> = bincode::serialize(&leaves).unwrap();
        let ffs_serialized_data: Vec<u8> = convert_ffs_array_to_vec(&leaves);
        let rkyv_serialized_data = rkyv::to_bytes::<rkyv::rancor::Error>(&leaves).unwrap();
        let speedy_serialized_data: Vec<u8> = leaves.write_to_vec().unwrap();

        let size_str = format!("group of {} nodes", group_size);

        // --- Serialization Benchmarks ---
        /*
        group.bench_with_input(BenchmarkId::new("serialize_bincode", &size_str), &leaves, |b, l| {
            b.iter(|| bincode::serialize(black_box(l)).unwrap());
        });
        */
        group.bench_with_input(BenchmarkId::new("serialize_ffs", &size_str), &leaves, |b, l| {
            b.iter(|| convert_ffs_array_to_vec::<QMerkleStoreSingleIdNode<Hash>, 49>(black_box(l)));
        });
        group.bench_with_input(BenchmarkId::new("serialize_rkyv", &size_str), &leaves, |b, l| {
            b.iter(|| rkyv::to_bytes::<rkyv::rancor::Error>(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("serialize_speedy", &size_str), &leaves, |b, l| {
            b.iter(|| black_box(l).write_to_vec().unwrap());
        });

        // --- Deserialization Benchmarks ---
        /*
        group.bench_with_input(BenchmarkId::new("deserialize_bincode", &size_str), &bincode_serialized_data, |b, data| {
            b.iter(|| bincode::deserialize::<Vec<QMerkleStoreSingleIdNode<Hash>>>(black_box(data)).unwrap());
        });
        */
        group.bench_with_input(BenchmarkId::new("deserialize_ffs", &size_str), &ffs_serialized_data, |b, data| {
            b.iter(|| convert_bytes_to_ffs_vec::<QMerkleStoreSingleIdNode<Hash>, 49>(black_box(data)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("deserialize_speedy", &size_str), &speedy_serialized_data, |b, data| {
            b.iter(|| Vec::<QMerkleStoreSingleIdNode<Hash>>::read_from_buffer(black_box(data)).unwrap());
        });

        // rkyv: Full deserialization (allocates and copies, like bincode)
        group.bench_with_input(BenchmarkId::new("deserialize_rkyv_full", &size_str), &rkyv_serialized_data, |b, data| {
            b.iter(|| rkyv::from_bytes::<Vec<QMerkleStoreSingleIdNode<Hash>>, rkyv::rancor::Error>(black_box(data)).unwrap());
        });
    }
    group.finish();
}

pub fn benchmark_group_of_groups_single_id_merkle_node_serialization_hash256(c: &mut Criterion) {
    let mut group = c.benchmark_group("Group of Groups Single Id Merkle Node Serialization - Hash256");
    type Hash = Hash256;
    for group_count in [100000] {
        for group_size in [200] {
            let node_groups = gen_test_group_of_groups_variable_size::<QMerkleStoreSingleIdNode<Hash>>(group_size, 50, group_count);
            //let bincode_serialized_data: Vec<Vec<u8>> = node_groups.iter().map(|x| bincode::serialize(&x).unwrap()).collect();
            let ffs_serialized_data: Vec<u8> = convert_ffs_group_of_groups_array_to_vec(&node_groups);
            let rkyv_serialized_data: Vec<Vec<u8>> = node_groups.iter().map(|x| rkyv::to_bytes::<rkyv::rancor::Error>(x).unwrap().to_vec()).collect();
            let speedy_serialized_data: Vec<Vec<u8>> = node_groups.iter().map(|x| x.write_to_vec().unwrap()).collect();

            let size_str = format!("{} groups of {} nodes", group_count, group_size);

            // --- Serialization Benchmarks ---
            /*
            group.bench_with_input(BenchmarkId::new("serialize_bincode", &size_str), &node_groups, |b, l| {
                b.iter(|| bincode::serialize(black_box(l)).unwrap());
            });
            */
            group.bench_with_input(BenchmarkId::new("serialize_ffs", &size_str), &node_groups, |b, l| {
                b.iter(|| convert_ffs_group_of_groups_array_to_vec::<QMerkleStoreSingleIdNode<Hash>, 49>(black_box(l)));
            });
            group.bench_with_input(BenchmarkId::new("serialize_rkyv", &size_str), &node_groups, |b, l| {
                b.iter(|| rkyv::to_bytes::<rkyv::rancor::Error>(black_box(l)).unwrap());
            });
            group.bench_with_input(BenchmarkId::new("serialize_speedy", &size_str), &node_groups, |b, l| {
                b.iter(|| black_box(l).write_to_vec().unwrap());
            });

            // --- Deserialization Benchmarks ---
            /*
            group.bench_with_input(BenchmarkId::new("deserialize_bincode", &size_str), &bincode_serialized_data, |b, data| {
                b.iter(|| {
                    black_box(data)
                        .iter()
                        .map(|x| bincode::deserialize::<Vec<QMerkleStoreSingleIdNode<Hash>>>(x).unwrap())
                        .collect::<Vec<_>>()
                });
            });
            */
            group.bench_with_input(BenchmarkId::new("deserialize_ffs", &size_str), &ffs_serialized_data, |b, data| {
                b.iter(|| convert_bytes_to_ffs_vec::<QMerkleStoreSingleIdNode<Hash>, 49>(black_box(data)).unwrap());
            });
            group.bench_with_input(BenchmarkId::new("deserialize_speedy", &size_str), &speedy_serialized_data, |b, data| {
                b.iter(|| {
                    black_box(data)
                        .iter()
                        .map(|x| Vec::<QMerkleStoreSingleIdNode<Hash>>::read_from_buffer(x).unwrap())
                        .collect::<Vec<_>>()
                });
            });

            // rkyv: Full deserialization (allocates and copies, like bincode)
            group.bench_with_input(BenchmarkId::new("deserialize_rkyv_full", &size_str), &rkyv_serialized_data, |b, data| {
                b.iter(|| black_box(data).iter().map(|x| rkyv::from_bytes::<Vec<QMerkleStoreSingleIdNode<Hash>>, rkyv::rancor::Error>(x).unwrap()).collect::<Vec<_>>());
            });
        }
    }
    group.finish();
}




pub fn benchmark_single_id_merkle_node_serialization_qhashout(c: &mut Criterion) {
    let mut group = c.benchmark_group("Single Id Merkle Node Serialization - QHashOut<GoldilocksField>");

    type Hash = PGoldilocksHash;
    for group_size in [100, 1000, 10000] {
        let leaves = gen_test_group::<QMerkleStoreSingleIdNode<Hash>>(group_size);
        //let bincode_serialized_data: Vec<u8> = bincode::serialize(&leaves).unwrap();
        let ffs_serialized_data: Vec<u8> = convert_ffs_array_to_vec(&leaves);
        let rkyv_serialized_data = rkyv::to_bytes::<rkyv::rancor::Error>(&leaves).unwrap();
        //let speedy_serialized_data: Vec<u8> = leaves.write_to_vec().unwrap();

        let size_str = format!("group of {} nodes", group_size);

        // --- Serialization Benchmarks ---
        /*
        group.bench_with_input(BenchmarkId::new("serialize_bincode", &size_str), &leaves, |b, l| {
            b.iter(|| bincode::serialize(black_box(l)).unwrap());
        });
        */
        group.bench_with_input(BenchmarkId::new("serialize_ffs", &size_str), &leaves, |b, l| {
            b.iter(|| convert_ffs_array_to_vec::<QMerkleStoreSingleIdNode<Hash>, 49>(black_box(l)));
        });
        group.bench_with_input(BenchmarkId::new("serialize_rkyv", &size_str), &leaves, |b, l| {
            b.iter(|| rkyv::to_bytes::<rkyv::rancor::Error>(black_box(l)).unwrap());
        });
        /*
        group.bench_with_input(BenchmarkId::new("serialize_speedy", &size_str), &leaves, |b, l| {
            b.iter(|| black_box(l).write_to_vec().unwrap());
        });
        */

        // --- Deserialization Benchmarks ---
        /*
        group.bench_with_input(BenchmarkId::new("deserialize_bincode", &size_str), &bincode_serialized_data, |b, data| {
            b.iter(|| bincode::deserialize::<Vec<QMerkleStoreSingleIdNode<Hash>>>(black_box(data)).unwrap());
        });
        */
        group.bench_with_input(BenchmarkId::new("deserialize_ffs", &size_str), &ffs_serialized_data, |b, data| {
            b.iter(|| convert_bytes_to_ffs_vec::<QMerkleStoreSingleIdNode<Hash>, 49>(black_box(data)).unwrap());
        });
        /*
        group.bench_with_input(BenchmarkId::new("deserialize_speedy", &size_str), &speedy_serialized_data, |b, data| {
            b.iter(|| Vec::<QMerkleStoreSingleIdNode<Hash>>::read_from_buffer(black_box(data)).unwrap());
        });

        */
        // rkyv: Full deserialization (allocates and copies, like bincode)
        group.bench_with_input(BenchmarkId::new("deserialize_rkyv_full", &size_str), &rkyv_serialized_data, |b, data| {
            b.iter(|| rkyv::from_bytes::<Vec<QMerkleStoreSingleIdNode<Hash>>, rkyv::rancor::Error>(black_box(data)).unwrap());
        });
    }
    group.finish();
}
fn fast_gen_rand_goldilocks_hashes_256(count: usize) -> Vec<PGoldilocksHash> {
    let mut hashes: Vec<PGoldilocksHash> = Vec::with_capacity(count);
    for _ in 0..count {
        let random_bytes: [u8; 32] = rand::random();
        hashes.push(PGoldilocksHash::from_ref_32bytes(&random_bytes));
    }
    hashes
}
fn fast_gen_rand_goldilocks_hashes_can_u63(count: usize) -> Vec<PGoldilocksHash> {
    let mut hashes: Vec<PGoldilocksHash> = Vec::with_capacity(count);
    for _ in 0..count {
        let a = rand::random::<u64>() & 0x7FFFFFFFFFFFFFFF; // 63 bits
        let b = rand::random::<u64>() & 0x7FFFFFFFFFFFFFFF; // 63 bits
        let c = rand::random::<u64>() & 0x7FFFFFFFFFFFFFFF; // 63 bits
        let d = rand::random::<u64>() & 0x7FFFFFFFFFFFFFFF; // 63 bits
        hashes.push(PGoldilocksHash::from_values(a, b, c, d));
    }
    hashes
}
fn fast_gen_rand_goldilocks_hashes_non_canonical_u64(count: usize) -> Vec<PGoldilocksHash> {
    let mut hashes: Vec<PGoldilocksHash> = Vec::with_capacity(count);
    for _ in 0..count {
        let a = rand::random::<u64>(); // 63 bits
        let b = rand::random::<u64>(); // 63 bits
        let c = rand::random::<u64>(); // 63 bits
        let d = rand::random::<u64>(); // 63 bits
        hashes.push(PGoldilocksHash::from_values(a, b, c, d));
    }
    hashes
}
pub fn benchmark_group_of_groups_single_id_merkle_node_serialization_qhashout(c: &mut Criterion) {
    let mut group = c.benchmark_group("Group of Groups Single Id Merkle Node Serialization - QHashOut<GoldilocksField>");
    type Hash = PGoldilocksHash;
    for group_count in [200000] {
        for group_size in [200] {
            let node_groups: Vec<Vec<QMerkleStoreSingleIdNode<PGoldilocksHash>>> = gen_test_group_of_groups_variable_size_goldilocksqhash(group_count, 50, group_size).into_iter().map(|z| {
                z.into_iter().map(|h|{
                    QMerkleStoreSingleIdNode { key: QMerkleStoreSingleIdKey::qp_rand_gen(), hash: h }
                }).collect::<Vec<QMerkleStoreSingleIdNode<Hash>>>()
            }).collect::<Vec<Vec<QMerkleStoreSingleIdNode<Hash>>>>();
            
            //let bincode_serialized_data: Vec<Vec<u8>> = node_groups.iter().map(|x| bincode::serialize(&x).unwrap()).collect();
            let ffs_serialized_data: Vec<u8> = convert_ffs_group_of_groups_array_to_vec(&node_groups);
            let rkyv_serialized_data: Vec<Vec<u8>> = node_groups.iter().map(|x| rkyv::to_bytes::<rkyv::rancor::Error>(x).unwrap().to_vec()).collect();
            //let speedy_serialized_data: Vec<Vec<u8>> = node_groups.iter().map(|x| x.write_to_vec().unwrap()).collect();

            let size_str = format!("{} groups of {} nodes", group_count, group_size);

            // --- Serialization Benchmarks ---
            /*
            group.bench_with_input(BenchmarkId::new("serialize_bincode", &size_str), &node_groups, |b, l| {
                b.iter(|| bincode::serialize(black_box(l)).unwrap());
            });
            */
            group.bench_with_input(BenchmarkId::new("serialize_ffs", &size_str), &node_groups, |b, l| {
                b.iter(|| convert_ffs_group_of_groups_array_to_vec::<QMerkleStoreSingleIdNode<Hash>, 49>(black_box(l)));
            });
            group.bench_with_input(BenchmarkId::new("serialize_rkyv", &size_str), &node_groups, |b, l| {
                b.iter(|| rkyv::to_bytes::<rkyv::rancor::Error>(black_box(l)).unwrap());
            });
            /*
            group.bench_with_input(BenchmarkId::new("serialize_speedy", &size_str), &node_groups, |b, l| {
                b.iter(|| black_box(l).write_to_vec().unwrap());
            });
            */
            // --- Deserialization Benchmarks ---
            /*
            group.bench_with_input(BenchmarkId::new("deserialize_bincode", &size_str), &bincode_serialized_data, |b, data| {
                b.iter(|| {
                    black_box(data)
                        .iter()
                        .map(|x| bincode::deserialize::<Vec<QMerkleStoreSingleIdNode<Hash>>>(x).unwrap())
                        .collect::<Vec<_>>()
                });
            });
            */
            group.bench_with_input(BenchmarkId::new("deserialize_ffs", &size_str), &ffs_serialized_data, |b, data| {
                b.iter(|| convert_bytes_to_ffs_vec::<QMerkleStoreSingleIdNode<Hash>, 49>(black_box(data)).unwrap());
            });
            /*
            group.bench_with_input(BenchmarkId::new("deserialize_speedy", &size_str), &speedy_serialized_data, |b, data| {
                b.iter(|| {
                    black_box(data)
                        .iter()
                        .map(|x| Vec::<QMerkleStoreSingleIdNode<Hash>>::read_from_buffer(x).unwrap())
                        .collect::<Vec<_>>()
                });
            });*/

            // rkyv: Full deserialization (allocates and copies, like bincode)
            group.bench_with_input(BenchmarkId::new("deserialize_rkyv_full", &size_str), &rkyv_serialized_data, |b, data| {
                b.iter(|| black_box(data).iter().map(|x| rkyv::from_bytes::<Vec<QMerkleStoreSingleIdNode<Hash>>, rkyv::rancor::Error>(x).unwrap()).collect::<Vec<_>>());
            });
        }
    }
    group.finish();
}
