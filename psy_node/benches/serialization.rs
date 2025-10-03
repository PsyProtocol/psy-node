use anyhow::Result;
use criterion::Criterion;
use parth_core::{
    crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, sha256::CoreSha256Hasher, traits::{MerkleHasher, MerkleZeroHasher, RandomHash}},
    data::{
        db::row::{
            QDatabaseDoubleIdTableRow, QDatabaseDoubleIdTableRowNoCheckpointId, QDatabaseKeyIdValueTableRow, QDatabaseSingleIdTableRow, QDoubleIdKey,
        },
        hash::hash256::Hash256,
        serializable::{QPDPair, QPDPairWithCheckpointId},
    },
    protocol::core_types::QHashBase,
};
use parth_p2::core::hash::{qhashout::QHashOut, traits::PoseidonHasher};
use plonky2::{field::{goldilocks_field::GoldilocksField, types::Sample}, hash::hash_types::RichField};
use rand::{thread_rng, Rng};
use rkyv::rancor;
use serde::{Deserialize, Serialize};
use speedy::{Readable, Writable};
trait ExSer {
    fn to_bytes(&self) -> Result<Vec<u8>>;
    fn from_bytes(bytes: &[u8]) -> Result<Self> where Self: Sized;
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, speedy::Readable, speedy::Writable)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct UPSEndCapResultCompact<F: RichField> {
    pub start_user_leaf_hash: QHashOut<F>,
    pub end_user_leaf_hash: QHashOut<F>,
    pub checkpoint_tree_root_hash: QHashOut<F>,
    pub user_id: F,
}
impl<F: RichField> UPSEndCapResultCompact<F> {
    pub fn new_empty(user_id: F) -> Self {
        Self {
            start_user_leaf_hash: QHashOut::<F>::ZERO,
            end_user_leaf_hash: QHashOut::<F>::ZERO,
            checkpoint_tree_root_hash: QHashOut::<F>::ZERO,
            user_id,
        }
    }
    pub fn new_random(user_id: F) -> Self {
        Self {
            start_user_leaf_hash: QHashOut::<F>::rand_hash(),
            end_user_leaf_hash: QHashOut::<F>::rand_hash(),
            checkpoint_tree_root_hash: QHashOut::<F>::rand_hash(),
            user_id,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, speedy::Readable, speedy::Writable)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct SubmitUserEndCapNonProofCoreInput<F: RichField> {
    pub checkpoint_id: F,
    pub stats: GUTAStats<F>,
    pub state_transition: UPSEndCapResultCompact<F>,
    pub new_user_leaf: QEDUserLeaf<F>,
}
impl<F: RichField> SubmitUserEndCapNonProofCoreInput<F> {
    pub fn new_empty(user_id: F) -> Self {
        Self {
            checkpoint_id: F::ZERO,
            stats: GUTAStats::<F>::new_empty(),
            state_transition: UPSEndCapResultCompact::<F>::new_empty(user_id),
            new_user_leaf: QEDUserLeaf::<F>::new_empty(user_id),
        }
    }
    pub fn new_random() -> Self {
        let mut rng = thread_rng();
        let user_id = F::rand();
        Self {
            checkpoint_id: F::rand(),
            stats: GUTAStats::<F>::new_random(),
            state_transition: UPSEndCapResultCompact::<F>::new_random(user_id),
            new_user_leaf: QEDUserLeaf::<F>::new_random(user_id),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, speedy::Readable, speedy::Writable)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct GUTAStats<F: RichField> {
    pub fees_collected: F,

    pub user_ops_processed: F,
    pub total_transactions: F,

    pub slots_modified: F,
}
impl<F: RichField> GUTAStats<F> {
    pub fn new_empty() -> Self {
        Self {
            fees_collected: F::ZERO,
            user_ops_processed: F::ZERO,
            total_transactions: F::ZERO,
            slots_modified: F::ZERO,
        }
    }
    pub fn new_random() -> Self {
        let mut rng = thread_rng();
        Self {
            fees_collected: F::rand(),
            user_ops_processed: F::rand(),
            total_transactions: F::rand(),
            slots_modified: F::rand(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, rkyv::Serialize, rkyv::Deserialize, rkyv::Archive, speedy::Readable, speedy::Writable)]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct QEDUserLeaf<F: RichField> {
    pub public_key: QHashOut<F>,
    pub user_state_tree_root: QHashOut<F>,
    pub balance: F,
    pub nonce: F,
    pub last_checkpoint_id: F,
    pub event_index: F,
    pub user_id: F,
}

impl<F: RichField> QEDUserLeaf<F> {
    pub fn new_empty(user_id: F) -> Self {
        Self {
            public_key: QHashOut::<F>::ZERO,
            user_state_tree_root: QHashOut::<F>::ZERO,
            balance: F::ZERO,
            nonce: F::ZERO,
            last_checkpoint_id: F::ZERO,
            event_index: F::ZERO,
            user_id,
        }
    }
    pub fn new_random(user_id: F) -> Self {
        Self {
            public_key: QHashOut::<F>::rand_hash(),
            user_state_tree_root: QHashOut::<F>::rand_hash(),
            balance: F::rand(),
            nonce: F::rand(),
            last_checkpoint_id: F::rand(),
            event_index: F::rand(),
            user_id,
        }
    }
}

fn generate_random_merkle_proof<Hash: PartialEq + Copy + RandomHash, H: MerkleHasher<Hash>>(tree_height: u8) -> MerkleProofCore<Hash> {
    let mut rng = thread_rng();
    let siblings = (0..(tree_height as usize))
        .map(|_| Hash::rand_hash())
        .collect();
    let value = Hash::rand_hash();
    let index = rng.gen::<u64>() % (1 << tree_height);

    MerkleProofCore::<Hash>::new_from_params::<H>(index, value, siblings)
}
fn generate_random_delta_merkle_proof<Hash: PartialEq + Copy + RandomHash, H: MerkleHasher<Hash>>(tree_height: u8) -> DeltaMerkleProofCore<Hash> {
    let mut rng = thread_rng();
    let siblings = (0..(tree_height as usize))
        .map(|_| Hash::rand_hash())
        .collect();
    let old_value = Hash::rand_hash();
    let new_value = Hash::rand_hash();
    let index = rng.gen::<u64>() % (1 << tree_height);

    DeltaMerkleProofCore::<Hash>::from_params::<H>(index, old_value, new_value, siblings)
}

fn bench_object_ops(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("serialization_v1");

    type F = GoldilocksField;
    type Hash = QHashOut<F>;
    type Hasher = PoseidonHasher;

    let basic_qhashout = QHashOut::<GoldilocksField>::rand_hash();

    let simple_merkle_proof_pgl: MerkleProofCore<Hash> = generate_random_merkle_proof::<Hash, Hasher>(32);
    let delta_merkle_proof_pgl: DeltaMerkleProofCore<Hash> = generate_random_delta_merkle_proof::<Hash, Hasher>(32);
    let fixed_hash_array_pgl: [Hash; 32] = core::array::from_fn(|_| QHashOut::<GoldilocksField>::rand_hash());

    let simple_merkle_proof_h256: MerkleProofCore<Hash256> = generate_random_merkle_proof::<Hash256, CoreSha256Hasher>(32);
    let delta_merkle_proof_h256: DeltaMerkleProofCore<Hash256> = generate_random_delta_merkle_proof::<Hash256, CoreSha256Hasher>(32);
    let fixed_hash_array_h256: [Hash256; 32] = core::array::from_fn(|_| Hash256::rand_hash());

    let user_leaf = QEDUserLeaf::<F>::new_random(F::rand());
    let ups_endcap = UPSEndCapResultCompact::<F>::new_random(F::rand());
    let submit_user_endcap_input = SubmitUserEndCapNonProofCoreInput::<F>::new_random();
    group.bench_function("serialize_qhashout_bincode", |b| {
        b.iter(|| {
            let _ = bincode::serialize(&basic_qhashout).unwrap();
        });
    });
    group.bench_function("deserialize_qhashout_bincode", |b| {
        let serialized = bincode::serialize(&basic_qhashout).unwrap();
        b.iter(|| {
            let _: QHashOut<F> = bincode::deserialize(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_qhashout_postcard", |b| {
        b.iter(|| {
            let _ = postcard::to_stdvec(&basic_qhashout).unwrap();
        });
    });
    group.bench_function("deserialize_qhashout_postcard", |b| {
        let serialized = postcard::to_stdvec(&basic_qhashout).unwrap();
        b.iter(|| { 
            let _: QHashOut<F> = postcard::from_bytes(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_simple_merkle_proof_pgl_bincode", |b| {
        b.iter(|| {
            let _ = bincode::serialize(&simple_merkle_proof_pgl).unwrap();
        });
    });
    group.bench_function("deserialize_simple_merkle_proof_pgl_bincode", |b| {
        let serialized = bincode::serialize(&simple_merkle_proof_pgl).unwrap();
        b.iter(|| {
            let _: MerkleProofCore<Hash> = bincode::deserialize(&serialized).unwrap();
        }); 
    }); 
    group.bench_function("serialize_simple_merkle_proof_pgl_postcard", |b| {
        b.iter(|| {
            let _ = postcard::to_stdvec(&simple_merkle_proof_pgl).unwrap();
        });
    });
    group.bench_function("deserialize_simple_merkle_proof_pgl_postcard", |b| {
        let serialized = postcard::to_stdvec(&simple_merkle_proof_pgl).unwrap();
        b.iter(|| {
            let _: MerkleProofCore<Hash> = postcard::from_bytes(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_delta_merkle_proof_pgl_bincode", |b| {
        b.iter(|| {
            let _ = bincode::serialize(&delta_merkle_proof_pgl).unwrap();
        });
    });
    group.bench_function("deserialize_delta_merkle_proof_pgl_bincode", |b| {
        let serialized = bincode::serialize(&delta_merkle_proof_pgl).unwrap();
        b.iter(|| {
            let _: DeltaMerkleProofCore<Hash> = bincode::deserialize(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_delta_merkle_proof_pgl_postcard", |b| {
        b.iter(|| {
            let _ = postcard::to_stdvec(&delta_merkle_proof_pgl).unwrap();
        });
    });
    group.bench_function("deserialize_delta_merkle_proof_pgl_postcard", |b| {
        let serialized = postcard::to_stdvec(&delta_merkle_proof_pgl).unwrap();
        b.iter(|| {
            let _: DeltaMerkleProofCore<Hash> = postcard::from_bytes(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_fixed_hash_array_pgl_bincode", |b| {
        b.iter(|| {
            let _ = bincode::serialize(&fixed_hash_array_pgl).unwrap();
        });
    });
    group.bench_function("deserialize_fixed_hash_array_pgl_bincode", |b| {
        let serialized = bincode::serialize(&fixed_hash_array_pgl).unwrap();
        b.iter(|| {
            let _: [Hash; 32] = bincode::deserialize(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_fixed_hash_array_pgl_postcard", |b| {
        b.iter(|| {
            let _ = postcard::to_stdvec(&fixed_hash_array_pgl).unwrap();
        });
    });
    group.bench_function("deserialize_fixed_hash_array_pgl_postcard", |b| {
        let serialized = postcard::to_stdvec(&fixed_hash_array_pgl).unwrap();
        b.iter(|| {
            let _: [Hash; 32] = postcard::from_bytes(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_simple_merkle_proof_h256_bincode", |b| {
        b.iter(|| {
            let _ = bincode::serialize(&simple_merkle_proof_h256).unwrap();
        });
    });
    group.bench_function("deserialize_simple_merkle_proof_h256_bincode", |b| {
        let serialized = bincode::serialize(&simple_merkle_proof_h256).unwrap();
        b.iter(|| {
            let _: MerkleProofCore<Hash256> = bincode::deserialize(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_simple_merkle_proof_h256_postcard", |b| {
        b.iter(|| { 
            let _ = postcard::to_stdvec(&simple_merkle_proof_h256).unwrap();
        });
    });
    group.bench_function("deserialize_simple_merkle_proof_h256_postcard", |b| {
        let serialized = postcard::to_stdvec(&simple_merkle_proof_h256).unwrap();
        b.iter(|| {
            let _: MerkleProofCore<Hash256> = postcard::from_bytes(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_delta_merkle_proof_h256_bincode", |b| {
        b.iter(|| {
            let _ = bincode::serialize(&delta_merkle_proof_h256).unwrap();
        });
    });
    group.bench_function("deserialize_delta_merkle_proof_h256_bincode", |b| {
        let serialized = bincode::serialize(&delta_merkle_proof_h256).unwrap();
        b.iter(|| {
            let _: DeltaMerkleProofCore<Hash256> = bincode::deserialize(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_delta_merkle_proof_h256_postcard", |b| {
        b.iter(|| {
            let _ = postcard::to_stdvec(&delta_merkle_proof_h256).unwrap();
        });
    });
    group.bench_function("deserialize_delta_merkle_proof_h256_postcard", |b| {
        let serialized = postcard::to_stdvec(&delta_merkle_proof_h256).unwrap();
        b.iter(|| {
            let _: DeltaMerkleProofCore<Hash256> = postcard::from_bytes(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_fixed_hash_array_h256_bincode", |b| {
        b.iter(|| {
            let _ = bincode::serialize(&fixed_hash_array_h256).unwrap();
        });
    });
    group.bench_function("deserialize_fixed_hash_array_h256_bincode", |b| {
        let serialized = bincode::serialize(&fixed_hash_array_h256).unwrap();
        b.iter(|| {     
            let _: [Hash256; 32] = bincode::deserialize(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_fixed_hash_array_h256_postcard", |b| {
        b.iter(|| {
            let _ = postcard::to_stdvec(&fixed_hash_array_h256).unwrap();
        });
    });
    group.bench_function("deserialize_fixed_hash_array_h256_postcard", |b| {
        let serialized = postcard::to_stdvec(&fixed_hash_array_h256).unwrap();
        b.iter(|| {
            let _: [Hash256; 32] = postcard::from_bytes(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_delta_merkle_proof_h256_rkyv", |b| {
        b.iter(|| {
            let _ = rkyv::to_bytes::<rancor::Error>(&delta_merkle_proof_h256).unwrap();
        });
    });
    group.bench_function("serialize_delta_merkle_proof_h256_speedy", |b| {
        b.iter(|| {
            let _ = delta_merkle_proof_h256.write_to_vec().unwrap();
        });
    });
    group.bench_function("deserialize_delta_merkle_proof_h256_speedy", |b| {
        let serialized = delta_merkle_proof_h256.write_to_vec().unwrap();
        b.iter(|| {
            let _: DeltaMerkleProofCore<Hash256> = DeltaMerkleProofCore::read_from_buffer(&serialized).unwrap();
        });
    });

    group.bench_function("serialize_user_leaf_h256_bincode", |b| {
        b.iter(|| {
            let _ = bincode::serialize(&user_leaf).unwrap();
        });
    });
    group.bench_function("deserialize_user_leaf_h256_bincode", |b| {
        let serialized = bincode::serialize(&user_leaf).unwrap();
        b.iter(|| {
            let _: QEDUserLeaf<F> = bincode::deserialize(&serialized).unwrap();
        });
    });
    group.bench_function("serialize_user_leaf_h256_postcard", |b| {
        b.iter(|| {
            let _ = postcard::to_stdvec(&user_leaf).unwrap();
        });
    });
}

criterion::criterion_group!(benches, bench_object_ops);
criterion::criterion_main!(benches);
