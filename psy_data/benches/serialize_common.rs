// allow dead code for benches
#![allow(dead_code)]
use criterion::{black_box, BenchmarkId, Criterion};
use parth_core::{data::{hash::hash256::Hash256, maybe_serialization::MaybeSpeedy}, felt::{QFelt, QFelt64}, generic_traits::QNamedType, pgoldilocks::{PGoldilocksFelt, PGoldilocksHash}, protocol::core_types::{QDBHashBase, QFHashBase}, utils::QPGenRandom, PHash, PF};
use psy_data::v1::qdata::{contract::ContractFunctionCodeDefinition, user::PQEDUserLeaf};
use psy_serialize::{FastFixedSerializable, PsyCanonicalDatabaseSerializeBaseMulti, PsyCanonicalDatabaseSerializeBaseSingle, PsyIOReadWrite};

use speedy::{Readable, Writable};
trait BenchFastRand {
    fn bench_rand_gen_fast() -> Self;
}
impl BenchFastRand for Hash256 {
    fn bench_rand_gen_fast() -> Self {
        Hash256::rand()
    }
}
impl BenchFastRand for PGoldilocksHash {
    fn bench_rand_gen_fast() -> Self {
        PGoldilocksHash::from_hash256_le(Hash256::rand())
    }
}
impl BenchFastRand for PGoldilocksFelt {
    fn bench_rand_gen_fast() -> Self {
        PGoldilocksFelt::qp_rand_gen()
    }
}

impl<F: BenchFastRand, Hash: BenchFastRand> BenchFastRand for PQEDUserLeaf<F, Hash> {
    fn bench_rand_gen_fast() -> Self {
        PQEDUserLeaf {
            user_id: F::bench_rand_gen_fast(),
            user_state_tree_root: Hash::bench_rand_gen_fast(),
            public_key: Hash::bench_rand_gen_fast(),
            balance: F::bench_rand_gen_fast(),
            nonce: F::bench_rand_gen_fast(),
            last_checkpoint_id: F::bench_rand_gen_fast(),
            event_index: F::bench_rand_gen_fast(),
        }
    }
}
fn gen_random_user_leaves<F: BenchFastRand, Hash: BenchFastRand>(count: usize) -> Vec<PQEDUserLeaf<F, Hash>> {
    let mut users = Vec::with_capacity(count);
    for _ in 0..count {
        users.push(PQEDUserLeaf::bench_rand_gen_fast());
    }
    users
}
fn benckmark_serialize_round_trip_user_leaf_internal<F: BenchFastRand + QFelt64 + QFelt + MaybeSpeedy,  Hash: BenchFastRand + QDBHashBase + QFHashBase<F>>(c: &mut Criterion, user_counts: &[usize]) {
    let mut group = c.benchmark_group(format!("serialize_user_leaf{}_v333", Hash::q_type_name()));


    // We test with a variety of input sizes to see how performance scales.
    for count in user_counts.iter() {
        // Generate the test data once per size.
        let items = gen_random_user_leaves::<F, Hash>(*count);

        let bincode_bytes = bincode::serialize(&items).expect("Bincode serialization should succeed");
        let canonical_bytes = PQEDUserLeaf::psy_ser_serialize_vec_of_self_ref(&items, false);
        let postcard_bytes = postcard::to_stdvec(&items).expect("Postcard serialization should succeed");


        //let ex_1 = items[0].user_id.write_to_vec()
        
        // Benchmark the naive implementation
        group.bench_with_input(BenchmarkId::new("serialize_bincode", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||bincode::serialize(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("serialize_speedy", *count), &items, |b, l| {
            b.iter(||black_box(l).write_to_vec().unwrap());
        });
        group.bench_with_input(BenchmarkId::new("serialize_postcard", *count), &items, |b, l| {
            b.iter(||postcard::to_stdvec(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("serialize_ffs_vec_of_self_ref", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| PQEDUserLeaf::ffs_serialize_vec_of_self_ref(black_box(l)));
        });
        group.bench_with_input(BenchmarkId::new("serialize_psy_ser_serialize_vec_of_self_ref", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| PQEDUserLeaf::psy_ser_serialize_vec_of_self_ref(black_box(l), false));
        });
        group.bench_with_input(BenchmarkId::new("serialize_psy_ser_serialize_vec_of_self", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| PQEDUserLeaf::psy_ser_serialize_vec_of_self(black_box(l).clone(), false));
        });
        group.bench_with_input(BenchmarkId::new("serialize_pio_write_many_to_bytes", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| PQEDUserLeaf::pio_write_many_to_bytes(&black_box(l), false));
        });


        
        // Benchmark the naive implementation
        group.bench_with_input(BenchmarkId::new("deserialize_bincode", *count), &bincode_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||bincode::deserialize::<Vec<PQEDUserLeaf<F, Hash>>>(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("deserialize_postcard", *count), &postcard_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||postcard::from_bytes::<Vec<PQEDUserLeaf<F, Hash>>>(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("ffs_deserialize_vec_of_self", *count), &canonical_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| PQEDUserLeaf::<F, Hash>::ffs_deserialize_vec_of_self(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("psy_ser_deserialize_vec_of_self", *count), &canonical_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| PQEDUserLeaf::<F, Hash>::psy_ser_deserialize_vec_of_self(black_box(l), false));
        });
        group.bench_with_input(BenchmarkId::new("deserialize_pio_write_many_to_bytes", *count), &canonical_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| PQEDUserLeaf::<F, Hash>::pio_read_many_from_ref_bytes(&black_box(l), None));
        });


        
    }
    group.finish();
}


fn benckmark_serialize_round_trip_user_leaf_internal_known_type(c: &mut Criterion, user_counts: &[usize]) {
    type Hash = PHash;
    type F = PF;
    type ItemType = PQEDUserLeaf<F, Hash>;
    let mut group = c.benchmark_group(format!("serialize_user_leaf{}_v333", Hash::q_type_name()));


    // We test with a variety of input sizes to see how performance scales.
    for count in user_counts.iter() {
        // Generate the test data once per size.
        let items = gen_random_user_leaves::<F, Hash>(*count);
        //let speedy_bytes = items.write_to_vec().expect("Serialization should succeed");

        let bincode_bytes = bincode::serialize(&items).expect("Bincode serialization should succeed");
        let canonical_bytes = PQEDUserLeaf::psy_ser_serialize_vec_of_self_ref(&items, false);
        let postcard_bytes = postcard::to_stdvec(&items).expect("Postcard serialization should succeed");

        let rkyv_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&items).expect("Rkyv serialization should succeed");
        


        //let ex_1 = items[0].user_id.write_to_vec()
        
        // Benchmark the naive implementation
        group.bench_with_input(BenchmarkId::new("serialize_bincode", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||bincode::serialize(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("serialize_speedy", *count), &items, |b, l| {
            b.iter(||black_box(l).write_to_vec().unwrap());
        });
        group.bench_with_input(BenchmarkId::new("serialize_postcard", *count), &items, |b, l| {
            b.iter(||postcard::to_stdvec(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("serialize_rkyv", *count), &items, |b, l| {
            b.iter(||rkyv::to_bytes::<rkyv::rancor::Error>(black_box(l)).unwrap());
        });
        /*
        group.bench_with_input(BenchmarkId::new("serialize_ffs_vec_of_self_ref", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| ItemType::ffs_serialize_vec_of_self_ref(black_box(l)));
        });
        */
        group.bench_with_input(BenchmarkId::new("serialize_psy_ser_serialize_vec_of_self_ref", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| ItemType::psy_ser_serialize_vec_of_self_ref(black_box(l), false));
        });
        /*
        group.bench_with_input(BenchmarkId::new("serialize_psy_ser_serialize_vec_of_self", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| ItemType::psy_ser_serialize_vec_of_self(black_box(l).clone(), false));
        });
        group.bench_with_input(BenchmarkId::new("serialize_pio_write_many_to_bytes", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| ItemType::pio_write_many_to_bytes(&black_box(l), false));
        });*/


        
        // Benchmark the naive implementation
        group.bench_with_input(BenchmarkId::new("deserialize_bincode", *count), &bincode_bytes, |b, l| {
            b.iter(||bincode::deserialize::<Vec<ItemType>>(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("deserialize_postcard", *count), &postcard_bytes, |b, l| {
            b.iter(||postcard::from_bytes::<Vec<ItemType>>(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("deserialize_speedy", *count), &canonical_bytes, |b, l| {
            b.iter(|| ItemType::read_from_buffer(black_box(l)).unwrap());
        });
        /*
        group.bench_with_input(BenchmarkId::new("ffs_deserialize_vec_of_self", *count), &canonical_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| ItemType::ffs_deserialize_vec_of_self(black_box(l)).unwrap());
        });*/
        group.bench_with_input(BenchmarkId::new("psy_ser_deserialize_vec_of_self", *count), &canonical_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| ItemType::psy_ser_deserialize_vec_of_self(black_box(l), false));
        });
        /*
        group.bench_with_input(BenchmarkId::new("deserialize_pio_write_many_to_bytes", *count), &canonical_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| ItemType::pio_read_many_from_ref_bytes(&black_box(l), None));
        });
        */
        group.bench_with_input("deserialize_rkyv_many", &rkyv_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| {
                rkyv::from_bytes::<Vec<ItemType>, rkyv::rancor::Error>(black_box(l)).unwrap();
            });
        });


        
    }
    group.finish();
}



pub fn benckmark_serialize_round_trip_contract_function(c: &mut Criterion) {
    let contract_function_counts: [usize; 2] = [100, 1000];
    let mut group = c.benchmark_group(format!("serialize_contract_functions_v1"));

    type ItemType = ContractFunctionCodeDefinition;
        let items = ItemType::qp_rand_gen();

        let speedy_bytes = items.write_to_vec().expect("Serialization should succeed");
        let bincode_bytes = bincode::serialize(&items).expect("Bincode serialization should succeed");
        let postcard_bytes = postcard::to_stdvec(&items).expect("Postcard serialization should succeed");
        let rkyv_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&items).expect("Rkyv serialization should succeed");
        let canonical_bytes = items.psy_ser_to_bytes_vec().expect("Psy Canonical Serialization should succeed");




        //let ex_1 = items[0].user_id.write_to_vec()

        
        // Benchmark the naive implementation
        group.bench_with_input("con_serialize_bincode_single", &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||bincode::serialize(black_box(l)).unwrap());
        });
        group.bench_with_input("con_serialize_speedy_single", &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||black_box(l).write_to_vec().unwrap());
        });
        group.bench_with_input("con_serialize_psy_canonical_single", &items, |b, l| {
            b.iter(||black_box(l).psy_ser_to_bytes_vec().unwrap());
        });
        group.bench_with_input("con_serialize_postcard_single", &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||postcard::to_stdvec(black_box(l)).unwrap());
        });
        group.bench_with_input("con_serialize_rkyv_single", &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||rkyv::to_bytes::<rkyv::rancor::Error>(black_box(l)).unwrap());
        });


        
        // Benchmark the naive implementation
        group.bench_with_input("con_deserialize_bincode_single", &bincode_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||bincode::deserialize::<ItemType>(black_box(l)).unwrap());
        });
        group.bench_with_input("con_deserialize_speedy_single", &speedy_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||ItemType::read_from_buffer(black_box(l)).unwrap());
        });
        group.bench_with_input("con_deserialize_psy_canonical_single", &canonical_bytes, |b, l| {
            b.iter(||ItemType::psy_ser_from_slice(black_box(l)).unwrap());
        });
        group.bench_with_input("con_deserialize_postcard_single", &postcard_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||postcard::from_bytes::<ItemType>(black_box(l)).unwrap());
        });
        group.bench_with_input("con_deserialize_rkyv_single", &rkyv_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| {
                rkyv::from_bytes::<ItemType, rkyv::rancor::Error>(black_box(l)).unwrap();
            });
        });

    // We test with a variety of input sizes to see how performance scales.
    for count in contract_function_counts.iter() {
        // Generate the test data once per size.
        let items = ItemType::qp_rand_gen_vec(*count);

        let speedy_bytes = items.write_to_vec().expect("Serialization should succeed");
        let bincode_bytes = bincode::serialize(&items).expect("Bincode serialization should succeed");
        let postcard_bytes = postcard::to_stdvec(&items).expect("Postcard serialization should succeed");
        let rkyv_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&items).expect("Rkyv serialization should succeed");
        let canonical_bytes = ItemType::psy_ser_serialize_vec_of_self_ref(&items, false);



        //let ex_1 = items[0].user_id.write_to_vec()
        
        // Benchmark the naive implementation
        group.bench_with_input(BenchmarkId::new("con_serialize_bincode", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||bincode::serialize(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("con_serialize_speedy", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||black_box(l).write_to_vec().unwrap());
        });
        group.bench_with_input(BenchmarkId::new("con_serialize_psy_canonical", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||ItemType::psy_ser_serialize_vec_of_self_ref(black_box(l), false));
        });
        group.bench_with_input(BenchmarkId::new("con_serialize_postcard", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||postcard::to_stdvec(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("con_serialize_rkyv", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||rkyv::to_bytes::<rkyv::rancor::Error>(black_box(l)).unwrap());
        });
        


        // Benchmark the naive implementation
        group.bench_with_input(BenchmarkId::new("con_deserialize_bincode", *count), &bincode_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||bincode::deserialize::<Vec<ItemType>>(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("con_deserialize_speedy", *count), &speedy_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||Vec::<ItemType>::read_from_buffer(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("con_deserialize_psy_canonical", *count), &canonical_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||ItemType::psy_ser_deserialize_vec_of_self(black_box(l), false).unwrap());
        });

        group.bench_with_input(BenchmarkId::new("con_deserialize_postcard", *count), &postcard_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||postcard::from_bytes::<Vec<ItemType>>(black_box(l)).unwrap());
        });
    
        group.bench_with_input(BenchmarkId::new("con_deserialize_rkyv", *count), &rkyv_bytes, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(|| {
                rkyv::from_bytes::<Vec<ItemType>, rkyv::rancor::Error>(black_box(l)).unwrap();
            });
        });

        
    }
    group.finish();
}


pub fn benckmark_serialization(c: &mut Criterion) {
    //let linear_hash_counts = vec![1, 10, 100, 1_000, 10_000];
    //let hash_iterations = vec![1, 10, 100, 1_000, 10_000, 100_000];
    //let merkle_tree_heights = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];


    //let linear_hash_counts = vec![10_000];
    //let hash_iterations = vec![10_000];
    //let merkle_tree_heights = vec![16];
    type F = PF;
    type Hash = PHash;

    //benckmark_serialize_round_trip_user_leaf_internal::<F, Hash>(c, &[10_000, 100_000]);
    benckmark_serialize_round_trip_user_leaf_internal_known_type(c, &[10_000, 100_000]);
}


    
