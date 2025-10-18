use parth_core::{felt::ToU64Value, pgoldilocks::QHashOut, utils::QPGenRandom, PF};
use psy_data::v1::qdata::user::PQEDUserLeaf;
use psy_serialize::FastFixedSerializable;


fn main() {

    let mut p = PQEDUserLeaf::<PF, QHashOut<PF>> {
        public_key: QHashOut::rand(),
        user_state_tree_root: QHashOut::rand(),
        balance: PF::qp_rand_gen(),
        nonce: PF::from_owned_u64(1),
        last_checkpoint_id: PF::from_owned_u64(10),
        event_index: PF::from_owned_u64(0),
        user_id: PF::from_owned_u64(42),
    };
    let original_p = p.clone();
    println!("Original struct: {:?}", p);

    let mut ser: [u8; 104] = p.ffs_into_bytes();
    let start = std::time::Instant::now();
    const TOTAL_ITERATIONS: usize = 10_000_000;
    let mut ctr = 0u64;
    for _ in 0..TOTAL_ITERATIONS {
        ctr += 123;
        ser = p.ffs_into_bytes();
        ser[0] = ((ctr>>4) & 0xFF) as u8;
        p = PQEDUserLeaf::<PF, QHashOut<PF>>::ffs_from_owned_bytes(ser);
        p.balance = PF::from_owned_u64(ctr);
    }
    println!("Ctr: {}", ctr);
    let duration = start.elapsed();
    println!("{} round trips took: {:?}", TOTAL_ITERATIONS, duration);
    println!("Average per round trip: {:?}", duration / TOTAL_ITERATIONS as u32);
    let ser = p.ffs_into_bytes();
    println!("Serialized bytes: {:?}", ser);
    let de = PQEDUserLeaf::<PF, QHashOut<PF>>::ffs_from_owned_bytes(ser);
    println!("Deserialized struct: {:?}", de);
    assert_ne!(de, original_p);
    assert_ne!(p, original_p);

}



