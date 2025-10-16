use bytemuck::{Pod, Zeroable};
use parth_core::{crypto::hash::traits::RandomHash, data::serializable::FastFixedSerializable, felt::FromPrimitiveValuesFelt, pgoldilocks::QHashOut, PF};
use psy_data::v1::qdata::user::PQEDUserLeaf;

#[inline(always)]
pub fn test_a(x: PQEDUserLeaf<PF, QHashOut<PF>>) -> [u8; 104] {
     x.ffs_into_bytes()
}
#[inline(always)]
pub fn test_a_back(x: [u8; 104]) ->  PQEDUserLeaf<PF, QHashOut<PF>> {
     PQEDUserLeaf::<PF, QHashOut<PF>>::ffs_from_owned_bytes(x)
}
fn main() {

    let mut p = PQEDUserLeaf {
        public_key: QHashOut::rand_hash(),
        user_state_tree_root: QHashOut::rand_hash(),
        balance: PF::from_u64_value(100),
        nonce: PF::from_u64_value(1),
        last_checkpoint_id: PF::from_u64_value(10),
        event_index: PF::from_u64_value(0),
        user_id: PF::from_u64_value(42),
    };

    let mut ser: [u8; 104] = test_a(p);
    let start = std::time::Instant::now();
    for _ in 0..1_000_000 {
        ser = test_a(p);
        p = test_a_back(ser);
    }
    let duration = start.elapsed();
    println!("10 million round trips took: {:?}", duration);
    println!("Average per round trip: {:?}", duration / 10000000);
    let ser = test_a(p);
    println!("Serialized bytes: {:?}", ser);
    let de = PQEDUserLeaf::<PF, QHashOut<PF>>::ffs_from_owned_bytes(ser);
    println!("Deserialized struct: {:?}", de);
    assert_eq!(p, de);

}

