// start ptypes_u64_hash256
// PF = u64, PHash = Hash256
#[cfg(feature = "ptypes_u64_hash256")]
pub type PF = u64;
#[cfg(feature = "ptypes_u64_hash256")]
pub type PHash = crate::data::hash::hash256::Hash256;
// end ptypes_u64_hash256


// start ptypes_goldilocks_qhashout 
// PF = GoldilocksField, PHash = QHashOut<GoldilocksField>
#[cfg(feature = "ptypes_goldilocks_qhashout")]
pub type PF = crate::pgoldilocks::PGoldilocksFelt;
#[cfg(feature = "ptypes_goldilocks_qhashout")]
pub type PHash = crate::pgoldilocks::PGoldilocksHash;
// end ptypes_goldilocks_qhashout


// start default ptype fallback
// PF = u64, PHash = Hash256
#[cfg(not(any(
    feature = "ptypes_u64_hash256",
    feature = "ptypes_goldilocks_qhashout"
)))]
pub type PF = u64;

#[cfg(not(any(
    feature = "ptypes_u64_hash256",
    feature = "ptypes_goldilocks_qhashout"
)))]
pub type PHash = crate::data::hash::hash256::Hash256;
// end default ptype fallback


