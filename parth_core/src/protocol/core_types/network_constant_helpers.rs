use crate::protocol::core_types::QNetworkTreeConstants;

#[inline]
pub const fn get_max_guta_circuit_merkle_tree_height<T: QNetworkTreeConstants>() -> usize {
    if T::REALM_GLOBAL_USER_TREE_HEIGHT_USIZE >= T::COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE {
        T::REALM_GLOBAL_USER_TREE_HEIGHT_USIZE
    } else {
        T::COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE
    } 
}