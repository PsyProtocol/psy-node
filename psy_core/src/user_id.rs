pub fn reverse_bits_in_limit(x: u64, num_bits: u8) -> u64 {
    let dif = 64 - num_bits as u64;
    (x).reverse_bits() >> dif
}

pub fn get_user_id_from_registration_id<const GROUP_REALM_HEIGHT: u8, const REALM_USER_TREE_HEIGHT: u8, const COORDINATOR_USER_TREE_HEIGHT: u8>(registration_id: u64) -> u64 {
    let realm_index = registration_id & ((1u64 << GROUP_REALM_HEIGHT) - 1);
    let user_index = (registration_id >> GROUP_REALM_HEIGHT) & ((1u64 << REALM_USER_TREE_HEIGHT) - 1);
    let group_id = (registration_id >> (GROUP_REALM_HEIGHT + REALM_USER_TREE_HEIGHT)) & ((1u64 << (COORDINATOR_USER_TREE_HEIGHT - GROUP_REALM_HEIGHT)) - 1);

    let reversed_realm_index = reverse_bits_in_limit(realm_index, GROUP_REALM_HEIGHT);
    let realm_id = (group_id << GROUP_REALM_HEIGHT) | reversed_realm_index;

    let user_index_half_bits = REALM_USER_TREE_HEIGHT / 2;
    let user_index_low_half = user_index & ((1u64 << user_index_half_bits) - 1);
    let user_index_high_half = (user_index >> user_index_half_bits) & ((1u64 << user_index_half_bits) - 1);

    let reversed_user_index_high_half = reverse_bits_in_limit(user_index_high_half, user_index_half_bits);
    let modified_user_index = (user_index_low_half << user_index_half_bits) | reversed_user_index_high_half;

    (realm_id << REALM_USER_TREE_HEIGHT) | modified_user_index
}