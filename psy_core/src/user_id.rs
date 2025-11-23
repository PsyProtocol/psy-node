pub fn reverse_bits_in_limit(x: u64, num_bits: u8) -> u64 {
    let dif = 64 - num_bits as u64;
    (x).reverse_bits() >> dif
}

pub fn get_user_id_from_registration_id(
    registration_id: u64,
    coordinator_user_tree_height: u8,
    realm_user_tree_height: u8,
    group_realm_height: u8,
) -> u64 {
    let realm_index = registration_id & ((1u64 << group_realm_height) - 1);
    let user_index = (registration_id >> group_realm_height) & ((1u64 << realm_user_tree_height) - 1);
    let group_id =
        (registration_id >> (group_realm_height + realm_user_tree_height)) & ((1u64 << (coordinator_user_tree_height - group_realm_height)) - 1);

    let reversed_realm_index = reverse_bits_in_limit(realm_index, group_realm_height);
    let realm_id = (group_id << group_realm_height) | reversed_realm_index;

    let user_index_half_bits = realm_user_tree_height / 2;
    let user_index_low_half = user_index & ((1u64 << user_index_half_bits) - 1);
    let user_index_high_half = (user_index >> user_index_half_bits) & ((1u64 << user_index_half_bits) - 1);

    let reversed_user_index_high_half = reverse_bits_in_limit(user_index_high_half, user_index_half_bits);
    let modified_user_index = (user_index_low_half << user_index_half_bits) | reversed_user_index_high_half;

    (realm_id << realm_user_tree_height) | modified_user_index
}