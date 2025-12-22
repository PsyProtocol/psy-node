// =================================================================================
// 1. Bridge Pattern: Abstracting "Little Endian Sum"
// =================================================================================

/// Abstraction layer to allow the same logic to drive both Plonky2 Circuit construction
/// and native Rust execution.
pub trait UserIdGeneratorBuilderBridge<Builder, Felt, Bit> {
    fn bridge_le_sum(
        builder: &mut Builder,
        bits: &[Bit],
    ) -> Felt;
}


// --- Native u64 Bridge (For Testing/Verification) ---
pub struct ExU64UserIdGeneratorBuilderBridge;

/// Helper to reconstruct a u64 from a slice of booleans.
fn le_sum_u64(bits: &[bool]) -> u64 {
    bits.iter().enumerate().fold(0u64, |acc, (i, b)| {
        if *b {
            acc | (1u64 << i)
        } else {
            acc
        }
    })
}

impl UserIdGeneratorBuilderBridge<(), u64, bool> for ExU64UserIdGeneratorBuilderBridge {
    fn bridge_le_sum(
        _builder: &mut (),
        bits: &[bool],
    ) -> u64 {
        le_sum_u64(bits)
    }
}

// =================================================================================
// 2. The Strategy Trait
// =================================================================================

pub trait UserIdGeneratorStrategy {
    /// 1. The Canonical Logic (Generic).
    /// Used by both ZK Circuits and the Native Test Bridge.
    /// Defines the bit-shuffling logic using Vector slices to ensure the Circuit
    /// and Native implementations are logically identical.
    fn circuit_get_user_id_from_user_registration_id<Bridge, Builder, Felt, Bit>(
        builder: &mut Builder,
        user_registration_tree_leaf_index_bits: &[Bit],
        coordinator_global_user_tree_height: u8,
        realm_global_user_tree_height: u8,
        group_realm_height: u8,
    ) -> Felt
    where
        Bit: Clone,
        Bridge: UserIdGeneratorBuilderBridge<Builder, Felt, Bit>;

    /// 2. The Optimized Native Implementation.
    /// Used in production for performance. Uses bitwise math instead of vectors.
    /// MUST be tested to ensure exact equivalence with `circuit_get_user_id_from_user_registration_id`.
    fn get_user_id_from_user_registration_id(
        user_registration_id: u64,
        coordinator_global_user_tree_height: u8,
        realm_global_user_tree_height: u8,
        group_realm_height: u8,
    ) -> u64;

    /// 3. The Inverse Implementation.
    /// Recovers the original sequential `user_registration_id` from the permuted `user_id`.
    fn get_user_registration_id_from_user_id(
        user_id: u64,
        coordinator_global_user_tree_height: u8,
        realm_global_user_tree_height: u8,
        group_realm_height: u8,
    ) -> u64;
}

/// Helper function to reverse the lowest `num_bits` of `x`.
fn reverse_bits_in_limit(x: u64, num_bits: u8) -> u64 {
    let difference = 64 - num_bits as u64;
    (x).reverse_bits() >> difference
}

// =================================================================================
// 3. Strategy Implementations
// =================================================================================

pub struct UserIdBitsStrategy0;
impl UserIdGeneratorStrategy for UserIdBitsStrategy0 {
    fn circuit_get_user_id_from_user_registration_id<Bridge, Builder, Felt, Bit>(
        builder: &mut Builder,
        bits: &[Bit], _c: u8, _r: u8, _g: u8,
    ) -> Felt where Bit: Clone, Bridge: UserIdGeneratorBuilderBridge<Builder, Felt, Bit> {

        Bridge::bridge_le_sum(builder, &bits)
    }
    fn get_user_id_from_user_registration_id(reg_id: u64, _c: u8, _r: u8, _g: u8) -> u64 {
        reg_id
    }
    fn get_user_registration_id_from_user_id(uid: u64, _c: u8, _r: u8, _g: u8) -> u64 {
        uid
    }
}
// --- Strategy 1: Full Reversal ---
pub struct UserIdBitsStrategy1;
impl UserIdGeneratorStrategy for UserIdBitsStrategy1 {
    fn circuit_get_user_id_from_user_registration_id<Bridge, Builder, Felt, Bit>(
        builder: &mut Builder,
        bits: &[Bit], _c: u8, _r: u8, _g: u8,
    ) -> Felt where Bit: Clone, Bridge: UserIdGeneratorBuilderBridge<Builder, Felt, Bit> {
        let mut reversed = bits.to_vec();
        reversed.reverse();
        Bridge::bridge_le_sum(builder, &reversed)
    }
    fn get_user_id_from_user_registration_id(reg_id: u64, c: u8, r: u8, _g: u8) -> u64 {
        reverse_bits_in_limit(reg_id, c + r)
    }
    fn get_user_registration_id_from_user_id(uid: u64, c: u8, r: u8, _g: u8) -> u64 {
        reverse_bits_in_limit(uid, c + r)
    }
}

// --- Strategy 2: Split & Rotate ---
pub struct UserIdBitsStrategy2;
impl UserIdGeneratorStrategy for UserIdBitsStrategy2 {
    fn circuit_get_user_id_from_user_registration_id<Bridge, Builder, Felt, Bit>(
        builder: &mut Builder, bits: &[Bit], c: u8, _r: u8, _g: u8,
    ) -> Felt where Bit: Clone, Bridge: UserIdGeneratorBuilderBridge<Builder, Felt, Bit> {
        let split = c as usize;
        let mut top = bits[0..split].to_vec();
        top.reverse();
        let bottom = bits[split..].to_vec();
        Bridge::bridge_le_sum(builder, &[bottom, top].concat())
    }
    fn get_user_id_from_user_registration_id(reg_id: u64, c: u8, r: u8, _g: u8) -> u64 {
        let low = reg_id & ((1 << c) - 1);
        let high = reg_id >> c;
        (reverse_bits_in_limit(low, c) << r) | high
    }
    fn get_user_registration_id_from_user_id(uid: u64, c: u8, r: u8, _g: u8) -> u64 {
        let bottom = uid & ((1 << r) - 1);
        let top = uid >> r;
        (bottom << c) | reverse_bits_in_limit(top, c)
    }
}

// --- Strategy 3: Fixed Split ---
pub struct UserIdBitsStrategy3;
impl UserIdGeneratorStrategy for UserIdBitsStrategy3 {
    fn circuit_get_user_id_from_user_registration_id<Bridge, Builder, Felt, Bit>(
        builder: &mut Builder, bits: &[Bit], _c: u8, _r: u8, _g: u8,
    ) -> Felt where Bit: Clone, Bridge: UserIdGeneratorBuilderBridge<Builder, Felt, Bit> {
        let mut top = bits[10..].to_vec();
        top.reverse();
        let bottom = bits[0..10].to_vec();
        Bridge::bridge_le_sum(builder, &[bottom, top].concat())
    }
    fn get_user_id_from_user_registration_id(reg_id: u64, c: u8, r: u8, _g: u8) -> u64 {
        let h = c + r;
        (reverse_bits_in_limit(reg_id >> 10, h - 10) << 10) | (reg_id & 0x3FF)
    }
    fn get_user_registration_id_from_user_id(uid: u64, c: u8, r: u8, _g: u8) -> u64 {
        let h = c + r;
        (reverse_bits_in_limit(uid >> 10, h - 10) << 10) | (uid & 0x3FF)
    }
}

// --- Strategy 4: Complex NCA (Split User) ---
// Distributes users across realms (Round Robin), but splits the user index within the realm
// to permute it.
pub struct UserIdBitsStrategy4;

impl UserIdGeneratorStrategy for UserIdBitsStrategy4 {
    fn circuit_get_user_id_from_user_registration_id<Bridge, Builder, Felt, Bit>(
        builder: &mut Builder,
        user_registration_tree_leaf_index_bits: &[Bit],
        _coordinator_global_user_tree_height: u8,
        realm_global_user_tree_height: u8,
        group_realm_height: u8,
    ) -> Felt
    where
        Bit: Clone,
        Bridge: UserIdGeneratorBuilderBridge<Builder, Felt, Bit>,
    {
        let g = group_realm_height as usize;
        let r = realm_global_user_tree_height as usize;

        let realm_index_bits = user_registration_tree_leaf_index_bits[0..g].to_vec();
        let user_index_bits = user_registration_tree_leaf_index_bits[g..(g + r)].to_vec();
        let group_id_bits = user_registration_tree_leaf_index_bits[(g + r)..].to_vec();

        let mut reversed_realm_index = realm_index_bits;
        reversed_realm_index.reverse();

        let half = r / 2;
        let user_low = user_index_bits[0..half].to_vec();
        let mut user_high = user_index_bits[half..].to_vec();
        user_high.reverse();

        // User Block: [HighRev, Low] (HighRev becomes LSB in le_sum)
        let modified_user = [user_high, user_low].concat();
        
        Bridge::bridge_le_sum(builder, &[modified_user, reversed_realm_index, group_id_bits].concat())
    }

    fn get_user_id_from_user_registration_id(
        reg_id: u64,
        coord_h: u8,
        realm_h: u8,
        group_h: u8,
    ) -> u64 {
        let realm_idx = reg_id & ((1 << group_h) - 1);
        let user_idx = (reg_id >> group_h) & ((1 << realm_h) - 1);
        let group_id = (reg_id >> (group_h + realm_h)) & ((1 << (coord_h - group_h)) - 1);

        let realm_rev = reverse_bits_in_limit(realm_idx, group_h);
        let full_realm = (group_id << group_h) | realm_rev;

        let half = realm_h / 2;
        let u_low = user_idx & ((1 << half) - 1);
        let u_high = (user_idx >> half) & ((1 << (realm_h - half)) - 1);
        let u_high_rev = reverse_bits_in_limit(u_high, realm_h - half);
        let mod_user = (u_low << (realm_h - half)) | u_high_rev;

        (full_realm << realm_h) | mod_user
    }

    fn get_user_registration_id_from_user_id(
        uid: u64,
        _coord_h: u8,
        realm_h: u8,
        group_h: u8,
    ) -> u64 {
        let mod_user = uid & ((1 << realm_h) - 1);
        let full_realm = uid >> realm_h;

        let half = realm_h / 2;
        let u_high_rev = mod_user & ((1 << (realm_h - half)) - 1);
        let u_low = mod_user >> (realm_h - half);
        let u_high = reverse_bits_in_limit(u_high_rev, realm_h - half);
        let user_idx = (u_high << half) | u_low;

        let realm_rev = full_realm & ((1 << group_h) - 1);
        let group_id = full_realm >> group_h;
        let realm_idx = reverse_bits_in_limit(realm_rev, group_h);

        (group_id << (group_h + realm_h)) | (user_idx << group_h) | realm_idx
    }
}

// --- Strategy 5: Max Distance ---
/// **Strategy 5: Round-Robin Realms + Full Bit-Reversal Users**
///
/// **Logic:**
/// 1. **Realm Selection:** Uses the lowest bits (LSB) of the registration ID to cycle 
///    through active realms. This ensures perfect load balancing (Round Robin).
/// 2. **User Placement:** Takes the `User Index` and **completely reverses the bits**.
///
/// **Effect:**
/// - Load is distributed evenly across $2^{group\_realm\_height}$ operators.
/// - Within each operator's tree, users are distributed maximally far apart 
///   (maximizing proof efficiency in sparse trees and privacy).
///
/// **Concrete Example (Group Height 4, 16 Realms):**
/// - `RegID 0`: Realm 0, User Index 0 -> Tree Position: Far Left
/// - `RegID 1`: Realm 8, User Index 0
/// - ...
/// - `RegID 16`: Realm 0, User Index 1 -> Tree Position: Far Right
///
/// **Recommended for:** High-volume networks (e.g., 100k+ users) where maximum
/// parallel write throughput and operator health are required.
pub struct UserIdBitsStrategy5;

impl UserIdGeneratorStrategy for UserIdBitsStrategy5 {
    fn circuit_get_user_id_from_user_registration_id<Bridge, Builder, Felt, Bit>(
        builder: &mut Builder,
        user_registration_tree_leaf_index_bits: &[Bit],
        _coordinator_global_user_tree_height: u8,
        realm_global_user_tree_height: u8,
        group_realm_height: u8,
    ) -> Felt
    where
        Bit: Clone,
        Bridge: UserIdGeneratorBuilderBridge<Builder, Felt, Bit>,
    {
        let group_realm_height_usize = group_realm_height as usize;
        let realm_global_user_tree_height_usize = realm_global_user_tree_height as usize;

        // 1. Slice Input Bits
        // LSBs (size: group_realm_height) -> Realm Index
        let realm_index_bits = user_registration_tree_leaf_index_bits[0..group_realm_height_usize].to_vec();
        
        // Middle (size: realm_global_user_tree_height) -> User Index
        let user_index_start = group_realm_height_usize;
        let user_index_end = group_realm_height_usize + realm_global_user_tree_height_usize;
        let user_index_bits = user_registration_tree_leaf_index_bits[user_index_start..user_index_end].to_vec();
        
        // MSBs (size: coordinator - group) -> Group ID
        let group_id_bits = user_registration_tree_leaf_index_bits[user_index_end..].to_vec();

        // 2. Process Realm Bits
        // Reverse them to ensure we jump significantly between realms (0 -> 8 -> 4...) 
        // rather than filling 0 -> 1 -> 2.
        let mut reversed_realm_index_bits = realm_index_bits;
        reversed_realm_index_bits.reverse();

        // 3. Process User Index Bits (THE CHANGE vs S4)
        // Fully reverse the bits for maximum distance within the realm tree.
        let mut reversed_user_index_bits = user_index_bits;
        reversed_user_index_bits.reverse();

        // 4. Final Assembly
        // Vector Order for le_sum (LSB -> MSB):
        // [Reversed User Index] [Reversed Realm Index] [Group ID]
        // This constructs an integer: (Group << ...) | (RevRealm << ...) | RevUser
        let new_bits = [reversed_user_index_bits, reversed_realm_index_bits, group_id_bits].concat();
        
        Bridge::bridge_le_sum(builder, &new_bits)
    }

    fn get_user_id_from_user_registration_id(
        user_registration_id: u64,
        coordinator_global_user_tree_height: u8,
        realm_global_user_tree_height: u8,
        group_realm_height: u8,
    ) -> u64 {
        // 1. Parse Input Registration ID
        let realm_index = user_registration_id & ((1u64 << group_realm_height) - 1);
        let user_index = (user_registration_id >> group_realm_height) & ((1u64 << realm_global_user_tree_height) - 1);
        
        let shift_amount_for_group = group_realm_height + realm_global_user_tree_height;
        let group_id_height = coordinator_global_user_tree_height - group_realm_height;
        let group_id = (user_registration_id >> shift_amount_for_group) & ((1u64 << group_id_height) - 1);

        // 2. Process Realm Part
        let reversed_realm_index = reverse_bits_in_limit(realm_index, group_realm_height);
        
        // Full Realm ID = (Group ID << Group_Height) | Reversed Realm Index
        let full_realm_id = (group_id << group_realm_height) | reversed_realm_index;

        // 3. Process User Part (Max Distance)
        let reversed_user_index = reverse_bits_in_limit(user_index, realm_global_user_tree_height);

        // 4. Final Assembly: (Full Realm ID << Realm_Height) | Reversed User Index
        (full_realm_id << realm_global_user_tree_height) | reversed_user_index
    }

    fn get_user_registration_id_from_user_id(
        user_id: u64,
        _coordinator_global_user_tree_height: u8,
        realm_global_user_tree_height: u8,
        group_realm_height: u8,
    ) -> u64 {
        // 1. Unpack Tree Index (User ID)
        // Structure: [Full Realm ID (MSB)] [Reversed User Index (LSB)]
        let reversed_user_index = user_id & ((1u64 << realm_global_user_tree_height) - 1);
        let full_realm_id = user_id >> realm_global_user_tree_height;

        // 2. Revert User Index
        // The inverse of a full reversal is a full reversal.
        let original_user_index = reverse_bits_in_limit(reversed_user_index, realm_global_user_tree_height);

        // 3. Revert Realm Part
        let reversed_realm_index = full_realm_id & ((1u64 << group_realm_height) - 1);
        let group_id = full_realm_id >> group_realm_height;
        
        let original_realm_index = reverse_bits_in_limit(reversed_realm_index, group_realm_height);

        // 4. Reconstruct Input Registration ID
        let shift_for_user = group_realm_height;
        let shift_for_group = group_realm_height + realm_global_user_tree_height;
        
        (group_id << shift_for_group) | (original_user_index << shift_for_user) | original_realm_index
    }
}

// =================================================================================
// 4. Public API Wrappers
// =================================================================================

// Default to Strategy 5 for maximum distance and load balancing
type UserIdBitsStrategy = UserIdBitsStrategy5;

pub fn get_user_id_from_user_registration_id(
    user_registration_id: u64,
    coordinator_global_user_tree_height: u8,
    realm_global_user_tree_height: u8,
    group_realm_height: u8,
) -> u64 {
    UserIdBitsStrategy::get_user_id_from_user_registration_id(
        user_registration_id, 
        coordinator_global_user_tree_height, 
        realm_global_user_tree_height, 
        group_realm_height
    )
}

pub fn get_user_registration_id_from_user_id(
    user_id: u64,
    coordinator_global_user_tree_height: u8,
    realm_global_user_tree_height: u8,
    group_realm_height: u8,
) -> u64 {
    UserIdBitsStrategy::get_user_registration_id_from_user_id(
        user_id, 
        coordinator_global_user_tree_height, 
        realm_global_user_tree_height, 
        group_realm_height
    )
}

pub fn circuit_user_registration_tree_index_bits_to_user_id<Bridge: UserIdGeneratorBuilderBridge<Builder, Felt, Bit>, Builder, Felt: Clone, Bit: Clone>(
    builder: &mut Builder,
    user_registration_tree_leaf_index_bits: &[Bit],
    coordinator_global_user_tree_height: u8,
    realm_global_user_tree_height: u8,
    group_realm_height: u8,
) -> Felt {
    UserIdBitsStrategy::circuit_get_user_id_from_user_registration_id::<Bridge, Builder, Felt, Bit>(
        builder,
        user_registration_tree_leaf_index_bits,
        coordinator_global_user_tree_height,
        realm_global_user_tree_height,
        group_realm_height,
    )
}

// =================================================================================
// 5. Comprehensive Tests
// =================================================================================

#[cfg(test)]
mod tests {
    use rand::{thread_rng, RngCore};

    use super::*;


    /// Helper to split a u64 into a vector of booleans (LSB first).
    fn split_u64_le(value: u64, num_bits: usize) -> Vec<bool> {
        (0..num_bits).map(|i| ((value >> i) & 1) == 1).collect()
    }

    // Constants based on QNetworkTreeConstants
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = 12;
    const REALM_GLOBAL_USER_TREE_HEIGHT: u8 = 20;
    const GROUP_REALM_HEIGHT: u8 = 4; // Set to 4 to test 16-realm load balancing

    fn verify_strategy_full_coverage<S: UserIdGeneratorStrategy>(
        name: &str,
        coordinator_global_user_tree_height: u8,
        realm_global_user_tree_height: u8,
        group_realm_height: u8,
    ) {
        println!("Verifying {} with Coord={}, Realm={}, Group={}", 
            name, coordinator_global_user_tree_height, realm_global_user_tree_height, group_realm_height);
        
        let mut rng = thread_rng();
        let global_user_tree_height = (coordinator_global_user_tree_height + realm_global_user_tree_height) as usize;
        let limit = 1u64 << global_user_tree_height;
        
        let mut test_user_registration_ids = Vec::new();
        // Sequential ranges for edge cases
        test_user_registration_ids.extend(0..2000); 
        test_user_registration_ids.extend((limit - 2000)..limit);
        // Random fuzzing
        for _ in 0..5000 {
            test_user_registration_ids.push(rng.next_u64() & (limit - 1));
        }

        for &user_registration_id in &test_user_registration_ids {
            let bits = split_u64_le(user_registration_id, global_user_tree_height);
            
            // 1. Generic (simulates Circuit Logic via Bridge)
            let generic = S::circuit_get_user_id_from_user_registration_id::<ExU64UserIdGeneratorBuilderBridge, (), u64, bool>(
                &mut (), 
                &bits, 
                coordinator_global_user_tree_height, 
                realm_global_user_tree_height, 
                group_realm_height
            );
            
            // 2. Optimized Native Logic
            let optimized = S::get_user_id_from_user_registration_id(
                user_registration_id,
                coordinator_global_user_tree_height, 
                realm_global_user_tree_height, 
                group_realm_height
            );

            assert_eq!(generic, optimized, "Generic vs Optimized mismatch for ID {}", user_registration_id);

            // 3. Inverse Logic
            let recovered = S::get_user_registration_id_from_user_id(
                optimized,
                coordinator_global_user_tree_height, 
                realm_global_user_tree_height, 
                group_realm_height
            );
            assert_eq!(user_registration_id, recovered, "Inverse failed for ID {}", user_registration_id);
        }
    }

    #[test]
    fn test_strategy_5_equivalence() { verify_strategy_full_coverage::<UserIdBitsStrategy5>("S5", COORDINATOR_GLOBAL_USER_TREE_HEIGHT, REALM_GLOBAL_USER_TREE_HEIGHT, GROUP_REALM_HEIGHT); }

    #[test]
    fn test_strategy_5_distribution() {
        // Specific test to prove Strategy 5 maximizes distance and balances load
        println!("Testing S5 Distribution Logic...");
        
        // Setup: Group=4 (16 Realms), UserHeight=10
        let g_h = 4;
        let r_h = 10;
        let c_h = 10; // arbitrary, just needs to be >= g_h

        // Case 1: Load Balancing across Realms
        // RegID 0 should be Realm 0
        // RegID 1 should be Realm 8 (since we reverse the realm index bits 0001 -> 1000)
        let id0 = UserIdBitsStrategy5::get_user_id_from_user_registration_id(0, c_h, r_h, g_h);
        let id1 = UserIdBitsStrategy5::get_user_id_from_user_registration_id(1, c_h, r_h, g_h);
        
        let realm0 = id0 >> r_h;
        let realm1 = id1 >> r_h;
        
        println!("RegID 0 -> Realm {}", realm0);
        println!("RegID 1 -> Realm {}", realm1);
        
        assert_ne!(realm0, realm1, "Sequential IDs should go to different realms");
        assert_eq!(realm0 & 0xF, 0, "RegID 0 -> Realm 0");
        assert_eq!(realm1 & 0xF, 8, "RegID 1 -> Realm 8 (Bit reversal check)");

        // Case 2: Max Distance within a Realm
        // RegID 0 -> Realm 0, User Index 0
        // RegID 16 -> Realm 0, User Index 1 (Cycle repeats after 16)
        let id16 = UserIdBitsStrategy5::get_user_id_from_user_registration_id(16, c_h, r_h, g_h);
        
        let user_idx_0 = id0 & ((1 << r_h) - 1);
        let user_idx_16 = id16 & ((1 << r_h) - 1);

        println!("RegID 0  (Realm 0, User 0) -> Tree Index: {:010b} ({})", user_idx_0, user_idx_0);
        println!("RegID 16 (Realm 0, User 1) -> Tree Index: {:010b} ({})", user_idx_16, user_idx_16);

        // Expectation: 
        // User 0 (00...0) -> Reversal -> 00...0 (Far Left)
        // User 1 (00...1) -> Reversal -> 10...0 (Far Right)
        assert_eq!(user_idx_0, 0);
        assert_eq!(user_idx_16, 1 << (r_h - 1), "User 1 should be at max distance from User 0");
    }

    #[test]
    fn test_strategy_4_edge_cases() {
        // Strategy 4 has integer division logic (R_H / 2). Test odd height.
        let odd_r_h = 13;
        let odd_c_h = 10;
        let odd_g_h = 1;
        let total = (odd_c_h + odd_r_h) as usize;
        
        let id = 12345u64;
        let bits = split_u64_le(id, total);
        
        let generic = UserIdBitsStrategy4::circuit_get_user_id_from_user_registration_id::<ExU64UserIdGeneratorBuilderBridge, (), u64, bool>(
            &mut (), &bits, odd_c_h, odd_r_h, odd_g_h
        );
        let optimized = UserIdBitsStrategy4::get_user_id_from_user_registration_id(id, odd_c_h, odd_r_h, odd_g_h);
        
        assert_eq!(generic, optimized, "Mismatch on odd Realm Height");
        
        let recovered = UserIdBitsStrategy4::get_user_registration_id_from_user_id(optimized, odd_c_h, odd_r_h, odd_g_h);
        assert_eq!(id, recovered, "Inverse failed on odd Realm Height");
    }
}