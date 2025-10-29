use parth_core::crypto::hash::traits::{MerkleHasher, ZeroableHash};


pub trait WithDummyStateTransition<Hash> {
    fn get_dummy_value(state_root: Hash) -> Self;
}
pub trait StateTransitionTrackable<Hash> {
    fn get_start_root(&self) -> Hash;
    fn get_end_root(&self) -> Hash;
}
pub trait StateTransitionTrackableWithEvents<Hash>: StateTransitionTrackable<Hash> {
    fn get_events_hash(&self) -> Hash;
}
pub trait AggStateTrackableInput<Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash>;
}

#[pderive::serialize_copy_hash]
pub struct DummyAggStateTransition<Hash> {
    pub state_transition_hash: Hash,
    pub allowed_circuit_hashes_root: Hash,
    pub is_deploy_contracts: bool,
    pub is_register_users: bool,
}

#[pderive::serialize_copy_hash]
pub struct DummyAggStateTransitionWithEvents<Hash> {
    pub state_transition_hash: Hash,
    pub event_transition_hash: Hash,
    pub allowed_circuit_hashes_root: Hash,
}

#[pderive::serialize_copy_hash]
pub struct AggStateTransition<Hash> {
    pub state_transition_start: Hash,
    pub state_transition_end: Hash,
}
impl<Hash> AggStateTransition<Hash> {
    pub fn new(state_transition_start: Hash, state_transition_end: Hash) -> Self {
        Self {
            state_transition_start,
            state_transition_end,
        }
    }
    pub fn get_combined_hash<Hasher: MerkleHasher<Hash>>(&self) -> Hash {
        Hasher::two_to_one(&self.state_transition_start, &self.state_transition_end)
    }
}
impl<Hash: Default> Default for AggStateTransition<Hash> {
    fn default() -> Self {
        Self {
            state_transition_start: Default::default(),
            state_transition_end: Default::default(),
        }
    }
}
impl<Hash: Copy> AggStateTrackableInput<Hash> for AggStateTransition<Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        *self
    }
}
impl<Hash, T: AggStateTrackableInput<Hash>> StateTransitionTrackable<Hash> for T {
    fn get_start_root(&self) -> Hash {
        self.get_state_transition().state_transition_start
    }

    fn get_end_root(&self) -> Hash {
        self.get_state_transition().state_transition_end
    }
}

impl<Hash: Copy> WithDummyStateTransition<Hash> for AggStateTransition<Hash> {
    fn get_dummy_value(state_root: Hash) -> Self {
        Self {
            state_transition_start: state_root,
            state_transition_end: state_root,
        }
    }
}

#[pderive::serialize_copy_hash]
pub struct AggStateTransitionInput<Hash> {
    pub left_input: AggStateTransition<Hash>,
    pub right_input: AggStateTransition<Hash>,
    pub left_proof_is_leaf: bool,
    pub right_proof_is_leaf: bool,
}
impl<Hash: Copy> WithDummyStateTransition<Hash> for AggStateTransitionInput<Hash> {
    fn get_dummy_value(state_root: Hash) -> Self {
        Self {
            left_input: AggStateTransition::<Hash>::get_dummy_value(state_root),
            right_input: AggStateTransition::<Hash>::get_dummy_value(state_root),
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }
}
impl<Hash: Copy> AggStateTrackableInput<Hash> for AggStateTransitionInput<Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        self.condense()
    }
}
impl<Hash: Copy> AggStateTransitionInput<Hash> {
    pub fn condense(&self) -> AggStateTransition<Hash> {
        AggStateTransition {
            state_transition_start: self.left_input.state_transition_start,
            state_transition_end: self.right_input.state_transition_end,
        }
    }
    pub fn combine_with_right_leaf<T: AggStateTrackableInput<Hash>>(&self, right: &T) -> Self {
        Self {
            left_input: self.condense(),
            right_input: right.get_state_transition(),
            left_proof_is_leaf: false,
            right_proof_is_leaf: true,
        }
    }
    pub fn combine_with_left_leaf<T: AggStateTrackableInput<Hash>>(&self, left: &T) -> Self {
        Self {
            left_input: left.get_state_transition(),
            right_input: self.condense(),
            left_proof_is_leaf: true,
            right_proof_is_leaf: false,
        }
    }
}

pub trait AggStateTrackableWithEventsInput<Hash> {
    fn get_state_transition_with_events<Hasher: MerkleHasher<Hash>>(&self) -> AggStateTransitionWithEvents<Hash>;
}


#[pderive::serialize_copy_hash]
pub struct AggStateTransitionWithEvents<Hash> {
    pub state_transition_start: Hash,
    pub state_transition_end: Hash,
    pub event_hash: Hash,
}
impl<Hash: Default> Default for AggStateTransitionWithEvents<Hash> {
    fn default() -> Self {
        Self {
            state_transition_start: Default::default(),
            state_transition_end: Default::default(),
            event_hash: Default::default(),
        }
    }
}
impl<Hash: Copy> AggStateTrackableInput<Hash> for AggStateTransitionWithEvents<Hash> {
    fn get_state_transition(&self) -> AggStateTransition<Hash> {
        AggStateTransition {
            state_transition_start: self.state_transition_start,
            state_transition_end: self.state_transition_end,
        }
    }
}
impl<Hash: Copy + ZeroableHash> WithDummyStateTransition<Hash> for AggStateTransitionWithEvents<Hash> {
    fn get_dummy_value(state_root: Hash) -> Self {
        Self {
            state_transition_start: state_root,
            state_transition_end: state_root,
            event_hash: Hash::get_zero_value(),
        }
    }
}


#[pderive::serialize_copy_hash]
pub struct AggStateTransitionWithEventsInput<Hash> {
    pub left_input: AggStateTransitionWithEvents<Hash>,
    pub right_input: AggStateTransitionWithEvents<Hash>,
    pub left_proof_is_leaf: bool,
    pub right_proof_is_leaf: bool,
}

impl<Hash: Copy + ZeroableHash> AggStateTrackableWithEventsInput<Hash> for AggStateTransitionWithEventsInput<Hash> {
    fn get_state_transition_with_events<Hasher: MerkleHasher<Hash>>(&self) -> AggStateTransitionWithEvents<Hash> {
        self.condense::<Hasher>()
    }
}
impl<Hash: ZeroableHash, T: AggStateTrackableInput<Hash>> StateTransitionTrackableWithEvents<Hash> for T {
    fn get_events_hash(&self) -> Hash {
        Hash::get_zero_value()
    }
}
impl<Hash: Copy + ZeroableHash> WithDummyStateTransition<Hash> for AggStateTransitionWithEventsInput<Hash> {
    fn get_dummy_value(state_root: Hash) -> Self {
        Self {
            left_input: AggStateTransitionWithEvents::<Hash>::get_dummy_value(state_root),
            right_input: AggStateTransitionWithEvents::<Hash>::get_dummy_value(state_root),
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }
}
impl<Hash: Copy + ZeroableHash> AggStateTransitionWithEventsInput<Hash> {
    pub fn condense<Hasher: MerkleHasher<Hash>>(&self) -> AggStateTransitionWithEvents<Hash> {
        AggStateTransitionWithEvents {
            state_transition_start: self.left_input.state_transition_start,
            state_transition_end: self.right_input.state_transition_end,
            event_hash: Hasher::two_to_one(&self.left_input.event_hash, &self.right_input.event_hash),
        }
    }
    pub fn combine_with_right_leaf<Hasher: MerkleHasher<Hash>, T: AggStateTrackableWithEventsInput<Hash>>(
        &self,
        right: &T,
    ) -> Self {
        Self {
            left_input: self.condense::<Hasher>(),
            right_input: right.get_state_transition_with_events::<Hasher>(),
            left_proof_is_leaf: false,
            right_proof_is_leaf: true,
        }
    }
    pub fn combine_with_left_leaf<Hasher: MerkleHasher<Hash>, T: AggStateTrackableWithEventsInput<Hash>>(&self, left: &T) -> Self {
        Self {
            left_input: left.get_state_transition_with_events::<Hasher>(),
            right_input: self.condense::<Hasher>(),
            left_proof_is_leaf: true,
            right_proof_is_leaf: false,
        }
    }
}