use std::prelude::*;

#[contract]
#[derive(Storage)]
pub struct VotingContract {
    pub proposal_a_count: Felt,
    pub proposal_b_count: Felt,
}

#[contract::write_method]
pub fn vote(choice: Felt) {
    assert(choice == 1 || choice == 2, "invalid choice");
    let c = VotingContractRef::new(ContractMetadata::current());
    if choice == 1 {
        c.proposal_a_count = c.proposal_a_count.get() + 1;
    } else {
        c.proposal_b_count = c.proposal_b_count.get() + 1;
    }
}

#[contract::write_method]
pub fn reset_voter() {
    let c = VotingContractRef::new(ContractMetadata::current());
    c.proposal_a_count = 0;
    c.proposal_b_count = 0;
}
