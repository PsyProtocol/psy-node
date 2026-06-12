use psy_compiler::compile;

#[test]
fn test_voting_contract() {
    let source = r#"
const MAX_VOTERS: usize = 1024;

#[derive(FeltSized)]
pub struct VoteRecord {
    pub has_voted: Felt,
    pub choice: Felt,
}

#[contract]
struct VotingContract {
    pub proposal_a_count: Felt,
    pub proposal_b_count: Felt,
    pub voters: ContractStateArray<MAX_VOTERS, VoteRecord>,
}

#[contract_implementation]
impl VotingContract {
    #[contract_method]
    pub fn vote(&mut self, ctx: &mut ChainContext, voter_id: Felt, choice: Felt) {
        let record = self.voters[voter_id];
        require(record.has_voted == 0, "already voted");
        require(choice == 1 || choice == 2, "invalid choice");

        self.voters[voter_id] = VoteRecord {
            has_voted: 1,
            choice: choice,
        };

        if choice == 1 {
            self.proposal_a_count = self.proposal_a_count + 1;
        } else {
            self.proposal_b_count = self.proposal_b_count + 1;
        }
    }

    #[contract_method]
    pub fn reset_voter(&mut self, ctx: &mut ChainContext, voter_id: Felt) {
        require(ctx.user_id == 0, "only admin can reset");
        self.voters[voter_id] = VoteRecord {
            has_voted: 0,
            choice: 0,
        };
    }
}
"#;
    let result = compile(source);
    assert!(result.is_ok(), "compile failed: {:?}", result.err());
}
