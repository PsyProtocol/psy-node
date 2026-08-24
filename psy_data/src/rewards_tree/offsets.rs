/*
================================================================================
                          REWARDS TREE STRUCTURE
================================================================================

[Level = 0]                         [ CST ]
                         (Checkpoint State Transition)
                                   N(0, 0)
                                      |
                     /----------------+----------------\
                    /                                   \
[Level = 1] [ AggURDCGUTA ]                         [ (Empty) ]
   (Agg User/Reg/Deploy/Update)                       N(1, 1)
               N(1, 0)
                  |
         /--------+--------\
        /                   \
[Level = 2]                [ AggRightTwo ]
     [ GU ]             (Intermediate Node)
  (GUTA Rewards)              N(2, 1)
     N(2, 0)                     |
                                 |
                        /--------+--------\
                       /                   \
[Level = 3]        [ RU ]            [ AggRightThree ]
              (Register Users)    (Intermediate Node)
                  N(3, 2)                N(3, 3)
                                             |
                                    /--------+--------\
                                   /                   \
[Level = 4]                    [ DC ]                 [ UC ]
                       (Deploy Contracts)     (Update Contracts)
                              N(4, 6)             N(4, 7)

================================================================================
Legend:
N(L, I)       : Node at Level L, Index I
CST           : Root of the transition logic
AggURDCGUTA   : Top of the actual rewards aggregation
GU            : GUTA Rewards Root
AggRightTwo   : Intermediate node combining RU and the DC/UC subtree
AggRightThree : Intermediate node combining DC and UC
RU            : Register Users Rewards Root
DC            : Deploy Contracts Rewards Root
UC            : Update Contracts Rewards Root

NOTE: with the addition of the update contracts (4th) child to the part-1 agg,
the deploy contracts rewards root moved from N(3, 3) to N(4, 6) so that update
contracts could be placed as its sibling at N(4, 7).
================================================================================
*/
pub const GUTA_REWARDS_TREE_OFFSET_ROOT_LEVEL: u8 = 2;
pub const GUTA_REWARDS_TREE_OFFSET_ROOT_INDEX: u64 = 0;

pub const REGISTER_USERS_REWARDS_TREE_OFFSET_ROOT_LEVEL: u8 = 3;
pub const REGISTER_USERS_REWARDS_TREE_OFFSET_ROOT_INDEX: u64 = 2;

pub const DEPLOY_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_LEVEL: u8 = 4;
pub const DEPLOY_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_INDEX: u64 = 6;

pub const UPDATE_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_LEVEL: u8 = 4;
pub const UPDATE_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_INDEX: u64 = 7;
