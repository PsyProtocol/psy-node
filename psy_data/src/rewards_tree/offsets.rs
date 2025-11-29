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
         (Agg User/Reg/Deploy)                        N(1, 1)
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
[Level = 3]        [ RU ]                 [ DC ]
              (Register Users)      (Deploy Contracts)
                  N(3, 2)                N(3, 3)

================================================================================
Legend:
N(L, I)       : Node at Level L, Index I
CST           : Root of the transition logic
AggURDCGUTA   : Top of the actual rewards aggregation
GU            : GUTA Rewards Root
AggRightTwo   : Intermediate node combining RU and DC
RU            : Register Users Rewards Root
DC            : Deploy Contracts Rewards Root
================================================================================
*/
pub const GUTA_REWARDS_TREE_OFFSET_ROOT_LEVEL: u8 = 2;
pub const GUTA_REWARDS_TREE_OFFSET_ROOT_INDEX: u64 = 0;

pub const REGISTER_USERS_REWARDS_TREE_OFFSET_ROOT_LEVEL: u8 = 3;
pub const REGISTER_USERS_REWARDS_TREE_OFFSET_ROOT_INDEX: u64 = 2;

pub const DEPLOY_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_LEVEL: u8 = 3;
pub const DEPLOY_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_INDEX: u64 = 3;
