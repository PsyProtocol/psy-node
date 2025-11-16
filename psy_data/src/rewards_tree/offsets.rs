/*

Visualization for how the rewards tree works:

                          [ REWARDS TREE ROOT ]
                                 N(0, 0)
                                    |
                 /------------------+------------------\
                /                                        \
               |                                          |
      [ GU (GUTA Rewards) ]               [ Agg RU and DC Intermediate Node ]
              N(1, 0)                                   N(1, 1)
       (Root of its subtree)                 (Parent of RU and DC Trees)
                / \                                      / \
               /   \                                    /   \
            (...) (...)                                /     \
                                       [ RU (Register Users) ]   [ DC (Deploy Contracts) ]
                                               N(2, 2)                   N(2, 3)
                                        (Root of its subtree)     (Root of its subtree)
== Key ==
GU: GUTA Rewards Tree
RU: Register Users Rewards Tree
DC: Deploy Contracts Rewards Tree
*/
pub const GUTA_REWARDS_TREE_OFFSET_ROOT_LEVEL: u8 = 1;
pub const GUTA_REWARDS_TREE_OFFSET_ROOT_INDEX: u64 = 0;

pub const REGISTER_USERS_REWARDS_TREE_OFFSET_ROOT_LEVEL: u8 = 2;
pub const REGISTER_USERS_REWARDS_TREE_OFFSET_ROOT_INDEX: u64 = 2;

pub const DEPLOY_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_LEVEL: u8 = 2;
pub const DEPLOY_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_INDEX: u64 = 3;