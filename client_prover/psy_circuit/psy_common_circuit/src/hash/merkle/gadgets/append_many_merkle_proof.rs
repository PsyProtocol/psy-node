

/*
this gadget helps you prove that an append only merkle tree with a current root `current_root` once had a root of `historical_root`
another way to think of this gadget is that it proves that, if you take a tree with root X and set all the leaves with index >= `gadget.index` to zero, the tree will have a new root Y
*/
/* 
#[derive(Debug, Clone)]
pub struct HistoricalRootMerkleProofGadget {
    pub current_root: HashOutTarget,
    pub historical_root: HashOutTarget,
    pub current_value: HashOutTarget,
    pub index: Target,
    pub siblings: Vec<HashOutTarget>,
}*/