use anyhow::{ensure, Result};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOut, RichField},
    plonk::{
        circuit_data::VerifierOnlyCircuitData,
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_common_circuit::proof_minifier::pm_core::get_circuit_fingerprint_generic;
use psy_crypto::hash::{
    merkle::{core::MerkleProofCore, utils::simple_merkle_tree::SimpleMerkleTree},
    traits::hasher::{FieldQHasher, MerkleZeroHasherWithMarkedLeaf},
};

use super::{
    claim_rewards_l1_user_header::UserRewardHeader,
    claim_rewards_l1_user_leaf::{UserRewardLeafCircuit, UserRewardLeafInput},
    claim_rewards_l1_user_mixed::{UserRewardLeftAggregateRightLeafCircuit, UserRewardLeftLeafRightAggregateCircuit},
    claim_rewards_l1_user_single_leaf::UserRewardSingleLeafCircuit,
    claim_rewards_l1_user_two_aggregate::{UserRewardTwoAggregateCircuit, USER_REWARD_AGG_WHITELIST_HEIGHT},
    claim_rewards_l1_user_two_leaf::UserRewardTwoLeafCircuit,
};

#[derive(Clone, Copy)]
pub enum UserRewardAggregateKind {
    SingleLeaf,
    TwoLeaf,
    LeftLeafRightAggregate,
    LeftAggregateRightLeaf,
    TwoAggregate,
}
pub struct UserRewardTreeResult<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub header: UserRewardHeader<F>,
    pub kind: UserRewardAggregateKind,
}
struct Node<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    proof: ProofWithPublicInputs<F, C, D>,
    header: UserRewardHeader<F>,
    kind: Option<UserRewardAggregateKind>,
}

pub struct UserRewardAggregateInclusions<F: RichField> {
    pub single_leaf: MerkleProofCore<QHashOut<F>>,
    pub two_leaf: MerkleProofCore<QHashOut<F>>,
    pub left_leaf_right_aggregate: MerkleProofCore<QHashOut<F>>,
    pub left_aggregate_right_leaf: MerkleProofCore<QHashOut<F>>,
    pub two_aggregate: MerkleProofCore<QHashOut<F>>,
    pub root: QHashOut<F>,
}
pub struct UserRewardTreeCircuitSet<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + FieldQHasher<C::F>,
{
    pub leaf: UserRewardLeafCircuit<C, D>,
    pub single_leaf: UserRewardSingleLeafCircuit<C, D>,
    pub two_leaf: UserRewardTwoLeafCircuit<C, D>,
    pub left_leaf_right_aggregate: UserRewardLeftLeafRightAggregateCircuit<C, D>,
    pub left_aggregate_right_leaf: UserRewardLeftAggregateRightLeafCircuit<C, D>,
    pub two_aggregate: UserRewardTwoAggregateCircuit<C, D>,
    pub inclusions: UserRewardAggregateInclusions<C::F>,
}
impl<C: GenericConfig<D>, const D: usize> UserRewardTreeCircuitSet<C, D>
where
    C::F: RichField + Extendable<D>,
    C::Hasher:
        AlgebraicHasher<C::F> + FieldQHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    pub fn new() -> Self {
        let leaf = UserRewardLeafCircuit::new();
        let single_leaf = UserRewardSingleLeafCircuit::new(leaf.circuit_data());
        let two_leaf = UserRewardTwoLeafCircuit::new(leaf.circuit_data());
        let left_leaf_right_aggregate = UserRewardLeftLeafRightAggregateCircuit::new(leaf.circuit_data(), two_leaf.circuit_data());
        let left_aggregate_right_leaf = UserRewardLeftAggregateRightLeafCircuit::new(leaf.circuit_data(), two_leaf.circuit_data());
        let two_aggregate = UserRewardTwoAggregateCircuit::new(
            &two_leaf.circuit_data().common,
            two_leaf.circuit_data().verifier_only.constants_sigmas_cap.height(),
        );
        let mut tree = SimpleMerkleTree::<C::Hasher, QHashOut<C::F>>::new(USER_REWARD_AGG_WHITELIST_HEIGHT as u8);
        tree.set_leaf(0, QHashOut(get_circuit_fingerprint_generic(&single_leaf.circuit_data().verifier_only)));
        tree.set_leaf(1, QHashOut(get_circuit_fingerprint_generic(&two_leaf.circuit_data().verifier_only)));
        tree.set_leaf(
            2,
            QHashOut(get_circuit_fingerprint_generic(&left_leaf_right_aggregate.circuit_data().verifier_only)),
        );
        tree.set_leaf(
            3,
            QHashOut(get_circuit_fingerprint_generic(&left_aggregate_right_leaf.circuit_data().verifier_only)),
        );
        tree.set_leaf(4, QHashOut(get_circuit_fingerprint_generic(&two_aggregate.circuit_data().verifier_only)));
        let root = tree.get_root();
        let inclusions = UserRewardAggregateInclusions {
            single_leaf: tree.get_leaf(0),
            two_leaf: tree.get_leaf(1),
            left_leaf_right_aggregate: tree.get_leaf(2),
            left_aggregate_right_leaf: tree.get_leaf(3),
            two_aggregate: tree.get_leaf(4),
            root,
        };
        Self {
            leaf,
            single_leaf,
            two_leaf,
            left_leaf_right_aggregate,
            left_aggregate_right_leaf,
            two_aggregate,
            inclusions,
        }
    }
    pub fn aggregate_parts(&self, kind: UserRewardAggregateKind) -> (&VerifierOnlyCircuitData<C, D>, &MerkleProofCore<QHashOut<C::F>>) {
        match kind {
            UserRewardAggregateKind::SingleLeaf => (&self.single_leaf.circuit_data().verifier_only, &self.inclusions.single_leaf),
            UserRewardAggregateKind::TwoLeaf => (&self.two_leaf.circuit_data().verifier_only, &self.inclusions.two_leaf),
            UserRewardAggregateKind::LeftLeafRightAggregate => (
                &self.left_leaf_right_aggregate.circuit_data().verifier_only,
                &self.inclusions.left_leaf_right_aggregate,
            ),
            UserRewardAggregateKind::LeftAggregateRightLeaf => (
                &self.left_aggregate_right_leaf.circuit_data().verifier_only,
                &self.inclusions.left_aggregate_right_leaf,
            ),
            UserRewardAggregateKind::TwoAggregate => (&self.two_aggregate.circuit_data().verifier_only, &self.inclusions.two_aggregate),
        }
    }
    pub fn verify(&self, result: &UserRewardTreeResult<C::F, C, D>) -> Result<()> {
        match result.kind {
            UserRewardAggregateKind::SingleLeaf => self.single_leaf.circuit_data().verify(result.proof.clone()),
            UserRewardAggregateKind::TwoLeaf => self.two_leaf.circuit_data().verify(result.proof.clone()),
            UserRewardAggregateKind::LeftLeafRightAggregate => self.left_leaf_right_aggregate.circuit_data().verify(result.proof.clone()),
            UserRewardAggregateKind::LeftAggregateRightLeaf => self.left_aggregate_right_leaf.circuit_data().verify(result.proof.clone()),
            UserRewardAggregateKind::TwoAggregate => self.two_aggregate.circuit_data().verify(result.proof.clone()),
        }
        .map_err(Into::into)
    }
    pub fn prove(&self, claims: &[UserRewardLeafInput<C::F>]) -> Result<UserRewardTreeResult<C::F, C, D>> {
        ensure!(!claims.is_empty(), "empty user reward tree");
        let mut nodes = claims
            .iter()
            .map(|claim| {
                let proof = self.leaf.prove(claim)?;
                let fields: [C::F; 19] = proof.public_inputs[..19].try_into().unwrap();
                Ok(Node {
                    proof,
                    header: UserRewardHeader { fields },
                    kind: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if nodes.len() == 1 {
            let node = nodes.pop().unwrap();
            let proof = self.single_leaf.prove(&node.proof, self.inclusions.root)?;
            return Ok(UserRewardTreeResult {
                proof,
                header: node.header,
                kind: UserRewardAggregateKind::SingleLeaf,
            });
        }
        while nodes.len() > 1 {
            let mut next = Vec::with_capacity((nodes.len() + 1) / 2);
            let mut it = nodes.into_iter();
            while let Some(left) = it.next() {
                let Some(right) = it.next() else {
                    next.push(left);
                    break;
                };
                let header = left.header.combine::<C::Hasher>(&right.header)?;
                let (proof, kind) = match (left.kind, right.kind) {
                    (None, None) => (
                        self.two_leaf.prove(&left.proof, &right.proof, self.inclusions.root)?,
                        UserRewardAggregateKind::TwoLeaf,
                    ),
                    (None, Some(rk)) => {
                        let (vd, inc) = self.aggregate_parts(rk);
                        (
                            self.left_leaf_right_aggregate.prove(&left.proof, &right.proof, vd, inc, &right.header)?,
                            UserRewardAggregateKind::LeftLeafRightAggregate,
                        )
                    }
                    (Some(lk), None) => {
                        let (vd, inc) = self.aggregate_parts(lk);
                        (
                            self.left_aggregate_right_leaf.prove(&right.proof, &left.proof, vd, inc, &left.header)?,
                            UserRewardAggregateKind::LeftAggregateRightLeaf,
                        )
                    }
                    (Some(lk), Some(rk)) => {
                        let (lvd, linc) = self.aggregate_parts(lk);
                        let (rvd, rinc) = self.aggregate_parts(rk);
                        (
                            self.two_aggregate
                                .prove((&left.proof, lvd, linc, &left.header), (&right.proof, rvd, rinc, &right.header))?,
                            UserRewardAggregateKind::TwoAggregate,
                        )
                    }
                };
                next.push(Node {
                    proof,
                    header,
                    kind: Some(kind),
                });
            }
            nodes = next;
        }
        let node = nodes.pop().unwrap();
        Ok(UserRewardTreeResult {
            proof: node.proof,
            header: node.header,
            kind: node.kind.unwrap(),
        })
    }
}
