use plonky2::{
    hash::hash_types::HashOut,
    plonk::{
        circuit_data::{CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::{
    common::witnesses::qrecursion::{
        header::QRecursionAggStandardHeader,
        proof_data::{QStandardBinaryTreeCircuitType, SimpleQTreeRecursionManagerInclusionProofs},
    },
    hash::{
        merkle::{
            core::{DeltaMerkleProofCore, MerkleProofCore},
            utils::simple_merkle_tree::SimpleMerkleTree,
        },
        traits::hasher::MerkleZeroHasherWithMarkedLeaf,
    },
};
use psy_vm::ups::circuit_manager::{PortableQTreeRecursion, PortableQTreeRecursionCircuitsData, PortableQTreeRecursionCircuitsProve};

use crate::{
    circuits::traits::qstandard::QStandardCircuit,
    treeprover::qrecursion::standard::{
        config::QRECURSION_CIRCUIT_WHITELIST_HEIGHT, manager::leaf_circuit_set::QStandardBinaryRecursionTreeCircuitSet,
    },
};
#[derive(Debug)]
pub struct PortableQTreeRecursionCircuits<C: GenericConfig<D>, const D: usize>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    //pub root_circuit: QRecursionStandardRootCircuit<C,D>,
    pub circuit_set: QStandardBinaryRecursionTreeCircuitSet<C, D>,
    pub circuit_inclusion_proofs: SimpleQTreeRecursionManagerInclusionProofs<C::F>,
}

impl<C: GenericConfig<D>, const D: usize> PortableQTreeRecursionCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    pub fn new(
        q_recursion_tree_height: usize,
        leaf_circuit_config_id: u64,
        leaf_verifier_data_cap_height: usize,
        leaf_child_common_data: &CommonCircuitData<C::F, D>,
    ) -> Self {
        let circuit_set = QStandardBinaryRecursionTreeCircuitSet::<C, D>::new(
            q_recursion_tree_height,
            leaf_circuit_config_id,
            leaf_verifier_data_cap_height,
            leaf_child_common_data,
        );
        let mut tmp_circuit_whitelist_tree = SimpleMerkleTree::<C::Hasher, QHashOut<C::F>>::new(QRECURSION_CIRCUIT_WHITELIST_HEIGHT as u8);

        tmp_circuit_whitelist_tree.set_leaf(
            QStandardBinaryTreeCircuitType::SingleLeaf.into(),
            circuit_set.single_leaf_circuit.get_fingerprint(),
        );

        tmp_circuit_whitelist_tree.set_leaf(
            QStandardBinaryTreeCircuitType::TwoLeaf.into(),
            circuit_set.two_leaf_circuit.get_fingerprint(),
        );

        tmp_circuit_whitelist_tree.set_leaf(
            QStandardBinaryTreeCircuitType::TwoAgg.into(),
            circuit_set.two_agg_circuit.get_fingerprint(),
        );

        tmp_circuit_whitelist_tree.set_leaf(
            QStandardBinaryTreeCircuitType::LeftAggRightLeaf.into(),
            circuit_set.left_agg_right_leaf_circuit.get_fingerprint(),
        );

        tmp_circuit_whitelist_tree.set_leaf(
            QStandardBinaryTreeCircuitType::LeftLeafRightAgg.into(),
            circuit_set.left_leaf_right_agg_circuit.get_fingerprint(),
        );

        let circuit_inclusion_proofs = SimpleQTreeRecursionManagerInclusionProofs {
            single_leaf_circuit_merkle_proof: tmp_circuit_whitelist_tree.get_leaf(QStandardBinaryTreeCircuitType::SingleLeaf.into()),
            two_leaf_circuit_merkle_proof: tmp_circuit_whitelist_tree.get_leaf(QStandardBinaryTreeCircuitType::TwoLeaf.into()),
            two_agg_circuit_merkle_proof: tmp_circuit_whitelist_tree.get_leaf(QStandardBinaryTreeCircuitType::TwoAgg.into()),
            left_leaf_right_agg_circuit_merkle_proof: tmp_circuit_whitelist_tree.get_leaf(QStandardBinaryTreeCircuitType::LeftLeafRightAgg.into()),
            left_agg_right_leaf_circuit_merkle_proof: tmp_circuit_whitelist_tree.get_leaf(QStandardBinaryTreeCircuitType::LeftAggRightLeaf.into()),
            circuit_whitelist_tree_root: tmp_circuit_whitelist_tree.get_root(),
        };

        /* let root_circuit = QRecursionStandardRootCircuit::<C,D>::new_with_minifier(
            circuit_set.two_agg_circuit.get_common_circuit_data_ref(),
            circuit_set.two_agg_circuit.get_verifier_config_ref().constants_sigmas_cap.height(),
            circuit_inclusion_proofs.circuit_whitelist_tree_root,
        );*/

        Self {
            //root_circuit,
            circuit_set,
            circuit_inclusion_proofs,
        }
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D>, const D: usize> PortableQTreeRecursionCircuitsData<C, D> for PortableQTreeRecursionCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn single_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.circuit_set.single_leaf_circuit.get_fingerprint()
    }
    async fn two_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.circuit_set.two_leaf_circuit.get_fingerprint()
    }
    async fn two_agg_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.circuit_set.two_agg_circuit.get_fingerprint()
    }
    async fn left_leaf_right_agg_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.circuit_set.left_leaf_right_agg_circuit.get_fingerprint()
    }
    async fn left_agg_right_leaf_circuit_fingerprint(&self) -> QHashOut<C::F> {
        self.circuit_set.left_agg_right_leaf_circuit.get_fingerprint()
    }
    async fn single_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.circuit_set.single_leaf_circuit.get_verifier_config_ref().clone().into()
    }
    async fn two_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.circuit_set.two_leaf_circuit.get_verifier_config_ref().clone().into()
    }
    async fn two_agg_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.circuit_set.two_agg_circuit.get_verifier_config_ref().clone().into()
    }
    async fn left_leaf_right_agg_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.circuit_set.left_leaf_right_agg_circuit.get_verifier_config_ref().clone().into()
    }
    async fn left_agg_right_leaf_circuit_verifier_config(&self) -> VerifierOnlyCircuitData<C, D> {
        self.circuit_set.left_agg_right_leaf_circuit.get_verifier_config_ref().clone().into()
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D>, const D: usize> PortableQTreeRecursionCircuitsProve<C, D> for PortableQTreeRecursionCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn get_verifier_data_by_type(&self, circuit_type: QStandardBinaryTreeCircuitType) -> VerifierOnlyCircuitData<C, D> {
        match circuit_type {
            QStandardBinaryTreeCircuitType::None => {
                panic!("tried to get verifier data for a circuit with type None")
            }
            QStandardBinaryTreeCircuitType::SingleLeaf => self.single_leaf_circuit_verifier_config().await,
            QStandardBinaryTreeCircuitType::TwoLeaf => self.two_leaf_circuit_verifier_config().await,
            QStandardBinaryTreeCircuitType::TwoAgg => self.two_agg_circuit_verifier_config().await,
            QStandardBinaryTreeCircuitType::LeftLeafRightAgg => self.left_leaf_right_agg_circuit_verifier_config().await,
            QStandardBinaryTreeCircuitType::LeftAggRightLeaf => self.left_agg_right_leaf_circuit_verifier_config().await,
            QStandardBinaryTreeCircuitType::Root => {
                panic!("tried to get verifier data for a circuit with type Root")
            }
        }
    }
    async fn prove_single_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<C::F>,
        single_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        single_proof: &ProofWithPublicInputs<C::F, C, D>,
        single_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.circuit_set
            .single_leaf_circuit
            .prove_base(agg_circuit_whitelist_root, single_insert_leaf_proof, single_proof, &single_verifier_data)
    }

    async fn prove_two_leaf_circuit(
        &self,
        agg_circuit_whitelist_root: QHashOut<C::F>,
        left_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.circuit_set.two_leaf_circuit.prove_base(
            agg_circuit_whitelist_root,
            left_insert_leaf_proof,
            left_proof,
            &left_verifier_data,
            right_insert_leaf_proof,
            right_proof,
            &right_verifier_data,
        )
    }

    async fn prove_two_agg_circuit(
        &self,
        left_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        left_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        right_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.circuit_set.two_agg_circuit.prove_base(
            left_agg_whitelist_merkle_proof,
            left_agg_proof_header,
            left_proof,
            &left_verifier_data,
            right_agg_whitelist_merkle_proof,
            right_agg_proof_header,
            right_proof,
            &right_verifier_data,
        )
    }

    async fn prove_left_leaf_right_agg_circuit(
        &self,
        left_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        right_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.circuit_set.left_leaf_right_agg_circuit.prove_base(
            left_insert_leaf_proof,
            left_proof,
            &left_verifier_data,
            right_agg_whitelist_merkle_proof,
            right_agg_proof_header,
            right_proof,
            &right_verifier_data,
        )
    }

    async fn prove_left_agg_right_leaf_circuit(
        &self,
        left_agg_whitelist_merkle_proof: &MerkleProofCore<QHashOut<C::F>>,
        left_agg_proof_header: &QRecursionAggStandardHeader<C::F>,
        left_proof: &ProofWithPublicInputs<C::F, C, D>,
        left_verifier_data: &VerifierOnlyCircuitData<C, D>,
        right_insert_leaf_proof: &DeltaMerkleProofCore<QHashOut<C::F>>,
        right_proof: &ProofWithPublicInputs<C::F, C, D>,
        right_verifier_data: &VerifierOnlyCircuitData<C, D>,
    ) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
        self.circuit_set.left_agg_right_leaf_circuit.prove_base(
            left_agg_whitelist_merkle_proof,
            left_agg_proof_header,
            left_proof,
            &left_verifier_data,
            right_insert_leaf_proof,
            right_proof,
            &right_verifier_data,
        )
    }
}

#[cfg_attr(not(target_arch = "wasm32"), maybe_async::maybe_async)]
#[cfg_attr(target_arch = "wasm32", maybe_async::maybe_async(?Send))]
impl<C: GenericConfig<D>, const D: usize> PortableQTreeRecursion<C, D> for PortableQTreeRecursionCircuits<C, D>
where
    C::Hasher: AlgebraicHasher<C::F> + MerkleZeroHasherWithMarkedLeaf<HashOut<C::F>> + MerkleZeroHasherWithMarkedLeaf<QHashOut<C::F>>,
{
    async fn circuit_inclusion_proofs(&self) -> &SimpleQTreeRecursionManagerInclusionProofs<C::F> {
        &self.circuit_inclusion_proofs
    }
}
