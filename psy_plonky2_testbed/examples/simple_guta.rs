use std::collections::HashMap;

use cf_utils::timer::DebugTimer;
use parth_common::memory_stores::{mem_tree_v3::SimpleMemoryMerkleStoreV3, simple_memory_tag_tree_store::SimpleMemoryTagTreeStore};
use parth_core::{
    crypto::hash::{merkle_proof::DeltaMerkleProofCore, nca::nca_proof::PartialUpdateNearestCommonAncestorProof, traits::QFieldHashable},
    felt::ZeroableFelt,
    pgoldilocks::PoseidonHasher,
    protocol::core_types::{QNetworkTreeCircuitConstants, QNetworkTreeConstants},
    PHash, PF,
};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    }, hash::poseidon::PoseidonHash, plonk::config::PoseidonGoldilocksConfig
};
use psy_core::job::job_id::ProvingJobCircuitType;
use psy_data::{proof_input::guta::{VerifyEndCapSimpleStandardInput, VerifyTwoEndCapCircuitInput}, v1::qdata::user::PQEDUserLeaf};
use psy_plonky2_basic_helpers::verifier::{circuit_library::CircuitInfoLibraryCore, simple_circuit_library::SimpleCircuitLibrary};
use psy_plonky2_circuits::{
    coordinator::coordinator_helper::QEDCoordinatorCircuitManager, end_cap::dummy::DummyUPSStandardEndCapCircuit,
    generated::cached_circuit_library::get_cached_circuit_library, qstandard::QStandardCircuit,
};
use psy_plonky2_testbed::state::chain::{SimpleTestNetworkConfig, SIMPLE_TESTNET_DEFAULT_USER_STATE_TREE_ROOT};
type F = PF;
type Hash = PHash;
type Hasher = PoseidonHasher;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

type N = SimpleTestNetworkConfig;

struct SimpleChainState {
    pub checkpoint_tree: SimpleMemoryMerkleStoreV3<Hasher, Hash>,
    pub global_user_tree: SimpleMemoryMerkleStoreV3<Hasher, Hash>,
    pub user_leaf_store: HashMap<u64, PQEDUserLeaf<F, Hash>>,
    pub tag_tree_store: SimpleMemoryTagTreeStore<Hasher, Hash>,
    pub simple_witness_store: HashMap<Hash, Vec<u8>>,
    pub simple_proof_store: HashMap<Hash, Vec<u8>>,
}
impl SimpleChainState {
    pub fn new() -> Self {
        Self {
            checkpoint_tree: SimpleMemoryMerkleStoreV3::new(N::CHECKPOINT_TREE_HEIGHT),
            global_user_tree: SimpleMemoryMerkleStoreV3::new(N::GLOBAL_USER_TREE_HEIGHT),
            user_leaf_store: HashMap::new(),
            tag_tree_store: SimpleMemoryTagTreeStore::<Hasher, Hash>::new(2),
            simple_witness_store: HashMap::new(),
            simple_proof_store: HashMap::new(),
        }
    }
    pub fn insert_users_base(count: usize) -> anyhow::Result<()> {
        Ok(())
    }
}

struct SimpleChainTestbedCircuits {
    pub circuits: QEDCoordinatorCircuitManager<C, D>,
    pub dummy_end_cap_circuit: DummyUPSStandardEndCapCircuit<C, D>,
    pub circuit_library: SimpleCircuitLibrary<F>,
}

impl SimpleChainTestbedCircuits {
    pub fn new() -> Self {
        let mut timer = DebugTimer::new("SimpleChainTestbedCircuits::new");
        let public_key = Hash::rand();
        timer.lap("end generate public key");
        let circuit_library = get_cached_circuit_library::<F>();
        timer.lap("end get_cached_circuit_library");
        let circuits = QEDCoordinatorCircuitManager::new_with_library(
            &circuit_library,
            N::REALM_GLOBAL_USER_TREE_HEIGHT_USIZE,
            N::GLOBAL_USER_TREE_HEIGHT_USIZE,
            N::GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT,
            N::CHECKPOINT_TREE_HEIGHT_USIZE,
            N::GROUP_REALM_HEIGHT as usize,
            N::MAX_USERS_TO_REGISTER_PER_PROOF,
            N::ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF,
            SIMPLE_TESTNET_DEFAULT_USER_STATE_TREE_ROOT,
            N::BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT,
            N::BATCH_USER_REGISTRATION_MAX_SUB_TREES,
            N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE,
            N::BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT,
            N::MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE,
            public_key,
        );
        timer.lap("end QEDCoordinatorCircuitManager::new_with_library");
        let dummy_end_cap_circuit = DummyUPSStandardEndCapCircuit::<C, D>::new_without_minifier();
        timer.lap("end DummyUPSStandardEndCapCircuit::new_without_minifier");
        Self {
            circuits,
            dummy_end_cap_circuit,
            circuit_library,
        }
    }
}

struct SimpleChainTestbed {
    pub state: SimpleChainState,
    pub circuits: SimpleChainTestbedCircuits,
}

impl SimpleChainTestbed {
    pub fn new() -> Self {
        let state = SimpleChainState::new();
        let circuits = SimpleChainTestbedCircuits::new();
        Self { state, circuits }
    }

    pub fn set_user_leaf(&mut self, user_leaf: PQEDUserLeaf<F, Hash>) -> DeltaMerkleProofCore<Hash> {
        self.state.user_leaf_store.insert(user_leaf.user_id.to_noncanonical_u64(), user_leaf);
        self.state
            .global_user_tree
            .set_leaf(user_leaf.user_id.to_noncanonical_u64(), user_leaf.qfhash::<Hasher>())
    }

    pub fn test_simple_guta_proofs(&mut self) -> anyhow::Result<()> {
        let checkpoint_0_hash = Hash::rand();
        let checkpoint_1_hash = Hash::rand();
        let checkpoint_2_hash = Hash::rand();

        self.state.checkpoint_tree.set_leaf(0, checkpoint_0_hash);
        self.state.checkpoint_tree.set_leaf(1, checkpoint_1_hash);
        self.state.checkpoint_tree.set_leaf(2, checkpoint_2_hash);

        let mut user_0 = PQEDUserLeaf {
            user_id: F::from_noncanonical_u64(0),
            public_key: Hash::rand(),
            nonce: F::ZERO_VALUE,
            last_checkpoint_id: F::ZERO_VALUE,
            user_state_tree_root: SIMPLE_TESTNET_DEFAULT_USER_STATE_TREE_ROOT,
            balance: F::ZERO_VALUE,
            event_index: F::ZERO_VALUE,
        };

        self.set_user_leaf(user_0.clone());

        let mut user_1 = PQEDUserLeaf {
            user_id: F::from_noncanonical_u64(1),
            public_key: Hash::rand(),
            nonce: F::ZERO_VALUE,
            last_checkpoint_id: F::ZERO_VALUE,
            user_state_tree_root: SIMPLE_TESTNET_DEFAULT_USER_STATE_TREE_ROOT,
            balance: F::ZERO_VALUE,
            event_index: F::ZERO_VALUE,
        };
        self.set_user_leaf(user_1.clone());

        let user_0_new_state_root = Hash::rand();
        let user_1_new_state_root = Hash::rand();

        let new_checkpoint_id = 2;
        let new_checkpoint_root = self.state.checkpoint_tree.get_root();
        let new_checkpoint_merkle_proof = self
            .state
            .checkpoint_tree
            .get_leaf(new_checkpoint_id);

        let mut timer = DebugTimer::new("test_simple_guta_proofs");
        let (new_user_leaf_0, public_inputs_expected_0, guta_stats_0, end_cap_result_0, proof_0) =
            self.circuits.dummy_end_cap_circuit.generate_proof_for_inputs(
                &user_0,
                user_0_new_state_root,
                new_checkpoint_id,
                new_checkpoint_root,
                2,
                10,
                N::GLOBAL_USER_TREE_HEIGHT,
            )?;
        timer.lap("end generate_proof_for_inputs user 0");

        let (new_user_leaf_1, public_inputs_expected_1, guta_stats_1, end_cap_result_1, proof_1) =
            self.circuits.dummy_end_cap_circuit.generate_proof_for_inputs(
                &user_1,
                user_1_new_state_root,
                new_checkpoint_id,
                new_checkpoint_root,
                2,
                10,
                N::GLOBAL_USER_TREE_HEIGHT,
            )?;
        timer.lap("end generate_proof_for_inputs user 1");

        let dmp_0 = self.set_user_leaf(new_user_leaf_0);
        let dmp_1 = self.set_user_leaf(new_user_leaf_1);
        let nca = PartialUpdateNearestCommonAncestorProof::<Hash>::from_delta_merkle_proof_pair::<Hasher>(&dmp_0, &dmp_1);
        let end_cap_input_0 = VerifyEndCapSimpleStandardInput {
            guta_stats: guta_stats_0,
            checkpoint_root: new_checkpoint_root,
            checkpoint_historical_merkle_proof: new_checkpoint_merkle_proof.clone(),
        };
        let end_cap_input_1 = VerifyEndCapSimpleStandardInput {
            guta_stats: guta_stats_1,
            checkpoint_root: new_checkpoint_root,
            checkpoint_historical_merkle_proof: new_checkpoint_merkle_proof.clone(),
        };

        let two_end_cap_input = VerifyTwoEndCapCircuitInput::<F, Hash> {
            guta_circuit_whitelist: self.circuits.circuit_library.get_group_inclusion_proof(ProvingJobCircuitType::GUTATwoGUTA, ProvingJobCircuitType::GUTATwoGUTA)?.root,
            a_end_cap: end_cap_input_0,
            b_end_cap: end_cap_input_1,
            nca_proof: nca,
        };
        let worker_public_key = Hash::rand();
        timer.lap("start verify_two_end_cap.prove_base");
        let two_end_cap_proof = self.circuits.circuits.guta_circuits.verify_two_end_cap
        .prove_base(
            worker_public_key, &two_end_cap_input, &proof_0, &proof_1, self.circuits.dummy_end_cap_circuit.get_verifier_config_ref())?;
        timer.lap("end verify_two_end_cap.prove_base");

        if two_end_cap_proof.public_inputs.len() == 0 {
            anyhow::bail!("two_end_cap_proof public inputs length mismatch");
        }

        Ok(())
    }
}

fn main() {
    let mut testbed = SimpleChainTestbed::new();
    testbed.test_simple_guta_proofs().unwrap();

}
