use std::fmt::Debug;

use kvq::traits::KVQPair;
use plonky2::hash::hash_types::RichField;
use psy_client_common::{
    data::qhashout::QHashOut,
    job::{
        id::{ProvingJobCircuitType, QProvingJobDataID},
        traits::QProofStore,
    },
    utils::graph::BidirectionalGraph,
};
use serde::{de::DeserializeOwned, Serialize};

use super::{
    data::{CircuitInputWithDependencies, CircuitInputWithJobId},
    generate_tree_inputs_with_position,
    tree_planner::BinaryTreePlanner,
    AggStateTrackableInput, AggStateTrackableWithEventsInput, AggStateTransition, AggStateTransitionWithEvents, DummyAggStateTransition,
    DummyAggStateTransitionWithEvents, TPLeafAggregator, WithDummyStateTransition,
};

pub fn get_dummy_tree_prover_ids_op_circuit(
    circuit_type: ProvingJobCircuitType,
    dummy_type: ProvingJobCircuitType,
    checkpoint_id: u64,
    group_id: u32,
    leaf_count: usize,
) -> Vec<Vec<QProvingJobDataID>> {
    let dummy_id = QProvingJobDataID::new_proof_job_id(checkpoint_id, 0, group_id, dummy_type, 0, 0);
    let leaves = (0..leaf_count)
        .map(|i| QProvingJobDataID::core_op_witness(checkpoint_id, 0, group_id, circuit_type, 0, i as u32))
        .collect::<Vec<_>>();
    get_dummy_tree_prover_ids(&leaves, dummy_id)
}

pub fn get_dummy_tree_prover_ids_leaf_template(
    leaf_template: QProvingJobDataID,
    dummy_id: QProvingJobDataID,
    leaf_count: usize,
) -> Vec<Vec<QProvingJobDataID>> {
    let leaves = (0..leaf_count).map(|i| leaf_template.with_task_index(i as u32)).collect::<Vec<_>>();
    get_dummy_tree_prover_ids(&leaves, dummy_id)
}
pub fn get_dummy_tree_prover_ids(leaves: &[QProvingJobDataID], dummy_id: QProvingJobDataID) -> Vec<Vec<QProvingJobDataID>> {
    if leaves.len() == 0 {
        vec![vec![dummy_id]]
    } else {
        let leaves_len = leaves.len();
        let levels = BinaryTreePlanner::new(leaves_len).levels;
        let mut job_ids = vec![leaves.to_vec()];

        for level_nodes in levels.into_iter() {
            let mut level_job_ids: Vec<QProvingJobDataID> = Vec::with_capacity(level_nodes.len());
            for node in level_nodes.into_iter() {
                let left_proof_id = job_ids[node.left_job.level as usize][node.left_job.index as usize].get_output_id();
                let self_witness_id = left_proof_id.get_tree_parent_proof_input_id();
                level_job_ids.push(self_witness_id);
            }
            job_ids.push(level_job_ids);
        }
        job_ids
    }
}
pub fn prepare_plan_tree_prover_from_leaves<
    F: RichField,
    LA: TPLeafAggregator<CircuitInputWithJobId<IL>, IO>,
    IL: Debug + Clone + Serialize + DeserializeOwned + PartialEq + AggStateTrackableInput<F>,
    IO: Debug + Clone + Serialize + DeserializeOwned + PartialEq + WithDummyStateTransition<F> + AggStateTrackableInput<F>,
>(
    leaves: &[CircuitInputWithJobId<IL>],
    dummy_id: QProvingJobDataID,
    dummy_state_root: QHashOut<F>,
    allowed_circuit_hashes_root: QHashOut<F>,
) -> anyhow::Result<(
    Vec<KVQPair<QProvingJobDataID, Vec<u8>>>,
    Vec<Vec<QProvingJobDataID>>,
    AggStateTransition<F>,
)> {
    if leaves.len() == 0 {
        //let dummy = IO::get_dummy_value(dummy_state_root);
        let dummy = DummyAggStateTransition {
            state_transition_hash: dummy_state_root,
            allowed_circuit_hashes_root: allowed_circuit_hashes_root,
            is_deploy_contracts: dummy_id.circuit_type == ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
            is_register_users: dummy_id.circuit_type == ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
        };
        let dv = bincode::serialize(&dummy)?;
        let dummy = IO::get_dummy_value(dummy_state_root);

        return Ok((
            vec![KVQPair { key: dummy_id, value: dv }],
            vec![vec![dummy_id]],
            dummy.get_state_transition(),
        ));
    } else if leaves.len() == 1 {
        return Ok((vec![], vec![vec![leaves[0].job_id]], leaves[0].get_state_transition()));
    }

    let levels = generate_tree_inputs_with_position::<LA, CircuitInputWithJobId<IL>, IO>(leaves);

    let proof_store_set_count = levels.iter().map(|l| l.len()).sum::<usize>();
    let mut future_ps_values = Vec::with_capacity(proof_store_set_count + 5);

    let mut job_ids = vec![leaves.iter().map(|x| x.job_id).collect::<Vec<_>>()];
    let total_levels = levels.len();
    let mut last_node_state = AggStateTransition::default();

    for (level, level_nodes) in levels.into_iter().enumerate() {
        let mut level_job_ids: Vec<QProvingJobDataID> = Vec::with_capacity(level_nodes.len());
        let total_nodes = level_nodes.len();

        for (index, node) in level_nodes.into_iter().enumerate() {
            let left_proof_id = job_ids[node.tree_position.left_job.level as usize][node.tree_position.left_job.index as usize].get_output_id();
            let right_proof_id = job_ids[node.tree_position.right_job.level as usize][node.tree_position.right_job.index as usize].get_output_id();
            let self_witness_id = left_proof_id.get_tree_parent_proof_input_id();
            let dependencies = vec![left_proof_id, right_proof_id];
            if (level + 1) == total_levels && (index + 1) == total_nodes {
                last_node_state = node.input.get_state_transition();
            }
            let input_data = bincode::serialize(&CircuitInputWithDependencies {
                input: node.input,
                dependencies,
            })?;
            future_ps_values.push(KVQPair {
                key: self_witness_id,
                value: input_data,
            });
            //proof_store.set_bytes_by_id(self_witness_id, &input_data)?;
            level_job_ids.push(self_witness_id);
        }
        job_ids.push(level_job_ids);
    }
    Ok((future_ps_values, job_ids, last_node_state))
}

pub fn plan_tree_prover_from_leaves<
    F: RichField,
    PS: QProofStore,
    LA: TPLeafAggregator<CircuitInputWithJobId<IL>, IO>,
    IL: Debug + Clone + Serialize + DeserializeOwned + PartialEq + AggStateTrackableInput<F>,
    IO: Debug + Clone + Serialize + DeserializeOwned + PartialEq + WithDummyStateTransition<F> + AggStateTrackableInput<F>,
>(
    leaves: &[CircuitInputWithJobId<IL>],
    proof_store: &mut PS,
    dummy_id: QProvingJobDataID,
    dummy_state_root: QHashOut<F>,
    allowed_circuit_hashes_root: QHashOut<F>,
) -> anyhow::Result<(Vec<Vec<QProvingJobDataID>>, AggStateTransition<F>, BidirectionalGraph<QProvingJobDataID>)> {
    if leaves.len() == 0 {
        //let dummy = IO::get_dummy_value(dummy_state_root);
        let dummy = DummyAggStateTransition {
            state_transition_hash: dummy_state_root,
            allowed_circuit_hashes_root: allowed_circuit_hashes_root,
            is_deploy_contracts: dummy_id.circuit_type == ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
            is_register_users: dummy_id.circuit_type == ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
        };
        proof_store.set_bytes_by_id(dummy_id, &bincode::serialize(&dummy)?)?;
        let dummy = IO::get_dummy_value(dummy_state_root);

        let mut graph = BidirectionalGraph::new();
        graph.add_node(dummy_id.get_output_id());
        return Ok((vec![vec![dummy_id]], dummy.get_state_transition(), graph));
    } else if leaves.len() == 1 {
        let mut graph = BidirectionalGraph::new();
        graph.add_node(leaves[0].job_id.get_output_id());
        return Ok((vec![vec![leaves[0].job_id]], leaves[0].get_state_transition(), graph));
    }

    let levels = generate_tree_inputs_with_position::<LA, CircuitInputWithJobId<IL>, IO>(leaves);
    let mut job_ids = vec![leaves.iter().map(|x| x.job_id).collect::<Vec<_>>()];
    let total_levels = levels.len();
    let mut last_node_state = AggStateTransition::default();

    let mut graph = BidirectionalGraph::new();

    for &leaf_job in &job_ids[0] {
        graph.add_node(leaf_job.get_output_id());
    }

    for (level, level_nodes) in levels.into_iter().enumerate() {
        let mut level_job_ids: Vec<QProvingJobDataID> = Vec::with_capacity(level_nodes.len());
        let total_nodes = level_nodes.len();

        for (index, node) in level_nodes.into_iter().enumerate() {
            let left_proof_id = job_ids[node.tree_position.left_job.level as usize][node.tree_position.left_job.index as usize].get_output_id();
            let right_proof_id = job_ids[node.tree_position.right_job.level as usize][node.tree_position.right_job.index as usize].get_output_id();
            let self_witness_id = left_proof_id.get_tree_parent_proof_input_id();
            let dependencies = vec![left_proof_id, right_proof_id];
            if (level + 1) == total_levels && (index + 1) == total_nodes {
                last_node_state = node.input.get_state_transition();
            }

            graph.add_node(self_witness_id.get_output_id());
            for &dep in &dependencies {
                graph.add_edge(self_witness_id.get_output_id(), dep);
            }

            let input_data = bincode::serialize(&CircuitInputWithDependencies {
                input: node.input,
                dependencies,
            })?;
            proof_store.set_bytes_by_id(self_witness_id, &input_data)?;
            level_job_ids.push(self_witness_id);
        }
        job_ids.push(level_job_ids);
    }
    Ok((job_ids, last_node_state, graph))
}

pub fn plan_tree_prover_from_leaves_with_events<
    F: RichField,
    PS: QProofStore,
    LA: TPLeafAggregator<CircuitInputWithJobId<IL>, IO>,
    IL: Debug + Clone + Serialize + DeserializeOwned + PartialEq + AggStateTrackableWithEventsInput<F>,
    IO: Debug + Clone + Serialize + DeserializeOwned + PartialEq + WithDummyStateTransition<F> + AggStateTrackableWithEventsInput<F>,
>(
    leaves: &[CircuitInputWithJobId<IL>],
    proof_store: &mut PS,
    dummy_id: QProvingJobDataID,
    dummy_state_root: QHashOut<F>,
    allowed_circuit_hashes_root: QHashOut<F>,
) -> anyhow::Result<(
    Vec<Vec<QProvingJobDataID>>,
    AggStateTransitionWithEvents<F>,
    BidirectionalGraph<QProvingJobDataID>,
)> {
    if leaves.len() == 0 {
        let dummy = DummyAggStateTransitionWithEvents {
            state_transition_hash: dummy_state_root,
            allowed_circuit_hashes_root: allowed_circuit_hashes_root,
            event_transition_hash: QHashOut::ZERO,
        };
        proof_store.set_bytes_by_id(dummy_id, &bincode::serialize(&dummy)?)?;
        let dummy = IO::get_dummy_value(dummy_state_root);

        let mut graph = BidirectionalGraph::new();
        graph.add_node(dummy_id.get_output_id());
        return Ok((vec![vec![dummy_id]], dummy.get_state_transition_with_events(), graph));
    } else if leaves.len() == 1 {
        let mut graph = BidirectionalGraph::new();
        graph.add_node(leaves[0].job_id.get_output_id());
        return Ok((vec![vec![leaves[0].job_id]], leaves[0].get_state_transition_with_events(), graph));
    }

    let levels = generate_tree_inputs_with_position::<LA, CircuitInputWithJobId<IL>, IO>(leaves);
    let mut job_ids = vec![leaves.iter().map(|x| x.job_id).collect::<Vec<_>>()];
    let total_levels = levels.len();
    let mut last_node_state = AggStateTransitionWithEvents::default();

    let mut graph = BidirectionalGraph::new();

    for &leaf_job in &job_ids[0] {
        graph.add_node(leaf_job.get_output_id());
    }
    for (level, level_nodes) in levels.into_iter().enumerate() {
        let mut level_job_ids: Vec<QProvingJobDataID> = Vec::with_capacity(level_nodes.len());
        let last_index = level_nodes.len();
        for (index, node) in level_nodes.into_iter().enumerate() {
            let left_proof_id = job_ids[node.tree_position.left_job.level as usize][node.tree_position.left_job.index as usize].get_output_id();
            let right_proof_id = job_ids[node.tree_position.right_job.level as usize][node.tree_position.right_job.index as usize].get_output_id();
            let self_witness_id = left_proof_id.get_tree_parent_proof_input_id();
            let dependencies = vec![left_proof_id, right_proof_id];
            if (level + 1) == total_levels && (index + 1) == last_index {
                last_node_state = node.input.get_state_transition_with_events();
            }

            graph.add_node(self_witness_id.get_output_id());
            for &dep in &dependencies {
                graph.add_edge(self_witness_id.get_output_id(), dep);
            }

            let input_data = bincode::serialize(&CircuitInputWithDependencies {
                input: node.input,
                dependencies,
            })?;
            proof_store.set_bytes_by_id(self_witness_id, &input_data)?;
            level_job_ids.push(self_witness_id);
        }
        job_ids.push(level_job_ids);
    }
    Ok((job_ids, last_node_state, graph))
}

pub fn prepare_plan_tree_prover_from_leaves_with_events<
    F: RichField,
    LA: TPLeafAggregator<CircuitInputWithJobId<IL>, IO>,
    IL: Debug + Clone + Serialize + DeserializeOwned + PartialEq + AggStateTrackableWithEventsInput<F>,
    IO: Debug + Clone + Serialize + DeserializeOwned + PartialEq + WithDummyStateTransition<F> + AggStateTrackableWithEventsInput<F>,
>(
    leaves: &[CircuitInputWithJobId<IL>],
    dummy_id: QProvingJobDataID,
    dummy_state_root: QHashOut<F>,
    allowed_circuit_hashes_root: QHashOut<F>,
) -> anyhow::Result<(
    Vec<KVQPair<QProvingJobDataID, Vec<u8>>>,
    Vec<Vec<QProvingJobDataID>>,
    AggStateTransitionWithEvents<F>,
)> {
    if leaves.len() == 0 {
        let dummy = DummyAggStateTransitionWithEvents {
            state_transition_hash: dummy_state_root,
            allowed_circuit_hashes_root: allowed_circuit_hashes_root,
            event_transition_hash: QHashOut::ZERO,
        };
        let dv = bincode::serialize(&dummy)?;
        let dummy = IO::get_dummy_value(dummy_state_root);

        return Ok((
            vec![KVQPair { key: dummy_id, value: dv }],
            vec![vec![dummy_id]],
            dummy.get_state_transition_with_events(),
        ));
    } else if leaves.len() == 1 {
        return Ok((vec![], vec![vec![leaves[0].job_id]], leaves[0].get_state_transition_with_events()));
    }

    let levels = generate_tree_inputs_with_position::<LA, CircuitInputWithJobId<IL>, IO>(leaves);
    let proof_store_set_count = levels.iter().map(|l| l.len()).sum::<usize>();
    let mut future_ps_values = Vec::with_capacity(proof_store_set_count + 5);

    let mut job_ids = vec![leaves.iter().map(|x| x.job_id).collect::<Vec<_>>()];
    let total_levels = levels.len();
    let mut last_node_state = AggStateTransitionWithEvents::default();
    for (level, level_nodes) in levels.into_iter().enumerate() {
        let mut level_job_ids: Vec<QProvingJobDataID> = Vec::with_capacity(level_nodes.len());
        let last_index = level_nodes.len();
        for (index, node) in level_nodes.into_iter().enumerate() {
            let left_proof_id = job_ids[node.tree_position.left_job.level as usize][node.tree_position.left_job.index as usize].get_output_id();
            let right_proof_id = job_ids[node.tree_position.right_job.level as usize][node.tree_position.right_job.index as usize].get_output_id();
            let self_witness_id = left_proof_id.get_tree_parent_proof_input_id();
            let dependencies = vec![left_proof_id, right_proof_id];
            if (level + 1) == total_levels && (index + 1) == last_index {
                last_node_state = node.input.get_state_transition_with_events();
            }
            let input_data = bincode::serialize(&CircuitInputWithDependencies {
                input: node.input,
                dependencies,
            })?;
            //proof_store.set_bytes_by_id(self_witness_id, &input_data)?;
            future_ps_values.push(KVQPair {
                key: self_witness_id,
                value: input_data,
            });
            level_job_ids.push(self_witness_id);
        }
        job_ids.push(level_job_ids);
    }
    Ok((future_ps_values, job_ids, last_node_state))
}
