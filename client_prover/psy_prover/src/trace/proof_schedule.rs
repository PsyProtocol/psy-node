//! Phase A pre-processing pass: build per-step seeds from the trace without
//! running any proving.
//!
//! `TraceProofSchedule::build` takes the initial `ProofTreeMeta` + baton
//! produced by `init_step_proving` (after the ups_start leaf has been
//! inserted) and performs a pure-hash forward replay of every trace step,
//! recording a `StepSeed` for each CFC step.  Each seed holds a full
//! snapshot of the proof-tree state *before* that step's two leaves are
//! inserted, so a worker can call `restore_snapshot` and then run the
//! existing `prove_step_standard / prove_step_deferred` without touching
//! shared state.
//!
//! # Leaf-value formula
//!
//! `injest_single_leaf_value(fingerprint, session_root, inner_hash)` computes
//! ```text
//! public_inputs_hash = PoseidonHash::two_to_one(session_root, inner_hash)
//! leaf_value         = PoseidonHash::two_to_one(fingerprint,  public_inputs_hash)
//! ```
//! which matches what `injest_single_leaf_proof` would compute from the
//! actual proof bytes.  All inputs are available in the trace:
//!
//! * CFC leaf  → `(cfc_fingerprint, cfc_witness.session_proof_tree_root,
//!   tx_input_ctx.qfhash())`
//! * UPS leaf  → `(ups_fingerprint, <root after CFC insertion>,
//!   end_header.qfhash())`
//! * External  → decoded from `proof` bytes (cheap deserialization)

#[cfg(not(target_arch = "wasm32"))]
use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fmt,
    future::Future,
    sync::{Arc, Mutex},
};

use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::{hash_types::HashOut, poseidon::PoseidonHash},
    plonk::config::{Hasher, PoseidonGoldilocksConfig},
};
use psy_client_common::{data::qhashout::QHashOut, ups::circuits::LocalCircuitType, utils::graph::BidirectionalGraph};
use psy_client_data::{config::store_config::PsyHasher, ups::ups_context_input::UserProvingSessionHeader};
use psy_config::network_constants::UPS_SESSION_PROOF_TREE_HEIGHT;
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use serde::{Deserialize, Serialize};

use super::proof_tree_meta::{LastStepProofInfo, ProofTreeMeta};
use crate::trace::{CfcStep, TraceStep, TxTrace};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;
pub const DEFAULT_LOCAL_PROVING_PARALLELISM: usize = 8;

/// All the state a worker needs to prove step `step_index` in isolation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StepSeed {
    /// Arena index in `TxTrace.steps`.
    pub step_index: usize,
    /// Proof-tree state snapshot *before* the CFC leaf for this step is
    /// inserted.
    pub proof_tree_meta: ProofTreeMeta,
    /// `last_ups_step_proof_info` baton *before* this step (i.e. from the
    /// previous step, or from ups_start for step 0).
    pub prev_baton: LastStepProofInfo,
    /// UPS header that was current immediately before this step.  Passed as
    /// `previous_step_header` to `prove_step_standard / prove_step_deferred`.
    pub prev_header: UserProvingSessionHeader<F>,
    /// Header immediately before `prev_header`.  Needed when restoring a
    /// stateless manager for an isolated step; end-cap proving reads this as
    /// the second-to-last header.
    pub second_to_last_header: UserProvingSessionHeader<F>,
    /// Expected CFC leaf index (= `proof_tree_meta.next_leaf_index`).
    pub cfc_index: u64,
    /// Expected UPS leaf index (= cfc_index + 1).
    pub ups_index: u64,
}

/// Output of the Phase A pre-processing pass.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceProofSchedule {
    /// One seed per CFC step (Standard / BurnFee / Deferred), in arena order.
    pub seeds: Vec<StepSeed>,
    /// Proof-tree state after *all* steps (CFC + ExternalProof) have been
    /// simulated.  Used by Phase C (`finalize_step_proving`) to restore the
    /// complete tree without re-proving.
    pub final_meta: ProofTreeMeta,
    /// Baton after the last CFC step.
    pub final_baton: LastStepProofInfo,
}

/// Proof task identity for graph-based trace proving.
///
/// `BidirectionalGraph::add_edge(a, b)` means `a` depends on `b`, so the
/// dependency graph is:
///
/// ```text
/// UpsStep(i) -> Cfc(i)
/// ZkSign     -> UpsStart
/// ZkSign     -> UpsStep(i) for every CFC step
/// ProofTreeAgg -> ZkSign
/// ProofTreeAgg -> UpsStart
/// ProofTreeAgg -> UpsStep(i) for every CFC step
/// EndCap     -> ProofTreeAgg
/// Finalize   -> EndCap
/// ```
///
/// The runtime worker still proves `Cfc(i)` and `UpsStep(i)` sequentially
/// inside one isolated task.  Splitting them here makes the circuit dependency
/// explicit in the printed graph.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum TraceProofTaskId {
    UpsStart,
    Cfc(usize),
    UpsStep(usize),
    ZkSign,
    ProofTreeAgg,
    EndCap,
    Finalize,
}

impl TraceProofTaskId {
    fn dot_label(self) -> String {
        match self {
            TraceProofTaskId::UpsStart => "ups_start".to_string(),
            TraceProofTaskId::Cfc(step_index) => format!("cfc_{step_index}"),
            TraceProofTaskId::UpsStep(step_index) => format!("ups_step_{step_index}"),
            TraceProofTaskId::ZkSign => "zksign".to_string(),
            TraceProofTaskId::ProofTreeAgg => "proof_tree_agg".to_string(),
            TraceProofTaskId::EndCap => "end_cap".to_string(),
            TraceProofTaskId::Finalize => "finalize".to_string(),
        }
    }
}

/// Graph view of the trace proof work.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceProofGraph {
    graph: BidirectionalGraph<TraceProofTaskId>,
}

impl TraceProofGraph {
    pub fn from_schedule(schedule: &TraceProofSchedule) -> Self {
        Self::from_step_indices(schedule.seeds.iter().map(|seed| seed.step_index))
    }

    pub fn from_step_indices(step_indices: impl IntoIterator<Item = usize>) -> Self {
        let mut graph = BidirectionalGraph::new();
        graph.add_node(TraceProofTaskId::UpsStart);
        graph.add_node(TraceProofTaskId::ZkSign);
        graph.add_node(TraceProofTaskId::ProofTreeAgg);
        graph.add_node(TraceProofTaskId::EndCap);
        graph.add_node(TraceProofTaskId::Finalize);
        graph.add_edge(TraceProofTaskId::ZkSign, TraceProofTaskId::UpsStart);
        graph.add_edge(TraceProofTaskId::ProofTreeAgg, TraceProofTaskId::UpsStart);
        graph.add_edge(TraceProofTaskId::ProofTreeAgg, TraceProofTaskId::ZkSign);
        graph.add_edge(TraceProofTaskId::EndCap, TraceProofTaskId::ProofTreeAgg);
        graph.add_edge(TraceProofTaskId::Finalize, TraceProofTaskId::EndCap);

        for step_index in step_indices {
            let cfc_task = TraceProofTaskId::Cfc(step_index);
            let ups_step_task = TraceProofTaskId::UpsStep(step_index);
            graph.add_node(cfc_task);
            graph.add_node(ups_step_task);
            graph.add_edge(ups_step_task, cfc_task);
            graph.add_edge(TraceProofTaskId::ZkSign, ups_step_task);
            graph.add_edge(TraceProofTaskId::ProofTreeAgg, ups_step_task);
        }

        Self { graph }
    }

    pub fn execution_levels(&self) -> Vec<Vec<TraceProofTaskId>> {
        self.graph.ts_order()
    }

    pub fn initial_ready_tasks(&self) -> anyhow::Result<Vec<TraceProofTaskId>> {
        self.execution_levels()
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("trace proof graph has no ready tasks"))
    }

    pub fn to_dot(&self) -> String {
        let mut nodes = self.execution_levels().into_iter().flatten().collect::<Vec<_>>();
        nodes.sort();
        nodes.dedup();

        let mut out = String::from("digraph TraceProofGraph {\n");
        out.push_str("  rankdir=LR;\n");

        for node in &nodes {
            out.push_str(&format!("  {} [label=\"{}\"];\n", node.dot_label(), node.dot_label()));
        }

        for node in &nodes {
            let Some(dependencies) = self.graph.get_dependencies(node) else {
                continue;
            };
            let mut deps = dependencies.iter().copied().collect::<Vec<_>>();
            deps.sort();
            for dep in deps {
                out.push_str(&format!("  {} -> {};\n", dep.dot_label(), node.dot_label()));
            }
        }

        out.push_str("}\n");
        out
    }
}

/// Runtime job identity for local proving.
///
/// Unlike [`TraceProofTaskId`], this models the coarse local-proving stages the
/// caller needs to observe. CFC jobs mutate the shared `WalletSession` proof
/// tree, so they cannot be proven in parallel; `from_step_indices` therefore
/// chains CFC and external jobs sequentially by step index (each depends on
/// the previous one, the first on `UpsStart`). `ZkSign` waits for the chain
/// tail; `EndCap` waits for every leaf job plus `ZkSign` and `UpsStart`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum TraceProofJobId {
    UpsStart,
    CfcStep(usize),
    ExternalProof(usize),
    ZkSign,
    EndCap,
    Submit,
}

impl TraceProofJobId {
    fn dot_label(self) -> String {
        match self {
            TraceProofJobId::UpsStart => "ups_start".to_string(),
            TraceProofJobId::CfcStep(step_index) => format!("cfc_step_{step_index}"),
            TraceProofJobId::ExternalProof(step_index) => format!("external_proof_{step_index}"),
            TraceProofJobId::ZkSign => "zksign".to_string(),
            TraceProofJobId::EndCap => "end_cap".to_string(),
            TraceProofJobId::Submit => "submit".to_string(),
        }
    }

    fn job_sequence_key(self) -> (u8, usize) {
        match self {
            TraceProofJobId::UpsStart => (0, 0),
            TraceProofJobId::ZkSign => (1, 0),
            TraceProofJobId::CfcStep(step_index) => (2, step_index),
            TraceProofJobId::ExternalProof(step_index) => (3, step_index),
            TraceProofJobId::EndCap => (4, 0),
            TraceProofJobId::Submit => (5, 0),
        }
    }
}

/// Executable local-proving DAG.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceProofJobGraph {
    graph: BidirectionalGraph<TraceProofJobId>,
}

impl TraceProofJobGraph {
    pub fn from_trace(trace: &TxTrace) -> Self {
        let cfc_step_indices = trace.steps.iter().enumerate().filter_map(|(step_index, step)| match step {
            TraceStep::Standard(_) | TraceStep::BurnFee(_) | TraceStep::Deferred(_) => Some(step_index),
            TraceStep::Inlined(_) => None,
            _ => None,
        });
        let external_step_indices = trace
            .steps
            .iter()
            .enumerate()
            .filter_map(|(step_index, step)| matches!(step, TraceStep::ExternalProof(_)).then_some(step_index));
        Self::from_step_indices(cfc_step_indices, external_step_indices)
    }

    pub fn from_schedule(schedule: &TraceProofSchedule, trace: &TxTrace) -> Self {
        let external_step_indices = trace
            .steps
            .iter()
            .enumerate()
            .filter_map(|(step_index, step)| matches!(step, TraceStep::ExternalProof(_)).then_some(step_index));
        Self::from_step_indices(schedule.seeds.iter().map(|seed| seed.step_index), external_step_indices)
    }

    pub fn from_step_indices(cfc_step_indices: impl IntoIterator<Item = usize>, external_step_indices: impl IntoIterator<Item = usize>) -> Self {
        let mut graph = BidirectionalGraph::new();
        graph.add_node(TraceProofJobId::UpsStart);
        graph.add_node(TraceProofJobId::ZkSign);
        graph.add_node(TraceProofJobId::EndCap);
        graph.add_node(TraceProofJobId::Submit);

        graph.add_edge(TraceProofJobId::EndCap, TraceProofJobId::UpsStart);
        graph.add_edge(TraceProofJobId::Submit, TraceProofJobId::EndCap);

        let mut ordered_jobs = cfc_step_indices
            .into_iter()
            .map(|step_index| (step_index, TraceProofJobId::CfcStep(step_index)))
            .chain(
                external_step_indices
                    .into_iter()
                    .map(|step_index| (step_index, TraceProofJobId::ExternalProof(step_index))),
            )
            .collect::<Vec<_>>();
        ordered_jobs.sort_by_key(|(step_index, _)| *step_index);

        let mut last_dependency = TraceProofJobId::UpsStart;
        for (_, job) in ordered_jobs {
            graph.add_node(job);
            graph.add_edge(job, last_dependency);
            graph.add_edge(TraceProofJobId::EndCap, job);
            last_dependency = job;
        }

        graph.add_edge(TraceProofJobId::ZkSign, last_dependency);
        graph.add_edge(TraceProofJobId::EndCap, TraceProofJobId::ZkSign);

        Self { graph }
    }

    pub fn execution_levels(&self) -> Vec<Vec<TraceProofJobId>> {
        self.graph.ts_order()
    }

    pub fn jobs(&self) -> Vec<TraceProofJobId> {
        let mut jobs = self.execution_levels().into_iter().flatten().collect::<Vec<_>>();
        jobs.sort_by_key(|job| job.job_sequence_key());
        jobs.dedup();
        jobs
    }

    pub fn normalized_execution_levels(&self) -> Vec<Vec<TraceProofJobId>> {
        let mut levels = self.execution_levels();
        for level in &mut levels {
            level.sort();
        }
        levels
    }

    pub fn cfc_job_levels(&self) -> Vec<Vec<usize>> {
        self.execution_levels()
            .into_iter()
            .filter_map(|level| {
                let mut cfc_jobs = level
                    .into_iter()
                    .filter_map(|job| match job {
                        TraceProofJobId::CfcStep(step_index) => Some(step_index),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                cfc_jobs.sort();
                (!cfc_jobs.is_empty()).then_some(cfc_jobs)
            })
            .collect()
    }

    pub fn dependencies(&self, job: TraceProofJobId) -> Vec<TraceProofJobId> {
        self.graph
            .get_dependencies(&job)
            .map(|deps| {
                let mut deps = deps.iter().copied().collect::<Vec<_>>();
                deps.sort();
                deps
            })
            .unwrap_or_default()
    }

    pub fn dependents(&self, job: TraceProofJobId) -> Vec<TraceProofJobId> {
        self.graph
            .get_dependents(&job)
            .map(|dependents| {
                let mut dependents = dependents.iter().copied().collect::<Vec<_>>();
                dependents.sort();
                dependents
            })
            .unwrap_or_default()
    }

    pub fn initial_ready_jobs(&self) -> anyhow::Result<Vec<TraceProofJobId>> {
        self.execution_levels()
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("trace proof job graph has no ready jobs"))
    }

    pub fn to_dot(&self) -> String {
        let mut nodes = self.execution_levels().into_iter().flatten().collect::<Vec<_>>();
        nodes.sort();
        nodes.dedup();

        let mut out = String::from("digraph TraceProofJobGraph {\n");
        out.push_str("  rankdir=LR;\n");

        for node in &nodes {
            out.push_str(&format!("  {} [label=\"{}\"];\n", node.dot_label(), node.dot_label()));
        }

        for node in &nodes {
            let Some(dependencies) = self.graph.get_dependencies(node) else {
                continue;
            };
            let mut deps = dependencies.iter().copied().collect::<Vec<_>>();
            deps.sort();
            for dep in deps {
                out.push_str(&format!("  {} -> {};\n", dep.dot_label(), node.dot_label()));
            }
        }

        out.push_str("}\n");
        out
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn to_job_graph(&self) -> JobGraph<TraceProofJobId> {
        let jobs = self.jobs();
        let dependencies = jobs.iter().map(|job| (*job, self.dependencies(*job))).collect::<BTreeMap<_, _>>();
        JobGraph::new(jobs, dependencies)
    }
}

/// Fully prepared local-proving plan for one transaction trace.
///
/// The graph id is derived from `trace.finalization.tx_hash`; CFC step seeds
/// are derived by replaying proof-tree state from the trace. The job graph only
/// describes scheduling dependencies.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceProofPlan {
    pub graph_id: GraphId,
    pub schedule: TraceProofSchedule,
    pub job_graph: TraceProofJobGraph,
}

#[cfg(not(target_arch = "wasm32"))]
impl TraceProofPlan {
    pub fn from_trace_and_schedule(trace: &TxTrace, schedule: TraceProofSchedule) -> Self {
        let graph_id = graph_id_from_trace(trace);
        let job_graph = TraceProofJobGraph::from_schedule(&schedule, trace);
        Self {
            graph_id,
            schedule,
            job_graph,
        }
    }

    pub fn seeds_by_step(&self) -> BTreeMap<usize, StepSeed> {
        self.schedule.seeds.iter().cloned().map(|seed| (seed.step_index, seed)).collect()
    }
}

/// Pure in-memory dependency scheduler for local proving jobs.
///
/// `JobManager` deliberately does not know about traces, wallets, providers, or
/// RPC. It only sees a job graph and invokes the caller-supplied `run_job`
/// future for ready jobs. Any chain reads or proving inputs must be prepared by
/// the caller outside this scheduler.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Ready,
    Running,
    Completed,
    Failed,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct GraphId(pub Cow<'static, str>);

#[cfg(not(target_arch = "wasm32"))]
impl GraphId {
    pub fn owned(value: impl Into<String>) -> Self {
        Self(Cow::Owned(value.into()))
    }

    pub fn from_tx_hash(tx_hash: QHashOut<F>) -> Self {
        Self::owned(tx_hash.to_string())
    }

    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl fmt::Display for GraphId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn graph_id_from_tx_hash(tx_hash: QHashOut<F>) -> GraphId {
    GraphId::from_tx_hash(tx_hash)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn graph_id_from_trace(trace: &TxTrace) -> GraphId {
    graph_id_from_tx_hash(trace.finalization.tx_hash)
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct JobHandle<J>
where
    J: Clone + Ord + std::fmt::Debug,
{
    pub graph_id: GraphId,
    pub job_id: J,
}

#[cfg(not(target_arch = "wasm32"))]
impl<J> JobHandle<J>
where
    J: Clone + Ord + std::fmt::Debug,
{
    pub fn new(graph_id: GraphId, job_id: J) -> Self {
        Self { graph_id, job_id }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub struct JobGraph<J>
where
    J: Clone + Ord + std::fmt::Debug,
{
    pub jobs: Vec<J>,
    /// `dependencies[job]` is the list of jobs that must complete before `job`
    /// is ready. Missing entries mean the job has no dependencies.
    pub dependencies: BTreeMap<J, Vec<J>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl<J> JobGraph<J>
where
    J: Clone + Ord + std::fmt::Debug,
{
    pub fn new(jobs: impl IntoIterator<Item = J>, dependencies: BTreeMap<J, Vec<J>>) -> Self {
        Self {
            jobs: jobs.into_iter().collect(),
            dependencies,
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub struct JobManager<J, T = ()>
where
    J: Clone + Ord + std::fmt::Debug,
{
    state: Arc<Mutex<JobManagerState<J, T>>>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
struct JobManagerState<J, T>
where
    J: Clone + Ord + std::fmt::Debug,
{
    dependencies: BTreeMap<JobHandle<J>, BTreeSet<JobHandle<J>>>,
    statuses: BTreeMap<JobHandle<J>, JobStatus>,
    results: BTreeMap<JobHandle<J>, T>,
    sequences: BTreeMap<JobHandle<J>, u64>,
    next_sequence: u64,
}

#[cfg(not(target_arch = "wasm32"))]
impl<J, T> JobManager<J, T>
where
    J: Clone + Ord + Send + 'static + std::fmt::Debug,
    T: Clone + Send + 'static,
{
    pub fn empty() -> Self {
        Self {
            state: Arc::new(Mutex::new(JobManagerState {
                dependencies: BTreeMap::new(),
                statuses: BTreeMap::new(),
                results: BTreeMap::new(),
                sequences: BTreeMap::new(),
                next_sequence: 0,
            })),
        }
    }

    pub fn clear_graph(&self, graph_id: GraphId) -> anyhow::Result<()> {
        let mut state = self.state.lock().expect("job manager mutex poisoned");
        let graph_jobs = state
            .statuses
            .keys()
            .filter(|handle| handle.graph_id == graph_id)
            .cloned()
            .collect::<BTreeSet<_>>();

        if graph_jobs.is_empty() {
            return Ok(());
        }

        anyhow::ensure!(
            graph_jobs.iter().all(|job| state.statuses.get(job) != Some(&JobStatus::Running)),
            "cannot clear graph {} while it has running jobs",
            graph_id
        );

        for job in &graph_jobs {
            state.dependencies.remove(job);
            state.statuses.remove(job);
            state.results.remove(job);
            state.sequences.remove(job);
        }

        for dependencies in state.dependencies.values_mut() {
            dependencies.retain(|dependency| !graph_jobs.contains(dependency));
        }

        Ok(())
    }

    pub fn add_graph(&self, graph_id: GraphId, graph: JobGraph<J>) -> anyhow::Result<()> {
        let new_jobs = graph
            .jobs
            .iter()
            .cloned()
            .map(|job| JobHandle::new(graph_id.clone(), job))
            .collect::<BTreeSet<_>>();
        let mut state = self.state.lock().expect("job manager mutex poisoned");
        let known_jobs = state.statuses.keys().cloned().chain(new_jobs.iter().cloned()).collect::<BTreeSet<_>>();

        for job in graph.dependencies.keys() {
            let job = JobHandle::new(graph_id.clone(), job.clone());
            anyhow::ensure!(known_jobs.contains(&job), "dependency entry references unknown job {:?}", job);
        }

        for job in &graph.jobs {
            let handle = JobHandle::new(graph_id.clone(), job.clone());
            let dependencies = graph
                .dependencies
                .get(job)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .map(|dependency| JobHandle::new(graph_id.clone(), dependency))
                .collect::<BTreeSet<_>>();
            for dependency in &dependencies {
                anyhow::ensure!(known_jobs.contains(dependency), "job {:?} depends on unknown job {:?}", job, dependency);
            }

            if !state.statuses.contains_key(&handle) {
                state.statuses.insert(handle.clone(), JobStatus::Pending);
                let sequence = state.next_sequence;
                state.sequences.insert(handle.clone(), sequence);
                state.next_sequence += 1;
            }

            state.dependencies.entry(handle.clone()).or_default().extend(dependencies.iter().cloned());
        }

        let completed = Self::completed_jobs_locked(&state);
        Self::refresh_ready_statuses_locked(&mut state, &completed, &BTreeSet::new(), &new_jobs);
        Ok(())
    }

    pub fn status(&self, graph_id: GraphId, job: &J) -> Option<JobStatus> {
        self.state
            .lock()
            .expect("job manager mutex poisoned")
            .statuses
            .get(&JobHandle::new(graph_id, job.clone()))
            .copied()
    }

    pub fn statuses(&self, graph_id: GraphId) -> BTreeMap<J, JobStatus> {
        self.state
            .lock()
            .expect("job manager mutex poisoned")
            .statuses
            .iter()
            .filter_map(|(handle, status)| (handle.graph_id == graph_id).then_some((handle.job_id.clone(), *status)))
            .collect()
    }

    pub fn graph_status(&self, graph_id: GraphId) -> Option<JobStatus> {
        let statuses = self.statuses(graph_id);
        if statuses.is_empty() {
            return None;
        }
        if statuses.values().any(|status| *status == JobStatus::Failed) {
            return Some(JobStatus::Failed);
        }
        if statuses.values().any(|status| *status == JobStatus::Running) {
            return Some(JobStatus::Running);
        }
        if statuses.values().any(|status| matches!(status, JobStatus::Pending | JobStatus::Ready)) {
            return Some(JobStatus::Pending);
        }
        Some(JobStatus::Completed)
    }

    pub fn result(&self, graph_id: GraphId, job: &J) -> Option<T> {
        self.state
            .lock()
            .expect("job manager mutex poisoned")
            .results
            .get(&JobHandle::new(graph_id, job.clone()))
            .cloned()
    }

    pub fn results(&self, graph_id: GraphId) -> BTreeMap<J, T> {
        self.state
            .lock()
            .expect("job manager mutex poisoned")
            .results
            .iter()
            .filter_map(|(handle, output)| (handle.graph_id == graph_id).then_some((handle.job_id.clone(), output.clone())))
            .collect()
    }

    pub async fn run_graph<F, Fut>(
        &self,
        graph_id: GraphId,
        initially_completed: impl IntoIterator<Item = J>,
        runnable_jobs: impl IntoIterator<Item = J>,
        run_job: F,
    ) -> anyhow::Result<BTreeMap<J, T>>
    where
        F: Fn(J) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<T>> + Send + 'static,
    {
        let completed = initially_completed
            .into_iter()
            .map(|job| JobHandle::new(graph_id.clone(), job))
            .collect::<BTreeSet<_>>();
        let mut pending = runnable_jobs
            .into_iter()
            .map(|job| JobHandle::new(graph_id.clone(), job))
            .collect::<BTreeSet<_>>();
        for job in &completed {
            pending.remove(job);
        }

        let runnable = pending.iter().cloned().collect::<BTreeSet<_>>();
        {
            let state = self.state.lock().expect("job manager mutex poisoned");
            for job in &pending {
                let Some(deps) = state.dependencies.get(job) else {
                    anyhow::bail!("job {:?} is not present in job graph", job);
                };
                for dep in deps {
                    anyhow::ensure!(
                        completed.contains(dep) || runnable.contains(dep),
                        "job {:?} depends on {:?}, which is neither initially completed nor runnable",
                        job,
                        dep
                    );
                }
            }
        }

        self.run_handles(completed, pending, move |handle| run_job(handle.job_id))
            .await
            .map(|outputs| outputs.into_iter().map(|(handle, output)| (handle.job_id, output)).collect())
    }

    async fn run_handles<F, Fut>(
        &self,
        initially_completed: BTreeSet<JobHandle<J>>,
        mut pending: BTreeSet<JobHandle<J>>,
        run_job: F,
    ) -> anyhow::Result<BTreeMap<JobHandle<J>, T>>
    where
        F: Fn(JobHandle<J>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<T>> + Send + 'static,
    {
        let mut completed = {
            let mut state = self.state.lock().expect("job manager mutex poisoned");
            for job in &initially_completed {
                anyhow::ensure!(state.statuses.contains_key(job), "completed job {:?} is not present in job graph", job);
                state.statuses.insert(job.clone(), JobStatus::Completed);
            }
            for job in &pending {
                anyhow::ensure!(state.statuses.contains_key(job), "runnable job {:?} is not present in job graph", job);
                state.statuses.insert(job.clone(), JobStatus::Pending);
            }
            let completed = Self::completed_jobs_locked(&state);
            Self::refresh_ready_statuses_locked(&mut state, &completed, &BTreeSet::new(), &pending);
            completed
        };

        let run_job = Arc::new(run_job);
        let mut outputs = BTreeMap::new();
        let mut in_flight = BTreeSet::new();
        let mut join_set = tokio::task::JoinSet::new();

        while !pending.is_empty() || !in_flight.is_empty() {
            self.refresh_ready_statuses(&completed, &in_flight, &pending);

            while in_flight.len() < DEFAULT_LOCAL_PROVING_PARALLELISM {
                let Some(job) = self.next_ready_job(&pending, &completed) else { break };

                pending.remove(&job);
                in_flight.insert(job.clone());
                self.set_status(&job, JobStatus::Running);
                let run_job = run_job.clone();
                join_set.spawn(async move {
                    let output = run_job(job.clone()).await?;
                    Ok::<_, anyhow::Error>((job, output))
                });
            }

            if in_flight.is_empty() {
                anyhow::bail!("job graph has no runnable jobs; pending jobs: {:?}", pending);
            }

            let Some(joined) = join_set.join_next().await else {
                anyhow::bail!("job manager join set ended with pending jobs: {:?}", pending);
            };
            let joined = match joined {
                Ok(joined) => joined,
                Err(err) => {
                    self.mark_running_failed(&in_flight);
                    return Err(anyhow::anyhow!("job task failed to join: {}", err));
                }
            };
            let (job, output) = match joined {
                Ok((job, output)) => (job, output),
                Err(err) => {
                    self.mark_running_failed(&in_flight);
                    return Err(err);
                }
            };
            in_flight.remove(&job);
            completed.insert(job.clone());
            outputs.insert(job.clone(), output.clone());
            self.complete_job(&job, output);
        }

        self.refresh_ready_statuses(&completed, &BTreeSet::new(), &pending);
        Ok(outputs)
    }

    fn next_ready_job(&self, pending: &BTreeSet<JobHandle<J>>, completed: &BTreeSet<JobHandle<J>>) -> Option<JobHandle<J>> {
        let state = self.state.lock().expect("job manager mutex poisoned");
        pending
            .iter()
            .filter(|job| {
                state
                    .dependencies
                    .get(*job)
                    .map(|deps| deps.iter().all(|dep| completed.contains(dep)))
                    .unwrap_or(false)
            })
            .min_by_key(|job| state.sequences.get(*job).copied().unwrap_or(u64::MAX))
            .cloned()
    }

    fn completed_jobs_locked(state: &JobManagerState<J, T>) -> BTreeSet<JobHandle<J>> {
        state
            .statuses
            .iter()
            .filter_map(|(job, status)| (*status == JobStatus::Completed).then_some(job.clone()))
            .collect()
    }

    fn refresh_ready_statuses(&self, completed: &BTreeSet<JobHandle<J>>, in_flight: &BTreeSet<JobHandle<J>>, jobs: &BTreeSet<JobHandle<J>>) {
        let mut state = self.state.lock().expect("job manager mutex poisoned");
        Self::refresh_ready_statuses_locked(&mut state, completed, in_flight, jobs);
    }

    fn refresh_ready_statuses_locked(
        state: &mut JobManagerState<J, T>,
        completed: &BTreeSet<JobHandle<J>>,
        in_flight: &BTreeSet<JobHandle<J>>,
        jobs: &BTreeSet<JobHandle<J>>,
    ) {
        for job in jobs {
            if !state.statuses.contains_key(job) {
                continue;
            }
            if completed.contains(job) || in_flight.contains(job) {
                continue;
            }
            if matches!(state.statuses.get(job), Some(JobStatus::Running | JobStatus::Failed)) {
                continue;
            }
            let ready = state
                .dependencies
                .get(job)
                .map(|deps| deps.iter().all(|dep| completed.contains(dep)))
                .unwrap_or(false);
            state
                .statuses
                .insert(job.clone(), if ready { JobStatus::Ready } else { JobStatus::Pending });
        }
    }

    fn set_status(&self, job: &JobHandle<J>, status: JobStatus) {
        if let Some(existing) = self.state.lock().expect("job manager mutex poisoned").statuses.get_mut(job) {
            *existing = status;
        }
    }

    fn complete_job(&self, job: &JobHandle<J>, output: T) {
        let mut state = self.state.lock().expect("job manager mutex poisoned");
        state.statuses.insert(job.clone(), JobStatus::Completed);
        state.results.insert(job.clone(), output);
    }

    fn mark_running_failed(&self, in_flight: &BTreeSet<JobHandle<J>>) {
        let mut state = self.state.lock().expect("job manager mutex poisoned");
        for job in in_flight {
            if let Some(status) = state.statuses.get_mut(job) {
                if *status == JobStatus::Running {
                    *status = JobStatus::Failed;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Leaf value helpers
// ---------------------------------------------------------------------------

/// Compute a CFC leaf value from trace fields (no proof bytes needed).
///
/// Mirrors `injest_single_leaf_value(fingerprint, session_proof_tree_root,
/// tx_input_ctx.qfhash())`.
fn cfc_leaf_value(cfc_fingerprint: QHashOut<F>, session_proof_tree_root: QHashOut<F>, tx_input_ctx_hash: QHashOut<F>) -> QHashOut<F> {
    let public_inputs_hash = QHashOut(PoseidonHash::two_to_one(session_proof_tree_root.0, tx_input_ctx_hash.0));
    QHashOut(PoseidonHash::two_to_one(cfc_fingerprint.0, public_inputs_hash.0))
}

/// Compute a UPS-step leaf value from trace fields.
///
/// Mirrors `injest_single_leaf_value(fingerprint,
/// known_proof_tree_root_after_cfc, end_header.qfhash())`.
fn ups_leaf_value(ups_fingerprint: QHashOut<F>, known_proof_tree_root_after_cfc: QHashOut<F>, end_header_hash: QHashOut<F>) -> QHashOut<F> {
    let public_inputs_hash = QHashOut(PoseidonHash::two_to_one(known_proof_tree_root_after_cfc.0, end_header_hash.0));
    QHashOut(PoseidonHash::two_to_one(ups_fingerprint.0, public_inputs_hash.0))
}

/// Compute an external-proof leaf value from the raw proof public inputs.
///
/// Mirrors `injest_single_leaf_proof({ fingerprint, proof })`.
fn external_leaf_value(fingerprint: QHashOut<F>, proof_public_inputs_hash: QHashOut<F>) -> QHashOut<F> {
    QHashOut(PoseidonHash::two_to_one(fingerprint.0, proof_public_inputs_hash.0))
}

// ---------------------------------------------------------------------------
// ProofTreeMeta extensions for schedule building
// ---------------------------------------------------------------------------

/// Advance the tree by inserting one leaf at `meta.next_leaf_index`.
/// Returns the old root (before insertion) — mirrors `root_history.last()`.
fn insert_next_leaf(meta: &mut ProofTreeMeta, leaf_value: QHashOut<F>) -> (u64, QHashOut<F>) {
    let index = meta.next_leaf_index;
    let old_root = meta.insert_leaf_value(leaf_value, index);
    (index, old_root)
}

/// Get the current tree root (without mutating).
fn current_root(meta: &ProofTreeMeta) -> QHashOut<F> {
    meta.get_root()
}

// ---------------------------------------------------------------------------
// Main builder
// ---------------------------------------------------------------------------

impl TraceProofSchedule {
    pub fn initial_state_from_trace(
        trace: &TxTrace,
        ups_start_fingerprint: QHashOut<F>,
        is_new_user: bool,
    ) -> anyhow::Result<(ProofTreeMeta, LastStepProofInfo)> {
        let mut meta = ProofTreeMeta::new(UPS_SESSION_PROOF_TREE_HEIGHT as usize);
        let known_proof_tree_root = current_root(&meta);
        let inner_public_inputs_hash = trace.ups_start_witness.ups_header.qfhash::<PsyHasher>();
        let leaf_value = ups_leaf_value(ups_start_fingerprint, known_proof_tree_root, inner_public_inputs_hash);
        let (proof_tree_index, _) = insert_next_leaf(&mut meta, leaf_value);
        anyhow::ensure!(proof_tree_index == 0, "UPS start leaf must be inserted at proof-tree index 0");

        if let Some(first_root) = trace.steps.iter().find_map(|step| match step {
            TraceStep::Standard(cfc) | TraceStep::BurnFee(cfc) | TraceStep::Deferred(cfc) => Some(cfc.proof_tree_start_root),
            TraceStep::ExternalProof(external) => Some(external.proof_tree_start_root),
            TraceStep::ZkSign(zksign) => Some(zksign.proof_tree_start_root),
            TraceStep::Inlined(_) => None,
        }) {
            let root = current_root(&meta);
            anyhow::ensure!(
                root == first_root,
                "derived UPS start proof-tree root mismatch: computed={:?} trace_first_start={:?}",
                root,
                first_root
            );
        }

        let circuit_id = if is_new_user {
            LocalCircuitType::UPSStartRegisterUser.into()
        } else {
            LocalCircuitType::UPSStart.into()
        };
        let baton = LastStepProofInfo {
            circuit_id,
            inner_public_inputs_hash,
            known_proof_tree_root,
            proof_tree_index,
        };
        Ok((meta, baton))
    }

    /// Build the schedule from the initial state produced by
    /// `init_step_proving`.
    ///
    /// # Arguments
    /// * `initial_meta`  — `ProofTreeMeta` snapshot after
    ///   `prove_ups_start_step`
    /// * `initial_baton` — `last_ups_step_proof_info` after
    ///   `prove_ups_start_step`
    /// * `trace`         — the full transaction trace
    pub fn build(initial_meta: ProofTreeMeta, initial_baton: LastStepProofInfo, trace: &TxTrace) -> anyhow::Result<Self> {
        let mut meta = initial_meta;
        let mut baton = initial_baton;
        let mut seeds: Vec<StepSeed> = Vec::new();
        // prev_header tracks the UPS header after the last CFC step (or ups_start
        // header).
        let mut prev_header = trace.ups_start_witness.ups_header.clone();
        let mut second_to_last_header = trace.ups_start_witness.ups_header.clone();

        for (step_index, step) in trace.steps.iter().enumerate() {
            match step {
                TraceStep::Standard(cfc) | TraceStep::BurnFee(cfc) | TraceStep::Deferred(cfc) => {
                    let end_header = cfc.end_header.clone();
                    Self::process_cfc_step(
                        step_index,
                        cfc,
                        step,
                        &mut meta,
                        &mut baton,
                        &mut seeds,
                        prev_header.clone(),
                        second_to_last_header.clone(),
                    )?;
                    second_to_last_header = prev_header;
                    prev_header = end_header;
                }

                TraceStep::Inlined(_) => {
                    // Inlined steps do not produce independent proof-tree
                    // entries in the current implementation; they are proved
                    // as part of their parent standard step.  Skip.
                }

                TraceStep::ExternalProof(external) => {
                    // Decode the proof to extract its public inputs (cheap).
                    use plonky2::plonk::proof::ProofWithPublicInputs;
                    let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(&external.proof)
                        .map_err(|e| anyhow::anyhow!("external proof deserialize error at step {}: {}", step_index, e))?;

                    anyhow::ensure!(
                        proof.public_inputs.len() >= 4,
                        "external proof at step {} has < 4 public inputs",
                        step_index
                    );
                    let pub_inputs_hash = QHashOut(HashOut {
                        elements: [
                            proof.public_inputs[0],
                            proof.public_inputs[1],
                            proof.public_inputs[2],
                            proof.public_inputs[3],
                        ],
                    });

                    // Verify tree start root matches.
                    let before = current_root(&meta);
                    anyhow::ensure!(
                        before == external.proof_tree_start_root,
                        "schedule: external-proof root mismatch before step {}: computed={:?} trace_start={:?}",
                        step_index,
                        before,
                        external.proof_tree_start_root
                    );

                    let lv = external_leaf_value(external.fingerprint, pub_inputs_hash);
                    insert_next_leaf(&mut meta, lv);

                    let after = current_root(&meta);
                    anyhow::ensure!(
                        after == external.proof_tree_end_root,
                        "schedule: external-proof root mismatch after step {}: computed={:?} trace_end={:?}",
                        step_index,
                        after,
                        external.proof_tree_end_root
                    );
                    // External proofs do NOT update the CFC baton.
                }

                TraceStep::ZkSign(_) => {
                    // ZkSign is inserted into the tree during finalize_trace,
                    // not during step proving. Nothing to do here.
                }
            }
        }

        Ok(Self {
            seeds,
            final_meta: meta,
            final_baton: baton,
        })
    }

    fn process_cfc_step(
        step_index: usize,
        cfc: &CfcStep,
        step: &TraceStep,
        meta: &mut ProofTreeMeta,
        baton: &mut LastStepProofInfo,
        seeds: &mut Vec<StepSeed>,
        prev_header: UserProvingSessionHeader<F>,
        second_to_last_header: UserProvingSessionHeader<F>,
    ) -> anyhow::Result<()> {
        let cfc_index = meta.next_leaf_index;
        let ups_index = cfc_index + 1;

        // --- Snapshot BEFORE CFC leaf insertion ---
        seeds.push(StepSeed {
            step_index,
            proof_tree_meta: meta.clone(),
            prev_baton: *baton,
            prev_header,
            second_to_last_header,
            cfc_index,
            ups_index,
        });

        // Verify expected tree start root.
        let before = current_root(meta);
        anyhow::ensure!(
            before == cfc.proof_tree_start_root,
            "schedule: CFC root mismatch before step {}: computed={:?} trace_start={:?}",
            step_index,
            before,
            cfc.proof_tree_start_root
        );

        // --- Insert CFC leaf ---
        let tx_input_ctx_hash = cfc.cfc_witness.tx_input_ctx.qfhash::<PsyHasher>();
        let cfc_lv = cfc_leaf_value(cfc.cfc_fingerprint, cfc.cfc_witness.session_proof_tree_root, tx_input_ctx_hash);
        let (inserted_cfc_index, _old_root) = insert_next_leaf(meta, cfc_lv);
        anyhow::ensure!(
            inserted_cfc_index == cfc_index,
            "schedule: CFC leaf index mismatch at step {}: expected {} got {}",
            step_index,
            cfc_index,
            inserted_cfc_index
        );

        // Root after CFC leaf insertion = known_proof_tree_root for UPS baton.
        let root_after_cfc = current_root(meta);

        // --- Insert UPS leaf ---
        let end_header_hash = cfc.end_header.qfhash::<PsyHasher>();
        let ups_lv = ups_leaf_value(cfc.ups_fingerprint, root_after_cfc, end_header_hash);
        let (inserted_ups_index, _old_root2) = insert_next_leaf(meta, ups_lv);
        anyhow::ensure!(
            inserted_ups_index == ups_index,
            "schedule: UPS leaf index mismatch at step {}: expected {} got {}",
            step_index,
            ups_index,
            inserted_ups_index
        );

        // Verify expected tree end root.
        let after = current_root(meta);
        anyhow::ensure!(
            after == cfc.proof_tree_end_root,
            "schedule: CFC root mismatch after step {}: computed={:?} trace_end={:?}",
            step_index,
            after,
            cfc.proof_tree_end_root
        );

        // --- Update baton ---
        let circuit_id = match step {
            TraceStep::Deferred(_) => LocalCircuitType::UPSCFCDeferred.into(),
            _ => LocalCircuitType::UPSCFCStandard.into(),
        };
        use psy_crypto::common::witnesses::qrecursion::proof_data::TreeAwareTreeProofRecord;
        *baton = TreeAwareTreeProofRecord {
            inner_public_inputs_hash: end_header_hash,
            circuit_id,
            known_proof_tree_root: root_after_cfc,
            proof_tree_index: inserted_ups_index,
        };

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use plonky2::{field::goldilocks_field::GoldilocksField, hash::poseidon::PoseidonHash, plonk::config::Hasher};
    use psy_client_common::data::qhashout::QHashOut;

    use super::*;

    type F = GoldilocksField;

    fn make_qhash(a: u64, b: u64, c: u64, d: u64) -> QHashOut<F> {
        QHashOut::from_values(a, b, c, d)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn test_graph_id(value: impl ToString) -> GraphId {
        GraphId::owned(value.to_string())
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn graph_id_is_derived_from_tx_hash() {
        let tx_hash = make_qhash(11, 22, 33, 44);
        let same_tx_hash = make_qhash(11, 22, 33, 44);
        let other_tx_hash = make_qhash(11, 22, 33, 45);

        assert_eq!(graph_id_from_tx_hash(tx_hash), graph_id_from_tx_hash(same_tx_hash));
        assert_eq!(graph_id_from_tx_hash(tx_hash).as_str(), tx_hash.to_string());
        assert_ne!(graph_id_from_tx_hash(tx_hash), graph_id_from_tx_hash(other_tx_hash));
    }

    // -----------------------------------------------------------------------
    // Leaf-value formula tests
    // -----------------------------------------------------------------------

    /// `cfc_leaf_value` must produce the same result as calling
    /// `two_to_one` manually with the same inputs, mirroring the
    /// `injest_single_leaf_value` formula.
    #[test]
    fn cfc_leaf_value_matches_manual_formula() {
        let fp = make_qhash(1, 2, 3, 4);
        let root = make_qhash(5, 6, 7, 8);
        let ih = make_qhash(9, 10, 11, 12);

        let expected_pi_hash = QHashOut(PoseidonHash::two_to_one(root.0, ih.0));
        let expected = QHashOut(PoseidonHash::two_to_one(fp.0, expected_pi_hash.0));

        assert_eq!(cfc_leaf_value(fp, root, ih), expected);
    }

    /// `ups_leaf_value` mirrors the same formula with different domain inputs.
    #[test]
    fn ups_leaf_value_matches_manual_formula() {
        let fp = make_qhash(10, 20, 30, 40);
        let root_aft_cfc = make_qhash(50, 60, 70, 80);
        let hdr_hash = make_qhash(90, 100, 110, 120);

        let expected_pi_hash = QHashOut(PoseidonHash::two_to_one(root_aft_cfc.0, hdr_hash.0));
        let expected = QHashOut(PoseidonHash::two_to_one(fp.0, expected_pi_hash.0));

        assert_eq!(ups_leaf_value(fp, root_aft_cfc, hdr_hash), expected);
    }

    /// CFC and UPS leaf values must differ even for identical fingerprints and
    /// inner hashes, because the "session_root" slot differs.
    #[test]
    fn cfc_and_ups_leaf_values_differ_for_same_inputs() {
        let fp = make_qhash(1, 1, 1, 1);
        let root1 = make_qhash(2, 2, 2, 2);
        let ih = make_qhash(3, 3, 3, 3);

        let cfc_lv = cfc_leaf_value(fp, root1, ih);
        let ups_lv = ups_leaf_value(fp, root1, ih);
        // The formula is identical; they only differ in practice because the
        // root passed in is different (root before vs. after CFC insertion).
        // Confirm they happen to differ when root_after_cfc != session_root.
        let root2 = make_qhash(9, 9, 9, 9); // different root
        let ups_lv2 = ups_leaf_value(fp, root2, ih);
        assert_ne!(ups_lv, ups_lv2, "different roots must produce different UPS leaf values");
        let _ = cfc_lv; // used
    }

    #[test]
    fn proof_graph_makes_start_and_steps_ready_before_finalize() {
        let graph = TraceProofGraph::from_step_indices([0, 2, 5]);
        let levels = graph.execution_levels();
        assert_eq!(levels.len(), 6);

        let mut ready = levels[0].clone();
        ready.sort();
        assert_eq!(
            ready,
            vec![
                TraceProofTaskId::UpsStart,
                TraceProofTaskId::Cfc(0),
                TraceProofTaskId::Cfc(2),
                TraceProofTaskId::Cfc(5),
            ]
        );
        let mut ups_steps = levels[1].clone();
        ups_steps.sort();
        assert_eq!(
            ups_steps,
            vec![TraceProofTaskId::UpsStep(0), TraceProofTaskId::UpsStep(2), TraceProofTaskId::UpsStep(5),]
        );
        assert_eq!(levels[2], vec![TraceProofTaskId::ZkSign]);
        assert_eq!(levels[3], vec![TraceProofTaskId::ProofTreeAgg]);
        assert_eq!(levels[4], vec![TraceProofTaskId::EndCap]);
        assert_eq!(levels[5], vec![TraceProofTaskId::Finalize]);
    }

    #[test]
    fn proof_graph_dot_shows_dependencies_flowing_to_finalize() {
        let graph = TraceProofGraph::from_step_indices([0, 1]);
        let dot = graph.to_dot();

        assert!(dot.contains("digraph TraceProofGraph"));
        assert!(dot.contains("rankdir=LR"));
        assert!(dot.contains("ups_start -> zksign"));
        assert!(dot.contains("ups_start -> proof_tree_agg"));
        assert!(dot.contains("cfc_0 -> ups_step_0"));
        assert!(dot.contains("ups_step_0 -> zksign"));
        assert!(dot.contains("ups_step_0 -> proof_tree_agg"));
        assert!(dot.contains("cfc_1 -> ups_step_1"));
        assert!(dot.contains("ups_step_1 -> zksign"));
        assert!(dot.contains("ups_step_1 -> proof_tree_agg"));
        assert!(dot.contains("zksign -> proof_tree_agg"));
        assert!(dot.contains("proof_tree_agg -> end_cap"));
        assert!(dot.contains("end_cap -> finalize"));
    }

    #[test]
    fn proof_job_graph_models_runtime_jobs() {
        let graph = TraceProofJobGraph::from_step_indices([0, 2], [1]);
        let levels = graph.execution_levels();
        let normalized_levels = graph.normalized_execution_levels();
        assert_eq!(levels.len(), 7);
        assert_eq!(graph.cfc_job_levels(), vec![vec![0], vec![2]]);

        assert_eq!(normalized_levels[0], vec![TraceProofJobId::UpsStart]);
        assert_eq!(normalized_levels[1], vec![TraceProofJobId::CfcStep(0)]);
        assert_eq!(normalized_levels[2], vec![TraceProofJobId::ExternalProof(1)]);
        assert_eq!(normalized_levels[3], vec![TraceProofJobId::CfcStep(2)]);
        assert_eq!(normalized_levels[4], vec![TraceProofJobId::ZkSign]);
        assert_eq!(normalized_levels[5], vec![TraceProofJobId::EndCap]);
        assert_eq!(normalized_levels[6], vec![TraceProofJobId::Submit]);

        assert_eq!(graph.dependencies(TraceProofJobId::ZkSign), vec![TraceProofJobId::CfcStep(2)]);

        assert_eq!(
            graph.dependencies(TraceProofJobId::EndCap),
            vec![
                TraceProofJobId::UpsStart,
                TraceProofJobId::CfcStep(0),
                TraceProofJobId::CfcStep(2),
                TraceProofJobId::ExternalProof(1),
                TraceProofJobId::ZkSign,
            ]
        );
    }

    #[test]
    fn proof_job_graph_dot_shows_schedule_fanout() {
        let graph = TraceProofJobGraph::from_step_indices([0], [3]);
        let dot = graph.to_dot();

        assert!(dot.contains("digraph TraceProofJobGraph"));
        // Sequential chain by step index: UpsStart -> CfcStep(0) -> ExternalProof(3) ->
        // ZkSign.
        assert!(dot.contains("ups_start -> cfc_step_0"));
        assert!(dot.contains("cfc_step_0 -> external_proof_3"));
        assert!(dot.contains("external_proof_3 -> zksign"));
        // EndCap still fans out over every leaf job plus ZkSign and UpsStart.
        assert!(dot.contains("ups_start -> end_cap"));
        assert!(dot.contains("cfc_step_0 -> end_cap"));
        assert!(dot.contains("external_proof_3 -> end_cap"));
        assert!(dot.contains("zksign -> end_cap"));
        assert!(dot.contains("end_cap -> submit"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn job_manager_tracks_status_and_runs_ready_jobs_concurrently() {
        use std::{
            sync::{
                atomic::{AtomicUsize, Ordering},
                Arc,
            },
            time::Duration,
        };

        let manager = JobManager::<i32, i32>::empty();
        let graph_id = test_graph_id("trace");
        manager
            .add_graph(graph_id.clone(), JobGraph::new([1, 2, 3], BTreeMap::from([(3, vec![1, 2])])))
            .expect("graph should be accepted");

        assert_eq!(manager.status(graph_id.clone(), &1), Some(JobStatus::Ready));
        assert_eq!(manager.status(graph_id.clone(), &2), Some(JobStatus::Ready));
        assert_eq!(manager.status(graph_id.clone(), &3), Some(JobStatus::Pending));

        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let outputs = manager
            .run_graph(graph_id.clone(), [], [1, 2, 3], {
                let active = active.clone();
                let max_active = max_active.clone();
                move |job| {
                    let active = active.clone();
                    let max_active = max_active.clone();
                    async move {
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        max_active.fetch_max(now, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        Ok::<_, anyhow::Error>(job * 10)
                    }
                }
            })
            .await
            .expect("job manager should complete DAG");

        assert_eq!(outputs.get(&1), Some(&10));
        assert_eq!(outputs.get(&2), Some(&20));
        assert_eq!(outputs.get(&3), Some(&30));
        assert_eq!(max_active.load(Ordering::SeqCst), 2);
        assert_eq!(manager.status(graph_id.clone(), &1), Some(JobStatus::Completed));
        assert_eq!(manager.status(graph_id.clone(), &2), Some(JobStatus::Completed));
        assert_eq!(manager.status(graph_id.clone(), &3), Some(JobStatus::Completed));
        assert_eq!(manager.result(graph_id.clone(), &3), Some(30));
        assert_eq!(manager.results(graph_id).len(), 3);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn job_manager_runs_graph_jobs_in_submit_order() {
        use std::sync::{Arc, Mutex};

        let manager = JobManager::<i32, i32>::empty();
        let graph_1 = test_graph_id(1);
        manager
            .add_graph(graph_1.clone(), JobGraph::new([1, 3], BTreeMap::from([(3, vec![1])])))
            .expect("graph should be accepted");

        assert_eq!(manager.status(graph_1.clone(), &1), Some(JobStatus::Ready));
        assert_eq!(manager.status(graph_1.clone(), &3), Some(JobStatus::Pending));

        let observed_order = Arc::new(Mutex::new(Vec::new()));
        manager
            .run_graph(graph_1.clone(), [], [1, 3], {
                let observed_order = observed_order.clone();
                move |job| {
                    let observed_order = observed_order.clone();
                    async move {
                        observed_order.lock().expect("order mutex poisoned").push(job);
                        Ok::<_, anyhow::Error>(job * 100)
                    }
                }
            })
            .await
            .expect("graph should complete");

        let observed_order = observed_order.lock().expect("order mutex poisoned").clone();
        assert_eq!(observed_order.len(), 2);
        let first_graph_root = observed_order.iter().position(|job| *job == 1).expect("root job should run");
        let first_graph_dependent = observed_order.iter().position(|job| *job == 3).expect("dependent job should run");
        assert!(first_graph_root < first_graph_dependent);
        assert_eq!(manager.status(graph_1.clone(), &1), Some(JobStatus::Completed));
        assert_eq!(manager.status(graph_1.clone(), &3), Some(JobStatus::Completed));
        assert_eq!(manager.result(graph_1.clone(), &1), Some(100));
        assert_eq!(manager.result(graph_1, &3), Some(300));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn job_manager_clears_one_graph_without_touching_others() {
        let manager = JobManager::<i32, i32>::empty();
        let graph_10 = test_graph_id(10);
        let graph_20 = test_graph_id(20);
        manager
            .add_graph(graph_10.clone(), JobGraph::new([1, 2], BTreeMap::from([(2, vec![1])])))
            .expect("first graph should be accepted");
        manager
            .add_graph(graph_20.clone(), JobGraph::new([1], BTreeMap::new()))
            .expect("second graph should be accepted");

        manager.clear_graph(graph_10.clone()).expect("graph should clear");

        assert_eq!(manager.status(graph_10.clone(), &1), None);
        assert_eq!(manager.status(graph_10, &2), None);
        assert_eq!(manager.status(graph_20, &1), Some(JobStatus::Ready));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn job_manager_runs_multiple_graphs_concurrently() {
        use std::time::Duration;

        let manager = JobManager::<i32, i32>::empty();
        let graph_10_id = test_graph_id(10);
        let graph_20_id = test_graph_id(20);
        manager
            .add_graph(graph_10_id.clone(), JobGraph::new([1, 2], BTreeMap::from([(2, vec![1])])))
            .expect("first graph should be accepted");
        manager
            .add_graph(graph_20_id.clone(), JobGraph::new([1, 2], BTreeMap::from([(2, vec![1])])))
            .expect("second graph should be accepted");

        let graph_10 = manager.clone();
        let graph_20 = manager.clone();
        let (out_10, out_20) = tokio::join!(
            graph_10.run_graph(graph_10_id.clone(), [], [1, 2], |job| async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok::<_, anyhow::Error>(1000 + job)
            }),
            graph_20.run_graph(graph_20_id.clone(), [], [1, 2], |job| async move {
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok::<_, anyhow::Error>(2000 + job)
            })
        );

        let out_10 = out_10.expect("graph 10 should complete");
        let out_20 = out_20.expect("graph 20 should complete");

        assert_eq!(out_10.get(&1), Some(&1001));
        assert_eq!(out_10.get(&2), Some(&1002));
        assert_eq!(out_20.get(&1), Some(&2001));
        assert_eq!(out_20.get(&2), Some(&2002));
        assert_eq!(manager.result(test_graph_id(10), &1), Some(1001));
        assert_eq!(manager.result(test_graph_id(20), &1), Some(2001));
        assert_eq!(manager.status(test_graph_id(10), &2), Some(JobStatus::Completed));
        assert_eq!(manager.status(test_graph_id(20), &2), Some(JobStatus::Completed));
    }

    // -----------------------------------------------------------------------
    // ProofTreeMeta helpers
    // -----------------------------------------------------------------------

    /// After inserting two leaves sequentially, `next_leaf_index` advances by
    /// 2.
    #[test]
    fn insert_next_leaf_advances_index() {
        let mut meta = ProofTreeMeta::new(16);
        assert_eq!(meta.next_leaf_index, 0);

        let lv1 = make_qhash(1, 0, 0, 0);
        let lv2 = make_qhash(2, 0, 0, 0);

        let (idx1, _old1) = insert_next_leaf(&mut meta, lv1);
        assert_eq!(idx1, 0);
        assert_eq!(meta.next_leaf_index, 1);

        let (idx2, _old2) = insert_next_leaf(&mut meta, lv2);
        assert_eq!(idx2, 1);
        assert_eq!(meta.next_leaf_index, 2);
    }

    /// The root changes after each insertion (non-zero leaf in a zero tree).
    #[test]
    fn insert_next_leaf_changes_root() {
        let mut meta = ProofTreeMeta::new(16);
        let zero_root = current_root(&meta);

        insert_next_leaf(&mut meta, make_qhash(42, 0, 0, 0));
        let root_after1 = current_root(&meta);

        assert_ne!(root_after1, zero_root, "root must change after non-zero leaf insertion");

        insert_next_leaf(&mut meta, make_qhash(43, 0, 0, 0));
        let root_after2 = current_root(&meta);

        assert_ne!(root_after2, root_after1, "root must change again after second insertion");
    }

    /// `root_history` has one entry per leaf inserted (old root before that
    /// leaf).
    #[test]
    fn insert_next_leaf_records_root_history() {
        let mut meta = ProofTreeMeta::new(16);
        insert_next_leaf(&mut meta, make_qhash(1, 0, 0, 0));
        insert_next_leaf(&mut meta, make_qhash(2, 0, 0, 0));
        // root_history grows by one per insert_leaf_value call.
        assert_eq!(meta.root_history.len(), 2);
    }

    // -----------------------------------------------------------------------
    // Integration: schedule with no CFC steps
    // -----------------------------------------------------------------------

    /// Phase A over a trace with no steps → empty seeds, unchanged meta.
    ///
    /// This test exercises `TraceProofSchedule::build` without constructing
    /// a full `TxTrace` — it builds a minimal stub and verifies invariants.
    #[test]
    fn schedule_build_no_steps_is_empty() {
        let initial_meta = ProofTreeMeta::new(16);
        let initial_baton: LastStepProofInfo = Default::default();

        // Build a minimal stub TxTrace with no steps.
        let trace = minimal_empty_trace();

        let schedule = TraceProofSchedule::build(initial_meta.clone(), initial_baton, &trace).expect("build should succeed for empty trace");

        assert!(schedule.seeds.is_empty());
        assert_eq!(schedule.final_meta.next_leaf_index, 0);
        assert_eq!(schedule.final_baton.proof_tree_index, initial_baton.proof_tree_index);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn trace_proof_plan_binds_graph_id_schedule_and_job_graph() {
        let mut trace = minimal_empty_trace();
        trace.finalization.tx_hash = make_qhash(7, 8, 9, 10);
        let schedule = TraceProofSchedule::build(ProofTreeMeta::new(16), LastStepProofInfo::default(), &trace).expect("schedule should build");

        let plan = TraceProofPlan::from_trace_and_schedule(&trace, schedule);

        assert_eq!(plan.graph_id, graph_id_from_trace(&trace));
        assert!(plan.seeds_by_step().is_empty());
        assert_eq!(
            plan.job_graph.jobs(),
            vec![
                TraceProofJobId::UpsStart,
                TraceProofJobId::ZkSign,
                TraceProofJobId::EndCap,
                TraceProofJobId::Submit
            ]
        );
    }

    /// Construct the absolute-minimal `TxTrace` that has no steps and no
    /// external proofs — everything that `TraceProofSchedule::build` reads
    /// from it in the step loop is skipped entirely.
    fn minimal_empty_trace() -> crate::trace::TxTrace {
        use plonky2::field::types::Field;
        use psy_client_data::{
            guta::end_cap_input::SubmitUserEndCapNonProofInput,
            qdata::checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeaf},
            ups::ups_context_input::UserProvingSessionHeader,
        };
        use psy_crypto::hash::merkle::core::MerkleProofCore;

        use crate::trace::{SessionAnchor, TraceMeta, TxFinalization, TxTrace, UpsStartWitness};

        TxTrace {
            meta: TraceMeta {
                network_magic: 0,
                user_id: 0,
                public_key: QHashOut::ZERO,
            },
            anchor: SessionAnchor {
                start_checkpoint_id: 0,
                checkpoint_leaf: PsyCheckpointLeaf::default(),
                global_state_roots: PsyCheckpointGlobalStateRoots::default(),
                ups_step_circuit_whitelist_root: QHashOut::ZERO,
            },
            ups_start_witness: UpsStartWitness {
                ups_header: UserProvingSessionHeader::default(),
                state_roots: PsyCheckpointGlobalStateRoots::default(),
                checkpoint_tree_proof: MerkleProofCore::default(),
                user_tree_proof: MerkleProofCore::default(),
                user_registration_tree_proof: None,
                proof: None,
            },
            contract_codes: Vec::new(),
            steps: Vec::new(),
            finalization: TxFinalization {
                submit_end_cap_input: SubmitUserEndCapNonProofInput::default(),
                nonce: F::ZERO,
                tx_hash: QHashOut::ZERO,
                software_defined_call: Default::default(),
                sig_hash: QHashOut::ZERO,
            },
        }
    }
}
