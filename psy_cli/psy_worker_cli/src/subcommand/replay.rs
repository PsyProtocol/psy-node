//! Offline replay of captured worker jobs.
//!
//! Reads the claim files written by the worker capture service
//! (`<Circuit>-g<goal>-<key16>.job.json.gz` with the edge's response,
//! `...proof.json.gz` with the proof the production worker sent back), proves
//! each job again with the same prover the worker uses, and checks the result
//! against production. Nothing here talks to the network.
//!
//! The prover blinds its proofs with fresh randomness, so two proofs of the
//! same job never have the same bytes. A replayed proof is equivalent to the
//! production one when it verifies, as the edge verifies a submission, with
//! the public inputs of the proof production sent. Separately, every
//! production proof is verified with this build's circuits: that fails when
//! the build's circuits are not the ones production runs (another network, a
//! different revision, or a change that altered a circuit).

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufReader, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    time::Instant,
};

use flate2::read::GzDecoder;
use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig};
use psy_core::{
    constants::chain_id::{PsyChainNetworkType, PsyNetworkTypeInput},
    job::job_id::QProvingJobDataID,
};
use psy_data::worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse;
use parth_core::protocol::core_types::{QZKProofPublicInputsHasherReader, QZKProofVerifier};
use psy_plonky2_circuits::{circuit_library::get_plonky2_circuit_library_and_prover_for_network, zk_verifier::PsyPlonky2ZKVerifier};
use psy_worker_core::worker::prover_trait::PsyWorkerGenericLibraryProver;
use serde::{de::IgnoredAny, Deserialize};

type C = PoseidonGoldilocksConfig;
const D: usize = 2;
type Hash = QHashOut<GoldilocksField>;
type JobInput = PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>;

const JOB_SUFFIX: &str = ".job.json.gz";
const PROOF_SUFFIX: &str = ".proof.json.gz";

#[derive(Deserialize)]
struct JobFile {
    key: String,
    response: RpcResult,
}

#[derive(Deserialize)]
struct RpcResult {
    result: JobInput,
}

#[derive(Deserialize)]
struct ProofFile {
    accepted: bool,
    request: SubmitRequest,
}

#[derive(Deserialize)]
struct SubmitRequest {
    // signature, timed request, job id, reward tag, proof
    params: (IgnoredAny, IgnoredAny, QProvingJobDataID, Hash, Vec<u8>),
}

/// A claim file located by its path, before anything is read:
/// `<role>/<day>/<circuit>-g<goal>-<key16>.job.json.gz`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ClaimPath {
    day: String,
    goal: u64,
    role: String,
    circuit: String,
    job_path: PathBuf,
}

struct Claim {
    key: String,
    role: String,
    circuit: String,
    input: JobInput,
    tag: Hash,
    recorded_proof: Vec<u8>,
}

#[derive(Default, Debug, PartialEq, Eq)]
struct LoadSummary {
    without_proof: usize,
    rejected: usize,
    unreadable: usize,
    mismatched: usize,
}

struct Outcome {
    key: String,
    role: String,
    circuit: String,
    pass: usize,
    wall_ms: f64,
    proof_bytes: usize,
    /// Verifies with the public inputs of the proof production sent.
    equivalent: bool,
    error: Option<String>,
}

fn read_gz_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let file = File::open(path).map_err(|e| anyhow::anyhow!("{}: {}", path.display(), e))?;
    serde_json::from_reader(BufReader::new(GzDecoder::new(BufReader::new(file)))).map_err(|e| anyhow::anyhow!("{}: {}", path.display(), e))
}

fn parse_claim_path(path: &Path) -> Option<ClaimPath> {
    let stem = path.file_name()?.to_str()?.strip_suffix(JOB_SUFFIX)?;
    let (rest, _key16) = stem.rsplit_once('-')?;
    let (circuit, goal) = rest.rsplit_once("-g")?;
    let day_dir = path.parent()?;
    Some(ClaimPath {
        day: day_dir.file_name()?.to_str()?.to_string(),
        goal: goal.parse().ok()?,
        role: day_dir.parent()?.file_name()?.to_str()?.to_string(),
        circuit: circuit.to_string(),
        job_path: path.to_path_buf(),
    })
}

fn find_claim_paths(dir: &Path, out: &mut Vec<ClaimPath>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir).map_err(|e| anyhow::anyhow!("{}: {}", dir.display(), e))? {
        let entry = entry?;
        // The entry's own type: a symbolic link is not followed.
        if entry.file_type()?.is_dir() {
            find_claim_paths(&entry.path(), out)?;
        } else if let Some(claim) = parse_claim_path(&entry.path()) {
            out.push(claim);
        }
    }
    Ok(())
}

/// Chooses claims by file name alone, oldest first (capture day, then goal
/// id, which is the checkpoint the job belongs to), so that only the chosen
/// files are read however large the store is.
fn select_claim_paths(inputs: &Path, role: Option<&str>, circuit: Option<&str>) -> anyhow::Result<Vec<ClaimPath>> {
    let mut paths = Vec::new();
    find_claim_paths(inputs, &mut paths)?;
    paths.retain(|p| role.is_none_or(|r| r == p.role) && circuit.is_none_or(|c| c == p.circuit));
    paths.sort();
    Ok(paths)
}

/// Loads up to `limit` claims that have an accepted proof, and up to
/// `per_circuit` of each role and circuit type.
fn load_claims(inputs: &Path, role: Option<&str>, circuit: Option<&str>, limit: usize, per_circuit: usize) -> anyhow::Result<(Vec<Claim>, LoadSummary)> {
    let mut summary = LoadSummary::default();
    let mut taken: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut claims = Vec::new();
    for candidate in select_claim_paths(inputs, role, circuit)? {
        if claims.len() >= limit {
            break;
        }
        let group = (candidate.role.clone(), candidate.circuit.clone());
        if taken.get(&group).copied().unwrap_or(0) >= per_circuit {
            continue;
        }
        let name = candidate.job_path.file_name().unwrap().to_str().unwrap();
        let proof_path = candidate.job_path.with_file_name(format!("{}{}", &name[..name.len() - JOB_SUFFIX.len()], PROOF_SUFFIX));
        if !proof_path.exists() {
            summary.without_proof += 1;
            continue;
        }
        // The small file first: a rejected proof costs no job parse.
        let proof: ProofFile = match read_gz_json(&proof_path) {
            Ok(proof) => proof,
            Err(e) => {
                summary.unreadable += 1;
                tracing::warn!("skipping unreadable proof: {}", e);
                continue;
            }
        };
        if !proof.accepted {
            summary.rejected += 1;
            continue;
        }
        let job: JobFile = match read_gz_json(&candidate.job_path) {
            Ok(job) => job,
            Err(e) => {
                summary.unreadable += 1;
                tracing::warn!("skipping unreadable claim: {}", e);
                continue;
            }
        };
        let (_, _, job_id, tag, recorded_proof) = proof.request.params;
        if job_id != job.response.result.base.job.job_id {
            summary.mismatched += 1;
            tracing::warn!("skipping {}: its proof file is for another job", candidate.job_path.display());
            continue;
        }
        *taken.entry(group).or_default() += 1;
        claims.push(Claim { key: job.key, role: candidate.role, circuit: candidate.circuit, input: job.response.result, tag, recorded_proof });
    }
    Ok((claims, summary))
}

/// User plus system CPU seconds consumed by this process so far, all threads.
fn process_cpu_seconds() -> anyhow::Result<f64> {
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    // Fields after the command name, which may itself contain spaces.
    let fields: Vec<&str> = stat.rsplit(')').next().unwrap_or("").split_whitespace().collect();
    let ticks = |i: usize| fields.get(i).and_then(|v| v.parse::<f64>().ok()).ok_or_else(|| anyhow::anyhow!("unexpected /proc/self/stat"));
    // utime and stime are fields 14 and 15 of the line, in USER_HZ units,
    // which the Linux ABI fixes at 100 per second.
    Ok((ticks(11)? + ticks(12)?) / 100.0)
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    sorted[((sorted.len() as f64 * q) as usize).min(sorted.len() - 1)]
}

pub fn run(
    inputs: String,
    network: Option<PsyNetworkTypeInput>,
    role: Option<String>,
    circuit: Option<String>,
    limit: usize,
    per_circuit: usize,
    concurrency: usize,
    passes: usize,
    out: Option<String>,
    dump_proofs: Option<String>,
    require_equivalent: bool,
) -> anyhow::Result<()> {
    let network: PsyChainNetworkType = network.unwrap_or_default().into();
    let (claims, summary) = load_claims(Path::new(&inputs), role.as_deref(), circuit.as_deref(), limit, per_circuit)?;
    println!(
        "[replay] loaded {} claims ({} without a proof, {} rejected by the edge, {} unreadable, {} with a proof for another job)",
        claims.len(),
        summary.without_proof,
        summary.rejected,
        summary.unreadable,
        summary.mismatched
    );
    if claims.is_empty() {
        anyhow::bail!("no replayable claims under {}", inputs);
    }

    let setup_start = Instant::now();
    let (gcv, prover) = get_plonky2_circuit_library_and_prover_for_network::<C, D>(network)?;
    let verifier = PsyPlonky2ZKVerifier::<C, D>::new(gcv);
    let library = &verifier.gcv.library;
    println!("[replay] circuits built in {:.1}s, cpu {:.1}s", setup_start.elapsed().as_secs_f64(), process_cpu_seconds()?);

    // What the edge does with a submitted proof: check its public inputs and verify it.
    let verifies = |claim: &Claim, proof: &[u8], public_inputs: Hash| -> bool {
        let circuit_type = claim.input.base.job.job_id.circuit_type.to_u8() as u32;
        catch_unwind(AssertUnwindSafe(|| verifier.verify_zk_proof_from_slice_check_public_inputs_hash(circuit_type, proof, public_inputs).is_ok())).unwrap_or(false)
    };
    // The public inputs production proved, and whether this build's circuits accept production's proof.
    let production: Vec<Option<Hash>> = claims
        .iter()
        .map(|claim| {
            let proof = PsyPlonky2ZKVerifier::<C, D>::try_proof_from_slice(&claim.recorded_proof).ok()?;
            let public_inputs = PsyPlonky2ZKVerifier::<C, D>::get_proof_public_inputs_hash(&proof).ok()?;
            verifies(claim, &claim.recorded_proof, public_inputs).then_some(public_inputs)
        })
        .collect();
    let production_verified = production.iter().filter(|p| p.is_some()).count();
    println!("[replay] {} of {} production proofs verify with this build's circuits", production_verified, claims.len());

    let concurrency = concurrency.max(1);
    let passes = passes.max(1);
    if let Some(dir) = &dump_proofs {
        std::fs::create_dir_all(dir)?;
        for claim in &claims {
            std::fs::write(Path::new(dir).join(format!("{}.recorded.proof", claim.key)), &claim.recorded_proof)?;
        }
    }
    // A panic inside one proof is that proof's failure, as in the worker.
    let prove = |input: JobInput, tag: Hash| -> anyhow::Result<Vec<u8>> {
        match catch_unwind(AssertUnwindSafe(|| prover.prove_job_from_api(library, input, tag))) {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("proving panicked")),
        }
    };

    // Untimed: the first proof of every circuit type, so that no timed pass
    // pays for paging a circuit in or starting the thread pool.
    let mut warmed = BTreeSet::new();
    for claim in &claims {
        if warmed.insert((claim.role.as_str(), claim.circuit.as_str())) {
            let _ = prove(claim.input.clone(), claim.tag);
        }
    }

    let mut outcomes = Vec::<Outcome>::new();
    let mut pass_lines = Vec::new();
    for pass in 0..passes {
        // The worker owns each job it proves; the copies are made before the clock starts.
        let inputs: Vec<Mutex<Option<JobInput>>> = claims.iter().map(|c| Mutex::new(Some(c.input.clone()))).collect();
        let pass_outcomes = Mutex::new(Vec::<(usize, Outcome, Option<Vec<u8>>)>::with_capacity(claims.len()));
        let next = AtomicUsize::new(0);
        let cpu_before = process_cpu_seconds()?;
        let wall = Instant::now();
        std::thread::scope(|scope| {
            for _ in 0..concurrency {
                scope.spawn(|| loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    let Some(claim) = claims.get(index) else { break };
                    let input = inputs[index].lock().unwrap().take().unwrap();
                    let start = Instant::now();
                    let result = prove(input, claim.tag);
                    let wall_ms = start.elapsed().as_secs_f64() * 1000.0;
                    let (proof, error) = match result {
                        Ok(proof) => (Some(proof), None),
                        Err(e) => (None, Some(format!("{:?}", e))),
                    };
                    let outcome = Outcome { key: claim.key.clone(), role: claim.role.clone(), circuit: claim.circuit.clone(), pass, wall_ms, proof_bytes: proof.as_ref().map_or(0, |p| p.len()), equivalent: false, error };
                    pass_outcomes.lock().unwrap().push((index, outcome, proof));
                });
            }
        });
        let wall_seconds = wall.elapsed().as_secs_f64();
        let cpu_seconds = process_cpu_seconds()? - cpu_before;
        // The clocks have stopped: check the proofs the way the edge would.
        let mut checked = Vec::with_capacity(claims.len());
        for (index, mut outcome, proof) in pass_outcomes.into_inner().unwrap() {
            if let Some(proof) = proof {
                let claim = &claims[index];
                outcome.equivalent = production[index].is_some_and(|public_inputs| verifies(claim, &proof, public_inputs));
                if let Some(dir) = &dump_proofs {
                    std::fs::write(Path::new(dir).join(format!("{}.pass{}.proof", claim.key, pass)), &proof)?;
                }
            }
            checked.push(outcome);
        }
        let pass_outcomes = checked;
        let proved = pass_outcomes.iter().filter(|o| o.error.is_none()).count();
        pass_lines.push(format!(
            "[replay] pass {}: {} proved, {} failed in {:.2}s wall = {:.2} proofs/s, {:.3} cpu-s per proof, {:.1} cores busy",
            pass,
            proved,
            pass_outcomes.len() - proved,
            wall_seconds,
            proved as f64 / wall_seconds,
            cpu_seconds / proved.max(1) as f64,
            cpu_seconds / wall_seconds
        ));
        outcomes.extend(pass_outcomes);
    }

    if let Some(path) = out {
        let mut file = std::io::BufWriter::new(File::create(&path)?);
        for o in &outcomes {
            writeln!(
                file,
                "{}",
                serde_json::json!({"key": o.key, "role": o.role, "circuit": o.circuit, "pass": o.pass, "wall_ms": o.wall_ms, "proof_bytes": o.proof_bytes, "equivalent": o.equivalent, "error": o.error})
            )?;
        }
    }

    // The table describes the last pass only; earlier passes are in the pass lines and in --out.
    let mut by_circuit: BTreeMap<(&str, &str), Vec<&Outcome>> = BTreeMap::new();
    for o in outcomes.iter().filter(|o| o.pass == passes - 1) {
        by_circuit.entry((o.role.as_str(), o.circuit.as_str())).or_default().push(o);
    }
    println!("{:<12} {:<46} {:>6} {:>9} {:>9} {:>9} {:>10} {:>6}", "role", "circuit", "proofs", "median_ms", "p95_ms", "max_ms", "equivalent", "failed");
    for ((role, circuit), items) in &by_circuit {
        let mut wall: Vec<f64> = items.iter().filter(|o| o.error.is_none()).map(|o| o.wall_ms).collect();
        wall.sort_by(|a, b| a.total_cmp(b));
        println!(
            "{:<12} {:<46} {:>6} {:>9.1} {:>9.1} {:>9.1} {:>10} {:>6}",
            role,
            circuit,
            items.len(),
            quantile(&wall, 0.5),
            quantile(&wall, 0.95),
            wall.last().copied().unwrap_or(0.0),
            items.iter().filter(|o| o.equivalent).count(),
            items.iter().filter(|o| o.error.is_some()).count()
        );
    }
    for line in &pass_lines {
        println!("{}", line);
    }
    let failed = outcomes.iter().filter(|o| o.error.is_some()).count();
    let not_equivalent = outcomes.iter().filter(|o| o.error.is_none() && !o.equivalent).count();
    println!(
        "[replay] concurrency {}, {} passes over {} claims: {} proofs equivalent to production, {} not, {} failed",
        concurrency,
        passes,
        claims.len(),
        outcomes.len() - failed - not_equivalent,
        not_equivalent,
        failed
    );
    if let Some(o) = outcomes.iter().find(|o| o.error.is_some()) {
        println!("[replay] first failure: {} {}: {}", o.circuit, o.key, o.error.as_deref().unwrap_or(""));
    }
    if production_verified < claims.len() {
        println!("[replay] this build's circuits reject {} production proofs: wrong --network, another revision, or a changed circuit", claims.len() - production_verified);
    }
    if failed > 0 || (require_equivalent && (not_equivalent > 0 || production_verified < claims.len())) {
        anyhow::bail!("replay did not reproduce production: {} not equivalent, {} failed, {} production proofs rejected", not_equivalent, failed, claims.len() - production_verified);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use parth_core::utils::QPGenRandom;

    /// A scratch directory removed when the test ends, passed or not.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("psy-worker-replay-{}-{}", name, std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_gz(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut encoder = GzEncoder::new(File::create(path).unwrap(), Compression::fast());
        encoder.write_all(text.as_bytes()).unwrap();
        encoder.finish().unwrap();
    }

    /// Writes a file the way the capture service does: a small head object
    /// with the request and response bodies spliced in verbatim.
    fn write_pair_file(path: &Path, head: serde_json::Value, request: &str, response: &str) {
        let mut head = serde_json::to_string(&head).unwrap();
        head.pop();
        write_gz(path, &format!("{},\"request\":{},\"response\":{}}}\n", head, request, response));
    }

    struct Written {
        input: JobInput,
        tag: Hash,
        proof: Vec<u8>,
    }

    /// One claim under `<root>/<role>/<day>/`, with a proof file unless `accepted` is None.
    fn write_claim(root: &Path, role: &str, day: &str, circuit: &str, goal: u64, key16: &str, accepted: Option<bool>) -> Written {
        let dir = root.join(role).join(day);
        let stem = format!("{}-g{}-{}", circuit, goal, key16);
        let input = JobInput::qp_rand_gen();
        let job_id = input.base.job.job_id;
        let tag = Hash::qp_rand_gen();
        let proof: Vec<u8> = vec![0, 1, 2, 254, 255, goal as u8];
        let job_id_json = serde_json::to_value(job_id).unwrap();
        // The bodies as jsonrpsee puts them on the wire.
        let fetch_request = r#"{"jsonrpc":"2.0","id":7,"method":"psy_worker_get_proving_work_with_child_proofs","params":[{},{}]}"#;
        let fetch_response = format!(r#"{{"jsonrpc":"2.0","id":7,"result":{}}}"#, serde_json::to_string(&input).unwrap());
        let job_head = serde_json::json!({"version": 1, "kind": "worker_job", "role": role, "port": 11337, "key": format!("{}-full-key", key16), "job_id": job_id_json, "circuit_type": circuit, "fetch_request_time": 1.0, "fetch_response_time": 2.0});
        write_pair_file(&dir.join(format!("{}{}", stem, JOB_SUFFIX)), job_head, fetch_request, &fetch_response);
        if let Some(accepted) = accepted {
            let submit_request = format!(
                r#"{{"jsonrpc":"2.0","id":8,"method":"psy_worker_submit_proof_raw","params":{}}}"#,
                serde_json::to_string(&(serde_json::json!({}), serde_json::json!({}), job_id, tag, &proof)).unwrap()
            );
            let mut head = serde_json::json!({"version": 1, "kind": "worker_proof", "role": role, "port": 11337, "key": format!("{}-full-key", key16), "job_id": job_id_json, "circuit_type": circuit, "accepted": accepted, "submit_request_time": 3.0, "submit_response_time": 4.0});
            // An answer that was not JSON is stored as null with its text in the head.
            let response = if accepted {
                r#"{"jsonrpc":"2.0","id":8,"result":null}"#
            } else {
                head["response_not_json"] = "bad gateway".into();
                head["http_status"] = 502.into();
                "null"
            };
            write_pair_file(&dir.join(format!("{}{}", stem, PROOF_SUFFIX)), head, &submit_request, response);
        }
        Written { input, tag, proof }
    }

    fn goals(claims: &[Claim]) -> Vec<u8> {
        claims.iter().map(|c| *c.recorded_proof.last().unwrap()).collect()
    }

    #[test]
    fn loads_what_the_capture_service_writes() {
        let scratch = Scratch::new("load");
        let written = write_claim(&scratch.0, "coordinator", "20260930", "GUTANoChange", 1, "aaaa", Some(true));
        // Rejected by the edge, never submitted, and not a claim file at all.
        write_claim(&scratch.0, "coordinator", "20260930", "GUTANoChange", 2, "bbbb", Some(false));
        write_claim(&scratch.0, "coordinator", "20260930", "GUTANoChange", 3, "cccc", None);
        std::fs::write(scratch.0.join("coordinator").join("20260930").join("notes.txt"), "x").unwrap();

        let (claims, summary) = load_claims(&scratch.0, None, None, usize::MAX, usize::MAX).unwrap();
        assert_eq!(claims.len(), 1);
        assert!(claims[0].input == written.input);
        assert!(claims[0].tag == written.tag);
        assert_eq!(claims[0].recorded_proof, written.proof);
        assert_eq!((claims[0].role.as_str(), claims[0].circuit.as_str(), claims[0].key.as_str()), ("coordinator", "GUTANoChange", "aaaa-full-key"));
        assert_eq!(summary, LoadSummary { without_proof: 1, rejected: 1, unreadable: 0, mismatched: 0 });
    }

    #[test]
    fn selects_oldest_first_by_name_with_filters_and_limits() {
        let scratch = Scratch::new("select");
        // Written out of order; two days, two roles, two circuit types.
        write_claim(&scratch.0, "coordinator", "20260930", "GUTANoChange", 12, "a3", Some(true));
        write_claim(&scratch.0, "coordinator", "20260929", "GUTANoChange", 90, "a1", Some(true));
        write_claim(&scratch.0, "coordinator", "20260930", "GUTANoChange", 9, "a2", Some(true));
        write_claim(&scratch.0, "coordinator", "20260930", "GenerateRollupStateTransitionProof", 10, "b1", Some(true));
        write_claim(&scratch.0, "realm-0", "20260930", "GUTASingleEndCap", 11, "c1", Some(true));

        let all = |role, circuit, limit, per_circuit| goals(&load_claims(&scratch.0, role, circuit, limit, per_circuit).unwrap().0);
        // Day first, then goal id as a number (9 before 10 before 12).
        assert_eq!(all(None, None, usize::MAX, usize::MAX), vec![90, 9, 10, 11, 12]);
        assert_eq!(all(None, None, 2, usize::MAX), vec![90, 9]);
        assert_eq!(all(None, None, usize::MAX, 1), vec![90, 10, 11]);
        assert_eq!(all(Some("coordinator"), None, usize::MAX, usize::MAX), vec![90, 9, 10, 12]);
        assert_eq!(all(Some("realm-0"), None, usize::MAX, usize::MAX), vec![11]);
        assert_eq!(all(None, Some("GUTANoChange"), usize::MAX, usize::MAX), vec![90, 9, 12]);
        assert!(all(None, Some("GUTANoChang"), usize::MAX, usize::MAX).is_empty());

        // A limit is met without reading the files beyond it: make them unreadable.
        write_gz(&scratch.0.join("coordinator/20260930/GUTANoChange-g12-a3.job.json.gz"), "not json");
        let (claims, summary) = load_claims(&scratch.0, None, None, 2, usize::MAX).unwrap();
        assert_eq!((goals(&claims), summary.unreadable), (vec![90, 9], 0));
    }

    #[test]
    fn skips_and_counts_files_it_cannot_use() {
        let scratch = Scratch::new("skip");
        write_claim(&scratch.0, "coordinator", "20260930", "GUTANoChange", 1, "aaaa", Some(true));
        write_claim(&scratch.0, "coordinator", "20260930", "GUTANoChange", 2, "bbbb", Some(true));
        write_claim(&scratch.0, "coordinator", "20260930", "GUTANoChange", 3, "cccc", Some(true));
        write_claim(&scratch.0, "coordinator", "20260930", "GUTANoChange", 5, "eeee", Some(true));
        let day = scratch.0.join("coordinator").join("20260930");
        // A truncated job file, and a proof file that belongs to another job.
        write_gz(&day.join("GUTANoChange-g2-bbbb.job.json.gz"), "{\"key\":\"k\",\"response\":{\"result\":{");
        std::fs::copy(day.join("GUTANoChange-g5-eeee.proof.json.gz"), day.join("GUTANoChange-g3-cccc.proof.json.gz")).unwrap();
        std::fs::write(day.join("GUTANoChange-g4-dddd.job.json.gz"), b"not gzip").unwrap();
        std::fs::write(day.join("GUTANoChange-g4-dddd.proof.json.gz"), b"not gzip").unwrap();

        let (claims, summary) = load_claims(&scratch.0, None, None, usize::MAX, usize::MAX).unwrap();
        assert_eq!(goals(&claims), vec![1, 5]);
        assert_eq!(summary, LoadSummary { without_proof: 0, rejected: 0, unreadable: 2, mismatched: 1 });
    }

    #[test]
    fn reads_cpu_time_of_this_process() {
        let before = process_cpu_seconds().unwrap();
        let mut x = 0u64;
        let start = Instant::now();
        while start.elapsed().as_millis() < 300 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        }
        std::hint::black_box(x);
        let used = process_cpu_seconds().unwrap() - before;
        assert!((0.2..2.0).contains(&used), "cpu seconds for a 300 ms busy loop: {}", used);
    }
}
