#!/usr/bin/env python3
"""Check selected real-service regressions by temporarily injecting known faults.

Run against one disposable service, using the same endpoint env var as coverage.
Every case must pass before injection, fail in its named test (not compilation),
and pass again after restoring the exact source bytes. This is a small directed
fault sample, not an exhaustive mutation score.
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import subprocess

ROOT = Path(__file__).resolve().parent.parent
CASES = {
    "scylla": [
        ("future_leaf_hides_snapshot", "src/tables/merkle/zero.rs", "dump_leaves_stream", "snapshot", "merkle_contract", "zero_id_dump_selects_history_before_future_overwrites"),
        ("future_append_leaf_hides_snapshot", "src/tables/merkle/zero.rs", "dump_leaves_stream_end_index", "snapshot", "merkle_contract", "append_only_dump_respects_snapshot_and_full_tree_boundary"),
        ("kiv_plain_no_write", "src/tables/object/kiv.rs", "insert_many_kivs", "noop", "table_contract", "kiv_batch_variants_return_values_in_requested_order"),
        ("kiv_generic_no_write", "src/tables/object/kiv.rs", "insert_many_kivs_t", "noop", "table_contract", "kiv_batch_variants_return_values_in_requested_order"),
        ("kiv_rows_no_write", "src/tables/object/kiv.rs", "insert_many_kiv_rows_t", "noop", "table_contract", "kiv_batch_variants_return_values_in_requested_order"),
        ("checkpoint_writer_no_write", "src/tables/object/single.rs", "insert_many_single_checkpointed_objects_at_checkpoint_t_single_insert_chunks", "noop", "table_contract", "packed_object_writers_preserve_ids_values_and_checkpoint_history"),
    ],
    "nats": [
        ("overfetch_past_limit", "src/queue.rs", "dump_queue_dq_bytes_ephemeral", "overfetch", "nats_live_surface", "ephemeral_publish_wait_dump_and_ack_modes"),
        ("noack_sends_ack", "src/queue.rs", "dump_queue_dq_bytes_ephemeral", "ack", "nats_live_surface", "ack_modes_change_server_pending_state"),
    ],
    "redis": [
        ("blocking_wait_uses_shared_pool", "src/store/core_fred.rs", "blocking_pop", "pool", "store_contract", "blocked_consumers_do_not_starve_producers_and_cancel_cleanly"),
        ("command_timeout_becomes_empty", "src/store/core_fred.rs", "wait_for_ephemeral_queue_item_bytes", "timeout", "store_contract", "queue_server_timeout_is_empty_but_command_and_type_errors_propagate"),
    ],
}


def inject(source, function, fault):
    # Only mutate the named function, so similarly named wrappers are unaffected.
    match = re.search(r"\basync fn " + re.escape(function) + r"(?=[<(])", source)
    if match is None:
        raise RuntimeError(f"Function anchor changed: {function}")
    start = match.start()
    brace = source.index("{", start)
    end = source.find("\n    async fn ", brace)
    public_end = source.find("\n    pub async fn ", brace)
    ends = [i for i in (end, public_end) if i >= 0]
    end = min(ends) if ends else len(source)
    body = source[brace:end]
    if fault == "noop":
        changed = "{\n        return Ok(()); // injected missing write\n" + body[1:]
    else:
        replacements = {
            "snapshot": ("prev_index = Some(node_index_i64);\n            }", "}\n            prev_index = Some(node_index_i64);"),
            "overfetch": ("max_messages(max_messages_per_batch.min(max_messages_total_to_dump))", "max_messages(max_messages_per_batch)"),
            "ack": ("// no-op", 'jet_msg.ack().await.map_err(|e| anyhow::anyhow!("{e}"))?;'),
            "pool": ("let client = self.client.clients()[0].clone_new();\n        let _connection = BlockingConnection(client.connect());\n        client.wait_for_connect().await?;", "let client = self.client.clients()[0].clone();"),
            "timeout": ("self.blocking_pop(&subject, timeout_secs).await?", "match self.blocking_pop(&subject, timeout_secs).await { Err(error) if error.downcast_ref::<fred::error::Error>().is_some_and(|e| e.kind() == &fred::error::ErrorKind::Timeout) => None, other => other?, }"),
        }
        old, new = replacements[fault]
        if body.count(old) != 1:
            raise RuntimeError(f"Fault anchor changed: {function}/{fault}")
        changed = body.replace(old, new)
    return source[:brace] + changed + source[end:]


def run_test(crate, test_file, test_name, log):
    command = ["cargo", "llvm-cov", "test", "--locked", "--no-report", "-p", crate,
               "--test", test_file, test_name, "--", "--ignored", "--exact", "--test-threads=1"]
    env = os.environ.copy()
    env.setdefault("CARGO_BUILD_JOBS", "2")
    env.setdefault("RAYON_NUM_THREADS", "2")
    env.setdefault("PSY_CONFIG_PATH", str(ROOT / "psy-genesis/config.json"))
    with log.open("w") as output:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = process.wait(timeout=300)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
    return code, log.read_text()


def stop(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    signal.signal(signal.SIGTERM, stop)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", choices=CASES)
    args = parser.parse_args()
    required = {"scylla": "PSY_TEST_SCYLLA", "nats": "NATS_INTEGRATION_URL", "redis": "REDIS_URL"}[args.module]
    if not os.environ.get(required):
        parser.error(f"{required} must point to a disposable test service")
    lock_path = ROOT / "target/db-coverage/.runner.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    # Share the coverage runner lock: no competing tests or source mutation.
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        results = []
        out = ROOT / "target/db-test-quality" / args.module
        out.mkdir(parents=True, exist_ok=True)
        (out / "results.json").write_text("[]\n")
        for name, relative, function, fault, test_file, test_name in CASES[args.module]:
            crate = f"psy_node_{args.module}"
            source = ROOT / crate / relative
            before = source.read_bytes()
            mutated = inject(before.decode(), function, fault).encode()
            backup = out / f"{name}.source-backup"
            backup.write_bytes(before)
            code, output = run_test(crate, test_file, test_name, out / f"{name}.baseline.log")
            if code != 0 or "test result: ok. 1 passed" not in output:
                raise RuntimeError(f"{name}: baseline failed; see {out}")
            if source.read_bytes() != before:
                raise RuntimeError(f"Source changed during baseline; refusing to overwrite {source}")
            try:
                source.write_bytes(mutated)
                code, output = run_test(crate, test_file, test_name, out / f"{name}.fault.log")
            finally:
                current = source.read_bytes()
                if current == mutated:
                    source.write_bytes(before)
                elif current != before:
                    raise RuntimeError(f"Concurrent source edit detected; recover original from {backup}")
            detected = code == 101 and f"---- {test_name} stdout ----" in output and "test result: FAILED" in output
            restored_code, restored = run_test(crate, test_file, test_name, out / f"{name}.restored.log")
            if not detected or restored_code != 0 or "test result: ok. 1 passed" not in restored:
                raise RuntimeError(f"{name}: fault survived or restored test failed; see {out}")
            results.append({"case": name, "test": test_name, "source_sha256": hashlib.sha256(before).hexdigest(),
                            "baseline": "PASS", "fault": "DETECTED", "restored": "PASS"})
            (out / "results.json").write_text(json.dumps(results, indent=2) + "\n")
            print(f"{name}: baseline PASS, injected fault DETECTED, restored PASS", flush=True)


if __name__ == "__main__":
    main()
