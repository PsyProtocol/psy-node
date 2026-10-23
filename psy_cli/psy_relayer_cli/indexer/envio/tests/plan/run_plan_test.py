#!/usr/bin/env python3
"""Plan regression test for the deposit read model (design section 9, phase 1).

For each requested scale it initializes the schema with Envio's own code
(generated/src/db/Migrations.res.js, i.e. the DDL `envio start` runs on an
empty database), loads deterministic synthetic data, rebuilds the generated
indexes from their captured definitions, and then plans and runs every shape in
queries.sql with EXPLAIN (ANALYZE, BUFFERS) under both custom and generic
plans. A gated shape fails on a Seq Scan (except DepositTreeMeta), on a missing
expected index, on more shared buffers than its bound, or on a wrong result.

Usage, from the Envio directory after `pnpm install` and `pnpm codegen`
(`--docker` starts and removes a throwaway postgres:16.13 container; with
--host the test creates its own database, refuses an existing one, and drops it
at the end; still never point it at a shared or production server):

    python3 tests/plan/run_plan_test.py --docker --rows 1000000 --rows 10000000

Planner settings stay at PostgreSQL defaults (random_page_cost 4,
effective_cache_size 4GB, parallel query on), which favour sequential scans
more than a tuned production server would. Durability settings in --docker
mode are relaxed for loading only. Requires python3, psql and node; --docker
also needs docker.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import time
from pathlib import Path

ENVIO_DIR = Path(__file__).resolve().parents[2]
QUERIES_PATH = Path(__file__).with_name("queries.sql")

# (chain_index, chain_id, share of every 10 deposits). Sepolia-heavy, as on
# the 2026-10-18 testnet.
CHAINS = [(0, 11155111, 7), (1, 97, 1), (2, 84532, 2)]
CHAIN_ID = {index: chain_id for index, chain_id, _ in CHAINS}
WHALES = 5          # accounts 0..4; every 50th deposit, all on chain_index 0
TOKENS = [
    "0x1111111111111111111111111111111111111111",
    "0x2222222222222222222222222222222222222222",
    "0x3333333333333333333333333333333333333333",
    "0x4444444444444444444444444444444444444444",
]
HASH_MULTIPLIER = 2654435761
LOADED = ["Deposit", "DepositLeaf", "AccountDepositStats", "WithdrawalClaim", "DepositTreeMeta",
          "FinalizedBatch"]
SEQ_SCAN_ALLOWED = {"DepositTreeMeta"}
AT_LEAST_ONE = -1   # expected row count: any non-empty result
REPEATS = 5

DOCKER_SETTINGS = [
    "shared_buffers=4GB", "maintenance_work_mem=2GB", "max_parallel_maintenance_workers=8",
    "max_wal_size=4GB", "checkpoint_timeout=1h", "fsync=off", "synchronous_commit=off",
    "full_page_writes=off", "wal_level=minimal", "max_wal_senders=0", "autovacuum=off",
]


# ── Deterministic synthetic data (mirrored in SQL below) ─────────────────────

def md5(text):
    return hashlib.md5(text.encode()).hexdigest()


def hex64(prefix, n):
    return "0x" + md5(f"{prefix}:{n}") + md5(f"{prefix}2:{n}")


def chain_of(g):
    m = g % 10
    return 0 if m < 7 else (1 if m == 7 else 2)


def local_of(g):
    m, q = g % 10, g // 10
    return [q * 7 + m, q, q * 2 + (m - 8)][chain_of(g)]


def account_of(g, accounts):
    if g % 50 == 0:
        return (g // 50) % WHALES
    return WHALES + (g * HASH_MULTIPLIER) % accounts


def tx_of(g):
    return g - 1 if g % 20 == 1 else g


ROW_SQL = """(
  SELECT g, ci, (CASE ci WHEN 0 THEN 11155111 WHEN 1 THEN 97 ELSE 84532 END) AS cid,
         (CASE ci WHEN 0 THEN (g / 10) * 7 + m WHEN 1 THEN g / 10 ELSE (g / 10) * 2 + (m - 8) END) AS loc,
         (CASE WHEN g % 50 = 0 THEN (g / 50) % {whales} ELSE {whales} + (g * {mult}) % {accounts} END) AS acct,
         (CASE WHEN g % 20 = 1 THEN g - 1 ELSE g END) AS tx
  FROM (SELECT g, g % 10 AS m, CASE WHEN g % 10 < 7 THEN 0 WHEN g % 10 = 7 THEN 1 ELSE 2 END AS ci
        FROM generate_series({lo}::bigint, {hi}::bigint - 1) AS g) s0
) s"""

TOKEN_ARRAY = "(ARRAY[" + ", ".join(f"'{t}'" for t in TOKENS) + "])[1 + g % 4]"


def h64(prefix, expr):
    return f"'0x' || md5('{prefix}:' || {expr}) || md5('{prefix}2:' || {expr})"


DEPOSIT_COLUMNS = {
    "id": "cid || '-' || loc",
    "chain_id": "cid",
    "chain_index": "ci",
    "deposit_index": "loc",
    "chain_local_deposit_index": "loc",
    "shield_address": h64("shield", "acct"),
    "token": TOKEN_ARRAY,
    "l2_token_contract_id": "'0x' || lpad(to_hex(1 + g % 4), 64, '0')",
    "amount": "((g % 1000000) + 1)::numeric * 1000000000000",
    "note_commitment": h64("note", "g"),
    "leaf_hash": h64("leaf", "g"),
    "block_number": "1000000 + loc / 2",
    "block_timestamp": "(1700000000 + (1000000 + loc / 2) * 12)::numeric",
    "tx_hash": h64("tx", "tx"),
}
LEAF_COLUMNS = {
    "id": "ci || '-' || loc",
    "chain_index": "ci",
    "chain_local_deposit_index": "loc",
    "deposit_index": "loc",
    "chain_id": "cid",
    "poseidon_leaf_hash": h64("pleaf", "g"),
    "block_number": "1000000 + loc / 2",
}
CLAIM_COLUMNS = {
    "id": "cid || '-' || nullifier",
    "chain_id": "cid",
    "nullifier": "nullifier",
    "recipient": "'0x' || substr(md5('rcpt:' || (g % 100000)), 1, 40)",
    "token": TOKEN_ARRAY,
    "amount": "((g % 1000) + 1)::numeric * 1000000000000",
    "block_number": "2000000 + g / 3",
    "tx_hash": h64("ctx", "g"),
}
# Finalized batches: three consecutive g share a block number (across chains),
# so the (block_number, id) cursor of follow_batches crosses equal blocks.
BATCH_COLUMNS = {
    "id": "cid || '-' || g",
    "chain_id": "cid",
    "finalized_checkpoint_id": "(g / 10)::numeric",
    "deposit_tree_root": h64("droot", "g"),
    "withdrawal_tree_root": h64("wroot", "g"),
    "block_number": "3000000 + g / 3",
    "tx_hash": h64("btx", "g"),
}
BATCH_ROW_SQL = """(
  SELECT g, (CASE WHEN g % 10 < 7 THEN 11155111 WHEN g % 10 = 7 THEN 97 ELSE 84532 END) AS cid
  FROM generate_series({lo}::bigint, {hi}::bigint - 1) AS g
) s"""


def batch_count(rows):
    return rows // 10 // 10 * 10


CLAIM_ROW_SQL = """(
  SELECT g, ci, (CASE ci WHEN 0 THEN 11155111 WHEN 1 THEN 97 ELSE 84532 END) AS cid,
         {nullifier} AS nullifier
  FROM (SELECT g, CASE WHEN g % 10 < 7 THEN 0 WHEN g % 10 = 7 THEN 1 ELSE 2 END AS ci
        FROM generate_series({{lo}}::bigint, {{hi}}::bigint - 1) AS g) s0
) s""".format(nullifier=h64("null", "g"))


# ── PostgreSQL access through psql ───────────────────────────────────────────

class Pg:
    def __init__(self, host, port, user, password, database, schema):
        self.host, self.port, self.user, self.password = host, str(port), user, password
        self.database, self.schema = database, schema

    def env(self):
        return {**os.environ, "PGHOST": self.host, "PGPORT": self.port, "PGUSER": self.user,
                "PGPASSWORD": self.password, "PGOPTIONS": "-c client_min_messages=warning"}

    def run(self, sql, database=None, search_path=True):
        prefix = f'SET search_path = "{self.schema}";\n' if search_path else ""
        result = subprocess.run(
            ["psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-d", database or self.database, "-f", "-"],
            input=prefix + sql, text=True, capture_output=True, env=self.env())
        if result.returncode != 0:
            raise RuntimeError(f"psql failed: {result.stderr.strip()}\n--- SQL ---\n{sql[:2000]}")
        return result.stdout

    def scalar(self, sql):
        return self.run(sql).strip()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_container(args):
    name = f"envio-plan-test-{os.getpid()}"
    port = free_port()
    password = "plan-test"
    command = ["docker", "run", "-d", "--name", name, "--shm-size", "4g",
               "-e", f"POSTGRES_PASSWORD={password}", "-p", f"127.0.0.1:{port}:5432"]
    if args.cpus:
        command += ["--cpus", str(args.cpus)]
    command += [args.image]
    for setting in DOCKER_SETTINGS:
        command += ["-c", setting]
    subprocess.run(command, check=True, capture_output=True)
    pg = Pg("127.0.0.1", port, "postgres", password, "postgres", args.schema)
    deadline = time.time() + 60
    while True:
        try:
            pg.run("SELECT 1", search_path=False)
            break
        except RuntimeError:
            if time.time() > deadline:
                stop_container(name)
                raise
            time.sleep(1)
    return name, pg


def stop_container(name):
    subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True)


# ── Schema initialization through Envio ──────────────────────────────────────

def schema_declared_indexes():
    """Index names Envio 2.32.10 derives from schema.graphql (<table>_<fields>)."""
    text = (ENVIO_DIR / "schema.graphql").read_text()
    names = set()
    for match in re.finditer(r"type\s+(\w+)\s+@entity(.*?)\{(.*?)\n\}", text, re.S):
        table, directives, body = match.groups()
        for fields in re.findall(r"@index\(fields:\s*\[([^\]]*)\]\)", directives):
            names.add(table + "_" + "_".join(re.findall(r'"(\w+)"', fields)))
        for line in body.splitlines():
            field = re.match(r"\s*(\w+)\s*:.*@index\b", line.split("#", 1)[0])
            if field:
                names.add(f"{table}_{field.group(1)}")
    return names


def envio_initialize(pg):
    migrations = ENVIO_DIR / "generated/src/db/Migrations.res.js"
    if not migrations.exists():
        raise SystemExit("generated/ is missing: run `pnpm codegen` in the Envio directory first")
    env = {**os.environ, "ENVIO_PG_HOST": pg.host, "ENVIO_PG_PORT": pg.port, "ENVIO_PG_USER": pg.user,
           "ENVIO_PG_PASSWORD": pg.password, "ENVIO_PG_DATABASE": pg.database,
           "ENVIO_PG_PUBLIC_SCHEMA": pg.schema, "ENVIO_HASURA": "false", "LOG_LEVEL": "warn"}
    subprocess.run(["node", "-e", f"require({json.dumps(str(migrations))}).runUpMigrations(true, true)"],
                   cwd=ENVIO_DIR, env=env, check=True, capture_output=True, text=True)


def catalog_indexes(pg):
    rows = pg.run(f"""
SELECT c.relname, i.relname, pg_get_indexdef(x.indexrelid), coalesce(con.conname, ''),
       coalesce(pg_get_constraintdef(con.oid), '')
FROM pg_index x
JOIN pg_class i ON i.oid = x.indexrelid
JOIN pg_class c ON c.oid = x.indrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_constraint con ON con.conindid = x.indexrelid AND con.contype = 'p'
WHERE n.nspname = '{pg.schema}' AND c.relname NOT LIKE 'envio\\_%' AND c.relkind = 'r'
ORDER BY 1, 2""")
    return [tuple(line.split("|")) for line in rows.splitlines() if line]


def entity_tables(pg):
    rows = pg.run(f"SELECT tablename FROM pg_tables WHERE schemaname = '{pg.schema}' ORDER BY 1")
    return {line for line in rows.splitlines() if line}


def columns(pg, table):
    rows = pg.run(f"""SELECT column_name FROM information_schema.columns
WHERE table_schema = '{pg.schema}' AND table_name = '{table}' ORDER BY ordinal_position""")
    return [line for line in rows.splitlines() if line]


def insert_sql(pg, table, mapping, source):
    cols = columns(pg, table)
    unknown = [c for c in cols if c not in mapping]
    if unknown:
        raise SystemExit(f"{table} has columns the generator does not know: {unknown}; update run_plan_test.py")
    names = ", ".join(f'"{c}"' for c in cols)
    exprs = ", ".join(mapping[c] for c in cols)
    return f'INSERT INTO "{table}" ({names}) SELECT {exprs} FROM {source};'


# ── Load ─────────────────────────────────────────────────────────────────────

def parallel(jobs, statements, label):
    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for future in concurrent.futures.as_completed([pool.submit(fn) for fn in statements]):
            future.result()
    print(f"  {label}: {time.time() - started:.1f}s", flush=True)


def load(pg, rows, jobs, index_jobs):
    claims = rows // 3 // 10 * 10
    batches = batch_count(rows)
    accounts = max(rows // 4, 1)
    indexes = [ix for ix in catalog_indexes(pg) if ix[0] in LOADED and ix[0] != "DepositTreeMeta"]
    for table, name, _, constraint, _ in indexes:
        if constraint:
            pg.run(f'ALTER TABLE "{table}" DROP CONSTRAINT "{constraint}";')
        else:
            pg.run(f'DROP INDEX "{name}";')

    chunk = 1_000_000
    deposit = insert_sql(pg, "Deposit", DEPOSIT_COLUMNS, ROW_SQL)
    leaf = insert_sql(pg, "DepositLeaf", LEAF_COLUMNS, ROW_SQL)
    claim = insert_sql(pg, "WithdrawalClaim", CLAIM_COLUMNS, CLAIM_ROW_SQL)
    batch = insert_sql(pg, "FinalizedBatch", BATCH_COLUMNS, BATCH_ROW_SQL)

    def chunks(total, template):
        out = []
        for lo in range(0, total, chunk):
            hi = min(lo + chunk, total)
            sql = template.format(lo=lo, hi=hi, whales=WHALES, mult=HASH_MULTIPLIER, accounts=accounts)
            out.append(lambda sql=sql: pg.run(sql))
        return out

    parallel(jobs, chunks(rows, deposit) + chunks(rows, leaf) + chunks(claims, claim)
             + chunks(batches, batch),
             f"insert {rows:,} deposits, {rows:,} leaves, {claims:,} claims, {batches:,} batches")

    started = time.time()
    pg.run("""SET work_mem = '4GB'; SET max_parallel_workers_per_gather = 8;
INSERT INTO "AccountDepositStats"
  (chain_id, chain_index, deposit_count, id, last_block_number, last_chain_local_deposit_index, shield_address)
SELECT chain_id, chain_index, count(*), chain_index || '-' || shield_address, max(block_number),
       max(chain_local_deposit_index), shield_address
FROM "Deposit" GROUP BY shield_address, chain_index, chain_id;""")
    print(f"  derive AccountDepositStats: {time.time() - started:.1f}s", flush=True)

    meta_values = []
    for index, chain_id, share in CHAINS:
        count = rows // 10 * share
        meta_values.append(
            f"({1000000 + (count - 1) // 2}, {index}, '0x00', '0x00', '{index}', {count}, 0, '0x00', '0x00')")
    pg.run('INSERT INTO "DepositTreeMeta" (block_number, chain_index, deposit_tree_root, '
           'finalized_keccak_deposit_tree_root, id, last_count, last_finalized_checkpoint_id, '
           'poseidon_deposit_tree_root, tx_hash) VALUES ' + ", ".join(meta_values) + ";")

    def rebuild(table, name, definition, constraint, constraint_def):
        sql = "SET maintenance_work_mem = '2GB'; SET max_parallel_maintenance_workers = 4;\n"
        if constraint:
            sql += f'ALTER TABLE "{table}" ADD CONSTRAINT "{constraint}" {constraint_def};'
        else:
            sql += definition + ";"
        pg.run(sql)

    parallel(index_jobs, [lambda ix=ix: rebuild(*ix) for ix in indexes], f"rebuild {len(indexes)} indexes")
    parallel(jobs, [lambda t=t: pg.run(f'VACUUM (ANALYZE) "{t}";') for t in LOADED], "vacuum analyze")
    after = [ix for ix in catalog_indexes(pg) if ix[0] in LOADED and ix[0] != "DepositTreeMeta"]
    if sorted(after) != sorted(indexes):
        raise SystemExit(f"rebuilt indexes differ from Envio's definitions:\n{indexes}\n{after}")
    return claims, accounts


# ── Query shapes ─────────────────────────────────────────────────────────────

def parse_queries():
    shapes = []
    for block in re.split(r"^(?=-- name:)", QUERIES_PATH.read_text(), flags=re.M)[1:]:
        meta = dict(re.findall(r"^-- (\w+):[ \t]*(.*)$", block, re.M))
        sql = "\n".join(line for line in block.splitlines() if not line.startswith("--")).strip()
        shapes.append({
            "name": meta["name"].strip(),
            "class": meta["class"].strip(),
            "params": [p.strip() for p in meta.get("params", "").split(",") if p.strip()],
            "indexes": [p.strip() for p in meta.get("index", "").split(",") if p.strip()],
            "max_buffers": int(meta["max_buffers"]),
            "gate": meta["gate"].strip() == "yes",
            "sql": sql.rstrip(";"),
        })
    return shapes


def literal(value):
    if isinstance(value, list):
        return "ARRAY[" + ", ".join(literal(v) for v in value) + "]::text[]"
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    return str(value)


def cases(rows, claims, accounts):
    """Parameters per shape and the expected result (row count, first value)."""
    count0 = rows // 10 * 7
    light_g = rows // 2 + 3
    light = hex64("shield", account_of(light_g, accounts))
    whale = hex64("shield", 0)
    whale_count = len(range(0, rows, 250))
    tx_g = rows // 2 + 1
    tx_rows = [g for g in (tx_g - 1, tx_g) if chain_of(g) == chain_of(tx_g)]
    nullifiers = [hex64("null", c) for c in range(claims // 2, claims) if c % 10 < 7][:100]
    missing = [hex64("missing", n) for n in range(5)]
    mid_block = (count0 // 2) // 1024 * 1024
    head_block = count0 // 1024 * 1024
    follow_limit = 1000
    claim_g = next(g for g in range(claims // 3, claims) if g % 10 < 7)
    claim_cursor = [CHAIN_ID[0], 2000000 + claim_g // 3, f"{CHAIN_ID[0]}-{hex64('null', claim_g)}", follow_limit]
    batch_g = next(g for g in range(batch_count(rows) // 3, batch_count(rows)) if g % 10 < 7)
    batch_cursor = [CHAIN_ID[0], 3000000 + batch_g // 3, f"{CHAIN_ID[0]}-{batch_g}", follow_limit]
    out = {
        "deposit_list_page": [
            ("light", [light, 0, CHAIN_ID[0]], (AT_LEAST_ONE, "11155111")),
            ("whale", [whale, 0, CHAIN_ID[0]], (min(100, whale_count), "11155111")),
        ],
        "deposit_list_next_page": [
            ("whale_mid", [whale, 0, CHAIN_ID[0], 175 * (whale_count // 2)], (min(100, whale_count // 2 - 1), None)),
        ],
        "deposit_list_offset_page": [
            ("whale_offset", [whale, 0, CHAIN_ID[0], max(0, min(5000, whale_count - 100))], (100, None)),
        ],
        "account_deposit_stats": [
            ("light", [f"0-{light}"], (1, None)),
            ("whale", [f"0-{whale}"], (1, str(whale_count))),
        ],
        "deposit_by_deposit_index": [
            ("near_head", [0, CHAIN_ID[0], count0 - 10], (1, "11155111")),
            ("bsc_mid", [1, CHAIN_ID[1], rows // 10 // 2], (1, "97")),
        ],
        "global_to_local_probe": [
            ("near_head", [0, CHAIN_ID[0], count0 - 5], (1, str(count0 - 5))),
            ("middle", [0, CHAIN_ID[0], count0 // 2], (1, str(count0 // 2))),
        ],
        "foreign_prefix_probe": [("head", [0, CHAIN_ID[0], count0], (1, "f"))],
        "deposit_by_tx_hash": [("two_deposit_tx", [hex64("tx", tx_of(tx_g)), chain_of(tx_g)], (len(tx_rows), None))],
        "leaf_range_1024": [("middle_block", [0, mid_block], (1024, str(mid_block)))],
        "leaf_stream_page": [("from_third", [0, count0 // 3], (10000, str(count0 // 3)))],
        "withdrawal_claims_by_nullifier": [("page_100", [CHAIN_ID[0], nullifiers + missing], (len(nullifiers), None))],
        "watermark": [("chain0", [0], (1, str(count0)))],
        "explorer_latest_deposits": [("chain0", [0], (100, "11155111"))],
        "explorer_feed_current": [("chain0", [CHAIN_ID[0]], (100, "11155111"))],
        "follow_deposits": [("from_third", [0, count0 // 3, follow_limit], (follow_limit, None))],
        "follow_leaves": [("from_third", [0, count0 // 3, follow_limit], (follow_limit, str(count0 // 3)))],
        "follow_claims": [("from_third", claim_cursor, (follow_limit, None))],
        "follow_batches": [("from_third", batch_cursor, (AT_LEAST_ONE, None))],
        "tree_meta_all": [("all_chains", [], (len(CHAINS), "0"))],
        "chain_progress": [("all_chains", [], None)],
        "envio_identity": [("one_row", [], (1, None))],
    }
    if count0 % 1024:
        out["leaf_range_1024"].append(("head_partial_block", [0, head_block], (count0 - head_block, str(head_block))))
    return out


def plan_nodes(plan):
    yield plan
    for child in plan.get("Plans", []):
        yield from plan_nodes(child)


def explain(pg, shape, params, mode):
    types = ", ".join(shape["params"])
    args = ", ".join(literal(p) for p in params)
    declared = f"({types})" if types else ""   # PREPARE and EXECUTE take no empty parentheses
    called = f"({args})" if args else ""
    prepare = f"SET plan_cache_mode = {mode};\nPREPARE q{declared} AS {shape['sql']};\n"
    explain_sql = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE q{called};\n"
    out = pg.run(prepare + explain_sql * (REPEATS + 1))
    decoder, pos, plans = json.JSONDecoder(), 0, []
    while pos < len(out):
        if out[pos].isspace():
            pos += 1
            continue
        value, pos = decoder.raw_decode(out, pos)
        plans.append(value[0])
    plans = plans[1:]  # first run warms the cache
    rows = pg.run(prepare + f"EXECUTE q{called};\n").splitlines()
    return plans, rows


def check(shape, case, plans, rows, expected):
    root = plans[-1]["Plan"]
    nodes = list(plan_nodes(root))
    seq = sorted({n.get("Relation Name") for n in nodes if n["Node Type"] == "Seq Scan"})
    used = sorted({n["Index Name"] for n in nodes if "Index Name" in n})
    buffers = max(p["Plan"].get("Shared Hit Blocks", 0) + p["Plan"].get("Shared Read Blocks", 0) for p in plans)
    problems = []
    bad_seq = [t for t in seq if t not in SEQ_SCAN_ALLOWED]
    if bad_seq:
        problems.append(f"Seq Scan on {bad_seq}")
    missing = [ix for ix in shape["indexes"] if ix not in used]
    if missing:
        problems.append(f"expected index not used: {missing}")
    if shape["max_buffers"] and buffers > shape["max_buffers"]:
        problems.append(f"{buffers} buffers > {shape['max_buffers']}")
    if expected is not None:
        count, first = expected
        if count == AT_LEAST_ONE and not rows:
            problems.append("no rows, expected at least one")
        elif count != AT_LEAST_ONE and len(rows) != count:
            problems.append(f"{len(rows)} rows, expected {count}")
        elif first is not None and rows and rows[0].split("|")[0] != first:
            problems.append(f"first value {rows[0].split('|')[0]}, expected {first}")
    times = [p["Execution Time"] for p in plans]
    return {
        "shape": shape["name"], "case": case, "class": shape["class"], "gate": shape["gate"],
        "plan_root": root["Node Type"], "indexes": used, "seq_scans": seq, "buffers": buffers,
        "rows": len(rows), "exec_ms_median": round(statistics.median(times), 3),
        "exec_ms_max": round(max(times), 3),
        "plan_ms_median": round(statistics.median(p.get("Planning Time", 0) for p in plans), 3),
        "problems": problems,
    }


def run_shapes(pg, rows, claims, accounts):
    results = []
    all_cases = cases(rows, claims, accounts)
    for shape in parse_queries():
        if shape["name"] not in all_cases:
            raise SystemExit(f"no cases defined for shape {shape['name']}")
        for case, params, expected in all_cases[shape["name"]]:
            for mode in ("force_custom_plan", "force_generic_plan"):
                plans, out = explain(pg, shape, params, mode)
                result = check(shape, case, plans, out, expected)
                result["plan_mode"] = "custom" if mode == "force_custom_plan" else "generic"
                results.append(result)
    return results


def sizes(pg):
    out = pg.run(f"""SELECT c.relname, c.reltuples::bigint, pg_relation_size(c.oid), pg_indexes_size(c.oid)
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = '{pg.schema}' AND c.relname IN ({", ".join(f"'{t}'" for t in LOADED)}) ORDER BY 1""")
    return {line.split("|")[0]: {"rows": int(line.split("|")[1]), "heap_bytes": int(line.split("|")[2]),
                                 "index_bytes": int(line.split("|")[3])}
            for line in out.splitlines() if line}


def btree_levels(pg):
    """Height of every B-tree on the loaded tables (pageinspect), when available."""
    try:
        pg.run("CREATE EXTENSION IF NOT EXISTS pageinspect SCHEMA public;")
        out = pg.run(f"""SELECT s.indexrelname,
       (public.bt_metap(quote_ident(s.schemaname) || '.' || quote_ident(s.indexrelname))).level
FROM pg_stat_user_indexes s
WHERE s.schemaname = '{pg.schema}' AND s.relname IN ({", ".join(f"'{t}'" for t in LOADED)}) ORDER BY 1""")
    except RuntimeError as error:
        return {"unavailable": str(error).splitlines()[0]}
    return {line.split("|")[0]: int(line.split("|")[1]) for line in out.splitlines() if line}


def print_table(scale, results):
    print(f"\n### {scale:,} deposits\n")
    print("| shape | case | plan | gate | root / indexes | buffers | rows | median ms | max ms | result |")
    print("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in results:
        status = "ok" if not r["problems"] else ("FAIL: " if r["gate"] else "report: ") + "; ".join(r["problems"])
        where = r["plan_root"] + (" / " + ", ".join(r["indexes"]) if r["indexes"] else "")
        if r["seq_scans"]:
            where += " / Seq Scan " + ", ".join(r["seq_scans"])
        print(f"| {r['shape']} | {r['case']} | {r['plan_mode']} | {'yes' if r['gate'] else 'report'} | {where} "
              f"| {r['buffers']} | {r['rows']} | {r['exec_ms_median']} | {r['exec_ms_max']} | {status} |")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rows", type=int, action="append", required=True,
                        help="deposit count of one scale (multiple of 1000); repeat for several scales")
    parser.add_argument("--docker", action="store_true", help="run a throwaway postgres container")
    parser.add_argument("--image", default="postgres:16.13")
    parser.add_argument("--cpus", type=float, default=None, help="docker --cpus limit")
    parser.add_argument("--keep", action="store_true", help="keep the container after the run")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--password", default=os.environ.get("PGPASSWORD", ""))
    parser.add_argument("--database", default=f"envio_plan_test_{os.getpid()}",
                        help="must not exist; created for the run and dropped afterwards")
    parser.add_argument("--schema", default="envio")
    parser.add_argument("--jobs", type=int, default=min(16, os.cpu_count() or 4), help="parallel load sessions")
    parser.add_argument("--index-jobs", type=int, default=3,
                        help="indexes rebuilt at once (each sort may spill its size to temp files)")
    parser.add_argument("--disk-path", default="/", help="filesystem holding the database, for the space check")
    parser.add_argument("--bytes-per-deposit", type=int, default=1500,
                        help="space estimate per deposit including leaves, claims, stats and indexes")
    parser.add_argument("--min-free-gb", type=float, default=40)
    parser.add_argument("--report", type=Path, help="write the JSON report here")
    args = parser.parse_args()
    if any(r % 1000 or r < 10000 for r in args.rows):
        parser.error("--rows must be multiples of 1000 and at least 10000 (the probe cases assume it)")
    if not args.docker and not args.host:
        parser.error("either --docker or --host is required")
    for tool in ["psql", "node"] + (["docker"] if args.docker else []):
        if not shutil.which(tool):
            parser.error(f"{tool} not found")

    container = None
    admin = None
    db_created = False
    report = {"settings": {}, "scales": []}
    failed = False
    try:
        if args.docker:
            container, admin = start_container(args)
        else:
            admin = Pg(args.host, args.port, args.user, args.password, "postgres", args.schema)
        # CREATE fails if the database exists, so an existing one is never touched.
        admin.run(f'CREATE DATABASE "{args.database}";', search_path=False)
        db_created = True
        pg = Pg(admin.host, admin.port, admin.user, admin.password, args.database, args.schema)
        report["settings"] = {
            "version": pg.scalar("SELECT version()"),
            "non_default": pg.run("SELECT name || '=' || setting FROM pg_settings "
                                  "WHERE source NOT IN ('default', 'override') ORDER BY 1").split(),
        }
        for rows in args.rows:
            print(f"scale {rows:,}: initializing schema with Envio", flush=True)
            envio_initialize(pg)  # drops the previous scale's schema first
            try:
                pg.run("CHECKPOINT;", search_path=False)  # release dropped files before the space check
            except RuntimeError:
                pass  # needs superuser or pg_checkpoint; the check is then only more conservative
            free_gb = shutil.disk_usage(args.disk_path).free / 2**30
            need_gb = rows * args.bytes_per_deposit / 2**30
            if free_gb - need_gb < args.min_free_gb:
                raise SystemExit(f"{rows:,} deposits need ~{need_gb:.0f} GiB; {free_gb:.0f} GiB free "
                                 f"would leave less than --min-free-gb {args.min_free_gb}")
            tables = entity_tables(pg)
            for table in LOADED:
                if table not in tables:
                    raise SystemExit(f"Envio did not create {table}: is generated/ from this schema.graphql?")
            declared = schema_declared_indexes()
            created = {ix[1] for ix in catalog_indexes(pg) if not ix[3]}
            if declared != created:
                raise SystemExit(f"generated/ is stale: schema declares {sorted(declared)}, "
                                 f"Envio created {sorted(created)}; run `pnpm codegen`")
            started = time.time()
            claims, accounts = load(pg, rows, args.jobs, args.index_jobs)
            load_s = time.time() - started
            results = run_shapes(pg, rows, claims, accounts)
            scale = {"deposits": rows, "claims": claims, "accounts": accounts, "load_seconds": round(load_s),
                     "sizes": sizes(pg), "btree_levels": btree_levels(pg), "results": results}
            report["scales"].append(scale)
            print_table(rows, results)
            print("\nsizes:", json.dumps(scale["sizes"]))
            print("btree levels:", json.dumps(scale["btree_levels"]))
            failed |= any(r["problems"] for r in results if r["gate"])
    finally:
        if db_created and not container:
            admin.run(f'DROP DATABASE IF EXISTS "{args.database}" WITH (FORCE);', search_path=False)
        if container and not args.keep:
            stop_container(container)
        elif container:
            print(f"kept container {container}")
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(f"report: {args.report}")
    print("\nPLAN TEST " + ("FAILED" if failed else "PASSED"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
