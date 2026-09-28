#!/usr/bin/env python3
"""Pinned Envio 2.32.10 history fix; no database/config/network operations."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tempfile

ORIGINAL = {
    "res": "524c8acdb1920b1de7bc24deedbf62af823b3f334dcac4d1e8650b563a2c87e2",
    "js": "993b094b64e1f2178c54a03722bd53e1cae8a5983562ab18573655e8f462a412",
}
# Conversion stays entirely inside PostgreSQL: NUMERIC never passes through a
# JavaScript Number. The named composite has exactly the history table's order.
# This preserves the public API used by generated IO and works for every entity.
QUERY_JS = r'''function (pgSchema, entityName, historyName) {
  function quote(name) { return '"' + name.replace(/"/g, '""') + '"'; }
  var history = quote(pgSchema) + '.' + quote(historyName);
  var entity = quote(pgSchema) + '.' + quote(entityName);
  return [
    'WITH target_ids AS (SELECT DISTINCT UNNEST($1::TEXT[]) AS id),',
    'missing_history AS (',
    '  SELECT e.* FROM ' + entity + ' e',
    '  JOIN target_ids t ON e.id = t.id',
    '  LEFT JOIN ' + history + ' h ON h.id = e.id',
    '  WHERE h.id IS NULL',
    ')',
    'INSERT INTO ' + history,
    'SELECT mapped.* FROM missing_history e',
    'CROSS JOIN LATERAL jsonb_populate_record(NULL::' + history + ',',
    "  to_jsonb(e) || jsonb_build_object('checkpoint_id', 0, 'envio_change', 'SET')) mapped;"
  ].join('\n');
}'''


def replacement(kind):
    if kind == "res":
        return ("// PSY_HISTORY_BACKFILL_BY_NAME_V1\n"
                "let psyHistoryBackfillQuery: (string, string, string) => string = %raw(`"
                + QUERY_JS + "`)\n\n"
                "let makeBackfillHistoryQuery = (~pgSchema, ~entityName, ~entityIndex) => {\n"
                "  psyHistoryBackfillQuery(pgSchema, entityName, historyTableName(~entityName, ~entityIndex))\n"
                "}\n\n")
    return ("// PSY_HISTORY_BACKFILL_BY_NAME_V1\nvar psyHistoryBackfillQuery = "
            + QUERY_JS + ";\n\n"
            "function makeBackfillHistoryQuery(pgSchema, entityName, entityIndex) {\n"
            "  return psyHistoryBackfillQuery(pgSchema, entityName, historyTableName(entityName, entityIndex));\n"
            "}\n\n")


def verify(text, kind):
    if QUERY_JS not in text:
        raise RuntimeError("History query implementation absent or changed")
    if kind == "res":
        if replacement(kind) not in text:
            raise RuntimeError("History query source call changed")
    elif not re.search(
        r"function makeBackfillHistoryQuery\(pgSchema, entityName, entityIndex\)\s*\{\s*"
        r"return psyHistoryBackfillQuery\(pgSchema, entityName, historyTableName\(entityName, entityIndex\)\);\s*\}",
        text,
    ):
        raise RuntimeError("History runtime does not call the corrected query")


def transform(text, kind):
    if "psyHistoryBackfillQuery" in text:
        verify(text, kind)
        return text
    if hashlib.sha256(text.encode()).hexdigest() != ORIGINAL[kind]:
        raise RuntimeError("Unknown EntityHistory source; review instead of overwriting")
    prefix = "let " if kind == "res" else "function "
    start = text.index(prefix + "makeBackfillHistoryQuery")
    end = text.index(prefix + "backfillHistory", start)
    result = text[:start] + replacement(kind) + text[end:]
    verify(result, kind)
    return result


def patch(home, check=False):
    packages = {p.resolve() for p in (
        home / "node_modules/envio", home / "generated/node_modules/envio"
    ) if p.exists()}
    if not packages:
        raise RuntimeError("Installed Envio missing; refusing silent skip")
    changes = []
    for package in sorted(packages):
        if json.loads((package / "package.json").read_text())["version"].lstrip("v") != "2.32.10":
            raise RuntimeError("Unsupported Envio version; review required")
        for kind, filename in (("res", "EntityHistory.res"), ("js", "EntityHistory.res.js")):
            path = package / "src/db" / filename
            old = path.read_text()
            if check:
                verify(old, kind)
                new = old
            else:
                new = transform(old, kind)
            changes.append((path, old, new))
    # Validate every package before writing. Replace, never mutate pnpm hardlinks.
    for path, old, new in changes:
        if old != new:
            with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as f:
                temp = Path(f.name)
                f.write(new)
            try:
                temp.chmod(path.stat().st_mode & 0o777)
                temp.replace(path)
            finally:
                temp.unlink(missing_ok=True)
    return [{"path": str(p), "sha256": hashlib.sha256(n.encode()).hexdigest()}
            for p, _, n in changes]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    print(json.dumps({"verified": True, "files": patch(args.home, args.check)}))
