#!/usr/bin/env python3
"""Provider certification probe for candidate L1 RPC providers.

Certifies candidate RPC endpoints for the psy-node bridge relayer before
rollout. Standard library only -- no third-party dependencies.

Input is a JSON file describing chains and candidates:

    {"chains": {"<name>": {"chain_id": 1, "bridge": "0x..",
                            "state_manager": "0x..", "start_block": 1}},
     "candidates": [{"chain": "<name>", "provider": "<label>",
                      "url_env": "ENV_VAR_NAME"}]}

A candidate normally names the environment variable holding its URL
(`url_env`), so the input file itself never contains a URL or secret. A
public, keyless endpoint may instead be written directly as a literal
`url` field (no environment lookup needed). `--env-file PATH` loads
`KEY=VALUE` lines into the lookup before candidates are resolved; an
already-set environment variable takes precedence over the file (dotenv
override=False convention).

The input is validated up front (`validate_spec`): a missing/malformed
chain field or a candidate referencing an unknown chain exits with
status 2 and a clear message, rather than crashing mid-run.

For each chain, a lightweight head pass (`eth_chainId` + `eth_blockNumber`
only) runs against every resolvable candidate first. The chain's
full-history scan then uses one shared end block for every candidate on
that chain -- `min(head among candidates that reported the correct
chain id) - confirmations` (default 12 blocks, `--confirmations`) --
instead of each candidate's own head taken at a different wall-clock
moment. Comparing deposit counts across candidates would otherwise be
unreliable simply because their heads were sampled a block or two apart.

Per candidate this then runs the checks from the session probe
prototype:
  - eth_chainId matches the configured chain id;
  - eth_blockNumber head (own head is still recorded, plus its lag
    behind the chain's max observed head);
  - largest successful eth_getLogs span on DepositRecorded near the
    candidate's own head, among 50000/10000/5000/1000/100/10 blocks;
  - eth_call of selector 0x7cd34bf4 on the StateManager, plus
    eth_getCode on the same address (an empty "0x" result means the
    address is wrong for this chain, not that the call itself failed);
  - eth_sendRawTransaction("0x00"), where a decode error counts as
    served, even when it arrives as an HTTP 4xx with a JSON-RPC error
    body rather than a 200 with a JSON-RPC error;
  - a full-history scan from start_block to the chain's shared,
    confirmed scan-end block in fixed 50000-block chunks, counting
    DepositRecorded logs (this is what the relayer's fixed-size
    chunking needs the provider to sustain -- deliberately NOT
    adaptive). Stops early after 3 consecutive chunk failures (the
    verdict is already REJECTED at that point); per-chunk progress
    (host + block range only) goes to stderr;
  - a receipt lookup for the last deposit tx found anywhere. A skipped
    receipt check is always visible in the `receipt` field
    ("skipped: no deposit tx"), never silently omitted.

One JSON line is printed per candidate (stdout) as it completes. At the
end a plain-text summary is printed per chain: the max deposit count
seen (candidates with the wrong chain id never count toward this max),
and each candidate marked:
  - CERTIFIED:  every check passed and its count equals the chain max;
  - INCOMPLETE: its count is lower, with no error (silent data loss);
  - REJECTED:   any check errored, or the chain id was wrong.
A chain whose max count is 0, or that has at most one non-REJECTED
candidate, gets an explicit `WARNING: ... certification is vacuous`
line -- there was nothing to compare the winner against.

Never prints a URL path, query, userinfo, or embedded key (secrets can
live in any of those); only the bare host is ever printed. Userinfo in a
candidate URL (`https://user:pass@host/...`) is stripped before the
request is built and sent as an `Authorization: Basic` header (user and
password percent-decoded first), so the resolver only ever sees the bare
host and basic-auth providers work. The header is not forwarded on a
redirect. Only `http` and `https` URLs are probed. Every error
string is scrubbed before being printed or stored: first of the
resolved URL's literal secret parts (userinfo, path, query, fragment,
and any path/query segment of 6+ characters, matched case-insensitively
so a key echoed back without its surrounding URL is still caught), then
of a host-based regex as a second layer (also case-insensitive, since
`urlparse` lowercases the host but an error message might not). Each
RPC call is capped at 40s.

Proxy environment variables (http_proxy, https_proxy, HTTP_PROXY,
HTTPS_PROXY) are ignored by default and every request goes directly to
the provider, because a proxy would receive the full candidate URL,
API key included. `--use-env-proxy` opts back in; the proxy then sees
full provider URLs, including API keys, plus any userinfo credentials
in the Authorization header (a warning is printed to stderr).

Exit status:
  0    every selected chain has at least one CERTIFIED candidate (or
       `--self-test` passed);
  1    `--chain` matched no candidates, any selected chain ends up with
       no CERTIFIED candidate, or `--self-test` failed;
  2    usage or input error, before any check runs: input spec fails
       validation, no input file argument, input file missing/unreadable/
       not UTF-8/not JSON, `--env-file` missing/a directory/unreadable/
       not UTF-8, or a negative `--confirmations` (argparse's own usage
       errors also exit 2);
  3    an unexpected internal error; only `ERROR: probe crashed: <Type>`
       is printed (the exception type name, never its message or a
       traceback, which could embed a URL);
  130  interrupted with Ctrl-C.
`--self-test` runs the scrubber, transport, and verdict logic against
canned data, using only mocks and a loopback HTTP server on 127.0.0.1.

Known bugs this probe guards against (found while prototyping / fix
rounds 1-4):
  - a JSON-RPC `error` field can be a bare string instead of an object;
  - some providers answer with HTTP 400/403/413 instead of a JSON-RPC
    error when a request (e.g. a too-large eth_getLogs range, or a
    deliberately-malformed raw tx) is rejected -- the HTTP error body
    (capped at 4096 bytes) is parsed for a JSON-RPC error before
    falling back to "HTTP {code}";
  - the old host-only scrub regex missed a mixed-case host, userinfo
    credentials, and a key echoed back without the host around it. The
    literal `user:pass@`/`user@` form is always redacted; the bare
    username/password strings are only redacted standalone when 4+
    characters, so a short one (e.g. "id") doesn't clobber ordinary text;
  - a missing input file, malformed JSON, a non-object top-level value,
    or a non-string `url`/`url_env` are all caught by `validate_spec()`
    (or the file/JSON read in `_run()`) and exit 2 with a clear message
    instead of an uncaught traceback;
  - a chain whose confirmed scan window ends up empty (`scan_end <
    start_block`, e.g. from a large `--confirmations` on a young chain)
    is flagged explicitly per candidate and in the summary, rather than
    silently reporting a deposit count of 0 that could look CERTIFIED;
  - a transport failure (timeout, connection reset, malformed URL) on
    eth_sendRawTransaction used to count as "served"; only a JSON-RPC
    error response that is not method-not-found/unsupported counts now;
  - a non-UTF-8 provider response body is recorded as an error for that
    check instead of losing the candidate.
"""
import argparse
import base64
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import unquote, urlparse, urlsplit, urlunsplit

TOPIC = "0xc6a707652dc6aea1d40642451dfaa5afbdf8ab6a176ebacd33dee14dc3ace472"
SM_SELECTOR = "0x7cd34bf4"  # StateManager read used by the relayer
SPAN_CANDIDATES = [50_000, 10_000, 5_000, 1_000, 100, 10]
SCAN_CHUNK = 50_000
TIMEOUT_S = 40
DEFAULT_CONFIRMATIONS = 12
MAX_CONSECUTIVE_SCAN_FAILURES = 3
RECEIPT_SKIPPED = "skipped: no deposit tx"
ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# A served-but-rejected eth_sendRawTransaction is a JSON-RPC error
# response carrying a decode/format error. A JSON-RPC error saying
# "method not found" (-32601) or not supported/available/allowed means
# the method itself is blocked. Transport failures are never a serve
# (see is_raw_tx_served()).
UNSERVED_METHOD_RE = re.compile(r"-32601|not (found|supported|available|allowed)", re.I)


# --------------------------------------------------------------------------
# env / url resolution
# --------------------------------------------------------------------------

def load_env_file(path):
    """Parse simple KEY=VALUE lines (optionally quoted). No shell semantics."""
    env = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            if key:
                env[key] = val
    return env


def build_env_lookup(env_file_path, base_env):
    """Merge an optional --env-file into base_env (normally os.environ).
    The existing environment always wins over a value from the file
    (dotenv override=False convention) -- the file only fills in names
    the environment doesn't already have."""
    merged = dict(load_env_file(env_file_path)) if env_file_path else {}
    merged.update(base_env)
    return merged


def resolve_candidate_url(candidate, env):
    """Returns (url, err). Exactly one of url/err is non-None."""
    literal = candidate.get("url")
    if literal:
        return literal, None
    env_name = candidate.get("url_env")
    if not env_name:
        return None, "candidate has neither 'url' nor 'url_env'"
    if env_name not in env or not env[env_name]:
        return None, f"env var {env_name} not set"
    return env[env_name], None


# --------------------------------------------------------------------------
# input validation
# --------------------------------------------------------------------------

def validate_spec(spec):
    """Returns a list of human-readable error strings; empty means valid.
    Checked up front so a malformed chain config or a candidate pointing
    at an unknown chain exits cleanly instead of crashing mid-run."""
    if not isinstance(spec, dict):
        return ["input: top-level JSON must be an object"]
    errors = []
    chains = spec.get("chains")
    candidates = spec.get("candidates")
    if not isinstance(chains, dict) or not chains:
        errors.append("input: 'chains' must be a non-empty object")
        chains = {}
    if not isinstance(candidates, list) or not candidates:
        errors.append("input: 'candidates' must be a non-empty array")
        candidates = []

    for name, cfg in chains.items():
        if not isinstance(cfg, dict):
            errors.append(f"chain {name!r}: config must be an object")
            continue
        for field in ("chain_id", "start_block"):
            if not isinstance(cfg.get(field), int) or isinstance(cfg.get(field), bool):
                errors.append(f"chain {name!r}: '{field}' must be an integer")
        for field in ("bridge", "state_manager"):
            val = cfg.get(field)
            if not isinstance(val, str) or not ADDR_RE.match(val):
                errors.append(f"chain {name!r}: '{field}' must be a 0x-prefixed 40-hex-char address")

    for i, cand in enumerate(candidates):
        if not isinstance(cand, dict):
            errors.append(f"candidates[{i}]: must be an object")
            continue
        provider_val = cand.get("provider")
        # A valid string 'provider' becomes the error label; anything else
        # (missing, or a non-string like a dict/list) falls back to the
        # index so f"{label!r}" formatting is always safe.
        label = provider_val if isinstance(provider_val, str) and provider_val else f"index {i}"
        if provider_val is not None and not isinstance(provider_val, str):
            errors.append(f"candidates[{i}]: 'provider' must be a string")
        elif not provider_val:
            errors.append(f"candidates[{i}]: missing 'provider'")

        chain_name = cand.get("chain")
        if chain_name is not None and not isinstance(chain_name, str):
            # 'chain_name not in chains' below would raise TypeError for an
            # unhashable value (e.g. a list or dict) -- check the type
            # first so a malformed 'chain' can never crash validation.
            errors.append(f"candidate {label!r}: 'chain' must be a string")
        elif not chain_name:
            errors.append(f"candidate {label!r}: missing 'chain'")
        elif chain_name not in chains:
            errors.append(f"candidate {label!r}: unknown chain {chain_name!r}")

        url_val = cand.get("url")
        url_env_val = cand.get("url_env")
        if url_val is not None and not isinstance(url_val, str):
            errors.append(f"candidate {label!r}: 'url' must be a string")
        if url_env_val is not None and not isinstance(url_env_val, str):
            errors.append(f"candidate {label!r}: 'url_env' must be a string")
        if not (isinstance(url_val, str) and url_val) and not (isinstance(url_env_val, str) and url_env_val):
            errors.append(f"candidate {label!r}: needs 'url' or 'url_env'")

    return errors


# --------------------------------------------------------------------------
# scrubbing
# --------------------------------------------------------------------------

def safe_host(url):
    """Best-effort hostname extraction that never raises. `urlparse(...)
    .hostname` can raise ValueError on a malformed URL (e.g. an
    unbalanced IPv6 literal like "http://[::1/..."); every place that
    needs a host for logging/output goes through this instead of calling
    urlparse() directly, so a bad candidate URL can never turn into an
    unhandled exception (and, with it, a leaked URL/key in a traceback)."""
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def _url_secret_parts(url):
    """Returns the secret-shaped literal substrings of url: the userinfo
    form, path, query, fragment, and every individual path/query segment
    of 6+ characters (long enough to plausibly be a key/token rather
    than a common word like "v2" or "rpc").

    The literal `user:pass@` / `user@` form is always included -- it's
    distinctive enough (anchored by the `@`) that stripping it doesn't
    clobber ordinary text, even when the username/password are short.
    The bare username and password strings are only added standalone
    when 4+ characters, so a short one (e.g. "id") doesn't get redacted
    out of unrelated text elsewhere in an error message."""
    try:
        p = urlparse(url)
    except ValueError:
        return set()
    parts = set()
    if p.username:
        userinfo = p.username if p.password is None else f"{p.username}:{p.password}"
        parts.add(f"{userinfo}@")
    # Both the raw (percent-encoded) and decoded forms: rpc() sends the
    # decoded credentials in an Authorization header, so an error echoing
    # them back would carry the decoded form.
    for cred in (p.username, p.password):
        if cred:
            for form in (cred, unquote(cred)):
                if len(form) >= 4:
                    parts.add(form)
    if p.path and p.path not in ("", "/"):
        parts.add(p.path)
    if p.query:
        parts.add(p.query)
    if p.fragment:
        parts.add(p.fragment)
    for seg in re.split(r"[/&=?;:]+", f"{p.path or ''} {p.query or ''}"):
        seg = seg.strip()
        if len(seg) >= 6:
            parts.add(seg)
    parts.discard("")
    return parts


def scrub(text, host, url=None):
    """Remove every secret-shaped part of `url` from text (literal,
    case-insensitive match: the full URL, userinfo, path, query,
    fragment, and long path/query segments), then fall back to a
    case-insensitive host-based regex as a second layer for anything
    the literal pass missed. Only the bare host is ever allowed through."""
    if text is None:
        return text
    replacement = host or "[redacted]"
    if url:
        text = re.sub(re.escape(url), replacement, text, flags=re.I)
        for part in sorted(_url_secret_parts(url), key=len, reverse=True):
            text = re.sub(re.escape(part), "[redacted]", text, flags=re.I)
    if host:
        text = re.sub(re.escape(host) + r"\S*", host, text, flags=re.I)
    return text


# --------------------------------------------------------------------------
# RPC transport
# --------------------------------------------------------------------------

def _parse_jsonrpc_error_body(body):
    """Best-effort parse of an HTTP error response body as a JSON-RPC
    error object. Returns a short formatted message, or None if the
    body isn't JSON-RPC shaped (never raises)."""
    if not body:
        return None
    try:
        data = json.loads(body)
    except (ValueError, TypeError, RecursionError):
        # ValueError covers JSONDecodeError and UnicodeDecodeError (a
        # non-UTF-8 body); RecursionError a pathologically nested one.
        return None
    if not isinstance(data, dict) or data.get("error") is None:
        return None
    e = data["error"]
    if isinstance(e, dict):
        return f"{e.get('code')} {str(e.get('message', ''))[:110]}"
    return str(e)[:110]


def _build_opener(use_env_proxy):
    """Direct connections by default: a ProxyHandler({}) ignores
    http_proxy/https_proxy/HTTP(S)_PROXY, because a proxy would receive
    the full candidate URL, API key included. `--use-env-proxy` opts back
    in to urllib's environment-proxy behavior. Redirect handling is
    urllib's default either way (the Authorization header is added as
    unredirected, so it is never forwarded -- see rpc_ex())."""
    if use_env_proxy:
        return urllib.request.build_opener()
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


# The transport rpc_ex() calls: `_OPEN(req, timeout=...)`. Replaced by
# set_proxy_mode(), and by the self-test with mocks.
_OPEN = _build_opener(False).open


def set_proxy_mode(use_env_proxy):
    global _OPEN
    _OPEN = _build_opener(use_env_proxy).open


def split_userinfo(url):
    """Returns (url_without_userinfo, authorization_header_or_None).

    urllib does not handle `https://user:pass@host/...` itself: it hands
    `user:pass@host` to the resolver as the host name (so the credentials
    could leave the machine as a DNS query) and never sends them, so a
    basic-auth provider would be falsely REJECTED. The userinfo is
    stripped from the URL here and turned into an `Authorization: Basic`
    header instead (user and password percent-decoded first, as RFC 3986
    requires). May raise ValueError on a malformed URL; rpc() calls it
    inside its own try."""
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url, None
    userinfo, _, hostport = parts.netloc.rpartition("@")
    user, sep, password = userinfo.partition(":")
    creds = f"{unquote(user)}:{unquote(password) if sep else ''}"
    token = base64.b64encode(creds.encode("utf-8")).decode("ascii")
    clean = urlunsplit((parts.scheme, hostport, parts.path, parts.query, parts.fragment))
    return clean, f"Basic {token}"


def rpc_ex(url, method, params, timeout=TIMEOUT_S):
    """Returns (result, err, elapsed_seconds, jsonrpc_error). err is a
    short unscrubbed string (caller is responsible for scrubbing before
    printing/storing). jsonrpc_error is True only when the provider
    answered with a parsed JSON-RPC error object (in an HTTP 200 body or
    an HTTP 4xx/5xx body); every transport failure (connection error,
    timeout, malformed URL, non-JSON body, bare HTTP status) is False."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    t0 = time.monotonic()
    try:
        # Request() itself can raise (e.g. ValueError("unknown url type: %r")
        # for a scheme-less URL, or an InvalidURL for a malformed IPv6
        # literal) -- and that error message embeds the full URL, including
        # any key in it. Building it inside this try means a malformed URL
        # is caught by the same handlers as a connection failure: the
        # generic Exception branch below returns only the exception TYPE
        # name, never str(e), so a URL/key can never escape this function.
        # Only http(s) is probed. Anything else is refused here, before
        # urllib's own "unknown url type: <scheme>" error can echo back
        # what it took for a scheme -- for a scheme-less `user:pass@host`
        # that would be the username.
        if urlsplit(url).scheme.lower() not in ("http", "https"):
            return None, "unsupported URL scheme (need http or https)", time.monotonic() - t0, False
        clean_url, auth = split_userinfo(url)
        req = urllib.request.Request(
            clean_url, body, {"Content-Type": "application/json", "User-Agent": "psy-rpc-probe/1"}
        )
        if auth:
            # Unredirected: urllib copies ordinary headers onto a redirect
            # to another host, but never unredirected ones, so the
            # credentials only ever go to the provider's own host.
            req.add_unredirected_header("Authorization", auth)
        with _OPEN(req, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        dt = time.monotonic() - t0
        # Some providers reject a request (an oversized eth_getLogs range,
        # a malformed raw tx) with an HTTP 4xx instead of a 200 carrying a
        # JSON-RPC error. Try to recover the JSON-RPC error from the body
        # (still capped to 110 chars, same as the 200 path) before falling
        # back to a bare "HTTP {code}".
        try:
            err_body = e.read(4096)
        except Exception:  # noqa: BLE001
            err_body = b""
        detail = _parse_jsonrpc_error_body(err_body)
        if detail:
            return None, f"HTTP {e.code}: {detail}", dt, True
        return None, f"HTTP {e.code}", dt, False
    except urllib.error.URLError as e:
        return None, f"URLError {e.reason}", time.monotonic() - t0, False
    except Exception as e:  # noqa: BLE001 -- never let one candidate crash the run
        return None, type(e).__name__, time.monotonic() - t0, False
    dt = time.monotonic() - t0
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        # ValueError covers JSONDecodeError and UnicodeDecodeError (a
        # non-UTF-8 body), so a garbage body is recorded as an error
        # instead of escaping and losing the candidate.
        return None, "invalid JSON response", dt, False
    if not isinstance(data, dict):
        return None, "unexpected response shape", dt, False
    if data.get("error") is not None:
        e = data["error"]
        if isinstance(e, dict):
            return None, f"{e.get('code')} {str(e.get('message', ''))[:110]}", dt, True
        # Seen in the wild: some providers put a bare string in `error`.
        return None, str(e)[:110], dt, True
    return data.get("result"), None, dt, False


def rpc(url, method, params, timeout=TIMEOUT_S):
    """Returns (result, err, elapsed_seconds); see rpc_ex()."""
    res, err, dt, _ = rpc_ex(url, method, params, timeout=timeout)
    return res, err, dt


def is_raw_tx_served(err, jsonrpc_error):
    """True if eth_sendRawTransaction("0x00") was served -- i.e. the
    provider decoded and rejected the garbage bytes. Only a JSON-RPC
    error response (`jsonrpc_error`, from an HTTP 200 body or a parsed
    HTTP 4xx body) with recognizable transaction decoding evidence counts.
    Quota, auth, disabled-method and unknown errors are not such evidence.
    `err` is None when the call "succeeded" (accepted a garbage tx,
    which is its own problem and reported separately). A transport
    failure -- connection error, timeout, malformed URL, bare HTTP
    status, non-JSON body -- is never a serve: nothing proves the request
    reached JSON-RPC handling at all."""
    if err is None or not jsonrpc_error:
        return False
    if UNSERVED_METHOD_RE.search(err):
        return False
    if re.search(r"quota|rate.?limit|capacity|unauthori[sz]ed|forbidden|disabled|not enabled|access denied|\b(401|403|429)\b", err, re.I):
        return False
    return bool(re.search(
        r"\brlp\b|decode error|decod\w*.*transaction|transaction.*decod|"
        r"transaction.*too short|empty transaction|input too short|unexpected end of (input|file)",
        err, re.I,
    ))


def evaluate_state_manager_check(call_res, call_err, code_res, code_err, host, url):
    """Pure combination of the eth_call + eth_getCode results into the
    two output strings and any error messages. A non-empty eth_call
    result alone isn't enough evidence the StateManager address is
    right for this chain -- an empty eth_getCode ("0x") means there's no
    contract there at all."""
    errors = []
    if call_res is not None:
        eth_call_out = "ok"
    else:
        eth_call_out = scrub(call_err, host, url)
        errors.append(f"eth_call: {eth_call_out}")
    if code_res is None:
        code_out = scrub(code_err, host, url)
        errors.append(f"eth_getCode: {code_out}")
    elif code_res in ("0x", "0x0", ""):
        code_out = "empty (wrong state_manager address?)"
        errors.append(f"eth_getCode: {code_out}")
    else:
        code_out = "ok"
    return eth_call_out, code_out, errors


# --------------------------------------------------------------------------
# shared per-chain head pass
# --------------------------------------------------------------------------

def fetch_head_info(url):
    """Two RPC calls: eth_chainId + eth_blockNumber. Run once per
    candidate up front for the whole chain, then reused by probe() so
    the rest of the checks never re-fetch chain id / head."""
    cid, cid_err, _ = rpc(url, "eth_chainId", [])
    chain_id = None
    if cid is not None:
        try:
            chain_id = int(cid, 16)
        except (TypeError, ValueError):
            cid_err = cid_err or f"malformed chain_id response {cid!r}"
    head, head_err, dt = rpc(url, "eth_blockNumber", [])
    head_val, head_ms = None, None
    if head is not None:
        try:
            head_val = int(head, 16)
            head_ms = int(dt * 1000)
        except (TypeError, ValueError):
            head_err = head_err or f"malformed blockNumber response {head!r}"
    return {
        "chain_id": chain_id,
        "chain_id_err": None if chain_id is not None else (cid_err or "no result"),
        "head": head_val,
        "head_err": None if head_val is not None else (head_err or "no result"),
        "head_ms": head_ms,
    }


def compute_scan_window(head_infos, wanted_chain_id, confirmations):
    """head_infos: iterable of {'chain_id': int|None, 'head': int|None,
    ...}. Only candidates that reported the correct chain id and a
    numeric head count toward the shared scan window -- otherwise a slow
    or broken candidate's missing head can't drag down (or a
    misconfigured one's wrong-chain head can't skew) what every
    candidate on the chain is compared against. Returns
    (scan_end, max_head); both None when nothing qualifies."""
    heads = [
        h["head"] for h in head_infos
        if h.get("chain_id") == wanted_chain_id and isinstance(h.get("head"), int)
    ]
    if not heads:
        return None, None
    return min(heads) - confirmations, max(heads)


# --------------------------------------------------------------------------
# per-candidate probe
# --------------------------------------------------------------------------

def _new_result(chain_name, provider, host):
    return {
        "chain": chain_name,
        "provider": provider,
        "host": host,
        "chain_id": None,
        "chain_ok": False,
        "head": None,
        "head_ms": None,
        "head_lag": None,
        "logs_max_range": 0,
        "logs_ms": None,
        "logs_count": None,
        "logs_err": None,
        "eth_call": None,
        "state_manager_code": None,
        "raw_tx_method": None,
        "scan_end_block": None,
        "scan_window_empty": False,
        "scan_chunks": 0,
        "scan_deposit_count": 0,
        "scan_failed_chunk": None,
        "scan_slowest_s": 0.0,
        "receipt": None,
        "errors": [],
    }


def _as_log_list(res):
    """Validates an eth_getLogs result shape before it's indexed: must be
    a list of dict entries. Returns (logs, None) when valid, or
    (None, error) when not -- a misbehaving provider that returns
    something else (a bare string, a dict, a list of non-object entries)
    is recorded as an error and skipped, rather than crashing on
    `res[-1]["transactionHash"]` or a bad `len()`."""
    if not isinstance(res, list):
        return None, "malformed getLogs result (not a list)"
    for entry in res:
        if not isinstance(entry, dict):
            return None, "malformed getLogs result (non-object entry)"
    return res, None


def scan_history(url, host, bridge, topic, start_block, scan_end):
    """Fixed 50000-block eth_getLogs scan from start_block to scan_end
    (inclusive), deliberately NOT adaptive -- this is what the relayer's
    real fixed-size chunking needs the provider to sustain. Stops after
    3 consecutive chunk failures (the candidate is already REJECTED at
    that point; no reason to keep hammering a broken endpoint for the
    rest of a potentially large range). Emits host+block-range-only
    progress lines to stderr."""
    total, calls, slow, first_err, last_tx, consecutive_fail = 0, 0, 0.0, None, None, 0
    b = start_block
    while b <= scan_end:
        e_block = min(b + SCAN_CHUNK - 1, scan_end)
        print(f"{host}: scanning blocks {b}-{e_block}", file=sys.stderr, flush=True)
        res, err, dt = rpc(url, "eth_getLogs", [{
            "address": bridge, "topics": [topic],
            "fromBlock": hex(b), "toBlock": hex(e_block),
        }], timeout=TIMEOUT_S)
        calls += 1
        slow = max(slow, dt)
        logs, shape_err = (None, None)
        if res is not None:
            logs, shape_err = _as_log_list(res)
        if res is None or logs is None:
            consecutive_fail += 1
            if first_err is None:
                reason = scrub(err, host, url) if res is None else shape_err
                first_err = f"blocks {b}..{e_block}: {reason}"
            if consecutive_fail >= MAX_CONSECUTIVE_SCAN_FAILURES:
                first_err += f" (stopped after {MAX_CONSECUTIVE_SCAN_FAILURES} consecutive chunk failures)"
                break
        else:
            consecutive_fail = 0
            total += len(logs)
            if logs:
                last_tx = logs[-1].get("transactionHash")
        b = e_block + 1
    return {
        "chunks": calls,
        "deposit_count": total,
        "failed_chunk": first_err,
        "slowest_s": round(slow, 1),
        "last_tx": last_tx,
    }


def probe(chain_name, chain_cfg, provider, url, head_info, scan_end, confirmations):
    host = safe_host(url)
    out = _new_result(chain_name, provider, host)

    # chain id / head come from the shared head pass -- no duplicate calls
    if head_info.get("chain_id_err"):
        msg = scrub(head_info["chain_id_err"], host, url)
        out["chain_id"] = f"ERR {msg}"
        out["errors"].append(f"chain_id: {msg}")
    else:
        cid_int = head_info.get("chain_id")
        out["chain_id"] = cid_int
        out["chain_ok"] = cid_int == chain_cfg["chain_id"]
        if not out["chain_ok"]:
            out["errors"].append(f"chain_id mismatch: got {cid_int}, want {chain_cfg['chain_id']}")

    own_head = head_info.get("head")
    if head_info.get("head_err"):
        msg = scrub(head_info["head_err"], host, url)
        out["head"] = f"ERR {msg}"
        out["errors"].append(f"head: {msg}")
    else:
        out["head"] = own_head
        out["head_ms"] = head_info.get("head_ms")
        max_head = head_info.get("max_head")
        if max_head is not None:
            out["head_lag"] = max_head - own_head

    # eth_call + eth_getCode on the StateManager (independent of head)
    call_res, call_err, _ = rpc(url, "eth_call", [{"to": chain_cfg["state_manager"], "data": SM_SELECTOR}, "latest"])
    code_res, code_err, _ = rpc(url, "eth_getCode", [chain_cfg["state_manager"], "latest"])
    eth_call_out, code_out, sm_errors = evaluate_state_manager_check(call_res, call_err, code_res, code_err, host, url)
    out["eth_call"] = eth_call_out
    out["state_manager_code"] = code_out
    out["errors"].extend(sm_errors)

    # eth_sendRawTransaction (independent of head)
    res, err, _, jsonrpc_error = rpc_ex(url, "eth_sendRawTransaction", ["0x00"])
    served = is_raw_tx_served(err, jsonrpc_error)
    if served:
        out["raw_tx_method"] = "served (rejected garbage)"
    else:
        detail = scrub(err, host, url) if err else "accepted garbage tx?!"
        out["raw_tx_method"] = f"NOT served: {detail}"
        out["errors"].append(f"raw_tx: {detail}")

    # largest successful eth_getLogs span near this candidate's OWN head
    # (a capability check, not part of the cross-candidate comparison)
    near_head_tx = None
    if isinstance(own_head, int):
        for span in SPAN_CANDIDATES:
            frm = max(own_head - span + 1, 0)
            res, err, dt = rpc(url, "eth_getLogs", [{
                "address": chain_cfg["bridge"], "topics": [TOPIC],
                "fromBlock": hex(frm), "toBlock": hex(own_head),
            }])
            if res is not None:
                logs, shape_err = _as_log_list(res)
                if logs is None:
                    out["logs_err"] = out["logs_err"] or shape_err
                    continue
                out["logs_max_range"] = span
                out["logs_ms"] = int(dt * 1000)
                out["logs_count"] = len(logs)
                if logs:
                    near_head_tx = logs[-1].get("transactionHash")
                break
            out["logs_err"] = out["logs_err"] or scrub(err, host, url)
        if out["logs_max_range"] == 0:
            out["errors"].append(f"eth_getLogs: {out['logs_err'] or 'no span succeeded'}")
    else:
        out["logs_err"] = "head unknown, cannot probe near-head span"
        out["errors"].append(f"eth_getLogs: {out['logs_err']}")

    # full-history scan up to the chain-wide confirmed scan_end (NOT this
    # candidate's own head -- see head_lag)
    out["scan_end_block"] = scan_end
    last_tx = None
    if scan_end is None:
        out["scan_failed_chunk"] = "scan skipped: no confirmed chain head available"
        out["errors"].append("scan: no confirmed chain head available")
    elif scan_end < chain_cfg["start_block"]:
        # The chain's shared, confirmed scan window ends before its own
        # start_block (e.g. a young chain combined with a large
        # --confirmations). A silent 0-chunk scan would report a deposit
        # count of 0 with no error, which could look CERTIFIED if every
        # other candidate on the chain shares the same empty window --
        # flag it explicitly instead.
        out["scan_window_empty"] = True
        out["scan_failed_chunk"] = "scan skipped: empty scan window (scan_end < start_block)"
        out["errors"].append("scan: empty scan window (scan_end < start_block)")
    else:
        scan = scan_history(url, host, chain_cfg["bridge"], TOPIC, chain_cfg["start_block"], scan_end)
        out["scan_chunks"] = scan["chunks"]
        out["scan_deposit_count"] = scan["deposit_count"]
        out["scan_failed_chunk"] = scan["failed_chunk"]
        out["scan_slowest_s"] = scan["slowest_s"]
        last_tx = scan["last_tx"]
        if scan["failed_chunk"]:
            out["errors"].append(f"scan: {scan['failed_chunk']}")

    # receipt lookup for the most recent deposit tx found anywhere; a
    # skipped check is always visible in the field, never silent
    tx_hash = last_tx or near_head_tx
    if tx_hash:
        res, err, _ = rpc(url, "eth_getTransactionReceipt", [tx_hash])
        if res:
            out["receipt"] = "ok"
        elif err:
            out["receipt"] = scrub(err, host, url)
            out["errors"].append(f"receipt: {out['receipt']}")
        else:
            out["receipt"] = "null"
            out["errors"].append("receipt: null result for a known tx hash")
    else:
        out["receipt"] = RECEIPT_SKIPPED

    return out


# --------------------------------------------------------------------------
# verdicts
# --------------------------------------------------------------------------

def compute_verdicts(results):
    """results: list of per-candidate dicts with 'chain', 'errors',
    'chain_ok' and 'scan_deposit_count'. Returns {chain: {
    "max_deposit_count": N, "verdicts": [(candidate_dict, verdict_str),
    ...]}}. A candidate with the wrong chain id never contributes to
    max_deposit_count -- its count isn't evidence of anything on the
    chain being certified."""
    by_chain = {}
    for r in results:
        by_chain.setdefault(r["chain"], []).append(r)
    summary = {}
    for chain_name, cands in by_chain.items():
        eligible = [c for c in cands if c.get("chain_ok") is True]
        max_count = max((c.get("scan_deposit_count") or 0 for c in eligible), default=0)
        verdicts = []
        for c in cands:
            if c.get("errors"):
                v = "REJECTED"
            elif (c.get("scan_deposit_count") or 0) < max_count:
                v = "INCOMPLETE"
            else:
                v = "CERTIFIED"
            verdicts.append((c, v))
        summary[chain_name] = {"max_deposit_count": max_count, "verdicts": verdicts}
    return summary


def is_vacuous(info):
    """True when a chain's certification has nothing meaningful to
    compare against: no deposits ever seen, or at most one candidate
    survived to be compared at all."""
    non_rejected = sum(1 for _, v in info["verdicts"] if v != "REJECTED")
    return info["max_deposit_count"] == 0 or non_rejected <= 1


def has_certified(summary):
    """True only if every chain in the summary has at least one
    CERTIFIED candidate."""
    if not summary:
        return False
    return all(any(v == "CERTIFIED" for _, v in info["verdicts"]) for info in summary.values())


def print_summary(results, confirmations):
    summary = compute_verdicts(results)
    print()
    print("=== Certification summary ===")
    print(f"(scan confirmations margin: {confirmations} blocks)")
    for chain_name, info in summary.items():
        print(f"\n{chain_name}: max deposit count seen = {info['max_deposit_count']}")
        chain_cands = [c for c, _ in info["verdicts"]]
        if any(c.get("scan_window_empty") for c in chain_cands):
            print(f"  WARNING: {chain_name}: scan window is empty (scan_end < start_block)")
        elif is_vacuous(info):
            print(f"  WARNING: {chain_name}: nothing to compare against -- certification is vacuous")
        for cand, verdict in info["verdicts"]:
            host = cand.get("host") or "?"
            provider = cand.get("provider") or "?"
            count = cand.get("scan_deposit_count")
            lag = cand.get("head_lag")
            lag_str = f" lag={lag}" if lag else ""
            if verdict == "REJECTED":
                reason = "; ".join(cand.get("errors") or []) or "unknown error"
                print(f"  REJECTED    {provider:<20} {host:<36} {reason}")
            elif verdict == "INCOMPLETE":
                print(f"  INCOMPLETE  {provider:<20} {host:<36} count={count}{lag_str}")
            else:
                print(f"  CERTIFIED   {provider:<20} {host:<36} count={count}{lag_str}")
    return summary


# --------------------------------------------------------------------------
# self-test (no external network access: mocks plus a 127.0.0.1 loopback server)
# --------------------------------------------------------------------------

def self_test():
    ok = True
    set_proxy_mode(False)  # always test the default (direct) transport

    def check(name, cond):
        nonlocal ok
        print(f"[{'PASS' if cond else 'FAIL'}] {name}")
        if not cond:
            ok = False

    # -- scrub(): baseline behavior --
    host = "eth-sepolia.g.alchemy.com"
    err_with_url = (
        f"URLError <urlopen error [Errno -2] Name or service not known> "
        f"https://{host}/v2/SECRETKEY123?foo=bar"
    )
    scrubbed = scrub(err_with_url, host, f"https://{host}/v2/SECRETKEY123?foo=bar")
    check(
        "scrub() strips path/query after host, keeps host",
        host in scrubbed and "SECRETKEY123" not in scrubbed and "foo=bar" not in scrubbed,
    )
    check("scrub() leaves text with no URL untouched", scrub("URLError timed out", host) == "URLError timed out")
    check("scrub() handles None text", scrub(None, host) is None)
    check("scrub() handles missing host/url", scrub("example.com/x?key=1", None) == "example.com/x?key=1")

    # -- scrub(): fix round 1 gaps --
    url_mixed = "https://User:Sup3rSecretPW@Eth-Sepolia.G.Alchemy.Com/v2/ABCDEF123456?id=99"
    host_mixed = urlparse(url_mixed).hostname  # urlparse always lowercases
    text_mixed = f"connection failed to {url_mixed}"
    scrubbed_mixed = scrub(text_mixed, host_mixed, url_mixed)
    check(
        "scrub() catches a mixed-case host in error text (case-insensitive)",
        "Eth-Sepolia" not in scrubbed_mixed and "eth-sepolia" in scrubbed_mixed.lower(),
    )
    check("scrub() redacts userinfo credentials", "Sup3rSecretPW" not in scrubbed_mixed and "User" not in scrubbed_mixed)
    check("scrub() redacts the path segment carrying the key", "ABCDEF123456" not in scrubbed_mixed)

    key = "SECRETKEY123456"
    text_bare_key = f"invalid api key {key}"
    scrubbed_bare_key = scrub(text_bare_key, "unrelated-host.example", f"https://unrelated-host.example/v2/{key}")
    check("scrub() redacts a bare key echoed without the host around it", key not in scrubbed_bare_key)

    url_query = "https://public.example/rpc?api_key=QUERYSECRET99"
    text_query = "error: api_key=QUERYSECRET99 rejected"
    scrubbed_query = scrub(text_query, "public.example", url_query)
    check("scrub() redacts a key in the query string", "QUERYSECRET99" not in scrubbed_query)

    # -- scrub(): fix round 2 -- short userinfo over-redaction --
    short_userinfo_url = "https://id:ab@public.example/rpc"
    text_short_userinfo = (
        "basic auth id:ab@ rejected; unrelated 'ab' and 'id' fields should "
        "stay readable elsewhere in this id-based log line"
    )
    scrubbed_short = scrub(text_short_userinfo, "public.example", short_userinfo_url)
    check(
        "scrub() always redacts the literal 'user:pass@' form even when short",
        "id:ab@" not in scrubbed_short,
    )
    check(
        "scrub() preserves short (<4 char) standalone username/password text elsewhere",
        "unrelated 'ab' and 'id' fields should stay readable elsewhere in this id-based log line" in scrubbed_short,
    )

    long_userinfo_url = "https://myusername:mypassword123@public.example/rpc"
    text_long_userinfo = "auth failed for myusername with secret mypassword123 today"
    scrubbed_long = scrub(text_long_userinfo, "public.example", long_userinfo_url)
    check("scrub() redacts a long (>=4 char) standalone username", "myusername" not in scrubbed_long)
    check("scrub() redacts a long (>=4 char) standalone password", "mypassword123" not in scrubbed_long)

    # -- load_env_file() / build_env_lookup() --
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
        f.write("# comment\nFOO_URL=https://example.com/v2/abc\nBAR=\"quoted value\"\n\nBAZ='single'\n")
        env_path = f.name
    try:
        parsed = load_env_file(env_path)
        check(
            "load_env_file() parses KEY=VALUE, strips quotes, skips comments/blank",
            parsed == {"FOO_URL": "https://example.com/v2/abc", "BAR": "quoted value", "BAZ": "single"},
        )
    finally:
        os.unlink(env_path)

    with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
        f.write("SHARED=from_file\nONLY_FILE=file_value\n")
        env_path2 = f.name
    try:
        merged = build_env_lookup(env_path2, {"SHARED": "from_process_env"})
        check("build_env_lookup(): existing environment wins over the file", merged["SHARED"] == "from_process_env")
        check("build_env_lookup(): file fills in keys missing from the environment", merged["ONLY_FILE"] == "file_value")
        check("build_env_lookup() with no file just returns base_env", build_env_lookup(None, {"X": "1"}) == {"X": "1"})
    finally:
        os.unlink(env_path2)

    # -- resolve_candidate_url() --
    url, err = resolve_candidate_url({"url": "https://public.example/rpc"}, {})
    check("resolve_candidate_url() prefers literal url", url == "https://public.example/rpc" and err is None)
    url, err = resolve_candidate_url({"url_env": "MISSING_VAR"}, {})
    check("resolve_candidate_url() reports unset env var", url is None and "MISSING_VAR" in err)
    url, err = resolve_candidate_url({"url_env": "SET_VAR"}, {"SET_VAR": "https://x.example/rpc"})
    check("resolve_candidate_url() resolves url_env from lookup", url == "https://x.example/rpc" and err is None)
    url, err = resolve_candidate_url({}, {})
    check("resolve_candidate_url() rejects candidate with neither field", url is None and err is not None)

    # -- validate_spec() --
    good_spec = {
        "chains": {"sepolia": {"chain_id": 11155111, "bridge": "0x" + "11" * 20,
                                "state_manager": "0x" + "22" * 20, "start_block": 1}},
        "candidates": [{"chain": "sepolia", "provider": "p", "url": "https://example.com"}],
    }
    check("validate_spec() accepts a well-formed spec", validate_spec(good_spec) == [])

    bad_spec = {
        "chains": {"sepolia": {"chain_id": "not-an-int", "bridge": "not-hex",
                                "state_manager": "0x" + "22" * 20, "start_block": 1}},
        "candidates": [{"chain": "unknownChain", "provider": "p", "url_env": "X"}],
    }
    errs = validate_spec(bad_spec)
    check("validate_spec() flags a non-integer chain_id", any("chain_id" in e for e in errs))
    check("validate_spec() flags a malformed bridge address", any("bridge" in e for e in errs))
    check("validate_spec() flags a candidate referencing an unknown chain", any("unknown chain" in e for e in errs))

    # -- validate_spec(): fix round 2 --
    check(
        "validate_spec() rejects a non-object top-level JSON value",
        validate_spec(["not", "an", "object"]) == ["input: top-level JSON must be an object"],
    )
    check("validate_spec() rejects a null top-level JSON value", validate_spec(None) == ["input: top-level JSON must be an object"])

    non_string_url_spec = {
        "chains": good_spec["chains"],
        "candidates": [{"chain": "sepolia", "provider": "p", "url": 12345}],
    }
    errs = validate_spec(non_string_url_spec)
    check("validate_spec() flags a non-string 'url'", any("'url' must be a string" in e for e in errs))

    non_string_url_env_spec = {
        "chains": good_spec["chains"],
        "candidates": [{"chain": "sepolia", "provider": "p", "url_env": ["NOT", "A", "STRING"]}],
    }
    errs = validate_spec(non_string_url_env_spec)
    check("validate_spec() flags a non-string 'url_env'", any("'url_env' must be a string" in e for e in errs))

    # -- rpc(): error field can be a string, not an object (prototype bug) --
    class FakeResp:
        def __init__(self, payload):
            self._payload = json.dumps(payload).encode()

        def read(self):
            return self._payload

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    orig_urlopen = _OPEN
    try:
        globals()["_OPEN"] = lambda req, timeout=None: FakeResp(
            {"jsonrpc": "2.0", "id": 1, "error": "rate limited"}
        )
        res, err, _ = rpc("http://example.invalid", "eth_chainId", [])
        check("rpc() handles a bare-string error field without crashing", res is None and err == "rate limited")

        globals()["_OPEN"] = lambda req, timeout=None: FakeResp(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "boom"}}
        )
        res, err, _ = rpc("http://example.invalid", "eth_chainId", [])
        check("rpc() handles a dict error field", res is None and err == "-32000 boom")

        globals()["_OPEN"] = lambda req, timeout=None: FakeResp(
            {"jsonrpc": "2.0", "id": 1, "result": "0xaa36a7"}
        )
        res, err, _ = rpc("http://example.invalid", "eth_chainId", [])
        check("rpc() returns result on success", res == "0xaa36a7" and err is None)

        # -- HTTP 400/403/413 instead of a JSON-RPC error (prototype bug) --
        for code in (400, 403, 413):
            def _raise(req, timeout=None, _code=code):
                raise urllib.error.HTTPError("http://example.invalid", _code, "rejected", None, None)

            globals()["_OPEN"] = _raise
            res, err, _ = rpc("http://example.invalid", "eth_getLogs", [{}])
            check(f"rpc() handles HTTP {code} without crashing", res is None and err == f"HTTP {code}")

        # -- fix round 1: parse a JSON-RPC error out of an HTTP error body --
        def _raise_http_with_body(code, body_bytes):
            def _raiser(req, timeout=None):
                raise urllib.error.HTTPError("http://example.invalid", code, "rejected", None, io.BytesIO(body_bytes))
            return _raiser

        decode_err_body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "rlp: could not decode"}}
        ).encode()
        globals()["_OPEN"] = _raise_http_with_body(400, decode_err_body)
        res, err, _, jre = rpc_ex("http://example.invalid", "eth_sendRawTransaction", ["0x00"])
        check(
            "rpc() parses a JSON-RPC error out of an HTTP 400 body",
            res is None and err == "HTTP 400: -32602 rlp: could not decode",
        )
        check("is_raw_tx_served() treats a decoded HTTP 400 body as served", is_raw_tx_served(err, jre) is True)

        globals()["_OPEN"] = _raise_http_with_body(403, b"")
        res, err, _ = rpc("http://example.invalid", "eth_call", [{}])
        check("rpc() falls back to a bare 'HTTP 403' when the body isn't JSON-RPC", err == "HTTP 403")

        # -- fix round 2: HTTP error body is capped at 4096 bytes --
        huge_body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "A" * 5000}}
        ).encode()
        check("self-test setup: the huge error body really is >4096 bytes", len(huge_body) > 4096)
        globals()["_OPEN"] = _raise_http_with_body(400, huge_body)
        res, err, _ = rpc("http://example.invalid", "eth_call", [{}])
        check(
            "rpc() reads at most 4096 bytes of an HTTP error body "
            "(a truncated-past-4096 JSON body falls back to a bare 'HTTP {code}')",
            err == "HTTP 400",
        )
    finally:
        globals()["_OPEN"] = orig_urlopen

    # -- is_raw_tx_served() --
    check("is_raw_tx_served(): None (accepted garbage) is not served", is_raw_tx_served(None, False) is False)
    check("is_raw_tx_served(): -32601 method-not-found is not served", is_raw_tx_served("-32601 method not found", True) is False)
    check("is_raw_tx_served(): bare 'HTTP 400' with no detail is not served", is_raw_tx_served("HTTP 400", False) is False)
    check("is_raw_tx_served(): a decode-error message is served", is_raw_tx_served("-32602 rlp: could not decode", True) is True)
    for error in ("429 monthly quota exceeded", "-32600 eth_sendRawTransaction not enabled on this endpoint",
                  "-32000 unauthorized", "-32000 server error", "-32602 invalid params",
                  "-32000 quota exceeded while decoding transaction"):
        check(f"is_raw_tx_served(): refuses ambiguous/blocked response {error}",
              is_raw_tx_served(error, True) is False)
    check(
        "is_raw_tx_served(): 'HTTP 400: <decoded jsonrpc>' counts as served",
        is_raw_tx_served("HTTP 400: -32602 rlp: could not decode", True) is True,
    )

    # -- evaluate_state_manager_check() --
    eth_call_out, code_out, errs = evaluate_state_manager_check(
        "0xdeadbeef", None, "0x60fe47b1", None, "host.example", "https://host.example/v2/key"
    )
    check("evaluate_state_manager_check(): ok when call succeeds and code is non-empty",
          eth_call_out == "ok" and code_out == "ok" and errs == [])

    eth_call_out, code_out, errs = evaluate_state_manager_check(
        "0xdeadbeef", None, "0x", None, "host.example", "https://host.example/v2/key"
    )
    check("evaluate_state_manager_check(): flags an empty eth_getCode result",
          code_out != "ok" and any("eth_getCode" in e for e in errs))

    eth_call_out, code_out, errs = evaluate_state_manager_check(
        None, "boom", "0x60fe47b1", None, "host.example", "https://host.example/v2/key"
    )
    check("evaluate_state_manager_check(): flags a failing eth_call",
          eth_call_out != "ok" and any("eth_call" in e for e in errs))

    # -- compute_scan_window() (fix round 1: shared per-chain scan window) --
    head_infos = [
        {"chain_id": 11155111, "head": 1000},
        {"chain_id": 11155111, "head": 1050},
        {"chain_id": 999, "head": 5000},   # wrong chain id -- excluded
        {"chain_id": 11155111, "head": None},  # head fetch failed -- excluded
    ]
    scan_end, max_head = compute_scan_window(head_infos, 11155111, 12)
    check("compute_scan_window(): scan_end is min eligible head minus confirmations", scan_end == 1000 - 12)
    check("compute_scan_window(): max_head is max eligible head", max_head == 1050)
    scan_end2, max_head2 = compute_scan_window([], 1, 12)
    check("compute_scan_window(): returns (None, None) with no eligible heads", scan_end2 is None and max_head2 is None)

    # -- scan_history() (fix round 1: stop after 3 consecutive failures) --
    globals()["_OPEN"] = orig_urlopen
    try:
        def _always_fail(req, timeout=None):
            raise urllib.error.HTTPError("http://example.invalid", 500, "boom", None, None)

        globals()["_OPEN"] = _always_fail
        result = scan_history("http://example.invalid", "host.example", "0xBridge", TOPIC, 0, 300_000)
        check(
            "scan_history() stops after 3 consecutive chunk failures instead of scanning the whole range",
            result["chunks"] == 3 and "stopped after 3 consecutive chunk failures" in (result["failed_chunk"] or ""),
        )

        globals()["_OPEN"] = lambda req, timeout=None: FakeResp({"jsonrpc": "2.0", "id": 1, "result": []})
        result = scan_history("http://example.invalid", "host.example", "0xBridge", TOPIC, 0, 99_999)
        check(
            "scan_history() covers the full range on success with no early stop",
            result["chunks"] == 2 and result["failed_chunk"] is None and result["deposit_count"] == 0,
        )
    finally:
        globals()["_OPEN"] = orig_urlopen

    # -- compute_verdicts() / is_vacuous() / has_certified() --
    canned = [
        {"chain": "sepolia", "provider": "good", "scan_deposit_count": 12, "errors": [], "chain_ok": True},
        {"chain": "sepolia", "provider": "partial", "scan_deposit_count": 5, "errors": [], "chain_ok": True},
        {"chain": "sepolia", "provider": "broken", "scan_deposit_count": 0,
         "errors": ["scan: blocks 1..50000: HTTP 413"], "chain_ok": True},
        {"chain": "sepolia", "provider": "wrong-chain", "scan_deposit_count": 999,
         "errors": ["chain_id mismatch: got 1, want 11155111"], "chain_ok": False},
        {"chain": "bscTestnet", "provider": "only", "scan_deposit_count": 3, "errors": [], "chain_ok": True},
    ]
    summary = compute_verdicts(canned)
    verdict_map = {c["provider"]: v for c, v in summary["sepolia"]["verdicts"]}
    check("verdict: max-count candidate is CERTIFIED", verdict_map["good"] == "CERTIFIED")
    check("verdict: lower count with no error is INCOMPLETE", verdict_map["partial"] == "INCOMPLETE")
    check("verdict: any error is REJECTED even with count 0", verdict_map["broken"] == "REJECTED")
    check("verdict: chain-id-mismatch candidate is REJECTED regardless of its count", verdict_map["wrong-chain"] == "REJECTED")
    check(
        "verdict: max_deposit_count excludes the chain-id-mismatch candidate's bogus count",
        summary["sepolia"]["max_deposit_count"] == 12,
    )
    check("verdict: single-candidate chain with no error is CERTIFIED", summary["bscTestnet"]["verdicts"][0][1] == "CERTIFIED")

    check("has_certified(): true when every chain has a CERTIFIED candidate", has_certified(summary))
    all_rejected_summary = {"sepolia": {"max_deposit_count": 0, "verdicts": [({"provider": "x"}, "REJECTED")]}}
    check("has_certified(): false when a chain has no CERTIFIED candidate", not has_certified(all_rejected_summary))
    check("has_certified(): false on an empty summary", not has_certified({}))

    check("is_vacuous(): true when max_deposit_count is 0", is_vacuous({"max_deposit_count": 0, "verdicts": [({}, "CERTIFIED")]}))
    check(
        "is_vacuous(): true with at most one non-REJECTED candidate",
        is_vacuous({"max_deposit_count": 5, "verdicts": [({}, "CERTIFIED"), ({}, "REJECTED")]}),
    )
    check(
        "is_vacuous(): false with two+ non-REJECTED candidates and a nonzero max",
        not is_vacuous({"max_deposit_count": 5, "verdicts": [({}, "CERTIFIED"), ({}, "INCOMPLETE")]}),
    )

    check("RECEIPT_SKIPPED constant matches the required field text", RECEIPT_SKIPPED == "skipped: no deposit tx")

    # -- fix round 2: an empty scan window (scan_end < start_block) is flagged --
    orig_urlopen4 = _OPEN
    try:
        def _generic_ok(req, timeout=None):
            body = json.loads(req.data)
            method = body.get("method")
            if method == "eth_sendRawTransaction":
                return FakeResp({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "rlp: could not decode"}})
            if method == "eth_getLogs":
                return FakeResp({"jsonrpc": "2.0", "id": 1, "result": []})
            if method == "eth_getCode":
                return FakeResp({"jsonrpc": "2.0", "id": 1, "result": "0x60fe47b1"})
            return FakeResp({"jsonrpc": "2.0", "id": 1, "result": "0xdeadbeef"})

        globals()["_OPEN"] = _generic_ok
        chain_cfg = {
            "chain_id": 11155111,
            "bridge": "0x" + "11" * 20,
            "state_manager": "0x" + "22" * 20,
            "start_block": 5_000_000,
        }
        head_info = {
            "chain_id": 11155111, "chain_id_err": None,
            "head": 4_999_000, "head_err": None, "head_ms": 5, "max_head": 4_999_000,
        }
        probe_result = probe(
            "sepolia", chain_cfg, "shrunk-window", "http://example.invalid",
            head_info, scan_end=4_998_000, confirmations=12,
        )
        check(
            "probe(): scan_end < start_block sets scan_window_empty and an error (not a silent 0)",
            probe_result.get("scan_window_empty") is True
            and any("empty scan window" in e for e in probe_result["errors"]),
        )
    finally:
        globals()["_OPEN"] = orig_urlopen4

    import contextlib
    buf = io.StringIO()
    empty_window_candidates = [
        {"chain": "sepolia", "provider": "a", "host": "a.example", "scan_deposit_count": 0,
         "errors": ["scan: empty scan window (scan_end < start_block)"], "chain_ok": True, "scan_window_empty": True},
        {"chain": "sepolia", "provider": "b", "host": "b.example", "scan_deposit_count": 0,
         "errors": ["scan: empty scan window (scan_end < start_block)"], "chain_ok": True, "scan_window_empty": True},
    ]
    with contextlib.redirect_stdout(buf):
        print_summary(empty_window_candidates, DEFAULT_CONFIRMATIONS)
    summary_text = buf.getvalue()
    check(
        "print_summary(): prints the empty-scan-window warning",
        "WARNING: sepolia: scan window is empty (scan_end < start_block)" in summary_text,
    )
    check("print_summary(): no candidate is shown as CERTIFIED when the scan window is empty", "CERTIFIED" not in summary_text)

    # -- fix round 2: validation holes in main()'s own file/JSON handling --
    import tempfile
    rc = main(["/nonexistent/path/does-not-exist.json"])
    check("main(): a missing input file exits 2 (no traceback)", rc == 2)

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("{not valid json")
        bad_json_path = f.name
    try:
        rc = main([bad_json_path])
        check("main(): malformed JSON exits 2 (no traceback)", rc == 2)
    finally:
        os.unlink(bad_json_path)

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write("[1, 2, 3]")
        non_object_path = f.name
    try:
        rc = main([non_object_path])
        check("main(): a non-object top-level JSON value exits 2 (no traceback)", rc == 2)
    finally:
        os.unlink(non_object_path)

    # -- fix round 3: a malformed candidate URL must never crash or leak --
    # (this was a real key-leak bug: Request() raised ValueError("unknown
    # url type: %r" % url) for a scheme-less URL, and that message embeds
    # the whole URL including any key in it -- outside rpc()'s try, so it
    # propagated to Python's default excepthook, which prints str(e).)
    fake_secret = "SUPERSECRETKEY999DOESNOTEXIST"
    res, err, _ = rpc(f"eth.example.com/v2/{fake_secret}", "eth_chainId", [])
    check("rpc(): a scheme-less URL doesn't raise -- returns a safe (result=None, err=str) pair", res is None and isinstance(err, str))
    check("rpc(): a scheme-less URL's error string never contains the secret", fake_secret not in (err or ""))

    res, err, _ = rpc(f"http://[::1/v2/{fake_secret}", "eth_chainId", [])
    check("rpc(): a malformed IPv6 URL doesn't raise -- returns a safe (result=None, err=str) pair", res is None and isinstance(err, str))
    check("rpc(): a malformed IPv6 URL's error string never contains the secret", fake_secret not in (err or ""))

    check("safe_host(): a malformed IPv6 URL doesn't raise (returns None)", safe_host(f"http://[::1/v2/{fake_secret}") is None)
    check("safe_host(): a normal URL still works", safe_host("https://public.example/rpc") == "public.example")

    # End-to-end: the whole main() pipeline, with urlopen mocked to
    # guarantee zero real network I/O (belt and suspenders on top of the
    # rpc()-level fix above), must not crash and must not leak the secret
    # anywhere in stdout or stderr.
    import contextlib

    orig_urlopen5 = _OPEN
    try:
        def _never_really_connect(req, timeout=None):
            raise OSError("simulated: no real network access during self-test")

        globals()["_OPEN"] = _never_really_connect
        fake_secret2 = "OTHERSECRETVALUE12345"
        for bad_url, label in (
            (f"eth.example.com/v2/{fake_secret2}", "scheme-less"),
            (f"http://[::1/v2/{fake_secret2}", "malformed-IPv6"),
        ):
            leak_spec = {
                "chains": {"sepolia": {"chain_id": 11155111, "bridge": "0x" + "11" * 20,
                                        "state_manager": "0x" + "22" * 20, "start_block": 1}},
                "candidates": [{"chain": "sepolia", "provider": "p", "url": bad_url}],
            }
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                json.dump(leak_spec, f)
                leak_spec_path = f.name
            try:
                out_buf, err_buf = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                    rc = main([leak_spec_path])
                captured = out_buf.getvalue() + err_buf.getvalue()
                check(f"main(): a {label} candidate URL doesn't crash the whole run", rc in (0, 1))
                check(f"main(): a {label} candidate URL's secret never leaks to stdout/stderr", fake_secret2 not in captured)
            finally:
                os.unlink(leak_spec_path)
    finally:
        globals()["_OPEN"] = orig_urlopen5

    # -- fix round 3: the top-level safety net in main() --
    safety_net_spec = {
        "chains": {"sepolia": {"chain_id": 11155111, "bridge": "0x" + "11" * 20,
                                "state_manager": "0x" + "22" * 20, "start_block": 1}},
        "candidates": [{"chain": "sepolia", "provider": "p", "url": "https://public.example/rpc"}],
    }
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(safety_net_spec, f)
        safety_net_path = f.name
    try:
        orig_csw = compute_scan_window

        def _boom(*a, **kw):
            raise RuntimeError("deliberate self-test crash")

        globals()["compute_scan_window"] = _boom
        try:
            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                rc = main([safety_net_path])
            check("main(): an unrelated internal crash is caught by the top-level safety net (exit 3)", rc == 3)
            check(
                "main(): the safety net prints only the exception type, never a traceback",
                "RuntimeError" in err_buf.getvalue() and "Traceback" not in err_buf.getvalue(),
            )
        finally:
            globals()["compute_scan_window"] = orig_csw

        def _interrupt(*a, **kw):
            raise KeyboardInterrupt()

        globals()["compute_scan_window"] = _interrupt
        try:
            rc = main([safety_net_path])
            check("main(): a KeyboardInterrupt during the run exits 130", rc == 130)
        finally:
            globals()["compute_scan_window"] = orig_csw

        def _sysexit(*a, **kw):
            raise SystemExit(42)

        globals()["compute_scan_window"] = _sysexit
        try:
            raised = False
            try:
                main([safety_net_path])
            except SystemExit as se:
                raised = True
                check("main(): a SystemExit raised internally keeps its original code", se.code == 42)
            check("main(): SystemExit is re-raised, not swallowed by the safety net", raised)
        finally:
            globals()["compute_scan_window"] = orig_csw
    finally:
        os.unlink(safety_net_path)

    # -- fix round 3: --env-file validation (missing file / directory) --
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(good_spec, f)
        env_flag_spec_path = f.name
    try:
        rc = main(["--env-file", "/nonexistent/env/file/path.env", env_flag_spec_path])
        check("main(): a missing --env-file exits 2 (no traceback)", rc == 2)

        with tempfile.TemporaryDirectory() as d:
            rc = main(["--env-file", d, env_flag_spec_path])
            check("main(): a directory passed as --env-file exits 2 (no traceback)", rc == 2)
    finally:
        os.unlink(env_flag_spec_path)

    # -- fix round 3: non-UTF-8 input file --
    with tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False) as f:
        f.write(b"\xff\xfe\x00\x01not valid utf-8 \xfe\xff")
        non_utf8_path = f.name
    try:
        rc = main([non_utf8_path])
        check("main(): a non-UTF-8 input file exits 2 (no traceback)", rc == 2)
    finally:
        os.unlink(non_utf8_path)

    # -- fix round 3: validate_spec() candidate 'chain'/'provider' must be strings --
    unhashable_chain_spec = {
        "chains": good_spec["chains"],
        "candidates": [{"chain": ["not", "hashable"], "provider": "p", "url": "https://example.com"}],
    }
    errs = validate_spec(unhashable_chain_spec)
    check("validate_spec() flags a non-string (unhashable) 'chain' without crashing", any("'chain' must be a string" in e for e in errs))

    dict_provider_spec = {
        "chains": good_spec["chains"],
        "candidates": [{"chain": "sepolia", "provider": {"not": "a string"}, "url": "https://example.com"}],
    }
    errs = validate_spec(dict_provider_spec)
    check("validate_spec() flags a non-string 'provider' without crashing", any("'provider' must be a string" in e for e in errs))

    # -- fix round 3: --confirmations must be >= 0 --
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(good_spec, f)
        neg_conf_path = f.name
    try:
        rc = main(["--confirmations", "-1", neg_conf_path])
        check("main(): a negative --confirmations exits 2", rc == 2)
    finally:
        os.unlink(neg_conf_path)

    # -- fix round 3: _as_log_list() and its use in scan_history()/probe() --
    logs, list_err = _as_log_list([{"transactionHash": "0xabc"}])
    check("_as_log_list() accepts a well-formed list of dicts", logs == [{"transactionHash": "0xabc"}] and list_err is None)
    logs, list_err = _as_log_list({"not": "a list"})
    check("_as_log_list() rejects a non-list result", logs is None and "not a list" in list_err)
    logs, list_err = _as_log_list(["not", "a", "dict"])
    check("_as_log_list() rejects a list of non-dict entries", logs is None and "non-object entry" in list_err)

    orig_urlopen6 = _OPEN
    try:
        def _malformed_logs(req, timeout=None):
            method = json.loads(req.data).get("method")
            if method == "eth_getLogs":
                return FakeResp({"jsonrpc": "2.0", "id": 1, "result": "not-a-list"})
            return FakeResp({"jsonrpc": "2.0", "id": 1, "result": []})

        globals()["_OPEN"] = _malformed_logs
        result = scan_history("http://example.invalid", "host.example", "0xBridge", TOPIC, 0, 49_999)
        check(
            "scan_history(): a malformed (non-list) eth_getLogs result is recorded as an error, not a crash",
            result["chunks"] == 1 and result["failed_chunk"] is not None and "malformed getLogs result" in result["failed_chunk"],
        )
    finally:
        globals()["_OPEN"] = orig_urlopen6


    # -- fix round 4: transport failures are never "served" --
    orig_urlopen7 = _OPEN
    try:
        transport_failures = [
            ("ValueError", ValueError("bad url")),
            ("TimeoutError", TimeoutError("timed out")),
            ("ConnectionResetError", ConnectionResetError(104, "Connection reset by peer")),
            ("URLError timed out", urllib.error.URLError("timed out")),
            ("URLError connection refused", urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))),
            ("bare HTTP 502", urllib.error.HTTPError("http://example.invalid", 502, "bad gateway", None, io.BytesIO(b"<html>"))),
        ]
        for label, exc in transport_failures:
            def _raise_exc(req, timeout=None, _exc=exc):
                raise _exc

            globals()["_OPEN"] = _raise_exc
            res, err, _, jre = rpc_ex("http://example.invalid", "eth_sendRawTransaction", ["0x00"])
            check(
                f"is_raw_tx_served(): a transport failure ({label}) is not served",
                err is not None and jre is False and is_raw_tx_served(err, jre) is False,
            )

        class RawResp(FakeResp):
            def __init__(self, raw):
                self._payload = raw

        globals()["_OPEN"] = lambda req, timeout=None: RawResp(b"<html>gateway</html>")
        res, err, _, jre = rpc_ex("http://example.invalid", "eth_sendRawTransaction", ["0x00"])
        check("is_raw_tx_served(): a non-JSON 200 body is not served", is_raw_tx_served(err, jre) is False)

        globals()["_OPEN"] = lambda req, timeout=None: FakeResp(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "rlp: could not decode"}}
        )
        res, err, _, jre = rpc_ex("http://example.invalid", "eth_sendRawTransaction", ["0x00"])
        check("is_raw_tx_served(): a 200 JSON-RPC decode error is served", is_raw_tx_served(err, jre) is True)

        globals()["_OPEN"] = lambda req, timeout=None: FakeResp(
            {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "method eth_sendRawTransaction not supported"}}
        )
        res, err, _, jre = rpc_ex("http://example.invalid", "eth_sendRawTransaction", ["0x00"])
        check("is_raw_tx_served(): a JSON-RPC 'not supported' error is not served", is_raw_tx_served(err, jre) is False)

        # -- fix round 4: a non-UTF-8 body is an error, not a lost candidate --
        globals()["_OPEN"] = lambda req, timeout=None: RawResp(b"\xff\xfe\x00garbage\xfe")
        try:
            res, err, _ = rpc("http://example.invalid", "eth_chainId", [])
            check("rpc(): a non-UTF-8 200 body is recorded as an error", res is None and err == "invalid JSON response")
        except Exception as e:  # noqa: BLE001
            check(f"rpc(): a non-UTF-8 200 body is recorded as an error (raised {type(e).__name__})", False)
        check(
            "_parse_jsonrpc_error_body(): a non-UTF-8 HTTP error body is ignored",
            _parse_jsonrpc_error_body(b"\xff\xfe\x00garbage\xfe") is None,
        )
    finally:
        globals()["_OPEN"] = orig_urlopen7

    # -- fix round 4: userinfo never reaches the resolver; sent as Basic auth --
    import base64 as _b64
    import socket
    import threading
    import http.server

    ui_user, ui_pass = "SECRETUSERxyz", "SECRETPASS@with:colon"
    enc_pass = "SECRETPASS%40with%3Acolon"
    want_auth = "Basic " + _b64.b64encode(f"{ui_user}:{ui_pass}".encode()).decode()

    clean, auth = split_userinfo(f"https://{ui_user}:{enc_pass}@rpc.example:8443/v2/SECRETKEYPATH?k=1")
    check(
        "split_userinfo(): strips userinfo, keeps host/port/path, percent-decodes into a Basic header",
        clean == "https://rpc.example:8443/v2/SECRETKEYPATH?k=1" and auth == want_auth,
    )
    check("split_userinfo(): a URL without userinfo is unchanged", split_userinfo("https://rpc.example/v2/k") == ("https://rpc.example/v2/k", None))
    check(
        "split_userinfo(): a user without a password gets an empty password",
        split_userinfo("https://SECRETUSERxyz@rpc.example/")[1] == "Basic " + _b64.b64encode(b"SECRETUSERxyz:").decode(),
    )

    resolved_hosts = []
    sent_requests = []
    orig_gai = socket.getaddrinfo
    orig_urlopen8 = _OPEN

    def _recording_gai(host, *a, **kw):
        resolved_hosts.append(host)
        raise socket.gaierror(-2, "simulated: resolver disabled in self-test")

    def _recording_urlopen(req, timeout=None):
        sent_requests.append((req.full_url, req.host, req.get_header("Authorization")))
        return orig_urlopen8(req, timeout=timeout)

    try:
        socket.getaddrinfo = _recording_gai
        globals()["_OPEN"] = _recording_urlopen
        res, err, _ = rpc(f"http://{ui_user}:{enc_pass}@probe-host.invalid:8545/v2/SECRETKEYPATH", "eth_chainId", [])
    finally:
        socket.getaddrinfo = orig_gai
        globals()["_OPEN"] = orig_urlopen8
    check(
        "rpc(): the resolver is only ever asked for the bare host, never userinfo",
        bool(resolved_hosts) and all(h == "probe-host.invalid" for h in resolved_hosts),
    )
    check(
        "rpc(): the request URL/host carry no userinfo and the Basic header is set",
        len(sent_requests) == 1 and "SECRET" not in sent_requests[0][0].split("/v2/")[0]
        and sent_requests[0][1] == "probe-host.invalid:8545" and sent_requests[0][2] == want_auth,
    )
    check("rpc(): a resolver failure's error text carries no userinfo", res is None and "SECRETUSER" not in (err or "") and "SECRETPASS" not in (err or ""))

    seen = {}

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen["auth"] = self.headers.get("Authorization")
            seen["path"] = self.path
            seen["host"] = self.headers.get("Host")
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            payload = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0xaa36a7"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *a):
            pass

    try:
        server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    except OSError as e:
        server = None
        check(f"loopback server could start (loopback unavailable: {type(e).__name__})", False)
    if server is not None:
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            res, err, _ = rpc(f"http://{ui_user}:{enc_pass}@127.0.0.1:{port}/v2/SECRETKEYPATH", "eth_chainId", [])
        finally:
            server.shutdown()
            server.server_close()
        check("rpc(): a basic-auth provider on loopback answers (not falsely REJECTED)", res == "0xaa36a7" and err is None)
        check("loopback server received the decoded credentials as an Authorization: Basic header", seen.get("auth") == want_auth)
        check(
            "loopback server saw the path but no userinfo in the Host header",
            seen.get("path") == "/v2/SECRETKEYPATH" and seen.get("host") == f"127.0.0.1:{port}",
        )

    # -- fix round 4: a non-UTF-8 --env-file exits 2 --
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(good_spec, f)
        env_utf8_spec_path = f.name
    with tempfile.NamedTemporaryFile("wb", suffix=".env", delete=False) as f:
        f.write(b"SEPOLIA_RPC_URL=https://h.example/v2/SECRET\xff\xfeKEY\n")
        bad_env_path = f.name
    try:
        err_buf = io.StringIO()
        with contextlib.redirect_stderr(err_buf):
            rc = main(["--env-file", bad_env_path, env_utf8_spec_path])
        check("main(): a non-UTF-8 --env-file exits 2", rc == 2)
        check("main(): the non-UTF-8 --env-file message quotes none of its contents", "SECRET" not in err_buf.getvalue())
    finally:
        os.unlink(env_utf8_spec_path)
        os.unlink(bad_env_path)

    # -- fix round 4: a non-http(s) scheme never echoes the scheme text --
    res, err, _ = rpc("SECRETUSERxyz:pw@host.example/v2/k", "eth_chainId", [])
    check("rpc(): a scheme-less 'user:pass@host' URL is refused without echoing the username", res is None and "SECRETUSER" not in (err or ""))


    # -- fix round 5: the Authorization header is never forwarded on a redirect --
    redirect_seen = []

    class _RedirectHandler(http.server.BaseHTTPRequestHandler):
        def _handle(self):
            redirect_seen.append((self.path, self.headers.get("Authorization")))
            if self.path.startswith("/v2/"):
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{self.server.server_address[1]}/redirected")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x1"}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = _handle

        def log_message(self, *a):
            pass

    def _serve(handler_cls):
        srv = http.server.HTTPServer(("127.0.0.1", 0), handler_cls)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv

    try:
        rsrv = _serve(_RedirectHandler)
    except OSError as e:
        rsrv = None
        check(f"loopback redirect server could start ({type(e).__name__})", False)
    if rsrv is not None:
        try:
            rport = rsrv.server_address[1]
            res, err, _ = rpc(f"http://{ui_user}:{enc_pass}@127.0.0.1:{rport}/v2/SECRETKEYPATH", "eth_chainId", [])
        finally:
            rsrv.shutdown()
            rsrv.server_close()
        check(
            "redirect: first hop carries the Basic header, the same-host redirected hop carries none",
            res == "0x1" and len(redirect_seen) == 2
            and redirect_seen[0] == ("/v2/SECRETKEYPATH", want_auth)
            and redirect_seen[1] == ("/redirected", None),
        )

    # -- fix round 5: proxy env vars are ignored unless --use-env-proxy --
    hits = {"target": [], "proxy": []}

    def _jsonrpc_handler(bucket):
        class _H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                hits[bucket].append(self.path)
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                payload = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0xaa36a7"}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass
        return _H

    try:
        tsrv = _serve(_jsonrpc_handler("target"))
        psrv = _serve(_jsonrpc_handler("proxy"))
    except OSError as e:
        tsrv = psrv = None
        check(f"loopback target/proxy servers could start ({type(e).__name__})", False)
    if tsrv is not None and psrv is not None:
        proxy_vars = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "no_proxy", "NO_PROXY")
        saved_env = {k: os.environ.get(k) for k in proxy_vars}
        target_url = f"http://127.0.0.1:{tsrv.server_address[1]}/v2/SECRETKEYPATH"
        proxy_url = f"http://127.0.0.1:{psrv.server_address[1]}"
        try:
            for k in proxy_vars:
                os.environ.pop(k, None)
            os.environ["http_proxy"] = proxy_url
            os.environ["HTTP_PROXY"] = proxy_url

            set_proxy_mode(False)
            res, err, _ = rpc(target_url, "eth_chainId", [])
            check(
                "proxy: default mode ignores http_proxy and goes straight to the provider",
                res == "0xaa36a7" and hits["target"] == ["/v2/SECRETKEYPATH"] and hits["proxy"] == [],
            )

            set_proxy_mode(True)
            hits["target"].clear()
            res, err, _ = rpc(target_url, "eth_chainId", [])
            check(
                "proxy: env-proxy mode sends the request (full URL, key included) to http_proxy",
                res == "0xaa36a7" and hits["target"] == [] and hits["proxy"] == [target_url],
            )

            # the CLI flag wires the switch: main() without and with --use-env-proxy
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                json.dump({"chains": good_spec["chains"],
                           "candidates": [{"chain": "sepolia", "provider": "p", "url": target_url}]}, f)
                proxy_spec_path = f.name
            try:
                for flag, want_proxy in (([], False), (["--use-env-proxy"], True)):
                    hits["target"].clear()
                    hits["proxy"].clear()
                    out_buf, err_buf = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(out_buf), contextlib.redirect_stderr(err_buf):
                        rc = main(flag + [proxy_spec_path])
                    label = "with --use-env-proxy" if want_proxy else "by default"
                    check(
                        f"main(): {label} the proxy is {'used' if want_proxy else 'never contacted'}",
                        rc in (0, 1) and (bool(hits["proxy"]) == want_proxy) and (bool(hits["target"]) != want_proxy),
                    )
                    if want_proxy:
                        check("main(): --use-env-proxy prints the proxy warning", "--use-env-proxy" in err_buf.getvalue())
            finally:
                os.unlink(proxy_spec_path)
        finally:
            set_proxy_mode(False)
            for k, v in saved_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            for srv in (tsrv, psrv):
                srv.shutdown()
                srv.server_close()

    print()
    print("SELF-TEST " + ("PASSED" if ok else "FAILED"))
    return ok


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def _run(args):
    """The actual probe run, isolated from main()'s top-level safety net
    below only by being a separate function -- every exception path here
    is still expected to be handled locally where possible (see the
    per-candidate try/excepts), with that outer net as the last resort."""
    if args.self_test:
        return 0 if self_test() else 1

    set_proxy_mode(args.use_env_proxy)
    if args.use_env_proxy:
        print("WARNING: --use-env-proxy: any configured HTTP(S) proxy will see full provider URLs, "
              "including API keys", file=sys.stderr)

    if not args.input:
        print("ERROR: an input JSON file is required unless --self-test is given", file=sys.stderr)
        return 2

    if args.confirmations < 0:
        print(f"ERROR: --confirmations must be >= 0 (got {args.confirmations})", file=sys.stderr)
        return 2

    try:
        with open(args.input, encoding="utf-8") as f:
            raw_text = f.read()
    except OSError as e:
        print(f"ERROR: cannot read input file {args.input!r}: {e.strerror or e}", file=sys.stderr)
        return 2
    except UnicodeDecodeError:
        print(f"ERROR: input file {args.input!r} is not valid UTF-8", file=sys.stderr)
        return 2
    try:
        spec = json.loads(raw_text)
    except json.JSONDecodeError as e:
        print(f"ERROR: input file {args.input!r} is not valid JSON: {e}", file=sys.stderr)
        return 2

    spec_errors = validate_spec(spec)
    if spec_errors:
        print("ERROR: invalid input spec:", file=sys.stderr)
        for e in spec_errors:
            print(f"  - {e}", file=sys.stderr)
        return 2

    chains = spec["chains"]
    candidates = spec["candidates"]
    if args.chain:
        candidates = [c for c in candidates if c.get("chain") == args.chain]
        if not candidates:
            print(f"ERROR: --chain {args.chain!r} matched no candidates", file=sys.stderr)
            return 1

    try:
        env = build_env_lookup(args.env_file, os.environ)
    except OSError as e:
        print(f"ERROR: cannot read env file {args.env_file!r}: {e.strerror or e}", file=sys.stderr)
        return 2
    except UnicodeDecodeError:
        # No detail from the exception: its message quotes raw bytes of
        # the file, which holds the candidate URLs.
        print(f"ERROR: env file {args.env_file!r} is not valid UTF-8", file=sys.stderr)
        return 2

    chain_order = []
    for c in candidates:
        if c["chain"] not in chain_order:
            chain_order.append(c["chain"])

    results = []
    for chain_name in chain_order:
        chain_cfg = chains[chain_name]
        chain_candidates = [c for c in candidates if c["chain"] == chain_name]

        resolved = []
        for cand in chain_candidates:
            provider = cand.get("provider", "?")
            url, err = resolve_candidate_url(cand, env)
            if url is None:
                r = _new_result(chain_name, provider, None)
                r["errors"].append(err)
                print(json.dumps(r), flush=True)
                results.append(r)
                continue
            resolved.append((cand, provider, url))

        head_infos = {}
        for cand, provider, url in resolved:
            try:
                head_infos[id(cand)] = fetch_head_info(url)
            except Exception as e:  # noqa: BLE001 -- a malformed candidate URL must never abort the whole chain
                head_infos[id(cand)] = {
                    "chain_id": None, "chain_id_err": f"crashed: {type(e).__name__}",
                    "head": None, "head_err": f"crashed: {type(e).__name__}", "head_ms": None,
                }

        scan_end, max_head = compute_scan_window(list(head_infos.values()), chain_cfg["chain_id"], args.confirmations)
        for hi in head_infos.values():
            hi["max_head"] = max_head

        for cand, provider, url in resolved:
            hi = head_infos[id(cand)]
            try:
                r = probe(chain_name, chain_cfg, provider, url, hi, scan_end, args.confirmations)
            except Exception as e:  # noqa: BLE001 -- one candidate must never abort the run
                r = _new_result(chain_name, provider, safe_host(url))
                r["errors"].append(f"probe crashed: {type(e).__name__}")
            print(json.dumps(r), flush=True)
            results.append(r)

    summary = print_summary(results, args.confirmations)
    return 0 if has_certified(summary) else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    ap.add_argument("input", nargs="?", help="path to a chains/candidates JSON file")
    ap.add_argument(
        "--env-file",
        help="KEY=VALUE file loaded into the url_env lookup; an already-set environment "
             "variable always takes precedence over a value from this file (dotenv override=False)",
    )
    ap.add_argument("--chain", help="only probe candidates for this chain name")
    ap.add_argument(
        "--confirmations", type=int, default=DEFAULT_CONFIRMATIONS,
        help=f"blocks subtracted from the shared per-chain min head before scanning (default {DEFAULT_CONFIRMATIONS}; must be >= 0)",
    )
    ap.add_argument(
        "--use-env-proxy", action="store_true",
        help="honour http_proxy/https_proxy/HTTP(S)_PROXY (ignored by default). The proxy will then "
             "see full provider URLs, including API keys in the path or query, and any "
             "userinfo credentials (sent as an Authorization header)",
    )
    ap.add_argument("--self-test", action="store_true", help="run built-in tests on canned data; no external network access "
                         "(mocks plus a loopback HTTP server on 127.0.0.1)")
    args = ap.parse_args(argv)

    # Last-resort safety net: every specific failure mode above already has
    # its own handling, but nothing may ever escape as an unhandled
    # exception -- Python's default excepthook prints the exception's
    # str(), which can embed a URL/key (as it did for the malformed-URL
    # crash this round fixes at its source). SystemExit (argparse's own
    # --help/error exit, or an explicit sys.exit) is re-raised untouched;
    # KeyboardInterrupt exits 130 with no traceback; anything else prints
    # only the exception's TYPE name and exits 3.
    try:
        return _run(args)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        return 130
    except BaseException as e:  # noqa: BLE001 -- intentionally broad: this is the last line of defense
        print(f"ERROR: probe crashed: {type(e).__name__}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
