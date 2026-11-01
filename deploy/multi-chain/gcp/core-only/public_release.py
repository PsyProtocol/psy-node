#!/usr/bin/env python3
"""Build and check the public side of a release: trust setup archive, config page, served bundles.

Everything here is derived from the L1 deployment documents and the public site description of the release
(public.json); no address is typed in. Network access goes through the fetch functions passed in, so a test
never touches the internet.
"""
import copy
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tarfile
import urllib.error
import urllib.request

import release_lock
from release_lock import require

PUBLIC_FILE = "public.json"
PUBLIC_SETUP_FILES = tuple(f"{prefix}{name}_groth16.bin" for prefix in ("", "deposit_append/", "withdrawal_claim/")
                           for name in ("circuit", "pk", "vk"))
FETCH_SECONDS = 30
ADDRESS = re.compile(r"0x[0-9a-fA-F]{40}")
# Three reference shapes: tags in the page; "./x.js" or "../x.js" relative to the chunk that holds it; and Vite's
# preload map entries "assets/x.js" or "/assets/x.js", which are relative to the site root.
SCRIPT_REFERENCE = re.compile(r"""(?:src|href)=["']([^"']+\.js)["']|["'](\.{1,2}/[A-Za-z0-9_.-]+\.js)["']|["'](/?assets/[A-Za-z0-9_.-]+\.js)["']""")
BUNDLE_FILE_LIMIT = 300
TRUST_ARCHIVE_LEVEL = 6
CREDENTIAL_NAMES = ("CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN")
CONTRACT_NAMES = (("AddressesProvider", "PsyAddressesProvider"), ("Bridge", "Bridge"), ("StateManager", "StateManager"),
                  ("Router", "Router"), ("ERC20Gateway", "ERC20Gateway"), ("ETHGateway", "ETHGateway"),
                  ("Multicall3", "Multicall3"), ("WETH", "WETH9"), ("TokenFaucetManager", "TokenFaucetManager"))
PUBLIC_KEYS = ("version", "environment", "l1_primary", "chains", "services", "frontends", "config_site", "trust_setup",
               "sites", "bundle_sites", "workflows", "dapp", "wallet")


def read_public(release_dir):
    document = release_lock.read_document(Path(release_dir) / PUBLIC_FILE)
    require(set(document) == set(PUBLIC_KEYS), "public.json fields differ from the expected set")
    require(set(document["chains"]) == set(release_lock.CHAINS), "public.json chains differ from the release chains")
    return document


def sha256_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read_cloudflare_env(path):
    """Account id and API token from a private `export NAME=value` file; the file must not be readable by others."""
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and not path.stat().st_mode & 0o077,
            "the credentials file must be a regular file readable only by its owner")
    values = {}
    for line in path.read_text().splitlines():
        name, equals, value = line.strip().removeprefix("export ").partition("=")
        if equals and name in CREDENTIAL_NAMES:
            values[name] = value.strip().strip("'\"")
    require(all(values.get(name) for name in CREDENTIAL_NAMES), "the credentials file lacks the Cloudflare account or API entry")
    return values


# ---- trust setup archive ----

def verify_setup_files(keystore, setup_manifest):
    """The nine public files exist and match the setup manifest; nothing else from the keystore is touched."""
    expected = setup_manifest["files"]
    for name in PUBLIC_SETUP_FILES:
        require(name in expected, f"setup manifest lacks {name}")
        path = Path(keystore) / name
        require(path.is_file() and not path.is_symlink(), f"missing trust setup file: {name}")
        require(path.stat().st_size == expected[name]["size"] and file_sha256(path) == expected[name]["sha256"],
                f"trust setup file differs from the setup manifest: {name}")


def build_trust_archive(keystore, setup_manifest, output_dir, archive_name):
    """A reproducible tar.gz of exactly the nine public files under keystore/, plus its .sha256 file."""
    verify_setup_files(keystore, setup_manifest)
    output_dir = Path(output_dir)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    archive = output_dir / archive_name
    temporary = archive.with_name(archive.name + ".partial")
    with open(temporary, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=TRUST_ARCHIVE_LEVEL, mtime=0) as zipped, \
            tarfile.open(fileobj=zipped, mode="w") as bundle:
        for name in PUBLIC_SETUP_FILES:
            member = tarfile.TarInfo("keystore/" + name)
            member.size, member.mode, member.mtime = (Path(keystore) / name).stat().st_size, 0o644, 0
            with open(Path(keystore) / name, "rb") as stream:
                bundle.addfile(member, stream)
    os.replace(temporary, archive)
    digest = file_sha256(archive)
    (output_dir / (archive_name + ".sha256")).write_text(f"{digest}  {archive_name}\n")
    return archive, digest


def archive_members(archive):
    with tarfile.open(archive, "r:gz") as bundle:
        return sorted(member.name for member in bundle.getmembers())


# ---- config document ----

def read_documents(state, state_dir):
    """The three L1 deployment summaries recorded by step 69, each checked against its recorded hash."""
    documents = {}
    for chain in release_lock.CHAINS:
        row = state["chains"][chain]["summary"]
        raw = Path(row["path"]).read_bytes()
        require(sha256_bytes(raw) == row["sha256"], f"{chain}: deployment document differs from its recorded hash")
        documents[chain] = json.loads(raw)
    return documents


def chain_entry(public, chain, document):
    protocol = document["protocol"]
    tokens = [{"symbol": token["symbol"], "decimals": token["decimals"], "l1_address": token["l1Address"],
               "l2_contract_id": token["l2TokenContractId"]} for token in protocol["tokens"].values()]
    return {"network": chain, "bridge_chain": protocol["chain"]["bridgeChain"], "chain_id": int(protocol["chain"]["l1ChainId"]),
            "chain_index": int(protocol["chain"]["l1ChainIndex"]), "name": protocol["chain"]["name"],
            "short_name": protocol["chain"]["shortName"], "native_currency": protocol["chain"]["nativeCurrency"],
            "rpc_url": public["chains"][chain]["rpc_url"], "explorer_url": public["chains"][chain].get("explorer_url", protocol["chain"]["defaultExplorerUrl"]),
            "gas_faucet_url": public["chains"][chain]["gas_faucet_url"], "contracts": dict(document["core"]),
            "tokens": tokens, "deployment_block": int(document["deploymentBlock"])}


def build_config(public, documents, trust_url, trust_sha256, installer_url, generated_at):
    """config.json from the L1 documents; the primary chain also fills the legacy single-chain fields."""
    entries = [chain_entry(public, chain, documents[chain]) for chain in release_lock.CHAINS]
    primary = next(entry for entry in entries if entry["network"] == public["l1_primary"]["network"])
    token = {item["symbol"]: item for item in primary["tokens"]}
    return {
        "generated_at": generated_at, "environment": public["environment"],
        "l1": {"network": primary["network"], "chain_id": primary["chain_id"], "chain_name": public["l1_primary"]["chain_name"],
               "chain_short_name": public["l1_primary"]["chain_short_name"], "rpc_url": primary["rpc_url"],
               "explorer_url": primary["explorer_url"]},
        "l1_chains": entries, "services": copy.deepcopy(public["services"]), "frontends": copy.deepcopy(public["frontends"]),
        "trust_setup": {"archive_url": trust_url, "install_script_url": installer_url, "sha256": trust_sha256,
                        "install_target": "~/.psy"},
        "contracts": [{"name": name, "address": primary["contracts"][key]} for name, key in CONTRACT_NAMES],
        "tokens": [{"symbol": "PSY", "name": "Psy Token", "address": token["PSY"]["l1_address"], "decimals": token["PSY"]["decimals"]},
                   {"symbol": "USDT", "name": "USDT", "address": token["USDT"]["l1_address"], "decimals": token["USDT"]["decimals"]}]}


def config_addresses(config):
    """Every contract and token address in a config document, as {label: lowercase address}."""
    found = {}
    for entry in config["l1_chains"]:
        for name, address in entry["contracts"].items():
            found[f"{entry['network']}.{name}"] = address.lower()
        for token in entry["tokens"]:
            found[f"{entry['network']}.token.{token['symbol']}"] = token["l1_address"].lower()
    for row in config["contracts"]:
        found[f"primary.{row['name']}"] = row["address"].lower()
    for token in config["tokens"]:
        found[f"primary.token.{token['symbol']}"] = token["address"].lower()
    return found


def document_addresses(documents, primary):
    found = {}
    for chain, document in documents.items():
        for name, address in document["core"].items():
            found[f"{chain}.{name}"] = address.lower()
        for token in document["protocol"]["tokens"].values():
            found[f"{chain}.token.{token['symbol']}"] = token["l1Address"].lower()
    document = documents[primary]
    for name, key in CONTRACT_NAMES:
        found[f"primary.{name}"] = document["core"][key].lower()
    for token in document["protocol"]["tokens"].values():
        found[f"primary.token.{token['symbol']}"] = token["l1Address"].lower()
    return found


def check_config_matches_documents(config, documents, primary):
    """Refuse a config whose address set or any single address differs from the L1 documents."""
    want, have = document_addresses(documents, primary), config_addresses(config)
    require(set(want) == set(have), "config address set differs from the L1 documents")
    wrong = sorted(label for label in want if want[label] != have[label])
    require(not wrong, "config address differs from the L1 documents: " + ", ".join(wrong[:5]))
    for entry in config["l1_chains"]:
        require(entry["deployment_block"] == int(documents[entry["network"]]["deploymentBlock"]),
                f"{entry['network']}: deployment block differs from the L1 documents")


def render_installer(archive_url, archive_name, sha256):
    paths = "\n".join("keystore/" + name for name in PUBLIC_SETUP_FILES)
    return (INSTALLER_TEMPLATE.replace("@URL@", archive_url).replace("@SHA@", sha256)
            .replace("@ARCHIVE@", archive_name).replace("@PATHS@", paths))


HEADERS = """/*
  Access-Control-Allow-Origin: *
  Cache-Control: no-store

/config.json
  Content-Type: application/json; charset=utf-8
  Access-Control-Allow-Origin: *
  Cache-Control: no-store

/install-groth16-trust-setup.sh
  Content-Type: text/x-shellscript; charset=utf-8
  Access-Control-Allow-Origin: *
  Cache-Control: no-store
"""
ROBOTS = "User-agent: *\nDisallow:\n"
INSTALLER_TEMPLATE = r'''#!/usr/bin/env bash
set -euo pipefail

url="@URL@"
expected_sha="@SHA@"
target="$HOME/.psy"
tmp_dir="$(mktemp -d)"
archive="$tmp_dir/@ARCHIVE@"

cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

if command -v curl >/dev/null 2>&1; then
  curl -fL --retry 3 --connect-timeout 10 "$url" -o "$archive"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$archive" "$url"
else
  echo "curl or wget is required" >&2
  exit 1
fi

if [ -n "$expected_sha" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    actual_sha="$(sha256sum "$archive" | awk '{print $1}')"
  else
    actual_sha="$(shasum -a 256 "$archive" | awk '{print $1}')"
  fi
  if [ "$actual_sha" != "$expected_sha" ]; then
    echo "sha256 mismatch: expected $expected_sha, got $actual_sha" >&2
    exit 1
  fi
fi

conflicts=()
while IFS= read -r path; do
  [ -e "$target/$path" ] && conflicts+=("$target/$path")
done <<'PATHS'
@PATHS@
PATHS

if [ "${#conflicts[@]}" -gt 0 ]; then
  echo "The following trust setup files already exist:"
  printf "  %s\n" "${conflicts[@]}"
  printf "Overwrite them? [y/N] "
  read -r answer
  case "$answer" in
    y|Y|yes|YES) ;;
    *)
      echo "Install cancelled; existing files were not changed."
      exit 1
      ;;
  esac
fi

mkdir -p "$target"
tar -xzf "$archive" -C "$target"
while IFS= read -r path; do
  chmod 0600 "$target/$path"
done <<'PATHS'
@PATHS@
PATHS

echo "Installed Groth16 trust setup into $target/keystore"
'''


def build_site(page_source, output_dir, config, installer):
    """The config page directory: the page sources, then the generated files, in a directory that did not exist."""
    output_dir = Path(output_dir)
    require(Path(page_source, "index.html").is_file(), "config page source has no index.html")
    if output_dir.exists():
        shutil.rmtree(output_dir)
    shutil.copytree(page_source, output_dir)
    (output_dir / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    (output_dir / "_headers").write_text(HEADERS)
    (output_dir / "robots.txt").write_text(ROBOTS)
    (output_dir / "install-groth16-trust-setup.sh").write_text(installer)
    return output_dir


# ---- live reads ----

def fetch(url, limit=None, method="GET"):
    """(status, body bytes) with no redirects followed beyond the default handler; network errors are (None, b'')."""
    request = urllib.request.Request(url, method=method, headers={"User-Agent": "psy-deploy-verify", "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_SECONDS) as response:
            return response.status, response.read(limit) if limit else response.read()
    except urllib.error.HTTPError as error:
        with error:
            return error.code, b""
    except (OSError, ValueError):
        return None, b""


def head_length(url):
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "psy-deploy-verify"})
    try:
        with urllib.request.urlopen(request, timeout=FETCH_SECONDS) as response:
            return response.status, int(response.headers.get("Content-Length", "-1"))
    except urllib.error.HTTPError as error:
        with error:
            return error.code, -1
    except (OSError, ValueError):
        return None, -1


def bundle_texts(site_url, fetch_function=None):
    """The served page and every script reachable from it, lowercased; capped in file count.

    A "./x.js" reference is resolved against the chunk that holds it, a bare "assets/x.js" against the site root.
    """
    fetch_function = fetch_function or fetch
    root = site_url if site_url.endswith("/") else site_url + "/"
    status, page = fetch_function(site_url)
    require(status == 200, f"{site_url} did not answer 200")
    pending, seen, texts = [(site_url, page.decode("utf-8", errors="replace"))], {site_url}, []
    while pending:
        origin, text = pending.pop()
        texts.append(text.lower())
        for found in SCRIPT_REFERENCE.finditer(text):
            reference = next(group for group in found.groups() if group)
            bare = reference.lstrip("/").startswith("assets/") and not reference.startswith(".")
            url = urllib.request.urljoin(root if bare else origin, reference)
            if url in seen or not url.startswith(root) or len(seen) >= BUNDLE_FILE_LIMIT:
                continue
            seen.add(url)
            status, body = fetch_function(url)
            if status == 200:
                pending.append((url, body.decode("utf-8", errors="replace")))
    return texts


def check_bundle(site_url, new_addresses, old_addresses, fetch_function=None):
    """The served bundle holds the new PSY addresses ({label: address}) and none of the old ones (a list); returns counts."""
    text = "\n".join(bundle_texts(site_url, fetch_function))
    missing = sorted(label for label, address in new_addresses.items() if address not in text)
    require(not missing, f"{site_url} does not serve the new address: {', '.join(missing)}")
    stale = sorted(address for address in old_addresses if address not in new_addresses.values() and address in text)
    require(not stale, f"{site_url} still serves an address of the previous release: {', '.join(stale)}")
    return {"checked": len(new_addresses), "previous_release_addresses": len(old_addresses)}
