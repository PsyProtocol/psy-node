import { createHash } from "node:crypto";
import { describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
  applyPreparation,
  assertCompilerProvenance,
  assertEvmSdkPeer,
  assertPnpmLockfile,
  guardSquashPins,
  loadValidatedPack,
  pinsFromManifest,
  publishPackages,
  redact,
  replacePsyNodeRevs,
  validateCargoGraph,
  switchConsumers,
  validatePacked,
  type Pack,
  type PrepareFs,
  type PrepareRepository,
  type RegistryPackage,
  type Runner,
} from "./workspace-operations";
import { assertLocalCargoGraph, assertNoLocalDependencies, nodeCratePaths, nodeDependencies, parseBunLock, rewriteNodeDependencies } from "./workspace-dependencies";
import { assertBunLock, assertLocalPnpmLock, replaceDirectDependencies, switchLocal } from "./workspace-operations";
import { WORKSPACE_REPOS } from "./workspace-create";

const OLD = "7d6815d22728debbc71f6a928f85aa4b209ebf4f";
const NEXT = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TOPIC = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const root = join(import.meta.dir, "../..");

describe("Cargo psy-node pins", () => {
  it("rewrites all 36 declarations without changing aliases or features", () => {
    const counts = { "psy-compiler": 11, "psy-sdk": 10, "psy-services": 15 };
    for (const [repo, count] of Object.entries(counts)) {
      const text = readFileSync(join(root, repo, "Cargo.toml"), "utf8");
      const before = pinsFromManifest(text, repo);
      expect(before).toHaveLength(count);
      const rewritten = replacePsyNodeRevs(text, NEXT, repo);
      const after = pinsFromManifest(rewritten, repo);
      expect(after.map(pin => `${pin.table}.${pin.key}|${pin.url}|${JSON.stringify(pin.rest)}`)).toEqual(
        before.map(pin => `${pin.table}.${pin.key}|${pin.url}|${JSON.stringify(pin.rest)}`),
      );
      expect(after.every(pin => pin.rev === NEXT)).toBe(true);
      expect(rewritten).toBe(text.replace(
        /(\bgit\s*=\s*"https:\/\/github\.com\/PsyProtocol\/psy-node(?:\.git)?"[^}\n]*\brev\s*=\s*")[0-9a-f]{40}(?=")/g,
        `$1${NEXT}`,
      ));
    }
  });

  it("rejects a psy-node pin outside the recognized dependency tables", () => {
    const toml = `[target.'cfg(unix)'.dependencies]\npsy_vm = { git = "https://github.com/PsyProtocol/psy-node.git", rev = "${OLD}" }\n`;
    expect(() => pinsFromManifest(toml, "fixture")).toThrow(/not a recognized/);
  });
});

describe("resolved Cargo graph", () => {
  it("requires every resolve edge and the requested psy-node revision", () => {
    const rev = NEXT;
    const source = `git+https://github.com/PsyProtocol/psy-node.git?rev=${rev}#${rev}`;
    const metadata = JSON.stringify({
      packages: [
        { name: "app", version: "0.1.0", id: "app", source: null, dependencies: [{ name: "psy_vm", source }] },
        { name: "psy_vm", version: "0.1.0", id: "psy_vm", source, dependencies: [{ name: "added", source: "registry+https://github.com/rust-lang/crates.io-index" }] },
        { name: "added", version: "1.0.0", id: "added", source: "registry+https://github.com/rust-lang/crates.io-index", dependencies: [] },
      ],
      resolve: { nodes: [{ id: "app", deps: [{ pkg: "psy_vm" }] }, { id: "psy_vm", deps: [{ pkg: "added" }] }, { id: "added", deps: [] }] },
    });
    const lock = `[[package]]\nname = "psy_vm"\nversion = "0.1.0"\nsource = "${source}"\n`;
    expect(validateCargoGraph(metadata, lock, rev)).toEqual(["psy_vm@0.1.0"]);
    expect(() => validateCargoGraph(metadata.replaceAll(rev, OLD), lock, rev)).toThrow(/expected/);
  });
});

describe("squash pin guard", () => {
  const pin = (rev: string) => [{ repo: "psy-services", pins: [{ crate: "dependencies.psy_core", rev }, { crate: "dev-dependencies.psy_client_data", rev }] }];
  it("rejects a newly introduced pin that is not on the frozen node origin", () => {
    expect(() => guardSquashPins({
      source: pin(TOPIC), base: pin(OLD), nodeOriginBase: OLD, isOnNodeOrigin: rev => rev === OLD,
    })).toThrow(/unpublished pin/);
  });

  it("rejects a retained pin that names a topic-only node commit", () => {
    expect(() => guardSquashPins({
      source: pin(TOPIC), base: pin(TOPIC), nodeOriginBase: OLD, topicNodeCommits: [TOPIC], isOnNodeOrigin: () => false,
    })).toThrow(/retains topic-only/);
  });

  it("accepts an origin pin and reports an unchanged historical pin", () => {
    const historical = "cccccccccccccccccccccccccccccccccccccccc";
    const source = pin(OLD);
    source[0].pins[1].rev = historical;
    const base = pin(OLD);
    base[0].pins[1].rev = historical;
    const result = guardSquashPins({
      source,
      base,
      nodeOriginBase: OLD,
      topicNodeCommits: [TOPIC],
      isOnNodeOrigin: rev => rev === OLD,
    });
    expect(result.unchanged).toEqual([
      { repo: "psy-services", crate: "dependencies.psy_core", rev: OLD },
      { repo: "psy-services", crate: "dev-dependencies.psy_client_data", rev: historical },
    ]);
  });
});

describe("package publication", () => {
  it("checks all four registry versions before publishing any tarball", async () => {
    const calls: string[] = [];
    const packs = ["@psy-protocol/utils", "@psy-protocol/psy-sdk", "@psy-protocol/contract-sdk", "@psy-protocol/evm-wallet"].map((name, index): Pack => ({
      name, version: "9.9.9", path: `/tmp/${index}.tgz`, integrity: `sha512-pack${index}`, manifest: { name, version: "9.9.9" }, entries: [],
    }));
    const lookup = async (name: string): Promise<RegistryPackage | null> => {
      calls.push(`lookup ${name}`);
      if (name === "@psy-protocol/evm-wallet") return { version: "9.9.9", integrity: "sha512-other", tarball: "https://registry.npmjs.org/evm-wallet" };
      return null;
    };
    await expect(publishPackages(packs, "latest", lookup, command => {
      calls.push(command.join(" "));
      return { code: 0, out: "", err: "" };
    })).rejects.toThrow(/integrity/);
    expect(calls.some(call => call.startsWith("npm publish"))).toBe(false);
    expect(calls.filter(call => call.startsWith("lookup")).map(call => call.slice(7))).toEqual(packs.map(pack => pack.name));
  });
});

describe("consumer lock evidence", () => {
  const lock = {
    importers: { "apps/account": { dependencies: {
      "@psy-protocol/psy-sdk": { specifier: "9.9.9", version: "9.9.9" },
      "@psy-protocol/evm-wallet": { specifier: "9.9.9", version: "9.9.9(@psy-protocol/psy-sdk@9.9.9)" },
    } } },
    packages: {
      "@psy-protocol/psy-sdk@9.9.9": { resolution: { integrity: "sha512-sdk" } },
      "@psy-protocol/evm-wallet@9.9.9": { resolution: { integrity: "sha512-wallet" } },
    },
    snapshots: {
      "@psy-protocol/psy-sdk@9.9.9": {},
      "@psy-protocol/evm-wallet@9.9.9(@psy-protocol/psy-sdk@9.9.9)": { dependencies: { "@psy-protocol/psy-sdk": "9.9.9" } },
    },
  };
  const checks = [
    { importer: "apps/account", name: "@psy-protocol/psy-sdk", version: "9.9.9", integrity: "sha512-sdk" },
    { importer: "apps/account", name: "@psy-protocol/evm-wallet", version: "9.9.9", integrity: "sha512-wallet" },
  ];

  it("accepts the peer-suffixed snapshot when integrity matches", () => {
    expect(() => assertPnpmLockfile(Bun.YAML.stringify(lock), checks)).not.toThrow();
  });

  it("rejects registry integrity or peer snapshot drift", () => {
    const drifted = structuredClone(lock);
    drifted.packages["@psy-protocol/psy-sdk@9.9.9"].resolution.integrity = "sha512-other";
    expect(() => assertPnpmLockfile(Bun.YAML.stringify(drifted), checks)).toThrow(/integrity/);
    const unpaired = structuredClone(lock);
    unpaired.snapshots["@psy-protocol/psy-sdk@1.0.0"] = {};
    unpaired.snapshots["@psy-protocol/evm-wallet@9.9.9(@psy-protocol/psy-sdk@9.9.9)"].dependencies["@psy-protocol/psy-sdk"] = "1.0.0";
    expect(() => assertPnpmLockfile(Bun.YAML.stringify(unpaired), checks)).toThrow();
    const prefixed = structuredClone(lock);
    prefixed.importers["apps/account"].dependencies["@psy-protocol/psy-sdk"].version = "9.9.90";
    prefixed.snapshots["@psy-protocol/psy-sdk@9.9.90"] = {};
    expect(() => assertPnpmLockfile(Bun.YAML.stringify(prefixed), checks)).toThrow(/resolved/);
  });
});

describe("EVM wallet SDK compatibility", () => {
  it("accepts 2.0.9 and rejects 9.9.9 against the declared peer", () => {
    expect(() => assertEvmSdkPeer("2.0.9", "^2.0.0")).not.toThrow();
    expect(() => assertEvmSdkPeer("9.9.9", "^2.0.0")).toThrow(/incompatible/);
    expect(() => assertEvmSdkPeer("2.0.9", undefined)).toThrow(/missing peer range/);
    expect(() => assertEvmSdkPeer("2.0.9", "2.0.9")).not.toThrow();
    for (const range of ["not-a-range", "", "^2.0", "^02.0.0", ">=2.0.0", "^2.0.0 || ^3.0.0"]) {
      expect(() => assertEvmSdkPeer("2.0.9", range)).toThrow(/missing peer range|unsupported SDK peer range/);
    }
  });

  it("rejects incompatible published peers before accessing consumer repositories", async () => {
    await expect(switchConsumers("/nonexistent-peer-fixture", "9.9.9", true, async () => ({
      version: "9.9.9", integrity: "sha512-fixture", tarball: "https://registry.npmjs.org/fixture.tgz",
      peerDependencies: { "@psy-protocol/psy-sdk": "^2.0.0" },
    }), () => { throw new Error("must not run a resolver"); })).rejects.toThrow(/incompatible/);
  });
});

describe("packed archive contract", () => {
  it("requires a regular entrypoint file and the intended SDK peer", () => {
    const manifest = { name: "@psy-protocol/evm-wallet", version: "9.9.9", main: "dist/index.cjs", peerDependencies: { "@psy-protocol/psy-sdk": "^2.0.0" } };
    expect(() => validatePacked(manifest, "9.9.9", [{ name: "package/dist/index.cjs", type: "5" }], {}, { "@psy-protocol/psy-sdk": "^2.0.0" })).toThrow(/missing concrete/);
    expect(() => validatePacked(manifest, "9.9.9", [{ name: "package/dist/index.cjs", type: "0" }], {}, { "@psy-protocol/psy-sdk": "^2.0.0" })).toThrow(/incompatible/);
    expect(() => validatePacked({ ...manifest, version: "2.0.9" }, "2.0.9", [{ name: "package/dist/index.cjs", type: "0" }], {}, { "@psy-protocol/psy-sdk": "^2.0.0" })).not.toThrow();
    expect(() => validatePacked({ ...manifest, dependencies: { left: "workspace:*" } }, "9.9.9", [{ name: "package/dist/index.cjs", type: "0" }])).toThrow(/workspace:/);
    expect(() => assertCompilerProvenance("{}")).toThrow(/compilerRevision/);
    for (const header of ["Authorization: Bearer SECRET", "Authorization: Basic SECRET"]) {
      const redacted = redact(`failed ${header}`);
      expect(redacted).not.toContain("SECRET");
      expect(redacted).toContain("[redacted]");
    }
  });
});

describe("validated pack loading", () => {
  const name = "@psy-protocol/evm-wallet";
  const version = "2.0.9";

  function tarEntries(files: [string, string][]): Buffer {
    const blocks: Buffer[] = [];
    for (const [entry, text] of files) {
      const content = Buffer.from(text);
      const header = Buffer.alloc(512);
      header.write(entry, 0, 100, "utf8");
      header.write("0000644\0", 100, "utf8");
      header.write("0000000\0", 108, "utf8");
      header.write("0000000\0", 116, "utf8");
      header.write(`${content.length.toString(8).padStart(11, "0")}\0`, 124, "utf8");
      header.write("0", 156, "utf8");
      header.write("ustar\0", 257, "utf8");
      header.write("00", 263, "utf8");
      header.write("        ", 148, "utf8");
      let checksum = 0;
      for (const byte of header) checksum += byte;
      header.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, "utf8");
      blocks.push(header, content, Buffer.alloc(Math.ceil(content.length / 512) * 512 - content.length));
    }
    blocks.push(Buffer.alloc(1024));
    return Buffer.concat(blocks);
  }

  function packedWalletOut(peer: string): string {
    const out = mkdtempSync(join(tmpdir(), "validated-pack-"));
    writeFileSync(join(out, `psy-protocol-evm-wallet-${version}.tgz`), gzipSync(tarEntries([
      ["package/package.json", JSON.stringify({
        name,
        version,
        main: "dist/index.cjs",
        peerDependencies: { "@psy-protocol/psy-sdk": peer },
      })],
      ["package/dist/index.cjs", "module.exports = {};\n"],
    ])));
    return out;
  }

  it("loads exact and caret 2.0.x peers on a compatible 2.0.9 tarball", () => {
    for (const peer of ["2.0.9", "^2.0.0", "^2.0.9"]) {
      const pack = loadValidatedPack(packedWalletOut(peer), name, version);
      expect(pack.name).toBe(name);
      expect(pack.version).toBe(version);
      expect(pack.integrity).toStartWith("sha512-");
      expect(pack.manifest.peerDependencies?.["@psy-protocol/psy-sdk"]).toBe(peer);
    }
  });

  it("rejects a tarball whose SDK peer is incompatible with the version", () => {
    expect(() => loadValidatedPack(packedWalletOut("^2.1.0"), name, version)).toThrow(/incompatible/);
  });
});

describe("workspace startup without the sibling SDK", () => {
  it("loads workspace commands when the provenance module is absent", () => {
    const dir = mkdtempSync(join(tmpdir(), "workspace-ops-"));
    mkdirSync(join(dir, "scripts"), { recursive: true });
    copyFileSync(join(import.meta.dir, "workspace.ts"), join(dir, "scripts/workspace.ts"));
    copyFileSync(join(import.meta.dir, "workspace-create.ts"), join(dir, "scripts/workspace-create.ts"));
    copyFileSync(join(import.meta.dir, "workspace-operations.ts"), join(dir, "scripts/workspace-operations.ts"));
    copyFileSync(join(import.meta.dir, "workspace-dependencies.ts"), join(dir, "scripts/workspace-dependencies.ts"));
    const result = spawnSync("bun", [join(dir, "scripts/workspace.ts"), "--help"], { encoding: "utf8" });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("status");
    expect(result.stdout).toContain("deps use-local");
    expect(result.stdout).toContain("packages publish");
    expect(result.stdout).not.toContain("workspace-release.ts");
    expect(`${result.stdout}${result.stderr}`).not.toContain("compiler-provenance");
  });
});

describe("local dependency cutover", () => {
  it("maps all 36 declarations by actual package and reverses to an explicit revision", () => {
    const crates = nodeCratePaths(join(root, "psy-node"));
    let count = 0;
    for (const repo of ["psy-compiler", "psy-sdk", "psy-services"]) {
      const directory = join(root, repo);
      const original = readFileSync(join(directory, "Cargo.toml"), "utf8");
      const local = rewriteNodeDependencies(original, directory, crates);
      const before = nodeDependencies(original);
      const after = nodeDependencies(local);
      count += after.length;
      for (let i = 0; i < after.length; i++) {
        expect(after[i].package).toBe(before[i].package);
        expect(after[i].value.features).toEqual(before[i].value.features);
        expect(after[i].value["default-features"]).toEqual(before[i].value["default-features"]);
        expect(after[i].value.git).toBeUndefined();
      }
      const published = nodeDependencies(rewriteNodeDependencies(local, directory, crates, NEXT));
      expect(published.every(dep => dep.value.rev === NEXT && !dep.value.path)).toBe(true);
      expect(published.map(dep => dep.value.git)).toEqual(before.map(dep => dep.value.git));
    }
    expect(count).toBe(36);
  });

  it("preserves patches and rejects mixed direct sources", () => {
    const directory = mkdtempSync(join(tmpdir(), "cohort-crates-"));
    const crate = join(directory, "psy-node/client");
    mkdirSync(crate, { recursive: true });
    const consumer = join(directory, "psy-sdk");
    mkdirSync(consumer);
    const crates = new Map([["actual", crate]]);
    const declaration = `alias = { git = "https://github.com/PsyProtocol/psy-node", rev = "${OLD}", package = "actual", features = ["one", "two"], default-features = false }`;
    const patch = '\n[patch.crates-io]\nunrelated = { path = "../elsewhere" }\n';
    const text = `[dependencies]\n${declaration}\n${patch}`;
    const changed = rewriteNodeDependencies(text, consumer, crates);
    expect(changed.endsWith(patch)).toBe(true);
    expect(nodeDependencies(changed)[0].value.features).toEqual(["one", "two"]);
    expect(() => rewriteNodeDependencies(text.replace(patch, '\nother = { package = "actual", path = "../psy-node/client" }\n'), consumer, crates)).toThrow(/mixed/);
  });

  it("rejects local graph packages from git and missing resolve edges", () => {
    const directory = mkdtempSync(join(tmpdir(), "cohort-graph-"));
    const crates = new Map([["actual", directory]]);
    const metadata = { packages: [{ id: "actual", name: "actual", source: null as string | null, manifest_path: join(directory, "Cargo.toml") }], resolve: { nodes: [{ id: "actual", deps: [] }] } };
    const lock = '[[package]]\nname = "actual"\nversion = "0.1.0"\n';
    expect(assertLocalCargoGraph(JSON.stringify(metadata), lock, crates, ["actual"], true)).toEqual(["actual"]);
    metadata.packages[0].source = `git+https://github.com/PsyProtocol/psy-node?rev=${OLD}`;
    expect(() => assertLocalCargoGraph(JSON.stringify(metadata), lock, crates, ["actual"], true)).toThrow(/mixed/);
  });

  it("parses Bun JSONC without corrupting comment-like strings", () => {
    const text = '{ // comment\n "url": "https://example.test/a,}", "array": [1,2,], }';
    expect(parseBunLock(text)).toEqual({ url: "https://example.test/a,}", array: [1, 2] });
    const name = "@psy-protocol/psy-sdk";
    const lock = `{ "workspaces": { "": { "dependencies": { "${name}": "2.0.8", }, }, }, "packages": { "${name}": ["${name}@2.0.8", "", {}, "sha512-real",], }, }`;
    expect(() => assertBunLock(lock, { [name]: "2.0.8" }, { [name]: "sha512-real" })).not.toThrow();
    expect(() => assertBunLock(lock, { [name]: "2.0.8" }, { [name]: "sha512-wrong" })).toThrow(/integrity/);
  });

  it("guards committed local manifests and lock entries, not product-ui", () => {
    expect(() => assertNoLocalDependencies("psy-sdk", "Cargo.toml", '[dependencies]\nalias = { package = "actual", path = "../psy-node/client" }')).toThrow(/local node/);
    for (const path of ["package.json", "apps/account/package.json"]) expect(() => assertNoLocalDependencies("psy-dapp", path, JSON.stringify({ dependencies: { "@psy-protocol/psy-sdk": "file:../psy-sdk/psy-ts-sdk/packages/psy-sdk" } }))).toThrow(/local SDK/);
    expect(() => assertNoLocalDependencies("psy-dapp", "package.json", JSON.stringify({ dependencies: { "@psy/product-ui": "file:../../product-ui" } }))).not.toThrow();
    expect(() => assertNoLocalDependencies("psy-dapp", "pnpm-lock.yaml", 'packages:\n  "@psy-protocol/psy-sdk@file:../sdk": {}\n')).toThrow(/local SDK/);
  });

  it("rewrites direct dependencies only and validates local pnpm identity", () => {
    const name = "@psy-protocol/psy-sdk";
    const spec = "file:../psy-sdk/psy-ts-sdk/packages/psy-sdk";
    const text = JSON.stringify({ dependencies: { [name]: "2.0.8", untouched: "1.0.0" }, scripts: { prepare: "must-not-run" } });
    expect(JSON.parse(replaceDirectDependencies(text, { [name]: spec }, "fixture")).scripts.prepare).toBe("must-not-run");
    const lock = { importers: { ".": { dependencies: { [name]: { specifier: spec, version: spec } } } }, packages: { [`${name}@${spec}`]: { resolution: { type: "directory", directory: spec.slice(5) } } }, snapshots: { [`${name}@${spec}`]: {} } };
    expect(() => assertLocalPnpmLock(Bun.YAML.stringify(lock), [{ importer: ".", name, spec, directory: spec.slice(5) }])).not.toThrow();
    lock.importers["."].dependencies[name].version = "2.0.8";
    expect(() => assertLocalPnpmLock(Bun.YAML.stringify(lock), [{ importer: ".", name, spec, directory: spec.slice(5) }])).toThrow(/sibling/);
  });

  it("requires explicit apply before installation", () => {
    expect(() => switchLocal("/not-a-workspace", false, true)).toThrow(/--install requires --apply/);
  });

  function cohortFixture(): { directory: string; git: (repo: string, ...args: string[]) => void } {
    const directory = mkdtempSync(join(tmpdir(), "cohort-local-"));
    const git = (repo: string, ...args: string[]): void => {
      const result = spawnSync("git", ["-C", join(directory, repo), ...args], { encoding: "utf8" });
      if (result.status !== 0) throw new Error(result.stderr);
    };
    for (const repo of WORKSPACE_REPOS) mkdirSync(join(directory, repo));
    const put = (path: string, text: string): void => {
      mkdirSync(join(directory, path, ".."), { recursive: true });
      writeFileSync(join(directory, path), text);
    };
    put("psy-node/Cargo.toml", '[workspace]\nmembers = ["client"]\n');
    put("psy-node/client/Cargo.toml", '[package]\nname = "actual"\nversion = "0.1.0"\n');
    for (const repo of ["psy-compiler", "psy-sdk", "psy-services"]) {
      put(`${repo}/Cargo.toml`, `[dependencies]\nalias = { package = "actual", git = "https://github.com/PsyProtocol/psy-node", rev = "${OLD}" }\n`);
      put(`${repo}/Cargo.lock`, 'version = 4\n');
    }
    for (const name of ["psy-sdk", "evm-wallet"]) {
      put(`psy-sdk/psy-ts-sdk/packages/${name}/package.json`, JSON.stringify({
        name: `@psy-protocol/${name}`, version: "2.0.8", files: ["dist"],
        main: "dist/index.cjs", module: "dist/index.mjs", types: "dist/index.d.ts",
        exports: { ".": { require: "./dist/index.cjs", import: "./dist/index.mjs", types: "./dist/index.d.ts" } },
        peerDependencies: name === "evm-wallet" ? { "@psy-protocol/psy-sdk": "^2.0.0" } : {},
      }));
      put(`psy-sdk/psy-ts-sdk/packages/${name}/dist/index.cjs`, "module.exports = {};\n");
      put(`psy-sdk/psy-ts-sdk/packages/${name}/dist/index.mjs`, "export {};\n");
      put(`psy-sdk/psy-ts-sdk/packages/${name}/dist/index.d.ts`, "export {};\n");
    }
    put("psy-wallet/package.json", JSON.stringify({ dependencies: { "@psy-protocol/psy-sdk": "2.0.8" } }));
    put("psy-dapp/package.json", '{"private":true}');
    for (const app of ["account", "bridge", "explorer", "ide"]) put(`psy-dapp/apps/${app}/package.json`, JSON.stringify({ dependencies: { "@psy-protocol/psy-sdk": "2.0.8", ...(app === "account" ? { "@psy-protocol/evm-wallet": "2.0.8" } : {}) } }));
    for (const path of ["psy-wallet/pnpm-lock.yaml", "psy-dapp/pnpm-lock.yaml", "psy-dapp/apps/account/pnpm-lock.yaml", "psy-dapp/apps/account/bun.lock"]) put(path, "{}\n");
    for (const repo of WORKSPACE_REPOS) {
      git(repo, "init", "-b", "feature/local");
      git(repo, "add", ".");
      git(repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-m", "fixture");
    }
    return { directory, git };
  }

  it("allows unrelated source dirt in preview but refuses owned dirt before resolution", () => {
    const { directory } = cohortFixture();
    writeFileSync(join(directory, "psy-node/source-change.rs"), "// unrelated\n");
    const original = readFileSync(join(directory, "psy-sdk/Cargo.toml"), "utf8");
    expect(switchLocal(directory, false)).toHaveLength(8);
    expect(readFileSync(join(directory, "psy-sdk/Cargo.toml"), "utf8")).toBe(original);
    writeFileSync(join(directory, "psy-dapp/apps/account/bun.lock"), "{ /* owned dirt */ }\n");
    expect(() => switchLocal(directory, true, false, () => { throw new Error("resolver must not run"); })).toThrow(/owned manifest\/lock is dirty/);
    expect(readFileSync(join(directory, "psy-sdk/Cargo.toml"), "utf8")).toBe(original);
  });

  it("rechecks owned bytes after tool preflight and before the first write", () => {
    const { directory } = cohortFixture();
    const manifest = join(directory, "psy-compiler/Cargo.toml");
    const before = readFileSync(manifest, "utf8");
    expect(() => switchLocal(directory, true, false, command => {
      if (command[0] === "cargo") writeFileSync(join(directory, "psy-wallet/package.json"), '{"changed":true}\n');
      return { code: 0, out: "10.34.5\n", err: "" };
    })).toThrow(/changed during preflight/);
    expect(readFileSync(manifest, "utf8")).toBe(before);
  });

  it("retains every rewritten manifest on resolver failure without staging", () => {
    const { directory, git } = cohortFixture();
    expect(() => switchLocal(directory, true, false, command => command[0] === "cargo" && command[1] === "metadata"
      ? { code: 1, out: "", err: "resolver failure" }
      : { code: 0, out: "10.34.5\n", err: "" })).toThrow(/partial local update/);
    expect(nodeDependencies(readFileSync(join(directory, "psy-compiler/Cargo.toml"), "utf8"))[0].value.path).toBe("../psy-node/client");
    expect(JSON.parse(readFileSync(join(directory, "psy-wallet/package.json"), "utf8")).dependencies["@psy-protocol/psy-sdk"]).toStartWith("file:");
    for (const repo of WORKSPACE_REPOS) git(repo, "diff", "--cached", "--exit-code");
  });

  it("rejects mismatched topic branches before any owned write", () => {
    const { directory, git } = cohortFixture();
    git("psy-services", "switch", "-c", "feature/other");
    expect(() => switchLocal(directory, false)).toThrow(/same topic/);
  });

  it("accepts pnpm 10.34.5 resolver-produced file peers and importer-relative workspace links", () => {
    // Observed with authored local packages, --offline, and no lifecycle scripts.
    const sdk = "@psy-protocol/psy-sdk";
    const evm = "@psy-protocol/evm-wallet";
    const selected = "file:../evm(@psy-protocol/psy-sdk@file:../sdk)";
    const lock = {
      importers: { "apps/account": { dependencies: {
        [sdk]: { specifier: "file:../../../sdk", version: "link:../../../sdk" },
        [evm]: { specifier: "file:../../../evm", version: selected },
      } } },
      packages: { [`${evm}@file:../evm`]: { resolution: { directory: "../evm", type: "directory" } }, [`${sdk}@file:../sdk`]: { resolution: { directory: "../sdk", type: "directory" } } },
      snapshots: { [`${evm}@${selected}`]: { dependencies: { [sdk]: "file:../sdk" } }, [`${sdk}@file:../sdk`]: {} },
    };
    const checks = [{ importer: "apps/account", name: sdk, spec: "file:../../../sdk", directory: "../sdk" }, { importer: "apps/account", name: evm, spec: "file:../../../evm", directory: "../evm" }];
    expect(() => assertLocalPnpmLock(Bun.YAML.stringify(lock), checks)).not.toThrow();
    lock.importers["apps/account"].dependencies[sdk].version = "file:../sdk";
    expect(() => assertLocalPnpmLock(Bun.YAML.stringify(lock), checks)).not.toThrow();
    lock.importers["apps/account"].dependencies[sdk].version = "link:../../wrong-sdk";
    expect(() => assertLocalPnpmLock(Bun.YAML.stringify(lock), checks)).toThrow(/sibling/);
  });

  it("accepts observed Bun 1.3.14 local tuples and rejects unknown tuple shapes", () => {
    const name = "@psy-protocol/psy-sdk";
    const spec = "file:../../../sdk";
    const lock = { workspaces: { "": { dependencies: { [name]: spec } } }, packages: { [name]: [`${name}@${spec}`, {}] } };
    expect(() => assertBunLock(JSON.stringify(lock), { [name]: spec })).not.toThrow();
    lock.packages[name][0] = `${name}@file:../../../wrong`;
    expect(() => assertBunLock(JSON.stringify(lock), { [name]: spec })).toThrow(/wrong sibling/);
    const registry = { workspaces: { "": { dependencies: { [name]: "2.0.8" } } }, packages: { [name]: [`${name}@2.0.8`, "", { bin: { fixture: "index.js" } }, "sha512-observed"] } };
    expect(() => assertBunLock(JSON.stringify(registry), { [name]: "2.0.8" }, { [name]: "sha512-observed" })).not.toThrow();
    registry.packages[name].push("sha512-observed");
    expect(() => assertBunLock(JSON.stringify(registry), { [name]: "2.0.8" }, { [name]: "sha512-observed" })).toThrow(/unknown Bun registry/);
  });

  it("refuses local tarball dependencies before registry lookup or publication", async () => {
    const packs = ["utils", "psy-sdk", "contract-sdk", "evm-wallet"].map(name => ({
      name: `@psy-protocol/${name}`, version: "2.0.8", path: "unused.tgz", integrity: "sha512-fixture",
      manifest: { name: `@psy-protocol/${name}`, version: "2.0.8", dependencies: name === "contract-sdk" ? { "@psy-protocol/psy-sdk": "file:../psy-sdk" } : {} }, entries: [],
    }));
    await expect(publishPackages(packs, "latest", async () => { throw new Error("must not contact registry"); })).rejects.toThrow(/refusing publication of local dependency/);
  });

  it("guards nested node declarations and source-null node lock identities without rejecting workspace crates", () => {
    const context = { nodePackages: ["psy_vm", "shared_name"], consumerPackages: ["consumer", "shared_name"] };
    const local = '[dependencies]\nvm = { package = "psy_vm", path = "../../psy-node/client_prover/psy_vm" }\n';
    expect(() => assertNoLocalDependencies("psy-sdk", "member/Cargo.toml", local, context)).toThrow(/local node dependency/);
    expect(() => assertNoLocalDependencies("psy-sdk", "member/Cargo.toml", '[dependencies]\nhelper = { path = "../helper" }\n', context)).not.toThrow();
    const lock = '[[package]]\nname = "consumer"\nversion = "0.1.0"\n\n[[package]]\nname = "shared_name"\nversion = "0.1.0"\n';
    expect(() => assertNoLocalDependencies("psy-sdk", "Cargo.lock", lock, context)).not.toThrow();
    const node = '\n[[package]]\nname = "psy_vm"\nversion = "0.1.0"\n';
    expect(() => assertNoLocalDependencies("psy-sdk", "member/Cargo.lock", lock + node, context)).toThrow(/local node lock package psy_vm/);
    expect(() => assertNoLocalDependencies("psy-sdk", "Cargo.lock", lock + node + `source = "git+https://github.com/PsyProtocol/psy-node?rev=${OLD}#${OLD}"\n`, context)).not.toThrow();
    expect(() => assertNoLocalDependencies("psy-node", "Cargo.lock", lock + node)).not.toThrow();
    expect(() => assertNoLocalDependencies("psy-sdk", "Cargo.lock", lock)).toThrow(/identities are required/);
  });
});

describe("prepare apply", () => {
  const parent = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const child = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const prepared = "cccccccccccccccccccccccccccccccccccccccc";
  const nodeBase = "dddddddddddddddddddddddddddddddddddddddd";
  const nodeNext = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
  const mode = 0o100644;
  const source = `git+https://github.com/PsyProtocol/psy-node.git?rev=${nodeNext}#${nodeNext}`;
  function digest(text: string): string { return createHash("sha256").update(text).digest("hex"); }
  function repository(name: string, head: string, files: Record<string, string>, gitlink?: { path: string; sha: string }): PrepareRepository {
    const path = join("/workspace", name);
    return {
      name, path, branch: "mainnet-beta", head,
      explicitPaths: Object.keys(files),
      ownedPaths: [...Object.keys(files), ...(gitlink ? [gitlink.path] : [])],
      files: [...Object.entries(files).map(([file, text]) => ({ path: file, sha256: digest(text), mode })), { path: ".gitmodules", sha256: null, mode: null }],
      gitmodulesSha256: null,
      gitlinks: gitlink ? [{ path: gitlink.path, child: "psy-genesis", from: gitlink.sha, nestedHead: gitlink.sha }] : [],
      cargo: null,
      nested: gitlink ? [{ path: join(path, gitlink.path), head: gitlink.sha, branch: "mainnet-beta", recorded: gitlink.sha, clean: true }] : [],
    };
  }
  function fake(heads: Record<string, string>, next: Record<string, string> = {}) {
    const calls: string[] = [];
    const staged: Record<string, string[]> = {};
    const links: Record<string, string> = {};
    const refs: Record<string, string> = {};
    const objects = new Set(Object.values(heads));
    const runner: Runner = (command, _cwd, env) => {
      calls.push(command.join(" "));
      const ok = (out = "") => ({ code: 0, out, err: "" });
      const denied = () => ({ code: 99, out: "", err: `unexpected command: ${command.join(" ")}` });
      if (command[0] !== "git" || env?.GIT_ALLOW_PROTOCOL !== "file" || env.GIT_CONFIG_COUNT !== "1" || env.GIT_CONFIG_KEY_0 !== "core.hooksPath" || env.GIT_CONFIG_VALUE_0 !== "/dev/null") return denied();
      if (command.slice(1, 4).join(" ") === "init --bare --quiet" && command.length === 5) return ok();
      if (command[1] !== "-C") return denied();
      const repo = command[2];
      const args = command.slice(3);
      const text = args.join(" ");
      if (args[0] === "rev-parse" && args[1] === "--verify" && args.length === 3) {
        const ref = args[2].replace(/\^\{commit\}$/, "");
        const sha = ref === "HEAD" ? heads[repo] : refs[`${repo}:${ref}`] || (objects.has(ref) ? ref : undefined);
        return sha ? ok(`${sha}\n`) : { code: 1, out: "", err: "unknown commit" };
      }
      if (text === "symbolic-ref --quiet --short HEAD") return ok("mainnet-beta\n");
      if (text === "diff --cached --name-only -z") return ok((staged[repo] || []).map(path => `${path}\0`).join(""));
      if (text === "ls-files --unmerged -z" || text === "status --porcelain=v1 --untracked-files=all --ignore-submodules=none") return ok();
      if (args[0] === "merge-base" && args[1] === "--is-ancestor" && args.length === 4) return ok();
      if (args[0] === "ls-files" && args[1] === "-s" && args[2] === "--" && args.length === 4) return ok(`160000 ${links[join(repo, args[3])] || child} 0\t${args[3]}\n`);
      if (args[0] === "ls-tree" && args[1] === "-r" && args[2] === "-z" && args.length === 4) return ok();
      if (text === "config --file .gitmodules --get-regexp ^submodule\\..*\\.path$") return { code: 1, out: "", err: "" };
      if (args[0] === "cat-file" && args[1] === "-e" && args.length === 3) return objects.has(args[2].replace(/\^\{commit\}$/, "")) ? ok() : { code: 1, out: "", err: "missing object" };
      if (args.slice(0, 6).join(" ") === "fetch --no-tags --no-write-fetch-head --refmap= --recurse-submodules=no /workspace/psy-node" && args.length === 7) {
        const [sha, ref] = args[6].split(":");
        if (heads[args[5]] !== sha || ref !== "refs/heads/prepare") return denied();
        refs[`${repo}:${ref}`] = sha;
        return ok();
      }
      if (args[0] === "--literal-pathspecs" && args[1] === "add" && args[2] === "--" && args.length > 3) {
        staged[repo] = [...(staged[repo] || []), ...args.slice(3)];
        return ok();
      }
      if (args[0] === "update-index" && args[1] === "--cacheinfo" && args[2] === "160000" && args.length === 5) {
        links[join(repo, args[4])] = args[3];
        staged[repo] = [...(staged[repo] || []), args[4]];
        return ok();
      }
      if (args.slice(0, 5).join(" ") === "submodule update --checkout --no-fetch --" && args.length === 6) {
        heads[join(repo, args[5])] = links[join(repo, args[5])];
        return ok();
      }
      if (args[0] === "commit" && args[1] === "--no-verify" && args[2] === "-m" && args.length === 4 && staged[repo]?.length && next[repo]) {
        heads[repo] = next[repo];
        objects.add(heads[repo]);
        staged[repo] = [];
        return ok();
      }
      return denied();
    };
    return { runner, calls, staged };
  }
  function memoryFs(files: Record<string, string>, directories: string[] = []): PrepareFs {
    const file = { isFile: () => true, isDirectory: () => false, isSymbolicLink: () => false, mode };
    const directory = { isFile: () => false, isDirectory: () => true, isSymbolicLink: () => false, mode: 0o40755 };
    const isDirectory = (path: string) => directories.includes(path) || Object.keys(files).some(file => file.startsWith(`${path}/`));
    return {
      readFileSync: path => { if (!(path in files)) throw new Error(`missing fixture file: ${path}`); return files[path]; },
      writeFileSync: (path, text) => { files[path] = text; },
      existsSync: path => path in files || isDirectory(path),
      realpathSync: path => path,
      lstatSync: path => path in files ? file : isDirectory(path) ? directory : undefined,
      mkdtempSync: () => "/tmp/workspace-prepare-memory",
      rmSync: () => undefined,
    };
  }

  it("commits only the owned path and skips a later empty repository", () => {
    const text = "owned\n";
    const first = repository("psy-genesis", parent, { "owned.txt": text });
    const second = repository("psy-contracts", parent, {});
    second.explicitPaths = [];
    second.ownedPaths = [];
    const files: Record<string, string> = { [join(first.path, "owned.txt")]: text };
    const heads: Record<string, string> = { [first.path]: parent, [second.path]: parent };
    files[join(first.path, "unrelated.rs")] = "unrelated dirt\n";
    const base = fake(heads, { [first.path]: prepared });
    const result = applyPreparation({ root: "/workspace", message: "prepare", repositories: [first, second], excluded: ["psy-node"] }, base.runner, memoryFs(files, [second.path]));
    expect(result.commits).toEqual([{ name: "psy-genesis", from: parent, to: prepared, paths: ["owned.txt"] }]);
    expect(result.skipped).toEqual(["psy-contracts"]);
    expect(files[join(first.path, "unrelated.rs")]).toBe("unrelated dirt\n");
    expect(base.calls.filter(call => call.includes(" add "))).toEqual([`git -C ${first.path} --literal-pathspecs add -- owned.txt`]);
    expect(base.calls.indexOf(`git -C ${first.path} --literal-pathspecs add -- owned.txt`)).toBeLessThan(base.calls.indexOf(`git -C ${first.path} commit --no-verify -m prepare`));
    expect(base.calls.some(call => call.startsWith("cargo") || call.includes("push"))).toBe(false);
  });

  it("pins the parent gitlink to the child's prepared commit without staging other paths", () => {
    const childRepo = repository("psy-genesis", parent, { "owned.txt": "child\n" });
    const parentRepo = repository("psy-node", parent, {}, { path: "psy-genesis", sha: child });
    parentRepo.explicitPaths = [];
    parentRepo.ownedPaths = ["psy-genesis"];
    parentRepo.files = [{ path: ".gitmodules", sha256: null, mode: null }];
    const heads: Record<string, string> = { [childRepo.path]: parent, [parentRepo.path]: parent, [join(parentRepo.path, "psy-genesis")]: child };
    const base = fake(heads, { [childRepo.path]: prepared, [parentRepo.path]: nodeNext });
    const result = applyPreparation({ root: "/workspace", message: "prepare", repositories: [childRepo, parentRepo], excluded: [] }, base.runner, memoryFs({ [join(childRepo.path, "owned.txt")]: "child\n", [join(parentRepo.path, "psy-genesis", ".git")]: "gitdir" }));
    expect(result.commits.map(item => item.to)).toEqual([prepared, nodeNext]);
    expect(base.calls.filter(call => call.includes("update-index"))).toEqual([`git -C ${parentRepo.path} update-index --cacheinfo 160000 ${result.commits[0].to} psy-genesis`]);
    expect(heads[join(parentRepo.path, "psy-genesis")]).toBe(result.commits[0].to);
    expect(base.calls.some(call => call.includes("push") || call.includes("reset"))).toBe(false);
  });

  it("resolves an unpublished node commit through a process-local git override and keeps the canonical URL", () => {
    const node = repository("psy-node", nodeBase, { "crate.rs": "node\n" });
    const sdk = repository("psy-sdk", parent, {});
    const manifest = `[dependencies]\npsy_vm = { git = "https://github.com/PsyProtocol/psy-node", rev = "${nodeBase}", package = "psy_vm" }\n`;
    const lock = `[[package]]\nname = "psy_vm"\nversion = "0.1.0"\nsource = "git+https://github.com/PsyProtocol/psy-node.git?rev=${nodeBase}#${nodeBase}"\n`;
    sdk.explicitPaths = [];
    sdk.ownedPaths = ["Cargo.toml", "Cargo.lock"];
    sdk.files = [{ path: "Cargo.toml", sha256: digest(manifest), mode }, { path: "Cargo.lock", sha256: digest(lock), mode }, { path: ".gitmodules", sha256: null, mode: null }];
    sdk.cargo = { dependency: "psy-node", from: [nodeBase] };
    const heads: Record<string, string> = { [node.path]: nodeBase, [sdk.path]: parent };
    const reads: Record<string, string> = {
      [join(sdk.path, "Cargo.toml")]: manifest, [join(sdk.path, "Cargo.lock")]: lock,
      [join(sdk.path, "package.json")]: '{"version":"2.0.8"}\n', [join(sdk.path, "pnpm-lock.yaml")]: "lockfileVersion: '9.0'\n",
      [join(node.path, "crate.rs")]: "node\n", [join(node.path, "unrelated.rs")]: "unrelated dirt\n",
      [join(node.path, "Cargo.toml")]: '[workspace]\nmembers = ["client_prover/psy_vm"]\n',
      [join(node.path, "client_prover/psy_vm/Cargo.toml")]: '[package]\nname = "psy_vm"\n',
    };
    const base = fake(heads, { [node.path]: nodeNext, [sdk.path]: prepared });
    let cargoEnv: NodeJS.ProcessEnv | undefined;
    const cargoCalls: string[][] = [];
    const runner: Runner = (command, cwd, env) => {
      if (command[0] !== "cargo") return base.runner(command, cwd, env);
      if (cwd !== sdk.path || !["metadata --format-version 1 --manifest-path Cargo.toml", "metadata --format-version 1 --manifest-path Cargo.toml --locked"].includes(command.slice(1).join(" "))) return { code: 99, out: "", err: "unexpected cargo command" };
      cargoCalls.push([...command]);
      cargoEnv = env;
      expect(heads[node.path]).toBe(nodeNext);
      expect(reads[join(sdk.path, "Cargo.toml")]).toContain(`rev = "${heads[node.path]}"`);
      expect(base.staged[sdk.path] || []).toEqual([]);
      if (!command.includes("--locked")) reads[join(sdk.path, "Cargo.lock")] = `[[package]]\nname = "psy_vm"\nversion = "0.1.0"\nsource = "${source}"\n`;
      return { code: 0, out: JSON.stringify({ packages: [{ name: "psy_vm", version: "0.1.0", id: "psy_vm", source, manifest_path: "/tmp/cargo/git/checkouts/psy-node/client_prover/psy_vm/Cargo.toml" }], resolve: { nodes: [{ id: "psy_vm", deps: [] }] } }), err: "" };
    };
    const preparedFs = memoryFs(reads);
    const result = applyPreparation({ root: "/workspace", message: "prepare", repositories: [node, sdk], excluded: [] }, runner, preparedFs);
    expect(result.commits.map(item => item.name)).toEqual(["psy-node", "psy-sdk"]);
    expect(reads[join(sdk.path, "Cargo.toml")]).toContain(`rev = "${nodeNext}"`);
    expect(reads[join(sdk.path, "Cargo.toml")]).toContain("https://github.com/PsyProtocol/psy-node");
    expect(reads[join(sdk.path, "Cargo.toml")]).not.toContain("/tmp/workspace-prepare-memory");
    expect(reads[join(sdk.path, "Cargo.lock")]).toContain(source);
    expect(reads[join(sdk.path, "package.json")]).toBe('{"version":"2.0.8"}\n');
    expect(reads[join(sdk.path, "pnpm-lock.yaml")]).toBe("lockfileVersion: '9.0'\n");
    expect(reads[join(node.path, "unrelated.rs")]).toBe("unrelated dirt\n");
    expect(result.commits[0].to).toBe(nodeNext);
    expect(result.commits[1].paths).toEqual(["Cargo.toml", "Cargo.lock"]);
    expect(cargoCalls).toHaveLength(2);
    expect(cargoCalls[1].at(-1)).toBe("--locked");
    expect(cargoEnv?.CARGO_NET_GIT_FETCH_WITH_CLI).toBe("true");
    expect(cargoEnv?.GIT_ALLOW_PROTOCOL).toBe("file");
    expect(cargoEnv?.GIT_CONFIG_KEY_0).toBe("protocol.file.allow");
    expect(cargoEnv?.GIT_CONFIG_VALUE_0).toBe("always");
    expect(cargoEnv?.GIT_CONFIG_KEY_1).toBe("url./workspace/psy-sdk.insteadOf");
    expect(cargoEnv?.GIT_CONFIG_VALUE_1).toBe("https://github.com/PsyProtocol/psy-sdk");
    expect(cargoEnv?.GIT_CONFIG_KEY_3).toBe("url./tmp/workspace-prepare-memory.insteadOf");
    expect(cargoEnv?.GIT_CONFIG_VALUE_3).toBe("https://github.com/PsyProtocol/psy-node");
    expect(cargoEnv?.GIT_CONFIG_KEY_4).toBe("url./tmp/workspace-prepare-memory.insteadOf");
    expect(cargoEnv?.GIT_CONFIG_VALUE_4).toBe("https://github.com/PsyProtocol/psy-node.git");
    expect(cargoEnv?.GIT_CONFIG_COUNT).toBe("6");
    expect(cargoEnv?.GIT_CONFIG_KEY_5).toBe("core.hooksPath");
    expect(cargoEnv?.GIT_CONFIG_VALUE_5).toBe("/dev/null");
    expect(base.calls.some(call => call.includes("push"))).toBe(false);
    expect(base.calls.some(call => call.includes("fetch") && call.includes(node.path) && call.includes(`${nodeNext}:refs/heads/prepare`))).toBe(true);
  });

  it("stops after a failed cargo resolution and does not commit or reset the consumer", () => {
    const node = repository("psy-node", nodeNext, {});
    node.explicitPaths = [];
    node.ownedPaths = [];
    node.files = [{ path: ".gitmodules", sha256: null, mode: null }];
    const sdk = repository("psy-sdk", parent, {});
    const manifest = `[dependencies]\npsy_vm = { git = "https://github.com/PsyProtocol/psy-node", rev = "${nodeBase}", package = "psy_vm" }\n`;
    sdk.ownedPaths = ["Cargo.toml", "Cargo.lock"];
    sdk.files = [{ path: "Cargo.toml", sha256: digest(manifest), mode }, { path: "Cargo.lock", sha256: digest("lock\n"), mode }, { path: ".gitmodules", sha256: null, mode: null }];
    sdk.cargo = { dependency: "psy-node", from: [nodeBase] };
    const reads: Record<string, string> = { [join(sdk.path, "Cargo.toml")]: manifest, [join(sdk.path, "Cargo.lock")]: "lock\n", [join(node.path, "Cargo.toml")]: '[workspace]\nmembers = ["client_prover/psy_vm"]\n', [join(node.path, "client_prover/psy_vm/Cargo.toml")]: '[package]\nname = "psy_vm"\n' };
    const base = fake({ [node.path]: nodeNext, [sdk.path]: parent });
    const calls = base.calls;
    const runner: Runner = (command, cwd, env) => {
      if (command.join(" ") === "cargo metadata --format-version 1 --manifest-path Cargo.toml" && cwd === sdk.path) {
        calls.push(command.join(" "));
        return { code: 1, out: "", err: "unresolved" };
      }
      return base.runner(command, cwd, env);
    };
    const preparedFs = memoryFs(reads);
    expect(() => applyPreparation({ root: "/workspace", message: "prepare", repositories: [node, sdk], excluded: [] }, runner, preparedFs)).toThrow(/partial prepare retained[\s\S]*unresolved/);
    expect(calls.some(call => call.includes("push") || call.includes(" commit ") || call.includes(" reset "))).toBe(false);
    expect(calls.some(call => call.includes("fetch") && call.includes(node.path) && call.includes(`${nodeNext}:refs/heads/prepare`))).toBe(true);
    expect(reads[join(sdk.path, "Cargo.toml")]).toContain(`rev = "${nodeNext}"`);
    expect(calls.filter(call => call.startsWith("cargo "))).toEqual(["cargo metadata --format-version 1 --manifest-path Cargo.toml"]);
    expect(reads[join(sdk.path, "Cargo.lock")]).toBe("lock\n");
  });

  it("rejects a stale later repository before any file or index write", () => {
    const first = repository("psy-genesis", parent, { "owned.txt": "first\n" });
    const second = repository("psy-contracts", parent, { "owned.txt": "preview\n" });
    const files = { [join(first.path, "owned.txt")]: "first\n", [join(second.path, "owned.txt")]: "changed\n" };
    const before = { ...files };
    const base = fake({ [first.path]: parent, [second.path]: parent }, { [first.path]: prepared });
    const fs = memoryFs(files);
    fs.writeFileSync = () => { throw new Error("must not write before all repositories pass preflight"); };
    fs.mkdtempSync = () => { throw new Error("must not create db before all repositories pass preflight"); };
    expect(() => applyPreparation({ root: "/workspace", message: "prepare", repositories: [first, second], excluded: [] }, base.runner, fs)).toThrow(/psy-contracts\/owned.txt: owned file changed since preparation preview/);
    expect(files).toEqual(before);
    expect(base.calls.some(call => / (add|commit|update-index|fetch) /.test(call))).toBe(false);
  });
});
