import { describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import {
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
  type RegistryPackage,
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
      expect(before.every(pin => pin.rev === OLD)).toBe(true);
      const rewritten = replacePsyNodeRevs(text, NEXT, repo);
      const after = pinsFromManifest(rewritten, repo);
      expect(after.map(pin => `${pin.table}.${pin.key}|${pin.url}|${JSON.stringify(pin.rest)}`)).toEqual(
        before.map(pin => `${pin.table}.${pin.key}|${pin.url}|${JSON.stringify(pin.rest)}`),
      );
      expect(after.every(pin => pin.rev === NEXT)).toBe(true);
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
