import { describe, expect, it } from "bun:test";
import {
    COORDINATOR_PROCESSOR_READY_MARKER,
    REALM_PROCESSOR_READY_MARKER,
    isExactProcessorReadyLine,
    s3CurlArgs,
} from "./locSetupDefaults";
import {
    evaluateCompilerArtifactStamp,
    isUsableGenesisData,
    readGenesisContractsArtifactStamp,
    resolveProjectsDir,
    RunningProcess,
    runStreamingCaptureStderr,
    retryProcessorStartup,
    startRealmProcessorBatchSequentially,
    writeCompilerArtifactStamp,
} from "./locSetupV4";
import type { GenesisContractsArtifactFingerprint } from "./locSetupV4";

describe("s3CurlArgs", () => {
    it("builds a shell-free curl argv that is fail-closed, follows redirects, and shows progress", () => {
        const args = s3CurlArgs("https://psy-protocol-devnet.s3.example/key.bin.zst", "/tmp/key.bin.zst.tmp");

        // No shell: the binary is invoked directly.
        expect(args[0]).toBe("curl");
        expect(args).not.toContain("bash");
        expect(args).not.toContain("-c");

        // Fail-closed: HTTP 4xx/5xx must produce a non-zero exit.
        expect(args).toContain("-f");

        // Errors still surface on piped (non-TTY) stderr.
        expect(args).toContain("-S");

        // Follow S3/CDN redirects.
        expect(args).toContain("-L");

        // Visible progress forced even though stderr is piped.
        expect(args).toContain("--progress-bar");

        // Progress is never silenced.
        expect(args).not.toContain("-s");
        expect(args).not.toContain("--silent");
        expect(args).not.toContain("--no-progress-meter");

        // Body is written to the destination temp file (atomic temp/extract flow
        // is the caller's responsibility); the URL is the final positional arg.
        const oIdx = args.indexOf("-o");
        expect(oIdx).toBeGreaterThan(-1);
        expect(args[oIdx + 1]).toBe("/tmp/key.bin.zst.tmp");
        expect(args[args.length - 1]).toBe("https://psy-protocol-devnet.s3.example/key.bin.zst");
    });

    it("preserves the destination and url verbatim for arbitrary paths", () => {
        const weird = "<workspace>/keystore/sub dir/circuit.bin.zst";
        const args = s3CurlArgs("https://x.example/a/b/c", weird);
        const oIdx = args.indexOf("-o");
        expect(args[oIdx + 1]).toBe(weird);
        expect(args[args.length - 1]).toBe("https://x.example/a/b/c");
    });
});

describe("runStreamingCaptureStderr", () => {
    it("captures stderr and propagates a non-zero exit code (fail-closed signal preserved)", async () => {
        const chunks: Uint8Array[] = [];
        const result = await runStreamingCaptureStderr(
            [process.execPath, "-e", "process.stderr.write('boom-diagnostic\\n'); process.exit(4)"],
            undefined,
            { stderrSink: (c) => chunks.push(c) },
        );

        // The exit code reaches the caller, so downloadS3File can fail-closed.
        expect(result.code).toBe(4);

        // Diagnostics are captured for the error message...
        expect(result.stderr).toContain("boom-diagnostic");

        // ...and the same bytes were streamed (teed) to the sink, i.e. visible
        // progress would reach the terminal in real use.
        const streamed = chunks.map((c) => new TextDecoder().decode(c)).join("");
        expect(streamed).toContain("boom-diagnostic");
    });

    it("returns code 0 on success and an empty captured stderr", async () => {
        const result = await runStreamingCaptureStderr(
            [process.execPath, "-e", "process.exit(0)"],
            undefined,
            { stderrSink: () => undefined },
        );
        expect(result.code).toBe(0);
        expect(result.stderr).toBe("");
    });

    it("propagates PWD via the cwd option (env.PWD equals cwd)", async () => {
        const cwd = process.cwd();
        const result = await runStreamingCaptureStderr(
            [process.execPath, "-e", `process.stderr.write(process.env.PWD + "\\n"); process.exit(0)`],
            cwd,
            { stderrSink: () => undefined },
        );
        expect(result.code).toBe(0);
        expect(result.stderr.trim()).toBe(cwd);
    });
});

describe("processor full-readiness startup", () => {
    it("accepts only exact processor completion markers", () => {
        expect(isExactProcessorReadyLine(COORDINATOR_PROCESSOR_READY_MARKER, COORDINATOR_PROCESSOR_READY_MARKER)).toBe(true);
        expect(isExactProcessorReadyLine(`INFO ${REALM_PROCESSOR_READY_MARKER}`, REALM_PROCESSOR_READY_MARKER)).toBe(true);
        expect(isExactProcessorReadyLine("[COORD_CREATE] processor new start", COORDINATOR_PROCESSOR_READY_MARKER)).toBe(false);
        expect(isExactProcessorReadyLine(`${COORDINATOR_PROCESSOR_READY_MARKER} trailing`, COORDINATOR_PROCESSOR_READY_MARKER)).toBe(false);
    });

    it("rejects non-transient pre-ready exits without retry", async () => {
        let attempts = 0;
        const startup = retryProcessorStartup("coordinator processor", async () => {
            attempts += 1;
            throw new Error("Process exited before initialization hint was found.\nfatal config error");
        }, { maxRetries: 3, retryDelayMs: 0 });
        await expect(startup).rejects.toThrow("fatal config error");
        expect(attempts).toBe(1);
    });

    it("retries transient Scylla raft add_entry failures", async () => {
        const attempts: number[] = [];
        const result = await retryProcessorStartup("realm 7 processor", async (attempt) => {
            attempts.push(attempt);
            if (attempt === 1) throw new Error("Scylla group 0 add_entry schema operation timed out");
            return "ready";
        }, { maxRetries: 2, retryDelayMs: 0 });
        expect(result).toBe("ready");
        expect(attempts).toEqual([1, 2]);
    });

    it("retries a readiness timeout after a transient Scylla failure", async () => {
        const attempts: number[] = [];
        const result = await retryProcessorStartup("realm 1 processor", async (attempt) => {
            attempts.push(attempt);
            if (attempt === 1) throw new Error("Scylla group 0 add_entry schema operation timed out");
            if (attempt === 2) throw new Error("Process did not reach its initialization marker within 180000ms");
            return "ready";
        }, { maxRetries: 3, retryDelayMs: 0 });
        expect(result).toBe("ready");
        expect(attempts).toEqual([1, 2, 3]);
    });

    it("resolves from the exact marker and rejects exit before it", async () => {
        const proc = await RunningProcess.spawnWithInitializationHint(
            [process.execPath, "-e", `process.stderr.write("${COORDINATOR_PROCESSOR_READY_MARKER}\\n", () => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0))`],
            (line) => isExactProcessorReadyLine(line, COORDINATOR_PROCESSOR_READY_MARKER),
            { initializationTimeoutMs: 500 },
        );
        expect(proc.isRunning()).toBe(true);
        proc.kill();
        await proc.proc.exited;

        const failed = RunningProcess.spawnWithInitializationHint(
            [process.execPath, "-e", "process.stderr.write('schema bootstrap failed\\n'); process.exit(7)"],
            (line) => isExactProcessorReadyLine(line, REALM_PROCESSOR_READY_MARKER),
            { initializationTimeoutMs: 500 },
        );
        await expect(failed).rejects.toThrow("Exit Code: 7");
        await expect(failed).rejects.toThrow("schema bootstrap failed");
    });
});

describe("startRealmProcessorBatchSequentially", () => {
    it("starts realms in readiness order and stops at the first failure", async () => {
        const started: number[] = [];
        const startup = startRealmProcessorBatchSequentially([4, 5, 6], async (realmId) => {
            started.push(realmId);
            if (realmId === 5) throw new Error("realm 5 failed readiness");
            return realmId;
        });
        await expect(startup).rejects.toThrow("realm 5 failed readiness");
        expect(started).toEqual([4, 5]);
    });
});

describe("isUsableGenesisData", () => {
    it("accepts canonical seconds and rejects milliseconds", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            const prefix = "x".repeat(70 * 1024);
            const milliseconds = `${dir}/milliseconds.json`;
            const seconds = `${dir}/seconds.json`;
            await Bun.write(milliseconds, `${prefix}\n{"checkpoint_stats":{"block_time":1764248609000}}`);
            await Bun.write(seconds, `${prefix}\n{"checkpoint_stats":{"block_time":1764248609}}`);
            expect(await isUsableGenesisData(seconds)).toBe(true);
            expect(await isUsableGenesisData(milliseconds)).toBe(false);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });
});

describe("resolveProjectsDir", () => {
    it("uses the explicit cohort directory when configured", () => {
        const originalProjectsDir = process.env.PSY_PROJECTS_DIR;
        try {
            process.env.PSY_PROJECTS_DIR = "<workspace>/mainnet-beta";
            expect(resolveProjectsDir()).toEndWith("<workspace>/mainnet-beta");
        } finally {
            if (originalProjectsDir === undefined) delete process.env.PSY_PROJECTS_DIR;
            else process.env.PSY_PROJECTS_DIR = originalProjectsDir;
        }
    });
});

describe("compiler/genesis artifact stamps", () => {
    const expected: GenesisContractsArtifactFingerprint = {
        compilerRevision: "rev",
        compilerSourcesHash: "sources",
        artifactSha256: "aa".repeat(32),
        artifactByteSize: 42,
    };

    it("matches only the exact compiler identity and artifact bytes", () => {
        expect(evaluateCompilerArtifactStamp({ ...expected }, expected)).toBe("match");
        expect(evaluateCompilerArtifactStamp(null, expected)).toBe("missing");
        expect(evaluateCompilerArtifactStamp({ ...expected, artifactByteSize: 43 }, expected)).toBe("mismatch");
        expect(evaluateCompilerArtifactStamp({ ...expected, artifactSha256: "bb".repeat(32) }, expected)).toBe("mismatch");
    });

    it("strictly reads and atomically replaces complete stamps", async () => {
        const dir = (await Bun.$`mktemp -d`.text()).trim();
        try {
            const stampPath = `${dir}/.genesis_contracts.compiler-artifact.json`;
            await Bun.write(stampPath, JSON.stringify({ compilerRevision: "rev", compilerSourcesHash: "sources" }));
            expect(await readGenesisContractsArtifactStamp(stampPath)).toBeNull();
            await writeCompilerArtifactStamp(stampPath, expected);
            expect(await readGenesisContractsArtifactStamp(stampPath)).toEqual(expected);
            expect(await Bun.file(`${stampPath}.tmp`).exists()).toBe(false);
        } finally {
            await Bun.$`rm -rf ${dir}`.quiet();
        }
    });
});