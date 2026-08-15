import { describe, expect, it } from "bun:test";
import { s3CurlArgs } from "./locSetupDefaults";
import {
    buildRollbackScyllaConfig,
    buildRollbackTopologyConfig,
    runStreamingCaptureStderr,
} from "./locSetupV4";

describe("buildRollbackTopologyConfig", () => {
    it("binds the exact contiguous Realm set started by the local devnet", () => {
        expect(buildRollbackTopologyConfig(7, 3)).toEqual({
            rollback_topology: {
                revision: 0,
                realms: [
                    { realm_id: 7, realm_sub_id: 1 },
                    { realm_id: 8, realm_sub_id: 1 },
                    { realm_id: 9, realm_sub_id: 1 },
                ],
            },
        });
    });

    it("rejects empty, negative, or overflowing Realm ranges", () => {
        expect(() => buildRollbackTopologyConfig(0, 0)).toThrow();
        expect(() => buildRollbackTopologyConfig(-1, 1)).toThrow();
        expect(() => buildRollbackTopologyConfig(0xffff_ffff, 2)).toThrow();
    });
});

describe("buildRollbackScyllaConfig", () => {
    it("uses one local replica unless RF3 is explicitly requested", () => {
        expect(buildRollbackScyllaConfig("127.0.0.1", false)).toEqual({
            url: "127.0.0.1:9042",
            ports: [9042],
            startDbArgs: ["./dev/start_db.sh", "--persist"],
        });
    });

    it("uses all three endpoints only for the explicit RF3 mode", () => {
        expect(buildRollbackScyllaConfig("10.0.0.5", true)).toEqual({
            url: "10.0.0.5:9042,10.0.0.5:9043,10.0.0.5:9044",
            ports: [9042, 9043, 9044],
            startDbArgs: ["./dev/start_db.sh", "--persist", "--rf3"],
        });
    });
});

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
