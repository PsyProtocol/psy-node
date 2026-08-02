import path from "node:path";
import { pathToFileURL } from "node:url";

async function main() {
  const compilerDir = process.env.PSY_COMPILER_MODULE_DIR;
  if (!compilerDir) {
    throw new Error("PSY_COMPILER_MODULE_DIR was not provided by the native adapter");
  }

  const compilerUrl = pathToFileURL(path.join(compilerDir, "psy_compiler.mjs")).href;
  const wasmBinaryUrl = pathToFileURL(path.join(compilerDir, "wasm-binary.mjs")).href;
  const [{ initSync, compile_source, compile_project }, { wasmBinary }] = await Promise.all([
    import(compilerUrl),
    import(wasmBinaryUrl),
  ]);

  const originalConsoleLog = console.log;
  const originalConsoleInfo = console.info;
  const originalConsoleDebug = console.debug;
  const originalConsoleWarn = console.warn;
  console.log = (...args) => console.error(...args);
  console.info = (...args) => console.error(...args);
  console.debug = (...args) => console.error(...args);
  console.warn = (...args) => console.error(...args);

  initSync({ module: wasmBinary });

  let requestJson = "";
  for await (const chunk of process.stdin) {
    requestJson += chunk;
  }
  const request = JSON.parse(requestJson);

  let result;
  if (request.mode === "source" && typeof request.source === "string") {
    result = compile_source(request.source);
  } else if (request.mode === "project" && request.project) {
    result = compile_project(JSON.stringify(request.project));
  } else {
    throw new Error(`unsupported compiler request mode: ${String(request.mode)}`);
  }

  if (typeof result !== "string") {
    throw new Error("local-web-compiler returned a non-string result");
  }
  console.log = originalConsoleLog;
  console.info = originalConsoleInfo;
  console.debug = originalConsoleDebug;
  console.warn = originalConsoleWarn;
  process.stdout.write(result);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
