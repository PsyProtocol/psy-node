/**
 * Re-exports `protocolConfig` from the psy-contracts checkout.
 *
 * psy-contracts is a sibling repository of psy-node (its gitlink was removed);
 * resolve the sibling first and fall back to the legacy nested checkout so
 * older layouts keep working. The location is only known at runtime, so the
 * module is loaded with require() instead of a static import.
 */
import fs from "node:fs";
import path from "node:path";
import type { ProtocolConfig } from "../../psy-contracts/protocol-config";

const contractsRoot = fs.existsSync(path.join(import.meta.dir, "..", "..", "psy-contracts", "package.json"))
    ? path.join(import.meta.dir, "..", "..", "psy-contracts")
    : path.join(import.meta.dir, "..", "psy-contracts");

export const protocolConfig: ProtocolConfig = require(path.join(contractsRoot, "protocol-config", "index.ts")).protocolConfig;
